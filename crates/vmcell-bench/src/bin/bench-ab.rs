//! `bench-ab`: the two-arm, one-host, one-session A/B regression harness (design §16, Performance).
//!
//! WHY THIS BINARY EXISTS. On 2026-08-21 a benchmark pass compared HEAD against the previous
//! release with ad-hoc shell, and three things went wrong. Each one is a mechanism here rather than
//! a paragraph in a runbook:
//!
//! 1. **The canonical results table had been measured on a different machine**, so absolute
//!    milliseconds could not answer "did we regress". Only an interleaved, same-host, same-session
//!    A/B can — [`vmcell_bench::ab::interleave`], and the deliberate absence of any
//!    "compare against a stored baseline from another machine" mode.
//! 2. **A control silently did not apply.** The driver exported `$VMCELL_KERNEL` to pin both arms
//!    to one guest kernel; the old arm's `bench-vm` predates that variable and composes
//!    `<artifacts_dir>/vmlinux` itself, so the arms booted 6.12.94 against 6.12.104 for an entire
//!    matrix. Every control here is checked by **digest** before a single VM boots, and the run is
//!    REFUSED — never warned-and-continued — when one fails: a violated control produces confident
//!    wrong numbers, which is worse than no numbers.
//! 3. **An arm's binary was swapped underneath a run** by a concurrent build, while `git status`
//!    stayed clean. The staged binaries are re-digested before *every* child spawn, not once at
//!    start-up, because the swap that motivated this landed between two cells of one matrix.
//!
//! And the statistics: **a single p50 is not evidence.** Of six deltas ≥10% in that pass's first
//! single-pass matrix, five evaporated under repeats and one reversed sign.
//!
//! WHAT GOES WHERE. Progress and diagnostics go to **stderr**; the comparison — the table, or the
//! `--format json` document — goes to **stdout**. A caller can therefore pipe the result without
//! filtering the narration, which is the same discipline `bench-vm --report json` follows one
//! process down.
//!
//! `print_stdout`/`print_stderr` are intentionally NOT denied here: emitting the comparison is the
//! point of the binary.
#![deny(missing_docs, unsafe_op_in_unsafe_fn, rustdoc::broken_intra_doc_links)]
#![deny(unreachable_pub)] // pub-in-private-module API-surface honesty
#![deny(
    clippy::undocumented_unsafe_blocks,
    clippy::missing_safety_doc,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::multiple_unsafe_ops_per_block // one obligation per SAFETY comment
)]
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::panic,
        clippy::unreachable,
        clippy::todo,
        clippy::unimplemented,
        clippy::indexing_slicing,
        clippy::dbg_macro,
        // AGENTS.md "Fail loud": no bare `let _ =` on a `Result`. `let_underscore_must_use` is the
        // narrowest instrument rustc/clippy has for that rule — and it is deliberately BROADER on
        // one axis, firing on any `#[must_use]` expression (a discarded `SharedRootfsWarning`, a
        // detached child), which is the same defect one step out: the compiler said this matters
        // and the code said nothing back. Scoped `not(test)` like every lint in this block.
        // `crates/vmcell/tests/lint_roster.rs` is the gate that this line exists in EVERY crate
        // root, so a new crate root cannot opt out by being new.
        clippy::let_underscore_must_use,
        clippy::allow_attributes,               // B11: prefer #[expect] over #[allow] in prod code
        clippy::allow_attributes_without_reason  // B11: every suppression states why
    )
)]

use clap::{Args as ClapArgs, Parser, Subcommand};
use serde::Serialize;
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command as ProcCommand;

use vmcell_bench::ab::{
    ArmManifest, DigestedFile, Run, Spec, guard_binaries_unchanged, guard_booted_artifacts,
    guard_distinct_rootfs, guard_same_kernel, guard_vmm_binaries, interleave,
};
use vmcell_bench::metrics::Direction;
use vmcell_bench::report::{BenchReport, Unit};
use vmcell_bench::stats::{RankTest, holm_bonferroni, mann_whitney, median};

/// Progress narration. Always stderr: stdout carries the comparison and nothing else, so
/// `bench-ab run --format json > out.json` is a document and not a document with a log in it.
macro_rules! progress {
    ($($arg:tt)*) => {{ eprintln!($($arg)*); }};
}

/// Where `prepare` stages each arm, relative to the HEAD checkout.
///
/// **Both facts about this location are load-bearing**, and neither is obvious:
///
/// * the blessed runner refuses to exec a target outside its own workspace `target/`
///   (`confine_under`), so an arm staged in `/tmp` cannot be wrapped at all; and
/// * `bench-vm` locates `vmcelld` as its own **sibling** (`current_exe().parent().join("vmcelld")`),
///   so staging into `target/release/` would leave the old harness measuring HEAD's daemon and
///   report it as the old arm's.
const ARMS_DIR_REL: &str = "target/ab-arms";

/// Where `prepare` puts each arm's git worktree, relative to the HEAD checkout.
const WORKTREES_DIR_REL: &str = "target/ab-worktrees";

/// The manifest file inside an arm's staging directory.
const MANIFEST_NAME: &str = "arm.json";

/// The blessed capability runner, as the `justfile` installs it (its `runner` variable). Relative
/// to the HEAD checkout.
const DEFAULT_RUNNER_REL: &str = ".vmcell-bin/debug/vmcell-test-runner";

/// The cgroup-delegation wrapper every live suite is invoked through.
const DEFAULT_SCOPE_SCRIPT_REL: &str = "scripts/with-delegated-scope.sh";

/// Repeats per (arm, spec) below which no verdict is printed, whatever the numbers look like.
///
/// FOUR IS NOT A ROUND NUMBER, it is the floor at which a verdict becomes *possible*. An exact
/// two-sided Mann-Whitney U over n=m=3 has 20 arrangements, so its most extreme outcome — every
/// sample of one arm above every sample of the other — is p = 2/20 = 0.10. No amount of separation
/// at three repeats can reach 0.05, so "no evidence" there would be a statement about the sample
/// size and not about the code. At n=m=4 the extreme is 2/70 ≈ 0.029, and the test can speak.
/// (This harness uses the normal approximation, which is anticonservative at these sizes; the floor
/// is derived from the exact test on purpose.)
const MIN_REPEATS_FOR_VERDICT: usize = 4;

/// The p below which a difference is called rather than left as "no evidence".
const SIGNIFICANCE: f64 = 0.05;

/// The default matrix: the three modes whose numbers a host-side change most often moves.
///
/// Deliberately small. A default that boots a hundred VMs is a default nobody runs twice, and the
/// interleaved plan multiplies it by (arms × repeats) — three specs at the default five repeats is
/// already thirty `bench-vm` invocations.
const DEFAULT_SPECS: [&str; 3] = [
    "cloud-hypervisor/latency",
    "cloud-hypervisor/vsock-rtt",
    "cloud-hypervisor/phase-budget",
];

/// The two-arm A/B regression harness.
#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about = "Interleaved two-arm A/B benchmark comparison for vmcell"
)]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

/// `bench-ab`'s two verbs.
#[derive(Subcommand, Debug)]
enum Cmd {
    /// Build and stage one arm from a git ref, and pin what it will boot.
    Prepare {
        /// The git ref to build: `HEAD`, a branch, a tag or a commit. It is resolved to a
        /// commit, and the arm's worktree is checked out at THAT — a reused worktree sitting at
        /// another commit is re-checked out, never silently rebuilt under the new ref's name.
        /// The ref must carry `bench-vm --report json`; `prepare` probes for it and refuses early.
        #[arg(long)]
        git_ref: String,
        /// The name this arm is reported under, e.g. `base` or `head`.
        #[arg(long)]
        label: String,
        /// Extra features for the arm's `vmcell-bench` build. An old ref may not have every
        /// feature today's default set carries, so the list is an input rather than a constant.
        #[arg(long)]
        features: Option<String>,
        /// The `vmlinux` that IS the control — copied into the arm's artifacts dir. Defaults to
        /// the kernel THIS checkout resolves (`$VMCELL_KERNEL`, else
        /// `<artifacts-dir>/vmlinux`).
        #[arg(long)]
        kernel: Option<PathBuf>,
    },
    /// Run the interleaved comparison over two prepared arms.
    Run(RunArgs),
}

/// The `run` verb's inputs.
///
/// WHY A STRUCT AND NOT EIGHT PARAMETERS. `cmd_run` took them positionally and carried this
/// tree's only function-scoped `#[expect(clippy::too_many_arguments)]` — a suppression over a
/// whole function body, which AGENTS.md allows only per statement. A `clap::Args` group is not a
/// type invented to silence a lint: clap parses straight into it, so the flag roster and the
/// function's parameter list stop being two lists that have to agree.
#[derive(ClapArgs, Debug)]
struct RunArgs {
    /// An arm's label. Pass exactly twice, with two DIFFERENT labels — this is an A/B, and the
    /// rank test compares two samples.
    #[arg(long = "arm")]
    arms: Vec<String>,
    /// A cell of the matrix: `<backend>/<mode>` plus any extra `bench-vm` arguments, e.g.
    /// `--spec 'cloud-hypervisor/latency --mem-mib 512'`. Repeatable; omitted runs the
    /// built-in default matrix.
    //
    // The default roster is `DEFAULT_SPECS`. Named in a `//` comment and not in the doc
    // comment above, because clap prints THAT as `--help` text and a rustdoc link renders
    // there as literal brackets — the same reason `vmcell-cli`'s `--release` keeps its
    // rationale off the doc comment.
    #[arg(long = "spec", value_parser = parse_spec)]
    specs: Vec<Spec>,
    /// How many times each (arm, spec) is measured. Below four per arm no verdict is
    /// printed at all — an exact rank test cannot reach p < 0.05 with three.
    //
    // The floor is `MIN_REPEATS_FOR_VERDICT`, whose rustdoc carries the arithmetic.
    #[arg(long, default_value_t = 5)]
    repeats: usize,
    /// `text` (default) or `json` — the whole comparison, for a tracked-metrics job.
    #[arg(long, default_value = "text", value_parser = parse_output_format)]
    format: OutputFormat,
    /// Spawn each `bench-vm` directly, with no `systemd-run` scope and no blessed runner. Use
    /// this when `bench-ab` is ITSELF already running inside the privilege window.
    #[arg(long, default_value_t = false)]
    no_wrap: bool,
    /// The blessed capability runner. Defaults to `.vmcell-bin/debug/vmcell-test-runner`
    /// under this checkout (`DEFAULT_RUNNER_REL`, the justfile's own `runner`).
    #[arg(long)]
    runner: Option<PathBuf>,
    /// The cgroup-delegation wrapper. Defaults to `scripts/with-delegated-scope.sh`
    /// (`DEFAULT_SCOPE_SCRIPT_REL`).
    #[arg(long)]
    scope_script: Option<PathBuf>,
}

/// What `--format` emits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OutputFormat {
    /// The human table.
    Text,
    /// The whole comparison as one JSON document.
    Json,
}

/// Parses `--format`, rejecting anything else at parse time rather than defaulting (H-BIN-1's rule:
/// an accepted input is honored or refused, never silently reinterpreted).
fn parse_output_format(s: &str) -> Result<OutputFormat, String> {
    match s {
        "text" => Ok(OutputFormat::Text),
        "json" => Ok(OutputFormat::Json),
        other => Err(format!("invalid format '{other}' (expected: text, json)")),
    }
}

/// Parses a `--spec`: `<backend>/<mode>` followed by any extra `bench-vm` arguments.
///
/// The extra arguments are part of the spec's identity ([`Spec::id`]), because two specs differing
/// only in `--mem-mib` are two different measurements and pooling them would be the unqualified
/// phase-row defect one level up.
fn parse_spec(s: &str) -> Result<Spec, String> {
    let mut words = s.split_whitespace();
    let head = words
        .next()
        .ok_or_else(|| format!("empty --spec '{s}' (expected <backend>/<mode>)"))?;
    let (backend, mode) = head.split_once('/').ok_or_else(|| {
        format!("--spec '{s}' must start with <backend>/<mode>, e.g. cloud-hypervisor/latency")
    })?;
    if backend.is_empty() || mode.is_empty() {
        return Err(format!(
            "--spec '{s}' must name both a backend and a mode, e.g. cloud-hypervisor/latency"
        ));
    }
    Ok(Spec::new(backend, mode).with_args(words))
}

// ----------------------------------------------------------------------------
// The child command — wrapped EXACTLY once.
// ----------------------------------------------------------------------------

/// The `$VMCELL_*` overrides **stripped** from every `bench-vm` child's environment.
///
/// WHY A CHILD INHERITS TOO MUCH. Setting `$VMCELL_ARTIFACTS_DIR` is not the same as controlling
/// what an arm boots: `vmcell::artifact::kernel_path` / `rootfs_path` read `$VMCELL_KERNEL` /
/// `$VMCELL_ROOTFS` **first** and only fall back to the artifacts dir, so an operator with either
/// exported — README's `VMCELL_*` contract table documents both as the downstream switch, and
/// `ci.yml` sets `$VMCELL_ROOTFS` on its downstream-example step — makes every arm boot ONE guest
/// artifact while this harness reports per-arm ones. That is the 2026-08-21 kernel control failing again, from the other side: there
/// the export did not reach an arm that predates it, here an export nobody made for this run
/// reaches every arm. `crates/vmcell-bench/tests/benchmark.rs` already had to clear the same pair
/// so a developer's exports could not send a dry-path test at a real artifact pair; this is that
/// lesson at the driver.
///
/// `$VMCELL_PINS` is here for the same reason one level back: it is the pins overlay every artifact
/// build folds in, so a leaked overlay silently re-keys what an arm's `prepare` produced.
///
/// **`$VMCELL_{CH,FC,QEMU,CROSVM}_BIN` are deliberately NOT sealed.** Those select the *host* VMM
/// binary, which both arms are supposed to share, and pinning one deliberately is the documented
/// workaround for an old arm that hardcodes the name (README's "point one run at a time through
/// `$VMCELL_CH_BIN`"). Stripping them would break the fix and hide nothing:
/// [`guard_vmm_binaries`] verifies the OUTCOME from the reports, which is the only evidence that
/// ever counted.
const SEALED_CHILD_VARS: [&str; 3] = ["VMCELL_KERNEL", "VMCELL_ROOTFS", "VMCELL_PINS"];

/// How each `bench-vm` child is wrapped.
#[derive(Debug, Clone)]
struct WrapPlan {
    /// False for `--no-wrap`: spawn the arm's binary directly.
    wrap: bool,
    /// The blessed capability runner.
    runner: PathBuf,
    /// The cgroup-delegation wrapper script.
    scope_script: PathBuf,
}

/// The ONE composer of a child's argv.
///
/// WRAPPED EXACTLY ONCE, and this is the whole reason the composition is a function with a test
/// rather than four lines at the spawn site. The blessed runner's file capabilities are
/// `BLESSED_FILE_CAPS` — the delivered `PRIVILEGED_CAPS` plus the transient `CAP_SETPCAP` — with
/// the effective bit set. The first wrap shrinks the bounding set to `PRIVILEGED_CAPS`, dropping
/// `CAP_SETPCAP` out of it, and `execve` then computes `pP' = (X & fP) | (pI & fI)` and returns
/// **EPERM** rather than degrading. A second wrap therefore cannot succeed, and it reports itself
/// as a bare `Operation not permitted (os error 1)` that names nothing — which is exactly how it
/// reached CI from `just test-bench`, five tests dead at 0.008s. `crates/vmcell-bench/tests/common`
/// carries that law for the test suite; this is its A/B-harness twin.
///
/// `--report json` is appended LAST so a spec's pass-through arguments cannot displace it: the
/// parent parses this child's stdout, and a child that printed the human table instead would fail
/// at `serde_json` with the table as the evidence.
fn child_argv(plan: &WrapPlan, bench_vm: &Path, spec: &Spec) -> Vec<OsString> {
    let mut argv: Vec<OsString> = Vec::new();
    if plan.wrap {
        // The same invocation `ci.yml` and the justfile header use for every live suite: a
        // transient user scope with the cgroup controllers delegated, so the per-VM cgroups the
        // limits legs need can be created at all.
        argv.push("systemd-run".into());
        argv.push("--user".into());
        argv.push("--scope".into());
        argv.push("-q".into());
        argv.push("--collect".into());
        argv.push("-p".into());
        argv.push("Delegate=yes".into());
        argv.push(plan.scope_script.clone().into_os_string());
        argv.push(plan.runner.clone().into_os_string());
    }
    argv.push(bench_vm.as_os_str().to_os_string());
    argv.push("--backend".into());
    argv.push(OsString::from(&spec.backend));
    argv.push("--mode".into());
    argv.push(OsString::from(&spec.mode));
    for extra in &spec.extra_args {
        argv.push(OsString::from(extra));
    }
    argv.push("--report".into());
    argv.push("json".into());
    argv
}

/// The ONE composer of a child's *environment*, beside [`child_argv`]'s composition of its argv.
///
/// Two halves, and both are controls rather than conveniences:
///
/// * `$VMCELL_ARTIFACTS_DIR` is SET to this arm's own dir. `bench-vm` otherwise resolves it by
///   ascending from its CWD, and the staged binary lives under HEAD's `target/`, so every arm
///   would boot HEAD's artifacts.
/// * every [`SEALED_CHILD_VARS`] entry is REMOVED, because the setting above is not sufficient —
///   the kernel and rootfs resolvers read their own variables first.
///
/// # Errors
/// Returns an error for an empty argv, which would be a [`child_argv`] bug rather than an input
/// problem.
fn child_command(arm: &ArmManifest, argv: &[OsString]) -> anyhow::Result<ProcCommand> {
    let (program, rest) = argv
        .split_first()
        .ok_or_else(|| anyhow::anyhow!("empty child argv (composer bug)"))?;
    let mut cmd = ProcCommand::new(program);
    cmd.args(rest)
        .env("VMCELL_ARTIFACTS_DIR", &arm.artifacts_dir);
    for var in SEALED_CHILD_VARS {
        cmd.env_remove(var);
    }
    Ok(cmd)
}

/// Whether this process is ALREADY inside the blessed runner's privilege window, read from a
/// `/proc/<pid>/status` dump.
///
/// The runner delivers `PRIVILEGED_CAPS` through the **ambient** set, so a non-zero `CapAmb` is the
/// direct observation that a first wrap has happened. Pure (the dump is an argument) so both
/// answers are testable outside the window.
///
/// A missing `CapAmb` line reads as "not inside": the field has existed since Linux 4.3, so its
/// absence means the probe itself is not working, and refusing every run on an unreadable
/// `/proc/self/status` would break the common case to guard the rare one. The wrap it would have
/// allowed still fails loud — with EPERM at spawn, which is what the refusal exists to *explain*,
/// not to prevent.
fn inside_privilege_window(proc_status: &str) -> bool {
    proc_status
        .lines()
        .find_map(|line| line.strip_prefix("CapAmb:"))
        .and_then(|hex| u64::from_str_radix(hex.trim(), 16).ok())
        .is_some_and(|caps| caps != 0)
}

/// The double-wrap refusal, as its own composer so the message is asserted rather than eyeballed.
fn double_wrap_refusal() -> String {
    "bench-ab is already running inside the blessed runner's privilege window (CapAmb is \
     non-empty), so wrapping each `bench-vm` child in the runner would be a SECOND wrap. The \
     first wrap shrank this process's bounding set to PRIVILEGED_CAPS, dropping the transient \
     CAP_SETPCAP that is still set +ep on the runner file, and execve returns EPERM rather than \
     degrading — the children would all die at spawn with a bare `os error 1`. THE FIX: pass \
     --no-wrap. The children then inherit PRIVILEGED_CAPS through the ambient set, which is \
     exactly how `just test-bench` spawns bench-vm from an already-wrapped test binary."
        .to_string()
}

// ----------------------------------------------------------------------------
// Aggregation and verdicts.
// ----------------------------------------------------------------------------

/// One comparable quantity: a spec's cell of the matrix, and one metric inside it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct MetricKey {
    /// [`Spec::id`] — backend, mode and the extra arguments, because those change what was
    /// measured.
    spec: String,
    /// The backend the reports declared (not the spec's, so a report that ran something else is
    /// visible).
    backend: String,
    /// The mode the reports declared.
    mode: String,
    /// The metric's stable identifier.
    metric: String,
}

/// One repeat's contribution to a row: the p50 that gets ranked, and the accounting that says
/// what that p50 is a p50 **of**.
///
/// WHY THE ACCOUNTING TRAVELS WITH THE NUMBER. The first collector pushed `metric.p50` and dropped
/// `Metric::{n, dropped, warmup_failed}` on the floor — which is survivorship bias with a p-value
/// attached, and `crate::report`'s own rustdoc had already stated the rule it broke: *"a p50 over
/// three surviving samples out of ten is a different claim from a p50 over ten, and a comparator
/// that cannot see the difference will happily rank them."* An arm whose boots failed seven times
/// out of ten reports the p50 of the three that survived — the *fast* ones, because a slow boot is
/// what times out — so the lossy arm looks better, and the comparator says so with confidence.
#[derive(Debug, Clone, Copy, PartialEq)]
struct RepeatSample {
    /// The p50 this repeat contributed.
    p50: f64,
    /// Iterations that became measurements inside that repeat.
    n: usize,
    /// Measurement iterations that produced no sample. These contaminate the percentile.
    dropped: usize,
    /// Warmup iterations that failed. Deliberately NOT treated as contamination — a failed warmup
    /// never entered the percentile, which is exactly why [`vmcell_bench::report::Metric`] keeps
    /// the two counts apart. It is still surfaced: an arm that could not complete its warmups was
    /// running on a different machine, morally speaking, than one that could.
    warmup_failed: usize,
}

/// One arm's side of a row: the series that gets ranked, and what it cost to obtain.
#[derive(Debug, Clone, Default, PartialEq)]
struct ArmSeries {
    /// One p50 per repeat, in plan order.
    p50s: Vec<f64>,
    /// Iterations that became measurements, summed over the repeats.
    samples: usize,
    /// Measurement iterations that produced no sample, summed over the repeats.
    dropped: usize,
    /// Warmup iterations that failed, summed over the repeats.
    warmup_failed: usize,
}

impl ArmSeries {
    /// Folds one arm's repeats into the ranked series plus its accounting.
    fn of(repeats: &[RepeatSample]) -> Self {
        let mut out = Self::default();
        for repeat in repeats {
            out.p50s.push(repeat.p50);
            out.samples += repeat.n;
            out.dropped += repeat.dropped;
            out.warmup_failed += repeat.warmup_failed;
        }
        out
    }
}

/// One key's series: the unit both arms must agree on, and each arm's per-repeat samples.
#[derive(Debug, Clone)]
struct KeySamples {
    /// The unit the first report declared for this metric. Non-optional by construction: the
    /// entry only exists because a metric created it.
    unit: Unit,
    /// Each arm's per-repeat samples, one entry per repeat.
    by_arm: BTreeMap<String, Vec<RepeatSample>>,
}

/// Every repeat's sample for one key, per arm.
type Samples = BTreeMap<MetricKey, KeySamples>;

/// The per-repeat samples each (arm, key) produced, one entry per repeat.
///
/// WHY p50 AND NOT THE RAW SAMPLES. A `bench-vm` invocation reports a distribution, not a sample;
/// pooling two arms' raw iterations would rank within-run noise against between-run noise and call
/// the result a difference. One run contributes one number, the rank test runs over repeats, and
/// that is the shape that survived on 2026-08-21 when five of six single-pass "deltas" evaporated.
///
/// The p50 does not travel alone: see [`RepeatSample`] for why the sample accounting rides with it.
///
/// # Errors
/// Returns an error when one metric name arrives in two different units. That is not a comparison
/// with a caveat, it is a 1000x regression nobody made — the same "the numbers were real and the
/// question was wrong" shape as the kernel control that did not apply — so it stops the run instead
/// of ranking microseconds against milliseconds.
///
/// Returns an error, too, for a report that carries one metric name TWICE. A report is another
/// process's output — and, for one of the two arms, another commit's — so it is parsed, not
/// trusted: a duplicated name silently contributes two repeats where the plan scheduled one, which
/// doubles that arm's `n`, halves the rank test's variance and manufactures significance out of a
/// bookkeeping bug in the emitter. There is no reading of a duplicate that produces a right
/// answer, so it stops the run.
fn collect_samples(runs: &[(String, Spec, BenchReport)]) -> anyhow::Result<Samples> {
    let mut out: Samples = BTreeMap::new();
    for (arm, spec, report) in runs {
        let mut seen: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
        for metric in &report.metrics {
            if !seen.insert(metric.name.as_str()) {
                anyhow::bail!(
                    "arm `{arm}` reported metric `{}` twice in one run of {} — a report carries \
                     one entry per measured quantity, and a duplicate would contribute two \
                     repeats where the plan scheduled one: that arm's sample count doubles, the \
                     rank test's variance falls, and a difference nobody made clears the \
                     threshold. Fix the emitting build rather than comparing against it.",
                    metric.name,
                    spec.id()
                );
            }
            let key = MetricKey {
                spec: spec.id(),
                backend: report.backend.clone(),
                mode: report.mode.clone(),
                metric: metric.name.clone(),
            };
            let entry = out.entry(key).or_insert_with(|| KeySamples {
                unit: metric.unit,
                by_arm: BTreeMap::new(),
            });
            if entry.unit != metric.unit {
                anyhow::bail!(
                    "metric `{}` arrived as {:?} and as {:?} across the arms of {} — a unit change \
                     is a schema change, and ranking one against the other would report a factor \
                     of a thousand as a regression. Compare arms whose report schema agrees.",
                    metric.name,
                    entry.unit,
                    metric.unit,
                    spec.id()
                );
            }
            entry
                .by_arm
                .entry(arm.clone())
                .or_default()
                .push(RepeatSample {
                    p50: metric.p50,
                    n: metric.n,
                    dropped: metric.dropped,
                    warmup_failed: metric.warmup_failed,
                });
        }
    }
    Ok(out)
}

/// Which way is better for `metric`, and whether this build actually declared it.
///
/// THE RULE THIS REPLACED was one line — `metric != "footprint_ksm_pages_sharing_delta"`, i.e.
/// "every metric is a cost except the one exception I remembered" — over the ~50 names
/// [`vmcell_bench::metrics::METRIC_DIRECTIONS`] now enumerates. It was wrong in two whole classes:
/// `footprint_guest_mem_available` is a *benefit* (it printed IMPROVEMENT for a guest that lost
/// memory), and every `phase_*_share` / `suspend_memory_file_share` is a **compositional
/// percentage** where no direction exists at all — make teardown twice as fast and connect's share
/// rises, so the table would call that a regression.
///
/// AN UNKNOWN NAME IS `Neutral` AND LOUD, NOT A REFUSAL. An A/B compares two git refs, so a metric
/// the other ref emits and this build has never heard of is the tool working as intended; refusing
/// the comparison would break exactly the cross-version case `bench-ab` exists for. The `false`
/// second element is what the caller turns into a warning. What keeps *this* tree's roster
/// complete is the other side: `bench-vm` refuses to emit a report naming a metric the roster does
/// not carry (`refuse_unregistered_metrics`), so a hole here cannot originate at home.
fn metric_direction(metric: &str) -> (Direction, bool) {
    match vmcell_bench::metrics::direction(metric) {
        Some(direction) => (direction, true),
        None => (Direction::Neutral, false),
    }
}

/// The warning an undeclared metric earns, as its own composer so it is asserted rather than
/// eyeballed.
fn undeclared_metric_warning(metric: &str) -> String {
    format!(
        "metric `{metric}` has no declared direction in this build, so its row prints a delta and \
         NO verdict — calling it a regression or an improvement would be a guess about which way \
         is better. Expected when an arm is a ref that emits metrics this one does not know; if \
         both arms are recent, add `{metric}` to vmcell_bench::metrics::METRIC_DIRECTIONS."
    )
}

/// The warning a note asymmetry earns.
///
/// Two arms are supposed to differ in *code*, not in the conditions they were measured under. A
/// run where one arm reports `cpufreq: NOT pinned` and the other does not is two different noise
/// floors, and every delta below it is partly that — the artifact already said so, and nothing
/// read it.
fn note_asymmetry_warning(note: &str, present: &str, absent: &str) -> String {
    format!(
        "arm `{present}` reported `{note}` and arm `{absent}` did not. The arms were measured \
         under different conditions, not just with different code — a self-skip on one side means \
         the two matrices are not the same matrix, and a cpufreq or capability difference means \
         the two noise floors are not the same floor. Re-run both arms under the same privileges \
         and the same host state before reading the verdicts below."
    )
}

/// What a row concludes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Verdict {
    /// Arm B is significantly worse.
    Regression,
    /// Arm B is significantly better.
    Improvement,
    /// The difference did not clear [`SIGNIFICANCE`] after the multiplicity correction.
    NoEvidence,
    /// Below [`MIN_REPEATS_FOR_VERDICT`] in one arm: no verdict is printed at all.
    InsufficientRepeats,
    /// One arm's percentiles are over a shrunken sample set: no verdict, because the two p50s are
    /// not the same kind of claim. See [`RepeatSample`] and [`judgeable`] — declared by the arm
    /// (`dropped`), or read off the iteration counts when the arm declared nothing.
    SampleLoss,
    /// The metric has no direction — a compositional share, or a name this build does not know.
    /// The delta is printed; a verdict word would be a guess.
    NoDirection,
}

impl Verdict {
    /// The word the table prints.
    ///
    /// The four non-findings must not read like findings — that is the whole rule, and it is why
    /// they are lower case beside the two shouted ones.
    fn label(self) -> &'static str {
        match self {
            Self::Regression => "REGRESSION",
            Self::Improvement => "IMPROVEMENT",
            Self::NoEvidence => "no evidence",
            Self::InsufficientRepeats => "insufficient repeats",
            Self::SampleLoss => "sample loss",
            Self::NoDirection => "no direction",
        }
    }
}

/// THE ONE PREDICATE for "is this row judgeable at all", read by [`verdict`] and [`in_family`].
///
/// `Ok(lower_is_better)` when a p would mean something for this row; `Err(verdict)` naming which
/// precondition it failed. Both callers ask this rather than restating the three checks, because a
/// row the table refuses to call and a row the multiplicity correction spends alpha on must be the
/// same set — two copies of a three-clause conjunction is the shape that has diverged every time it
/// has been written twice in this repo.
///
/// The checks are ordered so that each answers a question the next cannot:
///
/// 1. **The repeat floor**, first and unconditionally: below it no p is even computed, so there is
///    no number a reader could mistake for a finding.
/// 2. **Sample loss.** A dropped measurement iteration contaminates the percentile beside it, and
///    a boot that failed is disproportionately a *slow* boot, so the lossy arm looks faster. A
///    failed *warmup* does not contaminate anything (it never entered the percentile) and is
///    therefore surfaced but not disqualifying — the distinction `Metric` draws, honored here.
///
///    **Two questions, because the first one trusts the arm.** `dropped` is a number the measuring
///    binary chose to report, and the other arm of an A/B is *by construction* an older build:
///    `prepare` refuses an arm that predates `--report json` and nothing more, so an arm from any
///    commit before the emitter's own accounting was fixed reports `dropped = 0` over a truncated
///    sample set (every mode's loop `break`s on a failed boot, and the increment was written on
///    the arms that `continue`). Since both arms ran the same spec with the same arguments, they
///    planned the same number of iterations — so **unequal `samples` is loss, whatever `dropped`
///    says**, and it is the only half of this check that an arm this tree cannot fix still cannot
///    lie about.
/// 3. **No direction**: a compositional share, or a metric this build cannot classify.
fn judgeable(row: &Row) -> Result<bool, Verdict> {
    if row.n_a < MIN_REPEATS_FOR_VERDICT || row.n_b < MIN_REPEATS_FOR_VERDICT {
        return Err(Verdict::InsufficientRepeats);
    }
    if row.dropped_a > 0 || row.dropped_b > 0 || row.samples_a != row.samples_b {
        return Err(Verdict::SampleLoss);
    }
    match row.direction {
        Direction::LowerIsBetter => Ok(true),
        Direction::HigherIsBetter => Ok(false),
        Direction::Neutral => Err(Verdict::NoDirection),
    }
}

/// Decides a row's verdict from the ADJUSTED p.
///
/// Takes the whole [`Row`] rather than eight scalars: the verdict is a function of exactly those
/// fields, and a positional argument list that long is one transposed pair away from calling a
/// regression an improvement.
///
/// The p is the **adjusted** one, not the raw one: with ~20 rows in the default matrix, twenty
/// uncorrected tests at 0.05 produce a phantom verdict 64% of the time under a true null, which for
/// a tool built to stop reporting phantoms was the wrong default.
///
/// Equal medians are `NoEvidence` however small the p — a verdict names a direction, and equal
/// medians name none.
fn verdict(row: &Row) -> Verdict {
    let lower_is_better = match judgeable(row) {
        Ok(lower_is_better) => lower_is_better,
        Err(non_finding) => return non_finding,
    };
    let Some(p) = row.p_adjusted else {
        return Verdict::NoEvidence;
    };
    if p >= SIGNIFICANCE || (row.median_b - row.median_a).abs() < f64::EPSILON {
        return Verdict::NoEvidence;
    }
    if (row.median_b > row.median_a) == lower_is_better {
        Verdict::Regression
    } else {
        Verdict::Improvement
    }
}

/// Whether a row is a member of the multiplicity-corrected **family**.
///
/// The family is exactly the rows [`judgeable`] passes that also produced a p. Rows that cannot be
/// called — below the repeat floor, lossy, or directionless — are deliberately excluded, because
/// correcting for tests nobody interprets spends power on nothing and would silence the rows that
/// *can* be read. The family size is printed beside the table so a reader knows what the
/// adjustment was over.
fn in_family(row: &Row) -> bool {
    judgeable(row).is_ok() && row.p_two_sided.is_some()
}

/// One line of the comparison.
#[derive(Debug, Clone, Serialize)]
struct Row {
    /// [`Spec::id`].
    spec: String,
    /// The metric's stable identifier.
    metric: String,
    /// The unit both arms reported it in.
    unit: Unit,
    /// Repeats that produced a number, arm A.
    n_a: usize,
    /// Repeats that produced a number, arm B.
    n_b: usize,
    /// Iterations behind arm A's repeats — what its p50s are p50s OF.
    samples_a: usize,
    /// Iterations behind arm B's repeats.
    samples_b: usize,
    /// Measurement iterations arm A lost. Non-zero suppresses the verdict; see [`verdict`].
    dropped_a: usize,
    /// Measurement iterations arm B lost.
    dropped_b: usize,
    /// Warmup iterations arm A lost. Surfaced, not disqualifying.
    warmup_failed_a: usize,
    /// Warmup iterations arm B lost.
    warmup_failed_b: usize,
    /// Median of arm A's per-run p50s.
    median_a: f64,
    /// Median of arm B's per-run p50s.
    median_b: f64,
    /// `(median_b - median_a) / median_a`, as a percentage. `None` when arm A's median is zero and
    /// the ratio is undefined — printed as `n/a` rather than as an infinity a reader would believe.
    delta_pct: Option<f64>,
    /// Two-sided p from the tie-corrected rank test, **uncorrected**. Kept in the table and the
    /// JSON beside the adjusted value: the raw p is what a reader re-derives by hand, and hiding
    /// it would make the correction unauditable.
    p_two_sided: Option<f64>,
    /// The Holm-Bonferroni adjusted p over the family. `None` for a row outside the family — see
    /// [`in_family`]. **This is the value the verdict keys off.**
    p_adjusted: Option<f64>,
    /// P(a random arm-B sample > a random arm-A sample) — the effect size.
    prob_b_greater: Option<f64>,
    /// Which way is better for this metric.
    direction: Direction,
    /// Whether [`vmcell_bench::metrics`] actually declared that direction, or it defaulted to
    /// `Neutral` because this build does not know the metric.
    direction_declared: bool,
    /// The conclusion.
    verdict: Verdict,
}

/// Builds every comparable row, Holm-corrects the family, and sorts by adjusted p.
///
/// THREE PASSES, and the middle one is why this is not a `map`: the multiplicity correction is a
/// property of the whole family, so no row's verdict can be decided until every row's raw p exists.
/// Keying the verdict off the raw p — which is what the first version did — makes a twenty-row
/// matrix print a phantom verdict 64% of the time under a true null.
///
/// A key only one arm produced is skipped: it is the *plan's* problem (a mode that self-skipped on
/// one arm), and inventing a comparison out of one side is the shape of defect this tool exists to
/// prevent. The skipped keys come back as the second return value so the caller can say so out
/// loud rather than leave a silently shorter table.
fn build_rows(samples: &Samples, arm_a: &str, arm_b: &str) -> (Vec<Row>, Vec<MetricKey>) {
    let mut rows = Vec::new();
    let mut one_sided = Vec::new();

    // --- Pass 1: every row's numbers, with the RAW p and no verdict yet.
    for (key, series) in samples {
        let (Some(a), Some(b)) = (series.by_arm.get(arm_a), series.by_arm.get(arm_b)) else {
            one_sided.push(key.clone());
            continue;
        };
        let (a, b) = (ArmSeries::of(a), ArmSeries::of(b));
        let (Some(median_a), Some(median_b)) = (median(&a.p50s), median(&b.p50s)) else {
            one_sided.push(key.clone());
            continue;
        };
        // Below the floor the rank test is not even asked: see `MIN_REPEATS_FOR_VERDICT` for why a
        // p from three repeats is a statement about the sample size.
        let test: Option<RankTest> =
            if a.p50s.len() >= MIN_REPEATS_FOR_VERDICT && b.p50s.len() >= MIN_REPEATS_FOR_VERDICT {
                mann_whitney(&a.p50s, &b.p50s)
            } else {
                None
            };
        let (direction, direction_declared) = metric_direction(&key.metric);
        let delta_pct = if median_a.abs() < f64::EPSILON {
            None
        } else {
            Some((median_b - median_a) / median_a * 100.0)
        };
        rows.push(Row {
            spec: key.spec.clone(),
            metric: key.metric.clone(),
            unit: series.unit,
            n_a: a.p50s.len(),
            n_b: b.p50s.len(),
            samples_a: a.samples,
            samples_b: b.samples,
            dropped_a: a.dropped,
            dropped_b: b.dropped,
            warmup_failed_a: a.warmup_failed,
            warmup_failed_b: b.warmup_failed,
            median_a,
            median_b,
            delta_pct,
            p_two_sided: test.as_ref().map(|t| t.p_two_sided),
            // Filled in by pass 2, which needs every row's raw p first.
            p_adjusted: None,
            prob_b_greater: test.as_ref().map(|t| t.prob_b_greater),
            direction,
            direction_declared,
            verdict: Verdict::NoEvidence,
        });
    }

    // --- Pass 2: the family, and the Holm-Bonferroni correction over it.
    // The row index and its raw p are collected as ONE pair, and the adjusted values are zipped
    // back onto those pairs. Collecting the indices and the p-values as two vectors and then
    // matching them BY POSITION — which is what this did — is a silent misassignment waiting for
    // the day the two filters stop agreeing: `in_family` happens to require a `Some` p today, so
    // the p vector cannot come back shorter, and if it ever did, every row after the gap would be
    // handed a different row's adjusted p. There is no symptom for that but a wrong verdict, so
    // the shape is removed rather than commented.
    let family: Vec<(usize, f64)> = rows
        .iter()
        .enumerate()
        .filter(|(_, row)| in_family(row))
        .filter_map(|(index, row)| row.p_two_sided.map(|p| (index, p)))
        .collect();
    let raw: Vec<f64> = family.iter().map(|(_, p)| *p).collect();
    let adjusted = holm_bonferroni(&raw);
    for ((index, _), p) in family.iter().zip(&adjusted) {
        if let Some(row) = rows.get_mut(*index) {
            row.p_adjusted = Some(*p);
        }
    }

    // --- Pass 3: the verdicts, off the adjusted p.
    for row in &mut rows {
        let decided = verdict(row);
        row.verdict = decided;
    }

    // Sorted so the strongest findings are the first thing read, in three tiers: rows that got an
    // adjusted p, then rows with only a raw p (directionless or lossy — real numbers, no verdict),
    // then the unranked. A row with no p sorts last rather than at either extreme, where it would
    // look like a result. `total_cmp` keeps a NaN from scrambling the order.
    rows.sort_by(|x, y| {
        let tier = |row: &Row| -> u8 {
            match (row.p_adjusted, row.p_two_sided) {
                (Some(_), _) => 0,
                (None, Some(_)) => 1,
                (None, None) => 2,
            }
        };
        tier(x).cmp(&tier(y)).then_with(|| {
            match (
                x.p_adjusted.or(x.p_two_sided),
                y.p_adjusted.or(y.p_two_sided),
            ) {
                (Some(a), Some(b)) => a.total_cmp(&b).then_with(|| x.metric.cmp(&y.metric)),
                _ => x.metric.cmp(&y.metric),
            }
        })
    });
    (rows, one_sided)
}

/// The whole comparison, as `--format json` emits it.
#[derive(Debug, Serialize)]
struct Comparison {
    /// Arm A's label — the baseline the deltas are relative to.
    arm_a: String,
    /// Arm B's label.
    arm_b: String,
    /// Repeats per (arm, spec).
    repeats: usize,
    /// Every spec that ran, by [`Spec::id`].
    specs: Vec<String>,
    /// How many rows the Holm-Bonferroni correction was computed over — see [`in_family`]. A
    /// reader cannot check an adjusted p without it.
    family_size: usize,
    /// Loud notes that did not stop the run (a shared rootfs digest, an undeclared metric, a note
    /// one arm reported and the other did not).
    warnings: Vec<String>,
    /// Each arm's own notes, deduplicated and sorted — the self-skips and honesty caveats its runs
    /// recorded. `bench-vm` has always emitted these and nothing read them, which is how a
    /// `cpufreq: NOT pinned` on one side of a comparison stayed invisible.
    notes_by_arm: BTreeMap<String, Vec<String>>,
    /// Keys exactly one arm produced, as `<spec> / <metric>`: measured on one side, so not
    /// compared at all.
    ///
    /// WHY IN THE DOCUMENT AND NOT ONLY ON stderr. [`build_rows`] returns these, in its own words,
    /// "so the caller can say so out loud rather than leave a silently shorter table" — and the
    /// caller said it with `progress!`, which writes to stderr, which
    /// `bench-ab run --format json > out.json` discards. A mode that self-skipped on one arm then
    /// vanished from the artifact entirely: the table is shorter, nothing in it says why, and the
    /// rows that remain read as the whole comparison.
    not_compared: Vec<String>,
    /// The rows, sorted by adjusted p.
    rows: Vec<Row>,
}

/// The `better` cell: which way is better for this row's metric.
///
/// WHY THE TABLE SAYS IT PER ROW. The verdict word was the only place direction reached the
/// reader, and it is absent for exactly the rows that need it most: `no evidence`, `sample loss`
/// and `insufficient repeats` all print a signed `delta%` and no verdict, and every other row in
/// the table is a latency. `-30.0` on `footprint_guest_mem_available` reads as a 30% win to anyone
/// scanning the column, and it is a 30% loss — the same misreading the one-line direction rule
/// used to make on the reader's behalf.
///
/// `?` (this build cannot classify the name) is deliberately not the same cell as `none` (a
/// compositional share, which HAS no direction): one is a hole in this tree's roster, the other is
/// a fact about the quantity. The warnings list names the first.
fn render_direction(row: &Row) -> &'static str {
    if !row.direction_declared {
        return "?";
    }
    match row.direction {
        Direction::LowerIsBetter => "lower",
        Direction::HigherIsBetter => "higher",
        Direction::Neutral => "none",
    }
}

/// The width of a padded column: the widest cell it must hold, never narrower than its header.
///
/// WHY DERIVED AND NOT A CONSTANT. `{:<N}` pads but never truncates, so one cell wider than `N`
/// shifts every column after it and the table stops being readable exactly at the interesting row.
/// The widths were 30 and 34, the second justified by a comment naming
/// `footprint_ksm_pages_sharing_delta` (33 characters) as the roster's longest entry — a fact
/// about a roster, quoted in a comment, with nothing to keep it true as the roster grows. The
/// spec column's 30 was already wrong by construction: [`Spec::id`] appends the extra arguments
/// precisely so two runs of one mode are two measurements, so
/// `cloud-hypervisor/latency [--mem-mib 4096]` is 41 characters and any operator could produce it.
fn column_width(header: &str, cells: impl Iterator<Item = usize>) -> usize {
    cells.fold(header.chars().count(), usize::max)
}

/// Renders the human table.
///
/// The four non-finding verdicts print their medians but NO verdict word, and each for its own
/// reason: `insufficient repeats` (two anecdotes), `sample loss` (two p50s that are not the same
/// kind of claim), `no direction` (a share of a whole, or a metric this build cannot classify).
/// Printing a verdict beside any of them is the single-p50 mistake this harness was built to
/// retire, one class out.
fn render_table(cmp: &Comparison) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "=== A/B: {} (A) vs {} (B), repeats={} ===\n",
        cmp.arm_a, cmp.arm_b, cmp.repeats
    ));
    out.push_str(&format!(
        "delta is B relative to A, whichever way is better for the metric (the `better` column); \
         a verdict needs both arms at >= {MIN_REPEATS_FOR_VERDICT} repeats, equal iteration \
         counts with zero dropped, a declared direction, and p_adj < {SIGNIFICANCE}.\n"
    ));
    out.push_str(&format!(
        "p_adj is Holm-Bonferroni over the {} row(s) that could receive a verdict; p is the raw \
         uncorrected two-sided value.\n",
        cmp.family_size
    ));
    for w in &cmp.warnings {
        out.push_str(&format!("WARNING: {w}\n"));
    }
    // Both widths come from the cells they have to hold — see `column_width` for the two ways the
    // constants they replaced were already wrong.
    let spec_w = column_width("spec", cmp.rows.iter().map(|r| r.spec.chars().count()));
    let metric_w = column_width("metric", cmp.rows.iter().map(|r| r.metric.chars().count()));
    let loss_w = column_width(
        "loss",
        cmp.rows.iter().map(|r| render_loss(r).chars().count()),
    );
    out.push_str(&format!(
        "{:<spec_w$} {:<metric_w$} {:>6} {:>5} {:>11} {:>11} {:>8} {:>8} {:>8} {:>7} {:>loss_w$}  {}\n",
        "spec",
        "metric",
        "better",
        "n",
        "median A",
        "median B",
        "delta%",
        "p",
        "p_adj",
        "P(B>A)",
        "loss",
        "verdict"
    ));
    for row in &cmp.rows {
        let n = if row.n_a == row.n_b {
            row.n_a.to_string()
        } else {
            format!("{}/{}", row.n_a, row.n_b)
        };
        let delta = row
            .delta_pct
            .map_or_else(|| "n/a".to_string(), |d| format!("{d:+.1}"));
        let p = row
            .p_two_sided
            .map_or_else(|| "-".to_string(), |p| format!("{p:.4}"));
        let p_adj = row
            .p_adjusted
            .map_or_else(|| "-".to_string(), |p| format!("{p:.4}"));
        let effect = row
            .prob_b_greater
            .map_or_else(|| "-".to_string(), |e| format!("{e:.2}"));
        out.push_str(&format!(
            "{:<spec_w$} {:<metric_w$} {:>6} {:>5} {:>11.2} {:>11.2} {:>8} {:>8} {:>8} {:>7} {:>loss_w$}  {}\n",
            row.spec,
            row.metric,
            render_direction(row),
            n,
            row.median_a,
            row.median_b,
            delta,
            p,
            p_adj,
            effect,
            render_loss(row),
            row.verdict.label()
        ));
    }
    if cmp.rows.is_empty() {
        out.push_str("(no metric was produced by both arms — nothing to compare)\n");
    }
    // The rows that are NOT here, named. A shorter table with no explanation reads as a complete
    // comparison of a smaller matrix.
    if !cmp.not_compared.is_empty() {
        out.push_str(&format!(
            "not compared ({} measured by one arm only):\n",
            cmp.not_compared.len()
        ));
        for key in &cmp.not_compared {
            out.push_str(&format!("  {key}\n"));
        }
    }
    for (arm, notes) in &cmp.notes_by_arm {
        out.push_str(&format!("notes [{arm}]:\n"));
        if notes.is_empty() {
            out.push_str("  (none)\n");
        }
        for note in notes {
            out.push_str(&format!("  {note}\n"));
        }
    }
    out
}

/// The `loss` cell: iteration counts when they disagree, dropped measurement iterations, then
/// failed warmups, per arm.
///
/// `-` when nothing was lost, so the column is silent on a clean matrix and impossible to miss on
/// a contaminated one. The three prefixes mean three different things — `i` is the two arms'
/// surviving ITERATION counts, which disagree only when one arm measured less work than the other
/// (see [`judgeable`] for why that is read separately from `d`, and why it is the half an old arm
/// cannot misreport); `d` is a dropped iteration, which contaminates the percentile beside it and
/// suppresses the verdict; `w` is a failed warmup, which never entered the percentile and does
/// not. `i` and not `n`, because the table's `n` column is already the REPEAT count and one letter
/// must not mean two things in one row.
fn render_loss(row: &Row) -> String {
    let mut out = String::new();
    if row.samples_a != row.samples_b {
        out.push_str(&format!("i{}/{}", row.samples_a, row.samples_b));
    }
    if row.dropped_a > 0 || row.dropped_b > 0 {
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(&format!("d{}/{}", row.dropped_a, row.dropped_b));
    }
    if row.warmup_failed_a > 0 || row.warmup_failed_b > 0 {
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(&format!("w{}/{}", row.warmup_failed_a, row.warmup_failed_b));
    }
    if out.is_empty() { "-".to_string() } else { out }
}

// ----------------------------------------------------------------------------
// `prepare`
// ----------------------------------------------------------------------------

/// Runs one build/step command, inheriting stdio, and fails loud with the argv on a non-zero exit.
///
/// The argv is printed first so a failed `prepare` can be re-run by hand — a build failure inside a
/// worktree of a two-year-old tag is the expected failure here, and the operator needs the command.
///
/// # Errors
/// Returns an error when the command cannot be spawned or exits non-zero.
fn run_step(what: &str, cmd: &mut ProcCommand) -> anyhow::Result<()> {
    progress!("+ {what}: {cmd:?}");
    let status = cmd
        .status()
        .map_err(|e| anyhow::anyhow!("{what}: cannot spawn {cmd:?}: {e}"))?;
    if !status.success() {
        anyhow::bail!("{what}: {cmd:?} exited with {status}");
    }
    Ok(())
}

/// Stages one built binary into the arm's directory, preserving its mode.
///
/// # Errors
/// Returns an error when the source is missing (the build did not produce it) or the copy fails.
fn stage_binary(src: &Path, dst_dir: &Path, name: &str) -> anyhow::Result<PathBuf> {
    let dst = dst_dir.join(name);
    if !src.exists() {
        anyhow::bail!(
            "{name} was not built at {} — the arm's `cargo build --release` reported success but \
             produced no binary; check the --features list this ref accepts",
            src.display()
        );
    }
    std::fs::copy(src, &dst)
        .map_err(|e| anyhow::anyhow!("cannot stage {} to {}: {e}", src.display(), dst.display()))?;
    Ok(dst)
}

/// How `prepare` executes a build step.
///
/// A seam, because the three things worth a gate in `prepare` are all *argv and sequence* facts —
/// that every arm build is `--locked`, that the staged binary is probed before the expensive
/// artifact build, that the worktree is at the ref that was asked for — and every one of them was
/// previously only observable by running a full release build and a rootfs build in a builder
/// micro-VM. The git steps are NOT behind this seam: a fake git would prove nothing about a
/// worktree, so the tests drive real `git` in a throwaway repository.
type StepRunner<'a> = &'a mut dyn FnMut(&str, &mut ProcCommand) -> anyhow::Result<()>;

/// Runs `git <args>` in `dir` and returns its trimmed stdout.
///
/// # Errors
/// Returns an error when git cannot be spawned, exits non-zero (with its stderr, which is where
/// `unknown revision` lands), or writes non-UTF-8.
fn git_capture(dir: &Path, args: &[&str]) -> anyhow::Result<String> {
    let out = ProcCommand::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .output()
        .map_err(|e| anyhow::anyhow!("cannot spawn git {args:?} in {}: {e}", dir.display()))?;
    if !out.status.success() {
        anyhow::bail!(
            "git {args:?} in {} exited with {}: {}",
            dir.display(),
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// Puts `worktree` at `git_ref`'s commit and returns **the commit it is verified to be at**.
///
/// WHY RESOLVE BOTH SIDES. `prepare` reused an existing `<worktree>/.git` on the reasonable ground
/// that re-checking out a tag is minutes of rebuild for nothing — but it reused it without asking
/// WHERE it was, and then recorded `git_ref` from its own ARGUMENT. Re-preparing a label at a new
/// ref therefore rebuilt the old tree, measured it, and filed the numbers under the new ref's name:
/// a whole arm silently attributed to code it did not contain. A ref is also a moving name, so even
/// an untouched worktree can drift out from under one (`--git-ref main`, a week later).
///
/// The reuse optimization survives — a worktree already at the resolved commit skips the checkout —
/// but it is now conditional on the answer rather than on the directory existing. The returned sha
/// is read back from the worktree AFTER any checkout, so it is what the arm was built from and not
/// what it was asked for; that is what lands in [`ArmManifest::git_commit`].
///
/// # Errors
/// Returns an error when the ref does not resolve, when the checkout fails (a dirty worktree is
/// git's refusal, and it is the right one), or when the worktree is still not at the wanted commit
/// afterwards.
fn ensure_worktree_at(head: &Path, worktree: &Path, git_ref: &str) -> anyhow::Result<String> {
    let wanted =
        git_capture(head, &["rev-parse", &format!("{git_ref}^{{commit}}")]).map_err(|e| {
            anyhow::anyhow!(
                "--git-ref {git_ref} does not resolve to a commit in {}: {e}",
                head.display()
            )
        })?;
    if worktree.join(".git").exists() {
        let at = git_capture(worktree, &["rev-parse", "HEAD"])?;
        if at == wanted {
            progress!(
                "reusing worktree {} (already at {git_ref} = {})",
                worktree.display(),
                short_sha(&at)
            );
        } else {
            progress!(
                "worktree {} is at {} but --git-ref {git_ref} is {}: re-checking out",
                worktree.display(),
                short_sha(&at),
                short_sha(&wanted)
            );
            run_step(
                "git checkout --detach",
                ProcCommand::new("git")
                    .arg("-C")
                    .arg(worktree)
                    .arg("checkout")
                    .arg("--detach")
                    .arg(&wanted),
            )?;
        }
    } else {
        std::fs::create_dir_all(worktree.parent().unwrap_or(worktree))
            .map_err(|e| anyhow::anyhow!("cannot create {}: {e}", worktree.display()))?;
        // The RESOLVED sha, not the ref: `git worktree add <path> <ref>` would create a branch for
        // some ref shapes, and this arm must be a detached, immovable commit.
        run_step(
            "git worktree add",
            ProcCommand::new("git")
                .arg("-C")
                .arg(head)
                .arg("worktree")
                .arg("add")
                .arg("--detach")
                .arg(worktree)
                .arg(&wanted),
        )?;
    }
    // The postcondition, read back rather than assumed: this value is what the manifest records.
    let at = git_capture(worktree, &["rev-parse", "HEAD"])?;
    if at != wanted {
        anyhow::bail!(
            "worktree {} is at {at}, but --git-ref {git_ref} resolves to {wanted}. Building here \
             would measure one tree and report it under the other ref's name. THE FIX: \
             `git -C {} checkout --detach {wanted}`, or `git worktree remove {}` and re-run \
             prepare for a clean checkout.",
            worktree.display(),
            worktree.display(),
            worktree.display()
        );
    }
    Ok(at)
}

/// The first 12 characters of a sha, for messages. Falls back to the whole string so a malformed
/// one is shown rather than swallowed.
fn short_sha(sha: &str) -> &str {
    sha.get(..12).unwrap_or(sha)
}

/// What [`probe_reports_json`] looks for in the staged binary's `--help`.
const REPORT_FLAG_NEEDLE: &str = "--report";

/// Whether a `bench-vm --help` dump advertises the flag this harness needs.
///
/// Pure, so both answers are testable without a binary; the call site is gated by a `prepare` test
/// that stages a fake `bench-vm` printing each kind of help.
fn help_advertises_report_flag(help: &str) -> bool {
    help.contains(REPORT_FLAG_NEEDLE)
}

/// Refuses, at `prepare` time, an arm whose `bench-vm` predates `--report json`.
///
/// WHY HERE AND NOT AT THE FIRST CHILD. Without this the refusal still happens — `run_child`'s
/// `BenchReport::from_json` fails on the human table — but it happens after a full release build of
/// three crates AND an artifact build that boots a builder micro-VM, and then again for the arm's
/// twin. `--help` needs no KVM, no artifacts and no privileges, and the staged binary exists as
/// soon as it is staged, so the constraint is checked at the earliest point it CAN be, which is
/// also before the expensive half of `prepare`.
///
/// # Errors
/// Returns an error when the staged binary cannot be executed at all, or when its help does not
/// advertise [`REPORT_FLAG_NEEDLE`].
fn probe_reports_json(bench_vm: &Path, label: &str, git_ref: &str) -> anyhow::Result<()> {
    let out = ProcCommand::new(bench_vm)
        .arg("--help")
        .output()
        .map_err(|e| anyhow::anyhow!("cannot run {} --help: {e}", bench_vm.display()))?;
    let mut help = String::from_utf8_lossy(&out.stdout).into_owned();
    help.push_str(&String::from_utf8_lossy(&out.stderr));
    if help_advertises_report_flag(&help) {
        return Ok(());
    }
    anyhow::bail!(
        "arm `{label}` ({git_ref}) built a `bench-vm` with no `{REPORT_FLAG_NEEDLE}` flag: {} \
         --help does not advertise it. This harness parses each child's stdout as one JSON \
         BenchReport, so such an arm cannot be compared at all — it would fail at the first child, \
         after this build and an artifact build that boots a builder micro-VM. THE CONSTRAINT: \
         both refs must carry `bench-vm --report json`, which landed with this harness; comparing \
         against anything older means backporting the flag onto a branch off that ref and \
         preparing THAT.",
        bench_vm.display()
    )
}

/// `bench-ab prepare`.
///
/// # Errors
/// Returns an error at the first step that fails: the worktree checkout, either build, the
/// staging copies, the `--report json` probe, the arm's artifact build, the control kernel copy, or
/// the manifest write.
fn cmd_prepare(
    head: &Path,
    git_ref: &str,
    label: &str,
    features: Option<&str>,
    control_kernel: Option<PathBuf>,
    run: StepRunner<'_>,
) -> anyhow::Result<()> {
    // 1. The worktree, AT the requested ref — reused only when it is already there, which is not
    //    the same as "the directory exists". See `ensure_worktree_at`.
    let worktree = head.join(WORKTREES_DIR_REL).join(label);
    let git_commit = ensure_worktree_at(head, &worktree, git_ref)?;

    // 2. Build the arm's harness, its daemon and its CLI. Three separate invocations rather than
    //    one `-p a -p b -p c --features …`: cargo refuses a bare `--features` across several
    //    packages, and the feature list belongs to `vmcell-bench` alone.
    //
    //    `--locked` on every one of them (AGENTS.md, Docs and dependencies). An arm is a git ref
    //    plus its committed `Cargo.lock`; without the flag cargo silently re-resolves the lock in
    //    the worktree, so the arm measured is not the arm named — and an old ref re-resolved onto
    //    today's dependency versions is exactly the "same code, different numbers" confound this
    //    tool exists to eliminate.
    let mut bench_build = ProcCommand::new("cargo");
    bench_build
        .current_dir(&worktree)
        .arg("build")
        .arg("--locked")
        .arg("--release")
        .arg("-p")
        .arg("vmcell-bench");
    if let Some(features) = features {
        bench_build.arg("--features").arg(features);
    }
    run("build the arm's bench-vm", &mut bench_build)?;
    run(
        "build the arm's vmcelld",
        ProcCommand::new("cargo")
            .current_dir(&worktree)
            .arg("build")
            .arg("--locked")
            .arg("--release")
            .arg("-p")
            .arg("vmcelld"),
    )?;
    run(
        "build the arm's CLI (it builds the arm's own rootfs)",
        ProcCommand::new("cargo")
            .current_dir(&worktree)
            .arg("build")
            .arg("--locked")
            .arg("--release")
            .arg("-p")
            .arg("vmcell-cli"),
    )?;

    // 3. Stage the pair. See ARMS_DIR_REL for the two facts that decide this location.
    let arm_dir = head.join(ARMS_DIR_REL).join(label);
    std::fs::create_dir_all(&arm_dir)
        .map_err(|e| anyhow::anyhow!("cannot create {}: {e}", arm_dir.display()))?;
    let release = worktree.join("target/release");
    let bench_vm = stage_binary(&release.join("bench-vm"), &arm_dir, "bench-vm")?;
    let vmcelld = stage_binary(&release.join("vmcelld"), &arm_dir, "vmcelld")?;

    // …and refuse an unusable arm HERE, before the artifact build below boots a builder micro-VM.
    probe_reports_json(&bench_vm, label, git_ref)?;

    // 4. The arm's own artifacts, built by the arm's own CLI — a rootfs built by HEAD's pipeline
    //    would make every guest-side delta a comparison of one tree against itself.
    let artifacts_dir = worktree.join("target/vmcell-artifacts");
    run(
        "build the arm's artifacts",
        ProcCommand::new(release.join("vmcell"))
            .current_dir(&worktree)
            .env("VMCELL_ARTIFACTS_DIR", &artifacts_dir)
            .arg("build"),
    )?;

    // …and then THE CONTROL, which is a file copy and not an environment variable. `bench-vm`
    // binaries built before `$VMCELL_KERNEL` existed compose `<artifacts_dir>/vmlinux` themselves
    // and never read the environment, so an exported override reaches the new arm and not the old
    // one — which is how a whole matrix booted 6.12.94 against 6.12.104 while the driver reported
    // one kernel. The bytes are put where every arm, old and new, will look.
    let control_kernel = control_kernel.unwrap_or_else(vmcell::artifact::kernel_path);
    if !control_kernel.exists() {
        anyhow::bail!(
            "the control kernel {} does not exist — build it first (`vmcell build --kernel-source \
             host-make`) or name another with --kernel. Every arm must boot THIS file.",
            control_kernel.display()
        );
    }
    let arm_kernel = artifacts_dir.join("vmlinux");
    std::fs::copy(&control_kernel, &arm_kernel).map_err(|e| {
        anyhow::anyhow!(
            "cannot copy the control kernel {} to {}: {e}",
            control_kernel.display(),
            arm_kernel.display()
        )
    })?;
    progress!(
        "control kernel: copied {} -> {}",
        control_kernel.display(),
        arm_kernel.display()
    );

    // 5. Pin everything by content. A path is what the 2026-08-21 pass trusted.
    let manifest = ArmManifest {
        label: label.to_string(),
        git_ref: Some(git_ref.to_string()),
        // The RESOLVED commit, read back out of the worktree — not the argument, which is a
        // request and was recorded as if it were a fact.
        git_commit: Some(git_commit),
        bench_vm: DigestedFile::digest(bench_vm)?,
        vmcelld: Some(DigestedFile::digest(vmcelld)?),
        artifacts_dir: artifacts_dir.clone(),
        kernel: DigestedFile::digest(arm_kernel)?,
        rootfs: DigestedFile::digest(artifacts_dir.join("rootfs.erofs"))?,
    };
    let manifest_path = arm_dir.join(MANIFEST_NAME);
    manifest.save(&manifest_path)?;
    progress!("wrote {}", manifest_path.display());
    Ok(())
}

// ----------------------------------------------------------------------------
// `run`
// ----------------------------------------------------------------------------

/// Spawns one child and parses its report.
///
/// stderr is INHERITED so the child's own narration (its self-skips, its retries, its cpufreq
/// verdict) reaches the operator live; stdout is captured because in `--report json` it is the
/// report and nothing else.
///
/// # Errors
/// Returns an error when the child cannot be spawned, exits non-zero, or did not print a report of
/// this build's schema.
fn run_child(
    plan: &WrapPlan,
    arm: &ArmManifest,
    spec: &Spec,
    repeat: usize,
) -> anyhow::Result<BenchReport> {
    let argv = child_argv(plan, &arm.bench_vm.path, spec);
    progress!(
        "[{}] repeat {repeat} {}: {}",
        arm.label,
        spec.id(),
        render_argv(&argv)
    );
    // Argv and environment are composed by the two composers and NOWHERE else: naming the arm's
    // artifacts dir is not the proof (`guard_booted_artifacts` is), but sealing the environment
    // is what makes that guard's answer the right one instead of an accident of the shell.
    let output = child_command(arm, &argv)?
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit())
        .output()
        .map_err(|e| {
            anyhow::anyhow!(
                "arm `{}` {}: cannot spawn {}: {e}",
                arm.label,
                spec.id(),
                render_argv(&argv)
            )
        })?;
    if !output.status.success() {
        anyhow::bail!(
            "arm `{}` {} repeat {repeat} exited with {} — its diagnosis is on stderr above. A \
             failed run's partial metrics are deliberately not emitted, so there is nothing to \
             pool; fix the run rather than comparing what survived.",
            arm.label,
            spec.id(),
            output.status
        );
    }
    let stdout = String::from_utf8(output.stdout).map_err(|e| {
        anyhow::anyhow!(
            "arm `{}` {}: report is not UTF-8: {e}",
            arm.label,
            spec.id()
        )
    })?;
    BenchReport::from_json(&stdout).map_err(|e| {
        anyhow::anyhow!(
            "arm `{}` {}: {e}. An arm whose `bench-vm` predates `--report json` fails here rather \
             than being scraped — rebuild that arm from a ref that has it.",
            arm.label,
            spec.id()
        )
    })
}

/// A child argv as a copy-pasteable line.
fn render_argv(argv: &[OsString]) -> String {
    argv.iter()
        .map(|a| a.to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join(" ")
}

/// Loads an arm's manifest from its staging directory.
///
/// # Errors
/// Returns an error naming the missing manifest and the verb that writes it.
fn load_arm(head: &Path, label: &str) -> anyhow::Result<ArmManifest> {
    let path = head.join(ARMS_DIR_REL).join(label).join(MANIFEST_NAME);
    if !path.exists() {
        anyhow::bail!(
            "no manifest at {} — run `bench-ab prepare --git-ref <ref> --label {label}` first",
            path.display()
        );
    }
    Ok(ArmManifest::load(&path)?)
}

/// EVERY control that can be answered before a VM boots, in one seam-taking function.
///
/// WHY A FUNCTION AND NOT THREE LINES IN [`cmd_run`]. A guard with a red-on-inverse test proves the
/// predicate; it proves nothing about whether anybody calls it. Deleting `guard_same_kernel(&arms)?`
/// from an inline `run` body left the entire suite green — the exact "a green unit test beside an
/// unchanged call site" shape AGENTS.md names, and the reason this and [`execute_plan`] exist as
/// arguments-in/values-out helpers a test can drive.
///
/// Returns the loud-but-not-fatal notes, already printed. [`guard_distinct_rootfs`] is the one
/// guard that warns instead of refusing — two arms sharing a rootfs digest is entirely legitimate
/// when only host code changed — and its `#[must_use]` plus this crate's fail-loud lint make
/// dropping the notes a compile error.
///
/// # Errors
/// Returns an error when the arms do not share a guest kernel, or when an arm's staged binaries no
/// longer digest to what its manifest recorded.
fn run_preflight(arms: &[ArmManifest]) -> anyhow::Result<Vec<String>> {
    // A violated control produces confident wrong numbers, which is worse than no numbers, so each
    // of these refuses the run rather than annotating it.
    guard_same_kernel(arms)?;
    for arm in arms {
        guard_binaries_unchanged(arm)?;
    }
    let warnings: Vec<String> = guard_distinct_rootfs(arms)
        .iter()
        .map(ToString::to_string)
        .collect();
    for w in &warnings {
        progress!("WARNING: {w}");
    }
    Ok(warnings)
}

/// The interleaved run loop, with the child spawn INJECTED.
///
/// The seam is what makes the per-child re-digest testable at all: a fake spawn can swap a staged
/// binary between two cells — which is what a concurrent `cargo build --release` did on 2026-08-21,
/// mid-matrix, with `git status` clean throughout — and assert that the NEXT child is refused. With
/// the spawn hard-wired, the only way to exercise that call site is to boot thirty VMs.
///
/// # Errors
/// Returns an error when a scheduled arm has no manifest, when an arm's binaries changed under the
/// run, or when a child fails.
fn execute_plan<S>(
    plan_runs: &[Run],
    arms: &[ArmManifest],
    spawn: &mut S,
) -> anyhow::Result<Vec<(String, Spec, BenchReport)>>
where
    S: FnMut(&ArmManifest, &Spec, usize) -> anyhow::Result<BenchReport>,
{
    let by_label: BTreeMap<&str, &ArmManifest> =
        arms.iter().map(|a| (a.label.as_str(), a)).collect();
    let mut runs: Vec<(String, Spec, BenchReport)> = Vec::with_capacity(plan_runs.len());
    for scheduled in plan_runs {
        let arm = by_label
            .get(scheduled.arm.as_str())
            .ok_or_else(|| anyhow::anyhow!("planned an arm with no manifest: {}", scheduled.arm))?;
        // Re-checked before EVERY child, not once at start-up: the swap that motivated this landed
        // during a matrix, between two of its cells.
        guard_binaries_unchanged(arm)?;
        let report = spawn(arm, &scheduled.spec, scheduled.repeat)?;
        runs.push((scheduled.arm.clone(), scheduled.spec.clone(), report));
    }
    Ok(runs)
}

/// The whole comparison — controls, plan, loop, post-run controls, rows — with the child spawn
/// injected, so every one of those call sites can be driven by a test that boots nothing.
///
/// The arm labels come from the manifests rather than from a parallel argument: a label list that
/// could disagree with the arms it names is a second source of truth for "which arms are we
/// comparing", and this harness exists because two sources of truth disagreed silently.
///
/// # Errors
/// Returns an error when fewer than two arms are given, when any control refuses, when a child
/// fails, or when the arms' reports cannot be pooled (a metric that changed units).
fn run_comparison<S>(
    arms: &[ArmManifest],
    specs: &[Spec],
    repeats: usize,
    spawn: &mut S,
) -> anyhow::Result<Comparison>
where
    S: FnMut(&ArmManifest, &Spec, usize) -> anyhow::Result<BenchReport>,
{
    let labels: Vec<String> = arms.iter().map(|arm| arm.label.clone()).collect();
    let (arm_a, arm_b) = labels
        .split_first()
        .and_then(|(a, rest)| rest.first().map(|b| (a.clone(), b.clone())))
        .ok_or_else(|| {
            anyhow::anyhow!(
                "an A/B needs two arms (the rank test compares two samples); got {}",
                labels.len()
            )
        })?;

    let warnings = run_preflight(arms)?;

    let plan_runs: Vec<Run> = interleave(&labels, specs, repeats);
    if plan_runs.is_empty() {
        anyhow::bail!("nothing to run: --spec selected no cells");
    }
    progress!(
        "plan: {} runs ({} arms x {} specs x {repeats} repeats), interleaved",
        plan_runs.len(),
        labels.len(),
        specs.len()
    );
    let runs = execute_plan(&plan_runs, arms, spawn)?;

    // --- The post-run controls: only the emitted reports can answer these two.
    // --- What each child actually OPENED — a `$VMCELL_KERNEL`/`$VMCELL_ROOTFS` inherited from the
    // --- operator's shell redirects it ahead of the artifacts dir, and no prepare-time digest can
    // --- see that.
    guard_booted_artifacts(
        arms,
        runs.iter()
            .map(|(label, _, report)| (label.as_str(), report)),
    )?;
    // --- ...and which VMM binary it executed: an arm that predates `$VMCELL_*_BIN` hardcodes the
    // --- name and finds whatever is first on PATH.
    guard_vmm_binaries(
        runs.iter()
            .map(|(label, _, report)| (label.as_str(), report)),
    )?;

    let samples = collect_samples(&runs)?;
    let (rows, one_sided) = build_rows(&samples, &arm_a, &arm_b);
    let not_compared: Vec<String> = one_sided
        .iter()
        .map(|key| format!("{} / {}", key.spec, key.metric))
        .collect();
    for key in &not_compared {
        progress!("note: {key} was produced by only one arm; not compared");
    }

    // The children's own notes. `BenchReport::notes` carries every self-skip and honesty caveat a
    // run recorded — `cpufreq: NOT pinned`, `Cold Boot (WARM-CACHE: …)`, a capability refusal —
    // and NOTHING read them: the field was emitted, carried across the process boundary, and
    // dropped here. An arm that could not pin its CPUs compared against one that could is two
    // noise floors, and the artifact said so the whole time.
    let notes_by_arm = collect_notes(&runs);
    let mut late = note_asymmetry_warnings(&notes_by_arm, &arm_a, &arm_b);
    // …and the metrics whose direction this build cannot declare, once per NAME rather than once
    // per row: a spec whose twenty metrics are all unknown would otherwise bury the table.
    let mut undeclared: Vec<&str> = rows
        .iter()
        .filter(|row| !row.direction_declared)
        .map(|row| row.metric.as_str())
        .collect();
    undeclared.sort_unstable();
    undeclared.dedup();
    late.extend(undeclared.into_iter().map(undeclared_metric_warning));
    // Only the LATE warnings are printed here: `run_preflight` already printed its own, before
    // the first VM booted, which is the whole point of a control that runs early.
    for w in &late {
        progress!("WARNING: {w}");
    }
    let mut warnings = warnings;
    warnings.extend(late);

    let family_size = rows.iter().filter(|row| row.p_adjusted.is_some()).count();
    Ok(Comparison {
        arm_a,
        arm_b,
        repeats,
        specs: specs.iter().map(Spec::id).collect(),
        family_size,
        warnings,
        notes_by_arm,
        not_compared,
        rows,
    })
}

/// Each arm's notes, deduplicated and sorted, with an entry for **every** arm that ran.
///
/// An arm with nothing to say gets an empty vector rather than no key: "this arm reported no
/// caveats" and "nobody looked" must not render the same way, and the empty entry is what makes
/// the asymmetry below computable from the map alone.
fn collect_notes(runs: &[(String, Spec, BenchReport)]) -> BTreeMap<String, Vec<String>> {
    let mut out: BTreeMap<String, std::collections::BTreeSet<String>> = BTreeMap::new();
    for (arm, _, report) in runs {
        let entry = out.entry(arm.clone()).or_default();
        for note in &report.notes {
            entry.insert(note.clone());
        }
    }
    out.into_iter()
        .map(|(arm, notes)| (arm, notes.into_iter().collect()))
        .collect()
}

/// One warning per note that exactly one of the two compared arms reported.
///
/// Both directions, in one pass over the union: a note only arm B carries is as loud as one only
/// arm A carries. A note both arms carry is the *symmetric* case and says nothing about the
/// comparison — both matrices were shortened the same way — so it stays in the per-arm listing
/// without a warning.
fn note_asymmetry_warnings(
    notes_by_arm: &BTreeMap<String, Vec<String>>,
    arm_a: &str,
    arm_b: &str,
) -> Vec<String> {
    let side = |label: &str| -> std::collections::BTreeSet<&str> {
        notes_by_arm
            .get(label)
            .map(|notes| notes.iter().map(String::as_str).collect())
            .unwrap_or_default()
    };
    let (a, b) = (side(arm_a), side(arm_b));
    let mut out: Vec<String> = a
        .difference(&b)
        .map(|note| note_asymmetry_warning(note, arm_a, arm_b))
        .collect();
    out.extend(
        b.difference(&a)
            .map(|note| note_asymmetry_warning(note, arm_b, arm_a)),
    );
    out
}

/// The two arms of an A/B: exactly two labels, and two DIFFERENT ones.
///
/// WHY DISTINCTNESS IS PART OF THE ARITY CHECK. `--arm head --arm head` satisfied "exactly two"
/// and rendered a complete table: every row a `NO EVIDENCE` over a metric compared against
/// itself, thirty VM boots deep, with the rank test dutifully reporting p ≈ 1. That is a
/// full-page answer to a question nobody asked, and the reader has to notice the two column
/// headers are the same word to know it. The typo it comes from is `--arm base --arm base` while
/// meaning `base`/`head`, so the refusal names the fix.
///
/// Returns the two labels so the caller cannot load its arms without having asked: a call site
/// that skips this check does not compile.
///
/// # Errors
/// Returns an error when the count is not two, or when both labels name one arm.
fn two_arms(labels: &[String]) -> anyhow::Result<(&str, &str)> {
    let [a, b] = labels else {
        anyhow::bail!(
            "expected exactly two --arm labels (this is an A/B, and the rank test compares two \
             samples); got {}",
            labels.len()
        );
    };
    if a == b {
        anyhow::bail!(
            "both --arm labels are `{a}`, so every row would compare an arm against itself: the \
             table would be a full matrix of `no evidence` verdicts over thirty VM boots that \
             measured one tree twice. Pass the two arms you prepared, e.g. `--arm base --arm \
             head`; `bench-ab prepare --label <name>` is what creates each one."
        );
    }
    Ok((a, b))
}

/// The matrix to run: the operator's `--spec` list, or the built-in default when they gave none.
///
/// # Errors
/// Returns an error if a built-in default spec does not parse — a run that fails after the
/// operator typed nothing wrong.
fn resolve_specs(specs: Vec<Spec>) -> anyhow::Result<Vec<Spec>> {
    if !specs.is_empty() {
        return Ok(specs);
    }
    DEFAULT_SPECS
        .iter()
        .map(|s| parse_spec(s))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| anyhow::anyhow!("built-in default spec is invalid: {e}"))
}

/// `bench-ab run`.
///
/// # Errors
/// Returns an error when the arms are not two distinct prepared labels, an arm is missing, a
/// control guard fails, a child fails, or the arms did not run one VMM binary. Guard failures
/// happen BEFORE any VM boots.
fn cmd_run(head: &Path, args: RunArgs) -> anyhow::Result<()> {
    let (label_a, label_b) = two_arms(&args.arms)?;
    if args.repeats == 0 {
        anyhow::bail!("--repeats must be >= 1 (0 repeats measures nothing)");
    }
    let specs = resolve_specs(args.specs)?;
    let arms: Vec<ArmManifest> = [label_a, label_b]
        .into_iter()
        .map(|label| load_arm(head, label))
        .collect::<anyhow::Result<_>>()?;

    let plan = WrapPlan {
        wrap: !args.no_wrap,
        runner: args.runner.unwrap_or_else(|| head.join(DEFAULT_RUNNER_REL)),
        scope_script: args
            .scope_script
            .unwrap_or_else(|| head.join(DEFAULT_SCOPE_SCRIPT_REL)),
    };
    if plan.wrap {
        let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
        if inside_privilege_window(&status) {
            anyhow::bail!(double_wrap_refusal());
        }
        for (what, path) in [
            ("blessed runner", &plan.runner),
            ("scope script", &plan.scope_script),
        ] {
            if !path.exists() {
                anyhow::bail!(
                    "{what} {} does not exist. Run `just bless` (the runner) or pass --no-wrap to \
                     spawn each bench-vm directly.",
                    path.display()
                );
            }
        }
    }

    // Everything from here — the controls, the interleaved loop, the post-run controls, the rows —
    // is `run_comparison`, with the real spawn as its seam. The split is not tidiness: a guard
    // whose CALL SITE lives inline in this function is a guard whose deletion no test can see.
    let comparison = run_comparison(&arms, &specs, args.repeats, &mut |arm, spec, repeat| {
        run_child(&plan, arm, spec, repeat)
    })?;

    match args.format {
        OutputFormat::Text => print!("{}", render_table(&comparison)),
        OutputFormat::Json => println!(
            "{}",
            serde_json::to_string_pretty(&comparison)
                .map_err(|e| anyhow::anyhow!("cannot serialize the comparison: {e}"))?
        ),
    }
    Ok(())
}

/// The HEAD checkout this binary belongs to — the anchor for `target/ab-arms`, the runner and the
/// scope script.
///
/// `vmcell`'s ONE workspace-root ascent, called rather than mirrored: a second copy that drifted on
/// the marker string would stage arms into a different tree than the one whose runner it wraps them
/// with (`scripts/ban-workspace-root-ascent-copies.sh` is that class's gate).
fn head_checkout() -> PathBuf {
    vmcell::artifact::workspace_root()
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let head = head_checkout();
    match cli.command {
        Cmd::Prepare {
            git_ref,
            label,
            features,
            kernel,
        } => cmd_prepare(
            &head,
            &git_ref,
            &label,
            features.as_deref(),
            kernel,
            // The real step runner. `prepare`'s tests pass a recorder instead, which is how the
            // argv laws and the staging/probe sequence are gated without a toolchain.
            &mut |what: &str, cmd: &mut ProcCommand| run_step(what, cmd),
        ),
        Cmd::Run(args) => cmd_run(&head, args),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;
    use tempfile::TempDir;
    use vmcell_bench::report::{BinSource, Metric, REPORT_SCHEMA_VERSION};

    fn plan(wrap: bool) -> WrapPlan {
        WrapPlan {
            wrap,
            runner: PathBuf::from("/ws/.vmcell-bin/debug/vmcell-test-runner"),
            scope_script: PathBuf::from("/ws/scripts/with-delegated-scope.sh"),
        }
    }

    fn argv_strings(argv: &[OsString]) -> Vec<String> {
        argv.iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect()
    }

    /// A `Comparison` around `rows` with everything else empty, so a table-rendering assertion is
    /// about the rows and not about a fixture's warnings.
    fn comparison(rows: Vec<Row>, family_size: usize) -> Comparison {
        Comparison {
            arm_a: "a".to_string(),
            arm_b: "b".to_string(),
            repeats: 5,
            specs: vec![Spec::new("cloud-hypervisor", "latency").id()],
            family_size,
            warnings: Vec::new(),
            notes_by_arm: BTreeMap::new(),
            not_compared: Vec::new(),
            rows,
        }
    }

    /// A clean, verdict-less row, for the cell-rendering legs that vary one field at a time.
    fn bare_row(metric: &str) -> Row {
        Row {
            spec: Spec::new("cloud-hypervisor", "latency").id(),
            metric: metric.to_string(),
            unit: Unit::Millis,
            n_a: 5,
            n_b: 5,
            samples_a: 50,
            samples_b: 50,
            dropped_a: 0,
            dropped_b: 0,
            warmup_failed_a: 0,
            warmup_failed_b: 0,
            median_a: 40.0,
            median_b: 41.0,
            delta_pct: Some(2.5),
            p_two_sided: Some(0.9),
            p_adjusted: Some(1.0),
            prob_b_greater: Some(0.5),
            direction: Direction::LowerIsBetter,
            direction_declared: true,
            verdict: Verdict::NoEvidence,
        }
    }

    fn report(backend: &str, mode: &str, metrics: Vec<Metric>) -> BenchReport {
        BenchReport {
            schema_version: REPORT_SCHEMA_VERSION,
            backend: backend.to_string(),
            mode: mode.to_string(),
            vmm_binary: "/usr/bin/cloud-hypervisor".to_string(),
            vmm_binary_source: BinSource::Path,
            kernel: PathBuf::from("/artifacts/vmlinux"),
            rootfs: PathBuf::from("/artifacts/rootfs.erofs"),
            knobs: BTreeMap::new(),
            metrics,
            notes: Vec::new(),
        }
    }

    // THE DOUBLE-WRAP FOOTGUN, composed once and asserted here. `just test-bench`'s header records
    // what a second wrap costs: five tests dead at 0.008s with a bare `os error 1`, because the
    // first wrap shrank the bounding set below the runner file's `+ep` CAP_SETPCAP and execve
    // returns EPERM rather than degrading. RED on the inverse (a composer that pushes the runner
    // unconditionally, or twice): the occurrence count assert fails.
    #[test]
    fn the_child_is_wrapped_exactly_once() {
        let spec = Spec::new("cloud-hypervisor", "latency");
        let argv = argv_strings(&child_argv(
            &plan(true),
            Path::new("/ws/arms/head/bench-vm"),
            &spec,
        ));
        assert_eq!(
            argv,
            vec![
                "systemd-run",
                "--user",
                "--scope",
                "-q",
                "--collect",
                "-p",
                "Delegate=yes",
                "/ws/scripts/with-delegated-scope.sh",
                "/ws/.vmcell-bin/debug/vmcell-test-runner",
                "/ws/arms/head/bench-vm",
                "--backend",
                "cloud-hypervisor",
                "--mode",
                "latency",
                "--report",
                "json",
            ]
        );
        assert_eq!(
            argv.iter()
                .filter(|a| a.ends_with("vmcell-test-runner"))
                .count(),
            1,
            "the runner must appear exactly once: {argv:?}"
        );
        assert_eq!(
            argv.iter().filter(|a| *a == "systemd-run").count(),
            1,
            "one scope, not a scope inside a scope: {argv:?}"
        );
    }

    // `--no-wrap` is the escape hatch for the case the refusal below names: bench-ab itself already
    // inside the window. RED on the inverse (a composer that ignores `wrap`): the first-element
    // assert fails.
    #[test]
    fn no_wrap_spawns_the_arm_binary_directly() {
        let spec = Spec::new("qemu", "vsock-rtt");
        let argv = argv_strings(&child_argv(
            &plan(false),
            Path::new("/ws/arms/old/bench-vm"),
            &spec,
        ));
        assert_eq!(
            argv.first().map(String::as_str),
            Some("/ws/arms/old/bench-vm")
        );
        assert!(
            !argv.iter().any(|a| a.contains("vmcell-test-runner")),
            "{argv:?}"
        );
        assert!(!argv.iter().any(|a| a == "systemd-run"), "{argv:?}");
        assert_eq!(argv.last().map(String::as_str), Some("json"));
    }

    // A spec's pass-through arguments must not be able to displace `--report json`: the parent
    // parses this child's stdout, and a child that printed the human table fails at `serde_json`
    // with the table as the evidence. RED on the inverse (extras appended after the report flag):
    // the tail assert fails.
    #[test]
    fn the_report_flag_is_last_and_extras_precede_it() {
        let spec = Spec::new("cloud-hypervisor", "latency").with_args(["--mem-mib", "512"]);
        let argv = argv_strings(&child_argv(&plan(false), Path::new("/bench-vm"), &spec));
        assert_eq!(
            argv,
            vec![
                "/bench-vm",
                "--backend",
                "cloud-hypervisor",
                "--mode",
                "latency",
                "--mem-mib",
                "512",
                "--report",
                "json",
            ]
        );
    }

    // The refusal that turns an unreadable EPERM into a sentence. RED on the inverse (a probe that
    // always answers false, or that reads any CapAmb as "inside"): one of the two legs fails.
    #[test]
    fn a_non_empty_ambient_set_means_we_are_already_wrapped() {
        let outside = "Name:\tbench-ab\nCapBnd:\t000001ffffffffff\nCapAmb:\t0000000000000000\n";
        let inside = "Name:\tbench-ab\nCapBnd:\t0000000000201800\nCapAmb:\t0000000000201800\n";
        assert!(!inside_privilege_window(outside));
        assert!(inside_privilege_window(inside));
        // No CapAmb line at all: the probe is not working, and refusing every run to guard the
        // rare case would break the common one. Documented at the function.
        assert!(!inside_privilege_window("Name:\tbench-ab\n"));
        // The refusal names the fix, because a refusal that only says "no" gets worked around.
        assert!(double_wrap_refusal().contains("--no-wrap"));
    }

    // A spec is `<backend>/<mode>` plus pass-through args, and a malformed one is refused at parse
    // time rather than turning into a `--backend ''` the child rejects thirty VM boots later. RED
    // on the inverse (an accept-all parser): the three `is_err` asserts fail.
    #[test]
    fn spec_parsing_rejects_malformed_cells() {
        assert!(parse_spec("latency").is_err());
        assert!(parse_spec("/latency").is_err());
        assert!(parse_spec("cloud-hypervisor/").is_err());
        let spec = parse_spec("cloud-hypervisor/latency --mem-mib 512").expect("valid");
        assert_eq!(spec.backend, "cloud-hypervisor");
        assert_eq!(spec.mode, "latency");
        assert_eq!(spec.extra_args, vec!["--mem-mib", "512"]);
        // The extras are part of the identity: two --mem-mib values are two measurements.
        assert_ne!(
            spec.id(),
            parse_spec("cloud-hypervisor/latency").expect("valid").id()
        );
        // Every built-in default parses — a default that cannot be parsed is a run that fails
        // after the operator typed nothing wrong.
        for s in DEFAULT_SPECS {
            assert!(parse_spec(s).is_ok(), "default spec {s} must parse");
        }
    }

    // THE ARITY CHECK, both halves — and the second half is the one that shipped open:
    // `--arm head --arm head` passed "exactly two" and rendered a full, vacuous table of
    // `no evidence` rows over thirty VM boots that measured one tree twice. The check runs at the
    // CLI boundary here (parsed by clap, handed to `cmd_run`), not against the predicate alone,
    // because a predicate nobody calls is what this class of finding always is.
    //
    // RED on the inverse (the `a == b` arm deleted from `two_arms`): the duplicate legs fall
    // through to the missing-manifest error the positive control asserts, and the two
    // `contains` asserts fail.
    #[test]
    fn an_a_b_of_one_arm_against_itself_is_refused_before_anything_boots() {
        let labels = |names: &[&str]| names.iter().map(|s| (*s).to_string()).collect::<Vec<_>>();
        assert_eq!(
            two_arms(&labels(&["base", "head"])).expect("two distinct labels"),
            ("base", "head")
        );
        for wrong in [vec![], vec!["head"], vec!["a", "b", "c"]] {
            let err = two_arms(&labels(&wrong))
                .expect_err("not an A/B")
                .to_string();
            assert!(err.contains("exactly two --arm labels"), "{err}");
        }
        let err = two_arms(&labels(&["head", "head"]))
            .expect_err("one arm against itself")
            .to_string();
        assert!(err.contains("both --arm labels are `head`"), "{err}");
        assert!(
            err.contains("--arm base --arm head"),
            "the refusal must name the fix: {err}"
        );

        // THE CALL SITE, through the real clap parse. `cmd_run` refuses before it loads a
        // manifest or spawns anything, so this needs no prepared arm — which is the point: a
        // duplicate pair must not survive to the point where it costs thirty boots.
        let head = TempDir::new().expect("tempdir");
        let run_args = |args: &[&str]| match <Cli as clap::Parser>::parse_from(
            ["bench-ab", "run"].iter().chain(args).collect::<Vec<_>>(),
        )
        .command
        {
            Cmd::Run(run) => run,
            other => panic!("expected the run verb, got {other:?}"),
        };
        let err = cmd_run(head.path(), run_args(&["--arm", "head", "--arm", "head"]))
            .expect_err("a self-comparison must not run")
            .to_string();
        assert!(err.contains("compare an arm against itself"), "{err}");

        // THE POSITIVE CONTROL: two distinct labels get PAST the check — the run then stops on
        // the arm that was never prepared, which is a different refusal naming a different fix.
        // Without this leg, a `two_arms` that refused everything would satisfy the asserts above.
        let err = cmd_run(head.path(), run_args(&["--arm", "base", "--arm", "head"]))
            .expect_err("no arm is prepared under a fresh tempdir")
            .to_string();
        assert!(err.contains("bench-ab prepare"), "{err}");
        assert!(!err.contains("against itself"), "{err}");
    }

    // The matrix a `run` with no `--spec` actually gets. It used to be composed in `main`, where
    // no test reaches it; a default that does not parse is a run that fails after the operator
    // typed nothing wrong. RED on the inverse (`resolve_specs` returning the empty list through):
    // the length assert fails.
    #[test]
    fn no_spec_flag_runs_the_built_in_default_matrix() {
        let defaults = resolve_specs(Vec::new()).expect("the built-in matrix must parse");
        assert_eq!(defaults.len(), DEFAULT_SPECS.len());
        assert_eq!(
            defaults.iter().map(Spec::id).collect::<Vec<_>>(),
            DEFAULT_SPECS
                .iter()
                .map(|s| parse_spec(s).expect("default parses").id())
                .collect::<Vec<_>>()
        );
        // An explicit list is honored verbatim, never merged with the defaults: a matrix the
        // operator narrowed to one cell must not quietly run three.
        let one = parse_spec("qemu/latency").expect("valid");
        let given = resolve_specs(vec![one.clone()]).expect("an explicit list");
        assert_eq!(
            given.iter().map(Spec::id).collect::<Vec<_>>(),
            vec![one.id()]
        );
    }

    /// The verdict for a clean lower-is-better row, varying only the repeats, the adjusted p and
    /// the two medians. The dropped-iteration and direction axes have their own legs below, each
    /// built from [`bare_row`] so exactly one field moves at a time.
    fn clean_verdict(n_a: usize, n_b: usize, p: Option<f64>, med_a: f64, med_b: f64) -> Verdict {
        let mut row = bare_row("cold_boot");
        row.n_a = n_a;
        row.n_b = n_b;
        row.p_adjusted = p;
        row.median_a = med_a;
        row.median_b = med_b;
        verdict(&row)
    }

    /// The verdict for a clean row of the given direction, five repeats per arm.
    fn directed_verdict(direction: Direction, p: Option<f64>, med_a: f64, med_b: f64) -> Verdict {
        let mut row = bare_row("cold_boot");
        row.direction = direction;
        row.p_adjusted = p;
        row.median_a = med_a;
        row.median_b = med_b;
        verdict(&row)
    }

    // THE RULE: a metric with fewer than four repeats per arm prints `insufficient repeats`, never
    // a verdict — see MIN_REPEATS_FOR_VERDICT for why four is the floor and not a preference. RED
    // on the inverse (a verdict computed from whatever samples exist): the first two asserts fail.
    #[test]
    fn below_the_repeat_floor_there_is_no_verdict() {
        assert_eq!(
            clean_verdict(3, 9, Some(0.001), 10.0, 20.0),
            Verdict::InsufficientRepeats
        );
        assert_eq!(
            clean_verdict(9, 3, Some(0.001), 10.0, 20.0),
            Verdict::InsufficientRepeats
        );
        for non_finding in [
            Verdict::InsufficientRepeats,
            Verdict::SampleLoss,
            Verdict::NoDirection,
            Verdict::NoEvidence,
        ] {
            let label = non_finding.label();
            assert_eq!(
                label.to_lowercase(),
                label,
                "a non-finding must not read like one: {label}"
            );
        }
        // At the floor, the same numbers do produce one.
        assert_eq!(
            clean_verdict(4, 4, Some(0.001), 10.0, 20.0),
            Verdict::Regression
        );
    }

    // The direction half. A verdict word is a claim, and a table that guesses the direction will
    // eventually praise a regression. The rule this replaced was
    // `metric != "footprint_ksm_pages_sharing_delta"` — "everything is a cost except the one
    // exception I remembered" — over ~50 names. RED on the inverse (that one-liner restored, or a
    // `direction` that defaults instead of answering `None`): the benefit and share legs fail.
    #[test]
    fn the_verdict_names_the_direction_the_metric_actually_has() {
        // Lower is better (a latency): B slower is a regression, B faster an improvement.
        assert_eq!(
            clean_verdict(5, 5, Some(0.01), 10.0, 20.0),
            Verdict::Regression
        );
        assert_eq!(
            clean_verdict(5, 5, Some(0.01), 20.0, 10.0),
            Verdict::Improvement
        );
        // Higher is better (KSM pages deduped, guest memory kept): the same movement inverts.
        assert_eq!(
            directed_verdict(Direction::HigherIsBetter, Some(0.01), 10.0, 20.0),
            Verdict::Improvement
        );
        // Neutral: a delta, and NO verdict, however small the p.
        assert_eq!(
            directed_verdict(Direction::Neutral, Some(1e-9), 10.0, 20.0),
            Verdict::NoDirection
        );

        // …and the roster the rows read it out of. These four are the classes the one-liner got
        // wrong: two benefits it called costs, and a compositional share it gave a direction to.
        assert_eq!(
            metric_direction("cold_boot"),
            (Direction::LowerIsBetter, true)
        );
        assert_eq!(
            metric_direction("footprint_ksm_pages_sharing_delta"),
            (Direction::HigherIsBetter, true)
        );
        assert_eq!(
            metric_direction("footprint_guest_mem_available"),
            (Direction::HigherIsBetter, true),
            "guest memory the run KEPT is a benefit; under the old predicate a guest that lost \
             memory printed IMPROVEMENT"
        );
        assert_eq!(
            metric_direction("phase_cold_connect_share"),
            (Direction::Neutral, true),
            "a share of a whole rises when any OTHER part falls — make teardown twice as fast and \
             this row would read REGRESSION under a direction rule"
        );
        // An unknown name is Neutral AND flagged as undeclared, never a silent lower-is-better.
        assert_eq!(
            metric_direction("a_metric_only_the_other_ref_emits"),
            (Direction::Neutral, false)
        );

        // Not significant, and equal medians, are both "no evidence".
        assert_eq!(
            clean_verdict(5, 5, Some(0.4), 10.0, 20.0),
            Verdict::NoEvidence
        );
        assert_eq!(
            clean_verdict(5, 5, Some(0.001), 10.0, 10.0),
            Verdict::NoEvidence
        );
    }

    // THE ONE PREDICATE, checked at both of its call sites. The set of rows the table refuses to
    // call and the set the multiplicity correction refuses to spend alpha on must be THE SAME SET:
    // a family that counted rows nobody reads would silence the rows they do, and a family that
    // dropped a judgeable row would let a phantom through uncorrected. Two copies of a three-clause
    // conjunction is the shape that has diverged every time it has been written twice here, so both
    // sides ask `judgeable`. RED on the inverse (`in_family` restating the checks with any one of
    // them dropped, or a fourth check added to `verdict` alone): the equivalence fails on that axis.
    #[test]
    fn the_family_is_exactly_the_rows_the_table_can_call() {
        let precondition_failures = [
            Verdict::InsufficientRepeats,
            Verdict::SampleLoss,
            Verdict::NoDirection,
        ];
        let mut checked = 0_usize;
        let mut in_family_seen = 0_usize;
        for n_a in [MIN_REPEATS_FOR_VERDICT - 1, MIN_REPEATS_FOR_VERDICT] {
            for n_b in [MIN_REPEATS_FOR_VERDICT - 1, MIN_REPEATS_FOR_VERDICT] {
                for dropped_a in [0_usize, 3] {
                    for dropped_b in [0_usize, 3] {
                        // The fourth precondition axis: the two arms' surviving ITERATION counts.
                        // `dropped` is what the arm declared; this is what it cannot misreport, and
                        // both callers of `judgeable` have to agree about it too.
                        for samples_b in [50_usize, 15] {
                            for direction in [
                                Direction::LowerIsBetter,
                                Direction::HigherIsBetter,
                                Direction::Neutral,
                            ] {
                                for p in [None, Some(0.01_f64)] {
                                    let mut row = bare_row("cold_boot");
                                    row.n_a = n_a;
                                    row.n_b = n_b;
                                    row.dropped_a = dropped_a;
                                    row.dropped_b = dropped_b;
                                    row.samples_b = samples_b;
                                    row.direction = direction;
                                    row.p_two_sided = p;
                                    row.p_adjusted = p;
                                    let decided = verdict(&row);
                                    let failed_a_precondition =
                                        precondition_failures.contains(&decided);
                                    assert_eq!(
                                        in_family(&row),
                                        !failed_a_precondition && p.is_some(),
                                        "family membership and the table's verdict disagree for \
                                     {row:?} (verdict {decided:?})"
                                    );
                                    checked += 1;
                                    if in_family(&row) {
                                        in_family_seen += 1;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        assert_eq!(
            checked,
            2 * 2 * 2 * 2 * 2 * 3 * 2,
            "every axis must be driven"
        );
        // Non-vacuity in both directions: an equivalence over a set that is always empty (or
        // always full) is satisfied by any pair of predicates at all.
        assert!(
            in_family_seen > 0 && in_family_seen < checked,
            "{in_family_seen}"
        );
    }

    // THE COMPOSITIONAL SHARE, end to end through `build_rows` and the rendered table — the class
    // the old one-liner was silently wrong about for every `phase_*_share` row. Halving teardown
    // RAISES connect's share, and a direction rule calls that a regression. RED on the inverse
    // (`metric_direction` returning LowerIsBetter for a share): the share row reads REGRESSION and
    // the positive control below stops discriminating.
    #[test]
    fn a_compositional_share_gets_a_delta_and_no_verdict() {
        let spec = Spec::new("cloud-hypervisor", "phase-budget");
        let m = |name: &str, unit: Unit, p50: f64| Metric::new(name, unit, 10, p50, p50, p50, p50);
        let mut runs = Vec::new();
        for i in 0..5 {
            let jitter = f64::from(i);
            // Arm B's connect PHASE is unchanged in absolute µs, but its SHARE rose because the
            // rest of the path got faster. Exactly the situation a direction rule mishandles.
            runs.push((
                "a".to_string(),
                spec.clone(),
                report(
                    "cloud-hypervisor",
                    "phase-budget",
                    vec![
                        m("phase_cold_connect", Unit::Micros, 900.0 + jitter),
                        m("phase_cold_connect_share", Unit::Percent, 20.0 + jitter),
                    ],
                ),
            ));
            runs.push((
                "b".to_string(),
                spec.clone(),
                report(
                    "cloud-hypervisor",
                    "phase-budget",
                    vec![
                        m("phase_cold_connect", Unit::Micros, 900.0 + jitter),
                        m("phase_cold_connect_share", Unit::Percent, 40.0 + jitter),
                    ],
                ),
            ));
        }
        let samples = collect_samples(&runs).expect("one unit per metric");
        let (rows, _) = build_rows(&samples, "a", "b");
        let share = rows
            .iter()
            .find(|r| r.metric == "phase_cold_connect_share")
            .expect("the share row");
        assert_eq!(share.verdict, Verdict::NoDirection);
        assert_eq!(share.direction, Direction::Neutral);
        assert!(share.direction_declared, "the roster declares it Neutral");
        // The delta is still printed — the row is informative, it just carries no verdict.
        assert!(
            share.delta_pct.is_some_and(|d| d > 90.0),
            "the delta must still be reported: {:?}",
            share.delta_pct
        );
        // …and it is NOT in the corrected family, because it can never receive a verdict.
        assert!(share.p_adjusted.is_none(), "{share:?}");
        // THE POSITIVE CONTROL: the phase row beside it, in the same table, DOES get judged — so a
        // `NoDirection` that fired on everything would not satisfy this test.
        let phase = rows
            .iter()
            .find(|r| r.metric == "phase_cold_connect")
            .expect("the phase row");
        assert_eq!(phase.direction, Direction::LowerIsBetter);
        assert_ne!(phase.verdict, Verdict::NoDirection);
    }

    // Samples are keyed by (spec, backend, mode, metric) and pooled across repeats — never across
    // specs. Two specs of one mode differing only in an argument are two measurements, and a key
    // that collapsed them would average a 512 MiB run with a 4096 MiB one. RED on the inverse (a
    // key without the spec id): the two-key assert reads one.
    #[test]
    fn samples_are_pooled_across_repeats_and_never_across_specs() {
        let small = Spec::new("cloud-hypervisor", "latency").with_args(["--mem-mib", "512"]);
        let big = Spec::new("cloud-hypervisor", "latency").with_args(["--mem-mib", "4096"]);
        let m = |p50: f64| Metric::new("cold_boot", Unit::Millis, 10, p50, p50, p50, p50);
        let runs = vec![
            (
                "head".to_string(),
                small.clone(),
                report("cloud-hypervisor", "latency", vec![m(40.0)]),
            ),
            (
                "head".to_string(),
                small.clone(),
                report("cloud-hypervisor", "latency", vec![m(42.0)]),
            ),
            (
                "old".to_string(),
                small.clone(),
                report("cloud-hypervisor", "latency", vec![m(50.0)]),
            ),
            (
                "head".to_string(),
                big.clone(),
                report("cloud-hypervisor", "latency", vec![m(90.0)]),
            ),
        ];
        let samples = collect_samples(&runs).expect("one unit per metric");
        assert_eq!(samples.len(), 2, "one key per spec: {samples:?}");
        let small_key = samples
            .iter()
            .find(|(k, _)| k.spec == small.id())
            .map(|(_, v)| v)
            .expect("the small-mem spec");
        assert_eq!(
            small_key
                .by_arm
                .get("head")
                .map(|s| s.iter().map(|r| r.p50).collect::<Vec<_>>()),
            Some(vec![40.0, 42.0])
        );
        assert_eq!(
            small_key
                .by_arm
                .get("old")
                .map(|s| s.iter().map(|r| r.p50).collect::<Vec<_>>()),
            Some(vec![50.0])
        );
        assert_eq!(small_key.unit, Unit::Millis);

        // A metric name arriving in two different units is a schema change, not a comparison: one
        // arm's microseconds ranked against the other's milliseconds is a 1000x "regression"
        // nobody made. RED on the inverse (a collector that keeps the first unit and ranks
        // anyway): this `unwrap_err` fails.
        let mixed = vec![
            (
                "head".to_string(),
                small.clone(),
                report(
                    "cloud-hypervisor",
                    "latency",
                    vec![Metric::new(
                        "cold_boot",
                        Unit::Millis,
                        10,
                        40.0,
                        40.0,
                        40.0,
                        40.0,
                    )],
                ),
            ),
            (
                "old".to_string(),
                small.clone(),
                report(
                    "cloud-hypervisor",
                    "latency",
                    vec![Metric::new(
                        "cold_boot",
                        Unit::Micros,
                        10,
                        40000.0,
                        40000.0,
                        40000.0,
                        40000.0,
                    )],
                ),
            ),
        ];
        let err = collect_samples(&mixed)
            .expect_err("a unit change must stop the run")
            .to_string();
        assert!(err.contains("cold_boot"), "{err}");
    }

    // A REPORT IS PARSED, NOT TRUSTED — and for one of the two arms it is another COMMIT's output.
    // A report carrying one metric name twice contributes two repeats where the plan scheduled
    // one: that arm's `n` doubles, the rank test's variance falls with it, and a difference nobody
    // made clears the threshold — a phantom manufactured out of a bookkeeping bug in the emitter,
    // which is the exact class this whole harness exists to stop. RED on the inverse (the
    // duplicate check removed from `collect_samples`): the row below is built from six samples on
    // one side and three on the other, and reports a verdict.
    #[test]
    fn a_report_that_names_one_metric_twice_stops_the_run() {
        let spec = Spec::new("cloud-hypervisor", "latency");
        let m = |p50: f64| Metric::new("cold_boot", Unit::Millis, 10, p50, p50, p50, p50);
        let duplicated = vec![(
            "head".to_string(),
            spec.clone(),
            report("cloud-hypervisor", "latency", vec![m(40.0), m(41.0)]),
        )];
        let err = collect_samples(&duplicated)
            .expect_err("a duplicated metric name must stop the run")
            .to_string();
        assert!(err.contains("cold_boot"), "{err}");
        assert!(
            err.contains("twice"),
            "the message must name the defect: {err}"
        );

        // THE POSITIVE CONTROL: two DIFFERENT names in one report is the ordinary case, and a
        // refusal that fired on any two metrics would break every run.
        let honest = vec![(
            "head".to_string(),
            spec,
            report(
                "cloud-hypervisor",
                "latency",
                vec![
                    m(40.0),
                    Metric::new("warm_restore", Unit::Millis, 10, 12.0, 12.0, 12.0, 12.0),
                ],
            ),
        )];
        assert_eq!(
            collect_samples(&honest).expect("two distinct names").len(),
            2
        );
    }

    // SURVIVORSHIP BIAS WITH A P-VALUE ATTACHED. The first collector pushed `metric.p50` and threw
    // `Metric::{n, dropped, warmup_failed}` away, so a p50 over three surviving boots out of ten
    // ranked against a p50 over ten — and the surviving three are the FAST ones, because a slow
    // boot is what times out, so the broken arm wins. `report.rs`'s own rustdoc had already stated
    // the rule. RED on the inverse (`RepeatSample` carrying only the p50, or `collect_samples`
    // dropping the accounting): the per-repeat asserts fail.
    #[test]
    fn a_repeat_carries_what_its_p50_is_a_p50_of() {
        let spec = Spec::new("cloud-hypervisor", "latency");
        let lossy = Metric::new("cold_boot", Unit::Millis, 3, 40.0, 41.0, 42.0, 42.0)
            .with_dropped(7)
            .with_warmup_failed(2);
        let clean = Metric::new("cold_boot", Unit::Millis, 10, 55.0, 60.0, 61.0, 61.0);
        let runs = vec![
            (
                "broken".to_string(),
                spec.clone(),
                report("cloud-hypervisor", "latency", vec![lossy]),
            ),
            (
                "whole".to_string(),
                spec.clone(),
                report("cloud-hypervisor", "latency", vec![clean]),
            ),
        ];
        let samples = collect_samples(&runs).expect("one unit");
        let series = samples.values().next().expect("one key");
        assert_eq!(
            series.by_arm.get("broken").and_then(|r| r.first()).copied(),
            Some(RepeatSample {
                p50: 40.0,
                n: 3,
                dropped: 7,
                warmup_failed: 2,
            }),
            "the accounting must travel with the p50"
        );
        assert_eq!(
            series.by_arm.get("whole").and_then(|r| r.first()).copied(),
            Some(RepeatSample {
                p50: 55.0,
                n: 10,
                dropped: 0,
                warmup_failed: 0,
            })
        );
        // …and the fold that a row is built from sums both halves across repeats.
        let folded = ArmSeries::of(&[
            RepeatSample {
                p50: 1.0,
                n: 4,
                dropped: 6,
                warmup_failed: 1,
            },
            RepeatSample {
                p50: 2.0,
                n: 10,
                dropped: 0,
                warmup_failed: 0,
            },
        ]);
        assert_eq!(
            folded,
            ArmSeries {
                p50s: vec![1.0, 2.0],
                samples: 14,
                dropped: 6,
                warmup_failed: 1,
            }
        );
    }

    // …and the row it produces is MARKED, in the table and in the JSON, and gets no verdict. The
    // lossy arm here is faster on paper by every measure — that is the whole trap. RED on the
    // inverse (`verdict` ignoring `dropped`, or `render_loss` returning "-"): the verdict assert
    // reads IMPROVEMENT and the table assert fails.
    #[test]
    fn an_arm_that_lost_measurement_iterations_gets_no_verdict_and_says_so() {
        let spec = Spec::new("cloud-hypervisor", "latency");
        let mut runs = Vec::new();
        for i in 0..5 {
            let jitter = f64::from(i);
            // `b` looks dramatically faster — over three surviving boots out of ten.
            runs.push((
                "a".to_string(),
                spec.clone(),
                report(
                    "cloud-hypervisor",
                    "latency",
                    vec![Metric::new(
                        "cold_boot",
                        Unit::Millis,
                        10,
                        100.0 + jitter,
                        100.0,
                        100.0,
                        100.0,
                    )],
                ),
            ));
            runs.push((
                "b".to_string(),
                spec.clone(),
                report(
                    "cloud-hypervisor",
                    "latency",
                    vec![
                        Metric::new(
                            "cold_boot",
                            Unit::Millis,
                            3,
                            10.0 + jitter,
                            10.0,
                            10.0,
                            10.0,
                        )
                        .with_dropped(7),
                    ],
                ),
            ));
        }
        let samples = collect_samples(&runs).expect("one unit");
        let (rows, _) = build_rows(&samples, "a", "b");
        let row = rows.first().expect("one row");
        assert_eq!(
            row.verdict,
            Verdict::SampleLoss,
            "a p50 over 3 of 10 is not the same claim as a p50 over 10: {row:?}"
        );
        assert_eq!((row.dropped_a, row.dropped_b), (0, 35));
        assert_eq!((row.samples_a, row.samples_b), (50, 15));
        // Not in the corrected family: a row that cannot be called must not spend the family's
        // alpha either.
        assert!(row.p_adjusted.is_none());
        // Both halves in the cell: the iteration counts the two arms actually reached, and the
        // drops this arm declared. See `judgeable` for why the first is not redundant with the
        // second — an arm from an older commit reports the drops as zero.
        assert_eq!(render_loss(row), "i50/15 d0/35");

        let cmp = comparison(vec![row.clone()], 0);
        let table = render_table(&cmp);
        let line = table
            .lines()
            .find(|l| l.contains("cold_boot"))
            .expect("the row is rendered");
        assert!(line.contains("sample loss"), "{line}");
        assert!(
            line.contains("i50/15 d0/35"),
            "the table must show the loss: {line}"
        );
        assert!(!line.contains("IMPROVEMENT"), "{line}");
        // …and the JSON carries it too, since the tracked-metrics job reads that and not the table.
        let json = serde_json::to_string(&cmp).expect("serialize");
        for key in [
            "\"dropped_a\"",
            "\"dropped_b\"",
            "\"warmup_failed_a\"",
            "\"samples_a\"",
            "\"sample_loss\"",
        ] {
            assert!(json.contains(key), "the JSON must carry {key}: {json}");
        }
    }

    // THE HALF THE MEASURING ARM CANNOT MISREPORT. `dropped` is a number the arm's own binary
    // chose to write down, and the OTHER arm of an A/B is by construction an older build:
    // `prepare` refuses an arm that predates `--report json` and checks nothing else, so an arm
    // from any commit before that binary's drop accounting was fixed reports `dropped = 0` over a
    // sample set its own `break` truncated. The row above is then judgeable, and the lossy arm —
    // faster on paper, because a boot that failed is disproportionately a SLOW boot — earns a
    // confident IMPROVEMENT.
    //
    // Both arms ran the same spec with the same arguments, so they planned the same iterations:
    // unequal surviving `n` IS loss, whatever `dropped` says. RED on the inverse (`judgeable`
    // checking only `dropped`): the verdict below reads `improvement` over three surviving boots
    // against ten, and `render_loss` goes silent about it.
    #[test]
    fn an_arm_that_declares_no_drops_but_measured_less_work_still_gets_no_verdict() {
        let spec = Spec::new("cloud-hypervisor", "latency");
        // `n` is the only thing that differs; NOTHING is declared dropped, which is exactly what
        // an arm built before the emitter's fix reports.
        let arm_run = |p50: f64, n: usize| {
            (
                spec.clone(),
                report(
                    "cloud-hypervisor",
                    "latency",
                    vec![Metric::new(
                        "cold_boot",
                        Unit::Millis,
                        n,
                        p50,
                        p50,
                        p50,
                        p50,
                    )],
                ),
            )
        };
        let build = |n_b: usize| {
            let mut runs = Vec::new();
            for i in 0..5 {
                let jitter = f64::from(i);
                let (spec_a, report_a) = arm_run(100.0 + jitter, 10);
                runs.push(("a".to_string(), spec_a, report_a));
                let (spec_b, report_b) = arm_run(10.0 + jitter, n_b);
                runs.push(("b".to_string(), spec_b, report_b));
            }
            let samples = collect_samples(&runs).expect("one unit");
            let (rows, _) = build_rows(&samples, "a", "b");
            rows.into_iter().next().expect("one row")
        };

        let lossy = build(3);
        assert_eq!((lossy.dropped_a, lossy.dropped_b), (0, 0), "{lossy:?}");
        assert_eq!((lossy.samples_a, lossy.samples_b), (50, 15));
        assert_eq!(
            lossy.verdict,
            Verdict::SampleLoss,
            "three surviving boots of ten against ten of ten is not a comparison, whatever the arm \
             declared: {lossy:?}"
        );
        assert!(
            lossy.p_adjusted.is_none(),
            "and it spends no alpha: {lossy:?}"
        );
        assert_eq!(render_loss(&lossy), "i50/15");
        let line = render_table(&comparison(vec![lossy], 0));
        assert!(line.contains("i50/15"), "the table must show it: {line}");

        // THE POSITIVE CONTROL: the same arms, same medians, same everything — except that both
        // measured ten iterations. Without it, a `judgeable` that refused every row would satisfy
        // the asserts above.
        let clean = build(10);
        assert_eq!((clean.samples_a, clean.samples_b), (50, 50));
        assert_eq!(clean.verdict, Verdict::Improvement, "{clean:?}");
        assert_eq!(render_loss(&clean), "-");
    }

    // WHICH WAY IS BETTER, per row, in the table itself. The verdict word was the only place
    // direction reached the reader, and it is absent for exactly the rows that need it: a
    // `no evidence` / `sample loss` / `insufficient repeats` row prints a signed delta and nothing
    // else, and every other row in the table is a latency — so `-30.0` on a benefit reads as a win
    // to anyone scanning the column. RED on the inverse (`render_direction` answering one word for
    // everything, or the column dropped from the row format): the higher/lower legs collide, or
    // the cell assert fails on a row that has no verdict at all.
    #[test]
    fn every_row_says_which_way_is_better_even_when_it_has_no_verdict() {
        let mut latency = bare_row("cold_boot");
        latency.verdict = Verdict::NoEvidence;
        let mut benefit = bare_row("footprint_guest_mem_available");
        benefit.direction = Direction::HigherIsBetter;
        benefit.verdict = Verdict::NoEvidence;
        let mut share = bare_row("phase_cold_connect_share");
        share.direction = Direction::Neutral;
        share.verdict = Verdict::NoDirection;
        let mut unknown = bare_row("a_metric_only_the_other_ref_emits");
        unknown.direction = Direction::Neutral;
        unknown.direction_declared = false;
        unknown.verdict = Verdict::NoDirection;

        for (row, cell) in [
            (&latency, "lower"),
            (&benefit, "higher"),
            (&share, "none"),
            (&unknown, "?"),
        ] {
            assert_eq!(render_direction(row), cell, "{row:?}");
        }
        // A share and an unclassifiable name share a VERDICT (`no direction`) and must not share
        // this cell: one is a fact about the quantity, the other a hole in this build's roster.
        assert_ne!(render_direction(&share), render_direction(&unknown));

        let table = render_table(&comparison(vec![latency, benefit, share, unknown], 0));
        assert!(
            table.contains("better"),
            "the header names the column: {table}"
        );
        let cell_of = |metric: &str| -> String {
            table
                .lines()
                .find(|l| l.contains(metric))
                .unwrap_or_default()
                .to_string()
        };
        assert!(
            cell_of("footprint_guest_mem_available").contains("higher"),
            "a benefit's row must say so even with no verdict: {table}"
        );
        assert!(cell_of("cold_boot").contains("lower"), "{table}");
    }

    // A KEY ONLY ONE ARM PRODUCED leaves the table shorter and, before this, said so only through
    // `progress!` — i.e. on stderr, which `bench-ab run --format json > out.json` discards. The
    // artifact then showed a complete-looking comparison of a matrix half of which was never
    // compared. RED on the inverse (`not_compared` dropped from `Comparison`, or filled from
    // nothing): the JSON and table asserts fail.
    #[test]
    fn a_metric_only_one_arm_produced_is_named_in_the_document() {
        let dir = TempDir::new().expect("tempdir");
        let arms = vec![
            arm_fixture(dir.path(), "base", b"vmlinux", b"rootfs-A"),
            arm_fixture(dir.path(), "head", b"vmlinux", b"rootfs-B"),
        ];
        let specs = vec![Spec::new("cloud-hypervisor", "latency")];
        let cmp = run_comparison(&arms, &specs, 4, &mut |arm, _spec, _repeat| {
            let mut report = report_for(arm, 40.0);
            if arm.label == "head" {
                // The shape a self-skip makes: one arm's mode produced a metric the other's did
                // not (a capability the old ref did not have, a row a new ref added).
                report.metrics.push(Metric::new(
                    "warm_restore",
                    Unit::Millis,
                    10,
                    12.0,
                    12.0,
                    12.0,
                    12.0,
                ));
            }
            Ok(report)
        })
        .expect("two honest arms");
        assert_eq!(
            cmp.not_compared,
            vec!["cloud-hypervisor/latency / warm_restore".to_string()],
            "the uncompared key must reach the document"
        );
        // The POSITIVE CONTROL rides along: the key both arms produced IS compared.
        assert_eq!(cmp.rows.len(), 1);
        assert_eq!(
            cmp.rows.first().map(|r| r.metric.as_str()),
            Some("cold_boot")
        );
        let json = serde_json::to_string(&cmp).expect("serialize");
        assert!(json.contains("\"not_compared\""), "{json}");
        assert!(json.contains("warm_restore"), "{json}");
        let table = render_table(&cmp);
        assert!(table.contains("not compared"), "{table}");
        assert!(table.contains("warm_restore"), "{table}");
    }

    // THE COLUMN WIDTHS. `{:<N}` pads but never truncates, so one cell wider than its column
    // shifts every column after it — including the verdict. The widths were constants: 34 for the
    // metric, justified by a comment naming the roster's longest entry (a fact about a roster, in
    // a comment, with nothing keeping it true), and 30 for the spec, which `Spec::id` overflows by
    // design the moment a spec carries `--mem-mib 4096`. RED on the inverse (either width back to
    // a constant): the long-spec row's verdict no longer starts where the header's does.
    #[test]
    fn a_long_spec_id_or_metric_name_does_not_shift_the_columns() {
        let longest_metric = vmcell_bench::metrics::names()
            .max_by_key(|name| name.len())
            .expect("a non-empty roster");
        let mut wide = bare_row(longest_metric);
        wide.spec = Spec::new("cloud-hypervisor", "latency")
            .with_args(["--mem-mib", "4096"])
            .id();
        assert!(
            wide.spec.len() > 30 && longest_metric.len() > 20,
            "fixture must actually overflow the old constants: {} / {longest_metric}",
            wide.spec
        );
        let narrow = bare_row("vsock_rtt");
        let table = render_table(&comparison(vec![wide, narrow], 0));
        let header = table
            .lines()
            .find(|l| l.contains("median A"))
            .expect("the header row");
        let verdict_at = header.find("verdict").expect("the verdict column");
        for line in table.lines().filter(|l| l.contains("no evidence")) {
            assert_eq!(
                line.find("no evidence"),
                Some(verdict_at),
                "a row shifted the columns:\n{header}\n{line}"
            );
        }
    }

    // The distinction `Metric` draws and this comparator honors: a failed WARMUP never entered the
    // percentile, so it is surfaced but does not disqualify the row; a dropped MEASUREMENT
    // iteration does. RED on the inverse (treating the two counts alike in `verdict`): the
    // Regression assert reads `sample loss`.
    #[test]
    fn a_failed_warmup_is_surfaced_but_does_not_disqualify_the_row() {
        let mut row = bare_row("cold_boot");
        row.p_adjusted = Some(0.01);
        row.median_a = 10.0;
        row.median_b = 20.0;
        row.warmup_failed_a = 2;
        row.warmup_failed_b = 1;
        assert_eq!(
            verdict(&row),
            Verdict::Regression,
            "a failed warmup never entered the percentile, so it cannot contaminate it"
        );
        // …and the same row with a DROPPED measurement iteration loses its verdict — the two
        // counts are not interchangeable, which is exactly what `Metric` keeps them apart for.
        let mut lossy = row.clone();
        lossy.dropped_b = 4;
        assert_eq!(verdict(&lossy), Verdict::SampleLoss);
        assert_eq!(render_loss(&row), "w2/1");
        row.dropped_b = 4;
        assert_eq!(render_loss(&row), "d0/4 w2/1");
        row.warmup_failed_a = 0;
        row.warmup_failed_b = 0;
        assert_eq!(render_loss(&row), "d0/4");
        row.dropped_b = 0;
        assert_eq!(render_loss(&row), "-", "a clean row's column is silent");
    }

    // NO MULTIPLICITY HANDLING was the defect: ~20 rows, each getting its own uncorrected
    // two-sided test at 0.05, so a no-op change printed a verdict 64% of the time (1 - 0.95^20).
    // The discriminating pair below is one identical fixture measured in two family sizes — the
    // ONLY variable is how many other rows were tested beside it. RED on the inverse (a verdict
    // keyed off `p_two_sided`): the five-row leg reads REGRESSION.
    #[test]
    fn the_verdict_keys_off_the_adjusted_p_not_the_raw_one() {
        // `cold_boot` is fully separated across five repeats per arm: raw p ≈ 0.0122, which clears
        // 0.05 on its own. The companions are byte-identical across the arms (p = 1.0) and exist
        // only to enlarge the family.
        let companions = [
            "warm_restore",
            "vsock_rtt",
            "session_connect",
            "session_open",
        ];
        let build = |extra: usize| -> Comparison {
            let spec = Spec::new("cloud-hypervisor", "latency");
            let m = |name: &str, p50: f64| Metric::new(name, Unit::Millis, 10, p50, p50, p50, p50);
            let mut runs = Vec::new();
            for i in 0..5 {
                let jitter = f64::from(i);
                let mut a = vec![m("cold_boot", 10.0 + jitter)];
                let mut b = vec![m("cold_boot", 100.0 + jitter)];
                for name in companions.iter().take(extra) {
                    a.push(m(name, 50.0 + jitter));
                    b.push(m(name, 50.0 + jitter));
                }
                runs.push((
                    "a".to_string(),
                    spec.clone(),
                    report("cloud-hypervisor", "latency", a),
                ));
                runs.push((
                    "b".to_string(),
                    spec.clone(),
                    report("cloud-hypervisor", "latency", b),
                ));
            }
            let samples = collect_samples(&runs).expect("one unit per metric");
            let (rows, _) = build_rows(&samples, "a", "b");
            let family_size = rows.iter().filter(|r| r.p_adjusted.is_some()).count();
            comparison(rows, family_size)
        };

        // Family of two: 0.0122 x 2 = 0.0244, still under 0.05 — the finding survives.
        let small = build(1);
        assert_eq!(small.family_size, 2);
        let row = small
            .rows
            .iter()
            .find(|r| r.metric == "cold_boot")
            .expect("the separated row");
        assert_eq!(row.verdict, Verdict::Regression);

        // Family of five: the SAME numbers, 0.0122 x 5 = 0.061, and the row is no longer a
        // finding. Nothing about the measurement changed; only how many questions were asked.
        let big = build(4);
        assert_eq!(big.family_size, 5);
        let row = big
            .rows
            .iter()
            .find(|r| r.metric == "cold_boot")
            .expect("the separated row");
        assert!(
            row.p_two_sided.is_some_and(|p| p < SIGNIFICANCE),
            "the RAW p must still clear 0.05, or this test is not about the correction: {:?}",
            row.p_two_sided
        );
        assert!(
            row.p_adjusted.is_some_and(|p| p > SIGNIFICANCE),
            "adjusted: {:?}",
            row.p_adjusted
        );
        assert_eq!(row.verdict, Verdict::NoEvidence);

        // Both p-values reach the reader: the raw one is what a reviewer re-derives by hand, and
        // the family size is what makes the adjusted one checkable at all.
        let table = render_table(&big);
        assert!(table.contains("p_adj"), "{table}");
        assert!(
            table.contains("Holm-Bonferroni over the 5 row(s)"),
            "the family size must be printed: {table}"
        );
        let line = table
            .lines()
            .find(|l| l.contains("cold_boot"))
            .expect("the row");
        assert!(
            line.contains("0.0122"),
            "the raw p stays in the table: {line}"
        );
        let json = serde_json::to_string(&big).expect("serialize");
        assert!(json.contains("\"p_two_sided\""), "{json}");
        assert!(json.contains("\"p_adjusted\""), "{json}");
        assert!(json.contains("\"family_size\":5"), "{json}");
    }

    // The table is sorted by adjusted p (strongest finding first) with the unranked rows last, and
    // a one-armed key is reported as uncompared instead of silently vanishing. RED on the inverse
    // (an unsorted table, or `one_sided` dropped): the order assert or the `one_sided` assert
    // fails.
    #[test]
    fn rows_sort_by_p_with_the_unranked_last_and_name_the_uncompared() {
        let spec = Spec::new("cloud-hypervisor", "latency");
        let metric = |name: &str, p50: f64| Metric::new(name, Unit::Millis, 10, p50, p50, p50, p50);
        let mut runs = Vec::new();
        // `cold_boot` is fully separated across five repeats per arm (p well under 0.05);
        // `vsock_rtt` overlaps completely (no evidence); `warm_restore` has one repeat on each arm.
        for i in 0..5 {
            let jitter = f64::from(i);
            runs.push((
                "a".to_string(),
                spec.clone(),
                report(
                    "cloud-hypervisor",
                    "latency",
                    vec![
                        metric("cold_boot", 10.0 + jitter),
                        metric("vsock_rtt", 100.0 + jitter),
                    ],
                ),
            ));
            runs.push((
                "b".to_string(),
                spec.clone(),
                report(
                    "cloud-hypervisor",
                    "latency",
                    vec![
                        metric("cold_boot", 100.0 + jitter),
                        metric("vsock_rtt", 100.0 + jitter),
                    ],
                ),
            ));
        }
        runs.push((
            "a".to_string(),
            spec.clone(),
            report(
                "cloud-hypervisor",
                "latency",
                vec![metric("warm_restore", 1.0)],
            ),
        ));
        runs.push((
            "a".to_string(),
            spec.clone(),
            report(
                "cloud-hypervisor",
                "latency",
                vec![metric("session_open", 1.0)],
            ),
        ));
        runs.push((
            "b".to_string(),
            spec.clone(),
            report(
                "cloud-hypervisor",
                "latency",
                vec![metric("warm_restore", 2.0)],
            ),
        ));

        let samples = collect_samples(&runs).expect("one unit per metric");
        let (rows, one_sided) = build_rows(&samples, "a", "b");
        let names: Vec<&str> = rows.iter().map(|r| r.metric.as_str()).collect();
        assert_eq!(names, vec!["cold_boot", "vsock_rtt", "warm_restore"]);
        assert_eq!(rows.first().map(|r| r.verdict), Some(Verdict::Regression));
        assert_eq!(rows.get(1).map(|r| r.verdict), Some(Verdict::NoEvidence));
        assert_eq!(
            rows.get(2).map(|r| r.verdict),
            Some(Verdict::InsufficientRepeats)
        );
        assert_eq!(
            one_sided
                .iter()
                .map(|k| k.metric.as_str())
                .collect::<Vec<_>>(),
            vec!["session_open"],
            "a metric only one arm produced is named, not dropped"
        );

        // …and the rendering keeps the promise: the thin row shows no p, no effect size and no
        // verdict word.
        let family_size = rows.iter().filter(|r| r.p_adjusted.is_some()).count();
        let cmp = comparison(rows, family_size);
        let table = render_table(&cmp);
        let thin_line = table
            .lines()
            .find(|l| l.contains("warm_restore"))
            .expect("the thin row is rendered");
        assert!(thin_line.contains("insufficient repeats"), "{thin_line}");
        assert!(!thin_line.contains("REGRESSION"), "{thin_line}");
        assert!(!thin_line.contains("no evidence"), "{thin_line}");
        assert!(
            table.contains("REGRESSION"),
            "the separated row must still be called: {table}"
        );
    }

    // The format flag is an accepted input: honored or refused, never silently defaulted to text
    // for a parent that is about to parse JSON.
    #[test]
    fn output_format_parser_rejects_typos() {
        assert!(parse_output_format("jsonn").is_err());
        assert!(parse_output_format("").is_err());
        assert_eq!(parse_output_format("text"), Ok(OutputFormat::Text));
        assert_eq!(parse_output_format("json"), Ok(OutputFormat::Json));
    }

    // ------------------------------------------------------------------------------------
    // The child's ENVIRONMENT, and the arms it actually boots.
    // ------------------------------------------------------------------------------------

    /// An arm whose four pinned files really exist under `dir/label`, so the guards that re-read
    /// them have something to read.
    fn arm_fixture(dir: &Path, label: &str, kernel: &[u8], rootfs: &[u8]) -> ArmManifest {
        let arm_dir = dir.join(label);
        let artifacts = arm_dir.join("artifacts");
        std::fs::create_dir_all(&artifacts).expect("create arm dirs");
        let bench_vm = arm_dir.join("bench-vm");
        std::fs::write(&bench_vm, format!("bench-vm for {label}")).expect("write bench-vm");
        let kernel_path = artifacts.join("vmlinux");
        std::fs::write(&kernel_path, kernel).expect("write vmlinux");
        let rootfs_path = artifacts.join("rootfs.erofs");
        std::fs::write(&rootfs_path, rootfs).expect("write rootfs");
        ArmManifest {
            label: label.to_string(),
            git_ref: Some(label.to_string()),
            git_commit: Some(format!("{label:0>40}")),
            bench_vm: DigestedFile::digest(bench_vm).expect("digest bench-vm"),
            vmcelld: None,
            artifacts_dir: artifacts,
            kernel: DigestedFile::digest(kernel_path).expect("digest kernel"),
            rootfs: DigestedFile::digest(rootfs_path).expect("digest rootfs"),
        }
    }

    /// The report an honest run of `arm` emits: `bench-vm` composes both paths from
    /// `$VMCELL_ARTIFACTS_DIR`, so they are the arm's own pinned pair.
    fn report_for(arm: &ArmManifest, p50: f64) -> BenchReport {
        let mut report = report(
            "cloud-hypervisor",
            "latency",
            vec![Metric::new(
                "cold_boot",
                Unit::Millis,
                10,
                p50,
                p50,
                p50,
                p50,
            )],
        );
        report.kernel = arm.kernel.path.clone();
        report.rootfs = arm.rootfs.path.clone();
        report
    }

    // THE SEAL, at the composer. `bench-vm` resolves `$VMCELL_KERNEL`/`$VMCELL_ROOTFS` AHEAD of the
    // artifacts dir, so setting `$VMCELL_ARTIFACTS_DIR` is not control over what an arm boots —
    // an operator with either exported (README's contract table documents them; ci.yml exports
    // them) makes every arm boot ONE guest artifact while this harness reports per-arm ones. RED on
    // the inverse (any `env_remove` dropped from `child_command`): the matching assert fails.
    #[test]
    fn the_child_environment_is_sealed_and_named() {
        let dir = TempDir::new().expect("tempdir");
        let arm = arm_fixture(dir.path(), "head", b"vmlinux", b"rootfs");
        let spec = Spec::new("cloud-hypervisor", "latency");
        let argv = child_argv(&plan(false), &arm.bench_vm.path, &spec);
        let cmd = child_command(&arm, &argv).expect("compose");
        let envs: Vec<(String, Option<String>)> = cmd
            .get_envs()
            .map(|(k, v)| {
                (
                    k.to_string_lossy().into_owned(),
                    v.map(|v| v.to_string_lossy().into_owned()),
                )
            })
            .collect();
        assert!(
            envs.contains(&(
                "VMCELL_ARTIFACTS_DIR".to_string(),
                Some(arm.artifacts_dir.to_string_lossy().into_owned())
            )),
            "the arm's own artifacts dir must be named: {envs:?}"
        );
        for var in SEALED_CHILD_VARS {
            assert!(
                envs.contains(&(var.to_string(), None)),
                "${var} must be REMOVED from the child, not merely left unset here: {envs:?}"
            );
        }
        // The VMM binary resolvers are deliberately NOT sealed: pinning one is the documented
        // workaround for an old arm, and `guard_vmm_binaries` checks the outcome from the reports.
        assert!(
            !envs.iter().any(|(k, _)| k == "VMCELL_CH_BIN"),
            "sealing $VMCELL_CH_BIN would break the documented shim: {envs:?}"
        );
    }

    /// The `$VMCELL_*` variables the scan below finds and this harness deliberately does NOT strip,
    /// each with the reason it is safe to leave standing. An entry here is a decision, not a
    /// backlog: adding a name silences the gate, so the reason is what the next reader reviews.
    const UNSEALED_BY_DESIGN: [(&str, &str); 3] = [
        (
            "VMCELL_ARTIFACTS_DIR",
            "SET rather than removed — it is how each child is pointed at its OWN arm's artifacts",
        ),
        (
            "VMCELL_CH_BIN",
            "selects the HOST VMM binary, which both arms are supposed to share; pinning one \
             deliberately is the documented workaround for an arm that hardcodes the name, and \
             `guard_vmm_binaries` checks the outcome from the reports",
        ),
        (
            "VMCELL_SKIP_MANIFEST",
            "records capability skips; it selects nothing an arm boots",
        ),
    ];

    // THE ROSTER'S OWN GATE. `SEALED_CHILD_VARS` was written by enumerating the artifact module's
    // environment reads once, and a list compiled by reading is a list that goes stale the next
    // time somebody adds a resolver — which is the same shape as the defect it closes: an override
    // the driver did not know about, silently deciding what an arm boots. So the roster is checked
    // against the module rather than against memory. A scan that finds NOTHING is `gate
    // misconfigured` and fails, never a green verdict about a file it could not read.
    // RED on the inverse (a name dropped from `SEALED_CHILD_VARS`, or a new `$VMCELL_*` resolver
    // added upstream without a decision here): the per-name assert fails and names the variable.
    #[test]
    fn the_seal_roster_is_checked_against_the_artifact_module_not_memory() {
        let dir = vmcell::artifact::workspace_root().join("crates/vmcell/src/artifact");
        let mut sources = Vec::new();
        collect_rust_sources(&dir, &mut sources);
        assert!(
            !sources.is_empty(),
            "gate misconfigured: no Rust sources under {} — the only way to open nothing is to \
             have been pointed at nothing, so this is a broken scan and not a clean roster",
            dir.display()
        );
        let mut found: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        for path in &sources {
            let text = std::fs::read_to_string(path).unwrap_or_else(|e| {
                panic!("gate misconfigured: cannot read {}: {e}", path.display())
            });
            let mut rest = text.as_str();
            while let Some(at) = rest.find("\"VMCELL_") {
                let after = rest.split_at(at + 1).1;
                if let Some(name) = after.find('"').and_then(|end| after.get(..end)) {
                    found.insert(name.to_string());
                }
                rest = after;
            }
        }
        assert!(
            !found.is_empty(),
            "gate misconfigured: not one $VMCELL_* literal under {} — the module cannot have \
             stopped reading its own environment contract",
            dir.display()
        );
        for name in &found {
            let sealed = SEALED_CHILD_VARS.contains(&name.as_str());
            let exempt = UNSEALED_BY_DESIGN.iter().any(|(n, _)| n == name);
            assert!(
                sealed || exempt,
                "${name} is resolved by the artifact module but is neither sealed from every \
                 `bench-vm` child nor listed in UNSEALED_BY_DESIGN. Decide which it is: an \
                 override that redirects what an arm BOOTS belongs in SEALED_CHILD_VARS, anything \
                 else belongs in the exemption list WITH its reason. Found: {found:?}"
            );
            assert!(
                !(sealed && exempt),
                "${name} is both sealed and exempt — one of the two lists is wrong"
            );
        }
        // …and the roster names nothing the module does not resolve, so a deleted resolver leaves
        // a dead entry rather than a false sense of coverage.
        for name in SEALED_CHILD_VARS {
            assert!(
                found.contains(name),
                "${name} is sealed but the artifact module no longer resolves it: {found:?}"
            );
        }
    }

    /// Every `.rs` file under `dir`, recursively. Panics on an unreadable directory: see the
    /// zero-file rule at the caller.
    fn collect_rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
        let entries = std::fs::read_dir(dir)
            .unwrap_or_else(|e| panic!("gate misconfigured: cannot list {}: {e}", dir.display()));
        for entry in entries {
            let path = entry.expect("a directory entry").path();
            if path.is_dir() {
                collect_rust_sources(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }

    /// Marker the outer half of the sealed-environment test sets on the inner half's process.
    const SEALED_ENV_MARKER: &str = "BENCH_AB_SEALED_ENV_CHILD";

    /// A `bench-vm` stand-in that resolves its artifacts exactly the way the real one does —
    /// `$VMCELL_KERNEL` / `$VMCELL_ROOTFS` first, the artifacts dir second — and reports what it
    /// resolved. `SCHEMA` is substituted rather than `format!`ed because the body is mostly braces.
    const FAKE_BENCH_VM: &str = r#"#!/bin/sh
cat <<EOF
{"schema_version":SCHEMA,"backend":"cloud-hypervisor","mode":"latency","vmm_binary":"/usr/bin/cloud-hypervisor","vmm_binary_source":{"kind":"path"},"kernel":"${VMCELL_KERNEL:-$VMCELL_ARTIFACTS_DIR/vmlinux}","rootfs":"${VMCELL_ROOTFS:-$VMCELL_ARTIFACTS_DIR/rootfs.erofs}","knobs":{},"metrics":[],"notes":["pins=${VMCELL_PINS:-sealed}"]}
EOF
"#;

    /// Writes `body` to `path` and makes it executable.
    fn write_script(path: &Path, body: &str) {
        std::fs::write(path, body).expect("write script");
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
            .expect("chmod +x the script");
    }

    // THE SEAL, at the SPAWN SITE — the half `the_child_environment_is_sealed_and_named` cannot
    // reach. That test proves the composer; this one proves `run_child` goes through it AND that
    // the removal survives a real `execve`, by re-executing this test binary with the three
    // variables exported and driving a `bench-vm` stand-in that resolves them in the real one's
    // order. RED on the inverse (drop an `env_remove`, or spawn without `child_command`): the
    // inner assertions see `/leaked/...` and the outer sees a failed status.
    #[test]
    fn the_child_environment_is_sealed_against_a_poisoned_parent() {
        let exe = std::env::current_exe().expect("this test binary");
        let out = ProcCommand::new(exe)
            .args([
                "--exact",
                "tests::sealed_child_env_inner",
                "--ignored",
                "--nocapture",
            ])
            .env(SEALED_ENV_MARKER, "1")
            .env("VMCELL_KERNEL", "/leaked/vmlinux")
            .env("VMCELL_ROOTFS", "/leaked/rootfs.erofs")
            .env("VMCELL_PINS", "/leaked/pins.json")
            .output()
            .expect("re-execute this test binary");
        assert!(
            out.status.success(),
            "the inner leg failed under a poisoned parent environment:\n{}\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }

    #[test]
    #[ignore = "driven by `the_child_environment_is_sealed_against_a_poisoned_parent`, which \
                re-executes this binary with $VMCELL_KERNEL/$VMCELL_ROOTFS/$VMCELL_PINS exported. \
                Run on a clean environment it would assert nothing, so it fails loud instead."]
    fn sealed_child_env_inner() {
        assert!(
            std::env::var_os(SEALED_ENV_MARKER).is_some(),
            "this leg is only meaningful with the overrides exported; its driver is \
             `the_child_environment_is_sealed_against_a_poisoned_parent`"
        );
        let dir = TempDir::new().expect("tempdir");
        let arm = arm_fixture(dir.path(), "head", b"vmlinux", b"rootfs");
        write_script(
            &arm.bench_vm.path,
            &FAKE_BENCH_VM.replace("SCHEMA", &REPORT_SCHEMA_VERSION.to_string()),
        );
        // Re-digest: the fixture pinned the placeholder, and the guard the run loop applies would
        // otherwise refuse the script we just wrote.
        let arm = ArmManifest {
            bench_vm: DigestedFile::digest(&arm.bench_vm.path).expect("digest the stand-in"),
            ..arm
        };
        let spec = Spec::new("cloud-hypervisor", "latency");
        let report =
            run_child(&plan(false), &arm, &spec, 0).expect("the stand-in prints one report");
        assert_eq!(
            report.kernel, arm.kernel.path,
            "the child resolved $VMCELL_KERNEL from the parent instead of this arm's artifacts dir"
        );
        assert_eq!(
            report.rootfs, arm.rootfs.path,
            "the child resolved $VMCELL_ROOTFS from the parent instead of this arm's artifacts dir"
        );
        assert_eq!(report.notes, vec!["pins=sealed".to_string()]);
    }

    // ------------------------------------------------------------------------------------
    // The guard CALL SITES: `run_preflight`, `execute_plan`, `run_comparison`.
    // ------------------------------------------------------------------------------------

    // Deleting `guard_same_kernel(arms)?` from `run_preflight`, or `run_preflight(arms)?` from
    // `run_comparison`, used to leave the whole suite green: the guard had a red-on-inverse test
    // and its call site had none. RED on the inverse (either deletion): this goes green-to-red.
    // The spawn counter is the second half — a control that ran after the first VM booted would be
    // a control that reported on a machine already perturbed.
    #[test]
    fn run_comparison_refuses_a_kernel_mismatch_before_it_spawns_anything() {
        let dir = TempDir::new().expect("tempdir");
        let arms = vec![
            arm_fixture(dir.path(), "base", b"vmlinux 6.12.94", b"rootfs-A"),
            arm_fixture(dir.path(), "head", b"vmlinux 6.12.104", b"rootfs-B"),
        ];
        let specs = vec![Spec::new("cloud-hypervisor", "latency")];
        let mut spawned = 0_usize;
        let err = run_comparison(&arms, &specs, 5, &mut |arm, _spec, _repeat| {
            spawned += 1;
            Ok(report_for(arm, 40.0))
        })
        .expect_err("a violated control must refuse the run");
        assert!(err.to_string().contains("same guest kernel"), "{err}");
        assert_eq!(spawned, 0, "the controls must run before any VM boots");
    }

    // The rootfs guard's call site: a shared image is a WARNING, and a warning nobody carries out
    // of the run does not exist. RED on the inverse (`guard_distinct_rootfs`'s result dropped in
    // `run_preflight`, or the warnings not threaded into the comparison): the assert fails.
    #[test]
    fn run_comparison_carries_the_shared_rootfs_warning_into_its_output() {
        let dir = TempDir::new().expect("tempdir");
        let arms = vec![
            arm_fixture(dir.path(), "base", b"vmlinux", b"rootfs-SAME"),
            arm_fixture(dir.path(), "head", b"vmlinux", b"rootfs-SAME"),
        ];
        let specs = vec![Spec::new("cloud-hypervisor", "latency")];
        let cmp = run_comparison(&arms, &specs, 4, &mut |arm, _spec, _repeat| {
            Ok(report_for(arm, 40.0))
        })
        .expect("a shared rootfs is legitimate when only host code changed");
        assert_eq!(cmp.warnings.len(), 1, "{:?}", cmp.warnings);
        assert!(
            render_table(&cmp).contains("WARNING:"),
            "the table must print it: {}",
            render_table(&cmp)
        );
    }

    // The per-child re-digest's CALL SITE. The swap that motivated it landed DURING a matrix,
    // between two of its cells, so a check that ran once at start-up would have passed. The fake
    // spawn reproduces that exactly: it overwrites one arm's staged binary the way a concurrent
    // `cargo build --release` did. RED on the inverse (`guard_binaries_unchanged` deleted from the
    // loop): the run completes and `expect_err` fails.
    #[test]
    fn execute_plan_re_digests_before_every_child_not_once_at_start_up() {
        let dir = TempDir::new().expect("tempdir");
        let arms = vec![
            arm_fixture(dir.path(), "base", b"vmlinux", b"rootfs-A"),
            arm_fixture(dir.path(), "head", b"vmlinux", b"rootfs-B"),
        ];
        let labels: Vec<String> = arms.iter().map(|a| a.label.clone()).collect();
        let specs = vec![Spec::new("cloud-hypervisor", "latency")];
        // Two repeats: the plan is base, head, head, base — so the corrupted arm's SECOND cell is
        // the one that must be refused, which is what "not once at start-up" means.
        let plan_runs = interleave(&labels, &specs, 2);
        assert_eq!(plan_runs.len(), 4);
        let mut spawned = 0_usize;
        let err = execute_plan(&plan_runs, &arms, &mut |arm, _spec, _repeat| {
            spawned += 1;
            std::fs::write(&arms[0].bench_vm.path, b"patched by a concurrent build")
                .expect("overwrite the staged binary mid-matrix");
            Ok(report_for(arm, 40.0))
        })
        .expect_err("a binary swapped mid-matrix must stop the run");
        let message = err.to_string();
        assert!(message.contains("changed under the run"), "{message}");
        assert!(message.contains("base"), "{message}");
        assert_eq!(
            spawned, 3,
            "the first three cells ran; the corrupted arm's second cell was refused"
        );
    }

    // The POST-RUN control's call site. `guard_same_kernel` compares what PREPARE recorded, so it
    // is green here: the defect is entirely in what the child resolved, which only the report can
    // show. RED on the inverse (`guard_booted_artifacts` deleted from `run_comparison`): the
    // comparison completes and reports numbers from two arms that booted one kernel.
    #[test]
    fn run_comparison_refuses_a_child_that_booted_another_arms_kernel() {
        let dir = TempDir::new().expect("tempdir");
        let arms = vec![
            arm_fixture(dir.path(), "base", b"vmlinux 6.12.104", b"rootfs-A"),
            arm_fixture(dir.path(), "head", b"vmlinux 6.12.104", b"rootfs-B"),
        ];
        let leaked = arms[0].kernel.path.clone();
        let specs = vec![Spec::new("cloud-hypervisor", "latency")];
        let err = run_comparison(&arms, &specs, 4, &mut |arm, _spec, _repeat| {
            let mut report = report_for(arm, 40.0);
            // What an inherited $VMCELL_KERNEL does: every arm opens one file.
            report.kernel = leaked.clone();
            Ok(report)
        })
        .expect_err("a run that booted an artifact its arm never pinned is not comparable");
        let message = err.to_string();
        assert!(message.contains("VMCELL_KERNEL"), "{message}");
        assert!(message.contains("head"), "{message}");
    }

    // The other post-run control's call site, which had none either. RED on the inverse
    // (`guard_vmm_binaries` deleted from `run_comparison`): the comparison completes.
    #[test]
    fn run_comparison_refuses_arms_that_executed_different_vmm_binaries() {
        let dir = TempDir::new().expect("tempdir");
        let arms = vec![
            arm_fixture(dir.path(), "base", b"vmlinux", b"rootfs-A"),
            arm_fixture(dir.path(), "head", b"vmlinux", b"rootfs-B"),
        ];
        let specs = vec![Spec::new("cloud-hypervisor", "latency")];
        let err = run_comparison(&arms, &specs, 4, &mut |arm, _spec, _repeat| {
            let mut report = report_for(arm, 40.0);
            if arm.label == "base" {
                report.vmm_binary = "/usr/bin/cloud-hypervisor".to_string();
            } else {
                report.vmm_binary = "/home/x/.local/bin/cloud-hypervisor".to_string();
            }
            Ok(report)
        })
        .expect_err("two arms of one backend must have run one VMM binary");
        assert!(
            err.to_string().contains("same VMM binary"),
            "{}",
            err.to_string()
        );
    }

    // The positive control for all four refusals above: an honest run reaches a table. Without it
    // a guard that refused EVERYTHING would satisfy every test on this page.
    #[test]
    fn run_comparison_compares_two_honest_arms() {
        let dir = TempDir::new().expect("tempdir");
        let arms = vec![
            arm_fixture(dir.path(), "base", b"vmlinux 6.12.104", b"rootfs-A"),
            arm_fixture(dir.path(), "head", b"vmlinux 6.12.104", b"rootfs-B"),
        ];
        let specs = vec![Spec::new("cloud-hypervisor", "latency")];
        let mut spawned = 0_usize;
        let cmp = run_comparison(&arms, &specs, 5, &mut |arm, _spec, _repeat| {
            spawned += 1;
            // Fully separated so the row is called rather than left at "no evidence".
            let p50 = if arm.label == "base" { 40.0 } else { 80.0 };
            Ok(report_for(
                arm,
                p50 + f64::from(u32::try_from(spawned).unwrap_or(0)),
            ))
        })
        .expect("two honest arms compare");
        assert_eq!(spawned, 10, "2 arms x 1 spec x 5 repeats");
        assert_eq!(cmp.arm_a, "base");
        assert_eq!(cmp.arm_b, "head");
        assert_eq!(cmp.rows.len(), 1, "{:?}", cmp.rows);
        assert_eq!(
            cmp.rows.first().map(|r| r.verdict),
            Some(Verdict::Regression)
        );
    }

    // THE CHILDREN'S NOTES, which were emitted, carried across the process boundary, and then
    // DROPPED: `BenchReport::notes` had no reader anywhere in the comparator. A run where one arm
    // reports `cpufreq: NOT pinned` and the other does not is two different noise floors, and the
    // artifact said so the whole time. RED on the inverse (`collect_notes` not called, or
    // `note_asymmetry_warnings` dropped): the notes_by_arm assert or the warning assert fails.
    #[test]
    fn run_comparison_surfaces_each_arms_notes_and_flags_an_asymmetry() {
        let dir = TempDir::new().expect("tempdir");
        let arms = vec![
            arm_fixture(dir.path(), "base", b"vmlinux", b"rootfs-A"),
            arm_fixture(dir.path(), "head", b"vmlinux", b"rootfs-B"),
        ];
        let specs = vec![Spec::new("cloud-hypervisor", "latency")];
        let unpinned = "cpufreq: NOT pinned (need CAP_DAC_OVERRIDE via vmcell-test-runner)";
        let shared = "Warm Restore: backend qemu has no snapshot support; skipping";
        let cmp = run_comparison(&arms, &specs, 4, &mut |arm, _spec, _repeat| {
            let mut report = report_for(arm, 40.0);
            report.notes.push(shared.to_string());
            if arm.label == "base" {
                report.notes.push(unpinned.to_string());
            }
            Ok(report)
        })
        .expect("two honest arms compare");

        // Every arm gets an entry, deduplicated across its repeats — "this arm reported no
        // caveats" and "nobody looked" must not render the same way.
        assert_eq!(
            cmp.notes_by_arm.get("base").map(Vec::as_slice),
            Some([shared.to_string(), unpinned.to_string()].as_slice()),
            "{:?}",
            cmp.notes_by_arm
        );
        assert_eq!(
            cmp.notes_by_arm.get("head").map(Vec::as_slice),
            Some([shared.to_string()].as_slice())
        );

        // The ASYMMETRY is the loud part, and only the asymmetry: the note both arms carry says
        // nothing about the comparison and must not produce a warning, or every capability skip
        // on a machine would shout.
        let asymmetries: Vec<&String> = cmp
            .warnings
            .iter()
            .filter(|w| w.contains("did not"))
            .collect();
        assert_eq!(asymmetries.len(), 1, "{:?}", cmp.warnings);
        let warning = asymmetries.first().expect("the asymmetry warning");
        assert!(warning.contains(unpinned), "{warning}");
        assert!(warning.contains("base"), "{warning}");
        assert!(warning.contains("head"), "{warning}");
        assert!(
            !cmp.warnings.iter().any(|w| w.contains(shared)),
            "a note BOTH arms carry is symmetric and is not a warning: {:?}",
            cmp.warnings
        );

        // …and both halves reach the reader.
        let table = render_table(&cmp);
        assert!(table.contains("notes [base]:"), "{table}");
        assert!(table.contains("notes [head]:"), "{table}");
        assert!(table.contains(unpinned), "{table}");
        let json = serde_json::to_string(&cmp).expect("serialize");
        assert!(json.contains("\"notes_by_arm\""), "{json}");
        assert!(json.contains("cpufreq: NOT pinned"), "{json}");
    }

    // An arm that emits a metric this build has no direction for. Refusing would break the
    // cross-version comparison `bench-ab` exists for, so the row is `no direction` AND loud — the
    // one thing it must never be is a silent "lower is better", which is what the predicate this
    // replaced made it. RED on the inverse (`metric_direction` defaulting to LowerIsBetter, or the
    // warning not threaded into the comparison): the verdict or the warning assert fails.
    #[test]
    fn run_comparison_is_loud_about_a_metric_it_cannot_classify() {
        let dir = TempDir::new().expect("tempdir");
        let arms = vec![
            arm_fixture(dir.path(), "base", b"vmlinux", b"rootfs-A"),
            arm_fixture(dir.path(), "head", b"vmlinux", b"rootfs-B"),
        ];
        let specs = vec![Spec::new("cloud-hypervisor", "latency")];
        let unknown = "a_metric_only_the_other_ref_emits";
        let mut repeat = 0.0_f64;
        let cmp = run_comparison(&arms, &specs, 5, &mut |arm, _spec, _repeat| {
            repeat += 1.0;
            let mut report = report_for(arm, 40.0 + repeat);
            // Fully separated, so a comparator that guessed a direction WOULD print a verdict.
            let value = if arm.label == "base" {
                10.0 + repeat
            } else {
                100.0 + repeat
            };
            report.metrics.push(Metric::new(
                unknown,
                Unit::Count,
                10,
                value,
                value,
                value,
                value,
            ));
            Ok(report)
        })
        .expect("an unknown metric is not a reason to refuse a cross-version comparison");

        let row = cmp
            .rows
            .iter()
            .find(|r| r.metric == unknown)
            .expect("the unknown metric is still compared");
        assert!(!row.direction_declared);
        assert_eq!(row.direction, Direction::Neutral);
        assert_eq!(row.verdict, Verdict::NoDirection);
        assert!(
            row.delta_pct.is_some(),
            "the delta is still reported; only the verdict is withheld"
        );
        // Once per NAME, not once per row, and it names the fix.
        let about: Vec<&String> = cmp
            .warnings
            .iter()
            .filter(|w| w.contains(unknown))
            .collect();
        assert_eq!(about.len(), 1, "{:?}", cmp.warnings);
        assert!(
            about
                .first()
                .is_some_and(|w| w.contains("METRIC_DIRECTIONS")),
            "{:?}",
            about
        );
        // THE POSITIVE CONTROL: the declared metric in the same comparison is judged normally, so
        // a `NoDirection` that fired on everything would not satisfy this test.
        let known = cmp
            .rows
            .iter()
            .find(|r| r.metric == "cold_boot")
            .expect("the declared metric");
        assert!(known.direction_declared);
        assert_ne!(known.verdict, Verdict::NoDirection);
    }

    // ------------------------------------------------------------------------------------
    // `prepare`: the worktree's ref, `--locked`, and the `--report json` probe.
    // ------------------------------------------------------------------------------------

    /// Runs `git <args>` in `dir`, failing loud. Test-local on purpose: the fixture must be able to
    /// build a repository in ways `prepare` never does.
    fn git(dir: &Path, args: &[&str]) -> String {
        let out = ProcCommand::new("git")
            .arg("-C")
            .arg(dir)
            .args(args)
            .output()
            .unwrap_or_else(|e| panic!("cannot spawn git {args:?}: {e}"));
        assert!(
            out.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }

    /// A two-commit repository, each commit carrying a TAG. The second commit adds
    /// `only-in-two.txt`, which is how a test proves the WORKING TREE moved and not merely a ref.
    ///
    /// The tags matter: a test that prepares from a raw sha cannot tell a manifest that RESOLVED
    /// the ref from one that echoed its argument, because those two are the same string. `prepare`
    /// is given the tag; the manifest must name the commit.
    fn two_commit_repo(root: &Path) -> (PathBuf, String, String) {
        let repo = root.join("repo");
        std::fs::create_dir_all(&repo).expect("create repo dir");
        git(&repo, &["init", "-q"]);
        git(&repo, &["config", "user.email", "bench-ab@example.invalid"]);
        git(&repo, &["config", "user.name", "bench-ab test"]);
        git(&repo, &["config", "commit.gpgsign", "false"]);
        // `target/` is ignored the way the real checkout ignores it: `prepare` puts both the
        // worktrees and the staged arms under it.
        std::fs::write(repo.join(".gitignore"), "target/\n").expect("write .gitignore");
        std::fs::write(repo.join("one.txt"), "one").expect("write one.txt");
        git(&repo, &["add", "-A"]);
        git(&repo, &["commit", "-q", "-m", "one"]);
        git(&repo, &["tag", "arm-one"]);
        let one = git(&repo, &["rev-parse", "HEAD"]);
        std::fs::write(repo.join("only-in-two.txt"), "two").expect("write only-in-two.txt");
        git(&repo, &["add", "-A"]);
        git(&repo, &["commit", "-q", "-m", "two"]);
        git(&repo, &["tag", "arm-two"]);
        let two = git(&repo, &["rev-parse", "HEAD"]);
        (repo, one, two)
    }

    /// A `bench-vm --help` that advertises the flag this harness needs.
    const HELP_WITH_REPORT: &str =
        "#!/bin/sh\necho 'Options:\n  --report <REPORT>  text or json'\n";
    /// …and one from a ref that predates it.
    const HELP_WITHOUT_REPORT: &str = "#!/bin/sh\necho 'Options:\n  --backend <BACKEND>'\n";

    /// A `StepRunner` that records every argv and produces the files a real build would, so a whole
    /// `prepare` runs in milliseconds with no toolchain. `help` is what the staged `bench-vm`
    /// prints, which is what the probe reads.
    fn fake_steps(
        help: &'static str,
        log: std::rc::Rc<std::cell::RefCell<Vec<Vec<String>>>>,
    ) -> impl FnMut(&str, &mut ProcCommand) -> anyhow::Result<()> {
        move |_what: &str, cmd: &mut ProcCommand| {
            let program = cmd.get_program().to_string_lossy().into_owned();
            let args: Vec<String> = cmd
                .get_args()
                .map(|a| a.to_string_lossy().into_owned())
                .collect();
            log.borrow_mut().push(
                std::iter::once(program.clone())
                    .chain(args.iter().cloned())
                    .collect(),
            );
            if program == "cargo" {
                let worktree = cmd
                    .get_current_dir()
                    .ok_or_else(|| anyhow::anyhow!("a cargo step must run in the worktree"))?;
                let release = worktree.join("target/release");
                std::fs::create_dir_all(&release)?;
                if args.iter().any(|a| a == "vmcell-bench") {
                    write_script(&release.join("bench-vm"), help);
                } else if args.iter().any(|a| a == "vmcelld") {
                    std::fs::write(release.join("vmcelld"), b"fake vmcelld")?;
                } else if args.iter().any(|a| a == "vmcell-cli") {
                    std::fs::write(release.join("vmcell"), b"fake vmcell CLI")?;
                }
                return Ok(());
            }
            // The arm's own CLI, building the arm's own artifacts.
            let dir = cmd
                .get_envs()
                .find(|(k, _)| *k == std::ffi::OsStr::new("VMCELL_ARTIFACTS_DIR"))
                .and_then(|(_, v)| v)
                .map(PathBuf::from)
                .ok_or_else(|| anyhow::anyhow!("the artifact build must name its artifacts dir"))?;
            std::fs::create_dir_all(&dir)?;
            std::fs::write(dir.join("rootfs.erofs"), b"fake rootfs")?;
            Ok(())
        }
    }

    // THE REUSED WORKTREE. `prepare` reused `<worktree>/.git` without asking where it was, and then
    // recorded `git_ref` from its own ARGUMENT — so re-preparing a label at a new ref rebuilt the
    // OLD tree, measured it, and filed the numbers under the new ref's name. RED on the inverse
    // (reuse keyed on the directory existing, and `git_commit` taken from the argument): the second
    // leg's three asserts fail — the worktree is still at `one`, `only-in-two.txt` is absent, and
    // the manifest names a commit nothing was built from.
    #[test]
    fn prepare_re_checks_out_a_reused_worktree_and_records_the_resolved_commit() {
        let tmp = TempDir::new().expect("tempdir");
        let (repo, one, two) = two_commit_repo(tmp.path());
        let kernel = tmp.path().join("control-vmlinux");
        std::fs::write(&kernel, b"the control kernel").expect("write control kernel");
        let log = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let mut steps = fake_steps(HELP_WITH_REPORT, std::rc::Rc::clone(&log));

        // Prepared from the TAG, not the sha: `git_ref` is a request, `git_commit` is the fact,
        // and passing a raw sha would make the two indistinguishable.
        cmd_prepare(
            &repo,
            "arm-one",
            "base",
            None,
            Some(kernel.clone()),
            &mut steps,
        )
        .expect("prepare at the first commit");
        let manifest_path = repo.join(ARMS_DIR_REL).join("base").join(MANIFEST_NAME);
        let first = ArmManifest::load(&manifest_path).expect("load the manifest");
        assert_eq!(first.git_ref.as_deref(), Some("arm-one"));
        assert_eq!(
            first.git_commit.as_deref(),
            Some(one.as_str()),
            "the manifest must record the RESOLVED commit, not the argument"
        );

        // Re-prepare THE SAME LABEL at a different ref: the worktree exists, so this is the reuse
        // path, and it is the exact scenario that silently measured the old build.
        cmd_prepare(&repo, "arm-two", "base", None, Some(kernel), &mut steps)
            .expect("prepare at the second commit");
        let second = ArmManifest::load(&manifest_path).expect("reload the manifest");
        assert_eq!(
            second.git_commit.as_deref(),
            Some(two.as_str()),
            "a re-prepared label must record the commit it was actually rebuilt from"
        );
        let worktree = repo.join(WORKTREES_DIR_REL).join("base");
        assert_eq!(
            git(&worktree, &["rev-parse", "HEAD"]),
            two,
            "the worktree must be AT the ref the manifest names"
        );
        assert!(
            worktree.join("only-in-two.txt").exists(),
            "the working tree itself must have moved, not just HEAD"
        );
    }

    // AGENTS.md, Docs and dependencies: build `--locked`. An arm is a git ref plus its committed
    // Cargo.lock, and cargo silently re-resolves without the flag — an old ref built against
    // today's dependency versions is the "same code, different numbers" confound this harness
    // exists to remove. RED on the inverse (any `--locked` dropped): the per-argv assert fails.
    #[test]
    fn prepare_builds_every_arm_locked() {
        let tmp = TempDir::new().expect("tempdir");
        let (repo, _one, _two) = two_commit_repo(tmp.path());
        let kernel = tmp.path().join("control-vmlinux");
        std::fs::write(&kernel, b"the control kernel").expect("write control kernel");
        let log = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let mut steps = fake_steps(HELP_WITH_REPORT, std::rc::Rc::clone(&log));
        cmd_prepare(
            &repo,
            "arm-one",
            "base",
            Some("qemu"),
            Some(kernel),
            &mut steps,
        )
        .expect("prepare");

        let calls = log.borrow();
        let cargo: Vec<&Vec<String>> = calls
            .iter()
            .filter(|argv| argv.first().map(String::as_str) == Some("cargo"))
            .collect();
        assert_eq!(cargo.len(), 3, "bench-vm, vmcelld and the CLI: {calls:?}");
        for argv in &cargo {
            assert!(argv.contains(&"--locked".to_string()), "{argv:?}");
            assert!(argv.contains(&"--release".to_string()), "{argv:?}");
        }
        // The features list belongs to `vmcell-bench` alone — cargo refuses a bare `--features`
        // across several packages.
        let with_features: Vec<&&Vec<String>> = cargo
            .iter()
            .filter(|argv| argv.contains(&"--features".to_string()))
            .collect();
        assert_eq!(with_features.len(), 1, "{cargo:?}");
    }

    // AN ARM THAT CANNOT BE COMPARED, refused where it costs seconds instead of where it costs a
    // release build plus a builder micro-VM. RED on the inverse (no probe, or a probe placed after
    // the artifact build): either `prepare` succeeds, or the artifact step appears in the log.
    #[test]
    fn prepare_refuses_an_arm_whose_bench_vm_predates_report_json() {
        let tmp = TempDir::new().expect("tempdir");
        let (repo, _one, _two) = two_commit_repo(tmp.path());
        let kernel = tmp.path().join("control-vmlinux");
        std::fs::write(&kernel, b"the control kernel").expect("write control kernel");
        let log = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let mut steps = fake_steps(HELP_WITHOUT_REPORT, std::rc::Rc::clone(&log));
        let err = cmd_prepare(&repo, "arm-one", "old", None, Some(kernel), &mut steps)
            .expect_err("an arm with no --report json cannot be compared");
        let message = err.to_string();
        assert!(message.contains("--report"), "{message}");
        assert!(message.contains("builder micro-VM"), "{message}");

        let calls = log.borrow();
        assert!(
            !calls.iter().any(|argv| argv.first().is_some_and(
                |p| p.ends_with("/vmcell") && argv.get(1).map(String::as_str) == Some("build")
            )),
            "the refusal must land BEFORE the artifact build: {calls:?}"
        );
        assert!(
            !repo
                .join(ARMS_DIR_REL)
                .join("old")
                .join(MANIFEST_NAME)
                .exists(),
            "no manifest for an arm that cannot run"
        );
    }

    // The probe's predicate, both answers, so the call site above is not the only thing pinning it.
    #[test]
    fn the_report_flag_probe_reads_the_help_text() {
        assert!(help_advertises_report_flag(
            "Options:\n  --report <REPORT>  text or json"
        ));
        assert!(!help_advertises_report_flag(
            "Options:\n  --backend <BACKEND>"
        ));
        assert!(!help_advertises_report_flag(""));
    }

    // A ref that does not resolve is refused by name, before a worktree is created for it.
    #[test]
    fn prepare_refuses_a_ref_that_does_not_resolve() {
        let tmp = TempDir::new().expect("tempdir");
        let (repo, _one, _two) = two_commit_repo(tmp.path());
        let worktree = repo.join(WORKTREES_DIR_REL).join("nope");
        let err = ensure_worktree_at(&repo, &worktree, "no-such-ref")
            .expect_err("an unresolvable ref is an input error");
        assert!(err.to_string().contains("no-such-ref"), "{err}");
        assert!(!worktree.exists(), "nothing is created for a bad ref");
    }

    // The staging location is load-bearing twice over (the runner's `confine_under`, and
    // `bench-vm`'s sibling lookup of `vmcelld`), so the constant is pinned rather than left to be
    // "tidied" into /tmp by a future reader.
    #[test]
    fn arms_are_staged_under_the_head_workspace_target() {
        assert_eq!(ARMS_DIR_REL, "target/ab-arms");
        assert!(
            Path::new(ARMS_DIR_REL).starts_with("target"),
            "the blessed runner refuses to exec a target outside its own workspace target/"
        );
        // The runner default is the justfile's `runner` variable; a drift means `just bless`
        // blesses a copy this harness never invokes.
        assert_eq!(DEFAULT_RUNNER_REL, ".vmcell-bin/debug/vmcell-test-runner");
    }
}
