//! `bench-vm`: the cross-backend macro-benchmark harness (design §16, Performance). The composition
//! root that wires all four backends — Cloud Hypervisor, Firecracker, QEMU, crosvm — behind one
//! `--backend` flag, so a lever is measured the same way everywhere.
//!
//! `print_stdout`/`print_stderr` are intentionally NOT denied here — emitting the measured tables
//! and the per-run report on stdout/stderr is the whole point of a benchmark harness.
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
        // one axis, firing on any `#[must_use]` expression (a detached `JoinHandle`, a discarded
        // `Instant`), which is the same defect one step out: the compiler said this matters and the
        // code said nothing back. Scoped `not(test)` like every lint in this block: the rule's
        // stated harms (a swallowed teardown failure, a lost write, a wedged session) are
        // production harms, and forcing a reason onto a test's `try_init()` would manufacture the
        // hollow suppressions AGENTS.md rule 2 calls theater. `crates/vmcell/tests/lint_roster.rs`
        // is the gate that this line exists in EVERY crate root, so a new crate cannot opt out by
        // being new.
        clippy::let_underscore_must_use,
        clippy::allow_attributes,               // B11: prefer #[expect] over #[allow] in prod code
        clippy::allow_attributes_without_reason  // B11: every suppression states why
    )
)]

use clap::Parser;
use std::collections::BTreeMap;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use std::time::Instant;

use vmcell::HostEnv;
use vmcell::config::{Egress, NetConfig, RestoreMode, RootfsSource, VmConfig};
use vmcell::orchestrator::{MicroVm, VmidAllocator};
use vmcell::steward::protocol::ExecRequest;
use vmcell::steward::session::SessionSpecBuilder;
use vmcell::vmm::{VmInstance, Vmm};
use vmcell_bench::metrics;
use vmcell_bench::report::{BenchReport, BinSource, Metric, REPORT_SCHEMA_VERSION, Unit};

/// Whether the human-readable lines go to stderr instead of stdout. Set ONCE, in `main`, from
/// `--report`.
///
/// WHY A PROCESS-WIDE FLAG. `--report json` promises **one** [`BenchReport`] on stdout, and this
/// harness writes ~100 human lines from a dozen mode functions and a nested helper module. A
/// per-call-site format argument would be a hundred chances to leave one line on stdout, and one
/// stray line is the difference between a parseable report and the 2026-08-21 regex scraping this
/// whole feature exists to retire. The lines are not suppressed — a run that self-skipped half its
/// matrix must still say so — they move to stderr, where the parent reads them as the diagnosis.
static HUMAN_LINES_TO_STDERR: AtomicBool = AtomicBool::new(false); // allow-global-state: the process's OUTPUT STREAM choice, not shared program state — written once in `main` from `--report` before any output and only ever read; it holds no borrowed state and there is nothing for a seam to inject, since the thing it selects (`println!` vs `eprintln!`) is already process-global. The alternative is a format argument threaded through ~100 call sites in a dozen mode functions and a nested helper module, i.e. a hundred chances to leave one line on the stdout that `--report json` promises carries exactly one report

/// Reads the [`HUMAN_LINES_TO_STDERR`] routing decision. `Relaxed` is the whole ordering
/// requirement: the store happens in `main` before any benchmark starts, so no reader races it.
fn human_lines_to_stderr() -> bool {
    HUMAN_LINES_TO_STDERR.load(Ordering::Relaxed)
}

/// Prints one human-readable line, on the stream `--report` selected.
///
/// Every former `println!` in this binary is a `say!`: see [`HUMAN_LINES_TO_STDERR`] for why the
/// choice is one flag rather than a hundred call-site decisions.
macro_rules! say {
    ($($arg:tt)*) => {{
        if crate::human_lines_to_stderr() {
            eprintln!($($arg)*);
        } else {
            println!($($arg)*);
        }
    }};
}

/// What `--report` emits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReportFormat {
    /// The human table this harness has always printed, on stdout. The default: nothing existing
    /// changes shape.
    Text,
    /// One [`BenchReport`] as JSON on stdout, with the human lines on stderr.
    Json,
}

/// Parses `--report`, rejecting anything else at parse time (H-BIN-1) rather than defaulting.
///
/// A silently-defaulted `--report jsonn` would print the text table to a parent expecting JSON,
/// which fails at the parse step with the report's own bytes as the confusing evidence.
fn parse_report_format(s: &str) -> Result<ReportFormat, String> {
    match s {
        "text" => Ok(ReportFormat::Text),
        "json" => Ok(ReportFormat::Json),
        other => Err(format!(
            "invalid report format '{other}' (expected: text, json)"
        )),
    }
}

#[derive(Parser, Debug)]
#[command(author, version, about = "Macro-benchmarking harness for vmcell VMs")]
struct Args {
    #[arg(long, default_value = "cloud-hypervisor")]
    backend: String,

    /// Benchmark mode. `latency` preserves the original cold/warm boot bench.
    /// Others answer the design's open §16 (Performance) questions.
    #[arg(long, default_value = "latency")]
    mode: String,

    /// Iteration count. If unset, defaults to 200 for `vsock-rtt`, else 10.
    #[arg(long)]
    iterations: Option<usize>,

    #[arg(long, default_value_t = 3)]
    warmup: usize,

    /// Number of concurrently-resident guests for `footprint`.
    #[arg(long, default_value_t = 4)]
    count: usize,

    /// Guest RAM in MiB (floor 64). Used by every mode's VM config.
    #[arg(long, default_value_t = 256)]
    mem_mib: u32,

    /// Directory (must be on a real FS, NOT tmpfs) for the `latency` warm-restore,
    /// `suspend-size`, and `phase-budget` snapshots — a RAM-backed tmpfs would
    /// mis-measure suspend size and make warm-restore latency systematically
    /// optimistic (RAM-backed reads; design §16, Performance, snap-dir caveat).
    #[arg(long, default_value = "./target/vmcell-bench-snap")]
    snap_dir: String,

    /// Memory-restore strategy for the warm-restore path (CH `prefault`):
    /// `default` (VMM default), `eager` (`prefault=on`), or `lazy`
    /// (`prefault=off`, userfaultfd demand-paging). Drives the §16 (Performance)
    /// eager-vs-lazy benchmark; harmless for non-restore modes.
    #[arg(long, default_value = "default", value_parser = parse_restore_mode)]
    restore_mode: RestoreMode,

    /// Mark guest memory KSM-mergeable (CH `mergeable=on`, implies `shared=off`)
    /// so the `footprint` mode can measure KSM dedup (§16, Performance). Off by default.
    #[arg(long, default_value_t = false)]
    ksm_mergeable: bool,

    /// Kernel-version label to benchmark — selects `vmlinux-<label>` from
    /// `VMCELL_ARTIFACTS_DIR` (built by `vmcell build-kernels <label>`). Omit to use the
    /// default `vmlinux`. This is the kernel-version benchmark dimension.
    #[arg(long)]
    kernel: Option<String>,

    /// Timeouts profile: `default` (balanced), `low-latency` (min time-to-output),
    /// or `throughput` (min whole-lifecycle incl. teardown). Selects the
    /// `Timeouts` preset applied to every VM in the run. An unknown value is
    /// rejected at parse time (no silent default — H-BIN-1).
    #[arg(long, default_value = "default", value_parser = parse_profile)]
    profile: String,

    /// Guest kernel console verbosity: `balanced` (default, `loglevel=6`),
    /// `quiet` (3), `verbose` (7), or `debug` (8). Drives the serial-logging
    /// VM-exit cost dimension. An unknown value is rejected at parse time.
    #[arg(long, default_value = "balanced", value_parser = parse_verbosity)]
    kernel_verbosity: vmcell::config::KernelVerbosity,

    /// Guest console mode: `uart` (default, 8250 `ttyS0` — early-boot + panic
    /// capture, per-byte VM-exits) or `virtio-console` (`hvc0` — batched, ~no exit
    /// tax, but loses early boot / pre-virtio panics; not supported on Firecracker).
    /// An unknown value is rejected at parse time.
    #[arg(long, default_value = "uart", value_parser = parse_console)]
    console: vmcell::config::ConsoleMode,

    /// `net-egress` variant: `plain` (unprivileged smoltcp NAT + `Egress::Open` to a
    /// host responder — the datapath cost), `tls` (unprivileged smoltcp + `Egress::Filtered`
    /// MITM proxy, HTTPS-through-proxy — the per-connection cert-mint + guest↔proxy TLS
    /// handshake cost), or `privileged` (tap + netns + nft + `Egress::Filtered` — the
    /// privileged networked-start cost + the same MITM egress). `tls`/`privileged` need the
    /// `proxy` feature; `privileged` needs CAP_NET_ADMIN (self-skips otherwise). Ignored by
    /// other modes. An unknown value is rejected at parse time.
    #[arg(long, default_value = "plain", value_parser = parse_net_mode)]
    net_mode: String,

    /// Output format: `text` (default — the human table, unchanged) or `json` (one
    /// machine-readable `BenchReport` on stdout, with every human line on stderr).
    ///
    /// `json` exists because the 2026-08-21 A/B driver scraped this harness's table with regexes,
    /// and three of them broke in ways that produced a plausible float rather than an error:
    /// crosvm's log spam interleaved with the rows, the `Cold Boot (WARM-CACHE: …)` parenthetical
    /// moved the value's column, and the padded phase names shifted the split. An unknown value is
    /// rejected at parse time.
    #[arg(long, default_value = "text", value_parser = parse_report_format)]
    report: ReportFormat,
}

/// Validates the `--profile` flag, rejecting any value other than `default`,
/// `low-latency`, or `throughput` (H-BIN-1). Returns the validated name unchanged so
/// the run header can echo it; [`timeouts_for`] maps it to the preset.
fn parse_profile(s: &str) -> Result<String, String> {
    match s {
        "default" | "low-latency" | "throughput" => Ok(s.to_string()),
        other => Err(format!(
            "invalid profile '{other}' (expected: default, low-latency, throughput)"
        )),
    }
}

/// Maps the (already-validated by [`parse_profile`]) `--profile` name to a
/// [`Timeouts`](vmcell::config::Timeouts) preset.
fn timeouts_for(profile: &str) -> vmcell::config::Timeouts {
    match profile {
        "low-latency" => vmcell::config::Timeouts::low_latency(),
        "throughput" => vmcell::config::Timeouts::throughput(),
        // Only `"default"` reaches here for a validated flag; the catch-all keeps
        // the mapping total (the CLI value_parser is the actual gate).
        _ => vmcell::config::Timeouts::default(),
    }
}

/// Parses the `--kernel-verbosity` flag into a
/// [`KernelVerbosity`](vmcell::config::KernelVerbosity), rejecting unknown values
/// (H-BIN-1) instead of silently defaulting to `Balanced`.
fn parse_verbosity(s: &str) -> Result<vmcell::config::KernelVerbosity, String> {
    use vmcell::config::KernelVerbosity as K;
    match s {
        "quiet" => Ok(K::Quiet),
        "balanced" => Ok(K::Balanced),
        "verbose" => Ok(K::Verbose),
        "debug" => Ok(K::Debug),
        other => Err(format!(
            "invalid kernel-verbosity '{other}' (expected: quiet, balanced, verbose, debug)"
        )),
    }
}

/// Parses the `--console` flag into a [`ConsoleMode`](vmcell::config::ConsoleMode),
/// rejecting unknown values (H-BIN-1) instead of silently defaulting to `Uart`.
fn parse_console(s: &str) -> Result<vmcell::config::ConsoleMode, String> {
    use vmcell::config::ConsoleMode as C;
    match s {
        "uart" => Ok(C::Uart),
        "virtio-console" => Ok(C::VirtioConsole),
        other => Err(format!(
            "invalid console '{other}' (expected: uart, virtio-console)"
        )),
    }
}

/// Validates `--net-mode` (the `net-egress` variant selector), rejecting unknown values
/// at parse time (H-BIN-1) instead of silently defaulting.
fn parse_net_mode(s: &str) -> Result<String, String> {
    match s {
        "plain" | "tls" | "privileged" => Ok(s.to_string()),
        other => Err(format!(
            "invalid net-mode '{other}' (expected: plain, tls, privileged)"
        )),
    }
}

/// The run-header line echoing the resolved `--profile`/`--kernel-verbosity`/
/// `--console` knobs (H-BIN-1), so a run's actual configuration is visible rather
/// than silently defaulted.
fn resolved_knobs_line(args: &Args) -> String {
    format!(
        "profile: {}  kernel-verbosity: {:?}  console: {:?}",
        args.profile, args.kernel_verbosity, args.console
    )
}

/// Parses the `--restore-mode` flag into a [`RestoreMode`], rejecting any value
/// other than `default`, `eager`, or `lazy`.
fn parse_restore_mode(s: &str) -> Result<RestoreMode, String> {
    match s {
        "default" => Ok(RestoreMode::Default),
        "eager" => Ok(RestoreMode::Eager),
        "lazy" => Ok(RestoreMode::Lazy),
        other => Err(format!(
            "invalid restore mode '{other}' (expected: default, eager, lazy)"
        )),
    }
}

impl Args {
    /// Effective iteration count, applying the per-mode default when unset.
    fn iters(&self) -> usize {
        self.iterations
            .unwrap_or(if self.mode == "vsock-rtt" { 200 } else { 10 })
    }
}

/// THE ONE SPELLING of "how many measurement iterations produced no sample": what the mode set
/// out to take, minus what it collected.
///
/// WHY A SUBTRACTION AND NOT A COUNTER. It shipped as a `dropped += 1` per failure arm, and every
/// loop that gives up on a failed boot walks straight past the increment: `run_bench`'s
/// create/restore arm `break`s, so do the vsock and both egress RTT loops, `phase_budget_path`
/// passed a literal `0` for both counts, and `zygote`'s steward-ready row passed a literal `0`
/// beside a live counter. So the ONE failure mode this accounting exists for — a boot that failed,
/// which is disproportionately a SLOW boot — reported `dropped = 0` over a truncated sample set,
/// and `bench-ab`'s `SampleLoss` verdict, whose entire job is to refuse a verdict over exactly
/// that survivorship bias, stayed green on the arm that was losing samples. A `break` cannot walk
/// past a subtraction.
///
/// `saturating_sub` rather than a panic: a mode that collected more than it planned is a bug in
/// the caller's own bookkeeping, and aborting a completed matrix over it would destroy the numbers
/// that would let anyone diagnose it. It reads as "nothing dropped", which the sample count beside
/// it contradicts loudly.
fn dropped_iterations(planned: usize, collected: usize) -> usize {
    planned.saturating_sub(collected)
}

/// Formats the trailing `dropped=/warmup_failed=` accounting for a report line so a
/// silently-shrunk sample count is visible (H-BIN-2). Empty when nothing was dropped.
fn accounting_suffix(dropped: usize, warmup_failed: usize) -> String {
    if dropped == 0 && warmup_failed == 0 {
        String::new()
    } else {
        format!(" dropped={dropped} warmup_failed={warmup_failed}")
    }
}

/// One measured sample as the report carries it.
///
/// A latency is a `u128` of whole µs/ms and the report is `f64`, so the conversion happens in one
/// named place rather than at forty `as` sites. Lossless below 2^53 — a sample large enough to lose
/// a digit here is ~285 million years, and a benchmark that ran that long has a different problem.
fn sample_as_f64(v: u128) -> f64 {
    v as f64
}

/// Everything a run measured, in the shape [`BenchReport`] carries.
///
/// WHY A COLLECTOR AND NOT TWO FORMATTERS. `--report text` and `--report json` must not be able to
/// disagree about a value, and the way two renderers disagree is that one of them is edited. So
/// there is exactly one place a number is computed — [`Recorder::measure`] / [`Recorder::scalar`],
/// both of which RETURN what they recorded — and every human line prints the returned metric's own
/// fields. A row and its JSON field are then the same `f64` by construction, not by review.
///
/// The 2026-08-21 pass is the defect history: its driver re-derived the table's numbers with
/// regexes, and the numbers it got were not the numbers the harness had measured.
struct Recorder {
    /// Poison-tolerant because a lock poisoned by a panicking benchmark still holds the samples
    /// collected before the panic, and this harness's own panic path (`MicroVm::Drop`) is a
    /// teardown, not a data corruption.
    inner: std::sync::Mutex<Collected>,
}

/// The mutable half of a [`Recorder`].
#[derive(Default)]
struct Collected {
    metrics: Vec<Metric>,
    notes: Vec<String>,
    /// Names recorded that [`metrics::METRIC_DIRECTIONS`] does not carry — see
    /// [`Recorder::register`].
    unregistered: std::collections::BTreeSet<String>,
}

impl Recorder {
    fn new() -> Self {
        Self {
            inner: std::sync::Mutex::new(Collected::default()),
        }
    }

    /// Runs `f` against the collected state, recovering a poisoned lock rather than propagating it.
    fn with<R>(&self, f: impl FnOnce(&mut Collected) -> R) -> R {
        match self.inner.lock() {
            Ok(mut guard) => f(&mut guard),
            // A previous panic poisoned the lock. The data behind it is still every sample taken
            // before that panic, and dropping it would turn one failed iteration into a run with no
            // report at all.
            Err(poisoned) => f(&mut poisoned.into_inner()),
        }
    }

    /// Notes a metric name the direction roster does not carry.
    ///
    /// WHY THE EMITTER REFUSES AND THE COMPARATOR DOES NOT. `bench-ab` compares two git refs, so a
    /// metric the *other* ref emits and this build has never heard of is the tool working; it
    /// degrades that to a loud `Neutral`. But a metric THIS tree emits with no entry in
    /// `vmcell_bench::metrics::METRIC_DIRECTIONS` is a hole in the roster, and the pre-fix
    /// comparator turned exactly that hole into a silent "lower is better" — which prints
    /// IMPROVEMENT when a benefit gets worse. So every name goes through here, and
    /// [`refuse_unregistered_metrics`] stops the report before it can be compared.
    ///
    /// Recorded rather than panicked: this runs after a full matrix of VM boots, and the human
    /// lines on stderr are still the run's diagnosis. The refusal happens once, at the exit, and
    /// names every offender instead of the first one.
    fn register(&self, name: &str) {
        if metrics::direction(name).is_none() {
            self.with(|c| c.unregistered.insert(name.to_string()));
        }
    }

    /// Every metric name recorded that the direction roster does not carry, sorted.
    fn unregistered_metrics(&self) -> Vec<String> {
        self.with(|c| c.unregistered.iter().cloned().collect())
    }

    /// Computes a metric's percentiles ONCE (through the shared nearest-rank [`pcts`]), records it,
    /// and hands it back for the caller's text line. `None` when there were no samples.
    ///
    /// `name` is the stable snake_case identifier a comparator keys on — never the display label,
    /// which carries padding, the `(WARM-CACHE: …)` parenthetical and the backend in parentheses.
    ///
    /// `planned` is how many MEASUREMENT iterations the mode set out to take (post-warmup), and
    /// the metric's `dropped` count is derived from it through [`dropped_iterations`] rather than
    /// accepted from the caller — see that function for the four call sites whose hand-kept
    /// counters were walked past by a `break` or written as a literal `0`.
    fn measure(
        &self,
        name: &str,
        unit: Unit,
        samples: &mut [u128],
        planned: usize,
        warmup_failed: usize,
    ) -> Option<Metric> {
        self.register(name);
        let dropped = dropped_iterations(planned, samples.len());
        let (p50, p95, p99, max) = pcts(samples)?;
        let metric = Metric::new(
            name,
            unit,
            samples.len(),
            sample_as_f64(p50),
            sample_as_f64(p95),
            sample_as_f64(p99),
            sample_as_f64(max),
        )
        .with_dropped(dropped)
        .with_warmup_failed(warmup_failed);
        self.with(|c| c.metrics.push(metric.clone()));
        Some(metric)
    }

    /// Records a single number (a footprint total, a snapshot size, a share) and returns it, so the
    /// text line that prints it reads the recorded value rather than recomputing one beside it.
    ///
    /// A scalar carries the same value in all four percentile fields: the report has one metric
    /// shape, and a consumer that compares `p50` across arms then works uniformly instead of
    /// special-casing "this kind has no distribution". `n` is what the number summarises (the guest
    /// count, the sample count), so a per-guest mean over three guests is not read as one over ten.
    fn scalar(&self, name: &str, unit: Unit, n: usize, value: f64) -> f64 {
        self.register(name);
        self.with(|c| {
            c.metrics
                .push(Metric::new(name, unit, n, value, value, value, value));
        });
        value
    }

    /// Records a note verbatim (a self-skip, a capability refusal, an honesty caveat).
    fn note(&self, text: impl Into<String>) {
        self.with(|c| c.notes.push(text.into()));
    }

    /// Prints a caveat AND records it, through one call so the two cannot diverge — `None` is a
    /// run with nothing to disclose.
    ///
    /// A run that skipped half its matrix and a run that measured all of it must not be
    /// indistinguishable in the JSON artifact — that is the "control silently did not apply" shape
    /// of the 2026-08-21 defect, one layer up: the numbers were there, the reason they were the
    /// wrong numbers was not. Four caveats shipped as bare `say!`s inside an `if` at their call
    /// site and reached no report at all: the tmpfs snap-dir warning, the KSM acceleration
    /// refusal, the incomplete host-pid attribution, and the zygote's full-copy fan-out. Each one
    /// answers "are these two arms comparable", which is the one question the JSON exists for.
    ///
    /// It takes an `Option` because the DECISION belongs in a named composer (see
    /// [`snap_dir_tmpfs_caveat`] and its siblings), not in an `if` beside the printing: a
    /// condition spelled at the call site is a condition no test drives, which is exactly how
    /// these four came to be printed and never recorded.
    fn caveat(&self, text: Option<String>) {
        if let Some(text) = text {
            say!("{text}");
            self.note(text);
        }
    }

    /// A self-skip / capability refusal — a caveat whose condition is "the facility was absent",
    /// already decided by the caller's own capability probe. One body ([`Recorder::caveat`]), two
    /// names, because a skip reads as a skip at its thirteen call sites.
    fn skip(&self, text: String) {
        self.caveat(Some(text));
    }

    /// Everything collected, in emission order.
    fn drain(&self) -> (Vec<Metric>, Vec<String>) {
        self.with(|c| (std::mem::take(&mut c.metrics), std::mem::take(&mut c.notes)))
    }
}

/// THE CAVEAT COMPOSERS. Each answers "does this run have something to disclose about the numbers
/// it is about to print", and each is the entire decision — the call site is
/// `rec.caveat(<composer>(…))` with no `if` of its own, so every arm of the decision is reachable
/// from a unit test and the printed text and the recorded note are one string by construction.
/// `bench-vm`'s own call-site scan (`every_caveat_is_recorded_not_just_printed`) is what keeps
/// that shape; the class it closes is four caveats that printed and reached no report.
///
/// The warm-restore snapshot directory is RAM-backed, so the restore latency about to be measured
/// is optimistic (§16, Performance, snap-dir caveat). `None` when this is not a restore run (the
/// snapshot directory does not shape a cold-boot number) or when the directory is on a real
/// filesystem.
fn snap_dir_tmpfs_caveat(snap_dir: &Path, is_restore: bool, on_tmpfs: bool) -> Option<String> {
    (is_restore && on_tmpfs).then(|| {
        format!(
            "warning: snap-dir {} is on tmpfs; warm-restore latency will be optimistic (§16, \
             Performance) — an arm measured here is not comparable against one whose snapshots \
             went to a real filesystem",
            snap_dir.display()
        )
    })
}

/// The KSM scanner could not be accelerated, so the dedup window may not have converged.
///
/// This one qualifies a metric whose direction is INVERTED: `footprint_ksm_pages_sharing_delta` is
/// the roster's HigherIsBetter entry, so an arm that failed to accelerate the scanner reports a
/// smaller delta — which the comparator reads as the change having deduplicated less. Without the
/// note in the report, the reader cannot tell that from a real regression.
fn ksm_acceleration_caveat(accelerated: bool) -> Option<String> {
    (!accelerated).then(|| {
        format!(
            "footprint: WARN could not accelerate KSM (need CAP_DAC_OVERRIDE via the runner); \
             dedup may be partial, so `{}` under-reports here",
            metrics::FOOTPRINT_KSM_PAGES_SHARING_DELTA
        )
    })
}

/// The KSM scanner knobs were restored but the pages merged during this run stay merged (N-BIN-2).
///
/// A note rather than a line that scrolls away because of what `bench-ab` does with these runs: it
/// INTERLEAVES two arms on one host, so the merges this arm caused are part of the next arm's
/// starting state. `None` when the mergeable lever was off and nothing was merged.
fn ksm_residue_caveat(mergeable: bool) -> Option<String> {
    mergeable.then(|| {
        "KSM note: the scanner knobs were restored, but pages merged during this run stay merged \
         (host KSM state is not fully reset), so a later arm on this host starts from a partly \
         deduplicated baseline"
            .to_string()
    })
}

/// Fewer host PIDs resolved than guests booted, so the per-VM memory totals are deflated
/// (M-BIN-7). `None` when every guest's PID was resolved.
fn pid_attribution_caveat(resolved: usize, guests: usize) -> Option<String> {
    (resolved < guests).then(|| {
        format!(
            "footprint: warning — resolved {resolved}/{guests} host pids; per-VM memory \
             attribution is incomplete, so every total below is a floor"
        )
    })
}

/// The zygote fan-out paid a full byte copy per clone instead of a reflink. `None` on a reflinking
/// filesystem, which is the configuration the published fan-out numbers assume.
///
/// A full-copy fan-out and a reflinked one differ by the size of the suspend image per clone, so
/// two arms that disagree about this are not measuring the same operation — and nothing in the
/// numbers themselves says which one happened.
fn zygote_cow_caveat(cow: vmcell::CowSupport) -> Option<String> {
    (!cow.is_reflink()).then(|| {
        format!(
            "zygote: CoW is {cow:?}, so every clone paid a full byte copy of the suspend image \
             (reflink needs $TMPDIR and the master on one reflink-capable fs); fan-out numbers \
             here are not comparable against an arm that reflinked"
        )
    })
}

/// Reports p50/p95/p99/max for a sample set, collapsed onto the single [`pcts`]
/// helper (L-BIN-7) instead of a duplicate hand-rolled `floor` index that lacked the
/// nearest-rank clamp (H-BIN-1-revisited). `dropped`/`warmup_failed` surface any
/// iterations discarded during collection.
///
/// `name` is the human label (it carries the `(WARM-CACHE: …)` parenthetical) and `metric` is the
/// stable identifier the JSON report keys on; the printed numbers are the recorded metric's own
/// fields, so the row and the field cannot drift apart. This row is milliseconds on both of its
/// call sites, which is why the unit is fixed here rather than passed.
///
/// `planned` is the post-warmup iteration count the mode set out to take; the printed suffix and
/// the recorded metric read the loss out of the same [`dropped_iterations`] law, so the row and
/// the JSON field cannot disagree about how lossy the run was either.
fn report(
    rec: &Recorder,
    name: &str,
    metric: &str,
    latencies: &mut [u128],
    planned: usize,
    warmup_failed: usize,
) {
    let acct = accounting_suffix(dropped_iterations(planned, latencies.len()), warmup_failed);
    match rec.measure(metric, Unit::Millis, latencies, planned, warmup_failed) {
        Some(m) => say!(
            "{name}: count={}{acct} p50={}ms p95={}ms p99={}ms max={}ms",
            m.n,
            m.p50,
            m.p95,
            m.p99,
            m.max
        ),
        None => say!("{name}: No successful runs{acct}"),
    }
}

/// The three ways this harness discards a `Result` on purpose, as three named functions instead of
/// fifty-odd bare `let _ =` statements (AGENTS.md "Fail loud", and its Suppressions rule: *route
/// repeated legitimate sites through one helper so one suppression covers the class*).
///
/// Each is a real class, not a spelling convenience. Two of the three stop discarding altogether
/// and REPORT instead — a benchmark that silently failed to tear a VM down, or to remove the
/// snapshot dir the next run's warm-restore reads, produces numbers nobody can explain, which is
/// the harness-specific shape of the defect the rule is about. The third keeps the discard and
/// carries the single suppression for its whole class, with the reason stated at the statement.
mod best_effort {
    use super::{MicroVm, Vmm};
    use std::path::Path;

    /// Tears a benchmark VM down on a path whose outcome is **already decided** — an error is
    /// about to be reported, or the sample has already been taken.
    ///
    /// Discarding is correct because [`MicroVm`]'s `Drop` is the guaranteed teardown: a failed
    /// `shutdown()` has not leaked anything, it has only skipped the graceful half. It is still
    /// *reported*, because a run whose VMs all failed to shut down gracefully is a run whose
    /// teardown numbers mean something different.
    ///
    /// One call site (`phase_budget_path`) times this call. Printing inside that window costs
    /// microseconds — but only on the failure path, where the sample is already anomalous.
    pub(super) async fn shutdown<V: Vmm>(vm: MicroVm<V>) {
        if let Err(e) = vm.shutdown().await {
            say!("warning: graceful VM shutdown failed ({e}); Drop is the real teardown");
        }
    }

    /// Removes a scratch directory this harness owns — a snapshot dir, a zygote master — either
    /// before creating it or after the numbers are collected.
    ///
    /// Discarding is correct because the expected outcome is `NotFound`: the pre-clean runs before
    /// anything exists, and the post-run clean races nothing. Anything *else* is reported, so a
    /// snapshot dir that could not be removed cannot silently make the next run's warm-restore
    /// numbers a stale image's.
    pub(super) fn discard_dir(dir: &Path) {
        match std::fs::remove_dir_all(dir) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => say!("warning: could not remove {}: {e}", dir.display()),
        }
    }

    /// Serves one canned HTTP response on `conn`, best-effort.
    ///
    /// Discarding is correct because the *client* is the measurement: curl in the guest reports
    /// what it got, and a peer that hung up mid-response is a datum this side cannot improve on.
    /// The read is bounded first so a peer that connects and says nothing cannot wedge the
    /// responder thread.
    pub(super) fn serve_canned_response(conn: &mut std::net::TcpStream, head: &str, body: &[u8]) {
        use std::io::{Read, Write};
        let mut scratch = [0u8; 1024];
        // ONE suppression for the whole class, which is the point of the helper. Reporting here
        // would print once per benchmarked request on a `Connection: close` responder — noise on
        // stdout, which is where the measured tables go.
        #[expect(
            clippy::let_underscore_must_use,
            reason = "the guest-side curl is the measurement; a peer that hung up mid-response is a datum this side cannot improve on"
        )]
        let _ = conn
            .set_read_timeout(Some(std::time::Duration::from_millis(500)))
            .and_then(|()| conn.read(&mut scratch))
            .and_then(|_| conn.write_all(head.as_bytes()))
            .and_then(|()| conn.write_all(body))
            .and_then(|()| conn.flush());
    }
}

async fn run_bench<V: Vmm>(
    vmm: &V,
    rec: &Recorder,
    name: &str,
    metric: &str,
    args: &Args,
    allocator: VmidAllocator,
    is_restore: bool,
) -> anyhow::Result<()> {
    say!("Starting benchmark: {name}");
    let mut latencies = Vec::new();

    // L-BIN-7: resolve artifact paths and build the VM config through the SAME
    // helpers every other mode uses, instead of a hand-rolled duplicate that could
    // drift (it lacked `ksm_mergeable`, and re-derived the config knobs).
    let (dir, kernel_path, rootfs_path) = artifact_paths(args.kernel.as_deref())?;

    require_artifacts(name, &dir, &kernel_path, &rootfs_path)?;

    let cfg = build_cfg(args, kernel_path, rootfs_path, false, is_restore);
    let mut env = HostEnv::hermetic();
    env.vmids = allocator.clone();

    // CLI-5 / N-BIN-5: honor `--snap-dir` for the warm-restore snapshot, resolved on
    // the workspace root (not the process CWD) so it lands on the same real FS as the
    // artifacts, instead of `temp_dir()` (commonly tmpfs / RAM-backed), which makes
    // warm-restore latency systematically optimistic (§16, Performance, snap-dir caveat).
    let snap_dir = resolve_snap_dir(&args.snap_dir).join(format!(
        "latency-{}-{}",
        args.backend,
        std::process::id()
    ));
    rec.caveat(snap_dir_tmpfs_caveat(
        &snap_dir,
        is_restore,
        is_tmpfs(&snap_dir),
    ));
    // Best-effort pre-clean of a stale snapshot dir left by a prior aborted run; a
    // missing dir (the common case) is not an error worth surfacing.
    best_effort::discard_dir(&snap_dir);

    if is_restore {
        say!("Creating baseline snapshot for restore benchmark...");
        let mut base_vm = match MicroVm::start(vmm, cfg.clone(), &env).await {
            Ok(vm) => vm,
            // M-BIN-1: a baseline-snapshot failure is an attempted-and-failed run, not
            // a skip — fail loud so it can't masquerade as success.
            Err(e) => anyhow::bail!("{name}: failed to start base VM for snapshotting: {e}"),
        };
        if let Err(e) = base_vm.steward(None).await {
            // Best-effort graceful teardown of the base VM; `MicroVm::Drop` is the
            // real, guaranteed teardown, so a shutdown error is not actionable here.
            best_effort::shutdown(base_vm).await;
            anyhow::bail!("{name}: failed to connect to base VM steward: {e}");
        }
        if let Err(e) = std::fs::create_dir_all(&snap_dir) {
            // Best-effort teardown of the booted base VM before bailing.
            best_effort::shutdown(base_vm).await;
            anyhow::bail!(
                "{name}: cannot create snapshot dir {}: {e}",
                snap_dir.display()
            );
        }
        if let Err(e) = base_vm.snapshot(&snap_dir).await {
            // Best-effort cleanup on the snapshot-failure path: shut the base VM down
            // (Drop is the real teardown) and drop the partial snapshot dir.
            best_effort::shutdown(base_vm).await;
            best_effort::discard_dir(&snap_dir);
            anyhow::bail!("{name}: failed to take snapshot of base VM: {e}");
        }
        // Best-effort graceful shutdown of the base VM now that the snapshot is taken;
        // `MicroVm::Drop` guarantees the real teardown regardless.
        best_effort::shutdown(base_vm).await;
    }

    // Tracks whether every cold-boot iteration managed to drop the page cache.
    // M-BIN-8: under the file-cap runner (euid != 0) the `drop_caches` write is
    // silently ineffective (the procfs sysctl permission is euid-based), so
    // `drop_page_cache` verifies via a `Cached`-drop check rather than trusting the
    // write. If any iteration could not actually drop the cache, the cold numbers are
    // warm-cache and the label says so instead of mislabeling them.
    let mut page_cache_dropped = true;
    // H-BIN-2: post-warmup steward-connect failures shrink the sample set — count and
    // print them (with the iteration + error) instead of letting the count silently
    // drop. Warmup failures are tracked separately since they never count as samples.
    let mut warmup_failed = 0usize;

    for i in 0..(args.iters() + args.warmup) {
        if !is_restore && !drop_page_cache() {
            page_cache_dropped = false;
        }

        let start = Instant::now();
        let vm_res = if is_restore {
            MicroVm::restore(vmm, &snap_dir, cfg.clone(), &env).await
        } else {
            MicroVm::start(vmm, cfg.clone(), &env).await
        };

        match vm_res {
            Ok(mut vm) => {
                match vm.steward(None).await {
                    Ok(_steward) => {
                        let elapsed = start.elapsed().as_millis();
                        if i >= args.warmup {
                            latencies.push(elapsed);
                        }
                    }
                    Err(e) => {
                        // H-BIN-2: a silent `if let Ok(_steward)` hid steward-connect
                        // failures; surface each and account for the discarded sample.
                        say!("{name}: iteration {i} steward-connect failed: {e}");
                        if i < args.warmup {
                            warmup_failed += 1;
                        }
                        // No post-warmup counter: `dropped_iterations(planned, collected)` at the
                        // report below derives the loss, and derives it for the `break` arm too.
                    }
                }
                // Best-effort per-iteration teardown; `Drop` is the guaranteed path,
                // and a shutdown error must not corrupt the latency sample above.
                best_effort::shutdown(vm).await;
            }
            Err(e) => {
                say!("{name}: iteration {i} create/restore failed: {e}");
                break;
            }
        }
    }

    if is_restore {
        // Best-effort cleanup of the baseline snapshot dir after the run; a removal
        // failure is not worth aborting the (already-collected) report for.
        best_effort::discard_dir(&snap_dir);
    }

    let label = bench_label(name, is_restore, page_cache_dropped);
    // The WARM-CACHE annotation is a note, not just a label: `metric` is the stable identifier a
    // comparator keys on, so the caveat would otherwise vanish from the JSON entirely — and an arm
    // that could drop the page cache compared against one that could not is precisely the
    // silently-inapplicable control this harness exists to make visible.
    if label != name {
        rec.note(label.clone());
    }
    // `args.iters()`, NOT `dropped`: the parameter is the PLANNED count and `dropped_iterations`
    // subtracts the survivors from it. Passing the loss counter here made `saturating_sub` floor to
    // zero on every realistic run, so a run that lost three of ten reported `dropped=0` — and a
    // comparator that cannot see the loss ranks a lossy arm against a whole one (a failed boot is
    // disproportionately a SLOW boot, so the lossy arm looks faster).
    report(
        rec,
        &label,
        metric,
        &mut latencies,
        args.iters(),
        warmup_failed,
    );

    // M-BIN-1: attempted the run but collected zero post-warmup samples → fail loud so
    // automation sees a non-zero exit instead of a silent "No successful runs".
    if latencies.is_empty() {
        anyhow::bail!("{name}: no successful post-warmup samples");
    }
    Ok(())
}

/// Returns the report label, annotating a cold-boot benchmark whose page cache
/// could not be dropped — those latencies are warm-cache (systematically
/// optimistic), not cold, so they must not be reported as plain "cold".
fn bench_label(base: &str, is_restore: bool, page_cache_dropped: bool) -> String {
    if !is_restore && !page_cache_dropped {
        format!("{base} (WARM-CACHE: drop_caches unavailable — run as root for cold numbers)")
    } else {
        base.to_string()
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // Fail loud and early on a misinvocation, before any side effects (CPU-freq
    // pinning, booting). An unknown/feature-disabled `--backend`, an unknown
    // `--mode`, or an out-of-floor `--mem-mib` must exit non-zero — not print a
    // notice and silently succeed (M-CLI-1), and not panic at a `.build()`
    // `.expect()` site with a misleading "benchmark invariant" message (P22).
    validate_backend(&args.backend)?;
    validate_mode(&args.mode)?;
    validate_daemon_api_knobs(&args)?;
    validate_vm_params(&args)?;

    // ONE store, before the first `say!`: `--report json` owns stdout for the machine-readable
    // report, so every human line in this process moves to stderr. Set here, after validation
    // (whose refusals are clap's/anyhow's own stderr) and before any output of ours.
    if args.report == ReportFormat::Json {
        HUMAN_LINES_TO_STDERR.store(true, Ordering::Relaxed);
    }
    let rec = Recorder::new();

    // Resolve the §10.4 artifact contract here too, before any side effect: a `--kernel <label>`
    // that contradicts a `$VMCELL_KERNEL` redirect must exit non-zero at the boundary, not after
    // the CPU-freq pin and a mode's first boot. The modes re-resolve (it is pure); this call is
    // the early refusal AND the source of the attribution line below.
    let (artifacts_dir, kernel, rootfs) = artifact_paths(args.kernel.as_deref())?;

    // Resolved here rather than beside the line that prints it, because the `daemon-api` branch
    // below returns before that line and the report needs the pair on EVERY path. Honest for that
    // mode too: the `vmcelld` this spawns inherits this process's environment and resolves Cloud
    // Hypervisor through the same `$VMCELL_CH_BIN` (`vmcell::artifact::ch_binary_path`), and
    // `validate_daemon_api_knobs` has already refused any other backend for it.
    let (vmm_bin, vmm_bin_source) = vmm_binary(&args.backend)?;

    say!("Running benchmarks with backend: {}", args.backend);
    // The RESOLVED paths, not a re-derived filename: with `$VMCELL_KERNEL`/`$VMCELL_ROOTFS` set,
    // the files this run boots are not under the artifacts dir at all, and a run's attribution
    // must name what it actually measured (`bench-ignores-contract-artifact-overrides`).
    say!(
        "kernel: {} (label={})",
        kernel.display(),
        args.kernel.as_deref().unwrap_or("default")
    );
    say!("rootfs: {}", rootfs.display());
    say!("artifacts dir: {artifacts_dir}");
    // H-BIN-1: echo the resolved profile/verbosity/console so a run's actual knobs
    // are visible (and provably not silently defaulted from a rejected typo).
    say!("{}", resolved_knobs_line(&args));

    // Pin CPU frequency for the whole run (design §16, Performance, noise floor): every online
    // CPU is set to the `performance` governor with turbo disabled, and the prior
    // settings are restored when this guard drops — including on panic. Held until
    // `main` returns. Degrades to a logged no-op without CAP_DAC_OVERRIDE, so run
    // through `vmcell-test-runner` (or as root) to actually pin.
    let _freq_pin =
        match vmcell::cpufreq::CpuFreqPin::engage(vmcell::cpufreq::SysfsCpuFreq::system()) {
            Ok(pin) if pin.is_pinned() => {
                say!(
                    "cpufreq: pinned {} CPU(s) to `performance` + turbo off (restored on exit)",
                    pin.pinned_cpus()
                );
                Some(pin)
            }
            Ok(pin) => {
                // A NOTE, not just a line: an arm whose CPUs were pinned compared against one
                // whose were not is a comparison of two noise floors, and the JSON artifact is
                // where a comparator can still see that after the terminal has scrolled away.
                rec.skip(
                    "cpufreq: NOT pinned (need CAP_DAC_OVERRIDE via vmcell-test-runner) — \
                     latency numbers carry CPU-scaling noise"
                        .to_string(),
                );
                Some(pin)
            }
            Err(e) => {
                rec.skip(format!("cpufreq: pin unavailable: {e}"));
                None
            }
        };

    // `daemon-api` drives an already-spawned `vmcelld` over HTTP — it needs no local `Vmm`,
    // so branch here (after the freq-pin engages, so the daemon's VM boots are freq-pinned)
    // before the per-backend VMM construction. The knobs it cannot honor are already rejected
    // (`validate_daemon_api_knobs`); the ones it merely does not apply are disclosed here, next
    // to the header, so the results table cannot be read as a `--mem-mib 4096` run.
    if args.mode == "daemon-api" {
        let ignored = daemon_api_ignored_knobs_line();
        say!("{ignored}");
        rec.note(ignored);
        run_daemon_api(&rec, &args).await?;
        return emit_report(&args, &rec, &vmm_bin, &vmm_bin_source, &kernel, &rootfs);
    }

    let allocator = VmidAllocator::new();

    // `bench-ignores-contract-bin-resolvers`: the binary comes from the §10.4 contract
    // `VMCELL_*_BIN` resolver, not a hardcoded name — resolved ONCE above and echoed here
    // (H-BIN-1's rule: a run states the knobs it actually used), so a results table can be
    // attributed to the VMM build it measured instead of "whatever `crosvm` was first on PATH".
    // The parenthetical states which of those two it WAS; see [`resolve_vmm_binary`].
    say!("{}", vmm_binary_line(&vmm_bin, &vmm_bin_source));

    match args.backend.as_str() {
        #[cfg(feature = "cloud-hypervisor")]
        "cloud-hypervisor" => {
            let vmm = vmcell::vmm::cloud_hypervisor::CloudHypervisor::new(vmm_bin.clone());
            say!("Capabilities: {:?}", vmm.capabilities());
            run_mode(&vmm, &rec, "cloud-hypervisor", &args, allocator.clone()).await?;
        }
        #[cfg(feature = "firecracker")]
        "firecracker" => {
            let vmm = vmcell_firecracker::Firecracker::new(vmm_bin.clone());
            say!("Capabilities: {:?}", vmm.capabilities());
            run_mode(&vmm, &rec, "firecracker", &args, allocator.clone()).await?;
        }
        #[cfg(feature = "qemu")]
        "qemu" => {
            let vmm = vmcell_qemu::Qemu::new(vmm_bin.clone());
            say!("Capabilities: {:?}", vmm.capabilities());
            run_mode(&vmm, &rec, "qemu", &args, allocator.clone()).await?;
        }
        #[cfg(feature = "crosvm")]
        "crosvm" => {
            let vmm = vmcell_crosvm::Crosvm::new(vmm_bin.clone());
            say!("Capabilities: {:?}", vmm.capabilities());
            run_mode(&vmm, &rec, "crosvm", &args, allocator.clone()).await?;
        }
        // Unreachable after `validate_backend`, but fail loud rather than
        // silently succeed if the two ever drift.
        _ => anyhow::bail!(
            "unsupported or feature-disabled --backend '{}'",
            args.backend
        ),
    }

    emit_report(&args, &rec, &vmm_bin, &vmm_bin_source, &kernel, &rootfs)
}

/// The knobs that shape the numbers, as the report carries them.
///
/// `iterations` is the RESOLVED count (`Args::iters`, which defaults to 200 for `vsock-rtt` and 10
/// elsewhere), not the raw `Option`: an unset flag and its per-mode default produce different
/// sample sizes, and "the knob was unset" is not a thing a comparator can compare.
fn run_knobs(args: &Args) -> BTreeMap<String, String> {
    let mut knobs = BTreeMap::new();
    let mut put = |k: &str, v: String| {
        knobs.insert(k.to_string(), v);
    };
    put("profile", args.profile.clone());
    put("kernel_verbosity", format!("{:?}", args.kernel_verbosity));
    put("console", format!("{:?}", args.console));
    put("mem_mib", args.mem_mib.to_string());
    put("iterations", args.iters().to_string());
    put("warmup", args.warmup.to_string());
    put("count", args.count.to_string());
    put("restore_mode", format!("{:?}", args.restore_mode));
    put("ksm_mergeable", args.ksm_mergeable.to_string());
    put("net_mode", args.net_mode.clone());
    put("snap_dir", args.snap_dir.clone());
    knobs
}

/// Refuses a run that recorded a metric name `vmcell_bench::metrics::METRIC_DIRECTIONS` has no
/// direction for.
///
/// THE HOLE THIS CLOSES. The A/B comparator's direction rule used to be
/// `metric != "footprint_ksm_pages_sharing_delta"` — every other name defaulted to "lower is
/// better". A new metric that is a *benefit* (guest memory kept, pages deduped) therefore printed
/// `IMPROVEMENT` when it got worse and `REGRESSION` when it got better, and nothing anywhere could
/// see that: the default was silent by construction. The roster is now exhaustive, and this is what
/// keeps it exhaustive — the emitting side refuses rather than shipping a name the comparator would
/// have to guess about.
///
/// The refusal is late (after the matrix ran) on purpose: the alternative is a panic in the middle
/// of a benchmark, and the measured lines are already on stderr. It names EVERY offender, because
/// fixing them one exit code at a time is how a roster gets abandoned.
///
/// # Errors
/// Returns an error naming each unregistered metric and the roster to add it to.
fn refuse_unregistered_metrics(rec: &Recorder) -> anyhow::Result<()> {
    let unknown = rec.unregistered_metrics();
    if unknown.is_empty() {
        return Ok(());
    }
    anyhow::bail!(
        "this run recorded {} metric name(s) with no entry in \
         `vmcell_bench::metrics::METRIC_DIRECTIONS`: {}. A comparator cannot say REGRESSION or \
         IMPROVEMENT about a quantity whose direction nobody declared — the rule it replaced \
         assumed every metric was a cost, so a BENEFIT that got worse printed IMPROVEMENT. THE \
         FIX: add each name to the roster in `crates/vmcell-bench/src/metrics.rs` with its \
         direction (`LowerIsBetter` for a cost, `HigherIsBetter` for a benefit, `Neutral` for a \
         share of a whole, which has no direction at all).",
        unknown.len(),
        unknown.join(", ")
    )
}

/// Emits the machine-readable report on stdout under `--report json`; a no-op under `--report
/// text`, whose report IS the table already printed.
///
/// WHY ONLY ON THE SUCCESS PATH. A failed run's metric set is a partial matrix, and a comparator
/// that pooled it with a complete one would rank samples that measured different amounts of work —
/// the "confident numbers from an assumption nobody checked" shape this whole harness exists to
/// close. The non-zero exit is the signal, and the human lines (on stderr in this mode) are the
/// diagnosis.
///
/// # Errors
/// Propagates a serialization failure. It cannot be swallowed: a `--report json` invocation that
/// printed nothing and exited 0 is indistinguishable, to the parent, from a run that produced an
/// empty report.
fn emit_report(
    args: &Args,
    rec: &Recorder,
    vmm_bin: &str,
    vmm_bin_source: &BinSource,
    kernel: &Path,
    rootfs: &Path,
) -> anyhow::Result<()> {
    // BEFORE the format check, because a `--report text` run that emits a directionless metric is
    // the same hole one command away from being compared.
    refuse_unregistered_metrics(rec)?;
    // Straight to stdout, unconditionally: in this mode stdout carries the report and nothing else
    // (see `HUMAN_LINES_TO_STDERR`), so this is the one write that must NOT go through `say!`.
    if let Some(json) = stdout_report(args, rec, vmm_bin, vmm_bin_source, kernel, rootfs)? {
        println!("{json}");
    }
    Ok(())
}

/// The exact text `--report json` writes to stdout, or `None` under `--report text`.
///
/// WHY THE ROUTING IS A VALUE AND NOT AN `if` AROUND A `println!`. This one branch IS the
/// parent/child contract — `bench-ab` parses this process's stdout with
/// [`BenchReport::from_json`] — and the other half of the `--report` promise, that `text` is byte
/// for byte what it always was. Inverted (text dumping JSON onto the human table's stdout, json
/// emitting nothing at all), the whole suite stayed green: nothing could see the decision, because
/// the decision was spelled inside the one function whose output is a side effect. Returning the
/// text moves both arms into a unit test and leaves `emit_report` with a `println!` and nothing to
/// get wrong.
///
/// # Errors
/// Propagates a serialization failure.
fn stdout_report(
    args: &Args,
    rec: &Recorder,
    vmm_bin: &str,
    vmm_bin_source: &BinSource,
    kernel: &Path,
    rootfs: &Path,
) -> anyhow::Result<Option<String>> {
    if args.report != ReportFormat::Json {
        return Ok(None);
    }
    let report = build_report(args, rec, vmm_bin, vmm_bin_source, kernel, rootfs);
    Ok(Some(report.to_json()?))
}

/// Assembles the report from what the run actually resolved and measured.
///
/// Split from [`emit_report`] so the assembly is testable without capturing stdout: the printing is
/// one line, and the part worth a gate is that the run's *attribution* — which binary, resolved
/// how, which kernel, which knobs — is the report's, not a caller's recollection.
fn build_report(
    args: &Args,
    rec: &Recorder,
    vmm_bin: &str,
    vmm_bin_source: &BinSource,
    kernel: &Path,
    rootfs: &Path,
) -> BenchReport {
    let (metrics, notes) = rec.drain();
    BenchReport {
        schema_version: REPORT_SCHEMA_VERSION,
        backend: args.backend.clone(),
        mode: args.mode.clone(),
        vmm_binary: vmm_bin.to_string(),
        vmm_binary_source: vmm_bin_source.clone(),
        kernel: kernel.to_path_buf(),
        rootfs: rootfs.to_path_buf(),
        knobs: run_knobs(args),
        metrics,
        notes,
    }
}

/// The design §10.4 contract binary resolvers, as `(backend, env var, default binary)`.
/// ONE table, so `--backend X` boots exactly the binary `$VMCELL_*_BIN` names — the same law
/// `vmcell_artifact_validator::harness::{ch,fc,qemu,crosvm}_bin` applies to the conformance
/// battery and `vmcell::artifact::ch_binary_path()` applies to the artifact pipeline
/// (`bench-ignores-contract-bin-resolvers`: this harness used to hardcode the four names, so a
/// documented `$VMCELL_CROSVM_BIN` override silently measured whatever `crosvm` PATH resolved to
/// — or failed to spawn at all on a host where the binary is only reachable via the var).
/// Parity with the validator getters is asserted in the tests below; the table is the whole
/// list, so a backend added to [`supported_backends`] without an entry fails there too.
const VMM_BIN_RESOLVERS: [(&str, &str, &str); 4] = [
    ("cloud-hypervisor", "VMCELL_CH_BIN", "cloud-hypervisor"),
    ("firecracker", "VMCELL_FC_BIN", "firecracker"),
    ("qemu", "VMCELL_QEMU_BIN", "qemu-system-x86_64"),
    ("crosvm", "VMCELL_CROSVM_BIN", "crosvm"),
];

/// The `(env var, default binary)` §10.4 contract resolver for `backend`, or `None` when the
/// backend has no entry (a drift between [`VMM_BIN_RESOLVERS`] and the `--backend` dispatch —
/// surfaced as a loud error by [`vmm_binary`], never as a silently-hardcoded name).
fn vmm_bin_resolver(backend: &str) -> Option<(&'static str, &'static str)> {
    VMM_BIN_RESOLVERS
        .iter()
        .find(|(b, _, _)| *b == backend)
        .map(|(_, var, default)| (*var, *default))
}

/// Resolves `backend`'s VMM binary through `lookup` — the env reader, injected so the contract
/// behavior (override wins, else the documented default) is unit-testable **without** mutating
/// the process environment (this repo has no `set_var` anywhere: it is `unsafe` in edition 2024
/// and races sibling tests in a shared test process) — **and the provenance of the answer**.
///
/// WHY THE SOURCE IS PART OF THE ANSWER, and not re-derived by the caller. The attribution line
/// this feeds used to read `(via $VMCELL_CH_BIN)` unconditionally — it printed the name of the
/// variable the resolver *would* have consulted, whether or not the variable was set. Its own
/// comment said it exists so a results table can be attributed to the VMM build it measured
/// "instead of whatever `crosvm` was first on PATH", which is precisely the distinction the line
/// could not make. On 2026-08-21 that same class cost a whole matrix: the driver believed its
/// exports had applied because it had written them, and an arm that predates the variable resolved
/// the bare name off PATH. Only the resolving process can answer "where did this path come from",
/// so it answers here, once, and both the printed line and [`BenchReport::vmm_binary_source`] read
/// that one answer.
fn resolve_vmm_binary(
    backend: &str,
    lookup: impl Fn(&str) -> Option<String>,
) -> Option<(String, BinSource)> {
    // No emptiness/validity filtering: the validator's getters do `env::var(..).unwrap_or(default)`
    // verbatim, and a *different* interpretation of the same var here would be a second law.
    vmm_bin_resolver(backend).map(|(var, default)| match lookup(var) {
        Some(path) => (
            path,
            BinSource::EnvVar {
                name: var.to_string(),
            },
        ),
        // The documented default is a bare binary NAME, so `execve` finds it — or does not — on
        // PATH. Nothing the operator set decided it, which is exactly what `Path` states.
        None => (default.to_string(), BinSource::Path),
    })
}

/// The run-header attribution line: the binary this run executes, and where that path came from.
///
/// A composer rather than an inline `format!` so the PATH case is unit-testable without touching
/// the process environment (this repo has no `set_var`: it is `unsafe` in edition 2024 and races
/// sibling tests in a shared test process). The parenthetical is [`BinSource`]'s own `Display`, the
/// one rendering of a resolution, shared with the A/B harness's guard message — so "via $VAR" is
/// unprintable for a run that searched PATH.
fn vmm_binary_line(bin: &str, source: &BinSource) -> String {
    format!("vmm binary: {bin} ({source})")
}

/// The VMM binary this run should execute for `backend` **and how it was resolved**, read from the
/// process environment through the §10.4 contract var.
///
/// One function, not a bare-path convenience beside a provenance-carrying one: the pair is the
/// whole answer, and the two-function shape is how a caller ends up printing a variable name it
/// never read (see [`resolve_vmm_binary`]).
///
/// # Errors
/// Returns an error when `backend` has no [`VMM_BIN_RESOLVERS`] entry — i.e. the table and the
/// `--backend` dispatch drifted. Failing loud beats falling back to the bare backend name, which
/// is exactly the hardcoding this resolver replaced.
fn vmm_binary(backend: &str) -> anyhow::Result<(String, BinSource)> {
    resolve_vmm_binary(backend, |var| std::env::var(var).ok()).ok_or_else(|| {
        anyhow::anyhow!(
            "no VMCELL_*_BIN resolver for --backend '{backend}' (design §10.4 contract)"
        )
    })
}

/// The benchmark backends compiled into this binary, honoring the per-backend
/// feature gates. The set is the single source of truth shared with the
/// `--backend` dispatch in `main` so a feature-disabled backend reads as
/// unsupported rather than silently succeeding.
fn supported_backends() -> Vec<&'static str> {
    // `cloud-hypervisor` is a `required-features` of this binary, so the array
    // always has at least one element. cfg attributes gate the array elements
    // so a feature-disabled backend reads as unsupported.
    [
        #[cfg(feature = "cloud-hypervisor")]
        "cloud-hypervisor",
        #[cfg(feature = "firecracker")]
        "firecracker",
        #[cfg(feature = "qemu")]
        "qemu",
        #[cfg(feature = "crosvm")]
        "crosvm",
    ]
    .to_vec()
}

/// Validates `--backend` against [`supported_backends`].
///
/// # Errors
/// Returns an error when the backend is unknown or its feature was not enabled
/// at build time, so a CI/script typo or a feature-gated build exits non-zero
/// instead of printing a notice and returning `Ok`.
fn validate_backend(backend: &str) -> anyhow::Result<()> {
    let supported = supported_backends();
    if supported.contains(&backend) {
        Ok(())
    } else {
        anyhow::bail!(
            "unsupported or feature-disabled --backend '{backend}' (compiled-in: {})",
            supported.join(", ")
        )
    }
}

/// The benchmark modes this harness understands. Kept in one place so the
/// `--mode` validator and its error message cannot drift from the dispatcher in
/// [`run_mode`].
const VALID_MODES: &[&str] = &[
    "latency",
    "footprint",
    "suspend-size",
    "phase-budget",
    "vsock-rtt",
    "net-egress",
    "zygote",
    "session",
    "daemon-api",
];

/// Validates `--mode` against [`VALID_MODES`].
///
/// # Errors
/// Returns an error for an unknown mode so a typo exits non-zero instead of
/// printing "Unknown mode" and returning `Ok`.
fn validate_mode(mode: &str) -> anyhow::Result<()> {
    if VALID_MODES.contains(&mode) {
        Ok(())
    } else {
        anyhow::bail!(
            "unknown --mode '{mode}' (valid: {})",
            VALID_MODES.join(", ")
        )
    }
}

/// The VM-shaping knobs `--mode daemon-api` structurally cannot apply: it drives an
/// already-running `vmcelld`, which builds every VM from its OWN request DTO defaults, so these
/// flags never reach a guest. Disclosed in the run header rather than rejected — unlike
/// `--backend`/`--kernel` they do not *misname* the run, and rejecting them would break the
/// perf-matrix's uniform per-mode invocation.
const DAEMON_API_IGNORED_KNOBS: &[&str] = &[
    "--mem-mib",
    "--profile",
    "--kernel-verbosity",
    "--console",
    "--restore-mode",
    "--ksm-mergeable",
    "--count",
    "--net-mode",
    "--snap-dir",
];

/// The `daemon-api` ignored-knob disclosure line (`daemon-api-header-misnames-backend`): the run
/// header echoes `--profile`/`--console`/… for every mode (H-BIN-1), and on this mode those
/// echoes describe knobs the daemon never sees. Naming them beside the header is what keeps a
/// reader of the results table from attributing the numbers to them.
fn daemon_api_ignored_knobs_line() -> String {
    format!(
        "daemon-api: NOT applied (the daemon builds each VM from its own request defaults): {}",
        DAEMON_API_IGNORED_KNOBS.join(" ")
    )
}

/// Rejects the `--mode daemon-api` invocations whose knobs would **misname the results table**
/// (`daemon-api-header-misnames-backend`).
///
/// Two accepted inputs are structurally unhonorable on this mode, and both are printed in the run
/// header, so silently ignoring them mislabels the run: `--backend` (the header printed
/// "backend: firecracker" while the CH-backed daemon was measured) and `--kernel <label>` (the
/// header printed `vmlinux-<label>` while the daemon's create DTO names the plain `vmlinux` this
/// mode symlinks into its store). Rejecting is the choice that cannot mislead — a disclosure line
/// still leaves a wrong-but-plausible header on the page — and matches the AGENTS rule that every
/// accepted input is honored or rejected. The knobs that are merely inapplicable are disclosed by
/// [`daemon_api_ignored_knobs_line`] instead.
///
/// # Errors
/// Returns an error for `--mode daemon-api` with a non-`cloud-hypervisor` `--backend` or with a
/// `--kernel` label. Every other mode is untouched.
fn validate_daemon_api_knobs(args: &Args) -> anyhow::Result<()> {
    if args.mode != "daemon-api" {
        return Ok(());
    }
    if args.backend != "cloud-hypervisor" {
        anyhow::bail!(
            "--mode daemon-api benchmarks the CH-backed vmcelld, so --backend must be \
             cloud-hypervisor (got '{}'); drop the flag rather than have the header name a \
             backend that was never run",
            args.backend
        );
    }
    if let Some(label) = args.kernel.as_deref() {
        anyhow::bail!(
            "--mode daemon-api boots the daemon store's plain `vmlinux`, so it cannot honor \
             --kernel '{label}'; drop the flag (or run the labeled kernel through a non-daemon \
             mode)"
        );
    }
    Ok(())
}

/// Validates the VM parameters shared by every benchmark mode by running them
/// through [`VmConfig`]'s own builder, surfacing its typed validation error
/// (chiefly a `--mem-mib` below the documented 64 MiB floor) instead of
/// panicking later at the `.build().expect(...)` sites.
///
/// # Errors
/// Propagates any [`VmConfig`] build error — currently a `mem_mib` below the
/// floor — as a clear, non-panicking error, and rejects `--count 0` (N-BIN-2),
/// which the `footprint` mode would otherwise silently clamp to 1.
fn validate_vm_params(args: &Args) -> anyhow::Result<()> {
    // N-BIN-2: reject `--count 0` loudly rather than silently clamping to 1 — a run
    // that measures zero guests is a misinvocation, not a request for one guest.
    if args.count == 0 {
        anyhow::bail!("--count must be >= 1 (0 guests measures nothing)");
    }
    // Absolute placeholder paths: this probe validates the *numeric* knobs (mem floor) before any
    // side effect, and `VmConfig` now applies the same absolute/non-empty boundary checks to the
    // rootfs image that every other path input gets (`rootfs-image-escapes-boundary-validation`),
    // so relative literals here would fail the probe on EVERY invocation. Nothing opens them —
    // the real paths come from `artifact_paths` in each mode.
    VmConfig::builder(
        PathBuf::from("/vmcell-bench/validate/vmlinux"),
        RootfsSource::Erofs {
            image: PathBuf::from("/vmcell-bench/validate/rootfs.erofs"),
        },
    )
    .vcpus(1)
    .mem_mib(args.mem_mib)
    .network_disabled()
    .restore_mode(args.restore_mode)
    .ksm_mergeable(args.ksm_mergeable)
    .build()
    .map_err(|e| anyhow::anyhow!("invalid benchmark VM parameters: {e}"))?;
    Ok(())
}

/// Dispatches to the requested benchmark mode. `latency` preserves the original
/// cold/warm behaviour exactly (the dry-test path); the rest answer §16 (Performance).
///
/// # Errors
/// Returns an error for an unknown `--mode` so a typo exits non-zero rather than
/// printing a notice and returning `Ok`. `--mode` is normally pre-validated by
/// [`validate_mode`] in `main`; the trailing arm re-checks defensively so the
/// two cannot silently drift.
async fn run_mode<V: Vmm>(
    vmm: &V,
    rec: &Recorder,
    backend: &str,
    args: &Args,
    allocator: VmidAllocator,
) -> anyhow::Result<()> {
    match args.mode.as_str() {
        "latency" => {
            run_bench(
                vmm,
                rec,
                "Cold Boot",
                metrics::COLD_BOOT,
                args,
                allocator.clone(),
                false,
            )
            .await?;
            if vmm.capabilities().snapshot_restore {
                run_bench(
                    vmm,
                    rec,
                    "Warm Restore",
                    metrics::WARM_RESTORE,
                    args,
                    allocator.clone(),
                    true,
                )
                .await?;
            } else {
                // CLI-4 / §16 (Performance) visible-skip: a backend that does not advertise
                // `snapshot_restore` can't run Warm Restore (all three shipped backends now do,
                // §2.5, The capability matrix — this guards a re-gated or hypothetical backend).
                // Print the reason rather than silently dropping the benchmark; a genuine
                // capability skip is success (Ok), not a failure (M-BIN-1).
                rec.skip(format!(
                    "Warm Restore: backend {backend} has no snapshot support; skipping"
                ));
            }
            Ok(())
        }
        "footprint" => run_footprint(vmm, rec, backend, args, allocator).await,
        "suspend-size" => run_suspend_size(vmm, rec, backend, args, allocator).await,
        "phase-budget" => run_phase_budget(vmm, rec, backend, args, allocator).await,
        "vsock-rtt" => run_vsock_rtt(vmm, rec, backend, args, allocator).await,
        "net-egress" => run_net_egress(vmm, rec, backend, args, allocator).await,
        "zygote" => run_zygote(vmm, rec, backend, args, allocator).await,
        "session" => run_session(vmm, rec, backend, args, allocator).await,
        other => anyhow::bail!(
            "unknown --mode '{other}' (valid: {})",
            VALID_MODES.join(", ")
        ),
    }
}

// ----------------------------------------------------------------------------
// Shared helpers for the §16 (Performance) benchmark modes.
// ----------------------------------------------------------------------------

/// The kernel artifact filename for an optional version label (`vmlinux` or
/// `vmlinux-<sanitized-label>`) — `vmcell`'s shared
/// [`kernel_filename`](vmcell::artifact::kernel::kernel_filename) law, so this harness resolves
/// exactly the names the producers write rather than re-encoding the `.`→`-` sanitization.
fn kernel_filename(label: Option<&str>) -> String {
    vmcell::artifact::kernel::kernel_filename(label)
}

/// The workspace root, so `--snap-dir` anchors independent of the process CWD
/// (N-BIN-5) — `vmcell`'s **one** ascent
/// ([`workspace_root`](vmcell::artifact::workspace_root)), called rather than mirrored.
///
/// This was a hand-rolled third copy of that ascent, the last entry on design §17's open
/// "one law, one predicate" register: the library's was `pub(crate)`, so the collapse needed a
/// `vmcell`-side export and could not be done from this crate. The coupling §17 named is the
/// **marker string** the ascent looks for, which after this collapse is spelled in exactly one
/// file — a copy that drifted on it would ascend to a *different* directory, and this harness would
/// then measure warm-restore snapshots on one filesystem and boot artifacts from another,
/// silently, with both numbers reported as one run. `scripts/ban-workspace-root-ascent-copies.sh`
/// is the class's gate: a byte-identical copy is not a compile error, and the parity test below
/// cannot see one.
fn workspace_root() -> PathBuf {
    vmcell::artifact::workspace_root()
}

/// Resolves `--snap-dir` to an absolute, CWD-independent path anchored on the
/// workspace root (N-BIN-5): artifacts anchor there too (§10, The artifact build pipeline), so an out-of-root
/// invocation must not measure a *different* filesystem for the warm-restore snapshot
/// than for the artifacts. An absolute `--snap-dir` is honored verbatim.
fn resolve_snap_dir(raw: &str) -> PathBuf {
    let p = PathBuf::from(raw);
    if p.is_absolute() {
        p
    } else {
        workspace_root().join(p)
    }
}

/// The filesystem type backing `path`, per the longest mount-point prefix in a
/// `/proc/self/mountinfo` dump. Factored out (pure) so the tmpfs check is testable
/// without a real mount table (N-BIN-5).
fn path_fstype(mountinfo: &str, path: &Path) -> Option<String> {
    let mut best_len = 0usize;
    let mut best: Option<String> = None;
    for line in mountinfo.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        // Optional fields precede a `-` separator; mount point is field 4, fstype is
        // the first field after the separator.
        let Some(sep) = fields.iter().position(|f| *f == "-") else {
            continue;
        };
        let (Some(mp), Some(fstype)) = (fields.get(4), fields.get(sep + 1)) else {
            continue;
        };
        let mp = PathBuf::from(mp);
        if path.starts_with(&mp) {
            let len = mp.as_os_str().len();
            // `>=` so a longer (more specific) mount wins ties against the root `/`.
            if len >= best_len {
                best_len = len;
                best = Some((*fstype).to_string());
            }
        }
    }
    best
}

/// Best-effort check whether `path` lives on a tmpfs mount (RAM-backed), which makes
/// warm-restore latency systematically optimistic (§16, Performance). Consults
/// `/proc/self/mountinfo`; a non-Linux/unreadable table degrades to `false`.
fn is_tmpfs(path: &Path) -> bool {
    let canon = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    match std::fs::read_to_string("/proc/self/mountinfo") {
        Ok(mi) => path_fstype(&mi, &canon).as_deref() == Some("tmpfs"),
        Err(_) => false,
    }
}

/// Resolves the (dir, kernel, rootfs) artifact paths a run uses.
///
/// The kernel and rootfs come from the §10.4 toolkit getters — [`vmcell::artifact::kernel_path`]
/// and [`vmcell::artifact::rootfs_path`], the ONE place `$VMCELL_KERNEL` / `$VMCELL_ROOTFS` are
/// resolved — for the same reason every VMM binary comes from [`resolve_vmm_binary`]: a harness
/// that re-derives `<artifacts-dir>/vmlinux` itself honors no override, so a box pointed at a
/// custom kernel by every other tool silently benchmarked the default one and attributed the
/// numbers to the override (`bench-ignores-contract-artifact-overrides`). `$VMCELL_ROOTFS` also
/// makes the workspace artifact bootstrap a full no-op (§10.4), which is exactly the "I built
/// these myself" case a benchmark must measure rather than second-guess.
///
/// # Errors
/// `--kernel <label>` and `$VMCELL_KERNEL` cannot both be honored — see
/// [`resolve_artifact_paths`].
fn artifact_paths(kernel_label: Option<&str>) -> anyhow::Result<(String, PathBuf, PathBuf)> {
    resolve_artifact_paths(
        &vmcell::artifact::artifacts_dir(),
        vmcell::artifact::kernel_path(),
        vmcell::artifact::rootfs_path(),
        kernel_label,
    )
}

/// The pure core of [`artifact_paths`]: the toolkit getters' answers are passed in, so the override
/// behavior is unit-testable without mutating (and racing on) the process environment — the same
/// shape as [`resolve_vmm_binary`]'s injected lookup.
///
/// `$VMCELL_KERNEL` names ONE exact file, so a `--kernel <label>` selection (`vmlinux-<label>`
/// under the artifacts dir) cannot also be honored. Two accepted inputs that contradict each other
/// are rejected at the boundary rather than one silently winning (AGENTS.md: every accepted input
/// is honored or rejected). `$VMCELL_ROOTFS` has no such conflict — nothing else selects a rootfs.
///
/// Existence is NOT checked here: `$VMCELL_KERNEL` is a path redirect that still requires the file
/// to exist (§10.4), and that check belongs to [`require_artifacts`], which each mode runs against
/// the pair it is about to boot and which names the resolved paths in its refusal.
///
/// # Errors
/// Returns an error when `kernel_label` is set while `toolkit_kernel` is a `$VMCELL_KERNEL`
/// redirect (i.e. not the artifacts dir's default `vmlinux`).
fn resolve_artifact_paths(
    dir: &Path,
    toolkit_kernel: PathBuf,
    toolkit_rootfs: PathBuf,
    kernel_label: Option<&str>,
) -> anyhow::Result<(String, PathBuf, PathBuf)> {
    // "Was the kernel redirected?" asked by comparing against the dir's default — not by reading
    // $VMCELL_KERNEL again here, which would be a second copy of the resolution rule.
    let redirected = toolkit_kernel != dir.join(kernel_filename(None));
    let kernel = match kernel_label {
        Some(label) if redirected => anyhow::bail!(
            "--kernel {label} selects {} under the artifacts dir, but $VMCELL_KERNEL redirects the \
             kernel to {}: the two name different files. Drop one — unset $VMCELL_KERNEL to use \
             the label, or drop --kernel to benchmark the redirected kernel.",
            kernel_filename(Some(label)),
            toolkit_kernel.display()
        ),
        Some(label) => dir.join(kernel_filename(Some(label))),
        None => toolkit_kernel,
    };
    Ok((dir.to_string_lossy().into_owned(), kernel, toolkit_rootfs))
}

/// The two store-relative artifact names the `daemon-api` mode's REST bodies name. The store's
/// entries keep these names whatever the host files are called — the daemon resolves a client name
/// against its own `--artifacts-dir` (B12), so the link NAME is the daemon's contract while the
/// link TARGET is whatever [`artifact_paths`] resolved.
const DAEMON_STORE_NAMES: (&str, &str) = ("vmlinux", "rootfs.erofs");

/// Symlinks the resolved artifact pair into `store` under [`DAEMON_STORE_NAMES`] (the store reads
/// through symlinks — no copy of a 150 MB rootfs).
///
/// The targets are the **resolved** paths, not `<artifacts-dir>/<name>`: with `$VMCELL_KERNEL` or
/// `$VMCELL_ROOTFS` set, re-deriving the source from the dir stages a file the run never validated
/// — the same d8 defect one level down, and here it would either dangle or silently benchmark the
/// default artifact under the override's name.
///
/// # Errors
/// Returns an error naming the entry whose symlink could not be created.
fn stage_artifact_store(store: &Path, kernel: &Path, rootfs: &Path) -> anyhow::Result<()> {
    let (kernel_name, rootfs_name) = DAEMON_STORE_NAMES;
    for (name, src) in [(kernel_name, kernel), (rootfs_name, rootfs)] {
        std::os::unix::fs::symlink(src, store.join(name))
            .map_err(|e| anyhow::anyhow!("daemon-api: symlink {name} -> {}: {e}", src.display()))?;
    }
    Ok(())
}

/// The one "are the artifacts really there?" refusal, shared by every mode.
///
/// Fails LOUD (M-BIN-1) rather than exit-0 when either file is absent: the harness measured
/// nothing, so automation must not read it as success. It is also the existence half of the
/// `$VMCELL_KERNEL` contract (§10.4: a path redirect that still requires existence), which is why
/// the message names the missing **paths** and not just the artifacts dir — under an override the
/// missing file is not under that dir at all, and `"missing artifacts in <dir>"` sent the reader to
/// a directory where nothing was wrong. KVM-independent: it runs before any boot, which would
/// otherwise hang on the steward-connect timeout.
///
/// # Errors
/// Returns an error naming every missing path, after printing the mode's "No successful runs"
/// report line (the two together are what the dry-path test asserts).
fn require_artifacts(name: &str, dir: &str, kernel: &Path, rootfs: &Path) -> anyhow::Result<()> {
    let missing: Vec<String> = [kernel, rootfs]
        .iter()
        .filter(|p| !p.exists())
        .map(|p| p.display().to_string())
        .collect();
    if missing.is_empty() {
        return Ok(());
    }
    let missing = missing.join(", ");
    say!("{name}: No successful runs (missing artifacts in {dir}: {missing})");
    anyhow::bail!("{name}: missing artifacts in {dir}: {missing}");
}

/// Builds the standard network-disabled erofs VM config used by every mode,
/// applying the run's `--mem-mib`, `--restore-mode`, `--profile` timeouts,
/// `--kernel-verbosity`, and `--console` from `args`. `ksm_mergeable` stays an
/// explicit argument because only `footprint` opts into it (§16, Performance); every other
/// mode passes `false`.
fn build_cfg(
    args: &Args,
    kernel: PathBuf,
    rootfs: PathBuf,
    ksm_mergeable: bool,
    snapshotting: bool,
) -> VmConfig {
    VmConfig::builder(kernel, RootfsSource::Erofs { image: rootfs })
        .vcpus(1)
        .mem_mib(args.mem_mib)
        .network_disabled()
        // Snapshot-taking modes (warm-restore, suspend-size, phase-budget) mark the VM
        // snapshot-eligible, which for QEMU selects the in-kernel vhost-vsock transport
        // (§2.4); a no-op for CH/FC. Non-snapshot modes leave the default (QEMU's
        // external vhost-device-vsock), so a plain cold-boot benchmark needs no
        // `/dev/vhost-vsock` access. `network_disabled` (NetConfig::None) is
        // snapshot-compatible — it carries no vhost-user device.
        .snapshotting(snapshotting)
        .restore_mode(args.restore_mode)
        .ksm_mergeable(ksm_mergeable)
        .timeouts(timeouts_for(&args.profile))
        .kernel_verbosity(args.kernel_verbosity)
        .console_mode(args.console)
        .build()
        .expect("valid VM configuration benchmark invariant")
}

/// Reads a `/proc/meminfo` field in kB (`None` if unreadable/absent).
fn read_meminfo_kb(key: &str) -> Option<u64> {
    let s = std::fs::read_to_string("/proc/meminfo").ok()?;
    parse_kv_kb(&s, key)
}

/// Decides whether a `drop_caches` attempt actually took effect (M-BIN-8). A write
/// that "succeeds" but leaves `Cached` untouched is a warm cache — the permission was
/// silently ignored under the file-cap runner (euid != 0) — so only a real decrease in
/// `Cached` (or no cache to begin with) counts as cold.
fn cache_drop_effective(
    wrote: bool,
    cached_before: Option<u64>,
    cached_after: Option<u64>,
) -> bool {
    if !wrote {
        return false;
    }
    match (cached_before, cached_after) {
        // There was page cache to drop: require it to have actually shrunk.
        (Some(before), Some(after)) if before > 0 => after < before,
        // No prior cache (already cold) or meminfo unreadable → trust the write.
        _ => true,
    }
}

/// Drops the host page cache and verifies it took effect. Opens write-only (no
/// `O_CREAT`/`O_TRUNC`): `O_TRUNC` on a procfs sysctl is rejected even with
/// `CAP_DAC_OVERRIDE`, which silently broke the original `std::fs::write` cold path.
/// Returns true only if the write succeeds AND `Cached` actually dropped — a
/// successful-but-ineffective write (euid != 0 under the file-cap runner) is still a
/// warm cache and is flagged as such (M-BIN-8), rather than trusting write success.
fn drop_page_cache() -> bool {
    use std::io::Write;
    let before = read_meminfo_kb("Cached");
    let wrote = match std::fs::OpenOptions::new()
        .write(true)
        .open("/proc/sys/vm/drop_caches")
    {
        Ok(mut f) => f.write_all(b"3\n").is_ok(),
        Err(_) => false,
    };
    cache_drop_effective(wrote, before, read_meminfo_kb("Cached"))
}

/// p50/p95/p99/max of a sample set via the **nearest-rank** method: index
/// `ceil(q*n) - 1`, clamped to `[0, n-1]` (H-BIN-1-revisited). The old `floor(q*n)`
/// was one rank too high whenever `q*n` is integral — at N=20, `floor(20*0.95)=19`
/// returned the sample MAXIMUM as p95, so p95 and max were always identical.
fn pcts(latencies: &mut [u128]) -> Option<(u128, u128, u128, u128)> {
    if latencies.is_empty() {
        return None;
    }
    latencies.sort_unstable();
    let n = latencies.len();
    let last = n - 1;
    let idx = |q: f64| ((n as f64 * q).ceil() as usize).saturating_sub(1).min(last);
    // `.get()` rather than `[]`: the clamp above already proves every index in-bounds, so this is
    // the same values with no panic path to argue about — and no suppression to outlive its proof.
    Some((
        *latencies.get(idx(0.5))?,
        *latencies.get(idx(0.95))?,
        *latencies.get(idx(0.99))?,
        *latencies.get(last)?,
    ))
}

/// Reads a `/sys/kernel/mm/ksm/<field>` counter (0 if unavailable).
fn read_ksm(field: &str) -> u64 {
    std::fs::read_to_string(format!("/sys/kernel/mm/ksm/{field}"))
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}

/// Writes a `/sys/kernel/mm/ksm/<field>` (best-effort; the `root:root` sysfs file
/// needs `CAP_DAC_OVERRIDE`, which the test runner grants). Returns success.
fn write_ksm(field: &str, value: &str) -> bool {
    use std::io::Write as _;
    std::fs::OpenOptions::new()
        .write(true)
        .open(format!("/sys/kernel/mm/ksm/{field}"))
        .and_then(|mut f| f.write_all(value.as_bytes()))
        .is_ok()
}

/// Parses a `Key:  <value> kB`-style line (matches both `/proc/meminfo` and
/// `/proc/<pid>/status`). Returns the value in kB.
fn parse_kv_kb(text: &str, key: &str) -> Option<u64> {
    for line in text.lines() {
        let mut it = line.split_whitespace();
        if let Some(k) = it.next()
            && k.trim_end_matches(':') == key
            && let Some(v) = it.next()
            && let Ok(n) = v.parse::<u64>()
        {
            return Some(n);
        }
    }
    None
}

/// Reads one `/proc/<pid>/status` field in kB.
fn read_proc_status_kb(pid: u32, key: &str) -> Option<u64> {
    let s = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    parse_kv_kb(&s, key)
}

/// Finds the host VMM process for a VM by its unique per-VM tmp dir.
///
/// CH/FC do not put the vsock socket path verbatim on the command line, but the
/// `--api-socket` argument lives in the *same* unique `vmcell-vm-<pid>-<vmid>` dir,
/// which is `vsock_path`'s parent. Match that parent **with a trailing `/`** so
/// vmid 5 does not match vmid 50/51 (`vmcell-vm-…-5` is a substring of `…-50`).
///
/// M-BIN-7: several processes can share that per-VM dir on the command line — on
/// QEMU the `vhost-device-vsock` daemon is spawned (with a *lower* pid) before the
/// VMM and carries the same socket dir, so a plain first-match measures the wrong
/// process. Prefer the process whose cmdline also names the VMM binary (`vmm_hint`,
/// e.g. `cloud-hypervisor` / `qemu` / `firecracker`); only fall back to a dir-only
/// match (e.g. the vsock daemon) when no candidate names the VMM.
fn find_host_pid(vsock: &Path, vmm_hint: &str) -> Option<u32> {
    let parent = vsock
        .parent()
        .unwrap_or(vsock)
        .to_string_lossy()
        .to_string();
    let needle = format!("{parent}/");
    let full = vsock.to_string_lossy().to_string();
    let me = std::process::id();
    let mut fallback = None;
    for e in std::fs::read_dir("/proc").ok()?.flatten() {
        let pid: u32 = match e.file_name().to_string_lossy().parse() {
            Ok(p) => p,
            Err(_) => continue,
        };
        if pid == me {
            continue;
        }
        if let Ok(bytes) = std::fs::read(e.path().join("cmdline")) {
            // cmdline is NUL-separated; the path token stays intact in the lossy
            // string, and the trailing `/` keeps the match on a boundary.
            let s = String::from_utf8_lossy(&bytes);
            if s.contains(&full) || s.contains(&needle) {
                if s.contains(vmm_hint) {
                    // The actual VMM process — the one whose guest RAM we want.
                    return Some(pid);
                }
                // A dir-sharing helper (e.g. the vsock daemon); use only if nothing
                // better turns up.
                fallback.get_or_insert(pid);
            }
        }
    }
    fallback
}

/// The `(anon, shmem)` report annotations for a backend's guest-RAM memory model
/// (M-BIN-7): CH backs guest RAM with a shared memfd (accounted as `RssShmem`), while
/// Firecracker uses private anonymous guest RAM (accounted as `RssAnon`), so the
/// hard-coded CH-only labels would invert the reading on FC.
fn footprint_mem_notes(backend: &str) -> (&'static str, &'static str) {
    match backend {
        "cloud-hypervisor" => (
            "VMM overhead; guest RAM is shmem on CH",
            "CH guest-RAM memfd; the real density figure",
        ),
        "firecracker" => (
            "VMM overhead + private-anon guest RAM on Firecracker (the real density figure)",
            "shared shmem (minimal on FC; guest RAM is the anon line above)",
        ),
        // Probed 2026-07-17 (docs/benchmark-results.md): crosvm backs guest RAM with a memfd
        // accounted as `RssShmem` (the CH model — ~57 MiB/guest is the real density figure), with a
        // very light ~1 MiB/guest `RssAnon` VMM overhead (at the CH floor, far below QEMU's ~21).
        "crosvm" => (
            "VMM overhead; guest RAM is a shmem/memfd on crosvm (~1 MiB/guest — at the CH floor)",
            "crosvm guest-RAM memfd; the real density figure",
        ),
        _ => (
            "RssAnon: VMM overhead / anon guest RAM (backend-dependent)",
            "RssShmem: shared guest RAM, if the backend uses a memfd (backend-dependent)",
        ),
    }
}

/// Recursively lists `(path, size)` for every regular file under `dir`.
fn walk_files(dir: &Path) -> Vec<(PathBuf, u64)> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        if let Ok(rd) = std::fs::read_dir(&d) {
            for e in rd.flatten() {
                let p = e.path();
                if let Ok(md) = e.metadata() {
                    if md.is_dir() {
                        stack.push(p);
                    } else if md.is_file() {
                        out.push((p, md.len()));
                    }
                }
            }
        }
    }
    out
}

/// Picks a working zero-cost exec probe command, preferring `/bin/true`.
async fn pick_exec_cmd<V: Vmm>(vm: &mut MicroVm<V>) -> Vec<String> {
    let candidates = [
        vec!["/bin/true".to_string()],
        vec!["/usr/bin/true".to_string()],
        vec!["true".to_string()],
    ];
    for c in candidates {
        if let Ok(steward) = vm.steward(None).await
            && let Ok(o) = steward.exec(ExecRequest::new(c.clone())).await
            && o.code == 0
        {
            return c;
        }
    }
    vec!["cat".to_string(), "/proc/uptime".to_string()]
}

fn mean_u64(v: &[u64]) -> u64 {
    if v.is_empty() {
        0
    } else {
        v.iter().sum::<u64>() / v.len() as u64
    }
}

// ----------------------------------------------------------------------------
// §16 (Performance) — footprint: per-guest RAM, shared erofs page cache, KSM dedup.
// ----------------------------------------------------------------------------
async fn run_footprint<V: Vmm>(
    vmm: &V,
    rec: &Recorder,
    backend: &str,
    args: &Args,
    allocator: VmidAllocator,
) -> anyhow::Result<()> {
    let (dir, kernel, rootfs) = artifact_paths(args.kernel.as_deref())?;
    require_artifacts("footprint", &dir, &kernel, &rootfs)?;
    // N-BIN-2: `--count 0` is rejected loudly in `validate_vm_params`, so `count` is
    // >= 1 here (no silent `.max(1)` clamp).
    let count = args.count;
    let cfg = build_cfg(args, kernel, rootfs, args.ksm_mergeable, false);
    let mut env = HostEnv::hermetic();
    env.vmids = allocator.clone();

    let ksm_shared_before = read_ksm("pages_shared");
    let ksm_sharing_before = read_ksm("pages_sharing");

    // Boot guests one-by-one, holding them all alive in a Vec (so all N coexist),
    // and snapshot the *total* host RssAnon after each addition — this yields a
    // real marginal slope (step N minus step N-1) within a single invocation.
    let mut vms: Vec<MicroVm<V>> = Vec::new();
    let mut step_anon: Vec<u64> = Vec::new();
    let mut step_shmem: Vec<u64> = Vec::new();
    for i in 0..count {
        let mut vm = match MicroVm::start(vmm, cfg.clone(), &env).await {
            Ok(v) => v,
            Err(e) => {
                say!("footprint: boot {i} failed: {e}");
                break;
            }
        };
        if let Err(e) = vm.steward(None).await {
            say!("footprint: steward connect {i} failed: {e}");
            // Best-effort teardown of the just-booted guest before bailing; `Drop`
            // guarantees the real teardown, so a shutdown error is not actionable.
            best_effort::shutdown(vm).await;
            break;
        }
        vms.push(vm);
        // Sum host RssAnon and RssShmem across all alive VMs. CH backs guest RAM
        // with a shared memfd, so guest RAM is accounted as RssShmem, not RssAnon
        // (RssAnon is then just VMM overhead) — both slopes are reported.
        let mut anon = 0u64;
        let mut shmem = 0u64;
        for v in &vms {
            if let Some(pid) = find_host_pid(v.instance().vsock_path(), backend) {
                anon += read_proc_status_kb(pid, "RssAnon").unwrap_or(0);
                shmem += read_proc_status_kb(pid, "RssShmem").unwrap_or(0);
            }
        }
        step_anon.push(anon / 1024);
        step_shmem.push(shmem / 1024);
    }

    let n = vms.len();
    if n == 0 {
        say!("footprint: No successful runs");
        anyhow::bail!("footprint: no guests booted");
    }

    // Give KSM a window to scan & dedup the now-resident guest pages. With the
    // mergeable lever on, accelerate the scanner (CAP_DAC_OVERRIDE via the runner)
    // so dedup converges in a bounded window, then restore the prior KSM settings.
    let ksm_saved = if args.ksm_mergeable {
        let saved = (
            read_ksm("pages_to_scan"),
            read_ksm("sleep_millis"),
            read_ksm("run"),
        );
        // `run`/`pages_to_scan` are the essential knobs; `sleep_millis` is absent
        // on some kernels (7.x), so bump it opportunistically without requiring it.
        let accel = write_ksm("run", "1") && write_ksm("pages_to_scan", "20000");
        let _ = write_ksm("sleep_millis", "5");
        rec.caveat(ksm_acceleration_caveat(accel));
        Some(saved)
    } else {
        None
    };
    let window_secs = if args.ksm_mergeable { 25 } else { 8 };
    tokio::time::sleep(std::time::Duration::from_secs(window_secs)).await;
    let ksm_shared_after = read_ksm("pages_shared");
    let ksm_sharing_after = read_ksm("pages_sharing");
    if let Some((scan, sleep, run)) = ksm_saved {
        // Best-effort restore of the KSM scanner settings bumped above.
        let _ = write_ksm("pages_to_scan", &scan.to_string());
        let _ = write_ksm("sleep_millis", &sleep.to_string());
        let _ = write_ksm("run", &run.to_string());
    }

    let mut tot_anon = 0u64;
    let mut tot_file = 0u64;
    let mut tot_shmem = 0u64;
    let mut guest_total = 0u64;
    let mut guest_avail = Vec::new();
    let mut pid1_rss = Vec::new();
    // M-BIN-7: count how many per-VM host pids actually resolved, so an unresolved
    // process (collapsed to 0 by `unwrap_or(0)`) is visible instead of silently
    // deflating the reported totals.
    let mut resolved = 0usize;
    for v in vms.iter_mut() {
        let vsock = v.instance().vsock_path().to_path_buf();
        if let Some(pid) = find_host_pid(&vsock, backend) {
            resolved += 1;
            tot_anon += read_proc_status_kb(pid, "RssAnon").unwrap_or(0);
            tot_file += read_proc_status_kb(pid, "RssFile").unwrap_or(0);
            tot_shmem += read_proc_status_kb(pid, "RssShmem").unwrap_or(0);
        }
        if let Ok(steward) = v.steward(None).await {
            if let Ok(o) = steward
                .exec(ExecRequest::new(vec!["cat".into(), "/proc/meminfo".into()]))
                .await
            {
                let s = String::from_utf8_lossy(&o.stdout);
                if let Some(t) = parse_kv_kb(&s, "MemTotal") {
                    guest_total = t;
                }
                if let Some(a) = parse_kv_kb(&s, "MemAvailable") {
                    guest_avail.push(a);
                }
            }
            if let Ok(o) = steward
                .exec(ExecRequest::new(vec![
                    "cat".into(),
                    "/proc/1/status".into(),
                ]))
                .await
            {
                let s = String::from_utf8_lossy(&o.stdout);
                if let Some(r) = parse_kv_kb(&s, "VmRSS") {
                    pid1_rss.push(r);
                }
            }
        }
    }

    // Marginal cost of each additional resident guest: step N minus step N-1, with the first step
    // its own marginal. Carrying `prev` (seeded 0, so the first subtraction is a no-op) keeps this
    // index-free — the arithmetic that would panic on an empty/short slice cannot be written.
    let marginal_of = |steps: &[u64]| -> Vec<u64> {
        let mut prev = 0u64;
        steps
            .iter()
            .map(|&s| {
                let marginal = s.saturating_sub(prev);
                prev = s;
                marginal
            })
            .collect()
    };
    let marginals = marginal_of(&step_anon);
    let marg_mean = mean_u64(&marginals);
    let marginals_shmem = marginal_of(&step_shmem);
    let marg_mean_shmem = mean_u64(&marginals_shmem);

    let (anon_note, shmem_note) = footprint_mem_notes(backend);
    say!(
        "=== FOOTPRINT (backend={backend} N={n} mem_mib={}) ===",
        args.mem_mib
    );
    // M-BIN-7: surface incomplete host-pid attribution instead of silently reporting
    // deflated totals as if every VM resolved.
    rec.caveat(pid_attribution_caveat(resolved, n));
    // Both halves of each row are recorded, not just the total: a per-guest mean is integer
    // division of the MiB total by the guest count, so a consumer handed only the total would have
    // to re-derive the number the table shows — the "re-derive it downstream" step that produced
    // the wrong figures on 2026-08-21.
    let per_guest = |total_kb: u64| (total_kb / 1024) / n as u64;
    say!(
        "host RssAnon total = {} MiB  (per-guest mean = {} MiB)  [{anon_note}]",
        rec.scalar(
            metrics::FOOTPRINT_RSS_ANON_TOTAL,
            Unit::Mib,
            n,
            sample_as_f64(u128::from(tot_anon / 1024))
        ),
        rec.scalar(
            metrics::FOOTPRINT_RSS_ANON_PER_GUEST,
            Unit::Mib,
            n,
            sample_as_f64(u128::from(per_guest(tot_anon)))
        )
    );
    say!(
        "host RssFile total = {} MiB  (per-guest mean = {} MiB)  [shared-erofs page cache]",
        rec.scalar(
            metrics::FOOTPRINT_RSS_FILE_TOTAL,
            Unit::Mib,
            n,
            sample_as_f64(u128::from(tot_file / 1024))
        ),
        rec.scalar(
            metrics::FOOTPRINT_RSS_FILE_PER_GUEST,
            Unit::Mib,
            n,
            sample_as_f64(u128::from(per_guest(tot_file)))
        )
    );
    say!(
        "host RssShmem total = {} MiB  (per-guest mean = {} MiB)  [{shmem_note}]",
        rec.scalar(
            metrics::FOOTPRINT_RSS_SHMEM_TOTAL,
            Unit::Mib,
            n,
            sample_as_f64(u128::from(tot_shmem / 1024))
        ),
        rec.scalar(
            metrics::FOOTPRINT_RSS_SHMEM_PER_GUEST,
            Unit::Mib,
            n,
            sample_as_f64(u128::from(per_guest(tot_shmem)))
        )
    );
    say!("per-step total host RssAnon  (MiB) 1..N = {step_anon:?}");
    say!("per-step total host RssShmem (MiB) 1..N = {step_shmem:?}");
    say!(
        "marginal host RssAnon  per added guest (MiB): mean={}  series={marginals:?}  [VMM overhead only]",
        rec.scalar(
            metrics::FOOTPRINT_MARGINAL_RSS_ANON,
            Unit::Mib,
            n,
            sample_as_f64(u128::from(marg_mean))
        )
    );
    say!(
        "marginal host RssShmem per added guest (MiB): mean={}  series={marginals_shmem:?}  [guest-RAM touched; step N - step N-1]",
        rec.scalar(
            metrics::FOOTPRINT_MARGINAL_RSS_SHMEM,
            Unit::Mib,
            n,
            sample_as_f64(u128::from(marg_mean_shmem))
        )
    );
    let sharing_delta = ksm_sharing_after.saturating_sub(ksm_sharing_before);
    say!(
        "KSM pages_sharing: before={ksm_sharing_before} after={ksm_sharing_after} delta={} (~{} MiB dedup'd @4KiB)",
        rec.scalar(
            metrics::FOOTPRINT_KSM_PAGES_SHARING_DELTA,
            Unit::Count,
            n,
            sample_as_f64(u128::from(sharing_delta))
        ),
        sharing_delta * 4 / 1024
    );
    say!("KSM pages_shared:  before={ksm_shared_before} after={ksm_shared_after}");
    rec.caveat(ksm_residue_caveat(args.ksm_mergeable));
    say!(
        "guest MemTotal = {} MiB  MemAvailable mean = {} MiB",
        rec.scalar(
            metrics::FOOTPRINT_GUEST_MEM_TOTAL,
            Unit::Mib,
            n,
            sample_as_f64(u128::from(guest_total / 1024))
        ),
        rec.scalar(
            metrics::FOOTPRINT_GUEST_MEM_AVAILABLE,
            Unit::Mib,
            n,
            sample_as_f64(u128::from(mean_u64(&guest_avail) / 1024))
        )
    );
    // Recorded in BYTES and printed back as KiB: the report's `Unit` has no KiB, and inventing one
    // for a single row would put a unit in the schema that only this line ever emits. The division
    // is exact (the recorded value is `kib * 1024`), so the printed row is byte-identical to the
    // integer it used to print.
    say!(
        "guest pid1 (steward) RSS mean = {} KiB",
        rec.scalar(
            metrics::FOOTPRINT_GUEST_PID1_RSS,
            Unit::Bytes,
            n,
            sample_as_f64(u128::from(mean_u64(&pid1_rss)) * 1024)
        ) / 1024.0
    );

    // Best-effort teardown of every resident guest; `Drop` is the guaranteed path,
    // so a shutdown error on any one VM must not abort cleanup of the rest.
    for v in vms {
        best_effort::shutdown(v).await;
    }
    Ok(())
}

// ----------------------------------------------------------------------------
// §16 (Performance) — suspend-size: snapshot bytes + memory-file share, vs guest RAM.
// ----------------------------------------------------------------------------
async fn run_suspend_size<V: Vmm>(
    vmm: &V,
    rec: &Recorder,
    backend: &str,
    args: &Args,
    allocator: VmidAllocator,
) -> anyhow::Result<()> {
    let (dir, kernel, rootfs) = artifact_paths(args.kernel.as_deref())?;
    require_artifacts("suspend-size", &dir, &kernel, &rootfs)?;
    if !vmm.capabilities().snapshot_restore {
        // Genuine capability skip → success (M-BIN-1), not a failure.
        rec.skip(format!(
            "suspend-size: backend {backend} has no snapshot support; skipping"
        ));
        return Ok(());
    }
    let cfg = build_cfg(args, kernel, rootfs, false, true);
    let mut env = HostEnv::hermetic();
    env.vmids = allocator;
    let snap_dir = resolve_snap_dir(&args.snap_dir).join(format!(
        "suspend-{backend}-{}-{}",
        args.mem_mib,
        std::process::id()
    ));
    // Best-effort pre-clean of a stale snapshot dir from a prior aborted run.
    best_effort::discard_dir(&snap_dir);
    if let Err(e) = std::fs::create_dir_all(&snap_dir) {
        anyhow::bail!(
            "suspend-size: cannot create snap dir {}: {e}",
            snap_dir.display()
        );
    }

    let mut vm = match MicroVm::start(vmm, cfg, &env).await {
        Ok(v) => v,
        Err(e) => {
            // Best-effort removal of the (empty) snapshot dir before bailing.
            best_effort::discard_dir(&snap_dir);
            anyhow::bail!("suspend-size: boot failed: {e}");
        }
    };
    if let Err(e) = vm.steward(None).await {
        // Best-effort teardown + snapshot-dir cleanup; `Drop` guarantees the real
        // teardown and neither cleanup error is actionable.
        best_effort::shutdown(vm).await;
        best_effort::discard_dir(&snap_dir);
        anyhow::bail!("suspend-size: steward connect failed: {e}");
    }
    if let Err(e) = vm.snapshot(&snap_dir).await {
        // Best-effort teardown + partial-snapshot cleanup on the failure path.
        best_effort::shutdown(vm).await;
        best_effort::discard_dir(&snap_dir);
        anyhow::bail!("suspend-size: snapshot failed: {e}");
    }
    // Best-effort graceful shutdown before we measure the on-disk snapshot; `Drop`
    // guarantees teardown regardless of this result.
    best_effort::shutdown(vm).await;

    let files = walk_files(&snap_dir);
    let total: u64 = files.iter().map(|(_, s)| *s).sum();
    let (mem_path, mem_size) = files
        .iter()
        .max_by_key(|(_, s)| *s)
        .cloned()
        .unwrap_or((snap_dir.clone(), 0));
    let share = if total > 0 {
        (mem_size as f64) * 100.0 / (total as f64)
    } else {
        0.0
    };
    let fname = |p: &Path| -> String {
        p.file_name()
            .map(|n| n.to_string_lossy().into())
            .unwrap_or_default()
    };

    say!(
        "=== SUSPEND-SIZE (backend={backend} mem_mib={}) ===",
        args.mem_mib
    );
    // Every printed number here comes back out of the recorder, so the MiB rendering and the JSON
    // byte count are two views of one value rather than two computations of it.
    let total_bytes = rec.scalar(
        metrics::SUSPEND_TOTAL_BYTES,
        Unit::Bytes,
        1,
        sample_as_f64(u128::from(total)),
    );
    say!(
        "total snapshot bytes = {total_bytes} ({:.1} MiB)",
        total_bytes / 1048576.0
    );
    let mem_bytes = rec.scalar(
        metrics::SUSPEND_MEMORY_FILE_BYTES,
        Unit::Bytes,
        1,
        sample_as_f64(u128::from(mem_size)),
    );
    say!(
        "memory file = {} : {mem_bytes} bytes ({:.1} MiB)",
        fname(&mem_path),
        mem_bytes / 1048576.0
    );
    say!(
        "memory-file share of total = {:.1}%",
        rec.scalar(metrics::SUSPEND_MEMORY_FILE_SHARE, Unit::Percent, 1, share)
    );
    say!("all files:");
    for (p, s) in &files {
        say!("  {s:>12}  {}", fname(p));
    }

    // Best-effort cleanup of the measured snapshot dir now that it's been reported.
    best_effort::discard_dir(&snap_dir);
    Ok(())
}

// ----------------------------------------------------------------------------
// §16 (Performance) — phase-budget: per-phase distribution + share, restore and cold.
// ----------------------------------------------------------------------------
async fn build_baseline_snapshot<V: Vmm>(
    vmm: &V,
    cfg: &VmConfig,
    env: &HostEnv,
    snap_dir: &Path,
) -> Result<(), String> {
    let mut base = MicroVm::start(vmm, cfg.clone(), env)
        .await
        .map_err(|e| e.to_string())?;
    base.steward(None).await.map_err(|e| e.to_string())?;
    base.snapshot(snap_dir).await.map_err(|e| e.to_string())?;
    // Best-effort graceful shutdown of the baseline VM once its snapshot is written;
    // `Drop` guarantees teardown, so a shutdown error must not fail the (successful)
    // snapshot build we return `Ok` for.
    best_effort::shutdown(base).await;
    Ok(())
}

/// One phase-budget row: the phase's distribution and its share of the whole.
///
/// `metric` is QUALIFIED BY PATH (`phase_cold_connect`, `phase_restore_teardown`) because the COLD
/// and RESTORE paths print the same four row names — `create`/`connect`/`exec`/`teardown` — and the
/// 2026-08-21 collector, keying on the printed name, silently kept only the first path's numbers
/// and reported them as both. The share rides beside the distribution as its own `Percent` metric:
/// it is computed from the phase MEAN, which no percentile field carries, so a consumer handed only
/// the four percentiles could not recover it.
///
/// `planned` is the post-warmup iteration count the path set out to take. It used to be a literal
/// `0` for both loss counts, and `phase_budget_path` `break`s out of its loop on the first failed
/// create or connect — so eight phase rows, two totals and eight shares reported a clean sample
/// set over however many iterations happened before the first failure, and `bench-ab` ranked them
/// against a complete arm with no idea it was doing so.
fn report_phase(
    rec: &Recorder,
    name: &str,
    metric: &str,
    v: &mut [u128],
    planned: usize,
    total_mean_us: u128,
) {
    let n = v.len() as u128;
    let mean = v.iter().sum::<u128>().checked_div(n).unwrap_or(0);
    let share = if total_mean_us > 0 {
        (mean as f64) * 100.0 / (total_mean_us as f64)
    } else {
        0.0
    };
    match rec.measure(metric, Unit::Micros, v, planned, 0) {
        Some(m) => say!(
            "  {name}: p50={}µs p95={}µs max={}µs  share={:.1}%",
            m.p50,
            m.p95,
            m.max,
            rec.scalar(&metrics::share_metric(metric), Unit::Percent, m.n, share)
        ),
        // Unreachable from both call sites — `phase_budget_path` bails on an empty sample set
        // before it reports — and deliberately records NOTHING rather than a fabricated zero
        // metric: a comparator must not rank a row that was never measured.
        None => say!("  {name}: No successful samples"),
    }
}

async fn phase_budget_path<V: Vmm>(
    vmm: &V,
    rec: &Recorder,
    backend: &str,
    args: &Args,
    cfg: &VmConfig,
    env: &HostEnv,
    snap_dir: Option<PathBuf>,
) -> anyhow::Result<()> {
    let label = if snap_dir.is_some() {
        "RESTORE"
    } else {
        "COLD"
    };
    // The metric-name half of `label`. Qualifying by PATH is the whole point (see `report_phase`),
    // and deriving it from the same `snap_dir.is_some()` is what keeps the printed path and the
    // recorded path from ever naming different things.
    let path = if snap_dir.is_some() {
        "restore"
    } else {
        "cold"
    };
    let iters = args.iters();
    let mut p_create = Vec::new();
    let mut p_connect = Vec::new();
    let mut p_exec = Vec::new();
    let mut p_teardown = Vec::new();
    let mut cmd: Option<Vec<String>> = None;

    for i in 0..(iters + args.warmup) {
        if snap_dir.is_none() {
            // Best-effort cold-cache drop for the cold-boot budget. Unlike `run_bench`
            // (which labels the warm case), the phase-budget cold path is opt-in and
            // relative, so a failed drop just yields warm-cache create timing — not a
            // wrong result — and needs no CAP_SYS_ADMIN gate here.
            let _ = drop_page_cache();
        }
        let t0 = Instant::now();
        let vm_res = match &snap_dir {
            Some(d) => MicroVm::restore(vmm, d, cfg.clone(), env).await,
            None => MicroVm::start(vmm, cfg.clone(), env).await,
        };
        let t_create = t0.elapsed();
        let mut vm = match vm_res {
            Ok(v) => v,
            Err(e) => {
                say!("phase-budget {label}: iter {i} create failed: {e}");
                break;
            }
        };

        let t1 = Instant::now();
        let connect_ok = vm.steward(None).await.is_ok();
        let t_connect = t1.elapsed();
        if !connect_ok {
            say!("phase-budget {label}: iter {i} connect failed");
            // Best-effort teardown before bailing; `Drop` guarantees teardown.
            best_effort::shutdown(vm).await;
            break;
        }

        if cmd.is_none() {
            cmd = Some(pick_exec_cmd(&mut vm).await);
        }
        let argv = cmd
            .clone()
            .unwrap_or_else(|| vec!["cat".into(), "/proc/uptime".into()]);

        let t2 = Instant::now();
        if let Ok(steward) = vm.steward(None).await {
            // The exec *result* is intentionally unused: this phase measures the
            // exec-round-trip latency (t2..t_exec), not the command's exit/output.
            #[expect(
                clippy::let_underscore_must_use,
                reason = "this phase measures the exec ROUND TRIP; the command's exit/output is not the sample"
            )]
            let _ = steward.exec(ExecRequest::new(argv)).await;
        }
        let t_exec = t2.elapsed();

        let t3 = Instant::now();
        // Teardown is deliberately on the budget (§16, Performance): we time it, and `Drop`
        // still guarantees the real teardown if `shutdown` errors.
        best_effort::shutdown(vm).await;
        let t_teardown = t3.elapsed();

        if i >= args.warmup {
            p_create.push(t_create.as_micros());
            p_connect.push(t_connect.as_micros());
            p_exec.push(t_exec.as_micros());
            p_teardown.push(t_teardown.as_micros());
        }
    }

    if p_create.is_empty() {
        say!("phase-budget {label} ({backend}): No successful runs");
        anyhow::bail!("phase-budget {label} ({backend}): no successful post-warmup samples");
    }

    let sum = |v: &[u128]| -> u128 { v.iter().sum() };
    let runs = p_create.len() as u128;
    let total_mean = (sum(&p_create) + sum(&p_connect) + sum(&p_exec) + sum(&p_teardown)) / runs;
    say!(
        "=== PHASE-BUDGET {label} (backend={backend} n={}) ===",
        p_create.len()
    );
    report_phase(
        rec,
        "create  ",
        &metrics::phase_metric(path, "create"),
        &mut p_create,
        iters,
        total_mean,
    );
    report_phase(
        rec,
        "connect ",
        &metrics::phase_metric(path, "connect"),
        &mut p_connect,
        iters,
        total_mean,
    );
    report_phase(
        rec,
        "exec    ",
        &metrics::phase_metric(path, "exec"),
        &mut p_exec,
        iters,
        total_mean,
    );
    report_phase(
        rec,
        "teardown",
        &metrics::phase_metric(path, "teardown"),
        &mut p_teardown,
        iters,
        total_mean,
    );
    say!(
        "  TOTAL (sum of phase means) ~= {} µs",
        rec.scalar(
            &metrics::phase_total_metric(path),
            Unit::Micros,
            p_create.len(),
            sample_as_f64(total_mean)
        )
    );
    Ok(())
}

async fn run_phase_budget<V: Vmm>(
    vmm: &V,
    rec: &Recorder,
    backend: &str,
    args: &Args,
    allocator: VmidAllocator,
) -> anyhow::Result<()> {
    let (dir, kernel, rootfs) = artifact_paths(args.kernel.as_deref())?;
    require_artifacts("phase-budget", &dir, &kernel, &rootfs)?;
    let cfg = build_cfg(args, kernel, rootfs, false, true);
    let mut env = HostEnv::hermetic();
    env.vmids = allocator;

    // Cold-boot path (opt-in budget). A zero-sample cold path is an attempted-and-
    // failed run → propagate (M-BIN-1).
    phase_budget_path(vmm, rec, backend, args, &cfg, &env, None).await?;

    // Restore path (the hot path) — build the baseline snapshot once.
    if vmm.capabilities().snapshot_restore {
        let snap_dir = resolve_snap_dir(&args.snap_dir)
            .join(format!("phase-{backend}-{}", std::process::id()));
        // Best-effort pre-clean of a stale snapshot dir from a prior aborted run.
        best_effort::discard_dir(&snap_dir);
        if let Err(e) = std::fs::create_dir_all(&snap_dir) {
            anyhow::bail!("phase-budget: cannot create snap dir: {e}");
        }
        let baseline = build_baseline_snapshot(vmm, &cfg, &env, &snap_dir).await;
        let restore_res = match baseline {
            Ok(()) => {
                phase_budget_path(vmm, rec, backend, args, &cfg, &env, Some(snap_dir.clone())).await
            }
            Err(e) => Err(anyhow::anyhow!(
                "phase-budget: baseline snapshot failed: {e}"
            )),
        };
        // Best-effort cleanup of the baseline snapshot dir after the restore budget,
        // regardless of whether the restore path succeeded.
        best_effort::discard_dir(&snap_dir);
        restore_res?;
    } else {
        // Genuine capability skip → success; the cold path already ran.
        rec.skip(format!(
            "phase-budget: backend {backend} has no restore; cold path only"
        ));
    }
    Ok(())
}

// ----------------------------------------------------------------------------
// §16 (Performance) — vsock-rtt: control-plane exec round-trip latency floor.
// ----------------------------------------------------------------------------
async fn run_vsock_rtt<V: Vmm>(
    vmm: &V,
    rec: &Recorder,
    backend: &str,
    args: &Args,
    allocator: VmidAllocator,
) -> anyhow::Result<()> {
    let (dir, kernel, rootfs) = artifact_paths(args.kernel.as_deref())?;
    require_artifacts("vsock-rtt", &dir, &kernel, &rootfs)?;
    let cfg = build_cfg(args, kernel, rootfs, false, false);
    let mut env = HostEnv::hermetic();
    env.vmids = allocator;
    let iters = args.iters();

    let mut vm = match MicroVm::start(vmm, cfg, &env).await {
        Ok(v) => v,
        Err(e) => anyhow::bail!("vsock-rtt: boot failed: {e}"),
    };
    if let Err(e) = vm.steward(None).await {
        // Best-effort teardown before bailing; `Drop` guarantees teardown.
        best_effort::shutdown(vm).await;
        anyhow::bail!("vsock-rtt: steward connect failed: {e}");
    }
    let argv = pick_exec_cmd(&mut vm).await;

    for _ in 0..args.warmup {
        if let Ok(steward) = vm.steward(None).await {
            // Warmup iteration: the exec result is discarded on purpose (it primes
            // caches / the vsock path and is not part of the measured sample).
            #[expect(
                clippy::let_underscore_must_use,
                reason = "warmup: primes the caches and the vsock path; it is not part of the measured sample"
            )]
            let _ = steward.exec(ExecRequest::new(argv.clone())).await;
        }
    }

    let mut rtts = Vec::with_capacity(iters);
    // H-BIN-2: count exec failures that shrink the sample set instead of the silent
    // `if r.is_ok()` drop, and surface the error rather than a bare `break`.
    for i in 0..iters {
        let steward = match vm.steward(None).await {
            Ok(a) => a,
            Err(e) => {
                say!("vsock-rtt: iteration {i} steward-connect failed: {e}");
                break;
            }
        };
        let t = Instant::now();
        let r = steward.exec(ExecRequest::new(argv.clone())).await;
        let dt = t.elapsed().as_micros();
        match r {
            Ok(_) => rtts.push(dt),
            Err(e) => {
                say!("vsock-rtt: iteration {i} exec failed: {e}");
            }
        }
    }
    // Best-effort teardown after the run; `Drop` guarantees the real teardown, so a
    // shutdown error must not corrupt the collected RTT report below.
    best_effort::shutdown(vm).await;

    // Through the one law, so the printed row and the JSON field cannot disagree about how lossy
    // the run was — they did while this read the raw counter and `measure` below took `planned`.
    let acct = accounting_suffix(dropped_iterations(iters, rtts.len()), 0);
    say!(
        "=== VSOCK-RTT (backend={backend} n={}{acct} cmd={argv:?}) ===",
        rtts.len()
    );
    match rec.measure(metrics::VSOCK_RTT, Unit::Micros, &mut rtts, iters, 0) {
        Some(m) => {
            say!(
                "  per-round-trip exec latency: p50={}µs p95={}µs p99={}µs max={}µs",
                m.p50,
                m.p95,
                m.p99,
                m.max
            );
            Ok(())
        }
        None => {
            say!("  No successful runs");
            // M-BIN-1: attempted but zero samples → fail loud.
            anyhow::bail!("vsock-rtt: no successful exec round-trips");
        }
    }
}

// ----------------------------------------------------------------------------
// net-egress: boot-with-networking latency + in-guest egress round-trip (§13, the
// L-invariant data plane). Fills the coverage gap where every other mode uses
// `network_disabled()` and never exercises the smoltcp NAT.
// ----------------------------------------------------------------------------

/// A minimal host-side HTTP/1.1 responder for the `net-egress` benchmark: binds
/// `127.0.0.1:0`, answers every connection with a fixed 200 body, and is reaped on
/// `Drop` (ownership owns cleanup — it survives a panic mid-run). The guest reaches
/// it through the smoltcp NAT at `http://<gateway_ip>:<port>/`. In-process `std::net`
/// (no `python3 -m http.server` dependency, unlike the integration tests).
struct HostResponder {
    port: u16,
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl HostResponder {
    fn start() -> std::io::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let port = listener.local_addr()?.port();
        // Non-blocking accept + a poll loop so `Drop` can stop the thread promptly
        // without a self-connect wakeup hack.
        listener.set_nonblocking(true)?;
        let stop = Arc::new(AtomicBool::new(false));
        let stop_thread = stop.clone();
        let handle = std::thread::spawn(move || {
            const BODY: &[u8] = b"vmcell-egress-ok\n";
            while !stop_thread.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut conn, _)) => {
                        // Drain one request chunk (a GET fits in 1 KiB) before replying,
                        // so curl doesn't take an RST on unread data; then a fixed 200.
                        let head = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            BODY.len()
                        );
                        best_effort::serve_canned_response(&mut conn, &head, BODY);
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(std::time::Duration::from_millis(5));
                    }
                    // A real accept error (fd exhaustion, etc.) ends the responder; the
                    // bench's per-request checks then surface it as dropped samples.
                    Err(_) => break,
                }
            }
        });
        Ok(Self {
            port,
            stop,
            handle: Some(handle),
        })
    }
}

impl Drop for HostResponder {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            // `Drop` must not unwind, so the responder thread's panic payload is deliberately
            // dropped rather than resumed; the stop flag above is what actually ends it.
            #[expect(
                clippy::let_underscore_must_use,
                reason = "Drop must not unwind: a responder-thread panic payload is dropped, never resumed"
            )]
            let _ = h.join();
        }
    }
}

/// The in-guest egress client: `curl -s --max-time 5 <url>`. The `curl` this resolves to is the
/// **guest-tools multicall shim** at `/vmcell-tools/curl`, which the steward puts FIRST on the
/// child PATH (`child_path`): the OCI rootfs this repo builds carries no GNU curl at all, so the
/// shim is the only `curl` in the guest — the measured round-trip is that applet's HTTP GET, not
/// upstream curl's (the old comment claimed a rootfs `--include=curl`, which no shipped rootfs
/// recipe does).
fn egress_curl(url: &str) -> Vec<String> {
    vec![
        "curl".to_string(),
        "-s".to_string(),
        "--max-time".to_string(),
        "5".to_string(),
        url.to_string(),
    ]
}

/// §16 (Performance) — net-egress dispatcher: `--net-mode plain` (unprivileged smoltcp
/// NAT datapath), `tls` (unprivileged smoltcp + MITM proxy), or `privileged` (tap +
/// netns + nft + MITM proxy). Each self-skips where its facility is absent.
async fn run_net_egress<V: Vmm>(
    vmm: &V,
    rec: &Recorder,
    backend: &str,
    args: &Args,
    allocator: VmidAllocator,
) -> anyhow::Result<()> {
    match args.net_mode.as_str() {
        "plain" => run_net_egress_plain(vmm, rec, backend, args, allocator).await,
        "tls" => run_net_egress_filtered(vmm, rec, backend, args, allocator, false).await,
        "privileged" => run_net_egress_filtered(vmm, rec, backend, args, allocator, true).await,
        // Pre-validated by `parse_net_mode`; fail loud rather than silently succeed if the
        // two ever drift.
        other => anyhow::bail!("net-egress: unknown --net-mode '{other}'"),
    }
}

/// §16 (Performance) — net-egress `plain`: (A) VM start latency WITH the smoltcp NAT on
/// the boot path, and (B) the in-guest egress round-trip through the NAT to a host
/// endpoint (asserting a real egress byte, not a proxy signal — §15/AGENTS.md).
async fn run_net_egress_plain<V: Vmm>(
    vmm: &V,
    rec: &Recorder,
    backend: &str,
    args: &Args,
    allocator: VmidAllocator,
) -> anyhow::Result<()> {
    // Self-skip: the unprivileged smoltcp NAT needs the vhost-user-net device (CH +
    // QEMU; Firecracker has none). A capability skip is success (Ok), not a failure
    // (M-BIN-1).
    if !vmm.capabilities().unprivileged_vhost_user_net {
        rec.skip(format!(
            "net-egress: backend {backend} has no unprivileged vhost-user-net; skipping"
        ));
        return Ok(());
    }
    let (dir, kernel, rootfs) = artifact_paths(args.kernel.as_deref())?;
    require_artifacts("net-egress", &dir, &kernel, &rootfs)?;

    // Host endpoint the guest NATs to, owned in a Drop guard (reaped even on panic).
    let responder = HostResponder::start()
        .map_err(|e| anyhow::anyhow!("net-egress: failed to start host responder: {e}"))?;
    let host_port = responder.port;

    // Networked config (NOT `network_disabled()`); same tunable knobs as `build_cfg`.
    let cfg = VmConfig::builder(kernel, RootfsSource::Erofs { image: rootfs })
        .vcpus(1)
        .mem_mib(args.mem_mib)
        .net(NetConfig::Unprivileged {
            egress: Egress::Open,
            host_services_port: Some(host_port),
        })
        .restore_mode(args.restore_mode)
        .timeouts(timeouts_for(&args.profile))
        .kernel_verbosity(args.kernel_verbosity)
        .console_mode(args.console)
        .build()
        .map_err(|e| anyhow::anyhow!("net-egress: invalid config: {e}"))?;

    let mut env = HostEnv::hermetic();
    env.vmids = allocator;
    let iters = args.iters();

    // The smoltcp vhost-user-net daemon intermittently fails to bind its UDS (~10% of
    // boots the daemon thread errors and the socket never appears within the readiness
    // ceiling — a latent smoltcp bring-up flake this volume probe surfaced; the existing
    // egress tests boot a single VM and never hit it. See docs/benchmark-results.md).
    // Retry a transient boot failure on a FRESH VM (fresh smoltcp) a bounded number of
    // times, counting the retries so they are visible, not hidden (mirrors the QEMU vsock
    // re-spawn recovery). A steward-connect failure is separate `dropped` accounting.
    const NET_BOOT_RETRIES: usize = 5;

    // --- Phase A: start latency WITH the smoltcp NAT set up on the boot path ---
    let mut starts = Vec::new();
    let mut boot_retries = 0usize;
    for i in 0..(iters + args.warmup) {
        let mut attempt = 0usize;
        loop {
            let t = Instant::now();
            match MicroVm::start(vmm, cfg.clone(), &env).await {
                Ok(mut vm) => {
                    match vm.steward(None).await {
                        Ok(_) => {
                            let dt = t.elapsed().as_millis();
                            if i >= args.warmup {
                                starts.push(dt);
                            }
                        }
                        Err(e) => {
                            say!("net-egress: net-start iter {i} steward-connect failed: {e}");
                            if i >= args.warmup {}
                        }
                    }
                    best_effort::shutdown(vm).await;
                    break;
                }
                Err(e) => {
                    attempt += 1;
                    if attempt > NET_BOOT_RETRIES {
                        anyhow::bail!(
                            "net-egress: net-start iter {i} start failed after {attempt} attempts: {e}"
                        );
                    }
                    boot_retries += 1;
                    say!(
                        "net-egress: net-start iter {i} transient boot failure (attempt {attempt}, retrying): {e}"
                    );
                }
            }
        }
    }
    if boot_retries > 0 {
        say!(
            "net-egress: NET-START recovered {boot_retries} transient smoltcp-bringup boot failure(s) via retry"
        );
    }
    report(
        rec,
        "NET-START (boot with smoltcp NAT)",
        metrics::NET_START,
        &mut starts,
        iters,
        0,
    );

    // --- Phase B: steady egress round-trip (one warm VM, N in-guest curls) ---
    // Same bounded retry over the smoltcp bring-up flake as Phase A.
    let mut vm = {
        let mut attempt = 0usize;
        loop {
            match MicroVm::start(vmm, cfg.clone(), &env).await {
                Ok(v) => break v,
                Err(e) => {
                    attempt += 1;
                    if attempt > NET_BOOT_RETRIES {
                        anyhow::bail!(
                            "net-egress: egress VM boot failed after {attempt} attempts: {e}"
                        );
                    }
                    say!(
                        "net-egress: egress VM transient boot failure (attempt {attempt}, retrying): {e}"
                    );
                }
            }
        }
    };
    if let Err(e) = vm.steward(None).await {
        best_effort::shutdown(vm).await;
        anyhow::bail!("net-egress: egress VM steward connect failed: {e}");
    }
    let (gateway_ip, _guest_ip, _cidr) = vmcell::net::ip_math(vm.vmid())
        .map_err(|e| anyhow::anyhow!("net-egress: ip_math({}): {e}", vm.vmid()))?;
    let url = format!("http://{gateway_ip}:{host_port}/");

    // Warm-up: the guest configures eth0 from the kernel `ip=` line (IP-PNP) after
    // boot, so the first curl races the interface/NAT coming up. Retry until the first
    // success (bounded) before measuring the steady RTT — and require a real egress
    // byte (`code==0 && !stdout.is_empty()`), a data-plane assertion.
    let mut warmed = false;
    for _ in 0..40 {
        if let Ok(steward) = vm.steward(None).await
            && let Ok(o) = steward.exec(ExecRequest::new(egress_curl(&url))).await
            && o.code == 0
            && !o.stdout.is_empty()
        {
            warmed = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
    if !warmed {
        best_effort::shutdown(vm).await;
        anyhow::bail!("net-egress: no successful egress request within the warm-up budget");
    }

    let mut rtts = Vec::with_capacity(iters);
    for i in 0..iters {
        let steward = match vm.steward(None).await {
            Ok(a) => a,
            Err(e) => {
                say!("net-egress: egress iter {i} steward-connect failed: {e}");
                break;
            }
        };
        let t = Instant::now();
        let r = steward.exec(ExecRequest::new(egress_curl(&url))).await;
        let dt = t.elapsed().as_micros();
        match r {
            Ok(o) if o.code == 0 && !o.stdout.is_empty() => rtts.push(dt),
            Ok(o) => say!(
                "net-egress: egress iter {i} curl code={} stdout={}B (no egress byte)",
                o.code,
                o.stdout.len()
            ),
            Err(e) => say!("net-egress: egress iter {i} exec failed: {e}"),
        }
    }
    best_effort::shutdown(vm).await;
    // `responder` stays alive until here; its Drop reaps the host thread.

    let acct = accounting_suffix(dropped_iterations(iters, rtts.len()), 0);
    say!(
        "=== NET-EGRESS (backend={backend} n={}{acct} url={url}) ===",
        rtts.len()
    );
    match rec.measure(metrics::NET_EGRESS_RTT, Unit::Micros, &mut rtts, iters, 0) {
        Some(m) => {
            say!(
                "  in-guest curl round-trip (guest→NAT→host→guest): p50={}µs p95={}µs p99={}µs max={}µs",
                m.p50,
                m.p95,
                m.p99,
                m.max
            );
            Ok(())
        }
        None => {
            say!("  No successful egress round-trips");
            anyhow::bail!("net-egress: no egress samples");
        }
    }
}

/// Builds a `Filtered` proxy config whose MITM test-double answers any `*.probe.local`
/// host with a fixed body. The guest↔proxy TLS handshake + per-connection cert mint happen
/// at `CONNECT`, *before* the double is matched, so they are exercised with NO real upstream
/// origin (hudsucker's upstream leg pins webpki roots and can't reach a self-signed local
/// origin — so the upstream handshake is deliberately out of scope; §16). The proxy
/// self-generates its CA (baked into the rootfs trust store, so the guest verifies).
fn mitm_proxy_config() -> vmcell::config::ProxyConfig {
    // `Matcher`/`Responder` are `Fn` aliases over `hyper::Request` / `hudsucker::Body`, so the
    // types here must be the ones VMCELL resolved, not whatever this crate's own manifest would
    // pick. Naming them through the re-exports is the documented contract (design §10.4,
    // `vmcell::proxy::doubles`' module docs) and this call site is its in-tree proof: while
    // `bench-vm` carried its own `hudsucker = "0.24"` requirement, vmcell's bump to 0.25 put two
    // hudsuckers in the graph and this function stopped compiling with "expected
    // `vmcell::proxy::doubles::hudsucker::Body`, found `hudsucker::Body`" — the exact break the
    // module docs predict. Both direct requirements were dropped from Cargo.toml with this
    // change, so the mismatch is now unrepresentable rather than merely fixed.
    use vmcell::proxy::doubles::{hudsucker, hyper};

    // `ProxyConfig` is `#[non_exhaustive]`, so build via `default()` + field-set (the exact
    // pattern the `egress_proxy` test uses; clippy does not fire `field_reassign_with_default`
    // for a `#[non_exhaustive]` struct from another crate).
    let mut cfg = vmcell::config::ProxyConfig::default();
    cfg.doubles = std::sync::Arc::new(std::sync::RwLock::new(vec![
        vmcell::proxy::doubles::TestDouble {
            matcher: Box::new(|req| {
                req.method() != hyper::Method::CONNECT
                    && req
                        .uri()
                        .host()
                        .is_some_and(|h| h.ends_with(".probe.local"))
            }),
            responder: Box::new(|_req| {
                hyper::Response::builder()
                    .status(200)
                    .body(hudsucker::Body::from("vmcell-mitm-ok\n"))
                    .expect("static MITM response builds")
            }),
        },
    ]));
    cfg
}

// ----------------------------------------------------------------------------
// net-egress `tls` / `privileged`: the MITM egress proxy (per-connection cert mint +
// guest↔proxy TLS handshake) over either the unprivileged smoltcp NAT (`tls`) or the
// privileged tap + netns + nft path (`privileged`). Covers the two egress surfaces the
// `plain` NAT datapath probe leaves unmeasured (docs/benchmark-results.md coverage caveat).
// ----------------------------------------------------------------------------

/// §16 (Performance) — net-egress `tls`/`privileged`: (A) start latency WITH the filtered
/// egress set up (smoltcp+proxy, or netns+tap+nft+proxy), and (B) the in-guest
/// HTTPS-through-MITM-proxy round-trip (fresh unique host per iter → fresh cert mint),
/// asserting a real MITM'd body byte. `privileged=true` uses `NetConfig::Privileged` (tap)
/// and self-skips without CAP_NET_ADMIN; `false` uses unprivileged smoltcp and self-skips
/// without the vhost-user-net device.
async fn run_net_egress_filtered<V: Vmm>(
    vmm: &V,
    rec: &Recorder,
    backend: &str,
    args: &Args,
    allocator: VmidAllocator,
    privileged: bool,
) -> anyhow::Result<()> {
    let label = if privileged { "privileged" } else { "tls" };
    let sweep_prefix = vmcell::naming::netns_sweep_prefix(vmcell::naming::DEFAULT_RESOURCE_PREFIX);

    // Self-skip per variant (a capability skip is success, M-BIN-1).
    if privileged {
        if !vmcell::HostCapabilities::probe().privileged_net_available() {
            rec.skip(format!(
                "net-egress[{label}]: no CAP_NET_ADMIN / netns dir; skipping"
            ));
            return Ok(());
        }
        // Reap orphan `vmcell-net-*` netns from prior aborted/hard-killed runs before we start.
        let _ = vmcell::net::cleanup_orphan_netns(&sweep_prefix);
    } else if !vmm.capabilities().unprivileged_vhost_user_net {
        rec.skip(format!(
            "net-egress[{label}]: backend {backend} has no unprivileged vhost-user-net; skipping"
        ));
        return Ok(());
    }

    let (dir, kernel, rootfs) = artifact_paths(args.kernel.as_deref())?;
    require_artifacts(&format!("net-egress[{label}]"), &dir, &kernel, &rootfs)?;

    let egress = Egress::Filtered(mitm_proxy_config());
    let net = if privileged {
        NetConfig::Privileged { egress }
    } else {
        NetConfig::Unprivileged {
            egress,
            host_services_port: None,
        }
    };
    let cfg = VmConfig::builder(kernel, RootfsSource::Erofs { image: rootfs })
        .vcpus(1)
        .mem_mib(args.mem_mib)
        .net(net)
        .restore_mode(args.restore_mode)
        .timeouts(timeouts_for(&args.profile))
        .kernel_verbosity(args.kernel_verbosity)
        .console_mode(args.console)
        .build()
        .map_err(|e| anyhow::anyhow!("net-egress[{label}]: invalid config: {e}"))?;

    let mut env = HostEnv::hermetic();
    env.vmids = allocator;
    let iters = args.iters();
    // Bounded retry over transient net bring-up (the smoltcp flake for `tls`; a
    // netns/tap/nft hiccup for `privileged`), same recovery pattern as `plain`.
    const NET_BOOT_RETRIES: usize = 5;

    // --- Phase A: start latency WITH the filtered-egress net setup on the boot path ---
    let mut starts = Vec::new();
    let mut boot_retries = 0usize;
    for i in 0..(iters + args.warmup) {
        let mut attempt = 0usize;
        loop {
            let t = Instant::now();
            match MicroVm::start(vmm, cfg.clone(), &env).await {
                Ok(mut vm) => {
                    match vm.steward(None).await {
                        Ok(_) => {
                            let dt = t.elapsed().as_millis();
                            if i >= args.warmup {
                                starts.push(dt);
                            }
                        }
                        Err(e) => {
                            say!(
                                "net-egress[{label}]: net-start iter {i} steward-connect failed: {e}"
                            );
                            if i >= args.warmup {}
                        }
                    }
                    best_effort::shutdown(vm).await;
                    break;
                }
                Err(e) => {
                    attempt += 1;
                    if attempt > NET_BOOT_RETRIES {
                        anyhow::bail!(
                            "net-egress[{label}]: net-start iter {i} start failed after {attempt} attempts: {e}"
                        );
                    }
                    boot_retries += 1;
                    say!(
                        "net-egress[{label}]: net-start iter {i} transient boot failure (attempt {attempt}, retrying): {e}"
                    );
                }
            }
        }
    }
    if boot_retries > 0 {
        say!(
            "net-egress[{label}]: NET-START recovered {boot_retries} transient boot failure(s) via retry"
        );
    }
    let start_label = if privileged {
        "NET-START (boot with tap+netns+nft+proxy)"
    } else {
        "NET-START (boot with smoltcp NAT + MITM proxy)"
    };
    // Qualified by variant for the same reason the phase rows are qualified by path: `tls` and
    // `privileged` are two different egress surfaces printing one row name, and an unqualified
    // `net_start` would let a comparator pool them.
    let start_metric = if privileged {
        metrics::NET_START_PRIVILEGED
    } else {
        metrics::NET_START_TLS
    };
    report(rec, start_label, start_metric, &mut starts, iters, 0);

    // --- Phase B: steady MITM egress round-trip (one warm VM, N HTTPS-through-proxy curls) ---
    let mut vm = {
        let mut attempt = 0usize;
        loop {
            match MicroVm::start(vmm, cfg.clone(), &env).await {
                Ok(v) => break v,
                Err(e) => {
                    attempt += 1;
                    if attempt > NET_BOOT_RETRIES {
                        anyhow::bail!(
                            "net-egress[{label}]: egress VM boot failed after {attempt} attempts: {e}"
                        );
                    }
                    say!(
                        "net-egress[{label}]: egress VM transient boot failure (attempt {attempt}, retrying): {e}"
                    );
                }
            }
        }
    };
    if let Err(e) = vm.steward(None).await {
        best_effort::shutdown(vm).await;
        anyhow::bail!("net-egress[{label}]: egress VM steward connect failed: {e}");
    }
    let (gateway_ip, _guest_ip, _cidr) = vmcell::net::ip_math(vm.vmid())
        .map_err(|e| anyhow::anyhow!("net-egress[{label}]: ip_math({}): {e}", vm.vmid()))?;
    let proxy_port = match vm.proxy() {
        Some(p) => p.port,
        None => {
            best_effort::shutdown(vm).await;
            anyhow::bail!("net-egress[{label}]: filtered egress did not start a proxy");
        }
    };
    let proxy_url = format!("http://{gateway_ip}:{proxy_port}");
    // A fresh unique `*.probe.local` host per request → cache miss → fresh per-connection
    // cert mint each time (the moka authority cache is keyed by host). `--resolve …:1.2.3.4`
    // is a black-hole placeholder never contacted (the double answers post-handshake).
    let mitm_curl = |host: &str| -> (Vec<String>, Vec<(String, String)>) {
        (
            vec![
                "curl".to_string(),
                "-4".to_string(),
                "-k".to_string(),
                "-s".to_string(),
                "--max-time".to_string(),
                "5".to_string(),
                "--resolve".to_string(),
                format!("{host}:443:1.2.3.4"),
                format!("https://{host}/"),
            ],
            vec![
                ("http_proxy".to_string(), proxy_url.clone()),
                ("https_proxy".to_string(), proxy_url.clone()),
            ],
        )
    };

    // Warm-up: bring eth0 / NAT / proxy up + prime the CA; retry until the first successful
    // MITM'd byte before measuring the steady round-trip (data-plane assertion).
    let mut warmed = false;
    for w in 0..40 {
        let (argv, cenv) = mitm_curl(&format!("warm{w}.probe.local"));
        if let Ok(steward) = vm.steward(None).await
            && let Ok(o) = steward.exec(ExecRequest::new(argv).with_env(cenv)).await
            && o.code == 0
            && o.stdout.starts_with(b"vmcell-mitm-ok")
        {
            warmed = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
    if !warmed {
        best_effort::shutdown(vm).await;
        if privileged {
            let _ = vmcell::net::cleanup_orphan_netns(&sweep_prefix);
        }
        anyhow::bail!("net-egress[{label}]: no successful MITM egress within the warm-up budget");
    }

    let mut rtts = Vec::with_capacity(iters);
    for i in 0..iters {
        let (argv, cenv) = mitm_curl(&format!("h{i}.probe.local"));
        let steward = match vm.steward(None).await {
            Ok(a) => a,
            Err(e) => {
                say!("net-egress[{label}]: egress iter {i} steward-connect failed: {e}");
                break;
            }
        };
        let t = Instant::now();
        let r = steward.exec(ExecRequest::new(argv).with_env(cenv)).await;
        let dt = t.elapsed().as_micros();
        match r {
            Ok(o) if o.code == 0 && o.stdout.starts_with(b"vmcell-mitm-ok") => rtts.push(dt),
            Ok(o) => say!(
                "net-egress[{label}]: egress iter {i} MITM curl code={} stdout={}B (no MITM byte)",
                o.code,
                o.stdout.len()
            ),
            Err(e) => say!("net-egress[{label}]: egress iter {i} exec failed: {e}"),
        }
    }
    best_effort::shutdown(vm).await;
    // Belt-and-suspenders netns sweep for any panic residue (privileged only; a clean
    // `shutdown()` already removes this VM's netns).
    if privileged {
        let _ = vmcell::net::cleanup_orphan_netns(&sweep_prefix);
    }

    let acct = accounting_suffix(dropped_iterations(iters, rtts.len()), 0);
    let tag = if privileged {
        "NET-EGRESS-PRIV (MITM via tap+nft+proxy)"
    } else {
        "NET-EGRESS-TLS (MITM via smoltcp+proxy)"
    };
    say!("=== {tag} (backend={backend} n={}{acct}) ===", rtts.len());
    let rtt_metric = if privileged {
        metrics::NET_EGRESS_PRIVILEGED_RTT
    } else {
        metrics::NET_EGRESS_TLS_RTT
    };
    match rec.measure(rtt_metric, Unit::Micros, &mut rtts, iters, 0) {
        Some(m) => {
            say!(
                "  in-guest HTTPS-through-MITM-proxy round-trip (cert mint + TLS handshake): p50={}µs p95={}µs p99={}µs max={}µs",
                m.p50,
                m.p95,
                m.p99,
                m.max
            );
            Ok(())
        }
        None => {
            say!("  No successful MITM egress round-trips");
            anyhow::bail!("net-egress[{label}]: no MITM egress samples");
        }
    }
}

// ----------------------------------------------------------------------------
// zygote: CoW-clone fan-out latency. Snapshot a base once, then time restoring +
// resuming N CoW clones concurrently (the zygote/lineage fan-out the library-direct
// single-VM restore metric structurally cannot reach).
// ----------------------------------------------------------------------------

/// §16 (Performance) — zygote fan-out: snapshot a base VM once, then time
/// `Zygote::spawn_clones` to `--count` resumed CoW clones (plus the time to reach
/// steward-ready across all of them). `restore_rotates_host_paths` gates concurrent
/// fan-out (CH + QEMU); Firecracker degrades to the single-clone control.
async fn run_zygote<V: Vmm>(
    vmm: &V,
    rec: &Recorder,
    backend: &str,
    args: &Args,
    allocator: VmidAllocator,
) -> anyhow::Result<()> {
    let caps = vmm.capabilities();
    if !caps.snapshot_restore {
        rec.skip(format!(
            "zygote: backend {backend} has no snapshot support; skipping"
        ));
        return Ok(());
    }
    // FC rotates no host paths → only a single clone is representable (`spawn_clones`
    // would return `Unsupported` for n>1); CH/QEMU fan out to `--count`. Announce the
    // clamp loudly rather than silently measuring a different n (N-BIN-2 spirit).
    let requested = args.count;
    let clone_count = if caps.restore_rotates_host_paths {
        requested
    } else {
        if requested > 1 {
            rec.skip(format!(
                "zygote: backend {backend} does not rotate host paths; measuring the \
                 single-clone control (n=1), not {requested}"
            ));
        }
        1
    };

    let (dir, kernel, rootfs) = artifact_paths(args.kernel.as_deref())?;
    require_artifacts("zygote", &dir, &kernel, &rootfs)?;
    // snapshotting=true: QEMU needs the in-kernel vhost-vsock transport to restore.
    let cfg = build_cfg(args, kernel, rootfs, false, true);
    let mut env = HostEnv::hermetic();
    env.vmids = allocator;

    // --- Snapshot the base ONCE into the master zygote image ---
    let master =
        resolve_snap_dir(&args.snap_dir).join(format!("zygote-{backend}-{}", std::process::id()));
    best_effort::discard_dir(&master);
    std::fs::create_dir_all(&master).map_err(|e| {
        anyhow::anyhow!("zygote: cannot create master dir {}: {e}", master.display())
    })?;

    let mut base = match MicroVm::start(vmm, cfg.clone(), &env).await {
        Ok(v) => v,
        Err(e) => {
            best_effort::discard_dir(&master);
            anyhow::bail!("zygote: base VM start failed: {e}");
        }
    };
    if let Err(e) = base.steward(None).await {
        best_effort::shutdown(base).await;
        best_effort::discard_dir(&master);
        anyhow::bail!("zygote: base VM steward connect failed: {e}");
    }
    let zygote = match vmcell::Zygote::suspend(&mut base, cfg.clone(), &master).await {
        Ok(z) => z,
        Err(e) => {
            best_effort::shutdown(base).await;
            best_effort::discard_dir(&master);
            anyhow::bail!("zygote: suspend failed: {e}");
        }
    };
    best_effort::shutdown(base).await;
    let cow = zygote.probe_cow_support();
    say!("zygote master ready (fan-out={clone_count}); CoW support: {cow:?}");
    rec.caveat(zygote_cow_caveat(cow));

    // --- Timed fan-out: N clones restored + resumed concurrently per iteration ---
    let mut fanout = Vec::new(); // wall-clock to `clone_count` live+resumed clones
    let mut ready = Vec::new(); // + time to steward-ready across all clones
    for i in 0..(args.iters() + args.warmup) {
        let t_fan = Instant::now();
        let mut clones = match zygote.spawn_clones(vmm, clone_count, &env).await {
            Ok(c) => c,
            Err(e) => {
                // Counted by subtraction at the report (`dropped_iterations`), which is also what
                // finally gives the `ready` row below a real loss count — it passed a literal `0`
                // beside this live counter, so a fan-out that failed reported a clean sample set.
                say!("zygote: iteration {i} fan-out failed: {e}");
                continue;
            }
        };
        let fan_ms = t_fan.elapsed().as_millis();

        // Time to steward-ready across all clones (concurrent; the first steward() runs the
        // post-restore resync). Disjoint `&mut` borrows via `iter_mut`, so this is sound.
        let t_ready = Instant::now();
        let ready_res =
            futures::future::try_join_all(clones.iter_mut().map(|c| c.steward(None))).await;
        let ready_ms = t_ready.elapsed().as_millis();

        match ready_res {
            Ok(_) => {
                if i >= args.warmup {
                    fanout.push(fan_ms);
                    ready.push(ready_ms);
                }
            }
            Err(e) => say!("zygote: iteration {i} clone steward-ready failed: {e}"),
        }
        for c in clones {
            best_effort::shutdown(c).await;
        }
    }
    best_effort::discard_dir(&master);

    let acct = accounting_suffix(dropped_iterations(args.iters(), fanout.len()), 0);
    say!(
        "=== ZYGOTE (backend={backend} fan-out={clone_count} n={}{acct} cow={cow:?}) ===",
        fanout.len()
    );
    // `.floor()` reproduces the integer division this printed before the numbers started coming
    // out of the recorder — the per-clone figure is a rounded-down whole millisecond, not a rank.
    let per_clone =
        |p: f64| (p / f64::from(u32::try_from(clone_count.max(1)).unwrap_or(u32::MAX))).floor();
    match rec.measure(
        metrics::ZYGOTE_FANOUT,
        Unit::Millis,
        &mut fanout,
        args.iters(),
        0,
    ) {
        Some(m) => {
            say!(
                "  fan-out to {clone_count} resumed clones: p50={}ms p95={}ms p99={}ms max={}ms  (per-clone p50≈{}ms)",
                m.p50,
                m.p95,
                m.p99,
                m.max,
                per_clone(m.p50)
            );
        }
        None => {
            say!("  No successful fan-outs");
            anyhow::bail!("zygote: no successful fan-outs");
        }
    }
    if let Some(m) = rec.measure(
        metrics::ZYGOTE_STEWARD_READY,
        Unit::Millis,
        &mut ready,
        args.iters(),
        0,
    ) {
        say!(
            "  + time to steward-ready across all clones: p50={}ms p95={}ms p99={}ms max={}ms",
            m.p50,
            m.p95,
            m.p99,
            m.max
        );
    }
    Ok(())
}

// ----------------------------------------------------------------------------
// session: the interactive-session layer (`SessionMux`) the one-shot StewardClient
// path (measured by vsock-rtt) never exercises — the SECOND vsock handshake +
// per-session open/spawn. (There is no resume-by-id API: "session persistence" =
// long-lived sessions, not reattach-across-reconnect, so the connect handshake is
// the closest analogue to a resume.)
// ----------------------------------------------------------------------------

/// §16 (Performance) — session: (A) `connect_sessions` latency (the mux's own second
/// vsock connection + `Ready` handshake, separate from the cached `steward()` client),
/// and (B) per-session `open`→guest-spawn→`exit` on one persistent mux. Both assert a
/// real `code==0` exit before counting (data-plane liveness, not a connect-only signal).
/// Works on all four backends (sessions ride the same vsock; no capability gate).
async fn run_session<V: Vmm>(
    vmm: &V,
    rec: &Recorder,
    backend: &str,
    args: &Args,
    allocator: VmidAllocator,
) -> anyhow::Result<()> {
    let (dir, kernel, rootfs) = artifact_paths(args.kernel.as_deref())?;
    require_artifacts("session", &dir, &kernel, &rootfs)?;
    let cfg = build_cfg(args, kernel, rootfs, false, false);
    let mut env = HostEnv::hermetic();
    env.vmids = allocator;
    let iters = args.iters();

    let mut vm = match MicroVm::start(vmm, cfg, &env).await {
        Ok(v) => v,
        Err(e) => anyhow::bail!("session: boot failed: {e}"),
    };
    if let Err(e) = vm.steward(None).await {
        best_effort::shutdown(vm).await;
        anyhow::bail!("session: steward connect failed: {e}");
    }
    let argv = pick_exec_cmd(&mut vm).await;

    // --- Metric A: session-connect latency (the 2nd vsock handshake) ---
    // Each `connect_sessions` dials a fresh mux connection + `Ready` handshake, distinct
    // from the cached one-shot `steward()` client vsock-rtt reuses. Prove liveness (run one
    // command to `code==0`) before counting the sample, then drop the mux.
    let mut connect_rtts = Vec::with_capacity(iters);
    for _ in 0..args.warmup {
        if let Ok(mux) = vm.connect_sessions(None).await
            && let Ok(mut s) = mux.open_spec(SessionSpecBuilder::new(argv.clone())).await
        {
            // Warmup: the session runs to completion to prime the path; its exit code is not a
            // sample, and a session that failed to open was already filtered by the `if let`.
            let _ = s.wait().await;
        }
    }
    for i in 0..iters {
        let t = Instant::now();
        let mux = match vm.connect_sessions(None).await {
            Ok(m) => m,
            Err(e) => {
                say!("session: connect iter {i} failed: {e}");
                continue;
            }
        };
        let dt = t.elapsed().as_micros();
        let live = match mux.open_spec(SessionSpecBuilder::new(argv.clone())).await {
            Ok(mut s) => s.wait().await.code == 0,
            Err(_) => false,
        };
        drop(mux);
        if live {
            connect_rtts.push(dt);
        }
    }

    // --- Metric B: session-open latency on ONE persistent mux (open→spawn→exit) ---
    // `open` has no ack round-trip (it fires OpenSession and returns), so the real cost is
    // open→guest-spawn→Exit: time to `wait()`'s terminal exit, not `open()` alone.
    let mux = match vm.connect_sessions(None).await {
        Ok(m) => m,
        Err(e) => {
            best_effort::shutdown(vm).await;
            anyhow::bail!("session: mux connect failed: {e}");
        }
    };
    for _ in 0..args.warmup {
        if let Ok(mut s) = mux.open_spec(SessionSpecBuilder::new(argv.clone())).await {
            // Warmup: the session runs to completion to prime the path; its exit code is not a
            // sample, and a session that failed to open was already filtered by the `if let`.
            let _ = s.wait().await;
        }
    }
    let mut open_rtts = Vec::with_capacity(iters);
    for i in 0..iters {
        let t = Instant::now();
        let outcome = match mux.open_spec(SessionSpecBuilder::new(argv.clone())).await {
            Ok(mut s) => s.wait().await,
            Err(e) => {
                say!("session: open iter {i} failed: {e}");
                continue;
            }
        };
        let dt = t.elapsed().as_micros();
        if outcome.code == 0 {
            open_rtts.push(dt);
        }
    }
    drop(mux);
    best_effort::shutdown(vm).await;

    say!("=== SESSION (backend={backend} cmd={argv:?}) ===");
    let acct_c = accounting_suffix(dropped_iterations(iters, connect_rtts.len()), 0);
    match rec.measure(
        metrics::SESSION_CONNECT,
        Unit::Micros,
        &mut connect_rtts,
        iters,
        0,
    ) {
        Some(m) => say!(
            "  session-connect (2nd vsock handshake) n={}{acct_c}: p50={}µs p95={}µs p99={}µs max={}µs",
            m.n,
            m.p50,
            m.p95,
            m.p99,
            m.max
        ),
        None => {
            say!("  session-connect: No successful runs{acct_c}");
            anyhow::bail!("session: no successful mux connects");
        }
    }
    let acct_o = accounting_suffix(dropped_iterations(iters, open_rtts.len()), 0);
    match rec.measure(
        metrics::SESSION_OPEN,
        Unit::Micros,
        &mut open_rtts,
        iters,
        0,
    ) {
        Some(m) => {
            say!(
                "  session-open (open→spawn→exit) n={}{acct_o}: p50={}µs p95={}µs p99={}µs max={}µs",
                m.n,
                m.p50,
                m.p95,
                m.p99,
                m.max
            );
            Ok(())
        }
        None => {
            say!("  session-open: No successful runs{acct_o}");
            anyhow::bail!("session: no successful session opens");
        }
    }
}

// ----------------------------------------------------------------------------
// daemon-api: the `vmcelld` HTTP + broker-bridge overhead over the raw VMM op. Spawns its
// own `vmcelld` child (bench-vm runs under the blessed runner, so the daemon inherits the
// caps via the ambient set), drives create/restore/exec/list/destroy over HTTP, and reports
// through the shared `pcts` — replacing the former `scripts/perf-daemon.sh` (curl + a python
// percentile reimplementation + curl-`%{time_total}` timing + python JSON id-parsing).
// ----------------------------------------------------------------------------

/// Owns the spawned `vmcelld` child and tears it down on drop: SIGTERM (so the daemon's
/// signal handler runs `engine.shutdown_all()`, reaping every CH VM + the broker) → bounded
/// wait → SIGKILL backstop → reap. Mirrors the `vmcelld` integration harness; a bare kill
/// would orphan the live CH VMs.
struct DaemonChild(std::process::Child);

impl Drop for DaemonChild {
    fn drop(&mut self) {
        // If the child was already reaped (e.g. the health-poll's `try_wait` collected it
        // after an early daemon exit), its pid is freed and `Child::id()` is stale — do NOT
        // signal it (that pid may have been recycled). This mirrors std's own `Child::kill`,
        // which no-ops once the status is cached.
        if matches!(self.0.try_wait(), Ok(Some(_))) {
            return;
        }
        // SAFETY: `kill(2)` with a pid this process spawned and has NOT yet reaped (the guard
        // above), plus a valid signal constant. It transfers no pointers and touches no memory.
        unsafe {
            libc::kill(self.0.id() as libc::pid_t, libc::SIGTERM);
        }
        for _ in 0..50 {
            if matches!(self.0.try_wait(), Ok(Some(_))) {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        // The escalation after a 5 s SIGTERM grace. `Drop` cannot report and must not unwind; a
        // `kill`/`wait` that fails here means the child is already gone, which is the outcome
        // wanted anyway.
        #[expect(
            clippy::let_underscore_must_use,
            reason = "Drop-path SIGKILL escalation: a failure means the child is already reaped, which is the goal"
        )]
        let _ = self.0.kill();
        #[expect(
            clippy::let_underscore_must_use,
            reason = "same Drop path: reaping a child that is already gone is not an actionable error"
        )]
        let _ = self.0.wait();
    }
}

/// One timed HTTP request: `Instant` around send + a full body drain (the `curl
/// %{time_total}` equivalent). Returns (elapsed µs, parsed JSON body — `Null` for an empty
/// 204). A non-2xx status is a hard error (`error_for_status`), so a broken op fails loud.
async fn daemon_timed(req: reqwest::RequestBuilder) -> anyhow::Result<(u128, serde_json::Value)> {
    let t = Instant::now();
    let resp = req.send().await?.error_for_status()?;
    let body = resp.text().await?;
    let us = t.elapsed().as_micros();
    let v = if body.trim().is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_str(&body)?
    };
    Ok((us, v))
}

/// `POST /v1/vms` with `body`, returning (elapsed µs, the created `vm.id`). Parses via
/// `serde_json::Value` because the typed DTOs live in `vmcell-daemon`, which cannot be a
/// dependency of `vmcell` (the `vmcell-daemon → vmcell` back-edge makes it a cyclic package).
async fn daemon_create(
    http: &reqwest::Client,
    base: &str,
    body: &serde_json::Value,
) -> anyhow::Result<(u128, String)> {
    let (us, v) = daemon_timed(
        http.post(format!("{base}/v1/vms"))
            .header("content-type", "application/json")
            .body(body.to_string()),
    )
    .await?;
    // `.get()` rather than `v["vm"]["id"]`: serde_json's Index panics on a non-object, and a daemon
    // that answered with an error body is exactly the case this must report, not crash on.
    let id = v
        .get("vm")
        .and_then(|vm| vm.get("id"))
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("daemon-api: create response carried no vm.id"))?
        .to_string();
    Ok((us, id))
}

/// `DELETE /v1/vms/{id}`, returning the elapsed µs.
async fn daemon_destroy(http: &reqwest::Client, base: &str, id: &str) -> anyhow::Result<u128> {
    let (us, _) = daemon_timed(http.delete(format!("{base}/v1/vms/{id}"))).await?;
    Ok(us)
}

/// Reports a daemon op's µs samples as ms (one decimal) through the shared nearest-rank
/// `pcts` — the ONE percentile law (no second copy, unlike the retired python `pctl`).
fn report_daemon_op(rec: &Recorder, name: &str, samples: &mut [u128], planned: usize) {
    // The metric keeps the raw sample unit (µs) and the row renders it as ms: the one recorded
    // value is what both the table cell and the JSON field are computed from, so the display
    // rounding cannot become a second, disagreeing number. The metric name is derived from the op
    // name rather than passed, because these five rows ARE the op names — `daemon_create`,
    // `daemon_restore`, … — and a separate argument would be a second place to typo one.
    match rec.measure(
        &metrics::daemon_metric(name),
        Unit::Micros,
        samples,
        planned,
        0,
    ) {
        Some(m) => {
            let ms = |us: f64| us / 1000.0;
            say!(
                "  {name:8}: count={} p50={:.1}ms p95={:.1}ms p99={:.1}ms max={:.1}ms",
                m.n,
                ms(m.p50),
                ms(m.p95),
                ms(m.p99),
                ms(m.max)
            );
        }
        None => say!("  {name:8}: No successful samples"),
    }
}

/// §16 (Performance) — daemon-api: create/restore/exec/list/destroy latency through the
/// `vmcelld` HTTP + broker bridge. `list` (no VMM work) is the pure bridge floor; `restore`
/// exercises `restore_cow`. Spawns its own `vmcelld` (inheriting the runner's ambient caps),
/// times each op with `Instant`, and reports via `pcts`.
async fn run_daemon_api(rec: &Recorder, args: &Args) -> anyhow::Result<()> {
    // The daemon binary sits next to this one (same cargo profile dir: target/<profile>/).
    let exe =
        std::env::current_exe().map_err(|e| anyhow::anyhow!("daemon-api: current_exe: {e}"))?;
    let vmcelld = exe
        .parent()
        .ok_or_else(|| anyhow::anyhow!("daemon-api: current_exe has no parent dir"))?
        .join("vmcelld");
    if !vmcelld.exists() {
        anyhow::bail!(
            "daemon-api: vmcelld not built at {} (cargo build --locked --release -p vmcelld)",
            vmcelld.display()
        );
    }

    let (adir, kernel, rootfs) = artifact_paths(args.kernel.as_deref())?;
    require_artifacts("daemon-api", &adir, &kernel, &rootfs)?;

    // Private ephemeral artifact store: symlink the two prebuilt artifacts in (the store
    // reads through symlinks — no copy). Dropped (cleaned) at function end.
    let store = tempfile::tempdir().map_err(|e| anyhow::anyhow!("daemon-api: tempdir: {e}"))?;
    stage_artifact_store(store.path(), &kernel, &rootfs)?;

    // Free ephemeral port so a stale/parallel daemon does not collide.
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0")
            .map_err(|e| anyhow::anyhow!("daemon-api: bind ephemeral port: {e}"))?;
        l.local_addr()
            .map_err(|e| anyhow::anyhow!("daemon-api: local_addr: {e}"))?
            .port()
    };
    let base = format!("http://127.0.0.1:{port}");
    let iters = args.iters();
    let warmup = args.warmup;
    let total = iters + warmup;

    say!(
        "=== DAEMON-API (vmcelld HTTP + broker bridge; port={port} n={iters} warmup={warmup}) ==="
    );

    // Launch vmcelld directly — bench-vm runs under the blessed runner, so the daemon inherits
    // the three caps via the ambient set (the integration-harness path). Real broker split
    // (no --no-setup-broker) so the bridge is what we measure.
    let log = store.path().join("vmcelld.log");
    let logf = std::fs::File::create(&log)
        .map_err(|e| anyhow::anyhow!("daemon-api: create daemon log: {e}"))?;
    let logf2 = logf
        .try_clone()
        .map_err(|e| anyhow::anyhow!("daemon-api: dup daemon log fd: {e}"))?;
    let child = std::process::Command::new(&vmcelld)
        .arg("--artifacts-dir")
        .arg(store.path())
        .arg("--bind")
        .arg(format!("127.0.0.1:{port}"))
        .arg("--allow-unauthenticated")
        .arg("--resource-prefix")
        .arg("vmcd")
        .stdout(logf)
        .stderr(logf2)
        .spawn()
        .map_err(|e| anyhow::anyhow!("daemon-api: spawn vmcelld: {e}"))?;
    // Owns teardown from here (SIGTERM → wait → SIGKILL), even on an early `?`.
    let mut daemon = DaemonChild(child);

    let http = reqwest::Client::new();

    // Readiness: poll /healthz (20 s budget, matching the integration harness).
    let mut healthy = false;
    for _ in 0..80 {
        if let Ok(r) = http.get(format!("{base}/healthz")).send().await
            && r.status().is_success()
        {
            healthy = true;
            break;
        }
        if matches!(daemon.0.try_wait(), Ok(Some(_))) {
            anyhow::bail!(
                "daemon-api: vmcelld exited before healthz (log: {})",
                log.display()
            );
        }
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
    if !healthy {
        anyhow::bail!(
            "daemon-api: vmcelld not healthy in 20s (log: {})",
            log.display()
        );
    }

    // The store entry names, from the one const `stage_artifact_store` links them under — the
    // daemon resolves a client-named artifact against its own --artifacts-dir (B12), so a literal
    // here that drifts from the staging names is a 404 mid-benchmark.
    let (kernel_name, rootfs_name) = DAEMON_STORE_NAMES;
    let create_body = serde_json::json!({ "kernel": kernel_name, "rootfs": rootfs_name });
    let exec_body = serde_json::json!({ "argv": ["/bin/true"] });

    // --- Lifecycle loop: create -> destroy, timing each (warmup excluded) ---
    let mut create_us = Vec::with_capacity(iters);
    let mut destroy_us = Vec::with_capacity(iters);
    for i in 0..total {
        let (cms, id) = daemon_create(&http, &base, &create_body).await?;
        let dms = daemon_destroy(&http, &base, &id).await?;
        if i >= warmup {
            create_us.push(cms);
            destroy_us.push(dms);
        }
    }

    // --- Steady-op loop: one VM, N list + N exec (isolates the per-op bridge cost) ---
    let (_, sid) = daemon_create(&http, &base, &create_body).await?;
    for _ in 0..warmup {
        let _ = daemon_timed(http.get(format!("{base}/v1/vms"))).await?;
        let _ = daemon_timed(
            http.post(format!("{base}/v1/vms/{sid}/exec"))
                .header("content-type", "application/json")
                .body(exec_body.to_string()),
        )
        .await?;
    }
    let mut list_us = Vec::with_capacity(iters);
    let mut exec_us = Vec::with_capacity(iters);
    for _ in 0..iters {
        let (lms, _) = daemon_timed(http.get(format!("{base}/v1/vms"))).await?;
        list_us.push(lms);
        let (ems, _) = daemon_timed(
            http.post(format!("{base}/v1/vms/{sid}/exec"))
                .header("content-type", "application/json")
                .body(exec_body.to_string()),
        )
        .await?;
        exec_us.push(ems);
    }
    daemon_destroy(&http, &base, &sid).await?;

    // --- Restore loop: snapshot one source VM once, then time N `restore_cow` restores ---
    let (_, src_id) = daemon_create(
        &http,
        &base,
        &serde_json::json!({ "kernel": kernel_name, "rootfs": rootfs_name, "snapshotting": true }),
    )
    .await?;
    daemon_timed(
        http.post(format!("{base}/v1/vms/{src_id}/snapshot"))
            .header("content-type", "application/json")
            .body(serde_json::json!({ "artifact_prefix": "snap0" }).to_string()),
    )
    .await?;
    let restore_body = serde_json::json!({
        "kernel": kernel_name, "rootfs": rootfs_name, "snapshotting": true, "restore_from": "snap0"
    });
    let mut restore_us = Vec::with_capacity(iters);
    for i in 0..total {
        let (rms, rid) = daemon_create(&http, &base, &restore_body).await?;
        daemon_destroy(&http, &base, &rid).await?;
        if i >= warmup {
            restore_us.push(rms);
        }
    }
    daemon_destroy(&http, &base, &src_id).await?;

    report_daemon_op(rec, "create", &mut create_us, iters);
    report_daemon_op(rec, "restore", &mut restore_us, iters);
    report_daemon_op(rec, "exec", &mut exec_us, iters);
    report_daemon_op(rec, "list", &mut list_us, iters);
    report_daemon_op(rec, "destroy", &mut destroy_us, iters);
    say!("=== DAEMON-API done ===");

    // Explicit graceful teardown (rather than waiting for the drop) so a hiccup surfaces here;
    // `store` cleanup follows on its own drop.
    drop(daemon);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Buggy impl this guards: cold-boot latencies were reported under a plain
    // "Cold Boot" label even when the page cache was never dropped (warm cache),
    // so warm numbers masqueraded as cold. The label must flag the warm case.
    #[test]
    fn cold_label_flags_warm_cache_when_drop_unavailable() {
        assert!(bench_label("Cold Boot", false, false).contains("WARM-CACHE"));
        assert_eq!(bench_label("Cold Boot", false, true), "Cold Boot");
        // Restore is not page-cache sensitive in the same way; never flagged.
        assert_eq!(bench_label("Warm Restore", true, false), "Warm Restore");
    }

    // M-CLI-1: the `_` backend arm printed "Unsupported backend or feature not
    // enabled" then let `main` return `Ok(())`, so a typo or a feature-disabled
    // build exited 0. RED on the inverse (a validator that returns `Ok` for
    // anything): the unknown-backend assert below fails.
    #[test]
    fn validate_backend_rejects_unknown_backend() {
        assert!(validate_backend("totally-not-a-vmm").is_err());
        assert!(validate_backend("").is_err());
        // bench-vm's `required-features` always include `cloud-hypervisor`, so
        // the default backend must be accepted whenever this binary compiles.
        assert!(validate_backend("cloud-hypervisor").is_ok());
        // Every compiled-in backend round-trips through the validator.
        for b in supported_backends() {
            assert!(validate_backend(b).is_ok(), "backend {b} should be valid");
        }
    }

    // `bench-ignores-contract-bin-resolvers`: every backend arm hardcoded its binary name, so the
    // §10.4-contract `VMCELL_*_BIN` overrides (documented in README and perf-matrix.sh) did
    // nothing here. RED on that inverse (a hardcoded `"crosvm"`/`"firecracker"`/…): the override
    // asserts below fail. The lookup is injected, so this pins the behavior without touching the
    // process environment.
    #[test]
    fn vmm_binary_honors_contract_env_overrides() {
        let overridden = |var: &str| match var {
            "VMCELL_CH_BIN" => Some("/opt/vmm/ch-dev".to_string()),
            "VMCELL_FC_BIN" => Some("/opt/vmm/fc-dev".to_string()),
            "VMCELL_QEMU_BIN" => Some("/opt/vmm/qemu-dev".to_string()),
            "VMCELL_CROSVM_BIN" => Some("/opt/vmm/crosvm-dev".to_string()),
            _ => None,
        };
        for (backend, want) in [
            ("cloud-hypervisor", "/opt/vmm/ch-dev"),
            ("firecracker", "/opt/vmm/fc-dev"),
            ("qemu", "/opt/vmm/qemu-dev"),
            ("crosvm", "/opt/vmm/crosvm-dev"),
        ] {
            // The expected variable name comes from the ONE table, not a literal copied beside it:
            // a test that re-spells the var would keep passing while the table drifted, and it
            // would also be a second `"VMCELL_CH_BIN"` read for
            // `scripts/ban-ch-binary-resolver-copies.sh` to account for.
            let (var, _) = vmm_bin_resolver(backend).expect("every backend has a resolver");
            assert_eq!(
                resolve_vmm_binary(backend, overridden),
                Some((
                    want.to_string(),
                    BinSource::EnvVar {
                        name: var.to_string()
                    }
                )),
                "{backend} must resolve through its VMCELL_*_BIN override, and say so"
            );
        }

        // Unset → the documented default binary name (PATH resolution), per backend.
        let unset = |_: &str| None;
        assert_eq!(
            resolve_vmm_binary("qemu", unset),
            Some(("qemu-system-x86_64".to_string(), BinSource::Path))
        );
        assert_eq!(
            resolve_vmm_binary("cloud-hypervisor", unset),
            Some(("cloud-hypervisor".to_string(), BinSource::Path))
        );

        // A backend with no table entry resolves to nothing (and `vmm_binary` then fails loud)
        // rather than falling back to the bare name — the hardcoding this replaced.
        assert_eq!(resolve_vmm_binary("totally-not-a-vmm", unset), None);
        assert!(vmm_binary("totally-not-a-vmm").is_err());

        // Table/dispatch drift guard: every compiled-in backend has a resolver.
        for b in supported_backends() {
            assert!(
                vmm_bin_resolver(b).is_some(),
                "backend {b} has no VMCELL_*_BIN resolver entry"
            );
        }
    }

    // One-law parity with the §10.4 contract getters the artifact-validator ships (a dev-dep here,
    // linked only for the test cfg — the bin cannot depend on the validator in production without
    // a new edge). This pins the DEFAULT half of each resolver against the contract surface under
    // whatever the ambient env is; the var-name half is pinned by the injected-lookup test above.
    // RED on the inverse (a bench-local default like `"qemu"` for QEMU, the drift this guards):
    // the qemu assert fails.
    #[test]
    fn vmm_binary_matches_validator_contract_getters() {
        use vmcell_artifact_validator::harness;
        for (backend, contract) in [
            ("cloud-hypervisor", harness::ch_bin()),
            ("firecracker", harness::fc_bin()),
            ("qemu", harness::qemu_bin()),
            ("crosvm", harness::crosvm_bin()),
        ] {
            assert_eq!(
                vmm_binary(backend).expect("every backend has a resolver").0,
                contract,
                "{backend}: bench-vm and the validator harness must resolve one binary"
            );
        }
        // The CH leg is also the library's own pipeline law — same var, same default.
        assert_eq!(
            vmm_binary("cloud-hypervisor").expect("CH resolver").0,
            vmcell::artifact::ch_binary_path()
        );
    }

    // C4, design §17's LAST open "one law, one predicate" consolidation: this harness hand-rolled
    // the library's workspace-root ascent because `vmcell::artifact::workspace_root` was
    // `pub(crate)`. It is `pub` now and [`workspace_root`] delegates to it.
    //
    // The assertion is a POSITIVE identity, not `bench == library` — which after the delegation is
    // an `a == a` tautology that cannot fail. `expected` is derived STRUCTURALLY (this crate's
    // manifest dir is `<ws>/crates/vmcell-bench`, so the root is exactly two levels up) and is
    // therefore independent of the marker file the ascent hunts for: a copy that drifted on the
    // marker, or an ascent that found nothing and fell back to its start dir, resolves the CRATE
    // dir and reddens here. RED on that inverse verified by restoring the hand-rolled loop with a
    // typo'd marker: `resolve_snap_dir` then anchors on `crates/vmcell-bench`.
    //
    // What this test structurally CANNOT see is a BYTE-IDENTICAL second copy — it resolves the
    // same root, so parity holds while the duplicate is free to drift later. That half is
    // `scripts/ban-workspace-root-ascent-copies.sh`, which is why both gates ship.
    //
    // KVM-free, filesystem-free (no path is opened), env-free (no `set_var`).
    #[test]
    fn snap_dir_anchors_on_the_library_one_workspace_root() {
        let expected = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .expect("this crate is <workspace>/crates/vmcell-bench");
        assert_eq!(
            workspace_root(),
            expected,
            "bench-vm must anchor on the library's workspace root, not its own crate dir"
        );
        // The whole reason the ascent is called at all: a relative `--snap-dir` is CWD-independent.
        assert_eq!(resolve_snap_dir("snaps"), expected.join("snaps"));
        assert_eq!(resolve_snap_dir("a/b"), expected.join("a/b"));
        // An absolute `--snap-dir` is honored verbatim (the other half of the resolver's contract).
        assert_eq!(
            resolve_snap_dir("/mnt/nvme/snaps"),
            PathBuf::from("/mnt/nvme/snaps")
        );
    }

    // d8: the same §10.4 consistency for the ARTIFACTS. `artifact_paths` composed
    // `<artifacts-dir>/vmlinux` + `/rootfs.erofs` itself and never consulted
    // `$VMCELL_KERNEL`/`$VMCELL_ROOTFS`, so an override every other tool honors was invisible to a
    // benchmark run — including its attribution. The resolver takes the toolkit getters' answers as
    // arguments (the `resolve_vmm_binary` shape), so this pins the behavior without touching the
    // process environment; `bench_vm_honors_the_toolkit_artifact_overrides` drives the real binary
    // to prove the getters are actually where the answers come from. RED on the inverse (paths
    // re-derived from `dir`): the overridden asserts below fail.
    #[test]
    fn artifact_paths_resolve_through_the_toolkit_getters() {
        let dir = PathBuf::from("/artifacts");

        // No override: the getters answer with the dir's defaults, which pass through unchanged.
        let (d, k, r) =
            resolve_artifact_paths(&dir, dir.join("vmlinux"), dir.join("rootfs.erofs"), None)
                .expect("no label, no conflict");
        assert_eq!(d, "/artifacts");
        assert_eq!(k, dir.join(kernel_filename(None)));
        assert_eq!(r, dir.join("rootfs.erofs"));

        // Overridden: whatever the getters returned is what the run boots and reports.
        let (_, k, r) = resolve_artifact_paths(
            &dir,
            PathBuf::from("/elsewhere/vmlinux-custom"),
            PathBuf::from("/elsewhere/custom-rootfs.erofs"),
            None,
        )
        .expect("no label, no conflict");
        assert_eq!(k, PathBuf::from("/elsewhere/vmlinux-custom"));
        assert_eq!(r, PathBuf::from("/elsewhere/custom-rootfs.erofs"));
    }

    // d8, one level down: the `daemon-api` mode stages the pair into an ephemeral store by
    // SYMLINK, and it re-derived the sources as `<artifacts-dir>/<store name>` — so under
    // `$VMCELL_KERNEL`/`$VMCELL_ROOTFS` it staged files the run never validated (dangling, or the
    // default artifact wearing the override's name). RED on the inverse (`dir.join(name)` as the
    // link target): both `read_link` asserts below fail.
    #[test]
    fn the_daemon_store_stages_the_resolved_pair_not_the_dir_defaults() {
        let store = tempfile::tempdir().expect("store dir");
        let kernel = PathBuf::from("/elsewhere/vmlinux-custom");
        let rootfs = PathBuf::from("/elsewhere/custom-rootfs.erofs");
        stage_artifact_store(store.path(), &kernel, &rootfs).expect("staging succeeds");

        let (kernel_name, rootfs_name) = DAEMON_STORE_NAMES;
        // The ENTRY names are the daemon's contract (the REST bodies name them)…
        assert_eq!(
            std::fs::read_link(store.path().join(kernel_name)).expect("kernel link"),
            kernel,
            "the store entry must point at the RESOLVED kernel"
        );
        assert_eq!(
            std::fs::read_link(store.path().join(rootfs_name)).expect("rootfs link"),
            rootfs,
            "the store entry must point at the RESOLVED rootfs"
        );
    }

    // The label still works — and contradicting the redirect is REJECTED, not silently resolved
    // one way (AGENTS.md: an accepted input is honored or rejected). RED on the inverse (`Some(label)`
    // unconditionally winning, or the redirect unconditionally winning): the `expect_err` fails.
    #[test]
    fn artifact_paths_reject_a_label_that_contradicts_the_kernel_redirect() {
        let dir = PathBuf::from("/artifacts");

        // A label without a redirect: the label picks the file, through the real composer.
        let (_, k, _) = resolve_artifact_paths(
            &dir,
            dir.join("vmlinux"),
            dir.join("rootfs.erofs"),
            Some("6.12.94"),
        )
        .expect("a label alone is not a conflict");
        assert_eq!(k, dir.join(kernel_filename(Some("6.12.94"))));

        // A label WITH a redirect names two different files.
        let err = resolve_artifact_paths(
            &dir,
            PathBuf::from("/elsewhere/vmlinux-custom"),
            dir.join("rootfs.erofs"),
            Some("6.12.94"),
        )
        .expect_err("a label and a $VMCELL_KERNEL redirect cannot both be honored")
        .to_string();
        assert!(err.contains("$VMCELL_KERNEL"), "{err}");
        assert!(err.contains("/elsewhere/vmlinux-custom"), "{err}");
        assert!(
            err.contains(&kernel_filename(Some("6.12.94"))),
            "the refusal must name both candidates: {err}"
        );
    }

    // `daemon-api-header-misnames-backend`: `--backend firecracker --mode daemon-api` printed a
    // FIRECRACKER header (and `--kernel <label>` a `vmlinux-<label>` header) while the CH-backed
    // daemon booted plain `vmlinux` — an unhonorable input that mislabels the results table. RED
    // on the inverse (no validation / accept-all): the two `unwrap_err`/`is_err` asserts fail.
    #[test]
    fn daemon_api_rejects_knobs_it_cannot_honor() {
        let parse = |argv: &[&str]| <Args as clap::Parser>::parse_from(argv.to_vec());

        let err = validate_daemon_api_knobs(&parse(&[
            "bench-vm",
            "--mode",
            "daemon-api",
            "--backend",
            "firecracker",
        ]))
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("cloud-hypervisor"),
            "the refusal must name the backend that IS measured, got: {err}"
        );

        assert!(
            validate_daemon_api_knobs(&parse(&[
                "bench-vm",
                "--mode",
                "daemon-api",
                "--kernel",
                "6.12.94"
            ]))
            .is_err(),
            "a --kernel label the daemon store never boots must be rejected"
        );

        // The honored invocation, and every other mode, are untouched.
        assert!(validate_daemon_api_knobs(&parse(&["bench-vm", "--mode", "daemon-api"])).is_ok());
        assert!(
            validate_daemon_api_knobs(&parse(&[
                "bench-vm",
                "--mode",
                "daemon-api",
                "--backend",
                "cloud-hypervisor"
            ]))
            .is_ok()
        );
        assert!(
            validate_daemon_api_knobs(&parse(&[
                "bench-vm",
                "--mode",
                "latency",
                "--backend",
                "firecracker",
                "--kernel",
                "6.12.94"
            ]))
            .is_ok(),
            "non-daemon modes honor both flags and must not be rejected"
        );
    }

    // `daemon-api-header-misnames-backend` (disclosure half): the header echoes VM knobs the
    // daemon never applies, so the mode names them. RED on the inverse (an empty/omitted line):
    // the `--mem-mib`/`--console` asserts fail.
    #[test]
    fn daemon_api_discloses_inapplicable_knobs() {
        let line = daemon_api_ignored_knobs_line();
        assert!(line.contains("--mem-mib"), "{line}");
        assert!(line.contains("--console"), "{line}");
        assert!(line.contains("--profile"), "{line}");
        // The echoed knobs from `resolved_knobs_line` are exactly what this must cover.
        for knob in ["--profile", "--kernel-verbosity", "--console"] {
            assert!(
                DAEMON_API_IGNORED_KNOBS.contains(&knob),
                "header-echoed knob {knob} must be disclosed as not-applied"
            );
        }
    }

    // M-CLI-1: the `other =>` mode arm printed "Unknown mode" then returned, so
    // `run_mode` (and `main`) still reported success. RED on the inverse: an
    // accept-all validator fails the `is_err` asserts.
    #[test]
    fn validate_mode_rejects_unknown_mode() {
        assert!(validate_mode("latencyy").is_err());
        assert!(validate_mode("").is_err());
        for m in VALID_MODES {
            assert!(validate_mode(m).is_ok(), "mode {m} should be valid");
        }
    }

    // P22: bench-vm `.expect()`ed on the config builder, panicking with a
    // misleading "benchmark invariant" message for a `--mem-mib` below the 64
    // MiB floor. The validator must instead surface config's typed error.
    // RED on the inverse (no floor check, i.e. `.expect()`/accept-all): the
    // below-floor case panics or returns `Ok`, failing `unwrap_err`/the assert.
    #[test]
    fn validate_vm_params_rejects_mem_below_floor() {
        let bad = <Args as clap::Parser>::parse_from(["bench-vm", "--mem-mib", "32"]);
        let err = validate_vm_params(&bad).unwrap_err();
        assert!(
            err.to_string().contains("mem_mib must be >= 64"),
            "error should surface config's typed floor message, got: {err}"
        );
        // The documented floor itself is accepted.
        let ok = <Args as clap::Parser>::parse_from(["bench-vm", "--mem-mib", "64"]);
        assert!(validate_vm_params(&ok).is_ok());
    }

    // N-BIN-2: `--count 0` was silently clamped to 1 by `args.count.max(1)`. RED on
    // the inverse (silent clamp / no check): the count-0 case returns `Ok`.
    #[test]
    fn validate_vm_params_rejects_zero_count() {
        let bad = <Args as clap::Parser>::parse_from(["bench-vm", "--count", "0"]);
        assert!(validate_vm_params(&bad).is_err());
        let ok = <Args as clap::Parser>::parse_from(["bench-vm", "--count", "1"]);
        assert!(validate_vm_params(&ok).is_ok());
    }

    // H-BIN-1-revisited: `report`/`pcts` used `floor(q*n)`, one rank too high when
    // `q*n` is integral — at N=20 it returned index 19 (the MAX) for p95. Nearest-rank
    // `ceil(q*n)-1` gives p50=10, p95=19, p99=20. RED on the old `floor` impl (which
    // yields p50=11, p95=20).
    #[test]
    fn percentile_nearest_rank_correctness() {
        let mut v: Vec<u128> = (1..=20).collect();
        let (p50, p95, p99, max) = pcts(&mut v).expect("non-empty sample set");
        assert_eq!(p50, 10, "p50 nearest-rank");
        assert_eq!(p95, 19, "p95 nearest-rank (NOT the max)");
        assert_eq!(p99, 20, "p99 nearest-rank");
        assert_eq!(max, 20, "max is the last element");
        // Degenerate sizes stay in-bounds.
        assert_eq!(pcts(&mut [7u128]), Some((7, 7, 7, 7)));
        assert_eq!(pcts(&mut []), None);
    }

    // H-BIN-2: dropped/warmup-failed iterations silently shrank the reported count.
    // RED on the inverse (a suffix that is always empty): the `dropped=5` assert fails.
    #[test]
    fn accounting_suffix_surfaces_drops() {
        assert_eq!(accounting_suffix(0, 0), "");
        let s = accounting_suffix(5, 2);
        assert!(s.contains("dropped=5"), "got {s}");
        assert!(s.contains("warmup_failed=2"), "got {s}");
    }

    // M-BIN-8: the cold label trusted the `drop_caches` write's success alone, so a
    // silently-ineffective write (euid != 0) mislabeled a warm cache as cold. RED on
    // the inverse (`fn(...) -> wrote`): the (wrote, unchanged-Cached) case returns true.
    #[test]
    fn cache_drop_effective_flags_ineffective_write() {
        // Write failed → not effective (warm).
        assert!(!cache_drop_effective(false, Some(100), Some(10)));
        // Write "succeeded" but Cached did not drop → ineffective (warm).
        assert!(!cache_drop_effective(true, Some(100), Some(100)));
        // Write succeeded and Cached dropped → effective (cold).
        assert!(cache_drop_effective(true, Some(100), Some(10)));
        // No prior cache (already cold) → trivially effective.
        assert!(cache_drop_effective(true, Some(0), Some(0)));
    }

    // M-BIN-7: the footprint host-RAM annotations were hard-coded CH memfd/shmem
    // terms, which invert on Firecracker (private anon guest RAM). RED on the inverse
    // (always the CH strings): the FC anon assertion and the CH != FC assertion fail.
    #[test]
    fn footprint_notes_are_backend_specific() {
        let (_a_ch, s_ch) = footprint_mem_notes("cloud-hypervisor");
        assert!(s_ch.contains("memfd"), "CH shmem note should mention memfd");
        let (a_fc, s_fc) = footprint_mem_notes("firecracker");
        assert!(
            a_fc.to_lowercase().contains("anon"),
            "FC anon note should mention anon, got: {a_fc}"
        );
        assert_ne!(s_ch, s_fc, "CH and FC shmem notes must differ");
    }

    // H-BIN-1: `--profile`/`--kernel-verbosity`/`--console` silently defaulted on an
    // unknown value (the `_ => default` arms). RED on the inverse (accept-all
    // parser): the typo `is_err` asserts fail. Note the underscore spelling
    // `low_latency` (vs the hyphenated flag) is a real, rejected typo.
    #[test]
    fn cli_enum_parsers_reject_typos() {
        assert!(parse_profile("low_latency").is_err()); // underscore typo
        assert!(parse_profile("throughputt").is_err());
        assert!(parse_profile("low-latency").is_ok());
        assert!(parse_profile("default").is_ok());
        assert!(parse_profile("throughput").is_ok());

        assert!(parse_console("virtio_console_typo").is_err());
        assert!(parse_console("virtio-console").is_ok());
        assert!(parse_console("uart").is_ok());

        assert!(parse_verbosity("balancedd").is_err());
        assert!(parse_verbosity("quiet").is_ok());
        assert!(parse_verbosity("debug").is_ok());
    }

    // H-BIN-1: the run header now echoes the resolved knobs. RED on the inverse (no
    // echo / hard-coded defaults): the resolved values would be absent from the line.
    #[test]
    fn header_echoes_resolved_knobs() {
        let a = <Args as clap::Parser>::parse_from([
            "bench-vm",
            "--profile",
            "low-latency",
            "--console",
            "virtio-console",
        ]);
        let line = resolved_knobs_line(&a);
        assert!(line.contains("profile: low-latency"), "{line}");
        assert!(line.contains("VirtioConsole"), "{line}");
    }

    // THE PROVENANCE DEFECT (2026-08-21, and this is the fix's gate). The attribution line read
    //
    //     println!("vmm binary: {vmm_bin} (via ${})", vmm_bin_resolver(..).map_or("?", |(v,_)| v));
    //
    // — the name of the variable the resolver WOULD consult, printed whether or not it was set. So
    // a run that found `cloud-hypervisor` on PATH reported itself as pinned by $VMCELL_CH_BIN, and
    // the line's own comment says it exists to distinguish exactly those two cases ("instead of
    // whatever `crosvm` was first on PATH"). The same believing-the-export-applied mistake cost a
    // whole A/B matrix one crate over.
    //
    // RED ON THE INVERSE: restore the unconditional `(via $…)` and the PATH assertions below fail
    // — both the `contains("via $")` one and the exact-line one. The env-set leg is the positive
    // control: the variable IS named when it was actually read, so the fix cannot be "never print
    // the variable".
    #[test]
    fn a_path_resolution_is_never_attributed_to_an_env_var() {
        let unset = |_: &str| None;
        for backend in supported_backends() {
            let (bin, source) =
                resolve_vmm_binary(backend, unset).expect("every backend has a resolver");
            assert_eq!(
                source,
                BinSource::Path,
                "{backend} with no override is PATH"
            );
            let line = vmm_binary_line(&bin, &source);
            assert!(
                !line.contains("via $"),
                "{backend}: a PATH resolution must not name an environment variable: {line}"
            );
            assert_eq!(line, format!("vmm binary: {bin} (found on PATH)"));
        }

        // Positive control: when the variable really was read, the line names it. The variable's
        // name comes from the one table (see the sibling test) rather than a literal here.
        let (ch_var, _) = vmm_bin_resolver("cloud-hypervisor").expect("CH resolver");
        let (bin, source) = resolve_vmm_binary("cloud-hypervisor", |var| {
            (var == ch_var).then(|| "/opt/vmm/ch-dev".to_string())
        })
        .expect("CH resolver");
        assert_eq!(
            vmm_binary_line(&bin, &source),
            format!("vmm binary: /opt/vmm/ch-dev (via ${ch_var})")
        );
        // Which variable `cloud-hypervisor` maps to is already pinned by
        // `vmm_binary_honors_contract_env_overrides` (its lookup answers only for the contract
        // name), so re-spelling the literal here would only add a second read for
        // `scripts/ban-ch-binary-resolver-copies.sh` to account for.
    }

    // The report is the run's own attribution: the binary it executed AND how that path was
    // resolved, the kernel and rootfs it booted, the resolved knobs, and everything the recorder
    // collected. RED on the inverse (a report assembled from `args.backend`'s hardcoded default
    // binary, or one that drops the recorder's notes): the source, metric or note assert fails.
    #[test]
    fn the_report_carries_what_the_run_actually_resolved_and_measured() {
        let args = <Args as clap::Parser>::parse_from(["bench-vm", "--report", "json"]);
        let rec = Recorder::new();
        rec.skip("Warm Restore: backend firecracker has no snapshot support; skipping".to_string());
        let mut samples: Vec<u128> = vec![41, 42, 43];
        assert!(
            rec.measure("cold_boot", Unit::Millis, &mut samples, 0, 0)
                .is_some()
        );
        let report = build_report(
            &args,
            &rec,
            "/opt/vmm/ch-dev",
            &BinSource::EnvVar {
                name: "VMCELL_CH_BIN_FOR_THIS_FIXTURE".to_string(),
            },
            Path::new("/artifacts/vmlinux"),
            Path::new("/artifacts/rootfs.erofs"),
        );
        assert_eq!(report.schema_version, REPORT_SCHEMA_VERSION);
        assert_eq!(report.backend, "cloud-hypervisor");
        assert_eq!(report.mode, "latency");
        assert_eq!(report.vmm_binary, "/opt/vmm/ch-dev");
        assert_eq!(
            report.vmm_binary_source,
            BinSource::EnvVar {
                name: "VMCELL_CH_BIN_FOR_THIS_FIXTURE".to_string()
            }
        );
        assert_eq!(report.kernel, PathBuf::from("/artifacts/vmlinux"));
        assert_eq!(report.metric("cold_boot").map(|m| m.p50), Some(42.0));
        assert_eq!(report.notes.len(), 1, "{:?}", report.notes);
        assert_eq!(
            report.knobs.get("iterations").map(String::as_str),
            Some("10")
        );
        // …and it round-trips through the codec it ships over, which is what the parent parses.
        let json = report.to_json().expect("serialize");
        assert_eq!(BenchReport::from_json(&json).expect("parse"), report);
    }

    // H-BIN-1's rule applied to the new flag: an unknown `--report` must be rejected at parse time,
    // not defaulted. A silently-defaulted `--report jsonn` prints the human table to a parent that
    // is about to `serde_json::from_str` it. RED on the inverse (a `_ => Text` arm): the typo
    // asserts fail.
    #[test]
    fn report_format_parser_rejects_typos_and_defaults_to_text() {
        assert!(parse_report_format("jsonn").is_err());
        assert!(parse_report_format("JSON").is_err());
        assert!(parse_report_format("").is_err());
        assert_eq!(parse_report_format("text"), Ok(ReportFormat::Text));
        assert_eq!(parse_report_format("json"), Ok(ReportFormat::Json));
        // The DEFAULT is the whole compatibility promise: nothing existing changes shape.
        let a = <Args as clap::Parser>::parse_from(["bench-vm"]);
        assert_eq!(a.report, ReportFormat::Text);
    }

    // The text row and the JSON field must not be able to disagree about a value, which they can
    // only guarantee by being the same value. `measure` computes it ONCE and hands back what it
    // recorded; every row prints that. RED on the inverse (a `measure` that records one metric and
    // returns a freshly-computed other, or that records nothing): the equality below fails.
    #[test]
    fn the_recorded_metric_is_the_one_the_row_prints() {
        let rec = Recorder::new();
        let mut samples: Vec<u128> = (1..=20).collect();
        // 23 planned, 20 collected → 3 dropped, DERIVED. Passing the drop count in is what let
        // four call sites report a clean sample set over a truncated one (`dropped_iterations`).
        let returned = rec
            .measure("cold_boot", Unit::Millis, &mut samples, 23, 1)
            .expect("20 samples");
        let (metrics, notes) = rec.drain();
        assert_eq!(metrics, vec![returned.clone()]);
        assert!(notes.is_empty());
        // …and it is the shared nearest-rank answer, not a second percentile law: `pcts` over
        // 1..=20 is p50=10, p95=19, p99=20 (`percentile_nearest_rank_correctness`).
        assert_eq!(
            (returned.p50, returned.p95, returned.p99),
            (10.0, 19.0, 20.0)
        );
        assert_eq!(returned.n, 20);
        assert_eq!((returned.dropped, returned.warmup_failed), (3, 1));

        // An empty sample set records NOTHING: a comparator must not rank a row nobody measured.
        let rec = Recorder::new();
        assert!(
            rec.measure("cold_boot", Unit::Millis, &mut [], 0, 0)
                .is_none()
        );
        assert!(rec.drain().0.is_empty());
    }

    // THE SUPPLY SIDE OF `bench-ab`'s SAMPLE-LOSS VERDICT. That comparator refuses to call a row
    // whose `Metric::dropped` is non-zero, because a boot that failed is disproportionately a SLOW
    // boot and the lossy arm therefore looks faster — survivorship bias with a p-value attached.
    // The predicate was gated; what fed it was not. Every loop here that gives up on a failed boot
    // `break`s, walking past the `dropped += 1` it used to depend on, and `report_phase` passed a
    // literal `0` — so the arm that was losing samples reported a clean sample set and the gate
    // stayed green over exactly the run it exists to refuse.
    //
    // RED on the inverse (`measure` taking a caller-supplied `dropped` again, or
    // `dropped_iterations` returning 0): the seven-dropped assert fails, on the funnel AND on the
    // `report` forwarder that every latency row goes through.
    #[test]
    fn a_truncated_sample_set_reports_its_loss_with_no_counter_to_walk_past() {
        // Ten planned boots, three survived — the shape of a run whose fourth create failed.
        let rec = Recorder::new();
        let mut survivors: Vec<u128> = vec![40, 41, 42];
        let m = rec
            .measure(metrics::COLD_BOOT, Unit::Millis, &mut survivors, 10, 0)
            .expect("three surviving samples");
        assert_eq!(
            (m.n, m.dropped),
            (3, 7),
            "a p50 over three of ten planned boots must declare the seven, or the comparator ranks              it against a complete arm as if it were one"
        );

        // …and through the forwarder the latency rows actually call, so the fix is not one the
        // call sites can be written around.
        let rec = Recorder::new();
        let mut survivors: Vec<u128> = vec![40, 41, 42];
        report(&rec, "Cold Boot", metrics::COLD_BOOT, &mut survivors, 10, 2);
        let recorded = rec.drain().0;
        let m = recorded.first().expect("one metric");
        assert_eq!((m.n, m.dropped, m.warmup_failed), (3, 7, 2));

        // The floor: nothing lost is nothing declared, so the column stays silent on a clean
        // matrix. Without this a `dropped` that was always non-zero would satisfy the asserts
        // above and disqualify every row in the table.
        let rec = Recorder::new();
        let mut all: Vec<u128> = vec![40, 41, 42];
        let m = rec
            .measure(metrics::COLD_BOOT, Unit::Millis, &mut all, 3, 0)
            .expect("three samples");
        assert_eq!((m.n, m.dropped), (3, 0));
        // A caller that collected more than it planned is its own bug and must not underflow into
        // a usize the size of the address space.
        assert_eq!(dropped_iterations(3, 10), 0);
    }

    // The report module's stated rule, gated at the emitting side: phase-budget rows are qualified
    // BY PATH, because COLD and RESTORE print the same four row names and the 2026-08-21 collector
    // — keying on the printed name — silently kept only the first path and reported it as both.
    // RED on the inverse (an unqualified `create`/`connect`/… metric name, or a share that is
    // printed but not recorded): the name asserts, or the share assert, fail.
    #[test]
    fn phase_rows_are_qualified_by_path_so_cold_and_restore_cannot_collide() {
        let rec = Recorder::new();
        let mut cold: Vec<u128> = vec![100, 200, 300];
        let mut restore: Vec<u128> = vec![10, 20, 30];
        report_phase(&rec, "connect ", "phase_cold_connect", &mut cold, 3, 1000);
        report_phase(
            &rec,
            "connect ",
            "phase_restore_connect",
            &mut restore,
            3,
            1000,
        );
        let names: Vec<String> = rec.drain().0.into_iter().map(|m| m.name).collect();
        assert_eq!(
            names,
            vec![
                "phase_cold_connect",
                "phase_cold_connect_share",
                "phase_restore_connect",
                "phase_restore_connect_share",
            ],
            "the two paths must occupy four distinct metric names"
        );
    }

    // A self-skip is a NOTE, not just a line that scrolls away: a run that skipped half its matrix
    // and a run that measured all of it must not be indistinguishable in the JSON artifact. RED on
    // the inverse (a `say!` beside the skip instead of `rec.skip`, or `skip` no longer forwarding
    // to the one `caveat` body): the note assert fails.
    //
    // TWO MODES, not one: the class is "this run measured something other than what the table
    // implies", and it is spread across the matrix — a latency run without snapshot support and a
    // net-egress run without a vhost-user-net device skip for unrelated reasons and both must
    // reach the artifact. A one-mode fixture is how the four caveats beside these (see
    // `a_caveat_fires_exactly_when_its_condition_holds`) went a whole review without one.
    #[test]
    fn a_self_skip_is_recorded_as_a_note_verbatim() {
        let rec = Recorder::new();
        rec.skip("Warm Restore: backend firecracker has no snapshot support; skipping".to_string());
        rec.skip(
            "net-egress[tls]: backend firecracker has no unprivileged vhost-user-net; skipping"
                .to_string(),
        );
        let (metrics, notes) = rec.drain();
        assert!(metrics.is_empty());
        assert_eq!(
            notes,
            vec![
                "Warm Restore: backend firecracker has no snapshot support; skipping",
                "net-egress[tls]: backend firecracker has no unprivileged vhost-user-net; skipping",
            ],
            "every skip, in the order the matrix hit them"
        );
    }

    // THE PARENT/CHILD CONTRACT, both arms. `--report json` puts exactly one report on stdout and
    // `--report text` puts NOTHING there (its report is the table already printed). Inverting the
    // branch — text dumping JSON into the human table, json emitting nothing — left the whole
    // suite green while breaking both halves of the promise at once: the parent parses this
    // stdout, and "nothing existing changes shape" is what makes `text` the default.
    // RED on the inverse (`!=` flipped to `==` in `stdout_report`): the text arm's `is_none` and
    // the json arm's `expect` fail.
    #[test]
    fn only_the_json_format_puts_a_report_on_stdout() {
        let emitted = |argv: &[&str]| {
            let args = <Args as clap::Parser>::parse_from(argv);
            let rec = Recorder::new();
            let mut samples: Vec<u128> = vec![41, 42, 43];
            assert!(
                rec.measure(metrics::COLD_BOOT, Unit::Millis, &mut samples, 0, 0)
                    .is_some()
            );
            stdout_report(
                &args,
                &rec,
                "/usr/bin/cloud-hypervisor",
                &BinSource::Path,
                Path::new("/artifacts/vmlinux"),
                Path::new("/artifacts/rootfs.erofs"),
            )
            .expect("a declared metric serializes")
        };

        // TEXT: nothing on stdout at all — not an empty document, not a `null`.
        assert!(
            emitted(&["bench-vm"]).is_none(),
            "the default format must leave stdout to the human table"
        );
        assert!(emitted(&["bench-vm", "--report", "text"]).is_none());

        // JSON: one document, and it is a report the PARENT can read — asserted through
        // `BenchReport::from_json`, the same call `bench-ab` makes on this stdout, rather than
        // through a substring.
        let json = emitted(&["bench-vm", "--report", "json"]).expect("json emits a report");
        let parsed = BenchReport::from_json(&json).expect("the parent parses this stdout");
        assert_eq!(parsed.metric(metrics::COLD_BOOT).map(|m| m.p50), Some(42.0));
        assert_eq!(parsed.schema_version, REPORT_SCHEMA_VERSION);
    }

    /// Every caveat composer, with an input that makes it fire and one that does not.
    ///
    /// The roster is a `const` because the call-site scan below reads it: a composer added here
    /// and left uncalled fails there, and one called from an `if` at its call site fails there
    /// too.
    const CAVEAT_COMPOSERS: [&str; 5] = [
        "snap_dir_tmpfs_caveat",
        "ksm_acceleration_caveat",
        "ksm_residue_caveat",
        "pid_attribution_caveat",
        "zygote_cow_caveat",
    ];

    // THE CAVEATS ARE RECORDED, NOT JUST PRINTED — the decision half. Four of these shipped as a
    // bare `say!` inside an `if` at the call site, so they reached the terminal and never the
    // JSON: an arm whose snapshots were RAM-backed, whose KSM scanner never accelerated, whose
    // per-VM totals were deflated, or whose zygote paid a full copy per clone was
    // indistinguishable in the artifact from an arm where none of that happened. RED on the
    // inverse (any composer returning `Some` unconditionally, or `None` unconditionally): its
    // fires/silent pair fails by name.
    #[test]
    fn a_caveat_fires_exactly_when_its_condition_holds() {
        // The snapshot directory only shapes a RESTORE number, so a cold-boot run on tmpfs has
        // nothing to disclose — that third `false` leg is the one an `if is_tmpfs(..)` alone
        // would have got wrong.
        let dir = Path::new("/dev/shm/vmcell-bench-snap");
        let fired = snap_dir_tmpfs_caveat(dir, true, true).expect("a restore run on tmpfs");
        assert!(fired.contains("/dev/shm/vmcell-bench-snap"), "{fired}");
        assert!(fired.contains("optimistic"), "{fired}");
        assert_eq!(snap_dir_tmpfs_caveat(dir, false, true), None);
        assert_eq!(snap_dir_tmpfs_caveat(dir, true, false), None);

        // The KSM one names the metric it qualifies, and that metric is the roster's inverted
        // one: a smaller `pages_sharing` delta here is a measurement failure, not less dedup.
        let fired = ksm_acceleration_caveat(false).expect("an unaccelerated scanner");
        assert!(
            fired.contains(metrics::FOOTPRINT_KSM_PAGES_SHARING_DELTA),
            "the caveat must name the metric it qualifies: {fired}"
        );
        assert_eq!(
            vmcell_bench::metrics::direction(metrics::FOOTPRINT_KSM_PAGES_SHARING_DELTA),
            Some(vmcell_bench::metrics::Direction::HigherIsBetter),
            "if this stops being a benefit, the caveat's wording is wrong"
        );
        assert_eq!(ksm_acceleration_caveat(true), None);

        // Merged pages outlive the run, which is what makes them the NEXT interleaved arm's
        // starting state.
        assert!(
            ksm_residue_caveat(true)
                .expect("mergeable")
                .contains("not fully reset")
        );
        assert_eq!(ksm_residue_caveat(false), None);

        let fired = pid_attribution_caveat(3, 10).expect("seven pids unresolved");
        assert!(fired.contains("3/10"), "{fired}");
        assert_eq!(pid_attribution_caveat(10, 10), None);

        let fired = zygote_cow_caveat(vmcell::CowSupport::FullCopy).expect("a non-reflink fs");
        assert!(fired.contains("full byte copy"), "{fired}");
        assert_eq!(zygote_cow_caveat(vmcell::CowSupport::Reflink), None);

        // …and every one of them, once it fires, lands in the report verbatim. This is the class
        // the four defects belonged to: the decision was right and the note was never taken.
        let rec = Recorder::new();
        rec.caveat(pid_attribution_caveat(3, 10));
        rec.caveat(zygote_cow_caveat(vmcell::CowSupport::FullCopy));
        rec.caveat(ksm_acceleration_caveat(true)); // silent: records nothing
        let (metrics_taken, notes) = rec.drain();
        assert!(metrics_taken.is_empty());
        assert_eq!(
            notes,
            vec![
                pid_attribution_caveat(3, 10).expect("fires"),
                zygote_cow_caveat(vmcell::CowSupport::FullCopy).expect("fires"),
            ]
        );
    }

    // THE CALL-SITE HALF, over the production source. A composer with a red-on-inverse unit test
    // proves the decision; it proves nothing about whether the call site takes the note — and
    // "printed but never recorded" was the whole finding. Two directions, because either one
    // alone is satisfiable by the defect:
    //
    //   A. every composer's call site is `rec.caveat(<composer>(…))` — no `if` of its own, no
    //      `say!` beside it, and at least one call site per composer;
    //   B. every `.caveat(` argument is a listed composer (or the `skip` forwarder's `Some(text)`),
    //      so a caveat cannot come back as a condition spelled at the call site.
    //
    // A zero-length scan is `gate misconfigured` and fails: the only way to open nothing is to
    // have been pointed at nothing.
    // RED on the inverse (any site reverted to `if cond { say!(…) }`, or a composer called
    // anywhere but at `rec.caveat(`): the layer-A assert names the composer.
    #[test]
    fn every_caveat_is_recorded_not_just_printed() {
        let production = production_half_of_this_file();
        assert!(
            production.len() > 10_000,
            "gate misconfigured: the production half scanned to {} bytes",
            production.len()
        );

        // --- Layer A: each composer is called, and only ever as `rec.caveat`'s argument.
        for composer in CAVEAT_COMPOSERS {
            let needle = format!("{composer}(");
            let mut call_sites = 0_usize;
            let mut rest = production.as_str();
            let mut scanned = 0_usize;
            while let Some(at) = rest.find(&needle) {
                // Indexed into the WHOLE production half, not into `rest`: `rest` is a suffix,
                // and reading the prefix out of it silently yields nothing past the first hit.
                let before = production.get(..scanned + at).unwrap_or_default();
                let is_definition = before.ends_with("fn ");
                if !is_definition {
                    assert!(
                        before.ends_with("rec.caveat("),
                        "`{composer}` is called somewhere other than `rec.caveat(…)`. A caveat \
                         composed and then printed — or decided by an `if` beside the printing — \
                         is a caveat the JSON report never carries, which is exactly how the \
                         tmpfs, KSM, pid-attribution and zygote caveats reached the terminal and \
                         nothing else."
                    );
                    call_sites += 1;
                }
                let consumed = at + needle.len();
                rest = rest.split_at(consumed).1;
                scanned += consumed;
            }
            assert!(
                call_sites >= 1,
                "gate misconfigured: `{composer}` is in CAVEAT_COMPOSERS but nothing calls it; a \
                 caveat nobody can reach is not a caveat"
            );
        }

        // --- Layer B: nothing else reaches `caveat`.
        let mut recorded = 0_usize;
        let mut rest = production.as_str();
        while let Some(at) = rest.find(".caveat(") {
            let after = rest.split_at(at + ".caveat(".len()).1;
            let argument: String = after
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            // The forwarder is admitted by its EXACT spelling, not by "starts with `Some`": a
            // `rec.caveat(Some(format!(…)))` is the inline condition this layer exists to
            // refuse, and it would pass a looser check.
            let is_forwarder = after.starts_with("Some(text));");
            assert!(
                CAVEAT_COMPOSERS.contains(&argument.as_str()) || is_forwarder,
                "`.caveat({argument}…)` names neither a listed composer nor `Recorder::skip`'s \
                 one `Some(text)` forward. The decision belongs in a named composer with its own \
                 fires/silent test; an inline one is a condition no test drives."
            );
            recorded += 1;
            rest = after;
        }
        assert!(
            recorded >= CAVEAT_COMPOSERS.len(),
            "gate misconfigured: {recorded} `.caveat(` sites found for {} composers plus the \
             forwarder",
            CAVEAT_COMPOSERS.len()
        );
    }

    // The knobs travel RESOLVED. `--iterations` is an `Option` whose per-mode default (200 for
    // vsock-rtt, 10 elsewhere) decides the sample size, and "unset" is not something a comparator
    // can compare — two arms with the same unset flag and different modes measured different
    // amounts of work. RED on the inverse (`args.iterations` written through as-is): the
    // vsock-rtt assert reads "None"/"" instead of 200.
    #[test]
    fn run_knobs_carry_the_resolved_iteration_count() {
        let a = <Args as clap::Parser>::parse_from(["bench-vm", "--mode", "vsock-rtt"]);
        let knobs = run_knobs(&a);
        assert_eq!(knobs.get("iterations").map(String::as_str), Some("200"));
        let b = <Args as clap::Parser>::parse_from(["bench-vm", "--mode", "latency"]);
        assert_eq!(
            run_knobs(&b).get("iterations").map(String::as_str),
            Some("10")
        );
        // The knobs the run header echoes are all present, so a JSON reader can attribute the
        // numbers to the same configuration the text header names (H-BIN-1).
        for key in [
            "profile",
            "kernel_verbosity",
            "console",
            "mem_mib",
            "warmup",
        ] {
            assert!(knobs.contains_key(key), "knobs must carry {key}: {knobs:?}");
        }
    }

    /// Identifiers that legitimately stand in for a metric name at a `measure`/`scalar` call
    /// site, each with the reason it is not a `metrics::` path there.
    ///
    /// An entry is a decision, not a backlog: adding a name silences the scan below for that call
    /// site, so what the next reader reviews is the reason. Both of these are *forwarders* — they
    /// carry a name their caller chose — and the ban on bare roster literals is what keeps that
    /// caller honest: with no roster literal anywhere in the production half, a forwarder can only
    /// have been handed a `metrics::` path, or a name the roster does not carry at all, which
    /// `Recorder::register` refuses at the exit.
    const METRIC_NAME_FORWARDERS: [(&str, &str); 2] = [
        (
            "metric",
            "the `&str` parameter of `report`/`report_phase`; its callers pass the `metrics::` \
             path (or a composer), and the label beside it is the human row name",
        ),
        (
            "rtt_metric",
            "a local bound to one of two `metrics::` consts by the privileged/unprivileged branch",
        ),
    ];

    /// `text` with its `//` comments removed, string literals left intact.
    ///
    /// WHY THE SCAN BELOW NEEDS THIS. A comment is the right place to quote a metric name — the
    /// refusal in `refuse_unregistered_metrics` explains itself by quoting the one-line rule it
    /// replaced, `metric != "footprint_ksm_pages_sharing_delta"` — and a ban that reddens on its
    /// own documentation is a ban that gets deleted. The ban is about *code*, so the scan reads
    /// code.
    ///
    /// String-aware rather than a naive cut at `//`, because this file builds `http://` URLs: a
    /// line-truncating stripper would silently shorten those lines and could hide a real call site
    /// behind one. There are no block comments or raw strings here (the scan's own call-site floor
    /// is what notices if that stops being true).
    fn strip_line_comments(text: &str) -> String {
        let mut out = String::with_capacity(text.len());
        let mut chars = text.chars().peekable();
        let mut in_string = false;
        let mut in_comment = false;
        while let Some(c) = chars.next() {
            if in_comment {
                if c == '\n' {
                    in_comment = false;
                    out.push(c);
                }
                continue;
            }
            if in_string {
                out.push(c);
                if c == '\\' {
                    // An escape consumes the next character, so `\"` does not end the literal.
                    if let Some(next) = chars.next() {
                        out.push(next);
                    }
                } else if c == '"' {
                    in_string = false;
                }
                continue;
            }
            if c == '"' {
                in_string = true;
                out.push(c);
                continue;
            }
            if c == '/' && chars.peek() == Some(&'/') {
                in_comment = true;
                continue;
            }
            out.push(c);
        }
        out
    }

    /// The production half of this file: everything before its own `#[cfg(test)]` module.
    ///
    /// Scanning the tests too would be wrong in both directions — a test SHOULD assert against a
    /// literal metric name (asserting against the composer that produced it is vacuous), and a
    /// fixture may deliberately record a name the roster does not carry.
    fn production_half_of_this_file() -> String {
        let path =
            vmcell::artifact::workspace_root().join("crates/vmcell-bench/src/bin/bench-vm.rs");
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("gate misconfigured: cannot read {}: {e}", path.display()));
        let marker = "\n#[cfg(test)]\nmod tests {";
        let cut = text.find(marker).unwrap_or_else(|| {
            panic!(
                "gate misconfigured: no `{}` in {} — the scan cannot tell production from tests",
                marker.trim(),
                path.display()
            )
        });
        let production = text
            .get(..cut)
            .unwrap_or_else(|| panic!("gate misconfigured: cannot split {}", path.display()));
        strip_line_comments(production)
    }

    // THE ROSTER'S CALL-SITE GATE. A direction roster with a red-on-inverse unit test proves the
    // roster; it proves nothing about whether the metric names this binary emits are the names in
    // it. The rule it replaced was one line — "everything is a cost except the one exception I
    // remembered" — so a new metric got a direction nobody chose, and a BENEFIT that got worse
    // printed IMPROVEMENT. Three layers, in order of how early they catch it:
    //
    //   A. every `measure`/`scalar` name argument is a `metrics::` path (or a listed forwarder),
    //   B. no roster name appears as a bare string literal, so nothing can drift by re-spelling,
    //   C. `Recorder::register` + `refuse_unregistered_metrics` catch a name that is neither —
    //      at the exit of the run that emitted it, which is the only place a forwarded name is
    //      knowable at all.
    //
    // A zero-length scan is `gate misconfigured` and fails: the only way to open nothing is to have
    // been pointed at nothing. The roster's OWN completeness (composed names ↔ composers, both
    // directions) is `vmcell_bench::metrics`'s `the_composers_and_the_roster_agree_in_both_directions`;
    // this gate is its complement and asserts the roster is non-empty so a gutted roster cannot make
    // it vacuously green.
    // RED on the inverse (any `metrics::COLD_BOOT` reverted to `"cold_boot"`, or a new
    // `rec.scalar("something_new", …)` added): the literal ban or the call-site rule fails by name.
    #[test]
    fn every_metric_name_this_binary_emits_comes_from_the_roster() {
        let production = production_half_of_this_file();
        assert!(
            production.len() > 10_000,
            "gate misconfigured: the production half scanned to {} bytes",
            production.len()
        );
        let roster: Vec<&str> = metrics::names().collect();
        assert!(
            roster.len() > 40,
            "gate misconfigured: the direction roster holds {} names; this binary emits ~50, so a \
             roster this short cannot be what the ban below is checking against",
            roster.len()
        );

        // --- Layer A: every recorder call site names its metric through `metrics::`.
        let mut call_sites = 0_usize;
        for opener in [".measure(", ".scalar("] {
            let mut rest = production.as_str();
            while let Some(at) = rest.find(opener) {
                let after = rest.split_at(at + opener.len()).1;
                let argument = after.trim_start();
                // A bare literal stops the identifier scan at its opening quote, which would
                // report the offender as an empty string. Show what is actually written there.
                let head: String = if argument.starts_with('"') {
                    argument
                        .char_indices()
                        .take_while(|(i, c)| *i == 0 || *c != '"')
                        .map(|(_, c)| c)
                        .chain(std::iter::once('"'))
                        .collect()
                } else {
                    argument
                        .chars()
                        .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '&' || *c == ':')
                        .collect()
                };
                let ok = head.trim_start_matches('&').starts_with("metrics::")
                    || METRIC_NAME_FORWARDERS
                        .iter()
                        .any(|(name, _)| head.trim_start_matches('&') == *name);
                assert!(
                    ok,
                    "a `{opener}` call names its metric as `{head}`, which is neither a \
                     `metrics::` path nor a listed forwarder. A metric name spelled at the call \
                     site is a name the direction roster cannot see, and the roster is what stops \
                     the comparator guessing a direction. Add it to \
                     `vmcell_bench::metrics` and emit through the constant, or add the \
                     identifier to METRIC_NAME_FORWARDERS WITH its reason."
                );
                call_sites += 1;
                rest = after;
            }
        }
        assert!(
            call_sites >= 20,
            "gate misconfigured: only {call_sites} recorder call sites found; this binary has \
             tens of them, so the scan is not reading what it thinks it is"
        );

        // --- Layer B: no roster name is spelled as a bare literal anywhere in production.
        for name in &roster {
            let literal = format!("\"{name}\"");
            assert!(
                !production.contains(&literal),
                "the metric name {literal} is spelled as a bare string literal in this binary. \
                 That is a second place the name lives, and the two have to agree forever; emit \
                 `metrics::` instead so the roster entry and the emitted string are one fact."
            );
        }
    }

    /// The four recorder entry points that take a planned-iterations count, as
    /// `(call, 0-based index of the planned argument, argument count)`.
    ///
    /// The arity travels with the index so a signature that grows or reorders an argument fails
    /// this gate loudly instead of silently letting it check the wrong slot.
    const PLANNED_ARG_CALL_SITES: [(&str, usize, usize); 4] = [
        (".measure(", 3, 5),
        ("report(", 4, 6),
        ("report_phase(", 4, 6),
        ("report_daemon_op(", 3, 4),
    ];

    /// The top-level, comma-separated arguments of the call whose `(` sits at `open`.
    ///
    /// String- and nesting-aware, so `&metrics::phase_metric(path, "create")` is ONE argument and
    /// a `&mut [u128]` is not three. `None` when the parentheses never close — a scanner bug, and
    /// the caller asserts on it rather than skipping the site.
    fn call_arguments(text: &str, open: usize) -> Option<Vec<String>> {
        let mut depth = 0_usize;
        let mut in_string = false;
        let mut escaped = false;
        let mut args: Vec<String> = Vec::new();
        let mut current = String::new();
        for c in text.get(open..)?.chars() {
            if in_string {
                current.push(c);
                if escaped {
                    escaped = false;
                } else if c == '\\' {
                    escaped = true;
                } else if c == '"' {
                    in_string = false;
                }
                continue;
            }
            match c {
                '"' => {
                    in_string = true;
                    current.push(c);
                }
                '(' | '[' | '{' => {
                    depth += 1;
                    if depth > 1 {
                        current.push(c);
                    }
                }
                ')' | ']' | '}' => {
                    depth = depth.checked_sub(1)?;
                    if depth == 0 {
                        if !current.trim().is_empty() {
                            args.push(current.trim().to_string());
                        }
                        return Some(args);
                    }
                    current.push(c);
                }
                ',' if depth == 1 => {
                    args.push(current.trim().to_string());
                    current.clear();
                }
                _ => current.push(c),
            }
        }
        None
    }

    // THE DROP-ACCOUNTING CALL-SITE GATE, and it is the half that was missing. `bench-ab` refuses
    // to call a row whose `Metric::dropped` is non-zero — survivorship bias with a p-value
    // attached, since a boot that failed is disproportionately a SLOW boot and the lossy arm
    // therefore looks faster. That predicate had a red-on-inverse test. What FED it did not: the
    // count arrived as a caller-kept `dropped += 1`, and `run_bench`'s create/restore arm, the
    // vsock loop and both egress RTT loops all `break` past the increment, `phase_budget_path`
    // passed a literal `0`, and `zygote`'s steward-ready row passed a literal `0` beside a live
    // counter. Every one of those reported a CLEAN sample set over a truncated one.
    //
    // The count is now `dropped_iterations(planned, collected)`, which a `break` cannot walk past
    // — so the thing worth gating is that no call site quietly declares it planned nothing.
    // A zero-length scan is `gate misconfigured` and fails: the only way to open nothing is to
    // have been pointed at nothing.
    //
    // RED on the inverse (any site reverted to `0` for its planned count, e.g.
    // `rec.measure(metrics::ZYGOTE_STEWARD_READY, Unit::Millis, &mut ready, 0, 0)`): the zero
    // assert names the offending call.
    #[test]
    fn no_recorder_call_site_hardcodes_its_planned_iteration_count() {
        let production = production_half_of_this_file();
        assert!(
            production.len() > 10_000,
            "gate misconfigured: the production half scanned to {} bytes",
            production.len()
        );
        let mut sites = 0_usize;
        for (needle, planned_index, arity) in PLANNED_ARG_CALL_SITES {
            let mut from = 0_usize;
            let mut per_needle = 0_usize;
            while let Some(offset) = production.get(from..).and_then(|rest| rest.find(needle)) {
                let at = from + offset;
                from = at + needle.len();
                // `report(` must not match `build_report(` / `stdout_report(` / `emit_report(`.
                // Only for the needles that START with an identifier character: `.measure(` is
                // ALWAYS preceded by one (`rec.measure`), so applying the rule to it matched
                // nothing at all — which the per-needle floor below is what caught.
                let needs_boundary = needle
                    .chars()
                    .next()
                    .is_some_and(|c| c.is_alphanumeric() || c == '_');
                let boundary_ok = !needs_boundary
                    || at == 0
                    || !production
                        .get(..at)
                        .and_then(|before| before.chars().next_back())
                        .is_some_and(|c| c.is_alphanumeric() || c == '_');
                if !boundary_ok {
                    continue;
                }
                let open = at + needle.len() - 1;
                let args = call_arguments(&production, open).unwrap_or_else(|| {
                    panic!("gate misconfigured: unbalanced parentheses after `{needle}` at {at}")
                });
                assert_eq!(
                    args.len(),
                    arity,
                    "`{needle}` at byte {at} has {} arguments, not the {arity} this gate knows how                      to read: {args:?}. The signature moved — update PLANNED_ARG_CALL_SITES,                      because an index into the wrong slot is a gate that checks nothing.",
                    args.len()
                );
                let planned = args
                    .get(planned_index)
                    .map(String::as_str)
                    .unwrap_or_default();
                let bare = planned.trim_end_matches("usize").trim_end_matches('_');
                // A LOSS COUNTER in the planned slot is the same defect as a literal zero, and it
                // is the one that actually shipped: four sites passed their `dropped` /
                // `start_dropped` accumulator here, and because that counter is smaller than the
                // surviving sample count on any realistic run, `planned.saturating_sub(collected)`
                // floored to 0 and a run that lost three of ten reported a clean sweep. The
                // literal-zero assertion below could not see it — the argument is an identifier,
                // not "0" — so the class needs its own arm. Names, not values, are what a source
                // scan can check; a planned count is an iteration count and is never spelled
                // "dropped".
                assert!(
                    !bare.contains("dropped"),
                    "`{needle}` at byte {at} passes `{bare}` as its PLANNED count, but that names a \
                     loss counter. `Metric::dropped` is `planned - collected`, so a counter here \
                     underflows to zero and the run reports no loss at all — `bench-ab` then ranks \
                     a truncated arm against a complete one, and a failed boot is disproportionately \
                     a SLOW boot, so the lossy arm looks FASTER. Pass the post-warmup iteration \
                     count the loop set out to take (`iters` / `args.iters()`)."
                );
                assert_ne!(
                    bare, "0",
                    "`{needle}` at byte {at} declares it planned ZERO iterations, so every sample                      it lost is invisible: `Metric::dropped` is `planned - collected`, and a                      planned count of 0 makes a truncated run report a clean one. `bench-ab` then                      ranks it against a complete arm and prints a verdict. Pass the post-warmup                      iteration count the loop set out to take."
                );
                sites += 1;
                per_needle += 1;
            }
            assert!(
                per_needle > 0,
                "gate misconfigured: no `{needle}` call sites found; the scan is not reading what                  it thinks it is"
            );
        }
        assert!(
            sites >= 15,
            "gate misconfigured: only {sites} planned-count call sites found across              {} entry points; this binary has more than that",
            PLANNED_ARG_CALL_SITES.len()
        );
    }

    // THE FUNNEL'S REFUSAL — layer C, and the only layer that can see a name arriving through a
    // forwarder. RED on the inverse (`refuse_unregistered_metrics` deleted from `emit_report`, or
    // `Recorder::register` no longer called from `measure`/`scalar`): the `expect_err` fails.
    #[test]
    fn a_metric_with_no_declared_direction_refuses_the_report() {
        let args = <Args as clap::Parser>::parse_from(["bench-vm", "--report", "json"]);
        let emit = |rec: &Recorder| {
            emit_report(
                &args,
                rec,
                "/usr/bin/cloud-hypervisor",
                &BinSource::Path,
                Path::new("/artifacts/vmlinux"),
                Path::new("/artifacts/rootfs.erofs"),
            )
        };

        // A name nobody declared a direction for — the shape a new metric arrives in.
        let rec = Recorder::new();
        let _ = rec.scalar("brand_new_quantity", Unit::Count, 1, 7.0);
        let mut samples: Vec<u128> = vec![1, 2, 3];
        let _ = rec.measure("another_new_one", Unit::Millis, &mut samples, 0, 0);
        let err = emit(&rec)
            .expect_err("a metric with no declared direction must not reach a comparator")
            .to_string();
        assert!(err.contains("brand_new_quantity"), "{err}");
        assert!(err.contains("another_new_one"), "every offender: {err}");
        assert!(err.contains("METRIC_DIRECTIONS"), "name the fix: {err}");

        // A metric whose samples are EMPTY records nothing but is still checked: a name is wrong
        // whether or not it produced a number.
        let rec = Recorder::new();
        let _ = rec.measure("empty_but_undeclared", Unit::Millis, &mut [], 0, 0);
        assert!(emit(&rec).is_err(), "an empty sample set is still a name");

        // THE POSITIVE CONTROL. Without it a refusal that fired on everything would satisfy the
        // three asserts above.
        let rec = Recorder::new();
        let _ = rec.scalar(metrics::SUSPEND_TOTAL_BYTES, Unit::Bytes, 1, 4096.0);
        let mut samples: Vec<u128> = vec![41, 42, 43];
        assert!(
            rec.measure(metrics::COLD_BOOT, Unit::Millis, &mut samples, 0, 0)
                .is_some()
        );
        emit(&rec).expect("declared metrics emit a report");
    }

    // N-BIN-5: the tmpfs check must match the LONGEST mount-point prefix, not the
    // first (`/` matches every absolute path). RED on the inverse (first-match): the
    // nested `/home/x/target/snap` path resolves to the root `ext4` instead of tmpfs.
    #[test]
    fn path_fstype_uses_longest_mount_prefix() {
        let mi = "\
1 0 8:1 / / rw shared:1 - ext4 /dev/sda1 rw
2 0 0:22 / /dev/shm rw shared:2 - tmpfs tmpfs rw
3 0 0:23 / /home/x/target rw shared:3 - tmpfs tmpfs rw
";
        assert_eq!(
            path_fstype(mi, Path::new("/dev/shm/snap")).as_deref(),
            Some("tmpfs")
        );
        assert_eq!(
            path_fstype(mi, Path::new("/var/data")).as_deref(),
            Some("ext4")
        );
        assert_eq!(
            path_fstype(mi, Path::new("/home/x/target/vmcell-bench-snap")).as_deref(),
            Some("tmpfs")
        );
    }
}
