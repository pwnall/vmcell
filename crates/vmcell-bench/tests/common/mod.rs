//! Shared harness for the `bench-vm` subprocess tests.
//!
//! The artifact getters are re-exported from `vmcell_artifact_validator::harness` — the single
//! source of truth also used by `vmcell`'s integration suite (design §5.4/§8.5) — so the
//! `#[ignore]`d KVM benchmark tests trigger the same at-most-once rootfs/kernel build before
//! shelling out to `bench-vm`. Lives under `tests/common/` (a subdir, not `tests/common.rs`) so
//! cargo does not compile it as its own test target.
//!
//! # ONE composer for the child, and it never re-wraps (docs/90 G2's follow-on defect)
//!
//! `just test-bench` wraps THIS test binary with the blessed runner through nextest's
//! `CARGO_TARGET_<TRIPLET>_RUNNER` hook — that is how the live legs' `bench-vm` gets
//! `PRIVILEGED_CAPS`, and it is the same "wrapped test binary, directly-spawned privileged child"
//! shape `just test-daemon` uses for `vmcelld` (§11.2, Privilege and blessing).
//!
//! nextest passes its own environment through, so the *wrapped* test process still sees that
//! variable — and `assert_cmd`'s `Command::cargo_bin` door reads exactly that variable family and
//! composes `<runner> <bin>` in front of the binary it found. Every test here used that door, so
//! the suite wrapped TWICE: the runner once around the test binary, and again around `bench-vm`.
//!
//! The second wrap can never succeed, and the reason is worth stating once because the bare
//! `Operation not permitted (os error 1)` it produces names nothing:
//!
//! * the blessed runner's file capabilities are `cap_…,cap_setpcap+ep` — `BLESSED_FILE_CAPS`, the
//!   delivered `PRIVILEGED_CAPS` plus the **transient** `CAP_SETPCAP` the bounding-set shrink needs;
//! * the FIRST wrap performs that shrink, so by the time a test runs, the process's bounding set is
//!   exactly `PRIVILEGED_CAPS` — `CAP_SETPCAP` is gone from it;
//! * `execve(2)` computes `pP' = (X & fP) | (pI & fI)` and, when the file's effective bit is set and
//!   `fP` is not a subset of the bounding set `X`, returns **EPERM** ("insufficient to execute
//!   correctly", `security/commoncap.c`) rather than silently degrading.
//!
//! So there is one composer, [`bench_vm`], it resolves the binary through cargo's own
//! `CARGO_BIN_EXE_bench-vm` (compile-time, env-independent), and the child inherits the caps
//! through the **ambient** set — which `execve` preserves across a file that carries no
//! capabilities of its own. [`the_harness_never_re_wraps_bench_vm_in_the_target_runner`] and
//! [`the_child_is_spawned_directly_into_the_inherited_privilege_window`] are that law's gates, and
//! [`assert_bench_vm`] is the one spawn site, so a future EPERM here reports its cause instead of
//! its errno.

pub use vmcell_artifact_validator::harness::{get_rootfs, get_vmlinux};

use assert_cmd::assert::Assert;
use std::ffi::{CString, OsStr};
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

/// The `bench-vm` binary as cargo built it for **this** test target.
///
/// `env!` and not a runtime lookup: cargo sets `CARGO_BIN_EXE_<name>` for an integration test of the
/// package that owns the `[[bin]]`, so the path is fixed at compile time and cannot be redirected by
/// the environment — which is the whole defect this replaces (`assert_cmd`'s `cargo_bin` door
/// prepends `$CARGO_TARGET_<TRIPLET>_RUNNER`, and under `just test-bench` that variable is set).
pub const BENCH_VM_BIN: &str = env!("CARGO_BIN_EXE_bench-vm");

/// File name of the blessed capability runner, as the justfile installs it.
const RUNNER_FILE_NAME: &str = "vmcell-test-runner";

/// The ONE `bench-vm` command composer for this suite.
///
/// Spawns the binary **directly**. Under `just test-bench` this process is already inside the
/// privilege window, and the child inherits `PRIVILEGED_CAPS` through the ambient set; re-wrapping
/// it in the blessed runner is the EPERM documented in this module's header.
pub fn bench_vm() -> Command {
    Command::new(BENCH_VM_BIN)
}

/// Runs `cmd` and hands back `assert_cmd`'s [`Assert`], reporting a spawn EPERM as the
/// privilege-transition failure it is.
///
/// `assert_cmd`'s own `&mut Command` → `Assert` path panics with `Failed to spawn <argv>: <errno>`,
/// which is how the double wrap reached CI as five identical `Operation not permitted (os error 1)`
/// lines with no cause in them. Same `Assert`, same context line — only the error arm differs.
#[track_caller]
pub fn assert_bench_vm(cmd: &mut Command) -> Assert {
    match cmd.output() {
        Ok(output) => Assert::new(output).append_context("command", format!("{cmd:?}")),
        Err(err) => panic!(
            "{}",
            explain_spawn_failure(Path::new(cmd.get_program()), &err, &read_self_status())
        ),
    }
}

/// This process's `/proc/self/status`, or an empty string when it cannot be read.
///
/// Only ever an input to [`explain_spawn_failure`], which is already reporting a failure — an
/// unreadable status must not replace the diagnosis with a second error.
fn read_self_status() -> String {
    std::fs::read_to_string("/proc/self/status").unwrap_or_default()
}

/// The double-wrap paragraph: the law, and the fix, for the reader who hits this next.
const DOUBLE_WRAP_EXPLANATION: &str = "\
The program above IS the blessed capability runner, so this is a SECOND wrap. Its file capabilities \
are `BLESSED_FILE_CAPS` = PRIVILEGED_CAPS + the transient CAP_SETPCAP, with the effective bit set; \
the FIRST wrap already shrank this process's bounding set to PRIVILEGED_CAPS, dropping CAP_SETPCAP \
out of it. execve computes pP' = (X & fP) | (pI & fI) and returns EPERM when the file's effective \
bit is set and fP is not a subset of the bounding set X (\"insufficient to execute correctly\", \
security/commoncap.c). No blessing, rebuild or KVM probe changes that: the second exec cannot \
succeed from inside the window the first one opened.
FIX: wrap exactly once. Spawn the child through `common::bench_vm()`, which resolves \
env!(\"CARGO_BIN_EXE_bench-vm\") and execs it directly — the caps arrive through the inherited \
ambient set. Never through assert_cmd's cargo-bin door, which prepends \
$CARGO_TARGET_<TRIPLET>_RUNNER (the very variable `just test-bench` sets to wrap this binary).\n";

/// Renders a child-spawn failure, naming the **cause** when the cause is the privilege window this
/// suite runs inside.
///
/// Pure: the process state arrives as `proc_status` text so every arm is unit-testable off a KVM
/// host and outside the privileged window (see the tests at the bottom of this file). A non-EPERM
/// failure gets no privilege story at all — a helper that blamed the window for a missing binary
/// would be worse than the bare errno it replaces.
pub fn explain_spawn_failure(program: &Path, err: &io::Error, proc_status: &str) -> String {
    let mut msg = format!("failed to spawn {}: {err}", program.display());
    if err.raw_os_error() != Some(libc::EPERM) {
        return msg;
    }
    msg.push_str(
        "\n\nEPERM at spawn is a PRIVILEGE-WINDOW failure, not the child's own permissions. \
         `just test-bench` wraps this test binary with the blessed runner (nextest's target-runner \
         hook), so this process is already inside the privilege transition:\n",
    );
    for key in ["NoNewPrivs", "CapBnd", "CapAmb", "CapEff"] {
        if let Some(rest) = proc_status
            .lines()
            .find_map(|l| l.strip_prefix(&format!("{key}:")))
        {
            msg.push_str(&format!("  {key} = {}\n", rest.trim()));
        }
    }
    if program.file_name() == Some(OsStr::new(RUNNER_FILE_NAME)) {
        msg.push_str(DOUBLE_WRAP_EXPLANATION);
    } else {
        msg.push_str(
            "The program above is not the blessed runner, so this is not the double wrap; look for \
             another privileged exec (a file-capability or set-uid binary cannot be exec'd from a \
             shrunk bounding set) or a mount that forbids execution.\n",
        );
    }
    msg
}

/// The `security.capability` value on `path`: `Some(bytes)` when the file carries file
/// capabilities, `None` when it carries none.
///
/// Panics on any errno other than `ENODATA`/`ENOATTR`, so a probe that has stopped working cannot
/// read as "no file capabilities" — which is the answer the assertions below treat as good news.
fn file_capabilities(path: &Path) -> Option<Vec<u8>> {
    let c_path = CString::new(path.as_os_str().as_encoded_bytes()).expect("NUL-free path");
    let name = c"security.capability";
    let mut buf = [0u8; 64];
    // SAFETY: `getxattr` writes at most `buf.len()` bytes into `buf`; both pointers are valid for
    // the duration of the call and the two C strings are NUL-terminated.
    let n = unsafe {
        libc::getxattr(
            c_path.as_ptr(),
            name.as_ptr(),
            buf.as_mut_ptr().cast::<libc::c_void>(),
            buf.len(),
        )
    };
    if n >= 0 {
        return Some(buf[..usize::try_from(n).expect("non-negative")].to_vec());
    }
    let err = io::Error::last_os_error();
    // ENODATA and ENOATTR are the same value on Linux; name both, since "the attribute is absent"
    // is the load-bearing answer.
    if err.raw_os_error() == Some(libc::ENODATA) {
        None
    } else {
        panic!(
            "the file-capability probe on {} failed with {err} — it must answer \
             present-or-absent, never fail open, because \"absent\" is the good news here",
            path.display()
        )
    }
}

/// The nextest target-runner this process was wrapped with: `(variable name, runner path)`.
///
/// Discovered by scanning for the `CARGO_TARGET_*_RUNNER` family rather than composing one triple's
/// spelling, because that family is exactly what `assert_cmd`'s cargo-bin door reads. `None` means
/// this suite is running unwrapped (`just test-unit`, a plain `cargo test`).
fn target_runner() -> Option<(String, PathBuf)> {
    std::env::vars()
        .find(|(k, _)| k.starts_with("CARGO_TARGET_") && k.ends_with("_RUNNER"))
        .map(|(k, v)| {
            let first = v.split(' ').next().unwrap_or(&v).to_owned();
            (k, PathBuf::from(first))
        })
}

/// A source file with its `//` comment lines removed, so prose that *names* a banned spelling is
/// never a hit. (`ban-ci-script-handcopy.sh`'s rule, applied one file over.)
fn code_only(src: &str) -> String {
    src.lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// A justfile with its comment lines removed, so a recipe's prose (or a commented-out line) is
/// neither a false positive nor a false negative.
fn without_comments(text: &str) -> String {
    text.lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n")
}

/// The `justfile` body of the recipe called `name`, or `None` when there is no such recipe.
///
/// A recipe header sits at column 0, is the recipe name followed by `:` or by its parameter list,
/// and ends the line with `:`; the body is every following indented (or blank) line. Deliberately a
/// tiny textual extractor rather than a call out to `just --show`: these tests run in
/// `just test-unit` / `cargo test`, where a `just` binary is not guaranteed to be on `PATH`, and the
/// properties asserted below are textual anyway. (`crates/vmcell/tests/systemd_cell.rs` carries a
/// sibling extractor for the same reason; that one predates parameterized recipes and cannot match
/// `test-bench`'s header, and it is another crate's test-private helper — see implementation-notes.)
fn justfile_recipe_body(justfile: &str, name: &str) -> Option<String> {
    let mut body: Vec<&str> = Vec::new();
    let mut found = false;
    for line in justfile.lines() {
        if found {
            if line.is_empty() || line.starts_with([' ', '\t']) {
                body.push(line);
                continue;
            }
            break;
        }
        let Some(after) = line.strip_prefix(name) else {
            continue;
        };
        if (after.starts_with(':') || after.starts_with(' ')) && line.trim_end().ends_with(':') {
            found = true;
        }
    }
    found.then(|| body.join("\n"))
}

// ---------------------------------------------------------------------------------------------
// The gates for the law this module's header states. All four are KVM-free and privilege-free, so
// they run in `just test-unit` / `just ci` — the invocations that had no way to see this defect.
// ---------------------------------------------------------------------------------------------

/// `assert_cmd`'s runner-honoring door, spelled in pieces so this gate's own source is not a hit.
const DOOR: &str = concat!("cargo_", "bin(\"bench-vm\")");

/// `assert_cmd`'s spawning assertion door (`OutputAssertExt`), likewise in pieces.
///
/// It spawns the child itself and panics with the bare errno — which is how the double wrap reached
/// CI unexplained. Every child in `benchmark.rs` goes through [`assert_bench_vm`] instead.
const SPAWN_DOOR: &str = concat!(".", "assert()");

/// The environment variable naming the `bench-vm` binary, spelled in pieces as above.
const BIN_EXE_VAR: &str = concat!("CARGO_BIN_EXE_", "bench-vm");

/// The one sanctioned resolver, in its **source** spelling.
///
/// Only a real `env!` call can match: inside a string literal the quotes would have to be escaped
/// (`env!(\"…\")`), so this needle passes over both the fix instruction in
/// [`DOUBLE_WRAP_EXPLANATION`] and the assertion needle below, which name the same variable as
/// prose. That is what a bare `CARGO_BIN_EXE_bench-vm` needle could not do — it counted three
/// "resolvers" in this file, two of which were sentences, and no state of the tree satisfied it.
const RESOLVER: &str = concat!("env!(\"CARGO_BIN_EXE_", "bench-vm\")");

/// The one composer, and the one spawn site, as they are called from `benchmark.rs`.
///
/// `bench_vm()` with empty parens matches only the composer call — `assert_bench_vm(&mut cmd)`
/// carries an argument, so the two needles do not overlap.
const COMPOSER_CALL: &str = concat!("bench_", "vm()");
/// See [`COMPOSER_CALL`].
const EXPLAINER_CALL: &str = concat!("assert_bench_", "vm(");

const BENCHMARK_SRC: &str = include_str!("../benchmark.rs");
const COMMON_SRC: &str = include_str!("mod.rs");

/// **The ban.** No test composes its child through `assert_cmd`'s cargo-bin door, and the binary
/// path has exactly one spelling: cargo's `CARGO_BIN_EXE_bench-vm`.
///
/// Not a compile error in either direction (the door compiles fine and only misbehaves when the
/// target-runner variable is set, i.e. only under `just test-bench`), so it is scanned. Comment
/// lines are stripped and both needles are assembled with `concat!`, so this file's own prose and
/// consts cannot satisfy the gate.
///
/// RED ON THE INVERSE: put `Command::cargo_bin("bench-vm")` back into any test in `benchmark.rs`
/// (arm 1), resolve the path there instead of going through [`bench_vm`] (arm 4), or spawn a child
/// with `assert_cmd`'s own `.assert()` instead of [`assert_bench_vm`] (arm 5).
#[test]
fn the_harness_never_re_wraps_bench_vm_in_the_target_runner() {
    // Non-vacuity for both `include_str!`s before anything is counted: an empty or wrong file would
    // otherwise satisfy every "must not appear" assertion by holding nothing at all.
    assert!(
        BENCHMARK_SRC.contains("fn test_benchmark_fc"),
        "the scan must be reading tests/benchmark.rs"
    );
    assert!(
        COMMON_SRC.contains("pub fn bench_vm()"),
        "the scan must be reading this file"
    );

    let benchmark = code_only(BENCHMARK_SRC);
    let common = code_only(COMMON_SRC);

    // 1. THE BAN.
    assert_eq!(
        benchmark.matches(DOOR).count(),
        0,
        "tests/benchmark.rs must not compose `bench-vm` through assert_cmd's cargo-bin door: it \
         prepends $CARGO_TARGET_<TRIPLET>_RUNNER, which `just test-bench` sets to wrap this very \
         test binary, so the child is wrapped a second time and execve returns EPERM. Use \
         `common::bench_vm()`."
    );
    // 2. The ban's needle is still live — the door exists and is still reachable from here.
    assert_eq!(
        common.matches(DOOR).count(),
        1,
        "the door may appear exactly once in this file — in \
         `the_child_is_spawned_directly_into_the_inherited_privilege_window`'s positive control, \
         which is what proves the ban above still names a live hazard"
    );
    // 3. One resolver, in one file. Counted in its source spelling (see `RESOLVER`), so the two
    //    sentences in this file that *name* the variable are not miscounted as resolvers.
    assert_eq!(
        common.matches(RESOLVER).count(),
        1,
        "the `bench-vm` path has one spelling, `BENCH_VM_BIN`'s env! — a second resolver is the \
         drift this ban exists for"
    );
    // 4. …and `benchmark.rs` holds neither a resolver nor the variable it would read.
    assert_eq!(
        benchmark.matches(BIN_EXE_VAR).count(),
        0,
        "tests/benchmark.rs resolves nothing itself; it goes through `common::bench_vm()`"
    );
    // 5. Every child is spawned through the ONE site that explains an EPERM. `assert_cmd`'s own
    //    `.assert()` spawns and panics with the bare errno — the shape that reached CI as five
    //    `Operation not permitted (os error 1)` lines naming no cause.
    assert_eq!(
        benchmark.matches(SPAWN_DOOR).count(),
        0,
        "tests/benchmark.rs must not spawn through assert_cmd's `.assert()`: it panics with the \
         bare errno. Use `common::assert_bench_vm(&mut cmd)`, which reports a spawn EPERM as the \
         privilege-window failure it is."
    );
    let composed = benchmark.matches(COMPOSER_CALL).count();
    assert!(
        composed > 0,
        "tests/benchmark.rs must compose its children through `common::bench_vm()`"
    );
    assert_eq!(
        composed,
        benchmark.matches(EXPLAINER_CALL).count(),
        "every composed `bench-vm` command must be run through `assert_bench_vm` — a new test that \
         spawns one some other way loses the EPERM diagnosis this file exists to provide"
    );
}

/// **The behavioural half.** The composed child is `bench-vm` itself, and — when this suite is
/// running wrapped, which is what `just test-bench` does — the door really would have re-wrapped it
/// and the child really can inherit the window.
///
/// The wrapped legs are the positive controls the scan above cannot supply: they measure
/// `assert_cmd`'s actual behaviour under this recipe's environment, and they measure the file
/// capabilities that make the double wrap fatal (on the runner) and the direct spawn work (on
/// `bench-vm`, whose ambient set survives execve only because it carries none).
///
/// RED ON THE INVERSE: make [`bench_vm`] compose the runner (arm 1 fails); `setcap` the `bench-vm`
/// binary, which would clear the ambient set at execve and silently unprivilege every live leg
/// (arm 4 fails).
#[test]
fn the_child_is_spawned_directly_into_the_inherited_privilege_window() {
    // 1. The composer execs the binary, not a wrapper.
    let cmd = bench_vm();
    assert_eq!(
        Path::new(cmd.get_program()),
        Path::new(BENCH_VM_BIN),
        "the one composer must exec `bench-vm` directly"
    );
    assert!(cmd.get_args().next().is_none(), "no wrapper argv in front");

    // 2. `bench-vm` carries no file capabilities and no set-id bits, which is the precondition for
    //    the ambient set to survive its execve (execve clears the ambient set for a file that is
    //    privileged in either sense). This is how the live legs get PRIVILEGED_CAPS.
    assert_eq!(
        file_capabilities(Path::new(BENCH_VM_BIN)),
        None,
        "`bench-vm` must carry no file capabilities: execve CLEARS the ambient set for a file that \
         has them, so the caps `just test-bench` delivers would silently stop arriving (and with \
         the effective bit set the exec would EPERM like the double wrap does)"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(BENCH_VM_BIN)
            .expect("stat bench-vm")
            .permissions()
            .mode();
        assert_eq!(
            mode & 0o6000,
            0,
            "`bench-vm` must not be set-uid/set-gid, for the same ambient-clearing reason"
        );
    }

    let Some((var, runner)) = target_runner() else {
        // Unwrapped (`just test-unit`, plain `cargo test`): there is no target runner to be
        // re-wrapped by, so legs 3 and 4 have nothing to measure. The ban above still holds
        // everywhere, and `just test-bench`'s own recipe is gated by
        // `the_test_bench_recipe_still_wraps_and_still_selects_the_ignored_legs`.
        println!(
            "no CARGO_TARGET_*_RUNNER in this environment: running unwrapped, so the \
             re-wrap control and the runner's file-capability control do not apply here \
             (they run under `just test-bench`)"
        );
        return;
    };

    // 3. THE POSITIVE CONTROL for the ban: assert_cmd's door, under this recipe's own environment,
    //    really does compose `<runner> <bin>`. If assert_cmd ever stopped reading this variable the
    //    ban's needle would be stale, and this leg says so instead of passing quietly.
    use assert_cmd::prelude::CommandCargoExt;
    let wrapped = Command::cargo_bin("bench-vm").expect("the cargo-built bench-vm must exist");
    assert_eq!(
        Path::new(wrapped.get_program()),
        runner,
        "assert_cmd's cargo-bin door must still compose ${var} in front of the binary — that is \
         the hazard the ban in this file exists for; if it no longer does, the ban is stale"
    );

    // 4. …and the runner it would have composed carries file capabilities, which is *why* that
    //    second execve returns EPERM from inside the already-shrunk bounding set. The positive
    //    control for the probe used in leg 2, too: it can see file caps when they are there.
    assert!(
        file_capabilities(&runner).is_some(),
        "the blessed runner at {} must carry file capabilities — without them the wrap that \
         delivers PRIVILEGED_CAPS to this test binary did nothing, and the probe in leg 2 has no \
         positive control",
        runner.display()
    );
}

/// **The recipe half** (docs/90 G2): `just test-bench` still wraps this binary and still selects
/// the `#[ignore = "needs KVM"]` legs, and CI still gets there by invoking the recipe.
///
/// Each needle has a silent failure behind it. Drop the runner export and the live legs still pass —
/// unprivileged: the cpufreq pin degrades to a logged no-op and the numbers quietly carry scaling
/// noise. Drop `--run-ignored all` (or narrow the filter) and the recipe goes green having selected
/// only the three dry legs, which is finding G2 re-opened: the composition root's can-it-go-red
/// proof compiled and skipped. Drop `--no-tests=fail` and a filter that selects nothing is green.
/// Delete the ci.yml step and all of it runs nowhere.
///
/// RED ON THE INVERSE: remove any one of the needles from the recipe body, or the `just test-bench`
/// call from ci.yml.
#[test]
fn the_test_bench_recipe_still_wraps_and_still_selects_the_ignored_legs() {
    const JUSTFILE: &str = include_str!("../../../../justfile");
    const CI_YML: &str = include_str!("../../../../.github/workflows/ci.yml");

    let body = justfile_recipe_body(JUSTFILE, "test-bench").unwrap_or_else(|| {
        panic!(
            "the justfile must carry a `test-bench` recipe: it is the only invocation in the tree \
             that selects vmcell-bench's live legs (docs/90 G2)"
        )
    });
    let body = without_comments(&body);
    assert!(
        body.contains("cargo nextest run"),
        "the extractor must have found the recipe's real body, not an empty one:\n{body}"
    );

    for (needle, why) in [
        (
            "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER",
            "the wrap that delivers PRIVILEGED_CAPS to this binary (and, through the ambient set, \
             to bench-vm); without it the cpufreq pin is a logged no-op and nothing goes red",
        ),
        (
            "--run-ignored all",
            "the three `#[ignore = \"needs KVM\"]` legs are the entire point of this recipe \
             (docs/90 G2)",
        ),
        (
            "--no-tests=fail",
            "a filter that selects zero tests must be an error, not a green run",
        ),
        ("-p vmcell-bench", "the package that owns those legs"),
        ("binary(benchmark)", "the binary that holds them"),
        (
            "VMCELL_SKIP_MANIFEST",
            "run-scoped skips, like every sibling live-suite recipe (H-TEST-3)",
        ),
    ] {
        assert!(
            body.contains(needle),
            "`just test-bench` must carry {needle:?} — {why}. Recipe body:\n{body}"
        );
    }

    assert!(
        without_comments(CI_YML).contains("just test-bench"),
        ".github/workflows/ci.yml must invoke the `test-bench` recipe (AGENTS rule 3: the recipe, \
         never a hand-copied cargo line). Without that step the live legs run nowhere, which is \
         docs/90 G2 re-opened."
    );
}

/// **The diagnosis gate.** A spawn EPERM is reported as the privilege transition it is, and nothing
/// else is.
///
/// This is the readability half of the fix: the double wrap reached CI as five identical
/// `Operation not permitted (os error 1)` panics that named neither the bounding set nor the
/// runner, and the next reader of an EPERM here should get the cause instead of an errno.
///
/// RED ON THE INVERSE: return the bare error from [`explain_spawn_failure`] (arm 1), key the
/// double-wrap paragraph off something other than the program being the runner (arm 2), or blame
/// the window for every failure (arm 3, the cry-wolf inverse).
#[test]
fn a_spawn_eperm_is_reported_as_the_privilege_transition_it_is() {
    // The shape the CI failure actually had: wrapped once, bounding set already shrunk to the three
    // delivered caps (0x201002 = DAC_OVERRIDE|NET_ADMIN|SYS_ADMIN), CAP_SETPCAP no longer in it.
    const STATUS: &str = "Name:\tbenchmark\nNoNewPrivs:\t0\nCapBnd:\t0000000000201002\n\
                          CapAmb:\t0000000000201002\nCapEff:\t0000000000201002\n";
    let eperm = io::Error::from_raw_os_error(libc::EPERM);

    // 1. Through the runner: the double-wrap story, with the measured window in it.
    let msg = explain_spawn_failure(
        Path::new("/w/.vmcell-bin/debug/vmcell-test-runner"),
        &eperm,
        STATUS,
    );
    for needle in [
        "PRIVILEGE-WINDOW",
        "CapBnd = 0000000000201002",
        "CapAmb = 0000000000201002",
        "SECOND wrap",
        "CAP_SETPCAP",
        "pP' = (X & fP)",
        "wrap exactly once",
        "CARGO_BIN_EXE_bench-vm",
    ] {
        assert!(
            msg.contains(needle),
            "the EPERM diagnosis must name {needle:?} — it is what the reader needs and the bare \
             errno does not carry. Got:\n{msg}"
        );
    }

    // 2. EPERM on some OTHER program: still the window (it is the likely cause), but explicitly not
    //    the double wrap. Non-vacuity for the runner-detection branch — without this leg arm 1
    //    would pass on an explainer that told the same story about everything.
    let other = explain_spawn_failure(Path::new("/w/target/debug/bench-vm"), &eperm, STATUS);
    assert!(other.contains("CapBnd = 0000000000201002"));
    assert!(
        other.contains("not the blessed runner") && !other.contains("SECOND wrap"),
        "an EPERM on a non-runner program must not be reported as the double wrap. Got:\n{other}"
    );

    // 3. THE CRY-WOLF INVERSE: a missing binary is not a privilege problem, and a helper that said
    //    it was would send the next reader down this same wrong path.
    let enoent = explain_spawn_failure(
        Path::new("/w/.vmcell-bin/debug/vmcell-test-runner"),
        &io::Error::from_raw_os_error(libc::ENOENT),
        STATUS,
    );
    assert!(
        !enoent.to_lowercase().contains("privilege") && !enoent.contains("CapBnd"),
        "a non-EPERM spawn failure must get no privilege story. Got:\n{enoent}"
    );
    assert!(
        enoent.contains("vmcell-test-runner"),
        "…but it must still name the program it failed to spawn. Got:\n{enoent}"
    );
}
