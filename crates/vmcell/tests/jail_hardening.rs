//! Jailer-equivalent hardening gate (design §12.3, Layer 2 — the jailer-equivalent (JailSpec + apply_jail) / invariant §13, Cross-cutting invariants).
//!
//! These are the **non-theater** gates for Layer 2: they exercise the real pre-exec syscalls
//! (`build_vmm_cmd`'s `apply_jail`) and go **red on the inverse** — with neither KVM nor root,
//! so they run in `just test-unit`. `no_new_privs`, lowering `RLIMIT_CORE`, clearing
//! `PR_SET_DUMPABLE`, and a default-allow seccomp deny-list are all unprivileged, so a stand-in
//! child (`cat /proc/self/{status,limits}` or a forked child issuing one syscall) proves the
//! mechanism without a VMM.
//!
//! The one exception is `clear_ambient_caps`: an unprivileged process has an EMPTY ambient set,
//! so "the child's ambient set is empty" would pass against a `apply_jail` that did nothing.
//! That leg is therefore `#[ignore]`d and runs in the privileged suite, where the blessed runner
//! has raised `CAP_NET_ADMIN` into the ambient set (§11.2) and the assertion has teeth
//! (docs/78 `jail-gate-narrower-than-design-claims`).

use std::process::Stdio;
use std::sync::Arc;
use vmcell::config::JailConfig;
use vmcell::vmm::build_vmm_cmd;
use vmcell::vmm::jail::{JailSpec, apply_jail, build_vmm_deny_filter, jail_spec_from_config};

/// `CAP_NET_ADMIN` from `<linux/capability.h>`. The `libc` crate exports no `CAP_*` numbers and
/// `capctl` is not a `vmcell` dependency, so the one cap the blessed runner is guaranteed to
/// have raised into the ambient set (§11.2: `cap_net_admin,cap_sys_admin,cap_dac_override`) is
/// named here.
const CAP_NET_ADMIN: libc::c_int = 12;

/// Spawns `cat /proc/self/status /proc/self/limits` through `build_vmm_cmd` with `jail`
/// applied (no netns, so no caps are needed) and returns the child's stdout.
async fn spawn_stand_in_and_read_proc(jail: &JailSpec) -> String {
    let mut cmd = build_vmm_cmd(std::path::Path::new("/bin/cat"), None, jail);
    let out = cmd
        .arg("/proc/self/status")
        .arg("/proc/self/limits")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .await
        .expect("spawn stand-in /bin/cat through the jail");
    assert!(
        out.status.success(),
        "stand-in cat failed: {:?}",
        out.status
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// Extracts the soft `RLIMIT_CORE` value ("Max core file size") from `/proc/self/limits`
/// text: the 5th whitespace token of that line (`Max core file size <soft> <hard> bytes`).
fn core_soft_limit(limits: &str) -> Option<String> {
    limits
        .lines()
        .find(|l| l.starts_with("Max core file size"))
        .and_then(|l| l.split_whitespace().nth(4).map(str::to_string))
}

/// Forks, applies `spec` in the child, runs `probe` there, and `_exit`s with the probe's code;
/// returns the child's exit code. One helper for every probe-in-a-jailed-child leg (seccomp,
/// dumpable, ambient) — never a second copy of the fork dance.
///
/// Fork is safe here: the child does only async-signal-safe work (`apply_jail` is raw
/// prctl/setrlimit/seccomp on already-allocated inputs — including its error path, which
/// returns a bare errno — then the probe's raw syscalls and `_exit`), so there is no allocation
/// and no non-reentrant libc between `fork` and `_exit`, hence no post-fork lock hazard. Any
/// seccomp filter is compiled pre-fork. Reserved exit code: **20** = `apply_jail` itself failed.
fn fork_probe(spec: &JailSpec, probe: fn() -> i32) -> i32 {
    // SAFETY: fork in a test; the child path below is async-signal-safe (see the doc above).
    match unsafe { libc::fork() } {
        -1 => panic!("fork failed: {}", std::io::Error::last_os_error()),
        0 => {
            let code = match apply_jail(spec) {
                Ok(()) => probe(),
                Err(_) => 20,
            };
            // SAFETY: _exit is async-signal-safe and skips at-exit handlers (correct post-fork).
            unsafe { libc::_exit(code) };
        }
        pid => {
            let mut status: libc::c_int = 0;
            // SAFETY: waitpid on our own child pid with a valid status out-pointer.
            unsafe { libc::waitpid(pid, &mut status, 0) };
            assert!(libc::WIFEXITED(status), "child did not exit normally");
            libc::WEXITSTATUS(status)
        }
    }
}

/// Child probe for the deny-list leg: 10 = `unshare(0)` allowed, 11 = `unshare(0)` EPERM,
/// 12 = `unshare(0)` failed with another errno, 13 = the ALLOWED `getpid` was wrongly blocked.
fn probe_unshare_and_getpid() -> i32 {
    // getpid must still work (an allowed syscall).
    // SAFETY: getpid takes no args and cannot fail.
    let pid = unsafe { libc::syscall(libc::SYS_getpid) };
    if pid <= 0 {
        return 13;
    }
    // SAFETY: unshare(0) is a no-op; the deny-list turns it into EPERM.
    let r = unsafe { libc::syscall(libc::SYS_unshare, 0) };
    if r == 0 {
        return 10;
    }
    // SAFETY: read thread-local errno; async-signal-safe.
    let e = unsafe { *libc::__errno_location() };
    if e == libc::EPERM { 11 } else { 12 }
}

/// Child probe for the dumpable leg: the `PR_GET_DUMPABLE` value (0 = not dumpable, 1 = the
/// ordinary `SUID_DUMP_USER`), or 21 if the prctl itself errored.
///
/// `/proc/<pid>/status` has **no** `Dumpable` field (docs/78
/// `jail-gate-narrower-than-design-claims`), so the `cat` stand-in structurally cannot see this
/// flag — `prctl(PR_GET_DUMPABLE)` in the jailed child is the only read route.
fn probe_dumpable() -> i32 {
    // SAFETY: `prctl(PR_GET_DUMPABLE)` takes no pointer args; async-signal-safe.
    let d = unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) };
    if d < 0 { 21 } else { d }
}

/// Child probe for the ambient leg: 1 if `CAP_NET_ADMIN` is still in the ambient set, 0 if not,
/// 22 if the prctl errored.
fn probe_ambient_net_admin() -> i32 {
    // SAFETY: `prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET, cap, …)` takes no pointer args;
    // async-signal-safe.
    let r = unsafe {
        libc::prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_IS_SET,
            CAP_NET_ADMIN,
            0,
            0,
        )
    };
    if r < 0 { 22 } else { r }
}

// Guards §13 (Cross-cutting invariants): `apply_jail` sets PR_SET_NO_NEW_PRIVS and installs RLIMIT_CORE on the
// spawned child, and the INVERSE (a disabled jail) leaves both untouched — so deleting the
// prctl or the setrlimit in `apply_jail` reddens this. Root-free, KVM-free.
//
// The rlimit discriminator RAISES the soft core limit to a nonzero value rather than checking
// the hardened `=0`, because a CI host's ambient soft RLIMIT_CORE is often already 0 (so `=0`
// would pass trivially, testing nothing). A child seeing exactly `4096` can only come from
// `apply_jail` having called `setrlimit(RLIMIT_CORE, 4096)`.
#[tokio::test]
async fn apply_jail_sets_no_new_privs_and_the_core_rlimit() {
    // Hardened jail => NoNewPrivs=1.
    let hardened = jail_spec_from_config(&JailConfig::hardened()).expect("hardened spec");
    let proc = spawn_stand_in_and_read_proc(&hardened).await;
    assert!(
        proc.contains("NoNewPrivs:\t1"),
        "hardened jail must set NoNewPrivs=1 on the child; got:\n{proc}"
    );

    // Disabled jail => NoNewPrivs=0 (proving the NoNewPrivs assertion can fail).
    let disabled = jail_spec_from_config(&JailConfig::disabled()).expect("disabled spec");
    let proc = spawn_stand_in_and_read_proc(&disabled).await;
    assert!(
        proc.contains("NoNewPrivs:\t0"),
        "the disabled jail must leave NoNewPrivs=0 (the gate must be able to fail); got:\n{proc}"
    );

    // A jail that RAISES RLIMIT_CORE to 4096 => the child's soft core limit is exactly 4096.
    let raise_core = JailSpec {
        rlimit_core: Some(4096),
        ..JailSpec::default()
    };
    let proc = spawn_stand_in_and_read_proc(&raise_core).await;
    assert_eq!(
        core_soft_limit(&proc).as_deref(),
        Some("4096"),
        "apply_jail must set RLIMIT_CORE to the requested value; got:\n{proc}"
    );

    // The inverse: no rlimit_core => the child keeps the inherited soft limit, NOT 4096.
    let no_rlimit = JailSpec::default();
    let proc = spawn_stand_in_and_read_proc(&no_rlimit).await;
    assert_ne!(
        core_soft_limit(&proc).as_deref(),
        Some("4096"),
        "without rlimit_core, apply_jail must NOT set the core limit (the gate must be able to fail); got:\n{proc}"
    );
}

// Guards §13 (Cross-cutting invariants) / §12.3 (Layer 2 — the jailer-equivalent): `apply_jail`
// actually clears PR_SET_DUMPABLE (no core dump of guest RAM, no ptrace-attach by same-uid
// processes via the /proc ownership change), and the INVERSE (a spec with `non_dumpable` off)
// leaves the child dumpable — so deleting the prctl in `apply_jail` reddens here. Root-free,
// KVM-free. This is the leg §12.3's "asserts the post-apply capability/no_new_privs/DUMPABLE
// state" sentence claimed and the suite did not have (docs/78
// `jail-gate-narrower-than-design-claims`).
#[test]
fn apply_jail_clears_dumpable_and_the_inverse_leaves_it_set() {
    // Normalize this process's own dumpable flag to 1 first, so the inverse leg is deterministic
    // even under a launcher that left it cleared (an exec that RAISES privileges — a file-cap or
    // setuid binary — clears it, and the blessed runner is exactly that shape). 1 is the ordinary
    // value for an unprivileged process, so this is a no-op on a normal host and only removes an
    // environmental confound; the flag is inherited across `fork`, which is what the legs read.
    // SAFETY: `prctl(PR_SET_DUMPABLE, 1)` takes no pointer args and only affects this process.
    assert_eq!(
        unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 1, 0, 0, 0) },
        0,
        "PR_SET_DUMPABLE=1 must succeed: {}",
        std::io::Error::last_os_error()
    );

    let non_dumpable = JailSpec {
        non_dumpable: true,
        ..JailSpec::default()
    };
    assert_eq!(
        fork_probe(&non_dumpable, probe_dumpable),
        0,
        "non_dumpable=true must leave the child with PR_GET_DUMPABLE == 0"
    );

    // The inverse: non_dumpable off => the child keeps the inherited dumpable=1.
    assert_eq!(
        fork_probe(&JailSpec::default(), probe_dumpable),
        1,
        "without non_dumpable, apply_jail must NOT clear PR_SET_DUMPABLE (the gate must be able to fail)"
    );

    // And the shipped hardened config is on the clearing side (JailConfig::hardened() sets it).
    let hardened = jail_spec_from_config(&JailConfig::hardened()).expect("hardened spec");
    assert_eq!(
        fork_probe(&hardened, probe_dumpable),
        0,
        "JailConfig::hardened() must produce a non-dumpable VMM child"
    );
}

// Guards §13 (Cross-cutting invariants) / §12.3: `apply_jail` really empties the AMBIENT
// capability set when asked, and the INVERSE (the shipped `clear_ambient_caps = false` default,
// Appendix A reversal 9 — the VMM needs the inherited CAP_NET_ADMIN for tap ioctls) really
// leaves it intact. PRIVILEGED-ONLY and therefore `#[ignore]`d: an unprivileged process has an
// empty ambient set, so both legs would read 0 and a no-op `apply_jail` would pass. Under the
// blessed runner (`just test-privileged`, whose filter selects this binary) the process holds
// CAP_NET_ADMIN in ambient (§11.2), which the precondition below asserts rather than assumes —
// a green run here is real evidence, and a run without the runner fails loud instead of
// pretending. No KVM is needed, only the caps.
#[test]
#[ignore = "needs the blessed runner's ambient capability set (privileged suite)"]
fn apply_jail_clears_the_ambient_capability_set() {
    // Precondition (fail loud, never skip): this process must actually hold an ambient cap, or
    // the legs below are vacuous.
    assert_eq!(
        probe_ambient_net_admin(),
        1,
        "this leg needs CAP_NET_ADMIN in the AMBIENT set — run it through the blessed runner \
         (`just bless` + `just test-privileged`); without it the assertions would be vacuous"
    );

    let clearing = JailSpec {
        clear_ambient_caps: true,
        ..JailSpec::default()
    };
    assert_eq!(
        fork_probe(&clearing, probe_ambient_net_admin),
        0,
        "clear_ambient_caps=true must empty the child's ambient set"
    );

    // The inverse — and the SHIPPED default: the ambient cap survives into the VMM child, which
    // is what the privileged tap path depends on (Appendix A reversal 9).
    let hardened = jail_spec_from_config(&JailConfig::hardened()).expect("hardened spec");
    assert!(
        !hardened.clear_ambient_caps,
        "the shipped hardened jail must keep clear_ambient_caps off (Appendix A reversal 9)"
    );
    assert_eq!(
        fork_probe(&hardened, probe_ambient_net_admin),
        1,
        "with clear_ambient_caps off, apply_jail must NOT clear the ambient set (the gate must \
         be able to fail)"
    );
}

// Guards §13 (Cross-cutting invariants) (the seccomp deny-list, §12.3, Layer 2 — the jailer-equivalent (JailSpec + apply_jail)): the compiled deny-list, applied to a forked
// child, turns a normally-succeeding no-op `unshare(0)` into EPERM, while leaving an allowed
// syscall (`getpid`) working. The INVERSE (no filter) lets `unshare(0)` succeed — proving the
// gate fails on the inverse. Root-free (unprivileged no-op unshare + a default-allow filter),
// KVM-free.
#[test]
fn seccomp_deny_list_turns_unshare_into_eperm_via_fork() {
    // With the deny-list: unshare(0) -> EPERM (11), getpid still fine.
    let filter = build_vmm_deny_filter().expect("deny-list must compile");
    let denied = JailSpec {
        seccomp: Some(Arc::new(filter)),
        ..JailSpec::default()
    };
    assert_eq!(
        fork_probe(&denied, probe_unshare_and_getpid),
        11,
        "the seccomp deny-list must turn unshare(0) into EPERM (getpid still allowed)"
    );

    // The inverse: no filter -> unshare(0) succeeds (10). Proves the gate can fail.
    let allowed = JailSpec::default();
    assert_eq!(
        fork_probe(&allowed, probe_unshare_and_getpid),
        10,
        "without the deny-list, unshare(0) must succeed — the gate must be able to fail"
    );
}

/// Parses `/proc/<pid>/status`'s `SigIgn:` line — a 64-bit hex mask whose bit `n-1` is set when
/// signal `n` is ignored.
fn sig_ign_mask(status: &str) -> Option<u64> {
    status
        .lines()
        .find_map(|l| l.strip_prefix("SigIgn:"))
        .and_then(|v| u64::from_str_radix(v.trim(), 16).ok())
}

// docs/78 M9's second half. `vmcelld`'s cap-holding broker child sets SIGINT/SIGTERM to `SIG_IGN`
// so a terminal Ctrl-C cannot kill it before its ordered teardown runs — and an IGNORED
// disposition SURVIVES `execve`, so without a reset every VMM that child spawns would inherit it
// and stop responding to an operator's `kill`. `build_vmm_cmd`'s `pre_exec` resets both to
// `SIG_DFL` for exactly that reason.
//
// The daemon suite cannot observe this: cloud-hypervisor RE-ARMS its own INT/TERM handlers at
// start-up (measured `SigIgn: 0x4` under a parent ignoring both), so an assertion there would be
// vacuous. This is the committed gate the notes ledger recorded as missing — KVM-free and
// root-free, because the stand-in child is `/bin/cat`, which installs no handlers of its own.
//
// Red on the inverse: delete either `libc::signal(…, SIG_DFL)` from `build_vmm_cmd`'s closure and
// the corresponding bit is still set in the child's mask. The parent-side precondition is the
// positive control — it proves the mask really was inherited-ignorable, so a green result cannot
// come from the parent having never ignored the signals.
#[tokio::test]
async fn build_vmm_cmd_resets_inherited_ignored_signals_for_the_vmm_child() {
    const SIGINT_BIT: u64 = 1 << (libc::SIGINT as u64 - 1);
    const SIGTERM_BIT: u64 = 1 << (libc::SIGTERM as u64 - 1);

    // SAFETY: `signal(2)` with `SIG_IGN` on a valid signal number. nextest runs each test in its
    // own process, so this disposition is not shared with another test; it is restored below.
    let prev_int = unsafe { libc::signal(libc::SIGINT, libc::SIG_IGN) };
    // SAFETY: as above, for SIGTERM.
    let prev_term = unsafe { libc::signal(libc::SIGTERM, libc::SIG_IGN) };

    let parent = std::fs::read_to_string("/proc/self/status").expect("read own status");
    let parent_mask = sig_ign_mask(&parent).expect("parent SigIgn");
    assert_eq!(
        parent_mask & (SIGINT_BIT | SIGTERM_BIT),
        SIGINT_BIT | SIGTERM_BIT,
        "positive control: this process must actually be ignoring INT+TERM, or the child \
         assertion below proves nothing"
    );

    let status = spawn_stand_in_and_read_proc(&JailSpec::default()).await;

    // SAFETY: restore the dispositions captured above; valid signal numbers and handlers.
    unsafe { libc::signal(libc::SIGINT, prev_int) };
    // SAFETY: as above, for SIGTERM.
    unsafe { libc::signal(libc::SIGTERM, prev_term) };

    let child_mask = sig_ign_mask(&status).expect("child SigIgn");
    assert_eq!(
        child_mask & (SIGINT_BIT | SIGTERM_BIT),
        0,
        "a VMM spawned through build_vmm_cmd must NOT inherit an ignored INT/TERM \
         (child SigIgn {child_mask:#018x}); an operator's kill would be a no-op"
    );
}
