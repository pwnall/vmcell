//! Jailer-equivalent hardening gate (design §20.4 / invariant §12.22).
//!
//! These are the **non-theater** gates for Layer 2: they exercise the real pre-exec syscalls
//! (`build_vmm_cmd`'s `apply_jail`) and go **red on the inverse** — with neither KVM nor root,
//! so they run in `just test-unit`. `no_new_privs`, lowering `RLIMIT_CORE`, and a default-allow
//! seccomp deny-list are all unprivileged, so a stand-in child (`cat /proc/self/{status,limits}`
//! or a forked child issuing one syscall) proves the mechanism without a VMM.

use std::process::Stdio;
use std::sync::Arc;
use vmcell::config::JailConfig;
use vmcell::vmm::build_vmm_cmd;
use vmcell::vmm::jail::{JailSpec, apply_jail, build_vmm_deny_filter, jail_spec_from_config};

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

// Guards §12.22: `apply_jail` sets PR_SET_NO_NEW_PRIVS and installs RLIMIT_CORE on the
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

// Guards §12.22 (the seccomp deny-list, §20.4): the compiled deny-list, applied to a forked
// child, turns a normally-succeeding no-op `unshare(0)` into EPERM, while leaving an allowed
// syscall (`getpid`) working. The INVERSE (no filter) lets `unshare(0)` succeed — proving the
// gate fails on the inverse. Root-free (unprivileged no-op unshare + a default-allow filter),
// KVM-free. Fork is safe here: the child does only async-signal-safe work (`apply_jail`, one
// raw syscall, `_exit`) — no allocation, no libc lock — and the filter is compiled pre-fork.
#[test]
fn seccomp_deny_list_turns_unshare_into_eperm_via_fork() {
    // Child exit codes: 10 = unshare allowed, 11 = unshare EPERM, 12 = unshare other-errno,
    // 13 = the allowed getpid was (wrongly) blocked, 20 = apply_jail itself failed.
    fn run_child(spec: &JailSpec) -> i32 {
        // SAFETY: fork in a test; the child path below is async-signal-safe (apply_jail is
        // raw prctl/setrlimit/seccomp on already-allocated inputs, then one raw syscall and
        // _exit) — no allocation, no non-reentrant libc, so no post-fork lock hazard.
        match unsafe { libc::fork() } {
            -1 => panic!("fork failed: {}", std::io::Error::last_os_error()),
            0 => {
                let code = match apply_jail(spec) {
                    Ok(()) => {
                        // getpid must still work (an allowed syscall).
                        // SAFETY: getpid takes no args and cannot fail.
                        let pid = unsafe { libc::syscall(libc::SYS_getpid) };
                        if pid <= 0 {
                            13
                        } else {
                            // SAFETY: unshare(0) is a no-op; the deny-list turns it into EPERM.
                            let r = unsafe { libc::syscall(libc::SYS_unshare, 0) };
                            if r == 0 {
                                10
                            } else {
                                // SAFETY: read thread-local errno; async-signal-safe.
                                let e = unsafe { *libc::__errno_location() };
                                if e == libc::EPERM { 11 } else { 12 }
                            }
                        }
                    }
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

    // With the deny-list: unshare(0) -> EPERM (11), getpid still fine.
    let filter = build_vmm_deny_filter().expect("deny-list must compile");
    let denied = JailSpec {
        seccomp: Some(Arc::new(filter)),
        ..JailSpec::default()
    };
    assert_eq!(
        run_child(&denied),
        11,
        "the seccomp deny-list must turn unshare(0) into EPERM (getpid still allowed)"
    );

    // The inverse: no filter -> unshare(0) succeeds (10). Proves the gate can fail.
    let allowed = JailSpec::default();
    assert_eq!(
        run_child(&allowed),
        10,
        "without the deny-list, unshare(0) must succeed — the gate must be able to fail"
    );
}
