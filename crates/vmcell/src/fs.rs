//! Filesystem and storage management.
//!
//! Provides the virtiofs daemon implementation for sharing host directories with the VM.

// Removed forbid(unsafe_code) to allow pre_exec for pgid

use crate::config::{Access, Share};
use std::path::{Path, PathBuf};
#[cfg(not(feature = "experiment-fuse"))]
use std::process::Stdio;
#[cfg(not(feature = "experiment-fuse"))]
use tokio::process::Command;

#[cfg(feature = "experiment-fuse")]
mod in_process;

/// An advisory `flock(LOCK_EX)` held for the lifetime of the value (nix's safe RAII `Flock`, which
/// unlocks on drop, and on process death — so a crashed holder never wedges the next one).
///
/// **The one cross-process file lock.** Two places need to serialize writers that share an
/// artifacts directory, and both must agree on the mechanism or neither is safe:
///   * `artifact::ensure_test_artifacts` on `<dir>/.build.lock`, so concurrent test runs never
///     double-write the rootfs;
///   * `proxy::tls::CaManager::new_in` on `<dir>/.ca.lock`, because the CA is published as TWO
///     renames and a concurrent reader that looks between them sees a half-present pair.
///
/// It lives here rather than in either caller because the second copy is what drifts. `fs` is the
/// natural home: it is gated on `host-common`, which is exactly the feature set that brings in
/// `nix`, so both callers can reach it without widening anyone's dependencies.
pub(crate) struct FileLock(
    #[expect(dead_code, reason = "held only for its Drop, which releases the flock")]
    nix::fcntl::Flock<std::fs::File>,
);

impl FileLock {
    /// Creates `path` if absent and blocks until the exclusive lock is held.
    ///
    /// `truncate(false)` deliberately: the file is a pure lock token, never read, and truncating it
    /// would be a write the lock is supposed to be protecting.
    ///
    /// # Errors
    /// [`crate::error::Error::Io`] if the lock file cannot be opened or locked.
    pub(crate) fn acquire(path: &Path) -> crate::error::Result<Self> {
        let f = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(path)
            .map_err(crate::error::Error::Io)?;
        let locked = nix::fcntl::Flock::lock(f, nix::fcntl::FlockArg::LockExclusive)
            .map_err(|(_, e)| crate::error::Error::Io(std::io::Error::from(e)))?;
        Ok(Self(locked))
    }
}

/// A running virtiofs daemon instance.
#[derive(Debug)]
#[non_exhaustive]
pub struct VirtioFsDaemon {
    /// The path to the vhost-user socket.
    pub socket_path: PathBuf,
    /// The spawned `virtiofsd` child, **held** (never dropped early) so its
    /// pid/pgid cannot be recycled before `Drop` force-kills and reaps the whole
    /// process group. `Drop` reads the pgid from this live handle
    /// (`process.id()`), never a stale stored id: a dropped `tokio::process::Child`
    /// is orphan-reaped on `SIGCHLD`, which would free the pid for reuse and let
    /// `Drop` signal an unrelated process group (H-HOST-1 pid-reuse hazard). This
    /// matches the CH backend's "hold the Child, gate on `process.id()`" pattern.
    #[cfg(not(feature = "experiment-fuse"))]
    process: Option<tokio::process::Child>,
    #[cfg(feature = "experiment-fuse")]
    handle: Option<std::thread::JoinHandle<()>>,
    #[cfg(feature = "experiment-fuse")]
    kill_notifier: Option<vmm_sys_util::event::EventNotifier>,
}

impl VirtioFsDaemon {
    /// Starts a virtiofs daemon (using the standalone `virtiofsd` binary) for the given share,
    /// pacing its socket-readiness wait with `timeouts.api_socket_poll` (§9.4).
    ///
    /// **The one entry point.** §9.4 makes `api_socket_poll` pace *every* daemon readiness wait,
    /// so a second, shorter entry point that can only supply the default cadence *is* the
    /// divergence "one law, one predicate" forbids: a caller reaching for it would silently re-pin
    /// virtiofsd's wait to the default profile under `low_latency()` or `throughput()` (finding
    /// `virtiofsd-socket-wait-hardcoded-cadence`). Such a shim — `start(share, vm_tmp)`, deprecated
    /// since 0.13.0 — did sit here, kept alive only because removing a `pub fn` is a `vmcell` API
    /// break that belongs to a ledgered version bump rather than to a defect fix; it was deleted on
    /// the 0.22 → 0.23 edge (see that crate's contract ledger, and §10.4). Callers that want the
    /// default cadence pass `&Timeouts::default()` explicitly, which is a visible choice rather
    /// than an invisible one. `virtiofsd_declares_exactly_one_start_entry_point` is what keeps the
    /// twin from growing back, since nothing about a second `pub async fn` is a compile error.
    ///
    /// # Errors
    /// Returns an error if the daemon fails to spawn or create the socket.
    #[cfg(not(feature = "experiment-fuse"))]
    pub async fn start_paced(
        share: &Share,
        vm_tmp: &Path,
        timeouts: &crate::config::Timeouts,
    ) -> crate::error::Result<Self> {
        let socket_path = vm_tmp.join(format!("{}.sock", share.tag));

        let cache_arg = match share.cache {
            crate::config::CachePolicy::Never => "--cache=never",
            crate::config::CachePolicy::Auto => "--cache=auto",
            crate::config::CachePolicy::Always => "--cache=always",
        };

        let mut cmd = Command::new("virtiofsd");
        cmd.arg("--socket-path")
            .arg(&socket_path)
            .arg("--shared-dir")
            .arg(&share.host_path)
            .arg(cache_arg)
            .arg("--sandbox=namespace");

        if let Access::ReadOnly = share.access {
            cmd.arg("--readonly");
        }

        #[cfg(unix)]
        {
            // Decide whether to drop privileges for virtiofsd. The real confinement
            // boundary for the share is `--sandbox=namespace` plus `--readonly` for
            // RO shares (both applied above); a uid drop is defense-in-depth on top.
            //
            // A dedicated, per-share low-privilege service uid (allocated from a
            // reserved range alongside the CID/VMID) would be strictly better — a
            // daemon could then reach only its one directory. That allocator is not
            // yet wired up, so we drop to the invoking user (`SUDO_UID`) when we
            // have one and otherwise keep privileges under `--sandbox=namespace`.
            // We deliberately do NOT fall back to `nobody`, whose inability to read
            // a root-owned share would turn this hardening into an `EACCES` failure;
            // that deviation is logged in `implementation-notes.md`.
            match decide_virtiofsd_uid(
                nix::unistd::getuid().as_raw() == 0,
                std::env::var("SUDO_UID")
                    .ok()
                    .and_then(|s| s.parse::<u32>().ok()),
            ) {
                VirtiofsdUid::DropTo(uid) => {
                    cmd.uid(uid);
                }
                VirtiofsdUid::SandboxOnly => {
                    // Running as root with no invoking user to drop to and no
                    // dedicated service uid. We do NOT fall back to `nobody`
                    // (65534): nobody cannot read a root-owned share, so the daemon
                    // would `EACCES` — a uid hardening turning into a functional
                    // failure. Rely on `--sandbox=namespace` and make the gap loud.
                    tracing::warn!(
                        "virtiofsd: running as root with no usable SUDO_UID and no \
                         dedicated service uid; relying on --sandbox=namespace \
                         confinement instead of an EACCES-prone nobody drop"
                    );
                }
                VirtiofsdUid::InheritUnprivileged => {}
            }
            // Captured before the fork so the child can tell whether we are still its parent by
            // the time it arms `PR_SET_PDEATHSIG` (see `helper_daemon_pre_exec`).
            let spawning_parent = libc::pid_t::try_from(std::process::id()).unwrap_or(-1);
            // SAFETY: `pre_exec` runs the closure in the forked child before `execve`, so its body
            // must be async-signal-safe and non-allocating; it only calls
            // `helper_daemon_pre_exec`, which proves both at its definition, on a captured scalar.
            unsafe {
                cmd.pre_exec(move || helper_daemon_pre_exec(spawning_parent));
            }
        }

        // METRICS-FS-5: redirect stderr to a per-VM log file rather than an
        // `Stdio::piped()` pipe. On the success path the `Child` is dropped (only the
        // pgid is retained), so a captured-but-undrained pipe would wedge a chatty
        // daemon once the pipe buffer fills. A file is always drainable and still gives
        // us the daemon's diagnostics, which we read back on the failure paths below.
        let stderr_log_path = vm_tmp.join(format!("{}-virtiofsd.log", share.tag));
        let stderr_file = std::fs::File::create(&stderr_log_path).map_err(|e| {
            crate::error::Error::Subprocess(format!(
                "failed to create virtiofsd log {}: {}",
                stderr_log_path.display(),
                e
            ))
        })?;

        cmd.stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::from(stderr_file));

        let mut process = cmd.spawn().map_err(|e| {
            crate::error::Error::Subprocess(format!("failed to spawn virtiofsd: {e}"))
        })?;

        // §9.4: `api_socket_poll` paces EVERY VMM-control-socket / daemon readiness wait, and the
        // readiness loop itself is the single-source `vmm::wait_for_socket` — this site used to
        // hand-copy that loop on a hard-coded 50×20 ms grid, which both fixed the cadence and
        // forked the "socket appeared / process exited early / deadline" logic (finding
        // `virtiofsd-socket-wait-hardcoded-cadence`). Only the ceiling stays a constant (§9.4:
        // the failure ceilings are correctness constants, not knobs). The stderr-log read-back
        // and the kill/reap wrapper below are what `wait_for_socket` does NOT provide, so they
        // stay here around it.
        //
        // One diagnostic narrows deliberately: the shared helper folds a failing `try_wait` into
        // the deadline (`unwrap_or(None)`), so a poll error now surfaces as the readiness failure
        // *with the daemon's stderr* instead of a separate "failed to poll virtiofsd status"
        // message. Nothing is swallowed — the reap and the loud typed error still run — and the
        // alternative was keeping a second copy of the readiness loop alive to phrase one message.
        let (timeout_ms, interval_ms) = socket_wait_budget(timeouts);
        if let Err(e) =
            crate::vmm::wait_for_socket(&socket_path, Some(&mut process), timeout_ms, interval_ms)
                .await
        {
            // L-HOST-3: a dropped tokio `Child` is NOT killed (kill_on_drop is false), so
            // force-kill and reap the group before returning — otherwise this acquire-then-fail
            // path leaks a live virtiofsd holding the shared dir.
            //
            // The pgid is re-read from the LIVE handle rather than captured before the wait
            // (H-HOST-1 pid reuse): `wait_for_socket`'s `try_wait` reaps the child on the
            // exited-early arm, after which `process.id()` is `None` and `reap_process_group` is
            // a no-op — signalling the captured id there could hit a recycled process group.
            //
            // N-HOST-1: `reap_process_group` deliberately does NOT call `process.start_kill()` —
            // it SIGKILLs the group (`-pgid`) and `waitpid`s the leader, so a `start_kill` on the
            // just-reaped leader would be a guaranteed no-op error and is exactly the
            // leader-only API the teardown contract warns against.
            let live_pgid = process.id();
            crate::vmm::reap_process_group(&mut process, live_pgid);
            let stderr = std::fs::read_to_string(&stderr_log_path).unwrap_or_default();
            return Err(crate::error::Error::Subprocess(readiness_failure_message(
                &e,
                stderr.trim(),
            )));
        }

        Ok(Self {
            socket_path,
            // Hold the live `Child` (H-HOST-1) so its pid cannot be recycled before
            // `Drop` reaps the group; `Drop` reads the pgid from it, never a stored id.
            #[cfg(not(feature = "experiment-fuse"))]
            process: Some(process),
        })
    }

    /// Starts an in-process virtiofs daemon for the given share, for API parity with the
    /// `virtiofsd`-subprocess build.
    ///
    /// The in-process backend signals readiness directly from its worker thread, so there is no
    /// readiness poll for `timeouts.api_socket_poll` (§9.4) to pace and the profile is unused
    /// here; call sites pass their VM's `Timeouts` under either feature, so the shipped code does
    /// not fork on the feature flag.
    ///
    /// # Errors
    /// Returns an error if the virtiofs daemon fails to start or bind to the socket.
    #[cfg(feature = "experiment-fuse")]
    pub async fn start_paced(
        share: &Share,
        vm_tmp: &Path,
        _timeouts: &crate::config::Timeouts,
    ) -> crate::error::Result<Self> {
        let socket_path = vm_tmp.join(format!("{}.sock", share.tag));
        let read_only = matches!(share.access, Access::ReadOnly);
        // CFG-3: the in-process (fuse-backend-rs passthrough) backend cannot enforce a
        // read-only share, so it must fail loud rather than silently mount it rw.
        // Surface that as a typed, matchable `Error::Unsupported` (the capability
        // contract) up front — instead of the stringly `Error::Subprocess` the
        // daemon's `io::Error` was formerly wrapped into below. The in-process worker
        // keeps the same refusal as a lower-layer backstop.
        if read_only {
            return Err(crate::error::Error::from_removal(
                "in-process-virtiofsd",
                &crate::feature::Removal {
                    feature: crate::feature::Feature::VirtioFsShares,
                    by: crate::feature::Source::Config,
                    reason: "asks for a read-only share, which the in-process backend cannot serve",
                },
            ));
        }
        // `start_in_process_virtiofsd` only returns `Ok` after the worker thread has
        // built the daemon and signalled that it has reached its serve loop; a
        // construction failure is reported as a typed error rather than a thread
        // panic. Readiness therefore reflects an actually-serving daemon rather than
        // mere socket existence — the `Listener` binds the socket up front, so
        // polling for the socket file would report a dead daemon as ready (M-FS-2).
        let (handle, kill_notifier) = in_process::backend::start_in_process_virtiofsd(
            &socket_path,
            &share.host_path,
            read_only,
        )
        .map_err(|e| {
            crate::error::Error::Subprocess(format!("failed to start in-process virtiofsd: {e}"))
        })?;

        // The listener binds the socket synchronously before the worker signals
        // ready, so its absence here is a hard inconsistency rather than a
        // not-yet-ready race.
        if !socket_path.exists() {
            return Err(crate::error::Error::Subprocess(
                "in-process virtiofsd reported ready but its socket is missing".to_string(),
            ));
        }

        Ok(Self {
            socket_path,
            handle: Some(handle),
            kill_notifier: Some(kill_notifier),
        })
    }
}

impl Drop for VirtioFsDaemon {
    fn drop(&mut self) {
        #[cfg(not(feature = "experiment-fuse"))]
        {
            // H-HOST-1: read the pgid from the LIVE, still-held child handle so we
            // never signal a recycled pid. `process.id()` is `None` only once the
            // child has been reaped, in which case `reap_process_group` is a no-op.
            // Holding the `Child` until here pins the pid across the kill+reap; the
            // `Child` is dropped after this block, after the group has been reaped.
            // The kill+reap itself is the single-source `vmm::reap_process_group`
            // (finding `fs-reap-note-claims-consolidation-that-never-landed`: the
            // recorded v28 consolidation had never actually landed here).
            if let Some(mut process) = self.process.take() {
                let pgid = process.id();
                crate::vmm::reap_process_group(&mut process, pgid);
            }
        }
        #[cfg(feature = "experiment-fuse")]
        {
            if let Some(notifier) = self.kill_notifier.take() {
                let _ = notifier.notify();
            }
            if let Some(h) = self.handle.take() {
                let _ = h.join();
            }
        }
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

/// The `(timeout_ms, interval_ms)` pair the `virtiofsd` readiness wait passes to
/// [`crate::vmm::wait_for_socket`].
///
/// Extracted so the §9.4 pacing rule ("`api_socket_poll` paces **every** … daemon readiness
/// wait") is unit-testable without spawning a daemon: the cadence must come from the caller's
/// profile, never from a hard-coded grid. `wait_for_socket` clamps the interval to ≥1 ms itself,
/// so a zero-valued profile cannot busy-spin here either.
///
/// The **ceiling** is a failure ceiling, not a knob (§9.4 keeps the correctness ceilings as
/// constants and puts only the cadence in `Timeouts`) — and it is the ONE
/// [`crate::vmm::VMM_SOCKET_READY_TIMEOUT_MS`], not a copy of its value. A local `1000` sat here
/// with a doc claiming it was "the same 1 s ceiling `spawn_ch` passes to
/// `register_and_await_ready`", which was doubly untrue: that entry point takes no ceiling
/// argument at all, and nothing tied the two numbers together (docs/90 `fs.rs:380`). Both waits
/// answer the same question — has a locally spawned helper created its listening socket yet — so
/// they ride one const, and `socket_wait_ceiling_is_the_one_shared_readiness_ceiling` reddens if
/// they ever diverge.
#[cfg(not(feature = "experiment-fuse"))]
fn socket_wait_budget(timeouts: &crate::config::Timeouts) -> (u64, u64) {
    (
        crate::vmm::VMM_SOCKET_READY_TIMEOUT_MS,
        u64::try_from(timeouts.api_socket_poll.as_millis()).unwrap_or(u64::MAX),
    )
}

/// Renders a [`crate::vmm::wait_for_socket`] failure as the `virtiofsd`-specific message, with the
/// daemon's captured stderr appended.
///
/// The shared readiness helper reports a generic `Timeout` / "process exited early"; the daemon's
/// own stderr log (METRICS-FS-5) is what actually diagnoses the failure, and it is only readable
/// here. Kept pure so both arms are unit-testable.
#[cfg(not(feature = "experiment-fuse"))]
fn readiness_failure_message(err: &crate::error::Error, stderr: &str) -> String {
    match err {
        crate::error::Error::Timeout(_) => format!("virtiofsd failed to create socket: {stderr}"),
        // `wait_for_socket`'s fail-fast arm: the daemon exited before the socket appeared, and the
        // error carries the real exit status — far more informative than the later timeout.
        other => format!("virtiofsd exited prematurely ({other}): {stderr}"),
    }
}

/// The `pre_exec` body for the spawned `virtiofsd`: own process group + parent-death signal.
///
/// Runs in the forked child between `fork` and `execve`, so it may touch only async-signal-safe
/// operations and must not allocate — the error branches build the `io::Error` with
/// `from_raw_os_error` / `last_os_error` (non-allocating errno wrappers) rather than
/// `io::Error::other`, which would heap-allocate after the fork.
///
/// - `setpgid(0, 0)`: the daemon leads its own group, so teardown can SIGKILL `-pgid` and sweep
///   virtiofsd's sandbox children with it.
/// - `PR_SET_PDEATHSIG(SIGKILL)`: helper-daemon discipline (AGENTS.md, "Writing code"). Without
///   it, an orchestrator that is itself SIGKILLed (no `Drop`, no teardown) leaks a live daemon
///   holding the shared directory — the daemon's start-up sweep reclaims *directories*, never
///   processes, so nothing else would ever collect it (finding `virtiofsd-missing-pdeathsig`).
///
/// `spawning_parent` is our pid, captured *before* the fork: the parent-death signal is armed
/// after the fork, so a parent that dies inside that window is already gone when `prctl` runs and
/// the signal would never fire. Comparing it against `getppid()` closes the window.
///
/// The signal fires when the spawning *thread* exits (`pdeath_signal` is per-task, and `clone`
/// zeroes it in the new task), so the daemon dies with the tokio worker that spawned it — i.e. at
/// runtime shutdown, which is orchestrator teardown. That is the intent; `Drop`/`shutdown()`
/// normally get there first, and this is the backstop for the paths that never run (`SIGKILL`).
#[cfg(all(unix, not(feature = "experiment-fuse")))]
fn helper_daemon_pre_exec(spawning_parent: libc::pid_t) -> std::io::Result<()> {
    nix::unistd::setpgid(nix::unistd::Pid::from_raw(0), nix::unistd::Pid::from_raw(0))
        .map_err(|e| std::io::Error::from_raw_os_error(e as i32))?;
    // SAFETY: `prctl(PR_SET_PDEATHSIG, SIGKILL)` takes scalar arguments only — no pointers, no
    // buffers — and is a single async-signal-safe syscall acting on the calling process itself,
    // which is this forked child. It survives the following `execve` (only a credential-changing
    // exec clears it; `Command::uid` drops privilege via `setuid` before exec, not by exec'ing a
    // setuid binary).
    if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: `getppid()` takes no arguments, cannot fail, and is async-signal-safe. If our parent
    // died between the fork and the `prctl` above, we were already reparented and the armed signal
    // will never be delivered — refuse to exec rather than leak a daemon nothing will collect.
    if unsafe { libc::getppid() } != spawning_parent {
        return Err(std::io::Error::from_raw_os_error(libc::ESRCH));
    }
    Ok(())
}

/// Which uid the spawned `virtiofsd` should run as.
///
/// Extracted as a pure decision so the policy is unit-testable without spawning
/// a process: in particular that we never silently fall back to `nobody`, whose
/// inability to read a root-owned share would turn the uid hardening into an
/// `EACCES` functional failure.
#[cfg(all(unix, not(feature = "experiment-fuse")))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VirtiofsdUid {
    /// Not running as root: the daemon already runs as the unprivileged invoking
    /// user, so its uid is left unchanged.
    InheritUnprivileged,
    /// Running as root with a known invoking user (`SUDO_UID`); drop to that uid
    /// before `execve` so the daemon does not act as root.
    DropTo(u32),
    /// Running as root with no invoking user to drop to and no dedicated service
    /// uid: keep privileges and rely on `--sandbox=namespace` rather than the
    /// `EACCES`-prone `nobody` fallback.
    SandboxOnly,
}

/// Decides which uid `virtiofsd` should run as given whether we are root and the
/// parsed `SUDO_UID`.
#[cfg(all(unix, not(feature = "experiment-fuse")))]
fn decide_virtiofsd_uid(running_as_root: bool, sudo_uid: Option<u32>) -> VirtiofsdUid {
    if !running_as_root {
        return VirtiofsdUid::InheritUnprivileged;
    }
    match sudo_uid {
        // uid 0 is not a real privilege drop; treat it as "no usable invoking user".
        Some(uid) if uid != 0 => VirtiofsdUid::DropTo(uid),
        _ => VirtiofsdUid::SandboxOnly,
    }
}

#[cfg(all(test, unix, not(feature = "experiment-fuse")))]
mod uid_tests {
    use super::{VirtiofsdUid, decide_virtiofsd_uid};

    #[test]
    fn non_root_inherits_unprivileged() {
        assert_eq!(
            decide_virtiofsd_uid(false, Some(1000)),
            VirtiofsdUid::InheritUnprivileged
        );
        assert_eq!(
            decide_virtiofsd_uid(false, None),
            VirtiofsdUid::InheritUnprivileged
        );
    }

    #[test]
    fn root_with_sudo_uid_drops_to_it() {
        assert_eq!(
            decide_virtiofsd_uid(true, Some(1000)),
            VirtiofsdUid::DropTo(1000)
        );
    }

    #[test]
    fn root_without_sudo_uid_does_not_fall_back_to_nobody() {
        // The buggy impl returned `DropTo(65534)` (nobody), which `EACCES`es on a
        // root-owned share. This goes RED on that inverse.
        let decision = decide_virtiofsd_uid(true, None);
        assert_eq!(decision, VirtiofsdUid::SandboxOnly);
        assert_ne!(decision, VirtiofsdUid::DropTo(65534));
    }

    #[test]
    fn root_with_sudo_uid_zero_is_sandbox_only() {
        // `SUDO_UID=0` is not a real drop; do not treat it as one.
        assert_eq!(
            decide_virtiofsd_uid(true, Some(0)),
            VirtiofsdUid::SandboxOnly
        );
    }
}

#[cfg(all(test, not(feature = "experiment-fuse")))]
mod readiness_pacing_tests {
    use super::{readiness_failure_message, socket_wait_budget};
    use crate::config::Timeouts;
    use crate::vmm::VMM_SOCKET_READY_TIMEOUT_MS;
    use std::time::Duration;

    // §9.4: `api_socket_poll` paces EVERY daemon readiness wait. This goes RED on the pre-fix
    // implementation, whose hard-coded 50×20 ms grid ignored the profile entirely (the interval
    // would stay 20 for both profiles below).
    #[test]
    fn socket_wait_interval_comes_from_the_profile_not_a_hard_coded_grid() {
        let fast = Timeouts {
            api_socket_poll: Duration::from_millis(2),
            ..Timeouts::default()
        };
        assert_eq!(
            socket_wait_budget(&fast),
            (VMM_SOCKET_READY_TIMEOUT_MS, 2),
            "the readiness cadence must be the caller's api_socket_poll"
        );

        let slow = Timeouts {
            api_socket_poll: Duration::from_millis(37),
            ..Timeouts::default()
        };
        assert_eq!(socket_wait_budget(&slow), (VMM_SOCKET_READY_TIMEOUT_MS, 37));
    }

    // The ceiling is a correctness constant (§9.4) — and it is not a SECOND copy of one. virtiofsd's
    // socket wait rides the same `vmm::VMM_SOCKET_READY_TIMEOUT_MS` the VMM control socket does, so
    // the pair cannot drift the way the former local `1000` could (docs/90 `fs.rs:380`). RED on the
    // inverse: re-introduce a local ceiling here and retune it (the only defect this class has —
    // one of the two numbers moving) and the first assert fails naming both values.
    #[test]
    fn socket_wait_ceiling_is_the_one_shared_readiness_ceiling() {
        assert_eq!(
            socket_wait_budget(&Timeouts::default()).0,
            VMM_SOCKET_READY_TIMEOUT_MS,
            "virtiofsd's readiness ceiling must BE the shared one, not equal a copy of it"
        );
        // …and that shared ceiling is still the 1 s the pre-consolidation 50 × 20 ms loop
        // budgeted, so neither consolidation silently shortened or lengthened this wait.
        assert_eq!(VMM_SOCKET_READY_TIMEOUT_MS, 1000);
    }

    // The shared `wait_for_socket` reports a generic Timeout / "process exited early"; the two
    // virtiofsd-specific diagnoses (with the daemon's own stderr, which only this site can read)
    // must survive the consolidation. Goes RED if either arm loses its stderr or collapses into
    // the other's wording.
    #[test]
    fn readiness_failure_messages_keep_both_diagnoses_with_stderr() {
        let timeout = readiness_failure_message(
            &crate::error::Error::Timeout("socket failed to appear in time".into()),
            "vhost_user_fs: bad --shared-dir",
        );
        assert_eq!(
            timeout,
            "virtiofsd failed to create socket: vhost_user_fs: bad --shared-dir"
        );

        let exited = readiness_failure_message(
            &crate::error::Error::Vmm("process exited early: exit status: 1".into()),
            "unknown option --nope",
        );
        assert!(
            exited.contains("exited prematurely")
                && exited.contains("exit status: 1")
                && exited.contains("unknown option --nope"),
            "the early-exit arm must keep the status and the daemon stderr, got {exited}"
        );
    }
}

#[cfg(all(test, unix, not(feature = "experiment-fuse")))]
mod pre_exec_tests {
    use std::io::BufRead as _;
    use std::io::Write as _;
    use std::os::unix::process::CommandExt as _;

    /// Set on the re-exec'd middle process so it takes the "spawn a daemon and park" branch.
    const MIDDLE_ENV: &str = "VMCELL_FS_PRE_EXEC_MIDDLE";
    /// The libtest name of the test below; the middle process is re-exec'd with `--exact` on it.
    const MIDDLE_TEST: &str =
        "fs::pre_exec_tests::helper_daemon_dies_with_its_parent_and_leads_its_own_group";
    /// Line the middle process prints so the driver learns the daemon stand-in's pid.
    const PID_MARKER: &str = "VMCELL_DAEMON_PID=";

    /// The `/proc/<pid>/stat` state character, or `None` once the pid is gone.
    ///
    /// A killed-but-unreaped process is still signalable (`kill(pid, 0)` succeeds on a zombie), so
    /// "dead" here means *gone or `Z`* — the reap is init's job, not ours, and racing it would
    /// make this test flaky.
    fn process_state(pid: i32) -> Option<char> {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        // `comm` is parenthesized and may itself contain ')' — split on the LAST one.
        let after_comm = stat.rsplit_once(')')?.1;
        after_comm.split_whitespace().next()?.chars().next()
    }

    fn is_dead(pid: i32) -> bool {
        matches!(process_state(pid), None | Some('Z'))
    }

    // Helper-daemon discipline (AGENTS.md "Writing code"; finding `virtiofsd-missing-pdeathsig`):
    // a daemon spawned through `helper_daemon_pre_exec` must (a) lead its own process group, so
    // teardown can `kill(-pgid)` virtiofsd's sandbox children with it, and (b) carry
    // `PR_SET_PDEATHSIG(SIGKILL)`, so an orchestrator that is itself SIGKILLed — no `Drop`, no
    // `shutdown()`, no teardown at all — cannot leak a live daemon holding the shared dir.
    //
    // (b) is asserted as BEHAVIOR, not as the flag: `PR_GET_PDEATHSIG` is per-task and `clone`
    // zeroes it, so a readback from a libtest worker thread would report 0 however the exec'd
    // image was armed. So the test builds the real three-level shape — driver → middle process
    // (a re-exec of this test binary) → daemon stand-in spawned with the production `pre_exec` —
    // SIGKILLs the middle process, and requires the stand-in to die on its own.
    //
    // RED on the inverse: drop the `prctl` from `helper_daemon_pre_exec` and the orphaned stand-in
    // outlives its killed parent; drop the `setpgid` and it reports its parent's group.
    #[test]
    fn helper_daemon_dies_with_its_parent_and_leads_its_own_group() {
        let spawning_parent = libc::pid_t::try_from(std::process::id()).unwrap_or(-1);

        if std::env::var_os(MIDDLE_ENV).is_some() {
            // Middle role: spawn a long-lived daemon stand-in exactly the way `start_paced`
            // spawns virtiofsd, report its pid, and park until the driver SIGKILLs us. `sleep`
            // outlives the whole test unless something kills it, which is the point.
            let mut cmd = std::process::Command::new("sleep");
            cmd.arg("60");
            // SAFETY: `pre_exec` runs the closure in the forked child before `execve`; it only
            // calls the production `helper_daemon_pre_exec`, which is async-signal-safe and
            // non-allocating (proven at its definition), on a captured scalar.
            unsafe {
                cmd.pre_exec(move || super::helper_daemon_pre_exec(spawning_parent));
            }
            // Held (not dropped early) for the same reason `start_paced` holds virtiofsd's
            // `Child`: the pid must not be recycled while the driver is watching it. std does not
            // kill on drop.
            #[expect(
                clippy::zombie_processes,
                reason = "this middle process is SIGKILLed by the driver on purpose, so it can \
                          never wait() — the stand-in's death is exactly what is under test, and \
                          init reaps it"
            )]
            let child = cmd.spawn().expect("spawn the daemon stand-in");
            let pid = child.id();
            let mut out = std::io::stdout();
            writeln!(out, "{PID_MARKER}{pid}").expect("report the stand-in pid");
            // The driver reads this over a pipe, so line-buffering does not apply — flush.
            out.flush().expect("flush the stand-in pid");
            std::thread::sleep(std::time::Duration::from_secs(120));
            return;
        }

        // Driver role.
        let exe = std::env::current_exe().expect("current test binary");
        let mut middle = std::process::Command::new(exe)
            .args(["--exact", MIDDLE_TEST, "--nocapture"])
            .env(MIDDLE_ENV, "1")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("re-exec the middle process");

        // Read the stand-in's pid. EOF without the marker means the filter selected no test (CI
        // rule 3: a filter that matches nothing must not pass) or the middle role panicked.
        let mut reader = std::io::BufReader::new(middle.stdout.take().expect("piped stdout"));
        let mut daemon_pid = None;
        let mut line = String::new();
        while reader.read_line(&mut line).expect("read middle stdout") > 0 {
            if let Some(rest) = line.trim().strip_prefix(PID_MARKER) {
                daemon_pid = Some(rest.parse::<i32>().expect("stand-in pid"));
                break;
            }
            line.clear();
        }
        let daemon_pid = match daemon_pid {
            Some(pid) => pid,
            None => {
                let _ = middle.kill();
                let _ = middle.wait();
                panic!(
                    "the middle process never reported a stand-in pid (is {MIDDLE_TEST} still the test name?)"
                );
            }
        };

        // (a) Own process group, observable from here (`getpgid`), so `kill(-pgid)` in teardown
        // sweeps the daemon's own children rather than the orchestrator's group.
        let pgid = nix::unistd::getpgid(Some(nix::unistd::Pid::from_raw(daemon_pid)))
            .expect("stand-in process group");
        assert_eq!(
            pgid.as_raw(),
            daemon_pid,
            "the helper daemon must lead its own process group"
        );
        assert!(
            !is_dead(daemon_pid),
            "the stand-in must be alive before the parent is killed"
        );

        // (b) SIGKILL the middle process — the "orchestrator was hard-killed, no teardown ran"
        // case — and require the stand-in to die on its own.
        middle.kill().expect("SIGKILL the middle process");
        middle.wait().expect("reap the middle process");

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !is_dead(daemon_pid) && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let dead = is_dead(daemon_pid);
        if !dead {
            // Never leave a 60 s `sleep` behind on the failure path.
            let _ = nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(daemon_pid),
                nix::sys::signal::Signal::SIGKILL,
            );
        }
        assert!(
            dead,
            "the helper daemon outlived its SIGKILLed parent — PR_SET_PDEATHSIG(SIGKILL) is not armed"
        );
    }
}

#[cfg(all(test, unix, not(feature = "experiment-fuse")))]
mod drop_reaps_tests {
    use super::VirtioFsDaemon;

    // H-HOST-1 (teardown): `Drop` must force-kill and reap the HELD child's process
    // group, reading the pgid from the live `Child` handle rather than a stored raw
    // id. The pid-reuse RACE itself is not unit-testable without a process fake (a
    // controlled test never recycles the pid, so the buggy stored-pgid version would
    // "pass" too — see the change summary), but this locks the surrounding teardown
    // contract: a long-lived child in its own group is gone after `Drop`. It goes RED
    // if `Drop` stops killing/reaping the held process (e.g. the field or the
    // kill+waitpid is removed).
    #[tokio::test]
    async fn drop_kills_and_reaps_held_child_process_group() {
        // A child that outlives the test unless killed, in its OWN process group
        // (mirrors virtiofsd's `setpgid(0,0)`), so the group-kill path is exercised.
        let mut cmd = tokio::process::Command::new("sleep");
        cmd.arg("10");
        let spawning_parent = libc::pid_t::try_from(std::process::id()).unwrap_or(-1);
        // Routed through the production `pre_exec` body rather than a hand-copied `setpgid` so the
        // fixture cannot drift from what `start_paced` actually spawns (it is a test fixture,
        // not a helper daemon; inheriting PR_SET_PDEATHSIG is harmless — `Drop` kills it first).
        // SAFETY: `pre_exec` runs the closure in the forked child before `execve`; it only calls
        // `helper_daemon_pre_exec`, which is async-signal-safe and non-allocating (proven at its
        // definition), on a captured scalar.
        unsafe {
            cmd.pre_exec(move || super::helper_daemon_pre_exec(spawning_parent));
        }
        let child = cmd.spawn().expect("spawn sleep");
        let pid = child.id().expect("child has a pid") as i32;

        let daemon = VirtioFsDaemon {
            socket_path: std::env::temp_dir().join(format!("vmcell-h1-{pid}.sock")),
            process: Some(child),
        };
        // Sanity: the process is alive before `Drop` (signal 0 probes existence).
        assert!(
            nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(pid),
                None::<nix::sys::signal::Signal>
            )
            .is_ok(),
            "child must be alive before Drop"
        );

        drop(daemon);

        // `Drop`'s waitpid blocks until the reaped leader is gone, so by now
        // signalling the pid fails with ESRCH (no such process).
        assert_eq!(
            nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(pid),
                None::<nix::sys::signal::Signal>
            ),
            Err(nix::errno::Errno::ESRCH),
            "Drop must have killed and reaped the held child's process group"
        );
    }
}

#[cfg(all(test, feature = "experiment-fuse"))]
mod ro_share_tests {
    use super::VirtioFsDaemon;
    use crate::config::{Access, CachePolicy, Share};

    // CFG-3: the in-process (fuse-backend-rs passthrough) backend cannot enforce a
    // read-only share, so `start_paced` must fail loud with a typed, matchable
    // `Error::Unsupported` — NOT the stringly `Error::Subprocess` the daemon's
    // `io::Error` was formerly wrapped into. This goes red if the refusal regresses to
    // `Subprocess` (or, worse, silently mounts the share read-write).
    //
    // Driven through `start_paced` because it is the ONLY entry point: the unpaced `start` shim
    // that used to sit beside it was deleted in the 0.22 -> 0.23 bump (ledgered), so a caller
    // reaching for the shorter name is now a compile error rather than a deprecation warning.
    #[tokio::test]
    async fn ro_share_is_unsupported_not_subprocess() {
        let tmp = std::env::temp_dir().join(format!(
            "vmcell-fs-ro-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&tmp).expect("create host share dir");
        let share = Share::new("ro", &tmp, Access::ReadOnly, CachePolicy::Never);

        let err = VirtioFsDaemon::start_paced(&share, &tmp, &crate::config::Timeouts::default())
            .await
            .expect_err("a read-only share must be refused by the in-process backend");
        assert!(
            matches!(
                &err,
                crate::error::Error::Unsupported { feature, .. }
                    if feature == crate::feature::Feature::VirtioFsShares.name()
            ),
            "expected a typed Unsupported naming virtio_fs_shares, got {err:?}"
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }
}

/// Declaration-side gate for §9.4's "`api_socket_poll` paces **every** … daemon readiness wait":
/// this module exposes exactly **one** way to start a virtiofs daemon, and it is the paced one.
///
/// Why a scan, and why on the declaration rather than the call. The two backends that start
/// virtiofs daemons already gate their own *call sites*
/// (`every_virtiofs_start_here_is_paced_by_the_vm_config`, once in `vmm::cloud_hypervisor` and
/// once in `vmcell-qemu`), so an in-tree caller of an unpaced twin reddens there. Neither scan can
/// see a twin that is *declared* and never called in-tree — which is exactly the shape the
/// `#[deprecated]` `start(share, vm_tmp)` shim had across the ten releases from 0.13.0 to its
/// deletion here: reachable only by a downstream consumer, where the mispacing would be invisible
/// to this repo entirely. Adding a
/// second `pub async fn` beside [`VirtioFsDaemon::start_paced`] is not a compile error and moves
/// no signature `cargo semver-checks` reads, so a scan is the only thing that can go red on it
/// (AGENTS.md, "One law, one predicate").
///
/// Vacuity: the roster is asserted to be **exactly** [`EXPECTED_DECLARATIONS`] entries, so a scan
/// that matched nothing — a rename, a normalizer that ate the whole file — fails as a
/// misconfigured gate instead of passing over an empty set, and
/// [`the_scanner_reports_nothing_on_empty_source`] is the leg that proves that arm reachable.
#[cfg(test)]
mod one_start_entry_point_gate {
    /// This module's own source text. `include_str!` resolves relative to this file's directory,
    /// so a rename or a move of `fs.rs` is a compile error here rather than a silently empty scan,
    /// and rustc records the read in its dep-info so a stale copy is unreachable.
    const SOURCE: &str = include_str!("fs.rs");

    /// The name of the one entry point (§9.4): it takes the caller's `&Timeouts`, so the cadence
    /// is always the VM's own profile and never a default baked in by the callee.
    const THE_PACED_ENTRY_POINT: &str = "start_paced";

    /// How many declarations of it this file ships: one per `experiment-fuse` arm (the
    /// `virtiofsd`-subprocess build and the in-process one), which is why the count is 2 and not 1
    /// — the scan reads text, so both `#[cfg]` arms are always visible to it.
    const EXPECTED_DECLARATIONS: usize = 2;

    /// `source`'s production text: everything before its first test module, comment lines dropped
    /// and whitespace collapsed.
    ///
    /// Dropping comments keeps a rustdoc mention of an entry point (this file's own
    /// `start_paced` doc names the deleted shim, in prose) from being scanned as a declaration;
    /// collapsing whitespace keeps a rustfmt line break from hiding half of one. The truncation
    /// looks for both spellings this file uses — the plain `#[cfg(test)]` on the module below and
    /// the `#[cfg(all(test, …))]` on the ones above it — because cutting at only the first would
    /// leave several test modules inside the "production" half.
    ///
    /// Deliberately local rather than shared with `vmm::cloud_hypervisor`'s identically-shaped
    /// normalizer: that one is `pub(super)` inside a `#[cfg(test)]` module of a
    /// feature-gated backend, so it is unreachable from here, and it truncates on one marker where
    /// this file needs two. This is a test-local reader of one law, not a second law.
    fn production_code(source: &str) -> String {
        let cut = ["#[cfg(test)]", "#[cfg(all(test"]
            .iter()
            .filter_map(|marker| source.find(marker))
            .min()
            .unwrap_or(source.len());
        source[..cut]
            .lines()
            .map(str::trim)
            .filter(|line| !line.starts_with("//"))
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// The name of every `pub async fn` declared in `code`.
    fn public_async_fn_names(code: &str) -> Vec<&str> {
        const DECL: &str = "pub async fn ";
        code.match_indices(DECL)
            .map(|(at, _)| {
                let tail = &code[at + DECL.len()..];
                &tail[..tail.find(['(', '<', ' ']).unwrap_or(tail.len())]
            })
            .collect()
    }

    /// The law, as a predicate over a scanned roster: every publicly declared start entry point is
    /// the paced one, and the roster is **non-empty** — a scan that matched nothing is a
    /// misconfigured gate, never a pass.
    fn roster_is_only_the_paced_entry_point(names: &[&str]) -> bool {
        !names.is_empty() && names.iter().all(|name| *name == THE_PACED_ENTRY_POINT)
    }

    #[test]
    fn virtiofsd_declares_exactly_one_start_entry_point() {
        let code = production_code(SOURCE);
        let names = public_async_fn_names(&code);
        assert_eq!(
            names.len(),
            EXPECTED_DECLARATIONS,
            "gate misconfigured or the surface moved: expected {EXPECTED_DECLARATIONS} public \
             async entry points (one `{THE_PACED_ENTRY_POINT}` per `experiment-fuse` arm), found \
             {}: {names:?}. If one was legitimately added or removed, update \
             EXPECTED_DECLARATIONS — do not delete the scan.",
            names.len()
        );
        assert!(
            roster_is_only_the_paced_entry_point(&names),
            "§9.4: every public virtio-fs start entry point must be `{THE_PACED_ENTRY_POINT}`, \
             which takes the caller's `&Timeouts`; found {names:?}. A convenience twin that bakes \
             in the default cadence re-pins virtiofsd's readiness wait under `low_latency()` and \
             `throughput()` — pass `&Timeouts::default()` at the call site instead."
        );
    }

    /// The gate's own red-on-inverse: the predicate rejects the shim that was actually deleted on
    /// the 0.22 → 0.23 edge, and rejects the empty roster a vacuous scan would produce.
    #[test]
    fn the_predicate_rejects_the_deleted_shim_and_an_empty_scan() {
        assert!(!roster_is_only_the_paced_entry_point(&[
            "start",
            "start_paced"
        ]));
        assert!(!roster_is_only_the_paced_entry_point(&["start_unpaced"]));
        assert!(!roster_is_only_the_paced_entry_point(&[]));
        assert!(roster_is_only_the_paced_entry_point(&[
            "start_paced",
            "start_paced"
        ]));
    }

    /// The scanner's controls: a rustdoc mention of an entry point is not a declaration, a
    /// declaration split across rustfmt lines is still read whole, and a declaration inside a test
    /// module is not production surface. Goes red if the normalizer stops stripping comments (the
    /// prose `start(share, vm_tmp)` in this file's own rustdoc would then scan as a twin).
    #[test]
    fn the_scanner_reads_declarations_not_prose() {
        let synthetic = "/// Such a shim — pub async fn start(share, vm_tmp) — did sit here.\n\
             #[cfg(not(feature = \"experiment-fuse\"))]\n\
             pub async fn start_paced(\n    share: &Share,\n) -> Result<Self> {}\n\
             #[cfg(test)]\nmod tests { pub async fn start(x) {} }";
        let code = production_code(synthetic);
        let names = public_async_fn_names(&code);
        assert_eq!(names, ["start_paced"], "got {names:?}");
        assert!(roster_is_only_the_paced_entry_point(&names));
    }

    /// The zero-file leg, stated rather than implied: an empty scan yields an empty roster, which
    /// is why [`virtiofsd_declares_exactly_one_start_entry_point`]'s exact-count assertion is what
    /// makes a misconfigured gate red instead of green.
    #[test]
    fn the_scanner_reports_nothing_on_empty_source() {
        assert!(public_async_fn_names(&production_code("")).is_empty());
        assert!(
            public_async_fn_names(&production_code("#[cfg(test)] pub async fn start(x) {}"))
                .is_empty()
        );
    }
}
