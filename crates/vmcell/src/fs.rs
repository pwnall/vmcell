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
    /// Starts a virtiofs daemon (using the standalone `virtiofsd` binary) for the given share.
    ///
    /// # Errors
    /// Returns an error if the daemon fails to spawn or create the socket.
    #[cfg(not(feature = "experiment-fuse"))]
    pub async fn start(share: &Share, vm_tmp: &Path) -> crate::error::Result<Self> {
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
            // SAFETY: the `pre_exec` closure runs in the forked child before `execve`,
            // so it must touch only async-signal-safe operations. `setpgid` is
            // async-signal-safe, and the error branch builds the `io::Error` with
            // `from_raw_os_error` (a non-allocating wrapper around the errno) rather
            // than `io::Error::other`, which would heap-allocate after the fork.
            unsafe {
                cmd.pre_exec(|| {
                    nix::unistd::setpgid(
                        nix::unistd::Pid::from_raw(0),
                        nix::unistd::Pid::from_raw(0),
                    )
                    .map_err(|e| std::io::Error::from_raw_os_error(e as i32))?;
                    Ok(())
                });
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
            crate::error::Error::Subprocess(format!("failed to spawn virtiofsd: {}", e))
        })?;
        let pgid = process.id();

        // Wait for socket to be created
        let mut ready = false;
        for _ in 0..50 {
            if socket_path.exists() {
                ready = true;
                break;
            }
            match process.try_wait() {
                Ok(Some(status)) => {
                    let stderr = std::fs::read_to_string(&stderr_log_path).unwrap_or_default();
                    return Err(crate::error::Error::Subprocess(format!(
                        "virtiofsd exited prematurely with {}: {}",
                        status,
                        stderr.trim()
                    )));
                }
                Ok(None) => {}
                // Surface, rather than swallow, an error from polling the child:
                // a failed `try_wait` means we no longer know the daemon's state.
                // L-HOST-3: a dropped tokio `Child` is NOT killed (kill_on_drop is
                // false), so force-kill and reap the group before returning — the
                // same cleanup as the timeout path below — to avoid leaking a
                // possibly-live virtiofsd on this acquire-then-fail path.
                Err(e) => {
                    if let Some(p) = pgid {
                        let _ = nix::sys::signal::kill(
                            nix::unistd::Pid::from_raw(-(p as i32)),
                            nix::sys::signal::Signal::SIGKILL,
                        );
                        let _ = nix::sys::wait::waitpid(nix::unistd::Pid::from_raw(p as i32), None);
                    }
                    return Err(crate::error::Error::Subprocess(format!(
                        "failed to poll virtiofsd status: {e}"
                    )));
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        if !ready {
            if let Some(p) = pgid {
                let _ = nix::sys::signal::kill(
                    nix::unistd::Pid::from_raw(-(p as i32)),
                    nix::sys::signal::Signal::SIGKILL,
                );
                let _ = nix::sys::wait::waitpid(nix::unistd::Pid::from_raw(p as i32), None);
            }
            // N-HOST-1: no redundant `process.start_kill()` here — the pgid leader
            // (the virtiofsd process, which `setpgid`'d itself) was just SIGKILL'd
            // and reaped above, so `start_kill` on the reaped leader is a guaranteed
            // no-op error and is exactly the leader-only API the teardown contract
            // warns against.
            let stderr = std::fs::read_to_string(&stderr_log_path).unwrap_or_default();
            return Err(crate::error::Error::Subprocess(format!(
                "virtiofsd failed to create socket: {}",
                stderr.trim()
            )));
        }

        Ok(Self {
            socket_path,
            // Hold the live `Child` (H-HOST-1) so its pid cannot be recycled before
            // `Drop` reaps the group; `Drop` reads the pgid from it, not `pgid`.
            #[cfg(not(feature = "experiment-fuse"))]
            process: Some(process),
        })
    }

    #[cfg(feature = "experiment-fuse")]
    /// Starts a virtiofs daemon for the given share and returns its handler.
    ///
    /// # Errors
    /// Returns an error if the virtiofs daemon fails to start or bind to the socket.
    pub async fn start(share: &Share, vm_tmp: &Path) -> crate::error::Result<Self> {
        let socket_path = vm_tmp.join(format!("{}.sock", share.tag));
        let read_only = matches!(share.access, Access::ReadOnly);
        // CFG-3: the in-process (fuse-backend-rs passthrough) backend cannot enforce a
        // read-only share, so it must fail loud rather than silently mount it rw.
        // Surface that as a typed, matchable `Error::Unsupported` (the capability
        // contract) up front — instead of the stringly `Error::Subprocess` the
        // daemon's `io::Error` was formerly wrapped into below. The in-process worker
        // keeps the same refusal as a lower-layer backstop.
        if read_only {
            return Err(crate::error::Error::Unsupported {
                vmm: "in-process-virtiofsd".to_string(),
                feature: "read-only virtio-fs share (in-process backend)".to_string(),
            });
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
            crate::error::Error::Subprocess(format!("failed to start in-process virtiofsd: {}", e))
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
            // child has been reaped, in which case there is nothing to kill. Holding
            // the `Child` until here pins the pid across the kill+reap; the `Child`
            // is dropped after this block, after the group has already been reaped.
            if let Some(process) = self.process.take() {
                if let Some(pgid) = process.id() {
                    let _ = nix::sys::signal::kill(
                        nix::unistd::Pid::from_raw(-(pgid as i32)),
                        nix::sys::signal::Signal::SIGKILL,
                    );
                    let _ = nix::sys::wait::waitpid(nix::unistd::Pid::from_raw(pgid as i32), None);
                }
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
        // SAFETY: async-signal-safe `setpgid` runs in the forked child before exec.
        unsafe {
            cmd.pre_exec(|| {
                nix::unistd::setpgid(nix::unistd::Pid::from_raw(0), nix::unistd::Pid::from_raw(0))
                    .map_err(|e| std::io::Error::from_raw_os_error(e as i32))?;
                Ok(())
            });
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
    // read-only share, so `start` must fail loud with a typed, matchable
    // `Error::Unsupported` — NOT the stringly `Error::Subprocess` the daemon's
    // `io::Error` was formerly wrapped into. This goes red if the refusal regresses to
    // `Subprocess` (or, worse, silently mounts the share read-write).
    #[tokio::test]
    async fn ro_share_is_unsupported_not_subprocess() {
        let tmp = std::env::temp_dir().join(format!(
            "vmcell-fs-ro-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&tmp).expect("create host share dir");
        let share = Share::new("ro", &tmp, Access::ReadOnly, CachePolicy::Never);

        let err = VirtioFsDaemon::start(&share, &tmp)
            .await
            .expect_err("a read-only share must be refused by the in-process backend");
        assert!(
            matches!(
                &err,
                crate::error::Error::Unsupported { feature, .. } if feature.contains("read-only")
            ),
            "expected a typed Unsupported for a read-only share, got {err:?}"
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
