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
    #[cfg(not(feature = "experiment-fuse"))]
    // process: Child,
    #[cfg(not(feature = "experiment-fuse"))]
    pgid: Option<u32>,
    #[cfg(feature = "experiment-fuse")]
    #[allow(dead_code)]
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
            // Drop privileges for virtiofsd if we are running as root
            if nix::unistd::getuid().as_raw() == 0 {
                let uid = std::env::var("SUDO_UID")
                    .ok()
                    .and_then(|s| s.parse::<u32>().ok())
                    .unwrap_or(65534); // fallback to nobody
                cmd.uid(uid);
            }
            // SAFETY: pre_exec is safe here because we only call async-signal-safe functions (setpgid).
            unsafe {
                cmd.pre_exec(|| {
                    nix::unistd::setpgid(
                        nix::unistd::Pid::from_raw(0),
                        nix::unistd::Pid::from_raw(0),
                    )
                    .map_err(std::io::Error::other)?;
                    Ok(())
                });
            }
        }

        cmd.stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());

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
            if let Some(status) = process.try_wait().unwrap_or(None) {
                let mut stderr = String::new();
                if let Some(mut err_stream) = process.stderr.take() {
                    use tokio::io::AsyncReadExt;
                    let _ = err_stream.read_to_string(&mut stderr).await;
                }
                return Err(crate::error::Error::Subprocess(format!(
                    "virtiofsd exited prematurely with {}: {}",
                    status,
                    stderr.trim()
                )));
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
            let _ = process.start_kill();
            let mut stderr = String::new();
            if let Some(mut err_stream) = process.stderr.take() {
                use tokio::io::AsyncReadExt;
                let _ = err_stream.read_to_string(&mut stderr).await;
            }
            return Err(crate::error::Error::Subprocess(format!(
                "virtiofsd failed to create socket: {}",
                stderr.trim()
            )));
        }

        Ok(Self {
            socket_path,
            #[cfg(not(feature = "experiment-fuse"))]
            pgid,
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
        let (handle, kill_notifier) = in_process::backend::start_in_process_virtiofsd(
            &socket_path,
            &share.host_path,
            read_only,
        )
        .map_err(|e| {
            crate::error::Error::Subprocess(format!("failed to start in-process virtiofsd: {}", e))
        })?;

        // Wait for socket to be created
        let mut ready = false;
        for _ in 0..50 {
            if socket_path.exists() {
                ready = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        if !ready {
            return Err(crate::error::Error::Subprocess(
                "in-process virtiofsd failed to create socket".to_string(),
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
            if let Some(pgid) = self.pgid {
                let _ = nix::sys::signal::kill(
                    nix::unistd::Pid::from_raw(-(pgid as i32)),
                    nix::sys::signal::Signal::SIGKILL,
                );
                let _ = nix::sys::wait::waitpid(nix::unistd::Pid::from_raw(pgid as i32), None);
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
