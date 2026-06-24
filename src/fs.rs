//! Filesystem and storage management.
//!
//! Provides the virtiofs daemon implementation for sharing host directories with the VM.

use crate::config::{Access, Share};
use std::path::{Path, PathBuf};
#[cfg(not(feature = "experiment-fuse"))]
use std::process::Stdio;
#[cfg(not(feature = "experiment-fuse"))]
use tokio::process::{Child, Command};

#[cfg(feature = "experiment-fuse")]
#[path = "fs_in_process.rs"]
mod fs_in_process;

/// A running virtiofs daemon instance.
#[derive(Debug)]
#[non_exhaustive]
pub struct VirtioFsDaemon {
    /// The path to the vhost-user socket.
    pub socket_path: PathBuf,
    #[cfg(not(feature = "experiment-fuse"))]
    process: Child,
    #[cfg(feature = "experiment-fuse")]
    #[allow(dead_code)]
    handle: Option<std::thread::JoinHandle<()>>,
}

impl VirtioFsDaemon {
    /// Starts a virtiofs daemon (using the standalone `virtiofsd` binary) for the given share.
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
            .arg("--sandbox=none");

        if let Access::ReadOnly = share.access {
            cmd.arg("--readonly");
        }

        cmd.stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit());

        let process = cmd
            .spawn()
            .map_err(|e| crate::error::Error::Other(format!("failed to spawn virtiofsd: {}", e)))?;

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
            return Err(crate::error::Error::Other("virtiofsd failed to create socket".to_string()));
        }

        Ok(Self {
            socket_path,
            #[cfg(not(feature = "experiment-fuse"))]
            process,
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
        let handle = fs_in_process::backend::start_in_process_virtiofsd(
            &socket_path,
            &share.host_path,
            read_only,
        )
        .map_err(|e| {
            crate::error::Error::Other(format!("failed to start in-process virtiofsd: {}", e))
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
            return Err(crate::error::Error::Other("in-process virtiofsd failed to create socket".to_string()));
        }

        Ok(Self {
            socket_path,
            handle: Some(handle),
        })
    }
}

impl Drop for VirtioFsDaemon {
    fn drop(&mut self) {
        #[cfg(not(feature = "experiment-fuse"))]
        let _ = self.process.start_kill();
        let _ = std::fs::remove_file(&self.socket_path);
    }
}
