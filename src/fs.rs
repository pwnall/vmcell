use crate::config::{Access, Share};
use std::path::{Path, PathBuf};
#[cfg(not(feature = "experiment-fuse"))]
use tokio::process::{Child, Command};

#[cfg(feature = "experiment-fuse")]
#[path = "fs_in_process.rs"]
mod fs_in_process;

pub struct VirtioFsDaemon {
    pub socket_path: PathBuf,
    #[cfg(not(feature = "experiment-fuse"))]
    process: Child,
    #[cfg(feature = "experiment-fuse")]
    handle: Option<std::thread::JoinHandle<()>>,
}

impl VirtioFsDaemon {
    #[cfg(not(feature = "experiment-fuse"))]
    pub async fn start(share: &Share, vm_tmp: &Path) -> crate::error::Result<Self> {
        let socket_path = vm_tmp.join(format!("{}.sock", share.tag));

        let mut cmd = Command::new("virtiofsd");
        cmd.arg("--socket-path")
            .arg(&socket_path)
            .arg("--shared-dir")
            .arg(&share.host_path)
            .arg("--cache=never")
            .arg("--sandbox=none");

        if let Access::ReadOnly = share.access {
            cmd.arg("--read-only");
        }

        cmd.stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());

        let process = cmd
            .spawn()
            .map_err(|e| crate::error::Error::Other(format!("failed to spawn virtiofsd: {}", e)))?;

        // Wait for socket to be created
        for _ in 0..50 {
            if socket_path.exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }

        Ok(Self {
            socket_path,
            #[cfg(not(feature = "experiment-fuse"))]
            process,
        })
    }

    #[cfg(feature = "experiment-fuse")]
    pub async fn start(share: &Share, vm_tmp: &Path) -> crate::error::Result<Self> {
        let socket_path = vm_tmp.join(format!("{}.sock", share.tag));
        let read_only = matches!(share.access, Access::ReadOnly);
        let handle = fs_in_process::backend::start_in_process_virtiofsd(
            &socket_path,
            &share.host_path,
            read_only
        ).map_err(|e| crate::error::Error::Other(format!("failed to start in-process virtiofsd: {}", e)))?;

        // Wait for socket to be created
        for _ in 0..50 {
            if socket_path.exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
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
