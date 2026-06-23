use crate::artifact::{CacheKey, Stage, StageInputs, StageOutputs};
use crate::error::{Error, Result};
use std::path::Path;
use tokio::process::Command;

pub struct RootfsStage {
    pub release: String,
}

use async_trait::async_trait;

#[async_trait]
impl Stage for RootfsStage {
    fn name(&self) -> &str {
        "rootfs"
    }

    fn cache_key(&self, _inputs: &StageInputs) -> CacheKey {
        CacheKey(format!("rootfs-{}", self.release))
    }

    async fn run(&self, _inputs: &StageInputs, out: &Path) -> Result<StageOutputs> {
        let sh_target = std::fs::read_link("/bin/sh").unwrap_or_default();
        if !sh_target.to_string_lossy().ends_with("bash") {
            return Err(Error::Other(format!(
                "Rootfs building uses mmdebstrap, which has a hard-coded assumption that /bin/sh points to bash. Currently, /bin/sh points to {:?}. Please reconfigure your system (e.g., via `sudo dpkg-reconfigure dash` on Ubuntu) to use bash as the default system shell.",
                sh_target
            )));
        }

        let build_status = Command::new("cargo")
            .arg("build")
            .arg("--release")
            .arg("--bin")
            .arg("imp-guest-agent")
            .arg("--features")
            .arg("agent")
            .status()
            .await?;
        if !build_status.success() {
            return Err(Error::Other("Failed to build imp-guest-agent".into()));
        }

        #[cfg(not(feature = "experiment-erofs"))]
        let (status, mkfs_status, stderr_str) = {
            let mut mmdebstrap = Command::new("mmdebstrap")
                .arg("--variant=minbase")
                .arg("--include=systemd-sysv,iproute2,curl,python3")
                .arg("--customize-hook=copy-in target/release/imp-guest-agent /sbin/")
                .arg(&self.release)
                .arg("-")
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()?;

            let mmdebstrap_stdout: std::process::Stdio =
                mmdebstrap.stdout.take().unwrap().try_into().unwrap();

            let mut mkfs = Command::new("mkfs.erofs")
                .arg("--tar=f")
                .arg(out)
                .stdin(mmdebstrap_stdout)
                .spawn()?;

            let mut stderr_str = String::new();
            if let Some(mut stderr) = mmdebstrap.stderr.take() {
                tokio::io::AsyncReadExt::read_to_string(&mut stderr, &mut stderr_str).await?;
            }

            let mkfs_status = mkfs.wait().await?;
            let status = mmdebstrap.wait().await?;
            (status, mkfs_status, stderr_str)
        };

        #[cfg(feature = "experiment-erofs")]
        let (status, mkfs_status, stderr_str) = {
            let release = self.release.clone();
            let out = out.to_path_buf();
            tokio::task::spawn_blocking(move || -> crate::error::Result<_> {
                let mut mmdebstrap = std::process::Command::new("mmdebstrap")
                    .arg("--variant=minbase")
                    .arg("--include=systemd-sysv,iproute2,curl,python3")
                    .arg("--customize-hook=copy-in target/release/imp-guest-agent /sbin/")
                    .arg(&release)
                    .arg("-")
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::piped())
                    .spawn()
                    .map_err(|e| crate::error::Error::Other(e.to_string()))?;

                let stdout = mmdebstrap.stdout.take().unwrap();
                
                let archive = tar::Archive::new(stdout);
                let image = crate::artifact::tar2erofs::tar_to_erofs(archive)?;
                std::fs::write(out, image).map_err(|e| crate::error::Error::Other(e.to_string()))?;

                let mut stderr_str = String::new();
                if let Some(mut stderr) = mmdebstrap.stderr.take() {
                    use std::io::Read;
                    stderr.read_to_string(&mut stderr_str).ok();
                }

                let status = mmdebstrap.wait().map_err(|e| crate::error::Error::Other(e.to_string()))?;
                let mkfs_status = std::process::Command::new("true").status().unwrap();
                Ok((status, mkfs_status, stderr_str))
            }).await.map_err(|e| crate::error::Error::Other(e.to_string()))??
        };

        if !status.success() || !mkfs_status.success() {
            eprintln!("mmdebstrap stderr:\n{}", stderr_str);
            return Err(Error::Other("mmdebstrap or mkfs.erofs failed".into()));
        }

        Ok(StageOutputs {})
    }
}
