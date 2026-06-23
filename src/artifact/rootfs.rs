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
            return Err(Error::Other(format!("Rootfs building uses mmdebstrap, which has a hard-coded assumption that /bin/sh points to bash. Currently, /bin/sh points to {:?}. Please reconfigure your system (e.g., via `sudo dpkg-reconfigure dash` on Ubuntu) to use bash as the default system shell.", sh_target)));
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

        // Generate rootfs tarball and pipe to mkfs.erofs
        let mut mmdebstrap = Command::new("mmdebstrap")
            .arg("--variant=minbase")
            .arg("--include=systemd-sysv,iproute2")
            .arg("--customize-hook=copy-in target/release/imp-guest-agent /sbin/")
            .arg(&self.release)
            .arg("-")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()?;

        let mmdebstrap_stdout: std::process::Stdio = mmdebstrap.stdout.take().unwrap().try_into().unwrap();

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

        if !status.success() || !mkfs_status.success() {
            eprintln!("mmdebstrap stderr:\n{}", stderr_str);
            return Err(Error::Other("mmdebstrap or mkfs.erofs failed".into()));
        }

        Ok(StageOutputs {})
    }
}
