use crate::artifact::{CacheKey, Stage, StageInputs, StageOutputs};
use crate::error::{Error, Result};
use std::path::Path;
use tokio::process::Command;

pub struct KernelStage {
    pub kernel_source_url: String,
    pub microvm_config: String,
}

use async_trait::async_trait;

#[async_trait]
impl Stage for KernelStage {
    fn name(&self) -> &str {
        "kernel"
    }

    fn cache_key(&self, _inputs: &StageInputs) -> CacheKey {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        self.kernel_source_url.hash(&mut hasher);
        self.microvm_config.hash(&mut hasher);
        CacheKey(format!("kernel-{:x}", hasher.finish()))
    }

    async fn run(&self, _inputs: &StageInputs, out: &Path) -> Result<StageOutputs> {
        let workdir = out.parent().unwrap_or(Path::new(".")).join("kernel-build");
        tokio::fs::create_dir_all(&workdir).await?;

        let tarball = workdir.join("linux.tar.xz");

        if !tarball.exists() {
            let status = Command::new("wget")
                .arg("-O")
                .arg(&tarball)
                .arg(&self.kernel_source_url)
                .status()
                .await?;
            if !status.success() {
                return Err(Error::Other("Failed to download kernel source".into()));
            }
        }

        // We assume we need to extract if the Makefile doesn't exist
        if !workdir.join("Makefile").exists() {
            let status = Command::new("tar")
                .arg("xf")
                .arg(&tarball)
                .arg("-C")
                .arg(&workdir)
                .arg("--strip-components=1")
                .status()
                .await?;
            if !status.success() {
                return Err(Error::Other("Failed to extract kernel source".into()));
            }
        }

        let status = Command::new("make")
            .current_dir(&workdir)
            .arg("HOSTCC=gcc -std=gnu11")
            .arg("defconfig")
            .arg("kvm_guest.config")
            .status()
            .await?;
        if !status.success() {
            return Err(Error::Other(
                "make defconfig kvm_guest.config failed".into(),
            ));
        }

        let config_path = workdir.join(".config");
        // Append our specific config on top
        let mut current_config = tokio::fs::read_to_string(&config_path).await?;
        current_config.push_str("\n");
        current_config.push_str(&self.microvm_config);
        tokio::fs::write(&config_path, current_config).await?;

        let status = Command::new("make")
            .current_dir(&workdir)
            .arg("HOSTCC=gcc -std=gnu11")
            .arg("olddefconfig")
            .status()
            .await?;
        if !status.success() {
            return Err(Error::Other("make olddefconfig failed".into()));
        }

        let nproc = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);
        let status = Command::new("make")
            .current_dir(&workdir)
            .arg("CC=gcc -std=gnu11")
            .arg("HOSTCC=gcc -std=gnu11")
            .arg("-j")
            .arg(nproc.to_string())
            .arg("vmlinux")
            .status()
            .await?;
        if !status.success() {
            return Err(Error::Other("make vmlinux failed".into()));
        }

        tokio::fs::copy(workdir.join("vmlinux"), out).await?;

        Ok(StageOutputs {})
    }
}
