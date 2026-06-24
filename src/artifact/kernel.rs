//! Kernel artifact building.
//!
//! This module provides the `KernelStage` pipeline step, which downloads
//! and compiles a custom Linux kernel for the virtual machines.

use crate::artifact::{CacheKey, Stage, StageInputs, StageOutputs};
use crate::error::{Error, Result};
use std::path::Path;
use tokio::process::Command;

/// A pipeline stage that builds a Linux kernel image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelStage {
    /// URL to download the kernel source tarball from.
    pub kernel_source_url: String,
    /// Custom configuration snippet to append to the kernel config.
    pub microvm_config: String,
}

use async_trait::async_trait;

#[async_trait]
impl Stage for KernelStage {
    fn name(&self) -> &str {
        "kernel"
    }

    fn cache_key(&self, _inputs: &StageInputs) -> CacheKey {
        let mut hasher = blake3::Hasher::new();
        hasher.update(self.kernel_source_url.as_bytes());
        hasher.update(self.microvm_config.as_bytes());
        CacheKey(format!("kernel-{}", hasher.finalize().to_hex()))
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
        current_config.push('\n');
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kernel_cache_key() {
        let stage1 = KernelStage {
            kernel_source_url: "https://example.com/kernel".to_string(),
            microvm_config: "CONFIG_FOO=y\n".to_string(),
        };

        let mut stage2 = stage1.clone();
        stage2.microvm_config = "CONFIG_FOO=n\n".to_string();

        let inputs = StageInputs {};
        assert_ne!(stage1.cache_key(&inputs), stage2.cache_key(&inputs));
        assert_eq!(stage1.cache_key(&inputs), stage1.cache_key(&inputs));
    }
}
