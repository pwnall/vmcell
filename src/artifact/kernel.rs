//! Kernel artifact building.
//!
//! This module provides the `KernelStage` pipeline step, which downloads
//! and compiles a custom Linux kernel for the virtual machines.

use crate::artifact::{CacheKey, Stage, StageInputs, StageOutputs};
use crate::error::{Error, Result};
use std::path::Path;
use tokio::process::Command;

/// Interface for HTTP operations.
#[async_trait]
pub trait HttpClient: Send + Sync {
    /// Perform an HTTP GET request.
    async fn get(&self, url: &str) -> Result<Vec<u8>>;
}

/// A reqwest-based HTTP client.
pub struct ReqwestClient;
#[async_trait]
impl HttpClient for ReqwestClient {
    async fn get(&self, url: &str) -> Result<Vec<u8>> {
        let response = reqwest::get(url)
            .await
            .map_err(|e| Error::Artifact(format!("Failed to download: {}", e)))?;
        if !response.status().is_success() {
            return Err(Error::Artifact(format!(
                "Failed to download: status {}",
                response.status()
            )));
        }
        let bytes = response
            .bytes()
            .await
            .map_err(|e| Error::Artifact(format!("Failed to read: {}", e)))?;
        Ok(bytes.to_vec())
    }
}

/// A pipeline stage that builds a Linux kernel image.
pub struct KernelStage {
    /// The HTTP client to use for downloading the kernel source.
    pub http_client: std::sync::Arc<dyn HttpClient>,
}

use async_trait::async_trait;

#[async_trait]
impl Stage for KernelStage {
    fn name(&self) -> &str {
        "kernel"
    }

    fn out_path(&self, target_dir: &Path) -> std::path::PathBuf {
        target_dir.join("vmlinux")
    }

    fn cache_key(&self, inputs: &StageInputs) -> CacheKey {
        let mut hasher = blake3::Hasher::new();
        hasher.update(
            inputs
                .pins
                .get("kernel_source_url")
                .map(|s| s.as_bytes())
                .unwrap_or_default(),
        );
        hasher.update(
            inputs
                .pins
                .get("kernel_source_sha256")
                .map(|s| s.as_bytes())
                .unwrap_or_default(),
        );
        hasher.update(
            inputs
                .pins
                .get("kernel_microvm_config")
                .map(|s| s.as_bytes())
                .unwrap_or_default(),
        );
        CacheKey(format!("kernel-{}", hasher.finalize().to_hex()))
    }

    async fn run(&self, inputs: &StageInputs, out: &Path) -> Result<StageOutputs> {
        let kernel_source_url = inputs
            .pins
            .get("kernel_source_url")
            .ok_or_else(|| Error::Artifact("Missing kernel_source_url pin".into()))?;
        let kernel_source_sha256 = inputs
            .pins
            .get("kernel_source_sha256")
            .ok_or_else(|| Error::Artifact("Missing kernel_source_sha256 pin".into()))?;
        let microvm_config = inputs
            .pins
            .get("kernel_microvm_config")
            .ok_or_else(|| Error::Artifact("Missing kernel_microvm_config pin".into()))?;

        let workdir = out.parent().unwrap_or(Path::new(".")).join("kernel-build");
        tokio::fs::create_dir_all(&workdir).await?;

        let tarball = workdir.join("linux.tar.xz");

        if !tarball.exists() {
            let bytes = self.http_client.get(kernel_source_url).await?;
            tokio::fs::write(&tarball, bytes).await?;
        }

        // Verify SHA256 of the tarball
        let tarball_bytes = tokio::fs::read(&tarball).await?;
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.update(&tarball_bytes);
        let hash = format!("{:x}", hasher.finalize());
        if &hash != kernel_source_sha256 {
            return Err(Error::Artifact(format!(
                "Kernel source tarball hash mismatch: expected {}, got {}",
                kernel_source_sha256, hash
            )));
        }

        // We assume we need to extract if the Makefile doesn't exist
        if !workdir.join("Makefile").exists() {
            let tarball_path = tarball.clone();
            let workdir_path = workdir.clone();
            tokio::task::spawn_blocking(move || -> Result<()> {
                let tar_uncompressed_path = workdir_path.join("linux.tar");
                if !tar_uncompressed_path.exists() {
                    let xz_file = std::fs::File::open(&tarball_path)?;
                    let mut tar_file = std::fs::File::create(&tar_uncompressed_path)?;
                    lzma_rs::xz_decompress(&mut std::io::BufReader::new(xz_file), &mut tar_file)
                        .map_err(|e| Error::Artifact(format!("Decompression failed: {:?}", e)))?;
                }

                let tar_file_read = std::fs::File::open(&tar_uncompressed_path)?;
                let mut archive = tar::Archive::new(tar_file_read);
                for entry in archive.entries()? {
                    let mut file = entry?;
                    let path = file.path()?.into_owned();
                    let mut components = path.components();
                    if components.next().is_none() {
                        continue;
                    } // skip first component
                    let stripped_path: std::path::PathBuf = components.collect();
                    if stripped_path.as_os_str().is_empty() {
                        continue;
                    }
                    let out_path = workdir_path.join(stripped_path);

                    if file.header().entry_type() == tar::EntryType::Directory {
                        std::fs::create_dir_all(&out_path)?;
                    } else {
                        if let Some(parent) = out_path.parent() {
                            std::fs::create_dir_all(parent)?;
                        }
                        file.unpack(&out_path)?;
                    }
                }

                let _ = std::fs::remove_file(&tar_uncompressed_path);

                Ok(())
            })
            .await
            .expect("spawn_blocking failed")?;
        }

        let status = Command::new("make")
            .current_dir(&workdir)
            .env("HOSTCC", "gcc")
            .arg("defconfig")
            .arg("kvm_guest.config")
            .status()
            .await?;
        if !status.success() {
            return Err(Error::Subprocess(
                "Failed to write kernel config fragment".into(),
            ));
        }

        let config_path = workdir.join(".config");
        // Append our specific config on top
        let mut current_config = tokio::fs::read_to_string(&config_path).await?;
        current_config.push('\n');
        current_config.push_str(microvm_config);
        tokio::fs::write(&config_path, current_config).await?;

        let status = Command::new("make")
            .current_dir(&workdir)
            .env("HOSTCC", "gcc")
            .arg("olddefconfig")
            .status()
            .await?;
        if !status.success() {
            return Err(Error::Subprocess("make olddefconfig failed".into()));
        }

        let nproc = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);
        let status = Command::new("make")
            .current_dir(&workdir)
            .env("CC", "gcc")
            .env("HOSTCC", "gcc")
            .arg("-j")
            .arg(nproc.to_string())
            .arg("vmlinux")
            .status()
            .await?;
        if !status.success() {
            return Err(Error::Subprocess("make vmlinux failed".into()));
        }

        tokio::fs::copy(workdir.join("vmlinux"), out).await?;

        Ok(StageOutputs::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kernel_cache_key() {
        let stage = KernelStage {
            http_client: std::sync::Arc::new(ReqwestClient),
        };

        let mut inputs1 = StageInputs::default();
        inputs1.pins.insert(
            "kernel_source_url".into(),
            "https://example.com/kernel".into(),
        );
        inputs1
            .pins
            .insert("kernel_source_sha256".into(), "dummy".into());
        inputs1
            .pins
            .insert("kernel_microvm_config".into(), "CONFIG_FOO=y\n".into());

        let mut inputs2 = inputs1.clone();
        inputs2
            .pins
            .insert("kernel_microvm_config".into(), "CONFIG_FOO=n\n".into());

        let mut inputs3 = inputs1.clone();
        inputs3
            .pins
            .insert("kernel_source_sha256".into(), "dummy2".into());

        assert_ne!(stage.cache_key(&inputs1), stage.cache_key(&inputs2));
        assert_ne!(stage.cache_key(&inputs1), stage.cache_key(&inputs3));
        assert_eq!(stage.cache_key(&inputs1), stage.cache_key(&inputs1));
    }
}
