//! Root filesystem artifact building.
//!
//! This module provides the `RootfsStage` pipeline step, which creates a
//! minimal root filesystem for the virtual machines. It supports building
//! via OCI registry pull or by running mmdebstrap inside a micro-VM.

use crate::artifact::{CacheKey, Stage, StageInputs, StageOutputs};
use crate::error::{Error, Result};
use std::path::{Path, PathBuf};
use async_trait::async_trait;
use std::io::Read;

/// mmdebstrap micro-VM builder source.
pub mod mmdebstrap;
/// OCI registry pull source.
pub mod oci;

/// Root filesystem construction source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RootfsBuildSource {
    /// OCI registry pull source.
    Oci {
        /// The image to pull (e.g. `debian`).
        image: String,
        /// The pinned digest of the image.
        digest: String,
    },
    /// Full-apt source running mmdebstrap on the host.
    Mmdebstrap {
        /// The Debian release suite to use (e.g., "bookworm").
        release: String,
    },
}

/// A pipeline stage that builds a root filesystem.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootfsStage {
    /// The source method to build the root filesystem.
    pub source: RootfsBuildSource,
}

#[async_trait]
impl Stage for RootfsStage {
    fn name(&self) -> &str {
        "rootfs"
    }

    fn cache_key(&self, inputs: &StageInputs) -> CacheKey {
        match &self.source {
            RootfsBuildSource::Oci { image, digest } => {
                CacheKey(format!("rootfs-oci-{}-{}", image, digest))
            }
            RootfsBuildSource::Mmdebstrap { release } => {
                CacheKey(format!("rootfs-mmdebstrap-{}-{}", release, inputs.artifacts.len()))
            }
        }
    }

    async fn run(&self, inputs: &StageInputs, out: &Path) -> Result<StageOutputs> {
        let build_status = tokio::process::Command::new("cargo")
            .env("RUSTFLAGS", "-C target-feature=+crt-static")
            .arg("build")
            .arg("--release")
            .arg("--target")
            .arg("x86_64-unknown-linux-gnu")
            .arg("--bin")
            .arg("imp-guest-agent")
            .arg("--features")
            .arg("agent")
            .status()
            .await?;
        if !build_status.success() {
            return Err(Error::Subprocess("Failed to build imp-guest-agent".into()));
        }

        match &self.source {
            RootfsBuildSource::Oci { image, digest } => {
                oci::build_rootfs(image, digest, out).await
            }
            RootfsBuildSource::Mmdebstrap { release } => {
                mmdebstrap::build_rootfs(release, inputs, out).await
            }
        }
    }
}

/// Shared logic to take a list of tar streams, inject the agent and CA, and pack it into erofs.
#[cfg(feature = "am-fs-erofs")]
pub async fn pack_erofs_with_injection(
    tar_streams: Vec<Box<dyn Read + Send>>,
    out: &Path,
) -> Result<StageOutputs> {
    let out_buf = out.to_path_buf();
    
    // Inject agent and CA
    let mut injected_files = vec![
        ("usr/sbin/imp-guest-agent", Path::new("target/x86_64-unknown-linux-gnu/release/imp-guest-agent")),
    ];
    
    #[cfg(feature = "proxy")]
    let _ca_mgr = crate::proxy::tls::CaManager::new()?;
    #[cfg(feature = "proxy")]
    injected_files.push(("usr/local/share/ca-certificates/imp-ca.crt", Path::new("/tmp/imp-artifacts/ca.pem")));

    tokio::task::spawn_blocking(move || -> Result<StageOutputs> {
        let archives: Vec<tar::Archive<Box<dyn Read + Send>>> = tar_streams.into_iter().map(tar::Archive::new).collect();
        let image = crate::artifact::tar2erofs::tar_to_erofs(archives, injected_files)?;
        std::fs::write(&out_buf, image).map_err(|e| Error::Artifact(e.to_string()))?;
        let mut outputs = StageOutputs::default();
        outputs.artifacts.insert("rootfs".into(), out_buf);
        Ok(outputs)
    }).await.map_err(|e| Error::Artifact(e.to_string()))?
}

/// Shared logic to take a tar stream, inject the agent and CA, and pack it into erofs.
#[cfg(not(feature = "am-fs-erofs"))]
pub async fn pack_erofs_with_injection(
    _tar_streams: Vec<Box<dyn Read + Send>>,
    _out: &Path,
) -> Result<StageOutputs> {
    // mkfs.erofs fallback requires extracting the tar to a directory, adding the files,
    // and running mkfs.erofs. We assume am-fs-erofs is used for now.
    Err(Error::Artifact("am-fs-erofs feature is required for rootfs building".into()))
}
