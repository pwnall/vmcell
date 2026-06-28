use crate::artifact::{CacheKey, Stage, StageInputs, StageOutputs};
use crate::error::{Error, Result};
use async_trait::async_trait;
use std::path::Path;

/// A pipeline stage that builds the guest **test-helper** binary
/// (`imp-guest-tools`: the `ip`/`curl`/`kvm-ok` stand-ins), which is then baked
/// into the rootfs by [`crate::artifact::rootfs`].
///
/// Baking (rather than a virtio-fs share) is what lets the rootless egress test
/// use the tools: virtiofsd cannot enter its `--sandbox namespace` without
/// privileges, so a share would fail unprivileged, whereas the erofs rootfs is
/// served over virtio-blk in both modes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestToolsStage {}

#[async_trait]
impl Stage for GuestToolsStage {
    fn name(&self) -> &str {
        "guest_tools"
    }

    fn out_path(&self, target_dir: &Path) -> std::path::PathBuf {
        target_dir.join("guest_tools")
    }

    fn cache_key(&self, _inputs: &StageInputs) -> CacheKey {
        // Bump when this stage's build logic changes so a stale helper is not served.
        const STAGE_VERSION: u32 = 1;
        let mut hasher = blake3::Hasher::new();
        hasher.update(&STAGE_VERSION.to_le_bytes());
        // Fold the helper's source so a change rebuilds it — and, transitively
        // (via the rootfs stage's content hash of this artifact), re-bakes the
        // rootfs. Self-contained (the helper does not depend on the lib crate).
        let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());
        let src = std::path::Path::new(&manifest_dir).join("src/bin/imp-guest-tools.rs");
        if let Ok(content) = std::fs::read(&src) {
            hasher.update(&content);
        }
        CacheKey(format!("guest-tools-{}", hasher.finalize().to_hex()))
    }

    async fn run(&self, _inputs: &StageInputs, out: &Path) -> Result<StageOutputs> {
        // Built dynamically (no crt-static): the helper links reqwest/rustls
        // (aws-lc-rs C code) which does not link cleanly fully-static, and the
        // Debian rootfs ships glibc, so a dynamic binary runs there. The helper
        // only talks to the proxy/host by IP, so static-glibc DNS limits never
        // apply.
        let build_status = tokio::process::Command::new("cargo")
            .arg("build")
            .arg("--release")
            .arg("--target")
            .arg("x86_64-unknown-linux-gnu")
            .arg("--bin")
            .arg("imp-guest-tools")
            .arg("--features")
            .arg("guest-tools")
            .status()
            .await?;
        if !build_status.success() {
            return Err(Error::Subprocess("Failed to build imp-guest-tools".into()));
        }

        let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());
        let target_dir = std::env::var("CARGO_TARGET_DIR")
            .unwrap_or_else(|_| format!("{}/target", manifest_dir));
        let tools_path = std::path::PathBuf::from(target_dir)
            .join("x86_64-unknown-linux-gnu/release/imp-guest-tools");

        tokio::fs::copy(tools_path, out).await.map_err(Error::Io)?;

        let mut outputs = StageOutputs::default();
        outputs
            .artifacts
            .insert("guest_tools".into(), out.to_path_buf());
        Ok(outputs)
    }
}
