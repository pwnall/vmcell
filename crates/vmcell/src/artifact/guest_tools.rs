use crate::artifact::{CacheKey, Stage, StageInputs, StageOutputs};
use crate::error::{Error, Result};
use async_trait::async_trait;
use std::path::Path;

/// A pipeline stage that builds the guest **test-helper** binary
/// (`vmcell-guest-tools`: the `ip`/`curl`/`kvm-ok` stand-ins), which is then baked
/// into the rootfs by [`crate::artifact::rootfs`].
///
/// Baking (rather than a virtio-fs share) is what lets the unprivileged egress test
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
        // Bumped to 2 with the Cargo.lock-aware closure hash.
        const STAGE_VERSION: u32 = 2;
        let mut hasher = blake3::Hasher::new();
        hasher.update(&STAGE_VERSION.to_le_bytes());
        // Fold the helper's FULL source closure — its `.rs` source PLUS `Cargo.lock`
        // — so a change rebuilds it and, transitively (via the rootfs stage's content
        // hash of this artifact), re-bakes the rootfs. Folding `Cargo.lock` is what
        // catches a dependency bump: the helper links reqwest/rustls, so a bump
        // changes the BUILT binary while the `.rs` is byte-identical. The old
        // source-only hash missed that and re-served a stale ip/curl/kvm-ok helper.
        match crate::artifact::guest_tools_closure_hash(&crate::artifact::workspace_root()) {
            Ok(h) => hasher.update(h.as_bytes()),
            // A read failure must NOT silently degrade to a stable, content-blind key
            // that hits a stale cache (the old `if let Ok(content)` swallow). Fold the
            // error so the key cannot collide with a good one; the resulting cache miss
            // drives `run()`, which recomputes via the same Result helper and fails hard
            // with the real cause.
            Err(e) => hasher.update(format!("guest-tools-closure-error:{e}").as_bytes()),
        };
        CacheKey(format!("guest-tools-{}", hasher.finalize().to_hex()))
    }

    async fn run(&self, _inputs: &StageInputs, out: &Path) -> Result<StageOutputs> {
        // v15 workspace: the helper is its own member crate, built by `-p` from the
        // workspace root into the shared workspace `target/`.
        let ws_root = crate::artifact::workspace_root();
        // Fail hard if the helper's source closure (`.rs` source + `Cargo.lock`) is
        // unreadable — never silently build and serve a stale helper. Mirrors the
        // steward stage's run()-side hard stop; the returned hash is needed only
        // for its error effect here.
        crate::artifact::guest_tools_closure_hash(&ws_root)?;

        // Built dynamically (no crt-static): the helper links reqwest/rustls
        // (aws-lc-rs C code) which does not link cleanly fully-static, and the
        // Debian rootfs ships glibc, so a dynamic binary runs there. The helper
        // only talks to the proxy/host by IP, so static-glibc DNS limits never
        // apply.
        let build_status = tokio::process::Command::new("cargo")
            .current_dir(&ws_root)
            .arg("build")
            .arg("--release")
            .arg("--target")
            .arg("x86_64-unknown-linux-gnu")
            .arg("-p")
            .arg("vmcell-guest-tools")
            .status()
            .await?;
        if !build_status.success() {
            return Err(Error::Subprocess(
                "Failed to build vmcell-guest-tools".into(),
            ));
        }

        let target_dir = std::env::var("CARGO_TARGET_DIR")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|_| ws_root.join("target"));
        let tools_path = target_dir.join("x86_64-unknown-linux-gnu/release/vmcell-guest-tools");

        tokio::fs::copy(tools_path, out).await.map_err(Error::Io)?;

        let mut outputs = StageOutputs::default();
        outputs
            .artifacts
            .insert("guest_tools".into(), out.to_path_buf());
        Ok(outputs)
    }
}
