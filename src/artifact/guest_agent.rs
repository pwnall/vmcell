use crate::artifact::{CacheKey, Stage, StageInputs, StageOutputs};
use crate::error::{Error, Result};
use async_trait::async_trait;
use std::path::Path;

/// A pipeline stage that builds the guest agent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestAgentStage {}

#[async_trait]
impl Stage for GuestAgentStage {
    fn name(&self) -> &str {
        "guest_agent"
    }

    fn out_path(&self, target_dir: &Path) -> std::path::PathBuf {
        target_dir.join("guest_agent")
    }

    fn cache_key(&self, inputs: &StageInputs) -> CacheKey {
        // Bump when this stage's build logic changes so a stale agent is not served.
        const STAGE_VERSION: u32 = 1;
        let mut hasher = blake3::Hasher::new();
        hasher.update(&STAGE_VERSION.to_le_bytes());
        hasher.update(
            inputs
                .pins
                .get("guest_agent_src_hash")
                .map(|s| s.as_bytes())
                .unwrap_or_default(),
        );
        CacheKey(format!("guest-agent-{}", hasher.finalize().to_hex()))
    }

    async fn run(&self, _inputs: &StageInputs, out: &Path) -> Result<StageOutputs> {
        let build_status = tokio::process::Command::new("cargo")
            .env("RUSTFLAGS", "-C target-feature=+crt-static")
            .arg("build")
            .arg("--release")
            .arg("--target")
            .arg("x86_64-unknown-linux-gnu")
            .arg("--bin")
            .arg("vmcell-guest-agent")
            .arg("--features")
            .arg("agent")
            .status()
            .await?;
        if !build_status.success() {
            return Err(Error::Subprocess(
                "Failed to build vmcell-guest-agent".into(),
            ));
        }

        let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());
        let target_dir = std::env::var("CARGO_TARGET_DIR")
            .unwrap_or_else(|_| format!("{}/target", manifest_dir));
        let agent_path = std::path::PathBuf::from(target_dir)
            .join("x86_64-unknown-linux-gnu/release/vmcell-guest-agent");

        tokio::fs::copy(agent_path, out).await.map_err(Error::Io)?;

        let mut outputs = StageOutputs::default();
        outputs
            .artifacts
            .insert("guest_agent".into(), out.to_path_buf());
        Ok(outputs)
    }
}
