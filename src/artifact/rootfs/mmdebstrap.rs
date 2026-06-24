use crate::error::{Error, Result};
use crate::artifact::{StageInputs, StageOutputs};
use std::path::Path;

/// Builds a root filesystem using mmdebstrap on the host.
pub async fn build_rootfs(release: &str, _inputs: &StageInputs, out: &Path) -> Result<StageOutputs> {
    let temp_dir = tempfile::TempDir::new().map_err(|e| Error::Io(e))?;
    let tar_path = temp_dir.path().join("rootfs.tar");

    let status = tokio::process::Command::new("mmdebstrap")
        .arg("--variant=apt")
        .arg("--include=curl,ca-certificates")
        .arg(release)
        .arg(&tar_path)
        .status()
        .await
        .map_err(|e| Error::Io(e))?;

    if !status.success() {
        return Err(Error::Artifact(format!("mmdebstrap failed with status {}", status)));
    }

    if !tar_path.exists() {
        return Err(Error::Artifact("mmdebstrap succeeded but rootfs.tar is missing".into()));
    }

    let tar_file = std::fs::File::open(&tar_path).map_err(|e| Error::Io(e))?;
    let tar_stream: Box<dyn std::io::Read + Send> = Box::new(tar_file);

    super::pack_erofs_with_injection(vec![tar_stream], out).await
}
