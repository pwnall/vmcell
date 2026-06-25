use crate::agent::ExecRequest;
use crate::artifact::{StageInputs, StageOutputs};
use crate::config::{Access, CachePolicy, Egress, NetConfig, RootfsSource, Share, VmConfig};
use crate::error::{Error, Result};
use crate::orchestrator::{TestVm, VmidAllocator};
use crate::vmm::{CidAllocator, cloud_hypervisor::CloudHypervisor};
use std::path::Path;

use std::time::Duration;

/// Builds a root filesystem using mmdebstrap inside a builder micro-VM.
///
/// # Errors
/// Returns an error if the VM boot or mmdebstrap process fails.
pub async fn build_rootfs(release: &str, inputs: &StageInputs, out: &Path) -> Result<StageOutputs> {
    let vmlinux_path = inputs
        .artifacts
        .get("kernel")
        .ok_or_else(|| Error::Artifact("kernel artifact is required to boot builder VM".into()))?;

    let temp_dir = tempfile::TempDir::new().map_err(Error::Io)?;
    let builder_rootfs_path = temp_dir.path().join("builder_rootfs.erofs");

    // 1. Build builder rootfs using OCI source
    tracing::info!("Building builder VM rootfs...");
    super::oci::build_rootfs(
        "docker.io/library/debian",
        "sha256:a617c1cdde36a7e0194b2f07dff669e1753c03c3205356b94f9f350b0f9a57d1",
        inputs,
        &builder_rootfs_path,
    )
    .await?;

    // 2. Start builder VM
    let ch_bin = std::env::var("IMP_CH_BIN").unwrap_or_else(|_| "cloud-hypervisor".to_string());
    let vmm = CloudHypervisor::new(ch_bin);
    let cid_alloc = CidAllocator::new();
    let vmid_alloc = VmidAllocator::new();

    let host_out_dir = tempfile::TempDir::new().map_err(Error::Io)?;
    let share = Share::new(
        "imp-out",
        host_out_dir.path().to_path_buf(),
        Access::ReadWrite,
        CachePolicy::Never,
    );

    let cfg = VmConfig::builder(
        vmlinux_path.clone(),
        RootfsSource::Erofs {
            image: builder_rootfs_path,
        },
    )
    .with_share(share)
    .net(NetConfig::Rootless {
        egress: Egress::Open,
        host_services_port: None,
    })
    .build()?;

    tracing::info!("Starting builder VM...");
    let mut vm = TestVm::start(&vmm, cfg, &cid_alloc, vmid_alloc).await?;

    // Use a helper scope to ensure vm is shutdown on error
    let build_res = async {
        tracing::info!("Connecting to builder VM agent...");
        let agent = vm.agent(None).await?;

        // 3. Install mmdebstrap in VM
        tracing::info!("Installing mmdebstrap inside builder VM...");
        let outcome_update = agent
            .exec(ExecRequest {
                argv: vec!["apt-get".to_string(), "update".to_string()],
                env: vec![],
                cwd: None,
                timeout: Some(Duration::from_secs(120)),
            })
            .await?;
        if outcome_update.code != 0 {
            return Err(Error::Artifact(format!(
                "apt-get update failed with code {}: {}",
                outcome_update.code,
                String::from_utf8_lossy(&outcome_update.stderr)
            )));
        }

        let outcome_install = agent
            .exec(ExecRequest {
                argv: vec![
                    "apt-get".to_string(),
                    "install".to_string(),
                    "-y".to_string(),
                    "mmdebstrap".to_string(),
                    "ca-certificates".to_string(),
                ],
                env: vec![],
                cwd: None,
                timeout: Some(Duration::from_secs(240)),
            })
            .await?;
        if outcome_install.code != 0 {
            return Err(Error::Artifact(format!(
                "apt-get install mmdebstrap failed with code {}: {}",
                outcome_install.code,
                String::from_utf8_lossy(&outcome_install.stderr)
            )));
        }

        // 4. Run mmdebstrap inside builder VM
        tracing::info!("Running mmdebstrap inside builder VM...");
        let outcome_mmdebstrap = agent
            .exec(ExecRequest {
                argv: vec![
                    "mmdebstrap".to_string(),
                    "--variant=apt".to_string(),
                    "--include=curl,ca-certificates".to_string(),
                    release.to_string(),
                    "/imp-out/rootfs.tar".to_string(),
                ],
                env: vec![],
                cwd: None,
                timeout: Some(Duration::from_secs(600)),
            })
            .await?;
        if outcome_mmdebstrap.code != 0 {
            return Err(Error::Artifact(format!(
                "mmdebstrap inside VM failed with code {}: {}",
                outcome_mmdebstrap.code,
                String::from_utf8_lossy(&outcome_mmdebstrap.stderr)
            )));
        }

        Ok(())
    }
    .await;

    // Shutdown builder VM
    tracing::info!("Shutting down builder VM...");
    let _ = vm.shutdown().await;

    build_res?;

    // 5. Pack target EROFS from the generated tarball
    let tar_path = host_out_dir.path().join("rootfs.tar");
    if !tar_path.exists() {
        return Err(Error::Artifact(
            "mmdebstrap succeeded but rootfs.tar is missing".into(),
        ));
    }

    let tar_file = std::fs::File::open(&tar_path).map_err(Error::Io)?;
    let tar_stream: Box<dyn std::io::Read + Send> = Box::new(tar_file);

    super::pack_erofs_with_injection(vec![tar_stream], inputs, out).await
}
