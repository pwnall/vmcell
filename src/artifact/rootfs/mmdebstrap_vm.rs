use crate::error::{Error, Result};
use crate::artifact::{StageInputs, StageOutputs};
use std::path::Path;
use std::sync::Arc;
use tempfile::TempDir;

/// Builds a root filesystem using mmdebstrap inside a micro-VM.
pub async fn build_rootfs(release: &str, inputs: &StageInputs, out: &Path) -> Result<StageOutputs> {
    let kernel = inputs
        .artifacts
        .get("kernel")
        .ok_or_else(|| Error::Artifact("Missing kernel for builder VM".into()))?;

    // Create a temporary directory for our artifacts (OCI rootfs, and output tar)
    let temp_dir = TempDir::new().map_err(|e| Error::Io(e))?;
    let builder_rootfs_path = temp_dir.path().join("builder_rootfs.erofs");
    let out_dir = temp_dir.path().join("imp-out");
    std::fs::create_dir_all(&out_dir).map_err(|e| Error::Io(e))?;

    // 1. Build a temporary builder rootfs using OCI
    super::oci::build_rootfs("docker.io/library/debian", "trixie-slim", &builder_rootfs_path).await?;

    // 2. Set up the orchestrator objects
    let vmm = crate::vmm::cloud_hypervisor::CloudHypervisor::new("cloud-hypervisor");
    let cid_alloc = crate::vmm::CidAllocator::new();
    let vmid_alloc = Arc::new(crate::orchestrator::VmidAllocator::new());

    // 3. Configure the VM
    let cfg = crate::config::VmConfig::builder(
        kernel.clone(),
        crate::config::RootfsSource::Erofs { image: builder_rootfs_path },
    )
    .vcpus(4) // Need some power for mmdebstrap
    .mem_mib(2048)
    .net(crate::config::NetConfig::Rootless {
        egress: crate::config::Egress::Open,
        host_services: false,
    })
    .with_share(crate::config::Share::new(
        "imp-out",
        out_dir.clone(),
        crate::config::Access::ReadWrite,
        crate::config::CachePolicy::Auto,
    ))
    .build()?;

    // 4. Start the VM
    let mut vm = crate::orchestrator::TestVm::start(&vmm, cfg, &cid_alloc, vmid_alloc).await?;

    // 5. Connect to the guest agent
    let agent = vm.agent().await?;

    // 6. Run commands in the guest
    // Create the mount point and mount the virtiofs share
    let mount_req = crate::agent::ExecRequest {
        argv: vec![
            "/bin/sh".into(),
            "-c".into(),
            "mkdir -p /tmp/imp-out && mount -t virtiofs imp-out /tmp/imp-out".into(),
        ],
        env: vec![],
        cwd: None,
    };
    let mount_out = agent.exec(mount_req).await?;
    if mount_out.code != 0 {
        return Err(Error::Artifact(format!(
            "Failed to mount imp-out: {}",
            String::from_utf8_lossy(&mount_out.stderr)
        )));
    }

    // Update apt, install mmdebstrap, and run it
    let run_cmd = format!(
        "apt-get update && apt-get install -y mmdebstrap && mmdebstrap {} /tmp/imp-out/rootfs.tar",
        release
    );
    let run_req = crate::agent::ExecRequest {
        argv: vec!["/bin/sh".into(), "-c".into(), run_cmd],
        env: vec![],
        cwd: None,
    };
    let run_out = agent.exec(run_req).await?;
    if run_out.code != 0 {
        return Err(Error::Artifact(format!(
            "Failed to run mmdebstrap: stdout: {}\nstderr: {}",
            String::from_utf8_lossy(&run_out.stdout),
            String::from_utf8_lossy(&run_out.stderr)
        )));
    }

    // 7. Shutdown the VM
    vm.shutdown().await?;

    // 8. Stream the output tarball through the injection packing logic
    let tar_path = out_dir.join("rootfs.tar");
    if !tar_path.exists() {
        return Err(Error::Artifact("mmdebstrap succeeded but rootfs.tar is missing".into()));
    }

    let tar_file = std::fs::File::open(tar_path).map_err(|e| Error::Io(e))?;
    let streams: Vec<Box<dyn std::io::Read + Send>> = vec![Box::new(tar_file)];

    super::pack_erofs_with_injection(streams, out).await
}
