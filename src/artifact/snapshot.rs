//! Virtual machine snapshot artifact building.
//!
//! This module provides the `SnapshotStage` pipeline step, which boots a VM
//! to its ready state and takes a memory snapshot to enable fast booting later.

use crate::agent::protocol::ExecRequest;
use crate::artifact::{CacheKey, Stage, StageInputs, StageOutputs};
use crate::config::{RootfsSource, VmConfig};
use crate::error::Result;
use crate::orchestrator::TestVm;
use crate::vmm::VmInstance;
use crate::vmm::cloud_hypervisor::CloudHypervisor;
use std::path::Path;

/// A pipeline stage that creates a base VM snapshot for fast booting.
pub struct SnapshotStage {
    /// The CID allocator for VMs run by this stage.
    pub cid_alloc: std::sync::Arc<crate::vmm::CidAllocator>,
    /// The VMID allocator for VMs run by this stage.
    pub vmid_alloc: crate::orchestrator::VmidAllocator,
}

use async_trait::async_trait;

#[async_trait]
impl Stage for SnapshotStage {
    fn name(&self) -> &str {
        "snapshot"
    }

    fn out_path(&self, target_dir: &Path) -> std::path::PathBuf {
        target_dir.join("snapshot")
    }

    fn cache_key(&self, inputs: &StageInputs) -> CacheKey {
        let mut hasher = blake3::Hasher::new();
        for (k, v) in &inputs.artifacts {
            hasher.update(k.as_bytes());
            hasher.update(v.to_string_lossy().as_bytes());
        }
        CacheKey(format!("snapshot-{}", hasher.finalize().to_hex()))
    }

    async fn run(&self, inputs: &StageInputs, out: &Path) -> Result<StageOutputs> {
        let kernel = inputs
            .artifacts
            .get("kernel")
            .cloned()
            .unwrap_or_else(|| std::path::PathBuf::from("/tmp/vmlinux"));
        let rootfs_image = inputs
            .artifacts
            .get("rootfs")
            .cloned()
            .unwrap_or_else(|| std::path::PathBuf::from("/tmp/rootfs.erofs"));

        let cfg = VmConfig::builder(
            kernel,
            RootfsSource::Erofs {
                image: rootfs_image,
            },
        )
        .network_disabled()
        .build()
        .map_err(|e| crate::error::Error::Artifact(e.to_string()))?;

        let ch_binary =
            std::env::var("CLOUD_HYPERVISOR_PATH").unwrap_or_else(|_| "cloud-hypervisor".into());
        let vmm = CloudHypervisor::new(ch_binary);

        let cid_alloc = self.cid_alloc.clone();
        let vmid_alloc = self.vmid_alloc.clone();
        let mut vm = TestVm::start(
            &vmm,
            cfg,
            cid_alloc.clone(),
            vmid_alloc,
            Box::new(crate::metrics::DefaultCgroupFs),
        )
        .await?;

        // Wait for VM to boot fully via vsock agent
        let agent = vm.agent(None, &crate::orchestrator::RealClock).await?;
        let _ = agent
            .exec(ExecRequest::new(vec!["true".to_string()]))
            .await?;

        tokio::fs::create_dir_all(out)
            .await
            .map_err(crate::error::Error::Io)?;
        vm.instance_mut().snapshot(out).await?;

        vm.shutdown().await?;

        Ok(StageOutputs::default())
    }
}
