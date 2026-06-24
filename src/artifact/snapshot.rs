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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotStage {}



use async_trait::async_trait;

#[async_trait]
impl Stage for SnapshotStage {
    fn name(&self) -> &str {
        "snapshot"
    }

    fn cache_key(&self, _inputs: &StageInputs) -> CacheKey {
        CacheKey("snapshot-v1".to_string())
    }

    async fn run(&self, _inputs: &StageInputs, out: &Path) -> Result<StageOutputs> {
        let kernel = std::path::PathBuf::from(
            std::env::var("IMP_KERNEL").unwrap_or_else(|_| "/tmp/vmlinux".into()),
        );
        let rootfs_image = std::path::PathBuf::from(
            std::env::var("IMP_ROOTFS").unwrap_or_else(|_| "/tmp/rootfs.ext4".into()),
        );

        let cfg = VmConfig::builder(
            kernel,
            RootfsSource::Block {
                image: rootfs_image,
                overlay: None,
            },
        )
        .network_disabled()
        .build()
        .unwrap();

        let ch_binary =
            std::env::var("CLOUD_HYPERVISOR_PATH").unwrap_or_else(|_| "cloud-hypervisor".into());
        let vmm = CloudHypervisor::new(ch_binary);

        let cid_alloc = crate::vmm::CidAllocator::new();
        let vmid_alloc = std::sync::Arc::new(crate::orchestrator::VmidAllocator::new());
        let mut vm = TestVm::start(&vmm, cfg, &cid_alloc, vmid_alloc).await?;

        // Wait for VM to boot fully via vsock agent
        let mut agent = vm.agent().await?;
        let _ = agent
            .exec(ExecRequest {
                argv: vec!["true".to_string()],
                env: vec![],
                cwd: None,
            })
            .await?;

        tokio::fs::create_dir_all(out)
            .await
            .map_err(crate::error::Error::Io)?;
        vm.instance_mut().snapshot(out).await?;

        vm.shutdown().await?;

        Ok(StageOutputs::default())
    }
}
