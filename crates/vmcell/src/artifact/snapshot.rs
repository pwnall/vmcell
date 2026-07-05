//! Virtual machine snapshot artifact building.
//!
//! This module provides the `SnapshotStage` pipeline step, which boots a VM
//! to its ready state and takes a memory snapshot to enable fast booting later.

use crate::agent::protocol::ExecRequest;
use crate::artifact::{CacheKey, Stage, StageInputs, StageOutputs};
use crate::config::{RootfsSource, VmConfig};
use crate::error::Result;
use crate::orchestrator::MicroVm;
use crate::vmm::cloud_hypervisor::CloudHypervisor;
use std::path::{Path, PathBuf};

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
        // Bump when this stage's snapshot logic changes so stale snapshots are not served.
        const STAGE_VERSION: u32 = 1;
        let mut hasher = blake3::Hasher::new();
        hasher.update(&STAGE_VERSION.to_le_bytes());
        // Fold the pinned Cloud Hypervisor build identity (M-ART-7 / §16): a snapshot is only
        // valid for the exact CH build that produced it — CH does not guarantee cross-version
        // snapshot compatibility — so a CH upgrade must invalidate stale snapshots at build
        // time, not at first `restore()`. The pin travels via Stage 0 (`cloud_hypervisor` in
        // pins.json / resolved_pins). virtiofsd is not folded: a snapshot-eligible VM has no
        // vhost-user device (§3.3), so the snapshot itself never runs virtiofsd.
        hasher.update(b"ch\0");
        hasher.update(
            inputs
                .pins
                .get("cloud_hypervisor")
                .map(|s| s.as_bytes())
                .unwrap_or_default(),
        );
        // Hash the upstream kernel/rootfs CONTENT (deterministic, key-sorted) rather than
        // their `target_dir`-relative path strings: new kernel/rootfs bytes at the same path
        // must invalidate the snapshot, otherwise a stale snapshot is served.
        crate::artifact::hash_artifacts_sorted(&mut hasher, &inputs.artifacts);
        CacheKey(format!("snapshot-{}", hasher.finalize().to_hex()))
    }

    async fn run(&self, inputs: &StageInputs, out: &Path) -> Result<StageOutputs> {
        // A missing upstream artifact is a hard error, never a boot from a world-writable,
        // attacker-plantable `/tmp` path.
        let kernel =
            inputs.artifacts.get("kernel").cloned().ok_or_else(|| {
                crate::error::Error::Artifact("missing kernel upstream input".into())
            })?;
        let rootfs_image =
            inputs.artifacts.get("rootfs").cloned().ok_or_else(|| {
                crate::error::Error::Artifact("missing rootfs upstream input".into())
            })?;

        let cfg = snapshot_vm_config(kernel, rootfs_image)?;

        // Shared resolver so this stage and the mmdebstrap builder stage read the
        // SAME env var (VMCELL_CH_BIN) — no per-call-site CH-binary drift.
        let ch_binary = crate::artifact::ch_binary_path();
        let vmm = CloudHypervisor::new(ch_binary);

        let cid_alloc = self.cid_alloc.clone();
        let vmid_alloc = self.vmid_alloc.clone();
        let mut vm = MicroVm::start(
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
        // Go through the first-class `MicroVm::snapshot` verb (M-ART-2), not
        // `instance_mut().snapshot()`: the former invalidates the cached `AgentClient` after
        // a successful snapshot (so the resumed VM stays usable on every backend) and is the
        // self-guarding entry point aligned with the §3.3 snapshot-eligibility law.
        vm.snapshot(out).await?;

        vm.shutdown().await?;

        Ok(snapshot_outputs(out))
    }
}

/// Builds the snapshot stage's [`VmConfig`], declaring `snapshotting(true)` (M-ART-2) so the
/// §3.3 snapshot-eligibility guards in `config::build()` engage (a virtio-fs rootfs/share or
/// unprivileged vhost-user-net is rejected). `network_disabled` keeps the boot vhost-user-free.
fn snapshot_vm_config(kernel: PathBuf, rootfs_image: PathBuf) -> Result<VmConfig> {
    VmConfig::builder(
        kernel,
        RootfsSource::Erofs {
            image: rootfs_image,
        },
    )
    .network_disabled()
    .snapshotting(true)
    .build()
    .map_err(|e| crate::error::Error::Artifact(e.to_string()))
}

/// Builds the [`StageOutputs`] for a snapshot build, registering the snapshot directory under
/// `"snapshot"` (M-ART-1) so downstream stages and the warm-cache restore see it on a COLD
/// build, not only on a warm-cache hit. Mirrors `kernel_outputs`. Returning
/// `StageOutputs::default()` registered nothing on the cold path while the warm-cache fallback
/// did, so the two paths disagreed.
fn snapshot_outputs(out: &Path) -> StageOutputs {
    let mut outputs = StageOutputs::default();
    outputs
        .artifacts
        .insert("snapshot".to_string(), out.to_path_buf());
    outputs
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn stage() -> SnapshotStage {
        SnapshotStage {
            cid_alloc: std::sync::Arc::new(crate::vmm::CidAllocator::new()),
            vmid_alloc: crate::orchestrator::VmidAllocator::new(),
        }
    }

    fn write_tmp(dir: &Path, name: &str, content: &[u8]) -> PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, content).expect("write");
        p
    }

    // Guards ARTIFACT-PIPELINE-1: a buggy impl that hashes the `artifacts` HashMap in its
    // process-random iteration order yields different keys for identical content. Several
    // entries make the unsorted iteration overwhelmingly likely to differ across the two maps.
    #[test]
    fn test_snapshot_cache_key_order_independent() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut entries: Vec<(String, PathBuf)> = Vec::new();
        for i in 0..8 {
            let p = write_tmp(dir.path(), &format!("f{i}"), format!("c{i}").as_bytes());
            entries.push((format!("art{i}"), p));
        }
        let mut a = StageInputs::default();
        for (k, v) in entries.iter() {
            a.artifacts.insert(k.clone(), v.clone());
        }
        let mut b = StageInputs::default();
        for (k, v) in entries.iter().rev() {
            b.artifacts.insert(k.clone(), v.clone());
        }
        assert_eq!(stage().cache_key(&a), stage().cache_key(&b));
    }

    // Guards ARTIFACT-PIPELINE-2: hashing the path STRING (not content) leaves the snapshot
    // key unchanged when new kernel/rootfs bytes land at the same path.
    #[test]
    fn test_snapshot_cache_key_tracks_upstream_content() {
        let dir = tempfile::tempdir().expect("tempdir");
        let kernel = write_tmp(dir.path(), "vmlinux", b"kernel-v1");
        let rootfs = write_tmp(dir.path(), "rootfs.erofs", b"rootfs-v1");
        let mut inputs = StageInputs::default();
        inputs
            .artifacts
            .insert("kernel".to_string(), kernel.clone());
        inputs.artifacts.insert("rootfs".to_string(), rootfs);
        let k1 = stage().cache_key(&inputs);
        std::fs::write(&kernel, b"kernel-v2-rebuilt").expect("write");
        let k2 = stage().cache_key(&inputs);
        assert_ne!(k1, k2, "new kernel bytes must change the snapshot key");
    }

    // M-ART-1: the cold build path must register the `snapshot` artifact in its outputs
    // (like the warm-cache path does), or downstream stages lose it. A buggy
    // `Ok(StageOutputs::default())` registers nothing -> red here.
    #[test]
    fn test_snapshot_outputs_registers_snapshot_artifact() {
        let out = Path::new("/some/target/snapshot");
        let outputs = snapshot_outputs(out);
        assert_eq!(
            outputs.artifacts.get("snapshot").map(|p| p.as_path()),
            Some(out),
            "cold-build outputs must register the snapshot artifact (M-ART-1)"
        );
    }

    // M-ART-2: the snapshot stage must declare `snapshotting(true)` so the §3.3 snapshot-
    // eligibility guards in `config::build()` engage. The buggy config (no snapshotting flag)
    // leaves `cfg.snapshotting == false` -> red here. (config::build() separately rejects
    // Unprivileged + snapshotting; that negative test lives in config.rs.)
    #[test]
    fn test_snapshot_vm_config_declares_snapshotting() {
        let cfg = snapshot_vm_config(
            PathBuf::from("/k/vmlinux"),
            PathBuf::from("/r/rootfs.erofs"),
        )
        .expect("snapshot config must build");
        assert!(
            cfg.snapshotting,
            "the snapshot stage must declare snapshotting(true) (M-ART-2)"
        );
    }

    // M-ART-7: a Cloud Hypervisor version bump must invalidate the snapshot cache key (§16:
    // CH does not guarantee cross-version snapshot compatibility). The buggy version (no CH
    // fold) leaves the two keys equal -> red here.
    #[test]
    fn test_snapshot_cache_key_tracks_ch_identity() {
        let mut a = StageInputs::default();
        a.pins.insert("cloud_hypervisor".into(), "v40.0".into());
        let mut b = StageInputs::default();
        b.pins.insert("cloud_hypervisor".into(), "v41.0".into());
        assert_ne!(
            stage().cache_key(&a),
            stage().cache_key(&b),
            "a CH version bump must invalidate the snapshot cache key (M-ART-7)"
        );
    }

    // Guards ARTIFACT-PIPELINE-3: a missing upstream input must be a hard error (the kernel
    // check fires before any VM boot, so this runs without KVM), never a `/tmp/vmlinux` boot.
    #[tokio::test]
    async fn test_snapshot_missing_kernel_errors() {
        let dir = tempfile::tempdir().expect("tempdir");
        let out = dir.path().join("snapshot");
        let inputs = StageInputs::default();
        let res = stage().run(&inputs, &out).await;
        assert!(
            matches!(res, Err(crate::error::Error::Artifact(_))),
            "missing kernel upstream must hard-error, got {res:?}"
        );
    }
}
