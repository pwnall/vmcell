//! Root filesystem artifact building.
//!
//! This module provides the `RootfsStage` pipeline step, which creates a
//! minimal root filesystem for the virtual machines. It supports building
//! via OCI registry pull or by running mmdebstrap inside a micro-VM.

use crate::artifact::{CacheKey, Stage, StageInputs, StageOutputs};
use crate::error::{Error, Result};
use async_trait::async_trait;
use std::io::Read;
use std::path::Path;

/// mmdebstrap micro-VM builder source.
pub mod mmdebstrap;
/// OCI registry pull source.
pub mod oci;

/// Root filesystem construction source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RootfsBuildSource {
    /// OCI registry pull source.
    Oci,
    /// Full-apt source running mmdebstrap inside a micro-VM.
    Mmdebstrap {
        /// The Debian release suite to use (e.g., "bookworm").
        release: String,
    },
}

/// A pipeline stage that builds a root filesystem.
pub struct RootfsStage {
    /// The source method to build the root filesystem.
    pub source: RootfsBuildSource,
    /// The CID allocator for VMs run by this stage.
    pub cid_alloc: std::sync::Arc<crate::vmm::CidAllocator>,
}

#[async_trait]
impl Stage for RootfsStage {
    fn name(&self) -> &str {
        "rootfs"
    }

    fn out_path(&self, target_dir: &std::path::Path) -> std::path::PathBuf {
        target_dir.join("rootfs.erofs")
    }

    fn cache_key(&self, inputs: &StageInputs) -> CacheKey {
        // Bump when this stage's build logic changes so stale outputs are not served.
        const STAGE_VERSION: u32 = 1;
        let mut hasher = blake3::Hasher::new();
        hasher.update(&STAGE_VERSION.to_le_bytes());
        match &self.source {
            RootfsBuildSource::Oci => {
                hasher.update(b"oci");
                hasher.update(
                    inputs
                        .pins
                        .get("rootfs_image")
                        .map(|s| s.as_bytes())
                        .unwrap_or_default(),
                );
                hasher.update(
                    inputs
                        .pins
                        .get("rootfs_digest")
                        .map(|s| s.as_bytes())
                        .unwrap_or_default(),
                );
            }
            RootfsBuildSource::Mmdebstrap { release } => {
                hasher.update(b"mmdebstrap");
                hasher.update(release.as_bytes());
                hasher.update(
                    inputs
                        .pins
                        .get("debian_snapshot_timestamp")
                        .map(|s| s.as_bytes())
                        .unwrap_or_default(),
                );
            }
        }
        // The guest agent is injected into the rootfs, so its source identity (which
        // travels via the resolved pins) must be part of the key: rebuilding the agent at
        // the same path must invalidate the rootfs, otherwise a stale agent stays baked in.
        hasher.update(
            inputs
                .pins
                .get("guest_agent_src_hash")
                .map(|s| s.as_bytes())
                .unwrap_or_default(),
        );
        // Hash upstream artifact CONTENT in a deterministic (key-sorted) order rather than
        // their `target_dir`-relative path strings.
        crate::artifact::hash_artifacts_sorted(&mut hasher, &inputs.artifacts);
        CacheKey(format!("rootfs-{}", hasher.finalize().to_hex()))
    }

    async fn run(&self, inputs: &StageInputs, out: &Path) -> Result<StageOutputs> {
        match &self.source {
            RootfsBuildSource::Oci => {
                let image = inputs
                    .pins
                    .get("rootfs_image")
                    .ok_or_else(|| Error::Artifact("Missing rootfs_image pin".into()))?;
                let digest = inputs
                    .pins
                    .get("rootfs_digest")
                    .ok_or_else(|| Error::Artifact("Missing rootfs_digest pin".into()))?;
                oci::build_rootfs(image, digest, inputs, out).await
            }
            RootfsBuildSource::Mmdebstrap { release } => {
                mmdebstrap::build_rootfs(release, inputs, out, self.cid_alloc.clone()).await
            }
        }
    }
}

/// Shared logic to take a list of tar streams, inject the agent and CA, and pack it into erofs.
///
/// # Errors
/// Returns an error if the erofs packing or file injection fails.
#[cfg(feature = "am-fs-erofs")]
pub async fn pack_erofs_with_injection(
    tar_streams: Vec<Box<dyn Read + Send>>,
    inputs: &StageInputs,
    out: &Path,
) -> Result<StageOutputs> {
    let out_buf = out.to_path_buf();

    // A missing guest-agent input is a hard error, never a boot from a world-writable,
    // attacker-plantable `/tmp` path.
    let agent_path = inputs
        .artifacts
        .get("guest_agent")
        .cloned()
        .ok_or_else(|| Error::Artifact("missing guest_agent upstream input".into()))?;

    // Generate the proxy CA and actually WRITE it to the path we inject from. Without this
    // the injected `ca.pem` never exists and the erofs pack aborts (or, by dir coincidence,
    // bakes in a stale CA from a different directory).
    #[cfg(feature = "proxy")]
    let ca_path = {
        let ca_mgr = crate::proxy::tls::CaManager::new()?;
        let path = out.parent().unwrap_or(Path::new(".")).join("ca.pem");
        std::fs::write(&path, ca_mgr.ca_cert_pem()).map_err(Error::Io)?;
        path
    };

    // The guest test-helper (ip/curl/kvm-ok) is baked into the rootfs rather than
    // mounted as a virtio-fs share: virtiofsd cannot enter its sandbox
    // unprivileged, so a share fails in the unprivileged suite, whereas the erofs
    // rootfs is served over virtio-blk in both modes. Optional — builds that do
    // not run the GuestToolsStage simply omit it.
    let tools_path = inputs.artifacts.get("guest_tools").cloned();

    tokio::task::spawn_blocking(move || -> Result<StageOutputs> {
        let mut injected_files = vec![("usr/sbin/vmcell-guest-agent", agent_path.as_path())];
        #[cfg(feature = "proxy")]
        injected_files.push((
            "usr/local/share/ca-certificates/vmcell-ca.crt",
            ca_path.as_path(),
        ));

        let mut injected_symlinks: Vec<(&str, &str)> = Vec::new();
        if let Some(tp) = tools_path.as_deref() {
            injected_files.push(("vmcell-tools/vmcell-guest-tools", tp));
            // busybox-style multicall links resolved on the exec PATH (the guest
            // agent prepends /vmcell-tools).
            injected_symlinks.push(("vmcell-tools/ip", "vmcell-guest-tools"));
            injected_symlinks.push(("vmcell-tools/curl", "vmcell-guest-tools"));
            injected_symlinks.push(("vmcell-tools/kvm-ok", "vmcell-guest-tools"));
        }

        let archives: Vec<tar::Archive<Box<dyn Read + Send>>> =
            tar_streams.into_iter().map(tar::Archive::new).collect();
        let image =
            crate::artifact::tar2erofs::tar_to_erofs(archives, injected_files, injected_symlinks)?;
        std::fs::write(&out_buf, image).map_err(|e| Error::Artifact(e.to_string()))?;
        let mut outputs = StageOutputs::default();
        outputs.artifacts.insert("rootfs".into(), out_buf);
        Ok(outputs)
    })
    .await
    .map_err(|e| Error::Artifact(e.to_string()))?
}

/// Shared logic to take a tar stream, inject the agent and CA, and pack it into erofs.
#[cfg(not(feature = "am-fs-erofs"))]
pub async fn pack_erofs_with_injection(
    _tar_streams: Vec<Box<dyn Read + Send>>,
    _inputs: &StageInputs,
    _out: &Path,
) -> Result<StageOutputs> {
    // mkfs.erofs fallback requires extracting the tar to a directory, adding the files,
    // and running mkfs.erofs. We assume am-fs-erofs is used for now.
    Err(Error::Artifact(
        "am-fs-erofs feature is required for rootfs building".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::Arc;

    fn stage() -> RootfsStage {
        RootfsStage {
            source: RootfsBuildSource::Oci,
            cid_alloc: Arc::new(crate::vmm::CidAllocator::new()),
        }
    }

    fn write_tmp(dir: &std::path::Path, name: &str, content: &[u8]) -> PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, content).expect("write");
        p
    }

    // Guards ARTIFACT-PIPELINE-1: a buggy impl that hashes the `artifacts` HashMap in its
    // process-random iteration order yields different keys for identical content.
    #[test]
    fn test_rootfs_cache_key_order_independent() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut entries: Vec<(String, PathBuf)> = Vec::new();
        for i in 0..8 {
            let p = write_tmp(dir.path(), &format!("f{}", i), format!("c{}", i).as_bytes());
            entries.push((format!("art{}", i), p));
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

    // Guards ARTIFACT-PIPELINE-2: hashing the path STRING (not content) leaves the key
    // unchanged when a rebuilt upstream artifact lands at the same path.
    #[test]
    fn test_rootfs_cache_key_tracks_upstream_content() {
        let dir = tempfile::tempdir().expect("tempdir");
        let p = write_tmp(dir.path(), "guest_agent", b"agent-v1");
        let mut inputs = StageInputs::default();
        inputs
            .artifacts
            .insert("guest_agent".to_string(), p.clone());
        let k1 = stage().cache_key(&inputs);
        std::fs::write(&p, b"agent-v2-rebuilt-at-same-path").expect("write");
        let k2 = stage().cache_key(&inputs);
        assert_ne!(
            k1, k2,
            "rebuilt upstream content must change the rootfs key"
        );
    }

    // Guards ARTIFACT-PIPELINE-2: the rootfs key omitting `guest_agent_src_hash` lets a
    // stale agent stay baked in; folding it in makes the key sensitive to it.
    #[test]
    fn test_rootfs_cache_key_tracks_guest_agent_src_hash() {
        let mut a = StageInputs::default();
        a.pins
            .insert("guest_agent_src_hash".to_string(), "hash-aaa".to_string());
        let mut b = StageInputs::default();
        b.pins
            .insert("guest_agent_src_hash".to_string(), "hash-bbb".to_string());
        assert_ne!(stage().cache_key(&a), stage().cache_key(&b));
    }

    // Guards ARTIFACT-PIPELINE-3: a missing guest_agent input must be a hard error, never a
    // silent boot from a world-writable `/tmp/guest_agent`.
    #[cfg(feature = "am-fs-erofs")]
    #[tokio::test]
    async fn test_pack_erofs_missing_agent_errors() {
        let dir = tempfile::tempdir().expect("tempdir");
        let out = dir.path().join("rootfs.erofs");
        let inputs = StageInputs::default();
        let res = pack_erofs_with_injection(vec![], &inputs, &out).await;
        assert!(
            matches!(res, Err(Error::Artifact(_))),
            "missing guest_agent must be a hard error, got {:?}",
            res
        );
    }
}
