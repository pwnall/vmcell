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
    /// Explicit `(image, digest)` override for the OCI source (v15 `oci2erofs`, §8.2):
    /// `Some` ignores the pinned `rootfs_image`/`rootfs_digest` and pulls this digest-pinned
    /// base instead. `None` uses the pins (the default `vmcell build`).
    pub image_override: Option<(String, String)>,
    /// Static-musl guest agent to inject instead of the pipeline's default glibc agent
    /// (`oci2erofs --agent-musl`, §8.2). When `Some`, the libc6-presence guard is skipped.
    pub agent_musl: Option<std::path::PathBuf>,
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
        // v15: bumped to 2 with the oci2erofs image-override + agent-musl inputs.
        const STAGE_VERSION: u32 = 2;
        let mut hasher = blake3::Hasher::new();
        hasher.update(&STAGE_VERSION.to_le_bytes());
        // The injected-agent identity is an INPUT: the static-musl override path changes the
        // built rootfs vs. the default glibc agent, so fold its path (oci2erofs §8.2).
        match &self.agent_musl {
            Some(p) => {
                hasher.update(b"agent-musl\0");
                hasher.update(p.to_string_lossy().as_bytes());
            }
            None => {
                hasher.update(b"agent-default\0");
            }
        }
        match &self.source {
            RootfsBuildSource::Oci => {
                hasher.update(b"oci");
                // oci2erofs: the CLI-provided digest-pinned base is an INPUT (not a pin) and
                // must be content-addressed directly; otherwise a stale erofs is reused for a
                // different IMAGE@DIGEST. Fall back to the pins for the default `vmcell build`.
                let (image, digest) = match &self.image_override {
                    Some((i, d)) => (i.as_str(), d.as_str()),
                    None => (
                        inputs
                            .pins
                            .get("rootfs_image")
                            .map(String::as_str)
                            .unwrap_or_default(),
                        inputs
                            .pins
                            .get("rootfs_digest")
                            .map(String::as_str)
                            .unwrap_or_default(),
                    ),
                };
                hasher.update(image.as_bytes());
                hasher.update(b"\0");
                hasher.update(digest.as_bytes());
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
        // Hash only the upstream artifacts this stage actually CONSUMES (ART-9), in a
        // deterministic key-sorted order over their on-disk content. Folding *every*
        // upstream artifact meant a `kernel` rebuild invalidated the OCI rootfs, which does
        // not depend on the kernel (only the mmdebstrap source boots a builder VM off it).
        // Over-invalidating is safe-but-wasteful; scope the fold to consumed inputs:
        //   - OCI: the injected `guest_agent` + `guest_tools` binaries (base image is a
        //     pin/override, not an artifact).
        //   - mmdebstrap: the same injected binaries PLUS `kernel` (boots the builder VM).
        let consumed: &[&str] = match &self.source {
            RootfsBuildSource::Oci => &["guest_agent", "guest_tools"],
            RootfsBuildSource::Mmdebstrap { .. } => &["kernel", "guest_agent", "guest_tools"],
        };
        let filtered: std::collections::HashMap<String, std::path::PathBuf> = inputs
            .artifacts
            .iter()
            .filter(|(k, _)| consumed.contains(&k.as_str()))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        crate::artifact::hash_artifacts_sorted(&mut hasher, &filtered);
        CacheKey(format!("rootfs-{}", hasher.finalize().to_hex()))
    }

    async fn run(&self, inputs: &StageInputs, out: &Path) -> Result<StageOutputs> {
        match &self.source {
            RootfsBuildSource::Oci => {
                // oci2erofs (§8.2): the CLI override pulls an explicit digest-pinned base;
                // the default `vmcell build` resolves the pinned Debian image from the pins.
                let (image, digest) =
                    match &self.image_override {
                        Some((i, d)) => (i.clone(), d.clone()),
                        None => {
                            let image = inputs.pins.get("rootfs_image").ok_or_else(|| {
                                Error::Artifact("Missing rootfs_image pin".into())
                            })?;
                            let digest = inputs.pins.get("rootfs_digest").ok_or_else(|| {
                                Error::Artifact("Missing rootfs_digest pin".into())
                            })?;
                            (image.clone(), digest.clone())
                        }
                    };
                oci::build_rootfs(&image, &digest, inputs, out, self.agent_musl.as_deref()).await
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
    agent_musl: Option<&Path>,
) -> Result<StageOutputs> {
    let out_buf = out.to_path_buf();

    // The injected agent. A user-supplied static-musl binary (`--agent-musl`, oci2erofs §8.2)
    // overrides the pipeline's default glibc agent artifact; otherwise a missing default agent
    // is a hard error, never a boot from a world-writable, attacker-plantable `/tmp` path.
    let agent_path = match agent_musl {
        Some(p) => p.to_path_buf(),
        None => inputs
            .artifacts
            .get("guest_agent")
            .cloned()
            .ok_or_else(|| Error::Artifact("missing guest_agent upstream input".into()))?,
    };
    // The default (glibc) agent needs libc6 in the base; the static-musl agent does not.
    let require_libc6 = agent_musl.is_none();

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
        let image = crate::artifact::tar2erofs::tar_to_erofs(
            archives,
            injected_files,
            injected_symlinks,
            require_libc6,
        )?;
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
    _agent_musl: Option<&Path>,
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
            image_override: None,
            agent_musl: None,
        }
    }

    fn write_tmp(dir: &std::path::Path, name: &str, content: &[u8]) -> PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, content).expect("write");
        p
    }

    // Guards ARTIFACT-PIPELINE-1 for the CONSUMED-artifact fold: the two artifacts this OCI
    // stage consumes (`guest_agent`, `guest_tools`) must fold order-independently over their
    // content. Inserted in opposite orders, the content-addressed key must be identical.
    #[test]
    fn test_rootfs_cache_key_order_independent() {
        let dir = tempfile::tempdir().expect("tempdir");
        let agent = write_tmp(dir.path(), "guest_agent", b"agent-bytes");
        let tools = write_tmp(dir.path(), "guest_tools", b"tools-bytes");
        let mut a = StageInputs::default();
        a.artifacts.insert("guest_agent".to_string(), agent.clone());
        a.artifacts.insert("guest_tools".to_string(), tools.clone());
        let mut b = StageInputs::default();
        b.artifacts.insert("guest_tools".to_string(), tools);
        b.artifacts.insert("guest_agent".to_string(), agent);
        assert_eq!(stage().cache_key(&a), stage().cache_key(&b));
    }

    // ART-9: the OCI rootfs does NOT consume the kernel, so a kernel rebuild must NOT
    // invalidate the OCI rootfs key. The mmdebstrap source boots a builder VM off the
    // kernel, so for it a kernel change MUST change the key. Folding *all* upstream
    // artifacts (the bug) reddens the first assertion.
    #[test]
    fn test_rootfs_oci_key_ignores_kernel_mmdebstrap_folds_it() {
        let dir = tempfile::tempdir().expect("tempdir");
        let kernel = write_tmp(dir.path(), "vmlinux", b"kernel-v1");
        let mut inputs = StageInputs::default();
        inputs
            .artifacts
            .insert("kernel".to_string(), kernel.clone());

        // OCI stage: kernel is not consumed → rebuilding it leaves the key unchanged.
        let oci = stage();
        let oci_k1 = oci.cache_key(&inputs);
        std::fs::write(&kernel, b"kernel-v2-rebuilt").expect("write");
        let oci_k2 = oci.cache_key(&inputs);
        assert_eq!(
            oci_k1, oci_k2,
            "a kernel rebuild must NOT invalidate the OCI rootfs key (kernel not consumed)"
        );

        // mmdebstrap stage: kernel boots the builder VM → it IS consumed.
        let mmd = RootfsStage {
            source: RootfsBuildSource::Mmdebstrap {
                release: "trixie".into(),
            },
            cid_alloc: Arc::new(crate::vmm::CidAllocator::new()),
            image_override: None,
            agent_musl: None,
        };
        let mmd_k1 = mmd.cache_key(&inputs);
        std::fs::write(&kernel, b"kernel-v3-rebuilt").expect("write");
        let mmd_k2 = mmd.cache_key(&inputs);
        assert_ne!(
            mmd_k1, mmd_k2,
            "a kernel rebuild MUST invalidate the mmdebstrap rootfs key (kernel consumed)"
        );
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
        let res = pack_erofs_with_injection(vec![], &inputs, &out, None).await;
        assert!(
            matches!(res, Err(Error::Artifact(_))),
            "missing guest_agent must be a hard error, got {:?}",
            res
        );
    }
}
