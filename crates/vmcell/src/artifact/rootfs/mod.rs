//! Root filesystem artifact building.
//!
//! This module provides the `RootfsStage` pipeline step, which creates a minimal root
//! filesystem for the virtual machines from an **OCI registry pull** — the in-`vmcell`
//! bootstrap rootfs source (host-native, no VM). The full-apt **`mmdebstrap`-inside-a-VM**
//! source now lives in the separate `vmcell-rootfs-builder` crate (§5.4 / §8.2), which
//! calls [`pack_erofs_with_injection`] and [`resolve_builder_base`] here so every rootfs
//! source shares one inject/CA/erofs tail.

use crate::artifact::{CacheKey, Stage, StageInputs, StageOutputs};
use crate::error::{Error, Result};
use async_trait::async_trait;
use std::io::Read;
use std::path::Path;

/// OCI registry pull source.
pub mod oci;

/// A pipeline stage that builds a root filesystem from an OCI base image (the in-`vmcell`
/// bootstrap source, §8.2). The in-VM `mmdebstrap` source is `vmcell-rootfs-builder`.
pub struct RootfsStage {
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
        // v20: bumped to 3 — the shared injected-content fold (agent-musl + CA +
        // guest-agent source) moved into `fold_rootfs_injection_identity` (called first),
        // which reorders the hashed byte stream. A one-time OCI-rootfs rebuild is harmless.
        const STAGE_VERSION: u32 = 3;
        let mut hasher = blake3::Hasher::new();
        hasher.update(&STAGE_VERSION.to_le_bytes());
        // Fold the identity of everything the shared inject+pack tail bakes in (the optional
        // static-musl agent override, the deployment CA, the guest-agent source closure) —
        // ONE implementation, shared with the out-of-crate in-VM rootfs builders (§5.4).
        fold_rootfs_injection_identity(&mut hasher, inputs, self.agent_musl.as_deref());
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
        // Hash only the upstream artifacts this stage actually CONSUMES (ART-9), in a
        // deterministic key-sorted order over their on-disk content. Folding *every*
        // upstream artifact meant a `kernel` rebuild invalidated the OCI rootfs, which does
        // not depend on the kernel (the OCI source boots no VM). Scope the fold to the
        // injected `guest_agent` + `guest_tools` binaries (the base image is a pin/override,
        // not an artifact). The in-VM `mmdebstrap` source, which additionally consumes the
        // seed `kernel`, lives in `vmcell-rootfs-builder` and folds it in its own key.
        let consumed: &[&str] = &["guest_agent", "guest_tools"];
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
        // oci2erofs (§8.2): the CLI override pulls an explicit digest-pinned base;
        // the default `vmcell build` resolves the pinned Debian image from the pins.
        let (image, digest) = match &self.image_override {
            Some((i, d)) => (i.clone(), d.clone()),
            None => {
                let image = inputs
                    .pins
                    .get("rootfs_image")
                    .ok_or_else(|| Error::Artifact("Missing rootfs_image pin".into()))?;
                let digest = inputs
                    .pins
                    .get("rootfs_digest")
                    .ok_or_else(|| Error::Artifact("Missing rootfs_digest pin".into()))?;
                (image.clone(), digest.clone())
            }
        };
        oci::build_rootfs(&image, &digest, inputs, out, self.agent_musl.as_deref()).await
    }
}

/// Folds the identity of everything the shared inject+pack tail ([`pack_erofs_with_injection`])
/// bakes into a rootfs — the optional static-musl agent override (by CONTENT, H-ART-1), the
/// deployment proxy CA cert (M-ART-10), and the guest-agent source closure — into `hasher`.
///
/// Every rootfs builder folds this identically: the in-`vmcell` OCI [`RootfsStage`] and the
/// out-of-crate in-VM sources (`vmcell-rootfs-builder`). Kept here so there is exactly ONE
/// implementation of the injected-content identity (§5.4; AGENTS.md "don't triplicate;
/// extract") — a musl-agent/CA/agent rebuild then invalidates the cached erofs from any source.
///
/// Callers fold their own `STAGE_VERSION`, source discriminator, source-specific pins, and
/// consumed-artifact set (via [`crate::artifact::hash_artifacts_sorted`]) around this call.
#[cfg(feature = "pipeline")]
pub fn fold_rootfs_injection_identity(
    hasher: &mut blake3::Hasher,
    inputs: &StageInputs,
    agent_musl: Option<&Path>,
) {
    // The injected-agent identity: a static-musl override (folded by CONTENT, not path string,
    // since the GuestAgentStage is skipped on that path) vs. the default glibc agent. A read
    // failure folds a distinct marker; the resulting miss re-runs the build, which fails loud.
    match agent_musl {
        Some(p) => {
            hasher.update(b"agent-musl\0");
            match crate::artifact::hash_file(p) {
                Ok(h) => hasher.update(h.as_bytes()),
                Err(_) => hasher.update(format!("missing-agent-musl:{}", p.display()).as_bytes()),
            };
        }
        None => {
            hasher.update(b"agent-default\0");
        }
    }
    // The baked proxy CA cert content (M-ART-10): `run()` writes the deployment CA into the
    // rootfs as a side effect, so a CA rotation must invalidate the cached erofs or the guest
    // trusts the old CA and HTTPS intercept breaks silently. A read failure folds a marker.
    #[cfg(feature = "proxy")]
    {
        match crate::proxy::tls::CaManager::new().map(|m| m.ca_cert_pem().to_string()) {
            Ok(pem) => {
                hasher.update(b"ca\0");
                hasher.update(pem.as_bytes());
            }
            Err(e) => {
                hasher.update(format!("ca-read-error:{e}").as_bytes());
            }
        };
    }
    // The guest-agent source identity (travels via the resolved pins): rebuilding the agent
    // must invalidate the rootfs, otherwise a stale agent stays baked in.
    hasher.update(
        inputs
            .pins
            .get("guest_agent_src_hash")
            .map(String::as_bytes)
            .unwrap_or_default(),
    );
}

/// Resolves the builder-base image as an atomic `(image, digest)` pair from the resolved
/// pins, never mixing a pinned image with a hardcoded digest.
///
/// Public so the out-of-crate in-VM rootfs/kernel builders (`vmcell-rootfs-builder`,
/// `vmcell-kernel-builder`) resolve the builder-VM base image the *same* way the bootstrap
/// pipeline does — one resolver, no drift.
///
/// Precedence: the dedicated `builder_base_*` pins, else the `rootfs_*` pins. A
/// half-specified pair (image without digest, or vice-versa) or a completely missing base
/// is a hard error — a hardcoded fallback would mask a missing Stage-0 pin and could pin a
/// mismatched `image@digest` reference (M-PIPE-2 / B5 "no fallback masking a missing
/// upstream").
///
/// # Errors
/// Returns [`Error::Artifact`] if no pin pair is present, or only one half of a pair is set.
pub fn resolve_builder_base(
    pins: &std::collections::HashMap<String, String>,
) -> Result<(String, String)> {
    for (img_key, dig_key) in [
        ("builder_base_image", "builder_base_digest"),
        ("rootfs_image", "rootfs_digest"),
    ] {
        match (pins.get(img_key), pins.get(dig_key)) {
            (Some(img), Some(dig)) => return Ok((img.clone(), dig.clone())),
            (Some(_), None) | (None, Some(_)) => {
                return Err(Error::Artifact(format!(
                    "builder base pin pair half-specified: exactly one of \
                     {img_key}/{dig_key} is set; provide both or neither"
                )));
            }
            (None, None) => {}
        }
    }
    Err(Error::Artifact(
        "missing builder base image+digest pins (builder_base_* or rootfs_*); \
         refusing hardcoded fallback (would pin a mismatched image@digest)"
            .into(),
    ))
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
    use std::collections::HashMap;
    use std::path::PathBuf;

    fn stage() -> RootfsStage {
        RootfsStage {
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

    // ART-9: the OCI rootfs does NOT consume the kernel (it boots no VM), so a kernel
    // rebuild must NOT invalidate the OCI rootfs key. Folding *all* upstream artifacts (the
    // bug) reddens the assertion. (The in-VM `mmdebstrap` source, which consumes the seed
    // kernel, folds it in its own key in `vmcell-rootfs-builder`.)
    #[test]
    fn test_rootfs_oci_key_ignores_kernel() {
        let dir = tempfile::tempdir().expect("tempdir");
        let kernel = write_tmp(dir.path(), "vmlinux", b"kernel-v1");
        let mut inputs = StageInputs::default();
        inputs
            .artifacts
            .insert("kernel".to_string(), kernel.clone());

        let oci = stage();
        let oci_k1 = oci.cache_key(&inputs);
        std::fs::write(&kernel, b"kernel-v2-rebuilt").expect("write");
        let oci_k2 = oci.cache_key(&inputs);
        assert_eq!(
            oci_k1, oci_k2,
            "a kernel rebuild must NOT invalidate the OCI rootfs key (kernel not consumed)"
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

    // H-ART-1: the injected static-musl agent must be folded by CONTENT, not by its path
    // string. When `agent_musl` is set the GuestAgentStage is skipped, so the agent has no
    // other content identity in the key — rebuilding it at the SAME path must invalidate the
    // rootfs. The buggy path-string fold leaves k1 == k2 (same path) -> red here.
    #[test]
    fn test_rootfs_agent_musl_key_tracks_content() {
        let dir = tempfile::tempdir().expect("tempdir");
        let agent = write_tmp(dir.path(), "agent-musl", b"musl-v1");
        let s = RootfsStage {
            image_override: None,
            agent_musl: Some(agent.clone()),
        };
        let inputs = StageInputs::default();
        let k1 = s.cache_key(&inputs);
        // Rebuild the musl agent in place at the SAME path.
        std::fs::write(&agent, b"musl-v2-rebuilt-at-same-path").expect("write");
        let k2 = s.cache_key(&inputs);
        assert_ne!(
            k1, k2,
            "a rebuilt agent-musl at the same path must invalidate the rootfs key (H-ART-1)"
        );
    }

    // Guards M-PIPE-2 (moved from the mmdebstrap module with `resolve_builder_base`): image
    // and digest must resolve as ONE atomic pair, never an independent fallback that pairs a
    // pinned image with a hardcoded digest. Each branch is red on the buggy per-half-default
    // impl. The in-VM builder crates rely on this shared resolver.
    #[test]
    fn test_resolve_builder_base_pairs_atomically() {
        // image without digest must error (not pair with a hardcoded digest).
        let mut half = HashMap::new();
        half.insert(
            "rootfs_image".to_string(),
            "docker.io/library/debian".to_string(),
        );
        assert!(
            resolve_builder_base(&half).is_err(),
            "image without digest must error, not pair with a hardcoded digest"
        );

        // digest without image must also error.
        let mut half2 = HashMap::new();
        half2.insert("rootfs_digest".to_string(), "sha256:abc".to_string());
        assert!(resolve_builder_base(&half2).is_err());

        // Completely missing base errors (no hardcoded fallback masks a missing pin).
        assert!(resolve_builder_base(&HashMap::new()).is_err());

        // A complete rootfs pair resolves atomically.
        let mut full = HashMap::new();
        full.insert("rootfs_image".to_string(), "img".to_string());
        full.insert("rootfs_digest".to_string(), "sha256:abc".to_string());
        assert_eq!(
            resolve_builder_base(&full).expect("pair"),
            ("img".to_string(), "sha256:abc".to_string())
        );

        // Dedicated builder pins take precedence over the rootfs pins.
        let mut both = full.clone();
        both.insert("builder_base_image".to_string(), "bimg".to_string());
        both.insert("builder_base_digest".to_string(), "sha256:def".to_string());
        assert_eq!(
            resolve_builder_base(&both).expect("pair"),
            ("bimg".to_string(), "sha256:def".to_string())
        );
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
