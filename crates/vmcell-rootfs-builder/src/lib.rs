//! In-VM `mmdebstrap` rootfs builder (design §5.4).
//!
//! Where `vmcell`'s bootstrap rootfs source pulls and unpacks an OCI base image on the host
//! ([`vmcell::artifact::rootfs::RootfsStage`]), this crate builds a full-apt Debian rootfs by
//! booting a `vmcell` builder micro-VM, running `apt-get install mmdebstrap` and then
//! `mmdebstrap` against the pinned `snapshot.debian.org` archive over the guest agent. The
//! resulting rootfs tar is packed to the final erofs by `vmcell`'s shared inject+CA tail
//! [`vmcell::artifact::rootfs::pack_erofs_with_injection`], so it is injected and made
//! byte-deterministic exactly like the OCI source (§5.4).
//!
//! It is a [`vmcell::artifact::Stage`] so `vmcell-cli` can wire it into a `vmcell`
//! [`vmcell::artifact::Pipeline`] in place of the OCI [`vmcell::artifact::rootfs::RootfsStage`].
//! It depends on `vmcell`; `vmcell` has no dependency on this crate (§10.1).
//!
//! ## Networking
//! `apt`/`mmdebstrap` need a live Debian mirror, so the builder VM boots on the **privileged**
//! network path (`NetConfig::Privileged { egress: Egress::Open }`, netns + tap + nft
//! masquerade) — a build-time developer/CI operation where `CAP_NET_ADMIN` is acceptable
//! (§16). apt still performs the full in-guest gpg chain verification against the base
//! image's `debian-archive-keyring`.
#![deny(missing_docs, unsafe_op_in_unsafe_fn, rustdoc::broken_intra_doc_links)]
#![deny(unreachable_pub)] // pub-in-private-module API-surface honesty
#![deny(
    clippy::undocumented_unsafe_blocks,
    clippy::missing_safety_doc,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::multiple_unsafe_ops_per_block // one obligation per SAFETY comment
)]
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::panic,
        clippy::unreachable,
        clippy::todo,
        clippy::unimplemented,
        clippy::indexing_slicing,
        clippy::print_stdout,
        clippy::print_stderr,
        clippy::dbg_macro,
        clippy::allow_attributes,               // B11: prefer #[expect] over #[allow] in prod code
        clippy::allow_attributes_without_reason  // B11: every suppression states why
    )
)]

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use vmcell::artifact::rootfs::{
    fold_rootfs_injection_identity, pack_erofs_with_injection, resolve_builder_base,
};
use vmcell::artifact::{CacheKey, Stage, StageInputs, StageOutputs};
use vmcell::config::{Access, CachePolicy, Egress, NetConfig, RootfsSource, Share, VmConfig};
use vmcell::error::{Error, Result};
use vmcell::orchestrator::{MicroVm, RealClock, VmidAllocator};
use vmcell::vmm::CidAllocator;
use vmcell::vmm::cloud_hypervisor::CloudHypervisor;
use vmcell::{ExecOutcome, ExecRequest};

/// A pipeline stage that builds a Debian rootfs with `mmdebstrap` inside a builder micro-VM
/// (§5.4), producing the `rootfs` erofs artifact exactly like the OCI bootstrap source.
pub struct MmdebstrapRootfsStage {
    /// The Debian release suite to bootstrap (e.g. `"trixie"`).
    pub release: String,
    /// CID allocator for the builder VM this stage boots.
    pub cid_alloc: Arc<CidAllocator>,
}

/// The `deb` source line pointing at the pinned `snapshot.debian.org` archive. Kept a **pure**
/// function so the pin-driven mirror string is unit-testable. `[check-valid-until=no]` disables
/// only the Valid-Until freshness window (required for old snapshot timestamps), NEVER signature
/// verification; `http://` is safe because the content is gpg-signed (§11.2).
fn mirror_line(timestamp: &str, release: &str) -> String {
    format!(
        "deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/{timestamp}/ {release} main"
    )
}

/// Turns a guest [`ExecOutcome`] into a fail-loud [`Result`]: a non-zero exit at any step is a
/// hard [`Error::Artifact`] carrying the step + stderr, never an "any-result → success" swallow.
///
/// # Errors
/// [`Error::Artifact`] when `outcome.code != 0`.
fn check_step(step: &str, outcome: &ExecOutcome) -> Result<()> {
    if outcome.code != 0 {
        return Err(Error::Artifact(format!(
            "mmdebstrap build step `{step}` failed with code {}: {}",
            outcome.code,
            String::from_utf8_lossy(&outcome.stderr)
        )));
    }
    Ok(())
}

#[async_trait]
impl Stage for MmdebstrapRootfsStage {
    fn name(&self) -> &str {
        "rootfs"
    }

    fn out_path(&self, target_dir: &Path) -> std::path::PathBuf {
        target_dir.join("rootfs.erofs")
    }

    fn cache_key(&self, inputs: &StageInputs) -> CacheKey {
        // Bump when this stage's build logic changes so stale outputs are not served.
        const STAGE_VERSION: u32 = 1;
        let mut hasher = blake3::Hasher::new();
        hasher.update(&STAGE_VERSION.to_le_bytes());
        // The shared injected-content identity (agent + CA + guest-agent source), ONE
        // implementation reused from `vmcell` (§5.4). mmdebstrap always uses the default
        // glibc agent (its Debian rootfs ships libc6), so no musl override.
        fold_rootfs_injection_identity(&mut hasher, inputs, None);
        hasher.update(b"mmdebstrap");
        hasher.update(self.release.as_bytes());
        hasher.update(
            inputs
                .pins
                .get("debian_snapshot_timestamp")
                .map(String::as_bytes)
                .unwrap_or_default(),
        );
        // The builder-base image@digest the builder VM boots on (its apt toolchain builds the
        // rootfs), resolved the same way `run()` does. A resolution failure folds empty
        // strings; `run()` re-resolves and fails loud on a genuinely-missing pin.
        let (builder_image, builder_digest) =
            resolve_builder_base(&inputs.pins).unwrap_or_default();
        hasher.update(builder_image.as_bytes());
        hasher.update(b"\0");
        hasher.update(builder_digest.as_bytes());
        // Consumed upstream artifacts: the seed `kernel` (boots the builder VM) plus the
        // injected `guest_agent`/`guest_tools`, content-hashed in sorted order.
        let consumed: &[&str] = &["kernel", "guest_agent", "guest_tools"];
        let filtered: std::collections::HashMap<String, std::path::PathBuf> = inputs
            .artifacts
            .iter()
            .filter(|(k, _)| consumed.contains(&k.as_str()))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        vmcell::artifact::hash_artifacts_sorted(&mut hasher, &filtered);
        CacheKey::new(format!("rootfs-mmdebstrap-{}", hasher.finalize().to_hex()))
    }

    async fn run(&self, inputs: &StageInputs, out: &Path) -> Result<StageOutputs> {
        let seed_kernel = inputs.artifacts.get("kernel").cloned().ok_or_else(|| {
            Error::Artifact("kernel artifact is required to boot the mmdebstrap builder VM".into())
        })?;
        let timestamp = inputs
            .pins
            .get("debian_snapshot_timestamp")
            .ok_or_else(|| Error::Artifact("Missing debian_snapshot_timestamp pin".into()))?
            .clone();

        // Builder-base rootfs via the OCI bootstrap source, from the resolved (atomic) pins.
        let (builder_image, builder_digest) = resolve_builder_base(&inputs.pins)?;
        let scratch = tempfile::TempDir::new().map_err(Error::Io)?;
        let builder_rootfs = scratch.path().join("builder_rootfs.erofs");
        tracing::info!("building mmdebstrap builder-VM rootfs from {builder_image}");
        vmcell::artifact::rootfs::oci::build_rootfs(
            &builder_image,
            &builder_digest,
            inputs,
            &builder_rootfs,
            // The builder VM uses the default glibc agent (its OCI base ships libc6).
            None,
        )
        .await?;

        // Read-write output share the guest writes `rootfs.tar` onto.
        let out_dir = tempfile::TempDir::new().map_err(Error::Io)?;
        let out_share = Share::new(
            "vmcell-out",
            out_dir.path().to_path_buf(),
            Access::ReadWrite,
            CachePolicy::Never,
        );

        // Boot on the privileged network path with open egress so apt reaches the mirror.
        let cfg = VmConfig::builder(
            seed_kernel,
            RootfsSource::Erofs {
                image: builder_rootfs,
            },
        )
        .with_share(out_share)
        .net(NetConfig::Privileged {
            egress: Egress::Open,
            host_services_port: None,
        })
        .build()?;

        let vmm = CloudHypervisor::new(vmcell::artifact::ch_binary_path());
        let mut vm = MicroVm::start(
            &vmm,
            cfg,
            self.cid_alloc.clone(),
            VmidAllocator::new(),
            Box::new(vmcell::metrics::DefaultCgroupFs),
        )
        .await?;

        let release = self.release.clone();
        let build_res = async {
            let agent = vm.agent(None, &RealClock).await?;

            let update = agent
                .exec(
                    ExecRequest::new(vec!["apt-get".into(), "update".into()])
                        .with_timeout(Duration::from_secs(120)),
                )
                .await?;
            check_step("apt-get update", &update)?;

            let install = agent
                .exec(
                    ExecRequest::new(vec![
                        "apt-get".into(),
                        "install".into(),
                        "-y".into(),
                        "mmdebstrap".into(),
                        "ca-certificates".into(),
                    ])
                    .with_timeout(Duration::from_secs(240)),
                )
                .await?;
            check_step("apt-get install mmdebstrap", &install)?;

            // apt's in-guest gpg chain (the base image's `debian-archive-keyring`) verifies the
            // pinned snapshot Release files; `[check-valid-until=no]` relaxes only freshness.
            let mmd = agent
                .exec(
                    ExecRequest::new(vec![
                        "mmdebstrap".into(),
                        "--variant=apt".into(),
                        "--include=curl,ca-certificates".into(),
                        release.clone(),
                        "/vmcell-out/rootfs.tar".into(),
                        mirror_line(&timestamp, &release),
                    ])
                    .with_timeout(Duration::from_secs(600)),
                )
                .await?;
            check_step("mmdebstrap", &mmd)?;
            Ok::<(), Error>(())
        }
        .await;

        // Tear down the builder VM even on error; surface a shutdown failure as a warning.
        if let Err(e) = vm.shutdown().await {
            tracing::warn!("failed to shut down mmdebstrap builder VM: {e}");
        }
        build_res?;

        // Pack the generated tar to the final erofs via vmcell's shared inject+CA tail.
        let tar_path = out_dir.path().join("rootfs.tar");
        if !tar_path.exists() {
            return Err(Error::Artifact(
                "mmdebstrap reported success but produced no rootfs.tar on the output share".into(),
            ));
        }
        let tar_file = std::fs::File::open(&tar_path).map_err(Error::Io)?;
        let tar_stream: Box<dyn std::io::Read + Send> = Box::new(tar_file);
        pack_erofs_with_injection(vec![tar_stream], inputs, out, None).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stage() -> MmdebstrapRootfsStage {
        MmdebstrapRootfsStage {
            release: "trixie".into(),
            cid_alloc: Arc::new(CidAllocator::new()),
        }
    }

    // The mirror line is built from the pinned timestamp + release, with `[check-valid-until=no]`
    // (freshness only) and the snapshot archive host. The inverse — dropping the timestamp or the
    // flag — would fetch a live/unpinned mirror or fail on an expired Release.
    #[test]
    fn test_mirror_line_uses_pinned_timestamp() {
        let line = mirror_line("20250101T000000Z", "trixie");
        assert!(line.contains("snapshot.debian.org/archive/debian/20250101T000000Z/"));
        assert!(line.contains("[check-valid-until=no]"));
        assert!(line.trim_end().ends_with("trixie main"));
    }

    // A non-zero exit at any guest step is a HARD error (never swallowed).
    #[test]
    fn test_check_step_nonzero_is_hard_error() {
        let bad = ExecOutcome::new(100, vec![], b"E: Unable to locate package".to_vec());
        assert!(matches!(
            check_step("apt-get install mmdebstrap", &bad),
            Err(Error::Artifact(_))
        ));
        assert!(check_step("apt-get update", &ExecOutcome::new(0, vec![], vec![])).is_ok());
    }

    fn inputs() -> StageInputs {
        let mut i = StageInputs::default();
        i.pins.insert("rootfs_image".into(), "img".into());
        i.pins.insert("rootfs_digest".into(), "sha256:aaa".into());
        i.pins.insert(
            "debian_snapshot_timestamp".into(),
            "20250101T000000Z".into(),
        );
        i
    }

    // M-ART-4: re-pointing the builder-base digest (or the dedicated builder_base_* pins) must
    // invalidate the key — the builder VM boots that base. The inverse (not folding it) reuses a
    // rootfs built by a different base.
    #[test]
    fn test_cache_key_tracks_builder_base() {
        let s = stage();
        let a = inputs();
        let ka = s.cache_key(&a);

        let mut b = inputs();
        b.pins.insert("rootfs_digest".into(), "sha256:bbb".into());
        assert_ne!(
            ka,
            s.cache_key(&b),
            "re-pointing the builder-base digest must change the key"
        );

        let mut c = inputs();
        c.pins.insert("builder_base_image".into(), "bimg".into());
        c.pins
            .insert("builder_base_digest".into(), "sha256:ccc".into());
        assert_ne!(
            ka,
            s.cache_key(&c),
            "dedicated builder-base pins must fold into the key"
        );
    }

    // The snapshot timestamp is part of the identity: a different pinned snapshot yields a
    // different rootfs, so the key must change.
    #[test]
    fn test_cache_key_tracks_snapshot_timestamp() {
        let s = stage();
        let a = inputs();
        let mut b = inputs();
        b.pins.insert(
            "debian_snapshot_timestamp".into(),
            "20250601T000000Z".into(),
        );
        assert_ne!(s.cache_key(&a), s.cache_key(&b));
    }
}
