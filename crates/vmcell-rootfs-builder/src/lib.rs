//! In-VM `mmdebstrap` rootfs builder (design §4.3, The rootfs-construction contract).
//!
//! Where `vmcell`'s bootstrap rootfs source pulls and unpacks an OCI base image on the host
//! ([`vmcell::artifact::rootfs::RootfsStage`]), this crate builds a full-apt Debian rootfs by
//! booting a `vmcell` builder micro-VM, running `apt-get install mmdebstrap` and then
//! `mmdebstrap` against the pinned `snapshot.debian.org` archive over the steward. The
//! resulting rootfs tar is packed to the final erofs by `vmcell`'s shared inject+CA tail
//! [`vmcell::artifact::rootfs::pack_erofs_with_injection`], so it is injected and made
//! byte-deterministic exactly like the OCI source (§4.3, The rootfs-construction contract).
//!
//! It is a [`vmcell::artifact::Stage`] so `vmcell-cli` can wire it into a `vmcell`
//! [`vmcell::artifact::Pipeline`] in place of the OCI [`vmcell::artifact::rootfs::RootfsStage`].
//! It depends on `vmcell`; `vmcell` has no dependency on this crate (§9.1, Workspace layout).
//!
//! ## Networking
//! `apt`/`mmdebstrap` need a live Debian mirror, so the builder VM boots on the **privileged**
//! network path (`NetConfig::Privileged { egress: Egress::Open }`, netns + tap + nft
//! masquerade) — a build-time developer/CI operation where `CAP_NET_ADMIN` is acceptable
//! (§17, Open gaps and future capabilities). apt still performs the full in-guest gpg chain verification against the base
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
        // AGENTS.md "Fail loud": no bare `let _ =` on a `Result`. `let_underscore_must_use` is the
        // narrowest instrument rustc/clippy has for that rule — and it is deliberately BROADER on
        // one axis, firing on any `#[must_use]` expression (a detached `JoinHandle`, a discarded
        // `Instant`), which is the same defect one step out: the compiler said this matters and the
        // code said nothing back. Scoped `not(test)` like every lint in this block: the rule's
        // stated harms (a swallowed teardown failure, a lost write, a wedged session) are
        // production harms, and forcing a reason onto a test's `try_init()` would manufacture the
        // hollow suppressions AGENTS.md rule 2 calls theater. `crates/vmcell/tests/lint_roster.rs`
        // is the gate that this line exists in EVERY crate root, so a new crate cannot opt out by
        // being new.
        clippy::let_underscore_must_use,
        clippy::allow_attributes,               // B11: prefer #[expect] over #[allow] in prod code
        clippy::allow_attributes_without_reason  // B11: every suppression states why
    )
)]

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use vmcell::artifact::rootfs::{
    ExtraFile, fold_rootfs_injection_identity, pack_erofs_with_injection, resolve_builder_base,
};
use vmcell::artifact::{CacheKey, Stage, StageInputs, StageOutputs};
use vmcell::config::{Access, CachePolicy, Egress, NetConfig, RootfsSource, Share, VmConfig};
use vmcell::error::{Error, Result};
use vmcell::orchestrator::MicroVm;
use vmcell::vmm::CidAllocator;
use vmcell::vmm::cloud_hypervisor::CloudHypervisor;
use vmcell::{ExecOutcome, ExecRequest};

/// A pipeline stage that builds a Debian rootfs with `mmdebstrap` inside a builder micro-VM
/// (§4.3, The rootfs-construction contract), producing the `rootfs` erofs artifact exactly like the OCI bootstrap source.
pub struct MmdebstrapRootfsStage {
    /// The Debian release suite to bootstrap (e.g. `"trixie"`).
    pub release: String,
    /// CID allocator for the builder VM this stage boots.
    pub cid_alloc: Arc<CidAllocator>,
    /// Downstream files composed into the produced rootfs at pack time (§4.2, FR-V4). Empty
    /// for the default `vmcell build --rootfs-source mmdebstrap`.
    pub extra: Vec<ExtraFile>,
}

/// The mmdebstrap rootfs stage's cache-key version. Bump when this stage's build logic or its
/// folded identity changes so stale outputs are not served — the rootfs is a warm-cache
/// artifact, and an identity-fold change without the bump serves a stale image while every
/// test stays green (the recorded v20 precedent).
///
/// v30 (§18 delta 6): bumped to 2 — [`fold_rootfs_injection_identity`] gained the sorted
/// downstream extra-file triples.
/// v33 (§18 delta 7): bumped to 3 — the same shared fold gained the artifact's `XattrPolicy`,
/// which it folds unconditionally, so every key this stage has ever produced moves, **and** the
/// handler applet roster (the delta-6b gap, folded in the same bump because neither had shipped in
/// a released version). The fold now takes the whole `PackOptions`, which is what makes a
/// never-folded field a compile error there instead of a stale-cache hit here. The OCI
/// stage's own version bumps in the same edit and for the same reason: one fold, two callers,
/// and a caller that skipped the bump would serve its stale image while the other re-packed.
///
/// Module-level (rather than a `fn`-local `const`) so the bump itself is assertable KVM-free:
/// `mmdebstrap_stage_version_pins_the_identity_fold_bumps`.
const MMDEBSTRAP_STAGE_VERSION: u32 = 3;

/// The `deb` source line pointing at the pinned `snapshot.debian.org` archive. Kept a **pure**
/// function so the pin-driven mirror string is unit-testable. `[check-valid-until=no]` disables
/// only the Valid-Until freshness window (required for old snapshot timestamps), NEVER signature
/// verification; `http://` is safe because the content is gpg-signed (§10.3, External access, signing, and determinism scope).
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
        let mut hasher = blake3::Hasher::new();
        hasher.update(&MMDEBSTRAP_STAGE_VERSION.to_le_bytes());
        // The shared injected-content identity (steward + CA + steward source + the
        // downstream extra files), ONE implementation reused from `vmcell` (§4.3, The
        // rootfs-construction contract). mmdebstrap always uses the default glibc steward (its
        // Debian rootfs ships libc6), so no musl override.
        // Through `pack_options()` — the same struct `run` packs with — so the policy folded here
        // is by construction the policy the tail honors.
        let options = self.pack_options();
        fold_rootfs_injection_identity(&mut hasher, inputs, &options);
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
        // Consumed upstream artifacts, content-hashed in sorted order — read off the very
        // `PackOptions` folded above, so this stage's identity and the tail's lookups name one
        // handler.
        let consumed = Self::consumed_artifact_keys(&options);
        let filtered: std::collections::HashMap<String, std::path::PathBuf> = inputs
            .artifacts
            .iter()
            .filter(|(k, _)| consumed.iter().any(|c| c == k.as_str()))
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
            // The builder VM uses the default glibc steward (its OCI base ships libc6), no
            // downstream extra files, and the default handler's applet roster: this is the BUILDER
            // VM's own rootfs, not the rootfs being produced. Baking a consumer's daemon into
            // vmcell's build infrastructure (and into its cache key) is exactly what §13 invariant
            // G1 forbids; `self.extra` belongs on the final pack below.
            &vmcell::artifact::rootfs::PackOptions::new(),
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
        })
        .build()?;

        let vmm = CloudHypervisor::new(vmcell::artifact::ch_binary_path());
        // Bundle the builder's shared CID allocator with fresh (in-process) vmid +
        // default cgroup/clock/overlay seams into one `HostEnv` (design §18, Delta register: changes from the validated v27 build, delta 1).
        let mut env = vmcell::HostEnv::hermetic();
        env.cids = self.cid_alloc.clone();
        let mut vm = MicroVm::start(&vmm, cfg, &env).await?;

        let release = self.release.clone();
        let build_res = async {
            let steward = vm.steward(None).await?;

            let update = steward
                .exec(
                    ExecRequest::new(vec!["apt-get".into(), "update".into()])
                        .with_timeout(Duration::from_secs(120)),
                )
                .await?;
            check_step("apt-get update", &update)?;

            let install = steward
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
            let mmd = steward
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
        pack_erofs_with_injection(vec![tar_stream], inputs, out, &self.pack_options()).await
    }
}

impl MmdebstrapRootfsStage {
    /// The upstream artifacts this stage's identity folds: the seed `kernel` (it boots the builder
    /// VM, so a different seed is a different build — the OCI source consumes no kernel and folds
    /// none), plus the two binaries the shared inject+pack tail bakes.
    ///
    /// The handler entry is the key the **tail** reads — [`PackOptions::handler_key`], the one law —
    /// never the `"guest_tools"` literal it used to be. That literal is the H1 shape: it is correct
    /// only for the default handler, which is the only one this source can carry today, and a fold
    /// that agrees with the tail by coincidence stops agreeing the moment the coincidence ends. H1
    /// hid for a release exactly this way — a second spelling of "which handler is this?" that was
    /// right until a label appeared, at which point the identity keyed off one binary while the
    /// image baked another.
    ///
    /// Owned `String`s rather than `&str`, because the handler key is composed, not a literal.
    fn consumed_artifact_keys(options: &vmcell::artifact::rootfs::PackOptions) -> [String; 3] {
        [
            "kernel".to_string(),
            "steward".to_string(),
            options.handler_key(),
        ]
    }

    /// What this source tells the one inject+pack tail — read by `cache_key` AND by `run`, the
    /// way [`vmcell::artifact::rootfs::RootfsStage::pack_options`] is, so the identity this stage
    /// folds and the options it actually packs with cannot drift into agreeing by accident.
    fn pack_options(&self) -> vmcell::artifact::rootfs::PackOptions {
        vmcell::artifact::rootfs::PackOptions::new()
            .with_extra(self.extra.clone())
            // `Strip`, stated rather than defaulted: this source BUILDS its base with mmdebstrap
            // instead of resolving a registry entry, so it reads no `xattrs` declaration — §4.7 puts
            // the policy on the artifact, and this stage carries no field for one. That is a
            // *refusal*, not a silent drop: the composition root refuses a `rootfs` entry declaring
            // a non-default `xattrs` (or `format`) against this source
            // (`vmcell-cli`'s `reject_unproducible_rootfs_entry_for_mmdebstrap`), because the default
            // entry does describe the `rootfs.erofs` this stage writes. The day this source honors a
            // declaration, this is the one line that moves — and that refusal is what goes with it.
            .with_xattrs(vmcell::artifact::rootfs::XattrPolicy::Strip)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stage() -> MmdebstrapRootfsStage {
        MmdebstrapRootfsStage {
            release: "trixie".into(),
            cid_alloc: Arc::new(CidAllocator::new()),
            extra: Vec::new(),
        }
    }

    // Quality-gates v4 row 6, carried forward: this stage shares
    // `fold_rootfs_injection_identity` with the OCI stage, so EVERY change to what that fold
    // hashes must bump this const too — an un-bumped version serves the previously-packed rootfs
    // from the warm cache while every KVM-free test stays green (the recorded v20 precedent).
    // Two bumps live behind this literal: v30 delta 6 (→ 2, the extra-file triples) and v33
    // delta 7 (→ 3, the `XattrPolicy` folded unconditionally, plus the delta-6b applet roster).
    //
    // A literal-value assertion on purpose: a TRIPWIRE, not a derivation. RED on the inverse:
    // reverting the const to 2.
    #[test]
    fn mmdebstrap_stage_version_pins_the_identity_fold_bumps() {
        assert_eq!(
            MMDEBSTRAP_STAGE_VERSION, 3,
            "an identity-fold change requires this stage-version bump; without it a stale rootfs \
             is served from the warm cache. `fold_rootfs_injection_identity` is SHARED with the \
             OCI stage — if you bumped OCI_ROOTFS_STAGE_VERSION, bump this one too"
        );
    }

    // §18 delta 7, from the CONSUMER's position: this crate calls the shared, contract-surface
    // `fold_rootfs_injection_identity`, so it is this crate's key that goes stale if that fold
    // ever stops distinguishing the policies. Asserted here rather than only in `vmcell` because
    // the failure mode is cross-crate: `vmcell` could keep its own gate green with a fold that
    // reads the policy from somewhere this caller does not pass it.
    //
    // NOT asserted here: `stage().pack_options().xattrs == Strip`. That was the first draft, and
    // it CANNOT FAIL — `Strip` is the default, so deleting the `.with_xattrs(...)` line it exists
    // to guard leaves it green. It is recorded as documentation in `pack_options`' own comment
    // instead, where it is a stated choice rather than a gate pretending to be one.
    //
    // RED on the inverse: delete the `xattrs` fold at the tail of
    // `fold_rootfs_injection_identity` — both digests collapse to one.
    /// Folds one `PackOptions` through the shared, contract-surface identity fold. A helper so the
    /// two gates below differ in exactly the field under test and nothing else.
    fn fold_of(options: &vmcell::artifact::rootfs::PackOptions) -> String {
        let mut hasher = blake3::Hasher::new();
        fold_rootfs_injection_identity(&mut hasher, &StageInputs::default(), options);
        hasher.finalize().to_hex().to_string()
    }

    #[test]
    fn the_shared_fold_distinguishes_the_xattr_policies() {
        use vmcell::artifact::rootfs::{PackOptions, XattrPolicy};
        assert_ne!(
            fold_of(&PackOptions::new().with_xattrs(XattrPolicy::Strip)),
            fold_of(&PackOptions::new().with_xattrs(XattrPolicy::Preserve)),
            "the shared injected-content fold must make the xattr policy part of the rootfs \
             identity, or this stage serves a `Strip`-packed image for a `Preserve` declaration"
        );
    }

    // §18 delta 6b's gap, closed in delta 7, asserted from the CONSUMER's position for the same
    // reason the policy gate above is: this crate calls the shared fold, so it is this crate's key
    // that goes stale if the fold ever stops distinguishing rosters. The roster decides which
    // `<tools_dir>/<applet>` symlinks the tail bakes — the binary's content is identical either
    // way, so nothing else in the key moves when the roster does.
    //
    // RED on the inverse: delete the `applets` fold at the tail of
    // `fold_rootfs_injection_identity` — the two digests collapse to one.
    #[test]
    fn the_shared_fold_distinguishes_the_applet_rosters() {
        use vmcell::artifact::rootfs::PackOptions;
        let one = PackOptions::new().with_applets(vec!["ip".into(), "curl".into()]);
        let other = PackOptions::new().with_applets(vec!["ip".into()]);
        assert_ne!(
            fold_of(&one),
            fold_of(&other),
            "the shared injected-content fold must make the applet roster part of the rootfs \
             identity, or two handlers over one multicall binary share a key and this stage serves \
             the first roster's symlink set for the second roster's declaration"
        );
        assert_eq!(
            fold_of(&one),
            fold_of(&PackOptions::new().with_applets(vec!["ip".into(), "curl".into()])),
            "the same roster must fold to the same identity — a key that moved without the image \
             moving re-packs a multi-minute artifact for nothing"
        );
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

    // docs/90 H1, this crate's copy of it: the consumed-artifact set names the handler through the
    // ONE key law (`PackOptions::handler_key`), never a `"guest_tools"` literal. The literal was
    // right here — this source carries no handler label, so the default key IS `guest_tools` — and
    // that is precisely how H1 hid in `vmcell` for a release: a fold that agrees with the pack tail
    // by coincidence.
    //
    // Driven with a LABEL, which the shipped stage cannot produce today, because the coincidence is
    // what has to be tested: with the literal restored, the labelled case folds the default
    // handler's binary into the identity of an image packed from a different one.
    //
    // RED on the inverse: put `["kernel", "steward", "guest_tools"]` back in
    // `consumed_artifact_keys` — the labelled assertion fails naming `guest_tools`.
    #[test]
    fn the_consumed_set_names_the_handler_through_the_one_key_law() {
        use vmcell::artifact::handler::handler_artifact_key;
        use vmcell::artifact::rootfs::PackOptions;

        // The shipped shape: no label ⇒ the default handler's key, bit-for-bit what this stage has
        // always folded (so no existing artifact re-keys).
        assert_eq!(
            MmdebstrapRootfsStage::consumed_artifact_keys(&stage().pack_options()),
            [
                "kernel".to_string(),
                "steward".to_string(),
                handler_artifact_key(None)
            ],
        );

        // The discriminating shape: a labelled handler is published under `guest_tools-<label>`, and
        // that is the key the tail looks up — so it must be the key folded here.
        let labelled = PackOptions::new().with_handler_label(Some("acme"));
        assert_eq!(
            MmdebstrapRootfsStage::consumed_artifact_keys(&labelled)[2],
            handler_artifact_key(Some("acme")),
            "the fold must name the handler the tail reads, or the identity describes a binary the \
             image does not contain (H1)"
        );
        // …and the two are genuinely different keys, so the assertion above is not a tautology about
        // one string.
        assert_ne!(
            handler_artifact_key(Some("acme")),
            handler_artifact_key(None)
        );
    }

    // The consumed set is not just composed correctly, it is what `cache_key` actually filters on:
    // the default handler's binary content moves this stage's key. Without this leg the composer
    // above could be correct and unused (the H1 failure was a correct law with an unchanged call
    // site).
    //
    // RED on the inverse: drop the handler entry from `consumed_artifact_keys` — the key stops
    // moving and the two digests collapse.
    #[test]
    fn the_cache_key_folds_the_handler_binary_it_consumes() {
        use vmcell::artifact::handler::handler_artifact_key;

        let dir = tempfile::tempdir().expect("tempdir");
        let tools = dir.path().join("guest-tools");
        let s = stage();

        let key_of = |content: &[u8]| {
            std::fs::write(&tools, content).expect("write handler binary");
            let mut i = inputs();
            i.artifacts
                .insert(handler_artifact_key(None), tools.clone());
            s.cache_key(&i)
        };

        assert_ne!(
            key_of(b"handler v1"),
            key_of(b"handler v2"),
            "rebuilding the handler binary must invalidate this stage's key — the tail bakes it into \
             the image"
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
