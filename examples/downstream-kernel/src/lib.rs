//! What an out-of-repo vmcell consumer stands on, exercised from the consumer position.
//!
//! This crate is the living gate for the downstream toolkit contract (design §10.4, The downstream
//! toolkit contract): it owns a guest-kernel config fragment in *its* repo, builds a kernel carrying
//! it through the published toolkit (§5.6, The downstream kernel toolkit), asserts the fragment
//! actually survived `make olddefconfig`, and validates the result — with zero vmcell-source edits
//! and no fork of `pins.json`.
//!
//! Since v33 it also registers a **rootfs** and a **handler** through the same overlay (§10.5),
//! emits and reads back their feature-manifest declaration through the shipped pipeline (§7.4), and
//! drives the two-directional conformance kit's whole verdict law (§10.6) — the surface a consumer
//! now stands on that did not exist a register ago.
//!
//! **The fragment is mechanism, not consumer content** (invariant G1). `CONFIG_IKCONFIG` +
//! `CONFIG_IKCONFIG_PROC` are chosen because they are *self-proving*: a kernel built with them
//! exposes `/proc/config.gz`, a file that exists only if the fragment took, so the example can
//! assert on the data plane instead of on a proxy signal.
//!
//! **Reddening this crate is the intended failure mode of contract drift.** If a change to vmcell
//! breaks it, the fix is to reverse or version the contract change (the ledger at the top of
//! `crates/vmcell/Cargo.toml`), never to edit this crate back to green.
//!
//! The contract surface consumed here, item by item — **every row of the §10.4 list**, with the
//! parts a network-free, KVM-free consumer cannot reach named as scope rather than left implied:
//!
//! | §10.4 item | consumed by | out of this workspace's reach |
//! |---|---|---|
//! | pins schema + overlay, incl. v33's `rootfs` / `handlers` namespaces (§10.5) | [`overlay_path`], [`registry_entry`], [`rootfs_entry`], [`handler_entry`] | — |
//! | `Stage`, `Pipeline`, `ResolvePinsStage`, `StageInputs`/`StageOutputs`, `CacheKey`, the hash helpers | [`emit_feature_manifest`]; `tests/contract.rs`'s own `Stage` impl, folding both [`vmcell::artifact::hash_file`] and [`vmcell::artifact::hash_artifacts_sorted`] | — |
//! | the kernel build entry points + the resolved-config sidecar (§5.6) | [`vmcell::artifact::build_labelled_kernel`] (in `main.rs`), [`read_resolved_config`] | — |
//! | the **labelled rootfs / handler** build entry points (§10.5) | `RootfsFeaturesStage::labelled` in [`emit_feature_manifest`]; the `vmcell build --rootfs-label/--handler-label` legs in `ci-check.sh` | finishing a labelled *image* needs an OCI pull and finishing a labelled *handler* needs its digest-pinned fetch, so the selection surface and its refusals are pinned here and the pack itself is not |
//! | the **feature-manifest sidecar** (§7.4) | [`emit_feature_manifest`] → [`declaration`], through [`vmcell::feature::feature_manifest_path`] | — |
//! | `pack_erofs_with_injection` + `ExtraFile` + `XattrPolicy` (+ `RootfsFormat`) | [`pack_options`], and the erofs door's format refusal in `tests/contract.rs` | a completed pack needs a pulled base **and** a built steward, and the ext4 emitter additionally needs the external producer binary (§4.7); what is pinned here is the options composition, the reserved-dest law, the door's typed refusal and the filename laws |
//! | the `VMCELL_*` env table | [`artifacts_dir`], and the `getters` / `bins` probes in `main.rs` with their `ci-check.sh` legs | `VMCELL_SKIP_MANIFEST` — it is read only by vmcell's own `require_cap!` test helper and has no consumer-callable API, so there is nothing here to consume |
//! | the `vmcell-artifact-validator` battery + `KconfigValues`, incl. v33's `Warn`/`Unverified` (§10.6) | [`fragment_survived`], [`conformance_candidate`] + [`positive_control`], the five-state scripted battery in `tests/contract.rs`, and `validate` + `run_battery` in `main.rs` | a *live* absence probe (`snapshot_restore`) boots and snapshots, so the live leg declares only what this consumer's own artifacts claim; the judgement law itself is driven KVM-free through a scripted probe, which is the form §10.6 asks for |

#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]

use std::path::{Path, PathBuf};

use vmcell::artifact::handler::HandlerRegistryEntry;
use vmcell::artifact::rootfs::{ExtraFile, PackOptions, RootfsFeaturesStage, rootfs_filename};
use vmcell::artifact::{
    Cache, KernelRegistryEntry, Pipeline, ResolvePinsStage, RootfsFormat, RootfsRegistryEntry,
    XattrPolicy,
};
use vmcell::feature::{Feature, FeatureDeclaration, Source, feature_manifest_path};
use vmcell_artifact_validator::ArtifactSet;
use vmcell_artifact_validator::conformance::{ArtifactId, ConformanceSubject};
use vmcell_artifact_validator::kconfig::KconfigValues;

/// The `kernels.<label>` this consumer adds through its overlay, and therefore the name of the
/// kernel the toolkit builds (`vmlinux-ikconfig`).
pub const KERNEL_LABEL: &str = "ikconfig";

/// The `kernel_fragments.<NAME>` this consumer owns. vmcell never ships it; the overlay does.
pub const FRAGMENT_NAME: &str = "IKCONFIG";

/// The `rootfs.<label>` this consumer adds through its overlay (§10.5) — the artifact whose
/// declaration this workspace stands on, and therefore the name of the image
/// (`rootfs-acme.erofs`) and of its feature-manifest sidecar (`rootfs-acme.features`).
///
/// It registers the **same digest-pinned base** vmcell's own `rootfs.default` names, under a
/// different `xattrs` policy: a registration is a durable claim, so a label that pointed at a
/// fabricated digest would be a fixture rather than a consumer's entry, and nothing downstream
/// could cite it.
pub const ROOTFS_LABEL: &str = "acme";

/// The `handlers.<label>` this consumer adds through its overlay (§10.5) — the third artifact kind,
/// registered by digest because a path is an override and never a registration (F7).
pub const HANDLER_LABEL: &str = "acme";

/// The applet roster [`HANDLER_LABEL`] declares, which becomes the injection manifest's symlinks
/// (§10.5).
///
/// A consumer's roster is **data**, strict-parsed from its registry entry — there is no
/// `GUEST_TOOLS_APPLETS`-style const for it to be asserted against, and that asymmetry is the
/// contract's, not this example's.
pub const HANDLER_APPLETS: [&str; 2] = ["acme-probe", "acme-load"];

/// The in-guest destination this consumer composes into an image through
/// [`vmcell::artifact::rootfs::ExtraFile`] (§4.2 FR-V4) — a path under its own prefix, which is
/// exactly what `is_reserved_injection_path` (F5) must *not* reserve.
pub const INJECTED_DEST: &str = "/opt/acme/probe";

/// The [`ArtifactId`] the conformance battery reports this consumer's artifact pair under.
pub const CANDIDATE_ID: &str = "acme";

/// The [`ArtifactId`] of the paired positive control (§10.6): one id for the absence probe and the
/// control that keeps it honest, so the control cannot be dropped without the pairing reddening.
pub const CONTROL_ID: &str = "acme-positive-control";

/// The `xattrs` policy [`ROOTFS_LABEL`] declares, and therefore the
/// [`Feature::XattrPreserved`] stance vmcell **derives** from it (§4.7).
///
/// Stated here as the one fact this consumer asserts in both directions — the policy it wrote and
/// the derivation it expects — because the derivation is the half a consumer cannot see in its own
/// overlay: the entry says `"xattrs": "preserve"` and nothing in the JSON mentions the feature.
pub const DECLARED_XATTRS: XattrPolicy = XattrPolicy::Preserve;

/// The feature stance [`ROOTFS_LABEL`] declares by hand — the **non-derivable** half of its
/// `features` map (§7.4).
///
/// `false` is the interesting direction and the reason it is here: an artifact that declares a
/// feature absent is the one the §10.6 battery must probe *and* control for, and an under-claim
/// (it works anyway) is the `Warn` the two-directional kit exists to report.
pub const DECLARED_ABSENT: Feature = Feature::SnapshotRestore;

/// The feature this consumer's **kernel** declares, in the sidecar it authors beside its own
/// artifact (§7.4).
///
/// `proc_config_gz` is in vmcell's vocabulary *for* this example — it is the §5.6 data-plane proof —
/// and the kit has no probe for it, so the honest battery verdict is `Unverified` and the
/// differential proof is this workspace's own in-guest read of [`IN_GUEST_CONFIG`]. That pairing is
/// the point: the kit says what it cannot decide, and the consumer decides it another way.
pub const KERNEL_DECLARES: Feature = Feature::ProcConfigGz;

/// The symbols the fragment must leave **built in** (`=y`) in the resolved config.
///
/// `olddefconfig` silently drops any symbol whose dependencies are unmet (§5.6), so this list is
/// asserted against the *result* — the sidecar and, live, `/proc/config.gz` — never against the
/// fragment text that was submitted.
pub const REQUIRED_SYMBOLS: [&str; 2] = ["CONFIG_IKCONFIG", "CONFIG_IKCONFIG_PROC"];

/// The in-guest file that exists **only** when [`REQUIRED_SYMBOLS`] survived — the data-plane proof.
pub const IN_GUEST_CONFIG: &str = "/proc/config.gz";

/// This consumer's pins overlay (`$VMCELL_PINS`'s value for every leg of the example).
///
/// Baked from `CARGO_MANIFEST_DIR` at compile time, the way a cargo example addresses its own data
/// files: this crate is built and run on the same machine in every leg (its `ci-check.sh` and the
/// live CI job both run from the checkout).
#[must_use]
pub fn overlay_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("pins-overlay.json")
}

/// Where this consumer keeps its own artifacts: `$VMCELL_ARTIFACTS_DIR`, else a directory under
/// *this* workspace's `target/`.
///
/// Deliberately its own directory. `vmcell::artifact::artifacts_dir()` would resolve into the
/// vmcell checkout's `target/vmcell-artifacts` from here (its workspace-root ascent finds the
/// vmcell tree, because this example lives inside the repo), and a downstream build must never
/// write into — let alone clobber — the host project's artifact cache.
#[must_use]
pub fn artifacts_dir() -> PathBuf {
    std::env::var_os("VMCELL_ARTIFACTS_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("target/vmcell-artifacts"))
}

/// The [`KERNEL_LABEL`] entry of the merged (baseline + this consumer's overlay) `kernels`
/// registry.
///
/// This is the overlay half of the contract in one call: the label does not exist in vmcell's
/// committed `pins.json`, so a resolution that returns it proves the overlay was read, merged, and
/// its `fragments` key honored.
///
/// # Errors
/// Returns a message when the overlay cannot be resolved, when the label is absent (the overlay
/// was ignored — the failure this gate exists to catch), or when it declares the wrong fragments.
pub fn registry_entry() -> Result<KernelRegistryEntry, String> {
    let overlay = overlay_path();
    let registry = vmcell::artifact::resolve_kernel_registry(Some(&overlay))
        .map_err(|e| format!("resolving the kernels registry through {overlay:?} failed: {e}"))?;
    let entry = registry
        .iter()
        .find(|e| e.label == KERNEL_LABEL)
        .ok_or_else(|| {
            format!(
                "the resolved `kernels` registry has no `{KERNEL_LABEL}` label — the overlay \
                 {overlay:?} was not merged; resolved labels: [{}]",
                registry
                    .iter()
                    .map(|e| e.label.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        })?;
    if entry.fragments != vec![FRAGMENT_NAME.to_string()] {
        return Err(format!(
            "`kernels.{KERNEL_LABEL}.fragments` resolved to {:?}, expected [{FRAGMENT_NAME:?}]",
            entry.fragments
        ));
    }
    Ok(entry.clone())
}

/// The [`ROOTFS_LABEL`] entry of the merged `rootfs` registry, with the two facts this consumer
/// declared about it verified (§10.5, §4.7).
///
/// The v33 half of the overlay contract: the `rootfs` namespace did not exist before v33, so a
/// resolution that returns this label proves the new namespace is read and merged the way the
/// `kernels` one is. It checks its own declaration in **both** directions — the `xattrs` policy it
/// wrote, and the [`Feature::XattrPreserved`] stance vmcell derives from that policy — because the
/// derivation is the half no consumer can see in its own JSON, and a derivation that silently
/// stopped happening would leave this artifact claiming nothing while every build stayed green.
///
/// # Errors
/// Returns a message when the overlay cannot be resolved, when the label is absent (the `rootfs`
/// namespace was ignored — the failure this gate exists to catch), when the registration is not the
/// digest shape, or when either half of the declaration disagrees with what the overlay wrote.
pub fn rootfs_entry() -> Result<RootfsRegistryEntry, String> {
    let overlay = overlay_path();
    let entry = vmcell::artifact::resolve_rootfs_entry(Some(ROOTFS_LABEL), Some(&overlay))
        .map_err(|e| format!("resolving the rootfs registry through {overlay:?} failed: {e}"))?
        .ok_or_else(|| {
            format!(
                "the resolved `rootfs` registry has no `{ROOTFS_LABEL}` label — the overlay \
                 {overlay:?} was not merged into the v33 namespace"
            )
        })?;
    if entry.xattrs != DECLARED_XATTRS {
        return Err(format!(
            "`rootfs.{ROOTFS_LABEL}.xattrs` resolved to {:?}, expected {DECLARED_XATTRS:?} — the \
             policy this consumer declared was not honored",
            entry.xattrs
        ));
    }
    // The DERIVED stance (§4.7): one fact, one key. The overlay states the policy and never the
    // token, so this is the only place the consumer can observe that the derivation ran.
    match entry.features.get(&Feature::XattrPreserved) {
        Some(true) => {}
        other => {
            return Err(format!(
                "`{}` resolved to {other:?} for `rootfs.{ROOTFS_LABEL}`, expected Some(true) \
                 derived from `xattrs: {}` (§4.7) — the derivation is the artifact's whole claim, \
                 and an absent key reads as \"no stance\", not as \"preserved\"",
                Feature::XattrPreserved.name(),
                DECLARED_XATTRS.name()
            ));
        }
    }
    if entry.features.get(&DECLARED_ABSENT) != Some(&false) {
        return Err(format!(
            "`rootfs.{ROOTFS_LABEL}.features` lost the declared `{} = false` stance; resolved: {:?}",
            DECLARED_ABSENT.name(),
            entry.features
        ));
    }
    Ok(entry)
}

/// The [`HANDLER_LABEL`] entry of the merged `handlers` registry (§10.5) — the third artifact kind.
///
/// # Errors
/// Returns a message when the overlay cannot be resolved, when the label is absent, or when its
/// strict-parsed applet roster is not the one the overlay declared.
pub fn handler_entry() -> Result<HandlerRegistryEntry, String> {
    let overlay = overlay_path();
    let registry = vmcell::artifact::resolve_handler_registry(Some(&overlay))
        .map_err(|e| format!("resolving the handlers registry through {overlay:?} failed: {e}"))?;
    let entry = registry
        .iter()
        .find(|e| e.label == HANDLER_LABEL)
        .ok_or_else(|| {
            format!(
                "the resolved `handlers` registry has no `{HANDLER_LABEL}` label — the overlay \
                 {overlay:?} was not merged; resolved labels: [{}]",
                registry
                    .iter()
                    .map(|e| e.label.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        })?;
    let expected: Vec<String> = HANDLER_APPLETS.iter().map(|a| (*a).to_string()).collect();
    // `applet_roster()` and not the field: it is the one place a consumer's own roster and the
    // default handler's shared const meet, and an entry that lost its `applets` key would silently
    // fall back to vmcell's roster — an image full of applets this handler does not implement.
    if entry.applet_roster() != expected {
        return Err(format!(
            "`handlers.{HANDLER_LABEL}` resolved to the roster {:?}, expected {expected:?} — an \
             empty roster falls back to vmcell's own applets, which this handler does not carry",
            entry.applet_roster()
        ));
    }
    Ok(entry.clone())
}

/// Emits [`ROOTFS_LABEL`]'s feature-manifest sidecar into `target_dir` through the **shipped
/// pipeline**, and returns the sidecar's path (§7.4, §10.5).
///
/// This is the toolkit's own stage model driven from the consumer position: `ResolvePinsStage` (the
/// overlay, Stage 0) followed by `RootfsFeaturesStage::labelled` (the declaration producer), both
/// through [`Pipeline`]. It is the one *complete* v33 build a network-free consumer can run — the
/// image stage beside it needs an OCI pull — and it is the half that matters for the contract,
/// because the sidecar is how a declaration reaches a path-consuming cell.
///
/// The path is composed by [`vmcell::feature::feature_manifest_path`] over
/// [`vmcell::artifact::rootfs::rootfs_filename`], never by a local `format!`: both are contract
/// surface, and a second copy here is precisely the duplicate that drifts into a sidecar nobody
/// reads.
///
/// # Errors
/// Returns a message when the registry does not resolve, when the pipeline fails, when the sidecar
/// is not at the composed path, or when the pipeline did not register it as an artifact.
pub async fn emit_feature_manifest(target_dir: &Path) -> Result<PathBuf, String> {
    let entry = rootfs_entry()?;
    let pipeline = Pipeline::new(target_dir.to_path_buf())
        .add_stage(Box::new(ResolvePinsStage {
            overlay_file: Some(overlay_path()),
        }))
        .add_stage(Box::new(
            RootfsFeaturesStage::labelled(Some(ROOTFS_LABEL)).with_features(entry.features),
        ));
    let artifacts = pipeline
        .build(&Cache::default())
        .await
        .map_err(|e| format!("the declaration pipeline failed: {e}"))?;
    let sidecar = feature_manifest_path(
        &target_dir.join(rootfs_filename(Some(ROOTFS_LABEL), RootfsFormat::default())),
    );
    if !sidecar.is_file() {
        return Err(format!(
            "the feature manifest is not at {} — the sidecar naming law moved, and a reader \
             composing the same path finds nothing and falls back to the baseline (§7.4)",
            sidecar.display()
        ));
    }
    // …and the pipeline REGISTERED it, rather than merely leaving a file behind: a stage's payload
    // travels to the next stage through the artifact map, so an unregistered sidecar is one no
    // downstream stage can consume.
    if !artifacts.paths.values().any(|p| p == &sidecar) {
        return Err(format!(
            "the pipeline published {:?} but registered {:?}",
            sidecar, artifacts.paths
        ));
    }
    Ok(sidecar)
}

/// Reads the declaration that travels beside the rootfs image named by `image` (§7.4).
///
/// Through [`vmcell::feature::FeatureDeclaration::load_beside`] — the shipped reader, paired with
/// the shipped producer in [`emit_feature_manifest`] — so this consumer never becomes a second
/// place a declaration can come from.
///
/// # Errors
/// Returns a message when the sidecar exists but does not parse. An **absent** sidecar is the
/// baseline, not an error: that is the §7.4 law that keeps every pre-v33 artifact working, and
/// reporting it as a failure here would misstate the contract.
pub fn declaration(image: &Path) -> Result<FeatureDeclaration, String> {
    FeatureDeclaration::load_beside(image, Source::Rootfs(ROOTFS_LABEL.to_string())).map_err(|e| {
        format!(
            "the feature manifest beside {} is unreadable: {e}",
            image.display()
        )
    })
}

/// The [`PackOptions`] this consumer would hand the one inject+pack tail (§4.2, §10.5, §4.7).
///
/// Composed in **one** place so the labels, the roster, the policy and the injected file cannot be
/// spelled differently by the test that pins them and a caller that packs with them. Every field
/// comes from the resolved registry entries rather than from a literal: the handler label decides
/// which binary the tail bakes, the rootfs label decides which artifact key the image registers
/// under, and both were hardcoded defaults until v33 delta 6c — a labelled pack that silently
/// produced an image with no applets in it.
#[must_use]
pub fn pack_options(
    rootfs: &RootfsRegistryEntry,
    handler: &HandlerRegistryEntry,
    injected_src: &Path,
) -> PackOptions {
    PackOptions::new()
        .with_label(Some(&rootfs.label))
        .with_handler_label(Some(&handler.label))
        .with_applets(handler.applet_roster())
        .with_xattrs(rootfs.xattrs)
        .with_format(rootfs.format)
        .with_extra(vec![ExtraFile::new(INJECTED_DEST, injected_src, 0o644)])
}

/// The battery's candidate: this consumer's artifact pair, judged against the declaration that
/// travels with it (§10.6).
///
/// The declaration is passed in rather than read here, because §7.4 makes the registry entry the one
/// authority and the sidecar its travel form — a caller with a registry passes
/// [`rootfs_entry`]'s map, a caller with only files on disk passes [`declaration`]'s result, and
/// either way there is one authority.
#[must_use]
pub fn conformance_candidate(
    artifacts: ArtifactSet,
    declaration: FeatureDeclaration,
) -> ConformanceSubject {
    ConformanceSubject {
        id: ArtifactId::new(CANDIDATE_ID),
        artifacts,
        declaration,
    }
}

/// The paired **positive control** for `candidate`'s absence probes (§10.6): the same artifacts,
/// declaring `true` everywhere the candidate declares `false`.
///
/// One law, one composition, called by the KVM-free matrix and by the live leg alike. An absence
/// probe without a control is a constant that certifies everything — a probe that always answers
/// "absent" passes every absence check ever written — so the kit refuses to run when a control does
/// not declare what the candidate denies, and this is the function that keeps this consumer holding
/// up its end of that bargain.
#[must_use]
pub fn positive_control(candidate: &ConformanceSubject) -> ConformanceSubject {
    let stances = candidate
        .declaration
        .stances
        .iter()
        // Only the denied stances are flipped: a control that declared every feature present would
        // claim things about this artifact pair that nobody measured.
        .filter(|(_, stance)| !**stance)
        .map(|(feature, _)| (*feature, true))
        .collect();
    ConformanceSubject {
        id: ArtifactId::new(CONTROL_ID),
        artifacts: candidate.artifacts.clone(),
        declaration: FeatureDeclaration {
            source: candidate.declaration.source.clone(),
            stances,
        },
    }
}

/// Reads and parses the resolved-config sidecar published beside `kernel` (§5.6).
///
/// The sidecar path is composed by vmcell's own [`vmcell::artifact::kernel::resolved_config_path`]
/// rather than by a local `format!`: the naming rule is contract surface, and a second copy of it
/// here is precisely the duplicate that drifts.
///
/// # Errors
/// Returns a message when the sidecar is absent (a compiling producer that published nothing —
/// the silent-drop failure the sidecar exists to make loud) or does not parse as a `.config`.
pub fn read_resolved_config(kernel: &Path) -> Result<KconfigValues, String> {
    let sidecar = vmcell::artifact::kernel::resolved_config_path(kernel);
    let text = std::fs::read_to_string(&sidecar).map_err(|e| {
        format!(
            "resolved-config sidecar missing at {}: {e} — a compiling producer must publish it \
             beside the kernel (design §5.6); without it there is no evidence of what the kernel \
             actually contains",
            sidecar.display()
        )
    })?;
    KconfigValues::parse(&text)
        .map_err(|e| format!("sidecar {} is not a .config: {e}", sidecar.display()))
}

/// The **one** fragment-survival predicate, applied to every resolved config this example gets
/// hold of — the sidecar on the host and `/proc/config.gz` read back out of the booted guest.
///
/// One law, one predicate: two copies of "did the fragment take?" would let the host leg and the
/// guest leg disagree about what surviving means.
///
/// # Errors
/// Returns a message naming the first [`REQUIRED_SYMBOLS`] entry that is not built in, and
/// distinguishing "present but disabled" (the symbol's dependencies were unmet and
/// `olddefconfig` dropped it) from "never mentioned" (the fragment never reached the build).
pub fn fragment_survived(resolved: &KconfigValues, source: &str) -> Result<(), String> {
    for symbol in REQUIRED_SYMBOLS {
        if resolved.is_builtin(symbol) {
            continue;
        }
        return Err(match resolved.get(symbol) {
            Some(value) => format!(
                "{source}: `{symbol}` resolved to {value:?}, not `=y` — the `{FRAGMENT_NAME}` \
                 fragment reached the build but olddefconfig did not keep it built in"
            ),
            None => format!(
                "{source}: `{symbol}` is absent entirely — the `{FRAGMENT_NAME}` fragment never \
                 reached the build (check that `kernels.{KERNEL_LABEL}.fragments` resolved)"
            ),
        });
    }
    Ok(())
}

/// Asserts the config the guest reports contains every symbol/value the host-side sidecar
/// recorded — the round-trip half of the data-plane proof (§5.6).
///
/// A **subset**, not an equality, and the asymmetry is deliberate: `/proc/config.gz` is written by
/// kbuild from the same `.config` the sidecar was copied from, but it is regenerated by the build
/// and may carry symbols the copied file did not. Every symbol the sidecar recorded must appear in
/// the guest with the same value — that is what "the kernel that booted is the kernel whose config
/// we published" means, and it reddens if the sidecar belongs to a different build.
///
/// # Errors
/// Returns a message naming the first symbol that is missing or differs in the guest's copy, and
/// how many symbols were compared.
pub fn guest_config_round_trips(
    guest: &KconfigValues,
    sidecar: &KconfigValues,
) -> Result<usize, String> {
    for (symbol, value) in sidecar.iter() {
        match guest.get(symbol) {
            Some(in_guest) if in_guest == value => {}
            Some(in_guest) => {
                return Err(format!(
                    "{IN_GUEST_CONFIG} disagrees with the sidecar on `{symbol}`: guest {in_guest:?} \
                     vs sidecar {value:?} — the booted kernel is not the one the sidecar describes"
                ));
            }
            None => {
                return Err(format!(
                    "{IN_GUEST_CONFIG} does not mention `{symbol}`, which the sidecar records as \
                     {value:?} — the booted kernel is not the one the sidecar describes"
                ));
            }
        }
    }
    Ok(sidecar.len())
}
