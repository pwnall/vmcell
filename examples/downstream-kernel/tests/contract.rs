//! The KVM-free half of the downstream-contract gate (design §10.4).
//!
//! Everything here runs from the consumer position with no VM, no privileges and no network: the
//! overlay resolution (v30 delta 1), the sidecar naming rule and parser (v30 deltas 3 + 4), this
//! example's own survival predicates, and — since v33 — the three artifact-registry namespaces
//! (§10.5), the feature-manifest sidecar through the shipped pipeline (§7.4), the pack-surface
//! composition (§4.2/§4.7) and the two-directional conformance battery's whole verdict law (§10.6).
//! Each with the inverse that must redden it.
//!
//! The two env-driven groups (`VMCELL_*` override set present / absent, and the `*_BIN` resolvers)
//! are deliberately **not** here: `ensure_test_artifacts` memoizes per process and the resolvers
//! read the environment, so both need separate processes and live in `ci-check.sh` instead.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use downstream_kernel::{
    CANDIDATE_ID, CONTROL_ID, DECLARED_ABSENT, DECLARED_XATTRS, FRAGMENT_NAME, HANDLER_APPLETS,
    HANDLER_LABEL, INJECTED_DEST, KERNEL_DECLARES, KERNEL_LABEL, REQUIRED_SYMBOLS, ROOTFS_LABEL,
    conformance_candidate, declaration, emit_feature_manifest, fragment_survived,
    guest_config_round_trips, handler_entry, overlay_path, pack_options, positive_control,
    registry_entry, rootfs_entry,
};
use vmcell::artifact::rootfs::{
    RootfsFormat, is_reserved_injection_path, pack_erofs_with_injection,
    rootfs_artifact_from_filename, rootfs_filename,
};
use vmcell::artifact::{
    Cache, CacheKey, Pipeline, ResolvePinsStage, RootfsRegistration, Stage, StageInputs,
    StageOutputs, XattrPolicy,
};
use vmcell::error::{Error, Result};
use vmcell::feature::{Feature, FeatureDeclaration, Source, feature_manifest_path};
use vmcell::vmm::Vmm;
use vmcell::vmm::cloud_hypervisor::CloudHypervisor;
use vmcell_artifact_validator::conformance::{
    ArtifactId, ConformanceError, ConformanceOptions, ConformanceSubject, DEFAULT_BATTERY_BUDGET,
    EXPECTED_WARNINGS_CHECK_ID, FeatureProbe, ProbeOutcome, ProbePlan, Substrate,
    battery_check_ids, conformance_check_id, probe_plan, run_battery,
};
use vmcell_artifact_validator::kconfig::KconfigValues;
use vmcell_artifact_validator::{
    ArtifactSet, CheckStatus, DEFAULT_RUN_BUDGET, ValidationOptions, ValidationReport,
};

/// A resolved config in which both required symbols are built in — the shape a correct build
/// produces.
const SURVIVED: &str = "# Automatically generated file; DO NOT EDIT.\n\
                        CONFIG_IKCONFIG=y\n\
                        CONFIG_IKCONFIG_PROC=y\n\
                        CONFIG_EROFS_FS=y\n";

#[test]
fn the_overlay_adds_this_consumers_label_and_fragment() {
    // The contract's build half in one call: `ikconfig` exists in NO committed vmcell pins file,
    // so resolving it proves the overlay was found, merged, and its `fragments` key honored.
    let entry = registry_entry().expect("the overlay must resolve and declare the label");
    assert_eq!(entry.label, KERNEL_LABEL);
    assert_eq!(entry.fragments, vec![FRAGMENT_NAME.to_string()]);

    // …and the fragment NAME resolves to fragment TEXT, under the flattened pin key vmcell's own
    // flattener emits. The key is composed by `fragment_pin_key` — the exported law — never by a
    // local `format!`: re-deriving the spelling here is exactly the drift the composer was
    // exported to remove, and a consumer that guesses it gets a `Missing kernel_… pin` at build
    // time rather than a compile error. A label that resolved without its fragment text would
    // build an unmodified kernel and report success.
    let pins = vmcell::artifact::resolve_pins(Some(&overlay_path()))
        .expect("the overlay must resolve into the flat pin map");
    let text = pins
        .get(&vmcell::artifact::kernel::fragment_pin_key(FRAGMENT_NAME))
        .expect("the overlay's fragment must reach the flat pin map");
    for symbol in REQUIRED_SYMBOLS {
        assert!(
            text.contains(&format!("{symbol}=y")),
            "the fragment text must request {symbol}=y, got {text:?}"
        );
    }
    // The label's own source pins come from the overlay too (a labelled build with no source URL
    // would fail deep inside the producer instead of here). Composed through `kernel_pin_key` for
    // the same reason.
    assert!(
        pins.contains_key(&vmcell::artifact::kernel::kernel_pin_key(
            Some(KERNEL_LABEL),
            "source_url"
        )),
        "the overlay's kernels entry must contribute its source URL"
    );
}

#[test]
fn the_pin_keys_are_composed_by_vmcell_not_by_this_consumer() {
    // The pin-key spellings are contract surface, exactly like the sidecar path below, and this is
    // where the consumer position pins them. Both composers are called from
    // `the_overlay_adds_this_consumers_label_and_fragment` above, so that test moves WITH the law
    // and can no longer redden on a spelling change — which is correct (a consumer calling the law
    // is correct by construction) but would leave a silent change to the law unobserved
    // downstream. This test is the observation point: it asserts the composed spellings against
    // literals, so a change to either law reddens THIS example — the intended failure mode of
    // contract drift (§10.4) — instead of surfacing as a `Missing kernel_… pin` in a consumer's
    // build weeks later.
    //
    // Every expectation below is a BARE literal, never an interpolation of this consumer's own
    // constants. Two reasons, and both are load-bearing: an interpolated expectation moves with
    // `KERNEL_LABEL`, so it would keep passing if the label changed *and* stop pinning the law;
    // and `scripts/ban-kernel-key-composers.sh` bans exactly the interpolated shapes
    // (`"kernel_{`, `"kernel-{`) as re-derivations of the law, while sanctioning bare literals as
    // the way a test pins its output. Writing the pin the banned way would make this gate the
    // thing the other gate has to exempt.
    use vmcell::artifact::kernel::{fragment_pin_key, kernel_pin_key};

    assert_eq!(
        fragment_pin_key(FRAGMENT_NAME),
        "kernel_fragments_IKCONFIG",
        "the fragment pin-key law changed: `kernel_fragments_<NAME>` is what this consumer's \
         overlay and every downstream builder resolve through"
    );

    assert_eq!(
        kernel_pin_key(Some(KERNEL_LABEL), "source_url"),
        "kernel_ikconfig_source_url",
        "the labelled kernel pin-key law changed"
    );
    // A dotted label survives verbatim — the pin key never becomes a path, and a consumer that
    // sanitized it here would miss every labelled pin of a real kernel version.
    assert_eq!(
        kernel_pin_key(Some("6.12.94"), "source_sha256"),
        "kernel_6.12.94_source_sha256",
        "a dotted label must survive verbatim into the pin key"
    );

    // …and the unlabelled default route, which is a DIFFERENT shape (no label segment at all) —
    // without this leg a composer that ignored `None` and always inserted a segment would pass.
    assert_eq!(
        kernel_pin_key(None, "source_url"),
        "kernel_source_url",
        "the default (unlabelled) kernel pin-key law changed"
    );

    // The artifact-map key is the third exported spelling a downstream PRODUCER must register
    // under; a builder that guessed it would publish a `vmlinux` no vmcell stage ever reads.
    // Note the separator differs from the pin keys' (`-`, not `_`) — re-deriving that by hand is
    // precisely how a producer and its consumers drift apart with no compile error.
    assert_eq!(
        vmcell::artifact::kernel::kernel_artifact_key(Some(KERNEL_LABEL)),
        "kernel-ikconfig"
    );
    assert_eq!(
        vmcell::artifact::kernel::kernel_artifact_key(None),
        "kernel"
    );

    // Non-vacuity for the four label-bearing legs above: they are literals, so they would all
    // still pass if this consumer renamed its label out from under them. Anchoring the literals to
    // the constants the rest of this file uses is what keeps them honest.
    assert_eq!(KERNEL_LABEL, "ikconfig");
    assert_eq!(FRAGMENT_NAME, "IKCONFIG");
}

#[test]
fn without_the_overlay_the_committed_baseline_stands_alone() {
    // The fall-back half: no overlay ⇒ vmcell's own registry, byte-unchanged for consumers that do
    // not opt in. This is also the non-vacuity control for the test above — it proves the label
    // came from THIS consumer's overlay and not from vmcell's committed pins.
    let baseline = vmcell::artifact::resolve_kernel_registry(None)
        .expect("the committed baseline must resolve with no overlay");
    let labels: Vec<&str> = baseline.iter().map(|e| e.label.as_str()).collect();
    assert!(
        !labels.contains(&KERNEL_LABEL),
        "`{KERNEL_LABEL}` must NOT be in vmcell's committed registry — it is this consumer's own \
         label; resolved: {labels:?}"
    );
    assert!(
        !labels.is_empty(),
        "the committed baseline registry must not be empty (the resolution silently returned nothing)"
    );
}

#[test]
fn an_overlay_key_that_matches_no_pins_namespace_is_rejected_naming_it() {
    // The typo'd-override class, from the consumer position: `kernel_fragmets` matches no
    // namespace, so accepting it would silently resolve the whole fragment registry from the
    // baseline and build a kernel without the fragment — with a green log.
    let dir = tempfile::tempdir().expect("temp dir");
    let typo = dir.path().join("typo-overlay.json");
    std::fs::write(
        &typo,
        r#"{"kernel_fragmets": {"IKCONFIG": "CONFIG_IKCONFIG=y\n"}}"#,
    )
    .expect("write the typo'd overlay");

    let err = vmcell::artifact::resolve_pins(Some(&typo))
        .map(|p| format!("{p:?}"))
        .expect_err("a top-level key matching no pins namespace must be rejected");
    let msg = err.to_string();
    assert!(
        msg.contains("kernel_fragmets"),
        "the refusal must NAME the offending key so it can be fixed without guessing: {msg}"
    );
}

#[test]
fn the_sidecar_path_is_composed_by_vmcell_not_by_this_consumer() {
    // The naming rule is contract surface. Pinning it here means a change to it reddens this
    // example (the intended failure mode) rather than silently making every downstream sidecar
    // assertion look for the wrong file.
    let kernel = std::path::Path::new("/artifacts/vmlinux-ikconfig");
    assert_eq!(
        vmcell::artifact::kernel::resolved_config_path(kernel),
        std::path::PathBuf::from("/artifacts/vmlinux-ikconfig.config")
    );
}

#[test]
fn a_missing_resolved_config_sidecar_is_named_not_silently_skipped() {
    // The other half of v30 §18 delta 5's deliberate-red: with the sidecar dropped, the assertion must
    // fail NAMING the file it expected, never fall back to "no evidence, therefore fine". Every
    // compiling producer publishes it; a build that publishes none is exactly the silent-drop the
    // sidecar exists to expose.
    let dir = tempfile::tempdir().expect("temp dir");
    let kernel = dir.path().join("vmlinux-ikconfig");
    std::fs::write(&kernel, b"not really a kernel").expect("write the kernel stand-in");

    let err = downstream_kernel::read_resolved_config(&kernel)
        .map(|v| format!("{v:?}"))
        .expect_err("a missing sidecar must redden");
    assert!(
        err.contains("vmlinux-ikconfig.config"),
        "the refusal must name the sidecar it looked for: {err}"
    );

    // Positive control: with the sidecar present the same call succeeds, so the leg above is about
    // the missing file and not about the path composition.
    std::fs::write(kernel.with_extension("config"), SURVIVED).expect("write the sidecar");
    let values =
        downstream_kernel::read_resolved_config(&kernel).expect("a present sidecar parses");
    fragment_survived(&values, "positive control").expect("the fragment must read as surviving");
}

#[test]
fn the_survival_predicate_reddens_on_every_way_a_fragment_can_be_dropped() {
    // Positive control first: the shape a correct build produces must pass, or the negatives below
    // prove nothing.
    let ok = KconfigValues::parse(SURVIVED).expect("a resolved config must parse");
    fragment_survived(&ok, "positive control").expect("both symbols built in must pass");

    // Dropped by olddefconfig (dependencies unmet): present, disabled. The message must say so —
    // "absent" would send a fragment author looking in the wrong place.
    let dropped = KconfigValues::parse(
        "CONFIG_IKCONFIG=y\n# CONFIG_IKCONFIG_PROC is not set\nCONFIG_EROFS_FS=y\n",
    )
    .expect("parse");
    let err = fragment_survived(&dropped, "dropped").expect_err("a dropped symbol must redden");
    assert!(
        err.contains("CONFIG_IKCONFIG_PROC"),
        "must name the symbol: {err}"
    );
    assert!(
        err.contains("olddefconfig"),
        "must name the mechanism that dropped it: {err}"
    );

    // Never reached the build at all: the fragment was not applied.
    let absent = KconfigValues::parse("CONFIG_EROFS_FS=y\n").expect("parse");
    let err = fragment_survived(&absent, "absent").expect_err("an absent symbol must redden");
    assert!(
        err.contains("absent entirely"),
        "must distinguish absent: {err}"
    );

    // Built as a MODULE is not a satisfied clause — the guest has no early userspace to load it.
    let module =
        KconfigValues::parse("CONFIG_IKCONFIG=y\nCONFIG_IKCONFIG_PROC=m\n").expect("parse");
    fragment_survived(&module, "module").expect_err("=m must redden, not pass as 'enabled'");
}

#[test]
fn the_guest_round_trip_reddens_when_the_guest_config_is_not_the_sidecars() {
    let sidecar = KconfigValues::parse(SURVIVED).expect("parse");

    // Positive control: the guest may carry MORE symbols (kbuild regenerates the stored copy), but
    // every symbol the sidecar recorded must match.
    let superset = KconfigValues::parse(&format!("{SURVIVED}CONFIG_TMPFS=y\n")).expect("parse");
    let compared = guest_config_round_trips(&superset, &sidecar).expect("a superset must pass");
    assert_eq!(compared, sidecar.len());

    // A different build: same symbol, different value.
    let differs =
        KconfigValues::parse("CONFIG_IKCONFIG=y\nCONFIG_IKCONFIG_PROC=y\nCONFIG_EROFS_FS=m\n")
            .expect("parse");
    let err = guest_config_round_trips(&differs, &sidecar)
        .map(|n| n.to_string())
        .expect_err("a differing value must redden");
    assert!(
        err.contains("CONFIG_EROFS_FS"),
        "must name the symbol: {err}"
    );

    // A different build: the sidecar's symbol is missing from the guest entirely.
    let missing =
        KconfigValues::parse("CONFIG_IKCONFIG=y\nCONFIG_IKCONFIG_PROC=y\n").expect("parse");
    guest_config_round_trips(&missing, &sidecar)
        .map(|n| n.to_string())
        .expect_err("a missing symbol must redden");
}

// ═══════════════════════════════════════════════════════════════════════════════════════════════
// v33: THE ARTIFACT REGISTRY — three kinds, one shape (§10.5)
// ═══════════════════════════════════════════════════════════════════════════════════════════════

/// Writes `body` as an overlay in a fresh temp dir and returns the pair (the dir must outlive the
/// path, so it is returned too).
fn overlay_with(body: &str) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("overlay.json");
    std::fs::write(&path, body).expect("write the overlay");
    (dir, path)
}

/// The `Artifact` rejection message for an overlay, or a panic naming what came back instead.
fn rejection(body: &str) -> String {
    let (_dir, overlay) = overlay_with(body);
    match vmcell::artifact::resolve_rootfs_registry(Some(&overlay)) {
        Err(Error::Artifact(m)) => m,
        other => panic!("expected an Artifact rejection, got {other:?}"),
    }
}

// §10.5 GATE: this consumer's overlay extends the two namespaces v33 ADDED, and it does so by
// LEAF-WISE MERGE — vmcell's own labels survive beside the consumer's. Before v33 a second userland
// was a fork of `pins.json` and the guest handler was not an artifact at all; the whole point of the
// registry is that the label alone determines the artifact.
//
// RED on the inverse (make the overlay merge replace a namespace instead of merging into it, or
// teach the resolver to ignore the `rootfs`/`handlers` namespaces): `default` disappears from the
// roster, or `acme` never appears.
#[test]
fn the_overlay_registers_a_rootfs_and_a_handler_beside_vmcells_own() {
    let overlay = overlay_path();

    // The rootfs kind. `rootfs_entry()` checks the two halves of the declaration (the policy this
    // consumer wrote and the stance vmcell DERIVES from it) — see its rustdoc.
    let rootfs = rootfs_entry().expect("the overlay's rootfs entry must resolve");
    assert_eq!(rootfs.label, ROOTFS_LABEL);
    assert_eq!(rootfs.xattrs, DECLARED_XATTRS);
    // The default format, not declared, so the artifact stays byte-identical to its pre-delta-8
    // self — the migration promise, from the consumer position.
    assert_eq!(rootfs.format, RootfsFormat::Erofs);
    // Registration is a DIGEST (F7): a path would be an override, and an override is not something
    // a durable registry entry may mean.
    match &rootfs.registration {
        RootfsRegistration::Digest { image, digest } => {
            assert_eq!(image, "docker.io/library/debian");
            assert!(
                digest.starts_with("sha256:") && digest.len() == "sha256:".len() + 64,
                "a registration digest is `sha256:` + 64 hex: {digest}"
            );
        }
        other => panic!("this consumer registers by digest, resolved {other:?}"),
    }

    // The handler kind — the third artifact kind, which did not exist before v33.
    let handler = handler_entry().expect("the overlay's handler entry must resolve");
    assert_eq!(handler.label, HANDLER_LABEL);
    assert_eq!(
        handler.applet_roster(),
        HANDLER_APPLETS
            .iter()
            .map(|a| (*a).to_string())
            .collect::<Vec<_>>()
    );

    // THE MERGE, in both kinds: the roster is the union, sorted — vmcell's committed labels plus
    // this consumer's. A namespace-level replace (or a resolver reading only the overlay) loses the
    // baseline entries, and a consumer that registered one userland would silently have taken away
    // vmcell's own.
    let rootfs_labels =
        vmcell::artifact::resolve_rootfs_labels(Some(&overlay)).expect("rootfs labels resolve");
    assert_eq!(rootfs_labels, ["acme", "debian-systemd", "default"]);
    let handler_labels =
        vmcell::artifact::resolve_handler_labels(Some(&overlay)).expect("handler labels resolve");
    assert_eq!(handler_labels, ["acme", "default"]);

    // NON-VACUITY, and the fall-back half of the contract: with NO overlay, neither label exists —
    // so the assertions above are about this consumer's overlay and not about vmcell's pins.
    let baseline =
        vmcell::artifact::resolve_rootfs_labels(None).expect("the baseline registry resolves");
    assert!(
        !baseline.contains(&ROOTFS_LABEL.to_string()),
        "`{ROOTFS_LABEL}` must NOT be in vmcell's committed rootfs registry; resolved: {baseline:?}"
    );
    assert!(
        baseline.contains(&"default".to_string()),
        "fixture premise: vmcell's committed pins carry a `default` rootfs label"
    );
}

// §10.5 GATE (law F1 + F6 clause 1, from the consumer position): every declaration in a v33 entry is
// STRICT. A silently ignored declaration is one a consumer builds a fixture on — it declares a
// property, watches it be ignored, and ships the result.
//
// RED on the inverse (any of: `XattrPolicy::parse` falling back to the default on an unknown token;
// `Feature::parse` returning "absent" for an unknown one; dropping the derived-token refusal;
// dropping the legacy-shape reject): the matching leg's `resolve_*` returns Ok and the
// `expect_err` fires.
#[test]
fn every_declaration_in_a_v33_entry_is_strict_from_the_consumer_position() {
    // A typo'd xattr policy: `presevre` must not read as the default `strip`. (The digest is
    // well-formed on purpose — a malformed one is refused FIRST, by the registration-is-a-digest
    // law, and this leg is about the declaration beside it.)
    let msg = rejection(
        r#"{"rootfs": {"acme": {"image": "d.example/x",
             "digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
             "xattrs": "presevre"}}}"#,
    );
    assert!(
        msg.contains("presevre") && msg.contains("preserve"),
        "the refusal must name the typo AND the valid spellings: {msg}"
    );

    // A typo'd feature token in the same entry's `features` map (F6 clause 1).
    let msg = rejection(
        r#"{"rootfs": {"acme": {"image": "d.example/x",
             "digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
             "features": {"snapshot_restor": false}}}}"#,
    );
    assert!(
        msg.contains("snapshot_restor"),
        "the refusal must name the unknown feature token: {msg}"
    );

    // THE DERIVATION'S OTHER DIRECTION (§4.7): `xattr_preserved` is derived from `xattrs`, so
    // declaring it by hand is a hard error naming the derivation. Without this refusal the two
    // could desync — an entry stripping xattrs while claiming they survived.
    let msg = rejection(
        r#"{"rootfs": {"acme": {"image": "d.example/x",
             "digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
             "xattrs": "preserve", "features": {"xattr_preserved": true}}}}"#,
    );
    assert!(
        msg.contains(Feature::XattrPreserved.name()) && msg.contains("xattrs"),
        "the refusal must name both the token it refuses and the key it is derived from: {msg}"
    );

    // REGISTRATION IS A DIGEST (F7), and the format law is part of it: a truncated digest — or a
    // mutable tag — is refused at RESOLUTION, before any network round trip, because a registry
    // entry that resolves to "whatever is at that location today" is un-citable.
    let msg = rejection(r#"{"rootfs": {"acme": {"image": "d.example/x", "digest": "sha256:aa"}}}"#);
    assert!(
        msg.contains("sha256:<64 lowercase hex>"),
        "the refusal must state the digest format a registration takes: {msg}"
    );

    // A path where a registration belongs (F7): `path` is not a spelling of `unpinned_path`, and the
    // refusal has to say which key carries the dev override.
    let msg = rejection(r#"{"rootfs": {"acme": {"path": "/tmp/acme.erofs"}}}"#);
    assert!(
        msg.contains("unpinned_path"),
        "the refusal must name the one override key: {msg}"
    );

    // The retired v32 SINGLETON shape, which is what a consumer's stale overlay looks like. The
    // reject fires on the MERGED document — an overlay's `image`/`digest` leaves land beside
    // vmcell's label keys — and it must name the migration, never silently reinterpret.
    let msg = rejection(
        r#"{"rootfs": {"image": "d.example/x",
             "digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000"}}"#,
    );
    assert!(
        msg.contains("default") && msg.contains("§10.5"),
        "the refusal must name the map form the singleton migrates to: {msg}"
    );

    // POSITIVE CONTROL for all five: the same shape, spelled correctly, resolves. Without it every
    // leg above would pass against a resolver that rejected everything.
    let (_dir, overlay) = overlay_with(
        r#"{"rootfs": {"acme": {"image": "d.example/x",
             "digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
             "xattrs": "preserve", "features": {"snapshot_restore": false}}}}"#,
    );
    let entry = vmcell::artifact::resolve_rootfs_entry(Some("acme"), Some(&overlay))
        .expect("the well-formed entry resolves")
        .expect("…and carries the label");
    assert_eq!(entry.xattrs, XattrPolicy::Preserve);
    assert_eq!(entry.features.get(&Feature::XattrPreserved), Some(&true));
}

// ═══════════════════════════════════════════════════════════════════════════════════════════════
// v33: THE FEATURE-MANIFEST SIDECAR, through the shipped pipeline (§7.4)
// ═══════════════════════════════════════════════════════════════════════════════════════════════

// §7.4 GATE: a declaration reaches a path-consuming cell ONLY through the sidecar beside the
// artifact, so the producer (`RootfsFeaturesStage`, driven here by `Pipeline` behind
// `ResolvePinsStage`) and the reader (`FeatureDeclaration::load_beside`) must agree on the file's
// name and its content. This is the one COMPLETE v33 build a network-free consumer can run.
//
// RED on the inverse (change `feature_manifest_path` to append instead of replace, or point the
// producer at a differently-composed name): the sidecar is not at the composed path and
// `emit_feature_manifest` fails naming it — verified by doing exactly that.
#[tokio::test]
async fn the_declaration_sidecar_round_trips_through_the_shipped_pipeline() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let sidecar = emit_feature_manifest(tmp.path())
        .await
        .expect("the declaration pipeline must run from the consumer position");

    // The NAME, pinned against a bare literal: the law is contract surface, so a change to it must
    // redden this example rather than silently orphan every sidecar already written. Composed one
    // way here and asserted the other way round, exactly as the pin-key legs above are.
    assert_eq!(
        sidecar.file_name().and_then(|n| n.to_str()),
        Some("rootfs-acme.features"),
        "the sidecar naming law moved"
    );
    // …and the image it describes, from the one filename composer. Both formats derive the SAME
    // sidecar name (the extension is replaced), which is the coupling that lets one declaration
    // describe one label whichever filesystem its image is packed as.
    assert_eq!(
        feature_manifest_path(Path::new(&rootfs_filename(
            Some(ROOTFS_LABEL),
            RootfsFormat::Ext4
        )))
        .file_name()
        .and_then(|n| n.to_str()),
        Some("rootfs-acme.features")
    );

    // THE CONTENT: the reader gets back exactly what the registry entry declared — the hand-written
    // absence and the DERIVED xattr stance. A sidecar that travelled without the derivation would
    // leave a preserving artifact claiming nothing.
    let image = tmp
        .path()
        .join(rootfs_filename(Some(ROOTFS_LABEL), RootfsFormat::Erofs));
    let decl = declaration(&image).expect("the emitted sidecar must parse");
    assert_eq!(
        decl.stances.get(&DECLARED_ABSENT),
        Some(&false),
        "the declared absence must travel: {:?}",
        decl.stances
    );
    assert_eq!(
        decl.stances.get(&Feature::XattrPreserved),
        Some(&true),
        "the derived stance must travel: {:?}",
        decl.stances
    );
    // Provenance is the READER's to assign (the producer writes none), which is what makes the
    // §7.4 removal messages name the rootfs label.
    assert_eq!(decl.source, Some(Source::Rootfs(ROOTFS_LABEL.to_string())));

    // The rendered body round-trips through the parser it was written by.
    let reparsed = FeatureDeclaration::parse_manifest(
        &decl.render_manifest(),
        Source::Rootfs(ROOTFS_LABEL.to_string()),
    )
    .expect("the rendered manifest must parse back");
    assert_eq!(reparsed.stances, decl.stances);
}

// §7.4 GATE: the reader's two laws a consumer depends on — an ABSENT sidecar is the baseline
// (stated, so every pre-v33 artifact keeps working), and a MALFORMED one is a hard error (a typo'd
// declaration must not read as "no declaration").
//
// RED on the inverse (make `load_beside` fall back to the baseline on a parse error): the second
// half's `expect_err` fires.
#[test]
fn an_absent_declaration_is_the_baseline_and_a_malformed_one_is_a_hard_error() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let image = tmp.path().join("rootfs-acme.erofs");
    std::fs::write(&image, b"not really an image").expect("write the image stand-in");

    let baseline = declaration(&image).expect("an absent sidecar is the baseline, not an error");
    assert!(
        baseline.stances.is_empty(),
        "the baseline declares nothing: {:?}",
        baseline.stances
    );
    assert_eq!(
        baseline.source,
        Some(Source::Rootfs(ROOTFS_LABEL.to_string()))
    );

    std::fs::write(feature_manifest_path(&image), "snapshot_restor = false\n")
        .expect("write the malformed sidecar");
    let err = declaration(&image)
        .map(|d| format!("{d:?}"))
        .expect_err("a malformed sidecar must be a hard error, never the baseline");
    assert!(
        err.contains("snapshot_restor"),
        "the refusal must name the offending token: {err}"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════════════════════
// THE STAGE MODEL, from a consumer's own producer (§10.2)
// ═══════════════════════════════════════════════════════════════════════════════════════════════

/// A downstream producer: the shape a consumer's own stage has, wired behind Stage 0.
///
/// It reads the OVERLAY's pins out of `StageInputs` (proving Stage 0 published them), publishes its
/// payload under its own artifact key, and folds BOTH exported hash helpers into its `CacheKey`:
/// `hash_file` for its own input and `hash_artifacts_sorted` for the upstream artifact set. Both fold
/// **content that travels**, never a `target/`-relative path string (F4 rule 3), and the second one
/// also fixes the fold order — a raw `HashMap` walk would feed blake3 in a process-random order and
/// miss the cache at random.
struct AcmePayloadStage {
    /// The consumer-owned input whose bytes decide this stage's identity.
    source: PathBuf,
}

#[async_trait::async_trait]
impl Stage for AcmePayloadStage {
    fn name(&self) -> &str {
        "acme_payload"
    }

    fn out_path(&self, target_dir: &Path) -> PathBuf {
        target_dir.join("acme-payload")
    }

    fn cache_key(&self, inputs: &StageInputs) -> CacheKey {
        let mut hasher = blake3::Hasher::new();
        let hash = vmcell::artifact::hash_file(&self.source).unwrap_or_else(|e| {
            // A read failure folds a DISTINCT marker rather than an empty string, so a cache miss
            // drives `run()` and the real cause surfaces there (vmcell's own ART-11 idiom).
            format!("acme-source-read-error:{e}")
        });
        hasher.update(hash.as_bytes());
        // The upstream artifacts this stage consumes, through the exported helper — the documented
        // route for an out-of-crate builder, and the one that content-hashes each artifact and sorts
        // the keys instead of walking the map.
        vmcell::artifact::hash_artifacts_sorted(&mut hasher, &inputs.artifacts);
        CacheKey::new(format!("acme-payload-v1-{}", hasher.finalize().to_hex()))
    }

    async fn run(&self, inputs: &StageInputs, out: &Path) -> Result<StageOutputs> {
        // The overlay's own pin, read through the exported composer — the proof that Stage 0 ran
        // and merged this consumer's document.
        let key = vmcell::artifact::kernel::kernel_pin_key(Some(KERNEL_LABEL), "source_url");
        let url = inputs.pins.get(&key).ok_or_else(|| {
            Error::Artifact(format!(
                "`{key}` did not reach this stage: the overlay was not merged, or Stage 0 did not run"
            ))
        })?;
        std::fs::write(out, url).map_err(Error::Io)?;
        let mut outputs = StageOutputs::default();
        outputs
            .artifacts
            .insert("acme_payload".into(), out.to_path_buf());
        outputs.pins.insert("acme_payload_url".into(), url.clone());
        Ok(outputs)
    }
}

// §10.2 GATE: the stage model is contract surface, and a consumer's own producer is what it is for.
// This pins the three facts a downstream stage stands on: Stage 0's pins arrive in `StageInputs`,
// the payload is published in `Artifacts`, and the pipeline writes the `.cache_key` sidecar it
// derives from the stage's own path.
//
// RED on the inverse (drop `ResolvePinsStage` from the pipeline, or stop propagating a stage's
// `pins` into the next stage's inputs): `run` fails naming the missing pin.
#[tokio::test]
async fn a_consumers_own_stage_runs_behind_stage_zero_and_folds_content() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let source = tmp.path().join("acme-input.txt");
    std::fs::write(&source, b"v1").expect("write the consumer's input");

    let pipeline = || {
        Pipeline::new(tmp.path().join("out"))
            .add_stage(Box::new(ResolvePinsStage {
                overlay_file: Some(overlay_path()),
            }))
            .add_stage(Box::new(AcmePayloadStage {
                source: source.clone(),
            }))
    };
    let artifacts = pipeline()
        .build(&Cache::default())
        .await
        .expect("a consumer's pipeline must build from the consumer position");

    let payload = tmp.path().join("out/acme-payload");
    assert_eq!(
        artifacts.paths.get("acme_payload").map(PathBuf::as_path),
        Some(payload.as_path()),
        "the stage's payload must be published under its own artifact key: {:?}",
        artifacts.paths
    );
    assert!(
        std::fs::read_to_string(&payload)
            .expect("read the payload")
            .contains("linux-6.12.94.tar.xz"),
        "the payload must carry the value the OVERLAY pinned, not the baseline's"
    );
    // The pipeline's own cache metadata, at the path `Stage::cache_sidecar_path` derives.
    assert!(
        payload.with_extension("cache_key").is_file(),
        "the pipeline must write the stage's cache sidecar, or every build re-runs forever"
    );

    // CONTENT-ADDRESSED, not path-addressed: the same path with different bytes is a different
    // identity. This is the property `hash_file` is exported for.
    let key_before = AcmePayloadStage {
        source: source.clone(),
    }
    .cache_key(&StageInputs::default());
    std::fs::write(&source, b"v2").expect("edit the consumer's input");
    let key_after = AcmePayloadStage {
        source: source.clone(),
    }
    .cache_key(&StageInputs::default());
    assert_ne!(
        key_before, key_after,
        "editing the input must re-key the stage (F4 rule 3)"
    );

    // …and the UPSTREAM fold is live too: a stage whose consumed artifact set changed has a
    // different identity. Without this leg the `hash_artifacts_sorted` call could be deleted and
    // nothing here would redden — a fold nobody observes is a fold that quietly stops happening.
    let mut with_upstream = StageInputs::default();
    with_upstream
        .artifacts
        .insert("upstream".into(), source.clone());
    assert_ne!(
        AcmePayloadStage {
            source: source.clone(),
        }
        .cache_key(&with_upstream),
        key_after,
        "an upstream artifact must fold into a downstream stage's key"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════════════════════
// v33: THE PACK SURFACE — PackOptions, ExtraFile, XattrPolicy, RootfsFormat (§4.2/§4.7)
// ═══════════════════════════════════════════════════════════════════════════════════════════════

// §10.4 GATE: `pack_erofs_with_injection` + `ExtraFile` + the `XattrPolicy` parameter are named
// contract surface, and v33 grew `PackOptions` by three fields. This pins what a consumer composes
// and what the composition RESOLVES TO: which handler binary the tail bakes, which artifact key the
// image registers under, and that a consumer's own injected dest is not reserved.
//
// RED on the inverse (stop normalizing the reserved `default` spelling in `with_handler_label`, or
// go back to the hardcoded `"guest_tools"` / `"rootfs"` keys): the labelled assertions fire.
#[test]
fn the_pack_options_this_consumer_composes_name_its_own_labels_and_policy() {
    let rootfs = rootfs_entry().expect("rootfs entry");
    let handler = handler_entry().expect("handler entry");
    let tmp = tempfile::tempdir().expect("temp dir");
    let src = tmp.path().join("probe");
    std::fs::write(&src, b"probe").expect("write the injected file");

    let options = pack_options(&rootfs, &handler, &src);
    assert_eq!(options.xattrs, DECLARED_XATTRS);
    assert_eq!(options.format, RootfsFormat::Erofs);
    assert_eq!(options.label.as_deref(), Some(ROOTFS_LABEL));
    // WHICH BINARY the tail bakes — the field that did not exist until v33 delta 6c, whose absence
    // shipped images with no applet symlinks at all (`mini-init` included, which is an `init=`
    // target, so its absence panics the guest kernel).
    assert_eq!(options.handler_key(), "guest_tools-acme");
    assert_eq!(
        options.applet_roster(),
        HANDLER_APPLETS
            .iter()
            .map(|a| (*a).to_string())
            .collect::<Vec<_>>(),
        "a labelled handler's roster is its own, never vmcell's const"
    );
    assert_eq!(options.extra.len(), 1);
    assert_eq!(options.extra[0].dest, INJECTED_DEST);

    // The reserved `default` spelling normalizes to `None`, so the canonical artifact stays
    // byte-identical for a cell that names no label.
    assert_eq!(
        vmcell::artifact::rootfs::PackOptions::new()
            .with_handler_label(Some("default"))
            .handler_key(),
        "guest_tools",
        "`default` and the omitted spelling are the SAME request (§10.5)"
    );

    // F5, both directions: vmcell's own injections are reserved, this consumer's prefix is not.
    assert!(
        !is_reserved_injection_path(INJECTED_DEST),
        "a consumer's own dest must be injectable: {INJECTED_DEST}"
    );
    assert!(
        is_reserved_injection_path("/vmcell-tools/acme-probe"),
        "positive control: the tools dir is reserved as a whole"
    );
}

// §4.7 GATE (§18 delta 8): the erofs door refuses a format it does not pack — it neither silently
// overrides the caller's declaration nor silently ignores it (law F1). The format is an accepted
// input, so a door named for one format must say so.
//
// RED on the inverse (drop the format check from `pack_erofs_with_injection` and delegate
// unconditionally): the call no longer errors on the format and the `expect_err` fires.
#[tokio::test]
async fn the_erofs_door_refuses_a_format_it_does_not_pack() {
    let options = vmcell::artifact::rootfs::PackOptions::new().with_format(RootfsFormat::Ext4);
    let err = pack_erofs_with_injection(
        Vec::new(),
        &StageInputs::default(),
        Path::new("/nonexistent/out.ext4"),
        &options,
    )
    .await
    .map(|o| format!("{o:?}"))
    .expect_err("the erofs door must refuse an ext4 pack by name");
    let msg = err.to_string();
    assert!(
        msg.contains("ext4") && msg.contains("pack_rootfs_with_injection"),
        "the refusal must name the format AND the door that honors it: {msg}"
    );

    // POSITIVE CONTROL for the leg above: the SAME call with the default format gets PAST the format
    // gate — it fails later, on the steward the empty inputs do not carry, which is a different
    // message. Without this, the assertion would pass against a door that refused everything.
    let default_err = pack_erofs_with_injection(
        Vec::new(),
        &StageInputs::default(),
        Path::new("/nonexistent/out.erofs"),
        &vmcell::artifact::rootfs::PackOptions::new(),
    )
    .await
    .map(|o| format!("{o:?}"))
    .expect_err("empty inputs cannot pack anything");
    assert!(
        !default_err
            .to_string()
            .contains("this door packs erofs by name"),
        "the default format must pass the format gate: {default_err}"
    );
}

// §10.5/§4.7 GATE: the artifact FILENAME laws a consumer reads a built artifacts dir with, and their
// inverse. Both formats and the round trip, because delta 8's second format re-armed the
// "a sidecar reads as an artifact" defect until the inverse learned it.
//
// RED on the inverse (drop a format from `RootfsFormat::ALL`'s suffix table): the ext4 round trip
// returns `None`.
#[test]
fn the_rootfs_artifact_filename_laws_round_trip_for_both_formats() {
    assert_eq!(rootfs_filename(None, RootfsFormat::Erofs), "rootfs.erofs");
    assert_eq!(
        rootfs_filename(Some(ROOTFS_LABEL), RootfsFormat::Erofs),
        "rootfs-acme.erofs"
    );
    assert_eq!(
        rootfs_filename(Some(ROOTFS_LABEL), RootfsFormat::Ext4),
        "rootfs-acme.ext4"
    );
    // A dotted label is SANITIZED in the filename (and only there — the pin key keeps its dots).
    assert_eq!(
        rootfs_filename(Some("12.4"), RootfsFormat::Erofs),
        "rootfs-12-4.erofs"
    );

    for format in RootfsFormat::ALL {
        assert_eq!(
            rootfs_artifact_from_filename(&rootfs_filename(Some(ROOTFS_LABEL), format)),
            Some((ROOTFS_LABEL, format)),
            "the filename law and its inverse must agree on {}",
            format.name()
        );
    }
    // The default is not a labelled artifact, and a sidecar is not an artifact at all.
    assert_eq!(rootfs_artifact_from_filename("rootfs.erofs"), None);
    assert_eq!(rootfs_artifact_from_filename("rootfs-acme.cache_key"), None);
    assert_eq!(rootfs_artifact_from_filename("rootfs-acme.features"), None);
}

// ═══════════════════════════════════════════════════════════════════════════════════════════════
// v33: THE TWO-DIRECTIONAL CONFORMANCE BATTERY (§10.6)
// ═══════════════════════════════════════════════════════════════════════════════════════════════

/// A scripted [`FeatureProbe`] — the KVM-free seam §10.6 specifies the judgement law against.
///
/// Keyed by `(feature, artifact id)` so the candidate and its positive control can differ, which is
/// exactly what the four-leg matrix needs. An unscripted probe **panics**: the battery probes only
/// what is measurable, so being asked something the test did not script means the test is wrong
/// about the law, and a default outcome would hide that.
struct ScriptedProbe {
    /// What each artifact's data plane "does", per feature.
    outcomes: HashMap<(Feature, String), ProbeOutcome>,
    /// How long a probe takes. Non-zero only for the battery-budget leg, which needs a probe that
    /// actually awaits.
    delay: Duration,
}

impl ScriptedProbe {
    /// A probe that answers instantly.
    fn new(outcomes: HashMap<(Feature, String), ProbeOutcome>) -> Self {
        ScriptedProbe {
            outcomes,
            delay: Duration::ZERO,
        }
    }
}

impl FeatureProbe for ScriptedProbe {
    async fn probe(&self, feature: Feature, subject: &ConformanceSubject) -> ProbeOutcome {
        if !self.delay.is_zero() {
            tokio::time::sleep(self.delay).await;
        }
        self.outcomes
            .get(&(feature, subject.id.as_str().to_string()))
            .cloned()
            .unwrap_or_else(|| {
                panic!(
                    "the battery probed `{}` on \"{}\", which this test scripted no outcome for",
                    feature.name(),
                    subject.id
                )
            })
    }
}

/// The substrate every battery leg below runs on: cloud-hypervisor's own descriptor, with the host
/// axis **not probed** (`None` removes nothing) so the verdicts are the same on every machine.
///
/// Read off the shipped backend rather than hand-built: a local `VmmCapabilities` literal would be a
/// second declaration of what CH supports, and the `Skip` leg below depends on the real one
/// (`usb_host_passthrough: false`).
fn substrate() -> Substrate {
    let vmm = CloudHypervisor::new(vmcell_artifact_validator::harness::ch_bin());
    let caps = vmm.capabilities();
    assert!(
        caps.snapshot_restore && caps.lazy_restore && caps.virtio_console,
        "fixture premise: this substrate can exercise the claims the legs below make"
    );
    assert!(
        !caps.usb_host_passthrough,
        "fixture premise: the `Skip` leg needs a capability this backend does NOT have"
    );
    Substrate::new(vmm.id(), &caps, None)
}

/// The candidate this consumer's battery legs judge: its **real** registry declaration plus three
/// stances that pin the states the real one does not reach.
///
/// The declaration is the *input* to the law under test, so adding stances here is stating a claim,
/// not faking a measurement — every verdict below still comes from the kit.
fn candidate() -> ConformanceSubject {
    let entry = rootfs_entry().expect("rootfs entry");
    let mut stances = entry.features;
    // A present claim the substrate can exercise and the probe will contradict → Fail.
    stances.insert(Feature::VirtioConsole, true);
    // A present claim no probe can decide → Unverified.
    stances.insert(KERNEL_DECLARES, true);
    // An absence the probe will confirm, with a control that works → the only Pass an absence earns.
    stances.insert(Feature::LazyRestore, false);
    // An absence on a facility this backend does not have at all → Skip, unchanged by v33.
    stances.insert(Feature::UsbHostPassthrough, false);
    conformance_candidate(
        ArtifactSet::new("/nonexistent/vmlinux", "/nonexistent/rootfs.erofs"),
        FeatureDeclaration {
            source: Some(Source::Rootfs(ROOTFS_LABEL.to_string())),
            stances,
        },
    )
}

/// The scripted data plane for [`candidate`]: the outcomes that produce one of each verdict.
fn scripted_outcomes() -> HashMap<(Feature, String), ProbeOutcome> {
    let cand = CANDIDATE_ID.to_string();
    let ctl = CONTROL_ID.to_string();
    HashMap::from([
        // Present + works → Pass (the derived xattr stance, this consumer's real declaration).
        ((Feature::XattrPreserved, cand.clone()), ProbeOutcome::Works),
        // Present + broken → Fail.
        (
            (Feature::VirtioConsole, cand.clone()),
            ProbeOutcome::DoesNotWork("no hvc0 in the guest".into()),
        ),
        // Present + undecidable → Unverified. `NotRun` is what the SHIPPED probe returns for an
        // `Undecidable` plan, which the leg below pins rather than assumes.
        (
            (KERNEL_DECLARES, cand.clone()),
            ProbeOutcome::NotRun("no data-plane probe for it".into()),
        ),
        // Absent + does not work + control works → Pass (a verified absence).
        (
            (Feature::LazyRestore, cand.clone()),
            ProbeOutcome::DoesNotWork("prefault is always on for this artifact".into()),
        ),
        ((Feature::LazyRestore, ctl.clone()), ProbeOutcome::Works),
        // Absent + WORKS ANYWAY + control works → Warn (the under-claim).
        ((DECLARED_ABSENT, cand), ProbeOutcome::Works),
        ((DECLARED_ABSENT, ctl), ProbeOutcome::Works),
    ])
}

/// The status recorded for `id`, or a panic naming the roster.
fn status_of<'a>(report: &'a ValidationReport, id: &str) -> &'a CheckStatus {
    report
        .outcomes
        .iter()
        .find(|o| o.id == id)
        .map(|o| &o.status)
        .unwrap_or_else(|| {
            panic!(
                "the report has no `{id}`; it recorded {:?}",
                report.outcomes.iter().map(|o| o.id).collect::<Vec<_>>()
            )
        })
}

// §10.6 GATE: the five-state verdict law, all of it, from the consumer position — including the two
// states v33 ADDED. `Warn` is an under-claim (declared absent, works anyway) and is deliberately not
// a failure; `Unverified` is an absence-or-presence nothing can decide and is never a pass. The
// paired positive control is what makes the absence verdicts mean anything.
//
// RED on the inverse (delete the control probe in `battery_inner`, or fold `Warn`/`Unverified` into
// `Pass`/`Fail`): the `Warn` leg becomes `Pass` or the control legs turn `Unverified`.
#[tokio::test]
async fn the_battery_reports_every_state_the_v33_kit_added() {
    // The scripted `NotRun` mirrors the SHIPPED mapping rather than inventing one: this feature
    // genuinely has no probe, and if one ever lands, this assertion is what says so.
    assert!(
        matches!(probe_plan(KERNEL_DECLARES), ProbePlan::Undecidable(_)),
        "fixture premise: `{}` has no data-plane probe in the shipped kit",
        KERNEL_DECLARES.name()
    );
    // …and the one that DOES, so the matrix is not built entirely out of undecidables.
    assert!(
        matches!(probe_plan(DECLARED_ABSENT), ProbePlan::SnapshotRoundTrip),
        "fixture premise: `{}` is decidable by attempting it",
        DECLARED_ABSENT.name()
    );

    let candidate = candidate();
    let control = positive_control(&candidate);
    // The control declares TRUE exactly where the candidate declares false — the bargain the kit
    // refuses to run without.
    assert_eq!(control.stance(DECLARED_ABSENT), Some(true));
    assert_eq!(control.stance(Feature::LazyRestore), Some(true));
    assert_eq!(
        control.stance(Feature::VirtioConsole),
        None,
        "the control must not claim things nobody measured"
    );

    let opts = ConformanceOptions {
        // The under-claim is dispositioned, so it STAYS a warning. The other direction is the next
        // test.
        expected_warnings: [(DECLARED_ABSENT, ArtifactId::new(CANDIDATE_ID))]
            .into_iter()
            .collect(),
        ..ConformanceOptions::default()
    };
    let report = run_battery(
        &ScriptedProbe::new(scripted_outcomes()),
        &substrate(),
        &candidate,
        &control,
        &opts,
    )
    .await
    .expect("the battery must run: the control declares everything the candidate denies");

    assert_eq!(
        status_of(&report, conformance_check_id(Feature::XattrPreserved)),
        &CheckStatus::Pass,
        "a present claim the data plane confirms is a Pass"
    );
    assert_eq!(
        status_of(&report, conformance_check_id(Feature::LazyRestore)),
        &CheckStatus::Pass,
        "a VERIFIED absence — the control worked and the artifact did not — is the one Pass an \
         absence declaration can earn"
    );
    let CheckStatus::Fail(msg) = status_of(&report, conformance_check_id(Feature::VirtioConsole))
    else {
        panic!(
            "a present claim the data plane contradicts must Fail, got {:?}",
            status_of(&report, conformance_check_id(Feature::VirtioConsole))
        );
    };
    assert!(
        msg.contains("hvc0"),
        "the failure must carry the probe's own reason: {msg}"
    );

    // THE TWO NEW STATES.
    let CheckStatus::Warn(msg) = status_of(&report, conformance_check_id(DECLARED_ABSENT)) else {
        panic!(
            "a dispositioned under-claim must stay a Warn, got {:?}",
            status_of(&report, conformance_check_id(DECLARED_ABSENT))
        );
    };
    assert!(
        msg.contains(CONTROL_ID),
        "an under-claim must name the control that proved the probe discriminates: {msg}"
    );
    let CheckStatus::Unverified(msg) = status_of(&report, conformance_check_id(KERNEL_DECLARES))
    else {
        panic!(
            "an undecidable claim must be Unverified, never a pass, got {:?}",
            status_of(&report, conformance_check_id(KERNEL_DECLARES))
        );
    };
    assert!(
        !msg.is_empty(),
        "an Unverified must say WHY it could not be decided"
    );

    // …and `Skip` keeps its shipped meaning: the substrate cannot exercise the claim at all.
    let CheckStatus::Skip(reason) =
        status_of(&report, conformance_check_id(Feature::UsbHostPassthrough))
    else {
        panic!("a claim the substrate cannot exercise must Skip");
    };
    assert!(
        reason.contains("cloud-hypervisor"),
        "the skip must name who cannot exercise it (§7.4 provenance): {reason}"
    );

    // A feature the artifact says NOTHING about is not judged as absent — the baseline rule.
    assert!(
        matches!(
            status_of(&report, conformance_check_id(Feature::NestedVirt)),
            CheckStatus::Skip(_)
        ),
        "no stance is not a claim"
    );

    // The report is fail-only: the Warn and the Unverified above do not turn it red, and the
    // consumer inspects them explicitly.
    assert_eq!(report.warnings().count(), 1);
    assert_eq!(report.unverified().count(), 1);
    // The roster is complete on every path that produces a report.
    let recorded: Vec<&str> = report.outcomes.iter().map(|o| o.id).collect();
    for id in battery_check_ids() {
        assert!(recorded.contains(&id), "the battery must report `{id}`");
    }
}

// §10.6 GATE: BOTH directions of the expected-warning lifecycle. An un-triaged under-claim is
// promoted to a failure (a new one must be triaged, not accumulated), and an expectation whose
// warning no longer fires is itself reported — the unfulfilled-`#[expect]` rule one level up.
//
// RED on the inverse (drop either direction from `apply_warning_lifecycle`): the promotion leg sees
// a Warn, or the staleness leg sees a Pass.
#[tokio::test]
async fn an_untriaged_under_claim_is_promoted_and_a_stale_expectation_is_reported() {
    let candidate = candidate();
    let control = positive_control(&candidate);

    // Direction 1: nothing dispositioned → the under-claim is a failure naming the triage route.
    let report = run_battery(
        &ScriptedProbe::new(scripted_outcomes()),
        &substrate(),
        &candidate,
        &control,
        &ConformanceOptions::default(),
    )
    .await
    .expect("the battery runs");
    let CheckStatus::Fail(msg) = status_of(&report, conformance_check_id(DECLARED_ABSENT)) else {
        panic!("an un-triaged under-claim must be promoted to a failure");
    };
    assert!(
        msg.contains("expected_warnings") && msg.contains(DECLARED_ABSENT.name()),
        "the promotion must name the mechanism and the feature: {msg}"
    );
    assert_eq!(
        report.warnings().count(),
        0,
        "a promoted warning is no longer a warning"
    );

    // Direction 2: an expectation for a feature that did NOT warn (its absence was verified) is
    // reported, so a stale entry cannot sit there certifying nothing.
    let opts = ConformanceOptions {
        expected_warnings: [
            (DECLARED_ABSENT, ArtifactId::new(CANDIDATE_ID)),
            (Feature::LazyRestore, ArtifactId::new(CANDIDATE_ID)),
        ]
        .into_iter()
        .collect(),
        ..ConformanceOptions::default()
    };
    let report = run_battery(
        &ScriptedProbe::new(scripted_outcomes()),
        &substrate(),
        &candidate,
        &control,
        &opts,
    )
    .await
    .expect("the battery runs");
    let CheckStatus::Fail(msg) = status_of(&report, EXPECTED_WARNINGS_CHECK_ID) else {
        panic!("a stale expectation must be reported as an error of its own");
    };
    assert!(
        msg.contains(Feature::LazyRestore.name()),
        "the report must name the expectation that did not fire: {msg}"
    );
    // POSITIVE CONTROL: with only the expectation that DID fire, the same check passes — so the leg
    // above is about staleness and not about the check being red for everyone.
    let opts = ConformanceOptions {
        expected_warnings: [(DECLARED_ABSENT, ArtifactId::new(CANDIDATE_ID))]
            .into_iter()
            .collect(),
        ..ConformanceOptions::default()
    };
    let report = run_battery(
        &ScriptedProbe::new(scripted_outcomes()),
        &substrate(),
        &candidate,
        &control,
        &opts,
    )
    .await
    .expect("the battery runs");
    assert_eq!(
        status_of(&report, EXPECTED_WARNINGS_CHECK_ID),
        &CheckStatus::Pass
    );
}

// §10.6 GATE: the battery refuses to run rather than produce an unhonest absence verdict — no
// control, or a control that is the candidate itself. Refused BEFORE anything boots, which is what
// makes it usable as a consumer's pre-flight.
//
// RED on the inverse (drop the up-front control check): the run returns a report whose absence
// verdicts rest on a probe nothing proved discriminates.
#[tokio::test]
async fn the_battery_refuses_to_run_without_a_declaring_control() {
    let candidate = candidate();
    let opts = ConformanceOptions::default();
    let probe = ScriptedProbe::new(scripted_outcomes());

    // A control that declares nothing cannot control anything.
    let empty = ConformanceSubject {
        id: ArtifactId::new(CONTROL_ID),
        artifacts: candidate.artifacts.clone(),
        declaration: FeatureDeclaration::baseline(Source::Rootfs("baseline".into())),
    };
    match run_battery(&probe, &substrate(), &candidate, &empty, &opts).await {
        Err(ConformanceError::ControlDoesNotDeclare { feature, control }) => {
            assert_eq!(control, ArtifactId::new(CONTROL_ID));
            assert!(
                candidate.stance(feature) == Some(false),
                "the refusal must name a feature the candidate declares ABSENT, got {feature}"
            );
        }
        other => panic!("expected a ControlDoesNotDeclare refusal, got {other:?}"),
    }

    // …and the candidate cannot be its own control.
    match run_battery(&probe, &substrate(), &candidate, &candidate, &opts).await {
        Err(ConformanceError::ControlIsCandidate { id }) => {
            assert_eq!(id, ArtifactId::new(CANDIDATE_ID));
        }
        other => panic!("expected a ControlIsCandidate refusal, got {other:?}"),
    }
}

// §10.6/§17 GATE: the battery as a whole is bounded, and exceeding the budget is a TYPED error
// naming it — never a hang. A kit that doubles its check count doubles the visibility of "fails
// loudly per check, hangs per battery".
//
// RED on the inverse (drop the `timeout` around `battery_inner`): this test hangs instead of
// returning, which nextest's own timeout reports.
#[tokio::test]
async fn the_battery_honors_its_wall_clock_budget() {
    let candidate = candidate();
    let control = positive_control(&candidate);
    let probe = ScriptedProbe {
        outcomes: scripted_outcomes(),
        // Longer than the budget below, so the FIRST measurable probe outruns it.
        delay: Duration::from_millis(250),
    };
    let budget = Duration::from_millis(1);
    match run_battery(
        &probe,
        &substrate(),
        &candidate,
        &control,
        &ConformanceOptions {
            battery_budget: budget,
            ..ConformanceOptions::default()
        },
    )
    .await
    {
        Err(ConformanceError::BatteryBudgetExceeded { budget: got, .. }) => {
            assert_eq!(got, budget, "the error must name the budget it exceeded");
        }
        other => panic!("expected a BatteryBudgetExceeded error, got {other:?}"),
    }

    // POSITIVE CONTROL: the same battery on the default budget completes, so the leg above is about
    // the budget and not about the probe being unable to finish.
    assert!(
        DEFAULT_BATTERY_BUDGET > Duration::from_secs(60),
        "the shipped default budget must be generous enough for real boots"
    );
    run_battery(
        &ScriptedProbe::new(scripted_outcomes()),
        &substrate(),
        &candidate,
        &control,
        &ConformanceOptions::default(),
    )
    .await
    .expect("the same battery completes inside the default budget");
}

// §10.4 GATE: `ValidationOptions`' own wall-clock budget is ON by default and survives the `level`
// constructor. A consumer that opts out does so explicitly; a consumer that does not gets a bounded
// run. This is a ledgered field on a contract crate, so a silent change to its default belongs here.
//
// RED on the inverse (make `Default::default()` leave `run_budget: None`, or have `level()` re-spell
// the fields instead of a functional update): the assertions fire.
#[test]
fn the_validators_run_budget_is_on_by_default_and_survives_the_level_constructor() {
    assert_eq!(
        ValidationOptions::default().run_budget,
        Some(DEFAULT_RUN_BUDGET)
    );
    assert_eq!(
        ValidationOptions::level(vmcell_artifact_validator::Level::Full).run_budget,
        Some(DEFAULT_RUN_BUDGET),
        "the level constructor must not silently drop the budget"
    );
    assert_eq!(
        ConformanceOptions::default().battery_budget,
        DEFAULT_BATTERY_BUDGET
    );
}
