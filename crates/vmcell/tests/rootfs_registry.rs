//! The `rootfs` artifact registry (design §10.5; §18 delta 6), exercised from **outside** the crate
//! — the position a git-dep consumer registers a userland from.
//!
//! Every test here is KVM-free, network-free and toolchain-free. What they cover is the half of
//! §10.5 that has no other proof: that the reshape from a `{image, digest}` singleton to a map of
//! labels **changed nothing** for a cell that names no label, and that the legacy shape fails loud
//! naming the migration instead of being silently reinterpreted.
//!
//! The mirror of `kernel_toolkit.rs`, one kind over — deliberately a separate file rather than more
//! tests in that one, because the registry law is now shared and two batteries against one core is
//! how a kind-specific regression stays visible as a kind-specific failure.

use std::path::{Path, PathBuf};

use vmcell::artifact::registry::DEFAULT_LABEL;
use vmcell::artifact::registry::UNPINNED_PATH_KEY;
use vmcell::artifact::rootfs::{
    RootfsFeaturesStage, RootfsStage, features_artifact_key, rootfs_artifact_key, rootfs_filename,
    rootfs_label_from_filename, rootfs_pin_key,
};
use vmcell::artifact::{
    Cache, CacheKey, Pipeline, RootfsRegistration, RootfsRegistryEntry, Stage, StageInputs,
    resolve_pins, resolve_rootfs_entry, resolve_rootfs_labels, resolve_rootfs_registry,
};
use vmcell::error::Error;
use vmcell::feature::{Feature, FeatureDeclaration, Source, feature_manifest_path};

/// Writes an overlay document into `dir` and returns its path.
fn write_overlay(dir: &Path, body: &str) -> PathBuf {
    let path = dir.join("overlay.json");
    std::fs::write(&path, body).expect("write overlay");
    path
}

/// The cache key a rootfs `label` folds to under the pins `overlay` resolves — the deepest
/// artifact-identity point reachable from outside the crate, and the one that decides whether a
/// warm artifacts dir is a hit or a rebuild.
///
/// The artifact map is empty on purpose: this asks what the REGISTRY contributes to identity, and
/// the injected `steward`/`guest_tools` artifacts are the same on both sides of every comparison
/// below.
fn rootfs_cache_key(label: Option<&str>, overlay: Option<&Path>) -> CacheKey {
    let mut inputs = StageInputs::default();
    inputs.pins = resolve_pins(overlay).expect("the pins resolve");
    RootfsStage::labelled(label).cache_key(&inputs)
}

/// The rejection message for an overlay, or a panic naming what came back instead.
fn registry_err(overlay: &Path) -> String {
    match resolve_rootfs_registry(Some(overlay)) {
        Err(Error::Artifact(m)) => m,
        other => panic!("expected an Artifact rejection, got {other:?}"),
    }
}

/// The `(image, digest)` an entry's DIGEST registration names, or a panic naming the shape it
/// actually carries.
///
/// A test-local reader rather than an accessor on the type: §10.5's shape-per-entry is exactly what
/// makes "an unpinned entry has no image and no digest" unrepresentable, and an
/// `image() -> Option<&str>` on the entry would hand every consumer back the two-optional-fields
/// shape the enum exists to remove.
fn digest_registration(entry: &RootfsRegistryEntry) -> (&str, &str) {
    match &entry.registration {
        RootfsRegistration::Digest { image, digest } => (image.as_str(), digest.as_str()),
        other => panic!(
            "`{}` must carry a digest registration, got {other:?}",
            entry.label
        ),
    }
}

// §10.5's "what must not regress", and the single most load-bearing assertion in this delta: the
// canonical artifact stays byte-identical for a cell that names no label.
//
// The mechanism is that `rootfs.default` flattens to the UN-suffixed `rootfs_image`/`rootfs_digest`
// — the exact keys every pre-v33 reader uses, including `resolve_builder_base`, which picks the
// image that builds KERNELS. RED on a flattener that emits `rootfs_default_image` instead: every
// existing consumer would read a key nothing emits, and the kernel builders would lose their base.
#[test]
fn the_default_label_flattens_to_the_pre_v33_keys() {
    let pins = resolve_pins(None).expect("the committed baseline resolves");
    let image = pins
        .get("rootfs_image")
        .expect("`rootfs.default` must still emit the un-suffixed `rootfs_image`");
    let digest = pins
        .get("rootfs_digest")
        .expect("`rootfs.default` must still emit the un-suffixed `rootfs_digest`");

    // And the registry's own view agrees with the flat pins, so the two readers cannot drift.
    let registry = resolve_rootfs_registry(None).expect("the baseline registry resolves");
    let default = registry
        .iter()
        .find(|e| e.label == DEFAULT_LABEL)
        .expect("the committed baseline must register a `default` rootfs");
    assert_eq!(
        digest_registration(default),
        (image.as_str(), digest.as_str())
    );

    // The suffixed spelling must NOT also be emitted: two spellings of one pin is the drift the
    // one-law composer exists to prevent, and a consumer reading the wrong one gets no error.
    assert!(
        !pins.contains_key("rootfs_default_image"),
        "the default label must contribute no suffix"
    );
}

// The legacy singleton is rejected LOUD, naming the migration — never reinterpreted as
// `{"default": …}`. Two accepted shapes for one namespace is parser ambiguity waiting for a third,
// and a consumer whose overlay silently keeps working never learns the schema moved.
//
// RED on a resolver that falls back to the old shape: the overlay below resolves and the test's
// `expect_err` fails.
#[test]
fn the_legacy_singleton_shape_is_rejected_naming_the_migration() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let overlay = write_overlay(
        tmp.path(),
        r#"{ "rootfs": { "image": "docker.io/library/debian", "digest": "sha256:dead" } }"#,
    );
    let msg = registry_err(&overlay);
    for named in ["image", "digest", DEFAULT_LABEL, "§10.5"] {
        assert!(msg.contains(named), "the message must name {named}: {msg}");
    }

    // The migrated form is the positive control — so the rejection is about the SHAPE and not about
    // overlays touching `rootfs` at all.
    let migrated = write_overlay(
        tmp.path(),
        &format!(
            r#"{{ "rootfs": {{ "{DEFAULT_LABEL}": {{ "image": "downstream/base",
                 "digest": "sha256:{}" }} }} }}"#,
            "a".repeat(64)
        ),
    );
    let registry = resolve_rootfs_registry(Some(&migrated)).expect("the map form resolves");
    let default = registry
        .iter()
        .find(|e| e.label == DEFAULT_LABEL)
        .expect("the overlay's default entry");
    assert_eq!(digest_registration(default).0, "downstream/base");
}

// THE HYBRID CASE, and the reason the reject runs on the MERGED document rather than on the overlay.
// `merge_pins_documents` merges leaf-wise, so an overlay adding a label over a *singleton* baseline
// produces an object holding `image`/`digest` leaves BESIDE label keys — and that hybrid passes
// `parse_pins_overlay`'s shape check, which is top-level only.
//
// Here the baseline is already migrated, so the hybrid is built the other way round: an overlay that
// re-adds the singleton keys beside the baseline's labels. Either way the merged document is the
// only place both halves are visible at once, which is what this pins.
#[test]
fn a_hybrid_of_the_two_shapes_is_rejected_too() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let overlay = write_overlay(
        tmp.path(),
        r#"{ "rootfs": { "image": "docker.io/library/debian" } }"#,
    );
    let msg = registry_err(&overlay);
    assert!(
        msg.contains("image"),
        "a singleton key merged over a label map must still be refused: {msg}"
    );
    // It is genuinely a hybrid: the baseline's `default` label is present in the merged document,
    // so a reject keyed on "the namespace has no labels" would pass this case.
    let labels = resolve_rootfs_labels(None).expect("baseline labels");
    assert!(
        labels.iter().any(|l| l == DEFAULT_LABEL),
        "the baseline must carry the label this hybrid merges over"
    );
}

// Every accepted key is honored; every other key is REJECTED naming it (law F1). The one the design
// sketch shows but this delta does not implement — `xattrs` (§4.7) — is rejected with a forward
// reference rather than a bare "unknown", because a consumer copying §10.5's example deserves to be
// told WHEN rather than merely NO.
//
// This is also the F1-clean seam between deltas 6 and 7: `xattrs` is refused here and honored there,
// never accepted-and-ignored in between. `features` USED to sit in this table with a "delta 6c"
// forward reference; delta 6c honors it, so it moved to the accept-legs below — which is the whole
// point of writing the seam as a table entry rather than as a bare "unknown key" message.
#[test]
fn an_unknown_entry_key_is_rejected_naming_it() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let digest = format!("sha256:{}", "b".repeat(64));
    for (key, value, expected) in [
        ("xattrs", "\"preserve\"", "delta 7"),
        ("imgae", "\"typo\"", "known keys"),
        // A BARE `path` is refused pointing at the one named override key — R7 settled that a path
        // is an OVERRIDE and not a registration, so the shape exists only under a key that also
        // carries its consequences (the content-hashed identity, the `warn!`, the `bundle`
        // refusal). A bare "unknown key" message here would leave a consumer who read §10.5's F7
        // paragraph with no way to find the spelling.
        ("path", "\"/tmp/rootfs.erofs\"", UNPINNED_PATH_KEY),
    ] {
        let overlay = write_overlay(
            tmp.path(),
            &format!(
                r#"{{ "rootfs": {{ "acme": {{ "image": "i", "digest": "{digest}",
                     "{key}": {value} }} }} }}"#
            ),
        );
        let msg = registry_err(&overlay);
        assert!(msg.contains(key), "the message must name `{key}`: {msg}");
        assert!(
            msg.contains(expected),
            "the message must say {expected:?} for `{key}`: {msg}"
        );
    }
}

// A label resolves to a DIGEST, never a mutable tag — the `oci2-erofs` rule adopted as the
// registry's (§10.5). A registry entry that means "whatever is at that location today" is
// un-citable by any consumer's provenance discipline.
#[test]
fn an_entry_must_pin_a_sha256_digest() {
    let tmp = tempfile::tempdir().expect("tempdir");
    // UPPERCASE hex is refused too, as of §18 delta 6c (fuzz finding F-2): `sha256_hex` emits
    // lowercase and every verification site compares case-SENSITIVELY, so an uppercase
    // registration parsed clean here and could then never verify — a "digest mismatch" after the
    // fetch, naming two digests that look identical until you notice the case. The refusal names
    // the case and shows the lowercased form; the cross-kind parity of this message is pinned in
    // `handler_registry.rs::a_registration_must_pin_a_sha256_digest`.
    let upper = write_overlay(
        tmp.path(),
        &format!(
            r#"{{ "rootfs": {{ "acme": {{ "image": "i", "digest": "sha256:{}" }} }} }}"#,
            "CD".repeat(32)
        ),
    );
    let upper_msg = registry_err(&upper);
    for named in [
        "lowercase",
        "UPPERCASE",
        &format!("sha256:{}", "cd".repeat(32)),
    ] {
        assert!(
            upper_msg.contains(named),
            "the uppercase refusal must name {named}: {upper_msg}"
        );
    }
    // Positive control: the same digest lowercased resolves — the rejection is about the case.
    let lower = write_overlay(
        tmp.path(),
        &format!(
            r#"{{ "rootfs": {{ "acme": {{ "image": "i", "digest": "sha256:{}" }} }} }}"#,
            "cd".repeat(32)
        ),
    );
    assert!(
        resolve_rootfs_registry(Some(&lower))
            .expect("the lowercased digest must resolve")
            .iter()
            .any(|e| e.label == "acme"),
        "the lowercase form the refusal recommends must actually be accepted"
    );
    for bad in ["trixie-slim", "sha256:short", "sha1:aaaa", ""] {
        let overlay = write_overlay(
            tmp.path(),
            &format!(r#"{{ "rootfs": {{ "acme": {{ "image": "i", "digest": "{bad}" }} }} }}"#),
        );
        let msg = registry_err(&overlay);
        assert!(
            msg.contains("acme"),
            "the rejection must name the label: {msg}"
        );
    }
    // Positive control: a well-formed digest resolves, so the rejection is about the digest's shape
    // and not about labelled entries in general.
    let good = write_overlay(
        tmp.path(),
        &format!(
            r#"{{ "rootfs": {{ "acme": {{ "image": "i", "digest": "sha256:{}" }} }} }}"#,
            "c".repeat(64)
        ),
    );
    let registry = resolve_rootfs_registry(Some(&good)).expect("a pinned digest resolves");
    assert!(registry.iter().any(|e| e.label == "acme"));
}

// A downstream-added label is additive, enumerable, and SORTED — byte-lexicographically, the one
// order the shared registry core applies to every kind. The baseline's `default` survives beside it,
// which is what "an overlay extends rather than forks" means in practice.
#[test]
fn an_overlay_label_is_additive_and_the_order_is_pinned() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let digest = format!("sha256:{}", "d".repeat(64));
    let overlay = write_overlay(
        tmp.path(),
        &format!(
            r#"{{ "rootfs": {{ "zz-last": {{ "image": "i", "digest": "{digest}" }},
                 "aa-first": {{ "image": "i", "digest": "{digest}" }} }} }}"#
        ),
    );
    let labels = resolve_rootfs_labels(Some(&overlay)).expect("resolves");
    assert_eq!(
        labels,
        vec![
            "aa-first".to_string(),
            DEFAULT_LABEL.to_string(),
            "zz-last".to_string()
        ],
        "labels must be byte-lexicographic, with the baseline's default kept"
    );

    // And the labelled entries flatten to their own suffixed pins, which is what lets a stage
    // resolve a label without the default's keys shadowing it.
    let pins = resolve_pins(Some(&overlay)).expect("resolves");
    assert_eq!(
        pins.get(&rootfs_pin_key(Some("aa-first"), "digest")),
        Some(&digest)
    );
}

// The filename law and its inverse are pinned TOGETHER, over the real registry, so neither half can
// move alone. `bundle` walks the artifacts dir with the inverse, so a producer that stopped
// sanitizing would silently drop that rootfs from the manifest — the N-BIN-4 defect class.
#[test]
fn the_filename_law_round_trips_through_its_inverse() {
    for entry in resolve_rootfs_registry(None).expect("baseline registry") {
        let label = (entry.label != DEFAULT_LABEL).then_some(entry.label.as_str());
        let filename = rootfs_filename(label);
        assert_eq!(
            rootfs_label_from_filename(&filename),
            label.map(|l| l.replace('.', "-")).as_deref(),
            "`{filename}` must invert to the sanitized label it was composed from"
        );
    }

    // The sanitization itself, and the shapes the inverse must refuse: the bare default, a sidecar
    // that is not an `.erofs`, and a name whose remainder carries a `.` (which no filename this law
    // produces ever does, so one that appears is a sidecar).
    assert_eq!(rootfs_filename(None), "rootfs.erofs");
    assert_eq!(rootfs_filename(Some("12.4")), "rootfs-12-4.erofs");
    assert_eq!(rootfs_label_from_filename("rootfs.erofs"), None);
    assert_eq!(rootfs_label_from_filename("rootfs-acme.cache_key"), None);
    // …and the §7.4 declaration sidecar (§18 delta 6c) is a sidecar too: a walk that read
    // `rootfs-acme.features` as the artifact `rootfs-acme` would record a two-line text file as a
    // userland image, which is the exact shape of the defect the `.cache_key` case above pins.
    assert_eq!(rootfs_label_from_filename("rootfs-acme.features"), None);
    assert_eq!(rootfs_label_from_filename("rootfs-12.4.erofs"), None);
    assert_eq!(rootfs_label_from_filename("vmlinux-acme"), None);
    assert_eq!(
        rootfs_label_from_filename("rootfs-acme.erofs"),
        Some("acme")
    );

    // The artifact-key law's default arm is the one every pre-v33 downstream stage reads.
    assert_eq!(rootfs_artifact_key(None), "rootfs");
    assert_eq!(rootfs_artifact_key(Some("acme")), "rootfs-acme");
}

// Two labels that sanitize to one on-disk filename are refused NAMING BOTH — the shared core's
// collision reject, reached through the rootfs kind. Without it the second build silently overwrites
// the first and the two labels evict each other's cache entry forever.
#[test]
fn two_labels_colliding_on_one_filename_are_rejected() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let digest = format!("sha256:{}", "e".repeat(64));
    let overlay = write_overlay(
        tmp.path(),
        &format!(
            r#"{{ "rootfs": {{ "12.4": {{ "image": "i", "digest": "{digest}" }},
                 "12-4": {{ "image": "i", "digest": "{digest}" }} }} }}"#
        ),
    );
    let msg = registry_err(&overlay);
    for named in ["12.4", "12-4", "rootfs-12-4.erofs"] {
        assert!(msg.contains(named), "the message must name {named}: {msg}");
    }
}

// §10.5's LAZINESS GATE, written the way the design's own gate paragraph words it (§18 delta 6):
// "register a second label pointing at the same digest as `default`, build both, assert
// byte-identical outputs AND that `default`'s cache key did not move … then register a
// `debian-latest` label and assert a build that selects nothing does not build it."
//
// Three claims, one test, because they are one property — registering is not building:
//
//  1. a second label pinning the SAME digest as `default` resolves to the same `(image, digest)`
//     pair and folds to the SAME stage cache key. Identical inputs, identical key, one cached blob
//     — which is what "byte-identical outputs" means before a byte is packed (packing them is the
//     live leg's job; this half is the identity, and it is the half that can silently drift);
//  2. `default`'s own cache key is BYTE-IDENTICAL to what it was with no overlay at all. This is
//     the assertion the design calls the only one that catches a registry change quietly re-keying
//     every existing artifact: a re-key is invisible in every functional test — every build still
//     produces a correct image — and shows up only as every warm artifacts dir on every downstream
//     host rebuilding from scratch, once, silently;
//  3. a THIRD registered label (`debian-latest`, the design's own example of the userland that
//     would tax everyone) is enumerable and pinned, yet contributes nothing to a build that names
//     no label: same key, same stage name, same filename, and its own artifact is a DIFFERENT file
//     that the default build never names.
//
// RED on the inverse, verified two ways: (a) fold anything registry-wide into
// `RootfsStage::cache_key` — e.g. the whole resolved pins map instead of this label's two keys —
// and claims 2 and 3 fail, which is exactly the re-keying regression; (b) drop the label from
// `rootfs_pin_key` so both labels read the default's keys, and claim 3's distinct-artifact half
// fails. The kernel half of laziness (`build-kernels <label>…` / `--all` selecting a subset of a
// registry that holds more) is gated at the composition root, in `vmcell-cli`'s
// `build_kernels_selects_only_the_labels_it_names` — the library has no eager rootfs roster to
// make lazy, because the rootfs kind is selection-driven from birth.
#[test]
fn registering_a_label_builds_nothing_and_moves_no_existing_key() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let baseline = resolve_rootfs_registry(None).expect("the baseline registry resolves");
    let default = baseline
        .iter()
        .find(|e| e.label == DEFAULT_LABEL)
        .expect("the committed baseline must register a `default` rootfs");

    // `twin` re-registers the default's exact digest; `debian-latest` is the extra userland the
    // design names — registered, pinned, and nobody's business until something selects it.
    let overlay = write_overlay(
        tmp.path(),
        &format!(
            r#"{{ "rootfs": {{
                 "twin":          {{ "image": "{}", "digest": "{}" }},
                 "debian-latest": {{ "image": "docker.io/library/debian",
                                     "digest": "sha256:{}" }} }} }}"#,
            digest_registration(default).0,
            digest_registration(default).1,
            "c".repeat(64)
        ),
    );

    // The registrations really happened — without this the whole test is vacuous.
    let labels = resolve_rootfs_labels(Some(&overlay)).expect("the overlay resolves");
    assert_eq!(
        labels,
        vec![
            "debian-latest".to_string(),
            DEFAULT_LABEL.to_string(),
            "twin".to_string()
        ],
        "both labels must be registered beside the baseline's default"
    );

    // 1. Same digest, same entry, same key.
    let registry = resolve_rootfs_registry(Some(&overlay)).expect("the overlay resolves");
    let twin = registry
        .iter()
        .find(|e| e.label == "twin")
        .expect("`twin` must resolve");
    assert_eq!(
        digest_registration(twin),
        digest_registration(default),
        "a label pinning the same digest must resolve to the same pair"
    );
    assert_eq!(
        rootfs_cache_key(Some("twin"), Some(&overlay)),
        rootfs_cache_key(None, Some(&overlay)),
        "two labels on one digest are one artifact identity — same inputs, same key"
    );

    // 2. The default's key did not move: the empty-change property.
    assert_eq!(
        rootfs_cache_key(None, Some(&overlay)),
        rootfs_cache_key(None, None),
        "registering labels must not re-key the artifact a cell that names no label gets"
    );

    // 3. …and the third label is pinned (so it IS registered) yet builds nothing here: the default
    // stage still answers with the default's name and filename, and `debian-latest`'s artifact is a
    // different file, reachable only by naming it.
    let pins = resolve_pins(Some(&overlay)).expect("the overlay resolves");
    assert!(
        pins.contains_key(&rootfs_pin_key(Some("debian-latest"), "digest")),
        "`debian-latest` must be pinned, or claim 3 proves nothing"
    );
    let target = tmp.path();
    let default_stage = RootfsStage::labelled(None);
    assert_eq!(default_stage.name(), rootfs_artifact_key(None));
    assert_eq!(default_stage.out_path(target), target.join("rootfs.erofs"));
    let extra_stage = RootfsStage::labelled(Some("debian-latest"));
    assert_ne!(
        extra_stage.out_path(target),
        default_stage.out_path(target),
        "the registered-but-unselected label must land on its own file, never over the default's"
    );
    assert_ne!(
        rootfs_cache_key(Some("debian-latest"), Some(&overlay)),
        rootfs_cache_key(None, Some(&overlay)),
        "a different digest is a different identity — the `assert_ne!` is non-vacuous because \
         `twin`, above, pins the SAME digest and DOES match"
    );
}

// §7.4's `features` declaration on a registry entry (§18 delta 6c), strict-parsed through the ONE
// token table.
//
// The misspelling leg is the whole point of the clause: a token that read as "absent" would produce
// a cell that quietly does less while every downstream check passed, because nothing claimed the
// feature. So a typo must be a hard ERROR naming the token — and, separately, must NOT resolve at
// all, which the `expect_err` and the absence assertion below pin as two different claims.
//
// RED on the inverse, three ways: (a) match the token against a second, local table instead of
// `Feature::parse` — the typo resolves to nothing and the entry parses; (b) read the stance with
// `as_bool().unwrap_or(true)` — the `"false"` string leg parses to the OPPOSITE of what was
// written; (c) drop `features` from the accepted-key set — the positive control fails as an unknown
// key.
#[test]
fn a_features_declaration_is_strict_parsed_through_the_one_token_table() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let digest = format!("sha256:{}", "f".repeat(64));
    let entry = |features: &str| {
        write_overlay(
            tmp.path(),
            &format!(
                r#"{{ "rootfs": {{ "acme": {{ "image": "i", "digest": "{digest}",
                     "features": {features} }} }} }}"#
            ),
        )
    };

    // (a) An unknown token. Derived from a real name rather than typed, so the leg cannot rot into
    // testing a token that was never close to a real one.
    let real = Feature::SnapshotRestore.name();
    let typo = &real[..real.len() - 1];
    let msg = registry_err(&entry(&format!("{{\"{typo}\": false}}")));
    assert!(msg.contains(typo), "the message must name the token: {msg}");
    assert!(
        msg.contains(real),
        "the message must list the valid tokens: {msg}"
    );

    // (b) A non-boolean stance. `"false"` (the string) is the hazard: it is *truthy* to anything
    // that coerces, so a defaulted read would say `true` about an artifact that wrote `false`.
    let msg = registry_err(&entry("{\"snapshot_restore\": \"false\"}"));
    assert!(
        msg.contains("snapshot_restore"),
        "the message must name the key: {msg}"
    );

    // …and a `features` value that is not an object at all.
    let msg = registry_err(&entry("\"snapshot_restore\""));
    assert!(msg.contains("features"), "{msg}");

    // (c) The positive control: a well-formed declaration resolves onto the entry, keyed by the
    // parsed `Feature` rather than by the token it was written as.
    let overlay = entry("{\"snapshot_restore\": false, \"xattr_preserved\": true}");
    let registry = resolve_rootfs_registry(Some(&overlay)).expect("a valid declaration resolves");
    let acme = registry
        .iter()
        .find(|e| e.label == "acme")
        .expect("`acme` resolves");
    assert_eq!(acme.features.get(&Feature::SnapshotRestore), Some(&false));
    assert_eq!(acme.features.get(&Feature::XattrPreserved), Some(&true));

    // An entry that declares nothing carries an EMPTY map — the baseline, stated. Not `None`, and
    // not "everything absent": an artifact that says nothing is not declaring anything absent.
    let plain = write_overlay(
        tmp.path(),
        &format!(r#"{{ "rootfs": {{ "acme": {{ "image": "i", "digest": "{digest}" }} }} }}"#),
    );
    let registry = resolve_rootfs_registry(Some(&plain)).expect("resolves");
    assert!(
        registry
            .iter()
            .find(|e| e.label == "acme")
            .expect("`acme` resolves")
            .features
            .is_empty(),
        "an undeclared entry contributes no stances"
    );
}

// The committed `rootfs.default` declares `xattr_preserved = false`, and this is the assertion that
// keeps the canonical artifact honest rather than merely quiet.
//
// vmcell's own packer strips every xattr (the recorded PAX-xattr limitation, §4.2), yet before this
// delta the canonical `rootfs.erofs` carried no declaration at all — so `load_beside` returned the
// baseline, nothing removed `XattrPreserved`, and `FeatureSet::has(XattrPreserved)` answered TRUE
// for an artifact that preserves none. The declaration is what makes the intersection say what the
// packer does.
//
// RED on deleting the `features` key from `pins.json`'s `rootfs.default`.
#[test]
fn the_committed_default_declares_what_its_packer_actually_does() {
    let default = resolve_rootfs_entry(None, None)
        .expect("the baseline registry resolves")
        .expect("the committed baseline must register a `default` rootfs");
    assert_eq!(
        default.features.get(&Feature::XattrPreserved),
        Some(&false),
        "the canonical rootfs must DECLARE that its packer strips xattrs (§4.7/§7.4); with no \
         declaration the intersection reports the feature present"
    );
}

// §7.4's CACHE-IDENTITY SPLIT, and the single assertion that justifies the declaration producer
// being its own stage: "a declaration-only edit re-emits the sidecar (content-addressed on its own)
// and leaves the image key unmoved — a declaration change must not rebuild the image it describes."
//
// Two claims, opposite directions, which is what makes the pair non-vacuous:
//
//  1. editing ONLY a label's `features` declaration leaves `RootfsStage::cache_key` byte-identical.
//     RED by folding the declaration into `RootfsStage::cache_key` (or by flattening `features`
//     into the scalar pins the stage reads): a fact written *about* an image re-packs it, which is
//     the half §7.4 forbids by name;
//  2. the same edit MOVES `RootfsFeaturesStage::cache_key`. RED by dropping the declaration from
//     that fold: the sidecar goes stale forever, because the image key never moved either and the
//     warm hit republishes yesterday's file.
#[test]
fn a_declaration_edit_moves_the_sidecar_key_and_not_the_image_key() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let digest = format!("sha256:{}", "a".repeat(64));
    // Distinct FILES, not `write_overlay`'s one reused name: both overlays have to be readable at
    // the same time, and a shared path would make claim 1 compare an overlay with itself.
    let with_features = |name: &str, features: &str| {
        let path = tmp.path().join(name);
        std::fs::write(
            &path,
            format!(
                r#"{{ "rootfs": {{ "{DEFAULT_LABEL}": {{ "image": "downstream/base",
                     "digest": "{digest}"{features} }} }} }}"#
            ),
        )
        .expect("write overlay");
        path
    };
    let silent = with_features("silent.json", "");
    let declaring = with_features(
        "declaring.json",
        ", \"features\": {\"snapshot_restore\": false}",
    );

    // 1. The image identity does not move.
    assert_eq!(
        rootfs_cache_key(None, Some(&silent)),
        rootfs_cache_key(None, Some(&declaring)),
        "a declaration-only edit must leave the IMAGE's cache key byte-identical (§7.4)"
    );

    // 2. The sidecar's identity does.
    let features_key = |overlay: &Path| {
        let entry = resolve_rootfs_entry(None, Some(overlay))
            .expect("resolves")
            .expect("the default entry");
        RootfsFeaturesStage::labelled(None)
            .with_features(entry.features)
            .cache_key(&StageInputs::default())
    };
    assert_ne!(
        features_key(&silent),
        features_key(&declaring),
        "a declaration edit must move the SIDECAR's cache key, or the edit never reaches the disk"
    );

    // And the sidecar stage lands beside the image it describes, on its own file — the reader
    // (`FeatureDeclaration::load_beside`) composes the same name from the other side.
    let target = tmp.path();
    let entry = resolve_rootfs_entry(None, Some(&declaring))
        .expect("resolves")
        .expect("the default entry");
    let stage = RootfsFeaturesStage::labelled(None).with_features(entry.features);
    assert_eq!(stage.out_path(target), target.join("rootfs.features"));
    assert_eq!(
        stage.out_path(target),
        feature_manifest_path(&RootfsStage::labelled(None).out_path(target)),
        "producer and reader must compose one path"
    );
}

// The producer end-to-end, through the real `Pipeline`: a declared entry becomes a sidecar on disk
// that `FeatureDeclaration::load_beside` reads back — and an UNDECLARED entry still emits one.
//
// Unconditional emission is the decision that removes the stale-sidecar hazard: an empty manifest
// parses back to empty stances, which is semantically identical to an absent sidecar, so there is
// no behavior change for an undeclared label and no second "remove the file when the declaration
// went away" law to keep in agreement (the kernel's `clear_resolved_config` is exactly that second
// law, and it exists because that sidecar is conditional).
//
// Both legs use OVERLAY-ONLY labels rather than `default`. That is load-bearing: the pins merge is
// leaf-wise, so an overlay that re-states `default`'s image and digest still INHERITS the committed
// baseline's `features` declaration — a "silent" default is not silent, and the empty-declaration
// leg would be vacuous against it.
//
// RED on a `run` that returns early for an empty declaration: the `silent` leg's `exists` fails.
// RED on a `run` that never registers the sidecar in `StageOutputs`: the built `Artifacts` map has
// no entry for it on the cold path, so nothing downstream — `bundle` included — can name the file.
#[tokio::test]
async fn the_sidecar_is_emitted_and_readable_including_for_an_empty_declaration() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let digest = format!("sha256:{}", "b".repeat(64));
    let overlay = write_overlay(
        tmp.path(),
        &format!(
            r#"{{ "rootfs": {{
                 "declared": {{ "image": "i", "digest": "{digest}",
                                "features": {{"snapshot_restore": false}} }},
                 "silent":   {{ "image": "i", "digest": "{digest}" }} }} }}"#
        ),
    );

    for (label, expected) in [("declared", Some(false)), ("silent", None)] {
        let dir = tmp.path().join(label);
        let entry = resolve_rootfs_entry(Some(label), Some(&overlay))
            .expect("resolves")
            .expect("the overlay entry");
        // Non-vacuity: the two legs really do differ in what they declare.
        assert_eq!(
            entry.features.get(&Feature::SnapshotRestore),
            expected.as_ref(),
            "`{label}` must declare what this leg is about"
        );
        let stage =
            RootfsFeaturesStage::labelled(Some(label)).with_features(entry.features.clone());
        let sidecar = stage.out_path(&dir);

        let artifacts = Pipeline::new(dir.clone())
            .add_stage(Box::new(stage))
            .build(&Cache::default())
            .await
            .expect("the declaration stage runs");

        // Registered under its OWN artifact key, derived from the image's — which is what
        // content-addresses it with the image and lets `bundle` name it.
        assert_eq!(
            artifacts
                .paths
                .get(&features_artifact_key(&rootfs_artifact_key(Some(label)))),
            Some(&sidecar),
            "the sidecar must be registered as an artifact, not merely written"
        );
        assert!(
            sidecar.exists(),
            "the sidecar must be emitted even when the entry declares nothing: {}",
            sidecar.display()
        );

        // Read it back from the OTHER side — beside the image path, which is how a cell finds it.
        let declaration = FeatureDeclaration::load_beside(
            &RootfsStage::labelled(Some(label)).out_path(&dir),
            Source::Rootfs(rootfs_filename(Some(label))),
        )
        .expect("the emitted sidecar parses");
        assert_eq!(
            declaration.stances.get(&Feature::SnapshotRestore),
            expected.as_ref(),
            "what the entry declared must be what the sidecar says"
        );

        // A deleted sidecar comes back: the payload-existence check makes the next build a miss,
        // so a hand-cleaned artifacts dir re-declares rather than silently reverting to the
        // baseline (the failure mode is invisible — an artifact with no sidecar looks fine).
        std::fs::remove_file(&sidecar).expect("remove the sidecar");
        Pipeline::new(dir.clone())
            .add_stage(Box::new(
                RootfsFeaturesStage::labelled(Some(label)).with_features(entry.features.clone()),
            ))
            .build(&Cache::default())
            .await
            .expect("the second build runs");
        assert!(
            sidecar.exists(),
            "a vanished registered sidecar must be rebuilt, not republished as a dangling path"
        );
    }
}

// F7's DEV PATH-OVERRIDE, the third registration shape (§10.5; §18 delta 6c), parsed.
//
// §10.5 says only "under one explicitly named override key" and leaves entry-key-vs-reserved-label
// open; the decision is the ENTRY KEY (`unpinned_path`), recorded at the parse site. What this test
// pins is that the decision is enforced on BOTH halves: the key parses into its own registration
// shape, and it is mutually exclusive with the digest shape — because an entry carrying both would
// have vmcell silently pick a winner between a durable claim and a "whatever is there today".
//
// RED on the inverse, three ways: (a) drop `reject_multiple_registration_shapes` and the two-shape
// leg resolves to whichever arm the parser reaches first; (b) model the override as an OPTIONAL
// FIELD beside `image`/`digest` instead of a shape — the two-shape leg becomes representable and
// the `expect_err` fails; (c) drop `unpinned_path` from the accepted-key set and the positive
// control fails as an unknown key.
#[test]
fn an_unpinned_path_registration_is_its_own_shape_and_excludes_the_digest_one() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let digest = format!("sha256:{}", "a".repeat(64));

    // Two shapes in one entry, both orderings of the pair that can be written: `unpinned_path`
    // beside `digest`, and `unpinned_path` beside `image`. `image` alone is half the digest shape,
    // and it must still count AS that shape — otherwise an entry could smuggle a mutable image
    // reference in beside an override and have it silently ignored.
    for beside in [
        format!(r#""digest": "{digest}""#),
        r#""image": "docker.io/library/debian""#.to_string(),
    ] {
        let overlay = write_overlay(
            tmp.path(),
            &format!(
                r#"{{ "rootfs": {{ "acme": {{ {beside},
                     "{UNPINNED_PATH_KEY}": "/tmp/dev-rootfs.erofs" }} }} }}"#
            ),
        );
        let msg = registry_err(&overlay);
        assert!(
            msg.contains(UNPINNED_PATH_KEY),
            "the refusal must name the override shape: {msg}"
        );
        assert!(
            msg.contains("image") || msg.contains("digest"),
            "the refusal must name the digest shape it collided with: {msg}"
        );
    }

    // An empty override path is not "unset" — it is a registration that resolves to nothing.
    let empty = write_overlay(
        tmp.path(),
        &format!(r#"{{ "rootfs": {{ "acme": {{ "{UNPINNED_PATH_KEY}": "" }} }} }}"#),
    );
    assert!(
        registry_err(&empty).contains(UNPINNED_PATH_KEY),
        "an empty override path must be refused naming the key"
    );

    // The positive control: the override alone resolves into its own shape, carrying the path
    // VERBATIM — and it may still declare features, because a dev override that removes a
    // capability has to be able to say so (§7.4).
    let overlay = write_overlay(
        tmp.path(),
        &format!(
            r#"{{ "rootfs": {{ "acme": {{ "{UNPINNED_PATH_KEY}": "/tmp/dev-rootfs.erofs",
                 "features": {{"snapshot_restore": false}} }} }} }}"#
        ),
    );
    let registry = resolve_rootfs_registry(Some(&overlay)).expect("the dev override resolves");
    let acme = registry
        .iter()
        .find(|e| e.label == "acme")
        .expect("`acme` resolves");
    assert_eq!(
        acme.registration,
        RootfsRegistration::UnpinnedPath {
            path: PathBuf::from("/tmp/dev-rootfs.erofs")
        }
    );
    assert_eq!(acme.features.get(&Feature::SnapshotRestore), Some(&false));

    // PROVENANCE: the override reaches the flattened pins under the one key composer, which is what
    // carries it into the flattening of `resolved_pins.json` — the document `bundle` reads to
    // refuse an unpinned artifacts dir, and the only route by which `RootfsStage` learns about it.
    // RED on a flattener arm that drops the key: the label would resolve, build and bundle in
    // silence.
    let pins = resolve_pins(Some(&overlay)).expect("the overlay resolves");
    assert_eq!(
        pins.get(&rootfs_pin_key(Some("acme"), UNPINNED_PATH_KEY))
            .map(String::as_str),
        Some("/tmp/dev-rootfs.erofs"),
        "an unpinned rootfs registration must reach the flat pins"
    );
}

// The override is HONORED, which is the half that separates a parsed key from an accepted-and-
// ignored one (AGENTS.md's fail-loud rule: every accepted input is honored or rejected).
//
// Three claims, one test:
//
//  1. the label's published image is the pointed-at BYTES — asserted on content, not on "a file
//     appeared", which packing an OCI base would also satisfy;
//  2. editing the pointed-at file MOVES the stage's cache key, and touching an unrelated file does
//     not. An unpinned registration means "whatever is at that location today", so its identity has
//     to be read from the file; an identity read from the registration alone would serve yesterday's
//     image from a warm artifacts dir forever, with every test still green;
//  3. a path that is not there fails LOUD naming the label and the path — the one failure an
//     unpinned registration is actually prone to, because the registration outlives the day the
//     path was true.
//
// RED on the inverse, three ways: (1) a `run` that ignores the pin and packs from the pins'
// `image`/`digest` — it fails on the missing-pin error instead of publishing; (2) a `cache_key`
// that folds only the path string — claim 2's `assert_ne!` fails; (3) a `publish_unpinned` that
// swallows the copy error — claim 3 gets `Ok` and no file.
#[tokio::test]
async fn an_unpinned_rootfs_publishes_the_pointed_at_bytes_and_tracks_their_content() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let src = tmp.path().join("dev-rootfs.erofs");
    std::fs::write(&src, b"EROFS-DEV-IMAGE-v1").expect("seed the override target");
    let overlay = |path: &Path| {
        let file = tmp.path().join(format!(
            "overlay-{}.json",
            path.file_name().unwrap_or_default().to_string_lossy()
        ));
        std::fs::write(
            &file,
            format!(
                r#"{{ "rootfs": {{ "acme": {{ "{UNPINNED_PATH_KEY}": "{}" }} }} }}"#,
                path.display()
            ),
        )
        .expect("write overlay");
        file
    };
    let ov = overlay(&src);
    let mut inputs = StageInputs::default();
    inputs.pins = resolve_pins(Some(&ov)).expect("the overlay resolves");
    let stage = RootfsStage::labelled(Some("acme"));
    let out = tmp.path().join("artifacts").join("rootfs-acme.erofs");

    // 1. The bytes.
    let outputs = stage
        .run(&inputs, &out)
        .await
        .expect("the override publishes");
    assert_eq!(
        std::fs::read(&out).expect("read the published image"),
        b"EROFS-DEV-IMAGE-v1",
        "the override's own bytes must be published as the label's image"
    );
    // …and registered under the label's artifact key, so `bundle` and every downstream stage can
    // name it. RED on a publisher that registers the un-suffixed `rootfs` key for a labelled stage.
    assert_eq!(
        outputs.artifacts.get(&rootfs_artifact_key(Some("acme"))),
        Some(&out),
        "the published image must be registered under this label's artifact key"
    );

    // 2. The identity tracks the FILE.
    let before = stage.cache_key(&inputs);
    std::fs::write(&src, b"EROFS-DEV-IMAGE-v2-longer").expect("edit the override target");
    assert_ne!(
        before,
        stage.cache_key(&inputs),
        "editing the pointed-at image must re-key: an unpinned registration's identity is read \
         from the file, because the registration itself promises nothing"
    );
    // …and an UNRELATED file does not move it, which is what makes the claim above non-vacuous.
    let unrelated = tmp.path().join("something-else");
    std::fs::write(&unrelated, b"noise").expect("write");
    let after_edit = stage.cache_key(&inputs);
    std::fs::write(&unrelated, b"more noise").expect("rewrite");
    assert_eq!(
        after_edit,
        stage.cache_key(&inputs),
        "a file this registration does not name must not move its key"
    );
    // Two labels pointing at DIFFERENT files stay two artifacts even when the bytes agree.
    let twin_src = tmp.path().join("twin-rootfs.erofs");
    std::fs::write(&twin_src, b"EROFS-DEV-IMAGE-v2-longer").expect("write");
    let twin_ov = overlay(&twin_src);
    let mut twin_inputs = StageInputs::default();
    twin_inputs.pins = resolve_pins(Some(&twin_ov)).expect("resolves");
    assert_ne!(
        stage.cache_key(&inputs),
        stage.cache_key(&twin_inputs),
        "two paths are two registrations, even with momentarily identical bytes"
    );

    // 3. A path that is not there is loud, and names both facts.
    let gone = tmp.path().join("never-existed.erofs");
    let gone_ov = overlay(&gone);
    let mut gone_inputs = StageInputs::default();
    gone_inputs.pins = resolve_pins(Some(&gone_ov)).expect("resolves");
    let err = stage
        .run(&gone_inputs, &tmp.path().join("artifacts/missing.erofs"))
        .await
        .expect_err("an unreadable override path is a hard stop");
    let msg = err.to_string();
    assert!(
        msg.contains("acme"),
        "the failure must name the label: {msg}"
    );
    assert!(
        msg.contains(&gone.display().to_string()),
        "the failure must name the path: {msg}"
    );

    // And the shape is NOT contagious: a label that names no override still resolves through the
    // digest shape, so the branch above is a branch and not a mode switch.
    assert!(matches!(
        resolve_rootfs_entry(None, Some(&ov))
            .expect("resolves")
            .expect("the default entry")
            .registration,
        RootfsRegistration::Digest { .. }
    ));
}
