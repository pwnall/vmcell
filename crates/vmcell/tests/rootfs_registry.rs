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
use vmcell::artifact::rootfs::{
    rootfs_artifact_key, rootfs_filename, rootfs_label_from_filename, rootfs_pin_key,
};
use vmcell::artifact::{resolve_pins, resolve_rootfs_labels, resolve_rootfs_registry};
use vmcell::error::Error;

/// Writes an overlay document into `dir` and returns its path.
fn write_overlay(dir: &Path, body: &str) -> PathBuf {
    let path = dir.join("overlay.json");
    std::fs::write(&path, body).expect("write overlay");
    path
}

/// The rejection message for an overlay, or a panic naming what came back instead.
fn registry_err(overlay: &Path) -> String {
    match resolve_rootfs_registry(Some(overlay)) {
        Err(Error::Artifact(m)) => m,
        other => panic!("expected an Artifact rejection, got {other:?}"),
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
    assert_eq!(&default.image, image);
    assert_eq!(&default.digest, digest);

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
    assert_eq!(default.image, "downstream/base");
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

// Every accepted key is honored; every other key is REJECTED naming it (law F1). The two the design
// sketch shows but this delta does not implement — `xattrs` (§4.7) and `features` (§7.4) — are
// rejected with a forward reference rather than a bare "unknown", because a consumer copying §10.5's
// example deserves to be told WHEN rather than merely NO.
//
// This is also the F1-clean seam between deltas 6 and 7: `xattrs` is refused here and honored there,
// never accepted-and-ignored in between.
#[test]
fn an_unknown_entry_key_is_rejected_naming_it() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let digest = format!("sha256:{}", "b".repeat(64));
    for (key, value, expected) in [
        ("xattrs", "\"preserve\"", "delta 7"),
        ("features", "{\"snapshot_restore\": false}", "delta 6c"),
        ("imgae", "\"typo\"", "known keys"),
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
