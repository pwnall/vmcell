#![no_main]

use libfuzzer_sys::fuzz_target;
use std::collections::HashSet;
use vmcell::artifact::handler::{HandlerSource, handler_filename};
use vmcell::artifact::registry::{UNPINNED_PATH_KEY, registry_label};
use vmcell::artifact::rootfs::rootfs_artifact_stem;
use vmcell::artifact::{
    RootfsRegistration, fuzz_handler_registry, fuzz_merged_pins_document, fuzz_rootfs_registry,
};
use vmcell::feature::Feature;

// The artifact-registry entry parsers (design §10.5, invariant F7): a pins overlay's TEXT, through
// the strict top-level parse, the leaf-wise merge over the committed baseline, the retired-v32
// singleton reject, and then both label-map kinds — `rootfs.<label>` and `handlers.<label>`.
//
// WHO SUPPLIES THE BYTES: a downstream toolkit consumer's pins overlay (`$VMCELL_PINS` /
// `--pins`) — named contract surface (§10.4), and the document that decides WHICH bytes every
// artifact a cell boots is made of. Like `injection_dest` and `feature_manifest` this is LOCAL
// build config rather than an off-host wire, and it is ranked accordingly: what F7 protects is a
// registration silently meaning "whatever is at that location today", which is a provenance
// invariant rather than a remote-exploit boundary.
//
// WHY IT EARNS A SLOT: the whole kind is one week old, and it is a hand-written strict parser over
// caller JSON with five independent rejections layered on one object (unknown key, shape
// exclusivity, digest format, `unpinned_path` shape, `features` map) plus two rejections that only
// exist above the entry (the legacy-singleton reject, which fires on the MERGED document, and the
// sanitized-filename collision reject, which fires across entries). Every one of those is an
// ACCEPT-then-mean-something-else hazard rather than a crash hazard, so the value here is entirely
// in the properties below — a registration vmcell accepted and quietly reinterpreted is exactly the
// class §10.5 says it will not ship.
//
// PRODUCTION PRECONDITION MIRRORED: the file read, and nothing else. `resolve_rootfs_registry` /
// `resolve_handler_registry` take a `Path`, so the only literal form of them writes a temp file per
// iteration — I/O on a fuzz hot path, which every target here avoids. `fuzz_merged_pins_document`
// skips exactly `read_pins_overlay`; `parse_pins_overlay`'s strict top-level check, the merge and
// the legacy reject all run in the shipped order, and the two registry entry points below drive the
// SAME `RegistryKind` descriptors production ships (they call the same private
// `*_registry_from_doc`, so the namespace, the filename law and the collision message cannot fork).
// The two kinds are resolved through two separate calls on purpose: one both-kinds entry point
// returning one `Result` would let either kind's first rejection mask every input the other kind
// would have seen.
//
// SEEDS ARE A CORRECTNESS DEPENDENCY, not a speed-up: `parse_pins_overlay` refuses any top-level
// key that is not one of ten known namespaces, so random bytes never reach a registry entry at all.
// `fuzz/corpus/registry_entry/seed-*.json` carries one seed per shape and per rejection; see
// `fuzz/.gitignore`, which is the seed roster.
//
// PROPERTIES, for every ACCEPTED document —
//   * the merged `rootfs` object carries NEITHER retired singleton key. This is the legacy reject
//     stated as a property of the result rather than of the input, which is the only way to see it:
//     the hybrid it refuses is produced by the MERGE, not written by anyone.
//   * exactly one registration SHAPE was named in the entry that produced each resolved entry —
//     counted on the input object, because the resolved type is an enum and can only hold one, so
//     asserting on the enum alone would be vacuous. Two shapes accepted means whichever lost is a
//     registration the operator wrote and vmcell silently ignored.
//   * a `Digest`/`Registered` shape's digest is `sha256:` + 64 LOWERCASE hex. Recomputed HERE rather than
//     called back through the parser's own check: an assertion routed through the implementation it
//     is testing proves only that the implementation agrees with itself. (LOWERCASE hex since v33
//     delta 6c, when the two production copies became one predicate that rejects uppercase — see
//     `is_pinned_digest`.)
//   * every resolved field is the input's, byte for byte — no shape's value is defaulted,
//     re-derived or lifted from the baseline entry of the same name.
//   * every accepted `features` key re-parses through `Feature::parse`, the one token table (F6),
//     and the map is exactly as large as the input's, so no declaration was dropped.
//   * every accepted `applets` name is a bare file name, and `applet_roster()` is never empty —
//     an entry with no roster falls back to `GUEST_TOOLS_APPLETS`, so there is no injectable
//     handler with nothing to inject.
//   * the roster is sorted byte-lexicographically, holds exactly the document's labels, and no two
//     labels sanitize onto one on-disk filename.
//
// WHAT WOULD BE A FINDING: an accepted entry naming two shapes or none; an accepted digest that is
// not `sha256:<64 lowercase hex>`; an accepted document still carrying the v32 singleton; a resolved value
// that is not the one registered; a dropped `features` stance or `applets` name; two labels
// resolving onto one artifact filename; any panic.
//
// DRIVEN RED against five buggy implementations, one per layer, each reached from the committed
// seeds inside 90 s: `reject_legacy_pins_shapes` returning `Ok(())` (caught at the merged-document
// assertion); `rootfs_registry_entry`'s digest check weakened to "non-empty after `sha256:`" (caught
// on a mutated seed digest, `sha256:ac320f9a57d1`); `reject_multiple_registration_shapes`'s guard
// flipped to `< 3`, so an entry naming two shapes resolves to whichever the match arm reaches first
// (caught by the in-body positive control, on the first input); `rootfs_entry_features` returning an
// empty map, the accept-then-ignore shape (caught by the stance-count assertion, on the seed
// itself); and `reject_unpinned_digest` skipped in the handler digest arm (caught on a mutated
// handler seed, which is also this target's evidence that the handlers half is genuinely reached).

/// The registry's digest law, recomputed independently of the parser that enforces it.
///
/// **Lowercase** hex, as of v33 delta 6c: this predicate deliberately matched the looser shipped
/// behavior (either case) when the target landed, because a harness asserting a rule the code does
/// not enforce is a knowingly-red nightly job. The shared predicate
/// (`artifact::registry::reject_unpinned_digest`) now rejects uppercase at registration — vmcell
/// emits and compares digests lowercase, so an uppercase registration parsed clean and could then
/// never verify — and this recomputation tracks it. Loosening it back would let exactly that class
/// through unnoticed again.
fn is_pinned_digest(digest: &str) -> bool {
    let hex = digest.strip_prefix("sha256:").unwrap_or_default();
    hex.len() == 64 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// The entry object one resolved label was parsed from. Present by construction — the resolver maps
/// over the document's own keys — so its absence is itself a finding.
fn spec_of<'a>(doc: &'a serde_json::Value, namespace: &str, label: &str) -> &'a serde_json::Value {
    doc.get(namespace)
        .and_then(|ns| ns.get(label))
        .unwrap_or_else(|| {
            panic!("resolved `{namespace}.{label}` is not a key of the document it was parsed from")
        })
}

/// Asserts the shared roster law: sorted, one entry per document key, no two labels sharing an
/// on-disk artifact filename.
fn assert_roster(
    doc: &serde_json::Value,
    namespace: &str,
    labels: &[String],
    filename: &dyn Fn(&str) -> String,
) {
    let declared = doc
        .get(namespace)
        .and_then(serde_json::Value::as_object)
        .map_or(0, serde_json::Map::len);
    assert_eq!(
        labels.len(),
        declared,
        "`{namespace}` resolved {} entries from {declared} registered label(s); a dropped entry is \
         a registration vmcell silently ignored",
        labels.len()
    );
    assert!(
        labels.windows(2).all(|w| w[0] < w[1]),
        "`{namespace}` roster is not sorted byte-lexicographically: {labels:?} — build order would \
         follow document order, which a transitive `preserve_order` feature can change"
    );
    let mut filenames: HashSet<String> = HashSet::with_capacity(labels.len());
    for label in labels {
        let name = filename(label);
        assert!(
            filenames.insert(name.clone()),
            "`{namespace}` labels sanitize onto one artifact filename `{name}` ({labels:?}); the \
             second build would overwrite the first and the two would evict each other's cache \
             entry forever"
        );
    }
}

fuzz_target!(|data: &[u8]| {
    let Ok(overlay) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(doc) = fuzz_merged_pins_document(overlay) else {
        return;
    };

    // The legacy-singleton reject, as a property of the MERGED document.
    if let Some(rootfs) = doc.get("rootfs").and_then(serde_json::Value::as_object) {
        assert!(
            !rootfs.contains_key("image") && !rootfs.contains_key("digest"),
            "the merged pins document still carries a retired v32 `rootfs` singleton key; \
             `rootfs` is a registry of LABELS as of v33 (§10.5), and an accepted hybrid would make \
             `image`/`digest` read as label names"
        );
    }

    if let Ok(entries) = fuzz_rootfs_registry(&doc) {
        let labels: Vec<String> = entries.iter().map(|e| e.label.clone()).collect();
        // The STEM, which is the registry's collision key as of §18 delta 8: a rootfs's
        // `.cache_key` and `.features` sidecars are `with_extension` derivations of its image name,
        // so two labels sharing a stem collide on both whatever formats their images declare.
        assert_roster(&doc, "rootfs", &labels, &|l| {
            rootfs_artifact_stem(registry_label(l))
        });
        for entry in &entries {
            let spec = spec_of(&doc, "rootfs", &entry.label);
            let label = &entry.label;
            // `image` and `digest` are two halves of ONE shape, so they count once.
            let digest_shape = spec.get("image").is_some() || spec.get("digest").is_some();
            let unpinned = spec.get(UNPINNED_PATH_KEY).is_some();
            assert_eq!(
                usize::from(digest_shape) + usize::from(unpinned),
                1,
                "accepted `rootfs.{label}` names {} registration shape(s); an entry names EXACTLY \
                 one (§10.5, F7), or the loser is a registration vmcell silently ignored",
                usize::from(digest_shape) + usize::from(unpinned)
            );
            match &entry.registration {
                RootfsRegistration::Digest { image, digest } => {
                    assert!(
                        digest_shape,
                        "`rootfs.{label}` resolved to a digest shape it did not name"
                    );
                    assert_eq!(
                        spec.get("image").and_then(serde_json::Value::as_str),
                        Some(image.as_str()),
                        "`rootfs.{label}` resolved an image that is not the registered one"
                    );
                    assert_eq!(
                        spec.get("digest").and_then(serde_json::Value::as_str),
                        Some(digest.as_str()),
                        "`rootfs.{label}` resolved a digest that is not the registered one"
                    );
                    assert!(
                        is_pinned_digest(digest),
                        "accepted `rootfs.{label}.digest` is `{digest}`, not `sha256:<64 lowercase hex>`: a \
                         label resolving to a mutable tag means \"whatever is at that location \
                         today\", which no consumer's provenance discipline can cite"
                    );
                }
                RootfsRegistration::UnpinnedPath { path } => {
                    assert!(
                        unpinned,
                        "`rootfs.{label}` resolved to an override it did not name"
                    );
                    assert_eq!(
                        spec.get(UNPINNED_PATH_KEY)
                            .and_then(serde_json::Value::as_str),
                        path.to_str(),
                        "`rootfs.{label}` resolved an override path that is not the registered one"
                    );
                    assert!(
                        !path.as_os_str().is_empty(),
                        "accepted `rootfs.{label}.{UNPINNED_PATH_KEY}` is empty; the override's \
                         whole content is the file it names"
                    );
                }
            }
            let declared = spec.get("features").and_then(serde_json::Value::as_object);
            // `xattr_preserved` is the ONE stance that is not always a declaration (§4.7, §18
            // delta 7): a digest registration DERIVES it from its `xattrs` policy and refuses the
            // explicit token, while an `unpinned_path` registration derives nothing and may declare
            // it — vmcell packed none of those bytes, so only the operator knows. Counted out of
            // the declaration comparison on exactly the shape that derives it; comparing the raw
            // lengths would panic on every digest entry the corpus reaches, i.e. on valid input.
            let derives = matches!(entry.registration, RootfsRegistration::Digest { .. });
            assert_eq!(
                entry.features.len(),
                declared.map_or(0, serde_json::Map::len) + usize::from(derives),
                "accepted `rootfs.{label}` resolved {} stance(s) from {} declaration(s) plus {} \
                 derived; a dropped stance reads as the baseline, which is indistinguishable from \
                 the one the declaration meant to overturn (§7.4, F6)",
                entry.features.len(),
                declared.map_or(0, serde_json::Map::len),
                usize::from(derives)
            );
            assert_eq!(
                derives,
                entry.features.contains_key(&Feature::XattrPreserved)
                    && declared.is_none_or(|d| d.get(Feature::XattrPreserved.name()).is_none()),
                "accepted `rootfs.{label}` disagrees with itself about where its \
                 `xattr_preserved` stance came from: a digest entry derives it and refuses the \
                 token, an unpinned entry derives nothing and may declare it"
            );
            for (feature, stance) in &entry.features {
                assert_eq!(
                    Feature::parse(feature.name()).ok().as_ref(),
                    Some(feature),
                    "accepted `rootfs.{label}.features` holds a key that `Feature::parse` refuses; \
                     that would be two token tables where F6 says one"
                );
                if derives && *feature == Feature::XattrPreserved {
                    // The derived stance answers to the POLICY, not to a declaration.
                    assert_eq!(
                        *stance,
                        entry.xattrs.preserves(),
                        "accepted `rootfs.{label}` derived a stance its own `xattrs` policy does \
                         not imply (§4.7): the artifact would contradict its own manifest"
                    );
                    continue;
                }
                assert_eq!(
                    declared
                        .and_then(|d| d.get(feature.name()))
                        .and_then(serde_json::Value::as_bool),
                    Some(*stance),
                    "accepted `rootfs.{label}.features.{}` resolved a stance the entry did not \
                     declare as that boolean",
                    feature.name()
                );
            }
        }
    }

    if let Ok(entries) = fuzz_handler_registry(&doc) {
        let labels: Vec<String> = entries.iter().map(|e| e.label.clone()).collect();
        assert_roster(&doc, "handlers", &labels, &|l| {
            handler_filename(registry_label(l))
        });
        for entry in &entries {
            let spec = spec_of(&doc, "handlers", &entry.label);
            let label = &entry.label;
            let named = ["build", "digest", UNPINNED_PATH_KEY]
                .iter()
                .filter(|k| spec.get(*k).is_some())
                .count();
            assert_eq!(
                named, 1,
                "accepted `handlers.{label}` names {named} registration shape(s); an entry names \
                 EXACTLY one (§10.5, F7), or the shapes could disagree about which bytes the label \
                 means"
            );
            match &entry.source {
                HandlerSource::WorkspaceBuild { crate_name } => {
                    assert_eq!(
                        spec.get("build").and_then(serde_json::Value::as_str),
                        Some(format!("workspace:{crate_name}").as_str()),
                        "`handlers.{label}` resolved a crate that is not the registered \
                         `workspace:<crate>`"
                    );
                    assert!(
                        entry.applets.is_empty(),
                        "accepted `handlers.{label}` carries both a workspace `build` and an \
                         `applets` roster; a workspace handler's roster is the const its dispatch \
                         table is compile-time asserted against, so a second one could only \
                         disagree with it"
                    );
                }
                HandlerSource::Registered { digest, url } => {
                    assert!(
                        is_pinned_digest(digest),
                        "accepted `handlers.{label}.digest` is `{digest}`, not `sha256:<64 lowercase hex>`: \
                         registration is a digest (§10.5, F7)"
                    );
                    assert_eq!(
                        spec.get("digest").and_then(serde_json::Value::as_str),
                        Some(digest.as_str()),
                        "`handlers.{label}` resolved a digest that is not the registered one"
                    );
                    assert_eq!(
                        spec.get("source")
                            .and_then(|s| s.get("url"))
                            .and_then(serde_json::Value::as_str),
                        Some(url.as_str()),
                        "`handlers.{label}` resolved a fetch URL that is not the registered one"
                    );
                    assert!(
                        !url.is_empty(),
                        "accepted `handlers.{label}` pins a digest with an empty `source.url`; the \
                         digest is authoritative and the source is the instruction verified \
                         against it"
                    );
                }
                // The `--tools` per-run override is NOT a registration shape (§4.2, R7, v33 delta
                // 7): no accepted `handlers.<label>` document may resolve to it, whatever its
                // bytes. The unit gate states this for three hand-written shapes; this states it
                // for every document the corpus reaches.
                HandlerSource::Prebuilt { path } => {
                    panic!(
                        "accepted `handlers.{label}` resolved to the `--tools` per-run override \
                         ({path:?}); registration is a digest, an override is an argument (R7) — \
                         no pins key may produce this shape"
                    );
                }
                HandlerSource::UnpinnedPath { path } => {
                    assert_eq!(
                        spec.get(UNPINNED_PATH_KEY)
                            .and_then(serde_json::Value::as_str),
                        path.to_str(),
                        "`handlers.{label}` resolved an override path that is not the registered \
                         one"
                    );
                    assert!(
                        !path.as_os_str().is_empty(),
                        "accepted `handlers.{label}.{UNPINNED_PATH_KEY}` is empty"
                    );
                }
            }
            for applet in &entry.applets {
                assert!(
                    !applet.is_empty() && !applet.contains('/') && applet != "." && applet != "..",
                    "accepted `handlers.{label}.applets` holds {applet:?}, which is not a bare \
                     name; it would inject a symlink outside the tools dir"
                );
            }
            assert!(
                !entry.applet_roster().is_empty(),
                "accepted `handlers.{label}` resolves to an empty applet roster; an entry that \
                 declares none falls back to `GUEST_TOOLS_APPLETS`, so there is no handler with \
                 nothing to inject"
            );
        }
    }

    // Positive control, in the same body, so the target can never go quietly vacuous: the shapes a
    // real consumer writes still resolve, and an entry naming two shapes is still refused.
    let good = r#"{"rootfs":{"acme":{"unpinned_path":"/tmp/acme.erofs","features":{"xattr_preserved":true}}},
                   "handlers":{"acme":{"digest":"sha256:0000000000000000000000000000000000000000000000000000000000000000",
                                       "source":{"url":"https://example.invalid/h"},"applets":["acme-probe"]}}}"#;
    let doc = fuzz_merged_pins_document(good).expect("the consumer-shaped overlay must resolve");
    assert!(fuzz_rootfs_registry(&doc).is_ok());
    assert!(fuzz_handler_registry(&doc).is_ok());
    let both = r#"{"rootfs":{"acme":{"image":"docker.io/library/debian",
                                     "digest":"sha256:0000000000000000000000000000000000000000000000000000000000000000",
                                     "unpinned_path":"/tmp/acme.erofs"}}}"#;
    let doc = fuzz_merged_pins_document(both).expect("a two-shape entry parses as a document");
    assert!(
        fuzz_rootfs_registry(&doc).is_err(),
        "an entry naming both a digest and the `{UNPINNED_PATH_KEY}` override must be refused"
    );
});
