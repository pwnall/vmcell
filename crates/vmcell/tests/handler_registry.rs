//! The `handlers` artifact registry (design §10.5; §18 delta 6), exercised from **outside** the
//! crate — the position a git-dep consumer registers their own in-guest helper from.
//!
//! §10.5 calls the handler "not an artifact at all" before v33: `GuestToolsStage` built from the
//! workspace unconditionally, in both halves, with no prebuilt escape hatch. A consumer who wanted
//! their own helper had to fork the pins file or push a binary per boot through `PutFile` — which
//! caps at `MAX_FRAME_BYTES` and cannot set an executable mode. What this battery covers is the
//! half with no other proof: that registration is a **digest** (F7), that the default entry means
//! exactly the pre-v33 workspace build, and that a consumer's roster is data rather than a const.
//!
//! KVM-free, network-free, toolchain-free. One leg — `a_registered_handler_is_baked_into_the_rootfs`
//! — additionally runs the real inject+pack tail (still no network: the pack is fed no base layers
//! and a static-musl steward stand-in), because "the registration reaches the IMAGE" is the half
//! parse tests structurally cannot see. Its live twin is `handler_cell.rs`.

use std::path::{Path, PathBuf};

use vmcell::artifact::handler::{
    HandlerSource, handler_artifact_key, handler_filename, handler_label_from_artifact_key,
    handler_label_from_filename, handler_pin_key,
};
use vmcell::artifact::registry::{DEFAULT_LABEL, UNPINNED_PATH_KEY};
use vmcell::artifact::{resolve_handler_labels, resolve_handler_registry, resolve_pins};
use vmcell::error::Error;

/// Writes an overlay document into `dir` and returns its path.
fn write_overlay(dir: &Path, body: &str) -> PathBuf {
    let path = dir.join("overlay.json");
    std::fs::write(&path, body).expect("write overlay");
    path
}

/// The rejection message for an overlay, or a panic naming what came back instead.
fn registry_err(overlay: &Path) -> String {
    match resolve_handler_registry(Some(overlay)) {
        Err(Error::Artifact(m)) => m,
        other => panic!("expected an Artifact rejection, got {other:?}"),
    }
}

/// A syntactically valid registered entry body.
fn registered(digest_byte: char) -> String {
    format!(
        r#"{{ "digest": "sha256:{}", "source": {{ "url": "https://example.invalid/h" }} }}"#,
        std::iter::repeat_n(digest_byte, 64).collect::<String>()
    )
}

// §10.5's "the `default` entry names today's workspace build — behavior byte-identical, now stated
// in data instead of hardcoded". The committed baseline must SAY what vmcell has always DONE, or
// the registry is a second source of truth beside the code it replaced.
#[test]
fn the_committed_default_names_the_workspace_build() {
    let registry = resolve_handler_registry(None).expect("the baseline registry resolves");
    let default = registry
        .iter()
        .find(|e| e.label == DEFAULT_LABEL)
        .expect("the committed baseline must register a `default` handler");
    assert_eq!(
        default.source,
        HandlerSource::WorkspaceBuild {
            crate_name: "vmcell-guest-tools".to_string()
        },
        "the default handler is the workspace helper, stated in data"
    );

    // Its roster is the SHARED CONST, not a copy in the pins file: the guest binary's dispatch
    // table is compile-time asserted against that const, and a second roster here could only
    // disagree with it.
    assert!(
        default.applets.is_empty(),
        "the default entry carries no `applets` — its roster is GUEST_TOOLS_APPLETS"
    );
    assert_eq!(
        default.applet_roster(),
        vmcell_protocol::GUEST_TOOLS_APPLETS
            .iter()
            .map(|a| (*a).to_string())
            .collect::<Vec<_>>()
    );

    // And it flattens to the un-suffixed pin key, the same default-label law the rootfs kind uses.
    let pins = resolve_pins(None).expect("baseline pins");
    assert_eq!(
        pins.get(&handler_pin_key(None, "build"))
            .map(String::as_str),
        Some("workspace:vmcell-guest-tools")
    );
    assert!(!pins.contains_key("handler_default_build"));
}

// F7, in one test: THREE registration shapes exist, exhaustively, and an entry names EXACTLY ONE.
// Two-shapes and no-shape are both refused because either would leave the label meaning something
// other than one identified blob, with vmcell picking the winner silently.
//
// RED on the inverse, three ways: (a) drop `reject_multiple_registration_shapes` and the
// two-shape legs resolve to whichever arm the parser reaches first; (b) drop `unpinned_path` from
// the accepted-key set and the override leg fails as an unknown key; (c) resolve `unpinned_path`
// through a second local parse instead of `unpinned_path_registration` and the empty-string leg
// resolves to an entry pointing at "".
#[test]
fn an_entry_names_exactly_one_registration_shape() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let digest = format!("sha256:{}", "a".repeat(64));
    // Every unordered PAIR of the three shapes, each refused naming BOTH of the shapes it named —
    // a message naming only one of them would leave the operator guessing which registration was
    // ignored. Written as a table rather than as one `build` + `digest` case so a fourth shape
    // landing without its exclusivity entry cannot pass by being untested.
    for (body, shapes) in [
        (
            format!(r#"{{ "build": "workspace:x", "digest": "{digest}" }}"#),
            ["build", "digest"],
        ),
        (
            format!(r#"{{ "digest": "{digest}", "{UNPINNED_PATH_KEY}": "/tmp/h" }}"#),
            ["digest", UNPINNED_PATH_KEY],
        ),
        (
            format!(r#"{{ "build": "workspace:x", "{UNPINNED_PATH_KEY}": "/tmp/h" }}"#),
            ["build", UNPINNED_PATH_KEY],
        ),
    ] {
        let overlay = write_overlay(
            tmp.path(),
            &format!(r#"{{ "handlers": {{ "acme": {body} }} }}"#),
        );
        let msg = registry_err(&overlay);
        for shape in shapes {
            assert!(
                msg.contains(shape),
                "an entry naming two shapes must be refused naming `{shape}`: {msg}"
            );
        }
    }

    let neither = write_overlay(
        tmp.path(),
        r#"{ "handlers": { "acme": { "applets": ["p"] } } }"#,
    );
    let msg = registry_err(&neither);
    assert!(
        msg.contains("none of") && msg.contains("digest"),
        "an entry naming no shape must be refused naming the digest route: {msg}"
    );

    // A BARE `path` is still not a registration shape — it is an unknown key, refused naming it.
    // R7's whole point survives the override landing: an override is a deliberate act under ONE
    // explicitly named key that carries consequences (the content-hashed identity, the resolution
    // warning, the `bundle` refusal), not any key that happens to hold a path.
    let path_shaped = write_overlay(
        tmp.path(),
        r#"{ "handlers": { "acme": { "path": "/tmp/my-handler" } } }"#,
    );
    assert!(
        registry_err(&path_shaped).contains("path"),
        "a path-shaped registration must be refused naming the key"
    );

    // …and the override's own value is strict: an empty path is not "unset", it is a registration
    // that resolves to nothing.
    let empty = write_overlay(
        tmp.path(),
        &format!(r#"{{ "handlers": {{ "acme": {{ "{UNPINNED_PATH_KEY}": "" }} }} }}"#),
    );
    assert!(
        registry_err(&empty).contains(UNPINNED_PATH_KEY),
        "an empty override path must be refused naming the key"
    );

    // Positive control 1: the digest shape resolves.
    let good = write_overlay(
        tmp.path(),
        &format!(r#"{{ "handlers": {{ "acme": {} }} }}"#, registered('b')),
    );
    let registry = resolve_handler_registry(Some(&good)).expect("a digest registration resolves");
    let acme = registry
        .iter()
        .find(|e| e.label == "acme")
        .expect("the acme entry");
    assert!(matches!(&acme.source, HandlerSource::Registered { .. }));

    // Positive control 2: the THIRD shape resolves — a path under the one named override key,
    // carrying its own applet roster exactly as a registered handler does (it is a consumer's own
    // binary either way, so `GUEST_TOOLS_APPLETS` cannot speak for it).
    let unpinned = write_overlay(
        tmp.path(),
        &format!(
            r#"{{ "handlers": {{ "acme": {{ "{UNPINNED_PATH_KEY}": "/tmp/my-handler",
                 "applets": ["acme-probe"] }} }} }}"#
        ),
    );
    let registry = resolve_handler_registry(Some(&unpinned)).expect("the dev override resolves");
    let acme = registry
        .iter()
        .find(|e| e.label == "acme")
        .expect("the acme entry");
    assert_eq!(
        acme.source,
        HandlerSource::UnpinnedPath {
            path: PathBuf::from("/tmp/my-handler")
        }
    );
    assert_eq!(acme.applet_roster(), vec!["acme-probe".to_string()]);

    // And it reaches the FLAT pins — which is what carries it into `resolved_pins.json`'s
    // flattening, where `bundle`'s refusal reads it. RED on a flattener arm that drops the key:
    // the entry would resolve, build, and bundle without a word.
    let pins = resolve_pins(Some(&unpinned)).expect("the overlay resolves");
    assert_eq!(
        pins.get(&handler_pin_key(Some("acme"), UNPINNED_PATH_KEY))
            .map(String::as_str),
        Some("/tmp/my-handler"),
        "an unpinned handler registration must reach the flat pins"
    );
}

// A digest that is not `sha256:<64 lowercase hex>` is refused — the `oci2-erofs` rule adopted as
// the registry's, so a label can never resolve to a mutable reference.
//
// The UPPERCASE leg is the v33 delta 6c tightening (fuzz finding F-2). Both digest checks used to
// accept `sha256:ABCD…`, while `sha256_hex` emits lowercase and `verify_handler_digest` /
// `cached_blob_matches` compare case-SENSITIVELY: an uppercase registration parsed clean and could
// then never verify, so the operator met a "digest mismatch" naming two digests that look identical
// until you notice the case — after the fetch. An accepted input that cannot be honored is what
// AGENTS.md's fail-loud rule forbids.
//
// The last leg is the one-law binding: `handlers` and `rootfs` refuse through the SAME predicate
// (`registry::reject_unpinned_digest`), so the two sentences differ only by the namespace. Before
// 6c they were two functions with two messages — F7 IS this rule, which makes a second copy of it
// the delta's own law drifting.
//
// RED on the inverse: drop the lowercase clause from the shared predicate (the uppercase legs pass
// the value through and both `expect_err`s fail); give either kind its own copy again (the parity
// leg fails, printing both sentences).
#[test]
fn a_registration_must_pin_a_sha256_digest() {
    let tmp = tempfile::tempdir().expect("tempdir");
    for bad in ["latest", "sha256:short", "sha1:aaaa"] {
        let overlay = write_overlay(
            tmp.path(),
            &format!(
                r#"{{ "handlers": {{ "acme": {{ "digest": "{bad}",
                     "source": {{ "url": "https://example.invalid/h" }} }} }} }}"#
            ),
        );
        assert!(
            registry_err(&overlay).contains("acme"),
            "the rejection must name the label"
        );
    }

    // Uppercase hex: well formed in every other respect, and refused NAMING the case plus the
    // exact string to paste — an operator told only "must be sha256:<64 hex>" would read their own
    // 64 hex digits back and conclude vmcell is broken.
    let upper = write_overlay(
        tmp.path(),
        &format!(
            r#"{{ "handlers": {{ "acme": {{ "digest": "sha256:{}",
                 "source": {{ "url": "https://example.invalid/h" }} }} }} }}"#,
            "AB".repeat(32)
        ),
    );
    let msg = registry_err(&upper);
    for named in [
        "lowercase",
        "UPPERCASE",
        &format!("sha256:{}", "ab".repeat(32)),
    ] {
        assert!(
            msg.contains(named),
            "the uppercase refusal must name {named}: {msg}"
        );
    }
    // Positive control for that leg: the same digest lowercased resolves, so the rejection is about
    // the case and not about that value.
    let lower = write_overlay(
        tmp.path(),
        &format!(
            r#"{{ "handlers": {{ "acme": {{ "digest": "sha256:{}",
                 "source": {{ "url": "https://example.invalid/h" }} }} }} }}"#,
            "ab".repeat(32)
        ),
    );
    assert!(
        resolve_handler_registry(Some(&lower))
            .expect("the lowercased digest must resolve")
            .iter()
            .any(|e| e.label == "acme"),
        "the lowercase form the refusal recommends must actually be accepted"
    );

    // ONE predicate, two kinds: the same malformed value refused by `rootfs` yields the same
    // sentence with the namespace swapped. A kind that re-grows its own copy fails here.
    let rootfs_upper = write_overlay(
        tmp.path(),
        &format!(
            r#"{{ "rootfs": {{ "acme": {{ "image": "i", "digest": "sha256:{}" }} }} }}"#,
            "AB".repeat(32)
        ),
    );
    let rootfs_msg = match vmcell::artifact::resolve_rootfs_registry(Some(&rootfs_upper)) {
        Err(Error::Artifact(m)) => m,
        other => panic!("the rootfs kind must refuse the same value, got {other:?}"),
    };
    assert_eq!(
        msg,
        rootfs_msg.replacen("`rootfs.", "`handlers.", 1),
        "both kinds must refuse a malformed digest through the ONE shared predicate — the two \
         wordings drifted the whole time they were two functions"
    );

    // A digest with no `source.url` is refused too: the digest is authoritative and the source is
    // the instruction verified against it, so one without the other cannot be acted on.
    let no_source = write_overlay(
        tmp.path(),
        &format!(
            r#"{{ "handlers": {{ "acme": {{ "digest": "sha256:{}" }} }} }}"#,
            "c".repeat(64)
        ),
    );
    assert!(registry_err(&no_source).contains("source.url"));
}

// A consumer handler's applet roster is DATA, strict-parsed — because the const-assert that keeps
// the default handler honest binds the default handler only. A name that is not a bare file name
// would inject a symlink outside the tools dir.
#[test]
fn a_registered_handlers_applet_roster_is_strict_parsed() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let good = write_overlay(
        tmp.path(),
        &format!(
            r#"{{ "handlers": {{ "acme": {{ "digest": "sha256:{}",
                 "source": {{ "url": "https://example.invalid/h" }},
                 "applets": ["acme-probe", "acme-load"] }} }} }}"#,
            "d".repeat(64)
        ),
    );
    let registry = resolve_handler_registry(Some(&good)).expect("resolves");
    let acme = registry.iter().find(|e| e.label == "acme").expect("acme");
    assert_eq!(acme.applets, vec!["acme-probe", "acme-load"]);
    assert_eq!(
        acme.applet_roster(),
        acme.applets,
        "a registered handler's roster is its own, not the default's"
    );

    for bad in [
        r#"["ok", "../escape"]"#,
        r#"["sub/dir"]"#,
        r#"[""]"#,
        r#""notanarray""#,
    ] {
        let overlay = write_overlay(
            tmp.path(),
            &format!(
                r#"{{ "handlers": {{ "acme": {{ "digest": "sha256:{}",
                     "source": {{ "url": "u" }}, "applets": {bad} }} }} }}"#,
                "e".repeat(64)
            ),
        );
        assert!(
            registry_err(&overlay).contains("applets"),
            "{bad} must be refused naming the key"
        );
    }

    // A WORKSPACE handler may not carry a roster: its roster is the const its dispatch table is
    // compile-time asserted against, so a second one here could only disagree.
    let ws_with_roster = write_overlay(
        tmp.path(),
        r#"{ "handlers": { "acme": { "build": "workspace:x", "applets": ["p"] } } }"#,
    );
    let msg = registry_err(&ws_with_roster);
    assert!(
        msg.contains("GUEST_TOOLS_APPLETS"),
        "the refusal must name the const that already owns a workspace handler's roster: {msg}"
    );
}

// The `build` shape must name a workspace member through the one spelling; anything else is refused
// rather than guessed at.
#[test]
fn the_workspace_build_shape_is_strict() {
    let tmp = tempfile::tempdir().expect("tempdir");
    for bad in ["vmcell-guest-tools", "workspace:", "path:/x", ""] {
        let overlay = write_overlay(
            tmp.path(),
            &format!(r#"{{ "handlers": {{ "acme": {{ "build": "{bad}" }} }} }}"#),
        );
        assert!(
            registry_err(&overlay).contains("acme"),
            "`build: {bad:?}` must be refused naming the label"
        );
    }
}

// The filename law and its inverse are pinned together, and the artifact key keeps the pre-v33
// spelling for the default — the rootfs kind's byte-identity argument, one kind over. The pack tail
// reads `inputs.artifacts["guest_tools"]`, so renaming the default key would be a break with no
// benefit.
#[test]
fn the_filename_and_artifact_key_laws_round_trip() {
    assert_eq!(handler_artifact_key(None), "guest_tools");
    assert_eq!(handler_artifact_key(Some("acme")), "guest_tools-acme");
    // The artifact key's own inverse, which the pack tail reads to see whether the pipeline
    // published a handler it was not told to bake. It round-trips over the KEY form, dots and all
    // (`guest_tools-12.4`) — where `handler_label_from_filename` must answer `None`, because the
    // FILENAME law sanitizes `.`→`-` and so a dotted remainder there can only be a sidecar. That
    // divergence is the whole reason the two inverses are two functions.
    for label in [None, Some("acme"), Some("12.4")] {
        assert_eq!(
            handler_label_from_artifact_key(&handler_artifact_key(label)),
            label,
            "the artifact-key law must round-trip through its own inverse for {label:?}"
        );
    }
    assert_eq!(handler_label_from_artifact_key("guest_tools-"), None);
    assert_eq!(handler_label_from_artifact_key("rootfs-acme"), None);
    assert_eq!(handler_label_from_filename("guest_tools-12.4"), None);
    assert_eq!(handler_filename(None), "guest_tools");
    assert_eq!(handler_filename(Some("12.4")), "guest_tools-12-4");
    assert_eq!(handler_label_from_filename("guest_tools"), None);
    assert_eq!(
        handler_label_from_filename("guest_tools-acme"),
        Some("acme")
    );
    assert_eq!(
        handler_label_from_filename("guest_tools-acme.cache_key"),
        None
    );
    assert_eq!(handler_label_from_filename("vmlinux-acme"), None);

    for entry in resolve_handler_registry(None).expect("baseline registry") {
        let label = (entry.label != DEFAULT_LABEL).then_some(entry.label.as_str());
        let filename = handler_filename(label);
        assert_eq!(
            handler_label_from_filename(&filename),
            label.map(|l| l.replace('.', "-")).as_deref()
        );
    }
}

// A downstream-added handler is additive and sorted, with the baseline's default kept — the shared
// registry core's order law, reached through the third kind.
#[test]
fn overlay_handlers_are_additive_and_sorted() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let overlay = write_overlay(
        tmp.path(),
        &format!(
            r#"{{ "handlers": {{ "zz": {}, "aa": {} }} }}"#,
            registered('f'),
            registered('9')
        ),
    );
    assert_eq!(
        resolve_handler_labels(Some(&overlay)).expect("resolves"),
        vec![
            "aa".to_string(),
            DEFAULT_LABEL.to_string(),
            "zz".to_string()
        ]
    );
}

// R7's line, drawn where v33 delta 7 puts it: `HandlerSource::Prebuilt` is the `oci2-erofs
// --tools` per-run OVERRIDE, and no registry entry may ever resolve to it. A registration is a
// durable claim that outlives the session that made it; an override is one operator's per-run act.
// The two are already distinguished by their cache-key laws (`--tools` folds content only,
// `unpinned_path` folds the path as well), so a registry shape that leaked into the override
// variant would silently change the identity of every artifact built from it.
//
// RED on the inverse two ways: (a) point the `unpinned_path` arm of `handler_registry_entry` at
// `HandlerSource::Prebuilt` — the first loop reddens naming the shape; (b) add `"prebuilt"` (or
// `"tools"`) to the entry's accepted-key set — the second loop reddens because the key stops being
// refused.
#[test]
fn no_registry_shape_resolves_to_the_per_run_override() {
    let tmp = tempfile::tempdir().expect("tempdir");
    // Every registration shape §10.5 allows, resolved and inspected. The positive control is the
    // same loop: each shape DOES resolve, so "never `Prebuilt`" is a statement about which variant
    // came back, not about a parse that failed.
    for (shape, body) in [
        (
            "build",
            r#"{ "build": "workspace:vmcell-guest-tools" }"#.to_string(),
        ),
        ("digest", registered('a')),
        (
            UNPINNED_PATH_KEY,
            format!(r#"{{ "{UNPINNED_PATH_KEY}": "/tmp/my-handler" }}"#),
        ),
    ] {
        // A distinct directory per shape: `write_overlay` reuses one filename, and a shared one
        // would make every leg after the first assert against the previous leg's document.
        let dir = tmp.path().join(shape);
        std::fs::create_dir_all(&dir).expect("mkdir");
        let overlay = write_overlay(&dir, &format!(r#"{{ "handlers": {{ "acme": {body} }} }}"#));
        let registry = resolve_handler_registry(Some(&overlay))
            .unwrap_or_else(|e| panic!("the `{shape}` shape must resolve: {e}"));
        let acme = registry
            .iter()
            .find(|e| e.label == "acme")
            .unwrap_or_else(|| panic!("the `{shape}` entry"));
        assert!(
            !matches!(acme.source, HandlerSource::Prebuilt { .. }),
            "the `{shape}` registration must not resolve to the `--tools` per-run override \
             (R7: a registration is a digest, an override is an argument), got {:?}",
            acme.source
        );
    }
    // …and the override has no pins spelling at all: the two names it might plausibly claim are
    // refused as unknown keys, naming them.
    for key in ["prebuilt", "tools"] {
        let dir = tmp.path().join(format!("key-{key}"));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let overlay = write_overlay(
            &dir,
            &format!(r#"{{ "handlers": {{ "acme": {{ "{key}": "/tmp/my-handler" }} }} }}"#),
        );
        let msg = registry_err(&overlay);
        assert!(
            msg.contains(key),
            "an override spelled as a registry key must be refused NAMING it, got: {msg}"
        );
    }
}

/// Closes the shared proxy CA's publish window before a pack, from the consumer position.
///
/// The pack tail materializes `<artifacts-dir>/ca.pem` through `CaManager::new()`, which publishes
/// the (cert, key) pair as TWO renames; a process that looks between them gets the deliberate
/// `partial CA in …` refusal. nextest gives every test its own process, so on a cold artifacts dir
/// several of them can race. One successful call closes the window for the rest of this process.
/// The in-crate twin of this loop (`rootfs::stabilize_ca`) guards the same window for the unit
/// tests; it is `#[cfg(test)]`, which does not reach an integration binary.
#[cfg(all(feature = "pipeline", feature = "am-fs-erofs", feature = "proxy"))]
fn stabilize_ca() {
    let mut last = String::new();
    for _ in 0..50 {
        match vmcell::proxy::tls::CaManager::new() {
            Ok(_) => return,
            Err(e) => {
                last = e.to_string();
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
        }
    }
    panic!("the shared proxy CA never materialized; last error: {last}");
}

/// Without the `proxy` feature the tail bakes no CA, so there is nothing to stabilize.
#[cfg(all(feature = "pipeline", feature = "am-fs-erofs", not(feature = "proxy")))]
fn stabilize_ca() {}

// §10.5 / §18 delta 6b's end-to-end claim, from the position a consumer registers a handler from: a
// REGISTERED handler's binary is what the rootfs bakes, with the applet symlinks that make it
// reachable. Delta 6b's own notes deferred this to delta 9, and delta 9 shipped without it — which
// is how `--handler-label <any>` came to build a rootfs carrying no guest tools and no applet
// symlinks at all, and report success.
//
// The whole chain runs: overlay → `resolve_handler_registry` → `GuestToolsStage::labelled` (which
// publishes under `guest_tools-<label>`) → the artifact map → the one inject+pack tail. Nothing is
// stubbed between them, because every link but the last was already green while the image shipped
// empty.
//
// Three claims:
//   1. the REGISTERED binary's bytes are in the image (asserted on content, not on "the pack
//      succeeded", which the defect also did);
//   2. every `GUEST_TOOLS_APPLETS` name is in the image — a handler that declares no roster gets
//      vmcell's own, and `mini-init` being one of them is why a dropped roster is a guest kernel
//      panic rather than a missing test helper;
//   3. the mirror image: the SAME artifact map packed *without* declaring the label is REFUSED,
//      naming the handler the pipeline published. That is the state the defect packed silently, and
//      it is also the shape a mis-wired downstream pipeline (or the mmdebstrap source, whose stage
//      takes no handler label) produces.
//
// RED on the inverse (read `inputs.artifacts["guest_tools"]` at the tail again): claim 1 fails — the
// image carries neither the handler nor a symlink — and claim 3's refusal never happens.
#[cfg(all(feature = "pipeline", feature = "am-fs-erofs"))]
#[tokio::test]
async fn a_registered_handler_is_baked_into_the_rootfs() {
    use vmcell::artifact::guest_tools::GuestToolsStage;
    use vmcell::artifact::rootfs::{PackOptions, pack_rootfs_with_injection};
    use vmcell::artifact::{Stage, StageInputs};

    stabilize_ca();
    let tmp = tempfile::tempdir().expect("tempdir");
    // The consumer's own helper binary. Its bytes are the assertion: nothing else in the image can
    // contain them.
    const HANDLER_BYTES: &[u8] = b"#!/bin/sh\n# the acme handler, delta 6b\n";
    let handler_src = tmp.path().join("acme-handler");
    std::fs::write(&handler_src, HANDLER_BYTES).expect("write the consumer's handler");

    // Registered through the F7 dev override, which is the one registration shape that needs no
    // network: a digest entry would have to be fetched, and this leg is about what happens AFTER the
    // handler is published, which is identical for all three shapes.
    let overlay = write_overlay(
        tmp.path(),
        &format!(
            r#"{{ "handlers": {{ "acme": {{ "{UNPINNED_PATH_KEY}": "{}" }} }} }}"#,
            handler_src.display()
        ),
    );
    let entry = resolve_handler_registry(Some(&overlay))
        .expect("the overlay resolves")
        .into_iter()
        .find(|e| e.label == "acme")
        .expect("the acme entry");

    // The real stage, publishing under its own one key law.
    let stage = GuestToolsStage::labelled(Some("acme"), Some(entry.source.clone()));
    let published = stage.out_path(tmp.path());
    let outputs = stage
        .run(&StageInputs::default(), &published)
        .await
        .expect("the handler stage must publish the registered binary");
    let handler_key = handler_artifact_key(Some("acme"));
    assert_eq!(
        outputs.artifacts.get(&handler_key).map(PathBuf::as_path),
        Some(published.as_path()),
        "the stage must register the labelled handler under `{handler_key}`: {outputs:?}"
    );

    let musl = tmp.path().join("steward-musl");
    std::fs::write(&musl, b"#!static-steward").expect("write the steward stand-in");
    let mut inputs = StageInputs::default();
    inputs.artifacts.extend(outputs.artifacts.clone());

    let pack = async |handler_label: Option<&str>, name: &str| {
        let out = tmp.path().join(name);
        pack_rootfs_with_injection(
            vec![],
            &inputs,
            &out,
            &PackOptions::new()
                .with_steward_musl(Some(musl.clone()))
                .with_applets(entry.applet_roster())
                .with_handler_label(handler_label),
        )
        .await
        .map(|_| std::fs::read(&out).expect("read the packed image"))
    };
    let occurrences = |image: &[u8], needle: &[u8]| -> usize {
        image.windows(needle.len()).filter(|w| *w == needle).count()
    };

    // 1 + 2.
    let image = pack(Some("acme"), "rootfs-acme.erofs")
        .await
        .expect("the pack must succeed");
    assert_eq!(
        occurrences(&image, HANDLER_BYTES),
        1,
        "the REGISTERED handler's bytes must be baked into the rootfs — the whole point of \
         registering one"
    );
    assert!(
        !vmcell_protocol::GUEST_TOOLS_APPLETS.is_empty(),
        "an empty roster would make the loop below vacuous"
    );
    for applet in vmcell_protocol::GUEST_TOOLS_APPLETS {
        assert!(
            occurrences(&image, applet.as_bytes()) >= 1,
            "the image must carry a `/vmcell-tools/{applet}` entry: a handler that declares no \
             roster gets vmcell's own (`GUEST_TOOLS_APPLETS`), and `mini-init` is an `init=` target"
        );
    }

    // 3. The mirror image: the same map, the label undeclared, refused naming what WAS published.
    let err = pack(None, "rootfs-undeclared.erofs")
        .await
        .expect_err("a pipeline that published only a labelled handler must not pack silently");
    let msg = err.to_string();
    // The orphaned LABEL (what an operator types as `--handler-label`) and the key this pack went
    // looking for instead — the two facts that turn "no applets in the image" into an action.
    for named in ["acme", &handler_artifact_key(None)] {
        assert!(
            msg.contains(named),
            "the refusal must name {named} so the operator can see which handler was orphaned: \
             {msg}"
        );
    }
}
