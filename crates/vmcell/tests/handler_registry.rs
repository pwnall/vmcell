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
//! KVM-free, network-free, toolchain-free.

use std::path::{Path, PathBuf};

use vmcell::artifact::handler::{
    HandlerSource, handler_artifact_key, handler_filename, handler_label_from_filename,
    handler_pin_key,
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
