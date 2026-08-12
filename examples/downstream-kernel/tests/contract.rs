//! The KVM-free half of the downstream-contract gate (design v30 §10.4).
//!
//! Everything here runs from the consumer position with no VM, no privileges and no network: the
//! overlay resolution (delta 1), the sidecar naming rule and parser (deltas 3 + 4), and this
//! example's own survival predicates — each with the inverse that must redden it.
//!
//! The two env-driven legs (`VMCELL_*` override set present / absent) are deliberately **not**
//! here: `ensure_test_artifacts` memoizes per process, so they need separate processes and live in
//! `ci-check.sh` instead.

use downstream_kernel::{
    FRAGMENT_NAME, KERNEL_LABEL, REQUIRED_SYMBOLS, fragment_survived, guest_config_round_trips,
    overlay_path, registry_entry,
};
use vmcell_artifact_validator::kconfig::KconfigValues;

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

    // …and the fragment NAME resolves to fragment TEXT, under the flattened pin key the toolkit
    // documents (`kernel_fragments_<NAME>`). A label that resolved without its fragment text would
    // build an unmodified kernel and report success.
    let pins = vmcell::artifact::resolve_pins(Some(&overlay_path()))
        .expect("the overlay must resolve into the flat pin map");
    let text = pins
        .get(&format!("kernel_fragments_{FRAGMENT_NAME}"))
        .expect("the overlay's fragment must reach the flat pin map");
    for symbol in REQUIRED_SYMBOLS {
        assert!(
            text.contains(&format!("{symbol}=y")),
            "the fragment text must request {symbol}=y, got {text:?}"
        );
    }
    // The label's own source pins come from the overlay too (a labelled build with no source URL
    // would fail deep inside the producer instead of here).
    assert!(
        pins.contains_key(&format!("kernel_{KERNEL_LABEL}_source_url")),
        "the overlay's kernels entry must contribute its source URL"
    );
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
    // The other half of §18 delta 5's deliberate-red: with the sidecar dropped, the assertion must
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
