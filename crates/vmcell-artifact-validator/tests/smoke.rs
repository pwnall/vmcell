//! End-to-end smoke tests for the validator: the only proof that the conformance battery can
//! actually FAIL on a real boot, and that it passes on the known-good pair.
//!
//! KVM-gated (`#[ignore]`), and **selected by `just test-validator`** — the recipe the CI
//! `test-integration` job runs after the artifacts are built and the runner blessed. Before that
//! recipe existed, both tests were compiled and skipped by every invocation in the tree (`m24`):
//! an `#[ignore]`d test that no `--run-ignored all` filter selects is a suite that cannot go red.
//!
//! One test here is **not** `#[ignore]`d, and it boots nothing: the fake-blind axis each live leg
//! claims is stated in that leg's own rustdoc, and prose is the one part of a live test that no host
//! ever executes. [`the_fake_blind_axis_claims_state_what_the_shipped_probe_answers`] scans those
//! claims, so this file cannot go on describing a probe the crate stopped shipping.

use vmcell_artifact_validator::harness::{get_rootfs, get_vmlinux};
use vmcell_artifact_validator::{ArtifactSet, CheckStatus, Level, ValidationOptions, validate};

/// Known-good artifacts must pass the full contract with no failures.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs KVM + built artifacts"]
async fn validate_known_good_full_is_ok() {
    // Through the §10.4 getters, not `artifact::{kernel_path,rootfs_path}` directly: they run the
    // at-most-once, hash-gated artifact build first, so an edit to the steward or the packer
    // is validated instead of silently re-validating a stale rootfs, and a missing kernel fails
    // loud with the one-command fix rather than as a boot timeout.
    let artifacts = ArtifactSet::new(get_vmlinux(), get_rootfs());
    let report = validate(&artifacts, &ValidationOptions::level(Level::Full))
        .await
        .expect("validation should run on a KVM host with artifacts");
    for o in &report.outcomes {
        println!("[{:?}] {} -> {:?}", o.level, o.id, o.status);
    }
    assert!(
        report.is_ok(),
        "known-good artifacts must pass; failures: {:?}",
        report.failures().collect::<Vec<_>>()
    );
}

/// A non-boot kernel paired with a good rootfs must yield a boot failure — proving the report
/// surfaces contract violations rather than swallowing them.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs KVM + built artifacts"]
async fn validate_broken_kernel_reports_failure() {
    // A private, per-run fixture that dies with the test, not a fixed name in shared `/tmp`
    // (`smoke-fixed-tmp-fixture`): the old file was never removed, so on a shared host another
    // user's leftover turns this leg red with EACCES instead of the contract failure it exists to
    // prove. The guard binding outlives the `validate` call below — the file must still be there
    // when the VM tries to boot it.
    let bogus = tempfile::NamedTempFile::new().expect("bogus kernel fixture");
    std::fs::write(bogus.path(), b"this is not a kernel").expect("write bogus kernel");
    let artifacts = ArtifactSet::new(bogus.path(), get_rootfs());
    let report = validate(&artifacts, &ValidationOptions::default())
        .await
        .expect("validation should run (the bogus kernel file exists)");
    assert!(!report.is_ok(), "a non-boot kernel must produce failures");
    assert!(
        report
            .failures()
            .any(|f| f.id == "boot.steward_ready" || f.id == "boot.kernel_banner"),
        "expected a boot failure; got {:?}",
        report.failures().collect::<Vec<_>>()
    );
    // The delta's deliverable is the *message*, not just the id: the live leg asserts the
    // classifier reached the report. Cloud Hypervisor rejects a garbage kernel file at `vm.boot`,
    // so `MicroVm::start` fails with no console at all — the no-evidence rendering, which still
    // names the §5.4 candidate causes.
    let msg = report
        .failures()
        .find_map(|f| match &f.status {
            CheckStatus::Fail(m) => Some(m.clone()),
            _ => None,
        })
        .expect("a failure carries a message");
    assert!(
        msg.contains("no serial evidence:") || msg.contains("contract violation:"),
        "a boot failure must name the §5.4 clause it proved, or say why it could not: {msg}"
    );
    assert!(
        msg.contains("CONFIG_PVH"),
        "a garbage kernel file must point at the direct-boot PVH contract: {msg}"
    );
}

/// The **live** half of the two-directional battery (design §10.6, §18 delta 3): the one leg that
/// exercises [`conformance::LiveProbe`] itself.
///
/// Everything else about the battery — the four-leg matrix, the control pairing, the warning
/// lifecycle, the budget — is unit-gated against a scripted probe, because the judgement is what
/// delta 3 specifies and it must run on every machine. What a scripted probe structurally cannot
/// see is the probe's own wiring: the snapshot probe needs a real guest to hand shake, so a
/// fake-driven run of it answers `NotRun` — it stops in one of its **setup** arms (the config, the
/// start, the handshake), in milliseconds, and reports nothing measured. Since docs/90's M8 split,
/// neither answer that *decides* the feature is reachable without a guest: not `Works`, and not the
/// measured `DoesNotWork` either, which is now produced only past `MicroVm::snapshot` — the first
/// call that actually exercises the feature. This leg is that evidence, and it is deliberately the
/// **under-claim** direction, because it is the one only a live run can produce: the canonical
/// artifacts genuinely snapshot, so an artifact record that declares `snapshot_restore = false` for
/// them is an under-claim by construction.
///
/// The known-good pair plays both roles — under two different labels, which is the point: the
/// battery refuses a control that IS the candidate, so the labels are what the pairing is keyed on
/// and this leg proves the paired probe really runs twice against a real backend.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs KVM + built artifacts"]
async fn conformance_live_underclaim_warns_with_its_positive_control() {
    use vmcell::feature::{Feature, FeatureDeclaration, Source};
    use vmcell_artifact_validator::conformance::{
        ArtifactId, ConformanceOptions, ConformanceSubject, LiveProbe, Substrate, run_battery,
    };
    use vmcell_artifact_validator::harness::ch_bin;

    let artifacts = ArtifactSet::new(get_vmlinux(), get_rootfs());
    let vmm = vmcell::vmm::cloud_hypervisor::CloudHypervisor::new(ch_bin());
    let substrate = Substrate::of(&vmm);

    let declaring = |label: &str, stance: bool| {
        let mut declaration = FeatureDeclaration::baseline(Source::Rootfs(label.to_string()));
        declaration.stances.insert(Feature::SnapshotRestore, stance);
        ConformanceSubject {
            id: ArtifactId::new(label),
            artifacts: artifacts.clone(),
            declaration,
        }
    };
    let candidate = declaring("under-test-declares-no-snapshot", false);
    let control = declaring("known-good-declares-snapshot", true);

    let opts = ConformanceOptions {
        // Dispositioned, so the run is green: the under-claim below is this test's fixture, not a
        // defect in the artifacts. The un-dispositioned direction (promotion to a failure) is
        // unit-gated — it needs no VM to be true.
        expected_warnings: [(
            Feature::SnapshotRestore,
            ArtifactId::new("under-test-declares-no-snapshot"),
        )]
        .into_iter()
        .collect(),
        ..ConformanceOptions::default()
    };

    let report = run_battery(
        &LiveProbe::new(&vmm),
        &substrate,
        &candidate,
        &control,
        &opts,
    )
    .await
    .expect("the battery must run on a KVM host with artifacts");
    for o in &report.outcomes {
        println!("[{:?}] {} -> {:?}", o.level, o.id, o.status);
    }

    let snapshot = report
        .outcomes
        .iter()
        .find(|o| o.id == "conformance.snapshot_restore")
        .expect("the paired snapshot check is in the roster");
    let CheckStatus::Warn(msg) = &snapshot.status else {
        panic!(
            "the canonical artifacts DO snapshot, so declaring it absent must warn (an \
             under-claim) — got {:?}. A Pass here would mean the absence probe answered \"absent\" \
             for an artifact that demonstrably snapshots, i.e. the probe is a constant.",
            snapshot.status
        );
    };
    assert!(
        msg.contains(Feature::SnapshotRestore.name()),
        "the warning names the feature through the vocabulary: {msg}"
    );
    assert!(
        msg.contains("known-good-declares-snapshot"),
        "the warning names the positive control that ran against the same live backend: {msg}"
    );
    assert!(
        report.is_ok(),
        "a dispositioned under-claim leaves the run green; failures: {:?}",
        report.failures().collect::<Vec<_>>()
    );
}

/// The **live** wiring of the second decidable plan (`ProbePlan::XattrReadback`, §4.7/§18 delta 7):
/// the probe boots the artifact, walks its rootfs through the in-guest `xattr` applet, and comes
/// back with a completed observation.
///
/// This is the fake-blind half of that probe. A scripted probe proves the judgement; nothing but a
/// real guest proves that `sh` is there, that `find` is there, that `xattr` resolves on the exec
/// PATH, and that the walk terminates inside its budget — and every one of those failing would
/// otherwise surface as a plausible-looking `Unverified` nobody reads twice.
///
/// **What it can and cannot show, stated rather than implied.** The artifacts this suite has on
/// hand are packed under `XattrPolicy::Strip` — that is what `rootfs.default` declares — so the
/// probe's honest answer here is "walked the image, found none". That drives the `DoesNotWork`
/// answer and the control pairing; it does **not** drive the `Works` answer, which needs a
/// `Preserve`-packed image and is proved by `crates/vmcell/tests/xattr_policy.rs` one crate over.
///
/// So the assertion is on the pairing's own honesty: the positive control declares the feature over
/// the same (stripping) artifact, cannot demonstrate it, and the battery therefore refuses to call
/// the candidate's absence *verified*. That verdict is `Unverified` naming the control — a Pass
/// here would mean the kit awarded a verified absence with no working control, which is the
/// constant-that-certifies-everything §10.6 exists to forbid.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs KVM + built artifacts"]
async fn conformance_live_xattr_probe_walks_the_image_and_refuses_an_uncontrolled_absence() {
    use vmcell::feature::{Feature, FeatureDeclaration, Source};
    use vmcell_artifact_validator::conformance::{
        ArtifactId, ConformanceOptions, ConformanceSubject, LiveProbe, Substrate, run_battery,
    };
    use vmcell_artifact_validator::harness::ch_bin;

    let artifacts = ArtifactSet::new(get_vmlinux(), get_rootfs());
    let vmm = vmcell::vmm::cloud_hypervisor::CloudHypervisor::new(ch_bin());
    let substrate = Substrate::of(&vmm);

    let declaring = |label: &str, stance: bool| {
        let mut declaration = FeatureDeclaration::baseline(Source::Rootfs(label.to_string()));
        declaration.stances.insert(Feature::XattrPreserved, stance);
        ConformanceSubject {
            id: ArtifactId::new(label),
            artifacts: artifacts.clone(),
            declaration,
        }
    };

    let report = run_battery(
        &LiveProbe::new(&vmm),
        &substrate,
        &declaring("under-test-declares-no-xattrs", false),
        &declaring("control-declares-xattrs", true),
        &ConformanceOptions::default(),
    )
    .await
    .expect("the battery must run on a KVM host with artifacts");
    for o in &report.outcomes {
        println!("[{:?}] {} -> {:?}", o.level, o.id, o.status);
    }

    let xattr = report
        .outcomes
        .iter()
        .find(|o| o.id == "conformance.xattr_preserved")
        .expect("the paired xattr check is in the roster");
    let CheckStatus::Unverified(msg) = &xattr.status else {
        panic!(
            "the canonical artifacts are packed `strip`, so the positive control cannot \
             demonstrate the feature and the candidate's absence is NOT verified — got {:?}. A \
             Pass here would be a verified absence awarded with no working control; a Skip would \
             mean the probe never ran at all.",
            xattr.status
        );
    };
    assert!(
        msg.contains("control-declares-xattrs"),
        "the verdict must name the control that failed to demonstrate it: {msg}"
    );
    // The evidence the PROBE produced, not the judgement's own wording: this substring exists only
    // if the in-guest walk really ran and really completed. If `sh`, `find` or the `xattr` applet
    // were missing, the probe would answer `NotRun` and this text would be the "did not complete"
    // one instead.
    assert!(
        msg.contains("walked") && msg.contains("paths"),
        "the verdict must carry the in-guest walk's own evidence — a scan that never ran reports \
         that it did not complete, and the two must not read alike: {msg}"
    );
    assert!(
        !msg.contains("no data-plane probe"),
        "the kit must not still be reporting `NO_PROBE_YET` for a feature it now probes: {msg}"
    );
}

/// The KVM-free gate on this file's own prose: a live leg's rustdoc says what a *fake-driven* run of
/// its probe answers, and that sentence is the one thing in a `#[ignore]`d test that never runs.
///
/// It went stale exactly once and predictably: docs/90's M8 split `snapshot_restore_roundtrip`'s
/// single `Err` into a setup stop (`NotRun` → `Unverified`) and an exercised one (`DoesNotWork`, the
/// measurement an absence can be verified against), and the doc here kept promising the blanket
/// `DoesNotWork` the probe had stopped producing — which is the *pass* an absence declaration used to
/// earn from an artifact that could not boot. A reader trusting it would take this leg to be
/// redundant with the unit tests.
///
/// It scans, rather than re-testing the behavior: the behavior is unit-gated in the crate itself
/// (`conformance`'s `the_live_probe_maps_an_undecidable_plan_and_a_setup_failure_to_notrun` and
/// `an_unbootable_candidate_is_unverified_never_a_verified_absence`), and a second copy of that leg
/// here would be a second copy of a law rather than a gate on the claim.
#[test]
fn the_fake_blind_axis_claims_state_what_the_shipped_probe_answers() {
    const SOURCE: &str = include_str!("smoke.rs");

    /// The rustdoc block immediately above `anchor`, with the `///` markers stripped and whitespace
    /// collapsed so a sentence split across lines still matches. Panics if the anchor is missing or
    /// carries no doc — an extraction that silently returned nothing would make the assertions
    /// vacuous.
    fn doc_block_before(source: &str, anchor: &str) -> String {
        let before = source
            .split_once(anchor)
            .unwrap_or_else(|| panic!("`{anchor}` must exist in this file"))
            .0;
        let mut doc: Vec<&str> = Vec::new();
        for line in before.lines().rev() {
            let trimmed = line.trim_start();
            if let Some(rest) = trimmed.strip_prefix("///") {
                doc.push(rest);
                continue;
            }
            // Attributes (`#[tokio::test]`, `#[ignore]`) and blank lines sit between the doc and its
            // item; anything else ends the block.
            if doc.is_empty() && (trimmed.is_empty() || trimmed.starts_with("#[")) {
                continue;
            }
            break;
        }
        assert!(!doc.is_empty(), "`{anchor}` must carry a rustdoc block");
        doc.reverse();
        doc.join(" ")
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    }

    let doc = doc_block_before(
        SOURCE,
        "async fn conformance_live_underclaim_warns_with_its_positive_control()",
    );
    // The claim is about what the probe ANSWERS, so that is the phrase under test — not the bare
    // variant names, which the corrected sentence legitimately mentions in order to rule them out.
    assert!(
        doc.contains("answers `NotRun`"),
        "the snapshot leg's fake-blind claim must state the answer the shipped probe gives a \
         fake-driven run — a setup stop, `NotRun` (M8):\n{doc}"
    );
    assert!(
        !doc.contains("answers `DoesNotWork`"),
        "M8 made the measured `DoesNotWork` reachable only past `MicroVm::snapshot`, so no \
         fake-driven run answers it; this doc still promises it:\n{doc}"
    );
    // Non-vacuity for the extraction: the block really is the one that documents the snapshot probe.
    assert!(
        doc.contains("snapshot"),
        "the extracted block is not the snapshot leg's doc — the anchor must have moved:\n{doc}"
    );

    // The sibling leg's own claim, checked for the mirror-image staleness: its evidence sentence
    // rests on `NotRun` being what a probe that could not run reports, which is the same M8 line.
    let xattr = doc_block_before(
        SOURCE,
        "async fn conformance_live_xattr_probe_walks_the_image_and_refuses_an_uncontrolled_absence()",
    );
    assert!(
        xattr.contains("Unverified") && xattr.contains("control"),
        "the xattr leg's claim must still be about the pairing's honesty:\n{xattr}"
    );
}
