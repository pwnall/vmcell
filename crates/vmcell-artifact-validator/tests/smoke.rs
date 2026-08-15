//! End-to-end smoke tests for the validator: the only proof that the conformance battery can
//! actually FAIL on a real boot, and that it passes on the known-good pair.
//!
//! KVM-gated (`#[ignore]`), and **selected by `just test-validator`** — the recipe the CI
//! `test-integration` job runs after the artifacts are built and the runner blessed. Before that
//! recipe existed, both tests were compiled and skipped by every invocation in the tree (`m24`):
//! an `#[ignore]`d test that no `--run-ignored all` filter selects is a suite that cannot go red.

use vmcell_artifact_validator::harness::{get_rootfs, get_vmlinux};
use vmcell_artifact_validator::{ArtifactSet, CheckStatus, Level, ValidationOptions, validate};

/// Known-good artifacts must pass the full contract with no failures.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs KVM + built artifacts"]
async fn validate_known_good_full_is_ok() {
    // Through the §10.4 getters, not `artifact::{kernel_path,rootfs_path}` directly: they run the
    // at-most-once, hash-gated artifact build first, so an edit to the guest agent or the packer
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
            .any(|f| f.id == "boot.agent_ready" || f.id == "boot.kernel_banner"),
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
