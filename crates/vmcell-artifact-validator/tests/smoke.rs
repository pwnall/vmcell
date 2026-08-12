//! End-to-end smoke tests for the validator. KVM-gated (`#[ignore]`): run on a KVM host with
//! built artifacts via `cargo test -p vmcell-artifact-validator --test smoke -- --ignored`.

use vmcell_artifact_validator::{ArtifactSet, CheckStatus, Level, ValidationOptions, validate};

/// Known-good artifacts must pass the full contract with no failures.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs KVM + built artifacts"]
async fn validate_known_good_full_is_ok() {
    let artifacts = ArtifactSet::new(
        vmcell::artifact::kernel_path(),
        vmcell::artifact::rootfs_path(),
    );
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
    let bogus = std::env::temp_dir().join("vmcell-validate-bogus-kernel");
    std::fs::write(&bogus, b"this is not a kernel").expect("write bogus kernel");
    let artifacts = ArtifactSet::new(bogus, vmcell::artifact::rootfs_path());
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
