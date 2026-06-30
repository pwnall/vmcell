use assert_cmd::prelude::*;
use std::process::Command;

mod common;

// TESTS-FEATURES-2. The full benchmark needs KVM and is too slow for CI, so the CH path used
// to assert nothing (commented-out p50 check) — pure theater. Instead, drive bench-vm down a
// deterministic, KVM-independent DRY path: point it at an empty artifacts dir so no VM can be
// started (missing kernel/rootfs, and no KVM needed). The harness must degrade gracefully to
// the "No successful runs" report while still exiting 0. This runs in the default suite (no
// `#[ignore]`) and goes red if the dry path panics, exits non-zero, or stops reporting.
#[cfg(feature = "cloud-hypervisor")]
#[test]
fn test_benchmark_ch_dry() {
    let empty = tempfile::tempdir().unwrap();
    let mut cmd = Command::cargo_bin("bench-vm").unwrap();
    cmd.env("IMP_ARTIFACTS_DIR", empty.path())
        .arg("--backend")
        .arg("cloud-hypervisor")
        .arg("--iterations")
        .arg("1")
        .arg("--warmup")
        .arg("0");
    cmd.assert()
        .success()
        .stdout(predicates::str::contains("No successful runs"));
}

// TESTS-FEATURES-2 (Part C-e): serialization comes from the nextest `serial-host`
// group (which already covers `binary(benchmark)`), not an ad-hoc
// `#[serial_test::serial]` attribute.
#[cfg(feature = "firecracker")]
#[test]
#[ignore = "needs KVM"]
fn test_benchmark_fc() {
    let mut cmd = Command::cargo_bin("bench-vm").unwrap();
    cmd.arg("--backend")
        .arg("firecracker")
        .arg("--iterations")
        .arg("1")
        .arg("--warmup")
        .arg("0");
    cmd.assert()
        .success()
        .stdout(predicates::str::contains("p50="));
}

#[cfg(feature = "qemu")]
#[test]
#[ignore = "needs KVM"]
fn test_benchmark_qemu() {
    let mut cmd = Command::cargo_bin("bench-vm").unwrap();
    cmd.arg("--backend")
        .arg("qemu")
        .arg("--iterations")
        .arg("1")
        .arg("--warmup")
        .arg("0");
    cmd.assert()
        .success()
        .stdout(predicates::str::contains("p50="));
}
