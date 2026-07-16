use assert_cmd::prelude::*;
use std::process::Command;

mod common;

// TESTS-FEATURES-2. The full benchmark needs KVM and is too slow for CI, so the CH path used
// to assert nothing (commented-out p50 check) — pure theater. Instead, drive bench-vm down a
// deterministic, KVM-independent DRY path: point it at an empty artifacts dir so no VM can be
// started (missing kernel/rootfs, and no KVM needed). The harness must degrade *gracefully*:
// print the "No successful runs" report with a clear "missing artifacts" cause, and — per
// M-BIN-1 — exit NON-ZERO so a perf baseline / CI can't silently green-pass an empty result
// (zero post-warmup samples). Runs in the default suite (no `#[ignore]`); goes red if the dry
// path panics, stops reporting, or regresses to exiting 0 on a total failure.
#[cfg(feature = "cloud-hypervisor")]
#[test]
fn test_benchmark_ch_dry() {
    let empty = tempfile::tempdir().unwrap();
    let mut cmd = Command::cargo_bin("bench-vm").unwrap();
    cmd.env("VMCELL_ARTIFACTS_DIR", empty.path())
        .arg("--backend")
        .arg("cloud-hypervisor")
        .arg("--iterations")
        .arg("1")
        .arg("--warmup")
        .arg("0");
    cmd.assert()
        .failure()
        .stdout(predicates::str::contains("No successful runs"))
        .stderr(predicates::str::contains("missing artifacts"));
}

// TESTS-FEATURES-2 (Part C-e): serialization comes from the nextest `serial-host`
// group (which already covers `binary(benchmark)`), not an ad-hoc
// `#[serial_test::serial]` attribute.
#[cfg(feature = "firecracker")]
#[test]
#[ignore = "needs KVM"]
fn test_benchmark_fc() {
    // `bench-vm` resolves the default artifacts itself (this test shells out), so it does not go
    // through the harness auto-build. Touch the getters first so the rootfs is built at most once
    // per session (and the kernel's fail-loud fires) before bench-vm reads them.
    let _kernel = common::get_vmlinux();
    let _rootfs = common::get_rootfs();
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
    // See `test_benchmark_fc`: shells out to bench-vm, so trigger the harness auto-build first.
    let _kernel = common::get_vmlinux();
    let _rootfs = common::get_rootfs();
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

// See `test_benchmark_fc`. The `p50=` assertion comes from the snapshot-independent Cold Boot
// sub-bench, so this passes regardless of crosvm's (honest-false in v1) snapshot support. Needs a
// `crosvm` binary on PATH in addition to KVM.
#[cfg(feature = "crosvm")]
#[test]
#[ignore = "needs KVM"]
fn test_benchmark_crosvm() {
    let _kernel = common::get_vmlinux();
    let _rootfs = common::get_rootfs();
    let mut cmd = Command::cargo_bin("bench-vm").unwrap();
    cmd.arg("--backend")
        .arg("crosvm")
        .arg("--iterations")
        .arg("1")
        .arg("--warmup")
        .arg("0");
    cmd.assert()
        .success()
        .stdout(predicates::str::contains("p50="));
}
