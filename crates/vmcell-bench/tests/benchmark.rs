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
    // The overrides are cleared, not merely unset in the parent: `bench-vm` now honors
    // `$VMCELL_KERNEL`/`$VMCELL_ROOTFS` (§10.4), so a developer who exported them would otherwise
    // send this dry path at a REAL artifact pair and boot a VM.
    cmd.env("VMCELL_ARTIFACTS_DIR", empty.path())
        .env_remove("VMCELL_KERNEL")
        .env_remove("VMCELL_ROOTFS")
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

// d8 / §10.4: `$VMCELL_KERNEL` and `$VMCELL_ROOTFS` are the contract's artifact overrides — every
// other harness resolves through the toolkit getters, and `bench-vm` composed `<artifacts-dir>/…`
// itself, so a box pointed at a custom pair benchmarked the default one and attributed the numbers
// to the override. This drives the REAL binary (the bin's unit tests cover the pure resolver, which
// cannot prove the process actually reads the environment) down the same KVM-free dry path: both
// overrides name files that do not exist, so it fails at the existence check before any boot.
// RED on the inverse (paths composed from the artifacts dir): the run reports `<dir>/vmlinux` and
// `<dir>/rootfs.erofs`, and both `contains` assertions below fail.
#[cfg(feature = "cloud-hypervisor")]
#[test]
fn bench_vm_honors_the_toolkit_artifact_overrides() {
    let dir = tempfile::tempdir().unwrap();
    let kernel = dir.path().join("custom/vmlinux-from-the-override");
    let rootfs = dir.path().join("custom/rootfs-from-the-override.erofs");
    let mut cmd = Command::cargo_bin("bench-vm").unwrap();
    cmd.env("VMCELL_ARTIFACTS_DIR", dir.path())
        .env("VMCELL_KERNEL", &kernel)
        .env("VMCELL_ROOTFS", &rootfs)
        .args(["--backend", "cloud-hypervisor"])
        .args(["--iterations", "1", "--warmup", "0"]);
    cmd.assert()
        .failure()
        // The attribution line names what the run would really boot…
        .stdout(predicates::str::contains(format!(
            "kernel: {}",
            kernel.display()
        )))
        .stdout(predicates::str::contains(format!(
            "rootfs: {}",
            rootfs.display()
        )))
        // …and `$VMCELL_KERNEL` is a redirect that still REQUIRES existence: the refusal names the
        // overridden paths, not the artifacts dir where nothing is wrong.
        .stderr(predicates::str::contains(kernel.display().to_string()))
        .stderr(predicates::str::contains(rootfs.display().to_string()));
}

// The conflict half: `--kernel <label>` selects `vmlinux-<label>` under the artifacts dir while
// `$VMCELL_KERNEL` names one exact file. Two accepted inputs that contradict each other are
// rejected at the boundary — before the CPU-freq pin and any boot — never silently resolved one
// way. RED on the inverse (a resolver where one silently wins): the run proceeds and exits with a
// missing-artifacts error that names no conflict.
#[cfg(feature = "cloud-hypervisor")]
#[test]
fn bench_vm_rejects_a_kernel_label_that_contradicts_the_kernel_override() {
    let dir = tempfile::tempdir().unwrap();
    let mut cmd = Command::cargo_bin("bench-vm").unwrap();
    cmd.env("VMCELL_ARTIFACTS_DIR", dir.path())
        .env("VMCELL_KERNEL", dir.path().join("custom/vmlinux-x"))
        .env_remove("VMCELL_ROOTFS")
        .args(["--backend", "cloud-hypervisor"])
        .args(["--kernel", "6.12.94"])
        .args(["--iterations", "1", "--warmup", "0"]);
    cmd.assert()
        .failure()
        .stderr(predicates::str::contains("$VMCELL_KERNEL"))
        .stderr(predicates::str::contains("vmlinux-6-12-94"));
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
// sub-bench, so this passes independent of crosvm's snapshot path (which is live-validated true,
// §2.5 — the baked-CID Firecracker pattern). Needs a `crosvm` binary on PATH in addition to KVM.
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
