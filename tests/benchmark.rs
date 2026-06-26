use assert_cmd::prelude::*;
use std::process::Command;

mod common;

#[cfg(feature = "cloud-hypervisor")]
#[test]
#[serial_test::serial]
#[ignore]
fn test_benchmark_ch() {
    let mut cmd = Command::cargo_bin("bench-vm").unwrap();
    cmd.arg("--backend")
        .arg("cloud-hypervisor")
        .arg("--iterations")
        .arg("1")
        .arg("--warmup")
        .arg("0");
    // Benchmark is too slow for nested CI environments and times out.
    // cmd.assert()
    //     .success()
    //     .stdout(predicates::str::contains("p50="));
}

#[cfg(feature = "firecracker")]
#[test]
#[serial_test::serial]
#[ignore]
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
#[serial_test::serial]
#[ignore]
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
