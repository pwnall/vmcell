use vmcell::config::{Access, CachePolicy, RootfsSource, Share, VmConfig};

mod common;

// Part C: use the mandated `vmm_matrix_test!` + `require_cap!` harness instead of
// hand-rolled per-backend fns with a bare `return`-skip. `require_cap!` keeps the
// primary CH path unexempted (a CH cap miss panics) and emits one consistent
// skip-with-reason for FC/QEMU when `virtio_fs_shares` is unsupported. The macro
// also stamps each generated test `#[ignore = "needs KVM"]`.
vmm_matrix_test!(shares_ro_rw, |vmm| {
    require_cap!(vmcell::vmm::Vmm::capabilities(&vmm), virtio_fs_shares, vmm);
    test_shares_ro_rw_impl(&vmm).await;
});

// H-TEST-3: capability-honesty pin for `virtio_fs_shares`. `require_cap!` skips a
// backend that lacks this flag, and under nextest a skip is an INVISIBLE pass — so
// a descriptor regression (e.g. QEMU's `virtio_fs_shares` flipping to false) would
// silently turn `shares_ro_rw::qemu` into a green no-op with no test catching it.
// This non-KVM pin fixes the documented value for EVERY backend, so such a flip
// reddens HERE in the default suite. Mirrors the FC snapshot pins in
// src/vmm/firecracker.rs. Inverse: flip any asserted value and this goes red.
#[test]
fn capability_honesty_virtio_fs_shares() {
    #[cfg(feature = "cloud-hypervisor")]
    assert!(
        vmcell::vmm::Vmm::capabilities(&vmcell::vmm::cloud_hypervisor::CloudHypervisor::new(
            common::ch_bin()
        ))
        .virtio_fs_shares,
        "CH (primary) must support virtio_fs_shares; a false silently skips shares_ro_rw::cloud_hypervisor"
    );
    #[cfg(feature = "firecracker")]
    assert!(
        !vmcell::vmm::Vmm::capabilities(&vmcell_firecracker::Firecracker::new(common::fc_bin()))
            .virtio_fs_shares,
        "FC has no virtio-fs, so it must NOT advertise virtio_fs_shares; a true here hides a real gap"
    );
    #[cfg(feature = "qemu")]
    assert!(
        vmcell::vmm::Vmm::capabilities(&vmcell_qemu::Qemu::new(common::qemu_bin()))
            .virtio_fs_shares,
        "QEMU must support virtio_fs_shares; a false here silently skips shares_ro_rw::qemu"
    );
}

async fn test_shares_ro_rw_impl<V: vmcell::vmm::Vmm>(backend: &V) {
    let id = uuid::Uuid::new_v4();
    // OWNED (`common::TempTree`): the trailing `remove_dir_all` is skipped by every panicking
    // assertion between here and it, and a nextest retry re-runs the whole body.
    let tmp =
        common::TempTree::create(&format!("vmcell-test-shares-{}-{}", std::process::id(), id));
    let in_dir = tmp.join("in");
    let out_dir = tmp.join("out");
    std::fs::create_dir_all(&in_dir).unwrap();
    std::fs::create_dir_all(&out_dir).unwrap();

    // Seed the read-only share with the exact content the shared `checks::virtiofs_shares`
    // expects (§4.5, Shared directories (virtio-fs)); the RO-read / RO-write-EROFS / RW-visible contract lives in that one
    // extracted function the validator also runs.
    std::fs::write(in_dir.join("input.txt"), "hello world").unwrap();

    let cfg = VmConfig::builder(
        common::get_vmlinux(),
        RootfsSource::Erofs {
            image: common::get_rootfs(),
        },
    )
    .with_share(Share::new(
        "vmcell-in",
        &in_dir,
        Access::ReadOnly,
        CachePolicy::Never,
    ))
    .with_share(Share::new(
        "vmcell-out",
        &out_dir,
        Access::ReadWrite,
        CachePolicy::Never,
    ))
    .network_disabled()
    .build()
    .unwrap();

    let mut vm = common::start_vm(backend, cfg).await;
    let steward = vm
        .steward(Some(std::time::Duration::from_secs(60)))
        .await
        .expect("Failed to connect to steward");

    vmcell_artifact_validator::checks::virtiofs_shares(steward, &out_dir)
        .await
        .expect("virtio-fs RO/RW share contract");

    vm.kill().await.unwrap();
    // No trailing removal: `tmp` owns the tree and drops here (and on any panic above).
}
