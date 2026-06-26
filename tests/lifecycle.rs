use imp_testing::TestVm;
use imp_testing::config::{RootfsSource, VmConfig};
use imp_testing::vmm::VmInstance;
use imp_testing::vmm::cloud_hypervisor::CloudHypervisor;
use std::path::PathBuf;

mod common;

#[tokio::test]
#[ignore]
async fn test_lifecycle_force_kill_ch() {
    let vmm = CloudHypervisor::new(common::ch_bin());
    test_lifecycle_force_kill_impl(&vmm).await;
}

#[cfg(feature = "firecracker")]
#[tokio::test]
#[ignore]
async fn test_lifecycle_force_kill_fc() {
    let vmm = imp_testing::vmm::firecracker::Firecracker::new(common::fc_bin());
    test_lifecycle_force_kill_impl(&vmm).await;
}

#[cfg(feature = "qemu")]
#[tokio::test]
#[ignore]
async fn test_lifecycle_force_kill_qemu() {
    let vmm = imp_testing::vmm::qemu::Qemu::new(common::qemu_bin());
    test_lifecycle_force_kill_impl(&vmm).await;
}

async fn test_lifecycle_force_kill_impl<V: imp_testing::vmm::Vmm>(vmm: &V) {
    let vmlinux = PathBuf::from("/tmp/imp-artifacts/vmlinux");
    let rootfs = PathBuf::from("/tmp/imp-artifacts/rootfs.erofs");

    if !vmlinux.exists() || !rootfs.exists() {
        panic!("Artifacts not found, skipping lifecycle test");
    }

    let cfg = VmConfig::builder(vmlinux, RootfsSource::Erofs { image: rootfs })
        .network_disabled()
        .build()
        .unwrap();

    let cid_alloc = std::sync::Arc::new(imp_testing::vmm::CidAllocator::new());
    let vmid_alloc = imp_testing::orchestrator::VmidAllocator::new();
    let mut vm = TestVm::start(
        vmm,
        cfg,
        cid_alloc.clone(),
        vmid_alloc,
        Box::new(imp_testing::metrics::DefaultCgroupFs),
    )
    .await
    .expect("Failed to start VM");

    vm.instance_mut().kill().await.expect("Failed to kill VM");
}

#[tokio::test]
async fn test_lifecycle_fake_vmm() {
    use imp_testing::vmm::FakeVmm;
    let fake = FakeVmm::default();

    let cfg = VmConfig::builder(
        "/fake/kernel",
        RootfsSource::Erofs {
            image: PathBuf::from("/fake/rootfs"),
        },
    )
    .network_disabled()
    .build()
    .unwrap();

    let cid_alloc = std::sync::Arc::new(imp_testing::vmm::CidAllocator::new());
    let vmid_alloc = imp_testing::orchestrator::VmidAllocator::new();

    let vm = TestVm::start(
        &fake,
        cfg.clone(),
        cid_alloc.clone(),
        vmid_alloc.clone(),
        Box::new(imp_testing::metrics::DefaultCgroupFs),
    )
    .await
    .expect("Failed to start fake VM");

    // Check that create and boot were called
    {
        let calls = fake.calls.lock().unwrap();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0], "create");
        assert_eq!(calls[1], "boot");
    }

    // Shutdown should call request_shutdown
    vm.shutdown().await.expect("Failed to shutdown");

    // The FakeVmInstance records calls in the same shared vector
    {
        let calls = fake.calls.lock().unwrap();
        assert_eq!(calls[2], "request_shutdown");
        assert_eq!(calls[3], "kill");
    }

    // Now test restore
    let restore_vm = TestVm::restore(
        &fake,
        std::path::Path::new("/fake/snap"),
        cfg.clone(),
        cid_alloc.clone(),
        vmid_alloc.clone(),
        Box::new(imp_testing::metrics::DefaultCgroupFs),
    )
    .await
    .expect("Failed to restore fake VM");

    {
        let calls = fake.calls.lock().unwrap();
        assert_eq!(calls[4], "drop");
        assert_eq!(calls[5], "restore");
        assert_eq!(calls[6], "resume");
    }

    restore_vm.shutdown().await.expect("Failed to shutdown");
}

#[tokio::test]
#[serial_test::serial]
#[ignore]
async fn test_lifecycle_panic_residue_ch() {
    let vmm = CloudHypervisor::new(common::ch_bin());
    let vmlinux = PathBuf::from("/tmp/imp-artifacts/vmlinux");
    let rootfs = PathBuf::from("/tmp/imp-artifacts/rootfs.erofs");

    if !vmlinux.exists() || !rootfs.exists() {
        panic!("Artifacts not found, skipping panic residue test");
    }

    let mut cfg = VmConfig::builder(vmlinux, RootfsSource::Erofs { image: rootfs })
        .build()
        .unwrap();
    cfg.net = imp_testing::config::NetConfig::Rootless {
        egress: imp_testing::config::Egress::Open,
        host_services_port: None,
    };

    let cid_alloc = std::sync::Arc::new(imp_testing::vmm::CidAllocator::new());
    let vmid_alloc = imp_testing::orchestrator::VmidAllocator::new();

    let vmid = {
        let vm = TestVm::start(
            &vmm,
            cfg,
            cid_alloc.clone(),
            vmid_alloc,
            Box::new(imp_testing::metrics::DefaultCgroupFs),
        )
        .await
        .expect("Failed to start VM");

        let vmid = vm.vmid();

        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let _vm = vm;
            panic!("simulate panic inside scope");
        }));

        // Scope ends, but vm was already dropped during panic unwind
        vmid
    };

    // Give drop handlers a moment
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    // Check socket file
    let sock_path = format!("/tmp/imp-smoltcp-{}.sock", vmid);
    assert!(
        !std::path::Path::new(&sock_path).exists(),
        "Socket file should be cleaned up"
    );

    // Check cgroup
    let cg_path = format!("/sys/fs/cgroup/imp-vm-{}", vmid);
    assert!(
        !std::path::Path::new(&cg_path).exists(),
        "Cgroup should be cleaned up"
    );
}

#[tokio::test]
async fn test_lifecycle_fake_vmm_drop_order_on_panic() {
    use imp_testing::vmm::FakeVmm;
    let fake = FakeVmm::default();

    let cfg = imp_testing::config::VmConfig::builder(
        "/fake/kernel",
        imp_testing::config::RootfsSource::Erofs {
            image: std::path::PathBuf::from("/fake/rootfs"),
        },
    )
    .network_disabled()
    .build()
    .unwrap();

    let cid_alloc = std::sync::Arc::new(imp_testing::vmm::CidAllocator::new());
    let vmid_alloc = imp_testing::orchestrator::VmidAllocator::new();
    let calls_clone = fake.calls.clone();

    let _ = tokio::spawn(async move {
        let _vm = imp_testing::TestVm::start(
            &fake,
            cfg,
            cid_alloc.clone(),
            vmid_alloc,
            Box::new(imp_testing::metrics::DefaultCgroupFs),
        )
        .await
        .expect("Failed to start fake VM");
        panic!("simulate panic inside scope");
    })
    .await;

    let calls = calls_clone.lock().unwrap();
    // Verify drop was called on panic
    assert!(
        calls.contains(&"drop".to_string()),
        "FakeVmInstance drop should have been called on panic"
    );
}
