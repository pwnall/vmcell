use imp_testing::TestVm;
use imp_testing::config::{RootfsSource, VmConfig};
use imp_testing::vmm::VmInstance;
use imp_testing::vmm::cloud_hypervisor::CloudHypervisor;
use std::path::PathBuf;

#[tokio::test]
#[ignore]
async fn test_lifecycle_force_kill() {
    let ch = CloudHypervisor::new("cloud-hypervisor");

    let vmlinux = PathBuf::from("/tmp/imp-artifacts/vmlinux");
    let rootfs = PathBuf::from("/tmp/imp-artifacts/rootfs.erofs");

    if !vmlinux.exists() || !rootfs.exists() {
        println!("Artifacts not found, skipping lifecycle test");
        return;
    }

    let cfg = VmConfig::builder(vmlinux, RootfsSource::Erofs { image: rootfs })
        .network_disabled()
        .build().unwrap();

    let cid_alloc = imp_testing::vmm::CidAllocator::new();
    let vmid_alloc = std::sync::Arc::new(imp_testing::orchestrator::VmidAllocator::new());
    let mut vm = TestVm::start(&ch, cfg, &cid_alloc, vmid_alloc).await.expect("Failed to start VM");

    vm.instance_mut().kill().await.expect("Failed to kill VM");
}

#[tokio::test]
async fn test_lifecycle_fake_vmm() {
    use imp_testing::vmm::FakeVmm;
    let fake = FakeVmm::default();
    
    let cfg = VmConfig::builder("/fake/kernel", RootfsSource::Erofs { image: PathBuf::from("/fake/rootfs") })
        .network_disabled()
        .build().unwrap();

    let cid_alloc = imp_testing::vmm::CidAllocator::new();
    let vmid_alloc = std::sync::Arc::new(imp_testing::orchestrator::VmidAllocator::new());
    
    let vm = TestVm::start(&fake, cfg, &cid_alloc, vmid_alloc).await.expect("Failed to start fake VM");
    
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
        assert!(calls.contains(&"request_shutdown".to_string()));
    }
}
