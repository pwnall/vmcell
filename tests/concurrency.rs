use imp_testing::TestVm;
use imp_testing::config::{RootfsSource, VmConfig};
use imp_testing::vmm::cloud_hypervisor::CloudHypervisor;
use std::path::PathBuf;

mod common;

#[tokio::test]
#[ignore]
async fn test_concurrency() {
    let ch_binary = std::env::var("CLOUD_HYPERVISOR_PATH").unwrap_or_else(|_| "cloud-hypervisor".into());
    let vmm = CloudHypervisor::new(ch_binary);

    let vmlinux = common::get_vmlinux();
    let rootfs = common::get_rootfs();

    if vmlinux.is_none() || rootfs.is_none() {
        println!("Artifacts not found, skipping concurrency test");
        return;
    }

    let cfg = VmConfig::builder(vmlinux.unwrap(), RootfsSource::Erofs { image: rootfs.unwrap() })
        .network_disabled()
        .build().unwrap();

    let cid_alloc = imp_testing::vmm::CidAllocator::new();
    
    let mut vms = Vec::new();
    for _ in 0..5 {
        let vm = TestVm::start(&vmm, cfg.clone(), &cid_alloc).await.expect("Failed to start VM");
        vms.push(vm);
    }
    
    // Assert all 5 booted successfully and have distinct VMIDs
    let mut vmids = std::collections::HashSet::new();
    for vm in &vms {
        assert!(vmids.insert(vm.vmid()));
    }
    
    for vm in vms {
        vm.shutdown().await.expect("Failed to shut down VM");
    }
}
