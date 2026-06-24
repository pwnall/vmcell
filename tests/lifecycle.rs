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
    let mut vm = TestVm::start(&ch, cfg, &cid_alloc).await.expect("Failed to start VM");

    vm.instance_mut().kill().await.expect("Failed to kill VM");
}
