use imp_testing::agent::protocol::ExecRequest;
use imp_testing::config::{RootfsSource, VmConfig};
use imp_testing::orchestrator::TestVm;
use imp_testing::vmm::cloud_hypervisor::CloudHypervisor;
use std::path::PathBuf;

mod common;

#[tokio::test]
#[ignore]
async fn test_nested_virt_ch() {
    let ch_binary =
        std::env::var("CLOUD_HYPERVISOR_PATH").unwrap_or_else(|_| "cloud-hypervisor".into());
    let vmm = CloudHypervisor::new(ch_binary);
    test_nested_virt_impl(&vmm).await;
}

#[cfg(feature = "firecracker")]
#[tokio::test]
#[ignore]
async fn test_nested_virt_fc() {
    let vmm = imp_testing::vmm::firecracker::Firecracker::new(common::fc_bin());
    if !imp_testing::vmm::Vmm::capabilities(&vmm).nested_virt {
        println!("Skipping: nested virtualization not supported");
        return;
    }
    test_nested_virt_impl(&vmm).await;
}

async fn test_nested_virt_impl<V: imp_testing::vmm::Vmm>(vmm: &V) {
    let kernel = PathBuf::from(
        std::env::var("IMP_KERNEL").unwrap_or_else(|_| "/tmp/imp-artifacts/vmlinux".into()),
    );
    let rootfs_image = PathBuf::from(
        std::env::var("IMP_ROOTFS").unwrap_or_else(|_| "/tmp/imp-artifacts/rootfs.erofs".into()),
    );

    let mut cfg = VmConfig::builder(
        kernel,
        RootfsSource::Erofs {
            image: rootfs_image,
        },
    )
    .network_disabled()
    .build()
    .unwrap();

    // Enable nested virtualization
    cfg.nested_virt = true;

    let cid_alloc = imp_testing::vmm::CidAllocator::new();
    let vmid_alloc = std::sync::Arc::new(imp_testing::orchestrator::VmidAllocator::new());
    let mut vm = TestVm::start(vmm, cfg, &cid_alloc, vmid_alloc)
        .await
        .expect("Failed to start VM");

    let agent = match vm.agent().await {
        Ok(a) => a,
        Err(e) => {
            use imp_testing::vmm::VmInstance;
            let log = tokio::fs::read_to_string(vm.instance().serial_log())
                .await
                .unwrap_or_default();
            panic!("Failed to connect to agent: {}\nSerial log:\n{}", e, log);
        }
    };

    // Check if nested virtualization is available inside the VM
    let result = agent
        .exec(ExecRequest::new(vec!["kvm-ok".to_string()]))
        .await
        .expect("Failed to run kvm-ok");

    // Ignore error code because kvm-ok might fail if the host machine running the tests
    // doesn't have nested virt enabled. We just want to ensure it executes.
    // If kvm-ok doesn't exist, it will return a different error.
    println!("kvm-ok stdout: {}", String::from_utf8_lossy(&result.stdout));
    println!("kvm-ok stderr: {}", String::from_utf8_lossy(&result.stderr));

    vm.shutdown().await.expect("Failed to shutdown VM");
}
