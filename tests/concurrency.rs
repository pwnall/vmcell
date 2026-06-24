use imp_testing::TestVm;
use imp_testing::config::{RootfsSource, VmConfig};
use imp_testing::vmm::VmInstance;
use imp_testing::vmm::cloud_hypervisor::CloudHypervisor;

mod common;

#[tokio::test]
#[ignore]
async fn test_concurrency_ch() {
    let vmm = CloudHypervisor::new(common::ch_bin());
    test_concurrency_impl(&vmm).await;
}

#[cfg(feature = "firecracker")]
#[tokio::test]
#[ignore]
async fn test_concurrency_fc() {
    let vmm = imp_testing::vmm::firecracker::Firecracker::new(common::fc_bin());
    test_concurrency_impl(&vmm).await;
}

#[cfg(feature = "qemu")]
#[tokio::test]
#[ignore]
async fn test_concurrency_qemu() {
    let vmm = imp_testing::vmm::qemu::Qemu::new(common::qemu_bin());
    test_concurrency_impl(&vmm).await;
}

async fn test_concurrency_impl<V: imp_testing::vmm::Vmm>(vmm: &V) {

    let vmlinux = common::get_vmlinux();
    let rootfs = common::get_rootfs();

    if vmlinux.is_none() || rootfs.is_none() {
        println!("Artifacts not found, skipping concurrency test");
        return;
    }

    let cfg = VmConfig::builder(
        vmlinux.unwrap(),
        RootfsSource::Erofs {
            image: rootfs.unwrap(),
        },
    )
    .network_disabled()
    .build()
    .unwrap();

    let cid_alloc = imp_testing::vmm::CidAllocator::new();
    let vmid_alloc = std::sync::Arc::new(imp_testing::orchestrator::VmidAllocator::new());

    let mut vms = Vec::new();
    for _ in 0..5 {
        let vm = TestVm::start(vmm, cfg.clone(), &cid_alloc, vmid_alloc.clone())
            .await
            .expect("Failed to start VM");
        vms.push(vm);
    }

    // Assert all 5 booted successfully and have distinct VMIDs and vsock paths
    let mut vmids = std::collections::HashSet::new();
    let mut vsocks = std::collections::HashSet::new();
    for vm in &vms {
        assert!(vmids.insert(vm.vmid()));
        assert!(vsocks.insert(vm.instance().vsock_path().to_path_buf()));
    }

    for mut vm in vms {
        let agent = vm.agent().await.expect("Failed to connect to agent");
        let outcome = agent
            .exec(imp_testing::agent::ExecRequest::new(vec![
                "true".to_string(),
            ]))
            .await
            .expect("exec failed");
        assert_eq!(outcome.code, 0, "Execution should succeed");
        vm.shutdown().await.expect("Failed to shut down VM");
    }
}
