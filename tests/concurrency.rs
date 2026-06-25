use imp_testing::TestVm;
use imp_testing::config::{RootfsSource, VmConfig};
use imp_testing::vmm::VmInstance;
use imp_testing::vmm::cloud_hypervisor::CloudHypervisor;

mod common;

#[tokio::test]
#[serial_test::serial]
#[ignore]
async fn test_concurrency_ch() {
    let vmm = CloudHypervisor::new(common::ch_bin());
    test_concurrency_impl(&vmm).await;
}

#[cfg(feature = "firecracker")]
#[tokio::test]
#[serial_test::serial]
#[ignore]
async fn test_concurrency_fc() {
    let vmm = imp_testing::vmm::firecracker::Firecracker::new(common::fc_bin());
    test_concurrency_impl(&vmm).await;
}

#[cfg(feature = "qemu")]
#[tokio::test]
#[serial_test::serial]
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
    let vmid_alloc = imp_testing::orchestrator::VmidAllocator::new();

    let mut vms = Vec::new();
    for _ in 0..2 {
        let vm = TestVm::start(vmm, cfg.clone(), &cid_alloc, vmid_alloc.clone())
            .await
            .expect("Failed to start VM");
        vms.push(vm);
    }

    // Assert all booted successfully and have distinct VMIDs, guest CIDs, and vsock paths
    let mut vmids = std::collections::HashSet::new();
    let mut vsocks = std::collections::HashSet::new();
    let mut cids = std::collections::HashSet::new();
    for vm in &vms {
        assert!(vmids.insert(vm.vmid()));
        assert!(vsocks.insert(vm.instance().vsock_path().to_path_buf()));
        assert!(cids.insert(vm.instance().guest_cid()));
    }

    for mut vm in vms {
        let agent = match vm.agent(Some(std::time::Duration::from_secs(180))).await {
            Ok(a) => a,
            Err(e) => {
                if let Ok(log) = std::fs::read_to_string(vm.instance().serial_log()) {
                    println!("VM Serial log on connect timeout:\n{}", log);
                }
                panic!("Failed to connect to agent: {}", e);
            }
        };
        let outcome = match agent
            .exec(imp_testing::agent::ExecRequest::new(vec![
                "true".to_string(),
            ]))
            .await
        {
            Ok(o) => o,
            Err(e) => {
                if let Ok(log) = std::fs::read_to_string(vm.instance().serial_log()) {
                    println!("VM Serial log:\n{}", log);
                }
                panic!("exec failed: {}", e);
            }
        };
        assert_eq!(outcome.code, 0, "Execution should succeed");
        vm.shutdown().await.expect("Failed to shut down VM");
    }
}
