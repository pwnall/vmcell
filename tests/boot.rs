use imp_testing::TestVm;
use imp_testing::config::{RootfsSource, VmConfig};
use imp_testing::vmm::VmInstance;
use imp_testing::vmm::cloud_hypervisor::CloudHypervisor;

mod common;

#[tokio::test]
#[ignore]
async fn test_boot_ch() {
    let vmm = CloudHypervisor::new(common::ch_bin());
    test_boot_impl(&vmm).await;
}

#[cfg(feature = "firecracker")]
#[tokio::test]
#[ignore]
async fn test_boot_fc() {
    let vmm = imp_testing::vmm::firecracker::Firecracker::new(common::fc_bin());
    test_boot_impl(&vmm).await;
}

#[cfg(feature = "qemu")]
#[tokio::test]
#[ignore]
async fn test_boot_qemu() {
    let vmm = imp_testing::vmm::qemu::Qemu::new(common::qemu_bin());
    test_boot_impl(&vmm).await;
}

async fn test_boot_impl<V: imp_testing::vmm::Vmm>(vmm: &V) {
    let vmlinux = match common::get_vmlinux() {
        Some(p) => p,
        None => {
            println!("Artifacts not found, skipping boot test");
            return;
        }
    };
    let rootfs = match common::get_rootfs() {
        Some(p) => p,
        None => return,
    };

    let cfg = VmConfig::builder(vmlinux, RootfsSource::Erofs { image: rootfs })
        .network_disabled()
        .build()
        .unwrap();

    let cid_alloc = imp_testing::vmm::CidAllocator::new();
    let vmid_alloc = imp_testing::orchestrator::VmidAllocator::new();
    let mut vm = TestVm::start(
        vmm,
        cfg,
        &cid_alloc,
        vmid_alloc,
        Box::new(imp_testing::metrics::DefaultCgroupFs::default()),
    )
    .await
    .expect("Failed to start VM");
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    let log = std::fs::read_to_string(vm.instance().serial_log()).unwrap_or_default();
    println!("SERIAL LOG:\n{}", log);

    let serial_log = vm.instance().serial_log().to_path_buf();

    let mut booted = false;
    for _ in 0..100 {
        if serial_log.exists() {
            let log_content = tokio::fs::read_to_string(&serial_log)
                .await
                .unwrap_or_default();
            if log_content.contains("Linux version") {
                booted = true;
                break;
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    assert!(booted, "VM failed to boot (did not see expected log line)");

    let agent = vm
        .agent(
            Some(std::time::Duration::from_secs(60)),
            &imp_testing::orchestrator::RealClock,
        )
        .await
        .expect("Failed to connect to agent");

    let outcome = agent
        .exec(imp_testing::agent::ExecRequest::new(vec![
            "echo".to_string(),
            "hello from guest".to_string(),
        ]))
        .await
        .expect("exec failed");

    assert_eq!(outcome.code, 0, "exec returned non-zero code");
    let stdout = String::from_utf8_lossy(&outcome.stdout);
    assert!(
        stdout.contains("hello from guest"),
        "expected stdout to contain 'hello from guest', got: {}",
        stdout
    );

    vm.shutdown().await.expect("Failed to shutdown VM");
}
