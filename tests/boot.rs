use imp_testing::TestVm;
use imp_testing::config::{RootfsSource, VmConfig};
use imp_testing::vmm::VmInstance;
use imp_testing::vmm::cloud_hypervisor::CloudHypervisor;
use std::path::PathBuf;

mod common;

#[tokio::test]
#[ignore]
async fn test_boot() {
    let ch = CloudHypervisor::new(&common::ch_bin());

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
        .build().unwrap();

    let cid_alloc = imp_testing::vmm::CidAllocator::new();
    let vm = TestVm::start(&ch, cfg, &cid_alloc).await.expect("Failed to start VM");
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

    vm.shutdown().await.expect("Failed to shutdown VM");
}
