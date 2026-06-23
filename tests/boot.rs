use imp_testing::TestVm;
use imp_testing::config::{RootfsSource, VmConfig};
use imp_testing::vmm::VmInstance;
use imp_testing::vmm::cloud_hypervisor::CloudHypervisor;
use std::path::PathBuf;

#[tokio::test]
async fn test_boot() {
    let ch = CloudHypervisor::new("cloud-hypervisor");

    let vmlinux = PathBuf::from("/tmp/imp-artifacts/vmlinux");
    let rootfs = PathBuf::from("/tmp/imp-artifacts/rootfs.ext4");

    if !vmlinux.exists() || !rootfs.exists() {
        println!("Artifacts not found, skipping boot test");
        return;
    }

    let cfg = VmConfig::builder(vmlinux, RootfsSource::Erofs { image: rootfs })
        .network_disabled()
        .build();

    let vm = TestVm::start(&ch, cfg).await.expect("Failed to start VM");
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    let log = std::fs::read_to_string(vm.instance.serial_log()).unwrap_or_default();
    println!("SERIAL LOG:\n{}", log);

    let serial_log = vm.instance.serial_log().to_path_buf();

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
