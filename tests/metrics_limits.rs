use imp_testing::config::{RootfsSource, VmConfig};
use imp_testing::orchestrator::TestVm;
use imp_testing::vmm::cloud_hypervisor::CloudHypervisor;
use std::path::PathBuf;
use tokio::time::{Duration, sleep};

#[tokio::test]
async fn test_metrics_and_limits() {
    let kernel =
        PathBuf::from(std::env::var("IMP_KERNEL").unwrap_or_else(|_| "/tmp/imp-artifacts/vmlinux".into()));
    let rootfs_image =
        PathBuf::from(std::env::var("IMP_ROOTFS").unwrap_or_else(|_| "/tmp/imp-artifacts/rootfs.ext4".into()));

    let mut cfg = VmConfig::builder(
        kernel,
        RootfsSource::Erofs {
                image: rootfs_image,
            },
    )
    .network_disabled().build();

    // Set memory limit to 256 MiB
    cfg.limits.mem_max_mib = Some(256);

    let ch_binary =
        std::env::var("CLOUD_HYPERVISOR_PATH").unwrap_or_else(|_| "cloud-hypervisor".into());
    let vmm = CloudHypervisor::new(ch_binary);

    let vm = TestVm::start(&vmm, cfg).await.expect("Failed to start VM");

    // Wait a bit for the VM to boot and consume some memory
    sleep(Duration::from_secs(2)).await;

    let stats = vm.usage().await.expect("Failed to get VM stats");

    // Verify non-zero values
    assert!(stats.mem_current_mib > 0, "Current memory should be > 0");
    assert!(stats.mem_peak_mib > 0, "Peak memory should be > 0");
    assert!(stats.cpu_usec > 0, "CPU usage should be > 0");

    vm.shutdown().await.expect("Failed to shutdown VM");
}
