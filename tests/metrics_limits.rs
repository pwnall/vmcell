use imp_testing::config::{RootfsSource, VmConfig};
use imp_testing::orchestrator::TestVm;
use imp_testing::vmm::cloud_hypervisor::CloudHypervisor;
use std::path::PathBuf;
use tokio::time::{Duration, sleep};

#[tokio::test]
#[ignore]
async fn test_metrics_and_limits() {
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
    .build().unwrap();

    // Set memory limit to 256 MiB
    cfg.limits.mem_max_mib = Some(256);

    let ch_binary =
        std::env::var("CLOUD_HYPERVISOR_PATH").unwrap_or_else(|_| "cloud-hypervisor".into());
    let vmm = CloudHypervisor::new(ch_binary);

    let cid_alloc = imp_testing::vmm::CidAllocator::new();
    let vmid_alloc = std::sync::Arc::new(imp_testing::orchestrator::VmidAllocator::new());
    let vm = TestVm::start(&vmm, cfg, &cid_alloc, vmid_alloc).await.expect("Failed to start VM");

    // Wait a bit for the VM to boot and consume some memory
    sleep(Duration::from_secs(2)).await;

    let stats = vm.usage().await.expect("Failed to get VM stats");

    // Verify non-zero values if controller is enabled
    if stats.mem_current_mib > 0 {
        assert!(stats.mem_peak_mib > 0, "Peak memory should be > 0");

        // Assert memory limits were applied to cgroup
        let mut cgroup_name = format!("imp-vm-{}", vm.vmid());
        if let Ok(cgroup_str) = std::fs::read_to_string("/proc/self/cgroup") {
            if let Some(path) = cgroup_str.trim().split("0::").nth(1) {
                let mut base = path.trim_start_matches('/');
                if base.ends_with("/supervisor") {
                    base = base.trim_end_matches("/supervisor");
                }
                if !base.is_empty() {
                    cgroup_name = format!("{}/imp-vm-{}", base, vm.vmid());
                }
            }
        }
        let memory_max_path = format!("/sys/fs/cgroup/{}/memory.max", cgroup_name);
        if let Ok(content) = std::fs::read_to_string(&memory_max_path) {
            if let Ok(max_bytes) = content.trim().parse::<usize>() {
                assert_eq!(max_bytes, 256 << 20, "memory.max should match config");
            }
        }
    } else {
        println!("Memory controller not delegated, skipping memory metrics assertion");
    }
    // CPU usage might also be absent if cpu controller isn't delegated, check it:
    if stats.cpu_usec > 0 {
        println!("CPU usage: {}", stats.cpu_usec);
    } else {
        println!("CPU controller not delegated, skipping cpu metrics assertion");
    }

    vm.shutdown().await.expect("Failed to shutdown VM");
}
