use imp_testing::config::{RootfsSource, VmConfig};
use imp_testing::orchestrator::TestVm;
use imp_testing::vmm::cloud_hypervisor::CloudHypervisor;
use std::path::PathBuf;
use tokio::time::{Duration, sleep};

mod common;

#[tokio::test]
#[ignore]
async fn test_metrics_and_limits_ch() {
    let ch_binary =
        std::env::var("CLOUD_HYPERVISOR_PATH").unwrap_or_else(|_| "cloud-hypervisor".into());
    let vmm = CloudHypervisor::new(ch_binary);
    test_metrics_and_limits_impl(&vmm).await;
}

#[cfg(feature = "firecracker")]
#[tokio::test]
#[ignore]
async fn test_metrics_and_limits_fc() {
    let vmm = imp_testing::vmm::firecracker::Firecracker::new(common::fc_bin());
    test_metrics_and_limits_impl(&vmm).await;
}

#[cfg(feature = "qemu")]
#[tokio::test]
#[ignore]
async fn test_metrics_and_limits_qemu() {
    let vmm = imp_testing::vmm::qemu::Qemu::new(common::qemu_bin());
    test_metrics_and_limits_impl(&vmm).await;
}

async fn test_metrics_and_limits_impl<V: imp_testing::vmm::Vmm>(vmm: &V) {
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

    // Set memory limit to 256 MiB
    cfg.limits.mem_max_mib = Some(256);

    let cid_alloc = imp_testing::vmm::CidAllocator::new();
    let vmid_alloc = std::sync::Arc::new(imp_testing::orchestrator::VmidAllocator::new());
    let mut vm = TestVm::start(vmm, cfg, &cid_alloc, vmid_alloc)
        .await
        .expect("Failed to start VM");

    // Wait a bit for the VM to boot and consume some memory
    sleep(Duration::from_secs(2)).await;

    let stats_before = vm.usage().await.expect("Failed to get VM stats");

    // Verify non-zero values if controller is enabled
    if stats_before.mem_current_mib > 0 {
        assert!(stats_before.mem_peak_mib > 0, "Peak memory should be > 0");

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
    if stats_before.cpu_usec > 0 {
        println!("CPU usage: {}", stats_before.cpu_usec);
    } else {
        println!("CPU controller not delegated, skipping cpu metrics assertion");
    }

    // Test CPU average computation
    let cpu_test_outcome = vm
        .agent()
        .await
        .unwrap()
        .exec(imp_testing::agent::protocol::ExecRequest::new(vec![
            "sh".into(),
            "-c".into(),
            "timeout 2 md5sum /dev/zero || true".into(),
        ]))
        .await
        .expect("Failed to run cpu load");

    let stats_after_cpu = vm
        .usage()
        .await
        .expect("Failed to get VM stats after cpu load");
    if stats_before.cpu_usec > 0 {
        let diff_usec = stats_after_cpu
            .cpu_usec
            .saturating_sub(stats_before.cpu_usec);
        // timeout 2 should consume ~2 seconds of cpu time, so > 1,000,000 usec
        assert!(
            diff_usec > 1_000_000,
            "CPU usage should have increased by >1s (got {} usec)",
            diff_usec
        );
    }

    // Test OOM-kill
    // memory.max is 256 MiB. We try to allocate 300 MiB.
    let oom_outcome = vm
        .agent()
        .await
        .unwrap()
        .exec(imp_testing::agent::protocol::ExecRequest::new(vec![
            "dd".into(),
            "if=/dev/zero".into(),
            "of=/dev/shm/bloat".into(),
            "bs=1M".into(),
            "count=300".into(),
        ]))
        .await
        .expect("Failed to run memory bloat");

    assert_ne!(
        oom_outcome.code, 0,
        "dd should be killed by OOM killer, but exited with 0"
    );

    vm.shutdown().await.expect("Failed to shutdown VM");
}
