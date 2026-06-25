use imp_testing::config::{RootfsSource, VmConfig};
use imp_testing::orchestrator::TestVm;
use imp_testing::vmm::cloud_hypervisor::CloudHypervisor;
use std::path::PathBuf;
use tokio::time::{Duration, sleep};

mod common;

#[tokio::test]
#[serial_test::serial]
#[ignore]
async fn test_metrics_and_limits_ch() {
    let ch_binary =
        std::env::var("CLOUD_HYPERVISOR_PATH").unwrap_or_else(|_| "cloud-hypervisor".into());
    let vmm = CloudHypervisor::new(ch_binary);
    test_metrics_and_limits_impl(&vmm).await;
}

#[cfg(feature = "firecracker")]
#[tokio::test]
#[serial_test::serial]
#[ignore]
async fn test_metrics_and_limits_fc() {
    let vmm = imp_testing::vmm::firecracker::Firecracker::new(common::fc_bin());
    test_metrics_and_limits_impl(&vmm).await;
}

#[cfg(feature = "qemu")]
#[tokio::test]
#[serial_test::serial]
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
    let vmid_alloc = imp_testing::orchestrator::VmidAllocator::new();
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
    let start_time = std::time::Instant::now();
    let cpu_test_outcome = vm
        .agent(None)
        .await
        .unwrap()
        .exec(imp_testing::agent::protocol::ExecRequest::new(vec![
            "sh".into(),
            "-c".into(),
            "timeout 2 md5sum /dev/zero".into(),
        ]))
        .await
        .expect("Failed to run cpu load");

    // We used timeout 2, but md5sum /dev/zero will consume 100% of 1 CPU.
    // If it is killed by timeout, it might exit with 143 or 124 depending on timeout behavior.
    assert!(
        cpu_test_outcome.code != 0,
        "CPU load should be killed by timeout"
    );

    let elapsed = start_time.elapsed().as_secs_f64();

    let stats_after_cpu = vm
        .usage()
        .await
        .expect("Failed to get VM stats after cpu load");
    if stats_before.cpu_usec > 0 {
        let diff_usec = stats_after_cpu
            .cpu_usec
            .saturating_sub(stats_before.cpu_usec);
        let cpu_percent = (diff_usec as f64 / 1_000_000.0) / elapsed * 100.0;
        // The VM has 1 vcpu by default. So max is ~100%.
        assert!(
            cpu_percent > 50.0,
            "CPU usage should be >50% (got {}%, diff {} usec over {}s)",
            cpu_percent,
            diff_usec,
            elapsed
        );
    }

    // Test OOM-kill
    // memory.max is 256 MiB.
    let oom_outcome = vm
        .agent(None)
        .await
        .unwrap()
        .exec(imp_testing::agent::protocol::ExecRequest::new(vec![
            "tail".into(),
            "/dev/zero".into(),
        ]))
        .await
        .expect("Failed to run memory bloat");

    assert!(
        oom_outcome.code == 137
            || oom_outcome.code == 137 - 256
            || oom_outcome.code == 1
            || oom_outcome.code == -1, // sometimes represented as 137, sometimes we just get connection closed, sometimes malloc fails and returns 1
        "Process should be killed by OOM killer or exit due to ENOMEM, got code {}, stderr: {}",
        oom_outcome.code,
        String::from_utf8_lossy(&oom_outcome.stderr)
    );

    vm.shutdown().await.expect("Failed to shutdown VM");
}
