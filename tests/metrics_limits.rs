use imp_testing::config::{RootfsSource, VmConfig};
use imp_testing::orchestrator::TestVm;

use tokio::time::{Duration, sleep};

mod common;

vmm_matrix_test!(metrics_limits, |vmm| {
    test_metrics_and_limits_impl(&vmm).await;
});

/// Reconstructs the (possibly nested) cgroup-v2 slice name the orchestrator created for a VM,
/// mirroring `orchestrator::setup_env`: `{base}/imp-vm-{vmid}` when running under a delegated
/// sub-tree (systemd / the capability runner), otherwise a bare `imp-vm-{vmid}`. The test and
/// the orchestrator share a process, so `/proc/self/cgroup` resolves identically here.
fn vm_cgroup_name(vmid: u32) -> String {
    let mut cgroup_name = format!("imp-vm-{}", vmid);
    if let Ok(cgroup_str) = std::fs::read_to_string("/proc/self/cgroup") {
        if let Some(path) = cgroup_str.trim().split("0::").nth(1) {
            let mut base = path.trim_start_matches('/');
            if base.ends_with("/supervisor") {
                base = base.trim_end_matches("/supervisor");
            }
            if !base.is_empty() {
                cgroup_name = format!("{}/imp-vm-{}", base, vmid);
            }
        }
    }
    cgroup_name
}

/// Parses the `oom_kill` counter out of a cgroup-v2 `memory.events` file
/// (`key value` lines). Returns `None` when the line is absent.
fn parse_memory_events_oom_kill(contents: &str) -> Option<u64> {
    for line in contents.lines() {
        let mut it = line.split_whitespace();
        if it.next() == Some("oom_kill") {
            return it.next().and_then(|v| v.parse::<u64>().ok());
        }
    }
    None
}

async fn test_metrics_and_limits_impl<V: imp_testing::vmm::Vmm>(vmm: &V) {
    let kernel = common::get_vmlinux();
    let rootfs_image = common::get_rootfs();

    // Guest RAM (512 MiB) is deliberately set ABOVE the cgroup memory cap (256 MiB) so the
    // HOST cgroup — not the guest's own 128 MiB default — is the binding limit for the OOM
    // test below (TESTS-FEATURES-1). With the old default guest RAM, the in-guest workload
    // was OOM-killed by the guest, so deleting the host cap left the test green.
    let mut cfg = VmConfig::builder(
        kernel,
        RootfsSource::Erofs {
            image: rootfs_image,
        },
    )
    .mem_mib(512)
    .network_disabled()
    .build()
    .unwrap();

    // Cap the host cgroup well below guest RAM.
    cfg.limits.mem_max_mib = Some(256);

    let cid_alloc = std::sync::Arc::new(imp_testing::vmm::CidAllocator::new());
    let vmid_alloc = imp_testing::orchestrator::VmidAllocator::new();
    let mut vm = TestVm::start(
        vmm,
        cfg,
        cid_alloc.clone(),
        vmid_alloc,
        Box::new(imp_testing::metrics::DefaultCgroupFs),
    )
    .await
    .expect("Failed to start VM");

    // Wait a bit for the VM to boot and consume some memory.
    sleep(Duration::from_secs(2)).await;

    let stats_before = vm.usage().await.expect("Failed to get VM stats");

    let cgroup_name = vm_cgroup_name(vm.vmid());
    let cg_base = format!("/sys/fs/cgroup/{}", cgroup_name);

    // HARD precondition (TESTS-FEATURES-3): the memory controller MUST be delegated to the
    // slice, otherwise the limit assertions cannot run. A missing or `max` `memory.max` is a
    // real misconfiguration of the privileged runner, never a reason to silently pass. (This
    // test is `#[ignore]`d and only runs under the KVM/privileged tier where the capability
    // runner delegates the controllers.)
    let memory_max_path = format!("{}/memory.max", cg_base);
    let mem_max_raw = std::fs::read_to_string(&memory_max_path).unwrap_or_else(|e| {
        panic!(
            "memory controller not delegated to {} ({e}): cannot validate memory limits",
            cg_base
        )
    });
    let max_bytes: u64 = mem_max_raw.trim().parse().unwrap_or_else(|_| {
        panic!(
            "memory.max is {:?}, expected the 256 MiB byte cap — the limit was not applied",
            mem_max_raw.trim()
        )
    });
    assert_eq!(
        max_bytes,
        256 << 20,
        "memory.max should match the 256 MiB cap"
    );

    // With a delegated controller, live usage must be visible (not the silent-zero skip).
    assert!(
        stats_before.mem_current_mib > 0,
        "memory controller delegated but memory.current is 0"
    );
    assert!(stats_before.mem_peak_mib > 0, "Peak memory should be > 0");

    // Test CPU average computation.
    let start_time = std::time::Instant::now();
    let cpu_test_outcome = vm
        .agent(None, &imp_testing::orchestrator::RealClock)
        .await
        .unwrap()
        .exec(imp_testing::agent::protocol::ExecRequest::new(vec![
            "sh".into(),
            "-c".into(),
            "timeout 2 md5sum /dev/zero".into(),
        ]))
        .await
        .expect("Failed to run cpu load");

    // We used timeout 2, and md5sum /dev/zero saturates one CPU; the timeout kills it.
    assert!(
        cpu_test_outcome.code == 124 || cpu_test_outcome.code == 143,
        "CPU load should be killed by timeout (expected 124 or 143), got code {}",
        cpu_test_outcome.code
    );

    let elapsed = start_time.elapsed().as_secs_f64();

    let stats_after_cpu = vm
        .usage()
        .await
        .expect("Failed to get VM stats after cpu load");

    // HARD precondition (TESTS-FEATURES-3): the cpu controller MUST be delegated — a ~2s 100%
    // load must advance `cpu.stat` usage. Silently skipping the >50% assertion when
    // `cpu_usec == 0` was the skip==pass smell.
    assert!(
        stats_after_cpu.cpu_usec > stats_before.cpu_usec,
        "cpu controller not delegated (cpu_usec did not advance: before={}, after={})",
        stats_before.cpu_usec,
        stats_after_cpu.cpu_usec
    );
    let diff_usec = stats_after_cpu.cpu_usec - stats_before.cpu_usec;
    let cpu_percent = (diff_usec as f64 / 1_000_000.0) / elapsed * 100.0;
    // The VM has 1 vcpu by default, so the ceiling is ~100%.
    assert!(
        cpu_percent > 50.0,
        "CPU usage should be >50% (got {}%, diff {} usec over {}s)",
        cpu_percent,
        diff_usec,
        elapsed
    );

    // Test OOM-kill (TESTS-FEATURES-1). memory.max is 256 MiB while guest RAM is 512 MiB, so
    // the cgroup is the BINDING limit: a runaway allocation trips the HOST cgroup OOM killer,
    // observable via memory.events.oom_kill regardless of any in-guest exit code. A no-op host
    // memory limit (or a guest-RAM-bound OOM) leaves oom_kill at 0 and fails the assertion.
    let oom_exec = vm
        .agent(None, &imp_testing::orchestrator::RealClock)
        .await
        .unwrap()
        .exec(imp_testing::agent::protocol::ExecRequest::new(vec![
            "tail".into(),
            "/dev/zero".into(),
        ]))
        .await;
    // The VMM process itself may be the task the cgroup OOM-kills, so the exec may return
    // SIGKILL (137) or fail outright — either is acceptable; the binding signal is the host
    // cgroup counter polled below, not the in-guest exit code.
    match &oom_exec {
        Ok(o) => println!("memory bloat exec exit code: {}", o.code),
        Err(e) => println!("memory bloat exec failed (VMM likely OOM-killed): {e}"),
    }

    // Poll memory.events for the host-observable OOM (the counter can lag the kill slightly).
    let events_path = format!("{}/memory.events", cg_base);
    let mut oom_kill = 0u64;
    for _ in 0..50 {
        if let Ok(events) = std::fs::read_to_string(&events_path) {
            if let Some(n) = parse_memory_events_oom_kill(&events) {
                oom_kill = n;
                if oom_kill > 0 {
                    break;
                }
            }
        }
        sleep(Duration::from_millis(100)).await;
    }
    assert!(
        oom_kill > 0,
        "cgroup memory.max (256 MiB) must be the BINDING limit: expected memory.events \
         oom_kill > 0 at {}, got {}",
        events_path,
        oom_kill
    );

    // The VMM may already be dead (OOM-killed); tolerate a failed shutdown — Drop still tears
    // down the slice, netns and sockets. We only care that the OOM signal was observed.
    let _ = vm.shutdown().await;
}
