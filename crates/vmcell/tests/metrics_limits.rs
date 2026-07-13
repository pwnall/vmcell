use vmcell::config::{RootfsSource, VmConfig};
use vmcell::orchestrator::MicroVm;

use tokio::time::{Duration, sleep};

mod common;

vmm_matrix_test!(metrics_limits, |vmm| {
    test_metrics_and_limits_impl(&vmm).await;
});

// L-TEST-4 / H-HOST-3: the per-VM cgroup slice name is derived by
// `common::computed_cgroup_name`, which delegates the `/proc/self/cgroup` parse to
// the single canonical `vmcell::metrics::cgroup_base_from_proc` the orchestrator
// itself uses. The former line-for-line `vm_cgroup_name` duplicate here is deleted
// so a future naming change lives in exactly one place and cannot drift silently.

async fn test_metrics_and_limits_impl<V: vmcell::vmm::Vmm>(vmm: &V) {
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

    let env = vmcell::HostEnv::hermetic();
    let mut vm = MicroVm::start(vmm, cfg, &env)
        .await
        .expect("Failed to start VM");

    // Wait a bit for the VM to boot and consume some memory.
    sleep(Duration::from_secs(2)).await;

    let stats_before = vm.usage().await.expect("Failed to get VM stats");

    let cgroup_name = common::computed_cgroup_name(vm.vmid());
    let cg_base = format!("/sys/fs/cgroup/{cgroup_name}");

    // HARD precondition (TESTS-FEATURES-3): the memory controller MUST be delegated to the
    // slice, otherwise the limit assertions cannot run. A missing or `max` `memory.max` is a
    // real misconfiguration of the privileged runner, never a reason to silently pass. (This
    // test is `#[ignore]`d and only runs under the KVM/privileged tier where the capability
    // runner delegates the controllers.)
    let memory_max_path = format!("{cg_base}/memory.max");
    let mem_max_raw = std::fs::read_to_string(&memory_max_path).unwrap_or_else(|e| {
        panic!("memory controller not delegated to {cg_base} ({e}): cannot validate memory limits")
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

    // E1 hard-bound preconditions: a requested memory cap must ALSO disable the swap
    // escape hatch and enable group-OOM, otherwise shmem-backed guest RAM is reclaimed
    // to swap and the cap throttles instead of hard-killing (the empirical E1 bug:
    // host oom_kill stayed 0 while the guest OOM'd itself). These read back the exact
    // values metrics::create_slice must write; a metrics impl that omits them leaves
    // swap.max at "max" and oom.group at "0", turning these asserts red.
    let swap_max_raw = std::fs::read_to_string(format!("{cg_base}/memory.swap.max"))
        .expect("memory.swap.max must exist when the memory controller is delegated");
    assert_eq!(
        swap_max_raw.trim(),
        "0",
        "memory.swap.max must be 0 so the cap hard-bounds shmem-backed guest RAM (E1)"
    );
    let oom_group_raw = std::fs::read_to_string(format!("{cg_base}/memory.oom.group"))
        .expect("memory.oom.group must exist when the memory controller is delegated");
    assert_eq!(
        oom_group_raw.trim(),
        "1",
        "memory.oom.group must be 1 so the OOM kill takes the whole VM cgroup (E1)"
    );

    // With a delegated controller, live usage must be visible (not the silent-zero skip).
    assert!(
        stats_before.mem_current_mib > 0,
        "memory controller delegated but memory.current is 0"
    );
    assert!(stats_before.mem_peak_mib > 0, "Peak memory should be > 0");
    // §7.1 rule 3: the read path must honestly report enforcement. The controller is
    // delegated here (memory.max read back above), so mem_limit_enforced must be true; a
    // read path that never sets the flag leaves it false and this goes red.
    assert!(
        stats_before.mem_limit_enforced,
        "memory controller delegated but ResourceUsage::mem_limit_enforced is false"
    );

    // Test CPU average computation.
    let start_time = std::time::Instant::now();
    let cpu_test_outcome = vm
        .agent(None)
        .await
        .unwrap()
        .exec(vmcell::agent::protocol::ExecRequest::new(vec![
            "sh".into(),
            "-c".into(),
            "timeout 2 md5sum /dev/zero".into(),
        ]))
        .await
        .expect("Failed to run cpu load");

    // We used timeout 2, and md5sum /dev/zero saturates one CPU; the timeout kills it.
    // N-TEST-3: this is a BOUNDED two-value accept, not the loose `137 || 1 || -1`
    // smell. `timeout(1)` exits 124 when it has to send SIGKILL after its own grace
    // window; it exits 128+15=143 when the child dies from the initial SIGTERM it
    // sends first (which of the two occurs is a scheduling race). No other code is
    // accepted, so a command that instead exited 0 (never killed) still reddens.
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
        "CPU usage should be >50% (got {cpu_percent}%, diff {diff_usec} usec over {elapsed}s)"
    );

    // Test OOM-kill (TESTS-FEATURES-1): the host cgroup cap (256 MiB) is the binding limit
    // below the 512 MiB guest RAM, so a runaway allocation trips the HOST OOM killer
    // (memory.events oom_kill). This is the extracted `checks::metrics_mem_limit_ooms` the
    // validator runs (§7) — one implementation of the OOM-observation.
    vmcell_artifact_validator::checks::metrics_mem_limit_ooms(&mut vm)
        .await
        .expect("host cgroup memory cap must be the binding OOM limit");

    // The VMM may already be dead (OOM-killed); tolerate a failed shutdown — Drop still tears
    // down the slice, netns and sockets. We only care that the OOM signal was observed.
    let _ = vm.shutdown().await;
}
