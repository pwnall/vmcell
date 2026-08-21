use vmcell::config::{IoMax, ResourceLimits, RootfsSource, VmConfig};
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

/// The host directory holding `vmid`'s cgroup control files. One composition for every leg in
/// this file — the `/sys/fs/cgroup` root joined onto `common::computed_cgroup_name`, which is
/// itself the one naming law. Three legs read control files back, and a second copy of the join
/// is how a test starts reading a path that exists for no VM.
fn cgroup_dir(vmid: u32) -> String {
    format!("/sys/fs/cgroup/{}", common::computed_cgroup_name(vmid))
}

/// CPU usage over `elapsed_secs`, as a percentage of ONE core, from a `cpu.stat`
/// `usage_usec` delta. The single spelling of the conversion every CPU leg here asserts on: the
/// unthrottled leg wants `> 50%` of a core and the quota leg wants "near the quota", and those
/// two claims must be about the same number.
fn cpu_percent_of_one_core(diff_usec: u64, elapsed_secs: f64) -> f64 {
    (diff_usec as f64 / 1_000_000.0) / elapsed_secs * 100.0
}

/// Runs the in-guest CPU saturation load (`md5sum /dev/zero`, killed by `timeout`) and returns
/// the `cpu.stat` delta it produced together with the host-observed wall time it ran for.
///
/// One helper for both CPU legs so "the load" cannot differ between the unthrottled measurement
/// and the quota measurement — a quota leg that ran a *lighter* load would land near the quota for
/// the wrong reason.
///
/// N-TEST-3: the accepted exit codes are a BOUNDED two-value set, not a loose menu. `timeout`
/// exits 124 when it has to SIGKILL after its grace window and 128+15=143 when the child dies
/// from the initial SIGTERM (which of the two occurs is a scheduling race). A load that exited 0
/// — never killed, therefore not saturating — still reddens.
async fn run_cpu_load<V: vmcell::vmm::Vmm>(vm: &mut MicroVm<V>) -> (u64, f64) {
    let before = vm.usage().await.expect("cpu.stat before the load");
    let start = std::time::Instant::now();
    let outcome = vm
        .steward(None)
        .await
        .expect("steward must reach ready")
        .exec(vmcell::steward::protocol::ExecRequest::new(vec![
            "sh".into(),
            "-c".into(),
            "timeout 2 md5sum /dev/zero".into(),
        ]))
        .await
        .expect("Failed to run cpu load");
    assert!(
        outcome.code == 124 || outcome.code == 143,
        "CPU load should be killed by timeout (expected 124 or 143), got code {}",
        outcome.code
    );
    let elapsed = start.elapsed().as_secs_f64();
    let after = vm.usage().await.expect("cpu.stat after the load");
    assert!(
        after.cpu_usec > before.cpu_usec,
        "cpu controller not delegated (cpu_usec did not advance: before={}, after={})",
        before.cpu_usec,
        after.cpu_usec
    );
    (after.cpu_usec - before.cpu_usec, elapsed)
}

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

    // The prefix this VM's cgroup slice is named after, captured before `cfg` moves into
    // `MicroVm::start`: `checks::metrics_mem_limit_ooms` composes the `memory.events` path it
    // reads from it, and takes it as a required argument rather than assuming the default
    // (docs/81 d3).
    let resource_prefix = cfg.resource_prefix.clone();

    let env = vmcell::HostEnv::hermetic();
    let mut vm = MicroVm::start(vmm, cfg, &env)
        .await
        .expect("Failed to start VM");

    // Wait a bit for the VM to boot and consume some memory.
    sleep(Duration::from_secs(2)).await;

    let stats_before = vm.usage().await.expect("Failed to get VM stats");

    let cg_base = cgroup_dir(vm.vmid());

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
    // §7.1 (What is read and enforced) rule 3: the read path must honestly report enforcement. The controller is
    // delegated here (memory.max read back above), so mem_limit_enforced must be true; a
    // read path that never sets the flag leaves it false and this goes red.
    assert!(
        stats_before.mem_limit_enforced,
        "memory controller delegated but ResourceUsage::mem_limit_enforced is false"
    );

    // Test CPU average computation. The load, its bounded exit-code accept and the
    // cpu-controller-delegation precondition all live in `run_cpu_load` — the ONE definition of
    // "the load", shared with the `cpu_max_pct` quota leg below so the throttled measurement is
    // about the same work as this un-throttled one.
    let (diff_usec, elapsed) = run_cpu_load(&mut vm).await;
    let cpu_percent = cpu_percent_of_one_core(diff_usec, elapsed);
    // The VM has 1 vcpu by default, so the ceiling is ~100%. This VM has NO `cpu_max_pct`, so
    // the un-throttled figure is also the baseline the quota leg's ceiling is set against.
    assert!(
        cpu_percent > 50.0,
        "CPU usage should be >50% (got {cpu_percent}%, diff {diff_usec} usec over {elapsed}s)"
    );

    // Test OOM-kill (TESTS-FEATURES-1): the host cgroup cap (256 MiB) is the binding limit
    // below the 512 MiB guest RAM, so a runaway allocation trips the HOST OOM killer
    // (memory.events oom_kill). This is the extracted `checks::metrics_mem_limit_ooms` the
    // validator runs (§7, Resource monitoring and limits) — one implementation of the OOM-observation.
    vmcell_artifact_validator::checks::metrics_mem_limit_ooms(&mut vm, &resource_prefix)
        .await
        .expect("host cgroup memory cap must be the binding OOM limit");

    // The VMM may already be dead (OOM-killed); tolerate a failed shutdown — Drop still tears
    // down the slice, netns and sockets. We only care that the OOM signal was observed.
    let _ = vm.shutdown().await;
}

// docs/90 T1: `cpu_max_pct` — the second of the four `ResourceLimits` fields to get a live boot.
// §7.3's own history is the argument for measuring rather than rendering: `memory.max` alone did
// NOT bind a CH guest until `memory.swap.max=0` and `memory.oom.group=1` joined it, and no amount
// of rendered-string coverage could have produced that fact. `cpu.max`'s enforcement mechanism is
// different again — a per-period quota against a cgroup whose members are the VMM's vcpu and
// device THREADS, not the guest's processes — so "the string is right" says nothing about whether
// a guest burning a core is actually held to a quarter of one.
//
// DATA PLANE, two independent observations: `cpu.max` reads back the exact `(quota, period)` pair
// the requested 25% renders to, and the SAME in-guest load the un-throttled leg above runs
// measures near the quota instead of near a full core.
//
// RED ON THE INVERSE: drop the `cpu.max` write from `metrics::apply_requested_limits` (or let it
// warn-and-continue) and both halves go red — the read-back becomes `max 100000` and the measured
// figure jumps to the >50% the un-throttled leg asserts. The ceiling is deliberately set BELOW
// that leg's floor, so the two legs cannot both be green on a host where the quota is a no-op.
vmm_matrix_test!(metrics_cpu_quota, |vmm| {
    test_cpu_quota_impl(&vmm).await;
});

/// The requested CPU cap, as a percentage of one core.
const CPU_QUOTA_PCT: u32 = 25;

async fn test_cpu_quota_impl<V: vmcell::vmm::Vmm>(vmm: &V) {
    let mut cfg = VmConfig::builder(
        common::get_vmlinux(),
        RootfsSource::Erofs {
            image: common::get_rootfs(),
        },
    )
    .network_disabled()
    .build()
    .unwrap();
    cfg.limits.cpu_max_pct = Some(CPU_QUOTA_PCT);

    let env = vmcell::HostEnv::hermetic();
    let mut vm = MicroVm::start(vmm, cfg, &env)
        .await
        .expect("a 25% cpu quota must not prevent the VM from starting");

    // HARD precondition, same shape as the memory leg above: the cpu controller MUST be delegated
    // to the slice or the quota cannot have been applied. A missing or `max` quota is a real
    // misconfiguration of the privileged runner's scope (run the suite under
    // `systemd-run --user --scope -p Delegate=yes scripts/with-delegated-scope.sh`), never a
    // reason to silently pass.
    let cg_base = cgroup_dir(vm.vmid());
    let cpu_max_path = format!("{cg_base}/cpu.max");
    let cpu_max_raw = std::fs::read_to_string(&cpu_max_path).unwrap_or_else(|e| {
        panic!("cpu controller not delegated to {cg_base} ({e}): cannot validate the cpu quota")
    });
    // 25% of the fixed 100000us period is a 25000us quota. Spelled as the arithmetic rather than
    // as the literal pair, so a change to `CPU_QUOTA_PCT` cannot leave a stale expectation behind.
    let expected = format!("{} 100000", u64::from(CPU_QUOTA_PCT) * 1_000);
    assert_eq!(
        cpu_max_raw.trim(),
        expected,
        "cpu.max must be the {CPU_QUOTA_PCT}% quota pair; a {:?} means the requested limit never \
         reached the kernel",
        cpu_max_raw.trim()
    );

    let (diff_usec, elapsed) = run_cpu_load(&mut vm).await;
    let cpu_percent = cpu_percent_of_one_core(diff_usec, elapsed);
    println!(
        "cpu_max_pct={CPU_QUOTA_PCT}: measured {cpu_percent}% of one core \
         ({diff_usec} usec over {elapsed}s)"
    );
    // The floor proves the load actually ran under the quota (a wedged guest measuring ~0% would
    // otherwise satisfy any ceiling). The ceiling is the enforcement claim: it sits below the
    // un-throttled leg's >50% floor, so a quota that did nothing lands outside it. The band is
    // generous on both sides on purpose — the slice also charges the VMM's own device and API
    // threads, and the guest's `timeout 2` measures guest wall time while the host measures the
    // whole round trip, so the ratio drifts a few points either way between runs.
    assert!(
        cpu_percent > 5.0,
        "the in-guest load must actually consume CPU under the quota (got {cpu_percent}%, \
         {diff_usec} usec over {elapsed}s) — a ~0% reading means the load never ran"
    );
    assert!(
        cpu_percent < 45.0,
        "a {CPU_QUOTA_PCT}% cpu.max quota must hold the slice near the quota, well under the \
         un-throttled >50% this file's other leg measures; got {cpu_percent}% ({diff_usec} usec \
         over {elapsed}s) — the quota is not being enforced"
    );

    vm.shutdown().await.expect("shutdown after the quota load");
}

// docs/90 T1: `pids_max` — the third `ResourceLimits` field, and the one whose subject is easiest
// to get wrong. `pids.max` bounds the **host tasks** in the VM's slice (the VMM's threads), not
// the guest's processes, which the guest kernel accounts for entirely on its own. So the load has
// to come from the host side: a helper shell moves ITSELF into the VM's slice and forks until the
// kernel refuses, exactly as a co-tenant host process sharing the slice would.
//
// DATA PLANE: `pids.events`'s `max` counter — the kernel's own record that it refused a fork
// because of THIS limit — goes from 0 to nonzero, with `pids.max` read back as the requested
// value. `pids.events` is read after the VM is fully up but before the load, as the positive
// control: a booted VM's own threads fit under the cap (`max 0`), so the nonzero afterwards can
// only have come from the saturation.
//
// RED ON THE INVERSE: drop the `pids.max` write from `metrics::apply_requested_limits` and the
// limit reads `max`, all 400 forks succeed, and `pids.events` stays at `max 0` — both halves red.
vmm_matrix_test!(metrics_pids_max, |vmm| {
    test_pids_max_impl(&vmm).await;
});

/// The requested task cap: enough headroom that the limit binds the injected load rather than the
/// VMM itself, and far below the 400 forks that load attempts.
///
/// The figure is MEASURED, not guessed. `pids.peak` on a booted VM (2026-08-17) is 9 for Cloud
/// Hypervisor, 4 for Firecracker, 7 for QEMU and **18 for crosvm** — and *transient* demand during
/// device activation runs higher still: at 32 this leg reddened once in four runs on a loaded host
/// with `Failed to spawn thread for _disk0_q0: Resource temporarily unavailable`, a `NEEDS_RESET`
/// root disk and a guest kernel panic. That is the cap doing its job against the wrong subject: the
/// leg exists to prove the cap binds a *co-tenant*, not to find how close to a VMM's own peak a cap
/// may be set. `pids.peak` is printed below, so the real headroom is visible in every run's output
/// instead of being inferred from this comment.
const PIDS_MAX: u32 = 64;

/// The `max` counter from a cgroup-v2 `pids.events` file — the number of forks the kernel refused
/// because of `pids.max`. Absent file = `None` (the caller turns that into a loud failure).
fn pids_events_max(cg_base: &str) -> Option<u64> {
    let raw = std::fs::read_to_string(format!("{cg_base}/pids.events")).ok()?;
    raw.lines()
        .find_map(|l| l.strip_prefix("max "))
        .and_then(|v| v.trim().parse().ok())
}

async fn test_pids_max_impl<V: vmcell::vmm::Vmm>(vmm: &V) {
    let mut cfg = VmConfig::builder(
        common::get_vmlinux(),
        RootfsSource::Erofs {
            image: common::get_rootfs(),
        },
    )
    .network_disabled()
    .build()
    .unwrap();
    cfg.limits.pids_max = Some(PIDS_MAX);

    let env = vmcell::HostEnv::hermetic();
    let mut vm = MicroVm::start(vmm, cfg, &env)
        .await
        .expect("the pids cap must leave room for the VMM's own threads");

    // ORDERING IS LOAD-BEARING, and MEASURED (2026-08-17): the guest activates virtio-blk lazily,
    // some way into its own boot, and `MicroVm::start` returns as soon as CH accepts the boot API
    // call — so a fork storm launched immediately after `start` collides with CH spawning
    // `_disk0_q0`, which then fails EAGAIN against the very cap under test, wedges the root disk
    // (`NEEDS_RESET`) and times the steward out. Reaching steward-ready FIRST both fixes the
    // collision and is a claim worth making: the cap does not stop a VM from booting.
    let boot_ok = vm
        .steward(Some(Duration::from_secs(60)))
        .await
        .expect("a VM under the pids cap must still reach steward-ready")
        .exec(vmcell::steward::protocol::ExecRequest::new(vec![
            "true".into(),
        ]))
        .await
        .expect("exec on a VM booted under a pids cap");
    assert_eq!(boot_ok.code, 0, "pre-saturation exec failed: {boot_ok:?}");

    // HARD precondition (as with memory/cpu above): the pids controller must be delegated, or the
    // requested cap was never applied.
    let cg_base = cgroup_dir(vm.vmid());
    let pids_max_raw = std::fs::read_to_string(format!("{cg_base}/pids.max")).unwrap_or_else(|e| {
        panic!("pids controller not delegated to {cg_base} ({e}): cannot validate the pids cap")
    });
    assert_eq!(
        pids_max_raw.trim(),
        PIDS_MAX.to_string(),
        "pids.max must be the requested {PIDS_MAX}; a {:?} means the limit never reached the kernel",
        pids_max_raw.trim()
    );

    // Positive control, and the attribution the `> 0` below depends on: a FULLY BOOTED VM's own
    // threads fit under the cap with room to spare, so the counter is still clean here. Any
    // nonzero reading afterwards therefore belongs to the saturation and to nothing the VMM did.
    let before = pids_events_max(&cg_base)
        .expect("pids.events must exist when the pids controller is delegated");
    // Informational, not an assertion: `pids.peak` (Linux 6.1+) is the VMM's real high-water task
    // count, so every run's output records how much headroom `PIDS_MAX` actually left instead of
    // leaving a future reader to trust the constant's comment. Read BEFORE the load, which
    // saturates the cap by design.
    println!(
        "pids_max={PIDS_MAX}: VMM task high-water mark pids.peak={} (pids.current={})",
        std::fs::read_to_string(format!("{cg_base}/pids.peak"))
            .map_or_else(|_| "<unavailable>".to_string(), |s| s.trim().to_string()),
        std::fs::read_to_string(format!("{cg_base}/pids.current"))
            .map_or_else(|_| "<unavailable>".to_string(), |s| s.trim().to_string()),
    );
    assert_eq!(
        before, 0,
        "a booted VM's own threads must fit under the {PIDS_MAX}-task cap for the saturation below \
         to be attributable to the injected load; got {before} refusals already"
    );

    // The load: `/bin/sh` moves itself into the VM's slice (`$$` — writing a literal `0` is a
    // cgroup-v1 idiom the v2 interface rejects with EIO) and then forks background children until
    // the kernel refuses. Reserved exit code 3 = the move failed, which would make the rest
    // vacuous; any other nonzero code is expected, because a shell that cannot fork says so and
    // gives up. The children `sleep 2` rather than blocking forever so the slice is empty again
    // within seconds and teardown's `rmdir` cannot hit EBUSY — a test's own load is residue too.
    let script = format!(
        "echo $$ > {cg_base}/cgroup.procs || exit 3\n\
         i=0\n\
         while [ \"$i\" -lt 400 ]; do sleep 2 & i=$((i+1)); done\n\
         wait\n"
    );
    let out = tokio::process::Command::new("/bin/sh")
        .arg("-c")
        .arg(&script)
        .output()
        .await
        .expect("spawn the fork-storm helper");
    assert_ne!(
        out.status.code(),
        Some(3),
        "the helper could not move itself into {cg_base}/cgroup.procs — the slice is not a \
         cgroup-v2 `domain` this process may migrate into (a threaded systemd scope rejects it), \
         so the saturation below never happened. Run the suite under `systemd-run --user --scope \
         -p Delegate=yes scripts/with-delegated-scope.sh`. stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let after = pids_events_max(&cg_base).expect("pids.events after the fork storm");
    println!("pids_max={PIDS_MAX}: pids.events max {before} -> {after}");
    assert!(
        after > 0,
        "the kernel must have refused at least one fork against the {PIDS_MAX}-task cap \
         (pids.events max is still {after} after 400 attempted forks) — the limit is not being \
         enforced. helper stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Wait out the helper's children so the slice is task-free before teardown deletes it: a
    // `rmdir` of a cgroup that still holds tasks fails EBUSY and leaks the slice, and a test's own
    // load is residue too.
    sleep(Duration::from_millis(2500)).await;

    // `kill`, not `shutdown`: the VM has just had its slice saturated, and a graceful power-off
    // asks the VMM to do more work. Nothing here claims the VMM survives a saturated pids cap —
    // that is the cap doing its job, not a defect — and asserting it would be asserting something
    // the kernel does not promise. The pre-saturation exec above is what proves the cap left room
    // for a working VM; teardown-completeness is `tests/lifecycle.rs`'s residue battery.
    vm.kill().await.expect("kill after the fork storm");
}

// docs/90 T1's SHARP half: `io_max`. Its `device` field is a caller-supplied `"major:minor"`
// string, and until now nothing in the tree ever asked the kernel what it thinks of one — the
// coverage was `render_io_max`'s string. Two things can go wrong with a requested `io.max`, and
// BOTH must be loud, because the alternative is a VM that boots reporting isolation it does not
// have:
//
//   * the `io` controller is not delegated to the slice's parent (the common case in a systemd
//     **user** session: `scripts/with-delegated-scope.sh` warns `controller 'io' not available`
//     and `scripts/review-preflight-priv.sh` prints the delegated set) → the requested limit
//     cannot be applied at all → `CapabilityUnavailable` naming the controller;
//   * the controller IS delegated and the `major:minor` names no whole block device → the kernel's
//     own `blkg_conf_open_bdev` refuses it with `ENODEV` → `Error::Cgroup` ("fix the limit"), not
//     a delegation remediation that would send an operator chasing a cgroup mount that is fine.
//
// Which of the two applies is DECIDED by a measured host fact (`io` in the parent's
// `cgroup.controllers`) and asserted specifically — never "either error will do". So there is no
// arm in which this leg passes without asserting something, and no host on which it silently
// skips.
//
// WHICH ARM RUNS TODAY, measured: the not-delegated one. A default systemd **user** session
// delegates `cpu memory pids` and not `io`, all the way down — the preflight prints
// `root delegates [cpu memory pids]` and `with-delegated-scope.sh` warns `controller 'io' not
// available in this scope` — so the *kernel's* `ENODEV` verdict on a bad `major:minor` stays
// unobserved on this host class, and the arm above is dead code here. It is written and asserted
// anyway because it costs nothing and runs the moment this leg meets a host with `io` delegated
// (a root-level scope, or `systemctl set-property user.slice IODelegate`-style configuration).
//
// Cloud-hypervisor only, and NOT a matrix leg: `create_slice` runs before `Vmm::create`, so the
// refusal is entirely host-side and identical for every backend — a four-backend matrix would
// assert the same host behavior four times.
//
// RED ON THE INVERSE, two ways: (a) let `try_apply_limit_at` warn-and-continue instead of
// returning, and `MicroVm::start` returns `Ok` — the `expect_err` fires; (b) collapse the two
// errno classes onto one variant in `classify_limit_write_err`, and the arm assertion fires. The
// positive control below is what keeps (a) honest: the same config with `io_max` removed MUST
// boot, so the refusal is attributable to the limit and not to anything else in the config.
#[cfg(feature = "cloud-hypervisor")]
#[tokio::test]
#[ignore = "needs KVM (the positive control boots) + a delegated cgroup scope"]
async fn requested_io_max_is_refused_loudly_and_never_silently_unenforced() {
    let vmm = vmcell::vmm::cloud_hypervisor::CloudHypervisor::new(common::ch_bin());

    // A `major:minor` naming no block device on this host. Majors 240–254 are the kernel's LOCAL/
    // experimental range and are unassigned on a normal system; the loop below picks the first one
    // absent from `/sys/dev/block` rather than hard-coding a pair that a future host might use.
    let absent_device = (240..=254u32)
        .map(|major| format!("{major}:0"))
        .find(|dev| !std::path::Path::new(&format!("/sys/dev/block/{dev}")).exists())
        .expect("no unassigned block-device major in 240..=254 on this host");
    println!("io.max device under test (absent on this host): {absent_device}");

    let mk_cfg = |limits: ResourceLimits| {
        let mut cfg = VmConfig::builder(
            common::get_vmlinux(),
            RootfsSource::Erofs {
                image: common::get_rootfs(),
            },
        )
        .network_disabled()
        .build()
        .unwrap();
        cfg.limits = limits;
        cfg
    };

    // Whether the `io` controller is even available to the VM slice's parent — the same file
    // `metrics::try_apply_limit_at` consults, through the ONE measurement `IoDelegation` (below,
    // beside the enforcement leg that asks the same question to decide whether it can run at
    // all). Two spellings of "is `io` delegated?" that disagreed would have this leg asserting the
    // kernel-ENODEV arm while that one recorded an absent facility on the same host.
    let delegation = IoDelegation::measure();
    let io_delegated = delegation.delegated();
    println!("{}", delegation.describe());

    // `ResourceLimits`/`IoMax` are `#[non_exhaustive]`, so an out-of-crate caller assembles them
    // by mutation rather than by struct expression — the same route a real consumer takes.
    let mut bad_io = IoMax::default();
    bad_io.device = absent_device.clone();
    bad_io.wbps = Some(1 << 20);
    let mut bad_limits = ResourceLimits::default();
    bad_limits.io_max = Some(bad_io);

    let env = vmcell::HostEnv::hermetic();
    let err = MicroVm::start(&vmm, mk_cfg(bad_limits), &env)
        .await
        .map(|_| ())
        .expect_err(
            "a requested io.max that cannot be enforced must REFUSE the boot; a VM that starts \
             anyway reports isolation it does not have",
        );
    println!("io.max refusal: {err:?}");

    if io_delegated {
        assert!(
            matches!(err, vmcell::Error::Cgroup(_)),
            "with the `io` controller delegated, an io.max naming no block device is the KERNEL \
             rejecting the caller's value (ENODEV) — that is Error::Cgroup (\"fix the limit\"), \
             not a delegation remediation; got {err:?}"
        );
        assert!(
            err.to_string().contains(&absent_device),
            "the refusal must name the rejected value so an operator can see WHICH device string \
             was wrong; got {err}"
        );
    } else {
        assert!(
            matches!(err, vmcell::Error::CapabilityUnavailable { .. }),
            "without the `io` controller delegated, a requested io.max is an absent host \
             capability, not a bad value; got {err:?}"
        );
        assert!(
            err.to_string().contains("io"),
            "the refusal must name the controller an operator has to delegate; got {err}"
        );
    }

    // POSITIVE CONTROL: the identical config with no `io_max` boots. Without it, a refusal for
    // some unrelated reason (a missing artifact, an unusable scope) would read as a pass.
    let ok = MicroVm::start(&vmm, mk_cfg(ResourceLimits::default()), &env)
        .await
        .expect("positive control: the same config without io_max must boot");
    ok.shutdown().await.expect("shutdown the control VM");
}

// -------------------------------------------------------------------------------------------------
// D5: `io_max`'s ENFORCEMENT half — the cap observed THROTTLING a guest, or a recorded skip
// -------------------------------------------------------------------------------------------------
//
// The refusal leg above proves a requested `io.max` that cannot be applied refuses the boot. What
// it does not prove is the other half of the claim: that an `io.max` which IS applied bounds the
// VM's block I/O. Nothing in the tree measured that (docs/90 T2's "a knob nobody boots is a claim
// nobody makes", recorded in docs/implementation-notes.md as "no leg anywhere measures an `io.max`
// actually *throttling* a guest"), because the controller it needs is not delegated on the host
// class the suite runs on.
//
// So this closes the gap the way AGENTS.md rule 4's SECOND half asks — "cover it or record it" —
// with a record that can change: the leg PROBES the facility and either exercises it or records a
// reviewable capability skip. The shape is `common::probe_ext4_or_record_skip`'s, deliberately,
// including its broken-versus-absent distinction: a host whose `cgroup.controllers` cannot be read
// at all is misconfigured and PANICS, while a host that simply has no `io` there (or no block
// device under its scratch tree) records the skip. The day this suite meets an `io`-delegated
// host on block-backed scratch, the measurement below runs; until then the gap is a line in the
// skip manifest rather than an invisible hole.

/// The `io` controller's availability at the **parent** of every VM slice — measured once, here.
///
/// Two legs in this file need exactly this fact and must not each ask it their own way: the
/// refusal leg decides *which* typed error a bad `io.max` earns from it, and the throttling leg
/// decides whether it can run at all. Two spellings of "is `io` delegated?" that disagree would
/// have one leg asserting the kernel-`ENODEV` arm while the other records an absent facility on
/// the same host, and nothing would notice.
///
/// The parent is this process's own placement: [`vmcell::metrics::vm_slice_name`] composes a VM
/// slice as `{base}/{leaf}`, so `{base}` is the `cgroup.subtree_control` that
/// `metrics::try_apply_limit_at` writes `+io` into — and a controller can only be enabled there if
/// it is listed in that same cgroup's `cgroup.controllers`, which is what this reads.
#[cfg(feature = "cloud-hypervisor")]
struct IoDelegation {
    /// This process's cgroup-v2 placement — the parent of every slice the orchestrator creates.
    base: String,
    /// `{base}/cgroup.controllers`, or the rendered read failure. `Err` is a **broken** host (a
    /// cgroup-v2 placement whose controller listing cannot be read), never an absent facility.
    controllers: Result<String, String>,
}

#[cfg(feature = "cloud-hypervisor")]
impl IoDelegation {
    /// Measures the fact. Panics when this process has no cgroup-v2 placement at all — the
    /// orchestrator could not create a sibling slice either, so there is nothing to be honest
    /// about.
    fn measure() -> Self {
        let base = std::fs::read_to_string("/proc/self/cgroup")
            .ok()
            .and_then(|c| vmcell::metrics::cgroup_base_from_proc(&c))
            .expect("this process must have a cgroup-v2 placement to create a sibling slice under");
        let controllers =
            std::fs::read_to_string(format!("/sys/fs/cgroup/{base}/cgroup.controllers"))
                .map_err(|e| e.to_string());
        Self { base, controllers }
    }

    /// Whether `io` is available to be delegated to a VM slice. A whole-token match — never a
    /// substring — so `io` does not match an `ioX`, matching `metrics::controller_listed` (which
    /// is private, so this one line is spelled here rather than reached).
    fn delegated(&self) -> bool {
        self.controllers
            .as_ref()
            .is_ok_and(|c| c.split_whitespace().any(|t| t == "io"))
    }

    /// The one-line rendering both legs print, so a run's output always records which arm it took.
    fn describe(&self) -> String {
        match &self.controllers {
            Ok(c) => format!(
                "cgroup base {}: controllers [{}], io_delegated={}",
                self.base,
                c.trim(),
                self.delegated()
            ),
            Err(e) => format!(
                "cgroup base {}: cgroup.controllers UNREADABLE ({e})",
                self.base
            ),
        }
    }
}

/// The backend the `io_max` enforcement skips are attributed to.
///
/// Cloud Hypervisor because this battery is CH-only for the same reason the refusal leg is:
/// `create_slice` and the limit writes run before `Vmm::create`, so the behavior is entirely
/// host-side and identical for every backend — a four-backend matrix would assert one host fact
/// four times. Spelled once so the line that is written and any future gate that asserts it was
/// written cannot drift.
#[cfg(feature = "cloud-hypervisor")]
const IO_SKIP_VMM: &str = "cloud-hypervisor";

/// The capability recorded when the `io` controller is not delegated to the VM slice's parent.
#[cfg(feature = "cloud-hypervisor")]
const IO_SKIP_NO_DELEGATION: &str = "io_max_enforcement_no_io_delegation";

/// The capability recorded when the scratch tree is not backed by a block device `io.max` can
/// name — a distinct absence from [`IO_SKIP_NO_DELEGATION`], with a distinct remediation, so the
/// manifest says which one this host hit.
#[cfg(feature = "cloud-hypervisor")]
const IO_SKIP_NO_BLOCK_DEVICE: &str = "io_max_enforcement_no_block_backed_scratch";

/// The **whole** block device backing `path`, as the `major:minor` string `io.max` accepts, or a
/// rendered reason why there is none.
///
/// Whole device, not a partition: the kernel's `blkg_conf_open_bdev` refuses a partition with
/// `ENODEV` (the very errno the refusal leg above classifies), so a cap naming `259:2` would be
/// rejected while the I/O it meant to bound is charged to `259:0`. A partition's parent disk is
/// its sysfs parent — `/sys/dev/block/<maj>:<min>` is a symlink into `/sys/devices/…`, so `..`
/// resolves to the containing disk directory and its `dev` file is that disk's devno. The blkcg
/// counters agree with this choice: bios are charged to the whole disk's request queue, which is
/// why the vacuity guard below can read `io.stat` under the same key it capped.
///
/// An anonymous device (`major == 0`: tmpfs, overlayfs, btrfs' virtual devno) is the common answer
/// on this suite's usual host — `std::env::temp_dir()` is a tmpfs there — and is an absent
/// facility, not a broken host.
#[cfg(feature = "cloud-hypervisor")]
fn whole_block_device_of(path: &std::path::Path) -> Result<String, String> {
    use std::os::unix::fs::MetadataExt as _;
    let dev = std::fs::metadata(path)
        .map_err(|e| format!("stat {}: {e}", path.display()))?
        .dev();
    let (major, minor) = (libc::major(dev), libc::minor(dev));
    if major == 0 {
        return Err(format!(
            "{} sits on an anonymous device ({major}:{minor}) — a tmpfs/overlay/btrfs placement \
             has no block device for io.max to name",
            path.display()
        ));
    }
    let sys = format!("/sys/dev/block/{major}:{minor}");
    if !std::path::Path::new(&sys).exists() {
        return Err(format!(
            "{} is on {major}:{minor}, which has no {sys} entry",
            path.display()
        ));
    }
    if std::path::Path::new(&format!("{sys}/partition")).exists() {
        return std::fs::read_to_string(format!("{sys}/../dev"))
            .map(|d| d.trim().to_string())
            .map_err(|e| {
                format!("{major}:{minor} is a partition whose parent disk's dev is unreadable: {e}")
            });
    }
    Ok(format!("{major}:{minor}"))
}

/// **The one law** the enforcement leg asks before it boots anything: `Some(device)` — the
/// `major:minor` to cap — when this host can actually enforce an `io.max`, and `None`, after
/// recording a reviewable capability skip, when it cannot.
///
/// Two independent facilities have to be present, and the manifest names which one was missing:
/// the `io` controller delegated to the VM slice's parent, and a scratch tree on a block device.
/// Both absences are recorded rather than printed — a `println!("SKIP") + return` is a green PASS
/// (AGENTS.md), and the skip manifest is the only artifact a reviewer can read afterwards to see
/// that the `io_max` enforcement claim went unverified on this run.
///
/// A cgroup-v2 placement whose `cgroup.controllers` cannot be read is a **misconfiguration**, not
/// an absent facility, and panics — the same distinction `common::classify_ext4_refusal` draws
/// between a producer that is absent and one that is broken.
#[cfg(feature = "cloud-hypervisor")]
#[must_use]
fn probe_io_enforcement_or_record_skip(scratch: &std::path::Path) -> Option<String> {
    let delegation = IoDelegation::measure();
    println!("{}", delegation.describe());
    if let Err(e) = &delegation.controllers {
        panic!(
            "this process has a cgroup-v2 placement ({}) whose cgroup.controllers cannot be read \
             ({e}) — that is a broken cgroup mount, not an absent facility; fix the host rather \
             than skipping the io_max enforcement gate",
            delegation.base
        );
    }
    if !delegation.delegated() {
        common::record_capability_skip(IO_SKIP_VMM, IO_SKIP_NO_DELEGATION);
        println!(
            "SKIP: the `io` controller is not delegated to {} (a default systemd USER session \
             delegates cpu/memory/pids only), so no io.max written to a VM slice can bind. Run \
             this suite in a scope whose ancestors all enable `io` in cgroup.subtree_control.",
            delegation.base
        );
        return None;
    }
    match whole_block_device_of(scratch) {
        Ok(device) => {
            println!(
                "io.max enforcement device (whole disk under {}): {device}",
                scratch.display()
            );
            Some(device)
        }
        Err(why) => {
            common::record_capability_skip(IO_SKIP_VMM, IO_SKIP_NO_BLOCK_DEVICE);
            println!(
                "SKIP: {why} — io.max throttles requests to a named block device, so this leg \
                 needs its disk images on one. Point TMPDIR at a directory on a real disk to \
                 exercise it."
            );
            None
        }
    }
}

/// The write-bandwidth cap the throttled boot requests, in bytes per second.
///
/// 4 MiB/s against [`IO_WRITE_MIB`] of guest writes floors the throttled run at 8 s — an order of
/// magnitude above what the same write costs un-throttled on any disk this suite runs on, so the
/// differential below does not depend on the host's raw speed.
#[cfg(feature = "cloud-hypervisor")]
const IO_MAX_WBPS: u64 = 4 << 20;

/// How much the guest writes to its extra disk, in MiB. See [`IO_MAX_WBPS`].
#[cfg(feature = "cloud-hypervisor")]
const IO_WRITE_MIB: u64 = 32;

/// The `io.stat` line for `device` under `cg_base`, or `None` when the device has no line yet.
///
/// Test-side rather than through `metrics::parse_io_stat_bytes`: that helper is private AND sums
/// every device's counters, while the whole point here is the ONE device the cap named — a sum
/// would count the root disk's traffic and hide a cap that bound nothing.
#[cfg(feature = "cloud-hypervisor")]
fn io_stat_line(cg_base: &str, device: &str) -> Option<String> {
    let raw = std::fs::read_to_string(format!("{cg_base}/io.stat")).ok()?;
    raw.lines()
        .find(|l| l.split_whitespace().next() == Some(device))
        .map(str::to_string)
}

/// A `key=value` counter off one `io.stat` (or `io.max`) line, `None` when the key is absent.
#[cfg(feature = "cloud-hypervisor")]
fn io_counter(line: &str, key: &str) -> Option<u64> {
    line.split_whitespace()
        .find_map(|f| f.strip_prefix(&format!("{key}=")))
        .and_then(|v| v.parse().ok())
}

/// KVM-FREE gate for the three host laws the enforcement leg's measurement rests on, so they are
/// falsifiable **today** rather than only on the first `io`-delegated host the suite ever meets.
///
/// The leg above can only run where the facility exists; these three helpers decide what it caps
/// and what it reads back, and a wrong answer from any of them turns the vacuity guard into a
/// green pass — `io.max` silently applied to a partition (which the kernel refuses with `ENODEV`),
/// or a `wbytes` picked off the *wrong* device's line while the capped device moved nothing.
/// Nothing about them needs KVM, a VM, or a delegated controller, so they are gated here, in
/// `just test-unit`'s reach.
#[cfg(feature = "cloud-hypervisor")]
#[test]
fn the_io_max_enforcement_probe_resolves_whole_disks_and_per_device_counters() {
    use std::os::unix::fs::MetadataExt as _;

    // (1) `whole_block_device_of` against this host's REAL layout. The source devno is reserved
    // BEFORE the call so the partition arm's `assert_ne!` is non-vacuous.
    let here = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let dev = std::fs::metadata(here)
        .expect("stat the crate directory")
        .dev();
    let source = format!("{}:{}", libc::major(dev), libc::minor(dev));
    println!("crate dir {} sits on {source}", here.display());
    match whole_block_device_of(here) {
        // The only honest refusal is an anonymous device: a checkout on tmpfs/overlay/btrfs has
        // no block device at all. A refusal for a real one would silently skip the whole battery.
        Err(why) => assert_eq!(
            libc::major(dev),
            0,
            "{source} is a real block device, so the probe must resolve it rather than refuse: {why}"
        ),
        Ok(resolved) => {
            assert!(
                !std::path::Path::new(&format!("/sys/dev/block/{resolved}/partition")).exists(),
                "the probe resolved {source} to {resolved}, which is a PARTITION — the kernel's                  blkg_conf_open_bdev refuses those with ENODEV, so the cap would never apply"
            );
            assert!(
                std::path::Path::new(&format!("/sys/dev/block/{resolved}/dev")).exists(),
                "the probe resolved {source} to {resolved}, which is no block device at all"
            );
            if std::path::Path::new(&format!("/sys/dev/block/{source}/partition")).exists() {
                assert_ne!(
                    resolved, source,
                    "{source} is a partition and must resolve to its parent disk"
                );
            } else {
                assert_eq!(
                    resolved, source,
                    "a whole disk is its own answer; the probe must not walk past it"
                );
            }
        }
    }

    // (2) The counter readers, against a fixture `io.stat`. Both decoys exist because both wrong
    // implementations are the natural ones: a `contains` device match (`1259:0` carries `259:0` as
    // a substring) and a `contains` key match (`rwbytes=` carries `wbytes=`).
    let tmp = common::TempTree::create(&format!("vmcell-test-iostat-{}", std::process::id()));
    std::fs::write(
        tmp.join("io.stat"),
        "1259:0 rbytes=11 wbytes=7 rios=1 wios=1\n\
         259:0 rbytes=1024 rwbytes=99 wbytes=4096 rios=2 wios=3\n\
         8:0 rbytes=5 wbytes=6 rios=1 wios=1\n",
    )
    .expect("write the io.stat fixture");
    let base = tmp.path().to_str().expect("scratch path is UTF-8");
    let line = io_stat_line(base, "259:0").expect("the fixture has a 259:0 line");
    assert_eq!(
        io_counter(&line, "wbytes"),
        Some(4096),
        "wbytes must come from the capped device's own line, whole-key: {line:?}"
    );
    assert_eq!(
        io_stat_line(base, "8:0")
            .as_deref()
            .and_then(|l| io_counter(l, "wbytes")),
        Some(6),
        "each device's counters are its own"
    );
    assert_eq!(
        io_stat_line(base, "7:0"),
        None,
        "a device with no line has no counters — the enforcement leg reads that as zero charged"
    );
    // `tmp` owns the fixture and drops here, on the panic path too.
}

/// Times one in-guest write of [`IO_WRITE_MIB`] MiB to `/dev/vdb`, returning the exec outcome and
/// the host-observed wall time.
///
/// `oflag=direct` so the guest's own page cache cannot absorb the writes and hand virtio-blk a
/// handful of coalesced requests, and `conv=fsync` so `dd` does not return until the guest has
/// issued a FLUSH and the VMM's `fsync` has pushed every byte through the host block layer — which
/// is where `io.max` bills them. Without the flush the measurement would time a memcpy into the
/// host page cache and pass against an absent cap.
#[cfg(feature = "cloud-hypervisor")]
async fn timed_guest_write<V: vmcell::vmm::Vmm>(
    vm: &mut MicroVm<V>,
) -> (vmcell::ExecOutcome, u128) {
    let steward = vm
        .steward(Some(Duration::from_secs(120)))
        .await
        .expect("steward must reach ready");
    let start = std::time::Instant::now();
    let out = steward
        .exec(vmcell::steward::protocol::ExecRequest::new(vec![
            "dd".to_string(),
            "if=/dev/zero".to_string(),
            "of=/dev/vdb".to_string(),
            "bs=1M".to_string(),
            format!("count={IO_WRITE_MIB}"),
            "oflag=direct".to_string(),
            "conv=fsync".to_string(),
        ]))
        .await
        .expect("in-guest dd to the extra disk");
    (out, start.elapsed().as_millis())
}

// The DIFFERENTIAL, one variable: two boots of a byte-identical config that differ in exactly
// `cfg.limits.io_max` and nothing else — same kernel, same rootfs, same extra disk built the same
// way on the same filesystem, same workload. The un-capped boot is the twin the capped one is
// measured against, so a host whose disk is slow reddens neither leg.
//
// THREE assertions, none of which a passing run can skip:
//   1. `io.max` read back off the VM's own slice carries the requested `wbps=` for the capped
//      device — the kernel accepted the value (a cgroup value read back, not a proxy signal).
//   2. `io.stat`'s `wbytes` for that device advanced by most of what the guest wrote. This is the
//      VACUITY GUARD: if the writes were never charged to this cgroup and this device — a host
//      page cache that swallowed them, cgroup writeback not attributing to the slice — then the
//      timing below means nothing, and the leg must go RED rather than pass on a number it did
//      not earn.
//   3. The capped write took at least half its theoretical floor AND several times the twin's.
//
// RED ON THE INVERSE: raise `IO_MAX_WBPS` far above the host's disk speed (or drop the `io.max`
// write from `metrics::apply_limits`) and assertion 3 fires — the capped write finishes in the
// twin's time. Drop the `conv=fsync` and assertion 2 fires instead, which is the point of having
// it: the leg refuses to report a throttle it did not observe.
//
// NOT MEASURED ANYWHERE YET (2026-08-21, stated rather than implied): every host this suite has
// run on takes the skip — `io` is delegated to no default systemd user session, and
// `std::env::temp_dir()` is a tmpfs. The numbers above are derived from the cap, not from an
// observed run, and the first `io`-delegated host to run this is what turns them into measurements.
#[cfg(feature = "cloud-hypervisor")]
#[tokio::test]
#[ignore = "needs KVM + an `io`-delegated cgroup scope over block-backed scratch"]
async fn a_requested_io_max_actually_throttles_the_guests_block_io() {
    // OWNED (`common::TempTree`): removed on the success path AND on every panicking assertion
    // below, which matters more here than usual — this leg writes two 64 MiB images, and a leaked
    // fixture tree is what once filled this host's /tmp and reddened an unrelated suite.
    let tmp = common::TempTree::create(&format!(
        "vmcell-test-iomax-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock at or after the epoch")
            .as_nanos()
    ));

    // Probe BEFORE writing anything: on a host that takes the skip this leg costs an empty
    // directory rather than 128 MiB of tmpfs.
    let Some(device) = probe_io_enforcement_or_record_skip(tmp.path()) else {
        return;
    };

    // Two images, built identically, so the only thing that differs between the boots is the cap.
    let image_bytes = usize::try_from(IO_WRITE_MIB << 21).expect("image size fits usize");
    let baseline_img = tmp.join("baseline.raw");
    let capped_img = tmp.join("capped.raw");
    for img in [&baseline_img, &capped_img] {
        std::fs::write(img, vec![0u8; image_bytes]).expect("write the extra-disk image");
    }

    let vmm = vmcell::vmm::cloud_hypervisor::CloudHypervisor::new(common::ch_bin());
    let env = vmcell::HostEnv::hermetic();
    let mk_cfg = |image: &std::path::Path, io_max: Option<IoMax>| {
        let mut cfg = VmConfig::builder(
            common::get_vmlinux(),
            RootfsSource::Erofs {
                image: common::get_rootfs(),
            },
        )
        .with_extra_disk(vmcell::config::BlockDevice::read_write(image))
        .network_disabled()
        .build()
        .unwrap();
        cfg.limits.io_max = io_max;
        cfg
    };

    // The twin: same everything, no cap.
    let mut baseline = MicroVm::start(&vmm, mk_cfg(&baseline_img, None), &env)
        .await
        .expect("the un-capped twin must boot");
    let (baseline_out, baseline_ms) = timed_guest_write(&mut baseline).await;
    assert_eq!(
        baseline_out.code, 0,
        "the un-capped write failed (does this guest's dd support oflag=direct?): {baseline_out:?}"
    );
    baseline.kill().await.expect("kill the un-capped twin");

    // The capped boot. `IoMax` is `#[non_exhaustive]`, so it is assembled by mutation — the same
    // route an out-of-crate caller takes.
    let mut io = IoMax::default();
    io.device = device.clone();
    io.wbps = Some(IO_MAX_WBPS);
    let mut capped = MicroVm::start(&vmm, mk_cfg(&capped_img, Some(io)), &env)
        .await
        .expect("a VM under an enforceable io.max must boot");
    let cg_base = cgroup_dir(capped.vmid());

    // (1) The kernel accepted the requested value, on the device we asked for.
    let rule = std::fs::read_to_string(format!("{cg_base}/io.max"))
        .unwrap_or_else(|e| panic!("io controller not delegated to {cg_base} ({e})"))
        .lines()
        .find(|l| l.split_whitespace().next() == Some(device.as_str()))
        .map(str::to_string)
        .unwrap_or_else(|| panic!("{cg_base}/io.max carries no rule for {device}"));
    assert_eq!(
        io_counter(&rule, "wbps"),
        Some(IO_MAX_WBPS),
        "io.max must carry the requested wbps for {device}; got {rule:?}"
    );

    let before = io_stat_line(&cg_base, &device)
        .and_then(|l| io_counter(&l, "wbytes"))
        .unwrap_or(0);
    let (capped_out, capped_ms) = timed_guest_write(&mut capped).await;
    assert_eq!(
        capped_out.code, 0,
        "the capped write failed: {capped_out:?}"
    );
    let after = io_stat_line(&cg_base, &device)
        .and_then(|l| io_counter(&l, "wbytes"))
        .unwrap_or(0);

    let written = IO_WRITE_MIB << 20;
    println!(
        "io.max wbps={IO_MAX_WBPS} on {device}: {IO_WRITE_MIB} MiB written — capped {capped_ms}ms \
         vs un-capped {baseline_ms}ms; io.stat wbytes {before} -> {after}"
    );

    // (2) VACUITY GUARD: the bytes were charged to THIS slice on THAT device, so the time above
    // is the time of throttled block I/O and not of a memcpy into the host page cache.
    assert!(
        after.saturating_sub(before) >= written / 2,
        "only {} of the {written} bytes the guest wrote were charged to {device} in \
         {cg_base}/io.stat — the write never reached the block layer from this cgroup, so the \
         {capped_ms}ms below measures nothing about io.max (cgroup writeback needs the memory \
         controller on the same slice and a filesystem that supports it)",
        after.saturating_sub(before)
    );

    // (3) The cap bound the writes. Floor: `written / IO_MAX_WBPS` seconds is the theoretical
    // minimum; half of it leaves room for the bucket's initial fill and for whatever the guest
    // flushed before `dd` started timing, while staying far above the twin.
    let floor_ms = u128::from(written * 1000 / IO_MAX_WBPS / 2);
    assert!(
        capped_ms >= floor_ms,
        "{IO_WRITE_MIB} MiB at {IO_MAX_WBPS} B/s cannot complete in {capped_ms}ms (floor \
         {floor_ms}ms) — the io.max limit did not take effect"
    );
    assert!(
        capped_ms > baseline_ms.saturating_mul(3),
        "the capped write ({capped_ms}ms) must be far slower than the un-capped twin \
         ({baseline_ms}ms) on this same host"
    );

    capped.kill().await.expect("kill the capped VM");
    // No trailing removal: `tmp` owns the images and drops here (and on any panic above).
}
