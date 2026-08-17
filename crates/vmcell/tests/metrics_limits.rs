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
    // `metrics::try_apply_limit_at` consults, reached through the one `cgroup_base_from_proc` law
    // rather than a second `/proc/self/cgroup` parse. (The whole-token match is spelled here
    // because `metrics::controller_listed` is private; it is one line and the WHY is that `io`
    // must not match an `ioX`.)
    let base = std::fs::read_to_string("/proc/self/cgroup")
        .ok()
        .and_then(|c| vmcell::metrics::cgroup_base_from_proc(&c))
        .expect("this process must have a cgroup-v2 placement to create a sibling slice under");
    let controllers = std::fs::read_to_string(format!("/sys/fs/cgroup/{base}/cgroup.controllers"))
        .unwrap_or_default();
    let io_delegated = controllers.split_whitespace().any(|c| c == "io");
    println!(
        "cgroup base {base}: controllers [{}], io_delegated={io_delegated}",
        controllers.trim()
    );

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
