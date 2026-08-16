//! v33 delta 5's live battery (design §15.4, "the service-steward set"): the steward running as a
//! **service** under somebody else's init, which is the capability R1's placement predicate only
//! made expressible.
//!
//! Every leg here needs a real guest, and the reason is structural rather than incidental. `FakeVmm`
//! never runs the steward at all; the crate's own unit suite runs it in the host's process, where
//! there is no PID 1, no `pivot_root`, and no second init for an orphan to reparent to. The three
//! facts this delta turns on — `PR_SET_CHILD_SUBREAPER`, the per-mode SIGTERM policy, and
//! mini-init's restart — are each invisible to everything except a booted guest.
//!
//! The init is `mini-init` (§3.5): live-validating `Service` requires an init that is *not* the
//! steward, and neither the pinned minimal base (no systemd binary at all) nor CI can supply one.
//! It assembles the root through the steward library's own `assemble_guest_root`, so a cell here
//! differs from a `Pid1` cell in exactly one variable — who is PID 1.
//!
//! **`.steward_placement(...)` is not optional on any leg that wants a control plane.** Delta 4
//! derives `StewardPlacement::None` from `init: Some`, so a mini-init cell that names no placement
//! fails loud in `steward()` before any transport, and the leg would go red on the placement
//! message rather than on the mechanism under test.
//!
//! CH-only, like `tests/custom_init.rs` and the echo-server-as-`init=` leg: this is a guest-side
//! property reached through a host-side cmdline feature, so one primary-backend data-plane proof
//! suffices, and QEMU's external vsock-daemon bring-up would only add non-standard-boot flake.
//!
//! **These legs mean nothing against a stale rootfs.** `mini-init` is baked into `rootfs.erofs`;
//! run `vmcell build --kernel-source host-make` after any change to `vmcell-guest-tools` or
//! `vmcell-steward`, or the guest boots an image whose `/vmcell-tools/mini-init` does not exist.

#![cfg(feature = "cloud-hypervisor")]

use std::time::Duration;

use vmcell::config::{KernelVerbosity, RootfsSource, StewardPlacement, VmConfig};
use vmcell::steward::{ExecRequest, SessionSpecBuilder};

mod common;

/// The applet path the rootfs injection manifest emits for the `mini-init` roster entry.
const MINI_INIT: &str = "/vmcell-tools/mini-init";

/// Prints the pid of the running steward, or nothing if there is none.
///
/// `/proc/<pid>/comm` rather than `pidof`/`pgrep`: the pinned base ships neither, and this is the
/// same procfs read the steward's own tests make — a real observation, not a shim.
const STEWARD_PID_SH: &str = "for p in /proc/[0-9]*; do \
     [ \"$(cat \"$p/comm\" 2>/dev/null)\" = vmcell-steward ] && echo \"${p#/proc/}\"; \
     done";

/// Boots a cell whose PID 1 is `mini-init`, with the steward declared as a service.
///
/// `port` is the declared vsock port. Passing a non-default one exercises the full
/// `vmcell_steward_port=` path — emitted by the host cmdline builder, dialed by
/// `VsockEndpoint::with_port`, and (as of this delta) actually **bound** by the guest.
async fn boot_service_cell(
    vmm: &vmcell::vmm::cloud_hypervisor::CloudHypervisor,
    port: u32,
) -> vmcell::MicroVm<vmcell::vmm::cloud_hypervisor::CloudHypervisor> {
    let cfg = VmConfig::builder(
        common::get_vmlinux(),
        RootfsSource::Erofs {
            image: common::get_rootfs(),
        },
    )
    .init(MINI_INIT)
    .steward_placement(StewardPlacement::Service { port })
    .kernel_verbosity(KernelVerbosity::Verbose)
    .network_disabled()
    .build()
    .expect("Service composes with a custom init — only Pid1+init is the contradiction");

    common::start_vm(vmm, cfg).await
}

/// Boots an ordinary `Pid1` cell: the twin every `Service` leg here is compared against.
async fn boot_pid1_cell(
    vmm: &vmcell::vmm::cloud_hypervisor::CloudHypervisor,
) -> vmcell::MicroVm<vmcell::vmm::cloud_hypervisor::CloudHypervisor> {
    let cfg = VmConfig::builder(
        common::get_vmlinux(),
        RootfsSource::Erofs {
            image: common::get_rootfs(),
        },
    )
    .kernel_verbosity(KernelVerbosity::Verbose)
    .network_disabled()
    .build()
    .expect("naming no placement derives Pid1");

    common::start_vm(vmm, cfg).await
}

/// Runs one `sh -c` in the guest, tolerating a severed cached client.
///
/// The retry is not flake-padding: when a leg SIGTERMs the steward, the request in flight dies with
/// it and marks the cached client desynced, so the *next* `MicroVm::steward` evicts and re-dials
/// (the M7 eviction). Without a retry, the first call after a restart would fail on the corpse of
/// the previous connection and the leg would report the wrong cause.
async fn sh<V: vmcell::vmm::Vmm>(
    vm: &mut vmcell::MicroVm<V>,
    script: &str,
) -> vmcell::steward::ExecOutcome {
    let mut last = String::new();
    for attempt in 0..30 {
        match vm.steward(Some(Duration::from_secs(30))).await {
            Ok(client) => {
                let req = ExecRequest::new(vec!["/bin/sh".into(), "-c".into(), script.into()])
                    // Well past any leg's lifetime: `handle_exec` always arms a kill thread that
                    // SIGKILLs the child's PROCESS GROUP at the deadline, and a backgrounded
                    // payload inherits that group — the default 10 s would reap the very orphan
                    // some of these legs exist to observe.
                    .with_timeout(Duration::from_secs(600));
                match client.exec(req).await {
                    Ok(out) => return out,
                    Err(e) => last = format!("exec: {e}"),
                }
            }
            Err(e) => last = format!("steward: {e}"),
        }
        tokio::time::sleep(Duration::from_millis(500 * (attempt.min(4) + 1))).await;
    }
    panic!("`sh -c {script:?}` never succeeded; last error: {last}");
}

/// The trimmed stdout of one guest command.
async fn sh_out<V: vmcell::vmm::Vmm>(vm: &mut vmcell::MicroVm<V>, script: &str) -> String {
    let out = sh(vm, script).await;
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// Polls the serial log until it contains `needle`, or fails naming what it was waiting for.
async fn await_serial<V: vmcell::vmm::Vmm>(
    vm: &vmcell::MicroVm<V>,
    needle: &str,
    within: Duration,
) -> String {
    let log = vmcell::vmm::VmInstance::serial_log(vm.instance()).to_path_buf();
    let deadline = std::time::Instant::now() + within;
    let mut last = String::new();
    while std::time::Instant::now() < deadline {
        if let Ok(content) = tokio::fs::read_to_string(&log).await {
            if content.contains(needle) {
                return content;
            }
            last = content;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let tail: String = last
        .chars()
        .skip(last.chars().count().saturating_sub(4000))
        .collect();
    panic!(
        "serial log never contained {needle:?} within {within:?} (log {}); tail:\n{tail}",
        log.display(),
    );
}

/// Polls the serial log until `needle` appears at least `want` times.
///
/// Distinct from [`await_serial`] because "it happened again" is a different question from "it
/// happened", and conflating them is a race: waiting for `"restarting it"` and *then* counting the
/// starts reads the log in the window between mini-init announcing the restart and the restarted
/// program announcing itself. That race fired on the first plant run and reported the wrong cause.
async fn await_serial_count<V: vmcell::vmm::Vmm>(
    vm: &vmcell::MicroVm<V>,
    needle: &str,
    want: usize,
    within: Duration,
) -> String {
    let log = vmcell::vmm::VmInstance::serial_log(vm.instance()).to_path_buf();
    let deadline = std::time::Instant::now() + within;
    let mut seen = 0;
    let mut last = String::new();
    while std::time::Instant::now() < deadline {
        if let Ok(content) = tokio::fs::read_to_string(&log).await {
            seen = content.matches(needle).count();
            if seen >= want {
                return content;
            }
            last = content;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let tail: String = last
        .chars()
        .skip(last.chars().count().saturating_sub(4000))
        .collect();
    panic!(
        "serial log contained {needle:?} {seen} time(s), wanted {want}, within {within:?} \
         (log {}); tail:\n{tail}",
        log.display(),
    );
}

// -----------------------------------------------------------------------------------------------
// Leg 1 — `PR_SET_CHILD_SUBREAPER`, the difference that would otherwise be silent.
// -----------------------------------------------------------------------------------------------

/// Spawns an orphan in the guest and returns `(orphan pid, its PPid, the steward's pid)`.
///
/// The orphan is real: an inner shell writes its own pid, `exec`s a long sleep, and its parent
/// exits immediately — so by the time we read `/proc`, the inner process has been re-parented by
/// the kernel to whichever ancestor claims it.
async fn orphan_reparenting<V: vmcell::vmm::Vmm>(vm: &mut vmcell::MicroVm<V>) -> (u32, u32, u32) {
    // `</dev/null >/dev/null 2>&1` on the background job is load-bearing, not tidiness:
    // `handle_exec` joins both output pumps before it replies, and a backgrounded process that
    // inherits the exec's stdout pipe holds it open — so the reply would never arrive and the leg
    // would read as a hang rather than as a result. (It did, on the first live run.)
    let orphan: u32 = sh_out(
        vm,
        "sh -c 'echo $$ > /tmp/vmcell-orphan.pid; exec sleep 6000' \
           </dev/null >/dev/null 2>&1 & \
         sleep 1; cat /tmp/vmcell-orphan.pid",
    )
    .await
    .parse()
    .expect("the guest must report the orphan's pid");

    let ppid: u32 = sh_out(
        vm,
        &format!("sed -n 's/^PPid:[^0-9]*//p' /proc/{orphan}/status"),
    )
    .await
    .parse()
    .unwrap_or_else(|e| panic!("orphan {orphan} must still exist and report a PPid: {e}"));

    let steward: u32 = sh_out(vm, STEWARD_PID_SH)
        .await
        .parse()
        .expect("exactly one steward must be running");

    (orphan, ppid, steward)
}

/// **An orphaned descendant re-parents to the steward under BOTH placements.**
///
/// One law, two placements, and the two halves are true for different reasons — which is exactly
/// why this is the leg that proves the bit rather than a hang test. Under `Pid1` the steward *is*
/// pid 1, so every orphan reparents to it by definition and nothing needs setting. Under `Service`
/// it holds only because [`vmcell_steward::run`] sets `PR_SET_CHILD_SUBREAPER`; without the bit the
/// orphan reparents to **mini-init** instead and the assertion reads `PPid == 1 != steward`.
///
/// RED ON INVERSE: delete the `set_child_subreaper` call and the `Service` half fails with both pids
/// printed, naming mini-init as the claimant. It **fails** rather than hanging, which is the point —
/// §18 delta 5 sketches this leg as a hang bounded by the harness timeout, and a stalled leg is
/// indistinguishable from a slow box. The observable moved; the property did not.
///
/// (Recorded with it: `exec`'s own return does **not** depend on the bit. The steward waits on its
/// DIRECT child, which it reaps in either placement — so a double-forking payload's exit code comes
/// back with or without the subreaper, and a leg asserting only that would have been theater. What
/// the bit decides is who inherits the *grandchild*, which is what this asserts.)
#[tokio::test]
#[ignore = "needs KVM"]
async fn an_orphan_reparents_to_the_steward_under_service_placement() {
    let vmm = vmcell::vmm::cloud_hypervisor::CloudHypervisor::new(common::ch_bin());
    let mut vm = boot_service_cell(&vmm, vmcell_protocol::STEWARD_VSOCK_PORT).await;

    let (orphan, ppid, steward) = orphan_reparenting(&mut vm).await;
    assert_ne!(
        steward, 1,
        "under a Service placement the steward must NOT be pid 1 — mini-init is. If this fails, \
         the cell booted the steward directly and the leg below would pass vacuously."
    );
    assert_eq!(
        ppid, steward,
        "PR_SET_CHILD_SUBREAPER: orphan {orphan} must re-parent to the steward ({steward}), not to \
         mini-init (1). PPid={ppid} means the bit is not set, so the steward no longer sees the \
         descendants a Pid1 steward reaps by definition."
    );

    // The double-forking payload still returns its exit code — the liveness half of the design's
    // sketch, kept because it is worth pinning, but NOT presented as the subreaper's gate.
    let out = sh(&mut vm, "( sleep 0.2; exit 42 ) & exit 7").await;
    assert_eq!(
        out.code, 7,
        "exec reports the DIRECT child's exit code, in either placement"
    );

    vm.kill().await.unwrap();
}

/// The `Pid1` twin of the leg above: the same assertion, the placement that needs no `prctl`.
///
/// Pairing them is what makes the `Service` assertion about *placement*: without this control a
/// shell that silently failed to orphan anything would leave the `Service` leg green and the bit
/// untested.
#[tokio::test]
#[ignore = "needs KVM"]
async fn the_pid1_twin_reparents_the_same_orphan_without_a_subreaper_bit() {
    let vmm = vmcell::vmm::cloud_hypervisor::CloudHypervisor::new(common::ch_bin());
    let mut vm = boot_pid1_cell(&vmm).await;

    let (orphan, ppid, steward) = orphan_reparenting(&mut vm).await;
    assert_eq!(steward, 1, "under Pid1 the steward IS pid 1");
    assert_eq!(
        ppid, steward,
        "orphan {orphan} must re-parent to the steward; under Pid1 that is the kernel's own \
         definition and needs no prctl"
    );

    vm.kill().await.unwrap();
}

// -----------------------------------------------------------------------------------------------
// Leg 2 — the SIGTERM policy, both directions, and mini-init's restart.
// -----------------------------------------------------------------------------------------------

/// SIGTERM to a **service** steward tears down live sessions per law C3, exits cleanly, and
/// mini-init brings it back — so the guest stays up and a later `exec` works.
///
/// Three assertions in one leg because they are one causal chain, and splitting them would mean
/// three guest boots to prove one policy:
///
/// 1. **C3 residue is gone.** The victim is a *session* payload, deliberately: a session with no
///    timeout is persistent (no kill thread), it runs in its own process group, and sessions are
///    what law C3 is about. Before v33 the teardown was reachable only from `serve_connection`'s
///    own exit path, so a SIGTERM-driven shutdown had no way to reach a per-connection table at
///    all — `ConnectionRegistry` is what closes that.
/// 2. **The exit is clean, not a power-off.** A `Pid1` SIGTERM policy applied here would power the
///    machine off; the guest staying up *is* the assertion that the policy is placement-scoped.
/// 3. **mini-init restarts it**, which is what makes the whole leg satisfiable — §3.5 says so, and
///    it is why the applet restarts rather than merely supervising.
#[tokio::test]
#[ignore = "needs KVM"]
async fn sigterm_to_a_service_steward_tears_down_sessions_exits_and_is_restarted() {
    let vmm = vmcell::vmm::cloud_hypervisor::CloudHypervisor::new(common::ch_bin());
    let mut vm = boot_service_cell(&vmm, vmcell_protocol::STEWARD_VSOCK_PORT).await;

    // A persistent session holding a long-lived payload. `SessionSpecBuilder` with no `timeout` is
    // the documented persistent form, so nothing but law C3 will ever kill this process group.
    let mux = vm
        .connect_sessions(Some(Duration::from_secs(30)))
        .await
        .expect("a Service cell's session mux must connect");
    let _session = mux
        .open(
            SessionSpecBuilder::new(vec![
                "/bin/sh".into(),
                "-c".into(),
                "echo $$ > /tmp/vmcell-c3.pid; exec sleep 6000".into(),
            ])
            .build(),
        )
        .await
        .expect("the session must open");

    // Read the victim's pid through a separate one-shot exec, so the assertion below names a
    // specific process instead of pattern-matching a command line (which would match its searcher).
    let victim: u32 = {
        let mut pid = String::new();
        for _ in 0..40 {
            pid = sh_out(&mut vm, "cat /tmp/vmcell-c3.pid 2>/dev/null || true").await;
            if !pid.is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        pid.parse()
            .expect("the session payload must report its pid")
    };
    assert_eq!(
        sh_out(
            &mut vm,
            &format!("test -d /proc/{victim} && echo ALIVE || echo GONE")
        )
        .await,
        "ALIVE",
        "positive control: the payload must be running BEFORE the shutdown, or the residue \
         assertion below would pass vacuously"
    );

    // SIGTERM the steward from inside the guest. The exec that delivers it dies with the steward it
    // signals, so its own reply never arrives — expected, and why this leg reads the outcome
    // through the serial log and a reconnect rather than through the exec's return.
    if let Ok(client) = vm.steward(Some(Duration::from_secs(30))).await {
        let _ = client
            .exec(ExecRequest::new(vec![
                "/bin/sh".into(),
                "-c".into(),
                format!("{STEWARD_PID_SH} | while read p; do kill \"$p\"; done"),
            ]))
            .await;
    }

    // (3) mini-init restarted it. The serial log is the data plane: mini-init prints one line per
    // start, so a SECOND start means the steward really died and came back rather than never
    // having died.
    await_serial_count(&vm, "mini-init: started ", 2, Duration::from_secs(90)).await;

    // (2) The guest is still up — a `Pid1` SIGTERM policy here would have powered it off — and the
    // control plane is back on a freshly accepted connection.
    assert_eq!(sh_out(&mut vm, "echo back").await, "back");

    // (1) C3: the session's process group is gone. This is the assertion the shutdown path exists
    // for — before the registry, teardown could not reach a per-connection table from a signal.
    assert_eq!(
        sh_out(
            &mut vm,
            &format!("test -d /proc/{victim} && echo ALIVE || echo GONE")
        )
        .await,
        "GONE",
        "law C3: the service shutdown must kill every live session's process group. pid {victim} \
         outlived the steward that started it."
    );

    vm.kill().await.unwrap();
}

/// The `Pid1` twin: SIGTERM to a steward that **is** PID 1 powers the guest off.
///
/// Its own paragraph in §15.4, for a stated reason — "a SIGTERM policy that never powers off is the
/// same assertion-free shape one placement over". Asserting only that the service steward exits
/// cleanly would be satisfied by a steward that ignored SIGTERM entirely; this is the leg that says
/// the policy really is a policy.
#[tokio::test]
#[ignore = "needs KVM"]
async fn the_pid1_twin_powers_the_guest_off_on_sigterm() {
    let vmm = vmcell::vmm::cloud_hypervisor::CloudHypervisor::new(common::ch_bin());
    let mut vm = boot_pid1_cell(&vmm).await;

    // Positive control first: the control plane works, so a later failure is about the power-off
    // and not about a cell that never came up.
    assert_eq!(sh_out(&mut vm, "echo up").await, "up");

    // SIGTERM pid 1 from inside the guest. Under `Pid1` the steward's signal loop converges on
    // `power_off_never_returns`, which syncs and issues `reboot(RB_POWER_OFF)`.
    if let Ok(client) = vm.steward(Some(Duration::from_secs(30))).await {
        let _ = client
            .exec(ExecRequest::new(vec![
                "/bin/sh".into(),
                "-c".into(),
                "kill 1".into(),
            ]))
            .await;
    }

    // The KERNEL's own power-down line, not the steward's. The steward announces the power-off at
    // `info`, and with no `RUST_LOG` in the guest `tracing_subscriber`'s default filter drops
    // everything below `error` — so the steward's line is not an observable here, however much it
    // reads like one. `reboot(RB_POWER_OFF)` makes the kernel print its own, at a level
    // `KernelVerbosity::Verbose` admits, and that line is *better* evidence anyway: it says the
    // syscall was actually issued rather than that the steward intended to issue it.
    await_serial(&vm, "reboot: Power down", Duration::from_secs(90)).await;

    // And it really goes down rather than merely printing: the guest stops answering. A steward
    // that reached the syscall but left the machine up would pass the log check alone.
    let mut went_down = false;
    for _ in 0..60 {
        match vm.steward(Some(Duration::from_millis(500))).await {
            Ok(client) => {
                if client
                    .exec(ExecRequest::new(vec!["/bin/true".into()]))
                    .await
                    .is_err()
                {
                    went_down = true;
                    break;
                }
            }
            Err(_) => {
                went_down = true;
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert!(
        went_down,
        "a Pid1 steward must POWER THE GUEST OFF on SIGTERM, not log it and keep serving"
    );

    vm.kill().await.unwrap();
}

// -----------------------------------------------------------------------------------------------
// Leg 3 — the declared port, bound at last.
// -----------------------------------------------------------------------------------------------

/// A **non-default** declared port is emitted, dialed, *and bound*.
///
/// Delta 4 shipped the host halves and the premise sweep that followed found the guest half missing:
/// nothing under `crates/vmcell-steward` read `vmcell_steward_port`, so the token reached the guest,
/// the host dialed the declared port, and the steward listened on 5000. The failure surfaced only as
/// an opaque connect timeout — exactly the class §3.5 says the health gate exists to diagnose — and
/// no test in the tree could notice, because none declared a non-default port.
///
/// RED ON INVERSE: drop the `parse_steward_port` arm from `StewardOptions::apply_cmdline` and this
/// leg times out on the connect, which is the pre-delta-5 behavior said out loud. 5100 rather than
/// 5000 deliberately: with the default the buggy and correct guests agree everywhere.
#[tokio::test]
#[ignore = "needs KVM"]
async fn a_non_default_declared_port_is_actually_bound_by_the_guest() {
    let vmm = vmcell::vmm::cloud_hypervisor::CloudHypervisor::new(common::ch_bin());
    let mut vm = boot_service_cell(&vmm, 5100).await;

    // A SINGLE bounded connect, deliberately not the retrying `sh` helper: the failure this leg
    // guards is "nothing is listening on the declared port", and a retry loop turns that into a
    // ten-minute stall rather than a result. (Measured: with the parse planted out, the retrying
    // form took 594 s to report what this form reports in 20.) A stalled leg is indistinguishable
    // from a slow box, which is the shape AGENTS.md rule 2 exists to forbid.
    let out = tokio::time::timeout(Duration::from_secs(45), async {
        vm.steward(Some(Duration::from_secs(20)))
            .await
            .expect(
                "the steward must BIND the declared port, not merely be told about it. A connect \
                 failure here is the guest-side `vmcell_steward_port=` parse missing: the host \
                 emitted the token and dialed 5100 while the steward listened on the default.",
            )
            .exec(ExecRequest::new(vec![
                "/bin/sh".into(),
                "-c".into(),
                "echo declared-port-works".into(),
            ]))
            .await
            .expect("exec over the declared port")
    })
    .await
    .expect("the declared port must answer well inside the connect budget");
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "declared-port-works"
    );

    // The negative control, and it has to be a DIAL rather than a log line: the steward logs its
    // bound port at `info`, and the guest runs with no `RUST_LOG`, so `tracing_subscriber`'s
    // default filter keeps everything below `error` off the console. (Discovered by this leg
    // failing on its first live run while the exec above succeeded — the mechanism worked and the
    // observable did not exist.) `dial_vsock` is placement-blind by design and never consults the
    // control-plane guard, so it reaches the guest's vsock device directly: port 5000 must have
    // NOBODY on it, which is what makes "5100 works" mean the steward MOVED rather than that it
    // bound both.
    let default_port = vm
        .dial_vsock(vmcell_protocol::STEWARD_VSOCK_PORT, Duration::from_secs(5))
        .await;
    assert!(
        default_port.is_err(),
        "the steward must bind ONLY the declared port 5100; something is still listening on the \
         default 5000"
    );

    vm.kill().await.unwrap();
}

// -----------------------------------------------------------------------------------------------
// Leg 4 — the rapid-failure cap.
// -----------------------------------------------------------------------------------------------

/// A supervised program that cannot stay up powers the guest off fail-loud, rather than
/// crash-looping silently.
///
/// The cap is what keeps mini-init's restart policy honest: a guest that spins forever is
/// indistinguishable, to a host waiting out a connect budget, from a guest that is working. This
/// leg is reachable only because mini-init's supervised program is a **parameter** (the recorded
/// shift from §3.5's sketch): `-- /bin/false` is a program that exits instantly and always, which
/// no fixed-program init could express without a test-only hook in PID 1.
///
/// It deliberately declares no placement, because there is no steward in this cell at all — the
/// derived `StewardPlacement::None` is the honest description, and the assertion is entirely on the
/// serial console.
#[tokio::test]
#[ignore = "needs KVM"]
async fn the_rapid_failure_cap_powers_the_guest_off_fail_loud() {
    let vmm = vmcell::vmm::cloud_hypervisor::CloudHypervisor::new(common::ch_bin());
    let cfg = VmConfig::builder(
        common::get_vmlinux(),
        RootfsSource::Erofs {
            image: common::get_rootfs(),
        },
    )
    .init(MINI_INIT)
    // Everything after `--` is the kernel's hand-off to init's argv — the same mechanism the
    // echo-server-as-`init=` leg uses to learn its port.
    .with_kernel_arg("--")
    .with_kernel_arg("/bin/false")
    .kernel_verbosity(KernelVerbosity::Verbose)
    .network_disabled()
    .build()
    .expect("a mini-init cell with no steward derives StewardPlacement::None");

    let mut vm = common::start_vm(&vmm, cfg).await;

    // The cap names itself on the console. Matching the FATAL line discriminates the cap from every
    // other power-off path.
    let log = await_serial(&vm, "rapid-failure cap", Duration::from_secs(90)).await;
    assert!(
        log.contains("mini-init: FATAL"),
        "the cap must be fail-LOUD"
    );

    // Non-vacuity: it really did retry before giving up, rather than powering off on the first
    // failure — a different, much less useful policy the assertion above could not tell apart.
    assert!(
        log.matches("/bin/false exited").count() >= 2,
        "the cap must tolerate several rapid failures before tripping; the log shows it gave up \
         immediately"
    );

    vm.kill().await.unwrap();
}
