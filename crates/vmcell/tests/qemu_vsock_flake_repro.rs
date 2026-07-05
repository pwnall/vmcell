// Regression gate for the intermittent QEMU "Agent connection timed out" flake
// (docs/benchmark-results.md, "QEMU agent-timeout flake").
//
// ROOT CAUSE (diagnosed via this harness): QEMU's vsock rides an external
// `vhost-device-vsock` daemon over a `vhost-user-vsock` virtqueue. Its bring-up
// races: on ~11% of boots the data path comes up wedged for the VM's whole life —
// the daemon is alive and accepts the host `CONNECT`, but never reaches the guest
// listener (probe below returns "<no reply>"), and the guest itself is fine (boots,
// no panic under panic=1, agent running). CH/FC terminate vsock inside the VMM, so
// they never hit this — only QEMU does. The wedge is persistent-per-instance, so the
// host's 10 s of retries all fail.
//
// FIX (`MicroVm::start`'s control-plane health-gate → `VmInstance::verify_control_plane`,
// QEMU override): after boot, probe the vsock path with a bounded budget; a wedged
// VM is re-spawned on the same per-VM resources instead of being handed back to fail
// ~10 s later at `agent()`. With N=4 re-spawns the residual is ~0.11^5 ≈ 1.6e-5/VM.
//
// So this test is RED before the fix (reproduces the flake at ~11%) and GREEN after
// (the re-spawn makes every boot reach the agent). It runs in `just test-privileged`
// (which passes `--run-ignored all --features ...,qemu`); it is `#[ignore]`d so it
// stays out of the KVM-free `just ci` (`cargo nextest run --all-features`, no
// `--run-ignored`). The daemon-CONNECT probe on failure stays as the diagnostic that
// pinned the root cause, so a regression reports *why*, not just that it flaked.
//
// Run manually (needs the blessed runner + delegated scope, like test-privileged):
//   systemd-run --user --scope -p Delegate=yes scripts/with-delegated-scope.sh \
//     bash -c 'cargo test -p vmcell --features qemu --test qemu_vsock_flake_repro \
//       -- --ignored --nocapture'
#![cfg(feature = "qemu")]

use std::time::{Duration, Instant};
use vmcell::config::{RootfsSource, VmConfig};
use vmcell::orchestrator::RealClock;
use vmcell::vmm::VmInstance;

mod common;

// 30 boots at the measured ~11% wedge rate catches a fix regression (re-spawn
// removed) with P ≈ 1 - 0.89^30 ≈ 0.97, while the fix's ~1.6e-5/VM residual keeps a
// spurious red at ~5e-4. Validated green at 120 aggregate when the fix landed.
const ITERS: usize = 30;
const AGENT_TIMEOUT: Duration = Duration::from_secs(10);

// Raw host-side probe of the vhost-device-vsock daemon: connect to the host UDS,
// send the Firecracker-hybrid `CONNECT <port>` line, and return the daemon's first
// reply line. "OK <n>" => the daemon reached a guest listener on that port (guest
// side is up; failure is downstream). Anything else / EOF / refused => the daemon
// could not reach the guest (transport or guest-listen failure).
async fn probe_connect(uds: &std::path::Path) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut s = match tokio::net::UnixStream::connect(uds).await {
        Ok(s) => s,
        Err(e) => return format!("<UDS connect failed: {e}>"),
    };
    if let Err(e) = s.write_all(b"CONNECT 5000\n").await {
        return format!("<write failed: {e}>");
    }
    let mut buf = [0u8; 64];
    match tokio::time::timeout(Duration::from_millis(500), s.read(&mut buf)).await {
        Ok(Ok(0)) => "<EOF: daemon closed with no reply>".to_string(),
        Ok(Ok(n)) => format!("{:?}", String::from_utf8_lossy(&buf[..n])),
        Ok(Err(e)) => format!("<read error: {e}>"),
        Err(_) => "<no reply within 500ms>".to_string(),
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "investigation harness; boots QEMU in a loop"]
async fn qemu_vsock_flake_repro() {
    let vmm = vmcell::vmm::qemu::Qemu::new(common::qemu_bin());

    let mut ok = 0usize;
    let mut fail = 0usize;
    let mut connect_ms = Vec::new();

    for i in 0..ITERS {
        let cfg = VmConfig::builder(
            common::get_vmlinux(),
            RootfsSource::Erofs {
                image: common::get_rootfs(),
            },
        )
        .network_disabled()
        .build()
        .unwrap();

        let mut vm = match vmcell_artifact_validator::harness::try_start_vm(&vmm, cfg).await {
            Ok(vm) => vm,
            Err(e) => {
                fail += 1;
                eprintln!("[{i}] START FAILED: {e}");
                continue;
            }
        };
        let serial_path = vm.instance().serial_log().to_path_buf();

        let t = Instant::now();
        match vm.agent(Some(AGENT_TIMEOUT), &RealClock).await {
            Ok(_) => {
                ok += 1;
                connect_ms.push(t.elapsed().as_millis());
            }
            Err(e) => {
                fail += 1;
                // On a regression, pin the failure to the daemon->guest data path: the
                // probe below returns "<no reply>" for the wedge this test guards, so a
                // reader sees *why* it flaked, not just that it did.
                let uds = serial_path.with_file_name("vsock.sock");
                eprintln!(
                    "\n========== [{i}] AGENT FAILED after {:?}: {e}",
                    t.elapsed()
                );
                eprintln!("  vsock UDS present on host: {}", uds.exists());
                for probe in 0..3 {
                    eprintln!(
                        "  daemon CONNECT probe #{probe}: {}",
                        probe_connect(&uds).await
                    );
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
            }
        }
        let _ = vm.shutdown().await;
    }

    let p = |v: &mut Vec<u128>| {
        v.sort_unstable();
        v.get(v.len() / 2).copied().unwrap_or(0)
    };
    eprintln!(
        "\n==== QEMU vsock flake repro: {ok} ok / {fail} failed of {ITERS}  (connect p50={} ms) ====",
        p(&mut connect_ms)
    );
    assert_eq!(
        fail, 0,
        "reproduced the QEMU agent-connect flake ({fail}/{ITERS})"
    );
}
