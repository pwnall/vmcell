//! The contract checks, **extracted** from vmcell's integration suite so the validator and the
//! tests share one implementation. Each check is `async fn(...) -> Result<(), String>`
//! (`Ok` = the contract property held, `Err(msg)` = it was violated). The validator maps those
//! onto [`CheckStatus`](crate::CheckStatus); a refactored integration test calls the same
//! function and asserts `Ok`.
//!
//! Checks operate on the primitives they need — a `&mut AgentClient` for guest probes, a
//! `&MicroVm` for host-side reads (serial log, cgroup usage), or a backend `&V` for
//! multi-VM checks (concurrency). The [`run_core`]/[`run_extended`]/[`run_full`] orchestrators
//! boot capability-appropriate VMs and collect outcomes.

use std::path::Path;
use std::time::Duration;

use vmcell::ExecRequest;
use vmcell::agent::AgentClient;
use vmcell::config::{
    Access, CachePolicy, Egress, NetConfig, RootfsSource, Share, VmConfig, VmConfigBuilder,
};
use vmcell::orchestrator::MicroVm;
use vmcell::vmm::{VmInstance, Vmm};

use crate::classify::{BANNER_SIGNATURE, explain_boot_failure, explain_without_serial};
use crate::harness::{cgroup_memory_delegated, try_start_vm};
use crate::{ArtifactSet, CheckOutcome, Level};

/// The agent-handshake budget every check allows before it calls the boot failed (§9.4: deadlines
/// are outer-bounds-inner — this is the outer bound `AgentClient` turns into its `Instant`).
/// **One** statement of the number: an inline per-call 60-second literal anywhere in this module is
/// a second copy of the same law, and `every_agent_budget_is_a_named_const` reddens on it.
const AGENT_READY_BUDGET: Duration = Duration::from_secs(60);

/// The agent-handshake budget for a VM booted **concurrently with others**
/// (`concurrency_distinct_ids`): three guests contending for the same host take longer than one.
const CONCURRENT_AGENT_READY_BUDGET: Duration = Duration::from_secs(180);

/// How long [`kernel_banner`] waits for the kernel's banner before calling the boot failed.
const KERNEL_BANNER_BUDGET: Duration = Duration::from_secs(15);

/// How long `metrics.usage_readable` lets the booted guest run before reading its cgroup counters
/// back — `memory.peak` is only non-zero once the guest has actually touched memory.
const USAGE_SETTLE: Duration = Duration::from_secs(2);

/// How often [`await_kernel_banner`] re-reads the console while waiting.
const BANNER_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Reads `serial_log` and renders the classified boot failure — the one composition every arm with
/// a **live VM** uses (`fs` + [`explain_boot_failure`]).
///
/// The unreadable case is not silently rendered as an empty console: an empty captured log means
/// "the VM ran and printed nothing" (a real §5.4 signature), while an unreadable log is *absence of
/// evidence*, so it routes through [`explain_without_serial`] instead. Either way the message names
/// the console it consulted, so the reader can go look at it.
async fn explain_boot_failure_at(serial_log: &Path, base: &str) -> String {
    let base = format!("{base} (serial log {})", serial_log.display());
    match tokio::fs::read_to_string(serial_log).await {
        Ok(text) => explain_boot_failure(&text, &base),
        Err(e) => {
            tracing::warn!(
                path = %serial_log.display(),
                error = %e,
                "serial log unreadable; reporting the boot failure without console evidence"
            );
            explain_without_serial(&base, &format!("it could not be read: {e}"))
        }
    }
}

/// [`explain_boot_failure_at`] against a VM's own console — the single place a serial-log path is
/// derived from a [`MicroVm`].
async fn explain_boot_failure_for<V: Vmm>(vm: &MicroVm<V>, base: &str) -> String {
    explain_boot_failure_at(vm.instance().serial_log(), base).await
}

/// The message every `MicroVm::start` failure records — one shape for all of them, since they all
/// lose the console the same way (the per-VM scratch dir dies with the failed start).
fn failed_start(e: &impl std::fmt::Display) -> String {
    explain_without_serial(
        &format!("VM failed to start: {e}"),
        "MicroVm::start failed and took its per-VM scratch dir (with the console) with it",
    )
}

/// The base sentence every agent-handshake failure records, naming the budget that expired.
///
/// `budget` is passed rather than read off [`AGENT_READY_BUDGET`] so the sentence names the budget
/// the call **actually** used: the arms that inject a different one (a unit test's millisecond
/// budget, a concurrent boot's longer one) must not report the default's number.
fn agent_handshake_base(e: &impl std::fmt::Display, budget: Duration) -> String {
    format!(
        "agent handshake failed within the {}s budget: {e}",
        budget.as_secs()
    )
}

/// A base builder for `artifacts` (the caller-supplied kernel + erofs rootfs pair).
fn base_cfg(a: &ArtifactSet) -> VmConfigBuilder {
    VmConfig::builder(
        a.kernel.clone(),
        RootfsSource::Erofs {
            image: a.rootfs.clone(),
        },
    )
}

/// Runs `argv` in the guest, mapping an agent transport error into a check-failure string.
async fn exec(agent: &mut AgentClient, argv: &[&str]) -> Result<vmcell::ExecOutcome, String> {
    let req = ExecRequest::new(argv.iter().map(|s| (*s).to_string()).collect());
    agent
        .exec(req)
        .await
        .map_err(|e| format!("agent exec {argv:?} failed at the transport level: {e}"))
}

// ---------------------------------------------------------------------------
// Core checks (need only KVM; run on one net-disabled VM)
// ---------------------------------------------------------------------------

/// The kernel reaches userspace: the serial console shows the [`BANNER_SIGNATURE`] banner within a
/// bounded window (← `boot.rs`). A kernel that never boots (bad config, wrong format) reddens.
///
/// On failure the message names the §5.4 contract clause the serial log proves was broken
/// ([`explain_boot_failure`]) — never a bare timeout (§5.6).
///
/// # Errors
/// Returns `Err` if the kernel never reaches userspace within the boot window (bad config / wrong format) or the console cannot be read.
pub async fn kernel_banner<V: Vmm>(vm: &MicroVm<V>) -> Result<(), String> {
    await_kernel_banner(vm.instance().serial_log(), KERNEL_BANNER_BUDGET).await
}

/// The bounded banner poll, with the budget injected so it is drivable in a unit test (§9.4: the
/// deadline is an [`tokio::time::Instant`], computed once and bounding the whole loop).
///
/// Both failure shapes are distinguished, because they have different causes: a console that was
/// *read* and lacks the banner is evidence for [`explain_boot_failure`] to classify, while a
/// console file the VMM never created is *no* evidence and routes through
/// [`explain_without_serial`].
async fn await_kernel_banner(serial_log: &Path, budget: Duration) -> Result<(), String> {
    let deadline = tokio::time::Instant::now() + budget;
    // `None` until the file is first read: an unwritten console is the normal early-boot case, so
    // it is retried rather than reported. The newest text that *was* read is what the classifier
    // sees when the budget expires.
    let mut last: Option<String> = None;
    loop {
        if let Ok(content) = tokio::fs::read_to_string(serial_log).await {
            if content.contains(BANNER_SIGNATURE) {
                return Ok(());
            }
            last = Some(content);
        }
        if tokio::time::Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep(BANNER_POLL_INTERVAL).await;
    }
    let base = format!(
        "kernel did not print the '{BANNER_SIGNATURE}' banner within {}s (serial log {})",
        budget.as_secs(),
        serial_log.display()
    );
    Err(match last {
        Some(text) => explain_boot_failure(&text, &base),
        None => explain_without_serial(
            &base,
            "the VMM never created the serial log, so no console was captured",
        ),
    })
}

/// An exec round-trips: `echo` returns exit 0 with the expected stdout (← `boot.rs`). Proves the
/// vsock control plane + PID-1 agent exec path end to end.
///
/// # Errors
/// Returns `Err` if the exec fails, exits non-zero, or returns unexpected stdout.
pub async fn agent_exec_roundtrip(agent: &mut AgentClient) -> Result<(), String> {
    let out = exec(agent, &["echo", "vmcell-validate-marker"]).await?;
    if out.code != 0 {
        return Err(format!("echo exited {} (expected 0)", out.code));
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    if !stdout.contains("vmcell-validate-marker") {
        return Err(format!("echo stdout missing marker; got {stdout:?}"));
    }
    Ok(())
}

/// `put_file` then read the bytes back **in the guest** — a real round-trip, not a mock UDS
/// assertion (← `exec_vsock.rs`; AGENTS.md "mock where round-trip is required"). Proves the
/// PutFile protocol writes real guest files.
///
/// # Errors
/// Returns `Err` if `put_file` fails or the bytes read back in-guest differ.
pub async fn agent_put_file_roundtrip(agent: &mut AgentClient) -> Result<(), String> {
    let dst = "/run/vmcell-validate-putfile";
    let payload = b"vmcell-validate-putfile-payload-42";
    agent
        .put_file(dst, payload, Some(Duration::from_secs(10)))
        .await
        .map_err(|e| format!("put_file failed: {e}"))?;
    let out = exec(agent, &["cat", dst]).await?;
    if out.code != 0 {
        return Err(format!("reading back {dst} exited {}", out.code));
    }
    if out.stdout != payload {
        return Err(format!(
            "put_file round-trip mismatch: wrote {} bytes, read {} back",
            payload.len(),
            out.stdout.len()
        ));
    }
    Ok(())
}

/// The rootfs ships glibc `libc.so.6` (← §4.2, Rootfs sources and the one packer libc6 scan; the dynamically-linked agent already
/// proves it, but a custom rootfs is checked explicitly across the common multiarch paths).
///
/// # Errors
/// Returns `Err` if `libc.so.6` is absent from every probed multiarch path (or the probe exec fails).
pub async fn rootfs_libc6(agent: &mut AgentClient) -> Result<(), String> {
    let out = exec(
        agent,
        &[
            "sh",
            "-c",
            "test -e /lib/x86_64-linux-gnu/libc.so.6 || test -e /lib64/libc.so.6 \
             || test -e /usr/lib/x86_64-linux-gnu/libc.so.6",
        ],
    )
    .await?;
    if out.code != 0 {
        return Err("glibc libc.so.6 not found at any standard path (§5.4)".into());
    }
    Ok(())
}

/// The injected deployment proxy CA is baked into the trust store (← §4.2, Rootfs sources and the one packer / §10, The artifact build pipeline CA injection).
///
/// # Errors
/// Returns `Err` if the injected proxy CA is not present in the guest trust store.
pub async fn rootfs_ca_cert(agent: &mut AgentClient) -> Result<(), String> {
    let out = exec(
        agent,
        &[
            "test",
            "-f",
            "/usr/local/share/ca-certificates/vmcell-ca.crt",
        ],
    )
    .await?;
    if out.code != 0 {
        return Err(
            "injected deployment CA (/usr/local/share/ca-certificates/vmcell-ca.crt) missing"
                .into(),
        );
    }
    Ok(())
}

/// The in-rootfs guest-tools multicall is present and its `ip`/`curl`/`kvm-ok` names resolve on
/// the agent's exec PATH (← §4.4, The in-rootfs guest-tools helper).
///
/// # Errors
/// Returns `Err` if the guest-tools multicall or its `ip`/`curl`/`kvm-ok` names do not resolve on the exec PATH.
pub async fn rootfs_guest_tools(agent: &mut AgentClient) -> Result<(), String> {
    let out = exec(
        agent,
        &[
            "sh",
            "-c",
            "command -v ip >/dev/null && command -v curl >/dev/null && command -v kvm-ok >/dev/null",
        ],
    )
    .await?;
    if out.code != 0 {
        return Err("guest-tools ip/curl/kvm-ok not all resolvable on PATH (§5.3)".into());
    }
    Ok(())
}

/// The tmpfs overlay upper is writable over the read-only erofs base: write then read a file on
/// the root fs (← §4.1, The erofs read-only base + tmpfs overlay). A read-only-only root (missing overlay/tmpfs) reddens.
///
/// # Errors
/// Returns `Err` if the root fs is not writable (missing tmpfs overlay) or the write/read-back mismatches.
pub async fn rootfs_overlay_writable(agent: &mut AgentClient) -> Result<(), String> {
    let out = exec(
        agent,
        &[
            "sh",
            "-c",
            "echo overlay-probe > /vmcell-validate-overlay && cat /vmcell-validate-overlay \
             && rm -f /vmcell-validate-overlay",
        ],
    )
    .await?;
    if out.code != 0 {
        return Err(format!(
            "writing to the overlay root failed (exit {}): {}",
            out.code,
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    if !String::from_utf8_lossy(&out.stdout).contains("overlay-probe") {
        return Err("overlay write did not read back (tmpfs overlay upper not writable)".into());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Extended checks
// ---------------------------------------------------------------------------

/// The kernel's IP-PNP configured `eth0` at boot from the `ip=` cmdline — **no guest netlink**
/// (← `host_endpoint.rs`, §5.3, The kernel command line/§13, Cross-cutting invariants). Asserts, via guest-tools `ip`, that `eth0` is `state up`
/// carrying the **exact** `(vmid%254)+1` /30 address the orchestrator's `ip_math` expects (a
/// kernel that configured a wrong/default address, or a cmdline/`ip_math` desync, reddens), and
/// that a non-empty routing table exists (IP-PNP installs the default route).
///
/// # Errors
/// Returns `Err` if `eth0` is not `state up`, carries the wrong address vs `ip_math`, or has no route.
pub async fn net_ip_pnp<V: Vmm>(vm: &mut MicroVm<V>) -> Result<(), String> {
    let (_, guest_ip, _) = vmcell::net::ip_math(vm.vmid())
        .map_err(|e| format!("ip_math({}) failed: {e}", vm.vmid()))?;
    // Captured before the `&mut` agent borrow (see `guest_core_checks`).
    let serial_log = vm.instance().serial_log().to_path_buf();
    let agent = match vm.agent(Some(AGENT_READY_BUDGET)).await {
        Ok(a) => a,
        Err(e) => {
            return Err(explain_boot_failure_at(
                &serial_log,
                &agent_handshake_base(&e, AGENT_READY_BUDGET),
            )
            .await);
        }
    };
    let addr = exec(agent, &["ip", "a"]).await?;
    if addr.code != 0 {
        return Err(format!(
            "`ip a` exited {} (guest-tools ip unavailable?)",
            addr.code
        ));
    }
    let stdout = String::from_utf8_lossy(&addr.stdout);
    if !stdout.contains("eth0") || !stdout.contains("state up") {
        return Err(format!(
            "guest eth0 is not up — IP-PNP did not configure the interface at boot; `ip a` was:\n{stdout}"
        ));
    }
    // guest-tools `ip a` prints the `inet <addr>/<prefix>` line (SIOCGIFADDR), so verify the
    // exact IP-PNP address rather than merely that the link is up.
    if !stdout.contains(&format!("inet {guest_ip}/")) {
        return Err(format!(
            "guest eth0 does not carry its IP-PNP address {guest_ip}; `ip a` was:\n{stdout}"
        ));
    }
    let route = exec(agent, &["ip", "route"]).await?;
    if route.code != 0 {
        return Err(format!("`ip route` exited {}", route.code));
    }
    if route.stdout.is_empty() {
        return Err(
            "guest has no routes — IP-PNP did not install the default route from ip=".into(),
        );
    }
    Ok(())
}

/// A read-only virtio-fs share rejects writes with EROFS and serves reads; a read-write share's
/// writes are visible on the host (← `shares_ro_rw.rs`, §4.5, Shared directories (virtio-fs)). `in_marker` was written to the RO
/// share host-side; `host_out_dir` is the RW share's host directory.
///
/// # Errors
/// Returns `Err` if the RO share accepts a write (or fails reads) or the RW share's write is not visible host-side.
pub async fn virtiofs_shares(
    agent: &mut AgentClient,
    host_out_dir: &std::path::Path,
) -> Result<(), String> {
    // RO read works.
    let read = exec(agent, &["cat", "/vmcell-in/input.txt"]).await?;
    if read.code != 0 || read.stdout != b"hello world" {
        return Err(format!(
            "RO share read failed (exit {}, stdout {:?})",
            read.code,
            String::from_utf8_lossy(&read.stdout)
        ));
    }
    // RO write is rejected with the SPECIFIC EROFS signal (not any nonzero — §4.5, Shared directories (virtio-fs)/L-TEST-1).
    let ro_write = exec(agent, &["sh", "-c", "echo x > /vmcell-in/nope.txt"]).await?;
    if ro_write.code == 0 {
        return Err("write to a read-only virtio-fs share unexpectedly succeeded".into());
    }
    if !String::from_utf8_lossy(&ro_write.stderr).contains("Read-only file system") {
        return Err(format!(
            "RO share write must fail with EROFS 'Read-only file system'; got: {}",
            String::from_utf8_lossy(&ro_write.stderr)
        ));
    }
    // RW write is visible on the host.
    let rw_write = exec(agent, &["sh", "-c", "echo rw-ok > /vmcell-out/out.txt"]).await?;
    if rw_write.code != 0 {
        return Err(format!("RW share write exited {}", rw_write.code));
    }
    let host_seen = tokio::fs::read_to_string(host_out_dir.join("out.txt"))
        .await
        .map_err(|e| format!("RW share output not visible on host: {e}"))?;
    if host_seen.trim() != "rw-ok" {
        return Err(format!("RW share host content mismatch: {host_seen:?}"));
    }
    Ok(())
}

/// With nested virt enabled, the guest sees `/dev/kvm` — `kvm-ok` exits 0 (← `nested_virt.rs`,
/// §5.3, The kernel command line). The VM must have been booted with `nested_virt = true`.
///
/// # Errors
/// Returns `Err` if `/dev/kvm` is absent in the guest (`kvm-ok` non-zero) — e.g. the VM was not booted with `nested_virt`.
pub async fn nested_kvm_ok(agent: &mut AgentClient) -> Result<(), String> {
    let out = exec(agent, &["kvm-ok"]).await?;
    if out.code != 0 {
        return Err(format!(
            "kvm-ok exited {} — nested /dev/kvm not exposed to the guest",
            out.code
        ));
    }
    Ok(())
}

/// Per-VM cgroup usage is observable and honestly reports enforcement (← `metrics_limits.rs`,
/// §7.1, What is read and enforced). Requires the memory controller delegated (the caller gates on that).
///
/// # Errors
/// Returns `Err` if per-VM cgroup usage cannot be read or misreports enforcement.
pub async fn metrics_usage_readable<V: Vmm>(vm: &MicroVm<V>) -> Result<(), String> {
    let usage = vm
        .usage()
        .await
        .map_err(|e| format!("usage() failed: {e}"))?;
    if !usage.mem_limit_enforced {
        return Err(
            "memory controller delegated but ResourceUsage::mem_limit_enforced is false".into(),
        );
    }
    if usage.mem_peak_mib == 0 {
        return Err("memory controller delegated but memory.peak reads 0".into());
    }
    Ok(())
}

/// The whole `metrics.usage_readable` arm: the agent handshake that proves the guest actually
/// booted, the settle window that lets it touch memory, then [`metrics_usage_readable`].
///
/// Extracted with both durations injected so the **handshake decision** is drivable KVM-free
/// (`usage-readable-swallows-agent-handshake`): the handshake used to be a bare `let _`, so a guest
/// that never came up still reached the cgroup readout and the check could report anything but the
/// boot failure that caused it. Every sibling arm renders a failed handshake through
/// [`explain_boot_failure_at`]; this one now does too.
async fn usage_readable_after_agent_ready<V: Vmm>(
    vm: &mut MicroVm<V>,
    ready_budget: Duration,
    settle: Duration,
) -> Result<(), String> {
    // Captured before the `&mut` agent borrow (see `guest_core_checks`).
    let serial_log = vm.instance().serial_log().to_path_buf();
    if let Err(e) = vm.agent(Some(ready_budget)).await {
        return Err(
            explain_boot_failure_at(&serial_log, &agent_handshake_base(&e, ready_budget)).await,
        );
    }
    // Agent-ready: let the guest consume some memory before the counters are read back.
    tokio::time::sleep(settle).await;
    metrics_usage_readable(vm).await
}

// ---------------------------------------------------------------------------
// Full checks
// ---------------------------------------------------------------------------

/// Boots N VMs **concurrently** on shared allocators and asserts each gets a distinct
/// vmid / guest-CID / vsock path and execs successfully (← `concurrency.rs`, §13, Cross-cutting invariants). Catches an
/// allocator that hands out duplicates under contention.
///
/// # Errors
/// Returns `Err` if any concurrent VM fails to boot/exec or two VMs collide on vmid / guest-CID / vsock path.
pub async fn concurrency_distinct_ids<V: Vmm>(vmm: &V, a: &ArtifactSet) -> Result<(), String> {
    let cfg = base_cfg(a)
        .network_disabled()
        .build()
        .map_err(|e| format!("config build failed: {e}"))?;
    let env = vmcell::HostEnv::hermetic();

    // Drive N starts CONCURRENTLY on the shared allocators (join_all polls in place, so the
    // futures may borrow `vmm` — no `'static`/`spawn` needed).
    let starts = (0..3).map(|_| MicroVm::start(vmm, cfg.clone(), &env));
    let mut vms = Vec::new();
    for res in futures::future::join_all(starts).await {
        vms.push(res.map_err(|e| failed_start(&e))?);
    }

    let mut vmids = std::collections::HashSet::new();
    let mut vsocks = std::collections::HashSet::new();
    let mut cids = std::collections::HashSet::new();
    for vm in &vms {
        if !vmids.insert(vm.vmid()) {
            return Err(format!(
                "duplicate vmid {} under concurrent start",
                vm.vmid()
            ));
        }
        if !vsocks.insert(vm.instance().vsock_path().to_path_buf()) {
            return Err("duplicate vsock path under concurrent start".into());
        }
        if !cids.insert(vm.instance().guest_cid()) {
            return Err("duplicate guest CID under concurrent start".into());
        }
    }
    for mut vm in vms {
        // Captured before the `&mut` agent borrow (see `guest_core_checks`). The budget is
        // deliberately not `AGENT_READY_BUDGET`: three guests boot concurrently here.
        let serial_log = vm.instance().serial_log().to_path_buf();
        let agent = match vm.agent(Some(CONCURRENT_AGENT_READY_BUDGET)).await {
            Ok(a) => a,
            Err(e) => {
                // The sentence is composed by the one `agent_handshake_base` (now that it takes the
                // budget it must name), not a second copy of the phrasing that only differed in
                // which const it read.
                return Err(explain_boot_failure_at(
                    &serial_log,
                    &format!(
                        "a concurrently-started VM: {}",
                        agent_handshake_base(&e, CONCURRENT_AGENT_READY_BUDGET)
                    ),
                )
                .await);
            }
        };
        let out = exec(agent, &["true"]).await?;
        if out.code != 0 {
            return Err(format!("concurrent VM exec `true` exited {}", out.code));
        }
        let _ = vm.shutdown().await;
    }
    Ok(())
}

/// Snapshot a running VM and restore it, confirming the **restored** VM boots back to
/// agent-ready and execs (← `snapshot_restore.rs`, §8, Snapshot, restore, and cloning/§8.2, Restore correctness: a restored VM is not a fresh VM). Proves the artifact survives the
/// PVH snapshot/restore path. The VM must be a snapshot-eligible config (no vhost-user device).
///
/// # Errors
/// Returns `Err` if snapshot or restore fails, or the restored VM does not return to agent-ready and exec.
pub async fn snapshot_restore_roundtrip<V: Vmm>(vmm: &V, a: &ArtifactSet) -> Result<(), String> {
    let mut cfg = base_cfg(a)
        .network_disabled()
        .build()
        .map_err(|e| format!("snapshot-eligible config build failed: {e}"))?;
    // Snapshot-eligible: net=None → no vhost-user device (§13, Cross-cutting invariants); set the flag on the built
    // config (the pair is already vhost-user-free, so this stays valid).
    cfg.snapshotting = true;
    let env = vmcell::HostEnv::hermetic();
    let mut vm = MicroVm::start(vmm, cfg.clone(), &env)
        .await
        .map_err(|e| format!("snapshot-source: {}", failed_start(&e)))?;
    // Boot to agent-ready before snapshotting.
    if let Err(e) = vm.agent(Some(AGENT_READY_BUDGET)).await {
        let base = format!(
            "snapshot-source: {}",
            agent_handshake_base(&e, AGENT_READY_BUDGET)
        );
        return Err(explain_boot_failure_for(&vm, &base).await);
    }

    let snap_dir = tempfile::tempdir().map_err(|e| format!("tempdir: {e}"))?;
    vm.snapshot(snap_dir.path())
        .await
        .map_err(|e| format!("snapshot() failed: {e}"))?;
    let _ = vm.shutdown().await;

    let mut restored = MicroVm::restore(vmm, snap_dir.path(), cfg, &env)
        .await
        .map_err(|e| format!("restore() failed: {e}"))?;
    // Captured before the `&mut` agent borrow (see `guest_core_checks`).
    let restored_serial = restored.instance().serial_log().to_path_buf();
    let agent = match restored.agent(Some(AGENT_READY_BUDGET)).await {
        Ok(a) => a,
        Err(e) => {
            let base = format!(
                "restored VM: {}",
                agent_handshake_base(&e, AGENT_READY_BUDGET)
            );
            return Err(explain_boot_failure_at(&restored_serial, &base).await);
        }
    };
    let out = exec(agent, &["true"]).await?;
    if out.code != 0 {
        return Err(format!("restored VM exec `true` exited {}", out.code));
    }
    let _ = restored.shutdown().await;
    Ok(())
}

/// A host cgroup memory cap below guest RAM is the binding limit: a runaway allocation trips the
/// host OOM killer, observable via `memory.events` `oom_kill` (← `metrics_limits.rs`, §7, Resource monitoring and limits). The VM
/// must be booted with `mem_mib=512, limits.mem_max_mib=Some(256)`.
///
/// # Errors
/// Returns `Err` if the capped allocation does not trip the host OOM killer (no `oom_kill` observed) or the metric cannot be read.
pub async fn metrics_mem_limit_ooms<V: Vmm>(vm: &mut MicroVm<V>) -> Result<(), String> {
    let events_path = cgroup_events_path(vm.vmid());
    // Fire a runaway allocation; the VMM may itself be OOM-killed, so ignore the exec result —
    // the binding signal is the host counter.
    {
        // Captured before the `&mut` agent borrow (see `guest_core_checks`).
        let serial_log = vm.instance().serial_log().to_path_buf();
        let agent = match vm.agent(Some(AGENT_READY_BUDGET)).await {
            Ok(a) => a,
            Err(e) => {
                return Err(explain_boot_failure_at(
                    &serial_log,
                    &agent_handshake_base(&e, AGENT_READY_BUDGET),
                )
                .await);
            }
        };
        let _ = exec(agent, &["tail", "/dev/zero"]).await;
    }
    for _ in 0..50 {
        if let Ok(events) = std::fs::read_to_string(&events_path)
            && let Some(n) = parse_oom_kill(&events)
            && n > 0
        {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Err(format!(
        "cgroup memory cap did not trip the host OOM killer (no oom_kill at {})",
        events_path.display()
    ))
}

/// The `/sys/fs/cgroup/<slice>/memory.events` path for a vmid, using vmcell's canonical cgroup
/// base parser so it matches the orchestrator's slice placement.
fn cgroup_events_path(vmid: u32) -> std::path::PathBuf {
    let name = std::fs::read_to_string("/proc/self/cgroup")
        .ok()
        .and_then(|c| vmcell::metrics::cgroup_base_from_proc(&c))
        .map(|base| format!("{base}/vmcell-vm-{vmid}"))
        .unwrap_or_else(|| format!("vmcell-vm-{vmid}"));
    std::path::PathBuf::from(format!("/sys/fs/cgroup/{name}/memory.events"))
}

/// Parses `oom_kill` from a cgroup-v2 `memory.events` file (← `metrics_limits.rs`).
fn parse_oom_kill(contents: &str) -> Option<u64> {
    for line in contents.lines() {
        let mut it = line.split_whitespace();
        if it.next() == Some("oom_kill") {
            return it.next().and_then(|v| v.parse().ok());
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Orchestration: boot capability-appropriate VMs and collect outcomes
// ---------------------------------------------------------------------------

fn record(outcomes: &mut Vec<CheckOutcome>, id: &'static str, level: Level, r: Result<(), String>) {
    outcomes.push(CheckOutcome::from_result(id, level, r));
}

fn skip(
    outcomes: &mut Vec<CheckOutcome>,
    id: &'static str,
    level: Level,
    reason: impl Into<String>,
) {
    outcomes.push(CheckOutcome::skip(id, level, reason));
}

/// Core: one net-disabled VM → banner, agent-ready, exec/put-file round-trips, rootfs presence,
/// overlay, clean shutdown. Never skips (KVM is a precondition).
pub async fn run_core<V: Vmm>(vmm: &V, a: &ArtifactSet, outcomes: &mut Vec<CheckOutcome>) {
    let cfg = match base_cfg(a).network_disabled().build() {
        Ok(c) => c,
        Err(e) => {
            record(
                outcomes,
                "boot.config",
                Level::Core,
                Err(format!("config build failed: {e}")),
            );
            return;
        }
    };
    let mut vm = match try_start_vm(vmm, cfg).await {
        Ok(vm) => vm,
        Err(e) => {
            // `MicroVm::start` owns the per-VM temp dir, so on this arm the serial log is already
            // deleted — there is no console evidence at all, and `start` also fails for reasons
            // that are not the artifact pair (missing VMM binary, denied host resource), so this
            // must NOT assert the "not a direct-boot vmlinux" clause. Both Core boot checks are
            // recorded so a failed start never *shrinks* the report's roster.
            let msg = failed_start(&e);
            record(
                outcomes,
                "boot.kernel_banner",
                Level::Core,
                Err(msg.clone()),
            );
            record(outcomes, "boot.agent_ready", Level::Core, Err(msg));
            return;
        }
    };
    record(
        outcomes,
        "boot.kernel_banner",
        Level::Core,
        kernel_banner(&vm).await,
    );

    // agent-ready gates every guest probe; if it fails, record it and stop the guest checks.
    match vm.agent(Some(AGENT_READY_BUDGET)).await {
        Ok(_) => record(outcomes, "boot.agent_ready", Level::Core, Ok(())),
        Err(e) => {
            // The VM is still alive here, so its serial log is readable — this is the arm that
            // catches both the erofs root-mount panic (which surfaces only as "Panic detected in
            // serial log") and the missing-`CONFIG_VSOCKETS` guest.
            let msg =
                explain_boot_failure_for(&vm, &agent_handshake_base(&e, AGENT_READY_BUDGET)).await;
            record(outcomes, "boot.agent_ready", Level::Core, Err(msg));
            let _ = vm.shutdown().await;
            return;
        }
    }
    // Re-borrow the agent for each check (the connection is cached on the VM).
    for (id, res) in guest_core_checks(&mut vm).await {
        record(outcomes, id, Level::Core, res);
    }
    record(
        outcomes,
        "lifecycle.clean_shutdown",
        Level::Core,
        vm.shutdown().await.map_err(|e| e.to_string()),
    );
}

/// Runs the guest-facing Core checks against `vm`'s cached agent, returning (id, result) pairs.
async fn guest_core_checks<V: Vmm>(vm: &mut MicroVm<V>) -> Vec<(&'static str, Result<(), String>)> {
    // Captured before the `&mut` agent borrow so the failure arm can still read the console (the
    // borrow checker keeps the mutable borrow alive across the whole `match` here).
    let serial_log = vm.instance().serial_log().to_path_buf();
    let agent = match vm.agent(Some(AGENT_READY_BUDGET)).await {
        Ok(a) => a,
        Err(e) => {
            let msg =
                explain_boot_failure_at(&serial_log, &format!("agent unavailable: {e}")).await;
            return vec![("agent.exec_roundtrip", Err(msg))];
        }
    };
    vec![
        ("agent.exec_roundtrip", agent_exec_roundtrip(agent).await),
        (
            "agent.put_file_roundtrip",
            agent_put_file_roundtrip(agent).await,
        ),
        ("rootfs.libc6", rootfs_libc6(agent).await),
        ("rootfs.ca_cert", rootfs_ca_cert(agent).await),
        ("rootfs.guest_tools", rootfs_guest_tools(agent).await),
        (
            "rootfs.overlay_writable",
            rootfs_overlay_writable(agent).await,
        ),
    ]
}

/// Extended: capability-gated probes, each on its own appropriately-configured VM.
pub async fn run_extended<V: Vmm>(vmm: &V, a: &ArtifactSet, outcomes: &mut Vec<CheckOutcome>) {
    let caps = vmm.capabilities();

    // net / IP-PNP (unprivileged NAT).
    if caps.unprivileged_vhost_user_net {
        match base_cfg(a)
            .net(NetConfig::Unprivileged {
                egress: Egress::Open,
                host_services_port: None,
            })
            .build()
            .map_err(|e| e.to_string())
        {
            Err(e) => record(
                outcomes,
                "net.ip_pnp",
                Level::Extended,
                Err(format!("config: {e}")),
            ),
            Ok(cfg) => match try_start_vm(vmm, cfg).await {
                Err(e) => record(
                    outcomes,
                    "net.ip_pnp",
                    Level::Extended,
                    Err(failed_start(&e)),
                ),
                Ok(mut vm) => {
                    record(
                        outcomes,
                        "net.ip_pnp",
                        Level::Extended,
                        net_ip_pnp(&mut vm).await,
                    );
                    let _ = vm.shutdown().await;
                }
            },
        }
    } else {
        skip(
            outcomes,
            "net.ip_pnp",
            Level::Extended,
            format!("backend {} lacks unprivileged_vhost_user_net", vmm.id()),
        );
    }

    // virtio-fs shares. Needs both the backend capability AND CAP_SYS_ADMIN (for virtiofsd's
    // `--sandbox namespace`); without the cap virtiofsd cannot mount — an environment limitation,
    // not an artifact defect — so skip-with-reason rather than fail.
    if !caps.virtio_fs_shares {
        skip(
            outcomes,
            "virtiofs.shares",
            Level::Extended,
            format!("backend {} lacks virtio_fs_shares", vmm.id()),
        );
    } else if !crate::harness::has_cap_sys_admin() {
        skip(
            outcomes,
            "virtiofs.shares",
            Level::Extended,
            "virtio-fs shares need CAP_SYS_ADMIN for the virtiofsd sandbox",
        );
    } else {
        run_shares_check(vmm, a, outcomes).await;
    }

    // nested virt.
    if caps.nested_virt {
        match base_cfg(a)
            .network_disabled()
            .build()
            .map_err(|e| e.to_string())
        {
            Err(e) => record(
                outcomes,
                "nested.kvm_ok",
                Level::Extended,
                Err(format!("config: {e}")),
            ),
            Ok(mut cfg) => {
                cfg.nested_virt = true;
                match try_start_vm(vmm, cfg).await {
                    Err(e) => record(
                        outcomes,
                        "nested.kvm_ok",
                        Level::Extended,
                        Err(failed_start(&e)),
                    ),
                    Ok(mut vm) => {
                        // Captured before the `&mut` agent borrow (see `guest_core_checks`).
                        let serial_log = vm.instance().serial_log().to_path_buf();
                        let res = match vm.agent(Some(AGENT_READY_BUDGET)).await {
                            Ok(agent) => nested_kvm_ok(agent).await,
                            Err(e) => Err(explain_boot_failure_at(
                                &serial_log,
                                &agent_handshake_base(&e, AGENT_READY_BUDGET),
                            )
                            .await),
                        };
                        record(outcomes, "nested.kvm_ok", Level::Extended, res);
                        let _ = vm.shutdown().await;
                    }
                }
            }
        }
    } else {
        skip(
            outcomes,
            "nested.kvm_ok",
            Level::Extended,
            format!("backend {} lacks nested_virt", vmm.id()),
        );
    }

    // cgroup usage readout.
    if cgroup_memory_delegated() {
        match base_cfg(a)
            .network_disabled()
            .build()
            .map_err(|e| e.to_string())
        {
            Err(e) => record(
                outcomes,
                "metrics.usage_readable",
                Level::Extended,
                Err(format!("config: {e}")),
            ),
            Ok(mut cfg) => {
                cfg.limits.mem_max_mib = Some(256);
                match try_start_vm(vmm, cfg).await {
                    Err(e) => record(
                        outcomes,
                        "metrics.usage_readable",
                        Level::Extended,
                        Err(failed_start(&e)),
                    ),
                    Ok(mut vm) => {
                        record(
                            outcomes,
                            "metrics.usage_readable",
                            Level::Extended,
                            usage_readable_after_agent_ready(
                                &mut vm,
                                AGENT_READY_BUDGET,
                                USAGE_SETTLE,
                            )
                            .await,
                        );
                        let _ = vm.shutdown().await;
                    }
                }
            }
        }
    } else {
        skip(
            outcomes,
            "metrics.usage_readable",
            Level::Extended,
            "memory cgroup controller not delegated to this process",
        );
    }
}

/// Boots a VM with a RO + RW virtio-fs share and runs the shares check.
async fn run_shares_check<V: Vmm>(vmm: &V, a: &ArtifactSet, outcomes: &mut Vec<CheckOutcome>) {
    let tmp = match tempfile::tempdir() {
        Ok(t) => t,
        Err(e) => {
            record(
                outcomes,
                "virtiofs.shares",
                Level::Extended,
                Err(format!("tempdir: {e}")),
            );
            return;
        }
    };
    let in_dir = tmp.path().join("in");
    let out_dir = tmp.path().join("out");
    if let Err(e) =
        std::fs::create_dir_all(&in_dir).and_then(|()| std::fs::create_dir_all(&out_dir))
    {
        record(
            outcomes,
            "virtiofs.shares",
            Level::Extended,
            Err(format!("mkdir: {e}")),
        );
        return;
    }
    if let Err(e) = std::fs::write(in_dir.join("input.txt"), "hello world") {
        record(
            outcomes,
            "virtiofs.shares",
            Level::Extended,
            Err(format!("seed RO share: {e}")),
        );
        return;
    }
    let cfg = match base_cfg(a)
        .with_share(Share::new(
            "vmcell-in",
            &in_dir,
            Access::ReadOnly,
            CachePolicy::Never,
        ))
        .with_share(Share::new(
            "vmcell-out",
            &out_dir,
            Access::ReadWrite,
            CachePolicy::Never,
        ))
        .network_disabled()
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            record(
                outcomes,
                "virtiofs.shares",
                Level::Extended,
                Err(format!("config: {e}")),
            );
            return;
        }
    };
    match try_start_vm(vmm, cfg).await {
        Err(e) => record(
            outcomes,
            "virtiofs.shares",
            Level::Extended,
            Err(failed_start(&e)),
        ),
        Ok(mut vm) => {
            // Captured before the `&mut` agent borrow (see `guest_core_checks`).
            let serial_log = vm.instance().serial_log().to_path_buf();
            let res = match vm.agent(Some(AGENT_READY_BUDGET)).await {
                Ok(agent) => virtiofs_shares(agent, &out_dir).await,
                Err(e) => Err(explain_boot_failure_at(
                    &serial_log,
                    &agent_handshake_base(&e, AGENT_READY_BUDGET),
                )
                .await),
            };
            record(outcomes, "virtiofs.shares", Level::Extended, res);
            let _ = vm.shutdown().await;
        }
    }
}

/// Full: the expensive/privileged contract — snapshot/restore, concurrency, memory-limit OOM.
pub async fn run_full<V: Vmm>(vmm: &V, a: &ArtifactSet, outcomes: &mut Vec<CheckOutcome>) {
    let caps = vmm.capabilities();

    // concurrency (no special capability).
    record(
        outcomes,
        "concurrency.distinct_ids",
        Level::Full,
        concurrency_distinct_ids(vmm, a).await,
    );

    // snapshot / restore.
    if caps.snapshot_restore {
        record(
            outcomes,
            "snapshot.restore_roundtrip",
            Level::Full,
            snapshot_restore_roundtrip(vmm, a).await,
        );
    } else {
        skip(
            outcomes,
            "snapshot.restore_roundtrip",
            Level::Full,
            format!("backend {} lacks snapshot_restore", vmm.id()),
        );
    }

    // memory-limit OOM.
    if cgroup_memory_delegated() {
        match base_cfg(a)
            .mem_mib(512)
            .network_disabled()
            .build()
            .map_err(|e| e.to_string())
        {
            Err(e) => record(
                outcomes,
                "metrics.mem_limit_ooms",
                Level::Full,
                Err(format!("config: {e}")),
            ),
            Ok(mut cfg) => {
                cfg.limits.mem_max_mib = Some(256);
                match try_start_vm(vmm, cfg).await {
                    Err(e) => record(
                        outcomes,
                        "metrics.mem_limit_ooms",
                        Level::Full,
                        Err(failed_start(&e)),
                    ),
                    Ok(mut vm) => {
                        record(
                            outcomes,
                            "metrics.mem_limit_ooms",
                            Level::Full,
                            metrics_mem_limit_ooms(&mut vm).await,
                        );
                        let _ = vm.shutdown().await;
                    }
                }
            }
        }
    } else {
        skip(
            outcomes,
            "metrics.mem_limit_ooms",
            Level::Full,
            "memory cgroup controller not delegated to this process",
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vmcell::vmm::{FakeVmm, FaultMenu};

    #[test]
    fn test_parse_oom_kill() {
        assert_eq!(parse_oom_kill("low 0\noom_kill 3\n"), Some(3));
        assert_eq!(parse_oom_kill("low 0\nhigh 1\n"), None);
    }

    /// A guest that panicked mounting the erofs root, as the console really records it. Written to
    /// a real file by the tests below, because the bug class these tests exist to catch lives in
    /// the *reading* — `classify.rs`'s canned-log tests never touch the filesystem.
    const PANICKED_CONSOLE: &str = "\
[    0.000000] Linux version 6.12.94 (build@vmcell) #1 SMP PREEMPT_DYNAMIC
[    0.402244] No filesystem could mount root, tried:
[    0.402901] Kernel panic - not syncing: VFS: Unable to mount root fs on unknown-block(254,0)
";

    /// The same guest, before it ever printed the banner (the console the banner poll would see).
    const PANICKED_CONSOLE_NO_BANNER: &str = "\
[    0.402244] No filesystem could mount root, tried:
[    0.402901] Kernel panic - not syncing: VFS: Unable to mount root fs on unknown-block(254,0)
";

    // THE wiring gate. `classify.rs`'s tests all call the classifier directly, so a `serial_text`
    // that read the log and threw it away (`Ok(_) => String::new()`) left 21/21 green while every
    // classified boot failure reported the wrong clause. This drives the real fs read: the bytes on
    // disk must reach the classifier and the tail.
    #[tokio::test]
    async fn explain_boot_failure_at_classifies_the_console_it_read() {
        let dir = tempfile::tempdir().expect("tempdir");
        let log = dir.path().join("serial.log");
        std::fs::write(&log, PANICKED_CONSOLE).expect("write console");

        let msg = explain_boot_failure_at(&log, "agent handshake failed").await;
        assert!(msg.starts_with("agent handshake failed"), "{msg}");
        assert!(
            msg.contains("contract violation:") && msg.contains("CONFIG_EROFS_FS"),
            "the message must name the clause the console proves: {msg}"
        );
        assert!(
            msg.contains("VFS: Unable to mount root fs on unknown-block(254,0)"),
            "the tail must quote the console that was read: {msg}"
        );
        assert!(msg.contains(&log.display().to_string()), "{msg}");
    }

    // An unreadable console is absence of evidence, not proof of a silent console: it must not be
    // rendered as the "not a direct-boot PVH vmlinux" contract violation.
    #[tokio::test]
    async fn explain_boot_failure_at_reports_absence_when_the_console_is_unreadable() {
        let dir = tempfile::tempdir().expect("tempdir");
        let missing = dir.path().join("never-created.log");

        let msg = explain_boot_failure_at(&missing, "agent handshake failed").await;
        assert!(msg.contains("no serial evidence:"), "{msg}");
        assert!(msg.contains("it could not be read"), "{msg}");
        assert!(
            !msg.contains("contract violation:"),
            "an unreadable log proves no clause: {msg}"
        );
    }

    // The banner poll feeds the classifier the newest text it actually read. Guards dropping
    // `last` (the poll's only evidence) and a poll wired to a second copy of the banner literal.
    #[tokio::test]
    async fn await_kernel_banner_classifies_the_console_it_polled() {
        let dir = tempfile::tempdir().expect("tempdir");
        let log = dir.path().join("serial.log");
        std::fs::write(&log, PANICKED_CONSOLE_NO_BANNER).expect("write console");

        let err = await_kernel_banner(&log, Duration::from_millis(50))
            .await
            .expect_err("a console without the banner must fail the check");
        assert!(
            err.contains("contract violation:") && err.contains("CONFIG_EROFS_FS"),
            "the banner arm must classify the console it polled: {err}"
        );
    }

    // The positive control for the shared banner literal: a real banner line satisfies the poll.
    // Guards the poll and `classify_serial` drifting onto two different literals.
    #[tokio::test]
    async fn await_kernel_banner_accepts_the_shared_banner_literal() {
        let dir = tempfile::tempdir().expect("tempdir");
        let log = dir.path().join("serial.log");
        std::fs::write(&log, PANICKED_CONSOLE).expect("write console");
        assert!(
            PANICKED_CONSOLE.contains(BANNER_SIGNATURE),
            "the fixture must carry the banner the kernel really prints"
        );

        await_kernel_banner(&log, Duration::from_millis(50))
            .await
            .expect("a console carrying the banner passes the check");
    }

    // A console file the VMM never created is no evidence at all — not "the VM ran and printed
    // nothing". Guards the arm that used to classify an empty string as NoDirectBootKernel.
    #[tokio::test]
    async fn await_kernel_banner_without_a_console_reports_absence() {
        let dir = tempfile::tempdir().expect("tempdir");
        let missing = dir.path().join("never-created.log");

        let err = await_kernel_banner(&missing, Duration::from_millis(50))
            .await
            .expect_err("no console means the check fails");
        assert!(err.contains("no serial evidence:"), "{err}");
        assert!(
            !err.contains("contract violation:"),
            "a console that never existed proves no clause: {err}"
        );
        assert!(
            err.contains("CONFIG_PVH"),
            "the candidate cause survives: {err}"
        );
    }

    // `run_core`'s start-failure arm, driven end to end without KVM: both Core boot ids stay in the
    // report (a failed start must not shrink the roster) and both carry the no-evidence rendering
    // rather than an asserted contract violation — `MicroVm::start` also fails for reasons that are
    // not the artifact pair, which is exactly what a missing `cloud-hypervisor` binary looks like.
    #[tokio::test]
    async fn run_core_records_both_boot_checks_when_the_vm_never_starts() {
        let vmm = FakeVmm::with_faults(FaultMenu {
            fail_create: true,
            ..FaultMenu::default()
        });
        let artifacts = ArtifactSet::new("/nonexistent/vmlinux", "/nonexistent/rootfs.erofs");
        let mut outcomes = Vec::new();
        run_core(&vmm, &artifacts, &mut outcomes).await;

        let ids: Vec<&str> = outcomes.iter().map(|o| o.id).collect();
        assert_eq!(
            ids,
            vec!["boot.kernel_banner", "boot.agent_ready"],
            "{ids:?}"
        );
        for o in &outcomes {
            let crate::CheckStatus::Fail(msg) = &o.status else {
                panic!(
                    "{} must fail when the VM never starts: {:?}",
                    o.id, o.status
                );
            };
            assert!(msg.contains("VM failed to start:"), "{msg}");
            assert!(msg.contains("no serial evidence:"), "{msg}");
            assert!(
                !msg.contains("contract violation:"),
                "a VMM that never started proves no §5.4 clause: {msg}"
            );
            assert!(
                msg.contains("CONFIG_PVH"),
                "the candidate cause survives: {msg}"
            );
        }
    }

    // Every Extended/Full arm reports its boot failures through the same renderer as Core — the
    // crate doc's "every arm that reports a VM which failed to start" claim, driven. Guards the
    // bare `Err(format!("boot: {e}"))` these arms used to record, which named no clause, no
    // console, and no candidate cause.
    #[tokio::test]
    async fn every_extended_and_full_boot_failure_names_the_missing_evidence() {
        let vmm = FakeVmm::with_faults(FaultMenu {
            fail_create: true,
            ..FaultMenu::default()
        });
        let artifacts = ArtifactSet::new("/nonexistent/vmlinux", "/nonexistent/rootfs.erofs");
        let mut outcomes = Vec::new();
        run_extended(&vmm, &artifacts, &mut outcomes).await;
        run_full(&vmm, &artifacts, &mut outcomes).await;

        let failures: Vec<(&str, &String)> = outcomes
            .iter()
            .filter_map(|o| match &o.status {
                crate::CheckStatus::Fail(m) => Some((o.id, m)),
                _ => None,
            })
            .collect();
        assert!(
            failures.len() >= 3,
            "a backend that cannot create a VM must fail several Extended/Full checks; got \
             {failures:?} (skips: {:?})",
            outcomes
                .iter()
                .map(|o| (o.id, &o.status))
                .collect::<Vec<_>>()
        );
        for (id, msg) in failures {
            assert!(
                msg.contains("no serial evidence:"),
                "{id} reports a boot failure without routing through the renderers: {msg}"
            );
        }
    }

    // The agent budget is one law in one place. Guards re-inlining a per-call literal — the state
    // the module was in with the const declared and seven copies of the number still in the calls.
    #[test]
    fn every_agent_budget_is_a_named_const() {
        const SRC: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/checks.rs"));
        // Built at runtime so this test's own needles are not the thing it counts.
        let literal = format!("Duration::from_secs({})", AGENT_READY_BUDGET.as_secs());
        assert_eq!(
            SRC.matches(&literal).count(),
            1,
            "{literal} must appear exactly once (the AGENT_READY_BUDGET const)"
        );
        let inline_call = format!("agent(Some(Duration::{}", "from_secs");
        assert_eq!(
            SRC.matches(&inline_call).count(),
            0,
            "every `agent(Some(..))` budget must be a named const, not an inline literal"
        );
    }

    // `metrics.usage_readable` must FAIL, naming the boot failure, when the guest never hands
    // shakes. The handshake was a bare `let _` (`usage-readable-swallows-agent-handshake`), so the
    // arm walked into the cgroup readout on a guest that never booted and reported anything but the
    // reason — on a host where the counters happen to read back, a green PASS.
    //
    // KVM-free: the fake backend's vsock path has no listener, so the handshake genuinely fails;
    // the budget is injected (1s, not `AGENT_READY_BUDGET`) so it fails in a second rather than a
    // minute, and the message must name *that* budget. What this fake cannot see is the pass side —
    // a real delegated cgroup readout — which is the live `metrics.usage_readable` leg of a
    // `Level::Extended` validation run on a KVM host.
    #[tokio::test]
    async fn usage_readable_fails_naming_the_boot_failure_when_the_agent_never_handshakes() {
        let vmm = FakeVmm::default();
        let cfg = base_cfg(&ArtifactSet::new(
            "/nonexistent/vmlinux",
            "/nonexistent/rootfs.erofs",
        ))
        .network_disabled()
        .build()
        .expect("config builds");
        let mut vm = try_start_vm(&vmm, cfg)
            .await
            .expect("the fake backend starts");
        let serial = vm.instance().serial_log().display().to_string();

        let err = usage_readable_after_agent_ready(&mut vm, Duration::from_secs(1), Duration::ZERO)
            .await
            .expect_err("a guest that never hands shakes has no readable usage to report");
        assert!(
            err.starts_with("agent handshake failed within the 1s budget"),
            "the arm must report the handshake failure, with the budget it really used: {err}"
        );
        assert!(
            err.contains(&serial),
            "the message must name the VM's own console ({serial}): {err}"
        );
        assert!(
            !err.contains("memory controller delegated"),
            "a guest that never booted must not be reported as a cgroup readout problem: {err}"
        );
        vm.kill().await.expect("the fake backend stops");
    }

    // The one line that turns a VM into a console path. Guards `explain_boot_failure_for` reading
    // some other file than the VM's own serial log.
    #[tokio::test]
    async fn explain_boot_failure_for_reads_the_vms_own_console() {
        let vmm = FakeVmm::default();
        let cfg = base_cfg(&ArtifactSet::new(
            "/nonexistent/vmlinux",
            "/nonexistent/rootfs.erofs",
        ))
        .network_disabled()
        .build()
        .expect("config builds");
        let mut vm = try_start_vm(&vmm, cfg)
            .await
            .expect("the fake backend starts");
        let expected = vm.instance().serial_log().display().to_string();

        let msg = explain_boot_failure_for(&vm, "agent handshake failed").await;
        assert!(
            msg.contains(&expected),
            "the message must name the VM's own serial log ({expected}): {msg}"
        );
        vm.kill().await.expect("the fake backend stops");
    }
}
