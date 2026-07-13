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

use std::time::Duration;

use vmcell::ExecRequest;
use vmcell::agent::AgentClient;
use vmcell::config::{
    Access, CachePolicy, Egress, NetConfig, RootfsSource, Share, VmConfig, VmConfigBuilder,
};
use vmcell::orchestrator::MicroVm;
use vmcell::vmm::{VmInstance, Vmm};

use crate::harness::{cgroup_memory_delegated, try_start_vm};
use crate::{ArtifactSet, CheckOutcome, Level};

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

/// The kernel reaches userspace: the serial console shows the "Linux version" banner within a
/// bounded window (← `boot.rs`). A kernel that never boots (bad config, wrong format) reddens.
///
/// # Errors
/// Returns `Err` if the kernel never reaches userspace within the boot window (bad config / wrong format) or the console cannot be read.
pub async fn kernel_banner<V: Vmm>(vm: &MicroVm<V>) -> Result<(), String> {
    let log = vm.instance().serial_log().to_path_buf();
    for _ in 0..150 {
        if let Ok(content) = tokio::fs::read_to_string(&log).await
            && content.contains("Linux version")
        {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Err(format!(
        "kernel did not print the 'Linux version' banner within 15s (serial log {})",
        log.display()
    ))
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

/// The rootfs ships glibc `libc.so.6` (← §5.4 libc6 scan; the dynamically-linked agent already
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

/// The injected deployment proxy CA is baked into the trust store (← §5.4 / §11 CA injection).
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
/// the agent's exec PATH (← §5.3).
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
/// the root fs (← §5.1). A read-only-only root (missing overlay/tmpfs) reddens.
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
/// (← `host_endpoint.rs`, §8.3/§12.3). Asserts, via guest-tools `ip`, that `eth0` is `state up`
/// carrying the **exact** `(vmid%254)+1` /30 address the orchestrator's `ip_math` expects (a
/// kernel that configured a wrong/default address, or a cmdline/`ip_math` desync, reddens), and
/// that a non-empty routing table exists (IP-PNP installs the default route).
///
/// # Errors
/// Returns `Err` if `eth0` is not `state up`, carries the wrong address vs `ip_math`, or has no route.
pub async fn net_ip_pnp<V: Vmm>(vm: &mut MicroVm<V>) -> Result<(), String> {
    let (_, guest_ip, _) = vmcell::net::ip_math(vm.vmid())
        .map_err(|e| format!("ip_math({}) failed: {e}", vm.vmid()))?;
    let agent = vm
        .agent(Some(Duration::from_secs(60)))
        .await
        .map_err(|e| format!("agent connect failed: {e}"))?;
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
/// writes are visible on the host (← `shares_ro_rw.rs`, §5.2). `in_marker` was written to the RO
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
    // RO write is rejected with the SPECIFIC EROFS signal (not any nonzero — §5.2/L-TEST-1).
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
/// §8.3). The VM must have been booted with `nested_virt = true`.
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
/// §7.1). Requires the memory controller delegated (the caller gates on that).
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

// ---------------------------------------------------------------------------
// Full checks
// ---------------------------------------------------------------------------

/// Boots N VMs **concurrently** on shared allocators and asserts each gets a distinct
/// vmid / guest-CID / vsock path and execs successfully (← `concurrency.rs`, §12.0). Catches an
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
        vms.push(res.map_err(|e| format!("concurrent VM start failed: {e}"))?);
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
        let agent = vm
            .agent(Some(Duration::from_secs(180)))
            .await
            .map_err(|e| format!("concurrent VM agent connect failed: {e}"))?;
        let out = exec(agent, &["true"]).await?;
        if out.code != 0 {
            return Err(format!("concurrent VM exec `true` exited {}", out.code));
        }
        let _ = vm.shutdown().await;
    }
    Ok(())
}

/// Snapshot a running VM and restore it, confirming the **restored** VM boots back to
/// agent-ready and execs (← `snapshot_restore.rs`, §9/§12.4). Proves the artifact survives the
/// PVH snapshot/restore path. The VM must be a snapshot-eligible config (no vhost-user device).
///
/// # Errors
/// Returns `Err` if snapshot or restore fails, or the restored VM does not return to agent-ready and exec.
pub async fn snapshot_restore_roundtrip<V: Vmm>(vmm: &V, a: &ArtifactSet) -> Result<(), String> {
    let mut cfg = base_cfg(a)
        .network_disabled()
        .build()
        .map_err(|e| format!("snapshot-eligible config build failed: {e}"))?;
    // Snapshot-eligible: net=None → no vhost-user device (§12.1); set the flag on the built
    // config (the pair is already vhost-user-free, so this stays valid).
    cfg.snapshotting = true;
    let env = vmcell::HostEnv::hermetic();
    let mut vm = MicroVm::start(vmm, cfg.clone(), &env)
        .await
        .map_err(|e| format!("snapshot-source VM start failed: {e}"))?;
    // Boot to agent-ready before snapshotting.
    vm.agent(Some(Duration::from_secs(60)))
        .await
        .map_err(|e| format!("snapshot-source agent connect failed: {e}"))?;

    let snap_dir = tempfile::tempdir().map_err(|e| format!("tempdir: {e}"))?;
    vm.snapshot(snap_dir.path())
        .await
        .map_err(|e| format!("snapshot() failed: {e}"))?;
    let _ = vm.shutdown().await;

    let mut restored = MicroVm::restore(vmm, snap_dir.path(), cfg, &env)
        .await
        .map_err(|e| format!("restore() failed: {e}"))?;
    let agent = restored
        .agent(Some(Duration::from_secs(60)))
        .await
        .map_err(|e| format!("restored VM did not reach agent-ready: {e}"))?;
    let out = exec(agent, &["true"]).await?;
    if out.code != 0 {
        return Err(format!("restored VM exec `true` exited {}", out.code));
    }
    let _ = restored.shutdown().await;
    Ok(())
}

/// A host cgroup memory cap below guest RAM is the binding limit: a runaway allocation trips the
/// host OOM killer, observable via `memory.events` `oom_kill` (← `metrics_limits.rs`, §7). The VM
/// must be booted with `mem_mib=512, limits.mem_max_mib=Some(256)`.
///
/// # Errors
/// Returns `Err` if the capped allocation does not trip the host OOM killer (no `oom_kill` observed) or the metric cannot be read.
pub async fn metrics_mem_limit_ooms<V: Vmm>(vm: &mut MicroVm<V>) -> Result<(), String> {
    let events_path = cgroup_events_path(vm.vmid());
    // Fire a runaway allocation; the VMM may itself be OOM-killed, so ignore the exec result —
    // the binding signal is the host counter.
    {
        let agent = vm
            .agent(Some(Duration::from_secs(60)))
            .await
            .map_err(|e| format!("agent connect failed: {e}"))?;
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
            record(
                outcomes,
                "boot.agent_ready",
                Level::Core,
                Err(format!("VM failed to start: {e}")),
            );
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
    match vm.agent(Some(Duration::from_secs(60))).await {
        Ok(_) => record(outcomes, "boot.agent_ready", Level::Core, Ok(())),
        Err(e) => {
            record(
                outcomes,
                "boot.agent_ready",
                Level::Core,
                Err(format!("agent handshake failed: {e}")),
            );
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
    let agent = match vm.agent(Some(Duration::from_secs(60))).await {
        Ok(a) => a,
        Err(e) => {
            return vec![(
                "agent.exec_roundtrip",
                Err(format!("agent unavailable: {e}")),
            )];
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
                    Err(format!("boot: {e}")),
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
                        Err(format!("boot: {e}")),
                    ),
                    Ok(mut vm) => {
                        let res = match vm.agent(Some(Duration::from_secs(60))).await {
                            Ok(agent) => nested_kvm_ok(agent).await,
                            Err(e) => Err(format!("agent connect: {e}")),
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
                        Err(format!("boot: {e}")),
                    ),
                    Ok(mut vm) => {
                        // Let it consume some memory first.
                        let _ = vm.agent(Some(Duration::from_secs(60))).await;
                        tokio::time::sleep(Duration::from_secs(2)).await;
                        record(
                            outcomes,
                            "metrics.usage_readable",
                            Level::Extended,
                            metrics_usage_readable(&vm).await,
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
            Err(format!("boot: {e}")),
        ),
        Ok(mut vm) => {
            let res = match vm.agent(Some(Duration::from_secs(60))).await {
                Ok(agent) => virtiofs_shares(agent, &out_dir).await,
                Err(e) => Err(format!("agent connect: {e}")),
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
                        Err(format!("boot: {e}")),
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

    #[test]
    fn test_parse_oom_kill() {
        assert_eq!(parse_oom_kill("low 0\noom_kill 3\n"), Some(3));
        assert_eq!(parse_oom_kill("low 0\nhigh 1\n"), None);
    }
}
