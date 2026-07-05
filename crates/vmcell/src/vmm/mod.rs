//! Virtual Machine Monitor (VMM) abstraction and management.
//!
//! This module provides a generic abstraction for different VMM backends
//! (like Cloud Hypervisor), as well as fake implementations for testing.

use crate::config::VmConfig;
use crate::error::Result;
/// Cloud Hypervisor VMM backend implementation.
pub mod cloud_hypervisor;

pub use cloud_hypervisor::{ChInstance, CloudHypervisor};

#[cfg(feature = "firecracker")]
/// Firecracker VMM backend implementation.
pub mod firecracker;

#[cfg(feature = "firecracker")]
pub use firecracker::{FcInstance, Firecracker};

#[cfg(feature = "qemu")]
/// QEMU VMM backend implementation.
pub mod qemu;

#[cfg(feature = "qemu")]
pub use qemu::{Qemu, QemuInstance};

use serde::Serialize;
use std::path::{Path, PathBuf};

/// A trait for reading a serial log.
pub trait SerialLog: Send + Sync {
    /// Checks if the log contains a kernel panic.
    fn contains_panic(&self) -> bool;
}

/// A real serial log that reads from a file.
pub struct RealSerialLog {
    /// The path to the log file.
    pub path: PathBuf,
}

impl SerialLog for RealSerialLog {
    fn contains_panic(&self) -> bool {
        if self.path.exists()
            && let Ok(log_content) = std::fs::read_to_string(&self.path)
        {
            return log_content.contains("Kernel panic")
                || log_content.contains("panicked at")
                || log_content.contains("panic - not syncing");
        }
        false
    }
}

/// A fake serial log for testing.
pub struct FakeSerialLog {
    /// Whether a panic is simulated.
    pub panicked: bool,
}

impl SerialLog for FakeSerialLog {
    fn contains_panic(&self) -> bool {
        self.panicked
    }
}

/// Helper to send an HTTP request over a Unix domain socket.
///
/// Bounds the whole connect → handshake → send → collect sequence with a fixed
/// ceiling so a wedged VMM control socket can never hang a `create`/`boot`/`pause`/
/// `snapshot` RPC forever — the failure surfaces as a typed
/// [`Error::Timeout`](crate::error::Error::Timeout) before an outer readiness timeout
/// could mask it (M-VMM-2). The QMP path already caps at 2 s; this uses a wider margin.
///
/// # Errors
/// Returns an error if the request cannot be sent, the server returns a non-2xx
/// status (as [`Error::VmmApi`](crate::error::Error::VmmApi) carrying the status and
/// body), or the request does not complete within the timeout ceiling
/// ([`Error::Timeout`](crate::error::Error::Timeout)).
pub async fn unix_api_request<T: Serialize>(
    api_socket: &Path,
    method: &str,
    path: &str,
    body: Option<&T>,
) -> Result<()> {
    const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

    tokio::time::timeout(REQUEST_TIMEOUT, async move {
        let stream = tokio::net::UnixStream::connect(api_socket).await?;

        let io = hyper_util::rt::TokioIo::new(stream);
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;

        tokio::task::spawn(async move {
            if let Err(err) = conn.await {
                tracing::warn!("HTTP connection failed: {:?}", err);
            }
        });

        let body_bytes = if let Some(b) = body {
            serde_json::to_vec(b)
                .map_err(|e| crate::error::Error::Serialize(format!("serialize: {e}")))?
        } else {
            Vec::new()
        };

        let req = hyper::Request::builder()
            .method(method)
            .uri(path)
            .header("Host", "localhost")
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .body(http_body_util::Full::new(hyper::body::Bytes::from(
                body_bytes,
            )))?;

        let res = sender.send_request(req).await?;

        if !res.status().is_success() {
            let status = res.status();
            use http_body_util::BodyExt;
            let bytes = res
                .into_body()
                .collect()
                .await
                .map(|c| c.to_bytes())
                .unwrap_or_default();
            return Err(crate::error::Error::VmmApi {
                status: status.as_u16(),
                body: String::from_utf8_lossy(&bytes).into_owned(),
            });
        }

        Ok(())
    })
    .await
    .map_err(|_| {
        crate::error::Error::Timeout(format!(
            "VMM API request {method} {path} did not complete within {REQUEST_TIMEOUT:?}"
        ))
    })?
}

/// RAII guard owning a single per-VM scratch directory under the system temp dir
/// (`/tmp/vmcell-vm-{pid}-{vmid}/`).
///
/// The orchestrator creates exactly one of these per VM — before networking setup —
/// and threads its [`path`](VmTempDir::path) to every VMM backend through
/// [`PerVmResources::tmp_dir`]. Every per-VM temporary (the API/QMP socket, the
/// vsock socket, the serial log, the smoltcp NAT socket, virtiofsd sockets) lives
/// inside this one directory with a single owner, replacing the former
/// triplicated per-backend create/own/delete.
///
/// On [`Drop`] the directory and everything in it is removed via
/// `remove_vm_tmp_dir` (idempotent, private), so creating the guard early also reclaims
/// the directory if VM construction fails partway. `MicroVm` drops this guard
/// **after** the VMM process group, the vhost-user daemons, and the smoltcp
/// process are gone, so removal never races a process still holding a socket
/// inside it.
#[derive(Debug)]
pub struct VmTempDir {
    /// The owned per-VM directory path.
    path: PathBuf,
}

/// Builds the per-VM scratch-directory path under `base` for process `pid` and
/// VM id `vmid`.
///
/// Pure and **injective in `(pid, vmid)`**: the `-` delimiter guarantees that,
/// e.g., `(1, 23)` and `(12, 3)` never collapse to the same directory, so every
/// per-VM path derived from it (`api.sock`/`vsock.sock`/`serial.log`) is unique
/// per `(pid, vmid)`. This is the property the path-injectivity prop test pins
/// (design §12.3 / §12.7 — "Temp-dir collision on PID-only path"); isolating the
/// construction here is what makes `(pid, vmid)` prop-exercisable without a real
/// process id.
#[must_use]
pub(crate) fn per_vm_scratch_dir(prefix: &str, base: &Path, pid: u32, vmid: u32) -> PathBuf {
    base.join(crate::naming::scratch_dir_name(prefix, pid, vmid))
}

impl VmTempDir {
    /// Creates the per-VM temporary directory `<temp>/<prefix>-vm-{pid}-{vmid}/` and returns a guard
    /// that removes it on drop. `prefix` is the VM's [`resource_prefix`](crate::config::VmConfig).
    ///
    /// # Errors
    /// Returns an error if the directory cannot be created.
    pub async fn create(prefix: &str, vmid: u32) -> Result<Self> {
        let path = per_vm_scratch_dir(prefix, &std::env::temp_dir(), std::process::id(), vmid);
        tokio::fs::create_dir_all(&path).await?;
        Ok(Self { path })
    }

    /// Returns the path to the owned per-VM directory.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for VmTempDir {
    fn drop(&mut self) {
        remove_vm_tmp_dir(&self.path);
    }
}

/// Removes a per-VM temporary directory owned by a [`VmTempDir`] guard,
/// including its serial log, lock files, and any leftover sockets.
///
/// Without this the directory (holding `serial.log`, and `api.sock.lock` for CH)
/// leaks one-per-VM and `/tmp` grows unbounded across runs (E3). Call it on the
/// owning instance's `Drop`/teardown path **after** the VMM process group has
/// been reaped, so removal never races a live VMM.
///
/// Best-effort by design: this runs on the `Drop` path where there is no
/// `Result` to surface and `Drop` must not panic; the directory may also already
/// be gone. A genuine removal failure is logged for visibility rather than
/// swallowed silently.
pub(crate) fn remove_vm_tmp_dir(dir: &Path) {
    if let Err(e) = std::fs::remove_dir_all(dir) {
        // A missing directory is the normal idempotent-teardown case, not a leak.
        if e.kind() != std::io::ErrorKind::NotFound {
            tracing::warn!("failed to remove per-VM temp dir {}: {}", dir.display(), e);
        }
    }
}

/// Builds a Tokio command for the VMM, handling network namespaces and process groups.
pub fn build_vmm_cmd(binary_path: &Path, netns_name: Option<&str>) -> tokio::process::Command {
    let mut std_cmd = std::process::Command::new(binary_path);
    use std::os::unix::process::CommandExt;
    std_cmd.process_group(0);
    if let Some(netns) = netns_name {
        let netns_path = format!("/var/run/netns/{netns}\0");
        // The closure passed to `pre_exec` runs post-fork/pre-exec and calls only async-signal-safe
        // syscalls (`open`/`setns`/`close`) on the pre-allocated, NUL-terminated `netns_path` string —
        // no allocation, no non-reentrant libc call — so it is sound in the forked child. Defined
        // outside the `unsafe` block so each syscall carries its own one-op `unsafe` + SAFETY note.
        let enter_netns = move || -> std::io::Result<()> {
            // SAFETY: `open(2)` on the pre-allocated NUL-terminated `netns_path`; async-signal-safe.
            let fd = unsafe {
                libc::open(
                    netns_path.as_ptr() as *const libc::c_char,
                    libc::O_RDONLY | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                return Err(std::io::Error::last_os_error());
            }
            // SAFETY: `setns(2)` on the fd opened just above; async-signal-safe.
            if unsafe { libc::setns(fd, libc::CLONE_NEWNET) } != 0 {
                let err = std::io::Error::last_os_error();
                // SAFETY: close the fd opened above on the error path; async-signal-safe.
                unsafe { libc::close(fd) };
                return Err(err);
            }
            // SAFETY: close the fd opened above on the success path; async-signal-safe.
            unsafe { libc::close(fd) };
            Ok(())
        };
        // SAFETY: `pre_exec` runs `enter_netns` post-fork/pre-exec; it is async-signal-safe (above).
        unsafe {
            std_cmd.pre_exec(enter_netns);
        }
    }
    tokio::process::Command::from(std_cmd)
}

/// Waits until the given socket path appears, or times out.
///
/// Polls for the socket's existence on an absolute deadline. If the spawned process
/// exits before the socket appears, fails fast with the real exit status instead of
/// falling through to a later, less-informative timeout.
///
/// # Errors
/// - Returns [`Error::Vmm`](crate::error::Error::Vmm) if the process exits before the
///   socket appears.
/// - Returns [`Error::Timeout`](crate::error::Error::Timeout) if the socket does not
///   appear within `timeout_ms`.
pub async fn wait_for_socket(
    socket_path: &Path,
    process: &mut tokio::process::Child,
    timeout_ms: u64,
    interval_ms: u64,
) -> Result<()> {
    // The interval is caller-supplied via the pub `VmConfig.timeouts` field, so clamp
    // it to >= 1 ms (a 0 interval would busy-spin). Drive off an absolute deadline so
    // (a) the socket is checked at least once even when `interval_ms > timeout_ms`
    // (the old `timeout_ms / interval_ms == 0` computed zero iterations and returned
    // Timeout without a single check), and (b) a socket appearing in the final
    // sub-interval is not missed (L-VMM-1).
    let interval = std::time::Duration::from_millis(interval_ms.max(1));
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(timeout_ms);

    loop {
        if tokio::fs::try_exists(socket_path).await.unwrap_or(false) {
            return Ok(());
        }
        // Fail fast on an early VMM exit so the real cause surfaces instead of a
        // later, less-informative Timeout (M-VMM-8).
        if let Some(status) = process.try_wait().unwrap_or(None) {
            return Err(crate::error::Error::Vmm(format!(
                "process exited early: {status}"
            )));
        }

        let now = std::time::Instant::now();
        if now >= deadline {
            break;
        }
        let sleep_dur = interval.min(deadline - now);
        tokio::time::sleep(sleep_dur).await;
    }

    Err(crate::error::Error::Timeout(
        "socket failed to appear in time".into(),
    ))
}

/// Force-kills a just-spawned VMM process *group* (`SIGKILL` to `-pgid`) and reaps
/// the leader. Use on the error paths between spawning a VMM and constructing the
/// owning instance (whose `Drop` would otherwise do this): a failure there — e.g. a
/// cgroup `add_task` or a readiness timeout — must not leak a running VMM, because
/// `tokio::process::Child` does not kill on drop. No-op when `pgid` is `None`.
pub(crate) fn reap_process_group(process: &mut tokio::process::Child, pgid: Option<u32>) {
    let Some(pgid) = pgid else {
        return;
    };
    let _ = nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(-(pgid as i32)),
        nix::sys::signal::Signal::SIGKILL,
    );
    if let Some(pid) = process.id() {
        let _ = nix::sys::wait::waitpid(nix::unistd::Pid::from_raw(pid as i32), None);
    }
}

/// Registers a freshly-spawned VMM process with its cgroup and blocks until its
/// control socket appears, reaping the process **group** on any failure.
///
/// This is the one shared "capture pgid → `add_task` (reap-on-err) → `wait_for_socket`
/// (reap-on-err)" sequence for all three backends (VMM-2). It was copy-pasted into
/// `spawn_ch`/`spawn_fc`/`spawn_qemu` and had already diverged (QEMU wrapped the
/// readiness error in `Error::Vmm` while CH/FC propagated the raw error); routing
/// every backend through this helper makes the error handling **identical** — the
/// place per-backend divergence bugs hide (AGENTS.md "don't triplicate; extract").
///
/// `tokio::process::Child` does not kill on drop, so a cgroup `add_task` failure or a
/// readiness timeout here MUST reap the spawned VMM group or it leaks — the owning
/// instance (whose `Drop` reaps) is not constructed until the caller returns. Returns
/// the captured pgid on success.
///
/// # Errors
/// Returns — after reaping the process group — the raw underlying error: the cgroup
/// `add_task` failure, or the readiness [`Error::Timeout`]/process-exited-early
/// `Error` from [`wait_for_socket`]. The error is returned verbatim and identically
/// across backends, so no backend can silently diverge on how it wraps it.
pub(crate) async fn register_and_await_ready(
    process: &mut tokio::process::Child,
    cgroups: &dyn crate::metrics::CgroupFs,
    cgroup_name: &str,
    socket_path: &Path,
    timeout_ms: u64,
    interval_ms: u64,
) -> Result<Option<u32>> {
    // Capture the process-group id immediately: from here on any error must reap the
    // spawned VMM group, or it leaks.
    let pgid = process.id();

    if let Some(pid) = process.id()
        && let Err(e) = cgroups.add_task(cgroup_name, pid)
    {
        reap_process_group(process, pgid);
        return Err(e);
    }

    if let Err(e) = wait_for_socket(socket_path, process, timeout_ms, interval_ms).await {
        reap_process_group(process, pgid);
        return Err(e);
    }

    Ok(pgid)
}

/// Self-guard that rejects a virtio-fs **rootfs** for a backend that cannot boot one.
///
/// No backend supports a virtio-fs *rootfs* today: booting one would need virtiofsd
/// wired as the root device plus a `rootfstype=virtiofs` kernel cmdline. A plain
/// `VirtioFs`-rootfs config is nonetheless *buildable* — `config::build()` only
/// rejects it when **also** snapshotting — so it reaches `create()`. Without this
/// guard, CH/QEMU hit an empty match arm (no disk attached, no virtiofsd) while the
/// cmdline falls through to `root=/dev/vda rootfstype=ext4` for a VM that has no
/// `/dev/vda`, and the guest kernel-panics on a missing root — silently (VMM-1). Every
/// backend's `create()` therefore self-guards with this instead of assuming the caller
/// checked; it returns a typed [`Error::Unsupported`], mirroring Firecracker.
///
/// # Errors
/// Returns [`Error::Unsupported`] `{ vmm, feature: "virtio_fs_rootfs" }` when `rootfs`
/// is [`crate::config::RootfsSource::VirtioFs`]; `Ok(())` for every other rootfs.
pub(crate) fn reject_virtio_fs_rootfs(
    vmm: &str,
    rootfs: &crate::config::RootfsSource,
) -> Result<()> {
    if matches!(rootfs, crate::config::RootfsSource::VirtioFs { .. }) {
        return Err(crate::error::Error::Unsupported {
            vmm: vmm.to_string(),
            feature: "virtio_fs_rootfs".to_string(),
        });
    }
    Ok(())
}

/// Self-guard that rejects [`ConsoleMode::VirtioConsole`](crate::config::ConsoleMode::VirtioConsole)
/// on a backend whose capability descriptor does not advertise `virtio_console`
/// (Firecracker).
///
/// The kernel-cmdline `console=` token (`build_kernel_cmdline`) and the per-backend
/// console device wiring must move in lockstep: a backend that emitted `console=hvc0`
/// with no virtio-console device would send the guest's console output nowhere and
/// leave `serial.log` silent. Every backend's `create()`/`restore()` self-guards with
/// this instead of assuming the caller checked, returning a typed
/// [`Error::Unsupported`](crate::error::Error::Unsupported) that mirrors the other
/// capability rejects. A [`ConsoleMode::Uart`](crate::config::ConsoleMode::Uart)
/// config is always accepted.
///
/// # Errors
/// Returns [`Error::Unsupported`](crate::error::Error::Unsupported)
/// `{ vmm, feature: "virtio_console" }` when `mode` is `VirtioConsole` and
/// `caps.virtio_console` is `false`; `Ok(())` otherwise.
pub(crate) fn reject_unsupported_console(
    vmm: &str,
    caps: &VmmCapabilities,
    mode: crate::config::ConsoleMode,
) -> Result<()> {
    if matches!(mode, crate::config::ConsoleMode::VirtioConsole) && !caps.virtio_console {
        return Err(crate::error::Error::Unsupported {
            vmm: vmm.into(),
            feature: "virtio_console".into(),
        });
    }
    Ok(())
}

/// Returns `true` when a VM carrying any of these is **not** snapshot-eligible,
/// because it has a vhost-user device attached (a virtio-fs share/rootfs served by
/// virtiofsd, the unprivileged `vhost-user-net` NAT, or an external `vhost-user-net`
/// socket). The snapshot-eligibility law (§3.3) requires every backend to self-guard
/// `snapshot()`/`restore()` against such a VM rather than assume the caller checked.
///
/// This is the ONE shared predicate for all backends (M-VMM-5): the former per-backend
/// copies had already diverged — the Firecracker copy never grew the virtio-fs *rootfs*
/// term the CH copy carried, so a virtio-fs-rootfs restore slipped its guard (H-VMM-3).
/// Centralizing it makes that class of divergence impossible.
pub(crate) fn has_vhost_user_device(
    virtio_fs_share: bool,
    unprivileged_net: bool,
    vhost_user_net: bool,
) -> bool {
    virtio_fs_share || unprivileged_net || vhost_user_net
}

/// Returns `true` when `cfg`/`res` describe a VM that carries any vhost-user device and
/// is therefore **not** snapshot-eligible (§3.3). Covers all three boundary cases at
/// `restore()`/`snapshot()`: a virtio-fs data share **or** a virtio-fs *rootfs* (both
/// backed by virtiofsd — the rootfs case the per-backend copies used to miss, H-VMM-3),
/// the unprivileged `vhost-user-net` NAT, and an external `vhost-user-net` socket.
pub(crate) fn config_has_vhost_user_device(cfg: &VmConfig, res: &PerVmResources) -> bool {
    let virtio_fs = !cfg.shares.is_empty()
        || matches!(cfg.rootfs, crate::config::RootfsSource::VirtioFs { .. });
    has_vhost_user_device(
        virtio_fs,
        matches!(cfg.net, crate::config::NetConfig::Unprivileged { .. }),
        res.vhost_user_socket.is_some(),
    )
}

/// Allocates unique Context IDs (CIDs) for vsock connections.
/// CIDs >= 3 are available for guests.
#[derive(Debug)]
pub struct CidAllocator {
    active: std::sync::Mutex<std::collections::BTreeSet<u32>>,
}

impl CidAllocator {
    /// Creates a new CID allocator.
    #[must_use]
    pub fn new() -> Self {
        Self {
            active: std::sync::Mutex::new(std::collections::BTreeSet::new()),
        }
    }
}

impl Default for CidAllocator {
    fn default() -> Self {
        Self::new()
    }
}

impl CidAllocator {
    /// Allocates and returns a unique Context ID (CID) for VSOCK communication.
    ///
    /// # Errors
    /// Returns an error if all 252 guest CIDs are in use.
    pub fn allocate(&self) -> Result<u32> {
        // Recover from a poisoned lock instead of panicking: the guarded value is
        // a plain `BTreeSet` of live CIDs with no cross-field invariant, so a
        // panic mid-mutation cannot leave it in an unusable state — adopting the
        // inner set is sound.
        let mut active = self.active.lock().unwrap_or_else(|e| e.into_inner());
        for i in 3..=254 {
            if !active.contains(&i) {
                active.insert(i);
                return Ok(i);
            }
        }
        Err(crate::error::Error::Vmm(
            "CID allocator exhausted".to_string(),
        ))
    }

    /// Releases a previously allocated CID.
    pub fn release(&self, cid: u32) {
        // Recover from a poisoned lock instead of panicking: the guarded `BTreeSet`
        // of live CIDs has no cross-field invariant, so adopting the inner set is
        // sound.
        let mut active = self.active.lock().unwrap_or_else(|e| e.into_inner());
        active.remove(&cid);
    }
}

/// Per-VM resources allocated by the orchestrator before VM creation.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct PerVmResources {
    /// Name of the cgroup v2 slice for the VM.
    pub cgroup_name: String,
    /// Optional TAP interface name for privileged networking.
    pub tap_name: Option<String>,
    /// Optional network namespace name for privileged networking.
    pub netns_name: Option<String>,
    /// Optional vhost-user socket path for unprivileged networking.
    pub vhost_user_socket: Option<PathBuf>,
    /// Unique internal VM ID.
    pub vmid: u32,
    /// Context ID for vsock communication.
    pub guest_cid: u32,
    /// Per-VM scratch directory (owned by the orchestrator via [`VmTempDir`]).
    /// Backends derive all of their socket and serial-log paths inside this
    /// directory; it is created once before networking setup and removed once on
    /// teardown.
    pub tmp_dir: PathBuf,
}

/// Virtual Machine Monitor (VMM) capabilities.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct VmmCapabilities {
    /// True if the VMM supports snapshot and restore.
    pub snapshot_restore: bool,
    /// True if the VMM supports lazy userfaultfd-based demand-paged restore.
    pub lazy_restore: bool,
    /// True if the VMM supports virtio-fs shared directories.
    pub virtio_fs_shares: bool,
    /// True if the VMM supports vhost-user-net for unprivileged networking.
    pub unprivileged_vhost_user_net: bool,
    /// True if the VMM supports nested virtualization (exposing KVM to guest).
    pub nested_virt: bool,
    /// True if the VMM can attach a virtio-console (`hvc0`) device (Cloud
    /// Hypervisor and QEMU). Firecracker has no virtio-console, so a
    /// [`ConsoleMode::VirtioConsole`](crate::config::ConsoleMode::VirtioConsole)
    /// config is rejected there (`console=hvc0` with no device silences the log).
    pub virtio_console: bool,
    /// True if `restore()` gives the restored VM **fresh host-side socket paths**
    /// inside its own scratch dir. Cloud Hypervisor does: its restore config
    /// rewrite moves the vsock/serial paths into the new VM's tmp dir before
    /// launch (§9.2). Firecracker does not: `PUT /snapshot/load` re-binds the
    /// snapshot's recorded host vsock UDS path **verbatim** — no load-time
    /// override exists in FC v1.16. Consequences when `false`: every restore of
    /// a snapshot lineage shares the ONE baked host vsock path, so (a) restoring
    /// while the snapshotted VM (or a prior restore of it) is still alive is
    /// rejected by the backend's pre-restore liveness guard, and (b) concurrent
    /// restores from one snapshot lineage are unsupported (the design §16
    /// single-snapshot-CoW gap covers both backends anyway).
    pub restore_rotates_host_paths: bool,
}

/// Abstract Virtual Machine Monitor (VMM) trait.
///
/// A backend abstracts the differences between QEMU, Cloud Hypervisor, and
/// Firecracker. Every implementation **self-checks** unsupported operations against
/// its [`capabilities`](Vmm::capabilities) and returns
/// [`Error::Unsupported`](crate::error::Error::Unsupported) with a typed feature name
/// rather than assuming the caller validated first (design §3.1).
pub trait Vmm: Send + Sync {
    /// The associated instance type representing a running VM.
    type Instance: VmInstance;

    /// Creates a new VM from configuration.
    ///
    /// Spawns the VMM process, registers it with its cgroup, and waits for the control
    /// socket to appear. The returned instance is **ready to
    /// [`boot`](VmInstance::boot)** — the guest is configured but not yet running.
    ///
    /// # Errors
    /// Returns an error if the VMM process fails to spawn or become ready, or if the
    /// configuration is invalid for this backend — e.g.
    /// [`Error::Unsupported`](crate::error::Error::Unsupported) for a virtio-fs rootfs,
    /// an unsupported console mode, or unprivileged networking on a backend that lacks
    /// vhost-user-net.
    async fn create(
        &self,
        cfg: &VmConfig,
        res: &PerVmResources,
        cgroups: &dyn crate::metrics::CgroupFs,
    ) -> Result<Self::Instance>;

    /// Restores a VM from a snapshot directory.
    ///
    /// The returned instance is **paused**: the caller continues with
    /// [`resume`](VmInstance::resume), **never** [`boot`](VmInstance::boot) — the guest
    /// is already running inside the snapshot and is resumed from its paused point, not
    /// cold-booted (design §3.1). Device topology is reconstructed from the snapshot;
    /// `cfg` is consulted only for timeouts, console-mode validation, and capability
    /// self-checks.
    ///
    /// # Errors
    /// - [`Error::Unsupported`](crate::error::Error::Unsupported) when this backend does
    ///   not advertise `capabilities().snapshot_restore`.
    /// - [`Error::Unsupported`](crate::error::Error::Unsupported) when `cfg`/`res` carry
    ///   any vhost-user device (a virtio-fs share or rootfs, unprivileged networking, or
    ///   an external vhost-user-net socket) — the snapshot-eligibility law (§3.3)
    ///   rejects such a VM before restore.
    /// - Snapshot I/O, parse, or VMM-start errors.
    async fn restore(
        &self,
        snapshot_dir: &Path,
        cfg: &VmConfig,
        res: &PerVmResources,
        cgroups: &dyn crate::metrics::CgroupFs,
    ) -> Result<Self::Instance>;

    /// Returns the capabilities of this VMM backend.
    ///
    /// Callers **must** consult this before invoking optional operations (snapshot,
    /// restore, nested virt, virtio-fs, …); a `false` capability means the operation
    /// returns [`Error::Unsupported`](crate::error::Error::Unsupported).
    fn capabilities(&self) -> VmmCapabilities;

    /// Returns the string identifier of this VMM backend.
    fn id(&self) -> &str;
}

/// The vsock port the guest agent listens on and the host connects to. One
/// definition shared by the orchestrator's agent connect and the QEMU
/// control-plane health-gate probe (AGENTS.md "one law, one predicate") — the
/// guest agent's own `VSOCK_PORT` is its mirror on the other side of the boundary.
pub(crate) const AGENT_VSOCK_PORT: u32 = 5000;

/// Represents a running or created VM instance.
pub trait VmInstance: Send {
    /// Boots the VM from a created state.
    ///
    /// Valid only on instances returned by [`Vmm::create`], never on a restored
    /// instance — a restored VM is already running inside its snapshot and must be
    /// [`resume`](VmInstance::resume)d, not booted. Backends whose restored instance
    /// cannot boot self-guard and return
    /// [`Error::Unsupported`](crate::error::Error::Unsupported).
    ///
    /// # Errors
    /// Returns an error if the boot process fails, or
    /// [`Error::Unsupported`](crate::error::Error::Unsupported) if called on a restored
    /// instance.
    async fn boot(&mut self) -> Result<()>;
    /// Requests a graceful shutdown of the VM.
    ///
    /// # Errors
    /// Returns an error if the request cannot be sent.
    async fn request_shutdown(&mut self) -> Result<()>;
    /// Forcefully kills the VM instance.
    ///
    /// # Errors
    /// Returns an error if the VMM process cannot be killed.
    async fn kill(&mut self) -> Result<()>;
    /// Reports, without blocking, whether the underlying VMM process has already
    /// exited. The graceful [`MicroVm::shutdown`](crate::orchestrator::MicroVm::shutdown)
    /// polls this after `request_shutdown` so it can return as soon as the guest
    /// has actually powered off, instead of always sleeping the full grace window
    /// (the `try_wait` early-return ORCH-7 deferred). Defaults to `false`
    /// (conservative — "not known to have exited," so `shutdown` waits its bounded
    /// grace) for backends/fakes without a reapable process handle.
    async fn has_exited(&mut self) -> bool {
        false
    }
    /// Pauses the VM, preparing it for a snapshot.
    ///
    /// # Errors
    /// Returns an error if pausing fails.
    async fn pause(&mut self) -> Result<()>;
    /// Resumes the VM after it was paused or snapshot-restored.
    ///
    /// This is the continuation point for a restored instance (see
    /// [`Vmm::restore`]), which is returned paused rather than booted.
    ///
    /// # Errors
    /// Returns an error if resuming fails.
    async fn resume(&mut self) -> Result<()>;
    /// Snapshots the VM state to the specified directory.
    ///
    /// # Errors
    /// Returns an error if the snapshot operation fails.
    async fn snapshot(&mut self, dir: &Path) -> Result<()>;
    /// Returns the path to this instance's vsock control socket.
    fn vsock_path(&self) -> &Path;
    /// Returns the unique vsock Context ID (CID) assigned to this VM.
    fn guest_cid(&self) -> u32;
    /// Returns the path to the VM's serial log file.
    fn serial_log(&self) -> &Path;

    /// Bounded post-boot check that the guest control-plane (vsock) transport is
    /// actually carrying traffic, so [`MicroVm::start`](crate::MicroVm::start) can
    /// re-spawn a VM whose transport came up half-wired instead of returning it.
    ///
    /// Default: `Ok(())`. Cloud Hypervisor and Firecracker terminate vsock *inside*
    /// the VMM process, so the device cannot half-initialize — there is nothing to
    /// probe. QEMU overrides this: its vsock rides an **external**
    /// `vhost-device-vsock` daemon over a `vhost-user-vsock` virtqueue whose
    /// bring-up races. On the measured host ~11% of QEMU boots leave that data path
    /// wedged for the VM's entire life — the daemon accepts the host `CONNECT` but
    /// never reaches the guest listener — surfacing only ~10 s later as an agent
    /// connection timeout. Returning `Err` here lets the orchestrator recreate the
    /// VM instead. See `docs/benchmark-results.md` ("QEMU agent-timeout flake") and
    /// `tests/qemu_vsock_flake_repro.rs`.
    ///
    /// `budget` bounds the probe; a healthy transport answers well before it, so a
    /// healthy boot pays only its real connect latency, not the whole budget.
    ///
    /// # Errors
    /// Returns an error if the control plane is not confirmed live within `budget`.
    async fn verify_control_plane(
        &self,
        _budget: std::time::Duration,
        _timeouts: &crate::config::Timeouts,
    ) -> Result<()> {
        Ok(())
    }
}

/// A fake VMM for testing without booting a real VM.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct FakeVmm {
    /// Records calls made to the fake VMM.
    pub calls: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
}

/// A fake VM instance for testing.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct FakeVmInstance {
    /// Simulates a vsock path.
    pub vsock_path: PathBuf,
    /// Simulates a serial path.
    pub serial: PathBuf,
    /// Records calls made to the fake instance.
    pub calls: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
}

impl Vmm for FakeVmm {
    type Instance = FakeVmInstance;

    async fn create(
        &self,
        _cfg: &VmConfig,
        _res: &PerVmResources,
        _cgroups: &dyn crate::metrics::CgroupFs,
    ) -> Result<Self::Instance> {
        if let Ok(mut lock) = self.calls.lock() {
            lock.push("create".to_string());
        }
        Ok(FakeVmInstance {
            vsock_path: PathBuf::from("/tmp/fake-vsock"),
            serial: PathBuf::from("/tmp/fake-serial"),
            calls: self.calls.clone(),
        })
    }

    async fn restore(
        &self,
        _snapshot_dir: &Path,
        _cfg: &VmConfig,
        _res: &PerVmResources,
        _cgroups: &dyn crate::metrics::CgroupFs,
    ) -> Result<Self::Instance> {
        if let Ok(mut lock) = self.calls.lock() {
            lock.push("restore".to_string());
        }
        Ok(FakeVmInstance {
            vsock_path: PathBuf::from("/tmp/fake-vsock"),
            serial: PathBuf::from("/tmp/fake-serial"),
            calls: self.calls.clone(),
        })
    }

    fn capabilities(&self) -> VmmCapabilities {
        VmmCapabilities {
            snapshot_restore: true,
            lazy_restore: false,
            virtio_fs_shares: true,
            unprivileged_vhost_user_net: true,
            nested_virt: true,
            virtio_console: true,
            // Mirrors CH (the primary backend the fake stands in for). No fake-
            // backed test asserts on restore paths today; a test exercising the
            // FC-style verbatim-rebind semantics should build its own fake with
            // this set `false`.
            restore_rotates_host_paths: true,
        }
    }

    fn id(&self) -> &str {
        "fake"
    }
}

impl VmInstance for FakeVmInstance {
    async fn boot(&mut self) -> Result<()> {
        if let Ok(mut lock) = self.calls.lock() {
            lock.push("boot".to_string());
        }
        Ok(())
    }
    async fn request_shutdown(&mut self) -> Result<()> {
        if let Ok(mut lock) = self.calls.lock() {
            lock.push("request_shutdown".to_string());
        }
        Ok(())
    }
    async fn kill(&mut self) -> Result<()> {
        if let Ok(mut lock) = self.calls.lock() {
            lock.push("kill".to_string());
        }
        Ok(())
    }
    async fn has_exited(&mut self) -> bool {
        // The fake has no real VMM process to reap, so it is trivially "exited":
        // `shutdown()`'s grace poll returns immediately instead of waiting the full
        // ceiling, keeping the teardown-order unit test fast (it asserts order, not
        // timing).
        true
    }
    async fn pause(&mut self) -> Result<()> {
        if let Ok(mut lock) = self.calls.lock() {
            lock.push("pause".to_string());
        }
        Ok(())
    }
    async fn resume(&mut self) -> Result<()> {
        if let Ok(mut lock) = self.calls.lock() {
            lock.push("resume".to_string());
        }
        Ok(())
    }
    async fn snapshot(&mut self, _dir: &Path) -> Result<()> {
        if let Ok(mut lock) = self.calls.lock() {
            lock.push("snapshot".to_string());
        }
        Ok(())
    }
    fn vsock_path(&self) -> &Path {
        &self.vsock_path
    }
    fn guest_cid(&self) -> u32 {
        3
    }
    fn serial_log(&self) -> &Path {
        &self.serial
    }
}

impl Drop for FakeVmInstance {
    fn drop(&mut self) {
        if let Ok(mut lock) = self.calls.lock() {
            lock.push("drop".to_string());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    // Guards E3: the per-VM temp dir (serial.log + lock + stale sockets) must be
    // removed on teardown, not just the vsock socket. The inverse — a teardown
    // that removes only the sockets and leaves the directory — is exactly the
    // leak this finding reports, and goes red here because the dir still exists.
    #[test]
    fn test_remove_vm_tmp_dir_removes_whole_dir() {
        let parent = tempfile::tempdir().expect("create parent tempdir");
        let vm_dir = parent.path().join("vmcell-vm-1-2");
        std::fs::create_dir_all(&vm_dir).expect("create per-VM dir");
        std::fs::write(vm_dir.join("serial.log"), b"boot log").expect("write serial.log");
        std::fs::write(vm_dir.join("api.sock.lock"), b"").expect("write lock");
        assert!(vm_dir.exists(), "precondition: per-VM dir exists");

        remove_vm_tmp_dir(&vm_dir);

        assert!(
            !vm_dir.exists(),
            "per-VM temp dir (with serial.log) leaked after teardown"
        );

        // Idempotent: removing an already-gone dir is a no-op, not a panic/error.
        remove_vm_tmp_dir(&vm_dir);
    }

    // Guards VMM-1: the shared virtio-fs-rootfs self-guard every backend's `create()`
    // calls. The buggy inverse (no guard — the empty `VirtioFs => {}` match arm CH/QEMU
    // used to hit) silently builds an unbootable VM; here it makes the first assertion
    // go red. An erofs/block rootfs must NOT trip the guard (the inverse over-rejection).
    #[test]
    fn reject_virtio_fs_rootfs_rejects_only_virtio_fs() {
        use crate::config::RootfsSource;

        let err = reject_virtio_fs_rootfs(
            "cloud-hypervisor",
            &RootfsSource::VirtioFs {
                dir: PathBuf::from("/d"),
            },
        )
        .expect_err("a virtio-fs rootfs must be rejected");
        assert!(
            matches!(&err, crate::error::Error::Unsupported { vmm, feature }
                if vmm == "cloud-hypervisor" && feature == "virtio_fs_rootfs"),
            "expected virtio_fs_rootfs Unsupported, got {err:?}"
        );

        // erofs and block roots are bootable — the guard must let them through.
        reject_virtio_fs_rootfs(
            "qemu",
            &RootfsSource::Erofs {
                image: PathBuf::from("/i"),
            },
        )
        .expect("erofs rootfs must be accepted");
        reject_virtio_fs_rootfs(
            "firecracker",
            &RootfsSource::Block {
                image: PathBuf::from("/i"),
                overlay: None,
            },
        )
        .expect("block rootfs must be accepted");
    }

    /// Spawns a long-lived stand-in process in its own process group, returning the
    /// live tokio `Child`. Drives the reap tests without a real VMM binary.
    fn spawn_group_standin() -> tokio::process::Child {
        let mut std_cmd = std::process::Command::new("sleep");
        std_cmd.arg("60");
        use std::os::unix::process::CommandExt;
        std_cmd.process_group(0);
        tokio::process::Command::from(std_cmd)
            .spawn()
            .expect("spawn sleep stand-in")
    }

    // Guards VMM-2: the shared spawn+register+await-ready helper MUST reap the process
    // group when the control socket never appears (readiness failure). The buggy
    // inverse — a backend that diverged and dropped the bare `Child` (no kill-on-drop)
    // on the readiness path — would leave the process running; this asserts the helper
    // both surfaces a `Timeout` and kills the group.
    #[tokio::test]
    async fn register_and_await_ready_reaps_group_on_readiness_failure() {
        let mut process = spawn_group_standin();
        let pid = process.id().expect("stand-in pid") as i32;
        let cgroups = crate::metrics::FakeCgroupFs::new(); // add_task succeeds
        // A socket that never appears + a short timeout forces the readiness failure.
        let never = std::env::temp_dir().join("vmcell-nonexistent-readiness.sock");
        let _ = std::fs::remove_file(&never);

        let result =
            register_and_await_ready(&mut process, &cgroups, "vmcell-test", &never, 100, 20).await;
        assert!(
            matches!(result, Err(crate::error::Error::Timeout(_))),
            "readiness failure must surface a Timeout, got {result:?}"
        );

        // The process group must have been reaped. Poll to stay robust against the
        // host reaper winning the waitpid race.
        let mut gone = false;
        for _ in 0..50 {
            if nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), None).is_err() {
                gone = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(
            gone,
            "register_and_await_ready must reap the process group on a readiness failure"
        );
    }

    // Guards the interval clamp in `wait_for_socket`: the interval is caller-supplied
    // via the pub `VmConfig.timeouts` field, so an unclamped implementation (the buggy
    // inverse) computes `timeout_ms / 0` and panics before any readiness check runs.
    // With the clamp, a 0-interval call degrades to a 1 ms poll and still finds the
    // already-present socket path.
    #[tokio::test]
    async fn wait_for_socket_zero_interval_does_not_divide_by_zero() {
        // `kill_on_drop` (not `spawn_group_standin`) so the single-process stand-in
        // is reclaimed even when the call panics — the buggy-inverse path this test
        // guards never reaches the explicit reap below.
        let mut process = tokio::process::Command::new("sleep")
            .arg("60")
            .kill_on_drop(true)
            .spawn()
            .expect("spawn sleep stand-in");
        let dir = tempfile::tempdir().expect("create tempdir");
        let sock = dir.path().join("present.sock");
        std::fs::write(&sock, b"").expect("create stand-in socket path");

        let result = wait_for_socket(&sock, &mut process, 100, 0).await;

        // Best-effort prompt reap on the success path (kill_on_drop covers panic);
        // the discarded results cannot affect the verdict, which is `result` below.
        let _ = process.start_kill();
        let _ = process.wait().await;
        result.expect("a present socket with a 0 interval must succeed, not panic");
    }

    // Guards M-VMM-8: the readiness wait must surface an early VMM exit as the real
    // cause, not fall through to a Timeout a full window later. Inverse: delete the
    // `try_wait` guard and this returns a Timeout (after the whole deadline) instead of
    // a fast `Vmm("process exited early")`, reddening both assertions.
    #[tokio::test]
    async fn wait_for_socket_fails_fast_on_early_process_exit() {
        let mut process = tokio::process::Command::new("sh")
            .arg("-c")
            .arg("exit 7")
            .spawn()
            .expect("spawn sh");

        let dir = tempfile::tempdir().expect("create tempdir");
        let never = dir.path().join("vmcell-never-appears.sock");

        let start = std::time::Instant::now();
        // A generous 5 s ceiling: the fail-fast path must return in well under it.
        let result = wait_for_socket(&never, &mut process, 5000, 50).await;
        let elapsed = start.elapsed();

        assert!(
            matches!(&result, Err(crate::error::Error::Vmm(msg)) if msg.contains("exited early")),
            "an early process exit must return a Vmm error naming it, got {result:?}"
        );
        assert!(
            elapsed.as_millis() < 2000,
            "early exit must fail fast (well under the 5 s ceiling), took {elapsed:?}"
        );
    }

    // Guards L-VMM-1: with interval > timeout the old `timeout_ms / interval_ms == 0`
    // loop ran zero checks and returned Timeout without ever looking; the deadline loop
    // must still check at least once and find an already-present socket. Inverse:
    // restore the iteration-count loop and this returns Timeout immediately.
    #[tokio::test]
    async fn wait_for_socket_interval_greater_than_timeout_still_checks_once() {
        let mut process = tokio::process::Command::new("sleep")
            .arg("60")
            .kill_on_drop(true)
            .spawn()
            .expect("spawn sleep stand-in");
        let dir = tempfile::tempdir().expect("create tempdir");
        let sock = dir.path().join("present.sock");
        std::fs::write(&sock, b"").expect("create stand-in socket path");

        let result = wait_for_socket(&sock, &mut process, 100, 2000).await;
        let _ = process.start_kill();
        let _ = process.wait().await;
        result.expect("interval > timeout must still check the present socket once");
    }

    // Guards M-VMM-2: a control socket that accepts a connection but never speaks must
    // not hang a control RPC forever — it surfaces a typed Timeout. Paused time
    // auto-advances to the request ceiling once every task is parked on the silent
    // socket. Inverse: remove the `tokio::time::timeout` wrap and this never returns.
    #[tokio::test(start_paused = true)]
    async fn unix_api_request_times_out_on_wedged_socket() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let sock = dir.path().join("wedged.sock");
        let listener = tokio::net::UnixListener::bind(&sock).expect("bind wedged listener");
        tokio::spawn(async move {
            if let Ok((_stream, _)) = listener.accept().await {
                // Hold the accepted connection open but never respond.
                std::future::pending::<()>().await;
            }
        });

        let result = unix_api_request(&sock, "GET", "/health", None::<&()>).await;
        assert!(
            matches!(result, Err(crate::error::Error::Timeout(_))),
            "a wedged control socket must surface a Timeout, got {result:?}"
        );
    }

    // Guards M-VMM-9: a non-2xx reply must map to Error::VmmApi carrying the status AND
    // the response body (firecracker's T2 probe pattern-matches status 400 + body
    // "template"). Inverse: drop the body-collection loop and `body` is empty,
    // reddening `contains("template")`; drop the status mapping and it is not VmmApi.
    #[tokio::test]
    async fn unix_api_request_maps_non_2xx_status_and_body() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let sock = dir.path().join("api.sock");
        let listener = tokio::net::UnixListener::bind(&sock).expect("bind api listener");

        let server = tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                // Drain the request so the client's write completes.
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf).await;
                let resp = "HTTP/1.1 400 Bad Request\r\nContent-Length: 14\r\n\r\ntemplate error";
                let _ = stream.write_all(resp.as_bytes()).await;
                let _ = stream.flush().await;
                // Hold the connection briefly so the client reads the full body.
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        });

        let result = unix_api_request(&sock, "POST", "/test", None::<&serde_json::Value>).await;
        let _ = server.await;
        assert!(
            matches!(&result, Err(crate::error::Error::VmmApi { status: 400, body })
                if body.contains("template")),
            "a non-2xx reply must map to VmmApi with status + body, got {result:?}"
        );
    }

    fn res_with(vhost_user_socket: Option<PathBuf>) -> PerVmResources {
        PerVmResources {
            cgroup_name: "vmcell-test".to_string(),
            tap_name: Some("tap0".to_string()),
            netns_name: Some("ns0".to_string()),
            vhost_user_socket,
            vmid: 1,
            guest_cid: 3,
            tmp_dir: PathBuf::from("/tmp/vmcell-vm-test-1"),
        }
    }

    // Guards M-VMM-5 / H-VMM-3: the ONE shared snapshot-eligibility predicate. The
    // pure truth table plus the four config boundaries — including a virtio-fs
    // *rootfs* (the term the FC copy used to miss). Inverse: drop the
    // `RootfsSource::VirtioFs` term from `config_has_vhost_user_device` and the
    // virtio-fs-rootfs assertion reddens.
    #[test]
    fn config_has_vhost_user_device_covers_all_boundaries() {
        use crate::config::{Egress, NetConfig, RootfsSource};

        assert!(has_vhost_user_device(true, false, false));
        assert!(has_vhost_user_device(false, true, false));
        assert!(has_vhost_user_device(false, false, true));
        assert!(!has_vhost_user_device(false, false, false));

        let virtio_fs_rootfs = VmConfig::builder(
            "/k",
            RootfsSource::VirtioFs {
                dir: PathBuf::from("/d"),
            },
        )
        .build()
        .expect("build virtio-fs rootfs config");
        assert!(
            config_has_vhost_user_device(&virtio_fs_rootfs, &res_with(None)),
            "a virtio-fs rootfs must be treated as a vhost-user device"
        );

        let unprivileged = VmConfig::builder(
            "/k",
            RootfsSource::Erofs {
                image: PathBuf::from("/i"),
            },
        )
        .net(NetConfig::Unprivileged {
            egress: Egress::default(),
            host_services_port: None,
        })
        .build()
        .expect("build unprivileged config");
        assert!(config_has_vhost_user_device(&unprivileged, &res_with(None)));

        let plain = VmConfig::builder(
            "/k",
            RootfsSource::Erofs {
                image: PathBuf::from("/i"),
            },
        )
        .build()
        .expect("build plain config");
        assert!(config_has_vhost_user_device(
            &plain,
            &res_with(Some(PathBuf::from("/run/vhost.sock")))
        ));

        let eligible = VmConfig::builder(
            "/k",
            RootfsSource::Erofs {
                image: PathBuf::from("/i"),
            },
        )
        .net(NetConfig::Privileged {
            egress: Egress::default(),
            host_services_port: None,
        })
        .build()
        .expect("build eligible config");
        assert!(!config_has_vhost_user_device(&eligible, &res_with(None)));

        // §E1.3: an extra PLAIN virtio-blk device is NOT a vhost-user device, so it
        // must stay snapshot-eligible ("plain virtio-blk composes with snapshot",
        // v20 §17/§5.1). A false positive here would wrongly disqualify snapshot.
        // Inverse: add an `extra_disks` term to `config_has_vhost_user_device` and
        // this reddens.
        let with_extra_disk = VmConfig::builder(
            "/k",
            RootfsSource::Erofs {
                image: PathBuf::from("/i"),
            },
        )
        .with_extra_disk(crate::config::BlockDevice::read_write("/img/data.raw"))
        .build()
        .expect("build config with an extra disk");
        assert!(
            !config_has_vhost_user_device(&with_extra_disk, &res_with(None)),
            "a plain extra virtio-blk device must not disqualify snapshot eligibility"
        );
    }

    // Guards the shared console self-guard: VirtioConsole on a backend that does not
    // advertise `virtio_console` (Firecracker) must return a typed
    // `Unsupported { feature: "virtio_console" }`; a capable backend (CH/QEMU) must
    // accept it; and Uart is always accepted regardless of the capability. The buggy
    // inverse (no guard, or gating the wrong mode) lets a VirtioConsole config reach a
    // backend with no hvc0 device — `console=hvc0` then sinks nowhere and serial.log
    // goes silent — and reddens one of the assertions below.
    #[test]
    fn reject_unsupported_console_gates_only_virtio_on_incapable_backends() {
        use crate::config::ConsoleMode;

        let caps = |virtio_console: bool| VmmCapabilities {
            snapshot_restore: true,
            lazy_restore: false,
            virtio_fs_shares: true,
            unprivileged_vhost_user_net: true,
            nested_virt: true,
            virtio_console,
            restore_rotates_host_paths: true,
        };

        // FC-like (virtio_console:false) + VirtioConsole => Unsupported.
        let err =
            reject_unsupported_console("firecracker", &caps(false), ConsoleMode::VirtioConsole)
                .expect_err("an incapable backend must reject VirtioConsole");
        assert!(
            matches!(&err, crate::error::Error::Unsupported { vmm, feature }
                if vmm == "firecracker" && feature == "virtio_console"),
            "expected virtio_console Unsupported, got {err:?}"
        );

        // CH/QEMU-like (virtio_console:true) + VirtioConsole => Ok.
        reject_unsupported_console("cloud-hypervisor", &caps(true), ConsoleMode::VirtioConsole)
            .expect("a capable backend must accept VirtioConsole");
        reject_unsupported_console("qemu", &caps(true), ConsoleMode::VirtioConsole)
            .expect("a capable backend must accept VirtioConsole");

        // Uart is always accepted, on capable and incapable backends alike (the
        // over-rejection inverse — gating Uart too — reddens here).
        reject_unsupported_console("firecracker", &caps(false), ConsoleMode::Uart)
            .expect("Uart must always be accepted");
        reject_unsupported_console("cloud-hypervisor", &caps(true), ConsoleMode::Uart)
            .expect("Uart must always be accepted");
    }

    #[test]
    fn test_cid_allocator() {
        let alloc = CidAllocator::new();
        let cid1 = alloc.allocate().unwrap();
        let cid2 = alloc.allocate().unwrap();
        assert!(cid1 >= 3);
        assert!(cid2 > cid1);
        alloc.release(cid1);
        let cid3 = alloc.allocate().unwrap();
        assert_eq!(cid1, cid3);
    }

    // Guards VMM-7: a poisoned mutex must be recovered, not panicked on. The buggy
    // impl (`.lock().expect("mutex poisoned")`) aborts the test here.
    #[test]
    fn test_cid_allocator_recovers_from_poison() {
        let alloc = std::sync::Arc::new(CidAllocator::new());
        let poisoner = alloc.clone();
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = poisoner.active.lock().expect("fresh lock");
            panic!("poison the mutex while holding the guard");
        }));
        // The lock is now poisoned; both operations must still work.
        let cid = alloc.allocate().expect("allocate after poison");
        assert!(cid >= 3);
        alloc.release(cid);
    }

    proptest! {
        // Guards VMM-6: the previous version allocated and discarded, asserting
        // nothing. This asserts the allocator's contract so a broken allocator
        // (handing out reserved/duplicate/out-of-range CIDs, or failing the
        // release round-trip) goes red.
        #[test]
        fn test_cid_allocator_prop(n in 0usize..260) {
            let alloc = CidAllocator::new();
            let mut allocated: Vec<u32> = Vec::new();
            for _ in 0..n {
                match alloc.allocate() {
                    Ok(cid) => {
                        // Reserved CIDs 0/1/2 are never handed out, and the
                        // ceiling is 254.
                        prop_assert!(cid >= 3, "cid {} is in the reserved range", cid);
                        prop_assert!(cid <= 254, "cid {} exceeds the ceiling", cid);
                        // Uniqueness: a live CID is never handed out twice.
                        prop_assert!(!allocated.contains(&cid), "duplicate cid {}", cid);
                        allocated.push(cid);
                    }
                    Err(_) => {
                        // Exhaustion only after all 252 guest CIDs (3..=254) are live.
                        prop_assert_eq!(allocated.len(), 252);
                    }
                }
            }
            // release + re-allocate round-trips: a freed CID is handed back.
            if let Some(&first) = allocated.first() {
                alloc.release(first);
                let reused = alloc.allocate().expect("re-allocate after release");
                prop_assert_eq!(reused, first);
            }
        }
    }

    // Design §12.3 / §12.7: the per-VM scratch dir — and every per-VM socket/serial
    // path derived from it — must be INJECTIVE in (pid, vmid). These are the
    // DETERMINISTIC regression cases for the two documented buggy inverses, which a
    // random proptest almost never stumbles on (concatenation collisions are sparse
    // over the full input space — a coincidental-pass trap). Both go red reliably:
    //   * PID-only path (drops vmid): (5,1) and (5,2) would collapse to one dir.
    //   * delimiter-drop `vmcell-vm-{pid}-{vmid}`: (1,23) and (12,3) both -> "…-123".
    #[test]
    fn test_per_vm_path_delimiter_and_vmid_are_load_bearing() {
        let base = Path::new("/tmp");
        for leaf in ["api.sock", "vsock.sock", "serial.log"] {
            // vmid must participate (guards a PID-only regression).
            assert_ne!(
                per_vm_scratch_dir("vmcell", base, 5, 1).join(leaf),
                per_vm_scratch_dir("vmcell", base, 5, 2).join(leaf),
                "{leaf}: distinct vmids under one pid must not collide"
            );
            // The delimiter must participate (guards a `{pid}{vmid}` regression).
            assert_ne!(
                per_vm_scratch_dir("vmcell", base, 1, 23).join(leaf),
                per_vm_scratch_dir("vmcell", base, 12, 3).join(leaf),
                "{leaf}: (1,23) and (12,3) must not collide"
            );
        }
    }

    proptest! {
        // The general property: any two distinct (pid, vmid) pairs yield distinct
        // api.sock/vsock.sock/serial.log paths.
        #[test]
        fn test_per_vm_paths_injective_in_pid_vmid(
            pid1 in 0u32..100_000, vmid1 in 0u32..=254u32,
            pid2 in 0u32..100_000, vmid2 in 0u32..=254u32,
        ) {
            prop_assume!((pid1, vmid1) != (pid2, vmid2));
            let base = Path::new("/tmp");
            let d1 = per_vm_scratch_dir("vmcell", base, pid1, vmid1);
            let d2 = per_vm_scratch_dir("vmcell", base, pid2, vmid2);
            for leaf in ["api.sock", "vsock.sock", "serial.log"] {
                prop_assert_ne!(
                    d1.join(leaf),
                    d2.join(leaf),
                    "path {} collided for ({},{}) vs ({},{})",
                    leaf, pid1, vmid1, pid2, vmid2
                );
            }
        }
    }
}
