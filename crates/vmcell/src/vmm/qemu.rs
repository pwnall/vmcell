//! QEMU VMM backend.
//!
//! Provides the [`Qemu`] implementation of the `Vmm` trait.

use crate::config::VmConfig;
use crate::error::{Error, Result};
use crate::vmm::{PerVmResources, VmInstance, Vmm, VmmCapabilities, VsockEndpoint};
use std::path::{Path, PathBuf};
use std::process::Stdio;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::process::Child;

/// The QEMU VMM backend.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Qemu {
    /// Path to the `qemu-system-x86_64` executable.
    pub binary_path: PathBuf,
}

impl Qemu {
    /// Creates a new `Qemu` using the specified executable path.
    #[must_use]
    pub fn new(binary_path: impl Into<PathBuf>) -> Self {
        Self {
            binary_path: binary_path.into(),
        }
    }
}

/// A running instance of a QEMU VM.
#[derive(Debug)]
#[non_exhaustive]
pub struct QemuInstance {
    process: Child,
    qmp_socket: PathBuf,
    vsock_path: PathBuf,
    serial_path: PathBuf,
    _fs_daemons: Vec<crate::fs::VirtioFsDaemon>,
    _vsock_daemon: Option<Child>,
    cid: u32,
    /// How the host reaches this VM's guest agent (returned by
    /// [`VmInstance::vsock_endpoint`]): AF_VSOCK for a snapshot-eligible in-kernel
    /// vsock VM, AF_UNIX for the external-daemon default.
    endpoint: VsockEndpoint,
    pgid: Option<u32>,
    vsock_pgid: Option<u32>,
    // True once the VMM leader has been reaped (via `has_exited`/`kill`). After the
    // leader is reaped the kernel can recycle its pgid, so `kill`/`Drop` must NOT
    // re-`SIGKILL` the process group or they could hit an unrelated group (M-VMM-1).
    reaped: bool,
}

/// The kind of a single QMP protocol line.
///
/// QMP interleaves three shapes on the wire: the capabilities greeting, asynchronous
/// `{"event": ...}` notifications, and command results (`{"return": ...}` on success,
/// `{"error": ...}` on failure). Command code must read past events to the matching
/// result and classify success/failure by the top-level JSON key — never a substring —
/// so a `return` payload that merely *contains* the text `error` is not misread as a
/// failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QmpLine {
    /// An asynchronous `{"event": ...}` notification — never a command result.
    Event,
    /// A successful `{"return": ...}` command result.
    Return,
    /// A failed `{"error": ...}` command result.
    Error,
    /// The greeting, a blank line, or any other non-result line.
    Other,
}

/// Classifies a single QMP JSON line by its top-level key.
///
/// Returns [`QmpLine::Other`] for anything that is not a well-formed JSON object or
/// that carries none of the `event`/`return`/`error` keys (greeting, blank line,
/// garbage). Parsing the JSON — rather than substring-matching `"error"` — is what
/// keeps a `return` value whose payload contains the text `error` from being
/// misclassified as a failure.
fn classify_qmp_line(line: &str) -> QmpLine {
    match serde_json::from_str::<serde_json::Value>(line.trim()) {
        Ok(serde_json::Value::Object(map)) => {
            if map.contains_key("error") {
                QmpLine::Error
            } else if map.contains_key("return") {
                QmpLine::Return
            } else if map.contains_key("event") {
                QmpLine::Event
            } else {
                QmpLine::Other
            }
        }
        _ => QmpLine::Other,
    }
}

/// Inspects a QMP command-result line and fails if it carries an `error` object.
///
/// Success replies look like `{"return": {...}}`; failures look like
/// `{"error": {"class": ..., "desc": ...}}`. This is the shared check that
/// `boot`/`pause`/`resume`/`request_shutdown` apply so a failed command can never
/// masquerade as success. A non-result line (an async event or unparseable noise) is
/// also rejected rather than silently accepted — `qmp_command` is responsible for
/// reading past async events to the actual command result before calling this.
fn check_qmp_reply(reply: &str) -> Result<()> {
    match classify_qmp_line(reply) {
        QmpLine::Return => Ok(()),
        QmpLine::Error => Err(Error::Qmp(reply.trim().to_string())),
        QmpLine::Event | QmpLine::Other => Err(Error::Qmp(format!(
            "expected a QMP command result, got non-result line: {}",
            reply.trim()
        ))),
    }
}

/// The QEMU migration stream (guest RAM + device state) written by `snapshot()` and
/// read by `restore()` via `migrate`/`-incoming`.
const SNAPSHOT_STATE_FILE: &str = "state.bin";
/// The sidecar written beside [`SNAPSHOT_STATE_FILE`] (mirrors Firecracker's
/// `vmcell_host_paths.json`, §2.3, Firecracker — the density tier and the fastest restore).
const SNAPSHOT_SIDECAR_FILE: &str = "vmcell_qemu_snapshot.json";
/// Upper bound on `migrate`/`migrate-incoming` completion. Migration writes/reads
/// guest-RAM-sized bytes to a local file, so it completes far faster; this only bounds
/// a wedged migration so it surfaces as a typed error instead of hanging.
const MIGRATION_BUDGET: std::time::Duration = std::time::Duration::from_secs(120);

/// Sidecar written next to the QEMU migration stream at snapshot, read back at restore.
///
/// It carries only the identity value the fresh restore-time [`PerVmResources`] would
/// otherwise change but that migration requires to match the source: the guest CID
/// baked on the `vhost-vsock-pci` device. The guest's cached CID lives in the migrated
/// RAM, so the destination `-device guest-cid=` must equal the source (§8.2, Restore correctness: a restored VM is not a fresh VM; the audit's
/// "guest-cid must match on the destination `-device` line"). Everything else — RAM
/// size, vCPUs, rootfs, disks, console, net — comes from the caller-supplied `cfg`,
/// which must stay congruent across snapshot→restore exactly as it must for Cloud
/// Hypervisor and Firecracker.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct QemuSnapshotSidecar {
    /// The guest CID baked into the migration image's `vhost-vsock-pci` device.
    guest_cid: u32,
}

/// Serializes the snapshot sidecar into `dir`. Called only after `migrate` reports
/// `completed`; a write failure is propagated (never swallowed — M-RESTORE-2), since a
/// snapshot without its sidecar cannot be restored.
fn write_snapshot_sidecar(dir: &Path, sidecar: &QemuSnapshotSidecar) -> Result<()> {
    let json = serde_json::to_vec(sidecar)
        .map_err(|e| Error::Vmm(format!("failed to serialize QEMU snapshot sidecar: {e}")))?;
    std::fs::write(dir.join(SNAPSHOT_SIDECAR_FILE), json).map_err(Error::Io)
}

/// Reads and parses the snapshot sidecar from `dir` — before spawning anything on the
/// restore path, so a missing or corrupt sidecar fails loud with a clear error instead
/// of a later opaque migration failure.
fn read_snapshot_sidecar(dir: &Path) -> Result<QemuSnapshotSidecar> {
    let path = dir.join(SNAPSHOT_SIDECAR_FILE);
    let bytes = std::fs::read(&path).map_err(|e| {
        Error::Vmm(format!(
            "failed to read QEMU snapshot sidecar {}: {e}",
            path.display()
        ))
    })?;
    serde_json::from_slice(&bytes)
        .map_err(|e| Error::Vmm(format!("failed to parse QEMU snapshot sidecar: {e}")))
}

/// Reads QMP lines from `reader` past any asynchronous `{"event": ...}` notifications
/// to the first command result (`{"return": ...}` or `{"error": ...}`), leaving it in
/// `line`. The shared read-past-events discipline (M-VMM-3) that `qmp_command` inlines,
/// factored out so the single-connection migration driver reuses it for `migrate` and
/// each `query-migrate` poll.
async fn read_qmp_result<R: tokio::io::AsyncBufRead + Unpin>(
    reader: &mut R,
    line: &mut String,
) -> Result<()> {
    loop {
        line.clear();
        let n = reader.read_line(line).await.map_err(Error::Io)?;
        if n == 0 {
            return Err(Error::Qmp(
                "QMP connection closed before a command result arrived".into(),
            ));
        }
        if matches!(classify_qmp_line(line), QmpLine::Return | QmpLine::Error) {
            return Ok(());
        }
    }
}

impl QemuInstance {
    /// Builds the long-lived instance from a fresh [`SpawnedQemu`], taking ownership of
    /// the VMM/daemon handles so its `Drop` becomes the single teardown owner. Shared
    /// by `create` and `restore` so both construct the instance identically.
    fn from_spawned(spawned: SpawnedQemu) -> Self {
        let SpawnedQemu {
            qmp_socket,
            vsock_path,
            serial_path,
            process,
            vsock_daemon,
            fs_daemons,
            pgid,
            vsock_pgid,
            cid,
            endpoint,
        } = spawned;
        Self {
            process,
            qmp_socket,
            vsock_path,
            serial_path,
            _fs_daemons: fs_daemons,
            _vsock_daemon: vsock_daemon,
            cid,
            endpoint,
            pgid,
            vsock_pgid,
            reaped: false,
        }
    }

    async fn qmp_command(&self, cmd: &str) -> Result<String> {
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            let mut stream = UnixStream::connect(&self.qmp_socket).await?;

            let (r, mut w) = stream.split();
            let mut reader = BufReader::new(r);
            let mut line = String::new();

            // Read greeting
            reader.read_line(&mut line).await?;

            // Send capabilities
            w.write_all(b"{\"execute\": \"qmp_capabilities\"}\n")
                .await?;

            line.clear();
            reader.read_line(&mut line).await?;

            // Send the command, then read past any asynchronous events to the matching
            // command result. A single-line read could otherwise capture an interleaved
            // `{"event": ...}` notification and mask the real return/error (M-VMM-3).
            w.write_all(cmd.as_bytes()).await?;
            w.write_all(b"\n").await?;

            loop {
                line.clear();
                let n = reader.read_line(&mut line).await?;
                if n == 0 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "QMP connection closed before a command result arrived",
                    ));
                }
                // Stop at the first command result; skip async events and any
                // greeting/echo noise by looping.
                if matches!(classify_qmp_line(&line), QmpLine::Return | QmpLine::Error) {
                    break;
                }
            }

            Ok::<String, std::io::Error>(line)
        })
        .await
        .map_err(|_| Error::Qmp("Timeout waiting for QMP response".into()))?
        .map_err(Error::Io)
    }

    /// Sends a QMP command and fails if the reply carries a QMP `error` object.
    async fn qmp_command_checked(&self, cmd: &str) -> Result<()> {
        let reply = self.qmp_command(cmd).await?;
        check_qmp_reply(&reply)
    }

    /// Drives an outbound `migrate` (snapshot) or `migrate-incoming` (restore) plus its
    /// `query-migrate` completion poll on **one** QMP connection.
    ///
    /// A single connection is deliberate: re-handshaking `qmp_capabilities` on every
    /// `query-migrate` poll was a measured wiring gotcha (B15). The migration URI is a
    /// plain `file:` target — never `exec:`, which QEMU's `-sandbox …,spawn=deny`
    /// (`§12.2`, Layer 1 — the VMM's own seccomp filter) would kill, and never `fd:`, which the line-based QMP client can't do
    /// `getfd`/SCM_RIGHTS for. Polls until `query-migrate` reports `completed`; a
    /// `failed`/`cancelled` status or the [`MIGRATION_BUDGET`] elapsing is a typed
    /// error, never a silent timeout-through.
    async fn drive_migration(&self, execute_cmd: &str, budget: std::time::Duration) -> Result<()> {
        let deadline = tokio::time::Instant::now() + budget;
        let mut stream = UnixStream::connect(&self.qmp_socket)
            .await
            .map_err(Error::Io)?;
        let (r, mut w) = stream.split();
        let mut reader = BufReader::new(r);
        let mut line = String::new();

        // Greeting, then negotiate capabilities once for the whole migrate+poll session.
        reader.read_line(&mut line).await.map_err(Error::Io)?;
        w.write_all(b"{\"execute\": \"qmp_capabilities\"}\n")
            .await
            .map_err(Error::Io)?;
        line.clear();
        reader.read_line(&mut line).await.map_err(Error::Io)?;

        // Kick off the migration and confirm QEMU accepted the command.
        w.write_all(execute_cmd.as_bytes())
            .await
            .map_err(Error::Io)?;
        w.write_all(b"\n").await.map_err(Error::Io)?;
        read_qmp_result(&mut reader, &mut line).await?;
        check_qmp_reply(&line)?;

        // Poll to a terminal status on the same connection.
        loop {
            if tokio::time::Instant::now() > deadline {
                return Err(Error::Vmm(
                    "QEMU migration did not reach `completed` within the budget".into(),
                ));
            }
            w.write_all(b"{\"execute\": \"query-migrate\"}\n")
                .await
                .map_err(Error::Io)?;
            read_qmp_result(&mut reader, &mut line).await?;
            let value: serde_json::Value = serde_json::from_str(line.trim()).map_err(|e| {
                Error::Qmp(format!("query-migrate reply parse ({e}): {}", line.trim()))
            })?;
            let status = value
                .get("return")
                .and_then(|r| r.get("status"))
                .and_then(|s| s.as_str())
                .unwrap_or("");
            match status {
                "completed" => return Ok(()),
                "failed" | "cancelled" => {
                    return Err(Error::Vmm(format!(
                        "QEMU migration {status}: {}",
                        line.trim()
                    )));
                }
                // "setup" / "active" / "device" / "wait-unplug" / "" — still in flight.
                _ => tokio::time::sleep(std::time::Duration::from_millis(50)).await,
            }
        }
    }
}

/// Requires QEMU's external `vhost-device-vsock` daemon: maps a spawn failure to a
/// typed [`Error::Vmm`] instead of silently degrading to the root-only internal
/// kernel vsock.
///
/// The external daemon is QEMU's unprivileged control plane (§2.4, QEMU q35 — the fallback and most-proven nester). A missing or broken
/// `vhost-device-vsock` binary is a loud misconfiguration that must surface here — the
/// old silent `.ok()` fallback only re-emerged later as an opaque agent-handshake
/// timeout, violating the "checked before a timeout masks it" rule (M-VMM-2).
fn require_vsock_daemon(spawn_result: std::io::Result<Child>) -> Result<Child> {
    spawn_result.map_err(|e| {
        Error::Vmm(format!(
            "failed to spawn the external vhost-device-vsock daemon (QEMU unprivileged vsock control plane): {e}"
        ))
    })
}

/// Rejects a restore whose baked guest CID is still held by a live VM.
///
/// The in-kernel `vhost-vsock` CID is a **host-global** namespace, so restoring while
/// the source (or a prior restore of the same lineage) is still running would collide
/// when QEMU realizes `vhost-vsock-pci,guest-cid=<baked>` (the kernel's
/// `VHOST_VSOCK_SET_GUEST_CID` returns `EADDRINUSE`). This is the AF_VSOCK analog of
/// Firecracker's `reject_live_baked_vsock` (§2.3, Firecracker — the density tier and the fastest restore): a bounded connect to
/// `(cid, AGENT_VSOCK_PORT)` — a live guest agent answers, yielding a clear typed error
/// naming the CID; no listener (connect error/timeout) means the CID is free to reuse.
/// `restore_rotates_host_paths: false` makes concurrent same-lineage restore
/// `Unsupported` anyway (§17, Open gaps and future capabilities); this guards the misuse where the source is still alive.
/// The connect→realize TOCTOU window is a misuse guard, not a security boundary.
async fn reject_live_baked_cid(cid: u32) -> Result<()> {
    let addr = tokio_vsock::VsockAddr::new(cid, crate::vmm::AGENT_VSOCK_PORT);
    let probe = tokio::time::timeout(
        std::time::Duration::from_millis(100),
        tokio_vsock::VsockStream::connect(addr),
    )
    .await;
    if let Ok(Ok(_stream)) = probe {
        return Err(Error::Vmm(format!(
            "cannot restore: guest CID {cid} is still in use by a live VM \
             (in-kernel vhost-vsock is a host-global namespace) — tear the source down first"
        )));
    }
    Ok(())
}

/// RAII guard that owns a healthy `vhost-device-vsock` daemon and reaps its process
/// group on drop, unless explicitly disarmed via [`VsockDaemonGuard::into_inner`].
///
/// `spawn_qemu` spawns this daemon early, then runs several fallible steps (per-share
/// virtio-fs daemon start, the QEMU `cgroups.add_task`, QMP readiness). Each of those
/// error paths reaps QEMU's *own* group but — without this guard — would drop the
/// daemon `Child` (which has no `kill_on_drop`) and orphan the `vhost-device-vsock`
/// process group, because the owning `QemuInstance` (whose `Drop` reaps it) is not
/// constructed until the caller returns. Holding the daemon here closes that leak
/// (H-QEMU-1). On the success path the caller calls `into_inner` to hand ownership to
/// the long-lived `QemuInstance`.
struct VsockDaemonGuard {
    /// The owned daemon child, or `None` once disarmed by `into_inner`.
    daemon: Option<Child>,
    /// The daemon's process-group id, used to `SIGKILL` the whole group on reap.
    pgid: Option<u32>,
}

impl VsockDaemonGuard {
    /// Wraps a freshly-confirmed-healthy `vhost-device-vsock` daemon and its pgid.
    fn new(daemon: Child, pgid: Option<u32>) -> Self {
        Self {
            daemon: Some(daemon),
            pgid,
        }
    }

    /// Disarms the guard, returning the owned daemon and its pgid so the caller can
    /// transfer them to the long-lived `QemuInstance`. After this the guard's `Drop`
    /// is a no-op.
    fn into_inner(mut self) -> (Option<Child>, Option<u32>) {
        (self.daemon.take(), self.pgid)
    }
}

impl Drop for VsockDaemonGuard {
    fn drop(&mut self) {
        if let Some(mut daemon) = self.daemon.take() {
            crate::vmm::reap_process_group(&mut daemon, self.pgid);
        }
    }
}

/// The paths, process handles, and pgids produced by [`Qemu::spawn_qemu`]. A named
/// struct (not an 8-tuple) so the two adjacent `Option<u32>` pgids cannot be silently
/// swapped and cross-wire the SIGKILL targets in `kill`/`Drop` (L-VMM-6).
struct SpawnedQemu {
    qmp_socket: PathBuf,
    vsock_path: PathBuf,
    serial_path: PathBuf,
    process: Child,
    vsock_daemon: Option<Child>,
    fs_daemons: Vec<crate::fs::VirtioFsDaemon>,
    pgid: Option<u32>,
    vsock_pgid: Option<u32>,
    /// The effective guest CID the vsock device was bound to (the baked CID on a
    /// restore, `res.guest_cid` on create).
    cid: u32,
    /// How the host reaches this VM's guest agent — AF_VSOCK (in-kernel vsock) or
    /// AF_UNIX (external daemon).
    endpoint: VsockEndpoint,
}

/// Appends the config-independent QEMU machine flags that must be present on every
/// launch. `-S` freezes the guest vCPUs at spawn so the guest does not start running
/// until `boot()` issues `cont` — without it `create()` would already be running the
/// guest and `boot()` would be a no-op `cont` on an already-running VM (H-VMM-2). Split
/// out so a unit test can assert `-S` is emitted without spawning QEMU.
fn push_fixed_qemu_flags(cmd: &mut tokio::process::Command) {
    cmd.arg("-nodefaults")
        .arg("-no-user-config")
        .arg("-nographic")
        .arg("-cpu")
        .arg("host")
        .arg("-enable-kvm")
        // Freeze vCPUs at launch; boot() -> `cont` is the real start point (H-VMM-2).
        .arg("-S");
}

/// Selects the snapshot-eligible **in-kernel `vhost-vsock`** transport for a QEMU
/// config, versus the default external `vhost-device-vsock` daemon.
///
/// A snapshot-eligible VM must carry no vhost-user device (the eligibility law S1,
/// §8.1, The warm-snapshot path and the eligibility law), and the external vsock daemon *is* a vhost-user device — so a
/// `snapshotting` VM instead attaches the in-kernel `vhost-vsock-pci` device, the
/// only migratable QEMU vsock transport (§2.4, QEMU q35 — the fallback and most-proven nester). `snapshotting` is already
/// privileged-gated at [`VmConfig::build`](crate::config) (no unprivileged net, no
/// virtio-fs shares, no custom init), so it is a sound, **explicit, fail-loud**
/// selector — the one the removed silent `.ok()` fallback lacked (M-VMM-2). Wrapped
/// in one predicate so a future dedicated `vsock_transport` knob is a one-line
/// change here.
fn uses_in_kernel_vsock(cfg: &VmConfig) -> bool {
    cfg.snapshotting
}

/// Per-spawn transport/lifecycle knobs shared by `create` and `restore`, so both
/// drive the one [`Qemu::spawn_qemu`] builder instead of forking the argv
/// construction (the source/destination topology must stay congruent for migration,
/// so a second builder would be a divergence hazard).
struct SpawnParams {
    /// Attach the in-kernel `vhost-vsock-pci` device (the snapshot transport) instead
    /// of the external `vhost-device-vsock` daemon.
    in_kernel_vsock: bool,
    /// The guest CID the vsock device binds. `create`: `res.guest_cid`. `restore`:
    /// the CID baked into the snapshot — the device property must match the source,
    /// so the resumed guest keeps its frozen CID (M-VMM-3).
    guest_cid: u32,
    /// `true` on the restore path: launch with `-incoming defer` so the caller drives
    /// `migrate-incoming` over QMP, then `resume`. `false` on cold create.
    incoming: bool,
}

impl Qemu {
    async fn spawn_qemu(
        &self,
        cfg: &VmConfig,
        res: &PerVmResources,
        cgroups: &dyn crate::metrics::CgroupFs,
        params: &SpawnParams,
    ) -> Result<SpawnedQemu> {
        // The orchestrator owns the per-VM scratch dir; derive our socket and
        // serial-log paths inside it.
        let qmp_socket = res.tmp_dir.join("qmp.sock");
        let vsock_path = res.tmp_dir.join("vsock.sock"); // host connects here
        let vhost_vsock = res.tmp_dir.join("vhost-vsock.sock"); // qemu connects here
        let serial_path = res.tmp_dir.join("serial.log");

        // Re-spawn safety: `MicroVm::start`'s control-plane health-gate recreates a
        // QEMU VM on the SAME per-VM dir after a raced vsock bring-up
        // (`verify_control_plane`). The prior instance's `Drop` reaps the processes
        // but a stale *bound* socket left in the dir would make the fresh daemon/QEMU
        // fail to bind. Pre-clean like FC does for its api socket; a no-op (and thus
        // harmless) on the first spawn, when nothing exists yet.
        for stale in [&qmp_socket, &vsock_path, &vhost_vsock] {
            let _ = tokio::fs::remove_file(stale).await;
        }

        // The vsock transport forks here (one explicit, fail-loud selector — never a
        // silent fallback, M-VMM-2). The default is the external `vhost-device-vsock`
        // daemon (unprivileged, but a vhost-user device that can't migrate). A
        // `snapshotting` VM instead uses the in-kernel `vhost-vsock-pci` device
        // (attached below), which has no daemon: the guest is exposed on the host
        // AF_VSOCK namespace and the host dials it by CID — nothing to spawn, wait for,
        // or reap here.
        let vsock_guard: Option<VsockDaemonGuard> = if params.in_kernel_vsock {
            None
        } else {
            let mut std_vsock_cmd = std::process::Command::new("vhost-device-vsock");
            std_vsock_cmd
                .arg("--guest-cid")
                .arg(params.guest_cid.to_string())
                .arg("--socket")
                .arg(&vhost_vsock)
                .arg("--uds-path")
                .arg(&vsock_path);
            use std::os::unix::process::CommandExt;
            std_vsock_cmd.process_group(0);

            // A spawn failure (e.g. a missing/broken binary) fails loud and typed here
            // — it does NOT silently degrade to the in-kernel vsock, which would mask a
            // daemon misconfiguration as a later agent-handshake timeout (M-VMM-2).
            let mut vsock_daemon = require_vsock_daemon(
                tokio::process::Command::from(std_vsock_cmd)
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::inherit())
                    .spawn(),
            )?;

            let vsock_pgid = vsock_daemon.id();

            // Wait for the vhost-vsock socket to appear; on failure reap the daemon's
            // group before the RAII guard takes ownership, so a half-started daemon
            // never leaks.
            if let Err(e) = crate::vmm::wait_for_socket(
                &vhost_vsock,
                &mut vsock_daemon,
                1000,
                cfg.timeouts.api_socket_poll.as_millis() as u64,
            )
            .await
            {
                crate::vmm::reap_process_group(&mut vsock_daemon, vsock_pgid);
                return Err(Error::Vmm(format!(
                    "vhost-device-vsock failed to start: {e}"
                )));
            }

            // The daemon is healthy. Own it in an RAII guard so that EVERY subsequent
            // fallible step (per-share virtio-fs daemon start below, the QEMU
            // `cgroups.add_task`, and QMP readiness) reaps the vhost-device-vsock
            // process group on error — the QemuInstance whose Drop would otherwise reap
            // it is not constructed until the caller returns (H-QEMU-1).
            Some(VsockDaemonGuard::new(vsock_daemon, vsock_pgid))
        };

        let mut fs_daemons = Vec::new();
        for share in &cfg.shares {
            let daemon = crate::fs::VirtioFsDaemon::start(share, &res.tmp_dir).await?;
            fs_daemons.push(daemon);
        }

        // §12.2 (Layer 1 — the VMM's own seccomp filter)/§12.3 (Layer 2 — the jailer-equivalent (JailSpec + apply_jail)): QEMU had NO `-sandbox` — it ran unconfined. Enforcing now emits the
        // libseccomp sandbox (a QEMU built without libseccomp errors fail-loud on it, the
        // desired behavior); the jailer-equivalent hardening is applied in build_vmm_cmd.
        let seccomp_args = crate::vmm::seccomp::vmm_seccomp_args("qemu", cfg.vmm_seccomp)?;
        let jail = crate::vmm::jail::jail_spec_from_config(&cfg.jail)?;
        let mut cmd =
            crate::vmm::build_vmm_cmd(&self.binary_path, res.netns_name.as_deref(), &jail);
        cmd.args(&seccomp_args);

        cmd.arg("-M")
            .arg("q35,memory-backend=mem")
            .arg("-m")
            .arg(cfg.mem_mib.to_string())
            .arg("-smp")
            .arg(cfg.vcpus.to_string());
        // Fixed, config-independent flags — including `-S` to freeze the guest vCPUs at
        // launch so `boot()`'s `cont` is the real start point (H-VMM-2). The former
        // `-trace vhost_user_*` debug residue is dropped (L-VMM-4).
        push_fixed_qemu_flags(&mut cmd);
        cmd.arg("-object")
            .arg(format!(
                "memory-backend-file,id=mem,size={}M,mem-path=/dev/shm,share=on",
                cfg.mem_mib
            ))
            .arg("-qmp")
            .arg(format!("unix:{},server,nowait", qmp_socket.display()));

        // virtio-rng gives the guest `/dev/hwrng`. The post-restore CSPRNG reseed copies
        // 32 bytes `/dev/hwrng` → `/dev/urandom` in-guest (§8.2, Restore correctness: a restored VM is not a fresh VM); without an entropy
        // device that reseed reports `reseed_applied: false` and restored clones replay
        // frozen CSPRNG state — the same reason Firecracker's create() attaches
        // virtio-rng (§2.3, Firecracker — the density tier and the fastest restore). Present on every launch so the source and
        // restore topologies stay congruent for migration.
        cmd.arg("-object")
            .arg("rng-random,filename=/dev/urandom,id=rng0")
            .arg("-device")
            .arg("virtio-rng-pci,rng=rng0");

        // Console wiring, driven by the SAME `cfg.console_mode` as the cmdline
        // `console=` token (`build_kernel_cmdline`) so the two move in lockstep — a
        // desync sinks the guest console nowhere and `serial.log` goes silent.
        // `reject_unsupported_console` already gated an unsupported mode in create().
        match cfg.console_mode {
            // Uart: the 8250 `ttyS0` bytes go straight to serial.log.
            crate::config::ConsoleMode::Uart => {
                cmd.arg("-serial")
                    .arg(format!("file:{}", serial_path.display()));
            }
            // VirtioConsole: no `-serial`; `hvc0` is a virtconsole on a virtio-serial
            // bus (q35 already provides PCI) whose chardev writes serial.log.
            crate::config::ConsoleMode::VirtioConsole => {
                cmd.arg("-device")
                    .arg("virtio-serial-pci,id=virtio-serial0")
                    .arg("-chardev")
                    .arg(format!(
                        "file,id=charconsole0,path={}",
                        serial_path.display()
                    ))
                    .arg("-device")
                    .arg("virtconsole,chardev=charconsole0,id=console0");
            }
        }

        // Attach the vsock device selected above. The in-kernel `vhost-vsock-pci`
        // (snapshot-eligible, §2.4, QEMU q35 — the fallback and most-proven nester) is realized by QEMU against `/dev/vhost-vsock` — a
        // root:kvm device, so a jailed QEMU needs the runner's `CAP_DAC_OVERRIDE` to
        // open it; a permission failure surfaces loud at device realize, never a silent
        // downgrade (M-VMM-2). Its `guest-cid` is a device *property* (not migrated),
        // so restore reuses the baked CID here (§8.2). The default external daemon path
        // stays the `vhost-user-vsock-pci` chardev pair.
        if params.in_kernel_vsock {
            cmd.arg("-device")
                .arg(format!("vhost-vsock-pci,guest-cid={}", params.guest_cid));
        } else {
            cmd.arg("-chardev")
                .arg(format!("socket,id=vvsock,path={}", vhost_vsock.display()))
                .arg("-device")
                .arg("vhost-user-vsock-pci,chardev=vvsock");
        }

        match &cfg.rootfs {
            crate::config::RootfsSource::Erofs { image } => {
                cmd.arg("-drive")
                    .arg(format!(
                        "file={},format=raw,id=rfs,if=none,readonly=on,file.locking=off",
                        image.display()
                    ))
                    .arg("-device")
                    .arg("virtio-blk-pci,drive=rfs");
            }
            crate::config::RootfsSource::Block { image, overlay } => {
                cmd.arg("-drive")
                    .arg(format!(
                        "file={},format=raw,id=rfs,if=none,file.locking=off",
                        overlay.as_ref().unwrap_or(image).display()
                    ))
                    .arg("-device")
                    .arg("virtio-blk-pci,drive=rfs");
            }
        }

        // Extra virtio-blk devices (§4.6, Extra virtio-blk devices and disk-I/O throttling), attached AFTER the root `virtio-blk-pci` so
        // they enumerate `/dev/vdb`, `/dev/vdc`, … in order and never shift the root
        // off `/dev/vda`. Each is a split-form drive/device pair with its own id.
        // `readonly=on` only for read-only disks; `file.locking=off` matches the root.
        for (i, disk) in cfg.extra_disks.iter().enumerate() {
            let ro = if disk.readonly { ",readonly=on" } else { "" };
            // Disk-I/O fault injection (§4.6, Extra virtio-blk devices and disk-I/O throttling): QEMU's per-drive throttling takes the rate
            // directly (bytes/s, ops/s) — no token-bucket conversion, unset caps omitted.
            let mut throttle = String::new();
            if let Some(limit) = &disk.io_limit {
                if let Some(bps) = limit.bandwidth_bytes_per_sec {
                    throttle.push_str(&format!(",throttling.bps-total={bps}"));
                }
                if let Some(iops) = limit.iops {
                    throttle.push_str(&format!(",throttling.iops-total={iops}"));
                }
            }
            cmd.arg("-drive")
                .arg(format!(
                    "file={},format=raw,id=extra{},if=none{},file.locking=off{}",
                    disk.image.display(),
                    i,
                    ro,
                    throttle,
                ))
                .arg("-device")
                .arg(format!("virtio-blk-pci,drive=extra{i}"));
        }

        for (i, (share, daemon)) in cfg.shares.iter().zip(fs_daemons.iter()).enumerate() {
            cmd.arg("-chardev")
                .arg(format!(
                    "socket,id=vfs{},path={}",
                    i,
                    daemon.socket_path.display()
                ))
                .arg("-device")
                .arg(format!(
                    "vhost-user-fs-pci,chardev=vfs{},tag={}",
                    i, share.tag
                ));
        }

        if let Some(tap) = &res.tap_name {
            cmd.arg("-netdev")
                .arg(format!("tap,id=net0,ifname={tap},script=no,downscript=no"))
                .arg("-device")
                .arg("virtio-net-pci,netdev=net0");
        } else if let Some(socket) = &res.vhost_user_socket {
            cmd.arg("-chardev")
                .arg(format!("socket,id=net0,path={}", socket.display()))
                .arg("-netdev")
                .arg("vhost-user,id=vnet0,chardev=net0,vhostforce=on")
                .arg("-device")
                .arg(format!(
                    "virtio-net-pci,netdev=vnet0,mac={}",
                    crate::net::mac_math(res.vmid)?
                ));
        }

        let cmdline = crate::config::build_kernel_cmdline(cfg, res.vmid, "")?;
        cmd.arg("-kernel")
            .arg(&cfg.kernel)
            .arg("-append")
            .arg(&cmdline);

        // Restore launches with `-incoming defer`: the guest state is not loaded at
        // spawn — `restore()` drives `migrate-incoming` over QMP once QMP is ready and
        // waits for `query-migrate` to complete before returning the paused instance
        // (§8.1, The warm-snapshot path and the eligibility law). `-S` (always emitted) keeps the vCPUs stopped alongside it. On
        // cold `create` this is absent.
        if params.incoming {
            cmd.arg("-incoming").arg("defer");
        }

        let cmd_str = format!("{cmd:?}");
        // Debug level (not info): the full command line is diagnostic noise on every
        // create, and with stderr inherited it should not clutter harness output
        // (L-VMM-4).
        tracing::debug!("QEMU CMD: {}", cmd_str);

        let mut process = cmd
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()?;

        // Shared spawn+register+await-ready sequence (VMM-2): capture the pgid, add the
        // VMM to its cgroup, and block on the QMP socket — reaping the process group on
        // any failure. Routing through the shared helper drops QEMU's former
        // `Error::Vmm("QMP socket failed to appear")` wrapping so the readiness error is
        // now propagated raw, identically to CH/FC. On an error here the still-armed
        // `vsock_guard` (and `fs_daemons`) reap the vhost-user daemons via `?`/`Drop`.
        let pgid = crate::vmm::register_and_await_ready(
            &mut process,
            cgroups,
            &res.cgroup_name,
            &qmp_socket,
            1000,
            cfg.timeouts.api_socket_poll.as_millis() as u64,
        )
        .await?;

        // All post-spawn fallible steps succeeded; disarm the guard (if any) and hand
        // the daemon to the caller, which constructs the long-lived QemuInstance whose
        // Drop now owns the daemon's teardown. In-kernel vsock has no daemon.
        let (vsock_daemon, vsock_pgid) = match vsock_guard {
            Some(g) => g.into_inner(),
            None => (None, None),
        };

        // How the host reaches this VM's guest agent: in-kernel vsock is dialed by CID
        // over AF_VSOCK; the external daemon bridges to the AF_UNIX `vsock.sock`.
        let endpoint = if params.in_kernel_vsock {
            VsockEndpoint::Vsock {
                cid: params.guest_cid,
                port: crate::vmm::AGENT_VSOCK_PORT,
            }
        } else {
            VsockEndpoint::Unix {
                path: vsock_path.clone(),
                port: crate::vmm::AGENT_VSOCK_PORT,
            }
        };

        Ok(SpawnedQemu {
            qmp_socket,
            vsock_path,
            serial_path,
            process,
            vsock_daemon,
            fs_daemons,
            pgid,
            vsock_pgid,
            cid: params.guest_cid,
            endpoint,
        })
    }
}

impl Vmm for Qemu {
    type Instance = QemuInstance;

    async fn create(
        &self,
        cfg: &VmConfig,
        res: &PerVmResources,
        cgroups: &dyn crate::metrics::CgroupFs,
    ) -> Result<Self::Instance> {
        // The cmdline `console=` token and the serial/virtconsole device wiring in
        // `spawn_qemu` are both driven by `cfg.console_mode`; gate an unsupported
        // mode up front so they can never desync into a silent `serial.log`.
        crate::vmm::reject_unsupported_console("qemu", &self.capabilities(), cfg.console_mode)?;

        // Cold create: fresh CID, no `-incoming`. A `snapshotting` config selects the
        // in-kernel vhost-vsock transport (§2.4, QEMU q35 — the fallback and most-proven nester) so the VM is snapshot-eligible.
        let params = SpawnParams {
            in_kernel_vsock: uses_in_kernel_vsock(cfg),
            guest_cid: res.guest_cid,
            incoming: false,
        };
        Ok(QemuInstance::from_spawned(
            self.spawn_qemu(cfg, res, cgroups, &params).await?,
        ))
    }

    async fn restore(
        &self,
        snapshot_dir: &Path,
        cfg: &VmConfig,
        res: &PerVmResources,
        cgroups: &dyn crate::metrics::CgroupFs,
    ) -> Result<Self::Instance> {
        crate::vmm::reject_unsupported_console("qemu", &self.capabilities(), cfg.console_mode)?;

        // Eligibility (S1, §8.1, The warm-snapshot path and the eligibility law), defense in depth alongside `config::build()` and the
        // orchestrator re-check. The shared predicate catches a virtio-fs share or
        // unprivileged net; the in-kernel-vsock requirement catches the case it can't
        // see — a QEMU restore over the external `vhost-device-vsock` daemon, which is
        // itself a non-migratable vhost-user device.
        if crate::vmm::config_has_vhost_user_device(cfg, res) {
            return Err(Error::Unsupported {
                vmm: "qemu".to_string(),
                feature: "snapshot restore with a vhost-user device (virtio-fs share or unprivileged net)"
                    .to_string(),
            });
        }
        if !uses_in_kernel_vsock(cfg) {
            return Err(Error::Unsupported {
                vmm: "qemu".to_string(),
                feature: "snapshot restore requires the in-kernel vsock transport (set snapshotting=true)"
                    .to_string(),
            });
        }

        // Read the sidecar BEFORE spawning anything, so a missing/corrupt snapshot fails
        // loud with a clear error rather than a later opaque migration failure.
        let sidecar = read_snapshot_sidecar(snapshot_dir)?;
        let baked_cid = sidecar.guest_cid;

        // The baked CID is a host-global resource; reject if the source is still live.
        reject_live_baked_cid(baked_cid).await?;

        // Spawn a fresh, topology-congruent QEMU with `-incoming defer`, in-kernel vsock,
        // and the **baked** guest CID (the device property must match the source, §8.2, Restore correctness: a restored VM is not a fresh VM).
        let params = SpawnParams {
            in_kernel_vsock: true,
            guest_cid: baked_cid,
            incoming: true,
        };
        let instance =
            QemuInstance::from_spawned(self.spawn_qemu(cfg, res, cgroups, &params).await?);

        // Drive the incoming migration on the now-ready QMP socket and wait for it to
        // complete. The VM stays **paused** afterward (the source was paused during
        // `migrate`, and `-incoming` loads into that state): the orchestrator resumes
        // it via `resume()` — never `boot()` (§2.1, The trait and the capability descriptor). If this fails, `instance` drops
        // and reaps QEMU, so no half-restored VM leaks.
        let state = snapshot_dir.join(SNAPSHOT_STATE_FILE);
        let migrate_incoming = format!(
            "{{\"execute\": \"migrate-incoming\", \"arguments\": {{\"uri\": \"file:{}\"}}}}",
            state.display()
        );
        instance
            .drive_migration(&migrate_incoming, MIGRATION_BUDGET)
            .await?;
        Ok(instance)
    }

    fn capabilities(&self) -> VmmCapabilities {
        VmmCapabilities {
            // KVM-validated: a `snapshotting` QEMU on the in-kernel `vhost-vsock`
            // transport migrates to a file and restores via `-incoming` (§2.4, QEMU q35 — the fallback and most-proven nester).
            // Snapshot-eligible ONLY in that config — the external-daemon default
            // returns `Unsupported` from snapshot()/restore(). A deliberate re-gate must
            // flip this AND its capability-honesty test together (docs/45).
            snapshot_restore: true,
            // No UFFD/demand-paged restore backend for QEMU (§17, Open gaps and future capabilities).
            lazy_restore: false,
            virtio_fs_shares: true,
            unprivileged_vhost_user_net: true,
            nested_virt: true,
            virtio_console: true,
            // Single-lineage: restore reuses the baked guest CID and does not rotate
            // host-side identity, so concurrent same-lineage fan-out is `Unsupported`
            // (mirrors Firecracker, §2.3, Firecracker — the density tier and the fastest restore). Rotating the host-global CID to
            // enable concurrent QEMU zygote fan-out is recorded future work (§17, Open gaps and future capabilities).
            restore_rotates_host_paths: false,
        }
    }

    fn id(&self) -> &str {
        "qemu"
    }
}

impl VmInstance for QemuInstance {
    async fn boot(&mut self) -> Result<()> {
        self.qmp_command_checked("{\"execute\": \"cont\"}").await
    }

    async fn pause(&mut self) -> Result<()> {
        self.qmp_command_checked("{\"execute\": \"stop\"}").await
    }

    async fn resume(&mut self) -> Result<()> {
        self.qmp_command_checked("{\"execute\": \"cont\"}").await
    }

    async fn request_shutdown(&mut self) -> Result<()> {
        self.qmp_command_checked("{\"execute\": \"system_powerdown\"}")
            .await
    }

    async fn kill(&mut self) -> Result<()> {
        let _ = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            self.qmp_command("{\"execute\": \"quit\"}"),
        )
        .await;

        if let Some(pgid) = self.pgid {
            // Skip the group SIGKILL if the leader was already reaped (its pgid may be
            // recycled) — M-VMM-1.
            if !self.reaped {
                let _ = nix::sys::signal::kill(
                    nix::unistd::Pid::from_raw(-(pgid as i32)),
                    nix::sys::signal::Signal::SIGKILL,
                );
            }
        }
        let _ = self.process.wait().await;
        // The leader is reaped now; `Drop` must not re-signal a possibly-recycled pgid.
        self.reaped = true;

        if let Some(mut d) = self._vsock_daemon.take() {
            if let Some(v_pgid) = self.vsock_pgid {
                let _ = nix::sys::signal::kill(
                    nix::unistd::Pid::from_raw(-(v_pgid as i32)),
                    nix::sys::signal::Signal::SIGKILL,
                );
            }
            let _ = d.wait().await;
        }
        Ok(())
    }

    async fn has_exited(&mut self) -> bool {
        // Non-blocking reap of the QEMU leader; `Ok(Some(_))` means it exited after
        // `request_shutdown` (`system_powerdown`). Record the reap so `kill()`/`Drop`
        // do NOT re-`SIGKILL` the process group: once the leader is reaped the kernel
        // may recycle its pgid and signalling `-pgid` could hit an unrelated group
        // (M-VMM-1).
        if matches!(self.process.try_wait(), Ok(Some(_))) {
            self.reaped = true;
            true
        } else {
            false
        }
    }

    async fn snapshot(&mut self, dir: &Path) -> Result<()> {
        // Eligibility (S1, §8.1, The warm-snapshot path and the eligibility law): only the in-kernel `vhost-vsock` transport is
        // migratable. The external `vhost-device-vsock` daemon is a vhost-user device
        // the VMM cannot migrate — and the shared `config_has_vhost_user_device`
        // predicate does NOT see QEMU's own vsock daemon, so this endpoint check is
        // QEMU's own snapshot-eligibility guard. A `Vsock` endpoint ⟹ the VM was built
        // `snapshotting=true`, which `VmConfig::build()` already validated carries no
        // other vhost-user device (no virtio-fs share, no unprivileged net, no custom
        // init). A non-`Vsock` endpoint is a fail-loud typed `Unsupported`.
        let cid = match self.endpoint {
            VsockEndpoint::Vsock { cid, .. } => cid,
            VsockEndpoint::Unix { .. } => {
                return Err(Error::Unsupported {
                    vmm: "qemu".to_string(),
                    feature: "snapshot_restore (requires the in-kernel vsock transport; set snapshotting=true)"
                        .to_string(),
                });
            }
        };

        // pause → migrate-to-file → poll `completed` → resume the source. Mirrors the
        // CH/FC snapshot order (§8.1, The warm-snapshot path and the eligibility law); the orchestrator's `MicroVm::snapshot`
        // invalidates the cached agent client afterward, which covers QEMU's
        // pause/migrate severing the vsock connection.
        self.qmp_command_checked("{\"execute\": \"stop\"}").await?;

        let state = dir.join(SNAPSHOT_STATE_FILE);
        let migrate_cmd = format!(
            "{{\"execute\": \"migrate\", \"arguments\": {{\"uri\": \"file:{}\"}}}}",
            state.display()
        );
        // Write the sidecar only after `migrate` reports `completed`; propagate a write
        // failure (a snapshot without its sidecar can't be restored — M-RESTORE-2).
        let result = match self.drive_migration(&migrate_cmd, MIGRATION_BUDGET).await {
            Ok(()) => write_snapshot_sidecar(dir, &QemuSnapshotSidecar { guest_cid: cid }),
            Err(e) => Err(e),
        };

        // Resume the source VM regardless (best-effort, warn-only — matches FC/CH); the
        // snapshot `result` is what determines success.
        if let Err(e) = self.qmp_command_checked("{\"execute\": \"cont\"}").await {
            tracing::warn!("QEMU snapshot: failed to resume source after migrate: {e}");
        }
        result
    }

    fn vsock_path(&self) -> &Path {
        &self.vsock_path
    }

    fn vsock_endpoint(&self) -> VsockEndpoint {
        // AF_VSOCK by CID for the in-kernel vsock transport (snapshot-eligible VMs),
        // AF_UNIX over `vsock.sock` for the external-daemon default. Set once at spawn.
        self.endpoint.clone()
    }

    fn guest_cid(&self) -> u32 {
        self.cid
    }

    fn serial_log(&self) -> &Path {
        &self.serial_path
    }

    /// Probes QEMU's external `vhost-device-vsock` data path by doing the real agent
    /// handshake with a bounded budget (reusing the one connect/handshake law, so the
    /// `CONNECT`/`OK`/`Ready` protocol lives in exactly one place). A healthy boot
    /// binds its guest listener and answers `Ready` in well under the budget; a
    /// wedged vhost-user bring-up never answers, so this returns `Timeout` and the
    /// orchestrator re-spawns (see the trait doc). The probe client is dropped — the
    /// caller's lazy `agent()` reconnects, which the guest re-accepts on its still
    /// bound listener.
    ///
    /// The in-kernel `vhost-vsock` transport (snapshot-eligible VMs) has no
    /// vhost-user daemon and thus no bring-up race — it is a deterministic kernel
    /// device, exactly like CH's/FC's in-VMM vsock — so it needs no probe and returns
    /// `Ok(())` immediately (also avoiding a needless connect against a host-global
    /// CID on the re-spawn path).
    async fn verify_control_plane(
        &self,
        budget: std::time::Duration,
        timeouts: &crate::config::Timeouts,
    ) -> Result<()> {
        if let VsockEndpoint::Vsock { .. } = self.endpoint {
            return Ok(());
        }
        let serial = crate::vmm::RealSerialLog {
            path: self.serial_path.clone(),
        };
        crate::agent::AgentClient::connect_endpoint(&self.endpoint, budget, timeouts, &serial)
            .await
            .map(|_client| ())
    }
}

impl Drop for QemuInstance {
    fn drop(&mut self) {
        // Teardown order (AGENTS.md): VMM process group first — reaping it before
        // touching the daemons, sockets or the per-VM directory means cleanup never
        // races a live VMM.
        if let Some(pgid) = self.pgid {
            // Skip the group SIGKILL + reap if the leader was already reaped (via
            // `has_exited`/`kill`): its pgid may have been recycled (M-VMM-1).
            if !self.reaped {
                let _ = nix::sys::signal::kill(
                    nix::unistd::Pid::from_raw(-(pgid as i32)),
                    nix::sys::signal::Signal::SIGKILL,
                );
                if let Some(pid) = self.process.id() {
                    let _ = nix::sys::wait::waitpid(nix::unistd::Pid::from_raw(pid as i32), None);
                }
            }
        }
        // vhost-user daemons next: the external vhost-device-vsock and each virtiofsd
        // own sockets that live inside `tmp_dir`, so they must be reaped before that
        // directory is removed.
        if let Some(d) = self._vsock_daemon.as_mut()
            && let Some(v_pgid) = self.vsock_pgid
        {
            let _ = nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(-(v_pgid as i32)),
                nix::sys::signal::Signal::SIGKILL,
            );
            if let Some(pid) = d.id() {
                let _ = nix::sys::wait::waitpid(nix::unistd::Pid::from_raw(pid as i32), None);
            }
        }
        // Dropping each virtiofsd kills it and removes its own socket before the
        // orchestrator removes the shared per-VM directory.
        self._fs_daemons.clear();
        // Unlink our own sockets. The per-VM directory itself is owned and removed
        // once by the orchestrator's `VmTempDir` guard (after this instance and the
        // smoltcp process are dropped), not here. Mirrors CH.
        let _ = std::fs::remove_file(&self.qmp_socket);
        let _ = std::fs::remove_file(&self.vsock_path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Guards H-VMM-2: every QEMU launch must carry `-S` so the guest stays frozen until
    // boot() issues `cont`. Without it create() spawns an already-running guest and
    // boot() is a no-op cont that trivially succeeds on either impl — nothing else can
    // catch it. Inverse: drop `-S` from push_fixed_qemu_flags and this reddens.
    #[test]
    fn qemu_freezes_vcpus_with_dash_s_flag() {
        let mut cmd = tokio::process::Command::new("qemu-system-x86_64");
        push_fixed_qemu_flags(&mut cmd);
        let has_s = cmd
            .as_std()
            .get_args()
            .any(|a| a == std::ffi::OsStr::new("-S"));
        assert!(
            has_s,
            "QEMU must launch with -S to freeze vCPUs until boot()"
        );
    }

    fn restore_test_res() -> PerVmResources {
        PerVmResources {
            cgroup_name: "vmcell-test".to_string(),
            tap_name: Some("tap0".to_string()),
            netns_name: None,
            vhost_user_socket: None,
            vmid: 1,
            guest_cid: 3,
            tmp_dir: PathBuf::from("/tmp/vmcell-vm-test-1"),
        }
    }

    // Eligibility (S1): a QEMU restore of a NON-snapshotting config would use the
    // external `vhost-device-vsock` daemon — a non-migratable vhost-user device — so
    // it is rejected fail-loud *before spawning* (the shared `config_has_vhost_user_
    // device` predicate can't see QEMU's own daemon, so `uses_in_kernel_vsock` is the
    // guard). KVM-free because restore errors out before `spawn_qemu`. RED inverse: a
    // restore that spawned regardless would need KVM and not return this typed error.
    #[tokio::test]
    async fn restore_rejects_non_snapshotting_config_before_spawning() {
        use crate::config::{RootfsSource, VmConfig};

        let qemu = Qemu::new("/usr/bin/qemu-system-x86_64");
        let cfg = VmConfig::builder(
            "/k",
            RootfsSource::Erofs {
                image: PathBuf::from("/i"),
            },
        )
        .build()
        .expect("build config");
        let cgroups = crate::metrics::FakeCgroupFs::new();

        let err = qemu
            .restore(
                Path::new("/nonexistent-snapshot"),
                &cfg,
                &restore_test_res(),
                &cgroups,
            )
            .await
            .expect_err("QEMU restore of a non-snapshotting config must be Unsupported");
        assert!(
            matches!(&err, Error::Unsupported { vmm, feature }
                if vmm == "qemu" && feature.contains("in-kernel vsock")),
            "expected an in-kernel-vsock Unsupported, got {err:?}"
        );
    }

    // A snapshotting config whose snapshot dir has no sidecar fails loud when the
    // sidecar is read — which happens BEFORE `spawn_qemu`, so this is KVM-free and
    // proves the read-before-spawn ordering. RED inverse: reading the sidecar after
    // spawning would need KVM and lose this clean pre-spawn error.
    #[tokio::test]
    async fn restore_reads_sidecar_before_spawning() {
        use crate::config::{RootfsSource, VmConfig};

        let qemu = Qemu::new("/usr/bin/qemu-system-x86_64");
        let cfg = VmConfig::builder(
            "/k",
            RootfsSource::Erofs {
                image: PathBuf::from("/i"),
            },
        )
        .snapshotting(true)
        .build()
        .expect("build snapshotting config");
        let cgroups = crate::metrics::FakeCgroupFs::new();

        let err = qemu
            .restore(
                Path::new("/nonexistent-snapshot-dir"),
                &cfg,
                &restore_test_res(),
                &cgroups,
            )
            .await
            .expect_err("QEMU restore with a missing sidecar must fail before spawning");
        assert!(
            matches!(&err, Error::Vmm(msg) if msg.contains("snapshot sidecar")),
            "expected a sidecar-read Vmm error, got {err:?}"
        );
    }

    // The capability-honesty gate (mirrors Firecracker's): QEMU snapshot_restore is
    // KVM-validated ON via the in-kernel vhost-vsock + migrate/-incoming path, with
    // lazy_restore and restore_rotates_host_paths honestly OFF. Any deliberate re-gate
    // must flip the flag AND this test together (AGENTS.md: a capability change
    // re-validates empirically; docs/45 records the reason).
    #[test]
    fn capabilities_are_honest_about_snapshot_restore() {
        let caps = Qemu::new("/usr/bin/qemu-system-x86_64").capabilities();
        assert!(
            caps.snapshot_restore,
            "QEMU snapshot_restore is KVM-validated ON (in-kernel vhost-vsock + migrate/-incoming, §2.4)"
        );
        assert!(
            !caps.lazy_restore,
            "QEMU has no UFFD/demand-paged restore backend (§17)"
        );
        assert!(
            !caps.restore_rotates_host_paths,
            "QEMU restore reuses the baked CID (single-lineage); rotating the host-global CID for \
             concurrent fan-out is future work (§17)"
        );
    }

    // Guards VMM-3: a QMP reply carrying an `error` object must surface as
    // Err(Error::Qmp). The buggy impl (discarding the reply / returning Ok) would
    // let a failed pause/resume/request_shutdown masquerade as success — and
    // `resume` is on the restore path.
    #[test]
    fn qmp_error_reply_is_surfaced() {
        let err = "{\"error\": {\"class\": \"GenericError\", \"desc\": \"nope\"}}\n";
        assert!(matches!(check_qmp_reply(err), Err(Error::Qmp(_))));
    }

    #[test]
    fn qmp_success_reply_is_ok() {
        assert!(check_qmp_reply("{\"return\": {}}\n").is_ok());
    }

    // M-VMM-3: an async event line is NOT a command result. Treating it as success
    // would mask the real return/error. Red on the inverse (the old `.contains` /
    // single-line read that accepted whatever line arrived first).
    #[test]
    fn qmp_async_event_is_not_treated_as_success() {
        let event = "{\"event\": \"STOP\", \"timestamp\": {\"seconds\": 1, \"microseconds\": 2}}\n";
        assert!(matches!(check_qmp_reply(event), Err(Error::Qmp(_))));
    }

    // M-VMM-3: a SUCCESS reply whose `return` payload merely contains the string
    // "error" must be Ok. The old brittle `reply.contains("\"error\"")` wrongly
    // rejected this; top-level-key JSON classification accepts it (red on the old impl).
    #[test]
    fn qmp_return_with_error_valued_payload_is_ok() {
        let reply = "{\"return\": {\"status\": \"error\"}}\n";
        assert!(check_qmp_reply(reply).is_ok());
    }

    // M-VMM-3: classification keys off the top-level JSON key, not a substring.
    #[test]
    fn classify_qmp_line_uses_top_level_key() {
        assert_eq!(classify_qmp_line("{\"event\": \"RESUME\"}"), QmpLine::Event);
        assert_eq!(classify_qmp_line("{\"return\": {}}"), QmpLine::Return);
        assert_eq!(
            classify_qmp_line("{\"error\": {\"class\": \"GenericError\"}}"),
            QmpLine::Error
        );
        assert_eq!(
            classify_qmp_line("{\"QMP\": {\"version\": {}}}"),
            QmpLine::Other
        );
        assert_eq!(classify_qmp_line("not json at all"), QmpLine::Other);
    }

    // M-VMM-3: mirrors the qmp_command read loop's predicate — it keeps reading past
    // async events to the command result. A single-line read (the bug) would stop at
    // the first event, which this asserts is NOT a result.
    #[test]
    fn qmp_reader_skips_events_until_result() {
        let stream = [
            "{\"event\": \"RESUME\"}",
            "{\"event\": \"STOP\"}",
            "{\"return\": {}}",
        ];
        let result = stream
            .iter()
            .copied()
            .find(|l| matches!(classify_qmp_line(l), QmpLine::Return | QmpLine::Error));
        assert_eq!(result, Some("{\"return\": {}}"));
        // The first line alone — what a single read captures — is not a result.
        assert_eq!(classify_qmp_line(stream[0]), QmpLine::Event);
    }

    // M-VMM-2: a spawn failure for the external vhost-device-vsock daemon must surface
    // as a typed Error::Vmm, not be swallowed (the old `.spawn().ok()` turned the error
    // into a silent internal-vsock fallback that only failed later as a handshake
    // timeout). Red on the inverse: the `Result<Child>` signature cannot express the
    // swallow, and this pins the error mapping.
    #[test]
    fn missing_vsock_daemon_surfaces_typed_error() {
        let io_err =
            std::io::Error::new(std::io::ErrorKind::NotFound, "vhost-device-vsock missing");
        assert!(matches!(
            require_vsock_daemon(Err(io_err)),
            Err(Error::Vmm(_))
        ));
    }

    /// Spawns a long-lived stand-in process in its own process group, returning the
    /// live tokio `Child` plus its pid. Used to drive the `VsockDaemonGuard` reaping
    /// tests without needing the real `vhost-device-vsock` binary.
    fn spawn_group_standin() -> (Child, i32) {
        let mut std_cmd = std::process::Command::new("sleep");
        std_cmd.arg("60");
        use std::os::unix::process::CommandExt;
        std_cmd.process_group(0);
        let child = tokio::process::Command::from(std_cmd)
            .spawn()
            .expect("spawn sleep stand-in");
        let pid = child.id().expect("child pid") as i32;
        (child, pid)
    }

    // H-QEMU-1: dropping the guard MUST SIGKILL the daemon's process group and reap it.
    // Red on the inverse (the old code dropped the bare tokio `Child` — which has no
    // kill_on_drop — leaving the daemon running on every post-vsock-healthy error path).
    #[tokio::test]
    async fn vsock_guard_reaps_daemon_group_on_drop() {
        let (child, pid) = spawn_group_standin();
        let pgid = child.id();
        drop(VsockDaemonGuard::new(child, pgid));

        // Drop's blocking reap means the process is gone once drop returns; poll
        // briefly to stay robust against the host's reaper winning the waitpid race.
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
            "VsockDaemonGuard::drop must SIGKILL and reap the daemon process group"
        );
    }

    // H-QEMU-1 (success path): into_inner disarms the guard — it transfers ownership
    // WITHOUT reaping, so the long-lived QemuInstance keeps the daemon. Red on the
    // inverse (a guard that always reaps, or an into_inner that drops the child).
    #[tokio::test]
    async fn vsock_guard_into_inner_does_not_reap() {
        let (child, pid) = spawn_group_standin();
        let pgid = child.id();

        let (daemon, out_pgid) = VsockDaemonGuard::new(child, pgid).into_inner();
        assert_eq!(out_pgid, pgid, "into_inner must return the captured pgid");
        assert!(
            nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), None).is_ok(),
            "into_inner must transfer ownership without reaping the daemon"
        );

        // Clean up the stand-in so the test leaks nothing.
        let mut daemon = daemon.expect("into_inner returns the owned daemon");
        let _ = nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(-pid),
            nix::sys::signal::Signal::SIGKILL,
        );
        let _ = daemon.wait().await;
    }
}
