//! QEMU VMM backend for `vmcell`.
//!
//! Provides the [`Qemu`] implementation of the [`vmcell::vmm::Vmm`] trait and its running-instance
//! type [`QemuInstance`]. Extracted from the `vmcell` crate (design §2.4, QEMU q35 — the fallback
//! and most-proven nester) so the core library carries only the primary Cloud Hypervisor backend;
//! this crate depends on `vmcell` for the shared `Vmm`/`VmInstance` traits, the jail/seccomp
//! predicates (QEMU **must** pass `-sandbox …` via `vmm_seccomp_args` or it runs unconfined), and
//! the spawn/reap/console/snapshot-eligibility helpers — every "one law, one predicate" invariant
//! stays single-sourced in `vmcell`.

#![deny(missing_docs)]
#![deny(unreachable_pub)] // pub-in-private-module API-surface honesty
#![deny(
    clippy::undocumented_unsafe_blocks,
    clippy::missing_safety_doc,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::multiple_unsafe_ops_per_block, // one obligation per SAFETY comment
    unsafe_op_in_unsafe_fn,
    rustdoc::broken_intra_doc_links
)]
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::panic,
        clippy::unreachable,
        clippy::todo,
        clippy::unimplemented,
        clippy::indexing_slicing,
        clippy::print_stdout,
        clippy::print_stderr,
        clippy::dbg_macro,
        clippy::allow_attributes,               // B11: prefer #[expect] over #[allow] in prod code
        clippy::allow_attributes_without_reason  // B11: every suppression states why
    )
)]

use std::path::{Path, PathBuf};
use std::process::Stdio;
use vmcell::config::VmConfig;
use vmcell::error::{Error, Result};
// The v33 feature vocabulary (design §7.4, invariant F6). Every refusal below spells its feature
// through `Feature::name()` BY CONSTRUCTION, and the two shared `Removal` consts are the ONE
// spelling of their refusal across all four backends — the four had drifted into four different
// prose strings, which is what bred `feature.contains("vhost-user")` in three test suites.
use vmcell::feature::{Feature, IN_KERNEL_VSOCK_REQUIRED_FOR_SNAPSHOT, VHOST_USER_BLOCKS_SNAPSHOT};
use vmcell::vmm::{PerVmResources, VmInstance, Vmm, VmmCapabilities, VsockEndpoint};

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
    _fs_daemons: Vec<vmcell::fs::VirtioFsDaemon>,
    _vsock_daemon: Option<Child>,
    cid: u32,
    /// How the host reaches this VM's steward (returned by
    /// [`VmInstance::vsock_endpoint`]): AF_VSOCK for a snapshot-eligible in-kernel
    /// vsock VM, AF_UNIX for the external-daemon default.
    endpoint: VsockEndpoint,
    /// `true` if this VM carries a config-level vhost-user device (a virtio-fs share
    /// or unprivileged vhost-user-net) — recorded via `config_has_vhost_user_device`
    /// at spawn so `snapshot()` can reject it fail-loud (the S1 eligibility law). Task
    /// B decoupled the in-kernel Vsock transport from `snapshotting`, so a Vsock
    /// endpoint alone is **no longer** proof of eligibility.
    has_vhost_user_device: bool,
    /// Whether the backend advertises `snapshot_restore`, captured from
    /// [`Qemu::capabilities`] at construction so `snapshot()` can self-guard on the
    /// descriptor without a handle back to the backend (M-RESTORE-3, the CH shape).
    snapshot_restore_capable: bool,
    /// The VMM leader's process group AND the one-shot "already reaped" flag, owned
    /// together by the one shared helper ([`vmcell::vmm::VmmProcessGroup`], L1): `kill`,
    /// `has_exited` and `Drop` all route through it, so no copy can forget the M-VMM-1
    /// guard and SIGKILL a pgid the kernel has since recycled.
    group: vmcell::vmm::VmmProcessGroup,
    vsock_pgid: Option<u32>,
    /// The guest's RAM size, carried from [`vmcell::config::VmConfig::mem_mib`] at
    /// construction, because the snapshot's migration stream is a function of it
    /// ([`vmcell::vmm::snapshot_request_timeout`], M6): the stream is guest RAM plus
    /// device state, so a multi-GiB guest cannot ride a flat control-plane ceiling.
    mem_mib: u32,
    /// The host USB driver bindings this VM's passthrough displaced, taken before the spawn
    /// by [`vmcell::vmm::usb::claim_usb_host_devices`] and put back by teardown. The whole
    /// law is shared (`usb_host_passthrough` is a capability, so only the argv above is
    /// QEMU's); this backend owns just *when* to claim and *when* to restore.
    usb_claim: vmcell::vmm::usb::UsbHostClaim,
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
/// read by `restore()` via `migrate`/`-incoming`. The **only** file the snapshot dir
/// needs: restore rotates the host-global guest CID to a fresh `res.guest_cid`
/// (`restore_rotates_host_paths: true`, §2.4), so no baked-CID sidecar is carried — the
/// `guest-cid` is a QEMU device property, not part of this migration stream.
const SNAPSHOT_STATE_FILE: &str = "state.bin";
/// QEMU's measured **floor** on `migrate`/`migrate-incoming` completion (docs/78 M7).
///
/// It is a floor and not the budget: the budget is
/// [`QemuInstance::snapshot_budget`], which takes the larger of this and the shared
/// guest-RAM-proportional [`vmcell::vmm::snapshot_request_timeout`] (M6). The floor stays
/// because QEMU migration is not a single dense write the way CH/FC suspend images are —
/// it makes iterative dirty-page passes and a `query-migrate` poll round-trip per
/// iteration, which a pure write-throughput model does not capture. Above ≈7.3 GiB of
/// guest RAM the shared predicate exceeds it and takes over, which is exactly the
/// multi-GiB case M6 exists for.
///
/// This bounds only a **wedged** migration so it surfaces as a typed error instead of
/// hanging; it is not a latency SLA.
const MIGRATION_BUDGET: std::time::Duration = std::time::Duration::from_secs(120);

/// The ceiling, in milliseconds, for the **smoltcp NAT's** vhost-user socket to appear before QEMU
/// is exec'd — QEMU's one readiness wait that is NOT on
/// [`vmcell::vmm::VMM_SOCKET_READY_TIMEOUT_MS`], and named here for the same reason that one is
/// named: a bare literal at a call site is how six of them drifted apart (docs/81 §8).
///
/// It is deliberately wider than the VMM ceiling because the producer is different in kind: the
/// orchestrator's smoltcp NAT is a *thread*, not a child process, so there is no early exit to fail
/// fast on — a wedged producer can only be surfaced by the clock. (It is **not** wider because the
/// bind is late: `SmoltcpProcess::start` calls `Listener::new` on the caller's thread before the
/// worker is spawned, so the socket exists by the time `start` returns and this wait races nothing.
/// The "lazy bind from a background thread" mechanism this constant was originally written against
/// is withdrawn — design §17 — and the ceiling survives on the independent reason above.) Normally
/// the socket is already there; 2 s abandons a truly-failed bring-up promptly, so the caller's
/// bounded retry recovers on a fresh VM (the ~10 % flake the net-egress probe surfaced).
const SMOLTCP_SOCKET_READY_TIMEOUT_MS: u64 = 2000;

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
    ///
    /// `snapshot_restore_capable` is the backend descriptor's `snapshot_restore` flag,
    /// captured here because `snapshot()` runs on the instance and has no handle back to
    /// the [`Qemu`] backend (the same capture CH's `ChInstance` does, M-RESTORE-3).
    fn from_spawned(
        spawned: SpawnedQemu,
        snapshot_restore_capable: bool,
        usb_claim: vmcell::vmm::usb::UsbHostClaim,
        mem_mib: u32,
    ) -> Self {
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
            has_vhost_user_device,
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
            has_vhost_user_device,
            snapshot_restore_capable,
            group: vmcell::vmm::VmmProcessGroup::new(pgid),
            vsock_pgid,
            mem_mib,
            usb_claim,
        }
    }

    /// The wall-clock budget for THIS instance's snapshot/restore migration: the larger
    /// of QEMU's measured [`MIGRATION_BUDGET`] floor and the shared, guest-RAM-proportional
    /// [`vmcell::vmm::snapshot_request_timeout`] (M6).
    ///
    /// **One law, one predicate**: the guest-RAM term is not re-derived here — every
    /// backend's snapshot RPC sizes it in `vmcell::vmm`, and this backend contributes only
    /// its floor (see [`MIGRATION_BUDGET`] for why QEMU has one). Ordinary control ops
    /// (`stop`/`cont`/`system_powerdown`/`quit`) deliberately do NOT use this: they are flat
    /// in guest state and stay on `qmp_command`'s short 2 s ceiling, so a wedged
    /// `system_powerdown` cannot block the unconditional force-kill behind it.
    fn snapshot_budget(&self) -> std::time::Duration {
        MIGRATION_BUDGET.max(vmcell::vmm::snapshot_request_timeout(self.mem_mib))
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
    /// `failed`/`cancelled` status or the budget elapsing is a typed error, never a silent
    /// timeout-through.
    ///
    /// The budget is **not** a parameter: it is this instance's [`Self::snapshot_budget`], the
    /// guest-RAM-proportional one (M6). Both shipped call sites — `snapshot()`'s `migrate` and
    /// `restore()`'s `migrate-incoming` — move the same guest-RAM-sized stream, so neither may
    /// reach for the flat [`MIGRATION_BUDGET`] floor on its own; with the budget an argument, a
    /// call site that did was invisible to a gate on `snapshot_budget()` itself (docs/81 §8's
    /// "a gate on the helper is not a gate on the call"). Now it is a compile error.
    async fn drive_migration(&self, execute_cmd: &str) -> Result<()> {
        self.drive_migration_within(execute_cmd, self.snapshot_budget())
            .await
    }

    /// [`Self::drive_migration`] with an explicit budget.
    ///
    /// **Private**, and that is the point: it is the seam the M7 wedged-session gate uses to pass a
    /// budget short enough to keep the KVM-free suite fast, and no shipped call site may use it —
    /// `migration_budget_gate` scans for exactly that.
    async fn drive_migration_within(
        &self,
        execute_cmd: &str,
        budget: std::time::Duration,
    ) -> Result<()> {
        let deadline = tokio::time::Instant::now() + budget;
        // The budget bounds the WHOLE QMP session, not the gaps between polls (M7). A
        // QEMU whose main loop is wedged (or whose snapshot filesystem has stalled)
        // answers neither the greeting, nor `migrate`, nor a `query-migrate` — and a
        // between-iterations clock check never runs if the read before it never
        // returns, so `snapshot()`/`restore()` hung forever instead of surfacing the
        // typed error this const's doc promises. One `timeout_at` over the entire body
        // is the shape `qmp_command` already uses; the deadline is an `Instant` that
        // bounds every inner step (outer-bounds-inner), which is why no step below
        // re-checks the clock — a second copy of the law is what diverged here.
        tokio::time::timeout_at(deadline, async {
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
        })
        .await
        .map_err(|_| {
            Error::Vmm("QEMU migration did not reach `completed` within the budget".into())
        })?
    }
}

/// Requires QEMU's external `vhost-device-vsock` daemon: maps a spawn failure to a
/// typed [`Error::Vmm`] instead of silently degrading to the root-only internal
/// kernel vsock.
///
/// The external daemon is QEMU's unprivileged control plane (§2.4, QEMU q35 — the fallback and most-proven nester). A missing or broken
/// `vhost-device-vsock` binary is a loud misconfiguration that must surface here — the
/// old silent `.ok()` fallback only re-emerged later as an opaque steward-handshake
/// timeout, violating the "checked before a timeout masks it" rule (M-VMM-2).
fn require_vsock_daemon(spawn_result: std::io::Result<Child>) -> Result<Child> {
    spawn_result.map_err(|e| {
        Error::Vmm(format!(
            "failed to spawn the external vhost-device-vsock daemon (QEMU unprivileged vsock control plane): {e}"
        ))
    })
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
            vmcell::vmm::reap_process_group(&mut daemon, self.pgid);
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
    fs_daemons: Vec<vmcell::fs::VirtioFsDaemon>,
    pgid: Option<u32>,
    vsock_pgid: Option<u32>,
    /// The guest CID the vsock device was bound to — **always** the fresh `res.guest_cid`, on
    /// restore as on create: `guest-cid` is a QEMU device property and not part of the migration
    /// stream, so the destination programs a new allocator-unique CID
    /// (`restore_rotates_host_paths: true`, §2.4).
    cid: u32,
    /// How the host reaches this VM's steward — AF_VSOCK (in-kernel vsock) or
    /// AF_UNIX (external daemon).
    endpoint: VsockEndpoint,
    /// `config_has_vhost_user_device(cfg, res)` at spawn — threaded to `snapshot()`'s
    /// S1 eligibility guard (see [`QemuInstance::has_vhost_user_device`]).
    has_vhost_user_device: bool,
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

/// The id of the single xhci controller vmcell attaches when a config requests host-USB
/// passthrough. One controller carries every requested device (§2.4, QEMU q35 — the fallback and most-proven nester).
const USB_CONTROLLER_ID: &str = "vmcell-xhci";

/// Builds the host-USB passthrough argv fragment for `devices` (§2.4, QEMU q35 — the fallback and most-proven nester), v30 §18 (Delta register)
/// delta 9): one `-device qemu-xhci,id=vmcell-xhci` controller followed by one
/// `-device usb-host,vendorid=0x…,productid=0x…` per device, in call order.
///
/// Empty in, empty out — QEMU runs under `-nodefaults`, so a config with no USB device
/// gets **no** USB controller at all (the state crosvm has to force with `--no-usb`).
///
/// **Pure and unit-testable** (no I/O, no spawn, no `Command`), following
/// `vmcell_crosvm::build_crosvm_run_args`: QEMU's argv is otherwise assembled inline into
/// a `tokio::process::Command`, which is why its device flags were never goldenable. The
/// caller splices the result in with `cmd.args(...)`.
///
/// Both ids are rendered zero-padded lowercase hex (`0x1d6b`). `VmConfigBuilder::build`
/// has already rejected a zero id (QEMU reads zero as *unset* — match-any) and a
/// duplicate `(vendor_id, product_id)` pair, so this helper does no validation of its
/// own — it is the emitter, not a second copy of that law.
fn build_qemu_usb_args(devices: &[vmcell::config::UsbHostDevice]) -> Vec<String> {
    let mut args = Vec::new();
    if devices.is_empty() {
        return args;
    }
    args.push("-device".to_string());
    args.push(format!("qemu-xhci,id={USB_CONTROLLER_ID}"));
    for dev in devices {
        args.push("-device".to_string());
        args.push(format!(
            "usb-host,vendorid=0x{:04x},productid=0x{:04x}",
            dev.vendor_id, dev.product_id
        ));
    }
    args
}

/// Selects the **in-kernel `vhost-vsock`** transport for a QEMU config, versus the
/// default external `vhost-device-vsock` daemon. The **one** predicate every call site
/// (create, restore, endpoint wiring) reads — never a second copy (AGENTS.md "one law,
/// one predicate").
///
/// The selection is [`VmConfig::vsock_transport`], explicit and fail-loud — never the
/// silent `.ok()` daemon→in-kernel fallback commit `c59bb21f` removed (M-VMM-2):
///
/// - [`VsockTransport::InKernel`] → in-kernel (a privileged non-snapshot QEMU opting in
///   to shed the external-daemon bring-up flake).
/// - [`VsockTransport::ExternalDaemon`] → the daemon.
/// - [`VsockTransport::Auto`] → in-kernel iff `snapshotting`. A snapshot-eligible VM
///   must carry no vhost-user device (the eligibility law S1, §8.1), and the external
///   daemon *is* one, so the only migratable transport is the in-kernel
///   `vhost-vsock-pci` device (§2.4). `snapshotting` is privileged-gated at
///   [`VmConfig::build`](vmcell::config) (no unprivileged net / virtio-fs share / custom
///   init) and cannot pair with an explicit `ExternalDaemon`, so a snapshotting VM is
///   always in-kernel here.
///
/// The in-kernel device is realized against `/dev/vhost-vsock` (a `root:kvm` node); a
/// jailed QEMU needs the runner's `CAP_DAC_OVERRIDE` (or `kvm`-group membership) to open
/// it, and a permission failure surfaces loud at device realize — never a silent
/// downgrade to the daemon.
fn uses_in_kernel_vsock(cfg: &VmConfig) -> bool {
    match cfg.vsock_transport {
        vmcell::config::VsockTransport::InKernel => true,
        vmcell::config::VsockTransport::ExternalDaemon => false,
        vmcell::config::VsockTransport::Auto => cfg.snapshotting,
    }
}

/// The ONE `snapshot_restore` capability self-guard, shared by QEMU's `snapshot()` (via
/// [`qemu_snapshot_eligibility`], reading the flag the instance captured at construction)
/// and `restore()` (reading `self.capabilities()` directly) — the shape CH and FC already
/// carry (rubric B3 / M-RESTORE-3): a backend checks its OWN descriptor rather than
/// assuming its native semantics, so a deliberate re-gate of the flag turns every
/// snapshot/restore into this typed refusal instead of a live `migrate` against a QEMU
/// that no longer supports it. One predicate, so the two entry points cannot diverge.
///
/// # Errors
/// Returns [`Error::Unsupported`] when the descriptor does not advertise
/// `snapshot_restore`; the feature string equals the `VmmCapabilities` field name (§7.2) because
/// [`Error::unsupported`] composes it from [`Feature::name`] — never a literal (F6).
fn require_snapshot_restore_capable(snapshot_restore_capable: bool) -> Result<()> {
    if !snapshot_restore_capable {
        // The backend itself is the remover, so this is the bare capability refusal: no `Removal`,
        // no provenance decoration, and the rendering is byte-identical to the pre-v33 literal.
        return Err(Error::unsupported("qemu", Feature::SnapshotRestore));
    }
    Ok(())
}

/// Refuses a [`VmConfig`] asking for `nested_virt`/`lazy_restore` that this backend's
/// descriptor advertises as `false`, through the **one** shared predicate
/// [`vmcell::vmm::reject_unadvertised_capabilities`] (docs/81 d7).
///
/// QEMU's stake in it: `lazy_restore` is honest-false (no UFFD/demand-paged restore backend,
/// §17), so a [`RestoreMode::Lazy`](vmcell::config::RestoreMode::Lazy) config faulted eagerly
/// under a caller that had asked for demand paging — an accepted input silently downgraded.
/// QEMU advertises `nested_virt: true` (`-cpu host` exposes VMX and the cmdline sets
/// `kvm-intel.nested=1`), so that branch is dormant *today* — exactly like the
/// `reject_usb_host_devices` call in `create()`, whose flag is also `true`: a deliberate re-gate
/// of either flag turns every such config into the typed refusal, with no second site to update.
///
/// This wrapper exists only to bind the `"qemu"` name once; the law, both branches and the
/// N-VMM-1 feature strings live in the shared predicate. It landed as three byte-identical
/// per-backend copies and was hoisted.
///
/// # Errors
/// Returns [`Error::Unsupported`] `{ vmm: "qemu", feature }` naming the unadvertised capability.
fn reject_unadvertised_capabilities(caps: &VmmCapabilities, cfg: &VmConfig) -> Result<()> {
    vmcell::vmm::reject_unadvertised_capabilities("qemu", caps, cfg)
}

/// QEMU's authoritative snapshot-eligibility guard (S1, §8.1), checked at `snapshot()`
/// time on the instance itself. Three independent requirements, each a fail-loud typed
/// `Unsupported`:
///
/// 0. The backend must advertise `snapshot_restore` — the descriptor self-check
///    ([`require_snapshot_restore_capable`]) CH runs first in its own `snapshot_precheck`
///    and QEMU was missing entirely; the flag is captured at construction because the
///    instance has no handle back to the backend.
/// 1. The instance must ride the **in-kernel `Vsock` transport**. The external
///    `vhost-device-vsock` daemon is itself a non-migratable vhost-user device, and the
///    shared `config_has_vhost_user_device` predicate cannot see it — so this endpoint
///    check is QEMU's own.
/// 2. The VM must carry **no other vhost-user device** (`has_vhost_user_device`,
///    recorded from `config_has_vhost_user_device` at spawn). Before Task B a `Vsock`
///    endpoint implied `snapshotting=true`, whose `build()` already rejected such
///    devices; Task B lets a **non-snapshot** `InKernel` VM hold a `Vsock` endpoint
///    *and* a virtio-fs share / unprivileged net, so the endpoint is no longer proof of
///    eligibility and this second check is what upholds the law (mirrors the
///    `config_has_vhost_user_device` reject on the restore path).
fn qemu_snapshot_eligibility(
    snapshot_restore_capable: bool,
    endpoint: &VsockEndpoint,
    has_vhost_user_device: bool,
) -> Result<()> {
    require_snapshot_restore_capable(snapshot_restore_capable)?;
    // Both remaining refusals are the CONFIG's doing, not the backend's, so each says why through
    // its shared [`vmcell::feature::Removal`] instead of decorating the feature string: a decorated
    // string is a string a test then matches a fragment of (F6). `restore()` returns these very
    // same two consts, so the snapshot and restore halves cannot drift apart again.
    if !matches!(endpoint, VsockEndpoint::Vsock { .. }) {
        return Err(Error::from_removal(
            "qemu",
            &IN_KERNEL_VSOCK_REQUIRED_FOR_SNAPSHOT,
        ));
    }
    if has_vhost_user_device {
        return Err(Error::from_removal("qemu", &VHOST_USER_BLOCKS_SNAPSHOT));
    }
    Ok(())
}

/// Per-spawn transport/lifecycle knobs shared by `create` and `restore`, so both
/// drive the one [`Qemu::spawn_qemu`] path — and through it the one
/// [`qemu_launch_plan`] composer — instead of forking the argv construction (the
/// source/destination topology must stay congruent for migration, so a second builder
/// would be a divergence hazard).
struct SpawnParams {
    /// Attach the in-kernel `vhost-vsock-pci` device (the snapshot transport) instead
    /// of the external `vhost-device-vsock` daemon.
    in_kernel_vsock: bool,
    /// The guest CID the vsock device binds — always the **fresh** `res.guest_cid`
    /// on both paths. `guest-cid` is a QEMU device property, *not* part of the
    /// migration stream, so restore programs a new allocator-unique CID rather than
    /// the source's: the guest is reachable at the rotated CID after migrate-incoming
    /// (validated live, §2.4), which is what lets concurrent QEMU clones each hold
    /// their own CID on the host-global vhost-vsock namespace
    /// (`restore_rotates_host_paths: true`).
    guest_cid: u32,
    /// `true` on the restore path: launch with `-incoming defer` so the caller drives
    /// `migrate-incoming` over QMP, then `resume`. `false` on cold create.
    incoming: bool,
}

/// How the host reaches this VM's steward: the **transport** (in-kernel vsock is dialed by CID over
/// AF_VSOCK; the external daemon bridges to the AF_UNIX `vsock.sock`) and — law C8's FIRST question
/// — the **port**.
///
/// The port is the DECLARED one ([`StewardPlacement::steward_port`](vmcell::config::StewardPlacement::steward_port)),
/// never the protocol default, because [`QemuInstance::verify_control_plane`] probes this endpoint
/// *verbatim*: QEMU on the external-daemon transport is the only backend that probes at all, so
/// baking 5000 in dialed a dead port on a `Service { port: 5100 }` cell. The daemon accepts the
/// `CONNECT` and never answers a port with no guest listener, so the probe spent its whole budget,
/// the VM was destroyed and re-spawned, and after `MAX_CONTROL_PLANE_RESPAWNS` a healthy cell was
/// refused (M1). `MicroVm::steward`/`connect_sessions` re-key the port per call (`with_port`), which
/// is exactly why the defect was invisible everywhere except the probe.
///
/// [`StewardPlacement::None`](vmcell::config::StewardPlacement::None) has no steward and never
/// reaches the health gate (the orchestrator keys it on `steward_port().is_some()`), so the protocol
/// default stands in as an unused placeholder there — not as a silent fallback for a declared port,
/// of which there is none.
fn steward_endpoint(
    params: &SpawnParams,
    vsock_path: &Path,
    placement: vmcell::config::StewardPlacement,
) -> VsockEndpoint {
    let port = placement
        .steward_port()
        .unwrap_or(vmcell::vmm::STEWARD_VSOCK_PORT);
    if params.in_kernel_vsock {
        VsockEndpoint::Vsock {
            cid: params.guest_cid,
            port,
        }
    } else {
        VsockEndpoint::Unix {
            path: vsock_path.to_path_buf(),
            port,
        }
    }
}

/// The per-VM host paths the QEMU argv references, computed by [`Qemu::spawn_qemu`] and
/// consumed by the I/O-free composer [`qemu_launch_plan`].
///
/// Passing the virtio-fs daemons' *socket paths* (not the live `VirtioFsDaemon` handles)
/// is what keeps the composer free of process ownership: it reads paths, spawns nothing,
/// and can therefore be driven from a unit test that asserts the exact argv the launch
/// would exec.
struct QemuSpawnPaths<'a> {
    /// The QMP control socket QEMU serves (`-qmp unix:…`).
    qmp_socket: &'a Path,
    /// The AF_UNIX path the *host* dials for the steward on the external-daemon
    /// transport. Not in the argv — `vhost-device-vsock`'s `--uds-path` — but carried
    /// here so the spawn tail can name it once.
    vsock_path: &'a Path,
    /// The socket QEMU connects to as the `vhost-user-vsock` frontend.
    vhost_vsock: &'a Path,
    /// The file the guest console/serial bytes land in.
    serial_path: &'a Path,
    /// One socket path per [`VmConfig::shares`] entry, in the same order.
    fs_daemon_sockets: &'a [PathBuf],
}

/// The helper daemons a spawn has already started and still owns when the QEMU child is
/// launched — handed to [`finish_qemu_spawn`], which must reap them on every error path
/// until the long-lived `QemuInstance` takes over (H-QEMU-1).
struct SpawnedDaemons {
    /// The external `vhost-device-vsock` daemon (absent on the in-kernel transport).
    vsock: Option<VsockDaemonGuard>,
    /// One `virtiofsd` per configured share.
    fs: Vec<vmcell::fs::VirtioFsDaemon>,
}

impl Qemu {
    async fn spawn_qemu(
        &self,
        cfg: &VmConfig,
        res: &PerVmResources,
        cgroups: &dyn vmcell::metrics::CgroupFs,
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
            // daemon misconfiguration as a later steward-handshake timeout (M-VMM-2).
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
            if let Err(e) = vmcell::vmm::wait_for_vmm_socket(
                &vhost_vsock,
                Some(&mut vsock_daemon),
                cfg.timeouts.api_socket_poll.as_millis() as u64,
            )
            .await
            {
                vmcell::vmm::reap_process_group(&mut vsock_daemon, vsock_pgid);
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
            // §9.4: `api_socket_poll` paces EVERY daemon readiness wait — the same profile the
            // `vhost-device-vsock` wait above uses, so the two helper daemons of one VM cannot
            // poll on different cadences. The unpaced `start` shim would pin virtiofsd to the
            // default grid under `low_latency()`/`throughput()` (finding
            // `virtiofsd-socket-wait-hardcoded-cadence`). Gated by
            // `virtiofs_pacing_gate::every_virtiofs_start_here_is_paced_by_the_vm_config`.
            let daemon =
                vmcell::fs::VirtioFsDaemon::start_paced(share, &res.tmp_dir, &cfg.timeouts).await?;
            fs_daemons.push(daemon);
        }
        // The argv names each virtio-fs daemon by socket path only, so the composer gets
        // the paths — never the live `Child` handles this function still owns.
        let fs_daemon_sockets: Vec<PathBuf> =
            fs_daemons.iter().map(|d| d.socket_path.clone()).collect();

        // QEMU's `-chardev socket` connects as a *client* at exec with NO retry, so the
        // smoltcp NAT's UDS must be bound before the argv is exec'd — otherwise boots die
        // with "-chardev socket ...: Failed to connect ...: No such file or directory".
        // `SmoltcpProcess::start` binds it with `Listener::new` on the CALLER's thread,
        // before the vhost worker is spawned, so by the time control reaches here the
        // socket is already there and this wait normally returns on its first poll. It is
        // kept as the fail-loud gate for the case the clock is the only witness: smoltcp
        // is process-less (a thread, not a `Child`), so unlike the external vsock daemon
        // above there is no early exit to fail fast on. CH's vhost-user-net frontend would
        // tolerate a not-yet-bound socket via its own client-side reconnect over its
        // multi-second startup; QEMU does not. The 2 s ceiling abandons a truly-failed
        // smoltcp bring-up promptly (the ~10% flake the net-egress probe surfaced) so the
        // caller's bounded retry recovers on a fresh VM. Fails loud on timeout; the
        // mid-`start` teardown releases smoltcp. It runs HERE rather than beside the
        // `-chardev` it gates so that `qemu_launch_plan` performs no I/O at all and
        // the composed argv is assertable from a unit test.
        if res.tap_name.is_none()
            && let Some(socket) = &res.vhost_user_socket
        {
            vmcell::vmm::wait_for_socket(
                socket,
                None,
                SMOLTCP_SOCKET_READY_TIMEOUT_MS,
                cfg.timeouts.api_socket_poll.as_millis() as u64,
            )
            .await?;
        }

        let paths = QemuSpawnPaths {
            qmp_socket: &qmp_socket,
            vsock_path: &vsock_path,
            vhost_vsock: &vhost_vsock,
            serial_path: &serial_path,
            fs_daemon_sockets: &fs_daemon_sockets,
        };
        // M11: the whole launch — seccomp flag, jail spec, netns, argv — is composed inside
        // `qemu_launch_plan`, so `spawn_qemu` holds NO `JailConfig` and NO `JailSpec` and there
        // is no window in which the posture could be swapped between deciding it and applying
        // it. The plan's recorded posture is private to `vmcell::vmm::launch`, so the two-line
        // defeat (`let mut plan = …; plan.jail = weaker;`) does not compile; the KVM-free gate
        // asserts on the value it returns.
        let plan = qemu_launch_plan(&self.binary_path, cfg, res, params, &paths)?;
        let daemons = SpawnedDaemons {
            vsock: vsock_guard,
            fs: fs_daemons,
        };
        finish_qemu_spawn(plan, cfg, res, cgroups, params, daemons, &paths).await
    }
}

/// The pure, total mapping from a config to the complete QEMU launch (§2.4, M11) — every flag
/// the process is exec'd with, plus the jail posture it is confined by, and nothing else.
///
/// Split out of [`Qemu::spawn_qemu`] so the launch is **observable without spawning**: it
/// performs no I/O (the daemon starts and the vhost-user-net readiness wait stay in the
/// caller), so a unit test can build a `VmConfig`, call this, and assert over
/// [`LaunchPlan::argv`](vmcell::vmm::LaunchPlan::argv). That is what a pure per-*fragment*
/// helper cannot do: `build_qemu_usb_args` can be perfect while its result never reaches the
/// `Command`, and only a test over the *composed* argv sees the difference — the deleted-splice
/// defect its gate (`qemu_full_argv_splices_the_usb_fragment`) now catches.
///
/// The jail half is the same story one layer down. It is applied in `build_vmm_cmd`'s post-fork
/// `pre_exec` window, which nothing KVM-free observes, so while this function wrote
/// `jail_spec_from_config(&cfg.jail)?` inline the posture was an argument no gate could see:
/// rewriting that one token shipped every QEMU VM with a weaker — or absent — Layer-2
/// confinement and left `cargo test`, `just ci` and the whole live matrix green, because the
/// deny-list is default-allow/`EPERM` and no functional leg notices. Routing through
/// [`LaunchPlan::build`](vmcell::vmm::LaunchPlan::build) makes the posture a **returned value**
/// ([`LaunchPlan::jail`](vmcell::vmm::LaunchPlan::jail)) that
/// `the_qemu_launch_plan_ships_the_configured_jail_posture` asserts on, and the plan's record is
/// private to `vmcell::vmm::launch`, so the two-line defeat (`let mut plan = …;
/// plan.jail = weaker;`) does not compile here at all.
///
/// # Errors
/// Propagates the seccomp-spec, jail-spec, MAC-math and kernel-cmdline builders, and
/// fails loud when `paths.fs_daemon_sockets` does not carry one entry per configured
/// share (a length mismatch would otherwise `zip`-truncate a share's device out of the
/// argv silently).
fn qemu_launch_plan(
    binary_path: &Path,
    cfg: &VmConfig,
    res: &PerVmResources,
    params: &SpawnParams,
    paths: &QemuSpawnPaths<'_>,
) -> Result<vmcell::vmm::LaunchPlan> {
    if paths.fs_daemon_sockets.len() != cfg.shares.len() {
        return Err(Error::Vmm(format!(
            "virtio-fs daemon sockets ({}) do not match the configured shares ({})",
            paths.fs_daemon_sockets.len(),
            cfg.shares.len()
        )));
    }

    // §12.2 (Layer 1 — the VMM's own seccomp filter)/§12.3 (Layer 2 — the jailer-equivalent (JailSpec + apply_jail)): QEMU had NO `-sandbox` — it ran unconfined. Enforcing now emits the
    // libseccomp sandbox (a QEMU built without libseccomp errors fail-loud on it, the
    // desired behavior); the jailer-equivalent hardening is applied in build_vmm_cmd.
    let seccomp_args = vmcell::vmm::seccomp::vmm_seccomp_args("qemu", cfg.vmm_seccomp)?;
    // §12.3 (Layer 2): the ONE posture value, handed to the one constructor that both compiles
    // it into the `pre_exec` jail and records it — never a `JailSpec` this backend holds.
    let mut plan =
        vmcell::vmm::LaunchPlan::build(binary_path, res.netns_name.as_deref(), cfg.jail)?;
    let cmd = plan.command_mut();
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
    push_fixed_qemu_flags(cmd);
    cmd.arg("-object")
        .arg(format!(
            "memory-backend-file,id=mem,size={}M,mem-path=/dev/shm,share=on",
            cfg.mem_mib
        ))
        .arg("-qmp")
        .arg(format!("unix:{},server,nowait", paths.qmp_socket.display()));

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
        vmcell::config::ConsoleMode::Uart => {
            cmd.arg("-serial")
                .arg(format!("file:{}", paths.serial_path.display()));
        }
        // VirtioConsole: no `-serial`; `hvc0` is a virtconsole on a virtio-serial
        // bus (q35 already provides PCI) whose chardev writes serial.log.
        vmcell::config::ConsoleMode::VirtioConsole => {
            cmd.arg("-device")
                .arg("virtio-serial-pci,id=virtio-serial0")
                .arg("-chardev")
                .arg(format!(
                    "file,id=charconsole0,path={}",
                    paths.serial_path.display()
                ))
                .arg("-device")
                .arg("virtconsole,chardev=charconsole0,id=console0");
        }
    }

    // Attach the vsock device selected above. The in-kernel `vhost-vsock-pci`
    // (snapshot-eligible, §2.4, QEMU q35 — the fallback and most-proven nester) is realized by QEMU against `/dev/vhost-vsock` — a
    // root:kvm device, so a jailed QEMU needs the runner's `CAP_DAC_OVERRIDE` to
    // open it; a permission failure surfaces loud at device realize, never a silent
    // downgrade (M-VMM-2). Its `guest-cid` is a device *property* and NOT part of the migration
    // stream, which is why restore programs the FRESH `res.guest_cid` here rather than the source's
    // — QEMU is on the rotating side (`restore_rotates_host_paths: true`, §2.4), and each concurrent
    // clone therefore holds its own CID on the host-global vhost-vsock namespace. The default
    // external daemon path stays the `vhost-user-vsock-pci` chardev pair.
    if params.in_kernel_vsock {
        cmd.arg("-device")
            .arg(format!("vhost-vsock-pci,guest-cid={}", params.guest_cid));
    } else {
        cmd.arg("-chardev")
            .arg(format!(
                "socket,id=vvsock,path={}",
                paths.vhost_vsock.display()
            ))
            .arg("-device")
            .arg("vhost-user-vsock-pci,chardev=vvsock");
    }

    // *Which* host file backs `/dev/vda` is the one law,
    // `RootfsSource::effective_image` — the same predicate the config boundary's
    // duplicate-backing-file guard uses, so the guard can never protect a file this argv does
    // not attach. **Whether it is writable** is the other one law,
    // `RootfsSource::root_device_read_only`, which owns the exhaustive per-variant match: the
    // `Block` arm here open-coded the ABSENCE of `readonly=on`, contradicting the `ro` the cmdline
    // mounts it with (§4.7).
    let root_image = cfg.rootfs.effective_image().display().to_string();
    let root_ro = if cfg.rootfs.root_device_read_only() {
        ",readonly=on"
    } else {
        ""
    };
    cmd.arg("-drive")
        .arg(format!(
            "file={root_image},format=raw,id=rfs,if=none{root_ro},file.locking=off"
        ))
        .arg("-device")
        .arg("virtio-blk-pci,drive=rfs");

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

    for (i, (share, socket)) in cfg
        .shares
        .iter()
        .zip(paths.fs_daemon_sockets.iter())
        .enumerate()
    {
        cmd.arg("-chardev")
            .arg(format!("socket,id=vfs{},path={}", i, socket.display()))
            .arg("-device")
            .arg(format!(
                "vhost-user-fs-pci,chardev=vfs{},tag={}",
                i, share.tag
            ));
    }

    if let Some(tap) = &res.tap_name {
        // The guest MAC is the shared `mac_math(vmid)` (v30 §18 delta 8). QEMU previously emitted
        // NO `mac=` on the tap arm, so every guest carried QEMU's fixed default 52:54:00:12:34:56.
        // That was invisible while each privileged VM owned an isolated /30 L2 domain, but two
        // members of one segment bridge is a deterministic L2 collision — and the §6.5 claim that
        // "member MACs are bridge-unique by the existing collision-freedom law" was only true once
        // this line existed.
        cmd.arg("-netdev")
            .arg(format!("tap,id=net0,ifname={tap},script=no,downscript=no"))
            .arg("-device")
            .arg(format!(
                "virtio-net-pci,netdev=net0,mac={}",
                vmcell::net::mac_math(res.vmid)?
            ));
    } else if let Some(socket) = &res.vhost_user_socket {
        // QEMU's `-chardev socket` connects as a *client* at exec with NO retry, so the
        // socket must already be bound. It is: `SmoltcpProcess::start` binds it on the
        // caller's thread, and `spawn_qemu` additionally waits for this exact path to
        // appear (the readiness gate lives there so that this composer stays I/O-free),
        // so by the time the argv is exec'd it is bound.
        cmd.arg("-chardev")
            .arg(format!("socket,id=net0,path={}", socket.display()))
            .arg("-netdev")
            .arg("vhost-user,id=vnet0,chardev=net0,vhostforce=on")
            .arg("-device")
            .arg(format!(
                "virtio-net-pci,netdev=vnet0,mac={}",
                vmcell::net::mac_math(res.vmid)?
            ));
    }

    // Host-USB passthrough (§2.4, QEMU q35 — the fallback and most-proven nester)): the xhci controller + one `usb-host` per
    // requested device, from the pure `build_qemu_usb_args` helper. Placed after the
    // extra-disk block and immediately before `-kernel` — the design's window — at
    // its LATE edge deliberately: appending here leaves the PCI enumeration order of
    // every pre-existing device (root/extra virtio-blk, virtio-fs, virtio-net)
    // untouched, so adding USB cannot shift `/dev/vd*` or the NIC. Migration
    // congruence does not constrain the slot: `config::build()` rejects
    // snapshotting + USB.
    cmd.args(build_qemu_usb_args(&cfg.usb_host_devices));

    let cmdline = vmcell::config::build_kernel_cmdline(cfg, res, "")?;
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

    Ok(plan)
}

/// Launches the composed `plan`, registers it in its cgroup, waits for QMP, and hands the
/// caller the [`SpawnedQemu`] record — the I/O half of [`Qemu::spawn_qemu`], split from
/// the argv composition so that half can stay pure.
///
/// Takes the [`LaunchPlan`](vmcell::vmm::LaunchPlan) by value and spawns **exactly** what it
/// carries: the command and the jail posture it was compiled from travel together from
/// [`qemu_launch_plan`] to the `exec`, so no step between them can substitute either half.
///
/// Takes ownership of the still-armed helper `daemons`: every fallible step below must
/// reap them, and `?` here does exactly that.
///
/// # Errors
/// Propagates the spawn, cgroup-registration and QMP-readiness failures.
async fn finish_qemu_spawn(
    plan: vmcell::vmm::LaunchPlan,
    cfg: &VmConfig,
    res: &PerVmResources,
    cgroups: &dyn vmcell::metrics::CgroupFs,
    params: &SpawnParams,
    daemons: SpawnedDaemons,
    paths: &QemuSpawnPaths<'_>,
) -> Result<SpawnedQemu> {
    let SpawnedDaemons {
        vsock: vsock_guard,
        fs: fs_daemons,
    } = daemons;
    let mut cmd = plan.into_command();
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
    let pgid = vmcell::vmm::register_and_await_ready(
        &mut process,
        cgroups,
        &res.cgroup_name,
        paths.qmp_socket,
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

    let endpoint = steward_endpoint(params, paths.vsock_path, cfg.steward_placement);

    Ok(SpawnedQemu {
        qmp_socket: paths.qmp_socket.to_path_buf(),
        vsock_path: paths.vsock_path.to_path_buf(),
        serial_path: paths.serial_path.to_path_buf(),
        process,
        vsock_daemon,
        fs_daemons,
        pgid,
        vsock_pgid,
        cid: params.guest_cid,
        endpoint,
        // Record the S1 predicate now (the spawn path has cfg+res); `snapshot()` reads
        // it to reject a vhost-user-carrying VM even when Task B gave a non-snapshot
        // in-kernel VM a Vsock endpoint.
        has_vhost_user_device: vmcell::vmm::config_has_vhost_user_device(cfg, res),
    })
}

impl Vmm for Qemu {
    type Instance = QemuInstance;

    async fn create(
        &self,
        cfg: &VmConfig,
        res: &PerVmResources,
        cgroups: &dyn vmcell::metrics::CgroupFs,
    ) -> Result<Self::Instance> {
        // The cmdline `console=` token and the serial/virtconsole device wiring in
        // `spawn_qemu` are both driven by `cfg.console_mode`; gate an unsupported
        // mode up front so they can never desync into a silent `serial.log`.
        vmcell::vmm::reject_unsupported_console("qemu", &self.capabilities(), cfg.console_mode)?;
        // The descriptor `false` no other guard here can see: `lazy_restore`. Refuse a
        // `RestoreMode::Lazy` config rather than accept it and demand-page nothing.
        reject_unadvertised_capabilities(&self.capabilities(), cfg)?;
        // Self-check against our OWN descriptor rather than assuming QEMU semantics
        // (the §2.1 trait contract, and the same shape as CH's `snapshot_restore`
        // self-check): today `usb_host_passthrough` is `true`, so this passes — but a
        // re-gate of the flag turns every USB config into the typed refusal here,
        // through the ONE shared predicate, with no second copy to update.
        vmcell::vmm::reject_usb_host_devices("qemu", &self.capabilities(), &cfg.usb_host_devices)?;
        // …and the half the descriptor cannot answer: QEMU accepts a `usb-host` device
        // that matches nothing on this host **without a word** (measured, §2.4 notes on
        // `resolve_usb_device_node`), so the requested devices are resolved to their
        // usbfs nodes and proven openable here, before the spawn.
        let usb_claim = vmcell::vmm::usb::claim_usb_host_devices("qemu", &cfg.usb_host_devices)?;

        // Cold create: fresh CID, no `-incoming`. A `snapshotting` config selects the
        // in-kernel vhost-vsock transport (§2.4, QEMU q35 — the fallback and most-proven nester) so the VM is snapshot-eligible.
        let params = SpawnParams {
            in_kernel_vsock: uses_in_kernel_vsock(cfg),
            guest_cid: res.guest_cid,
            incoming: false,
        };
        Ok(QemuInstance::from_spawned(
            self.spawn_qemu(cfg, res, cgroups, &params).await?,
            self.capabilities().snapshot_restore,
            usb_claim,
            cfg.mem_mib,
        ))
    }

    async fn restore(
        &self,
        snapshot_dir: &Path,
        cfg: &VmConfig,
        res: &PerVmResources,
        cgroups: &dyn vmcell::metrics::CgroupFs,
    ) -> Result<Self::Instance> {
        // Self-check our OWN descriptor before doing any work, exactly as CH's
        // `restore` does (M-RESTORE-3): a re-gate of `snapshot_restore` must land as
        // this typed refusal, not as a spawn + `migrate-incoming` against a QEMU the
        // descriptor says cannot do it. One predicate with `snapshot()`'s self-guard.
        require_snapshot_restore_capable(self.capabilities().snapshot_restore)?;
        vmcell::vmm::reject_unsupported_console("qemu", &self.capabilities(), cfg.console_mode)?;
        // The half `reject_usb_host_devices` structurally CANNOT cover here: QEMU's
        // `usb_host_passthrough` is `true`, so create's precheck passes a USB config — and
        // `spawn_qemu` splices `-device usb-host,…` on the restore path too. A restored VM
        // therefore carried the devices in its argv with no `claim_usb_host_devices` behind
        // them: never resolved to a usbfs node, never proven openable, never put back at
        // teardown. A host USB device is host state living OUTSIDE guest RAM — the migration
        // stream carries the guest's view of the xhci controller, not the device — so the
        // honest outcome is the typed refusal the ONE shared restore predicate returns
        // (§8.1, The warm-snapshot path and the eligibility law), the same `Removal` the orchestrator boundary already returned for this
        // config. It runs before the eligibility guards below because a non-snapshotting USB
        // config (the only shape `build()` admits) would otherwise die on the in-kernel-vsock
        // arm and never name the input to drop.
        vmcell::vmm::reject_usb_host_devices_on_restore(
            "qemu",
            &self.capabilities(),
            &cfg.usb_host_devices,
        )?;
        // Same self-check `create()` makes, on the path that actually consumes
        // `cfg.restore_mode`: a restore must not accept what create rejects.
        reject_unadvertised_capabilities(&self.capabilities(), cfg)?;

        // Eligibility (S1, §8.1, The warm-snapshot path and the eligibility law), defense in depth alongside `config::build()` and the
        // orchestrator re-check. The shared predicate catches a virtio-fs share or
        // unprivileged net; the in-kernel-vsock requirement catches the case it can't
        // see — a QEMU restore over the external `vhost-device-vsock` daemon, which is
        // itself a non-migratable vhost-user device.
        // The same two shared `Removal` consts `qemu_snapshot_eligibility` returns (F6): one law,
        // one spelling, so the snapshot and restore halves of the eligibility rule state the
        // identical refusal instead of the two near-miss prose strings they carried before.
        if vmcell::vmm::config_has_vhost_user_device(cfg, res) {
            return Err(Error::from_removal("qemu", &VHOST_USER_BLOCKS_SNAPSHOT));
        }
        if !uses_in_kernel_vsock(cfg) {
            return Err(Error::from_removal(
                "qemu",
                &IN_KERNEL_VSOCK_REQUIRED_FOR_SNAPSHOT,
            ));
        }

        // Fail loud BEFORE spawning if the migration stream is missing, so a bad
        // snapshot dir surfaces as a clear typed error instead of a later opaque
        // migrate-incoming failure against a live QEMU.
        let state = snapshot_dir.join(SNAPSHOT_STATE_FILE);
        if !tokio::fs::try_exists(&state).await.unwrap_or(false) {
            return Err(Error::Vmm(format!(
                "QEMU snapshot state file {} is missing (not a valid snapshot dir)",
                state.display()
            )));
        }

        // Restore rotates the host-global guest CID: spawn with the **fresh**
        // `res.guest_cid` (allocator-unique among live VMs), not the source's. The
        // `guest-cid` is a QEMU device property, not part of the migration stream, so
        // the destination binds a new CID and the guest is reachable there after
        // migrate-incoming (validated live, §2.4). Each concurrent clone thus holds its
        // own CID on the host-global vhost-vsock namespace — the property that makes
        // concurrent QEMU zygote fan-out sound (`restore_rotates_host_paths: true`); a
        // kernel `VHOST_VSOCK_SET_GUEST_CID` `EADDRINUSE` at realize is the fail-loud
        // backstop if the allocator ever handed a still-live CID.
        let params = SpawnParams {
            in_kernel_vsock: true,
            guest_cid: res.guest_cid,
            incoming: true,
        };
        let instance = QemuInstance::from_spawned(
            self.spawn_qemu(cfg, res, cgroups, &params).await?,
            self.capabilities().snapshot_restore,
            // No USB claim on the restore path: a non-empty `usb_host_devices` is refused
            // by `reject_usb_host_devices_on_restore` above — in this backend as well as at
            // the orchestrator boundary (docs/78 M4) — so the list reaching here is empty by
            // construction, a restored VM never displaces a host driver, and there is
            // nothing to put back.
            vmcell::vmm::usb::UsbHostClaim::default(),
            cfg.mem_mib,
        );

        // Drive the incoming migration on the now-ready QMP socket and wait for it to
        // complete. The VM stays **paused** afterward (the source was paused during
        // `migrate`, and `-incoming` loads into that state): the orchestrator resumes
        // it via `resume()` — never `boot()` (§2.1, The trait and the capability descriptor). If this fails, `instance` drops
        // and reaps QEMU, so no half-restored VM leaks. (`state` was existence-checked
        // pre-spawn above.)
        let migrate_incoming = format!(
            "{{\"execute\": \"migrate-incoming\", \"arguments\": {{\"uri\": \"file:{}\"}}}}",
            state.display()
        );
        // M6: the incoming stream is the same guest-RAM-proportional artifact the
        // outgoing one is, so it rides the same budget (the FC precedent, which budgets
        // `/snapshot/create` AND `/snapshot/load` through the one predicate).
        instance.drive_migration(&migrate_incoming).await?;
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
            // Restore rotates the host-global guest CID to a fresh `res.guest_cid`
            // (the device `guest-cid` is not part of the migration stream, so the
            // destination binds a new CID and the guest is reachable there — validated
            // live, §2.4). Each concurrent clone therefore holds its own CID, so
            // concurrent QEMU zygote fan-out is supported — like CH, unlike FC's
            // verbatim baked-path rebind. A deliberate re-gate must flip this AND its
            // capability-honesty test together (docs/45).
            restore_rotates_host_paths: true,
            // QEMU has native per-drive throttling (`throttling.bps-total`/`iops-total`), §4.6.
            disk_io_throttle: true,
            // The ONE backend whose upstream binary attaches a host USB device: one
            // `qemu-xhci` controller plus a `usb-host` device per requested
            // `(vendorid, productid)` (§2.4, QEMU q35 — the fallback and most-proven nester), emitted by `build_qemu_usb_args`.
            //
            // What this `true` rests on — EXECUTED against QEMU 10.2.1 (Debian
            // 1:10.2.1+ds-1ubuntu3.2) on 2026-08-11, recorded under
            // "v30 delta 9 — host-USB passthrough" in docs/implementation-notes.md:
            //   * `qemu-system-x86_64 -device help` lists BOTH `qemu-xhci` and
            //     `usb-host`, and an absent device MODEL is fail-loud (a bogus name exits
            //     1 naming it) — so a libusb-less build cannot silently drop the device.
            //   * launching with vmcell's own Enforcing `-sandbox
            //     on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny`
            //     PLUS `-device qemu-xhci,id=vmcell-xhci -device usb-host,…` reaches QMP
            //     `prelaunch` — the libseccomp filter tolerates the usb-host/usbfs path,
            //     so no sandbox downgrade is owed (§2.4's second empirical question).
            //   * the third (device-node access) is answered per launch, not assumed:
            //     `require_usb_host_devices` resolves each requested id pair to its
            //     `/dev/bus/usb/BBB/DDD` node and proves it opens read-write — because
            //     the same run showed QEMU accepts an ABSENT device in total silence.
            //   * in-GUEST enumeration — the last question, CLOSED on 2026-08-12 by the
            //     opt-in `just test-usb-passthrough` leg against two real devices on this
            //     host: a Goodix fingerprint reader (27c6:609c, no host driver bound) and a
            //     Realtek 2.5G NIC (0bda:8156, whose interface held a live `r8152`). Both
            //     enumerate in-guest with the ids the config asked for, and the leg reddens
            //     when the argv splice is dropped.
            //     MEASURED CAVEAT, and the reason the recipe demands a *disposable* device:
            //     the device comes back on the host bus after the guest exits, but in the
            //     CONFIGURATION the guest left it in — the NIC returned at
            //     `bConfigurationValue=2` (of 3) with NO driver bound, so `r8152` did not
            //     re-bind and the host lost that netdev until the config is reset (write 1 to
            //     the device's `bConfigurationValue`, or replug). Passthrough is not
            //     transparent to the host driver.
            // So this `true` is now validated end to end, not presumed (AGENTS.md rule 5).
            // A re-gate must flip this AND its honesty pin.
            usb_host_passthrough: true,
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

        // The one shared signal/wait/flag sequence (L1): SIGKILL the group unless the
        // leader was already reaped, await it, record the reap (M-VMM-1).
        self.group.kill_and_wait(&mut self.process).await;

        // QEMU is gone, so the usbfs fds it held are closed and the interfaces are free:
        // put back the host drivers passthrough displaced. Ordered AFTER the reap on
        // purpose — re-binding while QEMU still holds the device would race it.
        self.usb_claim.restore();

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
        // `request_shutdown` (`system_powerdown`). The shared helper records the reap so
        // `kill()`/`Drop` cannot re-`SIGKILL` a possibly-recycled pgid.
        self.group.note_exit(&mut self.process)
    }

    async fn snapshot(&mut self, dir: &Path) -> Result<()> {
        // Eligibility (S1, §8.1) — the authoritative snapshot-time guard, now including
        // the `snapshot_restore` descriptor self-check (M-RESTORE-3) over the flag this
        // instance captured at construction. Restore rotates the CID (§2.4), so the
        // source CID is not persisted; the migration stream is the only artifact.
        qemu_snapshot_eligibility(
            self.snapshot_restore_capable,
            &self.endpoint,
            self.has_vhost_user_device,
        )?;

        // pause → migrate-to-file → poll `completed` → resume the source. Mirrors the
        // CH/FC snapshot order (§8.1, The warm-snapshot path and the eligibility law); the orchestrator's `MicroVm::snapshot`
        // invalidates the cached steward client afterward, which covers QEMU's
        // pause/migrate severing the vsock connection.
        self.qmp_command_checked("{\"execute\": \"stop\"}").await?;

        let state = dir.join(SNAPSHOT_STATE_FILE);
        let migrate_cmd = format!(
            "{{\"execute\": \"migrate\", \"arguments\": {{\"uri\": \"file:{}\"}}}}",
            state.display()
        );
        // The migration stream is the whole snapshot; its `completed`/`failed` status is
        // the result. No sidecar is written — restore programs a fresh CID (§2.4).
        // M6: the stream is guest RAM + device state, so the budget is
        // `snapshot_budget()` — the shared guest-RAM-proportional predicate over QEMU's
        // measured floor — NOT the flat control ceiling `qmp_command` uses for
        // `stop`/`cont`/`system_powerdown`.
        let result = self.drive_migration(&migrate_cmd).await;

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

    /// Probes QEMU's external `vhost-device-vsock` data path by doing the real steward
    /// handshake with a bounded budget (reusing the one connect/handshake law, so the
    /// `CONNECT`/`OK`/`Ready` protocol lives in exactly one place). A healthy boot
    /// binds its guest listener and answers `Ready` in well under the budget; a
    /// wedged vhost-user bring-up never answers, so this returns `Timeout` and the
    /// orchestrator re-spawns (see the trait doc). The probe client is dropped — the
    /// caller's lazy `steward()` reconnects, which the guest re-accepts on its still
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
        timeouts: &vmcell::config::Timeouts,
    ) -> Result<()> {
        if let VsockEndpoint::Vsock { .. } = self.endpoint {
            return Ok(());
        }
        let serial = vmcell::vmm::RealSerialLog {
            path: self.serial_path.clone(),
        };
        vmcell::steward::StewardClient::connect_endpoint(&self.endpoint, budget, timeouts, &serial)
            .await
            .map(|_client| ())
    }
}

impl Drop for QemuInstance {
    fn drop(&mut self) {
        // Teardown order (AGENTS.md): VMM process group first — reaping it before
        // touching the daemons, sockets or the per-VM directory means cleanup never
        // races a live VMM.
        // Same helper, same order as the graceful `kill()` path (L1): the group SIGKILL +
        // blocking reap is skipped if the leader was already reaped, since its pgid may
        // have been recycled (M-VMM-1).
        self.group.reap_now(&mut self.process);
        // With the VMM reaped, the host USB drivers it displaced can go back (same step,
        // same order, as the graceful `kill()` path — one helper, never a second copy).
        self.usb_claim.restore();
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

    /// The shared [`vmcell::metrics::FakeCgroupFs`], exposed by `vmcell`'s `test-support`
    /// feature (a dev-dependency of this crate). It replaces the hand-rolled per-crate
    /// `CgroupFs` fake this crate carried while `FakeCgroupFs` was `#[cfg(test)]`-only and
    /// therefore invisible downstream — one of four such copies (docs/81 §9).
    ///
    /// It is still structurally blind to the filesystem (AGENTS rule 4): it models slices,
    /// tasks and delegation in memory and writes no cgroup sysfs, so nothing driven by it is
    /// evidence about real cgroup residue or enforcement. That is `just test-privileged`.
    use vmcell::metrics::FakeCgroupFs;

    /// Asserts a refusal **is** the shared [`vmcell::feature::Removal`] handed in — not merely
    /// "some `snapshot_restore` refusal".
    ///
    /// F6 collapsed every snapshot refusal onto one feature string, so the exact
    /// `feature == Feature::SnapshotRestore.name()` comparison that replaced
    /// `feature.contains("in-kernel vsock")` no longer tells the external-daemon leg from the
    /// vhost-user leg: both spell `snapshot_restore`. The discriminator moved into the `Removal`,
    /// so this composes the expected error from the SHARED const through the one composer
    /// ([`Error::from_removal`]) and compares renderings — a leg that returns the wrong const goes
    /// red, and no test hand-spells the prose F6 retired: edit a const and both sides move together.
    #[track_caller]
    fn assert_is_removal(err: &Error, removal: &vmcell::feature::Removal) {
        assert!(
            matches!(err, Error::Unsupported { feature, .. } if feature == removal.feature.name()),
            "the feature string must be Feature::name() by construction (F6), got {err:?}"
        );
        assert_eq!(
            err.to_string(),
            Error::from_removal("qemu", removal).to_string(),
            "the refusal must be THIS removal: every snapshot refusal now spells `{}`, so the \
             provenance the Removal carries is the only thing separating the legs",
            removal.feature.name()
        );
    }

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

    // v30 §18 (Delta register) delta 9 / §2.4 (QEMU q35 — the fallback and most-proven nester): the host-USB argv GOLDEN. QEMU's argv is
    // otherwise assembled inline into a `Command`, so this is the reason the fragment was
    // extracted as a pure helper (the `build_crosvm_run_args` precedent). It pins, on
    // exact tokens: (a) no devices => NO USB argv at all (QEMU runs `-nodefaults`, so a
    // stray controller would appear in every VM); (b) exactly ONE `qemu-xhci` controller
    // regardless of device count; (c) one `usb-host` per device, in call order; (d) the
    // zero-padded lowercase `0x%04x` id rendering QEMU's property parser expects.
    // Red on the inverse: emitting the controller per device, `{:x}` (unpadded) or
    // `{}` (decimal) ids, or a controller with an empty device list.
    #[test]
    fn qemu_usb_args_golden() {
        use vmcell::config::UsbHostDevice;

        assert!(
            build_qemu_usb_args(&[]).is_empty(),
            "no USB device requested must emit no USB argv (QEMU is -nodefaults)"
        );

        assert_eq!(
            build_qemu_usb_args(&[UsbHostDevice::new(0x1d6b, 0x0002)]),
            vec![
                "-device".to_string(),
                "qemu-xhci,id=vmcell-xhci".to_string(),
                "-device".to_string(),
                "usb-host,vendorid=0x1d6b,productid=0x0002".to_string(),
            ]
        );

        // Two devices: still ONE controller, then both `usb-host` devices in order. The
        // second id (0x0a5c:0x0021) is padded on neither half by accident — `{:04x}`
        // renders `0x0a5c`/`0x0021`, which is what a `%i` QEMU property expects.
        assert_eq!(
            build_qemu_usb_args(&[
                UsbHostDevice::new(0x1d6b, 0x0002),
                UsbHostDevice::new(0x0a5c, 0x0021),
            ]),
            vec![
                "-device".to_string(),
                "qemu-xhci,id=vmcell-xhci".to_string(),
                "-device".to_string(),
                "usb-host,vendorid=0x1d6b,productid=0x0002".to_string(),
                "-device".to_string(),
                "usb-host,vendorid=0x0a5c,productid=0x0021".to_string(),
            ]
        );
    }

    /// A `VmConfig` carrying `devices` and nothing else unusual.
    fn usb_cfg(devices: &[vmcell::config::UsbHostDevice]) -> VmConfig {
        use vmcell::config::RootfsSource;
        let mut builder = VmConfig::builder(
            "/k",
            RootfsSource::Erofs {
                image: PathBuf::from("/i"),
            },
        );
        for device in devices {
            builder = builder.with_usb_host_device(*device);
        }
        builder.build().expect("build config")
    }

    /// The launch plan `spawn_qemu` would exec for `cfg`, built without spawning anything.
    ///
    /// One helper for both halves of the plan — the composed argv and the recorded jail posture
    /// — so no gate can assert on a launch some other gate did not see.
    fn test_plan(cfg: &VmConfig) -> vmcell::vmm::LaunchPlan {
        let params = SpawnParams {
            in_kernel_vsock: false,
            guest_cid: 3,
            incoming: false,
        };
        let paths = QemuSpawnPaths {
            qmp_socket: Path::new("/tmp/vmcell-argv-test/qmp.sock"),
            vsock_path: Path::new("/tmp/vmcell-argv-test/vsock.sock"),
            vhost_vsock: Path::new("/tmp/vmcell-argv-test/vhost-vsock.sock"),
            serial_path: Path::new("/tmp/vmcell-argv-test/serial.log"),
            fs_daemon_sockets: &[],
        };
        qemu_launch_plan(
            Path::new("/usr/bin/qemu-system-x86_64"),
            cfg,
            &restore_test_res(),
            &params,
            &paths,
        )
        .expect("the launch plan composes")
    }

    /// The **composed** argv `spawn_qemu` would exec for `cfg` — the real `Command`, read back
    /// through the shared [`vmcell::vmm::LaunchPlan::argv`] accessor without spawning anything.
    ///
    /// This is the observation point a per-fragment helper test cannot reach: it sees the
    /// `cmd.args(...)` splices themselves, so deleting one reddens.
    fn composed_argv(cfg: &VmConfig) -> Vec<String> {
        test_plan(cfg).argv()
    }

    // v30 §18 delta 9 GATE, over the COMPOSED argv (the fragment→`Command` seam). The
    // per-fragment golden above proves `build_qemu_usb_args` renders the right tokens; it
    // says nothing about whether they ever reach the process, and deleting the
    // `cmd.args(build_qemu_usb_args(...))` splice left every other gate green. This test
    // is the one that reddens on that deletion. It pins, on the real `Command`:
    // (a) the fragment appears CONTIGUOUSLY and in order in the argv the launch execs;
    // (b) it sits in the design's window — after the last virtio-blk device, before
    //     `-kernel` — so PCI enumeration of the existing devices is unshifted;
    // (c) USB is purely ADDITIVE: strip the fragment's window and the argv is identical
    //     to the same config with no USB device (a splice that also reordered or dropped
    //     another device would redden here);
    // (d) negative control: with no USB device requested, no USB token is emitted at all
    //     (QEMU is `-nodefaults`, so a stray controller would ride in every VM).
    #[test]
    fn qemu_full_argv_splices_the_usb_fragment() {
        use vmcell::config::UsbHostDevice;

        let devices = [
            UsbHostDevice::new(0x1d6b, 0x0002),
            UsbHostDevice::new(0x0a5c, 0x0021),
        ];
        let argv = composed_argv(&usb_cfg(&devices));
        let fragment = build_qemu_usb_args(&devices);

        let at = argv
            .windows(fragment.len())
            .position(|w| w == fragment)
            .unwrap_or_else(|| {
                panic!(
                    "the composed QEMU argv never carries the USB fragment {fragment:?} — \
                     `usb_host_passthrough` is advertised but the device is silently dropped; \
                     argv was {argv:?}"
                )
            });

        let kernel_at = argv
            .iter()
            .position(|a| a == "-kernel")
            .expect("every launch carries -kernel");
        let last_blk = argv
            .iter()
            .rposition(|a| a.starts_with("virtio-blk-pci"))
            .expect("every launch carries the root virtio-blk device");
        assert!(
            last_blk < at,
            "the USB fragment must follow the block devices so /dev/vd* cannot shift: {argv:?}"
        );
        assert!(
            at + fragment.len() <= kernel_at,
            "the USB fragment must precede -kernel (§2.4's window): {argv:?}"
        );

        let mut stripped = argv.clone();
        stripped.drain(at..at + fragment.len());
        assert_eq!(
            stripped,
            composed_argv(&usb_cfg(&[])),
            "attaching USB must add ONLY the USB fragment to the argv"
        );

        assert!(
            !composed_argv(&usb_cfg(&[]))
                .iter()
                .any(|a| a.contains("usb-host") || a.contains("xhci")),
            "a config with no USB device must get no USB argv at all (QEMU is -nodefaults)"
        );
    }

    /// A `VmConfig` identical to `usb_cfg(&[])` except for its VMM seccomp policy — the
    /// one axis the sandbox gate below varies, so the two composed argvs differ by
    /// exactly the `-sandbox` splice and nothing else.
    fn seccomp_cfg(policy: vmcell::config::VmmSeccomp) -> VmConfig {
        use vmcell::config::RootfsSource;
        VmConfig::builder(
            "/k",
            RootfsSource::Erofs {
                image: PathBuf::from("/i"),
            },
        )
        .vmm_seccomp(policy)
        .build()
        .expect("build config")
    }

    // M11 GATE, QEMU leg (KVM-free) — the LAYER-2 half, the sibling of the Layer-1 sandbox gate
    // below. The jail posture is applied in `build_vmm_cmd`'s post-fork `pre_exec` closure, which
    // NOTHING KVM-free can observe: while `qemu_launch_plan` wrote
    // `jail_spec_from_config(&cfg.jail)?` inline, rewriting that one token to a weakened config
    // shipped every QEMU VM with a different Layer-2 posture and left `cargo test`, `just ci` and
    // the whole live matrix green (the deny-list is default-allow/`EPERM`, so no functional leg
    // notices). Routing through `vmcell::vmm::LaunchPlan` makes the posture a RETURNED VALUE, so
    // it is assertable — and `LaunchPlan::jail` is private to `vmcell::vmm::launch`, so the
    // two-line defeat (`let mut plan = …; plan.jail = weaker;`) does not even compile here.
    //
    // Red on the inverse: hand `qemu_launch_plan`'s `LaunchPlan::build` any value other than
    // `cfg.jail` — `JailConfig::disabled()` is the interesting one — and the first assertion
    // reddens.
    #[test]
    fn the_qemu_launch_plan_ships_the_configured_jail_posture() {
        use vmcell::config::{JailConfig, RootfsSource};

        let plan_for = |jail: JailConfig| {
            let cfg = VmConfig::builder(
                "/k",
                RootfsSource::Erofs {
                    image: PathBuf::from("/i"),
                },
            )
            .jail(jail)
            .build()
            .expect("build config");
            let plan = test_plan(&cfg);
            (cfg, plan)
        };

        // The plan's jail half IS the configured posture.
        let (cfg, plan) = plan_for(JailConfig::hardened());
        assert_eq!(
            plan.jail(),
            cfg.jail,
            "the launch plan must ship `cfg.jail`, not a locally-built posture"
        );

        // Positive control, so the equality above is not a tautology about two identical structs:
        // a DIFFERENT requested posture produces a different record, and compiled, the difference
        // is real hardening versus none at all — what shipping the wrong value does.
        let (disabled_cfg, disabled_plan) = plan_for(JailConfig::disabled());
        assert_eq!(disabled_plan.jail(), disabled_cfg.jail);
        assert_ne!(
            plan.jail(),
            disabled_plan.jail(),
            "control: the two postures differ, so the plan is not returning a constant"
        );
        assert!(
            !vmcell::vmm::jail::jail_spec_from_config(&plan.jail())
                .expect("compile the shipped spec")
                .is_noop(),
            "the shipped hardened posture must compile to real hardening"
        );
        assert!(
            vmcell::vmm::jail::jail_spec_from_config(&disabled_plan.jail())
                .expect("compile the disabled spec")
                .is_noop(),
            "control: the disabled posture compiles to no hardening — what a wrong value ships"
        );

        // …and the two postures are the ONLY difference: the argv is byte-identical either way,
        // so this gate and the argv gates below observe one and the same launch (a plan that
        // smuggled a jail difference into the command line would redden here).
        assert_eq!(
            plan.argv(),
            disabled_plan.argv(),
            "the jail posture is a `pre_exec` property, never an argv one"
        );
    }

    // M11 / §12.2 (Layer 1 — the VMM's own seccomp filter) GATE, over the COMPOSED argv.
    // `vmm_seccomp_args` has its own golden in `vmcell`, but that says nothing about
    // whether the tokens ever reach the process: deleting `cmd.args(&seccomp_args)` from
    // `qemu_launch_plan` left every gate green while QEMU — which has NO sandbox unless
    // the flag is passed — ran unconfined. This is the test that reddens on that deletion,
    // the same fragment-vs-composed seam the delta-9 pass closed for USB. It pins:
    // (a) `Enforcing` puts `-sandbox` and its spec CONTIGUOUSLY in the launched argv
    //     (a splice that separated them would leave QEMU parsing a bare `-sandbox`);
    // (b) the value is the ONE shared `vmm_seccomp_args` predicate's, never a local copy;
    // (c) `Disabled` emits no sandbox token at all — and the two argvs differ by exactly
    //     that pair, so the splice cannot smuggle in or drop any other flag.
    #[test]
    fn qemu_full_argv_splices_the_sandbox_flag() {
        use vmcell::config::VmmSeccomp;

        let expected = vmcell::vmm::seccomp::vmm_seccomp_args("qemu", VmmSeccomp::Enforcing)
            .expect("the one seccomp predicate composes QEMU's Enforcing flag");
        assert_eq!(
            expected.len(),
            2,
            "QEMU's Enforcing policy is the `-sandbox <spec>` pair: {expected:?}"
        );

        let argv = composed_argv(&seccomp_cfg(VmmSeccomp::Enforcing));
        let at = argv
            .windows(expected.len())
            .position(|w| w == expected.as_slice())
            .unwrap_or_else(|| {
                panic!(
                    "the composed QEMU argv never carries the sandbox flag {expected:?} — \
                     QEMU launches UNCONFINED (it has no sandbox unless told); argv was {argv:?}"
                )
            });

        // Negative control: the loud opt-out emits no sandbox token whatsoever (a
        // `-sandbox off` regression would still match `contains("sandbox")`).
        let disabled = composed_argv(&seccomp_cfg(VmmSeccomp::Disabled));
        assert!(
            !disabled.iter().any(|a| a.contains("sandbox")),
            "VmmSeccomp::Disabled must emit no -sandbox token at all: {disabled:?}"
        );

        // …and Enforcing adds ONLY that pair: strip it and the two argvs are identical.
        let mut stripped = argv.clone();
        stripped.drain(at..at + expected.len());
        assert_eq!(
            stripped, disabled,
            "the sandbox splice must add ONLY the `-sandbox <spec>` pair to the argv"
        );
    }

    // Capability honesty (AGENTS.md rule 5 / §7.2): QEMU is the ONE backend advertising
    // `usb_host_passthrough`, and the flag must move together with what the launch
    // actually execs — a `true` with no `qemu-xhci` in the COMPOSED argv is the
    // silent-drop failure the capability exists to prevent. Red on the inverse: flip the
    // flag, make `build_qemu_usb_args` return empty for a non-empty list, or delete the
    // splice in `qemu_launch_plan`.
    #[test]
    fn qemu_usb_capability_matches_the_emitted_argv() {
        let caps = Qemu::new("/usr/bin/qemu-system-x86_64").capabilities();
        assert!(
            caps.usb_host_passthrough,
            "QEMU advertises usb_host_passthrough (qemu-xhci + usb-host, §2.4)"
        );
        let argv = composed_argv(&usb_cfg(&[vmcell::config::UsbHostDevice::new(
            0x1d6b, 0x0002,
        )]));
        assert!(
            argv.iter().any(|a| a == "qemu-xhci,id=vmcell-xhci"),
            "a true usb_host_passthrough must put the xhci controller on the real command \
             line; got {argv:?}"
        );
        assert!(
            argv.iter()
                .any(|a| a == "usb-host,vendorid=0x1d6b,productid=0x0002"),
            "a true usb_host_passthrough must put the requested device on the real command \
             line; got {argv:?}"
        );
    }

    // v30 §18 delta 8 GATE, over the COMPOSED argv. QEMU's tap arm emitted NO `mac=`, so every
    // guest carried QEMU's fixed default 52:54:00:12:34:56 — two members of one segment bridge
    // were a deterministic L2 collision, and §6.5's "member MACs are bridge-unique by the existing
    // collision-freedom law" was simply false here. Buggy impl guarded: dropping the `,mac=`
    // splice reddens on the identity assertion; hardcoding one MAC reddens on the distinctness
    // assertion. Recomputed through `vmcell::net::mac_math`, never a test-local format!.
    #[test]
    fn qemu_tap_argv_carries_the_vmid_derived_mac() {
        use vmcell::config::{RootfsSource, VmConfig};
        let cfg = VmConfig::builder(
            "/k",
            RootfsSource::Erofs {
                image: PathBuf::from("/i"),
            },
        )
        .build()
        .expect("build config");

        let argv = composed_argv(&cfg);
        let res = restore_test_res();
        let mac = vmcell::net::mac_math(res.vmid).expect("mac_math");
        assert!(
            argv.iter()
                .any(|a| a == &format!("virtio-net-pci,netdev=net0,mac={mac}")),
            "the tap arm must set the vmid-derived guest MAC; got {argv:?}"
        );
        assert!(
            !argv.iter().any(|a| a == "virtio-net-pci,netdev=net0"),
            "the bare, MAC-less net device must be gone (it took QEMU's fixed default MAC): {argv:?}"
        );
        // Distinct vmids give distinct MACs — the bridge-uniqueness property itself.
        let other_res = PerVmResources {
            vmid: res.vmid + 1,
            ..restore_test_res()
        };
        assert_ne!(
            mac,
            vmcell::net::mac_math(other_res.vmid).expect("mac_math"),
            "two members of one bridge must not share a MAC"
        );
    }

    // One law, one predicate (§13): the `-drive file=…` that becomes `/dev/vda` names
    // `RootfsSource::effective_image` — the SAME predicate the config boundary's
    // duplicate-backing-file guard uses. They used to be separate copies of
    // `overlay.as_ref().unwrap_or(image)`, so a divergence would have let the guard protect a file
    // this argv does not attach. Expected values are recomputed THROUGH the helper, never a
    // test-local literal, and asserted on the COMPOSED argv. Buggy impl this guards: emitting the
    // base image while an overlay is set (guest writes land in the shared base) reddens the
    // overlay leg.
    #[test]
    fn qemu_root_drive_uses_the_effective_image_law() {
        use vmcell::config::{RootfsSource, VmConfig};

        let base = PathBuf::from("/img/base.raw");
        let overlay = PathBuf::from("/img/vm-7-overlay.raw");

        let root_drive = |rootfs: RootfsSource| {
            let cfg = VmConfig::builder("/k", rootfs)
                .build()
                .expect("build config");
            let argv = composed_argv(&cfg);
            let spec = argv
                .iter()
                .find(|a| a.contains("id=rfs"))
                .expect("the root -drive must be present")
                .clone();
            (cfg, spec)
        };

        // Plain image: no overlay, so the base IS the effective image.
        let (plain_cfg, plain_spec) = root_drive(RootfsSource::Block {
            image: base.clone(),
            overlay: None,
        });
        // `readonly=on` is part of the expected string: the device's writability must not exceed
        // the mount's, and the mount is always `ro` (§4.7;
        // `RootfsSource::root_device_read_only`). Spelled as a literal in the expectation rather
        // than recomputed through the law, which would be vacuous now that the composer reads it —
        // this is the leg that reddens on the pre-delta-8 `Block` arm, which emitted no
        // `readonly=on` at all.
        assert_eq!(
            plain_spec,
            format!(
                "file={},format=raw,id=rfs,if=none,readonly=on,file.locking=off",
                plain_cfg.rootfs.effective_image().display()
            ),
            "the root -drive must name the effective image and attach it READ-ONLY"
        );

        // Overlay set: the overlay backs /dev/vda, the base is never attached.
        let (ovl_cfg, ovl_spec) = root_drive(RootfsSource::Block {
            image: base.clone(),
            overlay: Some(overlay),
        });
        assert_eq!(
            ovl_spec,
            format!(
                "file={},format=raw,id=rfs,if=none,readonly=on,file.locking=off",
                ovl_cfg.rootfs.effective_image().display()
            ),
            "with an overlay set, the overlay backs /dev/vda — and it is a per-VM private COPY, \
             not a write target, so it is attached read-only too"
        );
        // Non-vacuous: the two paths genuinely differ.
        assert_ne!(
            ovl_cfg.rootfs.effective_image(),
            base,
            "the overlay case must not resolve to the base image"
        );

        // EROFS: the image itself, read-only.
        let (erofs_cfg, erofs_spec) = root_drive(RootfsSource::Erofs {
            image: PathBuf::from("/img/rootfs.erofs"),
        });
        assert_eq!(
            erofs_spec,
            format!(
                "file={},format=raw,id=rfs,if=none,readonly=on,file.locking=off",
                erofs_cfg.rootfs.effective_image().display()
            ),
            "an EROFS root is the image itself, read-only"
        );
    }

    fn restore_test_res() -> PerVmResources {
        PerVmResources {
            cgroup_name: "vmcell-test".to_string(),
            tap_name: Some("tap0".to_string()),
            netns_name: None,
            segment: None,
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
        use vmcell::config::{RootfsSource, VmConfig};

        let qemu = Qemu::new("/usr/bin/qemu-system-x86_64");
        let cfg = VmConfig::builder(
            "/k",
            RootfsSource::Erofs {
                image: PathBuf::from("/i"),
            },
        )
        .build()
        .expect("build config");
        let cgroups = FakeCgroupFs::new();

        let err = qemu
            .restore(
                Path::new("/nonexistent-snapshot"),
                &cfg,
                &restore_test_res(),
                &cgroups,
            )
            .await
            .expect_err("QEMU restore of a non-snapshotting config must be Unsupported");
        // F6: the retired `feature.contains("in-kernel vsock")` matched the prose the refusal used
        // to carry. The feature string is `Feature::SnapshotRestore.name()` now, which alone cannot
        // separate this leg from the vhost-user one, so the leg is pinned to the shared const's
        // identity. The non-vacuity pair is the sibling test below: the SAME restore with
        // `snapshotting(true)` gets past this guard and reaches the state-file check.
        assert_is_removal(&err, &IN_KERNEL_VSOCK_REQUIRED_FOR_SNAPSHOT);
    }

    // docs/90 A3 (the open half of docs/78 M4), QEMU leg — the discriminating one. QEMU is the
    // ONE backend whose `usb_host_passthrough` is `true`, so `reject_usb_host_devices` passes a
    // USB config here and copying create's precheck into `restore()` would have been a NO-OP.
    // What `restore()` actually did with such a config, measured: `spawn_qemu` is shared, so it
    // spliced `-device qemu-xhci … -device usb-host,…` into the restored VM's argv while
    // `restore()` handed the instance a `UsbHostClaim::default()` — devices never resolved to a
    // usbfs node, never proven openable, never put back at teardown. A host USB device is host
    // state OUTSIDE guest RAM (the migration stream carries the guest's view of the xhci
    // controller, not the device), so the honest outcome is a typed refusal naming that reason:
    // the same `Removal` the orchestrator's clone-eligibility arm already returned.
    //
    // Four legs, all KVM-free and binary-free (the refusal precedes every spawn):
    //   1. the refusal itself, asserted by arm IDENTITY, not by a prose fragment;
    //   2. the discriminator — the capability arm of the shared predicate ACCEPTS this list on
    //      QEMU, so leg 1 can only have come from the restore-only arm;
    //   3. the cold path is untouched: `create()` travels past the descriptor precheck into the
    //      real host-side claim, which is where a USB config lives or dies on this backend;
    //   4. the non-vacuity control — the same restore MINUS the device reaches the next guard.
    //
    // Red on the inverse: delete the `reject_usb_host_devices_on_restore` call from `restore()`
    // and leg 1 gets the in-kernel-vsock refusal (the guard below it) instead of this one.
    #[tokio::test]
    async fn restore_refuses_a_host_usb_config_qemu_alone_can_create() {
        use vmcell::config::{RootfsSource, UsbHostDevice, VmConfig};

        let qemu = Qemu::new("/usr/bin/qemu-system-x86_64");
        let device = UsbHostDevice::new(0xdead, 0xbeef);
        // `build()` refuses `usb_host_devices` + `snapshotting`, so a host-USB config is
        // non-snapshotting BY CONSTRUCTION — which is exactly why the restore-side USB guard has
        // to run before the eligibility guards, and why leg 4 below is the control it needs.
        let usb_cfg = VmConfig::builder(
            "/k",
            RootfsSource::Erofs {
                image: PathBuf::from("/i"),
            },
        )
        .with_usb_host_device(device)
        .build()
        .expect("a host-USB device on a non-snapshotting config must build");
        let cgroups = FakeCgroupFs::new();

        // 1. The refusal, by arm identity.
        let err = qemu
            .restore(
                Path::new("/nonexistent-qemu-usb-snapshot"),
                &usb_cfg,
                &restore_test_res(),
                &cgroups,
            )
            .await
            .expect_err("a restored VM cannot re-attach a host USB device");
        assert_is_removal(&err, &vmcell::vmm::USB_PASSTHROUGH_BLOCKS_RESTORE);

        // 2. The discriminator: QEMU's descriptor says it CAN attach one, so the shared
        //    capability arm accepts this very list. Leg 1 is therefore the restore-only arm
        //    talking — not `reject_usb_host_devices` firing, which on this backend it cannot.
        let caps = <Qemu as Vmm>::capabilities(&qemu);
        assert!(
            caps.usb_host_passthrough,
            "QEMU is the backend that CAN pass a host USB device (§2.4, QEMU q35 — the fallback and most-proven nester): {caps:?}"
        );
        vmcell::vmm::reject_usb_host_devices("qemu", &caps, &usb_cfg.usb_host_devices)
            .expect("the capability arm must accept a USB list on QEMU");

        // 3. The cold path is unchanged: `create()` gets past the descriptor precheck and dies in
        //    the real host-side claim (`claim_usb_host_devices`), which is what a USB config is
        //    supposed to face on QEMU. `0xdead:0xbeef` matches no host device, so the claim is a
        //    read-only sysfs scan that detaches nothing.
        let err = qemu
            .create(&usb_cfg, &restore_test_res(), &cgroups)
            .await
            .expect_err("no host device matches dead:beef, so the claim fails loud");
        assert!(
            matches!(&err, Error::Vmm(msg) if msg.contains("host USB passthrough")),
            "create must still reach the host-side USB claim, not a typed refusal: {err:?}"
        );

        // 4. Non-vacuity: the SAME restore without the device travels past the new guard and dies
        //    on the eligibility guard below it — so leg 1 is about the device, not about restore
        //    refusing every non-snapshotting config.
        let clean_cfg = VmConfig::builder(
            "/k",
            RootfsSource::Erofs {
                image: PathBuf::from("/i"),
            },
        )
        .build()
        .expect("build the control config");
        let err = qemu
            .restore(
                Path::new("/nonexistent-qemu-usb-snapshot"),
                &clean_cfg,
                &restore_test_res(),
                &cgroups,
            )
            .await
            .expect_err("the control still fails on the external-vsock eligibility guard");
        assert_is_removal(&err, &IN_KERNEL_VSOCK_REQUIRED_FOR_SNAPSHOT);
    }

    // A snapshotting config whose snapshot dir has no migration stream fails loud when
    // the state file is existence-checked — which happens BEFORE `spawn_qemu`, so this
    // is KVM-free and proves the check-before-spawn ordering. RED inverse: checking the
    // state file after spawning (or letting migrate-incoming discover it) would need KVM
    // and lose this clean pre-spawn error.
    #[tokio::test]
    async fn restore_checks_state_file_before_spawning() {
        use vmcell::config::{RootfsSource, VmConfig};

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
        let cgroups = FakeCgroupFs::new();

        let err = qemu
            .restore(
                Path::new("/nonexistent-snapshot-dir"),
                &cfg,
                &restore_test_res(),
                &cgroups,
            )
            .await
            .expect_err("QEMU restore with a missing state file must fail before spawning");
        assert!(
            matches!(&err, Error::Vmm(msg) if msg.contains("state file") && msg.contains("missing")),
            "expected a missing-state-file Vmm error, got {err:?}"
        );
    }

    // The capability-honesty gate (mirrors CH's): QEMU snapshot_restore AND
    // restore_rotates_host_paths are both KVM-validated ON (in-kernel vhost-vsock +
    // migrate/-incoming, with a fresh rotated `res.guest_cid` per restore, §2.4), with
    // lazy_restore honestly OFF (no UFFD backend). Any deliberate re-gate must flip the
    // flag AND this test together (AGENTS.md: a capability change re-validates
    // empirically; docs/45 records the reason).
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
            caps.restore_rotates_host_paths,
            "QEMU restore rotates the host-global guest CID to a fresh res.guest_cid, so \
             concurrent zygote fan-out is supported (§2.4, validated live)"
        );
    }

    // docs/81 d7: `lazy_restore` is honest-false (no UFFD backend), so a `RestoreMode::Lazy`
    // config used to be accepted and faulted eagerly — an accepted input silently downgraded.
    // Both entry points must refuse it with the `VmmCapabilities` field name as the feature
    // string (N-VMM-1): `restore()` is the path that actually consumes `restore_mode`, and a
    // restore that accepts what create rejects is the crosvm M4 defect. Both legs are KVM-free
    // (the guard returns before any spawn — and, on the restore leg, before the state-file
    // check, which is what proves it ran). Inverse (dropping either call site) reddens that leg.
    #[tokio::test]
    async fn create_and_restore_reject_lazy_restore_with_capability_field_name() {
        use vmcell::config::{RestoreMode, RootfsSource, VmConfig};

        let qemu = Qemu::new("/usr/bin/qemu-system-x86_64");
        let cfg = VmConfig::builder(
            "/k",
            RootfsSource::Erofs {
                image: PathBuf::from("/i"),
            },
        )
        .snapshotting(true)
        .restore_mode(RestoreMode::Lazy)
        .build()
        .expect("build lazy-restore config");
        let cgroups = FakeCgroupFs::new();

        for err in [
            qemu.create(&cfg, &restore_test_res(), &cgroups)
                .await
                .expect_err("QEMU advertises lazy_restore: false"),
            qemu.restore(
                Path::new("/nonexistent-snapshot"),
                &cfg,
                &restore_test_res(),
                &cgroups,
            )
            .await
            .expect_err("restore must refuse exactly what create refuses"),
        ] {
            assert!(
                matches!(&err, Error::Unsupported { vmm, feature }
                    if vmm == "qemu" && feature == "lazy_restore"),
                "expected a lazy_restore Unsupported, got {err:?}"
            );
        }
    }

    // The positive control for the refusal above (AGENTS.md: a negative capability result needs
    // a positive control): the ALLOWED configs — every `RestoreMode` the descriptor can honor,
    // and `nested_virt: true`, which QEMU DOES advertise — must travel PAST the guard. Without
    // KVM they cannot reach a booted VM, so the control asserts on where they die: in the spawn
    // of a binary that does not exist, never as a typed capability refusal. `snapshotting(true)`
    // keeps the path daemon-free (in-kernel vsock), so nothing is spawned but QEMU itself, and
    // the scratch dir is absent so no artifact is left behind. Inverse (a guard that ignores
    // `cfg`/`caps` and refuses unconditionally) reddens this immediately.
    #[tokio::test]
    async fn create_accepts_what_the_descriptor_advertises() {
        use vmcell::config::{RestoreMode, RootfsSource, VmConfig};

        let qemu = Qemu::new("/nonexistent/vmcell-qemu-positive-control");
        let cgroups = FakeCgroupFs::new();
        for mode in [RestoreMode::Default, RestoreMode::Eager] {
            let cfg = VmConfig::builder(
                "/k",
                RootfsSource::Erofs {
                    image: PathBuf::from("/i"),
                },
            )
            .snapshotting(true)
            .nested_virt(true)
            .restore_mode(mode)
            .build()
            .expect("build an advertised config");
            let res = PerVmResources {
                tmp_dir: PathBuf::from("/tmp/vmcell-qemu-absent-positive-control"),
                ..restore_test_res()
            };
            let err = qemu
                .create(&cfg, &res, &cgroups)
                .await
                .expect_err("the absent binary ends the spawn");
            assert!(
                !matches!(&err, Error::Unsupported { feature, .. }
                    if feature == "nested_virt" || feature == "lazy_restore"),
                "an advertised config must reach the spawn, not a capability refusal: {err:?}"
            );
        }
    }

    // The refusals must key off the ONE descriptor value, not a hardcoded bool beside the check
    // — otherwise a flag flip leaves the refusal behind (the divergence class the shared
    // `reject_usb_host_devices` exists to prevent). Feeding synthetic descriptors proves each
    // branch reads `caps`: inverse (`if matches!(cfg.restore_mode, Lazy) {` with no
    // `&& !caps.lazy_restore`) reddens the `advertised` leg, and a `nested_virt` branch that
    // ignored `caps` would reject a config QEMU accepts today.
    #[test]
    fn capability_refusals_read_the_descriptor_not_a_hardcoded_bool() {
        use vmcell::config::{RestoreMode, RootfsSource, VmConfig};

        let cfg = |nested: bool, mode: RestoreMode| {
            VmConfig::builder(
                "/k",
                RootfsSource::Erofs {
                    image: PathBuf::from("/i"),
                },
            )
            .nested_virt(nested)
            .restore_mode(mode)
            .build()
            .expect("build config")
        };
        let shipped = Qemu::new("/usr/bin/qemu-system-x86_64").capabilities();
        assert!(shipped.nested_virt && !shipped.lazy_restore);

        // The shipped descriptor: nested virt is advertised, so it is ACCEPTED (the positive
        // control for the dormant branch); lazy restore is not, so it is refused by field name.
        reject_unadvertised_capabilities(&shipped, &cfg(true, RestoreMode::Default))
            .expect("QEMU advertises nested_virt, so a nested config must be accepted");
        let err = reject_unadvertised_capabilities(&shipped, &cfg(false, RestoreMode::Lazy))
            .expect_err("QEMU does not advertise lazy_restore");
        assert!(
            matches!(&err, Error::Unsupported { vmm, feature }
                if vmm == "qemu" && feature == "lazy_restore"),
            "expected a lazy_restore Unsupported, got {err:?}"
        );

        // A descriptor that advertised lazy restore accepts the same config, at the same site.
        let with_lazy = VmmCapabilities {
            lazy_restore: true,
            ..shipped.clone()
        };
        reject_unadvertised_capabilities(&with_lazy, &cfg(false, RestoreMode::Lazy))
            .expect("a descriptor advertising lazy_restore must accept a Lazy config");
        // …and one that re-gated nested virt refuses it, with no second site to update.
        let without_nested = VmmCapabilities {
            nested_virt: false,
            ..shipped
        };
        let err =
            reject_unadvertised_capabilities(&without_nested, &cfg(true, RestoreMode::Default))
                .expect_err("a re-gated nested_virt must refuse a nested config");
        assert!(
            matches!(&err, Error::Unsupported { vmm, feature }
                if vmm == "qemu" && feature == "nested_virt"),
            "expected a nested_virt Unsupported, got {err:?}"
        );
    }

    // The one transport-selection law (§2.4): `uses_in_kernel_vsock` reads
    // `vsock_transport`, decoupled from `snapshotting` (Task B). `Auto` follows
    // `snapshotting`; `InKernel`/`ExternalDaemon` force their transport regardless. RED
    // on the inverse (the old `cfg.snapshotting`-only predicate would return `false` for
    // a non-snapshot `InKernel` VM, silently sending it down the external daemon).
    #[test]
    fn uses_in_kernel_vsock_reads_transport() {
        use vmcell::config::{RootfsSource, VmConfig, VsockTransport};

        let cfg = |transport: VsockTransport, snapshotting: bool| {
            VmConfig::builder(
                "/k",
                RootfsSource::Erofs {
                    image: PathBuf::from("/i"),
                },
            )
            .snapshotting(snapshotting)
            .vsock_transport(transport)
            .build()
            .expect("build config")
        };

        // Auto tracks snapshotting (the historical default).
        assert!(!uses_in_kernel_vsock(&cfg(VsockTransport::Auto, false)));
        assert!(uses_in_kernel_vsock(&cfg(VsockTransport::Auto, true)));
        // InKernel forces in-kernel even for a NON-snapshot VM (the Task B lever).
        assert!(uses_in_kernel_vsock(&cfg(VsockTransport::InKernel, false)));
        assert!(uses_in_kernel_vsock(&cfg(VsockTransport::InKernel, true)));
        // ExternalDaemon forces the daemon on a non-snapshot VM (snapshotting +
        // ExternalDaemon is rejected at build(), so it cannot be constructed).
        assert!(!uses_in_kernel_vsock(&cfg(
            VsockTransport::ExternalDaemon,
            false
        )));
    }

    // M1, and the KVM-free half of its gate (the live half is the `Service{5100}` QEMU leg in
    // `vmcell/tests/service_steward.rs`): the endpoint this backend bakes at spawn carries the
    // DECLARED steward port. `verify_control_plane` probes that endpoint verbatim — it is the only
    // backend that probes at all — so a hardcoded default dialed 5000 at a guest listening on 5100,
    // and the health gate re-spawned a healthy cell to exhaustion and refused it.
    //
    // RED on the inverse: put `vmcell::vmm::STEWARD_VSOCK_PORT` back in either arm of
    // `steward_endpoint` and the `Service { port: 5100 }` assertions fail on both transports.
    #[test]
    fn the_spawned_endpoint_carries_the_declared_steward_port() {
        use vmcell::config::StewardPlacement;

        let vsock_path = PathBuf::from("/tmp/vmcell-m1/vsock.sock");
        let params = |in_kernel_vsock| SpawnParams {
            in_kernel_vsock,
            guest_cid: 42,
            incoming: false,
        };
        let port_of = |e: &VsockEndpoint| match e {
            VsockEndpoint::Unix { port, .. } | VsockEndpoint::Vsock { port, .. } => *port,
        };

        // A NON-default declared port, on BOTH transports: the external daemon is where the probe
        // actually runs, and the in-kernel arm is where a restored cell's endpoint comes from.
        for in_kernel in [false, true] {
            let endpoint = steward_endpoint(
                &params(in_kernel),
                &vsock_path,
                StewardPlacement::Service { port: 5100 },
            );
            assert_eq!(
                port_of(&endpoint),
                5100,
                "the probe dials THIS endpoint, so it must carry the declared port \
                 (in_kernel_vsock={in_kernel})"
            );
        }

        // The default placement is byte-identical to every release before v33 — the pay-for-what-
        // you-use floor — so a `Pid1` cell's endpoint must be unchanged.
        assert_eq!(
            port_of(&steward_endpoint(
                &params(false),
                &vsock_path,
                StewardPlacement::Pid1
            )),
            vmcell::vmm::STEWARD_VSOCK_PORT,
        );
        // …and the transport half still follows `in_kernel_vsock`, which the port change must not
        // have disturbed.
        assert!(matches!(
            steward_endpoint(&params(true), &vsock_path, StewardPlacement::Pid1),
            VsockEndpoint::Vsock { cid: 42, .. }
        ));
        assert!(matches!(
            steward_endpoint(&params(false), &vsock_path, StewardPlacement::Pid1),
            VsockEndpoint::Unix { ref path, .. } if path == &vsock_path
        ));
        // `None` never reaches the health gate, so its port is an unused placeholder — pinned so a
        // future reader does not mistake it for a dialable answer.
        assert_eq!(
            port_of(&steward_endpoint(
                &params(false),
                &vsock_path,
                StewardPlacement::None
            )),
            vmcell::vmm::STEWARD_VSOCK_PORT,
        );
    }

    // The authoritative snapshot-eligibility guard (S1). Task B decoupled the in-kernel
    // Vsock transport from `snapshotting`, so a `Vsock` endpoint alone no longer proves
    // eligibility — a non-snapshot `InKernel` VM can carry a virtio-fs share. The guard
    // must reject BOTH a non-Vsock endpoint (external daemon) AND a Vsock endpoint whose
    // VM carries a vhost-user device. RED on the inverse (the old endpoint-only guard):
    // `(Vsock, has_vhost_user_device=true)` would be wrongly accepted.
    #[test]
    fn snapshot_eligibility_rejects_vhost_user_even_on_vsock() {
        let vsock = VsockEndpoint::Vsock { cid: 3, port: 5000 };
        let unix = VsockEndpoint::Unix {
            path: PathBuf::from("/tmp/v.sock"),
            port: 5000,
        };
        // The only eligible combination: a capable backend, in-kernel Vsock transport, no
        // vhost-user device. This success is now load-bearing for BOTH refusals below — F6 gave
        // every leg the same feature string, so "refused" is only evidence against a control the
        // guard accepts; the `Removal` identity supplies the rest.
        assert!(qemu_snapshot_eligibility(true, &vsock, false).is_ok());
        // Vsock endpoint but the VM carries a vhost-user device (the Task B hole): reject.
        let err = qemu_snapshot_eligibility(true, &vsock, true)
            .expect_err("a vhost-user device must block a snapshot even on the Vsock transport");
        assert_is_removal(&err, &VHOST_USER_BLOCKS_SNAPSHOT);
        // External daemon (Unix endpoint) is a non-migratable vhost-user transport: reject — with
        // the OTHER shared const, which is exactly what keeps this leg distinct from the one above
        // now that both spell `snapshot_restore`.
        let err = qemu_snapshot_eligibility(true, &unix, false)
            .expect_err("the external vsock daemon must block a snapshot");
        assert_is_removal(&err, &IN_KERNEL_VSOCK_REQUIRED_FOR_SNAPSHOT);
        assert!(qemu_snapshot_eligibility(true, &unix, true).is_err());
    }

    // §6 (`qemu-crosvm-snapshot-restore-missing-capability-selfguard`): QEMU's
    // snapshot/restore boundary must self-check its OWN `snapshot_restore` descriptor —
    // the check CH and FC carry (M-RESTORE-3 / rubric B3) and QEMU lacked entirely, so a
    // deliberate re-gate of the flag would have left `snapshot()`/`restore()` happily
    // driving `migrate` on a backend advertising it cannot. The false branch is the one
    // the shipped descriptor (`snapshot_restore: true`) can never reach at runtime, so it
    // is pinned here directly. RED on the inverse: a `require_snapshot_restore_capable`
    // that ignores its argument, or a `qemu_snapshot_eligibility` that skips it, fails
    // the first two assertions.
    #[test]
    fn snapshot_precheck_self_guards_the_capability() {
        let vsock = VsockEndpoint::Vsock { cid: 3, port: 5000 };

        let err = require_snapshot_restore_capable(false)
            .expect_err("an incapable backend must refuse fail-loud");
        assert!(
            // §7.2 rule: the typed-refusal feature string equals the descriptor field name.
            matches!(&err, Error::Unsupported { vmm, feature }
                if vmm == "qemu" && feature == "snapshot_restore"),
            "expected a snapshot_restore Unsupported, got {err:?}"
        );

        // …and the instance-side guard runs it FIRST: an otherwise perfectly eligible VM
        // (in-kernel Vsock, no vhost-user device) is still refused on the descriptor.
        let err = qemu_snapshot_eligibility(false, &vsock, false)
            .expect_err("an incapable backend must refuse even an eligible VM");
        assert!(
            matches!(&err, Error::Unsupported { feature, .. } if feature == "snapshot_restore"),
            "expected a snapshot_restore Unsupported, got {err:?}"
        );

        // Positive control: the same VM on a capable backend is allowed, so the refusal
        // above is the capability check and not the eligibility law.
        assert!(require_snapshot_restore_capable(true).is_ok());
        assert!(qemu_snapshot_eligibility(true, &vsock, false).is_ok());
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

    /// A fake QMP server on `socket` that goes **silent** — the wedged-QEMU shape (stuck
    /// main loop, stalled snapshot filesystem): it never closes the connection (an EOF is
    /// a different, already-typed error) and simply stops answering. With `greet` it
    /// first completes the greeting + `qmp_capabilities` handshake and reads the
    /// `migrate` command, then answers nothing; without it, it is silent from the first
    /// byte, so the handshake read is the one that would block.
    fn spawn_silent_qmp_server(socket: &Path, greet: bool) -> tokio::task::JoinHandle<()> {
        let listener = tokio::net::UnixListener::bind(socket).expect("bind the fake QMP socket");
        tokio::spawn(async move {
            let mut stream = listener.accept().await.expect("fake QMP accept").0;
            if greet {
                let (r, mut w) = stream.split();
                let mut reader = BufReader::new(r);
                w.write_all(b"{\"QMP\": {\"version\": {}}}\n")
                    .await
                    .expect("greeting");
                let mut line = String::new();
                reader.read_line(&mut line).await.expect("qmp_capabilities");
                w.write_all(b"{\"return\": {}}\n")
                    .await
                    .expect("capabilities reply");
                line.clear();
                reader
                    .read_line(&mut line)
                    .await
                    .expect("the migrate command");
            }
            std::future::pending::<()>().await;
        })
    }

    /// A [`QemuInstance`] whose only real wiring is `qmp_socket` and `mem_mib`, so the
    /// QMP-driving methods can run against a fake server with no VMM. The process is a
    /// live child in its own group, so `Drop`'s reap stays honest rather than being
    /// skipped.
    fn instance_on_socket_with_mem(qmp_socket: &Path, mem_mib: u32) -> QemuInstance {
        let (process, _pid) = spawn_group_standin();
        let pgid = process.id();
        QemuInstance {
            process,
            qmp_socket: qmp_socket.to_path_buf(),
            vsock_path: qmp_socket.with_file_name("vsock.sock"),
            serial_path: qmp_socket.with_file_name("serial.log"),
            _fs_daemons: Vec::new(),
            _vsock_daemon: None,
            cid: 3,
            endpoint: VsockEndpoint::Vsock { cid: 3, port: 5000 },
            has_vhost_user_device: false,
            usb_claim: vmcell::vmm::usb::UsbHostClaim::default(),
            snapshot_restore_capable: true,
            group: vmcell::vmm::VmmProcessGroup::new(pgid),
            vsock_pgid: None,
            mem_mib,
        }
    }

    /// [`instance_on_socket_with_mem`] on the 128 MiB default the QMP gates use.
    fn instance_on_socket(qmp_socket: &Path) -> QemuInstance {
        instance_on_socket_with_mem(qmp_socket, 128)
    }

    // M7 GATE (KVM-free): `MIGRATION_BUDGET` must bound the WHOLE QMP session. It used to
    // be checked only between poll iterations, so the connect, the handshake reads, every
    // `write_all` and every `read_qmp_result` were unbounded — a QEMU that stops answering
    // QMP hung `snapshot()`/`restore()` forever, the exact wedge the const's own doc
    // claims it converts into a typed error. Both blocking points are driven: silent
    // after `migrate` (the poll-loop read) and silent from the first byte (the handshake
    // read, which the old between-iterations check could never reach). RED on the inverse
    // (delete the `timeout_at` wrapper): the call never returns and the wall-clock guard
    // below — 10× the budget — fires with a naming panic instead of hanging the suite.
    #[tokio::test]
    async fn drive_migration_bounds_a_wedged_qmp_session() {
        const BUDGET: std::time::Duration = std::time::Duration::from_millis(300);
        const GUARD: std::time::Duration = std::time::Duration::from_secs(3);

        let dir = tempfile::tempdir().expect("tempdir");
        for (leg, greet) in [("silent after migrate", true), ("silent handshake", false)] {
            let socket = dir.path().join(format!("qmp-{}.sock", u8::from(greet)));
            let server = spawn_silent_qmp_server(&socket, greet);
            let instance = instance_on_socket(&socket);

            let result = tokio::time::timeout(
                GUARD,
                instance.drive_migration_within(
                    "{\"execute\": \"migrate\", \"arguments\": {\"uri\": \"file:/dev/null\"}}",
                    BUDGET,
                ),
            )
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "M7: drive_migration hung past its {BUDGET:?} budget against a QEMU \
                     {leg} — the budget does not bound the QMP I/O"
                )
            });

            let err = result.expect_err("a wedged QMP session must surface a typed error");
            assert!(
                matches!(&err, Error::Vmm(msg) if msg.contains("within the budget")),
                "expected the migration-budget Vmm error ({leg}), got {err:?}"
            );
            server.abort();
        }
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

    // M6 GATE (KVM-free): the snapshot/restore migration is budgeted against GUEST RAM,
    // not a flat ceiling. QEMU keeps `MIGRATION_BUDGET` as a measured floor and takes the
    // larger of it and the ONE shared `vmcell::vmm::snapshot_request_timeout` — so a
    // multi-GiB guest gets strictly more budget than a small one, while an ordinary
    // control op keeps its short bound.
    //
    // Inverse (observed red): revert `snapshot_budget()` to a bare `MIGRATION_BUDGET` and
    // the 32 GiB leg equals the 128 MiB leg, reddening the strict inequality. Inverse 2:
    // route `qmp_command`'s 2 s control ceiling through `snapshot_budget()` too and the
    // "ordinary control ops stay short" assert reddens.
    // `#[tokio::test]`: the fixture spawns a real stand-in child, which needs a reactor.
    #[tokio::test]
    async fn snapshot_budget_grows_with_guest_ram_over_the_migration_floor() {
        let dir = tempfile::tempdir().expect("tempdir");
        let socket = dir.path().join("qmp-budget.sock");

        let small = instance_on_socket_with_mem(&socket, 128);
        let large = instance_on_socket_with_mem(&socket, 32 * 1024);

        assert!(
            large.snapshot_budget() > small.snapshot_budget(),
            "a 32 GiB guest must get MORE snapshot budget than a 128 MiB one: {:?} vs {:?}",
            large.snapshot_budget(),
            small.snapshot_budget()
        );
        // The guest-RAM term is the SHARED predicate's, not a local re-derivation.
        assert_eq!(
            large.snapshot_budget(),
            vmcell::vmm::snapshot_request_timeout(32 * 1024),
            "above the floor the budget IS the shared predicate"
        );
        // …and QEMU's measured floor still holds underneath it.
        assert_eq!(
            small.snapshot_budget(),
            MIGRATION_BUDGET,
            "below the floor the budget is QEMU's measured MIGRATION_BUDGET"
        );
        // An ordinary control op is NOT on this budget: `qmp_command` bounds
        // stop/cont/system_powerdown/quit at a flat 2 s so a wedged powerdown cannot
        // block the force-kill behind it. If that ever collapsed into `snapshot_budget()`,
        // the flat ceiling would be at least the 120 s floor.
        assert!(
            std::time::Duration::from_secs(2) < small.snapshot_budget(),
            "the control ceiling and the snapshot budget must not be the same value"
        );
    }

    // POSITIVE CONTROL for the gate above, and the gate on `Drop`'s OWN job: an instance whose
    // group has NOT been reaped must have its process group SIGKILLed + reaped when it is dropped
    // (L1 — `Drop` is the panic path of the one teardown order). Without this leg the
    // "must not signal a recycled pgid" assertion is satisfied by a `Drop` that reaps NOTHING —
    // which is precisely the regression the QEMU consolidation introduced and this leg caught: a
    // dropped-but-never-killed VM would leak its whole process group.
    //
    // Inverse (observed red): delete `self.group.reap_now(&mut self.process)` from `Drop` and the
    // stand-in survives, so `gone` stays false.
    #[tokio::test]
    async fn drop_reaps_an_unreaped_process_group() {
        let dir = tempfile::tempdir().expect("tempdir");
        let inst = instance_on_socket(&dir.path().join("absent-qmp.sock"));
        let live_pid = inst.process.id().expect("stand-in pid") as i32;
        drop(inst);

        let mut gone = false;
        for _ in 0..100 {
            if nix::sys::signal::kill(nix::unistd::Pid::from_raw(live_pid), None).is_err() {
                gone = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        // Best-effort cleanup if the drop did NOT reap, so a red run leaves no stray process.
        let _ = nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(-live_pid),
            nix::sys::signal::Signal::SIGKILL,
        );
        assert!(
            gone,
            "Drop on an UN-reaped instance must SIGKILL and reap its VMM process group"
        );
    }

    // M-VMM-1 GATE (KVM-free) on the SHIPPED call sites, not on the extracted helper:
    // once the QEMU leader is reaped its pgid can be recycled, so neither
    // `QemuInstance::kill` NOR its `Drop` may SIGKILL `-pgid`. A live decoy in its own
    // process group stands in for the recycled group; BOTH teardown paths are driven
    // against the same already-reaped instance, because a backend that routed only one of
    // them through the shared helper is the divergence this consolidation removes. QEMU
    // had no such gate before (CH and FC did) — it is one of the copies §9 found.
    //
    // Inverse (observed red): replace `self.group.kill_and_wait(&mut self.process).await`
    // in `kill` — or `self.group.reap_now(&mut self.process)` in `Drop` — with an
    // unguarded `vmcell::vmm::reap_process_group(...)` over the same pgid, and the decoy
    // dies, reddening the assert.
    #[tokio::test]
    async fn kill_and_drop_do_not_signal_pgid_when_reaped() {
        let (mut decoy, decoy_pid) = spawn_group_standin();

        // A fast-exiting child as the instance's own leader so `kill()`'s `process.wait()`
        // returns promptly instead of blocking on a live process.
        let leader = tokio::process::Command::new("true")
            .spawn()
            .expect("spawn `true` leader");
        let dir = tempfile::tempdir().expect("tempdir");
        let mut inst = QemuInstance {
            process: leader,
            qmp_socket: dir.path().join("absent-qmp.sock"),
            vsock_path: PathBuf::new(),
            serial_path: PathBuf::new(),
            _fs_daemons: Vec::new(),
            _vsock_daemon: None,
            cid: 3,
            endpoint: VsockEndpoint::Vsock { cid: 3, port: 5000 },
            has_vhost_user_device: false,
            usb_claim: vmcell::vmm::usb::UsbHostClaim::default(),
            snapshot_restore_capable: true,
            // The recycled-pgid state, which only the `test-support` constructor can
            // fabricate: no production path can mark a group reaped over a foreign pgid.
            group: vmcell::vmm::VmmProcessGroup::already_reaped_for_test(Some(decoy_pid as u32)),
            vsock_pgid: None,
            mem_mib: 128,
        };
        // `kill()` first tries a QMP `quit` against an absent socket; that fails fast and
        // is best-effort by design, so the reap path below is what is under test.
        inst.kill().await.expect("kill");
        assert!(
            inst.group.is_reaped(),
            "the group must still read as reaped after kill() — the flag is one-shot"
        );
        drop(inst);

        // A SIGKILL to the (recycled) pgid would land within a few ms; give it time.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let decoy_status = decoy.try_wait().expect("try_wait decoy");
        // Clean up the decoy regardless of the outcome — a test's own fixtures are
        // residue too.
        let _ = nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(-decoy_pid),
            nix::sys::signal::Signal::SIGKILL,
        );
        let _ = decoy.wait().await;

        assert!(
            decoy_status.is_none(),
            "kill()/Drop on a reaped QEMU instance must not SIGKILL a (recycled) pgid"
        );
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

/// What this file's four source-scanning gates read, and the one normalizer they read it through.
///
/// Scanning source is how a law whose drift is not a compile error gets a gate here (each gate
/// module's own doc carries its rationale; [`virtiofs_pacing_gate`]'s is the fullest). Every such
/// gate needs the same two things, so they live here once: three copies of `production_code` and
/// four of the `include_str!` had accumulated, one per gate, and a scanner that exists to notice
/// drift is the last helper that should be able to drift from its siblings — a fix applied to one
/// copy (the `//!` inner-doc lines the filter drops, say) silently leaves the others reading
/// different text.
#[cfg(test)]
mod gate_source {
    /// This file's own text, `include_str!`-ed once for every gate below.
    pub(super) const SOURCE: &str = include_str!("lib.rs");

    /// This file's production text: everything before the first `#[cfg(test)]`, comment lines
    /// dropped and whitespace collapsed.
    ///
    /// Dropping comments is what lets a gate's own prose name the very spelling it forbids, and
    /// collapsing whitespace is what makes a rustfmt-wrapped call site match as one string. Both are
    /// controlled by each gate's own `the_scanner_ignores_comments…` leg.
    pub(super) fn production_code(source: &str) -> String {
        let production = source
            .split_once("#[cfg(test)]")
            .map_or(source, |(before, _)| before);
        production
            .lines()
            .map(str::trim)
            .filter(|line| !line.starts_with("//"))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

/// Source-level gate for M6's "the migration budget is the instance's, never a call site's" — the
/// backstop behind the structural fix.
///
/// [`QemuInstance::drive_migration`] takes no budget argument, so a call site that reached for the
/// flat [`MIGRATION_BUDGET`] floor is a compile error. What a compiler cannot catch is a shipped
/// call site reaching for the private `drive_migration_within` seam that the M7 gate uses — same
/// file, same crate, one extra word. This scans for exactly that, in the same shape as
/// [`virtiofs_pacing_gate`] (whose doc carries the full rationale for scanning source).
#[cfg(test)]
mod migration_budget_gate {
    use super::gate_source::{SOURCE, production_code};

    /// The number of migrations this backend drives: two — `snapshot()`'s `migrate` and
    /// `restore()`'s `migrate-incoming`.
    ///
    /// Asserted exactly, so a scan that silently matched nothing — the way every source-scanning
    /// gate fails vacuously — reddens instead of passing over an empty set.
    const EXPECTED_MIGRATIONS: usize = 2;

    /// Method-call occurrences of `name` — the leading `.` is what separates a call from the
    /// `async fn name(` definition, which would otherwise inflate every count by one.
    fn method_call_count(code: &str, name: &str) -> usize {
        code.match_indices(&format!(".{name}(")).count()
    }

    /// Every `.drive_migration_within(` call expression in `code`, truncated at its statement's
    /// `;` so the budget it passes is visible.
    fn within_calls(code: &str) -> Vec<&str> {
        code.match_indices(".drive_migration_within(")
            .map(|(at, _)| {
                let tail = &code[at..];
                &tail[..tail.find(';').unwrap_or(tail.len())]
            })
            .collect()
    }

    // M6 GATE (KVM-free): both shipped migrations ride the instance's guest-RAM-proportional
    // budget. The `drive_migration(` count is the non-vacuity anchor; the `drive_migration_within(`
    // count is the law — the private short-budget seam belongs to the M7 gate alone.
    //
    // RED on the inverse: change either shipped call to `drive_migration_within(&cmd,
    // MIGRATION_BUDGET)` and the second assertion fires (and the first drops to 1).
    #[test]
    fn every_shipped_migration_rides_the_instance_budget() {
        let code = production_code(SOURCE);
        assert_eq!(
            method_call_count(&code, "drive_migration"),
            EXPECTED_MIGRATIONS,
            "expected {EXPECTED_MIGRATIONS} shipped `drive_migration(` calls (snapshot + restore). \
             If one was legitimately added or removed, update EXPECTED_MIGRATIONS — do not delete \
             the scan."
        );
        // The private short-budget seam has exactly ONE production caller — `drive_migration`'s
        // own delegation — and it must hand in the instance's guest-RAM-proportional budget. A
        // second caller, or this one passing anything else, is a shipped migration on the wrong
        // budget.
        let within = within_calls(&code);
        assert_eq!(
            within.len(),
            1,
            "`drive_migration_within` is the M7 gate's private seam: its only production caller \
             is `drive_migration`'s own delegation. A shipped migration goes through \
             `drive_migration`, which has no budget argument to get wrong (M6). Found: {within:?}"
        );
        assert!(
            within[0].contains("self.snapshot_budget()"),
            "the one `drive_migration_within` call must pass `self.snapshot_budget()`, never the \
             flat MIGRATION_BUDGET floor: `{}`",
            within[0]
        );
    }

    /// The scanner's own controls: prose in a comment is not a call, and a rustfmt-wrapped call is
    /// still seen whole — so the gate above is not a test that can only ever pass (AGENTS rule 2).
    #[test]
    fn the_migration_scanner_ignores_comments_and_survives_line_breaks() {
        let synthetic = "// self.drive_migration(&cmd) in a comment is not a call site\n\
             let r = self.drive_migration(\n    &migrate_cmd).await;\n\
             async fn drive_migration_within(&self, c: &str, b: Duration) {}\n\
             #[cfg(test)]\nmod tests { self.drive_migration_within(&c, BUDGET); }";
        let code = production_code(synthetic);
        // The wrapped call is seen whole; the comment and the `#[cfg(test)]` seam call are not.
        assert_eq!(method_call_count(&code, "drive_migration"), 1, "{code}");
        // The `_within` DEFINITION is present but is not a call, so no call is collected.
        assert!(within_calls(&code).is_empty(), "{code}");
        // …and a production `_within` CALL is seen, with the budget it passes visible — the
        // regression shape the law forbids.
        let regressed =
            production_code("let r = self.drive_migration_within(&c, MIGRATION_BUDGET);");
        let calls = within_calls(&regressed);
        assert_eq!(calls.len(), 1, "{calls:?}");
        assert!(!calls[0].contains("self.snapshot_budget()"), "{calls:?}");
    }
}

/// Source-level gate for §9.4's "`api_socket_poll` paces **every** daemon readiness wait" on the
/// shipped QEMU path — the sibling of `vmcell`'s `cloud_hypervisor::virtiofs_pacing_gate`, whose
/// module doc carries the full rationale for scanning source instead of behavior.
///
/// Deliberately a second copy rather than a shared helper: the scan must read *this crate's* own
/// source, and `include_str!`-ing a sibling crate's file would compile only from a workspace
/// checkout (it breaks a packaged build) while a runtime-shared predicate would have to become
/// public API of a contract crate to cross the crate boundary. The law itself is not duplicated —
/// it is `VirtioFsDaemon::start_paced`'s signature, which is single-sourced in `vmcell::fs`; these
/// are two readers of it.
#[cfg(test)]
mod virtiofs_pacing_gate {
    use super::gate_source::{SOURCE, production_code};

    /// The number of virtio-fs daemon starts this backend ships: one, in `create`.
    ///
    /// Asserted exactly, so a scan that silently matched nothing — the way every source-scanning
    /// gate fails vacuously — reddens instead of passing over an empty set.
    const EXPECTED_CALL_SITES: usize = 1;

    /// Every `VirtioFsDaemon::…` call expression in `code`, each truncated at its statement's `;`.
    fn virtiofs_start_calls(code: &str) -> Vec<&str> {
        code.match_indices("VirtioFsDaemon::")
            .map(|(at, _)| {
                let tail = &code[at..];
                &tail[..tail.find(';').unwrap_or(tail.len())]
            })
            .collect()
    }

    /// The law: a shipped virtio-fs start names the paced entry point **and** hands it the VM's
    /// own profile — the same profile this backend's `vhost-device-vsock` wait already uses.
    fn call_is_paced_by_the_vm_config(call: &str) -> bool {
        call.starts_with("VirtioFsDaemon::start_paced(") && call.contains("&cfg.timeouts")
    }

    #[test]
    fn every_virtiofs_start_here_is_paced_by_the_vm_config() {
        let code = production_code(SOURCE);
        let calls = virtiofs_start_calls(&code);
        assert_eq!(
            calls.len(),
            EXPECTED_CALL_SITES,
            "expected {EXPECTED_CALL_SITES} virtio-fs daemon start in `create`; found {}: \
             {calls:?}. If a site was legitimately added or removed, update EXPECTED_CALL_SITES — \
             do not delete the scan.",
            calls.len()
        );
        for call in &calls {
            assert!(
                call_is_paced_by_the_vm_config(call),
                "§9.4: this virtio-fs readiness wait is not paced by the VM's own profile — \
                 `{call}` must be `VirtioFsDaemon::start_paced(share, …, &cfg.timeouts)`"
            );
        }
    }

    /// The gate's own red-on-inverse: the predicate must reject both regression shapes, so the
    /// scan above is not a test that can only ever pass (AGENTS.md rule 2).
    #[test]
    fn the_pacing_predicate_rejects_both_regression_shapes() {
        assert!(!call_is_paced_by_the_vm_config(
            "VirtioFsDaemon::start(share, &res.tmp_dir).await?"
        ));
        assert!(!call_is_paced_by_the_vm_config(
            "VirtioFsDaemon::start_paced(share, &res.tmp_dir, &Timeouts::default()).await?"
        ));
        assert!(call_is_paced_by_the_vm_config(
            "VirtioFsDaemon::start_paced(share, &res.tmp_dir, &cfg.timeouts).await?"
        ));
    }

    /// The scanner's own controls: a prose mention of the entry point is not a call site, and a
    /// call split across two rustfmt lines is still seen whole.
    #[test]
    fn the_scanner_ignores_comments_and_survives_line_breaks() {
        let synthetic = "// a failed VirtioFsDaemon::start reaps the VMM\n\
             let daemon =\n    VirtioFsDaemon::start_paced(share, &res.tmp_dir,\n    \
             &cfg.timeouts).await?;\n#[cfg(test)]\nmod tests { VirtioFsDaemon::start(x); }";
        let code = production_code(synthetic);
        let calls = virtiofs_start_calls(&code);
        assert_eq!(calls.len(), 1, "got {calls:?}");
        assert!(call_is_paced_by_the_vm_config(calls[0]), "got {calls:?}");
    }
}

/// Source-level gate for M11's structural half on this backend: the launch is composed in
/// **one** place, and no second `JailSpec` compilation can reappear beside it.
///
/// [`the_qemu_launch_plan_ships_the_configured_jail_posture`](tests::the_qemu_launch_plan_ships_the_configured_jail_posture)
/// asserts the posture the plan *returns*; [`vmcell::vmm::LaunchPlan`]'s private field makes
/// overwriting that record a compile error. Neither can see the one remaining regression:
/// moving `jail_spec_from_config` + `build_vmm_cmd` back out of the plan into `qemu_launch_plan`
/// or `spawn_qemu`, which re-opens the window between deciding the posture and applying it and
/// leaves the plan's record describing a command nobody spawns. That is a property of this
/// file's *text*, so it is scanned — the same shape as the sibling [`virtiofs_pacing_gate`],
/// through the one [`gate_source`] normalizer every gate here shares.
///
/// It catches: a raw `jail_spec_from_config` call in this backend, a second launch-plan
/// construction, and a deleted one. It cannot catch: the wrong `JailConfig` handed to the plan —
/// that is behavioral, and the KVM-free plan gate asserts it directly.
#[cfg(test)]
mod jail_composition_gate {
    use super::gate_source::{SOURCE, production_code};

    /// The number of launch-plan constructions this backend ships: one, in
    /// [`super::qemu_launch_plan`].
    ///
    /// Asserted exactly, so a scan that silently matched nothing — the way every source-scanning
    /// gate fails vacuously — reddens instead of passing over an empty set, and a second
    /// (possibly divergent) construction reddens too.
    const EXPECTED_PLAN_BUILD_SITES: usize = 1;

    /// Every call expression naming `needle` in `code`, truncated at its statement's `;`.
    fn calls<'a>(code: &'a str, needle: &str) -> Vec<&'a str> {
        code.match_indices(needle)
            .map(|(at, _)| {
                let tail = &code[at..];
                &tail[..tail.find(';').unwrap_or(tail.len())]
            })
            .collect()
    }

    #[test]
    fn the_launch_is_composed_only_in_the_plan() {
        let code = production_code(SOURCE);

        let raw = calls(&code, "jail_spec_from_config(");
        assert!(
            raw.is_empty(),
            "M11: this backend must compile no `JailSpec` of its own — the one compilation lives \
             in `vmcell::vmm::LaunchPlan::build`, which records the very value it compiles. \
             Found {raw:?}"
        );
        let raw_cmd = calls(&code, "build_vmm_cmd(");
        assert!(
            raw_cmd.is_empty(),
            "M11: this backend must not build a VMM command outside the launch plan. Found \
             {raw_cmd:?}"
        );

        // The anti-vacuity half: the two assertions above are satisfied by a file with no launch
        // at all, so the launch must be here, exactly once.
        let builds = calls(&code, "LaunchPlan::build(");
        assert_eq!(
            builds.len(),
            EXPECTED_PLAN_BUILD_SITES,
            "expected {EXPECTED_PLAN_BUILD_SITES} `LaunchPlan::build` call; found {}: {builds:?}. \
             If a site was legitimately added or removed, update EXPECTED_PLAN_BUILD_SITES — do \
             not delete the scan.",
            builds.len()
        );
    }

    /// The scanner's own controls: a prose mention is not a call site, a call split across two
    /// rustfmt lines is still seen whole, and the regression shape is genuinely detected — so the
    /// scan above is not a test that can only ever pass (AGENTS.md rule 2).
    #[test]
    fn the_scanner_sees_the_regression_and_ignores_comments() {
        let regressed = "// the plan calls jail_spec_from_config for us\n\
             let jail =\n    vmcell::vmm::jail::jail_spec_from_config(\n    &cfg.jail)?;\n\
             #[cfg(test)]\nmod tests { LaunchPlan::build(x); }";
        let code = production_code(regressed);
        assert_eq!(calls(&code, "jail_spec_from_config(").len(), 1);
        assert!(calls(&code, "LaunchPlan::build(").is_empty());

        let composed = "// jail_spec_from_config in prose is not a call\n\
             let mut plan =\n    vmcell::vmm::LaunchPlan::build(b, n,\n    cfg.jail)?;";
        let code = production_code(composed);
        assert!(calls(&code, "jail_spec_from_config(").is_empty());
        assert_eq!(calls(&code, "LaunchPlan::build(").len(), 1);
    }
}

/// Source-level gate for M1's "the host dials the DECLARED steward port": the endpoint composition
/// lives in exactly one place, and the protocol default is spelled only as the placement-`None`
/// placeholder inside it.
///
/// The composer has its own unit test (`the_spawned_endpoint_carries_the_declared_steward_port`), and
/// that test cannot see the defect this gate is about: a second, inlined `VsockEndpoint` carrying
/// `STEWARD_VSOCK_PORT` — which is exactly the shape the defect shipped as, two of them, in
/// `finish_qemu_spawn`. Nor can a KVM-free behavioral test see it: reaching
/// `verify_control_plane`'s dial needs a booted guest, which is why the live half of this gate is
/// the `Service{5100}` QEMU leg in `vmcell/tests/service_steward.rs`.
///
/// Same shape and same honest limit as [`migration_budget_gate`]: a scan sees spellings, not values.
#[cfg(test)]
mod steward_port_gate {
    use super::gate_source::{SOURCE, production_code};

    /// Production mentions of the protocol default: one, the placement-`None` placeholder in
    /// `steward_endpoint`. Asserted exactly, so the scan cannot pass over an empty set.
    const EXPECTED_DEFAULT_PORT_MENTIONS: usize = 1;

    // M1 GATE (KVM-free): the composer is the one place that decides the dialed port, and the one
    // place allowed to name the protocol default.
    //
    // RED on the inverse: re-inline either `VsockEndpoint` arm with
    // `port: vmcell::vmm::STEWARD_VSOCK_PORT` in `finish_qemu_spawn` and the mention count goes to
    // 2 or 3; drop the composer and the `steward_port()` assertion fires.
    #[test]
    fn the_dialed_port_is_composed_once_from_the_declared_placement() {
        let code = production_code(SOURCE);
        let mentions = code.matches("STEWARD_VSOCK_PORT").count();
        assert_eq!(
            mentions, EXPECTED_DEFAULT_PORT_MENTIONS,
            "the protocol default may be spelled only as `steward_endpoint`'s placement-`None` \
             placeholder; every other mention is a dial site hardcoding a port the caller may have \
             re-declared (M1). Found {mentions}."
        );
        assert!(
            code.contains("placement .steward_port()") || code.contains("placement.steward_port()"),
            "the composed port must come from `StewardPlacement::steward_port()` — C8's first \
             question — not from a constant"
        );
        // Non-vacuity: the composer is actually the spawn path's endpoint, not dead code.
        assert!(
            code.contains("steward_endpoint(params,"),
            "`finish_qemu_spawn` must compose its endpoint through `steward_endpoint`"
        );
    }

    /// The scanner's own controls: prose is not code, and the regression shape is genuinely
    /// detected — so the gate above is not a test that can only ever pass (AGENTS.md rule 2).
    #[test]
    fn the_scanner_ignores_comments_and_sees_a_re_inlined_port() {
        let clean = "// port: vmcell::vmm::STEWARD_VSOCK_PORT in a comment is not a dial site\n\
             let port = placement.steward_port().unwrap_or(vmcell::vmm::STEWARD_VSOCK_PORT);\n\
             #[cfg(test)]\nmod tests { STEWARD_VSOCK_PORT }";
        assert_eq!(
            production_code(clean).matches("STEWARD_VSOCK_PORT").count(),
            EXPECTED_DEFAULT_PORT_MENTIONS,
        );
        let regressed = "let port = placement.steward_port().unwrap_or(vmcell::vmm::STEWARD_VSOCK_PORT); \
             let e = VsockEndpoint::Unix { path: p, port: vmcell::vmm::STEWARD_VSOCK_PORT };";
        assert!(
            production_code(regressed)
                .matches("STEWARD_VSOCK_PORT")
                .count()
                > EXPECTED_DEFAULT_PORT_MENTIONS,
            "a re-inlined default port must be visible to the scan"
        );
    }
}
