//! crosvm VMM backend for `vmcell`.
//!
//! Provides the [`Crosvm`] implementation of the [`vmcell::vmm::Vmm`] trait and its running-instance
//! type [`CrosvmInstance`]. crosvm is the ChromeOS Rust VMM; like Firecracker and QEMU it is a
//! secondary backend living outside the `vmcell` core (which carries only the primary Cloud
//! Hypervisor). This crate depends on `vmcell` for the shared `Vmm`/`VmInstance` traits, the
//! jail/seccomp predicates (crosvm routes its sandbox posture through `vmm_seccomp_args`), and the
//! spawn/reap/console/snapshot-eligibility helpers — every "one law, one predicate" invariant stays
//! single-sourced in `vmcell`.
//!
//! **Structure.** crosvm is driven like QEMU (a device model built on the launch command line),
//! not like Firecracker (a post-spawn REST sequence). Two differences from QEMU: (1) its control
//! plane is a side socket driven **out-of-band by re-invoking the crosvm binary as a client**
//! (`crosvm resume|suspend|powerbtn|stop <socket>`) — the socket protocol is unstable binary and is
//! never hand-rolled, so this crate needs no serde/JSON; (2) its vsock is the in-kernel vhost-vsock
//! device exposed on the host AF_VSOCK namespace (like a snapshot-eligible QEMU), so
//! [`CrosvmInstance::vsock_endpoint`] returns [`VsockEndpoint::Vsock`] and there is no external vsock
//! daemon to own.
//!
//! **Scope (validated live on a KVM host).** Boot, tap networking, block devices, in-kernel vsock,
//! sessions, and **snapshot/restore** are the shipped, matrix-validated data path. snapshot/restore
//! follows the **Firecracker** pattern, not QEMU's: crosvm bakes the vsock CID into the snapshot and
//! rejects a rotated `--vsock cid=` on restore, so `restore()` reuses the baked CID (carried in a
//! sidecar) and `restore_rotates_host_paths` is **false** — sequential lineage works, concurrent
//! fan-out from one snapshot does not. virtio-fs shares and unprivileged vhost-user-net stay
//! honest-**false** (unvalidated); each self-skips its matrix leg via `require_cap!`. See
//! `docs/implementation-notes.md` (crosvm reconciliation) for the remaining open items.

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
use vmcell::config::{ConsoleMode, VmConfig};
use vmcell::error::{Error, Result};
use vmcell::vmm::{PerVmResources, VmInstance, Vmm, VmmCapabilities, VsockEndpoint};

use tokio::process::Child;

/// The crosvm VMM backend.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Crosvm {
    /// Path to the `crosvm` executable (used both to launch the VM and, re-invoked as a client,
    /// to drive the control socket).
    pub binary_path: PathBuf,
}

impl Crosvm {
    /// Creates a new `Crosvm` using the specified executable path.
    #[must_use]
    pub fn new(binary_path: impl Into<PathBuf>) -> Self {
        Self {
            binary_path: binary_path.into(),
        }
    }
}

/// A running instance of a crosvm VM.
#[derive(Debug)]
#[non_exhaustive]
pub struct CrosvmInstance {
    process: Child,
    /// The `crosvm` binary, re-invoked as a client for every control operation.
    binary_path: PathBuf,
    control_socket: PathBuf,
    /// Vestigial AF_UNIX path returned by [`VmInstance::vsock_path`] for API parity; crosvm's vsock
    /// is in-kernel AF_VSOCK, so [`CrosvmInstance::vsock_endpoint`] is what the host actually dials.
    vsock_path: PathBuf,
    serial_path: PathBuf,
    cid: u32,
    pgid: Option<u32>,
    // True once the VMM leader has been reaped (via `has_exited`/`kill`). After the leader is reaped
    // the kernel can recycle its pgid, so `kill`/`Drop` must NOT re-`SIGKILL` the process group or
    // they could hit an unrelated group (M-VMM-1).
    reaped: bool,
    // `true` on an instance returned by `restore()`: the VM was launched `--suspended --restore`, so
    // the FIRST `resume()` must be `--full` (wake devices + vCPUs) to complete the restore. Consumed
    // (set false) only after that resume succeeds, so a transient failure stays retryable.
    restored: bool,
    // `config_has_vhost_user_device(cfg, res)` recorded at spawn — the S1 snapshot-eligibility guard
    // `snapshot()` reads. Always false for a crosvm VM (create() rejects shares/unpriv-net), but kept
    // as defense-in-depth so a future config path can't slip an ineligible VM past `snapshot()`.
    has_vhost_user_device: bool,
    // Whether the backend advertises snapshot/restore, captured from `capabilities()` at spawn so
    // `snapshot()` can self-guard without a handle to the backend (M-RESTORE-3, the CH shape).
    snapshot_restore_capable: bool,
}

/// Pre-flight self-checks for the [`CrosvmInstance::snapshot`] path.
///
/// `snapshot()` runs on the instance, which has no handle to the backend, so the `snapshot_restore`
/// capability is captured at spawn and re-checked here (M-RESTORE-3) alongside the
/// snapshot-eligibility law: a VM carrying a vhost-user device cannot be snapshotted. Factored as a
/// free function — the same shape Cloud Hypervisor ships (`snapshot_precheck`), not a second idiom —
/// so a KVM-free test can drive the false branch a live matrix can never reach (crosvm's descriptor
/// is `snapshot_restore: true`).
///
/// # Errors
/// Returns [`Error::Unsupported`] if the backend does not advertise `snapshot_restore`, or if the VM
/// has a vhost-user device attached.
fn snapshot_precheck(snapshot_restore_capable: bool, has_vhost_user: bool) -> Result<()> {
    if !snapshot_restore_capable {
        return Err(Error::Unsupported {
            vmm: "crosvm".to_string(),
            feature: "snapshot_restore".to_string(),
        });
    }
    if has_vhost_user {
        return Err(Error::Unsupported {
            vmm: "crosvm".to_string(),
            feature: "snapshot with a vhost-user device (virtio-fs share or unprivileged net)"
                .to_string(),
        });
    }
    Ok(())
}

/// Refuses a per-disk `io_limit`: crosvm's `--block` has no bandwidth/iops key (capability
/// `disk_io_throttle` is honest-false), so a throttled disk would otherwise be attached
/// **unthrottled** — an accepted input silently dropped.
///
/// One predicate shared by `create()` **and** `restore()`. M4: `restore()` used to accept exactly
/// what `create()` rejects (the restore run args are built by the same `build_crosvm_run_args`,
/// which has nowhere to put the limit), so a snapshot lineage could be restored with the throttle
/// quietly gone. The feature string matches the `VmmCapabilities` field name (N-VMM-1).
///
/// # Errors
/// Returns [`Error::Unsupported`] if any extra disk carries an `io_limit`.
fn reject_disk_io_throttle(cfg: &VmConfig) -> Result<()> {
    if cfg.extra_disks.iter().any(|d| d.io_limit.is_some()) {
        return Err(Error::Unsupported {
            vmm: "crosvm".to_string(),
            feature: "disk_io_throttle".to_string(),
        });
    }
    Ok(())
}

/// The [`JailConfig`](vmcell::config::JailConfig) actually handed to
/// [`apply_jail`](vmcell::vmm::jail::apply_jail) for a crosvm launch — the pure, total mapping from
/// the requested `(cfg.jail, cfg.vmm_seccomp)` pair to the Layer-2 posture that ships.
///
/// Sandbox posture (§12.2, validated live): crosvm ALWAYS runs `--disable-sandbox` (from
/// `vmm_seccomp_args`) because its own multiprocess minijail (`pivot_root` into `/var/empty` +
/// per-device child forking) is incompatible with the single-process supervision model. The Layer-2
/// jailer deny-list is therefore crosvm's **only** seccomp confinement, so `Enforcing` turns it ON
/// no matter what `cfg.jail` asked for (the backend is NEVER unconfined by default — the seccomp.rs
/// invariant), and `Disabled` — the loud opt-out — leaves `cfg.jail.seccomp_deny_list` exactly as
/// configured (it never forces the deny-list *off*, so an operator who asked for Layer 2 keeps it).
/// `Log` never reaches here: `vmm_seccomp_args` typed-refuses it for crosvm first.
///
/// Pure (a `Copy` in, a `Copy` out) so a KVM-free test can pin BOTH directions. M10: this flip lived
/// inline in `spawn` and deleting it left every KVM-free gate *and* the whole live `test-crosvm`
/// matrix green while crosvm ran with no seccomp filter at all.
fn effective_jail_config(cfg: &VmConfig) -> vmcell::config::JailConfig {
    let mut jail = cfg.jail; // JailConfig is Copy
    if matches!(cfg.vmm_seccomp, vmcell::config::VmmSeccomp::Enforcing) {
        jail.seccomp_deny_list = true;
    }
    jail
}

/// The crosvm snapshot artifact inside the caller's snapshot dir (`crosvm snapshot take <path>`).
/// A distinct basename so it never collides with the sidecars a caller writes into the same dir.
const SNAPSHOT_FILE: &str = "crosvm-snapshot";

/// Sidecar recording the guest vsock CID baked into the snapshot. crosvm bakes the CID into the
/// vsock device state and rejects a mismatched `--vsock cid=` on restore ("Virtio vsock incorrect
/// cid for restore"), so `restore()` must reprogram the EXACT baked CID — this file carries it across
/// the snapshot/restore boundary (the crosvm analogue of Firecracker's `HOST_PATHS_SIDECAR`, but
/// AF_VSOCK needs only the CID, not a host UDS path). Decimal text; no serde (this crate carries none).
const HOST_CID_SIDECAR: &str = "crosvm-host-cid.txt";

/// The crosvm capability descriptor, exposed as a free function so [`Crosvm::capabilities`], the
/// `restore()` self-guard (which reads it through `capabilities()`), and the instance-level
/// `snapshot()` self-guard (which reads the `snapshot_restore` bool captured from it at spawn) all
/// consult the **same** source of truth.
///
/// Each field is the **empirically validated** value (matrix + arg-builder tests). Flipping any of the
/// remaining `false`s to `true` re-validates against a pinned crosvm build (AGENTS.md rule 5) and
/// updates its capability-honesty test.
fn crosvm_capabilities() -> VmmCapabilities {
    VmmCapabilities {
        // crosvm `snapshot take` + `run --restore` over the virtio block/net/vsock/serial device set
        // (USB dropped via --no-usb — the one non-Suspendable device). Validated live: snapshot →
        // restore reusing the BAKED vsock CID (crosvm rejects a rotated one) → agent-exec, MAC/IP/
        // clock/RNG resync all pass the snapshot_restore matrix leg. A deliberate re-gate must flip
        // this AND its capability-honesty test together (docs/45).
        snapshot_restore: true,
        // No userfaultfd/demand-paged restore backend wired.
        lazy_restore: false,
        // crosvm has `--shared-dir type=fs` (in-process virtiofs), but it is unvalidated here and
        // its snapshot-eligibility framing (in-process, not an external vhost-user virtiofsd)
        // differs from the `config_has_vhost_user_device` law — honest-false until validated;
        // create() rejects a share fail-loud meanwhile.
        virtio_fs_shares: false,
        // Whether crosvm supports the unprivileged smoltcp/vhost-user-net datapath is unconfirmed.
        unprivileged_vhost_user_net: false,
        // crosvm documents no working guest `/dev/kvm` (no nested KVM) — a hard, documented false.
        nested_virt: false,
        // crosvm has `--serial hardware=virtio-console` (hvc0); a VirtioConsole config is accepted.
        virtio_console: true,
        // FALSE — the Firecracker pattern, NOT QEMU's. crosvm bakes the vsock CID into the snapshot
        // and REQUIRES the same CID on restore: a rotated `--vsock cid=` fails "Virtio vsock incorrect
        // cid for restore: Expected: N, Actual: M" (validated live). So `restore()` reuses the baked
        // CID (carried in a sidecar), the restored VM does not get a fresh host-side vsock identity,
        // and — like FC — restore-while-alive and concurrent restores from one lineage are unsupported
        // (the §17 single-snapshot-CoW gap). Flip this AND its capability-honesty test together only if
        // a future crosvm allows CID rotation on restore.
        restore_rotates_host_paths: false,
        // crosvm's `--block` has NO bandwidth/iops key (verified against `crosvm run --help`), so it
        // cannot rate-limit disk I/O like CH/FC/QEMU — `create()` rejects a throttled disk fail-loud.
        disk_io_throttle: false,
        // crosvm's default xhci USB controller is NOT `Suspendable` (validated live: `resume` panics
        // "Suspendable::wake not implemented for XhciController"), so vmcell always launches with
        // `--no-usb` (§2.5) — there is no controller to attach a host device to. Honest-false;
        // `create()` rejects a USB device fail-loud via the shared `reject_usb_host_devices`
        // predicate. Flipping this would require dropping `--no-usb`, which re-breaks snapshot.
        usb_host_passthrough: false,
    }
}

/// Builds the crosvm `--serial` device spec for `mode`, writing the guest console to `serial_path`.
///
/// The `hardware=` token moves in lockstep with the cmdline `console=` token
/// (`build_kernel_cmdline`): `Uart` → the 8250 `ttyS0` (`hardware=serial`), `VirtioConsole` →
/// `hvc0` (`hardware=virtio-console`). A desync would sink the guest console nowhere and leave
/// `serial.log` silent, so both are driven by the one `cfg.console_mode`.
fn serial_arg(mode: ConsoleMode, serial_path: &Path) -> String {
    let hardware = match mode {
        ConsoleMode::Uart => "serial",
        ConsoleMode::VirtioConsole => "virtio-console",
    };
    format!(
        "type=file,path={},hardware={hardware},num=1,console=true,stdin=false",
        serial_path.display()
    )
}

/// Builds the argument vector for `crosvm run` — everything **after** the `run` subcommand and the
/// seccomp/sandbox flags (which come from [`vmm_seccomp_args`](vmcell::vmm::seccomp::vmm_seccomp_args)).
///
/// The kernel image is the trailing positional argument, and the rootfs `--block` is emitted first
/// so it enumerates as `/dev/vda` — the device the shared cmdline (`root=/dev/vda`,
/// `build_kernel_cmdline`) boots from. crosvm's own `root=` auto-append is deliberately not used;
/// the cmdline owns the `root=` token, exactly as on Firecracker/QEMU. Pure and unit-testable (no
/// I/O, no spawn) so a KVM-free test can assert the freeze flag and device ordering.
///
/// # Errors
/// Returns an error if the guest MAC cannot be derived from `res.vmid`
/// ([`mac_math`](vmcell::net::mac_math)).
fn build_crosvm_run_args(
    cfg: &VmConfig,
    res: &PerVmResources,
    control_socket: &Path,
    serial_path: &Path,
    guest_cid: u32,
    cmdline: &str,
    restore_from: Option<&Path>,
) -> Result<Vec<String>> {
    let mut args: Vec<String> = Vec::new();

    // Control socket: the host drives lifecycle (resume/suspend/powerbtn/stop) over this side
    // socket by re-invoking the crosvm binary as a client. crosvm binds it at startup, so
    // `register_and_await_ready` waits on it as the readiness gate.
    args.push("-s".to_string());
    args.push(control_socket.display().to_string());

    // Create-then-boot split (mirrors QEMU `-S` / FC's deferred InstanceStart): `--suspended`
    // freezes the vCPUs AND devices at launch so the guest does not run until `boot()`/`resume()`
    // issues `crosvm resume --full`. On the RESTORE path it also holds the loaded snapshot paused so
    // `restore()` can return a paused instance for the orchestrator to resume (the trait contract).
    args.push("--suspended".to_string());

    // Restore path: load the snapshot's device + guest-RAM state on startup. The device topology is
    // reconstructed from the run args below (kernel/disks/net) against a FRESH `res` — but NOT the
    // vsock CID: crosvm bakes it into the snapshot and rejects a rotated `--vsock cid=` ("Virtio
    // vsock incorrect cid for restore", validated live), so the caller passes the sidecar-carried
    // BAKED `guest_cid` here while guest RAM is loaded verbatim (`restore_rotates_host_paths:
    // false` — the Firecracker pattern; see the capability descriptor above and `restore()` below).
    if let Some(snapshot) = restore_from {
        args.push("--restore".to_string());
        args.push(snapshot.display().to_string());
    }

    // `--suspended`/`resume` runs a device sleep/wake cycle that requires every attached device to
    // implement `Suspendable`. crosvm attaches a legacy xhci USB controller by default which does
    // NOT (validated live: `resume` panics `Suspendable::wake not implemented for XhciController`);
    // the guest needs no USB, so drop it. The remaining devices (virtio block/net/vsock/serial) are
    // the Suspendable set crosvm's suspend path supports.
    args.push("--no-usb".to_string());

    args.push("-c".to_string());
    args.push(cfg.vcpus.to_string());
    args.push("-m".to_string());
    args.push(cfg.mem_mib.to_string());

    // Console/serial, driven by the SAME `cfg.console_mode` as the cmdline `console=` token so the
    // two move in lockstep. `reject_unsupported_console` gated an unsupported mode in create().
    args.push("--serial".to_string());
    args.push(serial_arg(cfg.console_mode, serial_path));

    // In-kernel vhost-vsock on the host AF_VSOCK namespace at `(guest_cid, AGENT_VSOCK_PORT)`
    // (realized against `/dev/vhost-vsock`). No external daemon and no AF_UNIX bridge — the host
    // dials the CID directly (`vsock_endpoint` returns `VsockEndpoint::Vsock`).
    args.push("--vsock".to_string());
    args.push(format!("cid={guest_cid}"));

    // Networking: privileged TAP only for v1. Unprivileged vhost-user-net is rejected in create()
    // (capability `unprivileged_vhost_user_net` is honest-false until validated), so at most a tap
    // is present here. The guest MAC matches the shared `mac_math(vmid)` the other backends use.
    if let Some(tap) = &res.tap_name {
        args.push("--net".to_string());
        args.push(format!(
            "tap-name={tap},mac={}",
            vmcell::net::mac_math(res.vmid)?
        ));
    }

    // Block devices, in argument order → `/dev/vda`, `/dev/vdb`, … The rootfs MUST be first so it
    // enumerates as `/dev/vda`, which the cmdline boots from. `ro=true` for the read-only EROFS
    // image; a writable Block source (or its overlay) is read-write.
    match &cfg.rootfs {
        vmcell::config::RootfsSource::Erofs { image } => {
            args.push("--block".to_string());
            args.push(format!("path={},ro=true", image.display()));
        }
        vmcell::config::RootfsSource::Block { image, overlay } => {
            args.push("--block".to_string());
            args.push(format!(
                "path={}",
                overlay.as_ref().unwrap_or(image).display()
            ));
        }
    }

    // Extra virtio-blk devices (§4.6), attached AFTER the root disk so they enumerate `/dev/vdb`,
    // `/dev/vdc`, … in order and never displace `/dev/vda`. Per-disk I/O throttling (`io_limit`)
    // has no crosvm CLI equivalent and is rejected fail-loud by `reject_disk_io_throttle` on BOTH
    // the create and the restore path (M4), so it is absent here.
    for disk in &cfg.extra_disks {
        args.push("--block".to_string());
        if disk.readonly {
            args.push(format!("path={},ro=true", disk.image.display()));
        } else {
            args.push(format!("path={}", disk.image.display()));
        }
    }

    // Kernel command line (`-p`) then the kernel image as the trailing positional argument.
    args.push("-p".to_string());
    args.push(cmdline.to_string());
    args.push(cfg.kernel.display().to_string());

    Ok(args)
}

/// Builds the argument vector for a crosvm **control** invocation
/// (`crosvm <subcmd> <VM_SOCKET> [extra…]`).
///
/// The control socket is a positional argument that comes **before** any trailing flags (crosvm's
/// help is `crosvm resume <VM_SOCKET> [--full]`). One helper so the spelling lives in exactly one
/// place (and one KVM-free test). `extra` carries per-op flags such as `--full` for the boot resume.
fn crosvm_control_args(subcmd: &str, socket: &Path, extra: &[&str]) -> Vec<String> {
    let mut args = vec![subcmd.to_string(), socket.display().to_string()];
    args.extend(extra.iter().map(|s| (*s).to_string()));
    args
}

impl Crosvm {
    async fn spawn(
        &self,
        cfg: &VmConfig,
        res: &PerVmResources,
        cgroups: &dyn vmcell::metrics::CgroupFs,
        restore_from: Option<&Path>,
        // The vsock CID to program on `--vsock cid=` and report as `guest_cid()`. `res.guest_cid` on
        // a cold create; the snapshot's BAKED CID (from the sidecar) on restore, since crosvm requires
        // it to match the snapshot (`restore_rotates_host_paths: false`).
        guest_cid: u32,
    ) -> Result<CrosvmInstance> {
        // The orchestrator owns the per-VM scratch dir; derive our socket and serial-log paths
        // inside it.
        let control_socket = res.tmp_dir.join("crosvm.sock");
        let vsock_path = res.tmp_dir.join("vsock.sock"); // vestigial (crosvm uses AF_VSOCK)
        let serial_path = res.tmp_dir.join("serial.log");

        // Re-spawn safety: `MicroVm::start`'s health-gate may recreate a VM on the SAME per-VM dir;
        // a stale bound control socket left in the dir would make crosvm fail to bind. Pre-clean
        // (a no-op, and thus harmless, on the first spawn when nothing exists yet).
        let _ = tokio::fs::remove_file(&control_socket).await;

        let cmdline = vmcell::config::build_kernel_cmdline(cfg, res, "")?;

        // Sandbox posture (§12.2, validated live): the argv half is always `--disable-sandbox`, and
        // the confinement half is the Layer-2 deny-list `effective_jail_config` turns on — crosvm is
        // the one backend whose confinement is Layer 2 rather than its own filter, and it is the
        // per-backend deny-list enablement the deny-list was designed for (validated: crosvm boots +
        // execs + does tap/netns networking under the deny-list). The mapping is pure and pinned
        // KVM-free in both directions (M10) rather than open-coded here.
        let seccomp_args = vmcell::vmm::seccomp::vmm_seccomp_args("crosvm", cfg.vmm_seccomp)?;
        let jail = vmcell::vmm::jail::jail_spec_from_config(&effective_jail_config(cfg))?;
        let run_args = build_crosvm_run_args(
            cfg,
            res,
            &control_socket,
            &serial_path,
            guest_cid,
            &cmdline,
            restore_from,
        )?;

        let mut cmd =
            vmcell::vmm::build_vmm_cmd(&self.binary_path, res.netns_name.as_deref(), &jail);
        cmd.arg("run");
        cmd.args(&seccomp_args);
        cmd.args(&run_args);

        // Debug level (not info): the full command line is diagnostic noise on every create.
        tracing::debug!("crosvm CMD: {cmd:?}");

        let mut process = cmd
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()?;

        // Shared spawn+register+await-ready sequence (VMM-2): capture the pgid, add the VMM to its
        // cgroup, and block on the control socket — reaping the process group on any failure. The
        // readiness error is propagated raw, identically to CH/FC/QEMU.
        let pgid = vmcell::vmm::register_and_await_ready(
            &mut process,
            cgroups,
            &res.cgroup_name,
            &control_socket,
            1000,
            cfg.timeouts.api_socket_poll.as_millis() as u64,
        )
        .await?;

        Ok(CrosvmInstance {
            process,
            binary_path: self.binary_path.clone(),
            control_socket,
            vsock_path,
            serial_path,
            cid: guest_cid,
            pgid,
            reaped: false,
            // A restore-spawned instance is returned paused; its first `resume()` must be `--full`.
            restored: restore_from.is_some(),
            has_vhost_user_device: vmcell::vmm::config_has_vhost_user_device(cfg, res),
            // Captured from the ONE descriptor so `snapshot()` self-guards on the same source of
            // truth `capabilities()` reports (M-RESTORE-3).
            snapshot_restore_capable: self.capabilities().snapshot_restore,
        })
    }
}

impl Vmm for Crosvm {
    type Instance = CrosvmInstance;

    async fn create(
        &self,
        cfg: &VmConfig,
        res: &PerVmResources,
        cgroups: &dyn vmcell::metrics::CgroupFs,
    ) -> Result<Self::Instance> {
        // The cmdline `console=` token and the `--serial` device wiring are both driven by
        // `cfg.console_mode`; gate an unsupported mode up front so they can never desync into a
        // silent `serial.log`. crosvm supports virtio-console, so only a future capability flip
        // would trip this.
        vmcell::vmm::reject_unsupported_console("crosvm", &self.capabilities(), cfg.console_mode)?;

        let caps = self.capabilities();
        if let vmcell::config::NetConfig::Unprivileged { .. } = cfg.net
            && !caps.unprivileged_vhost_user_net
        {
            return Err(Error::Unsupported {
                vmm: "crosvm".to_string(),
                // N-VMM-1: match the VmmCapabilities field name so callers matching feature strings
                // see one consistent spelling across backends.
                feature: "unprivileged_vhost_user_net".to_string(),
            });
        }
        if res.vhost_user_socket.is_some() {
            return Err(Error::Unsupported {
                vmm: "crosvm".to_string(),
                feature: "vhost_user_socket".to_string(),
            });
        }
        if !cfg.shares.is_empty() {
            return Err(Error::Unsupported {
                vmm: "crosvm".to_string(),
                feature: "virtio_fs_shares".to_string(),
            });
        }
        // Per-disk I/O throttling has no crosvm CLI equivalent (capability `disk_io_throttle` is
        // false); reject a throttled disk fail-loud rather than silently drop the limit
        // (honor-or-reject accepted input). The one predicate `restore()` shares (M4).
        reject_disk_io_throttle(cfg)?;
        // vmcell always launches crosvm with `--no-usb` (the xhci controller is not `Suspendable`,
        // §2.5), so there is no bus to attach a host device to. Refuse through the ONE shared
        // predicate rather than silently ignoring the accepted input.
        vmcell::vmm::reject_usb_host_devices("crosvm", &caps, &cfg.usb_host_devices)?;

        self.spawn(cfg, res, cgroups, None, res.guest_cid).await
    }

    async fn restore(
        &self,
        snapshot_dir: &Path,
        cfg: &VmConfig,
        res: &PerVmResources,
        cgroups: &dyn vmcell::metrics::CgroupFs,
    ) -> Result<Self::Instance> {
        // VMM-5 / M-RESTORE-3: self-check the capability descriptor instead of assuming crosvm
        // semantics — the same shape CH and FC ship. crosvm's descriptor says `snapshot_restore:
        // true` today, so this branch is only reachable via a deliberate re-gate; the KVM-free
        // `snapshot_precheck` test drives the equivalent false branch on the snapshot side.
        if !self.capabilities().snapshot_restore {
            return Err(Error::Unsupported {
                vmm: "crosvm".to_string(),
                feature: "snapshot_restore".to_string(),
            });
        }
        vmcell::vmm::reject_unsupported_console("crosvm", &self.capabilities(), cfg.console_mode)?;

        // M4: `restore()` must refuse exactly what `create()` refuses — the restore run args come
        // from the same `build_crosvm_run_args`, which has nowhere to put an `io_limit`, so an
        // unguarded restore would silently attach the throttled disk unthrottled. One predicate,
        // both paths.
        reject_disk_io_throttle(cfg)?;

        // Eligibility (S1, §8.1), defense in depth alongside `config::build()`, the orchestrator
        // re-check, and `check_clone_eligible`. crosvm has no external vhost-user devices, so a share
        // or unprivileged net (both already rejected at create) is the only way this trips — reject
        // fail-loud before spawning a half-restored VM.
        if vmcell::vmm::config_has_vhost_user_device(cfg, res) {
            return Err(Error::Unsupported {
                vmm: "crosvm".to_string(),
                feature: "snapshot restore with a vhost-user device (virtio-fs share or unprivileged net)"
                    .to_string(),
            });
        }

        // Fail loud BEFORE spawning if the snapshot artifact or its CID sidecar is missing, so a bad
        // snapshot dir surfaces as a clear typed error instead of an opaque `crosvm run --restore`
        // failure. Both are written by `snapshot()`.
        let snapshot = snapshot_dir.join(SNAPSHOT_FILE);
        if !tokio::fs::try_exists(&snapshot).await.unwrap_or(false) {
            return Err(Error::Vmm(format!(
                "crosvm snapshot artifact {} is missing (not a valid snapshot dir)",
                snapshot.display()
            )));
        }
        // crosvm requires the restored `--vsock cid=` to match the snapshot's baked CID exactly, so
        // read it from the sidecar and reprogram it (NOT `res.guest_cid`). The guest keeps the baked
        // CID (`restore_rotates_host_paths: false`); the vmid/MAC/IP still rotate to `res.vmid` via the
        // orchestrator's post-restore resync. A missing/garbled sidecar is a fail-loud pre-spawn error.
        let baked_cid: u32 = tokio::fs::read_to_string(snapshot_dir.join(HOST_CID_SIDECAR))
            .await
            .map_err(|e| {
                Error::Vmm(format!(
                    "crosvm snapshot CID sidecar {} is missing/unreadable: {e}",
                    snapshot_dir.join(HOST_CID_SIDECAR).display()
                ))
            })?
            .trim()
            .parse()
            .map_err(|e| {
                Error::Vmm(format!(
                    "crosvm snapshot CID sidecar is not a valid CID: {e}"
                ))
            })?;

        // The instance is returned paused (`restored: true`); the orchestrator continues with
        // `resume()` — never `boot()` — which issues the completing `crosvm resume --full`.
        self.spawn(cfg, res, cgroups, Some(&snapshot), baked_cid)
            .await
    }

    fn capabilities(&self) -> VmmCapabilities {
        crosvm_capabilities()
    }

    fn id(&self) -> &str {
        "crosvm"
    }
}

impl CrosvmInstance {
    /// Runs one crosvm control subcommand against this instance's side socket and fails if crosvm
    /// exits non-zero.
    ///
    /// Each control op re-invokes the crosvm binary as a short-lived client (`crosvm <subcmd>
    /// <socket>`) — the socket protocol is unstable binary and is never hand-rolled. Awaiting the
    /// child reaps it. Not jailed or netns-entered: it is a host-side client, not the VMM.
    async fn run_control(&self, subcmd: &str, extra: &[&str]) -> Result<()> {
        let status = tokio::process::Command::new(&self.binary_path)
            .args(crosvm_control_args(subcmd, &self.control_socket, extra))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .status()
            .await?;
        if !status.success() {
            return Err(Error::Vmm(format!(
                "crosvm {subcmd} control command failed: {status}"
            )));
        }
        Ok(())
    }

    /// Writes a snapshot of the (already-suspended) VM to `path` via `crosvm snapshot take <path>
    /// <VM_SOCKET>`. The snapshot subcommand's positional order is `<snapshot_path> <VM_SOCKET>` — the
    /// path comes BEFORE the socket, so it does not fit `crosvm_control_args` (socket-first) and takes
    /// its own arg vector.
    async fn snapshot_take(&self, path: &Path) -> Result<()> {
        let status = tokio::process::Command::new(&self.binary_path)
            .arg("snapshot")
            .arg("take")
            .arg(path)
            .arg(&self.control_socket)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .status()
            .await?;
        if !status.success() {
            return Err(Error::Vmm(format!("crosvm snapshot take failed: {status}")));
        }
        Ok(())
    }
}

impl VmInstance for CrosvmInstance {
    async fn boot(&mut self) -> Result<()> {
        // Wake the vCPUs AND devices frozen by `--suspended` at create — the real start point (H-VMM-2
        // analogue). `--suspended` is a FULL suspend (devices + vCPUs), so boot needs `resume --full`:
        // a plain `resume` wakes only vCPUs and crosvm errors "Trying to wake Vcpus while Devices are
        // asleep" (validated live). boot() is only ever called on a `create()` instance; a restored
        // instance is continued via `resume()` (which does its own completing `--full`), never boot().
        self.run_control("resume", &["--full"]).await
    }

    async fn request_shutdown(&mut self) -> Result<()> {
        // ACPI power button: the guest agent (PID 1) honors it and powers off gracefully.
        self.run_control("powerbtn", &[]).await
    }

    async fn kill(&mut self) -> Result<()> {
        // Best-effort graceful stop first (bounded), then SIGKILL the process group and reap.
        let _ = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            self.run_control("stop", &[]),
        )
        .await;

        // Skip the group SIGKILL if the leader was already reaped (its pgid may be recycled) —
        // M-VMM-1.
        if let Some(pgid) = self.pgid
            && !self.reaped
        {
            let _ = nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(-(pgid as i32)),
                nix::sys::signal::Signal::SIGKILL,
            );
        }
        let _ = self.process.wait().await;
        // The leader is reaped now; `Drop` must not re-signal a possibly-recycled pgid.
        self.reaped = true;
        Ok(())
    }

    async fn has_exited(&mut self) -> bool {
        // Non-blocking reap of the crosvm leader; `Ok(Some(_))` means it exited after
        // `request_shutdown` (`powerbtn`). Record the reap so `kill()`/`Drop` do NOT re-`SIGKILL`
        // the process group — once the leader is reaped the kernel may recycle its pgid (M-VMM-1).
        if matches!(self.process.try_wait(), Ok(Some(_))) {
            self.reaped = true;
            true
        } else {
            false
        }
    }

    async fn pause(&mut self) -> Result<()> {
        // vCPU-only suspend of a running VM (devices keep running) — the conventional lightweight
        // pause/resume pair. Not `--full`: that is boot()'s job, matching the `--suspended` launch.
        self.run_control("suspend", &[]).await
    }

    async fn resume(&mut self) -> Result<()> {
        // A restored instance was launched `--suspended --restore`, so its FIRST resume must be
        // `--full` (wake devices + vCPUs, completing the restore — crosvm's `resume` after `--restore`
        // also waits for the restore to finish). A plain vCPU-only resume on that state errors "Trying
        // to wake Vcpus while Devices are asleep" (the same class as boot()). Subsequent resumes
        // (after a vCPU-only pause()) are vCPU-only. Consume `restored` only AFTER the resume succeeds,
        // so a transient failure leaves the next call able to retry the completing `--full`.
        let extra: &[&str] = if self.restored { &["--full"] } else { &[] };
        self.run_control("resume", extra).await?;
        self.restored = false;
        Ok(())
    }

    async fn snapshot(&mut self, dir: &Path) -> Result<()> {
        // M-RESTORE-3: self-check the `snapshot_restore` capability (captured from the backend
        // descriptor at spawn) before doing any work, and enforce the S1 snapshot-eligibility law —
        // refuse to snapshot a VM with a vhost-user device attached. crosvm has no external
        // vhost-user devices and rejects shares/unprivileged net at create, so the second half holds
        // by construction; both are kept as defense in depth (mirrors CH's `snapshot_precheck`).
        snapshot_precheck(self.snapshot_restore_capable, self.has_vhost_user_device)?;
        // Full-suspend (crosvm requires all devices asleep to snapshot) → `snapshot take` → persist
        // the baked-CID sidecar → resume the source. Mirrors the QEMU stop→migrate→cont / CH-FC
        // pause→snapshot→resume order; the orchestrator's `MicroVm::snapshot` invalidates the cached
        // agent client afterward, covering the suspend severing the vsock connection. The take + the
        // sidecar are BOTH required for a restorable snapshot, so either failing fails the snapshot
        // fail-loud; the source resume is best-effort (warn-only), matching QEMU/CH/FC.
        self.run_control("suspend", &["--full"]).await?;
        let result = match self.snapshot_take(&dir.join(SNAPSHOT_FILE)).await {
            // Restore reprograms this exact CID; a snapshot without its CID is unrestorable, so a
            // write failure is surfaced, never logged-and-swallowed (M-RESTORE-2).
            Ok(()) => tokio::fs::write(dir.join(HOST_CID_SIDECAR), self.cid.to_string())
                .await
                .map_err(Error::Io),
            Err(e) => Err(e),
        };
        if let Err(e) = self.run_control("resume", &["--full"]).await {
            tracing::warn!("crosvm snapshot: failed to resume source after take: {e}");
        }
        result
    }

    fn vsock_path(&self) -> &Path {
        &self.vsock_path
    }

    fn vsock_endpoint(&self) -> VsockEndpoint {
        // crosvm's in-kernel vhost-vsock exposes the guest on the host AF_VSOCK namespace at
        // `(cid, AGENT_VSOCK_PORT)` — NOT the AF_UNIX hybrid default. Override accordingly (the
        // agent transport branches only its connect prologue on this).
        VsockEndpoint::Vsock {
            cid: self.cid,
            port: vmcell::vmm::AGENT_VSOCK_PORT,
        }
    }

    fn guest_cid(&self) -> u32 {
        self.cid
    }

    fn serial_log(&self) -> &Path {
        &self.serial_path
    }
}

impl Drop for CrosvmInstance {
    fn drop(&mut self) {
        // Teardown order (AGENTS.md): reap the VMM process group first — before touching the
        // socket — so cleanup never races a live VMM. Skip the SIGKILL + reap if the leader was
        // already reaped (via `has_exited`/`kill`): its pgid may have been recycled (M-VMM-1).
        if let Some(pgid) = self.pgid
            && !self.reaped
        {
            let _ = nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(-(pgid as i32)),
                nix::sys::signal::Signal::SIGKILL,
            );
            if let Some(pid) = self.process.id() {
                let _ = nix::sys::wait::waitpid(nix::unistd::Pid::from_raw(pid as i32), None);
            }
        }
        // Unlink our own control socket; the per-VM directory itself is owned and removed once by
        // the orchestrator's `VmTempDir` guard after this instance is dropped. Mirrors CH/QEMU.
        let _ = std::fs::remove_file(&self.control_socket);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vmcell::config::{RootfsSource, VmConfig};

    /// A no-op [`vmcell::metrics::CgroupFs`] for the reject-before-spawn tests below, which exercise
    /// `create` capability guards that return **before** any cgroup interaction — so the fake's
    /// methods are never called.
    #[derive(Debug)]
    struct TestCgroupFs;

    impl vmcell::metrics::CgroupFs for TestCgroupFs {
        fn create_slice(
            &self,
            _name: &str,
            _limits: &vmcell::config::ResourceLimits,
        ) -> Result<()> {
            Ok(())
        }
        fn delete_slice(&self, _name: &str) -> Result<()> {
            Ok(())
        }
        fn read_stats(&self, _name: &str) -> Result<vmcell::metrics::ResourceUsage> {
            Ok(vmcell::metrics::ResourceUsage::default())
        }
        fn add_task(&self, _name: &str, _pid: u32) -> Result<()> {
            Ok(())
        }
    }

    fn test_res() -> PerVmResources {
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

    fn erofs_cfg() -> VmConfig {
        VmConfig::builder(
            "/boot/vmlinux",
            RootfsSource::Erofs {
                image: PathBuf::from("/img/rootfs.erofs"),
            },
        )
        .build()
        .expect("build config")
    }

    // Guards the create-then-boot split and root-disk ordering: every crosvm launch must carry
    // `--suspended` (so boot()'s `resume` is the real start point) and emit the rootfs `--block`
    // FIRST so it enumerates as `/dev/vda` (what the cmdline boots from). The kernel is the trailing
    // positional argument. Inverse: dropping `--suspended` (create() runs the guest, boot() no-ops)
    // or ordering an extra disk before the rootfs (root shifts off vda) reddens here.
    #[test]
    fn crosvm_run_args_freeze_root_and_kernel_ordering() {
        let cfg = erofs_cfg();
        let res = test_res();
        let args = build_crosvm_run_args(
            &cfg,
            &res,
            Path::new("/tmp/vmcell-vm-test-1/crosvm.sock"),
            Path::new("/tmp/vmcell-vm-test-1/serial.log"),
            3,
            "console=ttyS0 root=/dev/vda",
            None,
        )
        .expect("build run args");

        assert!(
            args.iter().any(|a| a == "--suspended"),
            "crosvm must launch with --suspended so boot()'s resume is the real start point"
        );
        // A cold create carries no `--restore`.
        assert!(
            !args.iter().any(|a| a == "--restore"),
            "a cold create must not pass --restore"
        );
        assert!(
            args.iter().any(|a| a == "-s"),
            "control socket flag missing"
        );
        // `--suspended`/resume runs a device sleep/wake cycle; crosvm's default xhci USB controller
        // is not Suspendable and panics on wake, so `--no-usb` must drop it (validated live).
        assert!(
            args.iter().any(|a| a == "--no-usb"),
            "crosvm must pass --no-usb: the default xhci controller is not Suspendable and panics on \
             the --suspended → resume wake"
        );

        // The rootfs `--block` must be the FIRST block, read-only for EROFS.
        let block_idx = args
            .iter()
            .position(|a| a == "--block")
            .expect("a rootfs --block must be present");
        let block_spec = &args[block_idx + 1];
        assert!(
            block_spec.contains("rootfs.erofs") && block_spec.contains("ro=true"),
            "first --block must be the read-only rootfs (→ /dev/vda), got {block_spec}"
        );

        // The sandbox flag comes from `vmm_seccomp_args`, never from the run-args builder.
        assert!(
            !args.iter().any(|a| a == "--disable-sandbox"),
            "run-args builder must not hard-code the sandbox posture"
        );

        // The kernel image is the trailing positional argument.
        assert_eq!(
            args.last().map(String::as_str),
            Some("/boot/vmlinux"),
            "the kernel image must be the last positional argument"
        );
    }

    // The tap MAC must match the shared `mac_math(vmid)` law (so the guest's derived identity lines
    // up with the other backends), and it rides the `--net tap-name=` device. Inverse: a hand-rolled
    // MAC or a missing `--net` reddens.
    #[test]
    fn crosvm_run_args_tap_uses_mac_math() {
        let cfg = erofs_cfg();
        let res = test_res();
        let args = build_crosvm_run_args(
            &cfg,
            &res,
            Path::new("/tmp/c.sock"),
            Path::new("/tmp/s.log"),
            3,
            "root=/dev/vda",
            None,
        )
        .expect("build run args");
        let net_idx = args
            .iter()
            .position(|a| a == "--net")
            .expect("a tap --net must be present when res.tap_name is set");
        let expected_mac = vmcell::net::mac_math(res.vmid).expect("mac");
        assert!(
            args[net_idx + 1].contains("tap-name=tap0")
                && args[net_idx + 1].contains(&format!("mac={expected_mac}")),
            "tap must carry tap-name and the mac_math MAC, got {}",
            args[net_idx + 1]
        );
    }

    // The restore path threads `--restore <snapshot>` into the SAME run args, still ending with the
    // kernel positional, and programs `--vsock cid=` from the `guest_cid` PARAMETER — which
    // `restore()` fills from the snapshot's BAKED CID sidecar, never from `res.guest_cid` (crosvm
    // rejects a rotated CID: "Virtio vsock incorrect cid for restore"; `restore_rotates_host_paths`
    // is false — the Firecracker pattern). The `7` below is that baked value, deliberately different
    // from `test_res().guest_cid` (3) so the assertion pins the parameter flow rather than passing
    // vacuously off the fresh `res`. Inverse: dropping `--restore`, emitting it after the kernel, or
    // sourcing the CID from `res` instead of the parameter reddens.
    #[test]
    fn crosvm_run_args_restore_emits_restore_flag() {
        let cfg = erofs_cfg();
        let res = test_res();
        let args = build_crosvm_run_args(
            &cfg,
            &res,
            Path::new("/tmp/c.sock"),
            Path::new("/tmp/s.log"),
            7,
            "root=/dev/vda",
            Some(Path::new("/snap/crosvm-snapshot")),
        )
        .expect("build restore run args");
        let restore_idx = args
            .iter()
            .position(|a| a == "--restore")
            .expect("restore must pass --restore");
        assert_eq!(args[restore_idx + 1], "/snap/crosvm-snapshot");
        // The baked CID rides `--vsock cid=<guest_cid param>`; `res.guest_cid` (3) must NOT leak in.
        assert!(
            args.iter().any(|a| a == "cid=7"),
            "restore must program the snapshot's baked guest CID on --vsock, not res.guest_cid"
        );
        assert_eq!(
            args.last().map(String::as_str),
            Some("/boot/vmlinux"),
            "the kernel image must still be the trailing positional argument on restore"
        );
    }

    // The `--serial hardware=` token must track `cfg.console_mode` in lockstep with the cmdline
    // `console=` token. Inverse: a fixed hardware= (or swapped mapping) sinks one mode's console.
    #[test]
    fn serial_arg_selects_hardware_per_console_mode() {
        assert!(serial_arg(ConsoleMode::Uart, Path::new("/s.log")).contains("hardware=serial"));
        assert!(
            serial_arg(ConsoleMode::VirtioConsole, Path::new("/s.log"))
                .contains("hardware=virtio-console")
        );
    }

    // The control socket is a positional argument BEFORE any trailing flags (`crosvm <subcmd>
    // <socket> [flags]`), the one spelling every control op shares. The boot resume needs `--full`
    // (the `--suspended` launch is a full device+vCPU suspend, so a plain resume errors "Trying to
    // wake Vcpus while Devices are asleep" — validated live). Inverse: a `--socket <path>` form, a
    // dropped socket, or a `--full` placed before the socket reddens.
    #[test]
    fn crosvm_control_args_positional_socket_then_flags() {
        assert_eq!(
            crosvm_control_args("suspend", Path::new("/run/crosvm.sock"), &[]),
            vec!["suspend".to_string(), "/run/crosvm.sock".to_string()]
        );
        assert_eq!(
            crosvm_control_args("resume", Path::new("/run/crosvm.sock"), &["--full"]),
            vec![
                "resume".to_string(),
                "/run/crosvm.sock".to_string(),
                "--full".to_string()
            ],
            "socket must be positional BEFORE --full (crosvm resume <VM_SOCKET> [--full])"
        );
    }

    // The capability-honesty gate (mirrors CH/FC/QEMU's): every crosvm capability is the empirically
    // validated value. Any deliberate re-gate must flip the flag AND this test together (AGENTS.md
    // rule 5: a capability change re-validates empirically). KVM-free.
    #[test]
    fn capabilities_are_honest_for_crosvm() {
        let caps = Crosvm::new("crosvm").capabilities();
        assert!(
            caps.snapshot_restore,
            "crosvm snapshot/restore is KVM-validated ON (snapshot take + run --restore over the \
             virtio device set, USB dropped via --no-usb)"
        );
        assert!(!caps.lazy_restore, "no UFFD/demand-paged restore backend");
        assert!(
            !caps.virtio_fs_shares,
            "crosvm --shared-dir is unvalidated here — honest-false"
        );
        assert!(
            !caps.unprivileged_vhost_user_net,
            "crosvm unprivileged vhost-user-net is unvalidated here — honest-false"
        );
        assert!(
            !caps.nested_virt,
            "crosvm documents no nested KVM — a hard false"
        );
        assert!(
            caps.virtio_console,
            "crosvm has --serial hardware=virtio-console (hvc0)"
        );
        assert!(
            !caps.restore_rotates_host_paths,
            "crosvm bakes the vsock CID into the snapshot and requires the SAME CID on restore \
             (validated: rotating it fails 'Virtio vsock incorrect cid for restore'), so restore \
             reuses the baked CID — the Firecracker pattern, NOT QEMU's rotation (§2.5)"
        );
        assert!(
            !caps.disk_io_throttle,
            "crosvm --block has no bandwidth/iops key — honest-false"
        );
        assert!(
            !caps.usb_host_passthrough,
            "vmcell always launches crosvm with --no-usb (its xhci is not Suspendable, §2.5), so \
             there is no bus to attach a host device to — honest-false; a true would silently \
             drop the requested device"
        );
    }

    // Guards N-VMM-1: the Unsupported.feature string for unprivileged networking must match the
    // VmmCapabilities field name (`unprivileged_vhost_user_net`). KVM-free — create() rejects before
    // spawning. Inverse: a spawn-anyway or a mismatched feature string reddens.
    #[tokio::test]
    async fn create_rejects_unprivileged_net_with_capability_field_name() {
        use vmcell::config::{Egress, NetConfig};
        let crosvm = Crosvm::new("/usr/bin/crosvm");
        let cfg = VmConfig::builder(
            "/k",
            RootfsSource::Erofs {
                image: PathBuf::from("/i"),
            },
        )
        .net(NetConfig::Unprivileged {
            egress: Egress::Open,
            host_services_port: None,
        })
        .build()
        .expect("build config");
        let res = PerVmResources {
            tap_name: None,
            ..test_res()
        };
        let err = crosvm
            .create(&cfg, &res, &TestCgroupFs)
            .await
            .expect_err("unprivileged net must be Unsupported on crosvm v1");
        assert!(
            matches!(&err, Error::Unsupported { vmm, feature }
                if vmm == "crosvm" && feature == "unprivileged_vhost_user_net"),
            "expected an unprivileged_vhost_user_net Unsupported, got {err:?}"
        );
    }

    // Restore fails loud BEFORE spawning when the snapshot artifact is missing — a bad snapshot dir
    // surfaces as a clear typed `Vmm` error, not an opaque `crosvm run --restore` failure. KVM-free
    // (the existence check precedes any spawn). Inverse: checking after spawning would need KVM and
    // lose this clean pre-spawn error.
    #[tokio::test]
    async fn restore_checks_snapshot_file_before_spawning() {
        let crosvm = Crosvm::new("/usr/bin/crosvm");
        let cfg = erofs_cfg();
        let err = crosvm
            .restore(
                Path::new("/nonexistent-crosvm-snapshot-dir"),
                &cfg,
                &test_res(),
                &TestCgroupFs,
            )
            .await
            .expect_err(
                "crosvm restore with a missing snapshot artifact must fail before spawning",
            );
        assert!(
            matches!(&err, Error::Vmm(msg) if msg.contains("snapshot artifact") && msg.contains("missing")),
            "expected a missing-snapshot-artifact Vmm error, got {err:?}"
        );
    }

    // Guards M10 — crosvm's ONLY seccomp confinement. crosvm always runs `--disable-sandbox`, so the
    // Layer-2 deny-list is the whole filter, and the `Enforcing → seccomp_deny_list = true` flip used
    // to live inline in `spawn` where deleting it left every KVM-free gate AND the entire live
    // `test-crosvm` matrix green (a silently unconfined VMM). Pins BOTH directions of the pure
    // mapping. KVM-free. Inverse: dropping the flip reddens the Enforcing assertion; force-clearing
    // the flag on `Disabled` reddens the operator-opt-in assertion; touching any other jail field
    // reddens the totality assertion.
    #[test]
    fn effective_jail_config_turns_the_deny_list_on_only_for_enforcing() {
        use vmcell::config::{JailConfig, VmmSeccomp};

        let cfg = |seccomp: VmmSeccomp, jail: JailConfig| {
            VmConfig::builder(
                "/boot/vmlinux",
                RootfsSource::Erofs {
                    image: PathBuf::from("/img/rootfs.erofs"),
                },
            )
            .vmm_seccomp(seccomp)
            .jail(jail)
            .build()
            .expect("build config")
        };

        // Enforcing: the deny-list is turned ON even though `hardened()` ships it off — this IS
        // crosvm's seccomp filter, so `Enforcing` may never leave the VMM unconfined.
        let hardened = JailConfig::hardened();
        assert!(
            !hardened.seccomp_deny_list,
            "precondition: the hardened default ships the deny-list OFF (the other backends carry \
             their own native filter)"
        );
        let enforcing = effective_jail_config(&cfg(VmmSeccomp::Enforcing, hardened));
        assert!(
            enforcing.seccomp_deny_list,
            "crosvm Enforcing must turn the Layer-2 deny-list ON: --disable-sandbox is always \
             passed, so without it the VMM runs with NO seccomp filter at all"
        );

        // Disabled (the loud opt-out): the requested posture is passed through untouched — off stays
        // off …
        let disabled = effective_jail_config(&cfg(VmmSeccomp::Disabled, hardened));
        assert!(
            !disabled.seccomp_deny_list,
            "crosvm Disabled must not silently re-enable the deny-list — the opt-out is deliberate"
        );
        // … and an operator who explicitly asked for Layer 2 keeps it (the flip is one-way).
        let mut opted_in = JailConfig::hardened();
        opted_in.seccomp_deny_list = true;
        assert!(
            effective_jail_config(&cfg(VmmSeccomp::Disabled, opted_in)).seccomp_deny_list,
            "an explicitly requested deny-list must survive VmmSeccomp::Disabled"
        );

        // Totality: `seccomp_deny_list` is the ONLY field the mapping touches, so the rest of the
        // operator's jail posture reaches `apply_jail` verbatim.
        let mut expected = hardened;
        expected.seccomp_deny_list = true;
        assert_eq!(
            enforcing, expected,
            "effective_jail_config must change seccomp_deny_list and nothing else"
        );
    }

    // Guards the B3 capability self-guard crosvm's rustdoc claimed but never had: `snapshot()` must
    // consult the captured `snapshot_restore` capability *and* the S1 vhost-user law. KVM-free — the
    // live matrix can never reach the false branch (the descriptor ships `snapshot_restore: true`),
    // which is exactly why the guard needs a unit gate. Inverse: a `snapshot()` that ignores the
    // descriptor reddens the first assertion; one that ignores the device law reddens the second.
    #[test]
    fn snapshot_precheck_enforces_capability_and_law() {
        // Backend that does not advertise snapshot_restore, even with a clean VM.
        let err = snapshot_precheck(false, false).expect_err("incapable backend must error");
        assert!(
            matches!(&err, Error::Unsupported { vmm, feature }
                if vmm == "crosvm" && feature == "snapshot_restore"),
            "expected a snapshot_restore Unsupported naming the VmmCapabilities field, got {err:?}"
        );

        // Capable backend, but the VM carries a vhost-user device.
        let err = snapshot_precheck(true, true).expect_err("vhost-user VM must error");
        assert!(
            matches!(&err, Error::Unsupported { feature, .. } if feature.contains("vhost-user")),
            "expected a vhost-user Unsupported, got {err:?}"
        );

        // Capable backend, snapshot-eligible VM: allowed (the positive control — the guard refuses
        // for a reason, not always).
        assert!(snapshot_precheck(true, false).is_ok());
    }

    // Guards M4's crosvm half: an `io_limit` that `create()` refuses must also be refused by
    // `restore()`, which otherwise builds the same run args with the limit silently dropped. KVM-free
    // (the rejection precedes the snapshot-artifact check and any spawn) and non-vacuous: the
    // snapshot dir does not exist, so an unguarded restore reaches the missing-artifact `Vmm` error
    // instead — which is precisely what this asserts it does NOT get. Inverse: deleting the
    // `reject_disk_io_throttle(cfg)?` call in `restore()` reddens here.
    #[tokio::test]
    async fn restore_rejects_disk_io_throttle_like_create() {
        use vmcell::config::{BlockDevice, DiskIoLimit};

        let crosvm = Crosvm::new("/usr/bin/crosvm");
        let cfg = VmConfig::builder(
            "/boot/vmlinux",
            RootfsSource::Erofs {
                image: PathBuf::from("/img/rootfs.erofs"),
            },
        )
        .with_extra_disk(
            BlockDevice::read_only("/img/data.raw")
                .with_io_limit(DiskIoLimit::bandwidth(2_000_000)),
        )
        .build()
        .expect("build config");

        let err = crosvm
            .restore(
                Path::new("/nonexistent-crosvm-snapshot-dir"),
                &cfg,
                &test_res(),
                &TestCgroupFs,
            )
            .await
            .expect_err("a throttled disk must be refused on restore, exactly as on create");
        assert!(
            matches!(&err, Error::Unsupported { vmm, feature }
                if vmm == "crosvm" && feature == "disk_io_throttle"),
            "expected a disk_io_throttle Unsupported (the VmmCapabilities field name, N-VMM-1), got \
             {err:?}"
        );

        // Positive control: the SAME restore without the throttle gets past this guard and fails on
        // the missing snapshot artifact — so the refusal above is about the io_limit, not about
        // restore refusing everything.
        let err = crosvm
            .restore(
                Path::new("/nonexistent-crosvm-snapshot-dir"),
                &erofs_cfg(),
                &test_res(),
                &TestCgroupFs,
            )
            .await
            .expect_err("the control path still fails on the missing snapshot artifact");
        assert!(
            matches!(&err, Error::Vmm(msg) if msg.contains("snapshot artifact")),
            "expected the un-throttled control to reach the missing-artifact error, got {err:?}"
        );
    }
}
