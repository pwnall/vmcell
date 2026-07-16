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
//! **v1 scope (unverified — no crosvm binary on the build host).** snapshot/restore, virtio-fs
//! shares, and unprivileged vhost-user-net are all honest-**false** capabilities pending live
//! validation; each self-skips its matrix leg via `require_cap!`. Boot + tap networking + block
//! devices + in-kernel vsock are the shipped data path. See `docs/implementation-notes.md`
//! (crosvm reconciliation) for the open validation items, and the exact crosvm flag spellings that
//! must be confirmed on the pinned build.

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
}

/// The crosvm capability descriptor, exposed as a free function so both [`Crosvm::capabilities`] and
/// the instance-level `snapshot()`/`restore()` self-guards consult the **same** source of truth.
///
/// Every field is **honest-conservative for v1** — no capability has been validated against a live
/// crosvm on this host, so only capabilities crosvm documents unconditionally are claimed. Flipping
/// any `false` to `true` re-validates empirically (AGENTS.md rule 5) and updates its honesty test.
fn crosvm_capabilities() -> VmmCapabilities {
    VmmCapabilities {
        // crosvm's `snapshot take`/`--restore` is upstream-experimental (limited device set,
        // unstable CBOR) and unvalidated here. Honest-false: every snapshot/zygote matrix leg
        // self-skips, and restore()/snapshot() return Unsupported fail-loud.
        snapshot_restore: false,
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
        // Moot while snapshot_restore is false; determined empirically when snapshot lands.
        restore_rotates_host_paths: false,
        // crosvm's `--block` has NO bandwidth/iops key (verified against `crosvm run --help`), so it
        // cannot rate-limit disk I/O like CH/FC/QEMU — `create()` rejects a throttled disk fail-loud.
        disk_io_throttle: false,
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
) -> Result<Vec<String>> {
    let mut args: Vec<String> = Vec::new();

    // Control socket: the host drives lifecycle (resume/suspend/powerbtn/stop) over this side
    // socket by re-invoking the crosvm binary as a client. crosvm binds it at startup, so
    // `register_and_await_ready` waits on it as the readiness gate.
    args.push("-s".to_string());
    args.push(control_socket.display().to_string());

    // Create-then-boot split (mirrors QEMU `-S` / FC's deferred InstanceStart): `--suspended`
    // freezes the vCPUs AND devices at launch so the guest does not run until `boot()` issues
    // `crosvm resume`. Without it `create()` would already be running the guest and `boot()` a no-op.
    args.push("--suspended".to_string());

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
    // has no crosvm CLI equivalent and is rejected fail-loud in create(), so it is absent here.
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

        let cmdline = vmcell::config::build_kernel_cmdline(cfg, res.vmid, "")?;

        // Sandbox posture (§12.2, validated live): crosvm ALWAYS runs `--disable-sandbox` (from
        // `vmm_seccomp_args`) because its own multiprocess minijail (`pivot_root` into `/var/empty`
        // + per-device child forking) is incompatible with the single-process supervision model.
        // Its seccomp confinement therefore comes from the Layer-2 jailer deny-list instead: turn it
        // ON for `Enforcing` (so the backend is NEVER unconfined by default — the seccomp.rs
        // invariant) and leave `cfg.jail`'s setting untouched for `Disabled` (the loud opt-out). This
        // is the one backend whose confinement is Layer-2 rather than its own filter, and it is the
        // per-backend deny-list enablement the deny-list was designed for (validated: crosvm boots +
        // execs + does tap/netns networking under the deny-list).
        let seccomp_args = vmcell::vmm::seccomp::vmm_seccomp_args("crosvm", cfg.vmm_seccomp)?;
        let mut jail_cfg = cfg.jail; // JailConfig is Copy
        if matches!(cfg.vmm_seccomp, vmcell::config::VmmSeccomp::Enforcing) {
            jail_cfg.seccomp_deny_list = true;
        }
        let jail = vmcell::vmm::jail::jail_spec_from_config(&jail_cfg)?;
        let run_args = build_crosvm_run_args(
            cfg,
            res,
            &control_socket,
            &serial_path,
            res.guest_cid,
            &cmdline,
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
            cid: res.guest_cid,
            pgid,
            reaped: false,
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
        // (honor-or-reject accepted input). The feature string matches the VmmCapabilities field
        // name (N-VMM-1) so a caller matching feature strings sees one consistent spelling.
        if cfg.extra_disks.iter().any(|d| d.io_limit.is_some()) {
            return Err(Error::Unsupported {
                vmm: "crosvm".to_string(),
                feature: "disk_io_throttle".to_string(),
            });
        }

        self.spawn(cfg, res, cgroups).await
    }

    async fn restore(
        &self,
        _snapshot_dir: &Path,
        _cfg: &VmConfig,
        _res: &PerVmResources,
        _cgroups: &dyn vmcell::metrics::CgroupFs,
    ) -> Result<Self::Instance> {
        // crosvm v1 does not implement snapshot/restore (capability `snapshot_restore` is
        // honest-false: upstream snapshot is experimental and unvalidated on this host). Self-guard
        // fail-loud — never spawn a half-restored VM. A deliberate re-gate lands the real restore
        // path AND flips the capability + its honesty test together.
        Err(Error::Unsupported {
            vmm: "crosvm".to_string(),
            feature: "snapshot_restore".to_string(),
        })
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
}

impl VmInstance for CrosvmInstance {
    async fn boot(&mut self) -> Result<()> {
        // Wake the vCPUs AND devices frozen by `--suspended` at create — the real start point (H-VMM-2
        // analogue). `--suspended` is a FULL suspend (devices + vCPUs), so boot needs `resume --full`:
        // a plain `resume` wakes only vCPUs and crosvm errors "Trying to wake Vcpus while Devices are
        // asleep" (validated live). A restored instance is never produced (restore() is Unsupported),
        // so there is no boot-after-restore case to guard.
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
        self.run_control("resume", &[]).await
    }

    async fn snapshot(&mut self, _dir: &Path) -> Result<()> {
        // Honest-false capability; self-guard fail-loud (mirrors restore()).
        Err(Error::Unsupported {
            vmm: "crosvm".to_string(),
            feature: "snapshot_restore".to_string(),
        })
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
        )
        .expect("build run args");

        assert!(
            args.iter().any(|a| a == "--suspended"),
            "crosvm must launch with --suspended so boot()'s resume is the real start point"
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

    // The capability-honesty gate (mirrors CH/FC/QEMU's): every crosvm v1 capability is the honest
    // conservative value. Any deliberate re-gate must flip the flag AND this test together (AGENTS.md
    // rule 5: a capability change re-validates empirically). KVM-free.
    #[test]
    fn capabilities_are_honest_for_crosvm_v1() {
        let caps = Crosvm::new("crosvm").capabilities();
        assert!(
            !caps.snapshot_restore,
            "crosvm snapshot is upstream-experimental and unvalidated here — honest-false in v1"
        );
        assert!(!caps.lazy_restore, "no UFFD/demand-paged restore backend");
        assert!(
            !caps.virtio_fs_shares,
            "crosvm --shared-dir is unvalidated here — honest-false in v1"
        );
        assert!(
            !caps.unprivileged_vhost_user_net,
            "crosvm unprivileged vhost-user-net is unvalidated here — honest-false in v1"
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
            "moot while snapshot_restore is false"
        );
        assert!(
            !caps.disk_io_throttle,
            "crosvm --block has no bandwidth/iops key — honest-false"
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

    // Restore is fail-loud Unsupported in v1 (snapshot_restore honest-false). KVM-free: restore
    // returns before any spawn. Inverse: a restore that spawned would need KVM and not return this
    // typed error.
    #[tokio::test]
    async fn restore_is_unsupported_in_v1() {
        let crosvm = Crosvm::new("/usr/bin/crosvm");
        let cfg = erofs_cfg();
        let err = crosvm
            .restore(Path::new("/snap"), &cfg, &test_res(), &TestCgroupFs)
            .await
            .expect_err("crosvm restore must be Unsupported in v1");
        assert!(
            matches!(&err, Error::Unsupported { vmm, feature }
                if vmm == "crosvm" && feature == "snapshot_restore"),
            "expected a snapshot_restore Unsupported, got {err:?}"
        );
    }
}
