//! QEMU VMM backend.
//!
//! Provides the [`Qemu`] implementation of the `Vmm` trait.

use crate::config::VmConfig;
use crate::error::{Error, Result};
use crate::vmm::{PerVmResources, VmInstance, Vmm, VmmCapabilities};
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
    pgid: Option<u32>,
    vsock_pgid: Option<u32>,
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

impl QemuInstance {
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
}

/// Requires QEMU's external `vhost-device-vsock` daemon: maps a spawn failure to a
/// typed [`Error::Vmm`] instead of silently degrading to the root-only internal
/// kernel vsock.
///
/// The external daemon is QEMU's unprivileged control plane (§3.2). A missing or broken
/// `vhost-device-vsock` binary is a loud misconfiguration that must surface here — the
/// old silent `.ok()` fallback only re-emerged later as an opaque agent-handshake
/// timeout, violating the "checked before a timeout masks it" rule (M-VMM-2).
fn require_vsock_daemon(spawn_result: std::io::Result<Child>) -> Result<Child> {
    spawn_result.map_err(|e| {
        Error::Vmm(format!(
            "failed to spawn the external vhost-device-vsock daemon (QEMU unprivileged vsock control plane): {}",
            e
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
            crate::vmm::reap_process_group(&mut daemon, self.pgid);
        }
    }
}

impl Qemu {
    async fn spawn_qemu(
        &self,
        cfg: &VmConfig,
        res: &PerVmResources,
        cgroups: &dyn crate::metrics::CgroupFs,
        snapshot_dir: Option<&Path>,
    ) -> Result<(
        PathBuf,
        PathBuf,
        PathBuf,
        Child,
        Option<Child>,
        Vec<crate::fs::VirtioFsDaemon>,
        Option<u32>,
        Option<u32>,
    )> {
        // The orchestrator owns the per-VM scratch dir; derive our socket and
        // serial-log paths inside it.
        let qmp_socket = res.tmp_dir.join("qmp.sock");
        let vsock_path = res.tmp_dir.join("vsock.sock"); // host connects here
        let vhost_vsock = res.tmp_dir.join("vhost-vsock.sock"); // qemu connects here
        let serial_path = res.tmp_dir.join("serial.log");

        let mut std_vsock_cmd = std::process::Command::new("vhost-device-vsock");
        std_vsock_cmd
            .arg("--guest-cid")
            .arg(res.guest_cid.to_string())
            .arg("--socket")
            .arg(&vhost_vsock)
            .arg("--uds-path")
            .arg(&vsock_path);
        use std::os::unix::process::CommandExt;
        std_vsock_cmd.process_group(0);

        // The external vhost-device-vsock daemon IS QEMU's unprivileged control plane
        // (§3.2). A spawn failure (e.g. a missing/broken binary) fails loud and typed
        // here — it does NOT silently degrade to the root-only internal kernel vsock,
        // which would only re-emerge later as an opaque agent-handshake timeout
        // (M-VMM-2).
        let mut vsock_daemon = require_vsock_daemon(
            tokio::process::Command::from(std_vsock_cmd)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::inherit())
                .spawn(),
        )?;

        let vsock_pgid = vsock_daemon.id();

        // Wait for the vhost-vsock socket to appear; on failure reap the daemon's
        // group before the RAII guard takes ownership, so a half-started daemon never
        // leaks.
        if let Err(e) = crate::vmm::wait_for_socket(&vhost_vsock, &mut vsock_daemon, 1000, 20).await
        {
            crate::vmm::reap_process_group(&mut vsock_daemon, vsock_pgid);
            return Err(Error::Vmm(format!(
                "vhost-device-vsock failed to start: {}",
                e
            )));
        }

        // The daemon is healthy. Own it in an RAII guard so that EVERY subsequent
        // fallible step (per-share virtio-fs daemon start below, the QEMU
        // `cgroups.add_task`, and QMP readiness) reaps the vhost-device-vsock process
        // group on error — the QemuInstance whose Drop would otherwise reap it is not
        // constructed until the caller returns (H-QEMU-1).
        let vsock_guard = VsockDaemonGuard::new(vsock_daemon, vsock_pgid);

        let mut fs_daemons = Vec::new();
        for share in &cfg.shares {
            let daemon = crate::fs::VirtioFsDaemon::start(share, &res.tmp_dir).await?;
            fs_daemons.push(daemon);
        }

        let mut cmd = crate::vmm::build_vmm_cmd(&self.binary_path, res.netns_name.as_deref());

        cmd.arg("-M")
            .arg("q35,memory-backend=mem")
            .arg("-m")
            .arg(cfg.mem_mib.to_string())
            .arg("-smp")
            .arg(cfg.vcpus.to_string())
            .arg("-nodefaults")
            .arg("-no-user-config")
            .arg("-nographic")
            .arg("-cpu")
            .arg("host")
            .arg("-enable-kvm")
            .arg("-trace")
            .arg("vhost_user_*")
            .arg("-object")
            .arg(format!(
                "memory-backend-file,id=mem,size={}M,mem-path=/dev/shm,share=on",
                cfg.mem_mib
            ))
            .arg("-qmp")
            .arg(format!("unix:{},server,nowait", qmp_socket.display()))
            .arg("-serial")
            .arg(format!("file:{}", serial_path.display()));

        // QEMU's unprivileged control plane is always the external vhost-device-vsock
        // daemon (required and confirmed healthy above), so attach it unconditionally.
        // The old silent fallback to the root-only internal vhost-vsock-pci is gone
        // (M-VMM-2): it had no config selector and only served to mask a daemon
        // failure as a later agent-handshake timeout.
        cmd.arg("-chardev")
            .arg(format!("socket,id=vvsock,path={}", vhost_vsock.display()))
            .arg("-device")
            .arg("vhost-user-vsock-pci,chardev=vvsock");

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
            crate::config::RootfsSource::VirtioFs { .. } => {}
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
                .arg(format!(
                    "tap,id=net0,ifname={},script=no,downscript=no",
                    tap
                ))
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

        let mut cmdline = format!(
            "console=ttyS0 root=/dev/vda rootfstype={} ro {} panic=1 init=/usr/sbin/vmcell-guest-agent vmcell_vmid={}",
            match &cfg.rootfs {
                crate::config::RootfsSource::Erofs { .. } => "erofs",
                _ => "ext4",
            },
            match &cfg.rootfs {
                crate::config::RootfsSource::Erofs { .. } => "",
                _ => "rootflags=noload",
            },
            res.vmid
        );
        if !matches!(cfg.net, crate::config::NetConfig::None) {
            let (host_ip, guest_ip, _) = crate::net::ip_math(res.vmid)?;
            cmdline.push_str(&format!(
                " ip={}::{}:255.255.255.252::eth0:off",
                guest_ip, host_ip
            ));
        }
        if cfg.nested_virt {
            cmdline.push_str(" kvm-intel.nested=1 kvm-amd.nested=1");
        }
        crate::config::push_share_args(&mut cmdline, &cfg.shares);
        cmd.arg("-kernel")
            .arg(&cfg.kernel)
            .arg("-append")
            .arg(&cmdline);

        if snapshot_dir.is_some() {
            cmd.arg("-incoming").arg("defer");
        }

        let cmd_str = format!("{:?}", cmd);
        tracing::info!("QEMU CMD: {}", cmd_str);

        let mut process = cmd
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()?;

        // Capture the process-group id immediately: from here on any error must reap
        // the spawned VMM group, or it leaks (the owning instance — whose Drop reaps
        // — is not constructed until the caller).
        let pgid = process.id();

        if let Some(pid) = process.id() {
            if let Err(e) = cgroups.add_task(&res.cgroup_name, pid) {
                crate::vmm::reap_process_group(&mut process, pgid);
                return Err(e);
            }
        }

        if let Err(e) = crate::vmm::wait_for_socket(&qmp_socket, &mut process, 1000, 20).await {
            crate::vmm::reap_process_group(&mut process, pgid);
            return Err(Error::Vmm(format!("QMP socket failed to appear: {}", e)));
        }

        // All post-spawn fallible steps succeeded; disarm the guard and hand the
        // daemon to the caller, which constructs the long-lived QemuInstance whose
        // Drop now owns the daemon's teardown.
        let (vsock_daemon, vsock_pgid) = vsock_guard.into_inner();

        Ok((
            qmp_socket,
            vsock_path,
            serial_path,
            process,
            vsock_daemon,
            fs_daemons,
            pgid,
            vsock_pgid,
        ))
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
        let (
            qmp_socket,
            vsock_path,
            serial_path,
            process,
            vsock_daemon,
            fs_daemons,
            pgid,
            vsock_pgid,
        ) = self.spawn_qemu(cfg, res, cgroups, None).await?;
        Ok(QemuInstance {
            process,
            qmp_socket,
            vsock_path,
            serial_path,
            _fs_daemons: fs_daemons,
            _vsock_daemon: vsock_daemon,
            cid: res.guest_cid,
            pgid,
            vsock_pgid,
        })
    }

    async fn restore(
        &self,
        _snapshot_dir: &Path,
        _cfg: &VmConfig,
        _res: &PerVmResources,
        _cgroups: &dyn crate::metrics::CgroupFs,
    ) -> Result<Self::Instance> {
        Err(Error::Unsupported {
            vmm: "qemu".to_string(),
            feature: "snapshot_restore".to_string(),
        })
    }

    fn capabilities(&self) -> VmmCapabilities {
        VmmCapabilities {
            snapshot_restore: false,
            lazy_restore: false,
            virtio_fs_shares: true,
            unprivileged_vhost_user_net: true,
            nested_virt: true,
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
            let _ = nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(-(pgid as i32)),
                nix::sys::signal::Signal::SIGKILL,
            );
        }
        let _ = self.process.wait().await;

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

    async fn snapshot(&mut self, _dir: &Path) -> Result<()> {
        Err(Error::Unsupported {
            vmm: "qemu".to_string(),
            feature: "snapshot_restore".to_string(),
        })
    }

    fn vsock_path(&self) -> &Path {
        &self.vsock_path
    }

    fn guest_cid(&self) -> u32 {
        self.cid
    }

    fn serial_log(&self) -> &Path {
        &self.serial_path
    }
}

impl Drop for QemuInstance {
    fn drop(&mut self) {
        // Teardown order (AGENTS.md): VMM process group first — reaping it before
        // touching the daemons, sockets or the per-VM directory means cleanup never
        // races a live VMM.
        if let Some(pgid) = self.pgid {
            let _ = nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(-(pgid as i32)),
                nix::sys::signal::Signal::SIGKILL,
            );
            if let Some(pid) = self.process.id() {
                let _ = nix::sys::wait::waitpid(nix::unistd::Pid::from_raw(pid as i32), None);
            }
        }
        // vhost-user daemons next: the external vhost-device-vsock and each virtiofsd
        // own sockets that live inside `tmp_dir`, so they must be reaped before that
        // directory is removed.
        if let Some(d) = self._vsock_daemon.as_mut() {
            if let Some(v_pgid) = self.vsock_pgid {
                let _ = nix::sys::signal::kill(
                    nix::unistd::Pid::from_raw(-(v_pgid as i32)),
                    nix::sys::signal::Signal::SIGKILL,
                );
                if let Some(pid) = d.id() {
                    let _ = nix::sys::wait::waitpid(nix::unistd::Pid::from_raw(pid as i32), None);
                }
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
