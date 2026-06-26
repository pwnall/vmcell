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

            // Send command
            w.write_all(cmd.as_bytes()).await?;
            w.write_all(b"\n").await?;

            line.clear();
            reader.read_line(&mut line).await?;

            Ok::<String, std::io::Error>(line)
        })
        .await
        .map_err(|_| Error::Qmp("Timeout waiting for QMP response".into()))?
        .map_err(Error::Io)
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
        PathBuf,
        Child,
        Option<Child>,
        Vec<crate::fs::VirtioFsDaemon>,
        Option<u32>,
        Option<u32>,
    )> {
        let tmp = crate::vmm::create_vm_tmp_dir(res.vmid).await?;

        let qmp_socket = tmp.join("qmp.sock");
        let vsock_path = tmp.join("vsock.sock"); // host connects here
        let vhost_vsock = tmp.join("vhost-vsock.sock"); // qemu connects here
        let serial_path = tmp.join("serial.log");

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

        let mut vsock_daemon = tokio::process::Command::from(std_vsock_cmd)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .ok();

        let vsock_pgid = vsock_daemon.as_ref().and_then(|d| d.id());

        if let Some(daemon) = vsock_daemon.as_mut() {
            // Wait for vhost-vsock socket to appear
            if let Err(e) = crate::vmm::wait_for_socket(&vhost_vsock, daemon, 1000, 20).await {
                return Err(Error::Vmm(format!(
                    "vhost-device-vsock failed to start: {}",
                    e
                )));
            }
        }

        let mut fs_daemons = Vec::new();
        for share in &cfg.shares {
            let daemon = crate::fs::VirtioFsDaemon::start(share, &tmp).await?;
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

        if vsock_daemon.is_some() {
            cmd.arg("-chardev")
                .arg(format!("socket,id=vvsock,path={}", vhost_vsock.display()))
                .arg("-device")
                .arg("vhost-user-vsock-pci,chardev=vvsock");
        } else {
            // fallback to internal vsock if module loaded (requires root, usually avoid)
            cmd.arg("-device")
                .arg(format!("vhost-vsock-pci,guest-cid={}", res.guest_cid));
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
            "console=ttyS0 root=/dev/vda rootfstype={} ro {} panic=1 init=/usr/sbin/imp-guest-agent imp_vmid={}",
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

        if let Some(pid) = process.id() {
            cgroups.add_task(&res.cgroup_name, pid)?;
        }

        if let Err(e) = crate::vmm::wait_for_socket(&qmp_socket, &mut process, 1000, 20).await {
            return Err(Error::Vmm(format!("QMP socket failed to appear: {}", e)));
        }

        let pgid = process.id();

        Ok((
            tmp,
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
            _tmp,
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
        let res = self.qmp_command("{\"execute\": \"cont\"}").await?;
        if res.contains("\"error\"") {
            return Err(Error::Qmp(format!("qmp cont error: {}", res)));
        }
        Ok(())
    }

    async fn pause(&mut self) -> Result<()> {
        self.qmp_command("{\"execute\": \"stop\"}").await?;
        Ok(())
    }

    async fn resume(&mut self) -> Result<()> {
        self.qmp_command("{\"execute\": \"cont\"}").await?;
        Ok(())
    }

    async fn request_shutdown(&mut self) -> Result<()> {
        self.qmp_command("{\"execute\": \"system_powerdown\"}")
            .await?;
        Ok(())
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
        if let Some(pgid) = self.pgid {
            let _ = nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(-(pgid as i32)),
                nix::sys::signal::Signal::SIGKILL,
            );
            if let Some(pid) = self.process.id() {
                let _ = nix::sys::wait::waitpid(nix::unistd::Pid::from_raw(pid as i32), None);
            }
        }
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
        let _ = std::fs::remove_file(&self.qmp_socket);
        let _ = std::fs::remove_file(&self.vsock_path);
    }
}
