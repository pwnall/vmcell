//! QEMU VMM backend.
//!
//! Provides the [`Qemu`] implementation of the `Vmm` trait.

use crate::config::VmConfig;
use crate::error::{Error, Result};
use crate::metrics::ResourceUsage;
use crate::vmm::{PerVmResources, VmInstance, Vmm, VmmCapabilities};
use std::path::{Path, PathBuf};
use std::process::Stdio;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::process::{Child, Command};

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
    cgroup_name: Option<String>,
    cid: u32,
    restored: bool,
}

impl QemuInstance {
    async fn qmp_command(&self, cmd: &str) -> Result<String> {
        let mut stream = UnixStream::connect(&self.qmp_socket)
            .await
            .map_err(|e| Error::Vmm(format!("qmp connect: {}", e)))?;
        
        let (r, mut w) = stream.split();
        let mut reader = BufReader::new(r);
        let mut line = String::new();
        
        // Read greeting
        reader.read_line(&mut line).await
            .map_err(|e| Error::Vmm(format!("qmp read greeting: {}", e)))?;
            
        // Send capabilities
        w.write_all(b"{\"execute\": \"qmp_capabilities\"}\n").await
            .map_err(|e| Error::Vmm(format!("qmp write caps: {}", e)))?;
            
        line.clear();
        reader.read_line(&mut line).await
            .map_err(|e| Error::Vmm(format!("qmp read caps: {}", e)))?;
            
        // Send command
        w.write_all(cmd.as_bytes()).await
            .map_err(|e| Error::Vmm(format!("qmp write cmd: {}", e)))?;
        w.write_all(b"\n").await
            .map_err(|e| Error::Vmm(format!("qmp write nl: {}", e)))?;
            
        line.clear();
        reader.read_line(&mut line).await
            .map_err(|e| Error::Vmm(format!("qmp read response: {}", e)))?;
            
        Ok(line)
    }
}

impl Qemu {
    async fn spawn_qemu(
        &self,
        cfg: &VmConfig,
        res: &PerVmResources,
        snapshot_dir: Option<&Path>,
    ) -> Result<(PathBuf, PathBuf, PathBuf, PathBuf, Child, Option<Child>, Vec<crate::fs::VirtioFsDaemon>)> {
        let tmp = std::env::temp_dir().join(format!("imp-vm-{}-{}", std::process::id(), res.vmid));
        tokio::fs::create_dir_all(&tmp).await?;

        let qmp_socket = tmp.join("qmp.sock");
        let vsock_path = tmp.join("vsock.sock"); // host connects here
        let vhost_vsock = tmp.join("vhost-vsock.sock"); // qemu connects here
        let serial_path = tmp.join("serial.log");

        // Spawn vhost-device-vsock
        let vsock_daemon = Command::new("vhost-device-vsock")
            .arg("--guest-cid")
            .arg(res.guest_cid.to_string())
            .arg("--socket")
            .arg(&vhost_vsock)
            .arg("--uds-path")
            .arg(&vsock_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .ok();

        if vsock_daemon.is_some() {
            // Wait for vhost-vsock socket to appear
            let mut ready = false;
            for _ in 0..50 {
                if tokio::fs::try_exists(&vhost_vsock).await.unwrap_or(false) {
                    ready = true;
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
            if !ready {
                return Err(Error::Vmm("vhost-device-vsock failed to start".into()));
            }
        }

        let mut fs_daemons = Vec::new();
        for share in &cfg.shares {
            let daemon = crate::fs::VirtioFsDaemon::start(share, &tmp).await?;
            fs_daemons.push(daemon);
        }

        let mut cmd = if let Some(netns) = &res.netns_name {
            let mut c = Command::new("ip");
            c.arg("netns").arg("exec").arg(netns).arg(&self.binary_path);
            c
        } else {
            Command::new(&self.binary_path)
        };

        cmd.arg("-M").arg("q35,memory-backend=mem")
           .arg("-m").arg(cfg.mem_mib.to_string())
           .arg("-smp").arg(cfg.vcpus.to_string())
           .arg("-nodefaults")
           .arg("-no-user-config")
           .arg("-nographic")
           .arg("-cpu").arg("host")
           .arg("-enable-kvm")
           .arg("-trace").arg("vhost_user_*")
           .arg("-object").arg(format!("memory-backend-file,id=mem,size={}M,mem-path=/dev/shm,share=on", cfg.mem_mib))
           .arg("-qmp").arg(format!("unix:{},server,nowait", qmp_socket.display()))
           .arg("-serial").arg(format!("file:{}", serial_path.display()));

        if vsock_daemon.is_some() {
            cmd.arg("-chardev").arg(format!("socket,id=vvsock,path={}", vhost_vsock.display()))
               .arg("-device").arg("vhost-user-vsock-pci,chardev=vvsock");
        } else {
            // fallback to internal vsock if module loaded (requires root, usually avoid)
            cmd.arg("-device").arg(format!("vhost-vsock-pci,guest-cid={}", res.guest_cid));
        }

        match &cfg.rootfs {
            crate::config::RootfsSource::Erofs { image } => {
                cmd.arg("-drive").arg(format!("file={},format=raw,id=rfs,if=none,readonly=on,file.locking=off", image.display()))
                   .arg("-device").arg("virtio-blk-pci,drive=rfs");
            }
            crate::config::RootfsSource::Block { image, overlay } => {
                cmd.arg("-drive").arg(format!("file={},format=raw,id=rfs,if=none,file.locking=off", overlay.as_ref().unwrap_or(image).display()))
                   .arg("-device").arg("virtio-blk-pci,drive=rfs");
            }
            crate::config::RootfsSource::VirtioFs { .. } => {}
        }

        for (i, (share, daemon)) in cfg.shares.iter().zip(fs_daemons.iter()).enumerate() {
            cmd.arg("-chardev").arg(format!("socket,id=vfs{},path={}", i, daemon.socket_path.display()))
               .arg("-device").arg(format!("vhost-user-fs-device,chardev=vfs{},tag={}", i, share.tag));
        }

        if let Some(tap) = &res.tap_name {
            cmd.arg("-netdev").arg(format!("tap,id=net0,ifname={},script=no,downscript=no", tap))
               .arg("-device").arg("virtio-net-pci,netdev=net0");
        } else if let Some(socket) = &res.vhost_user_socket {
            cmd.arg("-chardev").arg(format!("socket,id=net0,path={}", socket.display()))
               .arg("-netdev").arg("vhost-user,id=vnet0,chardev=net0,vhostforce=on")
               .arg("-device").arg(format!("virtio-net-pci,netdev=vnet0,mac=02:00:{:02x}:{:02x}:{:02x}:{:02x}", 
                                (res.vmid >> 24) & 0xff, (res.vmid >> 16) & 0xff, (res.vmid >> 8) & 0xff, res.vmid & 0xff));
        }

        if snapshot_dir.is_some() {
            cmd.arg("-incoming").arg("defer");
        } else {
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
                cmdline.push_str(&format!(
                    " ip=10.200.{}.2::10.200.{}.1:255.255.255.252::eth0:off",
                    res.vmid, res.vmid
                ));
            }
            cmd.arg("-kernel").arg(&cfg.kernel)
               .arg("-append").arg(&cmdline);
        }

        let process = cmd
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()?;

        if let Some(pid) = process.id() {
            if !res.cgroup_name.is_empty() {
                let procs_path = format!("/sys/fs/cgroup/{}/cgroup.procs", res.cgroup_name);
                let _ = tokio::fs::write(&procs_path, pid.to_string()).await;
            }
        }

        let mut socket_ready = false;
        for _ in 0..50 {
            if tokio::fs::try_exists(&qmp_socket).await.unwrap_or(false) {
                socket_ready = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }

        if !socket_ready {
            return Err(Error::Vmm("QMP socket failed to appear".into()));
        }

        Ok((tmp, qmp_socket, vsock_path, serial_path, process, vsock_daemon, fs_daemons))
    }
}

impl Vmm for Qemu {
    type Instance = QemuInstance;

    async fn create(&self, cfg: &VmConfig, res: &PerVmResources) -> Result<Self::Instance> {
        let (_tmp, qmp_socket, vsock_path, serial_path, process, vsock_daemon, fs_daemons) = self.spawn_qemu(cfg, res, None).await?;
        Ok(QemuInstance {
            process,
            qmp_socket,
            vsock_path,
            serial_path,
            _fs_daemons: fs_daemons,
            _vsock_daemon: vsock_daemon,
            cgroup_name: Some(res.cgroup_name.clone()),
            cid: res.guest_cid,
            restored: false,
        })
    }

    async fn restore(&self, snapshot_dir: &Path, cfg: &VmConfig, res: &PerVmResources) -> Result<Self::Instance> {
        let (_tmp, qmp_socket, vsock_path, serial_path, process, vsock_daemon, fs_daemons) = self.spawn_qemu(cfg, res, Some(snapshot_dir)).await?;
        let instance = QemuInstance {
            process,
            qmp_socket,
            vsock_path,
            serial_path,
            _fs_daemons: fs_daemons,
            _vsock_daemon: vsock_daemon,
            cgroup_name: Some(res.cgroup_name.clone()),
            cid: res.guest_cid,
            restored: true,
        };
        
        let migrate_cmd = format!(
            "{{\"execute\": \"migrate-incoming\", \"arguments\": {{\"uri\": \"exec:cat {}\"}}}}",
            snapshot_dir.join("state.bin").display()
        );
        instance.qmp_command(&migrate_cmd).await?;
        
        // Wait for migration to complete
        for _ in 0..50 {
            let res = instance.qmp_command("{\"execute\": \"query-migrate\"}").await?;
            if res.contains("\"status\": \"completed\"") {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        
        Ok(instance)
    }

    fn capabilities(&self) -> VmmCapabilities {
        VmmCapabilities {
            snapshot_restore: true,
            lazy_restore: false,
            virtio_fs_shares: true,
            rootless_vhost_user_net: true,
            nested_virt: true,
        }
    }
}

impl VmInstance for QemuInstance {
    async fn boot(&mut self) -> Result<()> {
        if !self.restored {
            self.qmp_command("{\"execute\": \"cont\"}").await?;
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
        self.qmp_command("{\"execute\": \"system_powerdown\"}").await?;
        Ok(())
    }

    async fn kill(&mut self) -> Result<()> {
        self.qmp_command("{\"execute\": \"quit\"}").await.ok();
        let _ = self.process.start_kill();
        if let Some(mut d) = self._vsock_daemon.take() {
            let _ = d.start_kill();
        }
        Ok(())
    }

    async fn snapshot(&mut self, dir: &Path) -> Result<()> {
        self.qmp_command("{\"execute\": \"stop\"}").await?;
        
        let state_path = dir.join("state.bin");
        let migrate_cmd = format!(
            "{{\"execute\": \"migrate\", \"arguments\": {{\"uri\": \"exec:cat > {}\"}}}}",
            state_path.display()
        );
        self.qmp_command(&migrate_cmd).await?;
        
        // Wait for migration to complete
        for _ in 0..50 {
            let res = self.qmp_command("{\"execute\": \"query-migrate\"}").await?;
            if res.contains("\"status\": \"completed\"") {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        
        self.qmp_command("{\"execute\": \"cont\"}").await?;
        Ok(())
    }

    async fn stats(&self) -> Result<ResourceUsage> {
        let mut usage = ResourceUsage::default();
        #[cfg(feature = "metrics")]
        {
            if let Some(cg_name) = &self.cgroup_name {
                let cg = cgroups_rs::Cgroup::load(Box::new(cgroups_rs::hierarchies::V2::new()), cg_name);
                for sub in cg.subsystems() {
                    match sub {
                        cgroups_rs::Subsystem::Mem(_) => {
                            let base_path = format!("/sys/fs/cgroup/{}", cg_name);
                            if let Ok(s) = std::fs::read_to_string(format!("{}/memory.current", base_path)) {
                                if let Ok(val) = s.trim().parse::<u64>() {
                                    usage.mem_current_mib = val / 1024 / 1024;
                                }
                            }
                            if let Ok(s) = std::fs::read_to_string(format!("{}/memory.peak", base_path)) {
                                if let Ok(val) = s.trim().parse::<u64>() {
                                    usage.mem_peak_mib = val / 1024 / 1024;
                                }
                            }
                        }
                        cgroups_rs::Subsystem::Cpu(c) => {
                            let stat = c.cpu().stat;
                            for line in stat.lines() {
                                if let Some(val) = line.strip_prefix("usage_usec ").and_then(|s| s.parse::<u64>().ok()) {
                                    usage.cpu_usec = val;
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
        Ok(usage)
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
        let _ = self.process.start_kill();
        if let Some(mut d) = self._vsock_daemon.take() {
            let _ = d.start_kill();
        }
        let _ = std::fs::remove_file(&self.qmp_socket);
        let _ = std::fs::remove_file(&self.vsock_path);
        
        #[cfg(feature = "metrics")]
        if let Some(cg_name) = &self.cgroup_name {
            let cg = cgroups_rs::Cgroup::load(Box::new(cgroups_rs::hierarchies::V2::new()), cg_name);
            let _ = cg.delete();
        }
    }
}
