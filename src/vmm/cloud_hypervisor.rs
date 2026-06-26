//! Cloud Hypervisor VMM backend.
//!
//! Provides the [`CloudHypervisor`] implementation of the `Vmm` trait,
//! along with the `ChInstance` running VM instance.

use crate::config::VmConfig;
use crate::error::{Error, Result};
use crate::vmm::{PerVmResources, VmInstance, Vmm, VmmCapabilities};
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::process::Stdio;

use tokio::process::Child;

/// The Cloud Hypervisor VMM backend.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct CloudHypervisor {
    /// Path to the `cloud-hypervisor` executable.
    pub binary_path: PathBuf,
}

impl CloudHypervisor {
    /// Creates a new `CloudHypervisor` using the specified executable path.
    #[must_use]
    pub fn new(binary_path: impl Into<PathBuf>) -> Self {
        Self {
            binary_path: binary_path.into(),
        }
    }
}

/// A running instance of a Cloud Hypervisor VM.
#[derive(Debug)]
#[non_exhaustive]
pub struct ChInstance {
    process: Child,
    api_socket: PathBuf,
    vsock_path: PathBuf,
    serial_path: PathBuf,
    _fs_daemons: Vec<crate::fs::VirtioFsDaemon>,
    cgroup_name: Option<String>,
    restored: bool,
    cid: u32,
    pgid: Option<u32>,
}

#[derive(Serialize)]
struct ChVmConfig {
    cpus: ChCpus,
    memory: ChMemory,
    payload: ChPayload,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    disks: Vec<ChDisk>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    fs: Vec<ChFs>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    net: Vec<ChNet>,
    serial: ChSerial,
    vsock: ChVsock,
}

#[derive(Serialize)]
struct ChCpus {
    boot_vcpus: u8,
    max_vcpus: u8,
}

#[derive(Serialize)]
struct ChMemory {
    size: u64,
    shared: bool,
}

#[derive(Serialize)]
struct ChPayload {
    kernel: PathBuf,
    cmdline: String,
}

#[derive(Serialize)]
struct ChDisk {
    path: PathBuf,
    readonly: bool,
    direct: bool,
}

#[derive(Serialize)]
struct ChFs {
    tag: String,
    socket: PathBuf,
    num_queues: usize,
    queue_size: usize,
}

#[derive(Serialize)]
struct ChNet {
    #[serde(skip_serializing_if = "Option::is_none")]
    tap: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mac: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    vhost_user: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    vhost_mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    vhost_socket: Option<PathBuf>,
}

#[derive(Serialize)]
struct ChSerial {
    mode: String,
    file: PathBuf,
}

#[derive(Serialize)]
struct ChVsock {
    cid: u32,
    socket: PathBuf,
}

impl ChInstance {
    async fn api_request(
        &self,
        method: &str,
        path: &str,
        body: Option<&impl Serialize>,
    ) -> Result<()> {
        crate::vmm::unix_api_request(&self.api_socket, method, path, body).await
    }
}

impl CloudHypervisor {
    async fn spawn_ch(
        &self,
        res: &PerVmResources,
        snapshot_dir: Option<&Path>,
        cgroups: &dyn crate::metrics::CgroupFs,
    ) -> Result<(
        std::path::PathBuf,
        std::path::PathBuf,
        std::path::PathBuf,
        std::path::PathBuf,
        tokio::process::Child,
        Option<u32>,
    )> {
        let tmp = crate::vmm::create_vm_tmp_dir(res.vmid).await?;

        let api_socket = tmp.join("api.sock");
        let vsock_path = tmp.join("vsock.sock");
        let serial_path = tmp.join("serial.log");

        let mut cmd = crate::vmm::build_vmm_cmd(&self.binary_path, res.netns_name.as_deref());

        if let Some(dir) = snapshot_dir {
            cmd.arg("--restore")
                .arg(format!("source_url=file://{}", dir.display()));
        }

        let process = cmd
            .arg("--api-socket")
            .arg(&api_socket)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()?;

        if let Some(pid) = process.id() {
            cgroups.add_task(&res.cgroup_name, pid)?;
        }

        if !crate::vmm::wait_for_socket(&api_socket, 1000, 20).await {
            return Err(Error::Vmm("API socket failed to appear".into()));
        }

        let pgid = process.id();
        Ok((tmp, api_socket, vsock_path, serial_path, process, pgid))
    }
}

impl Vmm for CloudHypervisor {
    type Instance = ChInstance;

    async fn create(
        &self,
        cfg: &VmConfig,
        res: &PerVmResources,
        cgroups: &dyn crate::metrics::CgroupFs,
    ) -> Result<Self::Instance> {
        let (tmp, api_socket, vsock_path, serial_path, process, pgid) =
            self.spawn_ch(res, None, cgroups).await?;

        let mut fs_daemons = Vec::new();
        let mut ch_fs = Vec::new();

        for share in &cfg.shares {
            let daemon = crate::fs::VirtioFsDaemon::start(share, &tmp).await?;
            ch_fs.push(ChFs {
                tag: share.tag.clone(),
                socket: daemon.socket_path.clone(),
                num_queues: 1,
                queue_size: 1024,
            });
            fs_daemons.push(daemon);
        }

        let cid = res.guest_cid;

        let instance = ChInstance {
            process,
            api_socket,
            vsock_path: vsock_path.clone(),
            serial_path: serial_path.clone(),
            _fs_daemons: fs_daemons,
            cgroup_name: Some(res.cgroup_name.clone()),
            restored: false,
            cid,
            pgid,
        };

        let mut ch_cfg = ChVmConfig {
            cpus: ChCpus {
                boot_vcpus: cfg.vcpus,
                max_vcpus: cfg.vcpus,
            },
            memory: ChMemory {
                size: (cfg.mem_mib as u64) << 20,
                shared: true,
            },
            payload: ChPayload {
                kernel: cfg.kernel.clone(),
                cmdline: {
                    let mut s = format!(
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
                        assert!(
                            res.vmid <= 254,
                            "vmid must be <= 254 for network configuration"
                        );
                        s.push_str(&format!(
                            " ip=10.200.{}.2::10.200.{}.1:255.255.255.252::eth0:off",
                            res.vmid, res.vmid
                        ));
                    }
                    if cfg.nested_virt {
                        s.push_str(" kvm-intel.nested=1 kvm-amd.nested=1");
                    }
                    s
                },
            },
            disks: vec![],
            fs: ch_fs,
            net: vec![],
            serial: ChSerial {
                mode: "File".into(),
                file: serial_path,
            },
            vsock: ChVsock {
                cid,
                socket: vsock_path,
            },
        };

        if let Some(tap) = &res.tap_name {
            ch_cfg.net.push(ChNet {
                tap: Some(tap.clone()),
                mac: None,
                vhost_user: None,
                vhost_mode: None,
                vhost_socket: None,
            });
        } else if let Some(socket) = &res.vhost_user_socket {
            assert!(res.vmid <= 254, "vmid must be <= 254 for MAC configuration");
            ch_cfg.net.push(ChNet {
                tap: None,
                mac: Some(format!(
                    "02:00:{:02x}:{:02x}:{:02x}:{:02x}",
                    (res.vmid >> 24) & 0xff,
                    (res.vmid >> 16) & 0xff,
                    (res.vmid >> 8) & 0xff,
                    res.vmid & 0xff
                )),
                vhost_user: Some(true),
                vhost_mode: Some("Client".to_string()),
                vhost_socket: Some(socket.clone()),
            });
        }

        match &cfg.rootfs {
            crate::config::RootfsSource::Erofs { image } => {
                ch_cfg.disks.push(ChDisk {
                    path: image.clone(),
                    readonly: true,
                    direct: false,
                });
            }
            crate::config::RootfsSource::Block { image, overlay } => {
                ch_cfg.disks.push(ChDisk {
                    path: overlay.as_ref().unwrap_or(image).clone(),
                    readonly: false,
                    direct: false,
                });
            }
            crate::config::RootfsSource::VirtioFs { .. } => {}
        }

        instance
            .api_request("PUT", "/api/v1/vm.create", Some(&ch_cfg))
            .await?;

        Ok(instance)
    }

    async fn restore(
        &self,
        snapshot_dir: &Path,
        cfg: &VmConfig,
        res: &PerVmResources,
        cgroups: &dyn crate::metrics::CgroupFs,
    ) -> Result<Self::Instance> {
        let (tmp, api_socket, vsock_path, serial_path, process, pgid) =
            self.spawn_ch(res, Some(snapshot_dir), cgroups).await?;

        let mut fs_daemons = Vec::new();
        for share in &cfg.shares {
            let daemon = crate::fs::VirtioFsDaemon::start(share, &tmp).await?;
            fs_daemons.push(daemon);
        }

        let cid = res.guest_cid;

        let instance = ChInstance {
            process,
            api_socket,
            vsock_path,
            serial_path,
            _fs_daemons: fs_daemons,
            cgroup_name: Some(res.cgroup_name.clone()),
            restored: true,
            cid,
            pgid,
        };

        Ok(instance)
    }

    fn capabilities(&self) -> VmmCapabilities {
        VmmCapabilities {
            snapshot_restore: true,
            lazy_restore: true, // CH supports memory_restore_mode
            virtio_fs_shares: true,
            unprivileged_vhost_user_net: true,
            nested_virt: true,
        }
    }
}

impl VmInstance for ChInstance {
    async fn boot(&mut self) -> Result<()> {
        if self.restored {
            self.api_request("PUT", "/api/v1/vm.resume", None::<&()>)
                .await
        } else {
            self.api_request("PUT", "/api/v1/vm.boot", None::<&()>)
                .await
        }
    }

    async fn request_shutdown(&mut self) -> Result<()> {
        self.api_request("PUT", "/api/v1/vm.shutdown", None::<&()>)
            .await
    }

    async fn kill(&mut self) -> Result<()> {
        if let Some(pgid) = self.pgid {
            let _ = nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(-(pgid as i32)),
                nix::sys::signal::Signal::SIGKILL,
            );
        }
        let _ = self.process.wait().await;
        Ok(())
    }

    async fn pause(&mut self) -> Result<()> {
        self.api_request("PUT", "/api/v1/vm.pause", None::<&()>)
            .await
    }

    async fn resume(&mut self) -> Result<()> {
        self.api_request("PUT", "/api/v1/vm.resume", None::<&()>)
            .await
    }

    async fn snapshot(&mut self, dir: &Path) -> Result<()> {
        #[derive(Serialize)]
        struct SnapshotReq {
            destination_url: String,
        }
        let req = SnapshotReq {
            destination_url: format!("file://{}", dir.display()),
        };
        self.api_request("PUT", "/api/v1/vm.pause", None::<&()>)
            .await?;
        let res = self
            .api_request("PUT", "/api/v1/vm.snapshot", Some(&req))
            .await;
        if let Err(e) = self
            .api_request("PUT", "/api/v1/vm.resume", None::<&()>)
            .await
        {
            tracing::warn!("Failed to resume VM after snapshot: {}", e);
        }
        res
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

impl Drop for ChInstance {
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
        let _ = std::fs::remove_file(&self.api_socket);
        let _ = std::fs::remove_file(&self.vsock_path);
        #[cfg(feature = "metrics")]
        if let Some(cg_name) = &self.cgroup_name {
            let cg =
                cgroups_rs::Cgroup::load(Box::new(cgroups_rs::hierarchies::V2::new()), cg_name);
            let _ = cg.delete();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ch_vm_config_serialization() {
        let cfg = ChVmConfig {
            cpus: ChCpus {
                boot_vcpus: 2,
                max_vcpus: 2,
            },
            memory: ChMemory {
                size: 1024,
                shared: true,
            },
            payload: ChPayload {
                kernel: PathBuf::from("/vmlinux"),
                cmdline: "console=ttyS0".into(),
            },
            disks: vec![],
            fs: vec![],
            net: vec![],
            serial: ChSerial {
                mode: "File".into(),
                file: PathBuf::from("/serial.log"),
            },
            vsock: ChVsock {
                cid: 3,
                socket: PathBuf::from("/vsock.sock"),
            },
        };
        let json = serde_json::to_string(&cfg).unwrap();
        assert!(json.contains("\"boot_vcpus\":2"));
        assert!(!json.contains("\"disks\"")); // skip_serializing_if empty
        assert!(
            json.contains("\"payload\":{\"kernel\":\"/vmlinux\",\"cmdline\":\"console=ttyS0\"}")
        );
    }
}
