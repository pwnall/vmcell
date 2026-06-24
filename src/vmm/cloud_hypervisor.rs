//! Cloud Hypervisor VMM backend.
//!
//! Provides the [`CloudHypervisor`] implementation of the `Vmm` trait,
//! along with the `ChInstance` running VM instance.

use crate::config::VmConfig;
use crate::error::{Error, Result};
use crate::metrics::ResourceUsage;
use crate::vmm::{PerVmResources, VmInstance, Vmm, VmmCapabilities};
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::process::Stdio;

use tokio::net::UnixStream;
use tokio::process::{Child, Command};

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
        let stream = UnixStream::connect(&self.api_socket)
            .await
            .map_err(|e| Error::Vmm(format!("socket connect: {}", e)))?;

        let io = hyper_util::rt::TokioIo::new(stream);
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
            .await
            .map_err(|e| Error::Vmm(format!("handshake error: {}", e)))?;

        tokio::task::spawn(async move {
            if let Err(err) = conn.await {
                tracing::warn!("HTTP connection failed: {:?}", err);
            }
        });

        let body_bytes = if let Some(b) = body {
            serde_json::to_vec(b).map_err(|e| Error::Serialize(format!("serialize: {}", e)))?
        } else {
            Vec::new()
        };

        let req = hyper::Request::builder()
            .method(method)
            .uri(path)
            .header("Host", "localhost")
            .header("Content-Type", "application/json")
            .body(http_body_util::Full::new(hyper::body::Bytes::from(
                body_bytes,
            )))
            .map_err(|e| Error::Vmm(format!("request builder error: {}", e)))?;

        let res = sender
            .send_request(req)
            .await
            .map_err(|e| Error::Vmm(format!("send_request error: {}", e)))?;

        if !res.status().is_success() {
            let status = res.status();
            use http_body_util::BodyExt;
            let bytes = res
                .into_body()
                .collect()
                .await
                .map(|c| c.to_bytes())
                .unwrap_or_default();
            return Err(Error::VmmApi {
                status: status.as_u16(),
                body: String::from_utf8_lossy(&bytes).into_owned(),
            });
        }

        Ok(())
    }
}

impl CloudHypervisor {
    async fn spawn_ch(
        &self,
        res: &PerVmResources,
        snapshot_dir: Option<&Path>,
    ) -> Result<(
        std::path::PathBuf,
        std::path::PathBuf,
        std::path::PathBuf,
        std::path::PathBuf,
        tokio::process::Child,
    )> {
        let tmp = std::env::temp_dir().join(format!("imp-vm-{}-{}", std::process::id(), res.vmid));
        tokio::fs::create_dir_all(&tmp).await?;

        let api_socket = tmp.join("api.sock");
        let vsock_path = tmp.join("vsock.sock");
        let serial_path = tmp.join("serial.log");

        let mut cmd = if let Some(netns) = &res.netns_name {
            let mut c = Command::new("ip");
            c.arg("netns").arg("exec").arg(netns).arg(&self.binary_path);
            c
        } else {
            Command::new(&self.binary_path)
        };

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
            if !res.cgroup_name.is_empty() {
                let procs_path = format!("/sys/fs/cgroup/{}/cgroup.procs", res.cgroup_name);
                if let Err(e) = tokio::fs::write(&procs_path, pid.to_string()).await {
                    tracing::error!(
                        "WARNING: failed to write process {} to {}: {:?}",
                        pid,
                        procs_path,
                        e
                    );
                } else {
                    tracing::info!("Added process {} to cgroup {}", pid, res.cgroup_name);
                }
            }
        }

        let mut socket_ready = false;
        for _ in 0..50 {
            if tokio::fs::try_exists(&api_socket).await.unwrap_or(false) {
                socket_ready = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }

        if !socket_ready {
            return Err(Error::Vmm("API socket failed to appear".into()));
        }

        Ok((tmp, api_socket, vsock_path, serial_path, process))
    }
}

impl Vmm for CloudHypervisor {
    type Instance = ChInstance;

    async fn create(&self, cfg: &VmConfig, res: &PerVmResources) -> Result<Self::Instance> {
        let (tmp, api_socket, vsock_path, serial_path, process) = self.spawn_ch(res, None).await?;

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
                        "console=ttyS0 root=/dev/vda rootfstype={} ro {} panic=1 init=/sbin/imp-guest-agent imp_vmid={}",
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
                        s.push_str(&format!(
                            " ip=10.200.{}.2::10.200.{}.1:255.255.255.252::eth0:off",
                            res.vmid, res.vmid
                        ));
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
    ) -> Result<Self::Instance> {
        let (tmp, api_socket, vsock_path, serial_path, process) =
            self.spawn_ch(res, Some(snapshot_dir)).await?;

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
        };

        Ok(instance)
    }

    fn capabilities(&self) -> VmmCapabilities {
        VmmCapabilities {
            snapshot_restore: true,
            lazy_restore: true, // CH supports memory_restore_mode
            virtio_fs_shares: true,
            rootless_vhost_user_net: true,
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
        if let Err(e) = self.process.kill().await {
            tracing::warn!("Failed to kill CH process: {}", e);
        }
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

    async fn stats(&self) -> Result<ResourceUsage> {
        let mut usage = ResourceUsage::default();
        #[cfg(feature = "metrics")]
        {
            if let Some(cg_name) = &self.cgroup_name {
                let cg =
                    cgroups_rs::Cgroup::load(Box::new(cgroups_rs::hierarchies::V2::new()), cg_name);
                for sub in cg.subsystems() {
                    match sub {
                        cgroups_rs::Subsystem::Mem(_) => {
                            let base_path = format!("/sys/fs/cgroup/{}", cg_name);
                            if let Ok(s) =
                                std::fs::read_to_string(format!("{}/memory.current", base_path))
                            {
                                if let Ok(val) = s.trim().parse::<u64>() {
                                    usage.mem_current_mib = val / 1024 / 1024;
                                }
                            }
                            if let Ok(s) =
                                std::fs::read_to_string(format!("{}/memory.peak", base_path))
                            {
                                if let Ok(val) = s.trim().parse::<u64>() {
                                    usage.mem_peak_mib = val / 1024 / 1024;
                                }
                            }
                        }
                        cgroups_rs::Subsystem::Cpu(c) => {
                            let stat = c.cpu().stat;
                            for line in stat.lines() {
                                if let Some(val) = line
                                    .strip_prefix("usage_usec ")
                                    .and_then(|s| s.parse::<u64>().ok())
                                {
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

impl Drop for ChInstance {
    fn drop(&mut self) {
        let _ = self.process.start_kill();
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
