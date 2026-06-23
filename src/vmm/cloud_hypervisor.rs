use crate::config::VmConfig;
use crate::error::{Error, Result};
use crate::metrics::ResourceUsage;
use crate::vmm::{PerVmResources, VmInstance, Vmm};
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::process::{Child, Command};

/// The Cloud Hypervisor VMM backend.
pub struct CloudHypervisor {
    /// Path to the `cloud-hypervisor` executable.
    pub binary_path: PathBuf,
}

impl CloudHypervisor {
    /// Creates a new `CloudHypervisor` using the specified executable path.
    pub fn new(binary_path: impl Into<PathBuf>) -> Self {
        Self {
            binary_path: binary_path.into(),
        }
    }
}

/// A running instance of a Cloud Hypervisor VM.
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
        let mut stream = UnixStream::connect(&self.api_socket)
            .await
            .map_err(|e| Error::Vmm(format!("socket connect: {}", e)))?;

        let body_bytes = if let Some(b) = body {
            serde_json::to_vec(b).map_err(|e| Error::Other(format!("serialize: {}", e)))?
        } else {
            Vec::new()
        };

        let req = format!(
            "{} {} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            method,
            path,
            body_bytes.len()
        );

        stream.write_all(req.as_bytes()).await?;
        stream.write_all(&body_bytes).await?;

        let mut resp = vec![0; 4096];
        let n = stream.read(&mut resp).await?;
        let resp_str = String::from_utf8_lossy(&resp[..n]);
        if !resp_str.starts_with("HTTP/1.1 200") && !resp_str.starts_with("HTTP/1.1 204") {
            return Err(Error::Vmm(format!("API error: {}", resp_str)));
        }
        Ok(())
    }
}

use async_trait::async_trait;

#[async_trait]
impl Vmm for CloudHypervisor {
    type Instance = ChInstance;

    async fn create(&self, cfg: &VmConfig, _res: &PerVmResources) -> Result<Self::Instance> {
        let tmp = std::env::temp_dir().join(format!("imp-vm-{}", std::process::id()));
        tokio::fs::create_dir_all(&tmp).await?;

        let api_socket = tmp.join("api.sock");
        let vsock_path = tmp.join("vsock.sock");
        let serial_path = tmp.join("serial.log");

        let mut cmd = if let Some(netns) = &_res.netns_name {
            let mut c = Command::new("ip");
            c.arg("netns").arg("exec").arg(netns).arg(&self.binary_path);
            c
        } else {
            Command::new(&self.binary_path)
        };

        if let Some(snapshot_dir) = &cfg.snapshot_dir {
            cmd.arg("--restore")
                .arg(format!("source_url=file://{}", snapshot_dir.display()));
        }

        let process = cmd
            .arg("--api-socket")
            .arg(&api_socket)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()?;

        if let Some(pid) = process.id() {
            if !_res.cgroup_name.is_empty() {
                let procs_path = format!("/sys/fs/cgroup/{}/cgroup.procs", _res.cgroup_name);
                if let Err(e) = std::fs::write(&procs_path, pid.to_string()) {
                    eprintln!("WARNING: failed to write process {} to {}: {:?}", pid, procs_path, e);
                } else {
                    println!("Added process {} to cgroup {}", pid, _res.cgroup_name);
                }
            }
        }

        for _ in 0..50 {
            if api_socket.exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }

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

        let cid = crate::vmm::CidAllocator::allocate();

        let instance = ChInstance {
            process,
            api_socket,
            vsock_path: vsock_path.clone(),
            serial_path: serial_path.clone(),
            _fs_daemons: fs_daemons,
            cgroup_name: Some(_res.cgroup_name.clone()),
            restored: cfg.snapshot_dir.is_some(),
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
                cmdline: format!(
                    "console=ttyS0 root=/dev/vda rootfstype={} ro {} panic=1 init=/sbin/imp-guest-agent imp_vmid={}",
                    match &cfg.rootfs {
                        crate::config::RootfsSource::Erofs { .. } => "erofs",
                        _ => "ext4",
                    },
                    match &cfg.rootfs {
                        crate::config::RootfsSource::Erofs { .. } => "",
                        _ => "rootflags=noload",
                    },
                    _res.vmid
                ),
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

        if let Some(tap) = &_res.tap_name {
            ch_cfg.net.push(ChNet {
                tap: Some(tap.clone()),
                mac: None,
                vhost_user: None,
                vhost_mode: None,
                vhost_socket: None,
            });
        } else if let Some(socket) = &_res.vhost_user_socket {
            ch_cfg.net.push(ChNet {
                tap: None,
                mac: Some(format!("02:00:00:00:00:{:02x}", _res.vmid)),
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

        if cfg.snapshot_dir.is_none() {
            instance
                .api_request("PUT", "/api/v1/vm.create", Some(&ch_cfg))
                .await?;
        }

        Ok(instance)
    }
}

#[async_trait]
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
        let _ = self.process.kill().await;
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
        let _ = self
            .api_request("PUT", "/api/v1/vm.resume", None::<&()>)
            .await;
        res
    }

    async fn stats(&self) -> Result<ResourceUsage> {
        let mut usage = ResourceUsage::default();
        if let Some(cg_name) = &self.cgroup_name {
            let cg =
                cgroups_rs::Cgroup::load(Box::new(cgroups_rs::hierarchies::V2::new()), cg_name);
            for sub in cg.subsystems() {
                match sub {
                    cgroups_rs::Subsystem::Mem(m) => {
                        let stat = m.memory_stat();
                        usage.mem_current_mib = stat.usage_in_bytes / 1024 / 1024;
                        usage.mem_peak_mib = stat.max_usage_in_bytes / 1024 / 1024;
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
        if let Some(cg_name) = &self.cgroup_name {
            let cg =
                cgroups_rs::Cgroup::load(Box::new(cgroups_rs::hierarchies::V2::new()), cg_name);
            let _ = cg.delete();
        }
    }
}
