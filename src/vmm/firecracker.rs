use crate::config::VmConfig;
use crate::error::{Error, Result};
use crate::metrics::ResourceUsage;
use crate::vmm::{PerVmResources, VmInstance, Vmm, VmmCapabilities};
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::process::Stdio;

use tokio::process::Child;

/// The Firecracker VMM backend.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Firecracker {
    /// Path to the `firecracker` executable.
    pub binary_path: PathBuf,
}

impl Firecracker {
    /// Creates a new `Firecracker` using the specified executable path.
    #[must_use]
    pub fn new(binary_path: impl Into<PathBuf>) -> Self {
        Self {
            binary_path: binary_path.into(),
        }
    }
}

/// A running instance of a Firecracker VM.
#[derive(Debug)]
#[non_exhaustive]
pub struct FcInstance {
    process: Child,
    api_socket: PathBuf,
    vsock_path: PathBuf,
    serial_path: PathBuf,
    cgroup_name: Option<String>,
    cid: u32,
    pgid: Option<u32>,
}

impl FcInstance {
    async fn api_request(
        &self,
        method: &str,
        path: &str,
        body: Option<&impl Serialize>,
    ) -> Result<()> {
        crate::vmm::unix_api_request(&self.api_socket, method, path, body).await
    }
}

impl Firecracker {
    async fn spawn_fc(
        &self,
        res: &PerVmResources,
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

        // Firecracker expects the socket to not exist before it creates it.
        let _ = tokio::fs::remove_file(&api_socket).await;

        let mut cmd = crate::vmm::build_vmm_cmd(&self.binary_path, res.netns_name.as_deref());

        let log_file = std::fs::File::create(&serial_path)?;
        let process = cmd
            .arg("--api-sock")
            .arg(&api_socket)
            .stdin(Stdio::null())
            .stdout(log_file)
            .stderr(Stdio::inherit())
            .spawn()?;

        if let Some(pid) = process.id() {
            crate::vmm::write_cgroup_procs(&res.cgroup_name, pid).await;
        }

        if !crate::vmm::wait_for_socket(&api_socket, 1000, 20).await {
            return Err(Error::Vmm("API socket failed to appear".into()));
        }

        let pgid = process.id();
        Ok((tmp, api_socket, vsock_path, serial_path, process, pgid))
    }
}


static CPU_TEMPLATE: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();

async fn detect_cpu_template(vmm: &Firecracker, cfg: &VmConfig) -> Option<String> {
    if let Some(val) = CPU_TEMPLATE.get() {
        return val.clone();
    }

    let template = probe_t2_template(vmm, cfg).await;
    let _ = CPU_TEMPLATE.set(template.clone());
    template
}

async fn probe_t2_template(vmm: &Firecracker, cfg: &VmConfig) -> Option<String> {
    let tmp_dir = std::env::temp_dir();
    let counter = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let api_socket = tmp_dir.join(format!(
        "imp-fc-probe-{}-{}.socket",
        std::process::id(),
        counter
    ));

    let mut std_cmd = std::process::Command::new(&vmm.binary_path);
    std_cmd.arg("--api-sock").arg(&api_socket);
    use std::os::unix::process::CommandExt;
    std_cmd.process_group(0);

    let mut process = match tokio::process::Command::from(std_cmd)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
    {
        Ok(p) => p,
        Err(_) => return None,
    };

    let mut socket_ready = false;
    for _ in 0..50 {
        if tokio::fs::try_exists(&api_socket).await.unwrap_or(false) {
            socket_ready = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }

    if !socket_ready {
        let _ = process.kill().await;
        return None;
    }

    let instance = FcInstance {
        process,
        api_socket: api_socket.clone(),
        vsock_path: PathBuf::new(),
        serial_path: PathBuf::new(),
        cgroup_name: None,
        cid: 0,
        pgid: None,
    };

    #[derive(Serialize)]
    struct MachineConfig {
        vcpu_count: u8,
        mem_size_mib: u32,
        smt: bool,
        cpu_template: Option<String>,
    }

    let mc_res = instance
        .api_request(
            "PUT",
            "/machine-config",
            Some(&MachineConfig {
                vcpu_count: 1,
                mem_size_mib: 128,
                smt: false,
                cpu_template: Some("T2".to_string()),
            }),
        )
        .await;

    if mc_res.is_err() {
        return None;
    }

    #[derive(Serialize)]
    struct BootSource {
        kernel_image_path: PathBuf,
        boot_args: String,
    }

    let bs_res = instance
        .api_request(
            "PUT",
            "/boot-source",
            Some(&BootSource {
                kernel_image_path: cfg.kernel.clone(),
                boot_args: "console=ttyS0 panic=1".to_string(),
            }),
        )
        .await;

    if bs_res.is_err() {
        return None;
    }

    #[derive(Serialize)]
    struct Action {
        action_type: String,
    }

    let boot_res = instance
        .api_request(
            "PUT",
            "/actions",
            Some(&Action {
                action_type: "InstanceStart".to_string(),
            }),
        )
        .await;

    let success = match boot_res {
        Ok(_) => true,
        Err(Error::VmmApi {
            status: 400,
            ref body,
        }) if body.contains("template") || body.contains("Template") => false,
        Err(_) => false,
    };

    if success {
        Some("T2".to_string())
    } else {
        None
    }
}

impl Vmm for Firecracker {
    type Instance = FcInstance;

    async fn create(&self, cfg: &VmConfig, res: &PerVmResources) -> Result<Self::Instance> {
        if !cfg.shares.is_empty() {
            return Err(Error::Vmm(
                "Firecracker does not support virtio-fs shares".into(),
            ));
        }

        let template = detect_cpu_template(self, cfg).await;

        let (_tmp, api_socket, vsock_path, serial_path, process, pgid) = self.spawn_fc(res).await?;

        let instance = FcInstance {
            process,
            api_socket,
            vsock_path: vsock_path.clone(),
            serial_path: serial_path.clone(),
            cgroup_name: Some(res.cgroup_name.clone()),
            cid: res.guest_cid,
            pgid,
        };

        #[derive(Serialize)]
        struct MachineConfig {
            vcpu_count: u8,
            mem_size_mib: u32,
            smt: bool,
            cpu_template: Option<String>,
        }
        instance
            .api_request(
                "PUT",
                "/machine-config",
                Some(&MachineConfig {
                    vcpu_count: cfg.vcpus,
                    mem_size_mib: cfg.mem_mib,
                    smt: false,
                    cpu_template: template,
                }),
            )
            .await?;

        // Configure Boot Source
        #[derive(Serialize)]
        struct BootSource {
            kernel_image_path: PathBuf,
            boot_args: String,
        }

        let cmdline = {
            let mut s = format!(
                "console=ttyS0 root=/dev/vda rootfstype={} ro {} panic=1 noxsave init=/usr/sbin/imp-guest-agent imp_vmid={}",
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
        };

        instance
            .api_request(
                "PUT",
                "/boot-source",
                Some(&BootSource {
                    kernel_image_path: cfg.kernel.clone(),
                    boot_args: cmdline,
                }),
            )
            .await?;

        // Configure Drive
        #[derive(Serialize)]
        struct Drive {
            drive_id: String,
            path_on_host: PathBuf,
            is_root_device: bool,
            is_read_only: bool,
        }

        let rootfs_path = match &cfg.rootfs {
            crate::config::RootfsSource::Erofs { image } => image.clone(),
            crate::config::RootfsSource::Block { image, overlay } => {
                overlay.as_ref().unwrap_or(image).clone()
            }
            crate::config::RootfsSource::VirtioFs { .. } => {
                return Err(Error::Vmm(
                    "Firecracker does not support virtio-fs rootfs".into(),
                ));
            }
        };

        let is_ro = matches!(&cfg.rootfs, crate::config::RootfsSource::Erofs { .. });

        instance
            .api_request(
                "PUT",
                "/drives/rootfs",
                Some(&Drive {
                    drive_id: "rootfs".to_string(),
                    path_on_host: rootfs_path,
                    is_root_device: true,
                    is_read_only: is_ro,
                }),
            )
            .await?;

        // Configure Network
        if let Some(tap) = &res.tap_name {
            assert!(res.vmid <= 254, "vmid must be <= 254 for MAC configuration");
            #[derive(Serialize)]
            struct NetworkInterface {
                iface_id: String,
                host_dev_name: String,
                guest_mac: String,
            }
            let mac = format!(
                "02:00:{:02x}:{:02x}:{:02x}:{:02x}",
                (res.vmid >> 24) & 0xff,
                (res.vmid >> 16) & 0xff,
                (res.vmid >> 8) & 0xff,
                res.vmid & 0xff
            );
            instance
                .api_request(
                    "PUT",
                    "/network-interfaces/eth0",
                    Some(&NetworkInterface {
                        iface_id: "eth0".to_string(),
                        host_dev_name: tap.clone(),
                        guest_mac: mac,
                    }),
                )
                .await?;
        }

        // Configure Vsock
        #[derive(Serialize)]
        struct Vsock {
            guest_cid: u32,
            uds_path: PathBuf,
        }
        instance
            .api_request(
                "PUT",
                "/vsock",
                Some(&Vsock {
                    guest_cid: res.guest_cid,
                    uds_path: vsock_path.clone(),
                }),
            )
            .await?;

        Ok(instance)
    }

    async fn restore(
        &self,
        snapshot_dir: &Path,
        _cfg: &VmConfig,
        res: &PerVmResources,
    ) -> Result<Self::Instance> {
        let (_tmp, api_socket, vsock_path, serial_path, process, pgid) = self.spawn_fc(res).await?;

        let instance = FcInstance {
            process,
            api_socket,
            vsock_path,
            serial_path,
            cgroup_name: Some(res.cgroup_name.clone()),
            cid: res.guest_cid,
            pgid,
        };

        // Load snapshot
        #[derive(Serialize)]
        struct MemBackend {
            backend_path: PathBuf,
            backend_type: String,
        }
        #[derive(Serialize)]
        struct SnapshotLoad {
            snapshot_path: PathBuf,
            mem_backend: MemBackend,
            resume_vm: bool,
        }

        instance
            .api_request(
                "PUT",
                "/snapshot/load",
                Some(&SnapshotLoad {
                    snapshot_path: snapshot_dir.join("snapshot_file"),
                    mem_backend: MemBackend {
                        backend_path: snapshot_dir.join("mem_file"),
                        backend_type: "File".to_string(),
                    },
                    resume_vm: false,
                }),
            )
            .await?;

        Ok(instance)
    }

    fn capabilities(&self) -> VmmCapabilities {
        VmmCapabilities {
            snapshot_restore: true,
            lazy_restore: true, // Firecracker supports UFFD lazy restore
            virtio_fs_shares: false,
            rootless_vhost_user_net: false,
            nested_virt: false,
        }
    }
}

impl VmInstance for FcInstance {
    async fn boot(&mut self) -> Result<()> {
        #[derive(Serialize)]
        struct Action {
            action_type: String,
        }
        self.api_request(
            "PUT",
            "/actions",
            Some(&Action {
                action_type: "InstanceStart".to_string(),
            }),
        )
        .await
    }

    async fn request_shutdown(&mut self) -> Result<()> {
        #[derive(Serialize)]
        struct Action {
            action_type: String,
        }
        self.api_request(
            "PUT",
            "/actions",
            Some(&Action {
                action_type: "SendCtrlAltDel".to_string(),
            }),
        )
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
        #[derive(Serialize)]
        struct Action {
            state: String,
        }
        self.api_request(
            "PATCH",
            "/vm",
            Some(&Action {
                state: "Paused".to_string(),
            }),
        )
        .await
    }

    async fn resume(&mut self) -> Result<()> {
        #[derive(Serialize)]
        struct Action {
            state: String,
        }
        self.api_request(
            "PATCH",
            "/vm",
            Some(&Action {
                state: "Resumed".to_string(),
            }),
        )
        .await
    }

    async fn snapshot(&mut self, dir: &Path) -> Result<()> {
        #[derive(Serialize)]
        struct SnapshotCreate {
            snapshot_type: String,
            snapshot_path: PathBuf,
            mem_file_path: PathBuf,
        }

        self.pause().await?;

        let res = self
            .api_request(
                "PUT",
                "/snapshot/create",
                Some(&SnapshotCreate {
                    snapshot_type: "Full".to_string(),
                    snapshot_path: dir.join("snapshot_file"),
                    mem_file_path: dir.join("mem_file"),
                }),
            )
            .await;

        if let Err(e) = self.resume().await {
            tracing::warn!("Failed to resume Firecracker after snapshot: {}", e);
        }

        res
    }

    async fn stats(&self) -> Result<ResourceUsage> {
        Ok(crate::metrics::read_cgroup_stats(
            self.cgroup_name.as_deref(),
        ))
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

impl Drop for FcInstance {
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
