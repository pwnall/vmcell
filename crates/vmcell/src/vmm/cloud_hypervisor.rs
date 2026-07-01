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
    restored: bool,
    // Whether the backend advertises snapshot/restore, captured from
    // `capabilities()` at construction so `snapshot()` can self-guard without a
    // handle to the backend (M-RESTORE-3).
    snapshot_restore_capable: bool,
    cid: u32,
    pgid: Option<u32>,
    // True if a vhost-user-net device is attached (unprivileged NAT). Such a VM is
    // not snapshot-eligible.
    vhost_user_net: bool,
}

/// Returns `true` when a VM carrying any of these is **not** snapshot-eligible,
/// because it has a vhost-user device attached (virtio-fs share, unprivileged net, or
/// vhost-user-net). The snapshot-eligibility law requires rejecting such a VM on
/// the `snapshot()`/`restore()` paths instead of attaching/keeping virtiofsd.
fn has_vhost_user_device(
    virtio_fs_share: bool,
    unprivileged_net: bool,
    vhost_user_net: bool,
) -> bool {
    virtio_fs_share || unprivileged_net || vhost_user_net
}

/// Returns `true` when `cfg`/`res` describe a VM that carries a vhost-user device
/// and is therefore **not** snapshot-eligible (§3.3 snapshot-eligibility law).
/// This covers all three §3.3 cases at the `restore()` boundary: a virtio-fs
/// *rootfs* **or** a virtio-fs data share (both served by virtiofsd), the
/// unprivileged `vhost-user-net` NAT, and an external `vhost-user-net` socket.
///
/// The virtio-fs *rootfs* case (`RootfsSource::VirtioFs`) is the one CH
/// `restore()` previously missed (M-RESTORE-3): it guarded data shares but not a
/// virtio-fs rootfs, which is equally backed by a vhost-user device.
fn config_has_vhost_user_device(cfg: &VmConfig, res: &PerVmResources) -> bool {
    let virtio_fs = !cfg.shares.is_empty()
        || matches!(cfg.rootfs, crate::config::RootfsSource::VirtioFs { .. });
    has_vhost_user_device(
        virtio_fs,
        matches!(cfg.net, crate::config::NetConfig::Unprivileged { .. }),
        res.vhost_user_socket.is_some(),
    )
}

/// Pre-flight self-checks for the `ChInstance::snapshot` path.
///
/// `snapshot()` runs on the instance, which has no handle to the backend, so the
/// `snapshot_restore` capability is captured at construction and re-checked here
/// (M-RESTORE-3) alongside the snapshot-eligibility law: a VM carrying a
/// vhost-user device cannot be snapshotted.
///
/// # Errors
/// Returns [`Error::Unsupported`] if the backend does not advertise
/// `snapshot_restore`, or if the VM has a vhost-user device attached.
fn snapshot_precheck(snapshot_restore_capable: bool, has_vhost_user: bool) -> Result<()> {
    if !snapshot_restore_capable {
        return Err(Error::Unsupported {
            vmm: "cloud-hypervisor".to_string(),
            feature: "snapshot_restore".to_string(),
        });
    }
    if has_vhost_user {
        return Err(Error::Unsupported {
            vmm: "cloud-hypervisor".to_string(),
            feature: "snapshot with a vhost-user device".to_string(),
        });
    }
    Ok(())
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
    mergeable: bool,
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
        restore_mode: crate::config::RestoreMode,
        cgroups: &dyn crate::metrics::CgroupFs,
    ) -> Result<(
        std::path::PathBuf,
        std::path::PathBuf,
        std::path::PathBuf,
        tokio::process::Child,
        Option<u32>,
    )> {
        // The orchestrator owns the per-VM scratch dir; derive our socket and
        // serial-log paths inside it.
        let api_socket = res.tmp_dir.join("api.sock");
        let vsock_path = res.tmp_dir.join("vsock.sock");
        let serial_path = res.tmp_dir.join("serial.log");

        let mut cmd = crate::vmm::build_vmm_cmd(&self.binary_path, res.netns_name.as_deref());

        if let Some(dir) = snapshot_dir {
            // CH `--restore` reconstructs every device from the snapshot's
            // config.json, including the vsock backend's UNIX socket and the serial
            // file — both recorded as the ORIGINAL instance's temp-dir paths, which
            // no longer exist. CH (v52) exposes no restore-time override for these,
            // so rewrite config.json to point at this restore's freshly-minted paths
            // before launching; otherwise the host connects to a vsock socket CH
            // never binds (the agent handshake times out) and the serial log stays
            // empty. In-place rewrite is fine for a single-use snapshot; restoring
            // many clones from one snapshot would need a copy-on-write of the
            // snapshot dir first.
            let config_path = dir.join("config.json");
            let content = tokio::fs::read_to_string(&config_path).await?;
            let mut config: serde_json::Value = serde_json::from_str(&content)?;
            if let Some(vsock) = config.get_mut("vsock") {
                vsock["socket"] =
                    serde_json::Value::String(vsock_path.to_string_lossy().into_owned());
            }
            if let Some(serial) = config.get_mut("serial") {
                serial["file"] =
                    serde_json::Value::String(serial_path.to_string_lossy().into_owned());
            }
            tokio::fs::write(&config_path, serde_json::to_string(&config)?).await?;

            // §13.3 eager-vs-lazy restore: CH v52's `--restore` accepts a
            // `prefault=on|off` modifier on the `source_url`. `on` eagerly faults
            // all guest memory in at restore time; `off` selects lazy/userfaultfd
            // demand-paging. `Default` omits the modifier and uses CH's own default.
            let mut restore_arg = format!("source_url=file://{}", dir.display());
            match restore_mode {
                crate::config::RestoreMode::Eager => restore_arg.push_str(",prefault=on"),
                crate::config::RestoreMode::Lazy => restore_arg.push_str(",prefault=off"),
                crate::config::RestoreMode::Default => {}
            }
            cmd.arg("--restore").arg(restore_arg);
        }

        let mut process = cmd
            .arg("--api-socket")
            .arg(&api_socket)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()?;

        // Capture the process-group id immediately: from here on any error must reap
        // the spawned VMM group, or it leaks (the owning ChInstance — whose Drop
        // reaps — is not constructed until the caller).
        let pgid = process.id();

        if let Some(pid) = process.id() {
            if let Err(e) = cgroups.add_task(&res.cgroup_name, pid) {
                crate::vmm::reap_process_group(&mut process, pgid);
                return Err(e);
            }
        }

        if let Err(e) = crate::vmm::wait_for_socket(&api_socket, &mut process, 1000, 20).await {
            crate::vmm::reap_process_group(&mut process, pgid);
            return Err(e);
        }

        Ok((api_socket, vsock_path, serial_path, process, pgid))
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
        let (api_socket, vsock_path, serial_path, process, pgid) = self
            .spawn_ch(res, None, crate::config::RestoreMode::Default, cgroups)
            .await?;

        let cid = res.guest_cid;

        // H-QEMU-1 (CH sibling): construct the owning instance *before* the
        // fallible virtiofsd starts. `tokio::process::Child` does not kill on
        // drop, so once `spawn_ch` has returned a live CH VMM, only the
        // instance's `Drop` (which reaps the process group, and any virtiofsd
        // already pushed below) frees it. Building the owner first means a failed
        // `VirtioFsDaemon::start` reaps the CH VMM instead of leaking it.
        let mut instance = ChInstance {
            process,
            api_socket,
            vsock_path: vsock_path.clone(),
            serial_path: serial_path.clone(),
            _fs_daemons: Vec::new(),
            restored: false,
            snapshot_restore_capable: self.capabilities().snapshot_restore,
            cid,
            pgid,
            vhost_user_net: res.vhost_user_socket.is_some(),
        };

        let mut ch_fs = Vec::new();
        for share in &cfg.shares {
            let daemon = crate::fs::VirtioFsDaemon::start(share, &res.tmp_dir).await?;
            ch_fs.push(ChFs {
                tag: share.tag.clone(),
                socket: daemon.socket_path.clone(),
                num_queues: 1,
                queue_size: 1024,
            });
            instance._fs_daemons.push(daemon);
        }

        let mut ch_cfg = ChVmConfig {
            cpus: ChCpus {
                boot_vcpus: cfg.vcpus,
                max_vcpus: cfg.vcpus,
            },
            memory: ChMemory {
                size: (cfg.mem_mib as u64) << 20,
                // KSM only deduplicates private-anonymous guest memory, so the
                // `mergeable` (KSM) lever requires `shared=off`. Default keeps
                // shared memory (the vhost-user paths need it); only the opt-in
                // §13.5 KSM-density benchmark flips both.
                shared: !cfg.ksm_mergeable,
                mergeable: cfg.ksm_mergeable,
            },
            payload: ChPayload {
                kernel: cfg.kernel.clone(),
                cmdline: {
                    let mut s = format!(
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
                        s.push_str(&format!(
                            " ip={}::{}:255.255.255.252::eth0:off",
                            guest_ip, host_ip
                        ));
                    }
                    if cfg.nested_virt {
                        s.push_str(" kvm-intel.nested=1 kvm-amd.nested=1");
                    }
                    crate::config::push_share_args(&mut s, &cfg.shares);
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
                mac: Some(crate::net::mac_math(res.vmid)?),
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
        // VMM-5: self-check the capability descriptor instead of assuming CH
        // semantics.
        if !self.capabilities().snapshot_restore {
            return Err(Error::Unsupported {
                vmm: "cloud-hypervisor".to_string(),
                feature: "snapshot_restore".to_string(),
            });
        }
        // C1 / snapshot-eligibility law: a snapshot-eligible VM has no vhost-user
        // device. Reject a virtio-fs *rootfs* or data share, unprivileged net, or an
        // external vhost-user-net *before* we would otherwise start virtiofsd
        // below. (M-RESTORE-3: the virtio-fs rootfs case was previously missed.)
        if config_has_vhost_user_device(cfg, res) {
            return Err(Error::Unsupported {
                vmm: "cloud-hypervisor".to_string(),
                feature: "snapshot/restore with a vhost-user device".to_string(),
            });
        }
        let (api_socket, vsock_path, serial_path, process, pgid) = self
            .spawn_ch(res, Some(snapshot_dir), cfg.restore_mode, cgroups)
            .await?;

        // The guard above guarantees `cfg.shares` is empty here, so this never
        // starts virtiofsd on a restored VM.
        let mut fs_daemons = Vec::new();
        for share in &cfg.shares {
            let daemon = crate::fs::VirtioFsDaemon::start(share, &res.tmp_dir).await?;
            fs_daemons.push(daemon);
        }

        let cid = res.guest_cid;

        let instance = ChInstance {
            process,
            api_socket,
            vsock_path,
            serial_path,
            _fs_daemons: fs_daemons,
            restored: true,
            snapshot_restore_capable: self.capabilities().snapshot_restore,
            cid,
            pgid,
            vhost_user_net: res.vhost_user_socket.is_some(),
        };

        Ok(instance)
    }

    fn capabilities(&self) -> VmmCapabilities {
        VmmCapabilities {
            snapshot_restore: true,
            // Eager-vs-lazy restore is plumbed via `VmConfig::restore_mode`
            // (CH `--restore source_url=…,prefault=on|off`).
            lazy_restore: true,
            virtio_fs_shares: true,
            unprivileged_vhost_user_net: true,
            nested_virt: true,
        }
    }

    fn id(&self) -> &str {
        "cloud-hypervisor"
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
        // M-RESTORE-3: self-check the `snapshot_restore` capability (captured from
        // the backend descriptor at construction) before doing any work, and
        // enforce the C1 snapshot-eligibility law — refuse to snapshot a VM with a
        // vhost-user device attached (virtiofsd or vhost-user-net).
        snapshot_precheck(
            self.snapshot_restore_capable,
            has_vhost_user_device(!self._fs_daemons.is_empty(), false, self.vhost_user_net),
        )?;
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
        // Teardown order (AGENTS.md): VMM process group first — reaping it before
        // touching virtiofsd or the per-VM directory means cleanup never races a
        // live VMM.
        if let Some(pgid) = self.pgid {
            let _ = nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(-(pgid as i32)),
                nix::sys::signal::Signal::SIGKILL,
            );
            if let Some(pid) = self.process.id() {
                let _ = nix::sys::wait::waitpid(nix::unistd::Pid::from_raw(pid as i32), None);
            }
        }
        // virtiofsd next: dropping each daemon kills it and removes its own socket
        // before the orchestrator removes the shared per-VM directory.
        self._fs_daemons.clear();
        // Unlink our own sockets. The per-VM directory itself is owned and removed
        // once by the orchestrator's `VmTempDir` guard (after this instance and the
        // smoltcp process are dropped), not here.
        let _ = std::fs::remove_file(&self.api_socket);
        let _ = std::fs::remove_file(&self.vsock_path);
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
                mergeable: false,
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

    // Guards C1/VMM-1: any vhost-user device (virtio-fs share, unprivileged net, or
    // vhost-user-net) makes a VM ineligible for snapshot/restore. The buggy impl
    // (no guard) would attach virtiofsd to a restored VM and snapshot a vhost-user
    // VM; this predicate backs both the `restore()` and `snapshot()` self-guards.
    #[test]
    fn vhost_user_device_guard() {
        assert!(has_vhost_user_device(true, false, false)); // virtio-fs data share
        assert!(has_vhost_user_device(false, true, false)); // unprivileged net
        assert!(has_vhost_user_device(false, false, true)); // external vhost-user-net
        // tap (privileged) net + erofs/block rootfs: snapshot-eligible.
        assert!(!has_vhost_user_device(false, false, false));
    }

    fn res_with(vhost_user_socket: Option<PathBuf>) -> PerVmResources {
        PerVmResources {
            cgroup_name: "vmcell-test".to_string(),
            tap_name: Some("tap0".to_string()),
            netns_name: Some("ns0".to_string()),
            vhost_user_socket,
            vmid: 1,
            guest_cid: 3,
            tmp_dir: PathBuf::from("/tmp/vmcell-vm-test-1"),
        }
    }

    // Guards M-RESTORE-3 (CH restore boundary): the snapshot-eligibility law's
    // third boundary must reject *all* vhost-user devices, including a virtio-fs
    // *rootfs*. The previous impl only checked `!cfg.shares.is_empty()`, so a
    // VirtioFs rootfs slipped through — that inverse makes the first assertion
    // below go red.
    #[test]
    fn config_vhost_user_device_covers_virtio_fs_rootfs() {
        use crate::config::{Egress, NetConfig, RootfsSource};

        // virtio-fs *rootfs*, no data share, no vhost-user-net: still ineligible.
        let virtio_fs_rootfs = VmConfig::builder(
            "/k",
            RootfsSource::VirtioFs {
                dir: PathBuf::from("/d"),
            },
        )
        .build()
        .expect("build virtio-fs rootfs config");
        assert!(
            config_has_vhost_user_device(&virtio_fs_rootfs, &res_with(None)),
            "virtio-fs rootfs must be rejected as a vhost-user device"
        );

        // unprivileged net is a vhost-user-net device.
        let unprivileged = VmConfig::builder(
            "/k",
            RootfsSource::Erofs {
                image: PathBuf::from("/i"),
            },
        )
        .net(NetConfig::Unprivileged {
            egress: Egress::default(),
            host_services_port: None,
        })
        .build()
        .expect("build unprivileged config");
        assert!(config_has_vhost_user_device(&unprivileged, &res_with(None)));

        // external vhost-user-net socket attached via resources.
        let plain = VmConfig::builder(
            "/k",
            RootfsSource::Erofs {
                image: PathBuf::from("/i"),
            },
        )
        .build()
        .expect("build plain config");
        assert!(config_has_vhost_user_device(
            &plain,
            &res_with(Some(PathBuf::from("/run/vhost.sock")))
        ));

        // erofs rootfs + privileged (tap) net + no external socket: eligible.
        let eligible = VmConfig::builder(
            "/k",
            RootfsSource::Erofs {
                image: PathBuf::from("/i"),
            },
        )
        .net(NetConfig::Privileged {
            egress: Egress::default(),
            host_services_port: None,
        })
        .build()
        .expect("build eligible config");
        assert!(!config_has_vhost_user_device(&eligible, &res_with(None)));
    }

    // Guards M-RESTORE-3 (CH snapshot boundary): `snapshot()` must self-check the
    // captured `snapshot_restore` capability *and* the vhost-user-device law. The
    // inverse of the capability check (snapshot() ignoring the descriptor) makes
    // the first assertion go red; the inverse of the device check makes the
    // second go red.
    #[test]
    fn snapshot_precheck_enforces_capability_and_law() {
        // Backend that does not advertise snapshot_restore, even with a clean VM.
        let err = snapshot_precheck(false, false).expect_err("incapable backend must error");
        assert!(
            matches!(&err, Error::Unsupported { feature, .. } if feature == "snapshot_restore"),
            "expected snapshot_restore Unsupported, got {err:?}"
        );

        // Capable backend, but the VM carries a vhost-user device.
        let err = snapshot_precheck(true, true).expect_err("vhost-user VM must error");
        assert!(
            matches!(&err, Error::Unsupported { feature, .. } if feature.contains("vhost-user")),
            "expected vhost-user Unsupported, got {err:?}"
        );

        // Capable backend, snapshot-eligible VM: allowed.
        assert!(snapshot_precheck(true, false).is_ok());
    }
}
