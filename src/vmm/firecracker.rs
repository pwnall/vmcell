use crate::config::VmConfig;
use crate::error::{Error, Result};
use crate::vmm::{PerVmResources, VmInstance, Vmm, VmmCapabilities};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Stdio;

use tokio::process::Child;

/// Sidecar file (written into the snapshot directory by [`FcInstance::snapshot`])
/// recording the host-side vsock/serial UDS paths the snapshot baked in.
///
/// Firecracker's `PUT /snapshot/load` restores the vsock device *verbatim* from
/// the snapshot — it rebinds the **original** host UDS path and offers no
/// load-time override. A restore therefore runs under a fresh, vmid-derived tmp
/// dir but must rebind (and have the agent dial) the path the snapshot recorded.
/// This sidecar carries that path across the snapshot/restore boundary.
const HOST_PATHS_SIDECAR: &str = "vmcell_host_paths.json";

/// Host-side UDS paths baked into a Firecracker snapshot, persisted alongside it
/// so a later restore can rebind/connect the exact socket FC recreates.
#[derive(Serialize, Deserialize)]
struct SnapshotHostPaths {
    vsock: PathBuf,
    serial: PathBuf,
}

/// Returns `true` when a VM carrying any of these is **not** snapshot-eligible,
/// because it has a vhost-user device attached (virtio-fs share, unprivileged net, or
/// external vhost-user-net). The snapshot-eligibility law (§3.3) requires every
/// backend to self-guard `snapshot()`/`restore()` against such a VM rather than
/// assume the caller already checked. Firecracker's `create()` already rejects all
/// vhost-user devices up front, so on FC this is defense in depth — it stays correct
/// if a future path constructs an `FcInstance` differently. Mirrors the CH helper.
fn has_vhost_user_device(
    virtio_fs_share: bool,
    unprivileged_net: bool,
    vhost_user_net: bool,
) -> bool {
    virtio_fs_share || unprivileged_net || vhost_user_net
}

/// The Firecracker capability descriptor, exposed as a free function so both
/// [`Firecracker::capabilities`] and [`FcInstance::snapshot`] consult the **same**
/// source of truth — the latter holds no handle to the `Firecracker` backend yet
/// must self-check `snapshot_restore` (M-RESTORE-3).
fn fc_capabilities() -> VmmCapabilities {
    VmmCapabilities {
        // E2 (empirical, KVM host): FC warm restore drops the first post-restore
        // exec ("Connection dropped during exec") whereas CH passes the same test.
        // The fix spans the guest agent's vsock re-bind and the host reconnect/retry
        // (outside this module) and needs KVM validation, so the capability is gated
        // OFF until it passes the matrix test on a KVM host — advertising a broken
        // capability is the "lying flag" smell. Flip back to `true` only then.
        snapshot_restore: false,
        // M-VMM-1: a real UFFD page-fault backend for `RestoreMode::Lazy` is not
        // wired (restore would hardcode `backend_type: "File"`, faulting eagerly), so
        // the flag is honest-false rather than silently degrading Lazy to eager.
        lazy_restore: false,
        virtio_fs_shares: false,
        unprivileged_vhost_user_net: false,
        nested_virt: false,
    }
}

/// Serializes and writes the host vsock/serial UDS paths Firecracker baked into a
/// snapshot to the [`HOST_PATHS_SIDECAR`] file in `dir`. The sidecar is part of the
/// snapshot artifact and `restore()` hard-requires it, so a serialize or write
/// failure is surfaced (M-RESTORE-2) — never logged-and-swallowed, which would
/// report an unrestorable snapshot as successful.
async fn write_host_paths_sidecar(dir: &Path, vsock: &Path, serial: &Path) -> Result<()> {
    let json = serde_json::to_string(&SnapshotHostPaths {
        vsock: vsock.to_path_buf(),
        serial: serial.to_path_buf(),
    })?;
    tokio::fs::write(dir.join(HOST_PATHS_SIDECAR), json).await?;
    Ok(())
}

/// The Firecracker VMM backend.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Firecracker {
    /// Path to the `firecracker` executable.
    pub binary_path: PathBuf,
    /// Lazily-probed T2 CPU-template support, cached on this instance (shared
    /// across clones). Replaces the former process-global `OnceLock` so the probe
    /// result is no longer module-global mutable state.
    cpu_template: std::sync::Arc<std::sync::OnceLock<Option<String>>>,
}

impl Firecracker {
    /// Creates a new `Firecracker` using the specified executable path.
    #[must_use]
    pub fn new(binary_path: impl Into<PathBuf>) -> Self {
        Self {
            binary_path: binary_path.into(),
            cpu_template: std::sync::Arc::new(std::sync::OnceLock::new()),
        }
    }

    /// Probes the host once for T2 CPU-template support, caching the result on
    /// this instance instead of in a process-global, so a later `Firecracker`
    /// with a different binary/config probes independently.
    async fn detect_cpu_template(&self, cfg: &VmConfig) -> Option<String> {
        if let Some(val) = self.cpu_template.get() {
            return val.clone();
        }

        let template = probe_t2_template(self, cfg).await;
        let _ = self.cpu_template.set(template.clone());
        template
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
    cid: u32,
    pgid: Option<u32>,
    /// True if an external vhost-user-net device is attached. Such a VM is not
    /// snapshot-eligible (§3.3); `snapshot()` self-guards on it. Always `false` on
    /// FC today because `create()` rejects every vhost-user device up front, but the
    /// field keeps the snapshot guard correct by construction. Mirrors CH.
    vhost_user_net: bool,
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

        // Firecracker expects the socket to not exist before it creates it.
        let _ = tokio::fs::remove_file(&api_socket).await;

        let mut cmd = crate::vmm::build_vmm_cmd(&self.binary_path, res.netns_name.as_deref());

        let log_file = std::fs::File::create(&serial_path)?;
        let mut process = cmd
            .arg("--api-sock")
            .arg(&api_socket)
            .stdin(Stdio::null())
            .stdout(log_file)
            .stderr(Stdio::inherit())
            .spawn()?;

        // Capture the process-group id immediately: from here on any error must reap
        // the spawned VMM group, or it leaks (the owning FcInstance — whose Drop
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

        Ok((tmp, api_socket, vsock_path, serial_path, process, pgid))
    }
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

    // The probe child is its own process-group leader (`process_group(0)`), so its
    // pid is the group id. Capture it so `FcInstance::drop` force-kills and reaps
    // the whole group on every exit path below — never own a live firecracker with
    // `pgid: None`, which would orphan the process and leak it.
    let pgid = process.id();
    let instance = FcInstance {
        process,
        api_socket: api_socket.clone(),
        vsock_path: PathBuf::new(),
        serial_path: PathBuf::new(),
        cid: 0,
        pgid,
        vhost_user_net: false,
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

    async fn create(
        &self,
        cfg: &VmConfig,
        res: &PerVmResources,
        cgroups: &dyn crate::metrics::CgroupFs,
    ) -> Result<Self::Instance> {
        let caps = self.capabilities();
        if let crate::config::NetConfig::Unprivileged { .. } = cfg.net {
            if !caps.unprivileged_vhost_user_net {
                return Err(Error::Unsupported {
                    vmm: "firecracker".to_string(),
                    feature: "unprivileged_net".to_string(),
                });
            }
        }
        if res.vhost_user_socket.is_some() {
            return Err(Error::Unsupported {
                vmm: "firecracker".to_string(),
                feature: "vhost_user_socket".to_string(),
            });
        }

        if !cfg.shares.is_empty() {
            return Err(Error::Unsupported {
                vmm: "firecracker".to_string(),
                feature: "virtio_fs_shares".to_string(),
            });
        }

        let template = self.detect_cpu_template(cfg).await;

        let (_tmp, api_socket, vsock_path, serial_path, process, pgid) =
            self.spawn_fc(res, cgroups).await?;

        let instance = FcInstance {
            process,
            api_socket,
            vsock_path: vsock_path.clone(),
            serial_path: serial_path.clone(),
            cid: res.guest_cid,
            pgid,
            // Always false here: the vhost-user-socket rejection above already
            // returned `Unsupported`. Computed from `res` to mirror CH and stay
            // correct if that guard ever moves.
            vhost_user_net: res.vhost_user_socket.is_some(),
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
                "console=ttyS0 root=/dev/vda rootfstype={} ro {} panic=1 noxsave init=/usr/sbin/vmcell-guest-agent vmcell_vmid={}",
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
                return Err(Error::Unsupported {
                    vmm: "firecracker".to_string(),
                    feature: "virtio_fs_rootfs".to_string(),
                });
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
            #[derive(Serialize)]
            struct NetworkInterface {
                iface_id: String,
                host_dev_name: String,
                guest_mac: String,
            }
            let mac = crate::net::mac_math(res.vmid)?;
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
        cfg: &VmConfig,
        res: &PerVmResources,
        cgroups: &dyn crate::metrics::CgroupFs,
    ) -> Result<Self::Instance> {
        // VMM-5: self-check the capability descriptor rather than assuming the
        // backend supports restore.
        if !self.capabilities().snapshot_restore {
            return Err(Error::Unsupported {
                vmm: "firecracker".to_string(),
                feature: "snapshot_restore".to_string(),
            });
        }
        // M-RESTORE-3 / snapshot-eligibility law: a snapshot-eligible VM has no
        // vhost-user device. Reject any virtio-fs share, unprivileged net, or external
        // vhost-user-net handed to us via the config, mirroring CH's guard, before
        // spawning a VMM. FC never attaches these, so this is defense in depth.
        if has_vhost_user_device(
            !cfg.shares.is_empty(),
            matches!(cfg.net, crate::config::NetConfig::Unprivileged { .. }),
            res.vhost_user_socket.is_some(),
        ) {
            return Err(Error::Unsupported {
                vmm: "firecracker".to_string(),
                feature: "snapshot/restore with a vhost-user device".to_string(),
            });
        }

        // Recover the host vsock/serial UDS paths the snapshot baked in (see
        // `snapshot()` and `HOST_PATHS_SIDECAR`). Read this *before* spawning so a
        // corrupt/foreign snapshot fails loud without leaking a VMM process.
        let sidecar_path = snapshot_dir.join(HOST_PATHS_SIDECAR);
        let sidecar = tokio::fs::read_to_string(&sidecar_path).await?;
        let host_paths: SnapshotHostPaths = serde_json::from_str(&sidecar)?;

        let (_tmp, api_socket, _vsock_path, _serial_path, process, pgid) =
            self.spawn_fc(res, cgroups).await?;

        // Firecracker rebinds the snapshot's recorded host vsock UDS at load time.
        // Remove any leftover socket file there first (a sequential restore reuses
        // the same path), otherwise the bind fails with EADDRINUSE. The directory is
        // kept so FC can recreate the socket and reopen the serial sink.
        let _ = tokio::fs::remove_file(&host_paths.vsock).await;

        let instance = FcInstance {
            process,
            api_socket,
            // Adopt the snapshot's paths so the agent dials the exact UDS FC
            // recreates, not the fresh (unused) vmid-derived path from `spawn_fc`.
            vsock_path: host_paths.vsock,
            serial_path: host_paths.serial,
            cid: res.guest_cid,
            pgid,
            // Guarded false above; computed from `res` to mirror CH.
            vhost_user_net: res.vhost_user_socket.is_some(),
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
        fc_capabilities()
    }

    fn id(&self) -> &str {
        "firecracker"
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
        // M-RESTORE-3: self-check the capability descriptor and the
        // snapshot-eligibility law (no vhost-user device) before doing any work,
        // mirroring CH's `snapshot()` guards. A backend never assumes the caller
        // already checked.
        if !fc_capabilities().snapshot_restore {
            return Err(Error::Unsupported {
                vmm: "firecracker".to_string(),
                feature: "snapshot_restore".to_string(),
            });
        }
        if has_vhost_user_device(false, false, self.vhost_user_net) {
            return Err(Error::Unsupported {
                vmm: "firecracker".to_string(),
                feature: "snapshot with a vhost-user device".to_string(),
            });
        }

        #[derive(Serialize)]
        struct SnapshotCreate {
            snapshot_type: String,
            snapshot_path: PathBuf,
            mem_file_path: PathBuf,
        }

        self.pause().await?;

        let snap_res = self
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

        // On success, persist the host vsock/serial UDS paths FC baked into the
        // snapshot so `restore()` can rebind/connect the exact socket it recreates
        // (FC offers no load-time vsock override). The sidecar is part of the
        // artifact and `restore()` hard-requires it, so a write failure is
        // propagated (M-RESTORE-2) — reporting an unrestorable snapshot as `Ok`
        // would only surface later as a confusing `restore()` error.
        let result = match snap_res {
            Ok(()) => write_host_paths_sidecar(dir, &self.vsock_path, &self.serial_path).await,
            Err(e) => Err(e),
        };

        // Always attempt to resume so a snapshot of a still-live VM is not stranded
        // paused; a resume failure is non-fatal and only logged.
        if let Err(e) = self.resume().await {
            tracing::warn!("Failed to resume Firecracker after snapshot: {}", e);
        }

        result
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Guards VMM-4: the CPU-template cache must live on the instance, not in a
    // process-global. The buggy impl (a `static OnceLock`) would let one
    // `Firecracker`'s probe result leak into a second, independently-configured
    // instance.
    #[test]
    fn cpu_template_cache_is_per_instance() {
        let a = Firecracker::new("/usr/bin/firecracker");
        let b = Firecracker::new("/usr/bin/firecracker");

        // Seed only `a`'s cache.
        let _ = a.cpu_template.set(Some("T2".to_string()));

        assert_eq!(a.cpu_template.get(), Some(&Some("T2".to_string())));
        // `b` has an independent, still-empty cache.
        assert_eq!(b.cpu_template.get(), None);
    }

    // Guards E2 (FC warm restore is empirically broken on a KVM host — gated off)
    // and M-VMM-1 (no real UFFD backend is wired). The advertised capability must be
    // HONEST. The buggy impl (advertising `snapshot_restore: true` while the first
    // post-restore exec drops, or `lazy_restore: true` while Lazy silently degrades
    // to eager) makes these asserts go red. With `true`, `require_cap!` would run a
    // broken FC restore scenario instead of skipping with reason. Flip these to
    // `true` only once FC warm restore passes the matrix test on a KVM host.
    #[test]
    fn capabilities_are_honest_about_snapshot_restore() {
        let caps = Firecracker::new("/usr/bin/firecracker").capabilities();
        assert!(
            !caps.snapshot_restore,
            "FC snapshot_restore must stay gated off until E2 is fixed and KVM-validated"
        );
        assert!(
            !caps.lazy_restore,
            "FC lazy_restore must be false until a real UFFD backend is wired (M-VMM-1)"
        );
        // The instance-facing free function and the `Vmm` trait method must agree, so
        // `FcInstance::snapshot`'s self-check sees the same gate the orchestrator does.
        assert_eq!(caps.snapshot_restore, fc_capabilities().snapshot_restore);
        assert_eq!(caps.lazy_restore, fc_capabilities().lazy_restore);
    }

    // Guards M-RESTORE-3: the snapshot-eligibility predicate (§3.3) that backs both
    // the `restore()` and `snapshot()` self-guards. The buggy impl (no guard — i.e.
    // a predicate that always returns false) would let a vhost-user VM be
    // snapshotted/restored.
    #[test]
    fn vhost_user_device_guard() {
        assert!(has_vhost_user_device(true, false, false)); // virtio-fs data share
        assert!(has_vhost_user_device(false, true, false)); // unprivileged net
        assert!(has_vhost_user_device(false, false, true)); // external vhost-user-net
        // privileged tap net + erofs/block rootfs: snapshot-eligible.
        assert!(!has_vhost_user_device(false, false, false));
    }

    // Guards M-RESTORE-2: the restore sidecar is part of the snapshot artifact, so a
    // write failure must be SURFACED, not swallowed. The buggy impl
    // (`let _ = tokio::fs::write(...).await; Ok(())`) returns `Ok` even when the
    // write fails, making `snapshot()` report an unrestorable snapshot as success;
    // the failure-path assert below then goes red. The happy path also round-trips
    // the exact paths so the sidecar is proven readable by `restore()`.
    #[tokio::test]
    async fn sidecar_write_round_trips_and_surfaces_errors() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vsock = PathBuf::from("/tmp/imp-vsock.sock");
        let serial = PathBuf::from("/tmp/imp-serial.log");

        // Happy path: the sidecar is written and round-trips back the exact paths.
        write_host_paths_sidecar(dir.path(), &vsock, &serial)
            .await
            .expect("sidecar write should succeed in a writable dir");
        let raw = tokio::fs::read_to_string(dir.path().join(HOST_PATHS_SIDECAR))
            .await
            .expect("sidecar file should exist after a successful write");
        let parsed: SnapshotHostPaths =
            serde_json::from_str(&raw).expect("sidecar should be valid json");
        assert_eq!(parsed.vsock, vsock);
        assert_eq!(parsed.serial, serial);

        // Failure path: a non-existent target directory makes the write fail; the
        // error MUST propagate rather than be swallowed into `Ok`.
        let missing = dir.path().join("does-not-exist").join("nested");
        assert!(
            write_host_paths_sidecar(&missing, &vsock, &serial)
                .await
                .is_err(),
            "a failed sidecar write must surface an error, not be swallowed"
        );
    }
}
