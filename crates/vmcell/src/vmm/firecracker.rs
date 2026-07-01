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

        let probe = probe_t2_template(self, cfg).await;
        // VMM-4: only a DEFINITE outcome (T2 supported or firmly unsupported) is
        // cached. A transient probe failure is warned about and left uncached so the
        // next `create()` re-probes — a one-off host hiccup must not permanently
        // disable the T2 template (and thus the extended-FPU restore guard) for every
        // VM sharing this backend.
        if probe == T2Probe::Failed {
            tracing::warn!(
                "Firecracker T2 CPU-template probe failed (transient host error, not a \
                 firm 'unsupported'); not caching a result — will re-probe on the next \
                 VM. Booting without a CPU template this time; the `noxsave` cmdline \
                 fallback still guards extended-FPU restore."
            );
        }
        if let Some(to_cache) = cache_decision(probe) {
            let _ = self.cpu_template.set(to_cache);
        }
        self.cpu_template.get().cloned().flatten()
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
    /// True if this instance came from a snapshot `restore()`. A restored FC VM is
    /// returned **paused** by `POST /snapshot/load {resume_vm:false}` and resumed via
    /// `resume()`, never `boot()` — so `boot()` self-guards on this flag and refuses
    /// to `InstanceStart` a restored VM (VMM-6). Mirrors CH's `restored` field.
    restored: bool,
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
        tokio::process::Child,
        Option<u32>,
    )> {
        // The orchestrator owns the per-VM scratch dir; derive our socket and
        // serial-log paths inside it.
        let api_socket = res.tmp_dir.join("api.sock");
        let vsock_path = res.tmp_dir.join("vsock.sock");
        let serial_path = res.tmp_dir.join("serial.log");

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

        // Shared spawn+register+await-ready sequence (VMM-2): capture the pgid, add
        // the VMM to its cgroup, and block on the API socket — reaping the process
        // group on any failure. Identical error handling across CH/FC/QEMU.
        let pgid = crate::vmm::register_and_await_ready(
            &mut process,
            cgroups,
            &res.cgroup_name,
            &api_socket,
            1000,
            20,
        )
        .await?;

        Ok((api_socket, vsock_path, serial_path, process, pgid))
    }
}

/// Outcome of the one-shot T2 CPU-template probe (VMM-4).
///
/// The old probe returned `Option<String>`, collapsing two very different cases into
/// `None`: a host that firmly reports T2 **unsupported**, and a probe that simply
/// **failed** (spawn/socket/API error — transient). Caching a transient failure as
/// "unsupported" permanently disables the T2 template — and thus the extended-FPU
/// restore guard — for every VM sharing the backend. Distinguishing the three lets
/// `detect_cpu_template` cache a definite answer but *re-probe* after a transient
/// failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum T2Probe {
    /// The host confirmed T2 support (the probe VM booted with the template).
    Supported,
    /// The host firmly rejected the T2 template (boot returned a template error).
    Unsupported,
    /// The probe could not complete (spawn/socket/API failure). Transient — must not
    /// be cached as a definitive answer.
    Failed,
}

/// Classifies the probe VM's `InstanceStart` result into a [`T2Probe`].
///
/// A `400` whose body mentions the template is the one **firm** "T2 unsupported"
/// signal; every other error (a `500`, a timeout, a transport error) is a transient
/// probe **failure**, not evidence that the host lacks T2 (VMM-4). Pure so the
/// distinction is unit-testable without spawning Firecracker.
fn classify_t2_boot(boot_res: &Result<()>) -> T2Probe {
    match boot_res {
        Ok(()) => T2Probe::Supported,
        Err(Error::VmmApi { status: 400, body })
            if body.contains("template") || body.contains("Template") =>
        {
            T2Probe::Unsupported
        }
        Err(_) => T2Probe::Failed,
    }
}

/// Maps a probe outcome to what (if anything) `detect_cpu_template` caches.
///
/// `None` means "do not cache — re-probe next time"; `Some(v)` is the value stored in
/// the shared `OnceLock`. A [`T2Probe::Failed`] must map to `None` (VMM-4): caching a
/// transient failure as "no template" is the exact permanent-disable bug. Pure so the
/// caching policy is unit-testable.
fn cache_decision(probe: T2Probe) -> Option<Option<String>> {
    match probe {
        T2Probe::Supported => Some(Some("T2".to_string())),
        T2Probe::Unsupported => Some(None),
        T2Probe::Failed => None,
    }
}

/// The extended-FPU restore-guard cmdline fragment for Firecracker (empty or `"noxsave "`).
///
/// A T2 CPU template masks the extended-state CPUID bits so the guest `glibc` never
/// dispatches to the AVX/AVX-512 routines whose XSAVE area can mismatch on restore
/// (design §138). `noxsave` is the **fallback** for hosts where the template does not
/// fit; applying it *with* a template needlessly disables the guest AVX2 the template
/// leaves usable, so it is emitted **only when no template was applied**. Returned with a
/// trailing space so it composes cleanly into the boot-args when non-empty and vanishes
/// when empty. Pure so the gating is unit-testable (audit E6,
/// `docs/41-experimental-conclusions-audit.md`).
fn noxsave_fallback(has_cpu_template: bool) -> &'static str {
    if has_cpu_template { "" } else { "noxsave " }
}

async fn probe_t2_template(vmm: &Firecracker, cfg: &VmConfig) -> T2Probe {
    let tmp_dir = std::env::temp_dir();
    let counter = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let api_socket = tmp_dir.join(format!(
        "vmcell-fc-probe-{}-{}.socket",
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
        Err(_) => return T2Probe::Failed,
    };

    // The probe child is its own process-group leader (`process_group(0)`), so its
    // pid is the group id. Capture it immediately so every failure path below reaps
    // the whole group — never own a live firecracker with `pgid: None`, which would
    // orphan the process and leak it.
    let pgid = process.id();

    // VMM-3: use the shared `wait_for_socket` (which also `try_wait`s the child and
    // fails fast on an early exit) instead of a hand-rolled `try_exists`-only loop,
    // and reap the process *group* via `reap_process_group` on failure instead of the
    // leader-only, non-blocking `process.kill()` (which orphans the group).
    if crate::vmm::wait_for_socket(&api_socket, &mut process, 1000, 20)
        .await
        .is_err()
    {
        crate::vmm::reap_process_group(&mut process, pgid);
        return T2Probe::Failed;
    }

    let instance = FcInstance {
        process,
        api_socket: api_socket.clone(),
        vsock_path: PathBuf::new(),
        serial_path: PathBuf::new(),
        cid: 0,
        pgid,
        vhost_user_net: false,
        restored: false,
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
        return T2Probe::Failed;
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
        return T2Probe::Failed;
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

    classify_t2_boot(&boot_res)
}

impl Vmm for Firecracker {
    type Instance = FcInstance;

    async fn create(
        &self,
        cfg: &VmConfig,
        res: &PerVmResources,
        cgroups: &dyn crate::metrics::CgroupFs,
    ) -> Result<Self::Instance> {
        // VMM-1: reject a virtio-fs *rootfs* up front via the shared self-guard
        // (mirrored across CH/QEMU/FC) rather than spawning a VMM and rejecting later
        // at the drive-configuration step. The `RootfsSource::VirtioFs` arm further
        // below stays as defense in depth.
        crate::vmm::reject_virtio_fs_rootfs(self.id(), &cfg.rootfs)?;

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
        // `noxsave` is the extended-FPU restore-guard *fallback*, applied only when no
        // CPU template was chosen (see `noxsave_fallback`); capture the decision now,
        // before `template` is moved into the machine-config request below.
        let fpu_guard = noxsave_fallback(template.is_some());

        let (api_socket, vsock_path, serial_path, process, pgid) =
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
            // Cold boot: `boot()` issues `InstanceStart` (not a resume).
            restored: false,
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
                "console=ttyS0 loglevel=6 random.trust_cpu=on random.trust_bootloader=on root=/dev/vda rootfstype={} ro {} panic=1 {}init=/usr/sbin/vmcell-guest-agent vmcell_vmid={}",
                match &cfg.rootfs {
                    crate::config::RootfsSource::Erofs { .. } => "erofs",
                    _ => "ext4",
                },
                match &cfg.rootfs {
                    crate::config::RootfsSource::Erofs { .. } => "",
                    _ => "rootflags=noload",
                },
                fpu_guard,
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

        let (api_socket, _vsock_path, serial_path, process, pgid) =
            self.spawn_fc(res, cgroups).await?;

        // Firecracker rebinds the snapshot's recorded host vsock UDS at load time.
        // Remove any leftover socket file there first (a sequential restore reuses
        // the same path), otherwise the bind fails with EADDRINUSE. The directory is
        // kept so FC can recreate the socket and reopen the serial sink.
        let _ = tokio::fs::remove_file(&host_paths.vsock).await;

        let instance = FcInstance {
            process,
            api_socket,
            // Adopt the snapshot's vsock path so the agent dials the exact UDS FC
            // recreates verbatim on load (no load-time override). Serial is the
            // opposite: FC writes it to the FRESH `spawn_fc` stdout redirect
            // (`res.tmp_dir/serial.log`), NOT the snapshot's baked serial path — so
            // `serial_log()`/panic detection must point at the fresh path, or it reads
            // an empty/stale file FC never writes (VMM-6).
            vsock_path: host_paths.vsock,
            serial_path,
            cid: res.guest_cid,
            pgid,
            // Guarded false above; computed from `res` to mirror CH.
            vhost_user_net: res.vhost_user_socket.is_some(),
            // Restored VMs are returned paused and resumed via `resume()`; `boot()`
            // self-guards on this and refuses to `InstanceStart` (VMM-6).
            restored: true,
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
        // VMM-6: a restored FC VM is returned paused by
        // `POST /snapshot/load {resume_vm:false}` and resumed via `resume()` — never
        // booted. Issuing `InstanceStart` on it is a misuse that would (re)start a
        // snapshot-loaded VM, so self-guard and fail loud (a silent `Ok(())` no-op
        // would violate the fail-loud contract) instead of `InstanceStart`-ing it.
        if self.restored {
            return Err(Error::Unsupported {
                vmm: "firecracker".to_string(),
                feature: "boot after restore (a restored VM is resumed, not booted)".to_string(),
            });
        }
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

    async fn has_exited(&mut self) -> bool {
        // Non-blocking reap of the VMM leader; `Ok(Some(_))` means it exited after
        // `request_shutdown`. Safe to reap early — the later SIGKILL of the dead
        // group is a no-op and `process.wait()` returns the cached status.
        matches!(self.process.try_wait(), Ok(Some(_)))
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
        // Teardown order (AGENTS.md): VMM process group first — reaping it before
        // touching the sockets or the per-VM directory means cleanup never races a
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
        // Unlink our own sockets. The per-VM directory itself is owned and removed
        // once by the orchestrator's `VmTempDir` guard (after this instance and the
        // smoltcp process are dropped), not here. Mirrors CH.
        let _ = std::fs::remove_file(&self.api_socket);
        let _ = std::fs::remove_file(&self.vsock_path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Guards VMM-1 for the FC `create()` path: a virtio-fs *rootfs* config reaches
    // create(), which self-guards up front with a typed `Unsupported` (FC also keeps a
    // defense-in-depth arm at the drive step). Inverse: an erofs rootfs must NOT trip
    // the guard.
    #[test]
    fn create_rejects_virtio_fs_rootfs() {
        use crate::config::RootfsSource;

        let err = crate::vmm::reject_virtio_fs_rootfs(
            Firecracker::new("/usr/bin/firecracker").id(),
            &RootfsSource::VirtioFs {
                dir: PathBuf::from("/d"),
            },
        )
        .expect_err("FC create() must reject a virtio-fs rootfs");
        assert!(
            matches!(&err, Error::Unsupported { vmm, feature }
                if vmm == "firecracker" && feature == "virtio_fs_rootfs"),
            "expected virtio_fs_rootfs Unsupported, got {err:?}"
        );

        crate::vmm::reject_virtio_fs_rootfs(
            Firecracker::new("/usr/bin/firecracker").id(),
            &RootfsSource::Erofs {
                image: PathBuf::from("/i"),
            },
        )
        .expect("an erofs rootfs must not trip the FC guard");
    }

    // Guards VMM-4: the probe must distinguish a firm "T2 unsupported" (a 400 template
    // error) from a transient probe failure (a 500, a non-template 400, a timeout, a
    // transport error). The buggy inverse — the old code collapsed every `Err(_)` to
    // "not supported" — makes the 500/timeout/non-template assertions go red.
    #[test]
    fn classify_t2_boot_distinguishes_unsupported_from_failed() {
        assert_eq!(classify_t2_boot(&Ok(())), T2Probe::Supported);
        assert_eq!(
            classify_t2_boot(&Err(Error::VmmApi {
                status: 400,
                body: "cpu template T2 not supported".to_string(),
            })),
            T2Probe::Unsupported
        );
        // A 500 is a host error, NOT a firm "unsupported".
        assert_eq!(
            classify_t2_boot(&Err(Error::VmmApi {
                status: 500,
                body: "internal error".to_string(),
            })),
            T2Probe::Failed
        );
        // A 400 that isn't about the template is also just a failure, not "unsupported".
        assert_eq!(
            classify_t2_boot(&Err(Error::VmmApi {
                status: 400,
                body: "some other validation error".to_string(),
            })),
            T2Probe::Failed
        );
        // A non-API error (timeout / transport) is a transient failure.
        assert_eq!(
            classify_t2_boot(&Err(Error::Timeout("probe".to_string()))),
            T2Probe::Failed
        );
    }

    // Guards VMM-4: a TRANSIENT probe failure must NOT be cached (so the next VM
    // re-probes); only a definite Supported/Unsupported is cached. The buggy inverse
    // (`Failed => Some(None)`) permanently disables the T2 template — and the
    // extended-FPU restore guard — for every VM after a single host hiccup; here the
    // `Failed` assertion goes red.
    #[test]
    fn cache_decision_never_caches_transient_failure() {
        assert_eq!(cache_decision(T2Probe::Failed), None);
        assert_eq!(
            cache_decision(T2Probe::Supported),
            Some(Some("T2".to_string()))
        );
        assert_eq!(cache_decision(T2Probe::Unsupported), Some(None));
    }

    /// `noxsave` is the extended-FPU guard *fallback* — emitted only when no CPU
    /// template was applied. With a template it must be absent (it would needlessly
    /// disable the guest AVX2 the template leaves usable). The inverse — the former
    /// unconditional `noxsave` (audit E6, over-applied even with T2) — makes the
    /// `true` case go red.
    #[test]
    fn noxsave_only_applied_without_cpu_template() {
        assert_eq!(noxsave_fallback(false), "noxsave ");
        assert_eq!(noxsave_fallback(true), "");
    }

    /// Spawns a long-lived stand-in process in its own process group so an
    /// `FcInstance` can own a real `Child` (whose `Drop`/`kill` reaps the group) in a
    /// test that never boots a real VM.
    fn spawn_group_standin() -> Child {
        let mut std_cmd = std::process::Command::new("sleep");
        std_cmd.arg("60");
        use std::os::unix::process::CommandExt;
        std_cmd.process_group(0);
        tokio::process::Command::from(std_cmd)
            .spawn()
            .expect("spawn sleep stand-in")
    }

    fn instance_with(restored: bool) -> FcInstance {
        let child = spawn_group_standin();
        FcInstance {
            pgid: child.id(),
            process: child,
            // A deliberately-absent api socket: a restored VM must refuse boot BEFORE
            // any api_request, so this path is never dialed on that branch.
            api_socket: std::env::temp_dir().join("vmcell-fc-boot-test-nonexistent.sock"),
            vsock_path: PathBuf::new(),
            serial_path: PathBuf::new(),
            cid: 3,
            vhost_user_net: false,
            restored,
        }
    }

    // Guards VMM-6: a restored FC instance must REFUSE `boot()` — a restored VM is
    // returned paused and resumed via `resume()`, never `InstanceStart`ed. The guard is
    // checked before any api_request, so it returns without touching the absent api
    // socket. The buggy inverse (no `restored` flag / no guard) would `InstanceStart` a
    // restored VM; here the restored assertion goes red. The cold instance must NOT
    // report boot-after-restore (it proceeds to InstanceStart and fails on the missing
    // socket with a transport error), which proves the `restored` flag is load-bearing.
    #[tokio::test]
    async fn restored_instance_refuses_boot() {
        let mut restored = instance_with(true);
        let err = restored
            .boot()
            .await
            .expect_err("a restored VM must refuse boot()");
        assert!(
            matches!(&err, Error::Unsupported { vmm, feature }
                if vmm == "firecracker" && feature.contains("boot after restore")),
            "expected boot-after-restore Unsupported, got {err:?}"
        );
        let _ = restored.kill().await;

        let mut cold = instance_with(false);
        let err = cold
            .boot()
            .await
            .expect_err("a cold VM with no api socket hits a transport error");
        assert!(
            !matches!(&err, Error::Unsupported { feature, .. } if feature.contains("boot after restore")),
            "a cold instance must not report boot-after-restore, got {err:?}"
        );
        let _ = cold.kill().await;
    }

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
        let vsock = PathBuf::from("/tmp/vmcell-vsock.sock");
        let serial = PathBuf::from("/tmp/vmcell-serial.log");

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
