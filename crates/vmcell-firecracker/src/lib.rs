//! Firecracker VMM backend for `vmcell`.
//!
//! Provides the [`Firecracker`] implementation of the [`vmcell::vmm::Vmm`] trait and its
//! running-instance type [`FcInstance`]. Extracted from the `vmcell` crate (design §2.1, The
//! trait and the capability descriptor) so the core library carries only the primary Cloud
//! Hypervisor backend; this crate depends on `vmcell` for the shared `Vmm`/`VmInstance` traits,
//! the jail/seccomp predicates, and the spawn/reap/console/snapshot-eligibility helpers — every
//! "one law, one predicate" invariant stays single-sourced in `vmcell`.

#![deny(missing_docs)]
#![deny(unreachable_pub)] // pub-in-private-module API-surface honesty
#![deny(
    clippy::undocumented_unsafe_blocks,
    clippy::missing_safety_doc,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::multiple_unsafe_ops_per_block, // one obligation per SAFETY comment
    unsafe_op_in_unsafe_fn,
    rustdoc::broken_intra_doc_links
)]
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::panic,
        clippy::unreachable,
        clippy::todo,
        clippy::unimplemented,
        clippy::indexing_slicing,
        clippy::print_stdout,
        clippy::print_stderr,
        clippy::dbg_macro,
        clippy::allow_attributes,               // B11: prefer #[expect] over #[allow] in prod code
        clippy::allow_attributes_without_reason  // B11: every suppression states why
    )
)]

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use vmcell::config::VmConfig;
use vmcell::error::{Error, Result};
use vmcell::vmm::{PerVmResources, VmInstance, Vmm, VmmCapabilities};

use tokio::process::Child;

/// Sidecar file (written into the snapshot directory by [`FcInstance::snapshot`])
/// recording the host-side vsock UDS path and guest CID the snapshot baked in.
///
/// Firecracker's `PUT /snapshot/load` restores the vsock device *verbatim* from
/// the snapshot — it rebinds the **original** host UDS path and offers no
/// load-time override. A restore therefore runs under a fresh, vmid-derived tmp
/// dir but must rebind (and have the agent dial) the path the snapshot recorded,
/// and report the guest's baked CID. This sidecar carries both across the
/// snapshot/restore boundary.
const HOST_PATHS_SIDECAR: &str = "vmcell_host_paths.json";

/// Host-side vsock UDS path and guest CID baked into a Firecracker snapshot,
/// persisted alongside it so a later restore can rebind the exact socket FC
/// recreates (it offers no load-time override) and report the guest's baked CID.
#[derive(Serialize, Deserialize)]
struct SnapshotHostPaths {
    /// Host vsock UDS path FC baked into the snapshot; `restore()` re-binds it verbatim.
    vsock: PathBuf,
    /// Guest CID baked into the snapshot. A restored FC VM keeps this CID (the vsock
    /// device is loaded verbatim), so `guest_cid()` must report it, not the
    /// orchestrator's fresh allocation (M-VMM-3).
    cid: u32,
}

/// The Firecracker capability descriptor, exposed as a free function so both
/// [`Firecracker::capabilities`] and [`FcInstance::snapshot`] consult the **same**
/// source of truth — the latter holds no handle to the `Firecracker` backend yet
/// must self-check `snapshot_restore` (M-RESTORE-3).
fn fc_capabilities() -> VmmCapabilities {
    VmmCapabilities {
        // E2 (empirical, KVM host, pre-v17): FC warm restore used to drop the first
        // post-restore exec ("Connection dropped during exec"). That symptom predated
        // the guest agent's generic re-bind-after-restore loop (REBIND_IDLE 250 ms,
        // cmdline-tunable, now event-driven poll(2)) and the native in-agent resync —
        // re-validated ON (EXP-E, docs/45-claude-perf-investigation.md): the full
        // snapshot_restore::firecracker matrix assertion set (post-restore exec,
        // native MAC rotation, reseed, fail-loud clock resync, ordered teardown)
        // passes repeatedly in isolation on a KVM host. Flip back to `false` only
        // with a reproducing failure recorded in docs/45.
        snapshot_restore: true,
        // M-VMM-1: a real UFFD page-fault backend for `RestoreMode::Lazy` is not
        // wired (restore would hardcode `backend_type: "File"`, faulting eagerly), so
        // the flag is honest-false rather than silently degrading Lazy to eager.
        lazy_restore: false,
        virtio_fs_shares: false,
        unprivileged_vhost_user_net: false,
        nested_virt: false,
        // Firecracker has no virtio-console device; a VirtioConsole config is
        // rejected up front by `reject_unsupported_console` so it can never emit
        // `console=hvc0` with no `hvc0` device.
        virtio_console: false,
        // FC's `PUT /snapshot/load` re-binds the snapshot's recorded host vsock
        // UDS path VERBATIM — no load-time override exists in v1.16 — so a
        // restored VM never gets fresh host-side socket paths (see
        // `HOST_PATHS_SIDECAR` and `reject_live_baked_vsock`). All restores of a
        // lineage share the one baked path: restore-while-alive is rejected and
        // concurrent restores from one lineage are unsupported.
        restore_rotates_host_paths: false,
    }
}

/// Serializes and writes the host vsock UDS path and guest CID Firecracker baked into
/// a snapshot to the [`HOST_PATHS_SIDECAR`] file in `dir`. The sidecar is part of the
/// snapshot artifact and `restore()` hard-requires it, so a serialize or write
/// failure is surfaced (M-RESTORE-2) — never logged-and-swallowed, which would
/// report an unrestorable snapshot as successful.
async fn write_host_paths_sidecar(dir: &Path, vsock: &Path, cid: u32) -> Result<()> {
    let json = serde_json::to_string(&SnapshotHostPaths {
        vsock: vsock.to_path_buf(),
        cid,
    })?;
    tokio::fs::write(dir.join(HOST_PATHS_SIDECAR), json).await?;
    Ok(())
}

/// Pre-restore guard + cleanup for the snapshot's baked host vsock UDS path
/// (`restore_rotates_host_paths: false` — FC re-binds this exact path verbatim).
///
/// A leftover socket *file* at the baked path is normal (the base VM's teardown
/// unlinks best-effort, and a sequential restore reuses the path), and must be
/// removed or FC's bind fails `EADDRINUSE`. But a socket that still **accepts a
/// connection** means a live VMM — the snapshotted VM or a prior restore of the
/// same lineage — still owns it; unlinking it would silently sever that VM's
/// agent transport. So: if the path exists, probe it with a short-timeout
/// connect and fail loud with a typed `Error::Vmm` naming the path when a
/// listener answers. Only a dead path (ECONNREFUSED / ENOENT / timeout) proceeds
/// to `remove_file` + `create_dir_all(parent)` — the parent re-creation matters
/// because the baked path lives in the long-gone base VM's scratch dir, and a
/// missing parent fails `PUT /snapshot/load` with ENOENT.
///
/// TOCTOU, honestly: the probe and the unlink are not atomic — a restore racing
/// this window can still lose. This is a *misuse guard* catching the realistic
/// sequential mistake (restoring while the lineage is alive), not a security
/// boundary; the single-lineage constraint (design §17, Open gaps and future capabilities) is the real contract.
async fn reject_live_baked_vsock(path: &Path) -> Result<()> {
    if tokio::fs::try_exists(path).await.unwrap_or(false) {
        // Only `Ok(Ok(_))` — a listener actually accepted the probe — rejects.
        // ECONNREFUSED / ENOENT / not-a-socket (`Ok(Err(_))`) and a probe timeout
        // (`Err(_)`) all mean no live listener owns the path: a stale leftover.
        if let Ok(Ok(_stream)) = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            tokio::net::UnixStream::connect(path),
        )
        .await
        {
            return Err(Error::Vmm(format!(
                "snapshot's baked host vsock path {} is still in use (a live \
                 listener accepted a probe connection): the snapshotted VM or a \
                 prior restore of this snapshot lineage still owns it; Firecracker \
                 re-binds this exact path verbatim, so restore must wait for that \
                 VM's teardown",
                path.display()
            )));
        }
    }
    let _ = tokio::fs::remove_file(path).await;
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
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
    /// snapshot-eligible (§2.5, The capability matrix); `snapshot()` self-guards on it. Always `false` on
    /// FC today because `create()` rejects every vhost-user device up front, but the
    /// field keeps the snapshot guard correct by construction. Mirrors CH.
    vhost_user_net: bool,
    /// True if this instance came from a snapshot `restore()`. A restored FC VM is
    /// returned **paused** by `POST /snapshot/load {resume_vm:false}` and resumed via
    /// `resume()`, never `boot()` — so `boot()` self-guards on this flag and refuses
    /// to `InstanceStart` a restored VM (VMM-6). Mirrors CH's `restored` field.
    restored: bool,
    /// True once the VMM leader has been reaped (via `has_exited`/`kill`). After the
    /// leader is reaped the kernel can recycle its pgid, so `kill`/`Drop` must NOT
    /// re-`SIGKILL` the process group or they could hit an unrelated group (M-VMM-1).
    reaped: bool,
}

impl FcInstance {
    async fn api_request(
        &self,
        method: &str,
        path: &str,
        body: Option<&impl Serialize>,
    ) -> Result<()> {
        vmcell::vmm::unix_api_request(&self.api_socket, method, path, body).await
    }
}

impl Firecracker {
    async fn spawn_fc(
        &self,
        cfg: &VmConfig,
        res: &PerVmResources,
        cgroups: &dyn vmcell::metrics::CgroupFs,
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

        // §12.2 (Layer 1 — the VMM's own seccomp filter)/§12.3 (Layer 2 — the jailer-equivalent (JailSpec + apply_jail)): FC's built-in seccomp filter is on unless `--no-seccomp` (Disabled);
        // the jailer-equivalent hardening is applied in build_vmm_cmd's forked-child window.
        let seccomp_args = vmcell::vmm::seccomp::vmm_seccomp_args("firecracker", cfg.vmm_seccomp)?;
        let jail = vmcell::vmm::jail::jail_spec_from_config(&cfg.jail)?;
        let mut cmd =
            vmcell::vmm::build_vmm_cmd(&self.binary_path, res.netns_name.as_deref(), &jail);
        cmd.args(&seccomp_args);

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
        let pgid = vmcell::vmm::register_and_await_ready(
            &mut process,
            cgroups,
            &res.cgroup_name,
            &api_socket,
            1000,
            cfg.timeouts.api_socket_poll.as_millis() as u64,
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
/// (design §2.3, Firecracker — the density tier and the fastest restore). `noxsave` is the **fallback** for hosts where the template does not
/// fit; applying it *with* a template needlessly disables the guest AVX2 the template
/// leaves usable, so it is emitted **only when no template was applied**. Returned with a
/// trailing space so it composes cleanly into the boot-args when non-empty and vanishes
/// when empty. Pure so the gating is unit-testable (audit E6,
/// `docs/41-experimental-conclusions-audit.md`).
fn noxsave_fallback(has_cpu_template: bool) -> &'static str {
    if has_cpu_template { "" } else { "noxsave " }
}

/// Reaps a failed T2-probe child's process group and unlinks its API socket. On the
/// `wait_for_socket`-failure branch no `FcInstance` owns the socket yet (the instance
/// is built only after a successful wait), so its `Drop` never runs — without this,
/// firecracker that created its socket then exited early orphans a
/// `vmcell-fc-probe-*.socket` in the temp dir. Reap first (VMM process group before
/// sockets), then unlink, mirroring `FcInstance::drop`.
fn reap_and_unlink_probe(process: &mut tokio::process::Child, pgid: Option<u32>, socket: &Path) {
    vmcell::vmm::reap_process_group(process, pgid);
    let _ = std::fs::remove_file(socket);
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
    if vmcell::vmm::wait_for_socket(
        &api_socket,
        Some(&mut process),
        1000,
        cfg.timeouts.api_socket_poll.as_millis() as u64,
    )
    .await
    .is_err()
    {
        reap_and_unlink_probe(&mut process, pgid, &api_socket);
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
        reaped: false,
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
        cgroups: &dyn vmcell::metrics::CgroupFs,
    ) -> Result<Self::Instance> {
        // FC has no virtio-console device, so a VirtioConsole config must be rejected
        // BEFORE build_kernel_cmdline — otherwise the boot args would carry
        // `console=hvc0` with no `hvc0` device and `serial.log` would stay empty.
        vmcell::vmm::reject_unsupported_console(
            "firecracker",
            &self.capabilities(),
            cfg.console_mode,
        )?;

        let caps = self.capabilities();
        if let vmcell::config::NetConfig::Unprivileged { .. } = cfg.net
            && !caps.unprivileged_vhost_user_net
        {
            return Err(Error::Unsupported {
                vmm: "firecracker".to_string(),
                // N-VMM-1: match the VmmCapabilities field name so callers matching
                // feature strings see one consistent spelling across backends.
                feature: "unprivileged_vhost_user_net".to_string(),
            });
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
            self.spawn_fc(cfg, res, cgroups).await?;

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
            reaped: false,
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

        let cmdline = vmcell::config::build_kernel_cmdline(cfg, res.vmid, fpu_guard)?;

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
            /// Optional I/O rate limiter (disk-I/O fault injection, §4.6, Extra virtio-blk devices and disk-I/O throttling). Omitted when
            /// the drive is unthrottled (FC's default).
            #[serde(skip_serializing_if = "Option::is_none")]
            rate_limiter: Option<FcRateLimiter>,
        }
        // FC's `rate_limiter` — bandwidth (bytes/s) and ops (IOPS) token buckets, the
        // SAME shape and `size=rate`/`refill_time=IO_LIMIT_REFILL_TIME_MS` conversion as
        // Cloud Hypervisor (one law, one predicate, §4.6, Extra virtio-blk devices and disk-I/O throttling).
        #[derive(Serialize)]
        struct FcRateLimiter {
            #[serde(skip_serializing_if = "Option::is_none")]
            bandwidth: Option<FcTokenBucket>,
            #[serde(skip_serializing_if = "Option::is_none")]
            ops: Option<FcTokenBucket>,
        }
        #[derive(Serialize)]
        struct FcTokenBucket {
            size: u64,
            refill_time: u64,
        }
        let fc_rate_limiter = |limit: &vmcell::config::DiskIoLimit| {
            let bucket = |rate: u64| FcTokenBucket {
                size: rate,
                refill_time: vmcell::config::IO_LIMIT_REFILL_TIME_MS,
            };
            FcRateLimiter {
                bandwidth: limit.bandwidth_bytes_per_sec.map(bucket),
                ops: limit.iops.map(bucket),
            }
        };

        let rootfs_path = match &cfg.rootfs {
            vmcell::config::RootfsSource::Erofs { image } => image.clone(),
            vmcell::config::RootfsSource::Block { image, overlay } => {
                overlay.as_ref().unwrap_or(image).clone()
            }
        };

        let is_ro = matches!(&cfg.rootfs, vmcell::config::RootfsSource::Erofs { .. });

        instance
            .api_request(
                "PUT",
                "/drives/rootfs",
                Some(&Drive {
                    drive_id: "rootfs".to_string(),
                    path_on_host: rootfs_path,
                    is_root_device: true,
                    is_read_only: is_ro,
                    rate_limiter: None,
                }),
            )
            .await?;

        // Extra virtio-blk devices (§4.6, Extra virtio-blk devices and disk-I/O throttling), PUT AFTER the root drive so they enumerate
        // `/dev/vdb`, `/dev/vdc`, … in order and never displace `/dev/vda`. Each is a
        // non-root drive on its own virtio-mmio slot; FC's MMIO region is finite, so a
        // very large list surfaces fail-loud as the backend's typed API error here,
        // never a silent drop.
        for (i, disk) in cfg.extra_disks.iter().enumerate() {
            let drive_id = format!("extra{i}");
            instance
                .api_request(
                    "PUT",
                    &format!("/drives/{drive_id}"),
                    Some(&Drive {
                        drive_id,
                        path_on_host: disk.image.clone(),
                        is_root_device: false,
                        is_read_only: disk.readonly,
                        rate_limiter: disk.io_limit.as_ref().map(fc_rate_limiter),
                    }),
                )
                .await?;
        }

        // Configure Network
        if let Some(tap) = &res.tap_name {
            #[derive(Serialize)]
            struct NetworkInterface {
                iface_id: String,
                host_dev_name: String,
                guest_mac: String,
            }
            let mac = vmcell::net::mac_math(res.vmid)?;
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

        // Configure the entropy device (virtio-rng -> guest /dev/hwrng). The
        // guest agent's post-restore CSPRNG reseed reads 32 bytes of /dev/hwrng
        // into /dev/urandom (design §8.2, Restore correctness: a restored VM is not a fresh VM); CH always carries an rng device, but
        // FC only attaches one when explicitly configured — without it the
        // restored guest replays the snapshot-frozen entropy pool and the resync
        // ack reports `reseed_applied: false`. The device is snapshot-supported
        // in FC v1.16, so it travels through snapshot/load like the other
        // virtio-mmio devices.
        #[derive(Serialize)]
        struct Entropy {}
        instance
            .api_request("PUT", "/entropy", Some(&Entropy {}))
            .await?;

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
        cgroups: &dyn vmcell::metrics::CgroupFs,
    ) -> Result<Self::Instance> {
        // FC has no virtio-console device; reject a VirtioConsole config before any
        // spawn/build_kernel_cmdline so it can never emit `console=hvc0` with no
        // `hvc0` device.
        vmcell::vmm::reject_unsupported_console(
            "firecracker",
            &self.capabilities(),
            cfg.console_mode,
        )?;
        // VMM-5: self-check the capability descriptor rather than assuming the
        // backend supports restore.
        if !self.capabilities().snapshot_restore {
            return Err(Error::Unsupported {
                vmm: "firecracker".to_string(),
                feature: "snapshot_restore".to_string(),
            });
        }
        // M-RESTORE-3 / H-VMM-3 / snapshot-eligibility law: a snapshot-eligible VM has
        // no vhost-user device. Use the SHARED predicate (which also covers a virtio-fs
        // *rootfs* — the case FC's former inline check missed) to reject any virtio-fs
        // share/rootfs, unprivileged net, or external vhost-user-net handed to us via
        // the config, before spawning a VMM. FC never attaches these, so this is
        // defense in depth.
        if vmcell::vmm::config_has_vhost_user_device(cfg, res) {
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

        // Firecracker rebinds the snapshot's recorded host vsock UDS at load time,
        // VERBATIM (`restore_rotates_host_paths: false`). Guard-then-clean the
        // baked path — reject a still-live listener, remove a stale leftover
        // (else the bind fails EADDRINUSE), resurrect the missing parent dir
        // (else `PUT /snapshot/load` fails ENOENT) — see `reject_live_baked_vsock`.
        // Runs BEFORE spawning, like the sidecar read above, so a rejected restore
        // fails loud without leaking a VMM process. The restored instance adopts
        // the path and its `Drop` removes the resurrected dir.
        reject_live_baked_vsock(&host_paths.vsock).await?;

        let (api_socket, _vsock_path, serial_path, process, pgid) =
            self.spawn_fc(cfg, res, cgroups).await?;

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
            // A restored guest keeps the CID baked into its snapshot (the vsock device
            // is loaded verbatim); report that, not the orchestrator's fresh allocation
            // (M-VMM-3).
            cid: host_paths.cid,
            pgid,
            // Guarded false above; computed from `res` to mirror CH.
            vhost_user_net: res.vhost_user_socket.is_some(),
            // Restored VMs are returned paused and resumed via `resume()`; `boot()`
            // self-guards on this and refuses to `InstanceStart` (VMM-6).
            restored: true,
            reaped: false,
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
            // Skip the group SIGKILL if the leader was already reaped (its pgid may be
            // recycled) — M-VMM-1.
            if !self.reaped {
                let _ = nix::sys::signal::kill(
                    nix::unistd::Pid::from_raw(-(pgid as i32)),
                    nix::sys::signal::Signal::SIGKILL,
                );
            }
        }
        let _ = self.process.wait().await;
        // The leader is reaped now; `Drop` must not re-signal a possibly-recycled pgid.
        self.reaped = true;
        Ok(())
    }

    async fn has_exited(&mut self) -> bool {
        // Non-blocking reap of the VMM leader; `Ok(Some(_))` means it exited after
        // `request_shutdown`. Record the reap so `kill()`/`Drop` do NOT re-`SIGKILL`
        // the process group: once the leader is reaped the kernel may recycle its pgid
        // and signalling `-pgid` could hit an unrelated group (M-VMM-1).
        if matches!(self.process.try_wait(), Ok(Some(_))) {
            self.reaped = true;
            true
        } else {
            false
        }
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
        if vmcell::vmm::has_vhost_user_device(false, false, self.vhost_user_net) {
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
            Ok(()) => write_host_paths_sidecar(dir, &self.vsock_path, self.cid).await,
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
            // Skip the group SIGKILL + reap if the leader was already reaped (via
            // `has_exited`/`kill`): its pgid may have been recycled (M-VMM-1).
            if !self.reaped {
                let _ = nix::sys::signal::kill(
                    nix::unistd::Pid::from_raw(-(pgid as i32)),
                    nix::sys::signal::Signal::SIGKILL,
                );
                if let Some(pid) = self.process.id() {
                    let _ = nix::sys::wait::waitpid(nix::unistd::Pid::from_raw(pid as i32), None);
                }
            }
        }
        // Unlink our own sockets. The per-VM directory itself is owned and removed
        // once by the orchestrator's `VmTempDir` guard (after this instance and the
        // smoltcp process are dropped), not here. Mirrors CH.
        let _ = std::fs::remove_file(&self.api_socket);
        let _ = std::fs::remove_file(&self.vsock_path);
        // A RESTORED instance adopts the snapshot's baked vsock path, whose parent
        // dir `restore()` resurrected (it belongs to the long-gone base VM, so no
        // `VmTempDir` guard owns it). Remove it here — `remove_dir` is
        // non-recursive, so it only succeeds once empty, and it is a no-op for a
        // cold-booted instance whose vsock lives in the guard-owned scratch dir
        // (still holding api.sock/serial.log at this point, and removed by the
        // guard anyway).
        if let Some(parent) = self.vsock_path.parent() {
            let _ = std::fs::remove_dir(parent);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A no-op [`vmcell::metrics::CgroupFs`] for the reject-before-spawn tests below, which
    /// exercise `create`/`restore` capability guards that return **before** any cgroup
    /// interaction — so the fake's methods are never called. Replaces the former
    /// `vmcell::metrics::FakeCgroupFs` (a `#[cfg(test)]`-only fixture that is not visible to a
    /// downstream crate's test build).
    #[derive(Debug)]
    struct TestCgroupFs;

    impl TestCgroupFs {
        fn new() -> Self {
            Self
        }
    }

    impl vmcell::metrics::CgroupFs for TestCgroupFs {
        fn create_slice(
            &self,
            _name: &str,
            _limits: &vmcell::config::ResourceLimits,
        ) -> Result<()> {
            Ok(())
        }
        fn delete_slice(&self, _name: &str) -> Result<()> {
            Ok(())
        }
        fn read_stats(&self, _name: &str) -> Result<vmcell::metrics::ResourceUsage> {
            Ok(vmcell::metrics::ResourceUsage::default())
        }
        fn add_task(&self, _name: &str, _pid: u32) -> Result<()> {
            Ok(())
        }
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

    // The T2-probe `wait_for_socket`-failure branch must unlink its API socket: no
    // FcInstance owns it there, so `Drop` never does. Residue check: the socket exists
    // before, is gone after. RED on the inverse (reap-only, no remove_file): the file
    // survives and `assert!(!socket.exists())` reddens.
    #[tokio::test]
    async fn reap_and_unlink_probe_removes_the_probe_socket() {
        let socket = std::env::temp_dir().join(format!(
            "vmcell-fc-probe-test-{}.socket",
            std::process::id()
        ));
        std::fs::write(&socket, b"").expect("seed probe socket");
        assert!(
            socket.exists(),
            "precondition: the probe socket exists before cleanup"
        );
        let mut child = spawn_group_standin();
        let pgid = child.id();
        reap_and_unlink_probe(&mut child, pgid, &socket);
        assert!(
            !socket.exists(),
            "the failed-probe branch must unlink its API socket"
        );
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
            reaped: false,
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

    // Guards the capability HONESTY in both directions: `snapshot_restore` is
    // advertised `true` only because the full FC restore matrix assertion set was
    // re-validated on a KVM host (EXP-E, docs/45 — the historical E2 drop predated
    // the generic re-bind + native resync); `lazy_restore` stays honest-false until
    // a real UFFD backend is wired (M-VMM-1 — Lazy would silently degrade to eager).
    // A regression that turns FC restore back into the E2 symptom must flip the
    // capability AND this test together, with the failure recorded in docs/45.
    #[test]
    fn capabilities_are_honest_about_snapshot_restore() {
        let caps = Firecracker::new("/usr/bin/firecracker").capabilities();
        assert!(
            caps.snapshot_restore,
            "FC snapshot_restore is KVM-validated ON (EXP-E); a deliberate re-gate must update docs/45"
        );
        assert!(
            !caps.lazy_restore,
            "FC lazy_restore must be false until a real UFFD backend is wired (M-VMM-1)"
        );
        // FC re-binds the snapshot's baked host vsock UDS path VERBATIM (no
        // load-time override in v1.16); advertising rotation would let callers
        // assume fresh per-restore paths FC cannot provide (and would flip the
        // snapshot_restore integration test onto the CH-only rotation asserts).
        assert!(
            !caps.restore_rotates_host_paths,
            "FC restore_rotates_host_paths must be false: /snapshot/load re-binds the \
             baked path verbatim"
        );
        // CH, by contrast, rewrites the restore config so the vsock lands in the NEW
        // VM's scratch dir (§8.2, Restore correctness: a restored VM is not a fresh VM) — the rotation semantics the integration test's
        // `assert_ne` branch encodes.
        assert!(
            vmcell::vmm::cloud_hypervisor::CloudHypervisor::new("/usr/bin/cloud-hypervisor")
                .capabilities()
                .restore_rotates_host_paths,
            "CH restore_rotates_host_paths must be true: the restore config rewrite \
             moves host socket paths into the restored VM's own scratch dir"
        );
        // The instance-facing free function and the `Vmm` trait method must agree, so
        // `FcInstance::snapshot`'s self-check sees the same gate the orchestrator does.
        assert_eq!(caps.snapshot_restore, fc_capabilities().snapshot_restore);
        assert_eq!(caps.lazy_restore, fc_capabilities().lazy_restore);
        assert_eq!(
            caps.restore_rotates_host_paths,
            fc_capabilities().restore_rotates_host_paths
        );
    }

    // Guards H-VMM-3: FC restore()'s snapshot-eligibility guard must reject a virtio-fs
    // data share (a vhost-user device) via the SHARED `config_has_vhost_user_device`
    // predicate. It returns BEFORE reading the sidecar or spawning, so no KVM/snapshot
    // artifact is needed. Inverse (an inline check that never consulted the shared
    // predicate) falls through to the sidecar read and fails with an I/O error, not
    // this typed vhost-user Unsupported — reddening the assert.
    #[tokio::test]
    async fn restore_rejects_virtio_fs_share() {
        use vmcell::config::{Access, CachePolicy, RootfsSource, Share};
        let fc = Firecracker::new("/usr/bin/firecracker");
        let cfg = VmConfig::builder(
            "/k",
            RootfsSource::Erofs {
                image: PathBuf::from("/i"),
            },
        )
        .with_share(Share::new(
            "data",
            "/tmp/data",
            Access::ReadOnly,
            CachePolicy::Auto,
        ))
        .build()
        .expect("build virtio-fs share config");
        let res = PerVmResources {
            cgroup_name: "vmcell-test".to_string(),
            tap_name: Some("tap0".to_string()),
            netns_name: None,
            vhost_user_socket: None,
            vmid: 1,
            guest_cid: 3,
            tmp_dir: std::env::temp_dir().join("vmcell-fc-restore-vfs-test"),
        };
        let cgroups = TestCgroupFs::new();
        let err = fc
            .restore(Path::new("/nonexistent-snapshot"), &cfg, &res, &cgroups)
            .await
            .expect_err("FC restore must reject a virtio-fs data share");
        assert!(
            matches!(&err, Error::Unsupported { vmm, feature }
                if vmm == "firecracker" && feature.contains("vhost-user")),
            "expected a vhost-user Unsupported, got {err:?}"
        );
    }

    // Guards N-VMM-1: the Unsupported.feature string for unprivileged networking must
    // match the VmmCapabilities field name (`unprivileged_vhost_user_net`), not the
    // ad-hoc `unprivileged_net`. create() reaches this check before spawning, so no KVM
    // is needed. Inverse (the old "unprivileged_net" literal) reddens the assert.
    #[tokio::test]
    async fn create_rejects_unprivileged_net_with_capability_field_name() {
        use vmcell::config::{Egress, NetConfig, RootfsSource};
        let fc = Firecracker::new("/usr/bin/firecracker");
        let cfg = VmConfig::builder(
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
        let res = PerVmResources {
            cgroup_name: "vmcell-test".to_string(),
            tap_name: None,
            netns_name: None,
            vhost_user_socket: None,
            vmid: 1,
            guest_cid: 3,
            tmp_dir: std::env::temp_dir().join("vmcell-fc-unpriv-test"),
        };
        let cgroups = TestCgroupFs::new();
        let err = fc
            .create(&cfg, &res, &cgroups)
            .await
            .expect_err("FC has no unprivileged vhost-user-net");
        assert!(
            matches!(&err, Error::Unsupported { vmm, feature }
                if vmm == "firecracker" && feature == "unprivileged_vhost_user_net"),
            "expected the capability-field-name feature string, got {err:?}"
        );
    }

    // Guards M-VMM-1: `has_exited` must RECORD the leader's reap so `kill`/`Drop` do not
    // re-`SIGKILL` a possibly-recycled pgid. Inverse: `has_exited` returns the bool
    // without setting `reaped` and the field stays false, reddening the assert.
    #[tokio::test]
    async fn has_exited_records_reaped() {
        let mut inst = instance_with(false);
        // Kill the stand-in leader's group so `has_exited` observes an exited process.
        if let Some(pgid) = inst.pgid {
            let _ = nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(-(pgid as i32)),
                nix::sys::signal::Signal::SIGKILL,
            );
        }
        let mut exited = false;
        for _ in 0..100 {
            if inst.has_exited().await {
                exited = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(exited, "has_exited must report the killed leader as exited");
        assert!(
            inst.reaped,
            "has_exited must record `reaped` after reaping the leader (M-VMM-1)"
        );
    }

    // Guards M-VMM-1: once the leader is reaped, its pgid can be recycled — `kill` must
    // NOT `SIGKILL` `-pgid` or it could hit an unrelated group. A live decoy process
    // stands in for that recycled group. Inverse: drop the `!self.reaped` guard in
    // `kill` and the decoy is SIGKILLed, so `try_wait` reports it exited — reddening
    // the assert.
    #[tokio::test]
    async fn kill_does_not_signal_pgid_when_reaped() {
        // Decoy occupying a pgid, in its own process group.
        let mut decoy = spawn_group_standin();
        let decoy_pid = decoy.id().expect("decoy pid") as i32;

        // The instance's own leader is already gone (reaped == true). Use a fast-exiting
        // child so `kill`'s `process.wait()` returns promptly instead of blocking.
        let leader = tokio::process::Command::new("true")
            .spawn()
            .expect("spawn `true` leader");
        let mut inst = FcInstance {
            process: leader,
            api_socket: PathBuf::new(),
            vsock_path: PathBuf::new(),
            serial_path: PathBuf::new(),
            cid: 3,
            pgid: Some(decoy_pid as u32),
            vhost_user_net: false,
            restored: false,
            reaped: true,
        };
        inst.kill().await.expect("kill");

        // A SIGKILL to the (recycled) pgid would land within a few ms; give it time.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let decoy_status = decoy.try_wait().expect("try_wait decoy");
        // Clean up the decoy regardless of the outcome.
        let _ = nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(-decoy_pid),
            nix::sys::signal::Signal::SIGKILL,
        );
        let _ = decoy.wait().await;

        assert!(
            decoy_status.is_none(),
            "kill() on a reaped instance must not SIGKILL a (recycled) pgid — the decoy died"
        );
    }

    // Guards M-RESTORE-2 + M-VMM-3: the restore sidecar is part of the snapshot
    // artifact, so a write failure must be SURFACED, not swallowed. The buggy impl
    // (`let _ = tokio::fs::write(...).await; Ok(())`) returns `Ok` even when the
    // write fails, making `snapshot()` report an unrestorable snapshot as success;
    // the failure-path assert below then goes red. The happy path round-trips the
    // vsock path AND the baked guest CID so `restore()` can rebind the socket and
    // report the CID — inverse (drop the `cid` field / read a fresh CID) reddens the
    // CID assertion.
    #[tokio::test]
    async fn sidecar_write_round_trips_and_surfaces_errors() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vsock = PathBuf::from("/tmp/vmcell-vsock.sock");
        let baked_cid: u32 = 7;

        // Happy path: the sidecar is written and round-trips back the exact vsock path
        // and baked CID.
        write_host_paths_sidecar(dir.path(), &vsock, baked_cid)
            .await
            .expect("sidecar write should succeed in a writable dir");
        let raw = tokio::fs::read_to_string(dir.path().join(HOST_PATHS_SIDECAR))
            .await
            .expect("sidecar file should exist after a successful write");
        let parsed: SnapshotHostPaths =
            serde_json::from_str(&raw).expect("sidecar should be valid json");
        assert_eq!(parsed.vsock, vsock);
        assert_eq!(
            parsed.cid, baked_cid,
            "the sidecar must carry the guest CID a restore reports (M-VMM-3)"
        );

        // Failure path: a non-existent target directory makes the write fail; the
        // error MUST propagate rather than be swallowed into `Ok`.
        let missing = dir.path().join("does-not-exist").join("nested");
        assert!(
            write_host_paths_sidecar(&missing, &vsock, baked_cid)
                .await
                .is_err(),
            "a failed sidecar write must surface an error, not be swallowed"
        );
    }

    // Guards the pre-restore liveness guard (`restore_rotates_host_paths: false`):
    // a baked vsock path with a LIVE listener (the snapshotted VM or a prior
    // restore of the lineage still running) must be rejected with a typed
    // still-in-use `Error::Vmm` naming the path — and the live socket must
    // SURVIVE. The buggy inverse — a guard that skips the connect probe and
    // unlinks unconditionally (the pre-guard `remove_file` + `create_dir_all`) —
    // returns `Ok` and severs the live VM's agent transport, reddening both
    // live-listener assertions (verified red). The stale-file and missing-file
    // arms pin the cleanup contract the happy restore path depends on.
    #[tokio::test]
    async fn reject_live_baked_vsock_rejects_live_listener_and_clears_stale() {
        let dir = tempfile::tempdir().expect("tempdir");

        // Live listener: typed rejection, socket left untouched.
        let live = dir.path().join("live.sock");
        let _listener = tokio::net::UnixListener::bind(&live).expect("bind live listener");
        let err = reject_live_baked_vsock(&live)
            .await
            .expect_err("a live listener on the baked path must be rejected");
        assert!(
            matches!(&err, Error::Vmm(msg)
                if msg.contains("still in use") && msg.contains("live.sock")),
            "expected a typed still-in-use Error::Vmm naming the path, got {err:?}"
        );
        assert!(
            live.exists(),
            "the guard must NOT unlink a live VM's socket on the reject path"
        );

        // Stale leftover (a dead socket file, no listener): cleared, parent kept —
        // the sequential-restore case where the bind would otherwise EADDRINUSE.
        let stale = dir.path().join("gone-vm").join("stale.sock");
        std::fs::create_dir_all(stale.parent().expect("parent")).expect("mk parent");
        drop(tokio::net::UnixListener::bind(&stale).expect("bind then drop = stale file"));
        assert!(stale.exists(), "precondition: the stale socket file exists");
        reject_live_baked_vsock(&stale)
            .await
            .expect("a stale socket file must be cleared, not rejected");
        assert!(!stale.exists(), "the stale socket file must be removed");

        // Missing file AND missing parent (the torn-down base VM's scratch dir):
        // Ok, with the parent resurrected so FC's verbatim re-bind can succeed.
        let missing = dir.path().join("gone-parent").join("missing.sock");
        reject_live_baked_vsock(&missing)
            .await
            .expect("a missing baked path must be accepted");
        assert!(
            missing.parent().expect("parent").is_dir(),
            "the baked path's parent dir must be (re)created for FC's verbatim re-bind"
        );
    }
}
