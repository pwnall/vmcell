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
    // The VMM leader's process group AND the one-shot "already reaped" flag, owned
    // together by the one shared helper (`vmm::VmmProcessGroup`, L1): `kill`, `has_exited`
    // and `Drop` all route through it, so no copy can forget the M-VMM-1 guard and
    // SIGKILL a pgid the kernel has since recycled.
    group: crate::vmm::VmmProcessGroup,
    // The guest's RAM size, carried from `VmConfig::mem_mib` at construction, because
    // the snapshot RPC's budget is a function of it (`vmm::snapshot_request_timeout`,
    // M6): a suspend image tracks guest RAM ~1:1, so the write cannot ride the flat
    // control-plane ceiling.
    mem_mib: u32,
    // True if a vhost-user-net device is attached (unprivileged NAT). Such a VM is
    // not snapshot-eligible.
    vhost_user_net: bool,
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
        return Err(Error::unsupported(
            "cloud-hypervisor",
            crate::feature::Feature::SnapshotRestore,
        ));
    }
    if has_vhost_user {
        return Err(Error::from_removal(
            "cloud-hypervisor",
            &crate::feature::VHOST_USER_BLOCKS_SNAPSHOT,
        ));
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
    console: ChConsole,
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

#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
struct ChDisk {
    path: PathBuf,
    readonly: bool,
    direct: bool,
    /// CH's explicit image format. Always `"Raw"` here — every image vmcell attaches
    /// (erofs root, ext4 `Block` root, extra raw block devices) is a raw image. Set
    /// explicitly because CH v52 **auto-detects** an unspecified image as raw and then
    /// **disables sector-0 writes** as a qcow2-misdetection safeguard — which silently
    /// makes a *writable* raw disk reject writes to its first sector (the ext4
    /// superblock region, or a guest write to `/dev/vdb` offset 0). Declaring `Raw`
    /// keeps the whole disk writable and drops CH's deprecation warnings.
    image_type: &'static str,
    /// Optional I/O rate limiter (disk-I/O fault injection, §4.6, Extra virtio-blk devices and disk-I/O throttling). Omitted when the disk
    /// is unthrottled so the JSON matches CH's default.
    #[serde(skip_serializing_if = "Option::is_none")]
    rate_limiter_config: Option<ChRateLimiter>,
}

/// The one image format vmcell attaches — every image is a raw block image (§4.6, Extra
/// virtio-blk devices and disk-I/O throttling / the CH sector-0-write fix above).
const CH_RAW_IMAGE_TYPE: &str = "Raw";

/// CH's per-disk `rate_limiter_config` — independent bandwidth (bytes/s) and ops (IOPS)
/// token buckets (§4.6, Extra virtio-blk devices and disk-I/O throttling). Each is omitted when its cap is unset.
#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
struct ChRateLimiter {
    #[serde(skip_serializing_if = "Option::is_none")]
    bandwidth: Option<ChTokenBucket>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ops: Option<ChTokenBucket>,
}

/// A CH token bucket: `size` tokens refilled every `refill_time` ms (→ `size` per
/// second at [`crate::config::IO_LIMIT_REFILL_TIME_MS`]).
#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
struct ChTokenBucket {
    size: u64,
    refill_time: u64,
}

/// Builds CH's `rate_limiter_config` from a [`DiskIoLimit`](crate::config::DiskIoLimit),
/// using the shared `size = rate`, `refill_time = IO_LIMIT_REFILL_TIME_MS` conversion
/// (one law, one predicate — Firecracker builds the identical bucket, §4.6, Extra virtio-blk devices and disk-I/O throttling).
fn ch_rate_limiter(limit: &crate::config::DiskIoLimit) -> ChRateLimiter {
    let bucket = |rate: u64| ChTokenBucket {
        size: rate,
        refill_time: crate::config::IO_LIMIT_REFILL_TIME_MS,
    };
    ChRateLimiter {
        bandwidth: limit.bandwidth_bytes_per_sec.map(bucket),
        ops: limit.iops.map(bucket),
    }
}

/// Builds the CH `disks[]` list: the **root disk first** (array index 0 = `/dev/vda`,
/// its `readonly` set from the rootfs kind), then the extra virtio-blk devices in
/// order (`/dev/vdb`, `/dev/vdc`, …, each honoring its own `readonly`, §4.6, Extra virtio-blk devices and disk-I/O throttling). CH
/// enumerates disks purely by array order, so this ordering is the load-bearing
/// contract with the cmdline's `root=/dev/vda`. Pure, so the ordering is unit-testable
/// without a running VMM. A virtio-fs rootfs contributes no disk (unreachable here —
/// `create()` rejects it up front, VMM-1 — kept for match exhaustiveness).
///
/// *Which* host file backs the root disk comes from the one law,
/// [`RootfsSource::effective_image`](crate::config::RootfsSource::effective_image) — the same
/// predicate the config boundary's duplicate-backing-file guard uses, so the guard can never
/// protect a file this wiring does not attach. The match stays exhaustive over the variants
/// (a new `RootfsSource` must be a compile error here) because the `readonly` flag is
/// per-variant.
fn build_ch_disks(cfg: &VmConfig) -> Vec<ChDisk> {
    let mut disks = Vec::with_capacity(1 + cfg.extra_disks.len());
    match &cfg.rootfs {
        crate::config::RootfsSource::Erofs { .. } => disks.push(ChDisk {
            path: cfg.rootfs.effective_image().to_path_buf(),
            readonly: true,
            direct: false,
            image_type: CH_RAW_IMAGE_TYPE,
            rate_limiter_config: None,
        }),
        crate::config::RootfsSource::Block { .. } => disks.push(ChDisk {
            path: cfg.rootfs.effective_image().to_path_buf(),
            readonly: false,
            direct: false,
            image_type: CH_RAW_IMAGE_TYPE,
            rate_limiter_config: None,
        }),
    }
    for disk in &cfg.extra_disks {
        disks.push(ChDisk {
            path: disk.image.clone(),
            readonly: disk.readonly,
            direct: false,
            image_type: CH_RAW_IMAGE_TYPE,
            rate_limiter_config: disk.io_limit.as_ref().map(ch_rate_limiter),
        });
    }
    disks
}

#[derive(Serialize)]
struct ChFs {
    tag: String,
    socket: PathBuf,
    num_queues: usize,
    queue_size: usize,
}

/// Builds the CH `net` device list: one tap device (privileged net), one vhost-user
/// client device with the vmid-derived MAC (unprivileged net), or none. Extracted
/// (like `build_ch_disks`) so the tap-vs-vhost-user shaping is unit-testable without
/// spawning CH.
fn build_ch_net(res: &PerVmResources) -> Result<Vec<ChNet>> {
    if let Some(tap) = &res.tap_name {
        Ok(vec![ChNet {
            tap: Some(tap.clone()),
            // The guest MAC is the shared `mac_math(vmid)` on BOTH arms (v30 §18 delta 8). The tap
            // arm previously emitted `mac: None`, leaving the guest MAC to CH's own undocumented
            // generation — harmless while each privileged VM owned an isolated /30 L2 domain, but a
            // shared segment bridge needs the vmid-derived, host-unique MAC the §6.5
            // collision-freedom argument assumes.
            mac: Some(crate::net::mac_math(res.vmid)?),
            vhost_user: None,
            vhost_mode: None,
            vhost_socket: None,
        }])
    } else if let Some(socket) = &res.vhost_user_socket {
        Ok(vec![ChNet {
            tap: None,
            mac: Some(crate::net::mac_math(res.vmid)?),
            vhost_user: Some(true),
            vhost_mode: Some("Client".to_string()),
            vhost_socket: Some(socket.clone()),
        }])
    } else {
        Ok(vec![])
    }
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
    #[serde(skip_serializing_if = "Option::is_none")]
    file: Option<PathBuf>,
}

/// CH `console` device config (mirrors [`ChSerial`]). CH attaches a default `Tty`
/// console; the [`ConsoleMode`](crate::config::ConsoleMode) wiring turns it `Off`
/// for the UART path and drives it as a `File`-backed virtio-console for the
/// `VirtioConsole` path so exactly one console sinks to `serial.log`.
#[derive(Serialize)]
struct ChConsole {
    mode: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    file: Option<PathBuf>,
}

/// Maps a [`ConsoleMode`](crate::config::ConsoleMode) to the CH `serial`/`console`
/// device pair, kept in lockstep with the cmdline `console=` token
/// (`build_kernel_cmdline`): `Uart` sinks the 8250 `ttyS0` to `serial.log`
/// (serial=`File`, console=`Off` — CH's default `Tty` console is turned off so no
/// stray second console appears); `VirtioConsole` sinks `hvc0` via CH's
/// virtio-console to the same file (serial=`Off`, console=`File`). Emitting the
/// wrong pair (or desyncing it from the cmdline token) silences `serial.log`.
fn console_devices(
    mode: crate::config::ConsoleMode,
    serial_path: PathBuf,
) -> (ChSerial, ChConsole) {
    match mode {
        crate::config::ConsoleMode::Uart => (
            ChSerial {
                mode: "File".into(),
                file: Some(serial_path),
            },
            ChConsole {
                mode: "Off".into(),
                file: None,
            },
        ),
        crate::config::ConsoleMode::VirtioConsole => (
            ChSerial {
                mode: "Off".into(),
                file: None,
            },
            ChConsole {
                mode: "File".into(),
                file: Some(serial_path),
            },
        ),
    }
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

    /// The same RPC on an explicit budget, for `vm.snapshot` — whose duration scales
    /// with guest RAM and therefore cannot ride the flat control ceiling (M6).
    async fn api_request_with(
        &self,
        method: &str,
        path: &str,
        body: Option<&impl Serialize>,
        budget: std::time::Duration,
    ) -> Result<()> {
        crate::vmm::unix_api_request_with(&self.api_socket, method, path, body, budget).await
    }
}

/// The paths and handles produced by [`CloudHypervisor::spawn_ch`].
struct SpawnedCh {
    api_socket: PathBuf,
    vsock_path: PathBuf,
    serial_path: PathBuf,
    process: Child,
    pgid: Option<u32>,
    /// The guest CID baked into a restored snapshot's `config.json` (`vsock.cid`), or
    /// `None` on a cold create. A restored guest keeps this CID verbatim (CH rebuilds
    /// the vsock device from the snapshot), so `guest_cid()` must report it rather than
    /// the orchestrator's fresh allocation (M-VMM-3).
    baked_cid: Option<u32>,
}

/// Reads the guest CID a CH snapshot baked into its `config.json` (`vsock.cid`).
///
/// Returns `None` when the field is absent or malformed so the caller falls back to
/// the fresh allocation. A restored guest keeps this CID verbatim (CH rebuilds the
/// vsock device from the snapshot), so `guest_cid()` must report it (M-VMM-3).
fn baked_cid_from_config(config: &serde_json::Value) -> Option<u32> {
    config
        .get("vsock")
        .and_then(|v| v.get("cid"))
        .and_then(serde_json::Value::as_u64)
        .and_then(|c| u32::try_from(c).ok())
}

/// The restored guest CID: a restored CH VM keeps the CID baked into its snapshot
/// (`vsock.cid` in config.json), reported by `guest_cid()`; it falls back to the
/// orchestrator's fresh allocation only when the snapshot's config.json lacked a
/// readable `vsock.cid` (M-VMM-3). One predicate for the wiring the live restore test
/// cannot pin (a sequential restore may legitimately be re-handed the freed CID).
fn restored_cid(baked_cid: Option<u32>, fresh_cid: u32) -> u32 {
    baked_cid.unwrap_or(fresh_cid)
}

/// Rewrites a CH restore `config.json` in place so its host-side paths point at the
/// fresh restore VM's scratch dir instead of the (deleted) original instance's.
///
/// The snapshot recorded the original VM's vsock socket and serial/console file paths;
/// CH (v52) exposes no restore-time override, so they must be rewritten before launch
/// or the host dials a vsock CH never binds (steward handshake times out) and the serial
/// log stays empty. Handles both console wirings: a `Uart` VM records the sink under
/// `serial.file` (console is `{"mode":"Off"}`), a `VirtioConsole` VM under
/// `console.file` (serial is `{"mode":"Off"}`). Extracted pure so its edge cases are
/// unit-testable without KVM (M-VMM-10).
///
/// # Errors
/// Currently infallible; returns [`Result`] so a future stricter rewrite can fail loud.
fn rewrite_restore_config(
    config: &mut serde_json::Value,
    vsock_path: &Path,
    serial_path: &Path,
    tap_name: Option<&str>,
) -> Result<()> {
    if let Some(vsock) = config.get_mut("vsock") {
        vsock["socket"] = serde_json::Value::String(vsock_path.to_string_lossy().into_owned());
    }
    // H-VMM-1: rewrite every net device's baked tap name to THIS restore's tap.
    // The snapshot recorded the ORIGINAL vmid's tap (`vmcell-tap-<old>`), which does
    // not exist in this restore's freshly-built netns — CH would open a dangling
    // device and guest egress would be dead. The guest's IP + default route are
    // rotated to match by the native resync (see `maybe_resync_after_restore`), so
    // the whole L2/L3 identity moves to the rotated vmid together.
    if let Some(tap) = tap_name
        && let Some(nets) = config.get_mut("net").and_then(|n| n.as_array_mut())
    {
        for net in nets.iter_mut() {
            if net.get("tap").is_some() {
                net["tap"] = serde_json::Value::String(tap.to_string());
            }
        }
    }
    // The serial sink lives under `serial.file` for a Uart VM and under `console.file`
    // for a VirtioConsole VM (the other device serializes as `{"mode":"Off"}` with no
    // `file`). Rewrite whichever one the snapshot recorded so the restored VM logs to
    // the fresh serial_path instead of the original instance's deleted temp path.
    if let Some(serial) = config.get_mut("serial")
        && serial.get("file").is_some()
    {
        serial["file"] = serde_json::Value::String(serial_path.to_string_lossy().into_owned());
    }
    if let Some(console) = config.get_mut("console")
        && console.get("file").is_some()
    {
        console["file"] = serde_json::Value::String(serial_path.to_string_lossy().into_owned());
    }
    Ok(())
}

/// Refuses a [`VmConfig`] asking for `nested_virt`/`lazy_restore` that this backend's
/// descriptor advertises as `false`, through the **one** shared predicate
/// [`crate::vmm::reject_unadvertised_capabilities`] (docs/81 d7).
///
/// Cloud Hypervisor advertises **both** as `true` (`-cpu host`-equivalent VMX exposure plus the
/// cmdline's `kvm-intel.nested=1`; `--restore source_url=…,prefault=off` for demand paging), so
/// both branches are dormant *today* — exactly like the `reject_usb_host_devices` call in
/// `create()` on QEMU, whose flag is also `true`. Routing the primary backend through the shared
/// predicate anyway is what makes it a **law** rather than a convention three secondary backends
/// happen to follow: a deliberate re-gate of either flag (a host without nested KVM, a CH build
/// whose `prefault=off` regressed) turns every such config into the typed refusal here, with no
/// second site to write and no window in which CH silently accepts what its own descriptor
/// denies.
///
/// This wrapper exists only to bind the `"cloud-hypervisor"` name once; the law, both branches
/// and the N-VMM-1 feature strings live in the shared predicate.
///
/// # Errors
/// Returns [`Error::Unsupported`] `{ vmm: "cloud-hypervisor", feature }` naming the unadvertised
/// capability.
fn reject_unadvertised_capabilities(caps: &VmmCapabilities, cfg: &VmConfig) -> Result<()> {
    crate::vmm::reject_unadvertised_capabilities("cloud-hypervisor", caps, cfg)
}

/// The `--restore` argument for a snapshot directory under a given [`RestoreMode`].
///
/// §8.3 eager-vs-lazy restore: CH v52's `--restore` accepts a `prefault=on|off` modifier on the
/// `source_url`. `on` eagerly faults all guest memory in at restore time; `off` selects
/// lazy/userfaultfd demand-paging; [`RestoreMode::Default`](crate::config::RestoreMode::Default)
/// omits the modifier and uses CH's own default. Pure, so the mapping is unit-testable without
/// spawning CH — and so [`ch_launch_plan`] can compose the whole argv with no I/O.
fn ch_restore_arg(dir: &Path, restore_mode: crate::config::RestoreMode) -> String {
    let mut arg = format!("source_url=file://{}", dir.display());
    match restore_mode {
        crate::config::RestoreMode::Eager => arg.push_str(",prefault=on"),
        crate::config::RestoreMode::Lazy => arg.push_str(",prefault=off"),
        crate::config::RestoreMode::Default => {}
    }
    arg
}

/// The pure, total mapping from a config to the complete Cloud Hypervisor launch (M11).
///
/// `spawn_ch` builds through this and spawns **only** what it returns, so the jail posture that
/// ships is a *returned value* a KVM-free test can assert on
/// ([`LaunchPlan::jail`](crate::vmm::LaunchPlan::jail)) rather than an inline
/// `jail_spec_from_config(&…)` argument no gate can see. The confinement is applied in
/// `build_vmm_cmd`'s post-fork `pre_exec` window, which nothing KVM-free observes — so without
/// this, rewriting the one `&cfg.jail` token to a weakened config ships every CH VM with a
/// different posture and the whole suite stays green (the M11 defect class, crosvm leg).
///
/// Performs **no I/O**: the restore path's `config.json` read/rewrite stays in `spawn_ch` and
/// reaches here only as the already-composed `restore_arg`, so a unit test can build a
/// `VmConfig`, call this, and assert over the composed argv.
///
/// # Errors
/// Propagates [`vmm_seccomp_args`](crate::vmm::seccomp::vmm_seccomp_args)'s typed refusal (CH
/// honors all three policies, so this cannot fire today) and
/// [`LaunchPlan::build`](crate::vmm::LaunchPlan::build)'s jail-compilation error.
fn ch_launch_plan(
    binary_path: &Path,
    cfg: &VmConfig,
    res: &PerVmResources,
    api_socket: &Path,
    restore_arg: Option<&str>,
) -> Result<crate::vmm::LaunchPlan> {
    // §12.2 (Layer 1): the VMM's own seccomp flag, one predicate.
    let seccomp_args = crate::vmm::seccomp::vmm_seccomp_args("cloud-hypervisor", cfg.vmm_seccomp)?;
    // §12.3 (Layer 2): the ONE posture value, handed to the one constructor that both compiles
    // it into the `pre_exec` jail and records it.
    let mut plan = crate::vmm::LaunchPlan::build(binary_path, res.netns_name.as_deref(), cfg.jail)?;
    let cmd = plan.command_mut();
    cmd.args(&seccomp_args);
    if let Some(arg) = restore_arg {
        cmd.arg("--restore").arg(arg);
    }
    cmd.arg("--api-socket").arg(api_socket);
    Ok(plan)
}

impl CloudHypervisor {
    async fn spawn_ch(
        &self,
        cfg: &VmConfig,
        res: &PerVmResources,
        snapshot_dir: Option<&Path>,
        restore_mode: crate::config::RestoreMode,
        cgroups: &dyn crate::metrics::CgroupFs,
    ) -> Result<SpawnedCh> {
        // The orchestrator owns the per-VM scratch dir; derive our socket and
        // serial-log paths inside it.
        let api_socket = res.tmp_dir.join("api.sock");
        let vsock_path = res.tmp_dir.join("vsock.sock");
        let serial_path = res.tmp_dir.join("serial.log");

        // M11: the whole launch — seccomp flag, jail spec, netns, argv — is composed inside
        // `ch_launch_plan`, so `spawn_ch` holds NO `JailConfig` and NO `JailSpec` and there is no
        // window in which the posture could be swapped between deciding it and applying it. The
        // plan's recorded posture is private to `vmm::launch`, so it cannot be overwritten here
        // even deliberately; the KVM-free gate asserts on it.
        //
        // The `--restore` modifier is pure (`ch_restore_arg`), so it is computed here, before the
        // snapshot's `config.json` is read — keeping the side-effect order (and every error
        // path's residue) byte-identical to the inline composition this replaced.
        let plan = ch_launch_plan(
            &self.binary_path,
            cfg,
            res,
            &api_socket,
            snapshot_dir
                .map(|dir| ch_restore_arg(dir, restore_mode))
                .as_deref(),
        )?;

        // The guest CID a restored snapshot baked in (populated from config.json in the
        // restore branch below); `None` on a cold create (M-VMM-3).
        let mut baked_cid: Option<u32> = None;

        if let Some(dir) = snapshot_dir {
            // CH `--restore` reconstructs every device from the snapshot's
            // config.json, including the vsock backend's UNIX socket and the serial
            // file — both recorded as the ORIGINAL instance's temp-dir paths, which
            // no longer exist. CH (v52) exposes no restore-time override for these,
            // so rewrite config.json to point at this restore's freshly-minted paths
            // before launching; otherwise the host connects to a vsock socket CH
            // never binds (the steward handshake times out) and the serial log stays
            // empty. In-place rewrite is fine for a single-use snapshot; restoring
            // many clones from one snapshot would need a copy-on-write of the
            // snapshot dir first.
            let config_path = dir.join("config.json");
            let content = tokio::fs::read_to_string(&config_path).await?;
            let mut config: serde_json::Value = serde_json::from_str(&content)?;
            // Surface the CID the snapshot baked in: the restored guest keeps it
            // verbatim, so `guest_cid()` must report it, not the fresh allocation
            // (M-VMM-3).
            baked_cid = baked_cid_from_config(&config);
            // Point the vsock/serial/console host paths at this restore's fresh scratch
            // dir before launch (M-VMM-10), and rewrite the baked tap name to this
            // restore's tap (H-VMM-1).
            rewrite_restore_config(
                &mut config,
                &vsock_path,
                &serial_path,
                res.tap_name.as_deref(),
            )?;
            tokio::fs::write(&config_path, serde_json::to_string(&config)?).await?;
        }

        let mut process = plan
            .into_command()
            .stdin(Stdio::null())
            .stdout(Stdio::null())
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
            cfg.timeouts.api_socket_poll.as_millis() as u64,
        )
        .await?;

        Ok(SpawnedCh {
            api_socket,
            vsock_path,
            serial_path,
            process,
            pgid,
            baked_cid,
        })
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
        // The cmdline `console=` token and the serial/console device pair below are
        // both derived from `cfg.console_mode`; gate an unsupported mode up front so
        // they can never desync into a silent `serial.log`.
        crate::vmm::reject_unsupported_console(
            "cloud-hypervisor",
            &self.capabilities(),
            cfg.console_mode,
        )?;

        // CH's upstream device model has no USB controller (§2.4, v30 §18 delta 9), so a
        // passthrough request is refused through the ONE shared predicate rather than
        // silently ignored.
        crate::vmm::reject_usb_host_devices(
            "cloud-hypervisor",
            &self.capabilities(),
            &cfg.usb_host_devices,
        )?;

        // §2.1: every backend self-checks its OWN descriptor rather than assuming the caller
        // consulted it. Both branches are dormant on CH's shipped descriptor (it advertises
        // `nested_virt` and `lazy_restore`), which is exactly why the call must be here: a
        // re-gate of either flag has no second site to update, and the primary backend is not
        // the one exception to the law.
        reject_unadvertised_capabilities(&self.capabilities(), cfg)?;

        let SpawnedCh {
            api_socket,
            vsock_path,
            serial_path,
            process,
            pgid,
            baked_cid: _,
        } = self
            .spawn_ch(cfg, res, None, crate::config::RestoreMode::Default, cgroups)
            .await?;

        let cid = res.guest_cid;

        // H-QEMU-1 (CH sibling): construct the owning instance *before* the
        // fallible virtiofsd starts. `tokio::process::Child` does not kill on
        // drop, so once `spawn_ch` has returned a live CH VMM, only the
        // instance's `Drop` (which reaps the process group, and any virtiofsd
        // already pushed below) frees it. Building the owner first means a failed
        // virtio-fs daemon start reaps the CH VMM instead of leaking it.
        let mut instance = ChInstance {
            process,
            api_socket,
            vsock_path: vsock_path.clone(),
            serial_path: serial_path.clone(),
            _fs_daemons: Vec::new(),
            restored: false,
            snapshot_restore_capable: self.capabilities().snapshot_restore,
            cid,
            group: crate::vmm::VmmProcessGroup::new(pgid),
            mem_mib: cfg.mem_mib,
            vhost_user_net: res.vhost_user_socket.is_some(),
        };

        let mut ch_fs = Vec::new();
        for share in &cfg.shares {
            // §9.4: `api_socket_poll` paces EVERY daemon readiness wait, so virtiofsd's wait gets
            // *this VM's* profile — the unpaced `start` shim would pin it to the default cadence
            // under `low_latency()`/`throughput()` (finding
            // `virtiofsd-socket-wait-hardcoded-cadence`; the fix landed the paced entry point but
            // left the shipped sites on the default). Gated by
            // `virtiofs_pacing_gate::every_virtiofs_start_here_is_paced_by_the_vm_config`.
            let daemon =
                crate::fs::VirtioFsDaemon::start_paced(share, &res.tmp_dir, &cfg.timeouts).await?;
            ch_fs.push(ChFs {
                tag: share.tag.clone(),
                socket: daemon.socket_path.clone(),
                num_queues: 1,
                queue_size: 1024,
            });
            instance._fs_daemons.push(daemon);
        }

        // Serial/console device pair, kept in lockstep with the cmdline `console=`
        // token derived from the same `cfg.console_mode`.
        let (serial, console) = console_devices(cfg.console_mode, serial_path);

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
                // §8.3 (Density levers) KSM-density benchmark flips both.
                shared: !cfg.ksm_mergeable,
                mergeable: cfg.ksm_mergeable,
            },
            payload: ChPayload {
                kernel: cfg.kernel.clone(),
                cmdline: crate::config::build_kernel_cmdline(cfg, res, "")?,
            },
            disks: vec![],
            fs: ch_fs,
            net: vec![],
            serial,
            console,
            vsock: ChVsock {
                cid,
                socket: vsock_path,
            },
        };

        ch_cfg.net = build_ch_net(res)?;

        ch_cfg.disks = build_ch_disks(cfg);

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
            return Err(Error::unsupported(
                "cloud-hypervisor",
                crate::feature::Feature::SnapshotRestore,
            ));
        }
        // Gate an unsupported console mode before spawn/config-rewrite: the restore
        // path re-derives the same serial/console wiring the snapshot baked in.
        crate::vmm::reject_unsupported_console(
            "cloud-hypervisor",
            &self.capabilities(),
            cfg.console_mode,
        )?;
        // The same descriptor self-check as `create()`. `restore()` is the path that actually
        // consumes `cfg.restore_mode` (it becomes `--restore source_url=…,prefault=on|off`), so
        // a restore that accepted exactly what create rejects is the crosvm M4 defect one path
        // over — dormant flags or not.
        reject_unadvertised_capabilities(&self.capabilities(), cfg)?;
        // C1 / snapshot-eligibility law: a snapshot-eligible VM has no vhost-user
        // device. Reject a virtio-fs *rootfs* or data share, unprivileged net, or an
        // external vhost-user-net *before* we would otherwise start virtiofsd
        // below. (M-RESTORE-3: the virtio-fs rootfs case was previously missed.)
        if crate::vmm::config_has_vhost_user_device(cfg, res) {
            return Err(Error::from_removal(
                "cloud-hypervisor",
                &crate::feature::VHOST_USER_BLOCKS_SNAPSHOT,
            ));
        }
        let SpawnedCh {
            api_socket,
            vsock_path,
            serial_path,
            process,
            pgid,
            baked_cid,
        } = self
            .spawn_ch(cfg, res, Some(snapshot_dir), cfg.restore_mode, cgroups)
            .await?;

        // The guard above guarantees `cfg.shares` is empty here, so this never
        // starts virtiofsd on a restored VM.
        let mut fs_daemons = Vec::new();
        for share in &cfg.shares {
            // Paced by this VM's profile, exactly like the create path above (§9.4). Unreachable
            // today (the guard keeps `cfg.shares` empty on restore), which is precisely why it
            // must not be allowed to drift back to the default-cadence shim unnoticed.
            let daemon =
                crate::fs::VirtioFsDaemon::start_paced(share, &res.tmp_dir, &cfg.timeouts).await?;
            fs_daemons.push(daemon);
        }

        // A restored guest keeps the CID baked into its snapshot; report that, not the
        // orchestrator's fresh allocation (M-VMM-3). Fall back to the fresh CID only if
        // the snapshot's config.json lacked a readable `vsock.cid`.
        let cid = restored_cid(baked_cid, res.guest_cid);

        let instance = ChInstance {
            process,
            api_socket,
            vsock_path,
            serial_path,
            _fs_daemons: fs_daemons,
            restored: true,
            snapshot_restore_capable: self.capabilities().snapshot_restore,
            cid,
            group: crate::vmm::VmmProcessGroup::new(pgid),
            mem_mib: cfg.mem_mib,
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
            virtio_console: true,
            // CH's restore config rewrite moves the vsock/serial paths into the
            // restored VM's OWN fresh scratch dir before launch (§8.2, Restore correctness: a restored VM is not a fresh VM), so every
            // restore gets rotated host-side socket paths.
            restore_rotates_host_paths: true,
            // CH has a native per-drive rate limiter (`rate_limiter_config`), §4.6.
            disk_io_throttle: true,
            // Cloud Hypervisor's upstream device model has no USB controller at all
            // (§2.4, v30 §18 delta 9), so host-USB passthrough is a hard, documented
            // false; `create()` rejects a USB device fail-loud via the shared
            // `reject_usb_host_devices` predicate.
            usb_host_passthrough: false,
        }
    }

    fn id(&self) -> &str {
        "cloud-hypervisor"
    }
}

impl VmInstance for ChInstance {
    async fn boot(&mut self) -> Result<()> {
        // §2.1 (The trait and the capability descriptor) / M-VMM-4: a restored VM is returned paused and resumed via `resume()`,
        // NEVER booted. Silently remapping boot()->vm.resume papered over the misuse;
        // fail loud and typed instead, mirroring Firecracker.
        if self.restored {
            // NOT a `Feature`: this is an API-state refusal, not a capability absence — a
            // restored VM is resumed, not booted. It keeps a single snake_case token (never prose)
            // so a caller matches it exactly, which is the half of F6 that applies here.
            return Err(Error::Unsupported {
                vmm: "cloud-hypervisor".to_string(),
                feature: "boot_after_restore".to_string(),
            });
        }
        self.api_request("PUT", "/api/v1/vm.boot", None::<&()>)
            .await
    }

    async fn request_shutdown(&mut self) -> Result<()> {
        self.api_request("PUT", "/api/v1/vm.shutdown", None::<&()>)
            .await
    }

    async fn kill(&mut self) -> Result<()> {
        // The one shared signal/wait/flag sequence (L1): SIGKILL the group unless the
        // leader was already reaped, await it, record the reap (M-VMM-1).
        self.group.kill_and_wait(&mut self.process).await;
        Ok(())
    }

    async fn has_exited(&mut self) -> bool {
        // Non-blocking reap of the VMM leader; `Ok(Some(_))` means it exited (the
        // guest powered off after `request_shutdown`). The shared helper records the
        // reap so `kill()`/`Drop` cannot re-`SIGKILL` a possibly-recycled pgid.
        self.group.note_exit(&mut self.process)
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
            crate::vmm::has_vhost_user_device(
                !self._fs_daemons.is_empty(),
                false,
                self.vhost_user_net,
            ),
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
        // M6: `vm.snapshot` writes a dense memory file that tracks guest RAM ~1:1, so it
        // is budgeted against `mem_mib` — the flat control ceiling is a guaranteed
        // spurious timeout on a multi-GiB guest.
        let res = self
            .api_request_with(
                "PUT",
                "/api/v1/vm.snapshot",
                Some(&req),
                crate::vmm::snapshot_request_timeout(self.mem_mib),
            )
            .await;
        // Resume on EVERY exit path, timeout included: a paused VM left behind by a
        // failed snapshot is a wedged VM, so the resume is attempted unconditionally and
        // only its own failure is warn-and-continue.
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
        // Same helper, same order as the graceful `kill()` path (L1): the group SIGKILL +
        // blocking reap is skipped if the leader was already reaped, since its pgid may
        // have been recycled (M-VMM-1).
        self.group.reap_now(&mut self.process);
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

    /// Spawns a stand-in CH API socket on `sock`: it answers `204` to every request
    /// immediately, except on `stall_path`, where it first waits `stall`
    /// (`None` = never answers at all). Returns the shared log of requested paths in
    /// arrival order, which is how the snapshot tests below observe whether the VM was
    /// left paused.
    ///
    /// One connection per request (that is what `unix_api_request` does), so each
    /// connection is served on its own task and a stalled snapshot cannot block the
    /// `vm.resume` that follows it.
    fn spawn_fake_ch_api(
        sock: &Path,
        stall_path: &'static str,
        stall: Option<std::time::Duration>,
    ) -> std::sync::Arc<std::sync::Mutex<Vec<String>>> {
        let listener = tokio::net::UnixListener::bind(sock).expect("bind fake CH API socket");
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let log = std::sync::Arc::clone(&seen);
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let log = std::sync::Arc::clone(&log);
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let mut buf = vec![0u8; 4096];
                    let Ok(n) = stream.read(&mut buf).await else {
                        return;
                    };
                    let head = String::from_utf8_lossy(&buf[..n]).into_owned();
                    let path = head
                        .split_whitespace()
                        .nth(1)
                        .unwrap_or_default()
                        .to_string();
                    log.lock().expect("fake API log").push(path.clone());
                    if path == stall_path {
                        match stall {
                            Some(d) => tokio::time::sleep(d).await,
                            None => std::future::pending::<()>().await,
                        }
                    }
                    // The client may already have timed out and dropped the connection;
                    // a write to that closed peer is the expected outcome, not a failure.
                    if stream
                        .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                        .await
                        .is_err()
                    {
                        return;
                    }
                    if stream.flush().await.is_err() {
                        return;
                    }
                    // Hold the connection open long enough for the client to read the
                    // reply before the socket closes.
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                });
            }
        });
        seen
    }

    /// A `ChInstance` wired to `api_socket` with `mem_mib` of guest RAM, owning a
    /// stand-in child process so `Drop`/`kill` have something real to reap.
    fn ch_instance_on(api_socket: PathBuf, mem_mib: u32) -> ChInstance {
        let mut std_cmd = std::process::Command::new("sleep");
        std_cmd.arg("60");
        use std::os::unix::process::CommandExt;
        std_cmd.process_group(0);
        let child = tokio::process::Command::from(std_cmd)
            .spawn()
            .expect("spawn stand-in VMM");
        ChInstance {
            group: crate::vmm::VmmProcessGroup::new(child.id()),
            process: child,
            api_socket,
            vsock_path: PathBuf::new(),
            serial_path: PathBuf::new(),
            _fs_daemons: Vec::new(),
            restored: false,
            snapshot_restore_capable: true,
            cid: 3,
            mem_mib,
            vhost_user_net: false,
        }
    }

    // Guards M6: `vm.snapshot` writes a memory file that tracks guest RAM ~1:1, so it
    // rides `snapshot_request_timeout(mem_mib)`, NOT the flat 5 s control ceiling. The
    // fake API stalls 6 s on `vm.snapshot` — past the shared ceiling, well inside a
    // 2 GiB guest's budget (37 s) — so the snapshot must SUCCEED and the three RPCs must
    // land in order. Real time, deliberately: the clock cannot be paused here, because
    // auto-advance races the multi-hop hyper response and expires the budget while the
    // reply is still in flight (observed: a spurious `vm.pause` timeout).
    // Inverse (route vm.snapshot back through the shared-ceiling `api_request`): the
    // stall exceeds 5 s and the `expect` on Ok reddens with a typed Timeout.
    #[tokio::test]
    async fn snapshot_rpc_is_budgeted_against_guest_ram_not_the_control_ceiling() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let sock = dir.path().join("api.sock");
        let seen = spawn_fake_ch_api(
            &sock,
            "/api/v1/vm.snapshot",
            Some(std::time::Duration::from_secs(6)),
        );
        let mut inst = ch_instance_on(sock, 2048);

        inst.snapshot(dir.path())
            .await
            .expect("a 6 s vm.snapshot must fit a 2 GiB guest's budget");

        let paths = seen.lock().expect("fake API log").clone();
        assert_eq!(
            paths,
            vec![
                "/api/v1/vm.pause".to_string(),
                "/api/v1/vm.snapshot".to_string(),
                "/api/v1/vm.resume".to_string(),
            ],
            "snapshot must be pause → snapshot → resume"
        );
        inst.kill().await.expect("reap the stand-in VMM");
    }

    // Guards M6's second half: when the snapshot RPC really does exceed its (sized)
    // budget, the failure is a typed Timeout AND the VM is RESUMED — a paused VM left
    // behind by a failed snapshot is a wedged VM. The fake never answers `vm.snapshot`,
    // so the wait is this guest's whole budget (64 MiB ⇒ 6 s) in real time.
    // Inverse (resume only on the `res` Ok path): no `vm.resume` is ever requested and
    // the ordered-paths assert reddens.
    #[tokio::test]
    async fn a_timed_out_snapshot_still_resumes_the_vm() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let sock = dir.path().join("api.sock");
        let seen = spawn_fake_ch_api(&sock, "/api/v1/vm.snapshot", None);
        let mut inst = ch_instance_on(sock, 64);

        let err = inst
            .snapshot(dir.path())
            .await
            .expect_err("a never-answered vm.snapshot must time out");
        assert!(
            matches!(&err, Error::Timeout(m) if m.contains("vm.snapshot")),
            "expected a typed Timeout naming the RPC, got {err:?}"
        );

        let paths = seen.lock().expect("fake API log").clone();
        assert_eq!(
            paths,
            vec![
                "/api/v1/vm.pause".to_string(),
                "/api/v1/vm.snapshot".to_string(),
                "/api/v1/vm.resume".to_string(),
            ],
            "a timed-out snapshot must still issue vm.resume, or the VM stays paused"
        );
        inst.kill().await.expect("reap the stand-in VMM");
    }

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
                file: Some(PathBuf::from("/serial.log")),
            },
            console: ChConsole {
                mode: "Off".into(),
                file: None,
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

    // §4.6 (Extra virtio-blk devices and disk-I/O throttling): the root disk is always disks[0] (/dev/vda) and extra virtio-blk devices
    // follow it in order (/dev/vdb, /dev/vdc, …), each with its own readonly flag.
    // Buggy impls this guards: extras pushed BEFORE the root (root shifts off /dev/vda
    // → the guest cannot mount root=/dev/vda), extras dropped, or the readonly flag
    // ignored.
    #[test]
    fn build_ch_disks_puts_root_first_then_extras() {
        use crate::config::{BlockDevice, RootfsSource, VmConfig};

        let cfg = VmConfig::builder(
            PathBuf::from("/vmlinux"),
            RootfsSource::Erofs {
                image: PathBuf::from("/rootfs.erofs"),
            },
        )
        .with_extra_disk(BlockDevice::read_only("/img/ro.raw"))
        .with_extra_disk(BlockDevice::read_write("/img/rw.raw"))
        .build()
        .unwrap();

        let disks = build_ch_disks(&cfg);
        assert_eq!(
            disks,
            vec![
                // /dev/vda — the erofs root, read-only.
                ChDisk {
                    path: PathBuf::from("/rootfs.erofs"),
                    readonly: true,
                    direct: false,
                    image_type: CH_RAW_IMAGE_TYPE,
                    rate_limiter_config: None,
                },
                // /dev/vdb — the first extra disk, read-only.
                ChDisk {
                    path: PathBuf::from("/img/ro.raw"),
                    readonly: true,
                    direct: false,
                    image_type: CH_RAW_IMAGE_TYPE,
                    rate_limiter_config: None,
                },
                // /dev/vdc — the second extra disk, read-write.
                ChDisk {
                    path: PathBuf::from("/img/rw.raw"),
                    readonly: false,
                    direct: false,
                    image_type: CH_RAW_IMAGE_TYPE,
                    rate_limiter_config: None,
                },
            ]
        );

        // No extra disks ⇒ just the root disk (default path unchanged).
        let plain = VmConfig::builder(
            PathBuf::from("/vmlinux"),
            RootfsSource::Erofs {
                image: PathBuf::from("/rootfs.erofs"),
            },
        )
        .build()
        .unwrap();
        assert_eq!(build_ch_disks(&plain).len(), 1);

        // The explicit `image_type=Raw` must reach CH's JSON (it stops CH v52 from
        // auto-detecting raw and disabling sector-0 writes on a writable disk). A
        // renamed/dropped field silences CH's format and reddens here.
        let json = serde_json::to_string(&disks[0]).unwrap();
        assert!(
            json.contains("\"image_type\":\"Raw\""),
            "disk config must declare image_type=Raw: {json}"
        );
        // An unthrottled disk omits rate_limiter_config entirely (matches CH's default).
        assert!(
            !json.contains("rate_limiter_config"),
            "unthrottled disk must omit rate_limiter_config: {json}"
        );
    }

    // One law, one predicate (§13, Cross-cutting invariants): the file the root disk is
    // composed from is `RootfsSource::effective_image` — the SAME predicate the config
    // boundary's duplicate-backing-file guard uses. The two used to be separate copies of
    // `overlay.as_ref().unwrap_or(image)`, so a divergence would have let the guard protect a
    // file this wiring does not attach (an extra disk aliasing the real root would pass
    // validation, and the guest would get two writable attachments of one image). Expected
    // values are recomputed THROUGH the helper, never a test-local literal. Buggy impl this
    // guards: attaching the base image while an overlay is set (the writes then land in the
    // shared base and every VM corrupts every other) — that reddens the overlay leg here.
    #[test]
    fn build_ch_root_disk_uses_the_effective_image_law() {
        use crate::config::{RootfsSource, VmConfig};

        let base = PathBuf::from("/img/base.raw");
        let overlay = PathBuf::from("/img/vm-7-overlay.raw");

        // Plain image: no overlay, so the base IS the effective image.
        let plain = VmConfig::builder(
            PathBuf::from("/vmlinux"),
            RootfsSource::Block {
                image: base.clone(),
                overlay: None,
            },
        )
        .build()
        .unwrap();
        assert_eq!(
            build_ch_disks(&plain)[0].path,
            plain.rootfs.effective_image(),
            "the root disk must be the effective image"
        );

        // Overlay set: the overlay backs /dev/vda and the base is never attached.
        let with_overlay = VmConfig::builder(
            PathBuf::from("/vmlinux"),
            RootfsSource::Block {
                image: base.clone(),
                overlay: Some(overlay),
            },
        )
        .build()
        .unwrap();
        let disks = build_ch_disks(&with_overlay);
        assert_eq!(
            disks[0].path,
            with_overlay.rootfs.effective_image(),
            "with an overlay set, the overlay backs /dev/vda"
        );
        // Non-vacuous: the two paths genuinely differ, so the assertion above is not
        // satisfied by the base image.
        assert_ne!(
            with_overlay.rootfs.effective_image(),
            base,
            "the overlay case must not resolve to the base image"
        );
        assert!(!disks[0].readonly, "a Block root is writable");

        // EROFS: the image itself, read-only.
        let erofs = VmConfig::builder(
            PathBuf::from("/vmlinux"),
            RootfsSource::Erofs {
                image: PathBuf::from("/rootfs.erofs"),
            },
        )
        .build()
        .unwrap();
        let erofs_disks = build_ch_disks(&erofs);
        assert_eq!(erofs_disks[0].path, erofs.rootfs.effective_image());
        assert!(erofs_disks[0].readonly, "an EROFS root is read-only");
    }

    // §4.6 (Extra virtio-blk devices and disk-I/O throttling): a DiskIoLimit becomes CH's `rate_limiter_config` token buckets — bandwidth
    // (bytes/s) and ops (IOPS) each `{ size: rate, refill_time: 1000 }`, and an unset
    // cap is omitted. Buggy impls: wrong refill_time (so `size` no longer means per-
    // second), a swapped bandwidth/ops key, or emitting a cap that was None.
    #[test]
    fn build_ch_disks_maps_io_limit_to_rate_limiter() {
        use crate::config::{BlockDevice, DiskIoLimit, RootfsSource, VmConfig};

        let cfg = VmConfig::builder(
            PathBuf::from("/vmlinux"),
            RootfsSource::Erofs {
                image: PathBuf::from("/rootfs.erofs"),
            },
        )
        .with_extra_disk(
            BlockDevice::read_only("/img/slow.raw")
                .with_io_limit(DiskIoLimit::bandwidth(2_000_000)),
        )
        .build()
        .unwrap();

        let disks = build_ch_disks(&cfg);
        // disks[1] is the throttled extra disk (disks[0] is the root).
        let rl = disks[1]
            .rate_limiter_config
            .as_ref()
            .expect("throttled disk must carry a rate limiter");
        assert_eq!(
            rl.bandwidth,
            Some(ChTokenBucket {
                size: 2_000_000,
                refill_time: 1000,
            }),
            "bandwidth bucket must be size=rate, refill_time=1000ms (→ bytes/second)"
        );
        assert_eq!(rl.ops, None, "an unset IOPS cap must be omitted");
        // The root disk stays unthrottled.
        assert_eq!(disks[0].rate_limiter_config, None);
    }

    // The serial/console device pair must move in lockstep with the cmdline
    // `console=` token, both derived from `cfg.console_mode`. Uart => serial File +
    // console Off; VirtioConsole => serial Off + console File. RED if the two are
    // swapped or desynced (either the guest console sinks nowhere and `serial.log`
    // goes silent, or two consoles fight over the file).
    #[test]
    fn console_devices_map_serial_and_console_in_lockstep() {
        use crate::config::ConsoleMode;
        let path = PathBuf::from("/tmp/serial.log");

        // Uart: 8250 ttyS0 sinks to serial.log; CH's default Tty console is OFF.
        let (serial, console) = console_devices(ConsoleMode::Uart, path.clone());
        let sj = serde_json::to_string(&serial).unwrap();
        let cj = serde_json::to_string(&console).unwrap();
        assert!(
            sj.contains("\"mode\":\"File\"") && sj.contains("/tmp/serial.log"),
            "uart serial must be a File sink to serial.log: {sj}"
        );
        assert_eq!(
            cj, "{\"mode\":\"Off\"}",
            "uart console must be Off with no file (no stray second console): {cj}"
        );

        // VirtioConsole: serial OFF, hvc0 console sinks to serial.log.
        let (serial, console) = console_devices(ConsoleMode::VirtioConsole, path.clone());
        let sj = serde_json::to_string(&serial).unwrap();
        let cj = serde_json::to_string(&console).unwrap();
        assert_eq!(
            sj, "{\"mode\":\"Off\"}",
            "virtio-console serial must be Off with no file: {sj}"
        );
        assert!(
            cj.contains("\"mode\":\"File\"") && cj.contains("/tmp/serial.log"),
            "virtio-console console must be a File sink to serial.log: {cj}"
        );
    }

    // Guards M-VMM-4: a restored CH VM is resumed via `resume()`, never booted; boot()
    // must fail loud and typed instead of silently remapping to `vm.resume`. The guard
    // runs before any api_request, so the absent api socket is never dialed. Inverse
    // (the old boot()->vm.resume remap) dials the missing socket and returns a
    // transport error, not this typed Unsupported — reddening the assertion.
    #[tokio::test]
    async fn restored_ch_instance_refuses_boot() {
        let mut std_cmd = std::process::Command::new("sleep");
        std_cmd.arg("60");
        use std::os::unix::process::CommandExt;
        std_cmd.process_group(0);
        let child = tokio::process::Command::from(std_cmd)
            .spawn()
            .expect("spawn stand-in");
        let mut inst = ChInstance {
            group: crate::vmm::VmmProcessGroup::new(child.id()),
            process: child,
            api_socket: std::env::temp_dir().join("vmcell-ch-boot-test-nonexistent.sock"),
            vsock_path: PathBuf::new(),
            serial_path: PathBuf::new(),
            _fs_daemons: Vec::new(),
            restored: true,
            snapshot_restore_capable: true,
            cid: 3,
            mem_mib: 128,
            vhost_user_net: false,
        };
        let err = inst
            .boot()
            .await
            .expect_err("a restored CH VM must refuse boot()");
        assert!(
            // An exact token, not a substring: the refusal now spells `boot_after_restore`
            // (single snake_case, never prose) precisely so this assertion can be an equality.
            matches!(&err, Error::Unsupported { vmm, feature }
                if vmm == "cloud-hypervisor" && feature == "boot_after_restore"),
            "expected boot-after-restore Unsupported, got {err:?}"
        );
        let _ = inst.kill().await;
    }

    // POSITIVE CONTROL for the gate above, and the gate on `Drop`'s OWN job: an instance whose
    // group has NOT been reaped must have its process group SIGKILLed + reaped when it is dropped
    // (L1 — `Drop` is the panic path of the one teardown order). Without this leg the
    // "must not signal a recycled pgid" assertion is satisfied by a `Drop` that reaps NOTHING —
    // which is precisely the regression the Cloud Hypervisor consolidation introduced and this leg caught: a
    // dropped-but-never-killed VM would leak its whole process group.
    //
    // Inverse (observed red): delete `self.group.reap_now(&mut self.process)` from `Drop` and the
    // stand-in survives, so `gone` stays false.
    #[tokio::test]
    async fn drop_reaps_an_unreaped_process_group() {
        let inst = ch_instance_on(PathBuf::new(), 128);
        let live_pid = inst.process.id().expect("stand-in pid") as i32;
        drop(inst);

        let mut gone = false;
        for _ in 0..100 {
            if nix::sys::signal::kill(nix::unistd::Pid::from_raw(live_pid), None).is_err() {
                gone = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        // Best-effort cleanup if the drop did NOT reap, so a red run leaves no stray process.
        let _ = nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(-live_pid),
            nix::sys::signal::Signal::SIGKILL,
        );
        assert!(
            gone,
            "Drop on an UN-reaped instance must SIGKILL and reap its VMM process group"
        );
    }

    // Guards M-VMM-1 (CH) on the SHIPPED call sites, not on the extracted helper: once the
    // leader is reaped its pgid can be recycled, so neither `kill()` NOR `Drop` may SIGKILL
    // `-pgid`. A live decoy process stands in for that recycled group, and BOTH teardown paths
    // are driven against the same already-reaped instance.
    //
    // Inverse (observed red): drop the `!self.reaped` guard in `VmmProcessGroup::kill_and_wait`
    // or `::reap_now` and the decoy is SIGKILLed — `try_wait` then reports it exited, reddening
    // the assert.
    #[tokio::test]
    async fn kill_and_drop_do_not_signal_pgid_when_reaped() {
        let mut decoy = {
            let mut c = std::process::Command::new("sleep");
            c.arg("60");
            use std::os::unix::process::CommandExt;
            c.process_group(0);
            tokio::process::Command::from(c)
                .spawn()
                .expect("spawn decoy")
        };
        let decoy_pid = decoy.id().expect("decoy pid") as i32;

        // A fast-exiting child as the instance's own leader so kill()'s process.wait()
        // returns promptly instead of blocking on a live process.
        let leader = tokio::process::Command::new("true")
            .spawn()
            .expect("spawn `true` leader");
        let mut inst = ChInstance {
            process: leader,
            api_socket: PathBuf::new(),
            vsock_path: PathBuf::new(),
            serial_path: PathBuf::new(),
            _fs_daemons: Vec::new(),
            restored: false,
            snapshot_restore_capable: true,
            cid: 3,
            // Already-reaped, pointing at the live decoy's group: the recycled-pgid
            // state, which only the `test-support` constructor can fabricate.
            group: crate::vmm::VmmProcessGroup::already_reaped_for_test(Some(decoy_pid as u32)),
            mem_mib: 128,
            vhost_user_net: false,
        };
        inst.kill().await.expect("kill");
        assert!(
            inst.group.is_reaped(),
            "the group must still read as reaped after kill() — the flag is one-shot"
        );
        // The `Drop` leg: dropping the instance must not re-signal either. Both teardown paths
        // are driven against the SAME already-reaped instance, because a backend that routed
        // only one of them through the shared helper is the divergence this consolidation
        // removes (the sibling backends' `kill_and_drop_do_not_signal_pgid_when_reaped`).
        drop(inst);

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let decoy_status = decoy.try_wait().expect("try_wait decoy");
        let _ = nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(-decoy_pid),
            nix::sys::signal::Signal::SIGKILL,
        );
        let _ = decoy.wait().await;

        assert!(
            decoy_status.is_none(),
            "kill()/Drop on a reaped CH instance must not SIGKILL a (recycled) pgid"
        );
    }

    // Guards M-VMM-3: a restored CH guest keeps the CID baked into its snapshot's
    // config.json; `guest_cid()` must report that, read from `vsock.cid`. Inverse:
    // ignore `vsock.cid` and return the fresh allocation — the Some(42) assertion reddens.
    #[test]
    fn baked_cid_from_config_reads_vsock_cid() {
        assert_eq!(
            baked_cid_from_config(&serde_json::json!({"vsock": {"cid": 42, "socket": "/x"}})),
            Some(42)
        );
        // Absent / malformed -> None so the caller falls back to the fresh allocation.
        assert_eq!(baked_cid_from_config(&serde_json::json!({})), None);
        assert_eq!(
            baked_cid_from_config(&serde_json::json!({"vsock": {}})),
            None
        );
        assert_eq!(
            baked_cid_from_config(&serde_json::json!({"vsock": {"cid": "not-a-number"}})),
            None
        );
    }

    // Pins the restored guest_cid() <- baked-CID WIRING (M-VMM-3), which the live restore
    // test cannot assert (it only checks in-range because a freed CID may be re-handed).
    // Inverse (return the fresh cid unconditionally) reddens the Some(baked) assert.
    #[test]
    fn restored_cid_prefers_baked_over_fresh() {
        assert_eq!(restored_cid(Some(42), 7), 42, "a baked vsock.cid must win");
        assert_eq!(
            restored_cid(None, 7),
            7,
            "missing vsock.cid falls back to the fresh allocation"
        );
    }

    // Shape-gate build_ch_net for BOTH net branches (like its four extracted siblings).
    // Inverse (branch swap, dropped mac, or a local format! MAC diverging from mac_math)
    // reddens the branch-specific / positive-identity asserts.
    //
    // v30 §18 delta 8: the tap arm carries `mac_math(vmid)` too. It used to emit `mac: None`,
    // leaving the guest MAC to CH's own generation — invisible while each privileged VM owned an
    // isolated /30, but two members of one segment bridge must not collide. Buggy impl guarded:
    // reverting to `mac: None` reddens the positive-identity assert; a constant MAC reddens the
    // distinctness assert.
    #[test]
    fn build_ch_net_shapes_tap_and_vhost_user_branches() {
        use crate::vmm::PerVmResources;
        let base = |tap: Option<String>, sock: Option<PathBuf>, vmid: u32| PerVmResources {
            cgroup_name: String::new(),
            tap_name: tap,
            netns_name: None,
            segment: None,
            vhost_user_socket: sock,
            vmid,
            guest_cid: 3,
            tmp_dir: PathBuf::new(),
        };

        // Privileged (tap) branch: a single tap device, no vhost fields, and the vmid-derived MAC.
        let tap_vmid = 7;
        let tap_net = build_ch_net(&base(Some("vmcell-tap0".into()), None, tap_vmid)).unwrap();
        assert_eq!(tap_net.len(), 1);
        let j = serde_json::to_string(&tap_net[0]).unwrap();
        assert!(
            j.contains("vmcell-tap0"),
            "tap device must carry the tap name: {j}"
        );
        assert!(
            !j.contains("vhost_user"),
            "tap device must not set vhost_user: {j}"
        );
        // Positive identity, recomputed through the one law (never a test-local format!).
        assert_eq!(
            tap_net[0].mac.as_deref(),
            Some(crate::net::mac_math(tap_vmid).unwrap().as_str()),
            "the tap arm must carry mac_math(vmid): {j}"
        );
        // …and two vmids get DISTINCT MACs, which is what makes a shared segment bridge sound.
        let other = build_ch_net(&base(Some("vmcell-tap1".into()), None, 8)).unwrap();
        assert_ne!(
            tap_net[0].mac, other[0].mac,
            "two vmids must not share a guest MAC on a segment bridge"
        );

        // Unprivileged (vhost-user) branch: client mode + the vmid-derived MAC.
        let vmid = 9;
        let vu_net = build_ch_net(&base(
            None,
            Some(PathBuf::from("/run/vmcell/net.sock")),
            vmid,
        ))
        .unwrap();
        assert_eq!(vu_net.len(), 1);
        let j = serde_json::to_string(&vu_net[0]).unwrap();
        assert!(j.contains("\"vhost_user\":true"), "{j}");
        assert!(j.contains("\"vhost_mode\":\"Client\""), "{j}");
        assert!(j.contains("/run/vmcell/net.sock"), "{j}");
        // Positive identity: the MAC is mac_math(vmid), recomputed (not a local format!).
        assert_eq!(
            vu_net[0].mac.as_deref(),
            Some(crate::net::mac_math(vmid).unwrap().as_str())
        );

        // No networking: empty device list.
        assert!(build_ch_net(&base(None, None, 1)).unwrap().is_empty());
    }

    // Guards M-VMM-10: the restore config rewrite must move vsock/serial host paths
    // into the fresh restore's scratch dir. A Uart VM records the sink under
    // `serial.file` (console Off). Inverse: drop the serial arm and serial.file keeps
    // the old, deleted path (the restored VM logs nowhere).
    #[test]
    fn rewrite_restore_config_rewrites_uart_paths() {
        let mut config = serde_json::json!({
            "vsock": { "cid": 3, "socket": "/old/vsock.sock" },
            "serial": { "mode": "File", "file": "/old/serial.log" },
            "console": { "mode": "Off" }
        });
        rewrite_restore_config(
            &mut config,
            &PathBuf::from("/new/vsock.sock"),
            &PathBuf::from("/new/serial.log"),
            None,
        )
        .expect("rewrite");
        assert_eq!(config["vsock"]["socket"], "/new/vsock.sock");
        assert_eq!(config["serial"]["file"], "/new/serial.log");
        assert_eq!(config["console"], serde_json::json!({"mode": "Off"}));
    }

    // M-VMM-10: a VirtioConsole VM records the sink under `console.file` (serial Off).
    // Inverse: drop the console arm and the VirtioConsole sink keeps the old path,
    // silencing serial.log on restore.
    #[test]
    fn rewrite_restore_config_rewrites_virtio_console_paths() {
        let mut config = serde_json::json!({
            "vsock": { "cid": 3, "socket": "/old/vsock.sock" },
            "serial": { "mode": "Off" },
            "console": { "mode": "File", "file": "/old/serial.log" }
        });
        rewrite_restore_config(
            &mut config,
            &PathBuf::from("/new/vsock.sock"),
            &PathBuf::from("/new/serial.log"),
            None,
        )
        .expect("rewrite");
        assert_eq!(config["console"]["file"], "/new/serial.log");
        assert_eq!(config["serial"], serde_json::json!({"mode": "Off"}));
        assert_eq!(config["vsock"]["socket"], "/new/vsock.sock");
    }

    // H-VMM-1: the restore config rewrite must re-point every net device's baked
    // tap (`vmcell-tap-<old>`) to THIS restore's tap. Inverse: drop the net-tap arm
    // and the restored guest opens the original vmid's tap — which does not exist in
    // the fresh netns — leaving egress dead. A `None` tap (no privileged net) leaves
    // the config untouched.
    #[test]
    fn rewrite_restore_config_rewrites_tap_name() {
        let mut config = serde_json::json!({
            "vsock": { "socket": "/old/vsock.sock" },
            "net": [ { "tap": "vmcell-tap-7", "mac": "02:00:00:00:00:07" } ],
        });
        rewrite_restore_config(
            &mut config,
            &PathBuf::from("/new/vsock.sock"),
            &PathBuf::from("/new/serial.log"),
            Some("vmcell-tap-42"),
        )
        .expect("rewrite");
        assert_eq!(config["net"][0]["tap"], "vmcell-tap-42");
        // The MAC is left for the in-guest resync to rotate; only the tap moves here.
        assert_eq!(config["net"][0]["mac"], "02:00:00:00:00:07");

        // With no tap (None), the net array is untouched.
        let mut config2 = serde_json::json!({
            "vsock": { "socket": "/old/vsock.sock" },
            "net": [ { "tap": "vmcell-tap-7" } ],
        });
        rewrite_restore_config(
            &mut config2,
            &PathBuf::from("/new/vsock.sock"),
            &PathBuf::from("/new/serial.log"),
            None,
        )
        .expect("rewrite");
        assert_eq!(config2["net"][0]["tap"], "vmcell-tap-7");
    }

    // M-VMM-10: the rewrite must not panic on a null `file` field.
    #[test]
    fn rewrite_restore_config_handles_null_file() {
        let mut config = serde_json::json!({
            "vsock": { "socket": "/old/vsock.sock" },
            "serial": { "file": null },
        });
        rewrite_restore_config(
            &mut config,
            &PathBuf::from("/new/vsock.sock"),
            &PathBuf::from("/new/serial.log"),
            None,
        )
        .expect("rewrite must not fail on a null file field");
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
            // F6: every snapshot refusal spells `snapshot_restore`, so this leg's discrimination
            // comes from its PAIRING with the positive control below (an eligible config on the
            // same capable backend must be ALLOWED) — not from the prose fragment it used to match.
            matches!(&err, Error::Unsupported { feature, .. }
                if feature == crate::feature::Feature::SnapshotRestore.name()),
            "expected a snapshot_restore Unsupported for the vhost-user config, got {err:?}"
        );

        // Capable backend, snapshot-eligible VM: allowed.
        assert!(snapshot_precheck(true, false).is_ok());
    }

    // docs/81 d7, CH leg. CH is the PRIMARY backend and the only one in the `vmcell` lib; a law
    // the three secondary backends obey and it does not is not one law. Both of CH's flags are
    // `true`, so the refusal is DORMANT on the shipped descriptor — which is precisely why this
    // gate keys off descriptor VALUES rather than end-to-end behavior: the branch that must
    // never rot is the one that fires after a future re-gate.
    //
    // Red on the inverse: hardcode either refusal (drop the `&& !caps.*` conjunct in the shared
    // predicate) and the `shipped` positive control reddens; misspell either feature string and
    // its `matches!` reddens; drop the shared predicate's `lazy_restore` branch entirely and the
    // `without_lazy` leg reddens.
    #[test]
    fn capability_refusals_read_the_descriptor_not_a_hardcoded_bool() {
        let cfg = |nested: bool, mode: crate::config::RestoreMode| {
            VmConfig::builder(
                "/k",
                crate::config::RootfsSource::Erofs {
                    image: PathBuf::from("/i"),
                },
            )
            .nested_virt(nested)
            .restore_mode(mode)
            .build()
            .expect("build config")
        };
        let shipped = CloudHypervisor::new("/usr/bin/cloud-hypervisor").capabilities();

        // The dormancy claim, asserted rather than asserted-in-prose: routing CH through the
        // shared predicate changes NOTHING about what CH accepts today, because it advertises
        // both. If a future descriptor edit flips either flag, this line reddens first and the
        // behavior change is deliberate instead of discovered.
        assert!(
            shipped.nested_virt && shipped.lazy_restore,
            "CH advertises both capabilities, so both refusals are dormant: {shipped:?}"
        );

        // Positive control: the config asking for BOTH travels past the guard on the shipped
        // descriptor. A guard that ignored `caps` and refused unconditionally reddens here.
        reject_unadvertised_capabilities(&shipped, &cfg(true, crate::config::RestoreMode::Lazy))
            .expect("CH advertises both, so a config asking for both must be accepted");

        // …and a descriptor that re-gated nested virt refuses it, at the same call site, with no
        // second site to update.
        let without_nested = VmmCapabilities {
            nested_virt: false,
            ..shipped.clone()
        };
        let err = reject_unadvertised_capabilities(
            &without_nested,
            &cfg(true, crate::config::RestoreMode::Default),
        )
        .expect_err("a re-gated nested_virt must refuse a nested config");
        assert!(
            matches!(&err, Error::Unsupported { vmm, feature }
                if vmm == "cloud-hypervisor" && feature == "nested_virt"),
            "expected a nested_virt Unsupported, got {err:?}"
        );

        // Same for lazy restore — the field `restore()` actually consumes.
        let without_lazy = VmmCapabilities {
            lazy_restore: false,
            ..shipped
        };
        let err = reject_unadvertised_capabilities(
            &without_lazy,
            &cfg(false, crate::config::RestoreMode::Lazy),
        )
        .expect_err("a re-gated lazy_restore must refuse a Lazy config");
        assert!(
            matches!(&err, Error::Unsupported { vmm, feature }
                if vmm == "cloud-hypervisor" && feature == "lazy_restore"),
            "expected a lazy_restore Unsupported, got {err:?}"
        );
    }

    /// A minimal `PerVmResources` for the pure launch-plan gates below.
    fn plan_test_res() -> PerVmResources {
        PerVmResources {
            cgroup_name: String::new(),
            tap_name: None,
            netns_name: None,
            segment: None,
            vhost_user_socket: None,
            vmid: 7,
            guest_cid: 3,
            tmp_dir: PathBuf::from("/tmp/vmcell-plan-test"),
        }
    }

    // The `--restore` modifier mapping (§8.3), pure and exhaustive over `RestoreMode`. It moved
    // out of `spawn_ch` so `ch_launch_plan` could stay I/O-free; that made it testable, so it is
    // tested. Inverse (swapping `prefault=on`/`off`, or emitting a modifier for `Default`)
    // reddens the corresponding leg — and swapping them is a silent eager/lazy inversion, the
    // exact "accepted input silently downgraded" class d7 exists for.
    #[test]
    fn ch_restore_arg_maps_each_mode_to_its_prefault_modifier() {
        let dir = Path::new("/snap/dir");
        assert_eq!(
            ch_restore_arg(dir, crate::config::RestoreMode::Default),
            "source_url=file:///snap/dir"
        );
        assert_eq!(
            ch_restore_arg(dir, crate::config::RestoreMode::Eager),
            "source_url=file:///snap/dir,prefault=on"
        );
        assert_eq!(
            ch_restore_arg(dir, crate::config::RestoreMode::Lazy),
            "source_url=file:///snap/dir,prefault=off"
        );
    }

    // M11 GATE, CH leg (KVM-free). The jail posture is applied in `build_vmm_cmd`'s post-fork
    // `pre_exec` closure, which NOTHING KVM-free can observe: while `spawn_ch` wrote
    // `jail_spec_from_config(&cfg.jail)?` inline, rewriting that one token to a weakened config
    // shipped every CH VM with a different Layer-2 posture and left `cargo test`, `just ci` and
    // the whole live matrix green. `ch_launch_plan` makes the posture a RETURNED VALUE, so it is
    // assertable — and `LaunchPlan::jail` is private to the sibling `vmm::launch` module, so the
    // two-line defeat (`let mut plan = …; plan.jail = weaker;`) does not even compile here.
    //
    // Red on the inverse: rewrite `ch_launch_plan`'s `cfg.jail` to `JailConfig::disabled()` (or
    // any other value) and the first assertion reddens.
    #[test]
    fn the_ch_launch_plan_ships_the_configured_jail_posture() {
        use crate::config::{JailConfig, VmmSeccomp};

        let plan_for = |jail: JailConfig| {
            let cfg = VmConfig::builder(
                "/boot/vmlinux",
                crate::config::RootfsSource::Erofs {
                    image: PathBuf::from("/img/rootfs.erofs"),
                },
            )
            .vmm_seccomp(VmmSeccomp::Enforcing)
            .jail(jail)
            .build()
            .expect("build config");
            let plan = ch_launch_plan(
                Path::new("/usr/bin/cloud-hypervisor"),
                &cfg,
                &plan_test_res(),
                Path::new("/tmp/api.sock"),
                None,
            )
            .expect("build the launch plan");
            (cfg, plan)
        };

        // The plan's jail half IS the configured posture.
        let (cfg, plan) = plan_for(JailConfig::hardened());
        assert_eq!(
            plan.jail(),
            cfg.jail,
            "the launch plan must ship `cfg.jail`, not a locally-built posture"
        );

        // Positive control, so the equality above is not a tautology about two identical
        // structs: a DIFFERENT requested posture produces a different recorded posture, and
        // compiled, the difference is real hardening versus none at all — which is what shipping
        // the wrong value would have produced.
        let (disabled_cfg, disabled_plan) = plan_for(JailConfig::disabled());
        assert_eq!(disabled_plan.jail(), disabled_cfg.jail);
        assert_ne!(
            plan.jail(),
            disabled_plan.jail(),
            "control: the two postures differ, so the plan is not returning a constant"
        );
        assert!(
            !crate::vmm::jail::jail_spec_from_config(&plan.jail())
                .expect("compile the shipped spec")
                .is_noop(),
            "the shipped hardened posture must compile to real hardening"
        );
        assert!(
            crate::vmm::jail::jail_spec_from_config(&disabled_plan.jail())
                .expect("compile the disabled spec")
                .is_noop(),
            "control: the disabled posture compiles to no hardening — what a wrong value ships"
        );
    }

    // The argv half of the same plan, asserted on the COMPOSED command rather than a fragment
    // (docs/78 M11): a perfect per-fragment helper whose result never reaches the `Command` is
    // exactly the defect the composed assertion catches. Both shapes are covered because the
    // restore path is the one that adds an argument.
    //
    // Red on the inverse: drop the `cmd.args(&seccomp_args)` splice, or the `--restore` splice,
    // and the corresponding `assert_eq!` reddens.
    #[test]
    fn the_ch_launch_plan_composes_the_whole_argv() {
        use crate::config::{RestoreMode, VmmSeccomp};

        let cfg = VmConfig::builder(
            "/boot/vmlinux",
            crate::config::RootfsSource::Erofs {
                image: PathBuf::from("/img/rootfs.erofs"),
            },
        )
        .vmm_seccomp(VmmSeccomp::Enforcing)
        .build()
        .expect("build config");

        let cold = ch_launch_plan(
            Path::new("/usr/bin/cloud-hypervisor"),
            &cfg,
            &plan_test_res(),
            Path::new("/tmp/api.sock"),
            None,
        )
        .expect("build the cold-create plan");
        assert_eq!(
            cold.argv(),
            ["--seccomp", "true", "--api-socket", "/tmp/api.sock"],
            "a cold create is the seccomp flag plus the API socket, in that order"
        );

        let restore_arg = ch_restore_arg(Path::new("/snap"), RestoreMode::Lazy);
        let restored = ch_launch_plan(
            Path::new("/usr/bin/cloud-hypervisor"),
            &cfg,
            &plan_test_res(),
            Path::new("/tmp/api.sock"),
            Some(&restore_arg),
        )
        .expect("build the restore plan");
        assert_eq!(
            restored.argv(),
            [
                "--seccomp",
                "true",
                "--restore",
                "source_url=file:///snap,prefault=off",
                "--api-socket",
                "/tmp/api.sock",
            ],
            "a restore splices `--restore <arg>` between the seccomp flag and the API socket"
        );
    }
}

/// Source-level gate for §9.4's "`api_socket_poll` paces **every** daemon readiness wait" on the
/// shipped Cloud Hypervisor path.
///
/// Why a source scan rather than a functional assertion: the property is *which entry point the
/// call site calls, and with which argument*. `create()`/`restore()` reach that line only by
/// spawning a real `cloud-hypervisor` and a real `virtiofsd`, so nothing KVM-free can observe the
/// resulting cadence, and `FakeVmm` never runs this file at all. That blindness is exactly how the
/// original fix for `virtiofsd-socket-wait-hardcoded-cadence` shipped with the paced entry point
/// and **zero production callers**: `fs.rs`'s unit gate exercises only the extracted
/// `socket_wait_budget`, and stayed green throughout. Precedent for scanning this file's own text:
/// `vmm::seccomp`'s `dispatched_backend_ids` and `vmcell-privilege`'s roster gate.
///
/// It catches: any virtio-fs daemon start in this backend's production code that is not
/// `start_paced(…, &cfg.timeouts)` — the deprecated default-cadence shim, a `&Timeouts::default()`
/// argument, or a new site added unpaced. It cannot catch: a mis-pacing invisible in this file's
/// text (e.g. a `cfg` whose `timeouts` were rewritten upstream), and the runtime behavior itself —
/// the live virtio-fs legs of `just test-privileged` remain the only proof that the daemon it
/// paces actually comes up.
#[cfg(test)]
mod virtiofs_pacing_gate {
    const SOURCE: &str = include_str!("cloud_hypervisor.rs");

    /// The number of virtio-fs daemon starts this backend ships: one on `create`, one on the
    /// (guarded, `cfg.shares`-empty) `restore` path.
    ///
    /// Asserted exactly, so a scan that silently matched nothing — the way every source-scanning
    /// gate fails vacuously — reddens instead of passing over an empty set.
    const EXPECTED_CALL_SITES: usize = 2;

    /// This file's production text: everything before the first `#[cfg(test)]`, comment lines
    /// dropped and whitespace collapsed.
    ///
    /// Dropping comments keeps a prose mention of an entry point from being scanned as a call;
    /// collapsing whitespace keeps a rustfmt line break from hiding half of one.
    ///
    /// `pub(super)` so this file's other source-level gate
    /// ([`super::capability_guard_gate`]) reads the SAME normalizer instead of carrying a second
    /// copy of it — two readers of one law, not two laws.
    pub(super) fn production_code(source: &str) -> String {
        let production = source
            .split_once("#[cfg(test)]")
            .map_or(source, |(before, _)| before);
        production
            .lines()
            .map(str::trim)
            .filter(|line| !line.starts_with("//"))
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// Every `VirtioFsDaemon::…` call expression in `code`, each truncated at its statement's `;`.
    fn virtiofs_start_calls(code: &str) -> Vec<&str> {
        code.match_indices("VirtioFsDaemon::")
            .map(|(at, _)| {
                let tail = &code[at..];
                &tail[..tail.find(';').unwrap_or(tail.len())]
            })
            .collect()
    }

    /// The law: a shipped virtio-fs start names the paced entry point **and** hands it the VM's
    /// own profile. `start_paced(…, &Timeouts::default())` is as much a violation as `start(…)` —
    /// both pin the readiness wait to the default cadence under `low_latency()`/`throughput()`.
    fn call_is_paced_by_the_vm_config(call: &str) -> bool {
        call.starts_with("VirtioFsDaemon::start_paced(") && call.contains("&cfg.timeouts")
    }

    #[test]
    fn every_virtiofs_start_here_is_paced_by_the_vm_config() {
        let code = production_code(SOURCE);
        let calls = virtiofs_start_calls(&code);
        assert_eq!(
            calls.len(),
            EXPECTED_CALL_SITES,
            "expected {EXPECTED_CALL_SITES} virtio-fs daemon starts (create + restore); found \
             {}: {calls:?}. If a site was legitimately added or removed, update \
             EXPECTED_CALL_SITES — do not delete the scan.",
            calls.len()
        );
        for call in &calls {
            assert!(
                call_is_paced_by_the_vm_config(call),
                "§9.4: this virtio-fs readiness wait is not paced by the VM's own profile — \
                 `{call}` must be `VirtioFsDaemon::start_paced(share, …, &cfg.timeouts)`"
            );
        }
    }

    /// The gate's own red-on-inverse: the predicate must reject both regression shapes, so the
    /// scan above is not a test that can only ever pass (AGENTS.md rule 2).
    #[test]
    fn the_pacing_predicate_rejects_both_regression_shapes() {
        assert!(!call_is_paced_by_the_vm_config(
            "VirtioFsDaemon::start(share, &res.tmp_dir).await?"
        ));
        assert!(!call_is_paced_by_the_vm_config(
            "VirtioFsDaemon::start_paced(share, &res.tmp_dir, &Timeouts::default()).await?"
        ));
        assert!(call_is_paced_by_the_vm_config(
            "VirtioFsDaemon::start_paced(share, &res.tmp_dir, &cfg.timeouts).await?"
        ));
    }

    /// The scanner's own controls: a prose mention of the entry point is not a call site, and a
    /// call split across two rustfmt lines is still seen whole.
    #[test]
    fn the_scanner_ignores_comments_and_survives_line_breaks() {
        let synthetic = "// a failed VirtioFsDaemon::start reaps the VMM\n\
             let daemon =\n    VirtioFsDaemon::start_paced(share, &res.tmp_dir,\n    \
             &cfg.timeouts).await?;\n#[cfg(test)]\nmod tests { VirtioFsDaemon::start(x); }";
        let code = production_code(synthetic);
        let calls = virtiofs_start_calls(&code);
        assert_eq!(calls.len(), 1, "got {calls:?}");
        assert!(call_is_paced_by_the_vm_config(calls[0]), "got {calls:?}");
    }
}

/// Source-level gate for §2.1's "every backend self-checks its **own** descriptor" on the
/// primary backend, where the check is *dormant* and therefore invisible to behavior.
///
/// Why a scan rather than a test that observes a refusal: CH advertises both `nested_virt` and
/// `lazy_restore`, so [`reject_unadvertised_capabilities`] returns `Ok(())` for every config CH
/// can be handed today. Deleting either call site changes **no** observable behavior — every
/// unit test, `just ci`, and the whole live matrix stay green — until someone re-gates a flag
/// and discovers the primary backend never consulted its descriptor. That is the same
/// gate-shaped hole M11 named for crosvm's jail posture, one law over; the sibling
/// [`virtiofs_pacing_gate`] is the in-file precedent for closing it, and this module reuses that
/// module's `production_code` normalizer rather than copying it.
///
/// It catches: a deleted or moved guard in either entry point, a guard that stopped reading
/// `self.capabilities()`, and a guard that drifted *after* the spawn it is supposed to precede.
/// It cannot catch: a wrong `vmm` string or a wrong feature spelling (the descriptor-keyed
/// `capability_refusals_read_the_descriptor_not_a_hardcoded_bool` covers those), or the shared
/// predicate's own logic (its home gate in `vmm::mod` covers that).
#[cfg(test)]
mod capability_guard_gate {
    use super::virtiofs_pacing_gate::production_code;

    const SOURCE: &str = include_str!("cloud_hypervisor.rs");

    /// The exact call shape both entry points ship. Naming `&self.capabilities()` in the
    /// pattern is load-bearing: it is what makes the refusal key off the ONE descriptor rather
    /// than a locally-built `VmmCapabilities` a re-gate would not reach. The wrapper's own
    /// definition and body do not contain this substring, so the scan sees call sites only.
    const GUARD_CALL: &str = "reject_unadvertised_capabilities(&self.capabilities(), cfg)";

    /// The spawn every guard must precede. Both entry points reach the VMM through this one
    /// call, so "before any spawn" is a position in the text, not a claim in a comment.
    ///
    /// Deliberately unqualified: rustfmt breaks the shipped call as `= self\n.spawn_ch(…)`, which
    /// [`production_code`] collapses to `= self .spawn_ch(…)` — a receiver-qualified marker would
    /// silently match nothing and the gate would pass on an absent spawn. (Caught by this gate on
    /// its first run.) The `async fn spawn_ch(` definition sits in the earlier `impl
    /// CloudHypervisor` block, outside both scanned regions, so it cannot be mistaken for a call.
    const SPAWN_CALL: &str = "spawn_ch(";

    /// Splits `code` into the production bodies of `create` and `restore`, in that order.
    ///
    /// `create` runs to the start of `restore`; `restore` runs to the end of the production
    /// text (`capabilities()` follows it in the same impl, which is harmless — it contains
    /// neither marker). Returns `None` if either entry point is missing, so a rename reddens
    /// loudly instead of scanning an empty region.
    fn entry_point_bodies(code: &str) -> Option<(&str, &str)> {
        let create_at = code.find("async fn create(")?;
        let restore_at = code.find("async fn restore(")?;
        // `create` is declared before `restore` in the `impl Vmm` block; if that ever inverts,
        // the subtraction below would panic, so fail the gate explicitly instead.
        if restore_at <= create_at {
            return None;
        }
        Some((&code[create_at..restore_at], &code[restore_at..]))
    }

    /// The law, per entry point: exactly one descriptor self-check, and it precedes the spawn.
    fn guards_before_spawn(body: &str) -> bool {
        let guards: Vec<_> = body.match_indices(GUARD_CALL).collect();
        let Some(spawn_at) = body.find(SPAWN_CALL) else {
            return false;
        };
        matches!(guards.as_slice(), [(guard_at, _)] if *guard_at < spawn_at)
    }

    #[test]
    fn create_and_restore_both_self_check_the_descriptor_before_spawning() {
        let code = production_code(SOURCE);
        let (create, restore) =
            entry_point_bodies(&code).expect("both `create` and `restore` must exist, in order");
        for (name, body) in [("create", create), ("restore", restore)] {
            assert!(
                guards_before_spawn(body),
                "§2.1: `{name}` must call `{GUARD_CALL}` exactly once, before `{SPAWN_CALL}`. \
                 CH advertises both capabilities, so deleting this call is behaviorally silent \
                 today and a silent accept the day a flag is re-gated."
            );
        }
    }

    /// The gate's own red-on-inverse: the predicate must reject every regression shape, so the
    /// scan above is not a test that can only ever pass (AGENTS.md rule 2).
    #[test]
    fn the_guard_predicate_rejects_the_regression_shapes() {
        let with_guard = "fn create() { reject_unadvertised_capabilities(&self.capabilities(), \
                          cfg)?; let x = self.spawn_ch(cfg).await?; }";
        assert!(guards_before_spawn(with_guard));

        // Deleted guard — the M11-shaped hole this exists for.
        assert!(!guards_before_spawn(
            "fn create() { let x = self.spawn_ch(cfg).await?; }"
        ));
        // Guard present but AFTER the spawn: the VMM process already exists.
        assert!(!guards_before_spawn(
            "fn create() { let x = self.spawn_ch(cfg).await?; \
             reject_unadvertised_capabilities(&self.capabilities(), cfg)?; }"
        ));
        // Guard fed a locally-built descriptor instead of the one `capabilities()` returns.
        assert!(!guards_before_spawn(
            "fn create() { reject_unadvertised_capabilities(&local_caps, cfg)?; \
             let x = self.spawn_ch(cfg).await?; }"
        ));
        // Two guards is as wrong as none: a second, possibly divergent, site.
        assert!(!guards_before_spawn(
            "fn create() { reject_unadvertised_capabilities(&self.capabilities(), cfg)?; \
             reject_unadvertised_capabilities(&self.capabilities(), cfg)?; \
             let x = self.spawn_ch(cfg).await?; }"
        ));
    }

    /// The splitter's own controls: a renamed entry point is a hard failure, not an empty scan,
    /// and the two bodies really are disjoint.
    #[test]
    fn the_entry_point_splitter_fails_loud_instead_of_scanning_nothing() {
        assert!(entry_point_bodies("async fn create() {} fn other() {}").is_none());
        assert!(entry_point_bodies("async fn restore() {}").is_none());
        assert!(entry_point_bodies("async fn restore() {} async fn create() {}").is_none());

        let (create, restore) =
            entry_point_bodies("async fn create(A) {a} async fn restore(B) {b}")
                .expect("both markers present, in order");
        assert!(create.contains("{a}") && !create.contains("{b}"));
        assert!(restore.contains("{b}") && !restore.contains("{a}"));
    }
}

/// Source-level gate for M11's structural half on this backend: the launch is composed in
/// **one** place, and no second `JailSpec` compilation can reappear beside it.
///
/// [`the_ch_launch_plan_ships_the_configured_jail_posture`](tests::the_ch_launch_plan_ships_the_configured_jail_posture)
/// asserts the posture the plan *returns*; [`crate::vmm::LaunchPlan`]'s private field makes
/// overwriting that record a compile error. Neither can see the one remaining regression:
/// moving `jail_spec_from_config` + `build_vmm_cmd` back out of the plan into `spawn_ch`, which
/// re-opens the window between deciding the posture and applying it and leaves the plan's record
/// describing a command nobody spawns. That is a property of this file's *text*, so it is
/// scanned — the same shape as the sibling [`virtiofs_pacing_gate`], whose `production_code`
/// normalizer this reuses.
///
/// It catches: a raw `jail_spec_from_config` call in this backend, a second launch-plan
/// construction, and a deleted one. It cannot catch: the wrong `JailConfig` handed to the plan —
/// that is behavioral, and the KVM-free plan gate asserts it directly.
#[cfg(test)]
mod jail_composition_gate {
    use super::virtiofs_pacing_gate::production_code;

    const SOURCE: &str = include_str!("cloud_hypervisor.rs");

    /// The number of launch-plan constructions this backend ships: one, in [`super::ch_launch_plan`].
    ///
    /// Asserted exactly, so a scan that silently matched nothing — the way every source-scanning
    /// gate fails vacuously — reddens instead of passing over an empty set, and a second
    /// (possibly divergent) construction reddens too.
    const EXPECTED_PLAN_BUILD_SITES: usize = 1;

    /// Every call expression naming `needle` in `code`, truncated at its statement's `;`.
    fn calls<'a>(code: &'a str, needle: &str) -> Vec<&'a str> {
        code.match_indices(needle)
            .map(|(at, _)| {
                let tail = &code[at..];
                &tail[..tail.find(';').unwrap_or(tail.len())]
            })
            .collect()
    }

    #[test]
    fn the_launch_is_composed_only_in_the_plan() {
        let code = production_code(SOURCE);

        let raw = calls(&code, "jail_spec_from_config(");
        assert!(
            raw.is_empty(),
            "M11: this backend must compile no `JailSpec` of its own — the one compilation lives \
             in `vmcell::vmm::LaunchPlan::build`, which records the very value it compiles. \
             Found {raw:?}"
        );
        let raw_cmd = calls(&code, "build_vmm_cmd(");
        assert!(
            raw_cmd.is_empty(),
            "M11: this backend must not build a VMM command outside the launch plan. Found \
             {raw_cmd:?}"
        );

        // The anti-vacuity half: the two assertions above are satisfied by a file with no launch
        // at all, so the launch must be here, exactly once.
        let builds = calls(&code, "LaunchPlan::build(");
        assert_eq!(
            builds.len(),
            EXPECTED_PLAN_BUILD_SITES,
            "expected {EXPECTED_PLAN_BUILD_SITES} `LaunchPlan::build` call; found {}: {builds:?}. \
             If a site was legitimately added or removed, update EXPECTED_PLAN_BUILD_SITES — do \
             not delete the scan.",
            builds.len()
        );
    }

    /// The scanner's own controls: a prose mention is not a call site, a call split across two
    /// rustfmt lines is still seen whole, and the regression shape is genuinely detected — so the
    /// scan above is not a test that can only ever pass (AGENTS.md rule 2).
    #[test]
    fn the_scanner_sees_the_regression_and_ignores_comments() {
        let regressed = "// the plan calls jail_spec_from_config for us\n\
             let jail =\n    crate::vmm::jail::jail_spec_from_config(\n    &cfg.jail)?;\n\
             #[cfg(test)]\nmod tests { LaunchPlan::build(x); }";
        let code = production_code(regressed);
        assert_eq!(calls(&code, "jail_spec_from_config(").len(), 1);
        assert!(calls(&code, "LaunchPlan::build(").is_empty());

        let composed = "// jail_spec_from_config in prose is not a call\n\
             let mut plan =\n    crate::vmm::LaunchPlan::build(b, n,\n    cfg.jail)?;";
        let code = production_code(composed);
        assert!(calls(&code, "jail_spec_from_config(").is_empty());
        assert_eq!(calls(&code, "LaunchPlan::build(").len(), 1);
    }
}
