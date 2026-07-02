//! Configuration models and builder for virtual machine instances.

#![forbid(unsafe_code)]

use std::path::PathBuf;

/// Configuration for a virtual machine instance.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct VmConfig {
    /// Number of virtual CPUs to allocate.
    pub vcpus: u8,
    /// Amount of memory in MiB.
    pub mem_mib: u32,
    /// Path to the kernel image (vmlinux).
    pub kernel: PathBuf,
    /// Source for the root filesystem.
    pub rootfs: RootfsSource,
    /// Shared directories to expose to the VM.
    pub shares: Vec<Share>,
    /// Networking configuration.
    pub net: NetConfig,
    /// Whether to expose KVM for nested virtualization.
    pub nested_virt: bool,
    /// Cgroup resource limits for the VM and its processes.
    pub limits: ResourceLimits,
    /// Indicates if this VM is configured to be snapshot-eligible.
    pub snapshotting: bool,
    /// Optional explicitly-configured VMID.
    pub vmid: Option<u32>,
    /// Memory-restore strategy applied on the snapshot-restore path.
    pub restore_mode: RestoreMode,
    /// Mark guest memory `MADV_MERGEABLE` so host KSM can deduplicate identical
    /// guest pages (CH `mergeable=on`). KSM only merges private-anonymous pages,
    /// so enabling this also disables memory sharing (`shared=off`), making it
    /// incompatible with vhost-user paths (unprivileged net, virtio-fs). A
    /// density-vs-CPU trade measured in §13.5.
    pub ksm_mergeable: bool,
    /// Guest kernel console log verbosity (`loglevel=`). Default
    /// [`KernelVerbosity::Balanced`] is the §15 perf-optimal; raise it only for
    /// debugging / a test that asserts on a specific kernel log line.
    pub kernel_verbosity: KernelVerbosity,
    /// Per-VM hot-path timing knobs (connect cadence, teardown grace, guest
    /// accept/re-bind polls). Default [`Timeouts::default`] is the shipped
    /// balanced profile; [`Timeouts::low_latency`] / [`Timeouts::throughput`]
    /// are ready-made presets (§10).
    pub timeouts: Timeouts,
    /// Guest console device driving `serial.log`. Default [`ConsoleMode::Uart`]
    /// (8250 `ttyS0`) is alive from the first instruction, so it captures early
    /// boot and a pre-virtio panic; [`ConsoleMode::VirtioConsole`] (`hvc0`) batches
    /// output via a virtqueue (no per-byte VM-exit) but only exists after the
    /// virtio-pci probe. The cmdline `console=` token and the per-backend device
    /// wiring are both derived from this field so they can never desync.
    pub console_mode: ConsoleMode,
}

/// Per-VM hot-path timing knobs, gathered so a workload can pick a profile in one
/// place. Only the timings that (a) sit on the per-test hot path and (b) a
/// workload legitimately trades are here; internal readiness/QMP/join timeouts
/// stay as constants (they are correctness-floor mechanics, not workload knobs).
///
/// Two presets are provided: [`Timeouts::low_latency`] minimizes time-to-output
/// (tightens every connect/accept cadence, leaves teardown graceful) and
/// [`Timeouts::throughput`] minimizes whole-lifecycle wall-clock (cuts the
/// graceful-shutdown grace). All constructors clamp to correctness floors so a
/// preset can never produce a busy-spin or a sub-viable window.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Timeouts {
    /// Host: initial/reset backoff between failed vsock connects while the VMM
    /// socket is still absent (mirrors the guest `accept_poll`; jointly the
    /// reconnect cadence). Floor 1 ms.
    pub connect_backoff_floor: std::time::Duration,
    /// Host: upper clamp for the doubling connect backoff. Floor = the floor.
    pub connect_backoff_cap: std::time::Duration,
    /// Host: per-byte read timeout for the vsock-mux `OK` handshake line. Floor 5 ms.
    pub connect_ok_read: std::time::Duration,
    /// Host: VMM control-socket readiness poll interval after spawn. Floor 1 ms.
    pub api_socket_poll: std::time::Duration,
    /// Host: ceiling for the graceful `shutdown()` grace window (polls
    /// `has_exited`, so this bounds only a guest that never exits on its own).
    /// The `Drop` force-kill path does not use this.
    pub shutdown_grace: std::time::Duration,
    /// Guest (emitted on the cmdline): non-blocking accept poll cadence. Floor 1 ms.
    pub guest_accept_poll: std::time::Duration,
    /// Guest (emitted on the cmdline): post-restore listener re-bind idle window.
    /// Floor 20 ms.
    pub guest_rebind_idle: std::time::Duration,
}

impl Default for Timeouts {
    /// The shipped balanced profile (the §15 post-optimization-pass values).
    fn default() -> Self {
        Self {
            connect_backoff_floor: std::time::Duration::from_millis(20),
            connect_backoff_cap: std::time::Duration::from_millis(100),
            connect_ok_read: std::time::Duration::from_millis(150),
            api_socket_poll: std::time::Duration::from_millis(5),
            shutdown_grace: std::time::Duration::from_millis(250),
            guest_accept_poll: std::time::Duration::from_millis(20),
            guest_rebind_idle: std::time::Duration::from_millis(250),
        }
    }
}

impl Timeouts {
    /// Clamps every field into its correctness floor so a hand-built or preset
    /// `Timeouts` can never busy-spin PID 1 or collapse a window below viability.
    #[must_use]
    fn clamped(mut self) -> Self {
        use std::time::Duration;
        let max = |a: Duration, b: Duration| if a > b { a } else { b };
        self.connect_backoff_floor = max(self.connect_backoff_floor, Duration::from_millis(1));
        self.connect_backoff_cap = max(self.connect_backoff_cap, self.connect_backoff_floor);
        self.connect_ok_read = max(self.connect_ok_read, Duration::from_millis(5));
        self.api_socket_poll = max(self.api_socket_poll, Duration::from_millis(1));
        self.guest_accept_poll = max(self.guest_accept_poll, Duration::from_millis(1));
        self.guest_rebind_idle = max(self.guest_rebind_idle, Duration::from_millis(20));
        self
    }

    /// Preset that minimizes **time-to-output** (start → first exec output):
    /// tightens every connect/accept cadence (host + guest) so the gap between
    /// "guest ready" and "host noticed" shrinks. Teardown is **not** optimized —
    /// `shutdown_grace` stays graceful (this profile excludes teardown by design).
    #[must_use]
    pub fn low_latency() -> Self {
        use std::time::Duration;
        Self {
            connect_backoff_floor: Duration::from_millis(5),
            connect_backoff_cap: Duration::from_millis(40),
            connect_ok_read: Duration::from_millis(100),
            api_socket_poll: Duration::from_millis(2),
            shutdown_grace: Duration::from_millis(250),
            guest_accept_poll: Duration::from_millis(5),
            guest_rebind_idle: Duration::from_millis(150),
        }
        .clamped()
    }

    /// Preset that minimizes **whole per-test wall-clock** (incl. teardown): cuts
    /// the graceful-`shutdown()` grace (the largest tunable in the aggregate) and
    /// keeps connect cadences moderate (tight polls cost idle-CPU wakeups, which
    /// hurt a dense farm). A caller that tears down via `Drop`/RAII already gets
    /// the ~27 ms fast path; this helps graceful-`shutdown()` users.
    #[must_use]
    pub fn throughput() -> Self {
        use std::time::Duration;
        Self {
            connect_backoff_floor: Duration::from_millis(10),
            connect_backoff_cap: Duration::from_millis(75),
            connect_ok_read: Duration::from_millis(150),
            api_socket_poll: Duration::from_millis(3),
            shutdown_grace: Duration::from_millis(50),
            guest_accept_poll: Duration::from_millis(10),
            guest_rebind_idle: Duration::from_millis(200),
        }
        .clamped()
    }
}

/// Appends the guest-side timing tokens to a kernel `cmdline` (§8.3). The guest
/// agent parses `vmcell_accept_poll_ms=` / `vmcell_rebind_idle_ms=` (whole ms,
/// clamped guest-side) to tune its accept/re-bind cadence per VM without a rootfs
/// rebuild; absent tokens fall back to the agent's compiled defaults.
pub(crate) fn push_guest_timeout_args(cmdline: &mut String, timeouts: &Timeouts) {
    cmdline.push_str(&format!(
        " vmcell_accept_poll_ms={} vmcell_rebind_idle_ms={}",
        timeouts.guest_accept_poll.as_millis(),
        timeouts.guest_rebind_idle.as_millis(),
    ));
}

/// Builds the guest kernel command line — the **single** source of truth shared by
/// all three backends (`console`, `loglevel`, RNG-trust, root/rootfs, `panic`,
/// `init`, `vmcell_vmid`, optional `ip=`/nested/shares, and the guest timing
/// tokens). Centralizing it fixes the prior triplication where QEMU's inline
/// cmdline silently omitted `loglevel=` (paying the full 8250 UART tax, §8.3).
/// `backend_extra` carries the one genuine per-backend fragment (Firecracker's
/// `noxsave ` FPU guard), inserted before `init=` exactly where it was.
///
/// # Errors
/// Propagates the `/30` host-IP math error when networking is enabled.
pub(crate) fn build_kernel_cmdline(
    cfg: &VmConfig,
    vmid: u32,
    backend_extra: &str,
) -> Result<String, crate::error::Error> {
    let rootfstype = match &cfg.rootfs {
        RootfsSource::Erofs { .. } => "erofs",
        _ => "ext4",
    };
    let rootflags = match &cfg.rootfs {
        RootfsSource::Erofs { .. } => "",
        _ => "rootflags=noload",
    };
    // `cryptomgr.notests` / `raid=noautodetect` skip boot work that is dead in this
    // guest: the built-in crypto self-tests (~10 ms measured via printk timestamps —
    // docs/45-claude-perf-investigation.md EXP-B) and the md RAID autodetect scan
    // (~2 ms; no RAID device can exist). Neither affects virtio/vsock/virtio-fs/erofs,
    // `ip=` autoconfig, panic capture, or the in-kernel crypto itself (self-tests are
    // a boot-time QA pass, not a runtime dependency).
    let mut s = format!(
        "console={} loglevel={} random.trust_cpu=on random.trust_bootloader=on \
         cryptomgr.notests raid=noautodetect \
         root=/dev/vda rootfstype={} ro {} panic=1 {}init=/usr/sbin/vmcell-guest-agent vmcell_vmid={}",
        cfg.console_mode.console(),
        cfg.kernel_verbosity.loglevel(),
        rootfstype,
        rootflags,
        backend_extra,
        vmid,
    );
    if !matches!(cfg.net, NetConfig::None) {
        let (host_ip, guest_ip, _) = crate::net::ip_math(vmid)?;
        s.push_str(&format!(
            " ip={}::{}:255.255.255.252::eth0:off",
            guest_ip, host_ip
        ));
    }
    if cfg.nested_virt {
        s.push_str(" kvm-intel.nested=1 kvm-amd.nested=1");
    }
    push_share_args(&mut s, &cfg.shares);
    push_guest_timeout_args(&mut s, &cfg.timeouts);
    Ok(s)
}

/// Options for the root filesystem backing the VM.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum RootfsSource {
    /// Read-only EROFS image. Shared across multiple VMs.
    Erofs {
        /// Path to the EROFS image file.
        image: PathBuf,
    },
    /// Writable or read-only block device image.
    Block {
        /// Base image file.
        image: PathBuf,
        /// Optional writable overlay file.
        overlay: Option<PathBuf>,
    },
    /// Root filesystem mounted via virtio-fs.
    VirtioFs {
        /// Path to the host directory serving as root.
        dir: PathBuf,
    },
}

/// Guest kernel console log verbosity, mapped to the `loglevel=` boot parameter.
///
/// Kernel `printk` to the legacy 8250 `ttyS0` UART is a **per-byte PIO trap → VM
/// exit** (§8.3), so verbose boot logging is a real cold-boot cost — the single
/// largest lever in the §15 latency pass. This knob lets debugging and specific
/// tests opt into a verbose log without making every VM pay the exit tax. Panic
/// capture ([`contains_panic`](crate::vmm::SerialLog::contains_panic), KERN_EMERG)
/// works at every level.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum KernelVerbosity {
    /// `loglevel=3` — err/crit only. Fastest boot, but a healthy log is nearly
    /// empty, so not suitable for a test that greps a boot line (e.g. `boot.rs`).
    Quiet,
    /// `loglevel=6` — the shipped default: drops the `KERN_INFO` device-probe
    /// flood while keeping the `NOTICE` banner + `WARN`/`ERR` + panic lines.
    #[default]
    Balanced,
    /// `loglevel=7` — adds the `KERN_INFO` flood back (pays the full UART tax);
    /// for diagnosing a device-probe issue.
    Verbose,
    /// `loglevel=8` — everything, for a wedged-boot post-mortem.
    Debug,
}

impl KernelVerbosity {
    /// The `loglevel=` numeric value for this verbosity (kernel console loglevel:
    /// a message prints iff its level `<` this value).
    #[must_use]
    pub fn loglevel(self) -> u8 {
        match self {
            KernelVerbosity::Quiet => 3,
            KernelVerbosity::Balanced => 6,
            KernelVerbosity::Verbose => 7,
            KernelVerbosity::Debug => 8,
        }
    }
}

/// Guest console device, mapped to the `console=` boot parameter and the matching
/// per-backend console device wiring.
///
/// The cmdline `console=` token and the device wiring must move in lockstep, or the
/// guest writes its console to a device that sinks nowhere and `serial.log` goes
/// silent. Both are derived from this one knob so they cannot desync.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConsoleMode {
    /// Legacy 8250 `ttyS0`: alive from the first instruction (early-boot + panic
    /// capture, §12.10) but per-byte PIO VM-exits. The safe default.
    #[default]
    Uart,
    /// virtio-console `hvc0`: batched via virtqueue (~no exit tax) — but only
    /// exists after virtio-pci probe, so early boot + a pre-virtio panic are LOST
    /// (use `Uart` for panic-sensitive / kernel-log tests). Not supported on
    /// Firecracker. For guest-code tests that don't inspect the kernel log.
    VirtioConsole,
}

impl ConsoleMode {
    /// The `console=` kernel-cmdline token for this mode (`ttyS0` for the 8250
    /// UART, `hvc0` for virtio-console).
    #[must_use]
    pub fn console(self) -> &'static str {
        match self {
            ConsoleMode::Uart => "ttyS0",
            ConsoleMode::VirtioConsole => "hvc0",
        }
    }
}

/// Memory-restore strategy for snapshot restore (Cloud Hypervisor `prefault`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum RestoreMode {
    /// The VMM's default (CH: lazy/demand-paged).
    #[default]
    Default,
    /// Eagerly fault all guest memory at restore (`prefault=on`).
    Eager,
    /// Lazily demand-page guest memory (`prefault=off`, userfaultfd).
    Lazy,
}

/// A host directory shared with the guest VM via virtio-fs.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct Share {
    /// The mount tag used by the guest to identify this share.
    pub tag: String,
    /// Path to the directory on the host.
    pub host_path: PathBuf,
    /// Access permissions for the guest.
    pub access: Access,
    /// Caching policy for the shared directory.
    pub cache: CachePolicy,
    /// In-guest mount point for this share. Defaults to `/<tag>`; override with
    /// [`Share::with_guest_path`] to decouple the mount path from the virtio-fs
    /// tag. Must be absolute and free of `:`/whitespace (it is encoded on the
    /// kernel command line, §5.2); [`VmConfigBuilder::build`] rejects violations.
    pub guest_path: PathBuf,
}

impl Share {
    /// Creates a new `Share` configuration mounted at `/<tag>` in the guest.
    ///
    /// Use [`Share::with_guest_path`] to mount it somewhere other than `/<tag>`.
    #[must_use]
    pub fn new(
        tag: impl Into<String>,
        host_path: impl Into<PathBuf>,
        access: Access,
        cache: CachePolicy,
    ) -> Self {
        let tag = tag.into();
        let guest_path = PathBuf::from(format!("/{tag}"));
        Self {
            tag,
            host_path: host_path.into(),
            access,
            cache,
            guest_path,
        }
    }

    /// Overrides the in-guest mount point for this share (default `/<tag>`).
    ///
    /// Lets a caller mount a share at an arbitrary absolute path — e.g. tag
    /// `data` mounted at `/srv/data` — decoupling the mount point from the
    /// virtio-fs tag for more generic workloads. The path must be absolute and
    /// contain neither `:` nor whitespace (it is encoded on the kernel command
    /// line, §5.2); [`VmConfigBuilder::build`] enforces this.
    #[must_use]
    pub fn with_guest_path(mut self, guest_path: impl Into<PathBuf>) -> Self {
        self.guest_path = guest_path.into();
        self
    }
}

/// Appends the guest boot-time mount plan for `shares` to a kernel `cmdline`.
///
/// The guest agent (PID 1) has no host-side view of [`VmConfig`], so the shares
/// it must mount — their tag, mount point, and access mode — travel on the kernel
/// command line as one `vmcell_share=<tag>:<guest_path>:<ro|rw>` token per share
/// (§5.2: tags and mount points are caller-defined, not built into the runner).
/// The agent reads `/proc/cmdline`, mounts each `tag` at its `guest_path` over
/// virtiofs (default `/<tag>`), and uses a read-only mount for `ro` shares. Tags
/// and guest paths are validated by [`VmConfigBuilder::build`] to be encodable
/// (no `:` or whitespace), so this token is unambiguous. No shares ⇒ nothing
/// appended.
pub(crate) fn push_share_args(cmdline: &mut String, shares: &[Share]) {
    for share in shares {
        let access = match share.access {
            Access::ReadOnly => "ro",
            Access::ReadWrite => "rw",
        };
        // `build()` validated guest_path as absolute, valid UTF-8, and free of
        // ':'/whitespace, so the lossy conversion is exact here.
        cmdline.push_str(&format!(
            " vmcell_share={}:{}:{}",
            share.tag,
            share.guest_path.to_string_lossy(),
            access
        ));
    }
}

/// Access level for a shared directory.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Access {
    /// Share is read-only.
    ReadOnly,
    /// Share is read-write.
    ReadWrite,
}

/// Cache policy for virtio-fs shares.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CachePolicy {
    /// Never cache file contents in the guest.
    Never,
    /// Automatically cache based on standard filesystem rules.
    Auto,
    /// Always cache.
    Always,
}

/// Networking mode and configuration for the VM.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum NetConfig {
    /// Privileged mode using TAP and netns (requires root/CAP_NET_ADMIN).
    Privileged {
        /// Egress proxy configuration.
        egress: Egress,
        /// Optional port for host services accessible from the guest.
        host_services_port: Option<u16>,
    },
    /// Unprivileged mode using an in-process smoltcp stack plus a vhost-user-net
    /// NAT, requiring no extra Linux capabilities (passt was deliberately rejected).
    Unprivileged {
        /// Egress proxy configuration.
        egress: Egress,
        /// Optional port for host services accessible from the guest.
        host_services_port: Option<u16>,
    },
    /// No networking configuration.
    #[default]
    None,
}

/// Egress filtering strategy for outbound network traffic.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum Egress {
    /// Traffic is transparently routed through a proxy.
    Filtered(ProxyConfig),
    /// All egress traffic is blocked.
    Blocked,
    /// Egress traffic is allowed without interception.
    #[default]
    Open,
}

/// Configuration for the transparent proxy.
#[derive(Clone, Default)]
#[non_exhaustive]
pub struct ProxyConfig {
    /// Test doubles to intercept and mock requests.
    #[cfg(feature = "proxy")]
    pub doubles: std::sync::Arc<std::sync::RwLock<Vec<crate::proxy::doubles::TestDouble>>>,
    /// Domains that should be blocked.
    pub blocked_domains: Vec<String>,
}

impl std::fmt::Debug for ProxyConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProxyConfig").finish_non_exhaustive()
    }
}

impl PartialEq for ProxyConfig {
    fn eq(&self, _other: &Self) -> bool {
        let same_blocked = self.blocked_domains == _other.blocked_domains;
        #[cfg(feature = "proxy")]
        {
            same_blocked && std::sync::Arc::ptr_eq(&self.doubles, &_other.doubles)
        }
        #[cfg(not(feature = "proxy"))]
        {
            same_blocked
        }
    }
}

impl Eq for ProxyConfig {}

/// Resource limits enforced via cgroup v2.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct ResourceLimits {
    /// Maximum memory in MiB (`memory.max`).
    pub mem_max_mib: Option<u32>,
    /// CPU usage limit as a percentage (`cpu.max`).
    pub cpu_max_pct: Option<u32>,
    /// Maximum number of processes/threads (`pids.max`).
    pub pids_max: Option<u32>,
    /// I/O bandwidth/IOPS limits (`io.max`).
    pub io_max: Option<IoMax>,
}

/// I/O maximum limits mapping to `io.max`.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct IoMax {
    /// Device node string, e.g., "8:0" or "254:0"
    pub device: String,
    /// Read bandwidth max in bytes per second
    pub rbps: Option<u64>,
    /// Write bandwidth max in bytes per second
    pub wbps: Option<u64>,
    /// Read IOPS max
    pub riops: Option<u64>,
    /// Write IOPS max
    pub wiops: Option<u64>,
}

impl VmConfig {
    /// Creates a builder for `VmConfig` with required parameters.
    #[must_use]
    pub fn builder(kernel: impl Into<PathBuf>, rootfs: RootfsSource) -> VmConfigBuilder {
        VmConfigBuilder {
            kernel: kernel.into(),
            rootfs,
            vcpus: 1,
            mem_mib: 128,
            shares: vec![],
            net: NetConfig::default(),
            nested_virt: false,
            limits: ResourceLimits::default(),
            snapshotting: false,
            vmid: None,
            restore_mode: RestoreMode::Default,
            ksm_mergeable: false,
            kernel_verbosity: KernelVerbosity::Balanced,
            timeouts: Timeouts::default(),
            console_mode: ConsoleMode::Uart,
        }
    }
}

/// A builder for constructing a `VmConfig`.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct VmConfigBuilder {
    kernel: PathBuf,
    rootfs: RootfsSource,
    vcpus: u8,
    mem_mib: u32,
    shares: Vec<Share>,
    net: NetConfig,
    nested_virt: bool,
    limits: ResourceLimits,
    snapshotting: bool,
    vmid: Option<u32>,
    restore_mode: RestoreMode,
    ksm_mergeable: bool,
    kernel_verbosity: KernelVerbosity,
    timeouts: Timeouts,
    console_mode: ConsoleMode,
}

impl VmConfigBuilder {
    /// Adds a shared directory.
    #[must_use]
    pub fn with_share(mut self, share: Share) -> Self {
        self.shares.push(share);
        self
    }

    /// Sets the number of virtual CPUs.
    #[must_use]
    pub fn vcpus(mut self, vcpus: u8) -> Self {
        self.vcpus = vcpus;
        self
    }

    /// Sets the memory size in MiB.
    #[must_use]
    pub fn mem_mib(mut self, mem_mib: u32) -> Self {
        self.mem_mib = mem_mib;
        self
    }

    /// Sets the networking configuration.
    #[must_use]
    pub fn net(mut self, net: NetConfig) -> Self {
        self.net = net;
        self
    }

    /// Enables or disables nested virtualization.
    #[must_use]
    pub fn nested_virt(mut self, nested_virt: bool) -> Self {
        self.nested_virt = nested_virt;
        self
    }

    /// Sets the cgroup resource limits.
    #[must_use]
    pub fn limits(mut self, limits: ResourceLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Sets whether the VM is expected to be snapshot-eligible.
    #[must_use]
    pub fn snapshotting(mut self, snapshotting: bool) -> Self {
        self.snapshotting = snapshotting;
        self
    }

    /// Explicitly sets the VMID for validation.
    #[must_use]
    pub fn vmid(mut self, vmid: u32) -> Self {
        self.vmid = Some(vmid);
        self
    }

    /// Sets the memory-restore strategy used on the snapshot-restore path.
    #[must_use]
    pub fn restore_mode(mut self, mode: RestoreMode) -> Self {
        self.restore_mode = mode;
        self
    }

    /// Enables KSM-mergeable (private-anonymous) guest memory (§13.5). See
    /// [`VmConfig::ksm_mergeable`] for the sharing trade-off.
    #[must_use]
    pub fn ksm_mergeable(mut self, mergeable: bool) -> Self {
        self.ksm_mergeable = mergeable;
        self
    }

    /// Sets the guest kernel console verbosity ([`KernelVerbosity`], default
    /// [`KernelVerbosity::Balanced`]). Raise it for debugging or a test that
    /// asserts on a specific kernel log line.
    #[must_use]
    pub fn kernel_verbosity(mut self, verbosity: KernelVerbosity) -> Self {
        self.kernel_verbosity = verbosity;
        self
    }

    /// Sets the per-VM hot-path [`Timeouts`] (default [`Timeouts::default`]). Use
    /// [`Timeouts::low_latency`] or [`Timeouts::throughput`] for the ready-made
    /// profiles.
    #[must_use]
    pub fn timeouts(mut self, timeouts: Timeouts) -> Self {
        self.timeouts = timeouts.clamped();
        self
    }

    /// Sets the guest [`ConsoleMode`] (default [`ConsoleMode::Uart`]). Choose
    /// [`ConsoleMode::VirtioConsole`] for guest-code tests that don't inspect the
    /// kernel log (it loses early boot / a pre-virtio panic and is unsupported on
    /// Firecracker).
    #[must_use]
    pub fn console_mode(mut self, m: ConsoleMode) -> Self {
        self.console_mode = m;
        self
    }

    /// Disables network access.
    #[must_use]
    pub fn network_disabled(mut self) -> Self {
        self.net = NetConfig::None;
        self
    }

    /// Builds the final [`VmConfig`], validating its internal consistency.
    ///
    /// # Errors
    /// Returns [`Error::Config`](crate::error::Error::Config) when the
    /// configuration is internally inconsistent. The validations performed are:
    /// - `vcpus == 0` (at least one vCPU is required);
    /// - `mem_mib` below the 64 MiB floor;
    /// - an empty kernel path;
    /// - an explicit `vmid` outside the `1..=254` window used by the `/30`
    ///   host-IP math;
    /// - a share with an empty mount tag, or two shares sharing a mount tag;
    /// - `snapshotting` combined with any vhost-user device — a virtio-fs
    ///   rootfs, any virtio-fs data share, or unprivileged (vhost-user-net)
    ///   networking — which violates the §3.3 snapshot-eligibility law;
    /// - `ksm_mergeable` combined with any vhost-user device (it sets CH
    ///   `shared=off`, mutually exclusive with the vhost-user paths — §13.5).
    ///
    /// This validates internal consistency only; it does **not** check that the
    /// kernel, rootfs, or share paths exist on disk.
    ///
    /// # Examples
    /// ```rust
    /// use vmcell::config::{VmConfig, RootfsSource};
    /// let cfg = VmConfig::builder("/path/to/kernel", RootfsSource::Erofs { image: "/path/to/rootfs".into() })
    ///     .vcpus(4)
    ///     .mem_mib(2048)
    ///     .build()
    ///     .unwrap();
    /// ```
    pub fn build(self) -> Result<VmConfig, crate::error::Error> {
        if self.vcpus == 0 {
            return Err(crate::error::Error::Config("vcpus must be > 0".into()));
        }
        if self.mem_mib < 64 {
            return Err(crate::error::Error::Config("mem_mib must be >= 64".into()));
        }
        if self.kernel.as_os_str().is_empty() {
            return Err(crate::error::Error::Config(
                "kernel path cannot be empty".into(),
            ));
        }

        if self.snapshotting {
            if let RootfsSource::VirtioFs { .. } = self.rootfs {
                return Err(crate::error::Error::Config(
                    "virtio-fs rootfs cannot be combined with snapshotting".into(),
                ));
            }
            // Snapshot-eligibility law: a snapshot-eligible VM must have no
            // vhost-user device attached. A virtio-fs data `Share` is served
            // by virtiofsd (a vhost-user device), so reject it here as well as
            // for the virtio-fs *rootfs* above.
            if !self.shares.is_empty() {
                return Err(crate::error::Error::Config(
                    "virtio-fs data shares cannot be combined with snapshotting".into(),
                ));
            }
            // Snapshot-eligibility law (§3.3), third boundary case: the unprivileged
            // network path is an in-process vhost-user-net device, so it is
            // mutually exclusive with snapshotting just like virtiofsd above.
            if matches!(self.net, NetConfig::Unprivileged { .. }) {
                return Err(crate::error::Error::Config(
                    "unprivileged (vhost-user-net) networking cannot be combined with snapshotting"
                        .into(),
                ));
            }
        }

        // §13.5 KSM lever: `ksm_mergeable` sets CH `mergeable=on, shared=off`,
        // and KSM only merges private-anonymous pages — so `shared=off` is
        // mutually exclusive with every vhost-user path. Enforce here (boundary
        // 1) so an invalid combination never becomes a `VmConfig` and instead
        // fails late at the backend, which sets `shared: !ksm_mergeable` while
        // still attaching the vhost-user device.
        if self.ksm_mergeable {
            if let RootfsSource::VirtioFs { .. } = self.rootfs {
                return Err(crate::error::Error::Config(
                    "ksm_mergeable cannot be combined with a virtio-fs rootfs (vhost-user)".into(),
                ));
            }
            if !self.shares.is_empty() {
                return Err(crate::error::Error::Config(
                    "ksm_mergeable cannot be combined with virtio-fs data shares (vhost-user)"
                        .into(),
                ));
            }
            if matches!(self.net, NetConfig::Unprivileged { .. }) {
                return Err(crate::error::Error::Config(
                    "ksm_mergeable cannot be combined with unprivileged (vhost-user-net) networking"
                        .into(),
                ));
            }
        }

        if let Some(vmid) = self.vmid {
            if vmid == 0 {
                return Err(crate::error::Error::Config("vmid must be >= 1".into()));
            }
            if vmid > 254 {
                return Err(crate::error::Error::Config("vmid must be <= 254".into()));
            }
        }

        let mut tags = std::collections::HashSet::new();
        let mut guest_paths = std::collections::HashSet::new();
        for share in &self.shares {
            if share.tag.is_empty() {
                return Err(crate::error::Error::Config(
                    "share tag cannot be empty".into(),
                ));
            }
            // The mount plan reaches the guest agent as
            // `vmcell_share=<tag>:<guest_path>:<ro|rw>` kernel-cmdline tokens (§5.2),
            // parsed by splitting on whitespace and then on ':'. A `:` or whitespace
            // in the tag or the guest path would corrupt that encoding and silently
            // mis-mount (or drop) the share, so reject it at the boundary rather than
            // discover it as a missing mount in-guest.
            if share.tag.contains(':') || share.tag.chars().any(char::is_whitespace) {
                return Err(crate::error::Error::Config(format!(
                    "share tag {:?} may not contain ':' or whitespace (it is encoded on the kernel cmdline)",
                    share.tag
                )));
            }
            if !tags.insert(share.tag.clone()) {
                return Err(crate::error::Error::Config(format!(
                    "duplicate share tag: {}",
                    share.tag
                )));
            }
            let guest_path = share.guest_path.to_str().ok_or_else(|| {
                crate::error::Error::Config(format!(
                    "share guest_path for tag {:?} must be valid UTF-8 (it is encoded on the kernel cmdline)",
                    share.tag
                ))
            })?;
            if !share.guest_path.is_absolute() {
                return Err(crate::error::Error::Config(format!(
                    "share guest_path {guest_path:?} (tag {:?}) must be an absolute path",
                    share.tag
                )));
            }
            if guest_path.contains(':') || guest_path.chars().any(char::is_whitespace) {
                return Err(crate::error::Error::Config(format!(
                    "share guest_path {guest_path:?} may not contain ':' or whitespace (it is encoded on the kernel cmdline)"
                )));
            }
            if !guest_paths.insert(guest_path.to_string()) {
                return Err(crate::error::Error::Config(format!(
                    "duplicate share guest_path: {guest_path}"
                )));
            }
        }

        Ok(VmConfig {
            kernel: self.kernel,
            rootfs: self.rootfs,
            vcpus: self.vcpus,
            mem_mib: self.mem_mib,
            shares: self.shares,
            net: self.net,
            nested_virt: self.nested_virt,
            limits: self.limits,
            snapshotting: self.snapshotting,
            vmid: self.vmid,
            restore_mode: self.restore_mode,
            ksm_mergeable: self.ksm_mergeable,
            kernel_verbosity: self.kernel_verbosity,
            timeouts: self.timeouts,
            console_mode: self.console_mode,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_builder_defaults() {
        let cfg = VmConfig::builder(
            PathBuf::from("/vmlinux"),
            RootfsSource::VirtioFs {
                dir: PathBuf::from("/rootfs"),
            },
        )
        .build()
        .unwrap();
        assert_eq!(cfg.vcpus, 1);
        assert_eq!(cfg.mem_mib, 128);
        assert!(!cfg.nested_virt);
    }

    // Guards the §13.3 eager-vs-lazy restore toggle: the builder must carry the
    // selected `RestoreMode` onto the built config, and default to `Default`.
    // Buggy impl: builder drops the field (always `Default`) — the `Eager`
    // assertion below would then fail.
    #[test]
    fn test_builder_restore_mode() {
        let default_cfg = VmConfig::builder(
            PathBuf::from("/vmlinux"),
            RootfsSource::Erofs {
                image: PathBuf::from("/rootfs.erofs"),
            },
        )
        .build()
        .unwrap();
        assert_eq!(default_cfg.restore_mode, RestoreMode::Default);

        let eager_cfg = VmConfig::builder(
            PathBuf::from("/vmlinux"),
            RootfsSource::Erofs {
                image: PathBuf::from("/rootfs.erofs"),
            },
        )
        .restore_mode(RestoreMode::Eager)
        .build()
        .unwrap();
        assert_eq!(eager_cfg.restore_mode, RestoreMode::Eager);
        assert_ne!(eager_cfg.restore_mode, RestoreMode::Default);
    }

    // Guards the §13.5 KSM density lever: the builder must carry `ksm_mergeable`
    // onto the built config and default to `false` (so normal VMs keep shared
    // memory). Buggy impl: builder drops the field — the `true` assertion fails.
    #[test]
    fn test_builder_ksm_mergeable() {
        let mk = |mergeable: bool| {
            VmConfig::builder(
                PathBuf::from("/vmlinux"),
                RootfsSource::Erofs {
                    image: PathBuf::from("/rootfs.erofs"),
                },
            )
            .ksm_mergeable(mergeable)
            .build()
            .unwrap()
        };
        assert!(!mk(false).ksm_mergeable);
        assert!(mk(true).ksm_mergeable);
        // Default (builder untouched) must be false.
        let default_cfg = VmConfig::builder(
            PathBuf::from("/vmlinux"),
            RootfsSource::Erofs {
                image: PathBuf::from("/rootfs.erofs"),
            },
        )
        .build()
        .unwrap();
        assert!(!default_cfg.ksm_mergeable);
    }

    #[test]
    fn test_builder_methods() {
        let cfg = VmConfig::builder(
            PathBuf::from("/vmlinux"),
            RootfsSource::VirtioFs {
                dir: PathBuf::from("/rootfs"),
            },
        )
        .with_share(Share::new(
            "test",
            "/tmp/test",
            Access::ReadOnly,
            CachePolicy::Auto,
        ))
        .network_disabled()
        .build()
        .unwrap();

        assert_eq!(cfg.shares.len(), 1);
        assert_eq!(cfg.shares[0].tag, "test");
        assert!(matches!(cfg.net, NetConfig::None));
    }

    #[test]
    fn test_reject_virtio_fs_snapshot() {
        let err = VmConfig::builder(
            PathBuf::from("/vmlinux"),
            RootfsSource::VirtioFs {
                dir: PathBuf::from("/rootfs"),
            },
        )
        .snapshotting(true)
        .build()
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("virtio-fs rootfs cannot be combined with snapshotting")
        );
    }

    #[test]
    fn test_reject_out_of_range_vmid() {
        let err = VmConfig::builder(
            PathBuf::from("/vmlinux"),
            RootfsSource::Erofs {
                image: PathBuf::from("/rootfs.erofs"),
            },
        )
        .vmid(255)
        .build()
        .unwrap_err();
        assert!(err.to_string().contains("vmid must be <= 254"));
    }

    // Guards C1 / snapshot-eligibility law. Buggy impl: build() only rejects a
    // virtio-fs *rootfs* + snapshot and lets a data `Share` (served by
    // virtiofsd, a vhost-user device) through on the snapshot path.
    #[test]
    fn test_reject_shares_with_snapshot() {
        let err = VmConfig::builder(
            PathBuf::from("/vmlinux"),
            RootfsSource::Erofs {
                image: PathBuf::from("/rootfs.erofs"),
            },
        )
        .with_share(Share::new(
            "data",
            "/tmp/data",
            Access::ReadOnly,
            CachePolicy::Auto,
        ))
        .snapshotting(true)
        .build()
        .unwrap_err();
        assert!(matches!(err, crate::error::Error::Config(_)));
        assert!(
            err.to_string()
                .contains("virtio-fs data shares cannot be combined with snapshotting"),
            "unexpected error: {err}"
        );
    }

    // Buggy impl: build() accepts vmid == 0, which is out of range for the /30
    // host-IP math.
    #[test]
    fn test_reject_zero_vmid() {
        let err = VmConfig::builder(
            PathBuf::from("/vmlinux"),
            RootfsSource::Erofs {
                image: PathBuf::from("/rootfs.erofs"),
            },
        )
        .vmid(0)
        .build()
        .unwrap_err();
        assert!(matches!(err, crate::error::Error::Config(_)));
        assert!(err.to_string().contains("vmid must be >= 1"));
    }

    // Buggy impl: build() does not reject vcpus == 0.
    #[test]
    fn test_reject_zero_vcpus() {
        let err = VmConfig::builder(
            PathBuf::from("/vmlinux"),
            RootfsSource::Erofs {
                image: PathBuf::from("/rootfs.erofs"),
            },
        )
        .vcpus(0)
        .build()
        .unwrap_err();
        assert!(matches!(err, crate::error::Error::Config(_)));
        assert!(err.to_string().contains("vcpus must be > 0"));
    }

    // Buggy impl: build() does not enforce the memory floor.
    #[test]
    fn test_reject_mem_below_floor() {
        let err = VmConfig::builder(
            PathBuf::from("/vmlinux"),
            RootfsSource::Erofs {
                image: PathBuf::from("/rootfs.erofs"),
            },
        )
        .mem_mib(32)
        .build()
        .unwrap_err();
        assert!(matches!(err, crate::error::Error::Config(_)));
        assert!(err.to_string().contains("mem_mib must be >= 64"));
    }

    // Buggy impl: build() accepts an empty kernel path.
    #[test]
    fn test_reject_empty_kernel() {
        let err = VmConfig::builder(
            PathBuf::from(""),
            RootfsSource::Erofs {
                image: PathBuf::from("/rootfs.erofs"),
            },
        )
        .build()
        .unwrap_err();
        assert!(matches!(err, crate::error::Error::Config(_)));
        assert!(err.to_string().contains("kernel path cannot be empty"));
    }

    // Buggy impl: build() does not reject two shares with the same mount tag.
    #[test]
    fn test_reject_duplicate_share_tags() {
        let err = VmConfig::builder(
            PathBuf::from("/vmlinux"),
            RootfsSource::Erofs {
                image: PathBuf::from("/rootfs.erofs"),
            },
        )
        .with_share(Share::new(
            "dup",
            "/tmp/a",
            Access::ReadOnly,
            CachePolicy::Auto,
        ))
        .with_share(Share::new(
            "dup",
            "/tmp/b",
            Access::ReadOnly,
            CachePolicy::Auto,
        ))
        .build()
        .unwrap_err();
        assert!(matches!(err, crate::error::Error::Config(_)));
        assert!(err.to_string().contains("duplicate share tag: dup"));
    }

    // A tag is encoded on the kernel cmdline as `vmcell_share=<tag>:<ro|rw>`
    // (§5.2); `:` or whitespace in a tag would corrupt that token and silently
    // mis-mount or drop the share, so `build()` must reject it at the boundary.
    // Buggy impl this guards: accepting any non-empty tag, then discovering the
    // breakage as a missing mount in-guest.
    #[test]
    fn test_reject_share_tag_with_colon_or_whitespace() {
        for bad in ["a:b", "has space", "tab\tinside"] {
            let err = VmConfig::builder(
                PathBuf::from("/vmlinux"),
                RootfsSource::Erofs {
                    image: PathBuf::from("/rootfs.erofs"),
                },
            )
            .with_share(Share::new(
                bad,
                "/tmp/a",
                Access::ReadOnly,
                CachePolicy::Auto,
            ))
            .build()
            .unwrap_err();
            assert!(
                matches!(err, crate::error::Error::Config(_)),
                "tag {bad:?} should be rejected"
            );
            assert!(
                err.to_string().contains("':' or whitespace"),
                "tag {bad:?} error should explain the cmdline-encoding constraint: {err}"
            );
        }
    }

    // Conversely, an ordinary caller-defined tag (with '-' and '.') builds fine —
    // tags are caller-defined (§5.2), not restricted to the old `imp-*` set.
    #[test]
    fn test_accept_custom_share_tag() {
        let cfg = VmConfig::builder(
            PathBuf::from("/vmlinux"),
            RootfsSource::Erofs {
                image: PathBuf::from("/rootfs.erofs"),
            },
        )
        .with_share(Share::new(
            "my-data.in",
            "/tmp/a",
            Access::ReadWrite,
            CachePolicy::Never,
        ))
        .build()
        .expect("a custom tag with '-'/'.' must be accepted");
        assert_eq!(cfg.shares[0].tag, "my-data.in");
    }

    // The host→guest mount plan encodes each share as a cmdline token with its
    // access mode. Buggy impls this guards: dropping the access mode, emitting
    // nothing for rw shares, or appending tokens when there are no shares.
    #[test]
    fn test_push_share_args_encodes_access() {
        let shares = vec![
            Share::new("in", "/tmp/a", Access::ReadOnly, CachePolicy::Never),
            Share::new("out", "/tmp/b", Access::ReadWrite, CachePolicy::Never),
        ];
        let mut cmdline = String::from("console=ttyS0");
        push_share_args(&mut cmdline, &shares);
        assert_eq!(
            cmdline,
            "console=ttyS0 vmcell_share=in:/in:ro vmcell_share=out:/out:rw"
        );

        let mut empty = String::from("console=ttyS0");
        push_share_args(&mut empty, &[]);
        assert_eq!(empty, "console=ttyS0", "no shares ⇒ nothing appended");
    }

    // `guest_path` defaults to `/<tag>` and `with_guest_path` overrides it,
    // decoupling the mount point from the tag — the token carries the chosen path.
    // Buggy impl this guards: ignoring guest_path and always mounting at `/<tag>`.
    #[test]
    fn test_with_guest_path_overrides_mount_point() {
        let default = Share::new("data", "/tmp/a", Access::ReadOnly, CachePolicy::Never);
        assert_eq!(default.guest_path, PathBuf::from("/data"));

        let custom = Share::new("data", "/tmp/a", Access::ReadOnly, CachePolicy::Never)
            .with_guest_path("/srv/data");
        assert_eq!(custom.guest_path, PathBuf::from("/srv/data"));

        let mut cmdline = String::new();
        push_share_args(&mut cmdline, std::slice::from_ref(&custom));
        assert_eq!(cmdline, " vmcell_share=data:/srv/data:ro");
    }

    // A guest_path must be absolute (it is a mount point) and encodable on the
    // cmdline. Buggy impl: accepting a relative or `:`-bearing mount point, which
    // mis-mounts or corrupts the boot line.
    #[test]
    fn test_reject_bad_guest_path() {
        let cases: [(&str, &str); 2] = [
            ("relative/dir", "absolute path"),
            ("/has:colon", "':' or whitespace"),
        ];
        for (bad, needle) in cases {
            let err = VmConfig::builder(
                PathBuf::from("/vmlinux"),
                RootfsSource::Erofs {
                    image: PathBuf::from("/rootfs.erofs"),
                },
            )
            .with_share(
                Share::new("data", "/tmp/a", Access::ReadOnly, CachePolicy::Never)
                    .with_guest_path(bad),
            )
            .build()
            .unwrap_err();
            assert!(
                matches!(err, crate::error::Error::Config(_)) && err.to_string().contains(needle),
                "guest_path {bad:?} should be rejected mentioning {needle:?}: {err}"
            );
        }
    }

    // Two distinct tags mounting the same guest path collide; build() rejects it.
    #[test]
    fn test_reject_duplicate_guest_path() {
        let err = VmConfig::builder(
            PathBuf::from("/vmlinux"),
            RootfsSource::Erofs {
                image: PathBuf::from("/rootfs.erofs"),
            },
        )
        .with_share(
            Share::new("a", "/tmp/a", Access::ReadOnly, CachePolicy::Never)
                .with_guest_path("/mnt/shared"),
        )
        .with_share(
            Share::new("b", "/tmp/b", Access::ReadOnly, CachePolicy::Never)
                .with_guest_path("/mnt/shared"),
        )
        .build()
        .unwrap_err();
        assert!(matches!(err, crate::error::Error::Config(_)));
        assert!(
            err.to_string()
                .contains("duplicate share guest_path: /mnt/shared"),
            "{err}"
        );
    }

    // M-RESTORE-3: the §3.3 snapshot-eligibility law's third boundary case.
    // Buggy impl: build() rejects snapshot + virtio-fs rootfs and snapshot +
    // data share but lets the unprivileged vhost-user-net path through, so this VM
    // would reach the backend and fail late attaching a vhost-user device.
    #[test]
    fn test_reject_unprivileged_net_with_snapshot() {
        let err = VmConfig::builder(
            PathBuf::from("/vmlinux"),
            RootfsSource::Erofs {
                image: PathBuf::from("/rootfs.erofs"),
            },
        )
        .net(NetConfig::Unprivileged {
            egress: Egress::Open,
            host_services_port: None,
        })
        .snapshotting(true)
        .build()
        .unwrap_err();
        assert!(matches!(err, crate::error::Error::Config(_)));
        assert!(
            err.to_string().contains(
                "unprivileged (vhost-user-net) networking cannot be combined with snapshotting"
            ),
            "unexpected error: {err}"
        );
    }

    // M-RESTORE-3 positive guard: the privileged tap path is NOT a vhost-user
    // device, so snapshot + Privileged net must still build. An over-broad
    // impl that rejects every net mode on the snapshot path turns this red
    // (the over-block smell AGENTS.md warns about).
    #[test]
    fn test_accept_snapshot_with_privileged_net() {
        let cfg = VmConfig::builder(
            PathBuf::from("/vmlinux"),
            RootfsSource::Erofs {
                image: PathBuf::from("/rootfs.erofs"),
            },
        )
        .net(NetConfig::Privileged {
            egress: Egress::Open,
            host_services_port: None,
        })
        .snapshotting(true)
        .build()
        .unwrap();
        assert!(cfg.snapshotting);
        assert!(matches!(cfg.net, NetConfig::Privileged { .. }));
    }

    // M-CONFIG-1: ksm_mergeable (CH shared=off) is mutually exclusive with a
    // virtio-fs rootfs (virtiofsd, a vhost-user device). Buggy impl: build()
    // accepts the combination and it fails late at the VMM.
    #[test]
    fn test_reject_ksm_mergeable_with_virtio_fs_rootfs() {
        let err = VmConfig::builder(
            PathBuf::from("/vmlinux"),
            RootfsSource::VirtioFs {
                dir: PathBuf::from("/rootfs"),
            },
        )
        .ksm_mergeable(true)
        .build()
        .unwrap_err();
        assert!(matches!(err, crate::error::Error::Config(_)));
        assert!(
            err.to_string()
                .contains("ksm_mergeable cannot be combined with a virtio-fs rootfs"),
            "unexpected error: {err}"
        );
    }

    // M-CONFIG-1: ksm_mergeable is mutually exclusive with a virtio-fs data
    // share (virtiofsd, a vhost-user device).
    #[test]
    fn test_reject_ksm_mergeable_with_data_share() {
        let err = VmConfig::builder(
            PathBuf::from("/vmlinux"),
            RootfsSource::Erofs {
                image: PathBuf::from("/rootfs.erofs"),
            },
        )
        .with_share(Share::new(
            "data",
            "/tmp/data",
            Access::ReadOnly,
            CachePolicy::Auto,
        ))
        .ksm_mergeable(true)
        .build()
        .unwrap_err();
        assert!(matches!(err, crate::error::Error::Config(_)));
        assert!(
            err.to_string()
                .contains("ksm_mergeable cannot be combined with virtio-fs data shares"),
            "unexpected error: {err}"
        );
    }

    // M-CONFIG-1: ksm_mergeable is mutually exclusive with unprivileged
    // vhost-user-net networking.
    #[test]
    fn test_reject_ksm_mergeable_with_unprivileged_net() {
        let err = VmConfig::builder(
            PathBuf::from("/vmlinux"),
            RootfsSource::Erofs {
                image: PathBuf::from("/rootfs.erofs"),
            },
        )
        .net(NetConfig::Unprivileged {
            egress: Egress::Open,
            host_services_port: None,
        })
        .ksm_mergeable(true)
        .build()
        .unwrap_err();
        assert!(matches!(err, crate::error::Error::Config(_)));
        assert!(
            err.to_string()
                .contains("ksm_mergeable cannot be combined with unprivileged"),
            "unexpected error: {err}"
        );
    }

    // M-CONFIG-1 positive guard: ksm_mergeable with NO vhost-user device (erofs
    // rootfs over virtio-blk, privileged tap net, no shares) is the supported
    // density combination and must still build. An impl that rejects every
    // ksm_mergeable config turns this red (over-block smell).
    #[test]
    fn test_accept_ksm_mergeable_without_vhost_user() {
        let cfg = VmConfig::builder(
            PathBuf::from("/vmlinux"),
            RootfsSource::Erofs {
                image: PathBuf::from("/rootfs.erofs"),
            },
        )
        .net(NetConfig::Privileged {
            egress: Egress::Open,
            host_services_port: None,
        })
        .ksm_mergeable(true)
        .build()
        .unwrap();
        assert!(cfg.ksm_mergeable);
    }

    // §8.3 UART tax lever: each verbosity maps to its `loglevel=` number. Buggy
    // impl this guards: an off-by-one or a swapped arm (e.g. Balanced→7, or
    // Verbose→6) — any wrong mapping turns one of these equalities red.
    #[test]
    fn kernel_verbosity_loglevel_mapping() {
        assert_eq!(KernelVerbosity::Quiet.loglevel(), 3);
        assert_eq!(KernelVerbosity::Balanced.loglevel(), 6);
        assert_eq!(KernelVerbosity::Verbose.loglevel(), 7);
        assert_eq!(KernelVerbosity::Debug.loglevel(), 8);
    }

    // §10 timing presets: `low_latency` tightens the connect/accept cadence but
    // leaves teardown graceful, and `throughput` cuts the graceful-shutdown grace.
    // Buggy impls this guards: a preset that forgets to lower a knob (equal to
    // default), or `low_latency` that also cuts `shutdown_grace` (the excluded
    // knob) — either flips one comparison.
    #[test]
    fn timeouts_presets_ordering() {
        let d = Timeouts::default();
        let ll = Timeouts::low_latency();
        let tp = Timeouts::throughput();
        assert!(ll.guest_accept_poll < d.guest_accept_poll);
        assert!(ll.connect_backoff_floor < d.connect_backoff_floor);
        assert!(tp.shutdown_grace < d.shutdown_grace);
        // low_latency deliberately excludes teardown: its grace stays == default.
        assert_eq!(ll.shutdown_grace, d.shutdown_grace);
    }

    // The builder's `.timeouts()` clamps every knob to its correctness floor so a
    // hand-built (or preset) `Timeouts` can never busy-spin PID 1. Buggy impl:
    // `.timeouts()` stores the value verbatim without `.clamped()`, so a 0 ms
    // poll survives — the assertions below then fail.
    #[test]
    fn timeouts_clamp_floors() {
        use std::time::Duration;
        let raw = Timeouts {
            connect_backoff_floor: Duration::from_millis(0),
            connect_backoff_cap: Duration::from_millis(100),
            connect_ok_read: Duration::from_millis(150),
            api_socket_poll: Duration::from_millis(5),
            shutdown_grace: Duration::from_millis(250),
            guest_accept_poll: Duration::from_millis(0),
            guest_rebind_idle: Duration::from_millis(250),
        };
        let cfg = VmConfig::builder(
            PathBuf::from("/vmlinux"),
            RootfsSource::Erofs {
                image: PathBuf::from("/rootfs.erofs"),
            },
        )
        .timeouts(raw)
        .build()
        .unwrap();
        assert!(cfg.timeouts.guest_accept_poll >= Duration::from_millis(1));
        assert!(cfg.timeouts.connect_backoff_floor >= Duration::from_millis(1));
    }

    // The shared cmdline builder is the single source of truth for `loglevel=` and
    // the guest timing tokens across all three backends — closing the prior
    // triplication where QEMU silently omitted `loglevel=`. Buggy impls this
    // guards: a builder that drops `loglevel=`, forgets the guest timing tokens,
    // ignores `backend_extra`, or mis-places the FPU guard relative to `init=`.
    #[test]
    fn build_kernel_cmdline_all_backends_have_loglevel() {
        let cfg = VmConfig::builder(
            PathBuf::from("/vmlinux"),
            RootfsSource::Erofs {
                image: PathBuf::from("/rootfs.erofs"),
            },
        )
        .network_disabled()
        .build()
        .unwrap();

        let plain = build_kernel_cmdline(&cfg, 1, "").unwrap();
        let fpu = build_kernel_cmdline(&cfg, 1, "noxsave ").unwrap();
        for c in [&plain, &fpu] {
            // The default (Uart) console token is `ttyS0`, emitted as the FIRST
            // cmdline token. A hardcoded `console=hvc0` (or a dropped token) reddens.
            assert!(
                c.contains("console=ttyS0"),
                "default console token missing: {c}"
            );
            assert!(
                c.starts_with("console=ttyS0"),
                "console must be the first token: {c}"
            );
            assert!(!c.contains("console=hvc0"), "Uart must not emit hvc0: {c}");
            assert!(c.contains("loglevel=6"), "missing loglevel: {c}");
            // Boot-probe trims (EXP-B, docs/45): the crypto self-test skip and the md
            // RAID autodetect skip are universal (all backends). A builder that drops
            // them silently re-pays the ~12 ms of dead boot work.
            assert!(
                c.contains("cryptomgr.notests"),
                "missing crypto self-test skip: {c}"
            );
            assert!(
                c.contains("raid=noautodetect"),
                "missing RAID autodetect skip: {c}"
            );
            assert!(
                c.contains("vmcell_accept_poll_ms=20"),
                "missing accept poll: {c}"
            );
            assert!(
                c.contains("vmcell_rebind_idle_ms=250"),
                "missing rebind idle: {c}"
            );
            assert!(
                c.contains("init=/usr/sbin/vmcell-guest-agent"),
                "missing init: {c}"
            );
        }
        // The FPU guard is inserted immediately before `init=`; the empty
        // backend_extra leaves `panic=1 init=` adjacent.
        assert!(
            fpu.contains("panic=1 noxsave init="),
            "fpu guard misplaced: {fpu}"
        );
        assert!(
            plain.contains("panic=1 init="),
            "unexpected extra token: {plain}"
        );

        let verbose = VmConfig::builder(
            PathBuf::from("/vmlinux"),
            RootfsSource::Erofs {
                image: PathBuf::from("/rootfs.erofs"),
            },
        )
        .kernel_verbosity(KernelVerbosity::Verbose)
        .network_disabled()
        .build()
        .unwrap();
        let vc = build_kernel_cmdline(&verbose, 1, "").unwrap();
        assert!(
            vc.contains("loglevel=7"),
            "verbose loglevel not honored: {vc}"
        );

        // A VirtioConsole VM must emit `console=hvc0` as the first token and NOT
        // `console=ttyS0`. A hardcoded `console=ttyS0` (the pre-knob wiring) reddens.
        let virtio = VmConfig::builder(
            PathBuf::from("/vmlinux"),
            RootfsSource::Erofs {
                image: PathBuf::from("/rootfs.erofs"),
            },
        )
        .console_mode(ConsoleMode::VirtioConsole)
        .network_disabled()
        .build()
        .unwrap();
        let hvc = build_kernel_cmdline(&virtio, 1, "").unwrap();
        assert!(
            hvc.starts_with("console=hvc0"),
            "VirtioConsole must emit console=hvc0 first: {hvc}"
        );
        assert!(
            !hvc.contains("console=ttyS0"),
            "VirtioConsole must not emit ttyS0: {hvc}"
        );
    }

    // §12.10 console knob: each mode maps to its `console=` token. Buggy impl this
    // guards: a swapped arm (Uart→hvc0 or VirtioConsole→ttyS0) reddens an equality.
    #[test]
    fn console_mode_mapping() {
        assert_eq!(ConsoleMode::Uart.console(), "ttyS0");
        assert_eq!(ConsoleMode::VirtioConsole.console(), "hvc0");
    }

    // The builder must carry the selected `ConsoleMode` onto the built config and
    // default to `Uart` (the safe early-boot + panic-capture console). Buggy impl:
    // the builder drops the field (always `Uart`) — the `VirtioConsole` assertion
    // then fails.
    #[test]
    fn console_mode_builder_carry_through() {
        let default_cfg = VmConfig::builder(
            PathBuf::from("/vmlinux"),
            RootfsSource::Erofs {
                image: PathBuf::from("/rootfs.erofs"),
            },
        )
        .build()
        .unwrap();
        assert_eq!(default_cfg.console_mode, ConsoleMode::Uart);

        let virtio_cfg = VmConfig::builder(
            PathBuf::from("/vmlinux"),
            RootfsSource::Erofs {
                image: PathBuf::from("/rootfs.erofs"),
            },
        )
        .console_mode(ConsoleMode::VirtioConsole)
        .build()
        .unwrap();
        assert_eq!(virtio_cfg.console_mode, ConsoleMode::VirtioConsole);
        assert_ne!(virtio_cfg.console_mode, ConsoleMode::Uart);
    }
}
