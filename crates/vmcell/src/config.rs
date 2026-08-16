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
    /// Selects the QEMU steward vsock transport (§2.4). Default
    /// [`VsockTransport::Auto`] — in-kernel when `snapshotting`, else the unprivileged
    /// external daemon. Set [`VsockTransport::InKernel`] to give a privileged
    /// non-snapshot QEMU the deterministic in-kernel transport (shedding the
    /// external-daemon bring-up flake). No effect on Cloud Hypervisor / Firecracker,
    /// which always terminate vsock inside the VMM.
    pub vsock_transport: VsockTransport,
    /// Optional explicitly-configured VMID.
    pub vmid: Option<u32>,
    /// Memory-restore strategy applied on the snapshot-restore path.
    pub restore_mode: RestoreMode,
    /// Mark guest memory `MADV_MERGEABLE` so host KSM can deduplicate identical
    /// guest pages (CH `mergeable=on`). KSM only merges private-anonymous pages,
    /// so enabling this also disables memory sharing (`shared=off`), making it
    /// incompatible with vhost-user paths (unprivileged net, virtio-fs). A
    /// density-vs-CPU trade measured in §8.3 (Density levers).
    pub ksm_mergeable: bool,
    /// Guest kernel console log verbosity (`loglevel=`). Default
    /// [`KernelVerbosity::Balanced`] is the §16 (Performance) perf-optimal; raise it only for
    /// debugging / a test that asserts on a specific kernel log line.
    pub kernel_verbosity: KernelVerbosity,
    /// Per-VM hot-path timing knobs (connect cadence, teardown grace, guest
    /// accept/re-bind polls). Default [`Timeouts::default`] is the shipped
    /// balanced profile; [`Timeouts::low_latency`] / [`Timeouts::throughput`]
    /// are ready-made presets (§9.4, Timeouts and the lifecycle nuances).
    pub timeouts: Timeouts,
    /// Guest console device driving `serial.log`. Default [`ConsoleMode::Uart`]
    /// (8250 `ttyS0`) is alive from the first instruction, so it captures early
    /// boot and a pre-virtio panic; [`ConsoleMode::VirtioConsole`] (`hvc0`) batches
    /// output via a virtqueue (no per-byte VM-exit) but only exists after the
    /// virtio-pci probe. The cmdline `console=` token and the per-backend device
    /// wiring are both derived from this field so they can never desync.
    pub console_mode: ConsoleMode,
    /// The prefix for this VM's swept host-resource names (netns/tap/cgroup/scratch), composed via
    /// [`crate::naming`]. Defaults to [`crate::naming::DEFAULT_RESOURCE_PREFIX`] (`"vmcell"`). The
    /// orphan sweep must be run with the SAME prefix (§13, Cross-cutting invariants) or it will not match this VM's leaks.
    pub resource_prefix: String,
    /// Extra virtio-blk devices attached **after** the root disk, enumerated by the
    /// guest as `/dev/vdb`, `/dev/vdc`, … in order (§4.6, Extra virtio-blk devices and disk-I/O throttling). Raw block devices — the
    /// guest workload owns any filesystem/mount; the steward does not auto-mount them.
    /// Plain virtio-blk composes with snapshotting (§13, Cross-cutting invariants); an extra disk's
    /// [`image`](BlockDevice::image) must live at a **stable path** to survive a
    /// restore. Default empty.
    pub extra_disks: Vec<BlockDevice>,
    /// Host USB devices passed through to the guest ([`UsbHostDevice`], §2.4, QEMU q35 — the fallback and most-proven nester).
    /// **QEMU only**: it is the one backend whose upstream binary attaches a host USB
    /// device, so it alone reports
    /// [`usb_host_passthrough`](crate::vmm::VmmCapabilities::usb_host_passthrough); every
    /// other backend's `create()` refuses a non-empty list with a typed
    /// [`Error::Unsupported`](crate::error::Error::Unsupported) rather than silently
    /// dropping it. A passed-through device is **not** migratable, so
    /// [`VmConfigBuilder::build`] rejects this combined with `snapshotting`. Default empty.
    pub usb_host_devices: Vec<UsbHostDevice>,
    /// Append-only extra kernel command-line arguments, appended **after** every
    /// token vmcell owns (§5.3, The kernel command line). An extra arg can add a boot parameter but can never
    /// override one vmcell controls; [`VmConfigBuilder::build`] rejects any arg whose
    /// key is reserved or starts with `vmcell_`, or that is not a single whitespace-
    /// free token. Default empty.
    pub extra_kernel_args: Vec<String>,
    /// Optional `init=` override (§5.3, The kernel command line). `None` boots the vmcell steward as
    /// PID 1 (the vsock control plane). `Some(path)` boots a **custom PID 1**, which
    /// **replaces the steward** — so the VM has no control plane
    /// ([`crate::orchestrator::MicroVm::steward`] fails loud) and cannot snapshot
    /// ([`VmConfigBuilder::build`] rejects
    /// `snapshotting` + a custom init, since the post-restore resync needs the steward).
    /// Observe such a VM via the serial log, a writable extra disk/share, or
    /// networking. A custom init also loses the steward's tmpfs overlay over the RO
    /// erofs root, so it usually pairs with a writable rootfs or extra disk. Default
    /// `None`.
    pub init: Option<PathBuf>,
    /// The VMM subprocess's own seccomp-BPF confinement (design §12.2, Layer 1 — the VMM's own seccomp filter). Default
    /// [`VmmSeccomp::Enforcing`] runs each backend under its audited native filter
    /// (`cloud-hypervisor --seccomp true`, Firecracker's built-in filter, `qemu
    /// -sandbox on,…`). The one predicate [`crate::vmm::seccomp::vmm_seccomp_args`]
    /// maps this to the per-backend flag and returns [`crate::error::Error::Unsupported`]
    /// for a policy a backend cannot honor (e.g. [`VmmSeccomp::Log`] on Firecracker/QEMU),
    /// never a silent downgrade. [`VmmSeccomp::Disabled`] is a deliberate, logged opt-out.
    pub vmm_seccomp: VmmSeccomp,
    /// Jailer-equivalent pre-exec hardening applied to the VMM child (design §12.3, Layer 2 — the jailer-equivalent (JailSpec + apply_jail)):
    /// `no_new_privs`, ambient-capability clear, non-dumpable, and rlimits, plus an
    /// optional coarse seccomp deny-list. Default [`JailConfig::default`] is the
    /// hardened profile ([`JailConfig::hardened`]). The pure config here is compiled to
    /// a runtime `JailSpec` and applied by [`crate::vmm::jail::apply_jail`] in the
    /// forked-child pre-exec window, shared by the in-process spawn and the setup
    /// broker (one law, §12.3, Layer 2 — the jailer-equivalent (JailSpec + apply_jail)).
    pub jail: JailConfig,
    /// Where this cell's steward runs (design §3.5, invariant C8).
    ///
    /// **Resolved** at [`VmConfigBuilder::build`]: when the caller names no placement it is
    /// *derived* — [`StewardPlacement::Pid1`] when `init` is `None`, [`StewardPlacement::None`]
    /// when `init` is `Some` — so every pre-v33 caller keeps its exact semantics. Read through the
    /// two C8 methods and never re-derived from [`Self::init`], which decides init *identity* only.
    pub steward_placement: StewardPlacement,
    /// Features this cell **demands**, resolved at `MicroVm::start` against the computed
    /// [`crate::feature::FeatureSet`] (design §7.4 clause 3, invariant F6).
    ///
    /// Deliberately resolved at `start` and not at [`VmConfigBuilder::build`]: `build()` never sees
    /// a backend (its validation is config-internal), and the intersection needs the backend and
    /// the artifacts, which exist at `start`. The payoff is that "this cell cannot snapshot" is
    /// answered **before anything boots**, with the removal's provenance in the error, instead of
    /// at the first `snapshot()` call.
    pub required_features: Vec<crate::feature::Feature>,
}

/// Where this cell's steward runs — **declared, never inferred** (design §3.5, invariant C8).
///
/// # The reframe this type exists for
///
/// Control-plane availability and init identity are **two facts**, and until v33 the tree stored
/// them as one predicate. `control_plane_disabled` was set from `cfg.init.is_some()`, and seven of
/// the eight places keying on `cfg.init` were asking "can I reach a steward?" and answering it with
/// "did the caller set `init=`?". Only the cmdline `init=` token is genuinely about init identity.
///
/// The price of the conflation was concrete: booting systemd — or any init system, or a container
/// runtime, or a distro image as shipped — cost the **entire** control plane (`steward()` fails
/// loud, no `exec`, no sessions, no snapshot), when nothing about a different PID 1 makes the
/// steward unreachable. The tree already contained the counter-example, deliberately:
/// `MicroVm::dial_vsock` never copied the guard, because the vsock *device* is attached
/// unconditionally on every backend. v33 applies that one decision to the other seven sites.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum StewardPlacement {
    /// The kernel starts the steward as PID 1 (`init=/usr/sbin/vmcell-steward`).
    ///
    /// The default, and byte-identical in cmdline and code path to every release before v33 — the
    /// pay-for-what-you-use floor: a cell that never names a placement cannot tell v33 landed.
    Pid1,
    /// The guest's own init starts the steward; the host dials `port`.
    ///
    /// [`VmConfig::init`] names the init — the two facts are stated separately now. This is what
    /// makes systemd, init-system testing, and distro-as-shipped images expressible at all.
    Service {
        /// The vsock port the guest's steward listens on. Defaults to
        /// [`vmcell_protocol::STEWARD_VSOCK_PORT`]; a different value travels to the guest as the
        /// `vmcell_steward_port=` cmdline token.
        port: u32,
    },
    /// No steward anywhere: today's `init=`-with-no-control-plane, **said out loud**.
    None,
}

impl StewardPlacement {
    /// **Control-plane availability** — law C8's first question: is a steward expected, and where?
    ///
    /// `Some(port)` = a steward is expected at that vsock port; `None` = no control plane. Read by
    /// `MicroVm::steward`, `MicroVm::connect_sessions`, and the control-plane health gate. None of
    /// them re-derives the fact from `cfg.init`.
    #[must_use]
    pub const fn steward_port(self) -> Option<u32> {
        match self {
            StewardPlacement::Pid1 => Some(vmcell_protocol::STEWARD_VSOCK_PORT),
            StewardPlacement::Service { port } => Some(port),
            StewardPlacement::None => Option::None,
        }
    }

    /// **Post-restore-resync reachability** — law C8's second question: may this cell snapshot?
    ///
    /// Deliberately **not** the same predicate as [`Self::steward_port`]: `Service { port: 5000 }`
    /// and `Pid1` are indistinguishable through the port, and the eligibility question is about the
    /// *placement*, not the port. That near-miss is why C8 is a two-method law.
    ///
    /// `true` only for [`Self::Pid1`] in v33. For [`Self::None`] the mandatory post-restore resync
    /// (§8.2) is structurally unreachable; for [`Self::Service`] the post-restore question — does
    /// the guest's init restart the steward after the vhost-vsock device is re-created, or does the
    /// idle re-bind cover it? — is real and **unmeasured**, so it stays rejected until measured
    /// (§17). Strictly narrower than the pre-v33 rejection, worse for nobody.
    ///
    /// Read by `MicroVm::snapshot`'s guard and the §8.1 eligibility predicate's placement arm.
    #[must_use]
    pub const fn resync_reachable(self) -> bool {
        matches!(self, StewardPlacement::Pid1)
    }
}

/// The VMM subprocess's own seccomp-BPF confinement policy (design §12.2, Layer 1 — the VMM's own seccomp filter).
///
/// [`crate::vmm::seccomp::vmm_seccomp_args`] is the single predicate that turns this
/// into a backend's native CLI flag; a policy a backend cannot honor is a typed
/// [`crate::error::Error::Unsupported`], not a silent fallback (§7.2, The fail-loud capability contract and HostCapabilities; capability honesty).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum VmmSeccomp {
    /// Enforce the backend's audited seccomp filter, killing on a disallowed syscall.
    /// The default — vmcell never leaves a backend unconfined by default (§12.2, Layer 1 — the VMM's own seccomp filter).
    #[default]
    Enforcing,
    /// Observe-only: log disallowed syscalls instead of killing (debugging a filter
    /// false-positive). Only Cloud Hypervisor supports it (`--seccomp log`); on
    /// Firecracker/QEMU it is [`crate::error::Error::Unsupported`].
    Log,
    /// No VMM seccomp. A deliberate, logged opt-out — never a silent default. The one
    /// legitimate reason is a QEMU workload whose feature needs `spawn` (which
    /// `-sandbox …,spawn=deny` blocks).
    Disabled,
}

/// Jailer-equivalent pre-exec hardening applied to the VMM child (design §12.3, Layer 2 — the jailer-equivalent (JailSpec + apply_jail)).
///
/// Pure, serializable configuration (no compiled BPF): [`crate::vmm::jail::apply_jail`]
/// compiles the optional deny-list once, pre-fork, and applies the rest in the
/// async-signal-safe child window. Mirrors the hardening Firecracker's `jailer` applies
/// to the VMM (minus the chroot/uid-drop increment, forward work §17, Open gaps and future capabilities).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct JailConfig {
    /// `prctl(PR_SET_NO_NEW_PRIVS, 1)` — the child (and anything it execs) can never
    /// gain privileges via a setuid/file-cap binary. Required before a seccomp filter.
    pub no_new_privs: bool,
    /// `prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL)` — clear the ambient capability set.
    /// **Default `false`, opt-in** (§17, Open gaps and future capabilities): in vmcell's current architecture the VMM *inherits*
    /// `CAP_NET_ADMIN` (via the ambient set on the `vmcell-test-runner` path) and **needs** it —
    /// a restored Cloud Hypervisor's `TapSetMac` and Firecracker's tap re-open both `EPERM`
    /// without it (validated on a KVM host). Clearing the VMM's caps is safe only once the tap is
    /// handed over fully configured (the fd-passing / uid-drop jailer increment), so this stays an
    /// opt-in for that future path rather than a default.
    pub clear_ambient_caps: bool,
    /// `prctl(PR_SET_DUMPABLE, 0)` — mark the VMM non-dumpable (blocks a same-uid
    /// `ptrace` of the process holding guest memory, and reinforces `rlimit_core`).
    pub non_dumpable: bool,
    /// `RLIMIT_CORE` — default `Some(0)`: a VMM core dump writes guest memory
    /// (potentially secrets) to disk, exactly the §12.3 (Layer 2 — the jailer-equivalent (JailSpec + apply_jail)) surface, so no core is allowed.
    pub rlimit_core: Option<u64>,
    /// `RLIMIT_FSIZE` — default `None` (unset): a snapshot-eligible VM writes a
    /// guest-RAM-sized suspend file, so a naïve `fsize=0` would break snapshot.
    pub rlimit_fsize: Option<u64>,
    /// `RLIMIT_NOFILE` — default `None`; set for a tighter open-fd ceiling on the VMM.
    pub rlimit_nofile: Option<u64>,
    /// Apply a coarse, default-allow seccomp **deny-list** (design §12.3, Layer 2 — the jailer-equivalent (JailSpec + apply_jail)) of syscalls a
    /// booting VMM never needs and an escape would want (`mount`, `ptrace`, `bpf`,
    /// `kexec_load`, module ops, `setns`, …) → `EPERM`. Ships **opt-in, default
    /// `false`**: the backend's own native filter ([`VmmSeccomp`]) is the shipped
    /// default confinement, and a host-applied filter on a live VMM is not yet
    /// KVM-host-validated (§17, Open gaps and future capabilities). The filter-application mechanism itself is gated
    /// KVM-free against a stand-in child.
    pub seccomp_deny_list: bool,
}

impl JailConfig {
    /// The hardened default: `no_new_privs` + `non_dumpable` + `RLIMIT_CORE=0`, no fsize/nofile
    /// cap, no host seccomp deny-list (the backend's native filter is the shipped default, §12.3, Layer 2 — the jailer-equivalent (JailSpec + apply_jail)).
    ///
    /// **`clear_ambient_caps` defaults to `false`** (empirically forced, §17, Open gaps and future capabilities): in vmcell's
    /// current architecture the VMM inherits `CAP_NET_ADMIN` (via the ambient set on the runner
    /// path) and **needs** it for privileged tap operations — a restored Cloud Hypervisor's
    /// `TapSetMac` and Firecracker's tap re-open both `EPERM` without it (validated on a KVM host:
    /// clearing ambient broke `*_survives_snapshot` restore-with-tap). Clearing the VMM's caps is
    /// safe only once the tap is handed over fully configured (the fd-passing / uid-drop jailer
    /// increment, §17, Open gaps and future capabilities); until then the field stays an opt-in for that future path.
    #[must_use]
    pub const fn hardened() -> Self {
        Self {
            no_new_privs: true,
            clear_ambient_caps: false,
            non_dumpable: true,
            rlimit_core: Some(0),
            rlimit_fsize: None,
            rlimit_nofile: None,
            seccomp_deny_list: false,
        }
    }

    /// A no-op jail (every hardening off) — for tests that spawn a stand-in needing the
    /// unrestricted inherited environment, and the buggy inverse the hardening gate checks.
    #[must_use]
    pub const fn disabled() -> Self {
        Self {
            no_new_privs: false,
            clear_ambient_caps: false,
            non_dumpable: false,
            rlimit_core: None,
            rlimit_fsize: None,
            rlimit_nofile: None,
            seccomp_deny_list: false,
        }
    }
}

impl Default for JailConfig {
    fn default() -> Self {
        Self::hardened()
    }
}

/// Per-VM hot-path timing knobs, gathered so a workload can pick a profile in one
/// place. Only the timings that (a) sit on the per-test hot path and (b) a
/// workload legitimately trades are here; internal readiness/QMP/join timeouts
/// stay as constants (they are correctness-floor mechanics, not workload knobs).
///
/// Two presets are provided: [`Timeouts::low_latency`] minimizes time-to-output
/// (tightens every connect/accept cadence, leaves teardown graceful) and
/// [`Timeouts::throughput`] minimizes whole-lifecycle wall-clock (cuts the
/// graceful-shutdown grace). The builder and preset constructors clamp to
/// correctness floors; because the fields are `pub`, a caller can mutate a
/// `VmConfig.timeouts` after `build()`, so the orchestrator **re-clamps** at
/// `MicroVm::start()` time (M-ORCH-3) — a preset or a hand-built `Timeouts` can
/// therefore never produce a busy-spin or a sub-viable window.
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
    /// The shipped balanced profile (the §16, Performance — post-optimization-pass values).
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
    ///
    /// `pub(crate)` so the orchestrator can re-clamp at `start()` time, guarding
    /// against post-`build()` mutation of the `pub` fields (M-ORCH-3).
    #[must_use]
    pub(crate) fn clamped(mut self) -> Self {
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

/// Appends the guest-side timing tokens to a kernel `cmdline` (§5.3, The kernel command line). The guest
/// steward parses `vmcell_accept_poll_ms=` / `vmcell_rebind_idle_ms=` (whole ms,
/// clamped guest-side) to tune its accept/re-bind cadence per VM without a rootfs
/// rebuild; absent tokens fall back to the steward's compiled defaults.
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
/// cmdline silently omitted `loglevel=` (paying the full 8250 UART tax, §5.3, The kernel command line).
/// `backend_extra` carries the one genuine per-backend fragment (Firecracker's
/// `noxsave ` FPU guard), inserted before `init=` exactly where it was.
///
/// It takes the whole [`PerVmResources`](crate::vmm::PerVmResources) rather than a bare `vmid`
/// (v30 §18 delta 8, a recorded signature shift): the `ip=` token now depends on `res.segment` —
/// a segment member gets `10.201.<s>.<k+1>` with gateway `.1` and mask `/24` instead of the per-VM
/// `/30` — and `PerVmResources` is the exhaustive struct that makes that dependency a compile
/// error for any backend that ignores it.
///
/// # Errors
/// Propagates the `/30` host-IP math error (or the segment `/24` math error) when networking is
/// enabled.
pub fn build_kernel_cmdline(
    cfg: &VmConfig,
    res: &crate::vmm::PerVmResources,
    backend_extra: &str,
) -> Result<String, crate::error::Error> {
    let vmid = res.vmid;
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
    // The `init=` token: the fixed vmcell steward (the default control-plane
    // PID 1) unless the caller overrides it (§5.3, The kernel command line). This is the ONE place either
    // `init=` token is constructed — a backend never string-builds it. A custom
    // init replaces the steward, so it forgoes the vsock control plane; the
    // consequence is honored fail-loud in the orchestrator, not here (see
    // `MicroVm::steward`). `build()` validated the override is a single safe token.
    let init = cfg.init.as_deref().map_or_else(
        || DEFAULT_INIT.to_string(),
        |p| p.to_string_lossy().into_owned(),
    );
    // §3.5: a non-default `Service` port travels to the guest on the trusted channel. It is a
    // `vmcell_`-prefixed token, so F3's prefix rule already reserves it against caller spoofing —
    // no edit to `RESERVED_CMDLINE_KEYS` is needed or wanted. NOTHING is emitted for the default
    // port, so a `Pid1` cell's cmdline is byte-identical to v32's (pinned by
    // `default_placement_emits_a_byte_identical_cmdline`).
    let steward_port_token = match cfg.steward_placement.steward_port() {
        Some(port) if port != vmcell_protocol::STEWARD_VSOCK_PORT => {
            format!(" vmcell_steward_port={port}")
        }
        _ => String::new(),
    };
    let mut s = format!(
        "console={} loglevel={} random.trust_cpu=on random.trust_bootloader=on \
         cryptomgr.notests raid=noautodetect \
         root=/dev/vda rootfstype={} ro {} panic=1 {}init={} vmcell_vmid={}{steward_port_token}",
        cfg.console_mode.console(),
        cfg.kernel_verbosity.loglevel(),
        rootfstype,
        rootflags,
        backend_extra,
        init,
        vmid,
    );
    // The guest configures `eth0` from this token and nothing else — zero netlink in PID 1
    // (law C6), on the per-VM /30 and on a segment alike. A segment member's address is read from
    // `res.segment`, the exhaustive-struct channel; the /24 mask and the `.1` gateway are the
    // segment's, not the /30's.
    if let Some(membership) = &res.segment {
        let (gateway, guest_ip, _) = membership.addresses()?;
        s.push_str(&format!(
            " ip={guest_ip}::{gateway}:255.255.255.0::eth0:off"
        ));
    } else if !matches!(cfg.net, NetConfig::None) {
        let (host_ip, guest_ip, _) = crate::net::ip_math(vmid)?;
        s.push_str(&format!(
            " ip={guest_ip}::{host_ip}:255.255.255.252::eth0:off"
        ));
    }
    // `nested_virt` controls the guest KVM's *nested* (L2) capability via the
    // `kvm-{intel,amd}.nested` module param. Emit it EXPLICITLY in both directions:
    // `-cpu host` exposes VMX unconditionally (so L1 `/dev/kvm` always exists), and
    // modern guest kernels default `nested=Y`, so omitting the token on `false`
    // would leave nested virt on — making the flag a silent no-op (L-TEST-6). The
    // explicit `=0` makes it a genuine, observable lever.
    if cfg.nested_virt {
        s.push_str(" kvm-intel.nested=1 kvm-amd.nested=1");
    } else {
        s.push_str(" kvm-intel.nested=0 kvm-amd.nested=0");
    }
    push_share_args(&mut s, &cfg.shares);
    push_guest_timeout_args(&mut s, &cfg.timeouts);
    // Append-only caller args go LAST — after every token vmcell owns — so they can
    // add a boot parameter but never clobber one (§5.3, The kernel command line). `build()` already rejected
    // any arg whose key is reserved or `vmcell_`-prefixed, so this is a safe splice.
    push_extra_kernel_args(&mut s, &cfg.extra_kernel_args);
    Ok(s)
}

/// The default `init=` target: the vmcell steward that serves the vsock control
/// plane as PID 1 (§3.4, The guest: vmcell-steward as PID 1). A caller may override it via [`VmConfig::init`], which
/// replaces the steward and therefore forgoes the control plane (§5.3, The kernel command line).
pub(crate) const DEFAULT_INIT: &str = "/usr/sbin/vmcell-steward";

/// The kernel-cmdline keys that [`build_kernel_cmdline`] owns and that
/// [`VmConfig::extra_kernel_args`] may therefore **not** set (append-only, §5.3, The kernel command line).
///
/// Kept in lockstep with the tokens the builder emits by the
/// `extra_kernel_args_cannot_clobber_reserved_tokens` coverage test: every token the
/// builder produces has a reserved key here (or the `vmcell_` prefix), so a caller
/// arg can never silently override a load-bearing boot parameter.
///
/// The coverage test structurally **cannot** discover the alias block below: it walks the
/// emitted tokens and asserts each key is reserved, and an alias shares no key with the token
/// it overrides (`rw` inverts `ro`; `quiet`/`debug`/`ignore_loglevel` override `loglevel=`).
/// Aliases are therefore listed by hand and guarded by their own negative test
/// (`reserved_cmdline_keys_cover_owned_token_aliases`) — adding a boot token whose kernel
/// semantics have an alias means adding the alias here too (finding `f3-alias-clobber-gap`).
///
/// Spelling here is free: [`is_reserved_cmdline_arg`] normalizes `-` to `_` on **both**
/// sides before comparing, exactly as the kernel's own parser does, so an entry written
/// `kvm-intel.nested` also reserves `kvm_intel.nested` and vice versa.
const RESERVED_CMDLINE_KEYS: &[&str] = &[
    "console",
    "loglevel",
    "random.trust_cpu",
    "random.trust_bootloader",
    "cryptomgr.notests",
    "raid",
    "root",
    "rootfstype",
    "rootflags",
    "ro",
    "panic",
    "init",
    "ip",
    "kvm-intel.nested",
    "kvm-amd.nested",
    "noxsave",
    // Aliases of tokens vmcell owns — same effect, different key, so the key-equality
    // check above would let them through.
    // `rw` inverts the owned `ro`: a `Block` root would then be mounted read-write while
    // `rootflags=noload` still suppresses ext4 journal replay — a dirty image mounted
    // writable with its journal ignored is silent filesystem corruption, not a boot failure.
    "rw",
    // `quiet` (console loglevel 4), `debug` (10) and `ignore_loglevel` (print everything)
    // each override the owned `loglevel=` **after** it on the cmdline (the kernel applies
    // them in order, and caller args go last), so a caller could silently reinstate the
    // full KERN_INFO UART flood the §16 boot lever exists to remove — or, via `quiet`,
    // suppress the boot lines a test greps for. `kernel_verbosity` is the dedicated knob.
    "quiet",
    "debug",
    "ignore_loglevel",
];

/// Whether `arg` collides with a boot token vmcell owns — its key is in
/// [`RESERVED_CMDLINE_KEYS`] or starts with `vmcell_` (every steward-trusted
/// token, §5.3, The kernel command line). The single predicate behind the append-only contract (§5.3, The kernel command line); the
/// key is the text before the first `=` (or the whole bare token).
///
/// The comparison is **dash/underscore-insensitive**, because the kernel's own parser is:
/// `kernel/params.c`'s `dash2underscore` folds `-` to `_` inside a parameter name for every
/// `parameq`/`parameqn` comparison — which is the only reason the `kvm-intel.nested=0` token
/// vmcell emits reaches a module parameter registered as `kvm_intel.nested` at all. A
/// byte-exact membership test therefore admitted the *respelling* of every reserved key
/// (`kvm_intel.nested=1`, `random.trust-cpu=off`, `ignore-loglevel`); caller args are
/// appended **last**, and the kernel applies duplicates in order, so the respelling silently
/// overrode the token vmcell owns (finding `m1`). Normalizing lives here, in the one
/// predicate, so every call site — and every future one — inherits it.
pub(crate) fn is_reserved_cmdline_arg(arg: &str) -> bool {
    let key = normalize_cmdline_key(arg.split('=').next().unwrap_or(arg));
    // The steward trusts every `vmcell_*` token (shares, accept/rebind cadence);
    // a caller arg spoofing one would mis-mount a share or busy-spin PID 1.
    key.starts_with("vmcell_")
        || RESERVED_CMDLINE_KEYS
            .iter()
            .any(|reserved| normalize_cmdline_key(reserved) == key)
}

/// Folds a kernel-cmdline parameter name to the spelling the kernel compares on
/// (`kernel/params.c`'s `dash2underscore`). Private to [`is_reserved_cmdline_arg`]'s law so
/// there is exactly one normalizer.
fn normalize_cmdline_key(key: &str) -> String {
    key.replace('-', "_")
}

/// Appends the validated append-only caller args to `cmdline`, one whitespace-
/// separated token each (§5.3, The kernel command line). No args ⇒ nothing appended.
pub(crate) fn push_extra_kernel_args(cmdline: &mut String, args: &[String]) {
    for arg in args {
        cmdline.push(' ');
        cmdline.push_str(arg);
    }
}

/// Validates a caller-supplied `init=` override path (§5.3, The kernel command line): valid UTF-8, absolute,
/// and a single cmdline token (no whitespace or control characters — a space would
/// forge a second boot token).
///
/// # Errors
/// Returns a human-readable reason when the path is empty, not UTF-8, not absolute,
/// or carries whitespace/control characters.
fn validate_init_path(init: &std::path::Path) -> Result<(), String> {
    let s = init.to_str().ok_or_else(|| {
        format!("init path {init:?} must be valid UTF-8 (it is encoded on the kernel cmdline)")
    })?;
    if s.is_empty() {
        return Err("init path cannot be empty".to_string());
    }
    if !init.is_absolute() {
        return Err(format!("init path {s:?} must be an absolute path"));
    }
    if s.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(format!(
            "init path {s:?} may not contain whitespace or control characters (it is a single kernel cmdline token)"
        ));
    }
    Ok(())
}

/// Validates one append-only caller kernel arg (§5.3, The kernel command line): non-empty, a single cmdline
/// token (no whitespace/control characters), and not colliding with a reserved token
/// vmcell owns ([`is_reserved_cmdline_arg`]).
///
/// # Errors
/// Returns a human-readable reason when the arg is empty, carries whitespace/control
/// characters, or would clobber a reserved boot token.
fn validate_extra_kernel_arg(arg: &str) -> Result<(), String> {
    if arg.is_empty() {
        return Err("extra kernel argument cannot be empty".to_string());
    }
    if arg.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(format!(
            "extra kernel argument {arg:?} may not contain whitespace or control characters (it is a single kernel cmdline token)"
        ));
    }
    if is_reserved_cmdline_arg(arg) {
        return Err(format!(
            "extra kernel argument {arg:?} collides with a boot token vmcell owns (append-only: extra args cannot override console/loglevel/root/rootfstype/init/ip/panic/kvm-*.nested or any vmcell_* token — use the dedicated VmConfig field, e.g. `init`, where one exists)"
        ));
    }
    Ok(())
}

/// Options for the root filesystem backing the VM.
///
/// Every VMM backend — including the out-of-tree `vmcell-firecracker`/`vmcell-qemu` crates — must
/// exhaustively map each rootfs source to its own device wiring, so this enum is deliberately
/// **not** `#[non_exhaustive]`: a new variant should be a compile error in every backend (fail-loud)
/// rather than an unhandled `_` arm. (`vmcell` is `publish = false`; there is no external consumer.)
///
/// The backends no longer each carry their own per-variant `match` for the root disk's *writability*
/// — that decision is now the one law [`RootfsSource::root_device_read_only`], beside
/// [`RootfsSource::effective_image`]. A new variant is still a compile error, in the two laws that
/// decide the wiring instead of in four copies of the same answer; and it was the four copies that
/// had drifted (all four attached the root read-write while `build_kernel_cmdline` mounted it `ro`).
#[derive(Clone, Debug)]
pub enum RootfsSource {
    /// Read-only EROFS image. Shared across multiple VMs.
    Erofs {
        /// Path to the EROFS image file.
        image: PathBuf,
    },
    /// Read-only ext4 (or other block-format) image — the §4.7 producer's output.
    ///
    /// **Read-only, like [`Erofs`](Self::Erofs), and for the same reason**: the guest mounts the
    /// root `ro` (see [`root_device_read_only`](Self::root_device_read_only) for the whole coupling).
    /// What this variant buys is not writability but **POSIX-completeness** — device nodes,
    /// extended attributes, ACLs, and the ext4 on-disk semantics a workload may be asserting on —
    /// which is exactly what the §15.4 ext4 battery's in-guest tree/xattr/device diff measures.
    /// It shares across concurrent VMs exactly as the erofs image does, so it needs no per-clone
    /// copy and no snapshot-eligibility arm.
    Block {
        /// Base image file.
        image: PathBuf,
        /// Optional **per-VM private copy** of the base image, attached in its place.
        ///
        /// Not a write target: the root is read-only either way (a `Block` root is mounted `ro`,
        /// and the device is attached read-only). It exists so a caller that wants a VM to own its
        /// own bytes — a copy-on-write clone materialized through `HostEnv::overlay` (S4) — can say
        /// so without rewriting the base path everywhere; when it is set the base image is never
        /// attached at all ([`effective_image`](Self::effective_image)).
        overlay: Option<PathBuf>,
    },
}

impl RootfsSource {
    /// The host file actually attached as the root disk (`/dev/vda`): the [`Block`](Self::Block)
    /// overlay when one is set — the base image is then never attached — else the base image.
    ///
    /// One law, one predicate (§13, Cross-cutting invariants): the boundary's
    /// duplicate-backing-file check and every backend's root-disk wiring must agree on *which*
    /// file backs the root device, or an extra virtio-blk disk naming the same file passes
    /// validation and the guest gets two writable attachments of one image — the exact
    /// corruption the extra-disk duplicate guard exists to prevent
    /// (finding `rootfs-image-escapes-boundary-validation`).
    #[must_use]
    pub fn effective_image(&self) -> &std::path::Path {
        match self {
            RootfsSource::Erofs { image } => image,
            RootfsSource::Block { image, overlay } => overlay.as_deref().unwrap_or(image),
        }
    }

    /// Whether the host file backing `/dev/vda` is attached to the guest **read-only**.
    ///
    /// One law, one predicate (§13, Cross-cutting invariants): every backend's root-disk wiring
    /// reads this — `readonly` on Cloud Hypervisor, `is_read_only` on Firecracker, `readonly=on` on
    /// QEMU, `ro=true` on crosvm — so the device's writability cannot drift away from the mount's.
    ///
    /// **The device's writability must not exceed the mount's, and the mount is always `ro`.**
    /// [`build_kernel_cmdline`] emits a bare `ro` with no rootfs conditional, and F3 reserves `rw`
    /// as an *alias* of that owned token precisely so a caller cannot flip it — the rationale
    /// recorded on the reserved-key list is that `rw` plus the `rootflags=noload` a `Block` root
    /// also carries is silent filesystem corruption rather than a boot failure. So the answer is
    /// `true` for every variant, and the exhaustive match is what makes a future writable variant
    /// answer this question (and the cmdline's) instead of inheriting a wrong default.
    ///
    /// This function exists because the four backends each carried their own copy of the decision
    /// and **all four had drifted**: each attached a `Block` root read-write while the cmdline
    /// mounted it read-only, so a guest could write straight through `/dev/vda` under a root
    /// filesystem the kernel believed was immutable — and N zygote clones share one image.
    /// `rootfs_device_writability_matches_the_mount` couples the two directions.
    #[must_use]
    pub fn root_device_read_only(&self) -> bool {
        match self {
            // A shared, immutable image: the format has no write path at all.
            RootfsSource::Erofs { .. } => true,
            // Read-only by ratification, not by accident — see the variant's own docs and §4.7.
            RootfsSource::Block { .. } => true,
        }
    }
}

/// An extra virtio-blk device attached to the VM in addition to the root disk
/// ([`VmConfig::extra_disks`], §4.6, Extra virtio-blk devices and disk-I/O throttling).
///
/// The guest kernel enumerates extra disks as `/dev/vdb`, `/dev/vdc`, … in
/// attachment order; the root disk is always `/dev/vda`. vmcell attaches the **raw**
/// block device only — the guest workload owns any partitioning, filesystem, or
/// mount (the steward does not auto-mount extra disks).
///
/// Plain virtio-blk is **not** a vhost-user device, so extra disks compose with
/// snapshotting (§13, Cross-cutting invariants). A block device's contents live on disk, *outside* the
/// memory snapshot, so the [`image`](BlockDevice::image) path must be **stable across
/// a restore** (CH/FC restore reconstruct devices from the paths recorded at snapshot
/// time), i.e. not inside the per-VM scratch dir.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct BlockDevice {
    /// Host path to the backing image file.
    pub image: PathBuf,
    /// Whether the device is attached read-only.
    pub readonly: bool,
    /// Optional I/O rate limit (disk-I/O fault injection, §4.6, Extra virtio-blk devices and disk-I/O throttling). `None` = unlimited.
    pub io_limit: Option<DiskIoLimit>,
}

impl BlockDevice {
    /// A read-only extra virtio-blk device backed by `image`.
    #[must_use]
    pub fn read_only(image: impl Into<PathBuf>) -> Self {
        Self {
            image: image.into(),
            readonly: true,
            io_limit: None,
        }
    }

    /// A read-write extra virtio-blk device backed by `image`.
    #[must_use]
    pub fn read_write(image: impl Into<PathBuf>) -> Self {
        Self {
            image: image.into(),
            readonly: false,
            io_limit: None,
        }
    }

    /// Attaches an I/O rate limit to this device (disk-I/O fault injection, §4.6, Extra virtio-blk devices and disk-I/O throttling), to
    /// simulate a slow or pressured disk. Validated at [`VmConfigBuilder::build`].
    #[must_use]
    pub fn with_io_limit(mut self, limit: DiskIoLimit) -> Self {
        self.io_limit = Some(limit);
        self
    }
}

/// A host USB device passed through to the guest, identified by its USB vendor and
/// product ID (§2.4, QEMU q35 — the fallback and most-proven nester).
///
/// Attached on QEMU as one `-device qemu-xhci` controller plus a
/// `-device usb-host,vendorid=0x…,productid=0x…` per device — the
/// [`usb_host_passthrough`](crate::vmm::VmmCapabilities::usb_host_passthrough)
/// capability, which only QEMU advertises. The pair identifies the device *by type*,
/// not by bus/port, so the host must expose exactly one matching device; both IDs are
/// required and validated at [`VmConfigBuilder::build`].
///
/// A passed-through device is host state living outside guest RAM, so it cannot be
/// migrated: `build()` rejects a USB device combined with `snapshotting`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct UsbHostDevice {
    /// The USB vendor ID (the `idVendor` sysfs value), e.g. `0x1d6b`.
    pub vendor_id: u16,
    /// The USB product ID (the `idProduct` sysfs value), e.g. `0x0002`.
    pub product_id: u16,
}

impl UsbHostDevice {
    /// A host USB device selected by its `(vendor_id, product_id)` pair.
    ///
    /// Both IDs must be non-zero — QEMU's `usb-host` treats a `0` `vendorid`/`productid`
    /// as *unset* (match-any) rather than as a literal match, so a zero would silently
    /// widen the selection to an arbitrary host device. [`VmConfigBuilder::build`]
    /// rejects that fail-loud.
    #[must_use]
    pub fn new(vendor_id: u16, product_id: u16) -> Self {
        Self {
            vendor_id,
            product_id,
        }
    }
}

/// An I/O rate limit for a [`BlockDevice`] — the portable form of disk-I/O fault
/// injection (§4.6, Extra virtio-blk devices and disk-I/O throttling), simulating a slow/pressured disk to test a workload's timeout /
/// retry / backpressure behavior. Each backend enforces it with its native token-bucket
/// rate limiter (Cloud Hypervisor `rate_limiter_config`, Firecracker `rate_limiter`,
/// QEMU `throttling.*`), so it composes with snapshotting like any plain virtio-blk.
///
/// At least one of the two caps must be set (a limit that limits nothing is rejected at
/// [`VmConfigBuilder::build`]); a set cap must be `> 0` (a `0` cap would wedge all I/O).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct DiskIoLimit {
    /// Read+write bandwidth cap in **bytes per second** (`None` = unlimited).
    pub bandwidth_bytes_per_sec: Option<u64>,
    /// Read+write **IOPS** cap — operations per second (`None` = unlimited).
    pub iops: Option<u64>,
}

impl DiskIoLimit {
    /// A limit with explicit bandwidth (bytes/second) and/or IOPS caps; `None` leaves
    /// that dimension unlimited. Construction seam for callers outside this crate (the
    /// struct is `#[non_exhaustive]`).
    #[must_use]
    pub fn new(bandwidth_bytes_per_sec: Option<u64>, iops: Option<u64>) -> Self {
        Self {
            bandwidth_bytes_per_sec,
            iops,
        }
    }

    /// A bandwidth-only cap of `bytes_per_sec` bytes/second.
    #[must_use]
    pub fn bandwidth(bytes_per_sec: u64) -> Self {
        Self {
            bandwidth_bytes_per_sec: Some(bytes_per_sec),
            iops: None,
        }
    }

    /// An IOPS-only cap of `iops` operations/second.
    #[must_use]
    pub fn iops(iops: u64) -> Self {
        Self {
            bandwidth_bytes_per_sec: None,
            iops: Some(iops),
        }
    }
}

/// The token-bucket refill window (milliseconds) every backend uses to express a
/// [`DiskIoLimit`] rate: a bucket of `size = rate` tokens refilled every
/// `IO_LIMIT_REFILL_TIME_MS` yields exactly `rate` tokens/second. The ONE conversion
/// shared by the CH and Firecracker rate-limiter builders (one law, one predicate), so
/// they can never express the same `DiskIoLimit` as different rates. QEMU takes the
/// per-second rate directly (`throttling.bps-total`/`iops-total`).
pub const IO_LIMIT_REFILL_TIME_MS: u64 = 1000;

/// Guest kernel console log verbosity, mapped to the `loglevel=` boot parameter.
///
/// Kernel `printk` to the legacy 8250 `ttyS0` UART is a **per-byte PIO trap → VM
/// exit** (§5.3, The kernel command line), so verbose boot logging is a real cold-boot cost — the single
/// largest lever in the §16 (Performance) latency pass. This knob lets debugging and specific
/// tests opt into a verbose log without making every VM pay the exit tax. Panic
/// capture works at every level:
/// [`contains_panic`](crate::vmm::SerialLog::contains_panic) matches the literal panic
/// markers (`Kernel panic`, `panicked at`, `panic - not syncing`), not log-level
/// prefixes (§5.3, The kernel command line — the "KERN_EMERG lines" phrasing earlier
/// revisions carried was drift).
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
// Not `#[non_exhaustive]`: each VMM backend (including the out-of-tree `vmcell-qemu` crate)
// exhaustively maps every console mode to its device wiring, so a new mode should be a compile
// error in every backend (fail-loud) rather than an unhandled `_`. (`vmcell` is `publish = false`.)
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ConsoleMode {
    /// Legacy 8250 `ttyS0`: alive from the first instruction (early-boot + panic
    /// capture, §5.3, The kernel command line) but per-byte PIO VM-exits. The safe default.
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

/// Selects the QEMU steward vsock transport (§2.4). QEMU is the only backend with
/// a choice here — CH and Firecracker always terminate vsock inside the VMM.
///
/// The two transports differ in privilege and in snapshot-eligibility:
///
/// - [`ExternalDaemon`](VsockTransport::ExternalDaemon) — an out-of-VMM
///   `vhost-device-vsock` daemon bridging to a host AF_UNIX socket. **Unprivileged**
///   (no `/dev/vhost-vsock` needed), but it *is* a vhost-user device, so it is
///   **not** snapshot-eligible, and its bring-up races (~11% of boots wedge the data
///   path — `tests/qemu_vsock_flake_repro.rs`), which `verify_control_plane` recovers
///   from by re-spawning.
/// - [`InKernel`](VsockTransport::InKernel) — the in-kernel `vhost-vsock-pci` device,
///   exposing the guest directly on the host AF_VSOCK namespace. **Requires
///   `/dev/vhost-vsock` access** (`CAP_DAC_OVERRIDE` or `kvm`-group membership) and
///   fails loud at device realize if it cannot open it (never a silent fallback,
///   M-VMM-2). It carries no daemon, so it is deterministic (no bring-up race) and is
///   the only migratable — hence snapshot-eligible — QEMU vsock transport.
///
/// A `snapshotting` VM is always driven onto `InKernel`: [`Auto`](VsockTransport::Auto)
/// resolves to it, and [`VmConfigBuilder::build`] rejects `snapshotting` combined with
/// an explicit `ExternalDaemon` (the invalid combination is fail-loud, not silently
/// overridden). The one predicate `uses_in_kernel_vsock` reads this field.
// Not `#[non_exhaustive]`: the QEMU backend (now the out-of-tree `vmcell-qemu` crate) exhaustively
// matches this in `uses_in_kernel_vsock`, and a new transport must force that decision to be
// re-made (a compile error) rather than slip through an unhandled `_` arm. (`vmcell` is
// `publish = false`; there is no external consumer relying on non-exhaustiveness.)
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum VsockTransport {
    /// `InKernel` when `snapshotting`, else `ExternalDaemon` — the unprivileged
    /// default that preserves the historical behavior.
    #[default]
    Auto,
    /// Force the in-kernel `vhost-vsock-pci` transport (needs `/dev/vhost-vsock`).
    /// Lets a **privileged non-snapshot** QEMU shed the external-daemon bring-up
    /// flake without opting into snapshotting.
    InKernel,
    /// Force the external `vhost-device-vsock` daemon (unprivileged). Rejected by
    /// `build()` when combined with `snapshotting` (a non-migratable vhost-user
    /// device cannot back a snapshot).
    ExternalDaemon,
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
    /// kernel command line, §4.5, Shared directories (virtio-fs)); [`VmConfigBuilder::build`] rejects violations.
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
    /// line, §4.5, Shared directories (virtio-fs)); [`VmConfigBuilder::build`] enforces this.
    #[must_use]
    pub fn with_guest_path(mut self, guest_path: impl Into<PathBuf>) -> Self {
        self.guest_path = guest_path.into();
        self
    }
}

/// Appends the guest boot-time mount plan for `shares` to a kernel `cmdline`.
///
/// The steward (PID 1) has no host-side view of [`VmConfig`], so the shares
/// it must mount — their tag, mount point, and access mode — travel on the kernel
/// command line as one `vmcell_share=<tag>:<guest_path>:<ro|rw>` token per share
/// (§4.5, Shared directories (virtio-fs): tags and mount points are caller-defined, not built into the runner).
/// The steward reads `/proc/cmdline`, mounts each `tag` at its `guest_path` over
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
    ///
    /// No `host_services_port`: host-service reachability is implemented **only** on the
    /// [`NetConfig::Unprivileged`] smoltcp NAT (§6.2, NetConfig and the two datapaths, design §18, Delta register — delta 4). The privileged TPROXY
    /// ruleset policy-drops everything but the web TPROXY and the proxy port, so the field would be
    /// a no-op here — the invalid state is made *unrepresentable* rather than accepted then
    /// rejected at `build()`.
    Privileged {
        /// Egress proxy configuration.
        egress: Egress,
    },
    /// Unprivileged mode using an in-process smoltcp stack plus a vhost-user-net
    /// NAT, requiring no extra Linux capabilities (passt was deliberately rejected).
    Unprivileged {
        /// Egress proxy configuration.
        egress: Egress,
        /// Optional port for host services accessible from the guest.
        ///
        /// Rejected by [`VmConfigBuilder::build`] when `egress` is [`Egress::Blocked`]: that
        /// variant refuses the outbound dial this port is reached by, so the pair cannot be
        /// honored (F1). It stays a field here rather than moving onto the `Egress` variants
        /// because `Egress` is public, `#[non_exhaustive]` and shared with the privileged arm —
        /// see the at-site rationale in `build()`.
        host_services_port: Option<u16>,
    },
    /// Shared L2 **segment** membership: the VM's tap lives in the segment's namespace, enslaved to
    /// the segment bridge, so two members reach each other over a real kernel-bridged L2 domain
    /// (§6.5, VM-to-VM segments; v30 §18 delta 8).
    ///
    /// Deliberately carries **no `egress` and no `host_services_port`**: a segment VM's
    /// connectivity is segment-internal by definition in v30, so a MITM proxy or a NAT forward on a
    /// member is *unrepresentable* rather than validated (the same move delta 4 made for
    /// `host_services_port`). Per-segment filtered egress is recorded forward work (§17).
    Segment {
        /// The segment to join. Every member holds a clone of this handle, and the namespace and
        /// bridge are reclaimed when the last holder drops.
        segment: crate::net::NetSegmentRef,
    },
    /// No networking configuration.
    #[default]
    None,
}

/// Whether `net` selects the **kernel tap in a netns** datapath — `Privileged` or `Segment`
/// (§6.2, NetConfig and the two datapaths).
///
/// The one predicate for that question, so no caller re-derives the mode from an ad-hoc match. Note
/// what it is *not*: the backends' device wiring keys on `res.tap_name.is_some()`, the stronger
/// exhaustive-struct channel (a `PerVmResources` field every backend must acknowledge to compile),
/// and `assert_tap_wiring_matches` below is the law that keeps the two in lockstep.
#[must_use]
pub fn net_uses_tap(net: &NetConfig) -> bool {
    match net {
        NetConfig::Privileged { .. } | NetConfig::Segment { .. } => true,
        NetConfig::Unprivileged { .. } | NetConfig::None => false,
        // No wildcard arm on purpose: `NetConfig` is `#[non_exhaustive]` to *consumers*, but
        // in-crate this match is exhaustive, so a new variant is a compile error here — the
        // fail-loud channel that stops a new datapath from silently defaulting to "no tap".
    }
}

/// Fail-loud post-condition: the resources the orchestrator allocated must agree with what
/// [`net_uses_tap`] says the config's datapath is.
///
/// A `Privileged`/`Segment` config with no tap would boot a guest with an unconfigurable `eth0`
/// (and, on a segment, no bridge port at all); a `Unprivileged`/`None` config carrying one would
/// take the backends' tap arm and silently ignore the NAT. Checked once, in the orchestrator, so
/// every backend can keep keying on `res.tap_name`.
///
/// # Errors
/// [`crate::error::Error::Network`] naming the mismatch.
pub(crate) fn assert_tap_wiring_matches(
    net: &NetConfig,
    tap_present: bool,
) -> Result<(), crate::error::Error> {
    if net_uses_tap(net) != tap_present {
        return Err(crate::error::Error::Network(format!(
            "network wiring mismatch: net_uses_tap = {}, but a tap interface is {} — a \
             tap-datapath config must be handed a tap, and a NAT/no-net config must not",
            net_uses_tap(net),
            if tap_present { "present" } else { "absent" },
        )));
    }
    Ok(())
}

/// Egress filtering strategy for outbound network traffic.
///
/// The three variants are ordered from most to least mediated, and **each one is honored on
/// both networking arms** — the privileged (netns + nft) arm and the unprivileged (smoltcp
/// NAT) arm. That was not always true: `Blocked` used to share `Open`'s empty else-path in
/// `setup_env`, so it installed no ruleset at all and was in fact *more* permissive than
/// `Filtered` (finding `M1`). Both arms now match this enum exhaustively, so a new variant is
/// a compile error rather than a silent fall-through into the most permissive behavior.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum Egress {
    /// Traffic is transparently routed through a proxy.
    ///
    /// Privileged: an nft ruleset with `policy drop` that admits only tcp/80,443 (redirected
    /// by TPROXY into the per-VM proxy) and the gateway's proxy port. Unprivileged: the proxy
    /// port is registered as a permanent NAT forward so a guest configured with
    /// `http_proxy=<gateway>:<port>` reaches it.
    Filtered(ProxyConfig),
    /// All egress traffic is blocked.
    ///
    /// Privileged: an accepts-nothing nft ruleset — `render_tproxy_rules`' shape minus both
    /// accept rules, and no TPROXY routing (there is no proxy to route to), so the per-VM
    /// netns drops everything including the §6.3 host-endpoint mechanism that `Open` leaves
    /// reachable. Unprivileged: no forward port is registered at all — neither a proxy port
    /// nor `host_services_port` — and the NAT refuses to open outbound host connections on
    /// the guest's behalf.
    ///
    /// Because there is no way to honor a `host_services_port` under this variant,
    /// [`VmConfigBuilder::build`] **rejects** the pair rather than accepting a port it would
    /// silently ignore (F1).
    Blocked,
    /// No egress **interception** is configured (no proxy is started).
    ///
    /// This is *not* unrestricted outbound internet: it selects "no filtering
    /// proxy", and connectivity is then whatever the networking mode's datapath
    /// natively provides — the unprivileged NAT reaches only the registered
    /// `host_services_port`/proxy forwards, and the privileged path reaches only
    /// what its TPROXY ruleset admits. Arbitrary outbound egress (dialing the
    /// frame's real destination / host masquerade) is **not implemented** for
    /// `Open` in either mode; see implementation-notes.md (§16, H-NET-4). Use
    /// [`Egress::Filtered`] for a mediated egress path.
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
#[derive(Clone, Debug, Default, PartialEq, Eq)]
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
            vsock_transport: VsockTransport::Auto,
            vmid: None,
            restore_mode: RestoreMode::Default,
            ksm_mergeable: false,
            kernel_verbosity: KernelVerbosity::Balanced,
            timeouts: Timeouts::default(),
            console_mode: ConsoleMode::Uart,
            resource_prefix: crate::naming::DEFAULT_RESOURCE_PREFIX.to_string(),
            extra_disks: vec![],
            usb_host_devices: vec![],
            extra_kernel_args: vec![],
            init: None,
            vmm_seccomp: VmmSeccomp::default(),
            jail: JailConfig::default(),
            required_features: vec![],
            steward_placement: None,
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
    vsock_transport: VsockTransport,
    vmid: Option<u32>,
    restore_mode: RestoreMode,
    ksm_mergeable: bool,
    kernel_verbosity: KernelVerbosity,
    timeouts: Timeouts,
    console_mode: ConsoleMode,
    resource_prefix: String,
    extra_disks: Vec<BlockDevice>,
    usb_host_devices: Vec<UsbHostDevice>,
    extra_kernel_args: Vec<String>,
    init: Option<PathBuf>,
    vmm_seccomp: VmmSeccomp,
    jail: JailConfig,
    required_features: Vec<crate::feature::Feature>,
    /// `None` = derive from `init` at `build()`. `Some` = the caller stated it explicitly.
    steward_placement: Option<StewardPlacement>,
}

impl VmConfigBuilder {
    /// Sets the VMM subprocess's own seccomp policy ([`VmConfig::vmm_seccomp`], §12.2, Layer 1 — the VMM's own seccomp filter).
    /// Default [`VmmSeccomp::Enforcing`].
    #[must_use]
    pub fn vmm_seccomp(mut self, policy: VmmSeccomp) -> Self {
        self.vmm_seccomp = policy;
        self
    }

    /// Sets the jailer-equivalent pre-exec hardening for the VMM child
    /// ([`VmConfig::jail`], §12.3, Layer 2 — the jailer-equivalent (JailSpec + apply_jail)). Default [`JailConfig::hardened`].
    #[must_use]
    pub fn jail(mut self, jail: JailConfig) -> Self {
        self.jail = jail;
        self
    }

    /// Adds a shared directory.
    #[must_use]
    pub fn with_share(mut self, share: Share) -> Self {
        self.shares.push(share);
        self
    }

    /// Attaches an extra virtio-blk device ([`BlockDevice`], §4.6, Extra virtio-blk devices and disk-I/O throttling), enumerated by the
    /// guest as the next `/dev/vd*` after the root disk in call order. Validated at
    /// [`build`](Self::build).
    #[must_use]
    pub fn with_extra_disk(mut self, disk: BlockDevice) -> Self {
        self.extra_disks.push(disk);
        self
    }

    /// Passes a host USB device through to the guest ([`UsbHostDevice`], §2.4, QEMU q35 — the fallback and most-proven nester).
    /// **QEMU only** — every other backend's `create()` refuses a non-empty list with a
    /// typed [`Error::Unsupported`](crate::error::Error::Unsupported). Validated at
    /// [`build`](Self::build), which rejects a zero ID, a duplicate device, and the
    /// combination with `snapshotting`.
    #[must_use]
    pub fn with_usb_host_device(mut self, device: UsbHostDevice) -> Self {
        self.usb_host_devices.push(device);
        self
    }

    /// Appends one append-only extra kernel command-line argument
    /// ([`VmConfig::extra_kernel_args`], §5.3, The kernel command line). Rejected at [`build`](Self::build) if
    /// it collides with a reserved token vmcell owns or is not a single safe token.
    #[must_use]
    pub fn with_kernel_arg(mut self, arg: impl Into<String>) -> Self {
        self.extra_kernel_args.push(arg.into());
        self
    }

    /// Overrides the guest `init=` target ([`VmConfig::init`], §5.3, The kernel command line). A custom init
    /// **replaces** the vmcell steward, forgoing the vsock control plane; validated
    /// at [`build`](Self::build), which also rejects it combined with `snapshotting`.
    #[must_use]
    pub fn init(mut self, init: impl Into<PathBuf>) -> Self {
        self.init = Some(init.into());
        self
    }

    /// **Demands** a feature of this cell ([`VmConfig::required_features`], design §7.4 clause 3).
    ///
    /// Resolved at `MicroVm::start` against the computed [`crate::feature::FeatureSet`] — the
    /// backend's descriptor intersected with the host's and every artifact's declarations — so a
    /// cell that cannot do what the caller needs is refused **before it boots**, with the
    /// [`crate::feature::Removal`]'s provenance in the typed
    /// [`Error::Unsupported`](crate::error::Error::Unsupported). Not validated at
    /// [`build`](Self::build), which by design never sees a backend.
    ///
    /// Calling it twice with the same feature is harmless (the resolution is a membership test).
    #[must_use]
    pub fn require(mut self, feature: crate::feature::Feature) -> Self {
        self.required_features.push(feature);
        self
    }

    /// Declares where this cell's steward runs ([`VmConfig::steward_placement`], design §3.5).
    ///
    /// Omit it and the placement is **derived** for byte-compatibility: [`StewardPlacement::Pid1`]
    /// when no `init` is set, [`StewardPlacement::None`] when one is — exactly the pre-v33
    /// semantics. State it to express what the derivation cannot: a guest whose own init starts the
    /// steward ([`StewardPlacement::Service`]), which is what makes systemd, init-system testing,
    /// and distro-as-shipped images reachable through the control plane at all.
    ///
    /// [`build`](Self::build) rejects the one contradictory pair, `Pid1` + a custom
    /// [`init`](Self::init) — the kernel cannot start the steward as PID 1 if `init=` names
    /// something else. Everything else composes, **including** `Service { port }` + `init: None`:
    /// the kernel starts the steward as PID 1 *and* the host treats it as a service. That
    /// combination is deliberately legal because it is what makes the placement predicate
    /// verifiable before a service-mode steward exists.
    #[must_use]
    pub fn steward_placement(mut self, placement: StewardPlacement) -> Self {
        self.steward_placement = Some(placement);
        self
    }

    /// Sets the prefix for this VM's swept host-resource names (netns/tap/cgroup/scratch); default
    /// [`crate::naming::DEFAULT_RESOURCE_PREFIX`]. Run the orphan sweep with the same prefix (§13, Cross-cutting invariants).
    /// Validated at [`build`](Self::build).
    #[must_use]
    pub fn resource_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.resource_prefix = prefix.into();
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

    /// Selects the QEMU steward vsock transport ([`VmConfig::vsock_transport`],
    /// §2.4). Default [`VsockTransport::Auto`]. [`VsockTransport::InKernel`] opts a
    /// privileged non-snapshot QEMU into the deterministic in-kernel transport;
    /// [`build`](Self::build) rejects [`VsockTransport::ExternalDaemon`] combined with
    /// `snapshotting`. No effect on Cloud Hypervisor / Firecracker.
    #[must_use]
    pub fn vsock_transport(mut self, transport: VsockTransport) -> Self {
        self.vsock_transport = transport;
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

    /// Enables KSM-mergeable (private-anonymous) guest memory (§8.3, Density levers). See
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
    ///   networking — which violates the §8.1 (The warm-snapshot path and the eligibility law) snapshot-eligibility law;
    /// - `ksm_mergeable` combined with any vhost-user device (it sets CH
    ///   `shared=off`, mutually exclusive with the vhost-user paths — §8.3, Density levers);
    /// - a [`UsbHostDevice`] with a zero vendor or product ID (QEMU reads a zero as
    ///   *unset* — match-any — not as a literal ID), two USB devices naming the same
    ///   `(vendor_id, product_id)` pair, or any USB device combined with
    ///   `snapshotting` (a passed-through host device is not migratable, §2.4, QEMU q35 — the fallback and most-proven nester);
    /// - [`Egress::Blocked`] combined with a `host_services_port` — the port names a host
    ///   endpoint the guest dials *out* to, which `Blocked` refuses, so honoring both is
    ///   impossible and the port would be silently unused (F1).
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
        // §3.5 / C8: RESOLVE the placement. Derived for byte-compatibility when the caller named
        // none — `Pid1` with no `init`, `None` with one — so every pre-v33 caller keeps its exact
        // semantics and a cell that never names a placement cannot tell v33 landed.
        let placement = self.steward_placement.unwrap_or(if self.init.is_some() {
            StewardPlacement::None
        } else {
            StewardPlacement::Pid1
        });

        // The ONE contradictory pair. Everything else composes — including `Service{port}` +
        // `init: None`, which is deliberately legal: the kernel starts the steward as PID 1 *and*
        // the host treats it as a service, which is what makes the placement predicate verifiable
        // before a service-mode steward exists.
        if placement == StewardPlacement::Pid1
            && let Some(init) = &self.init
        {
            return Err(crate::error::Error::Config(format!(
                "StewardPlacement::Pid1 cannot be combined with a custom init ({}): the kernel \
                 cannot start the steward as PID 1 if `init=` names something else. Declare \
                 StewardPlacement::Service {{ port }} if the guest's own init starts the steward, \
                 or StewardPlacement::None if nothing does.",
                init.display()
            )));
        }

        // F1, honored or rejected at construction: a declared port must be dialable. 0 and
        // u32::MAX are the AF_VSOCK reserved values (VMADDR_PORT_ANY is u32::MAX), so a cell
        // declaring either would bind or dial something it did not mean.
        if let StewardPlacement::Service { port } = placement
            && (port == 0 || port == u32::MAX)
        {
            return Err(crate::error::Error::Config(format!(
                "StewardPlacement::Service port {port} is reserved by AF_VSOCK (0 and \
                 u32::MAX/VMADDR_PORT_ANY); declare a real port"
            )));
        }

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

        // M-HOST-4: reject out-of-range resource-limit values at the boundary. A
        // bad value (e.g. `cpu_max_pct == 0` → a sub-floor `cpu.max` quota, or a
        // malformed `io.max` device key) is rejected by the kernel with EINVAL at
        // the cgroup write, where it would otherwise masquerade as a missing-
        // capability error and send the caller chasing a delegation problem.
        if self.limits.cpu_max_pct == Some(0) {
            return Err(crate::error::Error::Config(
                "cpu_max_pct must be > 0".into(),
            ));
        }
        if self.limits.mem_max_mib == Some(0) {
            return Err(crate::error::Error::Config(
                "mem_max_mib must be > 0".into(),
            ));
        }
        if self.limits.pids_max == Some(0) {
            return Err(crate::error::Error::Config("pids_max must be > 0".into()));
        }
        if let Some(io) = &self.limits.io_max {
            // cgroup `io.max` keys on a `maj:min` device number; anything else is
            // written verbatim and rejected with EINVAL.
            let valid = io.device.split_once(':').is_some_and(|(maj, min)| {
                !maj.is_empty()
                    && !min.is_empty()
                    && maj.bytes().all(|b| b.is_ascii_digit())
                    && min.bytes().all(|b| b.is_ascii_digit())
            });
            if !valid {
                return Err(crate::error::Error::Config(format!(
                    "io_max device {:?} must be in maj:min form (e.g. \"8:0\")",
                    io.device
                )));
            }
        }

        if self.snapshotting {
            // Snapshot requires the migratable in-kernel vsock transport (§2.4): the
            // external `vhost-device-vsock` daemon is a non-migratable vhost-user
            // device. `Auto` resolves to in-kernel for a snapshotting VM, but an
            // *explicit* `ExternalDaemon` is a contradiction — reject it fail-loud
            // rather than silently override the caller's request (M-VMM-2).
            if matches!(self.vsock_transport, VsockTransport::ExternalDaemon) {
                return Err(crate::error::Error::Config(
                    "snapshotting requires the in-kernel vsock transport and cannot be \
                     combined with vsock_transport = ExternalDaemon (the external \
                     vhost-device-vsock daemon is a non-migratable vhost-user device)"
                        .into(),
                ));
            }
            // The mandatory post-restore resync — clock, entropy reseed, MAC/IP rotation
            // (§13) — runs *through* the steward. A restored clone that cannot reach one would be
            // stranded on frozen identity with no way to fix it from inside (silently dead egress
            // / correlated RNG), the exact §13 trap.
            //
            // v33 delta 4 RE-KEYS this from `self.init.is_some()` onto the placement's second C8
            // method, which is the question it was always asking. The two differ exactly at
            // `Service`: a `Service` cell HAS a reachable steward, but whether the guest's init
            // restarts it after the vhost-vsock device is re-created is unmeasured (§17), so it
            // stays rejected until measured. The re-key is therefore strictly NARROWER than the
            // pre-v33 rule for `Pid1`+`init: None` (unchanged) and identical for everything the
            // old spelling caught — worse for nobody.
            if !placement.resync_reachable() {
                return Err(crate::error::Error::Config(format!(
                    "snapshotting requires the steward to run as PID 1 \
                     (StewardPlacement::Pid1); this config declares {placement:?}, and the \
                     mandatory post-restore resync runs through the steward"
                )));
            }
            // Snapshot-eligibility law: a snapshot-eligible VM must have no
            // vhost-user device attached. A virtio-fs data `Share` is served
            // by virtiofsd (a vhost-user device), so reject it here. (A
            // virtio-fs *rootfs* was the other vhost-user boundary case; design
            // §18 (Delta register) delta 5 removed that variant, making the combination
            // unrepresentable rather than rejected here.)
            if !self.shares.is_empty() {
                return Err(crate::error::Error::Config(
                    "virtio-fs data shares cannot be combined with snapshotting".into(),
                ));
            }
            // Snapshot-eligibility law (§8.1, The warm-snapshot path and the eligibility law), third boundary case: the unprivileged
            // network path is an in-process vhost-user-net device, so it is
            // mutually exclusive with snapshotting just like virtiofsd above.
            if matches!(self.net, NetConfig::Unprivileged { .. }) {
                return Err(crate::error::Error::Config(
                    "unprivileged (vhost-user-net) networking cannot be combined with snapshotting"
                        .into(),
                ));
            }
            // §6.5 (VM-to-VM segments), v30 §18 delta 8: restore-time slot and addressing
            // semantics for a segment are deliberately unspecified in v30 (§17) — a restored
            // member would resume holding a frozen slot address whose tap no longer exists, and
            // the fan-out would silently dual-claim it. Reject fail-loud at the boundary.
            if matches!(self.net, NetConfig::Segment { .. }) {
                return Err(crate::error::Error::Config(
                    "vm-to-vm segment membership cannot be combined with snapshotting (restore-time \
                     slot and addressing semantics are unspecified in v30)"
                        .into(),
                ));
            }
            // §2.4 (QEMU q35 — the fallback and most-proven nester), v30 §18 (Delta register) delta 9: a passed-through host USB device is
            // host state living OUTSIDE guest RAM — the migration stream carries the
            // guest's view of the xhci controller but not the host device behind it, so
            // a restore would resume a guest holding a handle to a device the
            // destination never attached. Reject fail-loud at the boundary rather than
            // silently dropping the device on restore.
            if !self.usb_host_devices.is_empty() {
                return Err(crate::error::Error::Config(
                    "host USB passthrough cannot be combined with snapshotting (a \
                     passed-through host device is not part of the migration stream)"
                        .into(),
                ));
            }
        }

        // §8.3 (Density levers) KSM lever: `ksm_mergeable` sets CH `mergeable=on, shared=off`,
        // and KSM only merges private-anonymous pages — so `shared=off` is
        // mutually exclusive with every vhost-user path. Enforce here (boundary
        // 1) so an invalid combination never becomes a `VmConfig` and instead
        // fails late at the backend, which sets `shared: !ksm_mergeable` while
        // still attaching the vhost-user device.
        if self.ksm_mergeable {
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

        // (Design §18, Delta register — delta 4: `host_services_port` now lives only on
        // `NetConfig::Unprivileged`, so a privileged config carrying it is unrepresentable — the
        // former accept-then-reject at this boundary is gone.)

        // F1, the residual half of finding `M1`: `Egress::Blocked` together with a
        // `host_services_port` is a contradiction, and it was being ACCEPTED with the port
        // silently unused. The port names a host endpoint the guest dials **out** to, which is
        // precisely what `Blocked` promises to refuse, so `nat_egress_plan` registers no forward
        // for it — a caller who asked for both got neither an endpoint nor a diagnostic. Every
        // accepted input is honored or rejected at construction; this one is rejected, naming
        // both fields.
        //
        // Why not make it unrepresentable (the stronger move delta 4 made for the privileged
        // arm): the port would have to migrate onto the egress variants
        // (`Open { host_services_port } | Filtered { proxy, host_services_port }`), and `Egress`
        // is public, `#[non_exhaustive]`, shared by BOTH datapath arms, and matched in the CLI,
        // the daemon DTOs, the bench harness and the example workspace — none of which have a
        // port to give. That is a contract break across the whole consumer surface to encode one
        // pair, so the boundary check is the deliberate trade; see implementation-notes.
        if let NetConfig::Unprivileged {
            egress: Egress::Blocked,
            host_services_port: Some(port),
        } = &self.net
        {
            return Err(crate::error::Error::Config(format!(
                "host_services_port = {port} cannot be combined with egress = Blocked: \
                 `Egress::Blocked` blocks all egress, and a host services port is a host \
                 endpoint the guest dials out to, so the port would be silently unused. Use \
                 `Egress::Open` (or `Egress::Filtered`) to reach it, or drop the port."
            )));
        }

        let mut tags = std::collections::HashSet::new();
        let mut guest_paths = std::collections::HashSet::new();
        for share in &self.shares {
            if share.tag.is_empty() {
                return Err(crate::error::Error::Config(
                    "share tag cannot be empty".into(),
                ));
            }
            // The mount plan reaches the steward as
            // `vmcell_share=<tag>:<guest_path>:<ro|rw>` kernel-cmdline tokens (§4.5, Shared directories (virtio-fs)),
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
            // The tag is also a *host filename*: `fs::VirtioFsDaemon::start_paced` names the
            // vhost-user socket `<vm_tmp>/<tag>.sock`, and the backends join it the same way.
            // A tag carrying a path separator (`../../etc/x`, `/abs`) escapes the per-VM
            // scratch dir, so virtiofsd would create-and-truncate a caller-chosen file
            // outside it — and outside what teardown sweeps. Require the tag to be exactly
            // one normal path component (no separator, no `.`/`..`, no root, no trailing
            // slash) so the join can never leave the scratch dir
            // (finding `share-tag-path-separator-escapes-scratch-dir`).
            let mut tag_components = std::path::Path::new(share.tag.as_str()).components();
            let tag_is_one_normal_component = match (tag_components.next(), tag_components.next()) {
                // Compare against the whole tag, not just "one component": `Path` normalizes
                // a trailing separator away, so `"a/"` yields a single `Normal("a")`.
                (Some(std::path::Component::Normal(c)), None) => {
                    c == std::ffi::OsStr::new(share.tag.as_str())
                }
                _ => false,
            };
            if !tag_is_one_normal_component {
                return Err(crate::error::Error::Config(format!(
                    "share tag {:?} must be a single normal path component (no '/', '.' or '..' — \
                     it names a host socket file inside the per-VM scratch dir)",
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
            // L-ORCH-7: existence stays unchecked (the host dir may be created
            // later), but an empty or relative `host_path` is a config error, not
            // a late virtiofsd-spawn subprocess failure. Reject it at the boundary.
            if share.host_path.as_os_str().is_empty() {
                return Err(crate::error::Error::Config(format!(
                    "share host_path for tag {:?} cannot be empty",
                    share.tag
                )));
            }
            if share.host_path.is_relative() {
                return Err(crate::error::Error::Config(format!(
                    "share host_path {:?} (tag {:?}) must be an absolute path",
                    share.host_path, share.tag
                )));
            }
        }

        // The root disk's backing file(s) get the same boundary treatment as every other
        // host path input — non-empty and absolute — instead of failing late as a VMM
        // "cannot open image" (finding `rootfs-image-escapes-boundary-validation`).
        // Existence stays unchecked, as for the share/extra-disk paths: the artifact may be
        // built after the config (the `Block` overlay is materialized by the CoW store).
        let mut rootfs_paths = vec![match &self.rootfs {
            RootfsSource::Erofs { image } | RootfsSource::Block { image, .. } => ("image", image),
        }];
        if let RootfsSource::Block {
            overlay: Some(overlay),
            ..
        } = &self.rootfs
        {
            rootfs_paths.push(("overlay", overlay));
        }
        for (what, path) in rootfs_paths {
            if path.as_os_str().is_empty() {
                return Err(crate::error::Error::Config(format!(
                    "rootfs {what} path cannot be empty"
                )));
            }
            if path.is_relative() {
                return Err(crate::error::Error::Config(format!(
                    "rootfs {what} {path:?} must be an absolute path"
                )));
            }
        }

        // Extra virtio-blk device images: absolute, non-empty, no duplicate backing
        // file (§4.6, Extra virtio-blk devices and disk-I/O throttling). Existence is deliberately NOT checked here (consistent with
        // the rootfs/share paths — the image may be created later); a bad path fails
        // loud at `create()`. A duplicate image is a rw corruption footgun (two
        // attachments of one file), so it is rejected at the boundary.
        //
        // The set is SEEDED with the root disk's effective backing file (the one law,
        // `RootfsSource::effective_image`), because an extra disk naming the Block root's image
        // is that same two-attachments corruption — and it used to build, since the guard only
        // compared extra disks against each other (finding
        // `rootfs-image-escapes-boundary-validation`).
        let mut extra_disk_images = std::collections::HashSet::new();
        extra_disk_images.insert(self.rootfs.effective_image().to_path_buf());
        for disk in &self.extra_disks {
            if disk.image.as_os_str().is_empty() {
                return Err(crate::error::Error::Config(
                    "extra disk image path cannot be empty".into(),
                ));
            }
            if disk.image.is_relative() {
                return Err(crate::error::Error::Config(format!(
                    "extra disk image {:?} must be an absolute path",
                    disk.image
                )));
            }
            if !extra_disk_images.insert(disk.image.clone()) {
                return Err(crate::error::Error::Config(format!(
                    "duplicate extra disk image: {} (already attached — as the root disk's \
                     backing file or as an earlier extra disk; two attachments of one image \
                     is a read-write corruption footgun)",
                    disk.image.display()
                )));
            }
            // Disk-I/O fault injection (§4.6, Extra virtio-blk devices and disk-I/O throttling): a limit must actually limit something, and
            // a set cap must be > 0 — a 0-byte/s or 0-IOPS bucket would wedge all I/O
            // (never refills), a silent deadlock. Reject both fail-loud at the boundary.
            if let Some(limit) = &disk.io_limit {
                if limit.bandwidth_bytes_per_sec.is_none() && limit.iops.is_none() {
                    return Err(crate::error::Error::Config(format!(
                        "extra disk {} has an io_limit that limits nothing (set bandwidth_bytes_per_sec and/or iops)",
                        disk.image.display()
                    )));
                }
                if limit.bandwidth_bytes_per_sec == Some(0) || limit.iops == Some(0) {
                    return Err(crate::error::Error::Config(format!(
                        "extra disk {} io_limit cap must be > 0 (a 0 cap would wedge all I/O)",
                        disk.image.display()
                    )));
                }
            }
        }

        // Host USB passthrough (§2.4, QEMU q35 — the fallback and most-proven nester), v30 §18 (Delta register) delta 9. QEMU's `usb-host`
        // selects by `(vendorid, productid)` and treats a **zero** id as *unset* — i.e.
        // "match any device on this axis" — so `vendorid=0x0000` would attach an
        // arbitrary host device instead of failing to find the requested one. Reject a
        // zero id at the boundary (honor-or-reject accepted input). A duplicate pair is
        // equally ambiguous: both `usb-host` devices would race for the ONE matching host
        // device, so the second silently gets nothing.
        let mut usb_ids = std::collections::HashSet::new();
        for dev in &self.usb_host_devices {
            if dev.vendor_id == 0 || dev.product_id == 0 {
                return Err(crate::error::Error::Config(format!(
                    "usb host device vendor_id/product_id must be non-zero (got \
                     {:#06x}:{:#06x}); QEMU reads a zero id as unset (match-any), not as a \
                     literal id",
                    dev.vendor_id, dev.product_id
                )));
            }
            if !usb_ids.insert((dev.vendor_id, dev.product_id)) {
                return Err(crate::error::Error::Config(format!(
                    "duplicate usb host device: {:#06x}:{:#06x}",
                    dev.vendor_id, dev.product_id
                )));
            }
        }

        // A custom `init=` override is a single load-bearing cmdline token selecting
        // PID 1, so it is validated at the boundary (§5.3, The kernel command line): absolute, UTF-8, no
        // whitespace/control chars that could forge a second boot token.
        if let Some(init) = &self.init {
            validate_init_path(init).map_err(crate::error::Error::Config)?;
        }

        // Append-only extra kernel args: each a single safe token whose key does not
        // collide with a reserved boot token vmcell owns (§5.3, The kernel command line).
        for arg in &self.extra_kernel_args {
            validate_extra_kernel_arg(arg).map_err(crate::error::Error::Config)?;
        }

        // The resource prefix becomes part of a netns / interface / cgroup / directory name, so an
        // invalid one is rejected fail-loud at construction (never silently sanitized).
        crate::naming::validate_resource_prefix(&self.resource_prefix)
            .map_err(crate::error::Error::Config)?;

        // §6.5 (VM-to-VM segments): one prefix must name every resource in the domain, or the F2
        // name/sweep lockstep splits across two prefixes — this member's tap would be created in a
        // namespace swept under a different filter, so a leak would never be reclaimed.
        if let NetConfig::Segment { segment } = &self.net
            && segment.prefix() != self.resource_prefix
        {
            return Err(crate::error::Error::Config(format!(
                "a segment member's resource_prefix ({:?}) must equal the prefix its segment was \
                 created with ({:?}): one prefix names and sweeps every resource in the domain",
                self.resource_prefix,
                segment.prefix()
            )));
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
            vsock_transport: self.vsock_transport,
            vmid: self.vmid,
            restore_mode: self.restore_mode,
            ksm_mergeable: self.ksm_mergeable,
            kernel_verbosity: self.kernel_verbosity,
            // Not re-`clamped()` here on purpose: clamping is single-sourced on the
            // `.timeouts()` setter, and the orchestrator re-clamps at `start()`
            // (M-ORCH-3) to catch post-`build()` mutation of this `pub` field. A
            // `.clamped()` here would be a redundant third copy of that one law.
            timeouts: self.timeouts,
            console_mode: self.console_mode,
            resource_prefix: self.resource_prefix,
            extra_disks: self.extra_disks,
            usb_host_devices: self.usb_host_devices,
            extra_kernel_args: self.extra_kernel_args,
            init: self.init,
            vmm_seccomp: self.vmm_seccomp,
            jail: self.jail,
            required_features: self.required_features,
            steward_placement: placement,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// The `PerVmResources` a non-segment VM with `vmid` is handed, for the cmdline tests.
    fn test_res(vmid: u32) -> crate::vmm::PerVmResources {
        crate::vmm::PerVmResources {
            cgroup_name: format!("vmcell-vm-{vmid}"),
            tap_name: None,
            netns_name: None,
            segment: None,
            vhost_user_socket: None,
            vmid,
            guest_cid: 3,
            tmp_dir: PathBuf::from(format!("/tmp/vmcell-vm-test-{vmid}")),
        }
    }

    /// The same, for a VM that is member `slot` of segment `segid`.
    fn test_res_in_segment(vmid: u32, segid: u32, slot: u32) -> crate::vmm::PerVmResources {
        crate::vmm::PerVmResources {
            segment: Some(crate::net::SegmentMembership {
                netns: crate::naming::segment_netns_name("vmcell", segid),
                tap_name: crate::naming::tap_name("vmcell", vmid),
                segid,
                slot,
            }),
            tap_name: Some(crate::naming::tap_name("vmcell", vmid)),
            netns_name: Some(crate::naming::segment_netns_name("vmcell", segid)),
            ..test_res(vmid)
        }
    }

    #[test]
    fn test_builder_defaults() {
        let cfg = VmConfig::builder(
            PathBuf::from("/vmlinux"),
            RootfsSource::Erofs {
                image: PathBuf::from("/rootfs.erofs"),
            },
        )
        .build()
        .unwrap();
        assert_eq!(cfg.vcpus, 1);
        assert_eq!(cfg.mem_mib, 128);
        assert!(!cfg.nested_virt);
    }

    // Guards the §8.2 (Restore correctness: a restored VM is not a fresh VM) eager-vs-lazy restore toggle: the builder must carry the
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

    // Guards the §8.3 (Density levers) KSM density lever: the builder must carry `ksm_mergeable`
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
            RootfsSource::Erofs {
                image: PathBuf::from("/rootfs.erofs"),
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

    // L-ORCH-6: the negative tests pin {0, 255, 32, 0-vcpu}, but an over-strict
    // impl (`vmid <= 1`, `mem_mib <= 64`) would also pass them. Pin the accepted
    // boundaries so shrinking the valid window one notch goes red here.
    #[test]
    fn accept_boundary_vmid_and_mem() {
        let mk = |f: &dyn Fn(VmConfigBuilder) -> VmConfigBuilder| {
            f(VmConfig::builder(
                PathBuf::from("/vmlinux"),
                RootfsSource::Erofs {
                    image: PathBuf::from("/rootfs.erofs"),
                },
            ))
            .build()
        };
        mk(&|b| b.vmid(1)).expect("vmid 1 is in range");
        mk(&|b| b.vmid(254)).expect("vmid 254 is in range");
        mk(&|b| b.mem_mib(64)).expect("mem_mib 64 is at the floor");
    }

    // Design §18 (Delta register) delta 4: `host_services_port` lives only on `NetConfig::Unprivileged` — a
    // privileged config carrying it is now a COMPILE error (the field was removed from the
    // `Privileged` variant), so the former "rejected on privileged" negative test is deleted as
    // unreachable. What remains is the positive control: the unprivileged path accepts the port.
    #[test]
    fn unprivileged_host_services_port_is_supported() {
        VmConfig::builder(
            PathBuf::from("/vmlinux"),
            RootfsSource::Erofs {
                image: PathBuf::from("/rootfs.erofs"),
            },
        )
        .net(NetConfig::Unprivileged {
            egress: Egress::Open,
            host_services_port: Some(8080),
        })
        .build()
        .expect("unprivileged host_services_port is supported");
    }

    // F1 (residual half of `M1`): `Egress::Blocked` + `host_services_port` is an invalid state
    // the type permits, and it used to build — the port was then silently unused, because
    // `nat_egress_plan` registers no forward under `Blocked`. An accepted input that no datapath
    // reads is the defect class M1 records, so it is refused at construction, naming BOTH fields
    // so the caller knows which one to drop.
    //
    // Buggy impl this guards: a `build()` that accepts the pair (i.e. deleting the check), and
    // — via the positive controls — one that over-rejects by refusing the port outright or
    // refusing `Blocked` itself.
    #[test]
    fn blocked_egress_with_a_host_services_port_is_refused() {
        let mk = |egress: Egress, port: Option<u16>| {
            VmConfig::builder(
                PathBuf::from("/vmlinux"),
                RootfsSource::Erofs {
                    image: PathBuf::from("/rootfs.erofs"),
                },
            )
            .net(NetConfig::Unprivileged {
                egress,
                host_services_port: port,
            })
            .build()
        };

        let err = mk(Egress::Blocked, Some(8080))
            .expect_err("`Blocked` + host_services_port must be refused, not silently ignored");
        let msg = err.to_string();
        assert!(
            msg.contains("host_services_port") && msg.contains("Blocked"),
            "the refusal must name BOTH fields so the caller knows what to change: {msg}"
        );

        // Positive controls: the port is honored on both variants that can reach it, and
        // `Blocked` on its own is a perfectly valid config.
        mk(Egress::Open, Some(8080)).expect("`Open` + host_services_port is the reachable pair");
        mk(Egress::Filtered(ProxyConfig::default()), Some(8080))
            .expect("`Filtered` + host_services_port is the reachable pair");
        mk(Egress::Blocked, None).expect("`Blocked` with no port is valid");
    }

    // L-ORCH-7: an empty or relative `host_path` is a boundary config error, not a
    // late virtiofsd-spawn subprocess failure. Buggy impl: `build()` accepts it.
    #[test]
    fn reject_bad_share_host_path() {
        for bad in ["", "rel/path"] {
            let err = VmConfig::builder(
                PathBuf::from("/vmlinux"),
                RootfsSource::Erofs {
                    image: PathBuf::from("/rootfs.erofs"),
                },
            )
            .with_share(Share::new("s", bad, Access::ReadOnly, CachePolicy::Auto))
            .build()
            .unwrap_err();
            assert!(
                matches!(err, crate::error::Error::Config(_)),
                "host_path {bad:?} must be rejected as a config error"
            );
            assert!(err.to_string().contains("host_path"));
        }
    }

    // The Erofs rootfs still builds a bootable `rootfstype=erofs` cmdline line
    // (the VirtioFs variant this test also guarded against is gone — design §18 (Delta register)
    // delta 5 — making that rejection a compile-time unrepresentable state).
    #[test]
    fn erofs_rootfs_cmdline_build() {
        let ok = VmConfig::builder(
            PathBuf::from("/vmlinux"),
            RootfsSource::Erofs {
                image: PathBuf::from("/rootfs.erofs"),
            },
        )
        .build()
        .unwrap();
        let c = build_kernel_cmdline(&ok, &test_res(1), "").unwrap();
        assert!(c.contains("rootfstype=erofs"), "{c}");
        // An Erofs root is read-only with no journal to replay, so `rootflags=noload`
        // (a Block-rootfs token) must be ABSENT. A refactor emitting it
        // unconditionally diverges from the RO erofs contract; this reddens on that.
        assert!(
            !c.contains("rootflags"),
            "Erofs rootfs must not emit rootflags: {c}"
        );
    }

    // M-HOST-4: out-of-range resource-limit values are rejected at build() so they
    // surface as a typed Config error, not a misattributed CapabilityUnavailable at
    // the cgroup write. RED if the boundary validation is absent (build returns Ok).
    #[test]
    fn reject_bad_resource_limits() {
        let mk = |limits: ResourceLimits| {
            VmConfig::builder(
                PathBuf::from("/vmlinux"),
                RootfsSource::Erofs {
                    image: PathBuf::from("/rootfs.erofs"),
                },
            )
            .limits(limits)
            .build()
        };
        let bad = [
            ResourceLimits {
                cpu_max_pct: Some(0),
                ..Default::default()
            },
            ResourceLimits {
                mem_max_mib: Some(0),
                ..Default::default()
            },
            ResourceLimits {
                pids_max: Some(0),
                ..Default::default()
            },
            ResourceLimits {
                io_max: Some(IoMax {
                    device: "notadev".into(),
                    ..Default::default()
                }),
                ..Default::default()
            },
            // Malformed maj:min sub-branches: empty major, empty minor, and a
            // non-digit minor. A "simplify" to `split_once(':').is_some()` would
            // accept `"8:x"` (it reaches the cgroup write as EINVAL, the exact
            // M-HOST-4 masquerade), so each must red here.
            ResourceLimits {
                io_max: Some(IoMax {
                    device: ":0".into(),
                    ..Default::default()
                }),
                ..Default::default()
            },
            ResourceLimits {
                io_max: Some(IoMax {
                    device: "8:".into(),
                    ..Default::default()
                }),
                ..Default::default()
            },
            ResourceLimits {
                io_max: Some(IoMax {
                    device: "8:x".into(),
                    ..Default::default()
                }),
                ..Default::default()
            },
        ];
        for limits in bad {
            assert!(
                matches!(mk(limits.clone()), Err(crate::error::Error::Config(_))),
                "limits {limits:?} must be rejected"
            );
        }
        // Valid limits still build (including a well-formed maj:min device).
        mk(ResourceLimits {
            cpu_max_pct: Some(50),
            mem_max_mib: Some(128),
            pids_max: Some(64),
            io_max: Some(IoMax {
                device: "8:0".into(),
                rbps: Some(1000),
                ..Default::default()
            }),
        })
        .expect("valid limits must build");
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
    // (§4.5, Shared directories (virtio-fs)); `:` or whitespace in a tag would corrupt that token and silently
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
    // tags are caller-defined (§4.5, Shared directories (virtio-fs)), not restricted to the old `imp-*` set.
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

    // Finding `share-tag-path-separator-escapes-scratch-dir`: the tag also names a host file —
    // `fs::VirtioFsDaemon::start_paced` builds `<vm_tmp>/<tag>.sock` — so a tag carrying a path
    // separator makes virtiofsd create-and-truncate a caller-chosen file OUTSIDE the per-VM
    // scratch dir, where teardown never sweeps it. None of these tags contain ':' or
    // whitespace, so the pre-existing cmdline-encoding check cannot see them; only the
    // single-normal-component rule can. Buggy impl this guards: dropping that rule (the
    // ':'/whitespace check alone) — every case below then builds.
    #[test]
    fn test_reject_share_tag_with_path_separator() {
        for bad in ["..", "a/b", "/abs", ".", "../../etc/x", "a/"] {
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
                err.to_string().contains("single normal path component"),
                "tag {bad:?} error should explain the scratch-dir constraint: {err}"
            );
        }
        // Positive control (over-rejection inverse): an ordinary tag — which IS a single
        // normal component — still builds and still names the socket.
        let cfg = VmConfig::builder(
            PathBuf::from("/vmlinux"),
            RootfsSource::Erofs {
                image: PathBuf::from("/rootfs.erofs"),
            },
        )
        .with_share(Share::new(
            "data",
            "/tmp/a",
            Access::ReadOnly,
            CachePolicy::Auto,
        ))
        .build()
        .expect("an ordinary single-component tag must still build");
        assert_eq!(cfg.shares[0].tag, "data");
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

    // M-RESTORE-3: the §8.1 (The warm-snapshot path and the eligibility law) snapshot-eligibility law's third boundary case.
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
        })
        .snapshotting(true)
        .build()
        .unwrap();
        assert!(cfg.snapshotting);
        assert!(matches!(cfg.net, NetConfig::Privileged { .. }));
    }

    // Task B: the default vsock transport is `Auto` and the builder carries an
    // explicit choice onto the built config. RED on the inverse (a builder that drops
    // the field, or a wrong default).
    #[test]
    fn vsock_transport_default_is_auto_and_builder_carries_it() {
        let default_cfg = VmConfig::builder(
            PathBuf::from("/vmlinux"),
            RootfsSource::Erofs {
                image: PathBuf::from("/rootfs.erofs"),
            },
        )
        .build()
        .unwrap();
        assert_eq!(default_cfg.vsock_transport, VsockTransport::Auto);

        let in_kernel = VmConfig::builder(
            PathBuf::from("/vmlinux"),
            RootfsSource::Erofs {
                image: PathBuf::from("/rootfs.erofs"),
            },
        )
        .vsock_transport(VsockTransport::InKernel)
        .build()
        .unwrap();
        assert_eq!(in_kernel.vsock_transport, VsockTransport::InKernel);
    }

    // Task B: snapshotting requires the migratable in-kernel transport, so an EXPLICIT
    // `ExternalDaemon` is a fail-loud contradiction (not silently overridden). RED on
    // the inverse (a build() that accepts the combination, or silently flips it).
    #[test]
    fn build_rejects_snapshotting_with_external_daemon_vsock() {
        let err = VmConfig::builder(
            PathBuf::from("/vmlinux"),
            RootfsSource::Erofs {
                image: PathBuf::from("/rootfs.erofs"),
            },
        )
        .snapshotting(true)
        .vsock_transport(VsockTransport::ExternalDaemon)
        .build()
        .unwrap_err();
        assert!(matches!(err, crate::error::Error::Config(_)));
        assert!(
            err.to_string().contains("ExternalDaemon"),
            "unexpected error: {err}"
        );
    }

    // Task B over-rejection guard: snapshotting with `Auto` (default) and with an
    // explicit `InKernel` must BOTH build — only `ExternalDaemon` is the contradiction.
    // RED on an over-broad reject that blocks the in-kernel/auto snapshot path.
    #[test]
    fn build_accepts_snapshotting_with_inkernel_and_auto() {
        for transport in [VsockTransport::Auto, VsockTransport::InKernel] {
            let cfg = VmConfig::builder(
                PathBuf::from("/vmlinux"),
                RootfsSource::Erofs {
                    image: PathBuf::from("/rootfs.erofs"),
                },
            )
            .snapshotting(true)
            .vsock_transport(transport)
            .build()
            .unwrap_or_else(|e| panic!("snapshotting + {transport:?} must build, got {e}"));
            assert!(cfg.snapshotting);
            assert_eq!(cfg.vsock_transport, transport);
        }
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
        })
        .ksm_mergeable(true)
        .build()
        .unwrap();
        assert!(cfg.ksm_mergeable);
    }

    // §5.3 (The kernel command line) UART tax lever: each verbosity maps to its `loglevel=` number. Buggy
    // impl this guards: an off-by-one or a swapped arm (e.g. Balanced→7, or
    // Verbose→6) — any wrong mapping turns one of these equalities red.
    #[test]
    fn kernel_verbosity_loglevel_mapping() {
        assert_eq!(KernelVerbosity::Quiet.loglevel(), 3);
        assert_eq!(KernelVerbosity::Balanced.loglevel(), 6);
        assert_eq!(KernelVerbosity::Verbose.loglevel(), 7);
        assert_eq!(KernelVerbosity::Debug.loglevel(), 8);
    }

    // §9.4 (Timeouts and the lifecycle nuances) timing presets: `low_latency` tightens the connect/accept cadence but
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

        let plain = build_kernel_cmdline(&cfg, &test_res(1), "").unwrap();
        let fpu = build_kernel_cmdline(&cfg, &test_res(1), "noxsave ").unwrap();
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
                c.contains("init=/usr/sbin/vmcell-steward"),
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
        let vc = build_kernel_cmdline(&verbose, &test_res(1), "").unwrap();
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
        let hvc = build_kernel_cmdline(&virtio, &test_res(1), "").unwrap();
        assert!(
            hvc.starts_with("console=hvc0"),
            "VirtioConsole must emit console=hvc0 first: {hvc}"
        );
        assert!(
            !hvc.contains("console=ttyS0"),
            "VirtioConsole must not emit ttyS0: {hvc}"
        );
    }

    // §5.3 (The kernel command line) console knob: each mode maps to its `console=` token. Buggy impl this
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

    // §4.6 (Extra virtio-blk devices and disk-I/O throttling): BlockDevice constructors set the readonly flag; a swapped arm (read_only
    // marking rw, or vice versa) reddens here.
    #[test]
    fn block_device_constructors() {
        let ro = BlockDevice::read_only("/img/data.raw");
        assert_eq!(ro.image, PathBuf::from("/img/data.raw"));
        assert!(ro.readonly);
        let rw = BlockDevice::read_write("/img/scratch.raw");
        assert!(!rw.readonly);
    }

    // §4.6 (Extra virtio-blk devices and disk-I/O throttling): the builder carries extra_disks onto the built config in order, default
    // empty. Buggy impl: the builder drops the field.
    #[test]
    fn builder_carries_extra_disks() {
        let empty = VmConfig::builder(
            PathBuf::from("/vmlinux"),
            RootfsSource::Erofs {
                image: PathBuf::from("/rootfs.erofs"),
            },
        )
        .build()
        .unwrap();
        assert!(empty.extra_disks.is_empty());

        let cfg = VmConfig::builder(
            PathBuf::from("/vmlinux"),
            RootfsSource::Erofs {
                image: PathBuf::from("/rootfs.erofs"),
            },
        )
        .with_extra_disk(BlockDevice::read_only("/img/a.raw"))
        .with_extra_disk(BlockDevice::read_write("/img/b.raw"))
        .build()
        .unwrap();
        assert_eq!(cfg.extra_disks.len(), 2);
        assert_eq!(cfg.extra_disks[0].image, PathBuf::from("/img/a.raw"));
        assert!(cfg.extra_disks[0].readonly);
        assert_eq!(cfg.extra_disks[1].image, PathBuf::from("/img/b.raw"));
        assert!(!cfg.extra_disks[1].readonly);
    }

    // §4.6 (Extra virtio-blk devices and disk-I/O throttling): build() rejects an empty / relative / duplicate extra-disk image. Buggy
    // impl: any of these reaches create() and fails late (or attaches one file twice).
    #[test]
    fn reject_bad_extra_disk_image() {
        let mk = |disk: BlockDevice| {
            VmConfig::builder(
                PathBuf::from("/vmlinux"),
                RootfsSource::Erofs {
                    image: PathBuf::from("/rootfs.erofs"),
                },
            )
            .with_extra_disk(disk)
            .build()
        };
        for (disk, needle) in [
            (BlockDevice::read_only(""), "cannot be empty"),
            (BlockDevice::read_only("rel/img.raw"), "absolute path"),
        ] {
            let err = mk(disk).unwrap_err();
            assert!(
                matches!(err, crate::error::Error::Config(_)) && err.to_string().contains(needle),
                "expected {needle:?}, got {err}"
            );
        }
        // Duplicate backing file across two attachments is a rw corruption footgun.
        let err = VmConfig::builder(
            PathBuf::from("/vmlinux"),
            RootfsSource::Erofs {
                image: PathBuf::from("/rootfs.erofs"),
            },
        )
        .with_extra_disk(BlockDevice::read_write("/img/dup.raw"))
        .with_extra_disk(BlockDevice::read_only("/img/dup.raw"))
        .build()
        .unwrap_err();
        assert!(
            matches!(err, crate::error::Error::Config(_))
                && err.to_string().contains("duplicate extra disk image"),
            "{err}"
        );
    }

    // §4.6 (Extra virtio-blk devices and disk-I/O throttling) positive control: a valid extra disk with an absolute path builds — the
    // over-rejection inverse (rejecting every extra disk) reddens here.
    #[test]
    fn accept_valid_extra_disk() {
        VmConfig::builder(
            PathBuf::from("/vmlinux"),
            RootfsSource::Erofs {
                image: PathBuf::from("/rootfs.erofs"),
            },
        )
        .with_extra_disk(BlockDevice::read_only("/img/data.raw"))
        .build()
        .expect("a valid absolute extra-disk image must build");
    }

    // Finding `rootfs-image-escapes-boundary-validation`, half 1: the duplicate-backing-file
    // guard used to compare extra disks against each other ONLY, so an extra disk naming the
    // root disk's backing file built — two attachments of one image, the exact rw corruption
    // the guard's own comment names. The expected path is recomputed through the one law
    // (`RootfsSource::effective_image`), never a test-local literal. Buggy impl this guards:
    // dropping the seed insert — every rejection below then builds.
    #[test]
    fn extra_disk_cannot_alias_the_root_disk_backing_file() {
        for rootfs in [
            RootfsSource::Erofs {
                image: PathBuf::from("/img/root.erofs"),
            },
            RootfsSource::Block {
                image: PathBuf::from("/img/root.raw"),
                overlay: None,
            },
            // With an overlay set, the OVERLAY is what every backend attaches as /dev/vda —
            // so that is the path an extra disk may not alias.
            RootfsSource::Block {
                image: PathBuf::from("/img/root.raw"),
                overlay: Some(PathBuf::from("/img/overlay.raw")),
            },
        ] {
            let root = rootfs.effective_image().to_path_buf();
            let err = VmConfig::builder(PathBuf::from("/vmlinux"), rootfs)
                .with_extra_disk(BlockDevice::read_write(&root))
                .build()
                .unwrap_err();
            assert!(
                matches!(err, crate::error::Error::Config(_))
                    && err.to_string().contains("duplicate extra disk image")
                    && err.to_string().contains(&root.display().to_string()),
                "an extra disk aliasing the root backing file {root:?} must be rejected: {err}"
            );
        }
        // Positive control (over-rejection inverse): a distinct extra disk alongside the same
        // root still builds.
        VmConfig::builder(
            PathBuf::from("/vmlinux"),
            RootfsSource::Block {
                image: PathBuf::from("/img/root.raw"),
                overlay: None,
            },
        )
        .with_extra_disk(BlockDevice::read_write("/img/data.raw"))
        .build()
        .expect("an extra disk with its own backing file must build");
    }

    // Finding `rootfs-image-escapes-boundary-validation`, half 2: the rootfs image/overlay are
    // host path inputs like any other, so they get the same empty/relative boundary checks the
    // share and extra-disk paths get — instead of failing late as a VMM "cannot open image".
    // Buggy impl this guards: dropping the rootfs path loop — every case below then builds.
    #[test]
    fn rootfs_paths_are_validated_at_the_boundary() {
        for (rootfs, needle) in [
            (
                RootfsSource::Erofs {
                    image: PathBuf::new(),
                },
                "image path cannot be empty",
            ),
            (
                RootfsSource::Erofs {
                    image: PathBuf::from("rel/rootfs.erofs"),
                },
                "must be an absolute path",
            ),
            (
                RootfsSource::Block {
                    image: PathBuf::from("rel/root.raw"),
                    overlay: None,
                },
                "must be an absolute path",
            ),
            (
                RootfsSource::Block {
                    image: PathBuf::from("/img/root.raw"),
                    overlay: Some(PathBuf::new()),
                },
                "overlay path cannot be empty",
            ),
            (
                RootfsSource::Block {
                    image: PathBuf::from("/img/root.raw"),
                    overlay: Some(PathBuf::from("rel/overlay.raw")),
                },
                "must be an absolute path",
            ),
        ] {
            let err = VmConfig::builder(PathBuf::from("/vmlinux"), rootfs)
                .build()
                .unwrap_err();
            assert!(
                matches!(err, crate::error::Error::Config(_)) && err.to_string().contains(needle),
                "expected {needle:?}, got {err}"
            );
        }
        // Positive control: absolute image + absolute overlay build.
        VmConfig::builder(
            PathBuf::from("/vmlinux"),
            RootfsSource::Block {
                image: PathBuf::from("/img/root.raw"),
                overlay: Some(PathBuf::from("/img/overlay.raw")),
            },
        )
        .build()
        .expect("absolute rootfs image + overlay must build");
    }

    // §2.4 (QEMU q35 — the fallback and most-proven nester), v30 §18 (Delta register) delta 9, rejection 1: a passed-through host USB
    // device is host state outside guest RAM, so it cannot ride the migration stream —
    // `snapshotting` + USB must be refused at the boundary. Buggy impl this guards: the
    // snapshotting block omits the USB arm, so the config builds and the VM snapshots
    // into an image that silently loses the device on restore.
    #[test]
    fn reject_usb_host_device_with_snapshot() {
        let err = VmConfig::builder(
            PathBuf::from("/vmlinux"),
            RootfsSource::Erofs {
                image: PathBuf::from("/rootfs.erofs"),
            },
        )
        .with_usb_host_device(UsbHostDevice::new(0x1d6b, 0x0002))
        .snapshotting(true)
        .build()
        .unwrap_err();
        assert!(matches!(err, crate::error::Error::Config(_)));
        assert!(
            err.to_string()
                .contains("host USB passthrough cannot be combined with snapshotting"),
            "unexpected error: {err}"
        );
    }

    // §2.4 (QEMU q35 — the fallback and most-proven nester), v30 §18 (Delta register) delta 9, rejection 2: a zero id is QEMU's *unset*
    // sentinel (match-any), not a literal id, so it would attach an ARBITRARY host
    // device; a duplicate `(vendor_id, product_id)` pair is equally ambiguous (two
    // `usb-host` devices racing for the one match). Buggy impl this guards: the id loop
    // is absent, so `0x0000:0x0000` builds and QEMU grabs whatever it finds first.
    #[test]
    fn reject_bad_usb_host_device() {
        let mk = |devs: &[UsbHostDevice]| {
            let mut b = VmConfig::builder(
                PathBuf::from("/vmlinux"),
                RootfsSource::Erofs {
                    image: PathBuf::from("/rootfs.erofs"),
                },
            );
            for d in devs {
                b = b.with_usb_host_device(*d);
            }
            b.build()
        };
        for (devs, needle) in [
            (vec![UsbHostDevice::new(0, 0x0002)], "must be non-zero"),
            (vec![UsbHostDevice::new(0x1d6b, 0)], "must be non-zero"),
            (
                vec![
                    UsbHostDevice::new(0x1d6b, 0x0002),
                    UsbHostDevice::new(0x1d6b, 0x0002),
                ],
                "duplicate usb host device",
            ),
        ] {
            let err = mk(&devs).unwrap_err();
            assert!(
                matches!(err, crate::error::Error::Config(_)) && err.to_string().contains(needle),
                "expected {needle:?}, got {err}"
            );
        }
    }

    // §2.4 (QEMU q35 — the fallback and most-proven nester) positive control for both rejections above: two DISTINCT non-zero devices
    // on a non-snapshotting config build, and land on `VmConfig` in call order. The
    // over-rejection inverse (refusing every USB device, or keying the duplicate check on
    // the vendor id alone) reddens here.
    #[test]
    fn accept_valid_usb_host_devices() {
        let cfg = VmConfig::builder(
            PathBuf::from("/vmlinux"),
            RootfsSource::Erofs {
                image: PathBuf::from("/rootfs.erofs"),
            },
        )
        .with_usb_host_device(UsbHostDevice::new(0x1d6b, 0x0002))
        .with_usb_host_device(UsbHostDevice::new(0x1d6b, 0x0003))
        .build()
        .expect("two distinct non-zero USB devices must build");
        assert_eq!(
            cfg.usb_host_devices,
            vec![
                UsbHostDevice::new(0x1d6b, 0x0002),
                UsbHostDevice::new(0x1d6b, 0x0003)
            ],
            "the builder must carry the devices through in call order"
        );
    }

    // §4.6 (Extra virtio-blk devices and disk-I/O throttling): DiskIoLimit constructors set the intended cap and leave the other unset; a
    // swapped arm (bandwidth() setting iops) reddens here.
    #[test]
    fn disk_io_limit_constructors() {
        let bw = DiskIoLimit::bandwidth(1_048_576);
        assert_eq!(bw.bandwidth_bytes_per_sec, Some(1_048_576));
        assert_eq!(bw.iops, None);
        let ops = DiskIoLimit::iops(500);
        assert_eq!(ops.iops, Some(500));
        assert_eq!(ops.bandwidth_bytes_per_sec, None);
    }

    // §4.6 (Extra virtio-blk devices and disk-I/O throttling): `with_io_limit` carries the limit onto the built disk; default is None.
    #[test]
    fn builder_carries_disk_io_limit() {
        let cfg = VmConfig::builder(
            PathBuf::from("/vmlinux"),
            RootfsSource::Erofs {
                image: PathBuf::from("/rootfs.erofs"),
            },
        )
        .with_extra_disk(BlockDevice::read_only("/img/plain.raw"))
        .with_extra_disk(
            BlockDevice::read_write("/img/slow.raw")
                .with_io_limit(DiskIoLimit::bandwidth(2_000_000)),
        )
        .build()
        .unwrap();
        assert_eq!(cfg.extra_disks[0].io_limit, None);
        assert_eq!(
            cfg.extra_disks[1].io_limit,
            Some(DiskIoLimit::bandwidth(2_000_000))
        );
    }

    // §4.6 (Extra virtio-blk devices and disk-I/O throttling): build() rejects an io_limit that limits nothing, or a 0 cap (which would
    // wedge all I/O — a silent deadlock). A genuine cap builds. Buggy impl: either is
    // accepted and the VM boots with a dead or no-op limiter.
    #[test]
    fn reject_bad_disk_io_limit() {
        let mk = |limit: DiskIoLimit| {
            VmConfig::builder(
                PathBuf::from("/vmlinux"),
                RootfsSource::Erofs {
                    image: PathBuf::from("/rootfs.erofs"),
                },
            )
            .with_extra_disk(BlockDevice::read_only("/img/d.raw").with_io_limit(limit))
            .build()
        };
        // Limits nothing.
        assert!(matches!(
            mk(DiskIoLimit::default()),
            Err(crate::error::Error::Config(_))
        ));
        // Zero caps.
        assert!(matches!(
            mk(DiskIoLimit::bandwidth(0)),
            Err(crate::error::Error::Config(_))
        ));
        assert!(matches!(
            mk(DiskIoLimit::iops(0)),
            Err(crate::error::Error::Config(_))
        ));
        // A real cap (both fields) builds.
        mk(DiskIoLimit {
            bandwidth_bytes_per_sec: Some(1_000_000),
            iops: Some(1000),
        })
        .expect("a genuine io_limit must build");
    }

    // §5.3 (The kernel command line): the builder carries the init override and defaults to None. Buggy impl:
    // the builder drops the field.
    #[test]
    fn builder_carries_init_override() {
        let default_cfg = VmConfig::builder(
            PathBuf::from("/vmlinux"),
            RootfsSource::Erofs {
                image: PathBuf::from("/rootfs.erofs"),
            },
        )
        .build()
        .unwrap();
        assert_eq!(default_cfg.init, None);

        let custom = VmConfig::builder(
            PathBuf::from("/vmlinux"),
            RootfsSource::Erofs {
                image: PathBuf::from("/rootfs.erofs"),
            },
        )
        .init("/bin/sh")
        .build()
        .unwrap();
        assert_eq!(custom.init, Some(PathBuf::from("/bin/sh")));
    }

    // §5.3 (The kernel command line): `validate_init_path` rejects a relative path, whitespace, and control
    // chars (a space forges a second cmdline token); accepts a clean absolute path.
    #[test]
    fn init_path_validation() {
        validate_init_path(std::path::Path::new("/sbin/my-init"))
            .expect("a clean absolute init path is valid");
        for bad in [
            "rel/init",
            "/bin/sh -c evil",
            "/bin/\tsh",
            "/bin/sh\nroot=/dev/x",
        ] {
            assert!(
                validate_init_path(std::path::Path::new(bad)).is_err(),
                "init path {bad:?} must be rejected"
            );
        }
        // A non-UTF-8 init path is unencodable on the kernel cmdline and must be
        // rejected. Guards a regression from `to_str().ok_or_else(..)` to
        // `to_string_lossy()`, which never fails and would silently emit U+FFFD.
        {
            use std::os::unix::ffi::OsStrExt;
            let non_utf8 = std::path::Path::new(std::ffi::OsStr::from_bytes(b"/bin/\xff"));
            assert!(
                validate_init_path(non_utf8).is_err(),
                "a non-UTF-8 init path must be rejected"
            );
        }
    }

    // §5.3 (The kernel command line): build() rejects snapshotting + a custom init (the post-restore resync
    // needs the steward a custom init replaces). Buggy impl: the combination builds and
    // a restored clone silently strands on frozen identity.
    #[test]
    fn reject_snapshot_with_custom_init() {
        let err = VmConfig::builder(
            PathBuf::from("/vmlinux"),
            RootfsSource::Erofs {
                image: PathBuf::from("/rootfs.erofs"),
            },
        )
        .init("/bin/sh")
        .snapshotting(true)
        .build()
        .unwrap_err();
        assert!(matches!(err, crate::error::Error::Config(_)));
        // v33 delta 4 re-keys this reject from `init.is_some()` onto the PLACEMENT's second C8
        // method, so the message names the placement. The rule is strictly narrower than before
        // (`Service` is now rejected explicitly rather than incidentally via `init`), and the
        // derived default still maps `init: Some` to `StewardPlacement::None`, which is what this
        // config gets — so the same input is still refused, for the reason it was always about.
        assert!(
            err.to_string()
                .contains("snapshotting requires the steward to run as PID 1"),
            "{err}"
        );
        // A custom init WITHOUT snapshotting must still build (over-rejection inverse).
        VmConfig::builder(
            PathBuf::from("/vmlinux"),
            RootfsSource::Erofs {
                image: PathBuf::from("/rootfs.erofs"),
            },
        )
        .init("/bin/sh")
        .build()
        .expect("a custom init without snapshotting must build");
    }

    // §5.3 (The kernel command line): `is_reserved_cmdline_arg` flags every token vmcell owns (by exact key or
    // the vmcell_ prefix) and lets a genuine custom arg through. Buggy impl: a missing
    // reserved key lets an extra arg clobber a load-bearing token.
    #[test]
    fn reserved_cmdline_arg_predicate() {
        for reserved in [
            "console=hvc0",
            "root=/dev/evil",
            "init=/bin/evil",
            "ip=1.2.3.4",
            "panic=0",
            "loglevel=8",
            "kvm-intel.nested=1",
            "ro",
            "vmcell_share=x:/x:rw",
            "vmcell_vmid=9",
            "vmcell_accept_poll_ms=0",
        ] {
            assert!(
                is_reserved_cmdline_arg(reserved),
                "{reserved:?} must be treated as reserved"
            );
        }
        for allowed in [
            "mitigations=off",
            "nokaslr",
            "systemd.unit=rescue.target",
            "foo.bar=baz",
        ] {
            assert!(
                !is_reserved_cmdline_arg(allowed),
                "{allowed:?} must be allowed as an append-only arg"
            );
        }
    }

    // Finding `f3-alias-clobber-gap`: F3 compares KEYS, so an alias of a token vmcell owns
    // slips through — it shares no key with what it overrides, which is exactly why the
    // `extra_kernel_args_cannot_clobber_reserved_tokens` coverage test (which walks emitted
    // tokens) structurally cannot discover these. `rw` inverts the owned `ro` (a Block root
    // mounted writable with `rootflags=noload` still suppressing journal replay); `quiet` /
    // `debug` / `ignore_loglevel` override the owned `loglevel=` because caller args go last.
    // Buggy impl this guards: the alias block missing from RESERVED_CMDLINE_KEYS.
    #[test]
    fn reserved_cmdline_keys_cover_owned_token_aliases() {
        for alias in ["rw", "quiet", "debug", "ignore_loglevel"] {
            assert!(
                is_reserved_cmdline_arg(alias),
                "{alias:?} aliases a token vmcell owns and must be reserved"
            );
            // …and the boundary must actually refuse it, not just the predicate.
            let err = VmConfig::builder(
                PathBuf::from("/vmlinux"),
                RootfsSource::Block {
                    image: PathBuf::from("/rootfs.img"),
                    overlay: None,
                },
            )
            .with_kernel_arg(alias)
            .build()
            .unwrap_err();
            assert!(
                matches!(err, crate::error::Error::Config(_))
                    && err
                        .to_string()
                        .contains("collides with a boot token vmcell owns"),
                "extra arg {alias:?} must be rejected at the boundary: {err}"
            );
        }
        // Positive control (over-rejection inverse): an unrelated append-only token that only
        // *resembles* the aliases still passes and is carried onto the cmdline.
        let cfg = VmConfig::builder(
            PathBuf::from("/vmlinux"),
            RootfsSource::Block {
                image: PathBuf::from("/rootfs.img"),
                overlay: None,
            },
        )
        .with_kernel_arg("quiet_boot=1")
        .with_kernel_arg("rwsem.debug=0")
        .build()
        .expect("an append-only arg that is not an owned-token alias must build");
        let c = build_kernel_cmdline(&cfg, &test_res(4), "").unwrap();
        assert!(c.ends_with(" quiet_boot=1 rwsem.debug=0"), "{c}");
    }

    // Finding `m1`: F3's alias law is spelled in terms of KEYS, and the kernel's own parser
    // folds `-` to `_` inside a parameter name (`kernel/params.c`'s `dash2underscore`, applied
    // by `parameq`/`parameqn`) — which is precisely why the `kvm-intel.nested=0` vmcell emits
    // binds a module parameter registered as `kvm_intel.nested`. A byte-exact membership test
    // therefore let the RESPELLING of every reserved key through (`kvm_intel.nested=1`,
    // `random.trust-cpu=off`, `ignore-loglevel`), and since caller args are appended LAST and
    // the kernel applies duplicates in order, the respelling overrode vmcell's own token.
    //
    // This iterates `RESERVED_CMDLINE_KEYS` itself rather than a hand-typed list, so a key
    // added to the const is covered in both spellings the day it lands. Buggy impl this
    // guards: `RESERVED_CMDLINE_KEYS.contains(&key)` on the raw key.
    #[test]
    fn reserved_cmdline_keys_are_refused_in_both_dash_and_underscore_spellings() {
        for reserved in RESERVED_CMDLINE_KEYS {
            for spelling in [reserved.replace('-', "_"), reserved.replace('_', "-")] {
                assert!(
                    is_reserved_cmdline_arg(&spelling),
                    "{spelling:?} is the kernel's own respelling of the reserved key \
                     {reserved:?} and must be refused"
                );
                assert!(
                    is_reserved_cmdline_arg(&format!("{spelling}=1")),
                    "{spelling:?}=1 must be refused: it overrides the owned {reserved:?} token"
                );
                // …and the boundary must actually refuse it, not just the predicate.
                let err = VmConfig::builder(
                    PathBuf::from("/vmlinux"),
                    RootfsSource::Block {
                        image: PathBuf::from("/rootfs.img"),
                        overlay: None,
                    },
                )
                .with_kernel_arg(format!("{spelling}=1"))
                .build()
                .unwrap_err();
                assert!(
                    matches!(err, crate::error::Error::Config(_))
                        && err
                            .to_string()
                            .contains("collides with a boot token vmcell owns"),
                    "extra arg {spelling:?}=1 must be rejected at the boundary: {err}"
                );
            }
        }
        // The `vmcell_*` prefix is steward-trusted and normalizes identically.
        assert!(
            is_reserved_cmdline_arg("vmcell-share=x:/x:rw"),
            "the dash respelling of a vmcell_ token is trusted by the steward too"
        );
        // Positive control (over-rejection inverse): keys that are NOT reserved stay
        // acceptable in both spellings — normalization must not swallow the whole namespace.
        for allowed in [
            "mitigations=off",
            "systemd.unit=rescue.target",
            "foo-bar.baz=1",
            "foo_bar.baz=1",
            "quiet_boot=1",
            "quiet-boot=1",
        ] {
            assert!(
                !is_reserved_cmdline_arg(allowed),
                "{allowed:?} collides with no owned token and must stay append-able"
            );
        }
    }

    // §5.3 (The kernel command line): build() rejects an extra arg that clobbers a reserved token, spoofs a
    // vmcell_ token, or carries whitespace; accepts a genuine custom arg.
    #[test]
    fn reject_bad_extra_kernel_arg() {
        let mk = |arg: &str| {
            VmConfig::builder(
                PathBuf::from("/vmlinux"),
                RootfsSource::Erofs {
                    image: PathBuf::from("/rootfs.erofs"),
                },
            )
            .with_kernel_arg(arg)
            .build()
        };
        for bad in [
            "root=/dev/evil",
            "init=/bin/evil",
            "vmcell_share=x:/x:rw",
            "has space",
            "",
        ] {
            let err = mk(bad).unwrap_err();
            assert!(
                matches!(err, crate::error::Error::Config(_)),
                "extra arg {bad:?} must be rejected: {err}"
            );
        }
        // A genuine append-only arg is accepted and carried in order.
        let cfg = VmConfig::builder(
            PathBuf::from("/vmlinux"),
            RootfsSource::Erofs {
                image: PathBuf::from("/rootfs.erofs"),
            },
        )
        .with_kernel_arg("mitigations=off")
        .with_kernel_arg("nokaslr")
        .build()
        .expect("valid append-only args must build");
        assert_eq!(cfg.extra_kernel_args, vec!["mitigations=off", "nokaslr"]);
    }

    // §5.3 (The kernel command line): the init override replaces the default `init=` token — exactly one
    // `init=`, and `root=`/`vmcell_vmid=` stay intact. Buggy impls: appending a second
    // `init=` alongside the default (a clobber + boot hazard), or ignoring the override.
    #[test]
    fn build_kernel_cmdline_honors_init_override() {
        let cfg = VmConfig::builder(
            PathBuf::from("/vmlinux"),
            RootfsSource::Erofs {
                image: PathBuf::from("/rootfs.erofs"),
            },
        )
        .init("/bin/sh")
        .network_disabled()
        .build()
        .unwrap();
        let c = build_kernel_cmdline(&cfg, &test_res(7), "").unwrap();
        assert!(c.contains("init=/bin/sh"), "override missing: {c}");
        assert!(
            !c.contains("init=/usr/sbin/vmcell-steward"),
            "default init must be replaced, not kept: {c}"
        );
        assert_eq!(
            c.matches("init=").count(),
            1,
            "exactly one init= token expected: {c}"
        );
        assert!(c.contains("root=/dev/vda"), "root token must remain: {c}");
        assert!(c.contains("vmcell_vmid=7"), "vmid token must remain: {c}");

        // The default (no override) still emits the steward (existing contract).
        let default_cfg = VmConfig::builder(
            PathBuf::from("/vmlinux"),
            RootfsSource::Erofs {
                image: PathBuf::from("/rootfs.erofs"),
            },
        )
        .network_disabled()
        .build()
        .unwrap();
        assert!(
            build_kernel_cmdline(&default_cfg, &test_res(1), "")
                .unwrap()
                .contains(&format!("init={DEFAULT_INIT}")),
            "default init token must be the steward"
        );
    }

    // §5.3 (The kernel command line): append-only args land AFTER every reserved token, in order. Buggy impl:
    // args spliced before the reserved block, or dropped.
    #[test]
    fn build_kernel_cmdline_appends_extra_args_last() {
        let cfg = VmConfig::builder(
            PathBuf::from("/vmlinux"),
            RootfsSource::Erofs {
                image: PathBuf::from("/rootfs.erofs"),
            },
        )
        .with_kernel_arg("mitigations=off")
        .with_kernel_arg("nokaslr")
        .network_disabled()
        .build()
        .unwrap();
        let c = build_kernel_cmdline(&cfg, &test_res(1), "").unwrap();
        assert!(
            c.ends_with(" mitigations=off nokaslr"),
            "extra args not last: {c}"
        );
        // The reserved tokens come strictly before the appended args.
        let init_at = c.find("init=").expect("init token present");
        let extra_at = c.find("mitigations=off").expect("extra arg present");
        assert!(
            init_at < extra_at,
            "extra args must follow the reserved block: {c}"
        );
    }

    // §5.3 (The kernel command line) the ONE-LAW GATE: every token `build_kernel_cmdline` emits has a reserved
    // key (or the vmcell_ prefix), so `is_reserved_cmdline_arg` — and hence the
    // append-only guard — can never fall out of sync with the builder. Add a new
    // builder token without reserving its key ⇒ this reddens.
    // ---- v30 §18 delta 8 (VM-to-VM segments) ----

    /// A `NetConfig::Segment` over a hermetic, kernel-free segment.
    fn fake_segment_config(prefix: &str) -> (crate::net::NetSegment, NetConfig) {
        let (seg, _env, _calls) = crate::net::segment::testing::fake_segment(prefix);
        let net = NetConfig::Segment {
            segment: seg.clone(),
        };
        (seg, net)
    }

    // `net_uses_tap` is the ONE predicate for "this datapath is a kernel tap in a netns", and it
    // is exhaustive in-crate. Buggy impl guarded: a `Segment` arm that answered `false` would let
    // `assert_tap_wiring_matches` accept a member with no tap (a guest with an unconfigurable
    // eth0 and no bridge port).
    #[test]
    fn net_uses_tap_covers_exactly_the_tap_datapaths() {
        let (_seg, segment_net) = fake_segment_config("vmcell");
        assert!(net_uses_tap(&NetConfig::Privileged {
            egress: Egress::Open
        }));
        assert!(net_uses_tap(&segment_net));
        assert!(!net_uses_tap(&NetConfig::Unprivileged {
            egress: Egress::Open,
            host_services_port: None
        }));
        assert!(!net_uses_tap(&NetConfig::None));
    }

    // The fail-loud post-condition the orchestrator runs after allocating resources. Buggy impl
    // guarded: a `Segment` arm in `setup_env` that forgot to set `tap_name` (or a NAT config that
    // set one) passes every other test and boots a silently-broken guest; this reddens.
    #[test]
    fn assert_tap_wiring_matches_rejects_both_mismatches() {
        let (_seg, segment_net) = fake_segment_config("vmcell");
        // Positive controls.
        assert!(assert_tap_wiring_matches(&segment_net, true).is_ok());
        assert!(
            assert_tap_wiring_matches(
                &NetConfig::Privileged {
                    egress: Egress::Open
                },
                true
            )
            .is_ok()
        );
        assert!(assert_tap_wiring_matches(&NetConfig::None, false).is_ok());
        // Both inverses are typed refusals, not silent acceptances.
        assert!(matches!(
            assert_tap_wiring_matches(&segment_net, false),
            Err(crate::error::Error::Network(_))
        ));
        assert!(matches!(
            assert_tap_wiring_matches(&NetConfig::None, true),
            Err(crate::error::Error::Network(_))
        ));
    }

    // §6.5: a member's `ip=` token is the SEGMENT /24 (gateway `.1`), not the per-VM /30 — read
    // from `res.segment`, the exhaustive-struct channel. Buggy impl guarded: a builder that kept
    // the `/30` branch for members hands the guest 10.200.x.2 with a 255.255.255.252 mask on a
    // bridge whose gateway is 10.201.<s>.1 — no route to any peer. Recomputed through
    // `segment_ip_math`, never a test-local literal.
    #[test]
    fn build_kernel_cmdline_emits_the_segment_subnet_for_a_member() {
        let (seg, segment_net) = fake_segment_config("vmcell");
        let cfg = VmConfig::builder(
            PathBuf::from("/vmlinux"),
            RootfsSource::Erofs {
                image: PathBuf::from("/rootfs.erofs"),
            },
        )
        .net(segment_net)
        .build()
        .expect("a segment config builds");

        let segid = seg.segid();
        let res = test_res_in_segment(5, segid, 2);
        let c = build_kernel_cmdline(&cfg, &res, "").unwrap();

        let (gateway, guest_ip, _) = crate::net::segment_ip_math(segid, 2).unwrap();
        assert!(
            c.contains(&format!(
                " ip={guest_ip}::{gateway}:255.255.255.0::eth0:off"
            )),
            "a segment member's ip= must carry the /24 and the bridge gateway: {c}"
        );
        // The per-VM /30 must NOT appear.
        let (host30, guest30, _) = crate::net::ip_math(5).unwrap();
        assert!(
            !c.contains(&format!(" ip={guest30}::{host30}")),
            "a member must not get the per-VM /30 token: {c}"
        );
        assert!(
            !c.contains("255.255.255.252"),
            "a member must not get the /30 netmask: {c}"
        );
        // Every emitted token is still reserved (law F3 holds on the segment path too).
        for token in c.split_ascii_whitespace() {
            assert!(
                is_reserved_cmdline_arg(token),
                "builder token {token:?} on the segment path is not reserved: {c}"
            );
        }
        // Positive control: the SAME config with no membership falls back to the /30.
        let plain = build_kernel_cmdline(&cfg, &test_res(5), "").unwrap();
        assert!(
            plain.contains(&format!(
                " ip={guest30}::{host30}:255.255.255.252::eth0:off"
            )),
            "a non-member must still get the per-VM /30: {plain}"
        );
    }

    // §6.5 typed refusal 1: snapshotting + Segment. Buggy impl guarded: without the arm, the pair
    // builds and the restore path mis-addresses a member from a frozen slot.
    #[test]
    fn build_rejects_snapshotting_with_a_segment() {
        let (_seg, segment_net) = fake_segment_config("vmcell");
        let err = VmConfig::builder(
            PathBuf::from("/vmlinux"),
            RootfsSource::Erofs {
                image: PathBuf::from("/rootfs.erofs"),
            },
        )
        .net(segment_net.clone())
        .snapshotting(true)
        .build()
        .expect_err("snapshotting + Segment must be refused");
        assert!(
            matches!(&err, crate::error::Error::Config(m) if m.contains("segment")),
            "expected a Config error naming segments, got {err:?}"
        );
        // Positive control: the same config without snapshotting builds.
        assert!(
            VmConfig::builder(
                PathBuf::from("/vmlinux"),
                RootfsSource::Erofs {
                    image: PathBuf::from("/rootfs.erofs"),
                },
            )
            .net(segment_net)
            .build()
            .is_ok()
        );
    }

    // §6.5 typed refusal 2: one prefix must name every resource in the domain (law F2). Buggy
    // impl guarded: without the check, an `acme`-prefixed member joins a `vmcell`-prefixed
    // segment, so its tap is created in a namespace the `acme` sweep filter never matches and a
    // leak is never reclaimed.
    #[test]
    fn build_rejects_a_member_whose_prefix_differs_from_its_segment() {
        let (_seg, segment_net) = fake_segment_config("vmcell");
        let err = VmConfig::builder(
            PathBuf::from("/vmlinux"),
            RootfsSource::Erofs {
                image: PathBuf::from("/rootfs.erofs"),
            },
        )
        .net(segment_net.clone())
        .resource_prefix("acme")
        .build()
        .expect_err("a prefix mismatch must be refused");
        assert!(
            matches!(&err, crate::error::Error::Config(m)
                if m.contains("resource_prefix") && m.contains("acme")),
            "expected a Config error naming both prefixes, got {err:?}"
        );

        // Positive control: a matching prefix on both sides builds.
        let (_seg2, segment_net2) = fake_segment_config("acme");
        assert!(
            VmConfig::builder(
                PathBuf::from("/vmlinux"),
                RootfsSource::Erofs {
                    image: PathBuf::from("/rootfs.erofs"),
                },
            )
            .net(segment_net2)
            .resource_prefix("acme")
            .build()
            .is_ok(),
            "a member whose prefix matches its segment must build"
        );
        // And the default-prefix member of the default-prefix segment still builds.
        assert!(
            VmConfig::builder(
                PathBuf::from("/vmlinux"),
                RootfsSource::Erofs {
                    image: PathBuf::from("/rootfs.erofs"),
                },
            )
            .net(segment_net)
            .build()
            .is_ok()
        );
    }

    #[test]
    fn extra_kernel_args_cannot_clobber_reserved_tokens() {
        // A config that exercises every conditional token: block rootfs (rootflags),
        // privileged net (ip=), a share (vmcell_share=), nested (kvm-*.nested=).
        let cfg = VmConfig::builder(
            PathBuf::from("/vmlinux"),
            RootfsSource::Block {
                image: PathBuf::from("/rootfs.img"),
                overlay: None,
            },
        )
        .net(NetConfig::Privileged {
            egress: Egress::Open,
        })
        .with_share(Share::new(
            "data",
            "/tmp/data",
            Access::ReadWrite,
            CachePolicy::Auto,
        ))
        .nested_virt(true)
        .build()
        .unwrap();
        // `noxsave ` is the FC backend_extra fragment — include it so its key is
        // covered too.
        let c = build_kernel_cmdline(&cfg, &test_res(5), "noxsave ").unwrap();
        for token in c.split_ascii_whitespace() {
            assert!(
                is_reserved_cmdline_arg(token),
                "builder token {token:?} is not reserved — an append-only arg with this \
                 key could clobber it. Add its key to RESERVED_CMDLINE_KEYS.\ncmdline: {c}"
            );
        }
        // Content/placement of the conditional tokens (a token being *reserved* does
        // not prove it is *correct*). The `ip=` autoconfig token must carry the /30
        // netmask and the exact host/guest IPs — recompute them through the one IP
        // law, never a test-local literal, so dropping the netmask or a positional
        // field reddens here even though the token key stays `ip`.
        let (host_ip, guest_ip, _) = crate::net::ip_math(5).unwrap();
        assert!(
            c.contains(&format!(
                " ip={guest_ip}::{host_ip}:255.255.255.252::eth0:off"
            )),
            "ip= autoconfig token (with /30 netmask) missing or malformed: {c}"
        );
        // A Block rootfs must carry `rootflags=noload`; emitting it unconditionally
        // (or dropping it here) is a boot break the reserved-key check cannot see.
        assert!(
            c.contains("rootflags=noload"),
            "Block rootfs must emit rootflags=noload: {c}"
        );
    }

    /// **The coupling** §4.7 ratifies: for every [`RootfsSource`] variant, the writability the
    /// backends attach the device with ([`RootfsSource::root_device_read_only`]) equals the
    /// writability the kernel mounts it with (the `ro`/`rw` token [`build_kernel_cmdline`] emits).
    ///
    /// Two directions, both of which had actually happened somewhere in this tree:
    ///
    /// * the **device** could be writable while the mount was read-only — the pre-delta-8 state,
    ///   in all four backends at once, so a guest could `dd` straight through `/dev/vda` beneath a
    ///   root filesystem the kernel believed was immutable (and N zygote clones share one image);
    /// * the **mount** could be made writable while the device stayed read-only, which is a boot
    ///   failure rather than corruption — but only because F3 reserves `rw`, and F3 reserves it
    ///   for the *other* reason (`rw` + `rootflags=noload` is silent corruption).
    ///
    /// Parsed out of the composed cmdline rather than asserted against a literal, so the law is
    /// checked against what the builder actually emits. RED on the inverse either way: return
    /// `false` from `root_device_read_only`'s `Block` arm, or emit `rw` in place of `ro`.
    #[test]
    fn rootfs_device_writability_matches_the_mount() {
        for rootfs in [
            RootfsSource::Erofs {
                image: PathBuf::from("/rootfs.erofs"),
            },
            RootfsSource::Block {
                image: PathBuf::from("/rootfs.img"),
                overlay: None,
            },
            RootfsSource::Block {
                image: PathBuf::from("/rootfs.img"),
                overlay: Some(PathBuf::from("/rootfs-vm7.img")),
            },
        ] {
            let cfg = VmConfig::builder(PathBuf::from("/vmlinux"), rootfs.clone())
                .build()
                .unwrap();
            let c = build_kernel_cmdline(&cfg, &test_res(5), "").unwrap();
            let tokens: Vec<&str> = c.split_ascii_whitespace().collect();
            let mount_ro = tokens.contains(&"ro");
            let mount_rw = tokens.contains(&"rw");
            // Non-vacuity: exactly one of the two aliases must be present, or "the mount is
            // read-only" would be satisfied by a cmdline that says nothing about it at all.
            assert!(
                mount_ro != mount_rw,
                "the cmdline must state the root mount's writability exactly once for \
                 {rootfs:?}: {c}"
            );
            assert_eq!(
                rootfs.root_device_read_only(),
                mount_ro,
                "the device's writability must not exceed the mount's (§4.7): {rootfs:?} is \
                 attached read-only={} while the cmdline mounts it {}",
                rootfs.root_device_read_only(),
                if mount_ro { "`ro`" } else { "`rw`" }
            );
            // …and the alias that would break the agreement is reserved in both directions, so a
            // caller cannot re-open the gap `extra_kernel_args` closes.
            for alias in ["ro", "rw"] {
                assert!(
                    is_reserved_cmdline_arg(alias),
                    "`{alias}` must stay reserved, or an appended arg can flip the mount out from \
                     under the device attachment"
                );
            }
        }
    }
}

/// Law C8's **call-site** gate: the two placement methods, and nothing else, answer the two
/// control-plane questions (design §3.5, §13 C8).
///
/// A gate on the extracted predicate is not a gate on the claim — that is the completeness-audit
/// lesson the §18 register promoted to a convention, and two of its six PARTIALs were invisible
/// precisely because a green unit test stood beside an unchanged call site. So this scans the
/// production sources for *where the questions are asked*, not for whether the methods exist.
#[cfg(test)]
mod placement_battery {
    use super::*;
    use std::path::PathBuf;

    fn b() -> VmConfigBuilder {
        VmConfig::builder(
            PathBuf::from("/vmlinux"),
            RootfsSource::Erofs {
                image: PathBuf::from("/rootfs.erofs"),
            },
        )
    }

    /// The derived default preserves every pre-v33 caller's semantics, both ways.
    #[test]
    fn the_default_placement_is_derived_from_init() {
        assert_eq!(
            b().build().expect("no init builds").steward_placement,
            StewardPlacement::Pid1,
            "no init => the kernel starts the steward as PID 1, exactly as before v33"
        );
        assert_eq!(
            b().init("/bin/workload")
                .build()
                .expect("custom init builds")
                .steward_placement,
            StewardPlacement::None,
            "a custom init => no steward is expected, which is what `init` USED to mean implicitly"
        );
    }

    /// **The pay-for-what-you-use floor**: a cell that names no placement emits a cmdline
    /// byte-identical to v32's.
    ///
    /// This is the assertion that makes "v33 changed nothing for existing callers" checkable
    /// rather than claimed. The `vmcell_steward_port=` token is emitted only for a NON-default
    /// port precisely so this holds.
    #[test]
    fn default_placement_emits_a_byte_identical_cmdline() {
        let default_cfg = b().build().expect("builds");
        let explicit = b()
            .steward_placement(StewardPlacement::Pid1)
            .build()
            .expect("builds");
        let res = crate::vmm::PerVmResources {
            cgroup_name: "vmcell-vm-7".to_string(),
            tap_name: None,
            netns_name: None,
            segment: None,
            vhost_user_socket: None,
            vmid: 7,
            guest_cid: 3,
            tmp_dir: PathBuf::from("/tmp/vmcell-vm-test-7"),
        };
        assert_eq!(
            build_kernel_cmdline(&default_cfg, &res, "").expect("cmdline"),
            build_kernel_cmdline(&explicit, &res, "").expect("cmdline"),
            "declaring the default explicitly must not move a single byte of the cmdline"
        );
        // And the token is absent entirely — not merely equal by luck.
        assert!(
            !build_kernel_cmdline(&default_cfg, &res, "")
                .expect("cmdline")
                .contains("vmcell_steward_port"),
            "no token is emitted for the default port"
        );
    }

    /// A NON-default `Service` port travels as the `vmcell_steward_port=` token — and F3's
    /// `vmcell_` prefix rule already reserves it against caller spoofing, with no edit to
    /// `RESERVED_CMDLINE_KEYS`.
    #[test]
    fn a_non_default_service_port_travels_on_the_cmdline_and_is_reserved() {
        let cfg = b()
            .steward_placement(StewardPlacement::Service { port: 5100 })
            .build()
            .expect("Service + init: None is deliberately legal");
        let res = crate::vmm::PerVmResources {
            cgroup_name: "vmcell-vm-7".to_string(),
            tap_name: None,
            netns_name: None,
            segment: None,
            vhost_user_socket: None,
            vmid: 7,
            guest_cid: 3,
            tmp_dir: PathBuf::from("/tmp/vmcell-vm-test-7"),
        };
        let cmdline = build_kernel_cmdline(&cfg, &res, "").expect("cmdline");
        assert!(
            cmdline.contains("vmcell_steward_port=5100"),
            "the declared port must reach the guest: {cmdline}"
        );
        assert!(
            is_reserved_cmdline_arg("vmcell_steward_port=9999"),
            "F3's `vmcell_` prefix rule must already reserve the token — a caller must not be \
             able to spoof the port the steward binds"
        );
    }

    /// `Service{port}` + `init: None` is DELIBERATELY legal — the kernel starts the steward as
    /// PID 1 *and* the host treats it as a service. It is what makes the placement predicate
    /// verifiable before a service-mode steward exists.
    #[test]
    fn service_with_no_init_composes() {
        let cfg = b()
            .steward_placement(StewardPlacement::Service {
                port: vmcell_protocol::STEWARD_VSOCK_PORT,
            })
            .build()
            .expect("Service + init: None must build");
        assert_eq!(
            cfg.steward_placement.steward_port(),
            Some(vmcell_protocol::STEWARD_VSOCK_PORT)
        );
        assert!(
            !cfg.steward_placement.resync_reachable(),
            "Service is not snapshot-eligible: whether the guest's init restarts the steward \
             after the vhost-vsock device is re-created is UNMEASURED (§17)"
        );
    }

    /// The ONE contradictory pair, and only it.
    #[test]
    fn pid1_plus_a_custom_init_is_the_only_rejected_composition() {
        let err = b()
            .steward_placement(StewardPlacement::Pid1)
            .init("/bin/workload")
            .build()
            .expect_err("Pid1 + custom init is a contradiction");
        assert!(
            err.to_string()
                .contains("cannot be combined with a custom init"),
            "{err}"
        );
        // Positive controls: every other composition builds.
        b().steward_placement(StewardPlacement::Service { port: 5000 })
            .init("/lib/systemd/systemd")
            .build()
            .expect("Service + a custom init is the systemd shape — it must build");
        b().steward_placement(StewardPlacement::None)
            .init("/bin/workload")
            .build()
            .expect("None + a custom init is today's no-control-plane shape");
        b().steward_placement(StewardPlacement::Pid1)
            .build()
            .expect("Pid1 with no init is the default");
    }

    /// **A declared port is HONORED, not just carried.**
    ///
    /// `Service { port }` is an accepted input, so F1 requires it to be honored or rejected — and
    /// delta 4's first cut did neither: `build()` accepted it, the cmdline builder emitted
    /// `vmcell_steward_port=`, and the HOST kept dialing the default because
    /// `VmInstance::vsock_endpoint` hard-codes it. The token reached the guest while the host
    /// dialed elsewhere; the mismatch would have surfaced only as an opaque connect timeout. This
    /// pins both halves — the cmdline token AND the endpoint the control plane dials.
    #[test]
    fn a_declared_service_port_is_honored_on_both_sides() {
        use crate::vmm::VsockEndpoint;

        let placement = StewardPlacement::Service { port: 5100 };
        let cfg = b().steward_placement(placement).build().expect("builds");

        // Guest side: the token carries it.
        let res = crate::vmm::PerVmResources {
            cgroup_name: "vmcell-vm-7".to_string(),
            tap_name: None,
            netns_name: None,
            segment: None,
            vhost_user_socket: None,
            vmid: 7,
            guest_cid: 3,
            tmp_dir: PathBuf::from("/tmp/vmcell-vm-test-7"),
        };
        assert!(
            build_kernel_cmdline(&cfg, &res, "")
                .expect("cmdline")
                .contains("vmcell_steward_port=5100")
        );

        // Host side: the endpoint the control plane dials carries it too, on BOTH transports.
        let unix = VsockEndpoint::Unix {
            path: PathBuf::from("/tmp/vsock.sock"),
            port: vmcell_protocol::STEWARD_VSOCK_PORT,
        };
        assert_eq!(
            unix.with_port(
                cfg.steward_placement
                    .steward_port()
                    .expect("Service has a port")
            ),
            VsockEndpoint::Unix {
                path: PathBuf::from("/tmp/vsock.sock"),
                port: 5100,
            },
            "the AF_UNIX control plane must dial the DECLARED port"
        );
        let vsock = VsockEndpoint::Vsock {
            cid: 3,
            port: vmcell_protocol::STEWARD_VSOCK_PORT,
        };
        assert_eq!(
            vsock.with_port(5100),
            VsockEndpoint::Vsock { cid: 3, port: 5100 },
            "the AF_VSOCK control plane (in-kernel QEMU, crosvm) must dial it too, keeping the CID"
        );

        // Positive control: a Pid1 cell is unmoved — same port, no token.
        let pid1 = b().build().expect("builds");
        assert_eq!(
            pid1.steward_placement.steward_port(),
            Some(vmcell_protocol::STEWARD_VSOCK_PORT)
        );
        assert!(
            !build_kernel_cmdline(&pid1, &res, "")
                .expect("cmdline")
                .contains("vmcell_steward_port")
        );
    }

    /// A reserved AF_VSOCK port is refused at construction (F1: honored or rejected).
    #[test]
    fn a_reserved_vsock_port_is_refused() {
        for bad in [0, u32::MAX] {
            let err = b()
                .steward_placement(StewardPlacement::Service { port: bad })
                .build()
                .expect_err("a reserved AF_VSOCK port must be refused");
            assert!(err.to_string().contains("reserved by AF_VSOCK"), "{err}");
        }
        // Positive control: a real port builds.
        b().steward_placement(StewardPlacement::Service { port: 5100 })
            .build()
            .expect("a real port builds");
    }

    /// `snapshotting` requires `Pid1` — and the rule is strictly NARROWER than the pre-v33 one.
    #[test]
    fn snapshotting_requires_pid1() {
        // `Service` is now rejected EXPLICITLY, where before it was unreachable via `init`.
        let err = b()
            .steward_placement(StewardPlacement::Service { port: 5000 })
            .snapshotting(true)
            .build()
            .expect_err("Service is not snapshot-eligible in v33");
        assert!(
            err.to_string()
                .contains("snapshotting requires the steward to run as PID 1"),
            "{err}"
        );
        // Positive control: the default placement still snapshots, unchanged.
        b().snapshotting(true)
            .build()
            .expect("Pid1 + snapshotting is the ordinary shape and must still build");
    }
}

#[cfg(test)]
mod c8_call_site_gate {
    /// `orchestrator.rs` and `config.rs`, comment-stripped, as `(file, line, code)`.
    fn production_lines() -> Vec<(&'static str, usize, String)> {
        let mut out = Vec::new();
        for (name, body) in [
            ("orchestrator.rs", include_str!("orchestrator.rs")),
            ("config.rs", include_str!("config.rs")),
        ] {
            // Stop at the crate's own `#[cfg(test)]` module: the gate is about PRODUCTION sites,
            // and the tests below legitimately name `cfg.init` and both methods while driving them.
            let prod = body.split("\n#[cfg(test)]\n").next().unwrap_or(body);
            for (i, l) in prod.lines().enumerate() {
                let code = l.split("//").next().unwrap_or("");
                if !code.trim().is_empty() {
                    out.push((name, i + 1, code.to_string()));
                }
            }
        }
        assert!(
            out.len() > 500,
            "the scan found only {} production lines — it is not reading the sources, so every \
             assertion below would pass vacuously",
            out.len()
        );
        out
    }

    /// **C8: `cfg.init` decides init IDENTITY only.**
    ///
    /// Before v33, seven of the eight sites keying on `cfg.init` were asking "can I reach a
    /// steward?" and answering it with "did the caller set `init=`?". After the re-key exactly
    /// three production sites may read it, and each is genuinely about *which binary is PID 1*:
    /// the cmdline `init=` token, `validate_init_path`, and the `Pid1`-plus-custom-init reject.
    ///
    /// An eighth site reading `cfg.init` to decide reachability is this law's violation, and it is
    /// the shape that would silently re-introduce the conflation.
    #[test]
    fn cfg_init_is_read_only_where_init_identity_is_the_question() {
        let readers: Vec<String> = production_lines()
            .into_iter()
            .filter(|(_, _, code)| {
                code.contains("cfg.init")
                    || code.contains("self.init")
                    || code.contains(".init.is_")
            })
            .map(|(f, l, code)| format!("{f}:{l}: {}", code.trim()))
            .collect();
        // Each surviving reader is init IDENTITY. Named individually so adding one is a review
        // event rather than a count that drifts.
        for r in &readers {
            assert!(
                r.contains("let init = cfg.init.as_deref()")      // the cmdline `init=` token
                    || r.contains("validate_init_path")           // the path validator
                    || r.contains("self.init = Some(")            // the builder setter
                    || r.contains("init: self.init")              // the build() move
                    || r.contains("if self.init.is_some()")       // the derived default
                    || r.contains("&& let Some(init) = &self.init") // the Pid1-contradiction reject
                    || r.contains("if let Some(init) = &self.init"),
                "C8: `{r}` reads `init` for something other than init IDENTITY. Control-plane \
                 availability is `StewardPlacement::steward_port()`; snapshot eligibility is \
                 `resync_reachable()`. Re-deriving either from `init` is the conflation v33 \
                 removed — seven sites did exactly that before the re-key."
            );
        }
    }

    /// **C8: the two methods answer the two questions, and are not interchanged.**
    ///
    /// `steward_port()` is availability (`steward()`, `connect_sessions()`, the health gate);
    /// `resync_reachable()` is snapshot eligibility (`snapshot()`'s guard, the eligibility
    /// predicate's placement arm). They differ **exactly at `Service`**, which has a port but no
    /// measured post-restore resync — so an eligibility site reading `steward_port()` is the
    /// violation the design's own review caught, and it is the one this half exists for.
    #[test]
    fn the_two_c8_methods_are_read_at_their_own_questions() {
        let lines = production_lines();
        let port_sites: Vec<String> = lines
            .iter()
            .filter(|(_, _, c)| c.contains("steward_port()"))
            .map(|(f, l, c)| format!("{f}:{l}: {}", c.trim()))
            .collect();
        let resync_sites: Vec<String> = lines
            .iter()
            .filter(|(_, _, c)| c.contains("resync_reachable()"))
            .map(|(f, l, c)| format!("{f}:{l}: {}", c.trim()))
            .collect();

        // Both must actually be read in production, or the "two methods" law is one method plus
        // dead code — which a gate that only counted violations would happily certify.
        assert!(
            port_sites.len() >= 3,
            "availability must be read at the health gate and both MicroVm constructions; found \
             {port_sites:#?}"
        );
        assert!(
            resync_sites.len() >= 2,
            "eligibility must be read at snapshot()'s guard AND the eligibility predicate; found \
             {resync_sites:#?}"
        );
        // The definitions themselves live in `config.rs`; every OTHER reader must be a call.
        for s in &port_sites {
            assert!(
                !s.contains("fn resync_reachable"),
                "the availability method must not be defined in terms of eligibility: {s}"
            );
        }
    }
}
