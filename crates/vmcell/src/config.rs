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
    /// The prefix for this VM's swept host-resource names (netns/tap/cgroup/scratch), composed via
    /// [`crate::naming`]. Defaults to [`crate::naming::DEFAULT_RESOURCE_PREFIX`] (`"vmcell"`). The
    /// orphan sweep must be run with the SAME prefix (§v21) or it will not match this VM's leaks.
    pub resource_prefix: String,
    /// Extra virtio-blk devices attached **after** the root disk, enumerated by the
    /// guest as `/dev/vdb`, `/dev/vdc`, … in order (§19.1). Raw block devices — the
    /// guest workload owns any filesystem/mount; the agent does not auto-mount them.
    /// Plain virtio-blk composes with snapshotting (§12.1); an extra disk's
    /// [`image`](BlockDevice::image) must live at a **stable path** to survive a
    /// restore. Default empty.
    pub extra_disks: Vec<BlockDevice>,
    /// Append-only extra kernel command-line arguments, appended **after** every
    /// token vmcell owns (§19.2.1). An extra arg can add a boot parameter but can never
    /// override one vmcell controls; [`VmConfigBuilder::build`] rejects any arg whose
    /// key is reserved or starts with `vmcell_`, or that is not a single whitespace-
    /// free token. Default empty.
    pub extra_kernel_args: Vec<String>,
    /// Optional `init=` override (§19.2.2). `None` boots the vmcell guest agent as
    /// PID 1 (the vsock control plane). `Some(path)` boots a **custom PID 1**, which
    /// **replaces the agent** — so the VM has no control plane
    /// ([`crate::orchestrator::MicroVm::agent`] fails loud) and cannot snapshot
    /// ([`VmConfigBuilder::build`] rejects
    /// `snapshotting` + a custom init, since the post-restore resync needs the agent).
    /// Observe such a VM via the serial log, a writable extra disk/share, or
    /// networking. A custom init also loses the agent's tmpfs overlay over the RO
    /// erofs root, so it usually pairs with a writable rootfs or extra disk. Default
    /// `None`.
    pub init: Option<PathBuf>,
    /// The VMM subprocess's own seccomp-BPF confinement (design §20.3). Default
    /// [`VmmSeccomp::Enforcing`] runs each backend under its audited native filter
    /// (`cloud-hypervisor --seccomp true`, Firecracker's built-in filter, `qemu
    /// -sandbox on,…`). The one predicate [`crate::vmm::seccomp::vmm_seccomp_args`]
    /// maps this to the per-backend flag and returns [`crate::error::Error::Unsupported`]
    /// for a policy a backend cannot honor (e.g. [`VmmSeccomp::Log`] on Firecracker/QEMU),
    /// never a silent downgrade. [`VmmSeccomp::Disabled`] is a deliberate, logged opt-out.
    pub vmm_seccomp: VmmSeccomp,
    /// Jailer-equivalent pre-exec hardening applied to the VMM child (design §20.4):
    /// `no_new_privs`, ambient-capability clear, non-dumpable, and rlimits, plus an
    /// optional coarse seccomp deny-list. Default [`JailConfig::default`] is the
    /// hardened profile ([`JailConfig::hardened`]). The pure config here is compiled to
    /// a runtime `JailSpec` and applied by [`crate::vmm::jail::apply_jail`] in the
    /// forked-child pre-exec window, shared by the in-process spawn and the setup
    /// broker (one law, §12.22).
    pub jail: JailConfig,
}

/// The VMM subprocess's own seccomp-BPF confinement policy (design §20.3 / §12.21).
///
/// [`crate::vmm::seccomp::vmm_seccomp_args`] is the single predicate that turns this
/// into a backend's native CLI flag; a policy a backend cannot honor is a typed
/// [`crate::error::Error::Unsupported`], not a silent fallback (§7.2 capability honesty).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum VmmSeccomp {
    /// Enforce the backend's audited seccomp filter, killing on a disallowed syscall.
    /// The default — vmcell never leaves a backend unconfined by default (§12.2).
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

/// Jailer-equivalent pre-exec hardening applied to the VMM child (design §20.4).
///
/// Pure, serializable configuration (no compiled BPF): [`crate::vmm::jail::apply_jail`]
/// compiles the optional deny-list once, pre-fork, and applies the rest in the
/// async-signal-safe child window. Mirrors the hardening Firecracker's `jailer` applies
/// to the VMM (minus the chroot/uid-drop increment, forward work §20.9).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct JailConfig {
    /// `prctl(PR_SET_NO_NEW_PRIVS, 1)` — the child (and anything it execs) can never
    /// gain privileges via a setuid/file-cap binary. Required before a seccomp filter.
    pub no_new_privs: bool,
    /// `prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL)` — clear the ambient capability set.
    /// **Default `false`, opt-in** (§20.9): in vmcell's current architecture the VMM *inherits*
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
    /// (potentially secrets) to disk, exactly the §12.18 surface, so no core is allowed.
    pub rlimit_core: Option<u64>,
    /// `RLIMIT_FSIZE` — default `None` (unset): a snapshot-eligible VM writes a
    /// guest-RAM-sized suspend file, so a naïve `fsize=0` would break snapshot.
    pub rlimit_fsize: Option<u64>,
    /// `RLIMIT_NOFILE` — default `None`; set for a tighter open-fd ceiling on the VMM.
    pub rlimit_nofile: Option<u64>,
    /// Apply a coarse, default-allow seccomp **deny-list** (design §20.4) of syscalls a
    /// booting VMM never needs and an escape would want (`mount`, `ptrace`, `bpf`,
    /// `kexec_load`, module ops, `setns`, …) → `EPERM`. Ships **opt-in, default
    /// `false`**: the backend's own native filter ([`VmmSeccomp`]) is the shipped
    /// default confinement, and a host-applied filter on a live VMM is not yet
    /// KVM-host-validated (§20.9). The filter-application mechanism itself is gated
    /// KVM-free against a stand-in child.
    pub seccomp_deny_list: bool,
}

impl JailConfig {
    /// The hardened default: `no_new_privs` + `non_dumpable` + `RLIMIT_CORE=0`, no fsize/nofile
    /// cap, no host seccomp deny-list (the backend's native filter is the shipped default, §20.4).
    ///
    /// **`clear_ambient_caps` defaults to `false`** (empirically forced, §20.9): in vmcell's
    /// current architecture the VMM inherits `CAP_NET_ADMIN` (via the ambient set on the runner
    /// path) and **needs** it for privileged tap operations — a restored Cloud Hypervisor's
    /// `TapSetMac` and Firecracker's tap re-open both `EPERM` without it (validated on a KVM host:
    /// clearing ambient broke `*_survives_snapshot` restore-with-tap). Clearing the VMM's caps is
    /// safe only once the tap is handed over fully configured (the fd-passing / uid-drop jailer
    /// increment, §20.9); until then the field stays an opt-in for that future path.
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
    // Self-guard (L-ORCH-2): a virtio-fs rootfs has no `/dev/vda`, so emitting the
    // `root=/dev/vda rootfstype=ext4` line below would build an unbootable cmdline
    // that kernel-panics the guest. Every backend rejects a virtio-fs rootfs up
    // front today, but this shared builder must not silently depend on "the caller
    // checked first" (AGENTS.md contract-self-guard).
    if let RootfsSource::VirtioFs { .. } = &cfg.rootfs {
        return Err(crate::error::Error::Config(
            "virtio-fs rootfs cannot be booted from the kernel cmdline (no /dev/vda block device)"
                .into(),
        ));
    }
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
    // The `init=` token: the fixed vmcell guest agent (the default control-plane
    // PID 1) unless the caller overrides it (§19.2.2). This is the ONE place either
    // `init=` token is constructed — a backend never string-builds it. A custom
    // init replaces the agent, so it forgoes the vsock control plane; the
    // consequence is honored fail-loud in the orchestrator, not here (see
    // `MicroVm::agent`). `build()` validated the override is a single safe token.
    let init = cfg.init.as_deref().map_or_else(
        || DEFAULT_INIT.to_string(),
        |p| p.to_string_lossy().into_owned(),
    );
    let mut s = format!(
        "console={} loglevel={} random.trust_cpu=on random.trust_bootloader=on \
         cryptomgr.notests raid=noautodetect \
         root=/dev/vda rootfstype={} ro {} panic=1 {}init={} vmcell_vmid={}",
        cfg.console_mode.console(),
        cfg.kernel_verbosity.loglevel(),
        rootfstype,
        rootflags,
        backend_extra,
        init,
        vmid,
    );
    if !matches!(cfg.net, NetConfig::None) {
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
    // add a boot parameter but never clobber one (§19.2.1). `build()` already rejected
    // any arg whose key is reserved or `vmcell_`-prefixed, so this is a safe splice.
    push_extra_kernel_args(&mut s, &cfg.extra_kernel_args);
    Ok(s)
}

/// The default `init=` target: the vmcell guest agent that serves the vsock control
/// plane as PID 1 (§4.3). A caller may override it via [`VmConfig::init`], which
/// replaces the agent and therefore forgoes the control plane (§19.2.2).
pub(crate) const DEFAULT_INIT: &str = "/usr/sbin/vmcell-guest-agent";

/// The kernel-cmdline keys that [`build_kernel_cmdline`] owns and that
/// [`VmConfig::extra_kernel_args`] may therefore **not** set (append-only, §19.2.1).
///
/// Kept in lockstep with the tokens the builder emits by the
/// `extra_kernel_args_cannot_clobber_reserved_tokens` coverage test: every token the
/// builder produces has a reserved key here (or the `vmcell_` prefix), so a caller
/// arg can never silently override a load-bearing boot parameter.
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
];

/// Whether `arg` collides with a boot token vmcell owns — its key is in
/// [`RESERVED_CMDLINE_KEYS`] or starts with `vmcell_` (every guest-agent-trusted
/// token, §8.3). The single predicate behind the append-only contract (§19.2.1); the
/// key is the text before the first `=` (or the whole bare token).
pub(crate) fn is_reserved_cmdline_arg(arg: &str) -> bool {
    let key = arg.split('=').next().unwrap_or(arg);
    // The guest agent trusts every `vmcell_*` token (shares, accept/rebind cadence);
    // a caller arg spoofing one would mis-mount a share or busy-spin PID 1.
    key.starts_with("vmcell_") || RESERVED_CMDLINE_KEYS.contains(&key)
}

/// Appends the validated append-only caller args to `cmdline`, one whitespace-
/// separated token each (§19.2.1). No args ⇒ nothing appended.
pub(crate) fn push_extra_kernel_args(cmdline: &mut String, args: &[String]) {
    for arg in args {
        cmdline.push(' ');
        cmdline.push_str(arg);
    }
}

/// Validates a caller-supplied `init=` override path (§19.2.2): valid UTF-8, absolute,
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

/// Validates one append-only caller kernel arg (§19.2.1): non-empty, a single cmdline
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

/// An extra virtio-blk device attached to the VM in addition to the root disk
/// ([`VmConfig::extra_disks`], §19.1).
///
/// The guest kernel enumerates extra disks as `/dev/vdb`, `/dev/vdc`, … in
/// attachment order; the root disk is always `/dev/vda`. vmcell attaches the **raw**
/// block device only — the guest workload owns any partitioning, filesystem, or
/// mount (the guest agent does not auto-mount extra disks).
///
/// Plain virtio-blk is **not** a vhost-user device, so extra disks compose with
/// snapshotting (§12.1). A block device's contents live on disk, *outside* the
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
    /// Optional I/O rate limit (disk-I/O fault injection, §19.5). `None` = unlimited.
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

    /// Attaches an I/O rate limit to this device (disk-I/O fault injection, §19.5), to
    /// simulate a slow or pressured disk. Validated at [`VmConfigBuilder::build`].
    #[must_use]
    pub fn with_io_limit(mut self, limit: DiskIoLimit) -> Self {
        self.io_limit = Some(limit);
        self
    }
}

/// An I/O rate limit for a [`BlockDevice`] — the portable form of disk-I/O fault
/// injection (§19.5), simulating a slow/pressured disk to test a workload's timeout /
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
pub(crate) const IO_LIMIT_REFILL_TIME_MS: u64 = 1000;

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
        /// Must be `None`: host-service reachability is only implemented on the
        /// [`NetConfig::Unprivileged`] NAT path. `config::build()` rejects
        /// `Some(_)` here rather than silently ignoring it (H-ORCH-3/H-NET-2) —
        /// the privileged TPROXY ruleset policy-drops everything but the web
        /// TPROXY and the proxy port, so a host-service port would not reach the
        /// guest anyway.
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
            vmid: None,
            restore_mode: RestoreMode::Default,
            ksm_mergeable: false,
            kernel_verbosity: KernelVerbosity::Balanced,
            timeouts: Timeouts::default(),
            console_mode: ConsoleMode::Uart,
            resource_prefix: crate::naming::DEFAULT_RESOURCE_PREFIX.to_string(),
            extra_disks: vec![],
            extra_kernel_args: vec![],
            init: None,
            vmm_seccomp: VmmSeccomp::default(),
            jail: JailConfig::default(),
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
    resource_prefix: String,
    extra_disks: Vec<BlockDevice>,
    extra_kernel_args: Vec<String>,
    init: Option<PathBuf>,
    vmm_seccomp: VmmSeccomp,
    jail: JailConfig,
}

impl VmConfigBuilder {
    /// Sets the VMM subprocess's own seccomp policy ([`VmConfig::vmm_seccomp`], §20.3).
    /// Default [`VmmSeccomp::Enforcing`].
    #[must_use]
    pub fn vmm_seccomp(mut self, policy: VmmSeccomp) -> Self {
        self.vmm_seccomp = policy;
        self
    }

    /// Sets the jailer-equivalent pre-exec hardening for the VMM child
    /// ([`VmConfig::jail`], §20.4). Default [`JailConfig::hardened`].
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

    /// Attaches an extra virtio-blk device ([`BlockDevice`], §19.1), enumerated by the
    /// guest as the next `/dev/vd*` after the root disk in call order. Validated at
    /// [`build`](Self::build).
    #[must_use]
    pub fn with_extra_disk(mut self, disk: BlockDevice) -> Self {
        self.extra_disks.push(disk);
        self
    }

    /// Appends one append-only extra kernel command-line argument
    /// ([`VmConfig::extra_kernel_args`], §19.2.1). Rejected at [`build`](Self::build) if
    /// it collides with a reserved token vmcell owns or is not a single safe token.
    #[must_use]
    pub fn with_kernel_arg(mut self, arg: impl Into<String>) -> Self {
        self.extra_kernel_args.push(arg.into());
        self
    }

    /// Overrides the guest `init=` target ([`VmConfig::init`], §19.2.2). A custom init
    /// **replaces** the vmcell guest agent, forgoing the vsock control plane; validated
    /// at [`build`](Self::build), which also rejects it combined with `snapshotting`.
    #[must_use]
    pub fn init(mut self, init: impl Into<PathBuf>) -> Self {
        self.init = Some(init.into());
        self
    }

    /// Sets the prefix for this VM's swept host-resource names (netns/tap/cgroup/scratch); default
    /// [`crate::naming::DEFAULT_RESOURCE_PREFIX`]. Run the orphan sweep with the same prefix (§v21).
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
            // A custom init replaces the vmcell guest agent (§19.2.2), and the mandatory
            // post-restore resync — clock, entropy reseed, MAC/IP rotation (§12.4) —
            // runs *through* that agent. A restored custom-init clone would be stranded
            // on frozen identity with no way to fix it from inside (silently dead
            // egress / correlated RNG), the exact §12.4 trap. Reject fail-loud here.
            if self.init.is_some() {
                return Err(crate::error::Error::Config(
                    "a custom init cannot be combined with snapshotting (the mandatory \
                     post-restore resync requires the vmcell guest agent, which a custom \
                     init replaces)"
                        .into(),
                ));
            }
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

        // H-ORCH-3/H-NET-2: `host_services_port` is only wired on the unprivileged
        // NAT path. On the privileged path the field is dropped, so accepting
        // `Some(_)` would be a silent no-op (the §12.2 fail-loud violation). Reject
        // it at the boundary with a typed error instead.
        if let NetConfig::Privileged {
            host_services_port: Some(_),
            ..
        } = self.net
        {
            return Err(crate::error::Error::Config(
                "host_services_port is only supported on Unprivileged networking".into(),
            ));
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

        // Extra virtio-blk device images: absolute, non-empty, no duplicate backing
        // file (§19.1.4). Existence is deliberately NOT checked here (consistent with
        // the rootfs/share paths — the image may be created later); a bad path fails
        // loud at `create()`. A duplicate image is a rw corruption footgun (two
        // attachments of one file), so it is rejected at the boundary.
        let mut extra_disk_images = std::collections::HashSet::new();
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
                    "duplicate extra disk image: {}",
                    disk.image.display()
                )));
            }
            // Disk-I/O fault injection (§19.5): a limit must actually limit something, and
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

        // A custom `init=` override is a single load-bearing cmdline token selecting
        // PID 1, so it is validated at the boundary (§19.2.2): absolute, UTF-8, no
        // whitespace/control chars that could forge a second boot token.
        if let Some(init) = &self.init {
            validate_init_path(init).map_err(crate::error::Error::Config)?;
        }

        // Append-only extra kernel args: each a single safe token whose key does not
        // collide with a reserved boot token vmcell owns (§19.2.1).
        for arg in &self.extra_kernel_args {
            validate_extra_kernel_arg(arg).map_err(crate::error::Error::Config)?;
        }

        // The resource prefix becomes part of a netns / interface / cgroup / directory name, so an
        // invalid one is rejected fail-loud at construction (never silently sanitized).
        crate::naming::validate_resource_prefix(&self.resource_prefix)
            .map_err(crate::error::Error::Config)?;

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
            resource_prefix: self.resource_prefix,
            extra_disks: self.extra_disks,
            extra_kernel_args: self.extra_kernel_args,
            init: self.init,
            vmm_seccomp: self.vmm_seccomp,
            jail: self.jail,
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

    // H-ORCH-3/H-NET-2: `host_services_port` is only wired on the unprivileged NAT
    // path; on the privileged path it was silently dropped (a §12.2 fail-loud
    // violation). Buggy impl this guards: `build()` accepts the combination.
    #[test]
    fn reject_privileged_with_host_services_port() {
        let err = VmConfig::builder(
            PathBuf::from("/vmlinux"),
            RootfsSource::Erofs {
                image: PathBuf::from("/rootfs.erofs"),
            },
        )
        .net(NetConfig::Privileged {
            egress: Egress::Open,
            host_services_port: Some(8080),
        })
        .build()
        .unwrap_err();
        assert!(matches!(err, crate::error::Error::Config(_)));
        assert!(err.to_string().contains("host_services_port"));
        // The unprivileged path with the same port must still build.
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

    // L-ORCH-2: the shared cmdline builder must self-guard against a virtio-fs
    // rootfs (no `/dev/vda`) rather than emitting an unbootable
    // `root=/dev/vda rootfstype=ext4` line. Buggy impl: the `_ => "ext4"` arm
    // silently produces the panicking cmdline.
    #[test]
    fn reject_virtio_fs_rootfs_cmdline_build() {
        let cfg = VmConfig::builder(
            PathBuf::from("/vmlinux"),
            RootfsSource::VirtioFs {
                dir: PathBuf::from("/rootfs"),
            },
        )
        .build()
        .unwrap();
        let err = build_kernel_cmdline(&cfg, 1, "").unwrap_err();
        assert!(matches!(err, crate::error::Error::Config(_)));
        // An erofs rootfs still builds a bootable line.
        let ok = VmConfig::builder(
            PathBuf::from("/vmlinux"),
            RootfsSource::Erofs {
                image: PathBuf::from("/rootfs.erofs"),
            },
        )
        .build()
        .unwrap();
        assert!(
            build_kernel_cmdline(&ok, 1, "")
                .unwrap()
                .contains("rootfstype=erofs")
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

    // §19.1: BlockDevice constructors set the readonly flag; a swapped arm (read_only
    // marking rw, or vice versa) reddens here.
    #[test]
    fn block_device_constructors() {
        let ro = BlockDevice::read_only("/img/data.raw");
        assert_eq!(ro.image, PathBuf::from("/img/data.raw"));
        assert!(ro.readonly);
        let rw = BlockDevice::read_write("/img/scratch.raw");
        assert!(!rw.readonly);
    }

    // §19.1: the builder carries extra_disks onto the built config in order, default
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

    // §19.1.4: build() rejects an empty / relative / duplicate extra-disk image. Buggy
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

    // §19.1.4 positive control: a valid extra disk with an absolute path builds — the
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

    // §19.5: DiskIoLimit constructors set the intended cap and leave the other unset; a
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

    // §19.5: `with_io_limit` carries the limit onto the built disk; default is None.
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

    // §19.5: build() rejects an io_limit that limits nothing, or a 0 cap (which would
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

    // §19.2.2: the builder carries the init override and defaults to None. Buggy impl:
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

    // §19.2.2: `validate_init_path` rejects a relative path, whitespace, and control
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
    }

    // §19.2.2: build() rejects snapshotting + a custom init (the post-restore resync
    // needs the agent a custom init replaces). Buggy impl: the combination builds and
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
        assert!(
            err.to_string()
                .contains("custom init cannot be combined with snapshotting"),
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

    // §19.2.1: `is_reserved_cmdline_arg` flags every token vmcell owns (by exact key or
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

    // §19.2.1: build() rejects an extra arg that clobbers a reserved token, spoofs a
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

    // §19.2.2: the init override replaces the default `init=` token — exactly one
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
        let c = build_kernel_cmdline(&cfg, 7, "").unwrap();
        assert!(c.contains("init=/bin/sh"), "override missing: {c}");
        assert!(
            !c.contains("init=/usr/sbin/vmcell-guest-agent"),
            "default init must be replaced, not kept: {c}"
        );
        assert_eq!(
            c.matches("init=").count(),
            1,
            "exactly one init= token expected: {c}"
        );
        assert!(c.contains("root=/dev/vda"), "root token must remain: {c}");
        assert!(c.contains("vmcell_vmid=7"), "vmid token must remain: {c}");

        // The default (no override) still emits the guest agent (existing contract).
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
            build_kernel_cmdline(&default_cfg, 1, "")
                .unwrap()
                .contains(&format!("init={DEFAULT_INIT}")),
            "default init token must be the guest agent"
        );
    }

    // §19.2.1: append-only args land AFTER every reserved token, in order. Buggy impl:
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
        let c = build_kernel_cmdline(&cfg, 1, "").unwrap();
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

    // §19.2.1 the ONE-LAW GATE: every token `build_kernel_cmdline` emits has a reserved
    // key (or the vmcell_ prefix), so `is_reserved_cmdline_arg` — and hence the
    // append-only guard — can never fall out of sync with the builder. Add a new
    // builder token without reserving its key ⇒ this reddens.
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
            host_services_port: None,
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
        let c = build_kernel_cmdline(&cfg, 5, "noxsave ").unwrap();
        for token in c.split_ascii_whitespace() {
            assert!(
                is_reserved_cmdline_arg(token),
                "builder token {token:?} is not reserved — an append-only arg with this \
                 key could clobber it. Add its key to RESERVED_CMDLINE_KEYS.\ncmdline: {c}"
            );
        }
    }
}
