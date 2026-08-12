//! The pure serial-log classifier: map a failed boot's console output onto the **§5.4 guest-kernel
//! contract clause** it broke (design §5.4, The guest-kernel contract and the bootstrap seed; §5.6,
//! The downstream kernel toolkit — "fails a named check loudly, not by hanging").
//!
//! A kernel missing a baseline symbol used to fail [`crate::checks::kernel_banner`] or
//! `boot.agent_ready` with a raw timeout and a raw serial tail. This module turns the known
//! signatures into the clause plus the missing symbols, and — for the residual class it does *not*
//! recognize — still emits the named check, the budget that expired, the serial tail, and a pointer
//! to the §5.4 checklist. A newly-understood signature grows [`classify_serial`]; it never grows the
//! timeout path.
//!
//! Everything here is pure `&str` → value: no filesystem, no VM, no KVM. That is what makes the
//! red-on-inverse canned-log tests the delta's gate. The *wiring* — reading a VM's console and
//! feeding it here — is gated separately in [`crate::checks`]'s tests, which drive the real
//! fs-reading path over fixture logs.
//!
//! ## Two renderers, and the difference between them
//! [`explain_boot_failure`] is for a boot whose console **was captured** (possibly empty: the VM
//! ran and printed nothing, which is itself evidence). [`explain_without_serial`] is for a failure
//! where **no console evidence exists at all** — the VMM never started, or its log could not be
//! read — and it names candidate causes instead of asserting a contract violation, because absence
//! of evidence is not evidence of a bad kernel (a missing `cloud-hypervisor` binary lands there
//! too). Every arm of [`crate::checks`] that **reports** a VM which failed to start
//! (`MicroVm::start`) or failed its agent handshake routes through one of the two — Core,
//! Extended and Full alike, gated by `run_core_records_both_boot_checks_when_the_vm_never_starts`
//! and `every_extended_and_full_boot_failure_names_the_missing_evidence`.
//!
//! ## The signatures are the emitters' real text
//! The strings below were taken from the code that prints them, not from prose:
//!
//! - the root-device and root-fs clauses from the kernel's own `init/do_mounts.c` texts (the
//!   empirically observed failure of a Firecracker CI microVM kernel on vmcell's erofs root, §5.4).
//!   The kernel prints `VFS: Cannot open root device` when the root *block device* never appeared
//!   (no virtio transport / no virtio-blk) and `No filesystem could mount root, tried:` when the
//!   device is there but no driver claims it — two different clauses, and the device case also
//!   panics with `VFS: Unable to mount root fs`, so the device signature is checked **first**;
//! - the vsock clause from the guest agent's **own** boot self-check
//!   (`vmcell-guest-agent: boot self-check: AF_VSOCK unavailable (…)`, emitted on `/dev/console`
//!   by PID 1 before it binds the listener). The design's wording names a vsock `EAFNOSUPPORT`;
//!   that mnemonic appears in **no** serial log — the errno renders as `Address family not
//!   supported by protocol (os error 97)`, and that phrase alone is *not* a signature either
//!   (the agent prints it verbatim for an unrelated `AF_INET` loopback failure). Keying on the
//!   agent's own stable prefix is both narrower and more reliable.

use crate::kconfig::KconfigValues;

/// How many trailing non-empty serial lines [`explain_boot_failure`] quotes. Bounded so a failure
/// message never carries a multi-megabyte console log into a caller's report.
pub const SERIAL_TAIL_LINES: usize = 20;

/// The kernel's `init/do_mounts.c` text for "the root **device node** is not there": no virtio
/// transport or no virtio-blk, so `/dev/vda` never appeared. Checked before
/// [`ROOT_FS_MOUNT_SIGNATURES`] because this failure *also* ends in the generic
/// `VFS: Unable to mount root fs` panic — matching the mount clause first would tell a kernel
/// missing `CONFIG_VIRTIO_BLK` to fix its erofs decompressor.
const ROOT_DEVICE_SIGNATURES: &[&str] = &["VFS: Cannot open root device"];

/// The kernel's `init/do_mounts.c` text for "the device is there but no filesystem driver claimed
/// it" — for vmcell that is the erofs/overlay symbol set (§5.4). `VFS: Unable to mount root fs` is
/// the panic both root failures end in; it reaches this clause only when no
/// [`ROOT_DEVICE_SIGNATURES`] entry matched.
const ROOT_FS_MOUNT_SIGNATURES: &[&str] = &[
    "No filesystem could mount root",
    "VFS: Unable to mount root fs",
];

/// The guest agent's own vsock diagnostics (`vmcell-guest-agent/src/main.rs`). Both reach the
/// serial console because PID 1's stdout/stderr are `/dev/console` (= `ttyS0`, §5.3).
const VSOCK_SIGNATURES: &[&str] = &[
    "boot self-check: AF_VSOCK unavailable",
    "failed to bind vsock",
];

/// The kernel's start-of-boot banner. Its **absence** in a captured console is the "not a
/// direct-boot `vmlinux`" signature: the VM ran and nothing reached the console.
///
/// Public because [`crate::checks::kernel_banner`] polls for the very same string and names it in
/// its own rustdoc — one law, one literal (a second copy would let the poll succeed while
/// [`classify_serial`] reported [`ContractViolation::NoDirectBootKernel`], or the reverse).
pub const BANNER_SIGNATURE: &str = "Linux version";

/// A §5.4 guest-kernel contract clause that a serial log proves was violated.
///
/// Non-exhaustive by design: §5.6 promises that a newly-understood signature grows the classifier,
/// and this crate is downstream contract surface (§10.4) — a new variant must not break a consumer.
///
/// Growing it is a three-place obligation, and the compiler enforces all three *inside* this crate
/// (`#[non_exhaustive]` only relaxes matching downstream): [`clause`](Self::clause),
/// [`symbols`](Self::symbols), and the test module's variant walk, which must have the new variant
/// **spliced into its cycle** so the per-variant assertions cover it.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum ContractViolation {
    /// The root **block device** never appeared, so there was nothing to mount — the §5.4 virtio
    /// transport + virtio-blk symbols, not the filesystem ones.
    RootDeviceMissing,
    /// The kernel booted but could not mount the erofs root — the §5.4 root-filesystem symbols.
    RootFsMount,
    /// The guest reached userspace but has no `AF_VSOCK` transport — the §3 control plane cannot
    /// come up, so no check past `boot.kernel_banner` can ever pass.
    VsockTransport,
    /// Nothing reached the console at all: the image is not a bootable direct-boot PVH `vmlinux`
    /// (or the 8250 console is not built in, so no evidence could be captured either way).
    NoDirectBootKernel,
}

impl ContractViolation {
    /// The §5.4 clause this violation breaks, as one line of prose for a check's failure message.
    #[must_use]
    pub fn clause(self) -> &'static str {
        match self {
            Self::RootDeviceMissing => {
                "§5.4 root device: the root block device never appeared, so the kernel had nothing \
                 to mount — the virtio transport and the block driver must be built in (CH uses \
                 virtio-pci, Firecracker virtio-mmio), and the `root=` cmdline must name the disk \
                 vmcell attaches (§5.3)"
            }
            Self::RootFsMount => {
                "§5.4 root filesystem: the kernel could not mount the erofs root — the erofs \
                 decompressor must match the packer (add CONFIG_EROFS_FS_ZIP for a compressed \
                 image; CONFIG_EXT4_FS only for the Block rootfs fallback), and the tmpfs overlay \
                 is mounted over it (§4.1)"
            }
            Self::VsockTransport => {
                "§5.4 control plane: the guest has no AF_VSOCK transport, so the §3 vsock control \
                 plane cannot come up (the agent's own boot self-check reported it)"
            }
            Self::NoDirectBootKernel => {
                "§5.4 boot protocol: nothing reached the serial console — the image is not a \
                 direct-boot PVH-ELF vmlinux (never a bzImage, never the EFI stub), or the 8250 \
                 console is not built in"
            }
        }
    }

    /// The kernel symbols §5.4 requires **unconditionally** for this clause, each `=y` (built in —
    /// the guest has no early userspace to load modules from, which is why [`missing_symbols`]
    /// tests them with [`KconfigValues::is_builtin`]). The conditional ones
    /// (`CONFIG_EROFS_FS_ZIP` for a compressed image, `CONFIG_EXT4_FS` for the Block rootfs
    /// fallback) are named in [`clause`](Self::clause), not here, so [`missing_symbols`] never
    /// reports a symbol the artifact pair does not actually need.
    #[must_use]
    pub fn symbols(self) -> &'static [&'static str] {
        match self {
            Self::RootDeviceMissing => &[
                "CONFIG_VIRTIO_BLK",
                "CONFIG_VIRTIO_PCI",
                "CONFIG_VIRTIO_MMIO",
            ],
            Self::RootFsMount => &["CONFIG_EROFS_FS", "CONFIG_OVERLAY_FS", "CONFIG_TMPFS"],
            Self::VsockTransport => &["CONFIG_VSOCKETS", "CONFIG_VIRTIO_VSOCKETS"],
            Self::NoDirectBootKernel => &[
                "CONFIG_PVH",
                "CONFIG_SERIAL_8250",
                "CONFIG_SERIAL_8250_CONSOLE",
            ],
        }
    }
}

/// Classify a serial log **captured from a VM that ran** and whose boot failed.
///
/// `None` means "no known §5.4 signature" — the residual class, which
/// [`explain_boot_failure`] still reports named-and-loud. A healthy boot log classifies as `None`.
///
/// An **empty** log is [`ContractViolation::NoDirectBootKernel`]: the VM ran and its console
/// produced nothing. That reading is only valid for a captured console — when no console evidence
/// exists (the VMM never started, the log could not be read) the caller must use
/// [`explain_without_serial`] instead of feeding an empty string here.
///
/// Precedence is most-specific-first: a root-fs panic quotes the banner it printed moments earlier,
/// and the vsock self-check runs only once userspace is up, so an earlier signature always wins.
/// Within the root failures the *device* signature outranks the *mount* signature, because a
/// missing device also ends in the generic `VFS: Unable to mount root fs` panic.
#[must_use]
pub fn classify_serial(log: &str) -> Option<ContractViolation> {
    if ROOT_DEVICE_SIGNATURES.iter().any(|s| log.contains(s)) {
        return Some(ContractViolation::RootDeviceMissing);
    }
    if ROOT_FS_MOUNT_SIGNATURES.iter().any(|s| log.contains(s)) {
        return Some(ContractViolation::RootFsMount);
    }
    if VSOCK_SIGNATURES.iter().any(|s| log.contains(s)) {
        return Some(ContractViolation::VsockTransport);
    }
    if !log.contains(BANNER_SIGNATURE) {
        return Some(ContractViolation::NoDirectBootKernel);
    }
    None
}

/// The §5.4 checklist pointer both renderers fall back to when no single clause is proven.
const CHECKLIST_POINTER: &str = "check the whole §5.4 guest-kernel contract checklist \
     (direct-boot PVH vmlinux; virtio pci/mmio/blk/net/console; vsock; fuse+virtio-fs; \
     erofs+overlay+tmpfs; ip-pnp; 8250 console) against the kernel's resolved .config";

/// Render a boot-failure message for a boot whose console **was captured**: `base` (the check's own
/// "what expired" sentence) followed by the classified §5.4 clause and its symbols, or — for the
/// residual class — the §5.4 checklist pointer; then the last [`SERIAL_TAIL_LINES`] non-empty lines
/// of the console.
///
/// With [`explain_without_serial`] this is one of the two renderers every [`crate::checks`] arm
/// that reports a failed start or a failed agent handshake goes through, so "the message names the
/// contract clause" is one law in one place (AGENTS.md, "One law, one predicate"). Which of the two
/// applies is decided by **whether
/// console evidence exists**, never by convenience: passing an empty `log` here asserts "the VM ran
/// and printed nothing", so a failure that produced no log at all belongs in
/// [`explain_without_serial`].
#[must_use]
pub fn explain_boot_failure(log: &str, base: &str) -> String {
    let mut msg = String::from(base);
    match classify_serial(log) {
        Some(v) => {
            msg.push_str("\n  contract violation: ");
            msg.push_str(v.clause());
            msg.push_str("\n  required kernel symbols (all =y): ");
            msg.push_str(&v.symbols().join(", "));
        }
        None => {
            msg.push_str("\n  no known §5.4 contract-violation signature in the serial log; ");
            msg.push_str(CHECKLIST_POINTER);
        }
    }
    msg.push_str("\n  serial tail:");
    let tail = serial_tail(log);
    if tail.is_empty() {
        msg.push_str(" (the serial console produced no output)");
    } else {
        for line in tail {
            msg.push_str("\n    ");
            msg.push_str(line);
        }
    }
    msg
}

/// Render a boot-failure message for a failure that produced **no console evidence at all** —
/// `no_evidence_because` says why (the VMM never started; the serial log could not be read).
///
/// It deliberately does **not** claim a contract violation. `MicroVm::start` fails for reasons that
/// have nothing to do with the artifact pair — a missing `cloud-hypervisor` binary, a tap/netns/
/// cgroup setup error, a VMM API error — and rendering those as "the image is not a direct-boot
/// PVH-ELF vmlinux" would name the wrong cause with full confidence. Instead it lists the candidate
/// causes, artifact ones included, so the §5.4 pointer is still there for the case where the VMM
/// really did reject the kernel image.
#[must_use]
pub fn explain_without_serial(base: &str, no_evidence_because: &str) -> String {
    let mut msg = String::from(base);
    msg.push_str("\n  no serial evidence: ");
    msg.push_str(no_evidence_because);
    msg.push_str(
        "\n  candidate causes, in the order they are cheapest to check: the VMM binary is missing \
         or refused to run; the host denied a resource (/dev/kvm, the network setup, a cgroup); \
         the VMM rejected the kernel image, which §5.4 requires to be a direct-boot PVH-ELF \
         vmlinux (CONFIG_PVH=y, never a bzImage, never the EFI stub); or the guest died before the \
         8250 console existed (CONFIG_SERIAL_8250=y, CONFIG_SERIAL_8250_CONSOLE=y). If the VMM did \
         start, ",
    );
    msg.push_str(CHECKLIST_POINTER);
    msg
}

/// The last [`SERIAL_TAIL_LINES`] non-empty lines of `log`, in order.
fn serial_tail(log: &str) -> Vec<&str> {
    let mut tail: Vec<&str> = log
        .lines()
        .map(str::trim_end)
        .filter(|l| !l.is_empty())
        .rev()
        .take(SERIAL_TAIL_LINES)
        .collect();
    tail.reverse();
    tail
}

/// Cross-check a resolved kernel `.config` (delta 3's `vmlinux-<label>.config` sidecar, parsed by
/// [`KconfigValues`]) against the symbols a classified violation names, returning the ones that are
/// **not built in**.
///
/// The predicate is [`KconfigValues::is_builtin`], not `is_enabled`: §5.4 requires `=y` for every
/// symbol [`ContractViolation::symbols`] names, and vmcell's guest has no early userspace to load a
/// module from — so `CONFIG_EROFS_FS=m` is exactly as broken as an absent symbol and must be
/// reported, not counted as satisfied.
///
/// This is the honest half of the classifier: the serial log says *which clause* broke, the
/// resolved config says *which symbol* `make olddefconfig` silently dropped (§5.6). An empty result
/// means the config disagrees with the console — worth reporting as-is, not as a missing symbol.
#[must_use]
pub fn missing_symbols(violation: ContractViolation, config: &KconfigValues) -> Vec<&'static str> {
    violation
        .symbols()
        .iter()
        .copied()
        .filter(|sym| !config.is_builtin(sym))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// vmcell's committed pins, the **other** copy of the §5.4 symbol roster (the design prose is
    /// the third). Embedded so `every_named_symbol_is_pinned_builtin` can cross-check them; the
    /// path reaches out of the crate directory exactly as `vmcell`'s own `COMMITTED_PINS` does
    /// (this crate is `publish = false`, and a git-dep consumer checks out the whole repository).
    const PINS_JSON: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../pins.json"));

    /// The next variant in the walk, as a **cycle**. Exhaustive on purpose: `#[non_exhaustive]`
    /// relaxes matching only for downstream crates, so a new [`ContractViolation`] variant is a
    /// compile error here until it is spliced in — which is what makes
    /// `every_violation_names_a_clause_and_symbols` and the pins cross-check cover it. Splice, do
    /// not append: an arm nothing points at is dead and the walk would never reach it.
    fn next_in_walk(v: ContractViolation) -> ContractViolation {
        match v {
            ContractViolation::RootDeviceMissing => ContractViolation::RootFsMount,
            ContractViolation::RootFsMount => ContractViolation::VsockTransport,
            ContractViolation::VsockTransport => ContractViolation::NoDirectBootKernel,
            ContractViolation::NoDirectBootKernel => ContractViolation::RootDeviceMissing,
        }
    }

    /// Every variant, by walking [`next_in_walk`]'s cycle once.
    fn all_violations() -> Vec<ContractViolation> {
        let start = ContractViolation::RootDeviceMissing;
        let mut out = vec![start];
        let mut v = next_in_walk(start);
        while v != start {
            assert!(
                !out.contains(&v),
                "the variant walk revisits {v:?} before closing"
            );
            out.push(v);
            v = next_in_walk(v);
        }
        out
    }

    /// `pins.json`'s `kernel.microvm_config`, parsed by this crate's own kconfig parser. Extracted
    /// textually (the crate has no JSON dependency): the value is one JSON string literal on one
    /// line, and a reflow fails this loudly rather than silently checking nothing.
    fn committed_microvm_config() -> KconfigValues {
        let line = PINS_JSON
            .lines()
            .find(|l| l.trim_start().starts_with("\"microvm_config\""))
            .expect("pins.json must carry kernel.microvm_config on one line");
        let (_, value) = line.split_once(':').expect("a JSON key: value line");
        let literal = value.trim().trim_end_matches(',');
        let inner = literal
            .strip_prefix('"')
            .and_then(|s| s.strip_suffix('"'))
            .expect("microvm_config is a JSON string literal");
        let text = inner.replace("\\n", "\n").replace("\\\"", "\"");
        KconfigValues::parse(&text).expect("pins.json's microvm_config is a valid .config fragment")
    }

    /// A realistic healthy CH boot: PVH banner, erofs root mounted, PID 1 up, vsock available.
    /// (The agent lines carry `tracing_subscriber`'s default fmt layout, target included.)
    const HEALTHY: &str = "\
[    0.000000] Linux version 6.12.94 (build@vmcell) (gcc (Debian 12.2.0-14) 12.2.0, GNU ld (GNU Binutils for Debian) 2.40) #1 SMP PREEMPT_DYNAMIC Fri Jul  3 11:22:41 UTC 2026
[    0.000000] Command line: console=ttyS0 loglevel=6 reboot=k panic=1 root=/dev/vda rootfstype=erofs ro init=/sbin/vmcell-guest-agent vmcell_vmid=7
[    0.000000] KERNEL supported cpus:
[    0.312004] virtio_blk virtio1: [vda] 40960 512-byte logical blocks (21.0 MB/20.0 MiB)
[    0.412233] EROFS (device vda): mounted with root inode @ nid 36.
[    0.418001] VFS: Mounted root (erofs filesystem) readonly on device 254:0.
[    0.421900] Run /sbin/vmcell-guest-agent as init process
2026-07-03T11:24:02.113842Z  INFO vmcell_guest_agent: vmcell-guest-agent: starting
2026-07-03T11:24:02.117001Z  INFO vmcell_guest_agent: vmcell-guest-agent: boot self-check: AF_VSOCK transport available
2026-07-03T11:24:02.118004Z  INFO vmcell_guest_agent: vmcell-guest-agent: boot self-check: virtiofs filesystem supported
2026-07-03T11:24:02.121550Z  INFO vmcell_guest_agent: vmcell-guest-agent: listening on vsock port 1024
";

    /// A kernel built without `CONFIG_EROFS_FS`: it boots, finds `vda`, and panics at root mount.
    /// (Kernel text from `init/do_mounts.c`; the observed §5.4 Firecracker-microVM-kernel failure.)
    const NO_EROFS: &str = "\
[    0.000000] Linux version 6.12.94 (build@vmcell) (gcc (Debian 12.2.0-14) 12.2.0) #1 SMP PREEMPT_DYNAMIC Fri Jul  3 11:22:41 UTC 2026
[    0.000000] Command line: console=ttyS0 loglevel=6 reboot=k panic=1 root=/dev/vda rootfstype=erofs ro init=/sbin/vmcell-guest-agent
[    0.395112] virtio_blk virtio1: [vda] 40960 512-byte logical blocks (21.0 MB/20.0 MiB)
[    0.401336] List of all partitions:
[    0.401770] fe00           20480 vda
[    0.401902]  driver: virtio_blk
[    0.402244] No filesystem could mount root, tried:
[    0.402901] Kernel panic - not syncing: VFS: Unable to mount root fs on unknown-block(254,0)
[    0.403001] CPU: 0 UID: 0 PID: 1 Comm: swapper/0 Not tainted 6.12.94 #1
[    0.403001] Call Trace:
[    0.403001]  panic+0x33c/0x360
";

    /// A kernel built without `CONFIG_VIRTIO_BLK` (or without the virtio transport): `vda` never
    /// appears, so the root *device* is missing. Note that the kernel ends in the **same**
    /// `VFS: Unable to mount root fs` panic as the no-filesystem case — the discriminator is the
    /// `Cannot open root device` line, which is why the device signature is checked first.
    const NO_VIRTIO_BLK: &str = "\
[    0.000000] Linux version 6.12.94 (build@vmcell) (gcc (Debian 12.2.0-14) 12.2.0) #1 SMP PREEMPT_DYNAMIC Fri Jul  3 11:22:41 UTC 2026
[    0.000000] Command line: console=ttyS0 loglevel=6 reboot=k panic=1 root=/dev/vda rootfstype=erofs ro init=/sbin/vmcell-guest-agent
[    0.401336] List of all partitions:
[    0.401770] No blockdev found
[    0.402244] VFS: Cannot open root device \"vda\" or unknown-block(0,0): error -6
[    0.402500] Please append a correct \"root=\" boot option; here are the available partitions:
[    0.402901] Kernel panic - not syncing: VFS: Unable to mount root fs on unknown-block(0,0)
";

    /// A kernel built without `CONFIG_VSOCKETS`: root mounts, PID 1 runs, the self-check reports the
    /// missing address family (errno 97 renders as prose — never as `EAFNOSUPPORT`).
    const NO_VSOCK: &str = "\
[    0.000000] Linux version 6.12.94 (build@vmcell) (gcc (Debian 12.2.0-14) 12.2.0) #1 SMP PREEMPT_DYNAMIC Fri Jul  3 11:22:41 UTC 2026
[    0.412233] EROFS (device vda): mounted with root inode @ nid 36.
[    0.421900] Run /sbin/vmcell-guest-agent as init process
2026-07-03T11:24:02.113842Z  INFO vmcell_guest_agent: vmcell-guest-agent: starting
2026-07-03T11:24:02.117412Z ERROR vmcell_guest_agent: vmcell-guest-agent: boot self-check: AF_VSOCK unavailable (Address family not supported by protocol (os error 97)); the vsock control plane will not come up
2026-07-03T11:24:02.118004Z  INFO vmcell_guest_agent: vmcell-guest-agent: boot self-check: virtiofs filesystem supported
";

    /// The later signature: the family exists but the listener bind fails (no `virtio_vsock`
    /// transport bound to the device).
    const VSOCK_BIND_FAILS: &str = "\
[    0.000000] Linux version 6.12.94 (build@vmcell) (gcc (Debian 12.2.0-14) 12.2.0) #1 SMP PREEMPT_DYNAMIC Fri Jul  3 11:22:41 UTC 2026
[    0.421900] Run /sbin/vmcell-guest-agent as init process
2026-07-03T11:24:02.117412Z  INFO vmcell_guest_agent: vmcell-guest-agent: boot self-check: AF_VSOCK transport available
2026-07-03T11:24:02.119003Z ERROR vmcell_guest_agent: vmcell-guest-agent: failed to bind vsock: No such device (os error 19)
";

    /// A guest whose *loopback* bring-up hits `EAFNOSUPPORT` — the same rendered errno prose as the
    /// vsock case, from a different, non-vsock clause. The agent's vsock self-check is green.
    const LOOPBACK_EAFNOSUPPORT: &str = "\
[    0.000000] Linux version 6.12.94 (build@vmcell) (gcc (Debian 12.2.0-14) 12.2.0) #1 SMP PREEMPT_DYNAMIC Fri Jul  3 11:22:41 UTC 2026
[    0.412233] EROFS (device vda): mounted with root inode @ nid 36.
2026-07-03T11:24:02.114900Z  WARN vmcell_guest_agent: vmcell-guest-agent: loopback bring-up failed: Address family not supported by protocol (os error 97); continuing without lo
2026-07-03T11:24:02.117001Z  INFO vmcell_guest_agent: vmcell-guest-agent: boot self-check: AF_VSOCK transport available
";

    // The headline §5.4 signature. Guards a classifier wired only to the timeout path or keyed on
    // "Kernel panic" (which `contains_panic` already matches and which names no clause).
    #[test]
    fn classify_root_fs_mount_panic() {
        assert_eq!(
            classify_serial(NO_EROFS),
            Some(ContractViolation::RootFsMount)
        );
        let msg = explain_boot_failure(NO_EROFS, "agent handshake failed");
        assert!(msg.contains("CONFIG_EROFS_FS"), "{msg}");
        assert!(msg.contains("CONFIG_OVERLAY_FS"), "{msg}");
        // The base message survives, and the tail quotes the panic line verbatim.
        assert!(msg.starts_with("agent handshake failed"), "{msg}");
        assert!(
            msg.contains("VFS: Unable to mount root fs on unknown-block(254,0)"),
            "{msg}"
        );
    }

    // A missing root DEVICE is not a missing filesystem driver. Guards the collapse of both root
    // failures into the erofs clause: `NO_VIRTIO_BLK` ends in the same `VFS: Unable to mount root
    // fs` panic as `NO_EROFS`, so a classifier that checks the mount signature first tells a kernel
    // missing CONFIG_VIRTIO_BLK to fix its erofs decompressor.
    #[test]
    fn classify_root_device_missing_outranks_the_mount_panic() {
        assert!(
            NO_VIRTIO_BLK.contains("VFS: Unable to mount root fs"),
            "the fixture must carry the shared panic line, or it proves nothing about precedence"
        );
        assert_eq!(
            classify_serial(NO_VIRTIO_BLK),
            Some(ContractViolation::RootDeviceMissing)
        );
        let msg = explain_boot_failure(NO_VIRTIO_BLK, "agent handshake failed");
        assert!(msg.contains("CONFIG_VIRTIO_BLK"), "{msg}");
        assert!(msg.contains("CONFIG_VIRTIO_PCI"), "{msg}");
        assert!(
            !msg.contains("CONFIG_EROFS_FS"),
            "a missing root device must not be blamed on the erofs decompressor: {msg}"
        );
        // …and the no-filesystem case still reaches the filesystem clause.
        assert_eq!(
            classify_serial(NO_EROFS),
            Some(ContractViolation::RootFsMount)
        );
    }

    // The vsock clause keys on the agent's own string. Guards a classifier written to the design's
    // literal wording (`EAFNOSUPPORT`), which would never fire on real output.
    #[test]
    fn classify_vsock_unavailable() {
        assert!(
            !NO_VSOCK.contains("EAFNOSUPPORT"),
            "the canned log must be what the guest really prints"
        );
        assert_eq!(
            classify_serial(NO_VSOCK),
            Some(ContractViolation::VsockTransport)
        );
        let msg = explain_boot_failure(NO_VSOCK, "agent handshake failed");
        assert!(msg.contains("CONFIG_VSOCKETS"), "{msg}");
        assert!(msg.contains("CONFIG_VIRTIO_VSOCKETS"), "{msg}");
    }

    // The second vsock signature (bind, not family). Guards keying on only the self-check line.
    #[test]
    fn classify_vsock_bind_failure() {
        assert_eq!(
            classify_serial(VSOCK_BIND_FAILS),
            Some(ContractViolation::VsockTransport)
        );
    }

    // Nothing on the console at all = not a direct-boot vmlinux. Guards a classifier that returns
    // `None` for an empty log (which would send the residual "check the whole checklist" text for
    // the one case we *can* name).
    #[test]
    fn classify_missing_banner() {
        assert_eq!(
            classify_serial(""),
            Some(ContractViolation::NoDirectBootKernel)
        );
        assert_eq!(
            classify_serial("   \n\n"),
            Some(ContractViolation::NoDirectBootKernel)
        );
        let msg = explain_boot_failure("", "the banner never appeared within 15s");
        assert!(msg.contains("CONFIG_PVH"), "{msg}");
        assert!(
            msg.contains("the serial console produced no output"),
            "{msg}"
        );
    }

    // Absence of evidence is not a contract violation. A VM that never started produced no console
    // for reasons that are usually NOT the artifact pair (a missing cloud-hypervisor binary, a
    // denied resource), so the message names candidates and keeps the §5.4 pointer — it must not
    // assert "the image is not a direct-boot PVH vmlinux". Guards a renderer that feeds `""` to
    // `explain_boot_failure` on this path.
    #[test]
    fn explain_without_serial_names_candidates_rather_than_asserting_a_violation() {
        let msg = explain_without_serial(
            "VM failed to start: VMM error: spawn cloud-hypervisor: No such file or directory",
            "MicroVm::start failed before any console was captured",
        );
        assert!(msg.starts_with("VM failed to start:"), "{msg}");
        assert!(
            !msg.contains("contract violation:"),
            "no clause is proven here: {msg}"
        );
        assert!(msg.contains("no serial evidence:"), "{msg}");
        assert!(msg.contains("the VMM binary is missing"), "{msg}");
        // The artifact cause stays reachable — it is one candidate among several.
        assert!(msg.contains("CONFIG_PVH=y"), "{msg}");
        assert!(
            msg.contains("§5.4 guest-kernel contract checklist"),
            "{msg}"
        );
    }

    // The positive control: a healthy boot must classify as nothing. Guards every over-broad
    // matcher at once — a healthy log contains "vsock", "VFS: Mounted root", "EROFS" and "panic"
    // is absent, so a matcher keyed on any of those substrings reddens here.
    #[test]
    fn classify_healthy_log_is_none() {
        assert!(HEALTHY.contains("vsock"), "the control must mention vsock");
        assert!(
            HEALTHY.contains("VFS: Mounted root"),
            "the control must contain a VFS line"
        );
        assert_eq!(classify_serial(HEALTHY), None);
    }

    // The rendered errno prose is NOT a signature: an unrelated AF_INET failure prints the exact
    // same words. Guards a classifier keyed on "Address family not supported".
    #[test]
    fn classify_unrelated_eafnosupport_is_not_the_vsock_clause() {
        assert!(
            LOOPBACK_EAFNOSUPPORT
                .contains("Address family not supported by protocol (os error 97)"),
            "the control must carry the same rendered errno as the vsock case"
        );
        assert_eq!(classify_serial(LOOPBACK_EAFNOSUPPORT), None);
    }

    // The residual class still fails named-and-loud: base sentence, checklist pointer, tail — and
    // no invented clause. Guards a renderer that reports only recognized violations.
    #[test]
    fn explain_unrecognized_failure_points_at_the_checklist() {
        let msg = explain_boot_failure(HEALTHY, "agent handshake failed within the 60s budget");
        assert!(
            msg.starts_with("agent handshake failed within the 60s budget"),
            "{msg}"
        );
        assert!(
            msg.contains("no known §5.4 contract-violation signature"),
            "{msg}"
        );
        assert!(!msg.contains("contract violation:"), "{msg}");
        assert!(msg.contains("listening on vsock port 1024"), "{msg}");
    }

    // The tail is a TAIL and it is bounded. Guards `take` on the un-reversed iterator (the head)
    // and an unbounded quote of a multi-megabyte serial log.
    #[test]
    fn explain_quotes_a_bounded_tail_not_the_head() {
        let mut log = String::from("[    0.000000] Linux version 6.12.94 first-line-marker\n");
        for i in 0..500 {
            log.push_str(&format!("[    1.0000{i:02}] filler line {i}\n"));
        }
        let msg = explain_boot_failure(&log, "boot failed");
        assert!(msg.contains("filler line 499"), "tail must reach the end");
        assert!(
            !msg.contains("first-line-marker"),
            "the head must not be quoted: {msg}"
        );
        assert_eq!(
            msg.matches("\n    ").count(),
            SERIAL_TAIL_LINES,
            "exactly {SERIAL_TAIL_LINES} tail lines"
        );
    }

    // Every variant carries a clause and at least one symbol. The list comes from `all_violations`,
    // whose `next_in_walk` match is exhaustive — so a variant added with `clause() => ""` and
    // `symbols() => &[]` does not compile until it is in the walk, and then reddens here. (The
    // former hand-written array covered exactly the three variants someone typed into it.)
    #[test]
    fn every_violation_names_a_clause_and_symbols() {
        let all = all_violations();
        assert!(
            all.contains(&ContractViolation::RootFsMount)
                && all.contains(&ContractViolation::RootDeviceMissing)
                && all.contains(&ContractViolation::VsockTransport)
                && all.contains(&ContractViolation::NoDirectBootKernel),
            "the walk dropped a known variant: {all:?}"
        );
        for v in all {
            assert!(v.clause().contains("§5.4"), "{v:?}");
            assert!(!v.symbols().is_empty(), "{v:?}");
            for sym in v.symbols() {
                assert!(sym.starts_with("CONFIG_"), "{sym}");
            }
        }
    }

    // The §5.4 symbol roster exists in three copies — the design prose, `pins.json`'s
    // `kernel.microvm_config`, and `symbols()` here — and nothing used to cross-check them, which
    // is how the root-device symbols went missing. Every symbol this module names must be pinned
    // `=y` in the config vmcell itself builds with. Guards a typo'd or invented symbol name too.
    #[test]
    fn every_named_symbol_is_pinned_builtin() {
        let cfg = committed_microvm_config();
        assert!(
            cfg.len() > 20,
            "the microvm_config extraction produced {} symbols — it is checking nothing",
            cfg.len()
        );
        for v in all_violations() {
            for sym in v.symbols() {
                assert!(
                    cfg.is_builtin(sym),
                    "{sym} (named by {v:?}) is not =y in pins.json's kernel.microvm_config — the \
                     §5.4 roster has diverged between the classifier and the pinned kernel config"
                );
            }
        }
    }

    // The config cross-check names the symbol `olddefconfig` dropped, and stays quiet when the
    // config disagrees with the console. Guards an inverted `is_enabled` filter.
    #[test]
    fn missing_symbols_names_what_the_resolved_config_dropped() {
        let cfg = KconfigValues::parse("CONFIG_VSOCKETS=y\n# CONFIG_VIRTIO_VSOCKETS is not set\n")
            .expect("parse");
        assert_eq!(
            missing_symbols(ContractViolation::VsockTransport, &cfg),
            vec!["CONFIG_VIRTIO_VSOCKETS"]
        );
        let both =
            KconfigValues::parse("CONFIG_VSOCKETS=y\nCONFIG_VIRTIO_VSOCKETS=y\n").expect("parse");
        assert!(missing_symbols(ContractViolation::VsockTransport, &both).is_empty());
    }

    // `=m` is NOT a satisfied §5.4 clause: the guest has no early userspace, so a module is never
    // loaded and the symbol is as missing as an absent one. Guards `missing_symbols` filtering on
    // `is_enabled` (y|m) — under which the exact case the cross-check exists to name (the console
    // says the root mount failed, the resolved .config says `CONFIG_EROFS_FS=m`) reported "no
    // missing symbols", i.e. "the config disagrees with the console".
    #[test]
    fn missing_symbols_counts_a_module_as_missing() {
        let cfg = KconfigValues::parse("CONFIG_EROFS_FS=m\nCONFIG_OVERLAY_FS=y\nCONFIG_TMPFS=y\n")
            .expect("parse");
        assert!(cfg.is_enabled("CONFIG_EROFS_FS"), "the fixture must be =m");
        assert_eq!(
            missing_symbols(ContractViolation::RootFsMount, &cfg),
            vec!["CONFIG_EROFS_FS"]
        );
    }
}
