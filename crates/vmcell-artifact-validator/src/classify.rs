//! The pure serial-log classifier: map a failed boot's console output onto the **§5.4 guest-kernel
//! contract clause** it broke (design §5.4, The guest-kernel contract and the bootstrap seed; §5.6,
//! The downstream kernel toolkit — "fails a named check loudly, not by hanging").
//!
//! A kernel missing a baseline symbol used to fail [`crate::checks::kernel_banner`] or
//! `boot.steward_ready` with a raw timeout and a raw serial tail. This module turns the known
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
//! [`explain_boot_failure_of`] is for a boot whose console **was captured** (possibly empty: the VM
//! ran and printed nothing, which is itself evidence). [`explain_without_serial`] is for a failure
//! where **no console evidence exists at all** — the VMM never started, or its log could not be
//! read — and it names candidate causes instead of asserting a contract violation, because absence
//! of evidence is not evidence of a bad kernel (a missing `cloud-hypervisor` binary lands there
//! too). Every arm of [`crate::checks`] that **reports** a VM which failed to start
//! (`MicroVm::start`) or failed its steward handshake routes through one of the two — Core,
//! Extended and Full alike, gated by `run_core_records_the_whole_roster_when_the_vm_never_starts`
//! and `every_extended_and_full_boot_failure_names_the_missing_evidence`.
//!
//! ## A restored VM's empty console is not a missing kernel
//! The captured-console renderer takes a [`BootKind`], because "nothing reached the console" means
//! opposite things for the two: a **fresh** boot that printed nothing never ran a kernel, while a
//! **restored** VM's console is empty *by construction* — its kernel printed the banner in the
//! snapshot source, minutes and one process ago. Feeding a restored VM's console to the fresh-boot
//! reading told `snapshot.restore_roundtrip` that a kernel which provably just booted "is not a
//! direct-boot PVH-ELF vmlinux". The kind is an explicit argument at every call site (no default)
//! so the question is answered, not assumed.
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
//! - the vsock clause from the steward's **own** boot self-check
//!   (`vmcell-steward: boot self-check: AF_VSOCK unavailable (…)`, emitted on `/dev/console`
//!   by PID 1 before it binds the listener). The design's wording names a vsock `EAFNOSUPPORT`;
//!   that mnemonic appears in **no** serial log — the errno renders as `Address family not
//!   supported by protocol (os error 97)`, and that phrase alone is *not* a signature either
//!   (the steward prints it verbatim for an unrelated `AF_INET` loopback failure). Keying on the
//!   steward's own stable prefix is both narrower and more reliable.

use std::borrow::Cow;

use vmcell::feature::{Feature, Removal};

use crate::kconfig::KconfigValues;

/// How many trailing non-empty serial lines [`explain_boot_failure_of`] quotes.
///
/// A line count is **not** a size bound: the console is guest-controlled, and a guest that prints
/// one un-newlined multi-megabyte line satisfies any line count while carrying the whole flood into
/// the caller's report. The size promise is kept by [`SERIAL_TAIL_MAX_LINE_BYTES`] and
/// [`SERIAL_TAIL_MAX_BYTES`]; all three bounds apply, whichever binds first.
pub const SERIAL_TAIL_LINES: usize = 20;

/// The per-line byte cap on a quoted serial line. A longer line is truncated at a UTF-8 boundary
/// and marked with [`TRUNCATION_MARKER`] naming the elided byte count, so the reader knows the
/// quote is partial rather than seeing a silently shortened kernel message.
pub const SERIAL_TAIL_MAX_LINE_BYTES: usize = 512;

/// The total byte cap over every quoted line together — the bound that actually keeps a
/// multi-megabyte console out of a caller's report when the flood is spread over many lines.
/// Lines are taken from the end (it is a *tail*), so the newest output survives the cap.
///
/// Larger than [`SERIAL_TAIL_MAX_LINE_BYTES`] by construction, so one capped line always fits and
/// the tail is never rendered empty for a console that did produce output
/// (`the_line_cap_fits_inside_the_total_cap`).
pub const SERIAL_TAIL_MAX_BYTES: usize = 4096;

/// What a truncated tail line ends with, before the elided byte count. Public so a caller matching
/// on the rendered message has the literal rather than a copy of it.
pub const TRUNCATION_MARKER: &str = "… truncated, ";

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

/// The steward's own vsock diagnostics (`vmcell-steward/src/main.rs`). Both reach the
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

/// Which boot the captured console belongs to — the one fact that decides whether an **absent**
/// kernel banner is evidence about the kernel image.
///
/// Non-exhaustive for the same reason as [`ContractViolation`]: this crate is downstream contract
/// surface (§10.4), and a third console origin (a zygote clone's, say) must not break a consumer.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum BootKind {
    /// The VM was started from its kernel entry point (`MicroVm::start`). The kernel banner must
    /// appear, so its absence is the [`ContractViolation::NoDirectBootKernel`] signature.
    Fresh,
    /// The VM was resumed from a snapshot (`MicroVm::restore`). Its kernel booted in the snapshot
    /// **source** — a different VM, a different console file — so the restored instance's console
    /// starts empty by construction and an absent banner proves nothing about the kernel image.
    /// Every other §5.4 signature still applies: a restored guest that prints one reaches the same
    /// clause a fresh one would.
    Restored,
}

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
                 plane cannot come up (the steward's own boot self-check reported it)"
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

/// Classify a **fresh** boot's serial log — [`classify_serial_of`] with [`BootKind::Fresh`].
///
/// Kept as the short spelling for the common case (every check that boots a VM from its kernel
/// entry point); a restored VM's console must go through [`classify_serial_of`] instead, because
/// the missing-banner arm below does not hold for it.
#[must_use]
pub fn classify_serial(log: &str) -> Option<ContractViolation> {
    classify_serial_of(BootKind::Fresh, log)
}

/// Classify a serial log **captured from a VM that ran** and whose boot failed.
///
/// `None` means "no known §5.4 signature" — the residual class, which
/// [`explain_boot_failure_of`] still reports named-and-loud. A healthy boot log classifies as
/// `None`.
///
/// An **empty** log is [`ContractViolation::NoDirectBootKernel`] for a [`BootKind::Fresh`] boot:
/// the VM ran and its console produced nothing. That reading is only valid for a captured console
/// — when no console evidence exists (the VMM never started, the log could not be read) the caller
/// must use [`explain_without_serial`] instead of feeding an empty string here — and only for a
/// fresh boot: a [`BootKind::Restored`] VM's console is empty by construction, so the arm is not
/// applied to it and the residual class (`None`) is the honest answer.
///
/// Precedence is most-specific-first: a root-fs panic quotes the banner it printed moments earlier,
/// and the vsock self-check runs only once userspace is up, so an earlier signature always wins.
/// Within the root failures the *device* signature outranks the *mount* signature, because a
/// missing device also ends in the generic `VFS: Unable to mount root fs` panic.
#[must_use]
pub fn classify_serial_of(kind: BootKind, log: &str) -> Option<ContractViolation> {
    if ROOT_DEVICE_SIGNATURES.iter().any(|s| log.contains(s)) {
        return Some(ContractViolation::RootDeviceMissing);
    }
    if ROOT_FS_MOUNT_SIGNATURES.iter().any(|s| log.contains(s)) {
        return Some(ContractViolation::RootFsMount);
    }
    if VSOCK_SIGNATURES.iter().any(|s| log.contains(s)) {
        return Some(ContractViolation::VsockTransport);
    }
    // Fresh only: a restored VM never re-runs the kernel's early boot, so it never re-prints the
    // banner (§8.2) and the absence carries no information about the kernel image.
    if matches!(kind, BootKind::Fresh) && !log.contains(BANNER_SIGNATURE) {
        return Some(ContractViolation::NoDirectBootKernel);
    }
    None
}

/// The §5.4 checklist pointer both renderers fall back to when no single clause is proven.
const CHECKLIST_POINTER: &str = "check the whole §5.4 guest-kernel contract checklist \
     (direct-boot PVH vmlinux; virtio pci/mmio/blk/net/console; vsock; fuse+virtio-fs; \
     erofs+overlay+tmpfs; ip-pnp; 8250 console) against the kernel's resolved .config";

/// The note a restored VM's empty console gets instead of the fresh boot's "not a direct-boot
/// vmlinux" verdict — the honest reading of the same absence (§8.2).
const RESTORED_EMPTY_CONSOLE_NOTE: &str = "this console belongs to a VM RESTORED from a snapshot: \
     its kernel printed the boot banner in the snapshot source, on that VM's console, so an empty \
     console here is expected and says nothing about the kernel image. Look at the restore path \
     first (the snapshot directory's contents, the VMM's restore API, the steward's post-restore \
     resync) before the §5.4 kernel contract";

/// Render a boot-failure message for a **fresh** boot whose console was captured —
/// [`explain_boot_failure_of`] with [`BootKind::Fresh`].
#[must_use]
pub fn explain_boot_failure(log: &str, base: &str) -> String {
    explain_boot_failure_of(BootKind::Fresh, log, base)
}

/// Render a boot-failure message for a boot whose console **was captured**: `base` (the check's own
/// "what expired" sentence) followed by the classified §5.4 clause and its symbols, or — for the
/// residual class — the §5.4 checklist pointer; then the last [`SERIAL_TAIL_LINES`] non-empty lines
/// of the console, bounded by [`SERIAL_TAIL_MAX_LINE_BYTES`] and [`SERIAL_TAIL_MAX_BYTES`].
///
/// With [`explain_without_serial`] this is one of the two renderers every [`crate::checks`] arm
/// that reports a failed start or a failed steward handshake goes through, so "the message names the
/// contract clause" is one law in one place (AGENTS.md, "One law, one predicate"). Which of the two
/// applies is decided by **whether
/// console evidence exists**, never by convenience: passing an empty `log` here asserts "the VM ran
/// and printed nothing", so a failure that produced no log at all belongs in
/// [`explain_without_serial`].
///
/// `kind` decides how the *absence* of a banner reads (see [`BootKind`]); a
/// [`BootKind::Restored`] console with no banner is reported as the residual class **plus** the
/// note explaining why its emptiness is expected, never as "this is not a kernel".
#[must_use]
pub fn explain_boot_failure_of(kind: BootKind, log: &str, base: &str) -> String {
    let mut msg = String::from(base);
    match classify_serial_of(kind, log) {
        Some(v) => {
            msg.push_str("\n  contract violation: ");
            msg.push_str(v.clause());
            msg.push_str("\n  required kernel symbols (all =y): ");
            msg.push_str(&v.symbols().join(", "));
        }
        None => {
            msg.push_str("\n  no known §5.4 contract-violation signature in the serial log; ");
            msg.push_str(CHECKLIST_POINTER);
            if matches!(kind, BootKind::Restored) && !log.contains(BANNER_SIGNATURE) {
                msg.push_str("\n  note: ");
                msg.push_str(RESTORED_EMPTY_CONSOLE_NOTE);
            }
        }
    }
    msg.push_str("\n  serial tail:");
    let tail = serial_tail(log);
    if tail.is_empty() {
        msg.push_str(" (the serial console produced no output)");
    } else {
        for line in &tail {
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

// ---------------------------------------------------------------------------
// The conformance renderers (design §10.6, §18 delta 3)
// ---------------------------------------------------------------------------
//
// A `Warn` goes through the classifier for exactly the reason a `Fail` does: "an under-claim with
// no explanation is a bare bool again" (§10.6). The three below are the only places a conformance
// verdict's prose is composed, and every one of them names the feature through `Feature::name()`
// (F6: refusal and report strings are composed from the vocabulary, never hand-spelled — which is
// what lets a test match on the feature name instead of on a phrase).

/// Render the message a [`crate::CheckStatus::Fail`] carries when a **declared-present** feature
/// does not hold.
///
/// `removal` is `Some` when an axis of the substrate positively removes the feature — the §7.4
/// provenance case, where the message must name *who* says it cannot work (a backend, the host, the
/// config), because "it failed" and "this backend never had it" are different bugs with different
/// owners. `evidence` is what the probe actually observed.
#[must_use]
pub fn explain_broken_claim(
    feature: Feature,
    artifact: &str,
    removal: Option<&Removal>,
    evidence: &str,
) -> String {
    let mut msg = format!(
        "artifact \"{artifact}\" declares `{}` and it does not hold here",
        feature.name()
    );
    if let Some(removal) = removal {
        // `Removal`'s own Display: `<feature>: unavailable (<source> <reason>)` — the one spelling,
        // so the provenance a consumer reads here is byte-identical to the one `vmcell`'s typed
        // refusals carry.
        msg.push_str("\n  provenance: ");
        msg.push_str(&removal.to_string());
    }
    msg.push_str("\n  evidence: ");
    msg.push_str(evidence);
    msg.push_str(
        "\n  a DECLARED feature that does not work is an error: the declaration is the claim a \
         consumer builds fixtures on. Either the artifact must deliver it, or the declaration must \
         stop claiming it (§7.4 — the registry entry is the one authority, its sidecar the travel \
         form).",
    );
    msg
}

/// Render the message a [`crate::CheckStatus::Warn`] carries: the artifact declares the feature
/// **absent** and the data plane says otherwise, with the positive control that proves the probe
/// discriminates.
///
/// Deliberately *not* phrased as a failure. Under-claiming is a documentation defect; reddening it
/// would push declarers toward over-claiming, which is the direction this kit cannot catch cheaply
/// and the one that actually breaks consumers.
#[must_use]
pub fn explain_underclaim(feature: Feature, artifact: &str, control: &str) -> String {
    format!(
        "artifact \"{artifact}\" declares `{}` ABSENT, but the probe demonstrated it working — an \
         under-claim.\n  positive control: the same probe answered \"works\" for \"{control}\", \
         which is what makes \"works\" here a measurement rather than a probe that always says \
         yes.\n  this is a DOCUMENTATION defect, not a runtime one: nothing in the cell is broken, \
         and it is not reported as a failure because reddening an under-claim pushes declarers \
         toward over-claiming. Fix the declaration (§7.4) or disposition it in \
         `expected_warnings` (§10.6).",
        feature.name()
    )
}

/// Render the message a [`crate::CheckStatus::Unverified`] carries: an absence that **cannot be
/// decided**, and why.
///
/// The state exists because proving a negative is sometimes impractical, and an honest kit says so
/// per check instead of quietly counting the absence as verified — the same distinction
/// [`KconfigValues::get`] draws between a symbol `olddefconfig` dropped and one the author
/// disabled.
#[must_use]
pub fn explain_undecidable(feature: Feature, artifact: &str, why: &str) -> String {
    format!(
        "artifact \"{artifact}\"'s declaration about `{}` could not be decided: {why}.\n  an \
         undecidable absence is NEVER counted as a pass — it is reported so the caller knows this \
         part of the claim is unmeasured, exactly as a skip is.",
        feature.name()
    )
}

/// The last non-empty lines of `log`, in order, under all three bounds: at most
/// [`SERIAL_TAIL_LINES`] lines, each at most [`SERIAL_TAIL_MAX_LINE_BYTES`] bytes (longer ones are
/// truncated and marked), and at most [`SERIAL_TAIL_MAX_BYTES`] bytes in total.
///
/// The console is **guest-controlled**, so the line count alone bounds nothing: one un-newlined
/// multi-megabyte line, or 20 one-megabyte ones, satisfy it while flooding the caller's report (and
/// vmcell's own logs, since these messages are persisted artifacts). Lines are consumed from the
/// end, so the byte budget is spent on the newest output — the part a boot failure is diagnosed
/// from.
fn serial_tail(log: &str) -> Vec<Cow<'_, str>> {
    let mut tail: Vec<Cow<'_, str>> = Vec::new();
    let mut budget = SERIAL_TAIL_MAX_BYTES;
    for line in log
        .lines()
        .map(str::trim_end)
        .filter(|l| !l.is_empty())
        .rev()
        .take(SERIAL_TAIL_LINES)
    {
        let quoted = cap_line(line);
        // A capped line always fits an untouched budget (`the_line_cap_fits_inside_the_total_cap`),
        // so this only ever stops a tail that already has lines in it — never renders an empty one
        // for a console that produced output.
        if quoted.len() > budget {
            break;
        }
        budget -= quoted.len();
        tail.push(quoted);
    }
    tail.reverse();
    tail
}

/// One tail line, truncated to [`SERIAL_TAIL_MAX_LINE_BYTES`] at a UTF-8 boundary and marked with
/// the elided byte count. Borrowed unchanged when it already fits.
fn cap_line(line: &str) -> Cow<'_, str> {
    if line.len() <= SERIAL_TAIL_MAX_LINE_BYTES {
        return Cow::Borrowed(line);
    }
    // Walk back to a char boundary: a guest can emit multi-byte UTF-8 (or invalid bytes that
    // `read_to_string` already replaced), and slicing mid-character panics.
    let mut end = SERIAL_TAIL_MAX_LINE_BYTES;
    while end > 0 && !line.is_char_boundary(end) {
        end -= 1;
    }
    let head = line.get(..end).unwrap_or("");
    Cow::Owned(format!(
        "{head}{TRUNCATION_MARKER}{} bytes elided",
        line.len() - end
    ))
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
    /// (The steward lines carry `tracing_subscriber`'s default fmt layout, target included.)
    const HEALTHY: &str = "\
[    0.000000] Linux version 6.12.94 (build@vmcell) (gcc (Debian 12.2.0-14) 12.2.0, GNU ld (GNU Binutils for Debian) 2.40) #1 SMP PREEMPT_DYNAMIC Fri Jul  3 11:22:41 UTC 2026
[    0.000000] Command line: console=ttyS0 loglevel=6 reboot=k panic=1 root=/dev/vda rootfstype=erofs ro init=/sbin/vmcell-steward vmcell_vmid=7
[    0.000000] KERNEL supported cpus:
[    0.312004] virtio_blk virtio1: [vda] 40960 512-byte logical blocks (21.0 MB/20.0 MiB)
[    0.412233] EROFS (device vda): mounted with root inode @ nid 36.
[    0.418001] VFS: Mounted root (erofs filesystem) readonly on device 254:0.
[    0.421900] Run /sbin/vmcell-steward as init process
2026-07-03T11:24:02.113842Z  INFO vmcell_steward: vmcell-steward: starting
2026-07-03T11:24:02.117001Z  INFO vmcell_steward: vmcell-steward: boot self-check: AF_VSOCK transport available
2026-07-03T11:24:02.118004Z  INFO vmcell_steward: vmcell-steward: boot self-check: virtiofs filesystem supported
2026-07-03T11:24:02.121550Z  INFO vmcell_steward: vmcell-steward: listening on vsock port 1024
";

    /// A kernel built without `CONFIG_EROFS_FS`: it boots, finds `vda`, and panics at root mount.
    /// (Kernel text from `init/do_mounts.c`; the observed §5.4 Firecracker-microVM-kernel failure.)
    const NO_EROFS: &str = "\
[    0.000000] Linux version 6.12.94 (build@vmcell) (gcc (Debian 12.2.0-14) 12.2.0) #1 SMP PREEMPT_DYNAMIC Fri Jul  3 11:22:41 UTC 2026
[    0.000000] Command line: console=ttyS0 loglevel=6 reboot=k panic=1 root=/dev/vda rootfstype=erofs ro init=/sbin/vmcell-steward
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
[    0.000000] Command line: console=ttyS0 loglevel=6 reboot=k panic=1 root=/dev/vda rootfstype=erofs ro init=/sbin/vmcell-steward
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
[    0.421900] Run /sbin/vmcell-steward as init process
2026-07-03T11:24:02.113842Z  INFO vmcell_steward: vmcell-steward: starting
2026-07-03T11:24:02.117412Z ERROR vmcell_steward: vmcell-steward: boot self-check: AF_VSOCK unavailable (Address family not supported by protocol (os error 97)); the vsock control plane will not come up
2026-07-03T11:24:02.118004Z  INFO vmcell_steward: vmcell-steward: boot self-check: virtiofs filesystem supported
";

    /// The later signature: the family exists but the listener bind fails (no `virtio_vsock`
    /// transport bound to the device).
    const VSOCK_BIND_FAILS: &str = "\
[    0.000000] Linux version 6.12.94 (build@vmcell) (gcc (Debian 12.2.0-14) 12.2.0) #1 SMP PREEMPT_DYNAMIC Fri Jul  3 11:22:41 UTC 2026
[    0.421900] Run /sbin/vmcell-steward as init process
2026-07-03T11:24:02.117412Z  INFO vmcell_steward: vmcell-steward: boot self-check: AF_VSOCK transport available
2026-07-03T11:24:02.119003Z ERROR vmcell_steward: vmcell-steward: failed to bind vsock: No such device (os error 19)
";

    /// A guest whose *loopback* bring-up hits `EAFNOSUPPORT` — the same rendered errno prose as the
    /// vsock case, from a different, non-vsock clause. The steward's vsock self-check is green.
    const LOOPBACK_EAFNOSUPPORT: &str = "\
[    0.000000] Linux version 6.12.94 (build@vmcell) (gcc (Debian 12.2.0-14) 12.2.0) #1 SMP PREEMPT_DYNAMIC Fri Jul  3 11:22:41 UTC 2026
[    0.412233] EROFS (device vda): mounted with root inode @ nid 36.
2026-07-03T11:24:02.114900Z  WARN vmcell_steward: vmcell-steward: loopback bring-up failed: Address family not supported by protocol (os error 97); continuing without lo
2026-07-03T11:24:02.117001Z  INFO vmcell_steward: vmcell-steward: boot self-check: AF_VSOCK transport available
";

    // The headline §5.4 signature. Guards a classifier wired only to the timeout path or keyed on
    // "Kernel panic" (which `contains_panic` already matches and which names no clause).
    #[test]
    fn classify_root_fs_mount_panic() {
        assert_eq!(
            classify_serial(NO_EROFS),
            Some(ContractViolation::RootFsMount)
        );
        let msg = explain_boot_failure(NO_EROFS, "steward handshake failed");
        assert!(msg.contains("CONFIG_EROFS_FS"), "{msg}");
        assert!(msg.contains("CONFIG_OVERLAY_FS"), "{msg}");
        // The base message survives, and the tail quotes the panic line verbatim.
        assert!(msg.starts_with("steward handshake failed"), "{msg}");
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
        let msg = explain_boot_failure(NO_VIRTIO_BLK, "steward handshake failed");
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

    // The vsock clause keys on the steward's own string. Guards a classifier written to the design's
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
        let msg = explain_boot_failure(NO_VSOCK, "steward handshake failed");
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
        let msg = explain_boot_failure(HEALTHY, "steward handshake failed within the 60s budget");
        assert!(
            msg.starts_with("steward handshake failed within the 60s budget"),
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

    // m9, BOTH arms. A restored VM's console is empty BY CONSTRUCTION (its kernel printed the
    // banner in the snapshot source), so the fresh-boot reading of "no banner" — "this is not a
    // direct-boot PVH-ELF vmlinux" — diagnosed a kernel that provably just booted as not being a
    // kernel. Guards the classifier that ignores `BootKind` (either direction): dropping the
    // `Fresh` conjunct greens the restored assertions but reddens the fresh ones, and hard-coding
    // `Restored` reddens the fresh ones.
    #[test]
    fn a_restored_vms_empty_console_is_not_a_missing_kernel() {
        // Fresh: unchanged, still the one case we CAN name.
        assert_eq!(
            classify_serial_of(BootKind::Fresh, ""),
            Some(ContractViolation::NoDirectBootKernel)
        );
        // Restored: no clause is proven.
        assert_eq!(classify_serial_of(BootKind::Restored, ""), None);
        assert_eq!(classify_serial_of(BootKind::Restored, "   \n\n"), None);

        let base = "restored VM: steward handshake failed within the 60s budget";
        let restored = explain_boot_failure_of(BootKind::Restored, "", base);
        assert!(restored.starts_with(base), "{restored}");
        assert!(
            !restored.contains("contract violation:"),
            "no §5.4 clause is proven by a restored VM's empty console: {restored}"
        );
        assert!(
            !restored.contains("CONFIG_PVH"),
            "a restored VM must not be told its kernel is not a direct-boot vmlinux: {restored}"
        );
        assert!(
            restored.contains("RESTORED from a snapshot"),
            "the message must say why the empty console is expected: {restored}"
        );
        assert!(
            restored.contains("the snapshot directory"),
            "the message must point at the restore path: {restored}"
        );

        // The fresh renderer keeps the verdict it earned.
        let fresh = explain_boot_failure_of(BootKind::Fresh, "", "the banner never appeared");
        assert!(fresh.contains("CONFIG_PVH"), "{fresh}");
        assert!(!fresh.contains("RESTORED from a snapshot"), "{fresh}");
    }

    // The kind relaxes ONLY the banner arm: a restored guest that really does print a §5.4
    // signature reaches the same clause a fresh one would. Guards a `BootKind::Restored` arm that
    // short-circuits the whole classifier to `None`.
    #[test]
    fn a_restored_console_still_reaches_every_other_clause() {
        for (log, want) in [
            (NO_EROFS, ContractViolation::RootFsMount),
            (NO_VIRTIO_BLK, ContractViolation::RootDeviceMissing),
            (VSOCK_BIND_FAILS, ContractViolation::VsockTransport),
        ] {
            assert_eq!(
                classify_serial_of(BootKind::Restored, log),
                Some(want),
                "a restored VM's console must still classify {want:?}"
            );
        }
        // …and a healthy restored console is still the residual class, with no restored note
        // (the banner IS there — this console is not the empty-by-construction case).
        assert_eq!(classify_serial_of(BootKind::Restored, HEALTHY), None);
        let msg = explain_boot_failure_of(BootKind::Restored, HEALTHY, "handshake failed");
        assert!(!msg.contains("RESTORED from a snapshot"), "{msg}");
    }

    // The default spelling is the fresh one, so the short `classify_serial`/`explain_boot_failure`
    // wrappers cannot drift from the `BootKind::Fresh` path they claim to be.
    #[test]
    fn the_short_spellings_are_the_fresh_boot_kind() {
        for log in ["", HEALTHY, NO_EROFS, NO_VIRTIO_BLK, NO_VSOCK] {
            assert_eq!(
                classify_serial(log),
                classify_serial_of(BootKind::Fresh, log)
            );
            assert_eq!(
                explain_boot_failure(log, "base"),
                explain_boot_failure_of(BootKind::Fresh, log, "base")
            );
        }
    }

    // m17: the per-line cap must fit inside the total cap, or a single over-long line would blow
    // the whole budget and `serial_tail` would render an EMPTY tail ("the serial console produced
    // no output") for a console that produced plenty. Guards a future cap edit that inverts them.
    #[test]
    fn the_line_cap_fits_inside_the_total_cap() {
        // The rendered worst case: a full-length head plus the marker and a 7-digit byte count.
        let worst =
            SERIAL_TAIL_MAX_LINE_BYTES + TRUNCATION_MARKER.len() + " bytes elided".len() + 9;
        assert!(
            worst < SERIAL_TAIL_MAX_BYTES,
            "a single capped line ({worst} B) must fit the total budget ({SERIAL_TAIL_MAX_BYTES} B)"
        );
    }

    // m17, the headline case. `SERIAL_TAIL_LINES` bounds LINES, and the console is
    // guest-controlled: one un-newlined multi-megabyte line satisfies the line count while carrying
    // the whole flood into the caller's report (and into vmcell's persisted logs), which is exactly
    // what the const's rustdoc promised could not happen. Guards a `serial_tail` with no byte cap:
    // the length assertion below reddens with a ~4 MB message.
    #[test]
    fn explain_bounds_a_single_multi_megabyte_console_line() {
        let flood = "F".repeat(4 * 1024 * 1024);
        let mut log = String::from("[    0.000000] Linux version 6.12.94 (build@vmcell)\n");
        log.push_str("[    1.000000] guest-flood: ");
        log.push_str(&flood);
        log.push_str(" END-OF-FLOOD\n");
        assert!(log.len() > 4 * 1024 * 1024, "the fixture must be a flood");

        let msg = explain_boot_failure(&log, "steward handshake failed");
        assert!(
            msg.len() < 8 * 1024,
            "a failure message must not carry a multi-megabyte console: {} bytes",
            msg.len()
        );
        assert!(
            !msg.contains("END-OF-FLOOD"),
            "the over-long line must be truncated, not quoted whole"
        );
        assert!(
            msg.contains(TRUNCATION_MARKER) && msg.contains("bytes elided"),
            "a truncated quote must say so, with the elided byte count: {msg}"
        );
        // The head of the line survives, so the reader still sees what the guest was printing.
        assert!(msg.contains("guest-flood: FFFF"), "{msg}");
    }

    // m17, the other direction: many long lines. The per-line cap alone leaves
    // `SERIAL_TAIL_LINES * SERIAL_TAIL_MAX_LINE_BYTES` bytes reachable, so the TOTAL cap is what
    // binds here — and it must spend its budget on the NEWEST lines (it is a tail).
    #[test]
    fn explain_bounds_the_total_tail_across_many_long_lines() {
        let mut log = String::from("[    0.000000] Linux version 6.12.94 (build@vmcell)\n");
        for i in 0..40 {
            log.push_str(&format!("[    1.0{i:03}] line-{i}: {}\n", "L".repeat(900)));
        }
        let msg = explain_boot_failure(&log, "steward handshake failed");
        assert!(
            msg.len() < SERIAL_TAIL_MAX_BYTES + 2048,
            "the quoted tail must respect the total byte cap: {} bytes",
            msg.len()
        );
        let quoted = msg.matches("\n    ").count();
        assert!(
            quoted > 0 && quoted < SERIAL_TAIL_LINES,
            "the total cap must bind before the line cap here (quoted {quoted} lines)"
        );
        // Newest first out of the budget: the last line is quoted, an older one is not.
        assert!(
            msg.contains("line-39:"),
            "the tail must reach the end: {msg}"
        );
        assert!(
            !msg.contains("line-20:"),
            "the byte budget must drop the older lines, not the newer ones: {msg}"
        );
    }

    // A multi-byte character straddling the per-line cap must not panic the truncation (the guest
    // controls the bytes; `read_to_string` yields real UTF-8 with replacement chars). Guards
    // `&line[..SERIAL_TAIL_MAX_LINE_BYTES]`, which panics mid-character.
    #[test]
    fn cap_line_truncates_on_a_char_boundary() {
        // 'é' is 2 bytes: filling to exactly the cap puts a boundary AT the cap, so shift by one.
        let line = format!(
            "{}é{}",
            "x".repeat(SERIAL_TAIL_MAX_LINE_BYTES - 1),
            "y".repeat(64)
        );
        let capped = cap_line(&line);
        assert!(capped.len() < line.len(), "the line must be truncated");
        assert!(capped.contains(TRUNCATION_MARKER), "{capped}");
        assert!(
            !capped.contains('é'),
            "the straddling character is dropped, not split: {capped}"
        );
        // A short line is borrowed unchanged.
        assert!(matches!(cap_line("[    0.1] short"), Cow::Borrowed(_)));
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

    // ── The conformance renderers (§10.6) ────────────────────────────────────────────────────

    // A Warn goes through the classifier for the same reason a Fail does: an under-claim with no
    // explanation is a bare bool again. The message must (a) name the feature through the
    // vocabulary, so a consumer matches `Feature::name()` and never a hand-spelled phrase (F6),
    // (b) name the positive control — the thing that makes "it works" a measurement rather than a
    // probe that always says yes — and (c) not read as a failure, because the whole point of the
    // state is that reddening an under-claim pushes declarers toward over-claiming.
    #[test]
    fn the_underclaim_renderer_names_the_feature_the_control_and_the_defect_class() {
        let msg = explain_underclaim(Feature::SnapshotRestore, "debian-systemd", "canonical");
        assert!(msg.contains(Feature::SnapshotRestore.name()), "{msg}");
        assert!(
            msg.contains("debian-systemd") && msg.contains("canonical"),
            "{msg}"
        );
        assert!(msg.contains("DOCUMENTATION defect"), "{msg}");
        assert!(
            msg.contains("expected_warnings"),
            "an under-claim must say how to disposition it: {msg}"
        );
        // The feature name is composed, not spelled: a renderer that hardcoded "snapshot" would
        // pass the first assertion for the wrong reason, so the two other features are rendered
        // too and must differ exactly in that token.
        let other = explain_underclaim(Feature::XattrPreserved, "debian-systemd", "canonical");
        assert!(other.contains(Feature::XattrPreserved.name()), "{other}");
        assert!(!other.contains(Feature::SnapshotRestore.name()), "{other}");
    }

    // §7.4 provenance in the report: a claim the SUBSTRATE removes must name who removed it and
    // why, in `Removal`'s one spelling — so "this backend never had it" and "it broke" are not the
    // same sentence to a reader who has to fix one of them.
    #[test]
    fn the_broken_claim_renderer_carries_the_removal_provenance() {
        let removal = Removal {
            feature: Feature::SnapshotRestore,
            by: vmcell::feature::Source::Backend("qemu".into()),
            reason: "does not support it",
        };
        let with = explain_broken_claim(
            Feature::SnapshotRestore,
            "debian-systemd",
            Some(&removal),
            "the substrate says so",
        );
        assert!(with.contains(&removal.to_string()), "{with}");
        assert!(with.contains("backend \"qemu\""), "{with}");

        // Without a removal there is no provenance line to invent: the evidence stands alone.
        let without = explain_broken_claim(
            Feature::SnapshotRestore,
            "debian-systemd",
            None,
            "restore() returned an error",
        );
        assert!(!without.contains("provenance:"), "{without}");
        assert!(without.contains("restore() returned an error"), "{without}");
        assert!(
            without.contains(Feature::SnapshotRestore.name()),
            "{without}"
        );
    }

    // An undecidable absence must say so in the message, not only in the variant: a report is read
    // as text far more often than it is matched on, and "unverified" that reads like "verified" is
    // the skip==pass hazard one level up.
    #[test]
    fn the_undecidable_renderer_refuses_to_read_as_a_pass() {
        let msg = explain_undecidable(
            Feature::NestedVirt,
            "debian-systemd",
            "the positive control could not demonstrate it here",
        );
        assert!(msg.contains(Feature::NestedVirt.name()), "{msg}");
        assert!(msg.contains("NEVER counted as a pass"), "{msg}");
        assert!(
            msg.contains("the positive control could not demonstrate it here"),
            "{msg}"
        );
    }
}
