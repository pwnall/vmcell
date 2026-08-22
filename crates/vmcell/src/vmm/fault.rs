//! Structured guest-kernel fault capture: the one host-side reading of a serial console that maps
//! it onto the **typed** fault the guest kernel reported — panic, oops, KASAN report, lockdep splat
//! — so a lifecycle operation names the *cause* instead of the *symptom* (§5.3, The kernel command
//! line, for the console this reads; §5.4, The guest-kernel contract and the bootstrap seed).
//!
//! ## Why a guest that oopsed must not report a handshake timeout
//! Before this module the host had one boolean, [`SerialLog::contains_panic`](crate::vmm::SerialLog),
//! and every other guest-kernel death reached the caller as
//! [`Error::Timeout`](crate::error::Error::Timeout) — "Steward connection timed out". That names
//! the host's own expired budget, which is true and useless: the guest kernel had already printed
//! the reason on the console the host was holding open. A KASAN report in an erofs decompressor and
//! a wedged `vhost-device-vsock` daemon produced byte-identical errors, so the first question a
//! reader asked was always "which of the two is it?" — a question the evidence already answered.
//!
//! ## What this module is NOT
//! It is not `vmcell-artifact-validator`'s [`classify`] — and the two are deliberately **not**
//! merged. They answer different questions off the same bytes:
//!
//! - the validator maps a *boot* console onto the §5.4 **artifact contract clause** an
//!   artifact pair broke (`VFS: Cannot open root device` → "your kernel lacks `CONFIG_VIRTIO_BLK`"),
//!   for a conformance battery whose job is to grade an artifact;
//! - this module maps *any* console onto the **guest kernel fault** a running host operation
//!   should fail with, for a caller whose VM just died under it.
//!
//! Their signature sets are disjoint, so there is no duplicated "what does an oops look like"
//! anywhere in the tree, and the boundary is already drawn from the other side: the validator's own
//! source records that it deliberately does not claim `Kernel panic`, because the host owns that
//! literal. The panic literals therefore live **here**, in exactly one place, and
//! [`SerialLog::contains_panic`](crate::vmm::SerialLog::contains_panic) is defined in terms of them
//! rather than carrying its own copy. `scripts/ban-inline-kernel-fault-signature.sh` is the gate
//! that keeps a second copy from appearing, since a duplicated needle is not a compile error.
//!
//! Direction of any future consolidation is fixed by the dependency edge:
//! `vmcell-artifact-validator` depends on `vmcell`, never the reverse, so if the two ever *do* need
//! one recognizer it lands here and the validator calls it.
//!
//! [`classify`]: https://docs.rs/vmcell-artifact-validator
//!
//! ## The signatures are the emitters' real text
//! Every needle below was taken from the kernel source that prints it, and each const names that
//! file. A signature is matched with `str::contains` against a whole console, so it must be text
//! the kernel prints on **one** line and must be specific enough that ordinary boot output — or a
//! kernel command line that merely mentions the word — cannot produce it. `panic=` on the cmdline
//! (§5.3) is the standing example: it contains "panic" and matches no needle here.

use super::SerialLog;
use crate::error::Error;
use vmcell_protocol::capped_debug;

/// KASAN's report header, from `mm/kasan/report.c` (`print_report`): every report opens
/// `BUG: KASAN: <bug-type> in <symbol>` between two rows of `=`.
///
/// The bare word `KASAN` is **not** a needle: it is also a kernel config-fragment label this repo
/// ships (§5.5's `6.12.94 + [KASAN, LOCKDEP]`), so it appears in cmdline echoes and in
/// `/proc/version` lines of perfectly healthy KASAN builds.
const KASAN_SIGNATURES: &[&str] = &["BUG: KASAN:"];

/// The x86 oops family, from `arch/x86/kernel/dumpstack.c` (`__die`/`oops_end` print
/// `Oops: 0000 [#1] …`), `arch/x86/mm/fault.c` (`show_fault_oops` prints the two `BUG:` lines),
/// `arch/x86/kernel/traps.c` (`general protection fault, probably for non-canonical address …`),
/// and `include/asm-generic/bug.h` (`BUG()` prints `kernel BUG at <file>:<line>!`). The arm64
/// spelling (`arch/arm64/kernel/traps.c`, `Internal error: Oops: …`) is listed too: the second
/// architecture is §17 work, but a needle costs nothing and a missing one costs a mystery.
const OOPS_SIGNATURES: &[&str] = &[
    "Oops: ",
    "BUG: kernel NULL pointer dereference",
    "BUG: unable to handle page fault",
    "general protection fault",
    "kernel BUG at ",
    "Internal error: Oops",
];

/// The kernel has stopped, from `kernel/panic.c` (`panic()` prints
/// `Kernel panic - not syncing: <msg>`), plus Rust's own std panic header (`panicked at
/// <file>:<line>:<col>`).
///
/// A Rust panic is userspace, not the kernel — but under the [`Pid1`] placement (§3.5, Steward
/// placement and the service-mode steward) that userspace is the steward, and a PID 1 that dies is
/// `Kernel panic - not syncing: Attempted to kill init!` a microsecond later. Grouping the two is
/// what [`SerialLog::contains_panic`](crate::vmm::SerialLog::contains_panic) has always done; this const
/// is that set, unchanged, now with exactly one home.
///
/// [`Pid1`]: crate::config::StewardPlacement::Pid1
const PANIC_SIGNATURES: &[&str] = &["Kernel panic", "panicked at", "panic - not syncing"];

/// The lock validator's report headers, from `kernel/locking/lockdep.c`
/// (`print_circular_bug`, `print_deadlock_bug`, `print_bad_irq_dependency`, `print_usage_bug`,
/// `print_freed_lock_bug`).
///
/// Advisory by construction: unless the kernel was built `panic_on_warn`, it keeps running after a
/// splat — which is why [`GuestFault::Lockdep`] never aborts a wait (see [`classify_serial_fault`]).
const LOCKDEP_SIGNATURES: &[&str] = &[
    "possible circular locking dependency detected",
    "possible recursive locking detected",
    "possible irq lock inversion dependency detected",
    "inconsistent lock state",
    "BUG: held lock freed!",
];

/// What [`SerialFault::opaque_panic`] carries where a console line would go, so a reader can tell
/// "the guest printed this" from "whoever reported this had no console text to quote".
pub const NO_CONSOLE_EVIDENCE: &str = "(no console text available)";

/// A recognizable way for a guest kernel to have died or misbehaved, as proven by its serial
/// console.
///
/// `#[non_exhaustive]` because a newly-understood signature grows this enum and `vmcell` has
/// out-of-repo consumers (§10.4): a new variant must not break a downstream `match`. Inside this
/// crate the compiler still enforces the growth obligation in all three places — the two
/// `match self` tables below and `FAULT_PRECEDENCE`, whose completeness is pinned by
/// `every_fault_class_is_in_the_precedence_list`.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum GuestFault {
    /// KASAN reported a memory-safety violation in the guest kernel.
    Kasan,
    /// The guest kernel took a fatal exception (an oops / `BUG()` / page fault it cannot handle).
    Oops,
    /// The guest kernel stopped, or its PID 1 died and the kernel stopped because of it.
    Panic,
    /// The guest kernel's lock validator reported a potential deadlock. **Advisory**: the kernel
    /// keeps running.
    Lockdep,
}

/// The order [`classify_serial_fault`] tries the classes in — the ONE precedence list, so
/// "which fault does a console with three of them report?" has a single answer.
///
/// Two rules produce it, in this order:
///
/// 1. **Most specific cause first.** A KASAN report that ends in an oops that ends in a panic is
///    one event with three lines of evidence, and only the first names what to fix. This is the
///    same rule `vmcell-artifact-validator`'s classifier applies to the §5.4 clauses, for the same
///    reason.
/// 2. **Fatal outranks advisory.** A lockdep splat is *not* evidence about a later, unrelated
///    panic — the kernel survived the splat and kept booting — so [`GuestFault::Panic`] is tried
///    before [`GuestFault::Lockdep`] even though a splat is "more specific" text.
const FAULT_PRECEDENCE: &[GuestFault] = &[
    GuestFault::Kasan,
    GuestFault::Oops,
    GuestFault::Panic,
    GuestFault::Lockdep,
];

impl GuestFault {
    /// The console needles that prove this fault class, each taken from the kernel source that
    /// prints it (see the consts' own rustdoc).
    ///
    /// Public so a caller can state *what* the host looks for without copying the literals — the
    /// duplication `scripts/ban-inline-kernel-fault-signature.sh` exists to stop.
    #[must_use]
    pub fn signatures(self) -> &'static [&'static str] {
        match self {
            Self::Kasan => KASAN_SIGNATURES,
            Self::Oops => OOPS_SIGNATURES,
            Self::Panic => PANIC_SIGNATURES,
            Self::Lockdep => LOCKDEP_SIGNATURES,
        }
    }

    /// One line of prose saying what this class means and what it implies for the VM — the
    /// operator-facing half of the classification, kept out of [`core::fmt::Display`] so a log line
    /// stays one line and a report can be long.
    #[must_use]
    pub fn explain(self) -> &'static str {
        match self {
            Self::Kasan => {
                "the guest kernel's KASAN instrumentation reported a memory-safety violation \
                 (mm/kasan/report.c); the kernel may keep running, but nothing it does afterwards \
                 is trustworthy"
            }
            Self::Oops => {
                "the guest kernel took a fatal exception and killed the faulting task \
                 (arch/x86/kernel/dumpstack.c); if that task was PID 1 the kernel panics \
                 immediately afterwards"
            }
            Self::Panic => {
                "the guest kernel stopped (kernel/panic.c), or its PID 1 died and the kernel \
                 stopped because of it — no later poll of this guest can succeed"
            }
            Self::Lockdep => {
                "the guest kernel's lock validator reported a potential deadlock \
                 (kernel/locking/lockdep.c); advisory — the kernel keeps running, so this explains \
                 a hang rather than proving one"
            }
        }
    }
}

impl core::fmt::Display for GuestFault {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let name = match self {
            Self::Kasan => "KASAN report",
            Self::Oops => "kernel oops",
            Self::Panic => "kernel panic",
            Self::Lockdep => "lockdep splat",
        };
        f.write_str(name)
    }
}

/// What a serial console proves about the guest kernel: which fault class, whether the kernel has
/// **stopped**, and the one console line that says so.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SerialFault {
    kind: GuestFault,
    halted: bool,
    evidence: String,
}

impl SerialFault {
    /// A [`GuestFault::Panic`] with **no console line to quote** — the honest report from a
    /// [`SerialLog`] that can answer `contains_panic()` and nothing else (the default
    /// [`SerialLog::classify_fault`] body, and every recording fake).
    ///
    /// Evidence-free by construction rather than by accident: a fake that was handed no console
    /// text must not be able to produce a quote, so this constructor takes no argument and the
    /// only way to get a real one is [`classify_serial_fault`] over real bytes.
    #[must_use]
    pub fn opaque_panic() -> Self {
        Self {
            kind: GuestFault::Panic,
            halted: true,
            evidence: NO_CONSOLE_EVIDENCE.to_string(),
        }
    }

    /// The fault class, chosen by `FAULT_PRECEDENCE`.
    #[must_use]
    pub fn kind(&self) -> GuestFault {
        self.kind
    }

    /// Whether the console shows the kernel has **stopped** — i.e. carries a
    /// [`GuestFault::Panic`] signature, whatever [`kind`](Self::kind) says.
    ///
    /// This is a **second, orthogonal question**, not a synonym for
    /// `kind() == GuestFault::Panic`, and the two differ on exactly the consoles that matter: a
    /// KASAN report followed by `Kernel panic - not syncing` classifies as
    /// [`GuestFault::Kasan`] (the cause) and is `halted` (the consequence). A caller waiting on the
    /// guest uses *this* to decide whether waiting longer can help; it uses
    /// [`kind`](Self::kind) to say what happened.
    #[must_use]
    pub fn halted(&self) -> bool {
        self.halted
    }

    /// The console line carrying the matched signature, already rendered through
    /// [`capped_debug`] — quoted, escaped, and truncated.
    ///
    /// The console is **guest-controlled**, and a guest that prints one un-newlined megabyte
    /// satisfies any line-based bound, so the cap is the repo's shared one rather than a local
    /// choice (AGENTS.md: "A log line that renders a whole guest-controlled frame is a flood").
    /// The whole tail stays where it always was — in the serial log file the caller named.
    #[must_use]
    pub fn evidence(&self) -> &str {
        &self.evidence
    }

    /// Turn this fault into the typed error a host lifecycle operation returns, naming the
    /// operation that was waiting when the fault was observed.
    ///
    /// `op` is the host's own words for what it was doing ("steward vsock handshake"), so the
    /// message carries both halves: what the host wanted and why the guest could not give it.
    #[must_use]
    pub fn into_error(self, op: &str) -> Error {
        Error::GuestKernelFault {
            fault: self.kind,
            op: op.to_string(),
            evidence: self.evidence,
        }
    }
}

impl core::fmt::Display for SerialFault {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}: {}", self.kind, self.evidence)
    }
}

/// The first console line carrying any of `signatures`, or `None`.
///
/// Line-based on purpose: every needle is text the kernel prints on one line, so a whole-console
/// `contains` and this agree by construction — and this additionally yields the line to quote.
fn first_line_matching<'a>(log: &'a str, signatures: &[&str]) -> Option<&'a str> {
    log.lines()
        .find(|line| signatures.iter().any(|needle| line.contains(needle)))
}

/// Whether a console could carry **any** known fault signature, in one whole-buffer pass.
///
/// The cheap half of [`classify_serial_fault`]: `false` proves no class can match, because a
/// needle absent from the buffer is absent from every line of it. `true` proves nothing on its own
/// — the classifier still does the line-by-line work to pick the class and quote its evidence.
///
/// The needle set is the union of [`GuestFault::signatures`] over [`FAULT_PRECEDENCE`], computed
/// here rather than restated, so a class added to the enum widens this filter by construction and
/// cannot be forgotten. `every_known_signature_survives_the_prefilter` is that law's gate.
fn may_carry_fault(log: &str) -> bool {
    FAULT_PRECEDENCE
        .iter()
        .flat_map(|kind| kind.signatures())
        .any(|needle| log.contains(needle))
}

/// Whether a console carries a [`GuestFault::Panic`] signature — "the guest kernel has stopped".
///
/// The ONE definition of that question. [`SerialLog::contains_panic`](crate::vmm::SerialLog) is this
/// function applied to a log's bytes, so the boolean detector that shipped first and the classifier
/// added here can never disagree about what a panic looks like.
#[must_use]
pub fn log_reports_panic(log: &str) -> bool {
    first_line_matching(log, GuestFault::Panic.signatures()).is_some()
}

/// Classify a serial console: the most specific guest-kernel fault it proves, or `None`.
///
/// `None` is the answer for a healthy boot, for an empty console, and for a console whose failure
/// this module does not recognize — and it is the **important** answer, because a classifier that
/// fires on everything is worse than none: every `None` is a caller that keeps its own honest
/// error (a host-side timeout stays a host-side timeout).
///
/// The returned [`SerialFault`] answers two questions, not one: `kind()` is the cause, chosen by
/// `FAULT_PRECEDENCE`, and `halted()` is whether the kernel stopped. They are computed
/// separately so a KASAN report that ended in a panic reports the KASAN *and* still tells a waiting
/// caller to give up.
#[must_use]
pub fn classify_serial_fault(log: &str) -> Option<SerialFault> {
    // The healthy console is the only console whose latency matters, and it is exactly the case
    // where nothing short-circuits: without this, a healthy log costs five whole-console
    // `lines()` passes (one for `halted`, one per `FAULT_PRECEDENCE` class), each testing every
    // needle against every line. One whole-buffer pass over the same needle union answers "is
    // there anything here at all" at `memmem` throughput instead. Measured on a 10 KB console:
    // 56 us before, and this call site sits in `StewardClient::connect_framed`'s retry loop, which
    // re-reads and re-scans a console that is still GROWING during boot.
    //
    // Semantics are unchanged, not approximated: a needle absent from the whole buffer is absent
    // from every line of it, so every `first_line_matching` below would have returned `None`. The
    // union is taken from `signatures()` — never a second literal list — which is both the
    // one-law-one-predicate requirement and what makes the tempting narrowing (a single `"panic"`
    // needle) unrepresentable: every healthy console echoes the `panic=1` cmdline token §5.3
    // emits, so that prefilter would match every healthy boot and quietly do nothing.
    // `PANIC_SIGNATURES` is inside the union (Panic is a `FAULT_PRECEDENCE` member), so `halted`
    // cannot be true when this returns early.
    if !may_carry_fault(log) {
        return None;
    }
    let halted = log_reports_panic(log);
    for &kind in FAULT_PRECEDENCE {
        if let Some(line) = first_line_matching(log, kind.signatures()) {
            return Some(SerialFault {
                kind,
                halted,
                evidence: capped_debug(&line.trim()),
            });
        }
    }
    None
}

/// The one host-side reading of "my budget expired": ask the console whether the guest is the
/// reason, and return the typed guest fault if it is, or the caller's own timeout if it is not.
///
/// **This is where a host problem must not become a guest-fault report.** The only thing that can
/// produce a [`Error::GuestKernelFault`] here is text the guest actually printed: an unreadable
/// console, an absent one, and a healthy one all fall through to `Error::Timeout(timeout_msg)`,
/// which is the error the caller would have returned anyway. A wedged `vhost-device-vsock` daemon,
/// a missing socket and a busy host therefore still report themselves.
///
/// Every expiry arm of one operation routes through this, so "an expired wait consults the console"
/// is one law with one implementation rather than a check some arms remembered (AGENTS.md, "One
/// law, one predicate").
#[must_use]
pub fn expiry_error(serial_log: &dyn SerialLog, op: &str, timeout_msg: &str) -> Error {
    match serial_log.classify_fault() {
        Some(fault) => fault.into_error(op),
        None => Error::Timeout(timeout_msg.to_string()),
    }
}
