//! The KVM-free half of the vmcell benchmark harness: the machine-readable report, the rank
//! statistics, and the A/B arm bookkeeping (design §16, Performance).
//!
//! WHY THIS LIBRARY EXISTS. `bench-vm` was a single 3600-line binary with no library target, so
//! two things followed: every number it produced could only be consumed by scraping its stdout,
//! and every rule about *how* a comparison must be run lived in ad-hoc shell that no test could
//! reach. A benchmark pass on 2026-08-21 paid for both, four times over, and each lesson is a
//! module here:
//!
//! 1. **The canonical results table had been measured on a different machine.** Absolute
//!    milliseconds cannot answer "did we regress"; only an interleaved, same-host, same-session A/B
//!    can. That is [`ab::interleave`], and it is why "compare against a stored baseline from
//!    another machine" is deliberately absent from this crate rather than merely unimplemented.
//! 2. **A control silently did not apply.** The driver exported `$VMCELL_KERNEL` to pin both arms
//!    to one guest kernel — but the *old* arm's `bench-vm` predates that variable and composes
//!    `<artifacts_dir>/vmlinux` itself, so the arms booted 6.12.94 against 6.12.104 for an entire
//!    matrix while the driver reported one kernel. The same class had already been caught for
//!    `$VMCELL_CH_BIN` (old arms hardcode the PATH name) and shimmed via PATH; the kernel got the
//!    export but not the proof. Hence [`ab::guard_same_kernel`] and [`ab::guard_vmm_binaries`]:
//!    **a control is verified by digest, never by "we exported the variable"**. And its post-run
//!    twin, [`ab::guard_booted_artifacts`]: a prepare-time digest is a statement about two files
//!    before anything ran, and it stays green against a child that resolved a *different* file —
//!    which an inherited `$VMCELL_KERNEL`/`$VMCELL_ROOTFS` makes every child do, since `bench-vm`
//!    reads those ahead of the artifacts dir. Only the emitted report witnesses what was opened.
//! 3. **An arm's binary was swapped underneath a run.** A concurrent experiment overwrote
//!    `target/release/bench-vm` with a patched build while `git status` stayed clean, so a run
//!    measured the fixed arm and reported it as stock — [`ab::guard_binaries_unchanged`].
//! 4. **A single p50 is not evidence.** Of six deltas ≥10% in the first single-pass matrix, five
//!    evaporated under repeats and one reversed sign. Only a repeated, interleaved measurement with
//!    a rank test survived — [`stats::mann_whitney`] — and, over a twenty-row matrix, only one
//!    corrected for multiplicity: twenty independent tests at 0.05 produce a phantom verdict 64% of
//!    the time under a true null, so the verdict word keys off [`stats::holm_bonferroni`].
//! 5. **A verdict word is a claim about DIRECTION**, and the first direction rule was "everything
//!    is a cost except the one exception I remembered". [`metrics`] replaces it with an exhaustive
//!    three-way roster, because a benefit ranked as a cost prints IMPROVEMENT for a regression, and
//!    a compositional share has no direction at all — make teardown twice as fast and every other
//!    phase's share rises.
//!
//! Nothing here boots a VM or touches `/dev/kvm`: [`stats`] is pure arithmetic and [`ab`] reaches
//! no further than the filesystem, so the whole library is unit-tested under `just test-unit`.
//!
//! `print_stdout`/`print_stderr` ARE denied here, unlike in `bench-vm.rs` where emitting the
//! measured tables is the point: a guard that prints instead of returning its finding cannot be
//! asserted on, and these guards exist precisely to be asserted on.
#![deny(missing_docs, unsafe_op_in_unsafe_fn, rustdoc::broken_intra_doc_links)]
#![deny(unreachable_pub)] // pub-in-private-module API-surface honesty
#![deny(
    clippy::undocumented_unsafe_blocks,
    clippy::missing_safety_doc,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::multiple_unsafe_ops_per_block // one obligation per SAFETY comment
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
        // AGENTS.md "Fail loud": no bare `let _ =` on a `Result`. `let_underscore_must_use` is the
        // narrowest instrument rustc/clippy has for that rule — and it is deliberately BROADER on
        // one axis, firing on any `#[must_use]` expression (a detached `JoinHandle`, a discarded
        // `Instant`), which is the same defect one step out: the compiler said this matters and the
        // code said nothing back. Scoped `not(test)` like every lint in this block: the rule's
        // stated harms (a swallowed teardown failure, a lost write, a wedged session) are
        // production harms, and forcing a reason onto a test's `try_init()` would manufacture the
        // hollow suppressions AGENTS.md rule 2 calls theater. `crates/vmcell/tests/lint_roster.rs`
        // is the gate that this line exists in EVERY crate root, so a new crate cannot opt out by
        // being new.
        clippy::let_underscore_must_use,
        clippy::allow_attributes,               // B11: prefer #[expect] over #[allow] in prod code
        clippy::allow_attributes_without_reason  // B11: every suppression states why
    )
)]

pub mod ab;
pub mod metrics;
pub mod report;
pub mod stats;
