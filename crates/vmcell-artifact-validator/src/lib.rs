//! Validate custom-built vmcell artifacts (kernel, rootfs) against the artifact↔system
//! contract (design v20 §5.4, §8.5, §12) by booting real test micro-VMs.
//!
//! A developer pairs a custom artifact with a known-good counterpart — a custom `vmlinux`
//! with a trusted `rootfs.erofs`, or vice versa — and calls [`validate`]. It boots micro-VMs
//! via `vmcell`, drives the guest agent to probe the guest, and returns a
//! [`ValidationReport`] listing every check's outcome. **Success is an empty failure list**
//! ([`ValidationReport::is_ok`] / [`ValidationReport::into_result`]).
//!
//! The checks are **extracted** from vmcell's integration suite ([`checks`]) so the validator
//! and the tests share one implementation — a check that regresses reddens both.
//!
//! ## Layers and the skip==pass hazard
//! Checks are grouped into [`Level`]s. `Core` is always run and **never skips** — the
//! validator requires KVM as a precondition (no `/dev/kvm` → [`validate`] returns `Err`, never
//! a green all-skipped report). `Extended`/`Full` checks that need a host capability the run
//! lacks (CAP_NET_ADMIN, cgroup delegation, a backend feature) record a
//! [`CheckStatus::Skip`] with a reason — never a silent pass.
#![deny(missing_docs, unsafe_op_in_unsafe_fn, rustdoc::broken_intra_doc_links)]
#![deny(
    clippy::undocumented_unsafe_blocks,
    clippy::missing_safety_doc,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc
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
        clippy::dbg_macro
    )
)]

pub mod checks;
pub mod harness;

use std::path::PathBuf;
use vmcell::vmm::cloud_hypervisor::CloudHypervisor;

/// The artifact pair under validation. The caller always supplies **both** — the custom
/// artifact plus a known-good counterpart it chose (the management system owns "known-good").
#[derive(Clone, Debug)]
pub struct ArtifactSet {
    /// Path to the direct-boot `vmlinux` kernel image.
    pub kernel: PathBuf,
    /// Path to the read-only erofs root filesystem image.
    pub rootfs: PathBuf,
}

impl ArtifactSet {
    /// A pair from explicit paths.
    #[must_use]
    pub fn new(kernel: impl Into<PathBuf>, rootfs: impl Into<PathBuf>) -> Self {
        Self {
            kernel: kernel.into(),
            rootfs: rootfs.into(),
        }
    }
}

/// How much of the contract to exercise. Ordered: `Full` ⊇ `Extended` ⊇ `Core`.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Level {
    /// Direct boot, erofs root, PID-1 agent handshake, exec/put-file round-trip, injected
    /// agent/CA/guest-tools present, overlay writable, clean shutdown. Needs only KVM.
    Core,
    /// `Core` plus capability-gated probes: IP-PNP networking, virtio-fs RO/RW shares, nested
    /// `/dev/kvm`, cgroup usage readout.
    Extended,
    /// `Extended` plus the expensive/privileged contract: egress proxy, snapshot/restore state
    /// rotation, memory-limit OOM, concurrent-boot identity distinctness.
    Full,
}

impl Level {
    fn as_str(self) -> &'static str {
        match self {
            Level::Core => "core",
            Level::Extended => "extended",
            Level::Full => "full",
        }
    }
}

/// Knobs for a validation run.
#[derive(Clone, Debug)]
pub struct ValidationOptions {
    /// The deepest level of checks to run (default [`Level::Core`]).
    pub level: Level,
}

impl Default for ValidationOptions {
    fn default() -> Self {
        Self { level: Level::Core }
    }
}

impl ValidationOptions {
    /// Options running up to `level`.
    #[must_use]
    pub fn level(level: Level) -> Self {
        Self { level }
    }
}

/// The result of a single contract check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CheckStatus {
    /// The contract property held.
    Pass,
    /// The contract property was violated; carries a human-readable reason.
    Fail(String),
    /// The check could not run because the host lacks a capability; carries the reason. A
    /// skip is **never** a pass — it is surfaced so the caller can judge coverage.
    Skip(String),
}

/// One check's identity and outcome.
#[derive(Clone, Debug)]
pub struct CheckOutcome {
    /// A stable dotted id, e.g. `"boot.agent_ready"`.
    pub id: &'static str,
    /// The level this check belongs to.
    pub level: Level,
    /// The outcome.
    pub status: CheckStatus,
}

impl CheckOutcome {
    fn pass(id: &'static str, level: Level) -> Self {
        Self {
            id,
            level,
            status: CheckStatus::Pass,
        }
    }
    fn fail(id: &'static str, level: Level, msg: impl Into<String>) -> Self {
        Self {
            id,
            level,
            status: CheckStatus::Fail(msg.into()),
        }
    }
    fn skip(id: &'static str, level: Level, reason: impl Into<String>) -> Self {
        Self {
            id,
            level,
            status: CheckStatus::Skip(reason.into()),
        }
    }
    /// From an extracted-check `Result`: `Ok` → Pass, `Err(msg)` → Fail.
    fn from_result(id: &'static str, level: Level, r: Result<(), String>) -> Self {
        match r {
            Ok(()) => Self::pass(id, level),
            Err(m) => Self::fail(id, level, m),
        }
    }
}

/// The full validation report: one [`CheckOutcome`] per check that was considered.
#[derive(Clone, Debug)]
pub struct ValidationReport {
    /// Every check outcome, in run order.
    pub outcomes: Vec<CheckOutcome>,
}

impl ValidationReport {
    /// The failures — the "list of failures" the caller acts on.
    pub fn failures(&self) -> impl Iterator<Item = &CheckOutcome> {
        self.outcomes
            .iter()
            .filter(|o| matches!(o.status, CheckStatus::Fail(_)))
    }

    /// The skipped checks (capability-gated), with their reasons.
    pub fn skipped(&self) -> impl Iterator<Item = &CheckOutcome> {
        self.outcomes
            .iter()
            .filter(|o| matches!(o.status, CheckStatus::Skip(_)))
    }

    /// True when there are **no failures**. (Skips do not fail a run, but the caller can
    /// inspect [`skipped`](Self::skipped) to judge coverage.)
    #[must_use]
    pub fn is_ok(&self) -> bool {
        self.failures().next().is_none()
    }

    /// The "Ok response" form: `Ok(())` on no failures, else `Err(failures)`.
    ///
    /// # Errors
    /// Returns the list of failing [`CheckOutcome`]s when any check failed.
    pub fn into_result(self) -> Result<(), Vec<CheckOutcome>> {
        let failures: Vec<CheckOutcome> = self
            .outcomes
            .into_iter()
            .filter(|o| matches!(o.status, CheckStatus::Fail(_)))
            .collect();
        if failures.is_empty() {
            Ok(())
        } else {
            Err(failures)
        }
    }
}

/// Validate an artifact pair against the contract up to `opts.level`, booting real micro-VMs.
///
/// Returns a [`ValidationReport`]; contract violations — **including "the kernel did not
/// boot"** — are [`CheckStatus::Fail`] entries, not the outer `Err`. The outer `Err` is
/// reserved for "validation could not run at all": a missing artifact file, or no `/dev/kvm`
/// (the `Core` precondition — refusing to emit a green all-skipped report).
///
/// # Errors
/// - [`vmcell::Error::Artifact`] if `artifacts.kernel` or `artifacts.rootfs` does not exist.
/// - [`vmcell::Error::CapabilityUnavailable`] if `/dev/kvm` is absent (cannot validate).
pub async fn validate(
    artifacts: &ArtifactSet,
    opts: &ValidationOptions,
) -> vmcell::Result<ValidationReport> {
    if !artifacts.kernel.exists() {
        return Err(vmcell::Error::Artifact(format!(
            "kernel artifact does not exist: {}",
            artifacts.kernel.display()
        )));
    }
    if !artifacts.rootfs.exists() {
        return Err(vmcell::Error::Artifact(format!(
            "rootfs artifact does not exist: {}",
            artifacts.rootfs.display()
        )));
    }
    if !harness::has_kvm() {
        // Core is unconditional; without KVM we cannot verify a single contract property, so
        // we refuse rather than return an all-`Skip` report that `is_ok()` would call green.
        return Err(vmcell::Error::CapabilityUnavailable {
            op: "artifact validation".into(),
            needed: "/dev/kvm (no VM can boot to verify the contract)".into(),
        });
    }

    let vmm = CloudHypervisor::new(harness::ch_bin());
    let mut outcomes: Vec<CheckOutcome> = Vec::new();

    checks::run_core(&vmm, artifacts, &mut outcomes).await;
    if opts.level >= Level::Extended {
        checks::run_extended(&vmm, artifacts, &mut outcomes).await;
    }
    if opts.level >= Level::Full {
        checks::run_full(&vmm, artifacts, &mut outcomes).await;
    }

    tracing::info!(
        level = opts.level.as_str(),
        checks = outcomes.len(),
        failures = outcomes
            .iter()
            .filter(|o| matches!(o.status, CheckStatus::Fail(_)))
            .count(),
        "artifact validation complete"
    );
    Ok(ValidationReport { outcomes })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn outcome(id: &'static str, level: Level, status: CheckStatus) -> CheckOutcome {
        CheckOutcome { id, level, status }
    }

    // A report with no Fail is ok(); into_result() is Ok. Skips do NOT fail a run, but they
    // are not silently dropped — they remain inspectable.
    #[test]
    fn test_report_ok_when_no_failures() {
        let report = ValidationReport {
            outcomes: vec![
                outcome("a", Level::Core, CheckStatus::Pass),
                outcome(
                    "b",
                    Level::Extended,
                    CheckStatus::Skip("no CAP_NET_ADMIN".into()),
                ),
            ],
        };
        assert!(report.is_ok());
        assert_eq!(report.skipped().count(), 1);
        assert!(report.clone().into_result().is_ok());
    }

    // Any Fail makes the report not-ok and into_result() Err with exactly the failures.
    #[test]
    fn test_report_fails_on_any_failure() {
        let report = ValidationReport {
            outcomes: vec![
                outcome("a", Level::Core, CheckStatus::Pass),
                outcome(
                    "b",
                    Level::Core,
                    CheckStatus::Fail("kernel did not boot".into()),
                ),
                outcome("c", Level::Full, CheckStatus::Skip("no snapshot".into())),
            ],
        };
        assert!(!report.is_ok());
        assert_eq!(report.failures().count(), 1);
        let err = report.into_result().unwrap_err();
        assert_eq!(err.len(), 1);
        assert_eq!(err[0].id, "b");
    }

    // Level ordering gates which groups run: Core < Extended < Full.
    #[test]
    fn test_level_ordering() {
        assert!(Level::Core < Level::Extended);
        assert!(Level::Extended < Level::Full);
        assert!(Level::Full >= Level::Core);
    }
}
