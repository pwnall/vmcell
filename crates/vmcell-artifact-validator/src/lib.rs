//! Validate custom-built vmcell artifacts (kernel, rootfs) against the artifact↔system
//! contract (design §4.3, The rootfs-construction contract, §5.4, The guest-kernel contract
//! and the bootstrap seed, §13, Cross-cutting invariants) by booting real test micro-VMs.
//!
//! A developer pairs a custom artifact with a known-good counterpart — a custom `vmlinux`
//! with a trusted `rootfs.erofs`, or vice versa — and calls [`validate`] (or [`validate_with`],
//! which takes the backend instead of picking Cloud Hypervisor). It boots micro-VMs
//! via `vmcell`, drives the steward to probe the guest, and returns a
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
//!
//! **Every check records or skips its id on every path** (design §10.6), including the paths that
//! fail before the guest ever hands shakes: each level's roster is a named list ([`checks`]'s
//! `CORE_CHECK_IDS` and its siblings) that the run fills to the end, so a report never *shrinks*
//! when a boot fails and all three rosters are enumerable without KVM. That is what lets the
//! rustdoc roster gate below cover Core and Extended, not just Full.
//!
//! ## Two directions, and the states between pass and fail
//! [`validate`] checks one direction: a **present** property that does not hold. The
//! [`conformance`] battery adds the other — an artifact that declares a feature **absent** which
//! in fact works — because an unchecked declaration is a fact a consumer will build a fixture on
//! (design §10.6). It brings [`CheckStatus::Warn`] (an under-claim: a documentation defect, not a
//! runtime one) and [`CheckStatus::Unverified`] (an absence no observation can decide, with why),
//! and every absence probe is paired with a positive control under **one** check id.
//! [`ValidationReport::into_result`] stays **Fail-only**: neither new state fails a run on its own,
//! and an unexpected `Warn` is promoted to `Fail` by [`conformance::ConformanceOptions`] rather
//! than by widening what "failure" means.
//!
//! ## Naming what a bad kernel is missing
//! A boot failure never reports a bare timeout. Every arm of [`checks`] that **reports** a VM
//! which failed to start (`MicroVm::start`) or failed its steward handshake — Core, Extended and
//! Full alike — renders through one of the two [`classify`] renderers, chosen by whether console
//! evidence exists:
//!
//! - [`classify::explain_boot_failure_of`] — the console *was* captured. It maps the known serial
//!   signatures onto the §5.4 guest-kernel contract clause they break (root device, root-fs mount,
//!   the vsock transport, no direct-boot kernel at all) and, for the residual class, still emits
//!   the named check, the budget that expired, the serial tail, and a pointer to the §5.4
//!   checklist. It takes a [`classify::BootKind`], because the "nothing reached the console"
//!   reading is a fresh boot's: a **restored** VM's console is empty by construction (its kernel
//!   printed the banner in the snapshot source), so `snapshot.restore_roundtrip` must not diagnose
//!   a kernel that provably just booted as not being a kernel.
//! - [`classify::explain_without_serial`] — there is *no* console evidence (the VMM never started,
//!   or the log could not be read). It names candidate causes instead of asserting a clause,
//!   because a missing `cloud-hypervisor` binary is not a bad kernel.
//!
//! [`kconfig::KconfigValues`] is the matching mechanism for the other half of §5.6: asserting
//! against a *resolved* `.config`, since `make olddefconfig` silently drops symbols whose
//! dependencies are unmet.
//!
//! ## Example: validating an artifact pair
//!
//! Both examples below are `no_run` doctests: they boot real micro-VMs, and [`validate`] refuses to
//! run at all without `/dev/kvm` rather than emit a green all-skipped report. `just test-doc`
//! compiles them, so this is the battery's API as it ships.
//!
//! ```no_run
//! use std::time::Duration;
//! use vmcell_artifact_validator::{ArtifactSet, Level, ValidationOptions, harness, validate};
//!
//! # #[tokio::main]
//! # async fn main() -> vmcell::Result<()> {
//! // A custom kernel paired with a known-good rootfs. The caller supplies BOTH, because
//! // "known-good" is the management system's judgement and not this crate's. The `harness` getters
//! // are the documented downstream route — `$VMCELL_KERNEL` / `$VMCELL_ROOTFS` after an existence
//! // check — and they panic naming that route rather than guessing when it is not set.
//! let artifacts = ArtifactSet::new("/artifacts/vmlinux-custom", harness::get_rootfs());
//! let opts = ValidationOptions {
//!     level: Level::Full,
//!     // Bounds the WHOLE run — every level, every boot, end to end — on top of the per-check
//!     // deadlines. `None` opts out explicitly for a caller that bounds the run itself (a nextest
//!     // timeout, a CI job budget); either way it is honored, and exceeding it is a typed
//!     // `vmcell::Error::Timeout` naming the level that outran it, never a hang.
//!     run_budget: Some(Duration::from_secs(15 * 60)),
//! };
//! // `ValidationOptions::level(Level::Core)` is the same choice on the default budget.
//!
//! let report = validate(&artifacts, &opts).await?;
//! // A skip is never a pass, so coverage is judged separately from success.
//! for skipped in report.skipped() {
//!     eprintln!("skipped {}: {:?}", skipped.id, skipped.status);
//! }
//! if let Err(failures) = report.into_result() {
//!     for f in &failures {
//!         eprintln!("FAIL {}: {:?}", f.id, f.status);
//!     }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Example: the two-directional battery
//!
//! [`conformance::run_battery`] judges an artifact's **declaration** against the data plane in both
//! directions, and pairs every absence probe with a positive control on a second artifact (§10.6).
//!
//! ```no_run
//! use vmcell::feature::{Feature, FeatureDeclaration, Source};
//! use vmcell::vmm::cloud_hypervisor::CloudHypervisor;
//! use vmcell_artifact_validator::conformance::{
//!     ArtifactId, ConformanceOptions, ConformanceSubject, LiveProbe, Substrate, run_battery,
//! };
//! use vmcell_artifact_validator::{ArtifactSet, harness};
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let vmm = CloudHypervisor::new(harness::ch_bin());
//! // What this backend on this host can exercise at all, from `vmcell`'s one intersection site.
//! // Where the substrate itself removes a feature, a declared-PRESENT claim is a `Fail` (it cannot
//! // hold here, and the provenance names who says so) and a declared-ABSENT one is a `Skip` — never
//! // a measured absence, because the control would fail for the substrate's reason, not the
//! // artifact's.
//! let substrate = Substrate::of(&vmm);
//!
//! // The candidate. Its declaration is read from the sidecar beside its image — the travel form of
//! // its registry entry — and an absent sidecar is the stated baseline, not "everything absent".
//! let candidate_artifacts = ArtifactSet::new(harness::get_vmlinux(), "/artifacts/rootfs-acme.erofs");
//! let candidate = ConformanceSubject {
//!     id: ArtifactId::new("acme"),
//!     declaration: FeatureDeclaration::load_beside(
//!         &candidate_artifacts.rootfs,
//!         Source::Rootfs("acme".into()),
//!     )?,
//!     artifacts: candidate_artifacts,
//! };
//!
//! // The positive control: a DIFFERENT artifact that declares what the candidate denies. Both
//! // mistakes — the control being the candidate, and a control that declares nothing — are refused
//! // before anything boots, because a battery with no usable control cannot verify an absence.
//! let mut declaration = FeatureDeclaration::baseline(Source::Rootfs("default".into()));
//! declaration.stances.insert(Feature::SnapshotRestore, true);
//! let control = ConformanceSubject {
//!     id: ArtifactId::new("default"),
//!     artifacts: ArtifactSet::new(harness::get_vmlinux(), harness::get_rootfs()),
//!     declaration,
//! };
//!
//! let report = run_battery(
//!     &LiveProbe::new(&vmm),
//!     &substrate,
//!     &candidate,
//!     &control,
//!     &ConformanceOptions::default(),
//! )
//! .await?;
//!
//! // `Warn` is an under-claim — declared absent, demonstrably working. It is a documentation defect,
//! // so it never fails the run; an UN-triaged one has already become a `Fail` by the time it lands
//! // here, via `ConformanceOptions::expected_warnings`.
//! for w in report.warnings() {
//!     eprintln!("under-claim {}: {:?}", w.id, w.status);
//! }
//! # Ok(())
//! # }
//! ```
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
        clippy::allow_attributes,               // B11: prefer #[expect] over #[allow] in prod code
        clippy::allow_attributes_without_reason  // B11: every suppression states why
    )
)]

pub mod checks;
pub mod classify;
pub mod conformance;
pub mod harness;
pub mod kconfig;

use std::path::PathBuf;
use std::time::Duration;
use vmcell::vmm::Vmm;
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
    /// Direct boot, erofs root, PID-1 steward handshake, exec/put-file round-trip, injected
    /// steward/CA/guest-tools present, overlay writable, clean shutdown. Needs only KVM.
    ///
    /// The shipped roster, named by check id: `boot.config` (the VM config the artifact pair
    /// builds), `boot.kernel_banner` (the kernel reaches userspace), `boot.steward_ready` (the
    /// vsock control plane hands shakes), `steward.exec_roundtrip`, `steward.put_file_roundtrip`,
    /// `rootfs.libc6`, `rootfs.ca_cert`, `rootfs.guest_tools`, `rootfs.overlay_writable`, and
    /// `lifecycle.clean_shutdown`. Every one of them is recorded or skipped on **every** path —
    /// a run that dies before the handshake still reports the whole roster — which is what makes
    /// `level_core_rustdoc_names_exactly_the_shipped_checks` enumerable without KVM.
    Core,
    /// `Core` plus capability-gated probes, named by check id: `net.ip_pnp` (IP-PNP configured
    /// `eth0` at the address the orchestrator's math predicts), `virtiofs.shares` (a read-only
    /// share rejects writes with EROFS and a read-write share is visible host-side),
    /// `nested.kvm_ok` (nested KVM reaches the guest), and `metrics.usage_readable` (per-VM cgroup
    /// counters read back and report enforcement honestly).
    ///
    /// Records-or-skips on every path like `Core`, so
    /// `level_extended_rustdoc_names_exactly_the_shipped_checks` gates this roster the same way.
    Extended,
    /// `Extended` plus the expensive checks, each on VMs of its own — the shipped roster, named by
    /// check id: `concurrency.distinct_ids` (three concurrently-started VMs get distinct
    /// vmid/CID/vsock and each execs), `snapshot.restore_roundtrip` (a snapshotted VM restores back
    /// to steward-ready and execs), `metrics.mem_limit_ooms` (a host cgroup cap below guest RAM trips
    /// the host OOM killer).
    ///
    /// Two things this level does **not** do, despite an earlier roster here promising them
    /// (`level-full-rustdoc-claims-absent-checks`): there is no egress-proxy check, and the
    /// restore leg asserts a working guest, **not** the §8.2 state rotation (post-restore MAC /
    /// vsock path / in-guest default route). Both live in vmcell's own privileged suite
    /// (`tests/egress_proxy.rs`, `tests/snapshot_restore.rs`), which validates the *system*; this
    /// crate validates an *artifact pair* against the contract. The roster above is exactly what
    /// `checks::run_full` records — `level_full_rustdoc_names_exactly_the_shipped_checks` reddens
    /// if the two drift apart.
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

/// The default overall budget for a [`validate`] run: generous enough for a `Level::Full` roster of
/// real, sequential boots, finite so a wedged one is a typed error instead of a hung CI job.
///
/// Deliberately its own constant rather than a reuse of
/// [`conformance::DEFAULT_BATTERY_BUDGET`]: the two bound different rosters (the three levels here,
/// a declared feature roster there), and one const for both would silently re-budget one when the
/// other's roster grew.
pub const DEFAULT_RUN_BUDGET: Duration = Duration::from_secs(20 * 60);

/// Knobs for a validation run.
///
/// **Data only**, deliberately: there is no backend field here, and the backend is a parameter of
/// [`validate_with`] instead. [`vmcell::vmm::Vmm`] is not dyn-compatible, so a field could hold
/// neither an erased backend nor an erased factory, and the enum-of-backends alternative would make
/// this crate depend on every backend crate while still excluding a consumer's own (the full
/// reasoning, with the compiler's verdict, is on [`validate_with`]). Keeping this struct plain
/// `Clone + Debug` data is what lets a caller build it from a config file or a CLI flag and clone it
/// across runs.
#[derive(Clone, Debug)]
pub struct ValidationOptions {
    /// The deepest level of checks to run (default [`Level::Core`]).
    pub level: Level,
    /// The wall-clock budget for the **whole** run — every level, every boot, end to end
    /// (default `Some(`[`DEFAULT_RUN_BUDGET`]`)`).
    ///
    /// Per-check deadlines are unchanged and each one still fails loud; this bounds their **sum**.
    /// A `Level::Full` run boots several VMs sequentially, so without it the only ceiling was
    /// whatever those deadlines happened to add up to — the gap
    /// [`conformance::ConformanceOptions::battery_budget`] closed for the battery and not for this,
    /// older, entry point (design §17; the scoping is recorded in `docs/implementation-notes.md`).
    ///
    /// `None` opts out **explicitly**, for a caller that bounds the run itself (a nextest timeout, a
    /// CI job budget). Either way it is honored, never silently ignored: exceeded is
    /// [`vmcell::Error::Timeout`] naming the budget, the level that outran it and the checks that
    /// completed first — never a hang, and never a green report with its tail missing.
    pub run_budget: Option<Duration>,
}

impl Default for ValidationOptions {
    fn default() -> Self {
        Self {
            level: Level::Core,
            run_budget: Some(DEFAULT_RUN_BUDGET),
        }
    }
}

impl ValidationOptions {
    /// Options running up to `level`, on the default budget.
    #[must_use]
    pub fn level(level: Level) -> Self {
        // Functional update, not a fresh literal: a constructor that re-spells the other fields is
        // how the budget would silently become `None` for every `level()` caller when a later field
        // is added. `the_default_and_the_level_constructor_both_carry_the_default_budget` reddens
        // on one.
        Self {
            level,
            ..Self::default()
        }
    }
}

/// The result of a single contract check — the five states of design §10.6.
///
/// Three of them shipped before v33; `Warn` and `Unverified` are delta 3's, and they exist because
/// a two-directional kit has two more answers than a one-directional one. **The new states never
/// absorb the old ones' meaning**: `Fail` stays "a declared-present property that does not hold",
/// and `Skip` stays "the substrate cannot exercise the claim at all".
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CheckStatus {
    /// The contract property held.
    Pass,
    /// The contract property was violated; carries a human-readable reason.
    Fail(String),
    /// An **absent** declaration that the data plane contradicts: the artifact says it cannot, and
    /// it demonstrably can. Carries the explanation ([`classify::explain_underclaim`]).
    ///
    /// Deliberately not a failure. Under-claiming is a *documentation* defect, not a runtime one,
    /// and reddening it would push declarers toward over-claiming — the exact wrong incentive, and
    /// the one direction this kit cannot catch cheaply. The lifecycle that keeps warnings from
    /// silting up is [`conformance::ConformanceOptions::expected_warnings`], which promotes an
    /// **un-triaged** warning to [`CheckStatus::Fail`] and reports a triaged one that no longer
    /// fires as an error of its own.
    Warn(String),
    /// An absence that **cannot be decided**, carrying why.
    ///
    /// Never counted as a pass. Proving a negative is sometimes impractical: snapshot absence is
    /// testable by attempting a snapshot, page-sharing absence is not, because no in-guest
    /// observation distinguishes "the host is not sharing pages" from "it is and nothing diverged
    /// yet". The same distinction [`kconfig::KconfigValues::get`] draws between `None` (the symbol
    /// was dropped) and `Some(KconfigValue::No)` (the author disabled it): an honest kit says which
    /// one it is, per check.
    Unverified(String),
    /// The check could not run because the host lacks a capability; carries the reason. A
    /// skip is **never** a pass — it is surfaced so the caller can judge coverage.
    Skip(String),
}

/// One check's identity and outcome.
#[derive(Clone, Debug)]
pub struct CheckOutcome {
    /// A stable dotted id, e.g. `"boot.steward_ready"`.
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
    /// A judged outcome (the [`conformance`] battery computes the status first, through
    /// [`conformance::judge`], and only then names the check it belongs to).
    fn judged(id: &'static str, level: Level, status: CheckStatus) -> Self {
        Self { id, level, status }
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

    /// The under-claims ([`CheckStatus::Warn`]): declared-absent properties that work.
    ///
    /// These do **not** fail the run (see the variant's rationale). A warning that survived
    /// [`conformance::ConformanceOptions::expected_warnings`] is one the caller has dispositioned;
    /// an un-dispositioned one is already a [`CheckStatus::Fail`] by the time it lands here.
    pub fn warnings(&self) -> impl Iterator<Item = &CheckOutcome> {
        self.outcomes
            .iter()
            .filter(|o| matches!(o.status, CheckStatus::Warn(_)))
    }

    /// The undecidable absences ([`CheckStatus::Unverified`]), with why each one could not be
    /// decided. Never a pass — inspect them exactly as you would [`skipped`](Self::skipped).
    pub fn unverified(&self) -> impl Iterator<Item = &CheckOutcome> {
        self.outcomes
            .iter()
            .filter(|o| matches!(o.status, CheckStatus::Unverified(_)))
    }

    /// True when there are **no failures**. (Skips, warnings and unverified absences do not fail a
    /// run, but the caller can inspect [`skipped`](Self::skipped) / [`warnings`](Self::warnings) /
    /// [`unverified`](Self::unverified) to judge coverage.)
    #[must_use]
    pub fn is_ok(&self) -> bool {
        self.failures().next().is_none()
    }

    /// The "Ok response" form: `Ok(())` on no failures, else `Err(failures)`.
    ///
    /// **Fail-only, unchanged by the v33 states** (design §10.6): a report carrying `Warn`s and
    /// `Unverified`s but no `Fail` returns `Ok(())`. Widening this would make an under-claim red,
    /// which is the incentive [`CheckStatus::Warn`] exists to avoid, and would make an undecidable
    /// absence indistinguishable from a violated claim. Pinned by
    /// `into_result_is_fail_only_across_all_five_states`.
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

/// Validate an artifact pair against the contract up to `opts.level`, booting real micro-VMs on
/// Cloud Hypervisor.
///
/// This is [`validate_with`] on `default_backend`, plus the `/dev/kvm` precondition that backend
/// needs. A caller with a backend of its own — a secondary backend crate, or an out-of-tree one —
/// calls [`validate_with`] directly; that function's rustdoc records why the knob is a parameter
/// rather than a field on [`ValidationOptions`].
///
/// Returns a [`ValidationReport`]; contract violations — **including "the kernel did not
/// boot"** — are [`CheckStatus::Fail`] entries, not the outer `Err`. The outer `Err` is
/// reserved for "validation could not run at all": a missing artifact file, or no `/dev/kvm`
/// (the `Core` precondition — refusing to emit a green all-skipped report).
///
/// # Errors
/// - [`vmcell::Error::Artifact`] if `artifacts.kernel` or `artifacts.rootfs` does not exist.
/// - [`vmcell::Error::CapabilityUnavailable`] if `/dev/kvm` is absent (cannot validate).
/// - [`vmcell::Error::Timeout`] if the run outran [`ValidationOptions::run_budget`], naming the
///   level that outran it and the checks that completed first.
pub async fn validate(
    artifacts: &ArtifactSet,
    opts: &ValidationOptions,
) -> vmcell::Result<ValidationReport> {
    // Before the host probe, so a caller who typo'd a path hears about the path rather than about
    // the host. `validate_with` runs the same predicate again for its own inputs.
    ensure_artifacts_exist(artifacts)?;
    if !harness::has_kvm() {
        // Core is unconditional; without KVM we cannot verify a single contract property, so
        // we refuse rather than return an all-`Skip` report that `is_ok()` would call green.
        // This probe belongs to THIS door, not to `validate_with`: it is the door that chose a
        // backend, so it is the one that knows the backend needs `/dev/kvm`.
        return Err(vmcell::Error::CapabilityUnavailable {
            op: "artifact validation".into(),
            needed: "/dev/kvm (no VM can boot to verify the contract)".into(),
        });
    }

    validate_with(&default_backend(), artifacts, opts).await
}

/// The backend [`validate`] picks: Cloud Hypervisor — the primary backend, the only one in the
/// `vmcell` lib — on the binary the §10.4 (The downstream toolkit contract) `VMCELL_CH_BIN`
/// resolver names.
///
/// Its own function rather than an expression inside [`validate`], so the default is a **value a
/// test can interrogate** without KVM: `the_default_backend_is_still_cloud_hypervisor` asserts its
/// [`Vmm::id`]. A default that exists only as an expression in the middle of an entry point can be
/// checked by reading the source and in no other way, and this one has to survive the knob below
/// unchanged.
fn default_backend() -> CloudHypervisor {
    CloudHypervisor::new(harness::ch_bin())
}

/// Both artifact files exist — the one input-validation predicate, called by **both** doors.
///
/// Two call sites, each with its own reason: [`validate`] runs it ahead of its `/dev/kvm` probe to
/// order the two refusals, and [`validate_with`] runs it because it is an entry point of its own —
/// a door that trusts another door's check is one refactor away from not being checked at all. The
/// cost of the second call is two `Path::exists` calls; the cost of the alternative is a public
/// entry point that accepts a path it never looks at.
///
/// # Errors
/// [`vmcell::Error::Artifact`] naming the file that does not exist.
fn ensure_artifacts_exist(artifacts: &ArtifactSet) -> vmcell::Result<()> {
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
    Ok(())
}

/// Validate an artifact pair on a **caller-supplied backend**: [`validate`]'s body, with the
/// backend chosen by the caller instead of by this crate.
///
/// [`validate`] is this function on `default_backend` — Cloud Hypervisor, unchanged — so a
/// consumer that never names a backend sees exactly what it saw before.
///
/// # Why the knob is a parameter and not a field on [`ValidationOptions`]
/// Design §17 (Open gaps and deferred work) records the hardcode and sketches "a backend knob on
/// `ValidationOptions`". That shape does not hold, and a sketched signature is advisory where the
/// behavior and its gate bind (AGENTS.md), so the shift is recorded here and in
/// `docs/implementation-notes.md` rather than being silent. Two structural reasons:
///
/// 1. **[`Vmm`] is not dyn-compatible.** `create` and `restore` are `async fn`, so `dyn Vmm` does
///    not compile at all (`error[E0038]: the trait `vmcell::Vmm` is not dyn compatible … because
///    method `create` is `async``). A *field* holding an erased backend — or an erased factory
///    over one — is therefore not expressible. What remains is a generic `ValidationOptions<V>`,
///    which routes the same type parameter through the configuration type, infects every signature
///    that carries one, and buys nothing this parameter does not.
/// 2. **The alternative rustc itself suggests, "an enum where each variant holds one of these
///    types", inverts the layering.** Those variants live in `vmcell-firecracker`, `vmcell-qemu`
///    and `vmcell-crosvm`, and every one of them depends on `vmcell`; a validator enumerating them
///    would drag all three into a contract crate — and a consumer's own out-of-tree backend, the
///    caller this knob exists for, would still be unreachable.
///
/// So the backend travels with the call, as it does at every other composition root in this
/// workspace: `vmcell-bench`'s `bench-vm` picks the concrete backend in `main` (cargo features
/// decide which backend crates are linked at all) and hands it to one generic `run_mode<V: Vmm>`,
/// and this crate's own [`conformance::run_battery`] already takes its backend from the caller
/// through [`conformance::LiveProbe`]. [`ValidationOptions`] stays what it is: `Clone + Debug`
/// data, with no field a caller must now fill in.
///
/// # The other entry point
/// [`conformance::run_battery`] needs no knob added — it never had the hardcode. The two §10.4
/// doors are symmetric **after** this change rather than because of it, so the asymmetry design
/// §17 records for `run_budget` (the battery bounded, this door not) does not repeat here.
///
/// # What this door does not check
/// It does **not** probe `/dev/kvm`. The caller chose the backend, so the caller is the one who
/// knows whether it needs one: every shipped backend does — [`harness::has_kvm`] is public for
/// exactly that preflight, and [`validate`] performs it for the Cloud Hypervisor it picks — while a
/// test double does not. Refusing on the double's behalf would put this knob's own gate behind the
/// facility the knob exists to be testable without. It does run the same artifact-existence
/// refusal, through the one predicate (`ensure_artifacts_exist`).
///
/// ```no_run
/// use vmcell::vmm::cloud_hypervisor::CloudHypervisor;
/// use vmcell_artifact_validator::{ArtifactSet, Level, ValidationOptions, harness, validate_with};
///
/// # #[tokio::main]
/// # async fn main() -> vmcell::Result<()> {
/// // Any `Vmm`: a secondary backend crate's, or a consumer's own. This one is the default spelled
/// // out — `validate` is precisely this call.
/// assert!(harness::has_kvm(), "every shipped backend boots on /dev/kvm");
/// let vmm = CloudHypervisor::new(harness::ch_bin());
/// let artifacts = ArtifactSet::new(harness::get_vmlinux(), harness::get_rootfs());
/// let report = validate_with(&vmm, &artifacts, &ValidationOptions::level(Level::Core)).await?;
/// eprintln!("{} checks", report.outcomes.len());
/// # Ok(())
/// # }
/// ```
///
/// # Errors
/// - [`vmcell::Error::Artifact`] if `artifacts.kernel` or `artifacts.rootfs` does not exist.
/// - [`vmcell::Error::Timeout`] if the run outran [`ValidationOptions::run_budget`], naming the
///   level that outran it and the checks that completed first.
pub async fn validate_with<V: Vmm>(
    vmm: &V,
    artifacts: &ArtifactSet,
    opts: &ValidationOptions,
) -> vmcell::Result<ValidationReport> {
    ensure_artifacts_exist(artifacts)?;
    let outcomes = match run_levels_bounded(opts.level, opts.run_budget, |level| async move {
        let mut level_outcomes: Vec<CheckOutcome> = Vec::new();
        run_level(level, vmm, artifacts, &mut level_outcomes).await;
        level_outcomes
    })
    .await
    {
        Ok(outcomes) => outcomes,
        Err((budget, level, completed)) => {
            return Err(run_budget_exceeded(budget, level, &completed));
        }
    };

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

/// Runs one level's checks — **the one place** a [`Level`] is turned into its runner, so a level
/// cannot acquire a second, unbudgeted call site
/// (`every_level_runner_is_called_only_through_run_level` scans for one).
async fn run_level<V: Vmm>(
    level: Level,
    vmm: &V,
    artifacts: &ArtifactSet,
    outcomes: &mut Vec<CheckOutcome>,
) {
    match level {
        Level::Core => checks::run_core(vmm, artifacts, outcomes).await,
        Level::Extended => checks::run_extended(vmm, artifacts, outcomes).await,
        Level::Full => checks::run_full(vmm, artifacts, outcomes).await,
    }
}

/// Runs every level up to `deepest` under **one absolute deadline**, accumulating their outcomes.
///
/// `Err((budget, level, completed))` is "this level outran the budget", carrying every check that
/// had completed — the shape [`conformance::ConformanceError::BatteryBudgetExceeded`] uses, because
/// a bare timeout that says only "too slow" never says where it hung.
///
/// Generic over the runner so the budget is gated against a future the test controls: a boot is not
/// a deterministic wedge (`harness::try_start_vm` wires the real cgroup seam, which fails *fast* on
/// a host with no delegated subtree), and a gate whose wedge depends on the machine is not a gate.
async fn run_levels_bounded<F, Fut>(
    deepest: Level,
    budget: Option<Duration>,
    mut run: F,
) -> Result<Vec<CheckOutcome>, (Duration, Level, Vec<CheckOutcome>)>
where
    F: FnMut(Level) -> Fut,
    Fut: Future<Output = Vec<CheckOutcome>>,
{
    // ONE `Instant`, computed once, bounding the whole run — a per-level `Duration` would hand each
    // level a fresh copy of the budget and bound nothing overall (§9.4: outer-bounds-inner). Kept
    // beside the budget it came from so the refusal can name it without an `unwrap`.
    let bound = budget.map(|budget| (budget, tokio::time::Instant::now() + budget));
    let mut completed: Vec<CheckOutcome> = Vec::new();
    for level in [Level::Core, Level::Extended, Level::Full] {
        if level > deepest {
            break;
        }
        let run_one = run(level);
        // `timeout_at`, not `timeout`: one deadline for every level is what makes the bound the
        // run's, and a level that starts already past it is refused immediately instead of being
        // handed the rest of a budget that is gone.
        let level_outcomes = match bound {
            Some((budget, deadline)) => match tokio::time::timeout_at(deadline, run_one).await {
                Ok(level_outcomes) => level_outcomes,
                // The wedged level's own partial outcomes go down with the cancelled future (it
                // owns its buffer); what the error carries is every check that COMPLETED, which is
                // the half a reader acts on.
                Err(_) => return Err((budget, level, completed)),
            },
            None => run_one.await,
        };
        completed.extend(level_outcomes);
    }
    Ok(completed)
}

/// The typed refusal a run that outran its budget returns.
///
/// [`vmcell::Error::Timeout`] rather than a `Fail` outcome in the report: the artifact violated
/// nothing — the *run* did not finish — and a `Skip` would make an unfinished run green (the
/// skip==pass hazard this crate's rustdoc opens with).
fn run_budget_exceeded(
    budget: Duration,
    level: Level,
    completed: &[CheckOutcome],
) -> vmcell::Error {
    let ids: Vec<&str> = completed.iter().map(|o| o.id).collect();
    vmcell::Error::Timeout(format!(
        "artifact validation exceeded its {}s run_budget while running the {} checks; {} check(s) \
         completed first: [{}]. The budget bounds the whole run (per-check deadlines are \
         unchanged), so this is a wedged boot or an under-budgeted run, never a hang.",
        budget.as_secs(),
        level.as_str(),
        ids.len(),
        ids.join(", ")
    ))
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

    // The five states, and the ONE contract `into_result` keeps across all of them: Fail-only.
    // Design §10.6 states this explicitly ("`into_result()`'s Fail-only contract is unchanged") and
    // it is the clause a later "surely a Warn should be an error too" edit would quietly break —
    // which would make under-claiming red and over-claiming green, the exact inversion the Warn
    // state exists to prevent. RED on the inverse: widen either filter to include Warn or
    // Unverified and both halves of this test go red.
    #[test]
    fn into_result_is_fail_only_across_all_five_states() {
        let report = ValidationReport {
            outcomes: vec![
                outcome("a", Level::Core, CheckStatus::Pass),
                outcome("b", Level::Extended, CheckStatus::Skip("no cap".into())),
                outcome(
                    "c",
                    Level::Full,
                    CheckStatus::Warn("declared absent; it works".into()),
                ),
                outcome(
                    "d",
                    Level::Full,
                    CheckStatus::Unverified("no observation decides this".into()),
                ),
            ],
        };
        assert!(
            report.is_ok(),
            "a report with no Fail is ok, whatever else it carries"
        );
        assert_eq!(report.warnings().count(), 1);
        assert_eq!(report.unverified().count(), 1);
        assert_eq!(report.skipped().count(), 1);
        assert_eq!(report.failures().count(), 0);
        assert!(
            report.clone().into_result().is_ok(),
            "into_result is Fail-only: Warn and Unverified must not become failures"
        );

        // The positive control for the same three iterators: one Fail among them still fails the
        // run and lands in the error list alone, so the assertions above are about the *states*,
        // not about a report that cannot fail at all.
        let mut with_fail = report;
        with_fail.outcomes.push(outcome(
            "e",
            Level::Full,
            CheckStatus::Fail("broken".into()),
        ));
        assert!(!with_fail.is_ok());
        let failures = with_fail.into_result().expect_err("a Fail fails the run");
        assert_eq!(failures.len(), 1, "{failures:?}");
        assert_eq!(failures[0].id, "e");
    }

    /// The check ids one [`Level`] variant's rustdoc names, read out of this file: every backticked
    /// dotted token in the doc block that precedes that variant.
    fn documented_level_ids(variant: &str) -> std::collections::BTreeSet<String> {
        const SRC: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/lib.rs"));
        let head = SRC
            .split_once(&format!("\n    {variant},"))
            .unwrap_or_else(|| panic!("the {variant} variant is declared in this file"))
            .0;
        // Walk back over the variant's own doc lines only (the loop stops at `Extended,`).
        let doc: Vec<&str> = head
            .lines()
            .rev()
            .take_while(|l| l.trim_start().starts_with("///"))
            .collect();
        doc.iter()
            // Odd segments of a backtick split are the code spans; a dotted, space-free one is a
            // check id (`/dev/kvm`, `Extended` and prose are not).
            .flat_map(|l| l.split('`').skip(1).step_by(2))
            .filter(|t| t.contains('.') && !t.contains(char::is_whitespace) && !t.contains('/'))
            .map(ToString::to_string)
            .collect()
    }

    /// The ids one level's runner records against a backend that cannot create a VM.
    ///
    /// `fail_create` is what keeps the roster gates KVM-free *and* complete: since v33 delta 3
    /// every check records **or skips** its id on every path, so a run that dies before the first
    /// guest handshake still enumerates the whole roster (`checks::CORE_CHECK_IDS` and its
    /// siblings are the lists that get filled).
    async fn shipped_ids_of(level: Level) -> std::collections::BTreeSet<String> {
        let vmm = vmcell::vmm::FakeVmm::with_faults(vmcell::vmm::FaultMenu {
            fail_create: true,
            ..vmcell::vmm::FaultMenu::default()
        });
        let artifacts = ArtifactSet::new("/nonexistent/vmlinux", "/nonexistent/rootfs.erofs");
        let mut outcomes = Vec::new();
        // Through the shipped `run_level`, not a second `match` over the levels: a copy here would
        // be the roster gates measuring a dispatch table `validate` does not use.
        run_level(level, &vmm, &artifacts, &mut outcomes).await;
        assert!(
            outcomes.iter().all(|o| o.level == level),
            "a level's runner must record only its own level: {:?}",
            outcomes.iter().map(|o| (o.id, o.level)).collect::<Vec<_>>()
        );
        outcomes.iter().map(|o| o.id.to_string()).collect()
    }

    /// The roster gate itself, shared by all three levels (design §10.6: "the rustdoc gate is
    /// uniform"). The defect it was filed for (`level-full-rustdoc-claims-absent-checks`) —
    /// a rustdoc promising an egress-proxy check and restore state-rotation assertions `run_full`
    /// has never run — was always level-independent; only the enumeration was missing, and delta 3
    /// fixed that with the records-or-skips-on-every-path mechanism rather than waiving the gate.
    ///
    /// Prose cannot be diffed against behavior, so the doc names ids and the run learns the
    /// shipped set: a promised-but-absent check is a lie to a consumer (this rustdoc is downstream
    /// contract surface, §10.4), and a shipped-but-undocumented one is invisible coverage.
    async fn assert_rustdoc_names_the_shipped_checks(level: Level, variant: &str) {
        let shipped = shipped_ids_of(level).await;
        assert!(
            !shipped.is_empty(),
            "the {variant} runner records at least one check"
        );
        assert_eq!(
            documented_level_ids(variant),
            shipped,
            "the Level::{variant} rustdoc must name exactly the checks that level runs"
        );
    }

    #[tokio::test]
    async fn level_core_rustdoc_names_exactly_the_shipped_checks() {
        assert_rustdoc_names_the_shipped_checks(Level::Core, "Core").await;
    }

    #[tokio::test]
    async fn level_extended_rustdoc_names_exactly_the_shipped_checks() {
        assert_rustdoc_names_the_shipped_checks(Level::Extended, "Extended").await;
    }

    #[tokio::test]
    async fn level_full_rustdoc_names_exactly_the_shipped_checks() {
        assert_rustdoc_names_the_shipped_checks(Level::Full, "Full").await;
    }

    // Level ordering gates which groups run: Core < Extended < Full.
    #[test]
    fn test_level_ordering() {
        assert!(Level::Core < Level::Extended);
        assert!(Level::Extended < Level::Full);
        assert!(Level::Full >= Level::Core);
    }

    // ── The run budget (design §17's gap for `validate`, closed) ──────────────────────────────

    /// One outcome, so a stub level runner returns something identifiable.
    fn stub_outcome(level: Level) -> CheckOutcome {
        CheckOutcome::pass(
            match level {
                Level::Core => "stub.core",
                Level::Extended => "stub.extended",
                Level::Full => "stub.full",
            },
            level,
        )
    }

    // A wedged level trips the WHOLE-RUN budget as a typed error naming it — the property per-check
    // deadlines cannot provide, since a `Level::Full` run boots several VMs sequentially and their
    // sum was the only ceiling. The outer `timeout` is this test's own harness bound: if the budget
    // ever stops binding, this fails in five seconds instead of wedging the suite forever.
    //
    // Real time, deliberately (the battery-budget test's argument): `start_paused` would auto-advance
    // the clock past the budget and prove nothing about wall-clock behavior. A STUB runner, also
    // deliberately: a real boot is not a deterministic wedge — `try_start_vm` wires the real cgroup
    // seam, which fails fast on a host with no delegated subtree, so a boot-driven version of this
    // gate would pass here and pass vacuously on CI.
    //
    // RED on the inverse (verified): drop the `timeout_at` in `run_levels_bounded` and this fails on
    // the harness timeout instead of returning.
    #[tokio::test]
    async fn the_run_budget_bounds_the_whole_run_typed_and_never_hangs() {
        let budget = Duration::from_millis(50);
        let run = run_levels_bounded(Level::Full, Some(budget), |level| async move {
            if level == Level::Extended {
                // A level that never answers — not one that answers slowly. Only the run-wide
                // budget can end this.
                let () = std::future::pending().await;
            }
            vec![stub_outcome(level)]
        });
        let outcome = tokio::time::timeout(Duration::from_secs(5), run)
            .await
            .expect("the run must return on its own budget, not on this harness timeout");

        let Err((reported, level, completed)) = outcome else {
            panic!("a wedged level must trip the run budget, got {outcome:?}");
        };
        assert_eq!(reported, budget);
        assert_eq!(level, Level::Extended, "the error names WHERE it hung");
        assert_eq!(
            completed.iter().map(|o| o.id).collect::<Vec<&str>>(),
            vec!["stub.core"],
            "the checks that completed before the wedge are what the reader acts on"
        );

        let rendered = run_budget_exceeded(reported, level, &completed).to_string();
        assert!(
            rendered.contains("run_budget") && rendered.contains("extended"),
            "the typed error names the budget and the level that outran it: {rendered}"
        );
        assert!(
            rendered.contains("stub.core"),
            "…and the checks that completed first: {rendered}"
        );
        assert!(
            matches!(
                run_budget_exceeded(reported, level, &completed),
                vmcell::Error::Timeout(_)
            ),
            "an unfinished run is a timeout, never a report whose missing tail reads as green"
        );
    }

    // The positive control for the gate above, in both directions: a run that fits its budget
    // returns every level's outcomes, and `None` (the explicit opt-out) runs unbounded. Without this
    // the budget could be bounding everything to zero and the test above would still pass.
    #[tokio::test]
    async fn a_run_that_fits_its_budget_reports_every_level_it_was_asked_for() {
        for budget in [Some(Duration::from_secs(30)), None] {
            let outcomes = run_levels_bounded(Level::Extended, budget, |level| async move {
                vec![stub_outcome(level)]
            })
            .await
            .expect("a run that fits its budget reports");
            assert_eq!(
                outcomes.iter().map(|o| o.id).collect::<Vec<&str>>(),
                vec!["stub.core", "stub.extended"],
                "budget {budget:?}: every level up to the deepest asked for, and no deeper"
            );
        }
    }

    // The default arm gets the strictest scrutiny (AGENTS.md): the budget must be ON by default, and
    // the `level()` constructor must not silently drop it — a caller that never names the budget is
    // the caller this gap was open for.
    #[test]
    fn the_default_and_the_level_constructor_both_carry_the_default_budget() {
        assert_eq!(
            ValidationOptions::default().run_budget,
            Some(DEFAULT_RUN_BUDGET)
        );
        assert_eq!(
            ValidationOptions::level(Level::Full).run_budget,
            Some(DEFAULT_RUN_BUDGET)
        );
        assert_eq!(ValidationOptions::level(Level::Full).level, Level::Full);
    }

    /// A backend that records every call and creates nothing — what keeps every gate in this
    /// module KVM-free.
    fn recording_backend() -> vmcell::vmm::FakeVmm {
        vmcell::vmm::FakeVmm::with_faults(vmcell::vmm::FaultMenu {
            fail_create: true,
            ..vmcell::vmm::FaultMenu::default()
        })
    }

    /// An artifact pair that EXISTS, since both doors refuse one that does not. The bytes are
    /// never read — a backend that cannot create a VM never opens them — so the fixture is two
    /// files and their tempdir.
    ///
    /// The `TempDir` is returned rather than dropped here: it owns its cleanup on the panic path as
    /// well as the success path (AGENTS.md, "a test's own fixtures are residue too"), and a
    /// caller that drops it early would delete the very files the precondition then looks for.
    fn artifact_fixture() -> (tempfile::TempDir, ArtifactSet) {
        let dir = tempfile::tempdir().expect("a tempdir for the artifact fixture");
        let kernel = dir.path().join("vmlinux");
        let rootfs = dir.path().join("rootfs.erofs");
        std::fs::write(&kernel, b"not a kernel").expect("write the fixture kernel");
        std::fs::write(&rootfs, b"not a rootfs").expect("write the fixture rootfs");
        let artifacts = ArtifactSet::new(kernel, rootfs);
        (dir, artifacts)
    }

    // The wiring, behaviorally: `validate_with` runs exactly the levels its options ask for, through
    // the bounded sequencer, and returns a report. `fail_create` keeps it KVM-free — every check
    // records or skips its id on every path, so the rosters are enumerable against a backend that
    // cannot create a VM.
    #[tokio::test]
    async fn validate_with_runs_exactly_the_levels_its_options_ask_for() {
        let vmm = recording_backend();
        let (_fixture, artifacts) = artifact_fixture();
        for (deepest, expected) in [
            (Level::Core, vec![Level::Core]),
            (Level::Extended, vec![Level::Core, Level::Extended]),
            (Level::Full, vec![Level::Core, Level::Extended, Level::Full]),
        ] {
            let report = validate_with(&vmm, &artifacts, &ValidationOptions::level(deepest))
                .await
                .expect("a run inside its budget reports");
            let mut levels: Vec<Level> = report.outcomes.iter().map(|o| o.level).collect();
            levels.dedup();
            assert_eq!(levels, expected, "deepest = {deepest:?}");
            assert!(
                report
                    .outcomes
                    .iter()
                    .any(|o| o.id == "boot.config" && matches!(o.status, CheckStatus::Pass)),
                "the run really reached the shipped checks: {:?}",
                report.outcomes
            );
        }
    }

    // THE KNOB, behaviorally: `validate_with` boots on the backend the CALLER handed it, not on
    // the one `validate` picks. `FakeVmm` records every `create` it is asked for, so "the caller's
    // backend was the one driven" is an assertion and not an inference — and the fake needs no
    // `/dev/kvm`, which is exactly why that probe stayed on `validate` and did not move into this
    // door.
    //
    // RED on the inverse (verified): ignore the `vmm` argument in `validate_with` and run on
    // `default_backend()` instead — the fake's call log stays empty and this fails, on a host with
    // KVM and on one without.
    //
    // WHAT THIS FAKE CANNOT SEE, and the live leg that does (AGENTS.md): it boots nothing and
    // touches no filesystem, so it proves the dispatch and not that a real backend still comes up
    // through this door. `tests/smoke.rs`'s `#[ignore]`d legs are that half — they run `validate`,
    // which IS `validate_with` on the default backend, against real artifacts under
    // `just test-validator`.
    #[tokio::test]
    async fn validate_with_runs_on_the_caller_supplied_backend() {
        let vmm = recording_backend();
        let (_fixture, artifacts) = artifact_fixture();

        let report = validate_with(&vmm, &artifacts, &ValidationOptions::level(Level::Core))
            .await
            .expect("a run inside its budget reports");

        let calls = vmm.calls.lock().expect("the fake's call log").clone();
        assert!(
            calls.iter().any(|c| c == "create"),
            "the caller's backend must be the one driven, but it was never asked to create a VM: \
             {calls:?}"
        );
        // …and the report is that backend's story, not another's: the scripted failure the caller
        // handed in is what the boot check reports back.
        assert!(
            report.outcomes.iter().any(|o| matches!(
                &o.status,
                CheckStatus::Fail(m) if m.contains("scripted create failure")
            )),
            "the failure text must trace to the caller's backend: {:?}",
            report.outcomes
        );
    }

    // Both doors reject an artifact pair that does not exist, through the ONE predicate — including
    // `validate_with`, the door a caller reaches without passing `validate`'s checks first. With the
    // positive control: the same call on an existent pair gets past the precondition and runs.
    //
    // RED on the inverse (verified): drop `ensure_artifacts_exist` from `validate_with`'s body and
    // both legs return `Ok` with a report full of boot failures instead of the typed refusal.
    #[tokio::test]
    async fn validate_with_refuses_an_artifact_pair_that_does_not_exist() {
        let vmm = recording_backend();
        let (_fixture, good) = artifact_fixture();
        for (artifacts, missing) in [
            (
                ArtifactSet::new("/nonexistent/vmlinux", &good.rootfs),
                "kernel artifact does not exist",
            ),
            (
                ArtifactSet::new(&good.kernel, "/nonexistent/rootfs.erofs"),
                "rootfs artifact does not exist",
            ),
        ] {
            let err = validate_with(&vmm, &artifacts, &ValidationOptions::default())
                .await
                .expect_err(
                    "a missing artifact is a typed refusal, never a report of boot failures",
                );
            assert!(
                matches!(&err, vmcell::Error::Artifact(m) if m.contains(missing)),
                "expected an Artifact error naming {missing}, got {err:?}"
            );
        }

        validate_with(&vmm, &good, &ValidationOptions::level(Level::Core))
            .await
            .expect("the positive control: an existent pair gets past the precondition");
    }

    // THE DEFAULT, which the knob must not have moved: `validate` still boots Cloud Hypervisor.
    // Two halves, because neither is enough alone — the identity of the value, and the fact that
    // `validate` is what runs on it. The `/dev/kvm` refusal makes `validate` itself unrunnable here,
    // so the second half is source-scanned, in the shape
    // `every_level_runner_is_called_only_through_run_level` uses.
    //
    // RED on the inverse (verified): point `default_backend` at another backend and the id assert
    // fails; inline the construction back into `validate` and the delegation assert fails.
    #[test]
    fn the_default_backend_is_still_cloud_hypervisor() {
        assert_eq!(
            default_backend().id(),
            "cloud-hypervisor",
            "the shipped default is the primary backend; changing it changes every consumer's run"
        );

        let code = production_statements();
        let body = code
            .split_once("pub async fn validate(")
            .expect("`validate` is this crate's default door")
            .1;
        let end = body
            .find("\n}\n")
            .expect("the function has a closing brace");
        let body = body.get(..end).expect("a char boundary at a newline");
        assert!(
            body.contains("validate_with(&default_backend(), artifacts, opts)"),
            "`validate` must BE `validate_with` on the default backend — a second body is a second \
             place the default can drift: {body}"
        );
    }

    // The symmetry `validate_with`'s rustdoc claims, gated instead of asserted in prose: no OTHER
    // door in this crate names a concrete backend. `conformance::run_battery` takes the caller's
    // through `LiveProbe`, and every `checks::` arm is generic over `Vmm`; a later "default it to
    // cloud-hypervisor here too" re-opens the gap this change closed, one file over, where no test
    // of this door would see it.
    #[test]
    fn only_the_default_door_names_a_concrete_backend() {
        const SOURCES: [(&str, &str); 5] = [
            (
                "src/lib.rs",
                include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/lib.rs")),
            ),
            (
                "src/checks.rs",
                include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/checks.rs")),
            ),
            (
                "src/conformance.rs",
                include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/conformance.rs")),
            ),
            (
                "src/harness.rs",
                include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/harness.rs")),
            ),
            (
                "src/kconfig.rs",
                include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/kconfig.rs")),
            ),
        ];
        // VACUITY, the arm every scan in this repo carries: a roster that reads nothing reports a
        // clean tree. Each file must have production text, and `lib.rs`'s must still hold the door
        // this test is about.
        let mut total = 0usize;
        for (name, source) in SOURCES {
            let production = strip_doc_comments(production_half(source));
            assert!(
                !production.trim().is_empty(),
                "gate misconfigured: {name} yielded no production text"
            );
            total += production.matches("CloudHypervisor::new(").count();
            if name != "src/lib.rs" {
                assert!(
                    !production.contains("CloudHypervisor"),
                    "{name} names a concrete backend; every door but `validate` takes the caller's"
                );
            }
        }
        assert!(
            strip_doc_comments(production_half(SOURCES[0].1))
                .contains("pub async fn validate_with"),
            "gate misconfigured: the scan no longer reads the file holding the knob"
        );
        assert_eq!(
            total, 1,
            "exactly ONE production site constructs a backend, and it is `default_backend`"
        );
    }

    /// Everything in `source` before its test module — the half that ships.
    fn production_half(source: &str) -> &str {
        source
            .split_once("\n#[cfg(test)]")
            .map_or(source, |(production, _)| production)
    }

    /// `text` without its comment lines. A construction shown in a rustdoc EXAMPLE is documentation,
    /// not a call site, and a scan that counts construction sites must not count it — this crate's
    /// front door documents the default by spelling it out.
    fn strip_doc_comments(text: &str) -> String {
        text.lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<&str>>()
            .join("\n")
    }

    /// This file's production statements: [`production_code`] with the comment lines dropped.
    fn production_statements() -> String {
        strip_doc_comments(production_code())
    }

    /// This file's production text — everything before the test module.
    fn production_code() -> &'static str {
        const SRC: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/lib.rs"));
        SRC.split_once("\n#[cfg(test)]\nmod tests {")
            .expect("this file has a test module")
            .0
    }

    // The budget binds the whole run only if EVERY level goes through the one bounded sequencer. A
    // later edit adding a direct `checks::run_*` call beside it restores the unbounded path
    // silently: the levels that kept using the helper stay bounded, so no behavioral test reddens
    // and the run's ceiling quietly becomes "whatever the per-check deadlines add up to" again. The
    // gate binds the call sites, not just the extracted predicate (AGENTS.md), so it is source-
    // scanned in the shape `checks::every_roster_id_has_a_recording_site` uses.
    #[test]
    fn every_level_runner_is_called_only_through_run_level() {
        let code = production_code();
        let dispatch = code
            .split_once("async fn run_level")
            .expect("`run_level` is the one dispatch")
            .1;
        let dispatch_end = dispatch
            .find("\n}\n")
            .expect("the function has a closing brace");
        let dispatch = dispatch
            .get(..dispatch_end)
            .expect("a char boundary at a newline");
        for runner in [
            "checks::run_core(",
            "checks::run_extended(",
            "checks::run_full(",
        ] {
            assert_eq!(
                code.matches(runner).count(),
                1,
                "`{runner}` must be called from exactly one production site — a second one is a \
                 level run the run budget does not bound"
            );
            assert!(
                dispatch.contains(runner),
                "`{runner}`'s one call site must be `run_level`, which `run_levels_bounded` is the \
                 only caller of: {dispatch}"
            );
        }
    }
}
