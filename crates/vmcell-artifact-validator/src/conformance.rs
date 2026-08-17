//! The **two-directional** conformance battery (design §10.6, §18 delta 3).
//!
//! [`crate::validate`] checks one direction: a property the artifact *has* that does not work.
//! Once §7.4 lets an artifact **declare** and §10.5 lets anyone register one, the other direction
//! matters as much — a declaration is a claim, and an unchecked claim is worse than no claim,
//! because it is a fact a consumer will build a fixture on.
//!
//! # The two things that make an absence check honest
//!
//! 1. **A positive control, under the same check id.** An absence probe without one is a constant
//!    that silently certifies everything: a probe that always answers "absent" passes every absence
//!    check ever written. So every absence verdict here is judged against a second probe run —
//!    the same probe, against an artifact that *declares* the feature — and if that control cannot
//!    demonstrate the feature on this substrate, the verdict is [`CheckStatus::Unverified`], never
//!    a green "verified absence". The pair is **one** check id ([`conformance_check_id`]), so the
//!    control cannot be deleted without the roster gate and the four-leg matrix reddening.
//! 2. **A state between pass and fail, in each direction.** [`CheckStatus::Warn`] for an
//!    under-claim (declared absent, demonstrably works — a documentation defect, and reddening it
//!    would push declarers toward over-claiming) and [`CheckStatus::Unverified`] for an absence no
//!    observation this kit can make decides.
//!
//! # The acceptance shape (design §10.6, the four legs)
//!
//! | the artifact's declaration | the substrate | verdict |
//! |---|---|---|
//! | declares the feature | a backend that has it, and it works | [`CheckStatus::Pass`] |
//! | declares the feature | a backend that does **not** have it | [`CheckStatus::Fail`] naming the backend (§7.4 provenance) |
//! | declares it absent | the control works, the artifact does not | [`CheckStatus::Pass`] — a *verified* absence |
//! | declares it absent | the control works, and so does the artifact | [`CheckStatus::Warn`] — an under-claim |
//!
//! The fourth leg is the control for the third: if the probe answered "absent" unconditionally the
//! fourth leg would be a Pass too, and the whole battery would certify anything. `four_leg_*` in
//! this module's tests drives all four, and the fifth row — the control itself failing — is what
//! keeps the third leg from being a coincidence.
//!
//! # What is judged, and against what
//!
//! "Present" and "absent" are judged against **the artifact's declaration** — the claim under test
//! — never against the computed intersection (design §10.6). The intersection appears only as the
//! *substrate's* verdict ([`Substrate`]), computed by `vmcell`'s one intersection site from the
//! backend descriptor and the host, with the artifact under test deliberately left out of it: a
//! claim judged against a set that already contains the claim proves nothing.
//!
//! # Cost
//!
//! The battery is **on-demand, never on cell boot**: an absence probe is by construction the most
//! expensive kind (it boots to prove a negative). A feature the artifact says nothing about costs
//! nothing — no probe runs — so the price is proportional to what was actually declared.

use std::collections::BTreeSet;
use std::fmt;
use std::time::Duration;

use vmcell::feature::{Feature, FeatureDeclaration, FeatureSet, HostDeclaration, Removal};
use vmcell::vmm::{Vmm, VmmCapabilities};

use crate::classify::{explain_broken_claim, explain_undecidable, explain_underclaim};
use crate::{ArtifactSet, CheckOutcome, CheckStatus, Level, ValidationReport};

/// The default overall battery budget: generous enough for a full declared roster of real boots,
/// finite so a wedged probe is a typed error instead of a hung CI job (design §17's recorded gap,
/// closed here).
pub const DEFAULT_BATTERY_BUDGET: Duration = Duration::from_secs(20 * 60);

/// The label of one artifact under test — the identity a [`CheckStatus::Warn`] is dispositioned
/// against in [`ConformanceOptions::expected_warnings`].
///
/// A newtype rather than a bare `String` because the expectation set is keyed on
/// `(Feature, ArtifactId)`: an untyped pair invites the two halves being swapped at a call site,
/// and the whole point of the lifecycle is that an expectation names *exactly* which artifact's
/// under-claim was triaged.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct ArtifactId(String);

impl ArtifactId {
    /// The id for `label` (a registry label, §10.5 — or any name the caller uses for the artifact).
    #[must_use]
    pub fn new(label: impl Into<String>) -> Self {
        ArtifactId(label.into())
    }

    /// The label as a string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ArtifactId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// One artifact pair under test, plus the declaration it makes about itself.
///
/// The declaration is supplied by the caller rather than read here, because §7.4 makes the
/// **registry entry** the one authority and the sidecar its travel form: a caller with a registry
/// passes the resolved entry's declaration, and a caller with only files on disk passes
/// [`vmcell::feature::FeatureDeclaration::load_beside`]'s result. Either way this crate never
/// becomes a second place a declaration can come from.
#[derive(Clone, Debug)]
pub struct ConformanceSubject {
    /// The artifact's label.
    pub id: ArtifactId,
    /// The kernel + rootfs pair to boot.
    pub artifacts: ArtifactSet,
    /// What this artifact declares about itself.
    pub declaration: FeatureDeclaration,
}

impl ConformanceSubject {
    /// The stance this subject takes on `feature`: `Some(true)` declared present, `Some(false)`
    /// declared absent, `None` no stance at all (the artifact does not speak about it, §7.4).
    #[must_use]
    pub fn stance(&self, feature: Feature) -> Option<bool> {
        self.declaration.stances.get(&feature).copied()
    }
}

/// What a probe observed at the data plane.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ProbeOutcome {
    /// The probe exercised the feature and it worked.
    Works,
    /// The probe exercised the feature and it did not work; carries the failure text (already
    /// classified by [`crate::classify`] when it was a boot failure).
    DoesNotWork(String),
    /// The probe was **not run**, carrying why. Never a substitute for either answer above: an
    /// unrun probe decides nothing, which is exactly what [`CheckStatus::Unverified`] reports.
    NotRun(String),
}

/// The seam the battery observes a feature through.
///
/// A trait rather than a hardcoded call because the *judgement* — the four-leg matrix, the control
/// pairing, the warning lifecycle — is what delta 3 specifies, and it must be drivable without KVM.
/// The shipped implementation is [`LiveProbe`], which boots real VMs through [`crate::checks`];
/// the tests drive a scripted one, so every leg of the matrix runs on every machine.
#[expect(
    async_fn_in_trait,
    reason = "the battery calls this seam directly (never boxed, never spawned), so the desugared \
              non-Send future is exactly what is wanted; matches the `Vmm` trait it wraps"
)]
pub trait FeatureProbe {
    /// Observes `feature` on `subject` at the data plane.
    async fn probe(&self, feature: Feature, subject: &ConformanceSubject) -> ProbeOutcome;
}

/// What the shipped battery can do about a feature — the one place a feature is mapped onto a
/// data-plane probe.
///
/// Exhaustive over [`Feature`], so a new variant in `vmcell`'s vocabulary is a **compile error**
/// here until it states which of the two it is. That is the §7.4 granularity clause held up from
/// the other side: a variant is supposed to have a validated §10.6 check behind it, and this is
/// where the absence of one becomes visible instead of silently meaning "unchecked".
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ProbePlan {
    /// Decidable by attempting the thing: snapshot the cell and restore it.
    SnapshotRoundTrip,
    /// Decidable by reading attributes back in-guest: boot the artifact and walk its own rootfs
    /// asking the `xattr` applet whether any path carries an extended attribute (§4.7, §18 delta 7).
    ///
    /// It became decidable when delta 7 landed the reader: before the applet there was no way to
    /// ask a guest the question at all, which is why this feature sat on [`ProbePlan::Undecidable`]
    /// with the rest. What it measures is stated exactly in
    /// [`crate::checks::xattr_preserved_probe`] — "this artifact carries at least one extended
    /// attribute" — and, deliberately, it does not distinguish a policy that stripped them from a
    /// base that had none: both are the same fact about the artifact under test, which is the fact
    /// the declaration claims.
    XattrReadback,
    /// Not decidable by any observation this kit can make; the string says why, and what a
    /// decidable probe would need.
    Undecidable(&'static str),
}

/// The nested-virt reason, spelled once (it is the one every reader will want to argue with).
///
/// `kvm-ok` — "is `/dev/kvm` there?" — is **not** a causal probe for nested virt: `-cpu host`
/// exposes VMX to L1 unconditionally, so `/dev/kvm` exists in the guest whether or not nesting was
/// asked for. vmcell's own matrix learned this the expensive way and asserts the guest KVM module
/// parameter instead (`crates/vmcell/tests/nested_virt.rs`, the `nested_virt_disabled` control).
/// That parameter answers a question about the *cell's configuration*, not about the artifact's
/// declaration, so it cannot serve as this battery's absence probe: an artifact that declares no
/// nested support and a cell booted with nesting off are indistinguishable through it. Hence
/// `Unverified`, with the upgrade path named — never a naive `/dev/kvm` check, which would report
/// "works" for every artifact and turn every nested-virt absence declaration into a Warn.
const NESTED_VIRT_UNDECIDABLE: &str = "no in-guest observation this kit can make distinguishes an artifact that carries no nested-KVM \
     support from a cell that was simply not booted with nesting: `/dev/kvm` is exposed by `-cpu \
     host` regardless, and the causal signal (the guest kvm_intel/kvm_amd `nested` module \
     parameter) answers about the cell's configuration, not the artifact's declaration. Deciding it \
     needs an artifact-differential probe (two cells, identical configuration, differing only in \
     the kernel artifact) — see vmcell's `nested_virt_disabled` matrix leg for the parameter read";

/// The reason every feature with no data-plane probe carries.
const NO_PROBE_YET: &str = "this kit has no data-plane probe for the feature yet, so neither its presence nor its absence \
     is measured here; an absence is reported as undecided rather than assumed";

/// The one feature→probe mapping (see [`ProbePlan`]).
#[must_use]
pub fn probe_plan(feature: Feature) -> ProbePlan {
    match feature {
        // Decidable exactly as §10.6 says: "snapshot absence is testable by attempting a snapshot".
        Feature::SnapshotRestore => ProbePlan::SnapshotRoundTrip,
        Feature::NestedVirt => ProbePlan::Undecidable(NESTED_VIRT_UNDECIDABLE),
        // Decidable since §18 delta 7 put a reader in the guest. Left `Undecidable` while the
        // `xattr` applet did not exist; leaving it there once it did would have been the
        // accepted-but-not-honored shape — a kit reporting "no data-plane probe" for the one
        // artifact property it can now actually observe.
        Feature::XattrPreserved => ProbePlan::XattrReadback,
        Feature::LazyRestore
        | Feature::VirtioFsShares
        | Feature::UnprivilegedVhostUserNet
        | Feature::VirtioConsole
        | Feature::RestoreRotatesHostPaths
        | Feature::DiskIoThrottle
        | Feature::UsbHostPassthrough
        | Feature::ControlPlane
        | Feature::ProcConfigGz => ProbePlan::Undecidable(NO_PROBE_YET),
    }
}

/// The paired check id for `feature` — **one id for the absence probe and its positive control**.
///
/// Composed from [`Feature::name`] and pinned against it by `check_ids_are_composed_from_the_
/// feature_name`, so the id vocabulary cannot drift from the feature vocabulary (F6: refusal and
/// report strings are composed from the enum, never hand-spelled). The `&'static str` arms exist
/// because a [`CheckOutcome`] id is `&'static str`; the gate is what keeps them honest.
#[must_use]
pub fn conformance_check_id(feature: Feature) -> &'static str {
    match feature {
        Feature::SnapshotRestore => "conformance.snapshot_restore",
        Feature::LazyRestore => "conformance.lazy_restore",
        Feature::VirtioFsShares => "conformance.virtio_fs_shares",
        Feature::UnprivilegedVhostUserNet => "conformance.unprivileged_vhost_user_net",
        Feature::NestedVirt => "conformance.nested_virt",
        Feature::VirtioConsole => "conformance.virtio_console",
        Feature::RestoreRotatesHostPaths => "conformance.restore_rotates_host_paths",
        Feature::DiskIoThrottle => "conformance.disk_io_throttle",
        Feature::UsbHostPassthrough => "conformance.usb_host_passthrough",
        Feature::ControlPlane => "conformance.control_plane",
        Feature::XattrPreserved => "conformance.xattr_preserved",
        Feature::ProcConfigGz => "conformance.proc_config_gz",
    }
}

/// The id the expected-warning lifecycle reports against (the *other* direction: an expectation
/// that no longer fires).
pub const EXPECTED_WARNINGS_CHECK_ID: &str = "conformance.expected_warnings";

/// The battery's roster: one paired id per [`Feature`], plus [`EXPECTED_WARNINGS_CHECK_ID`].
///
/// Built at call time from `Feature::ALL` so it cannot drift from the vocabulary. The battery reports
/// it whole on every path that produces a report — by construction rather than by a fill tail, unlike
/// the [`Level`] rosters (`crate::checks::CORE_CHECK_IDS`), because it judges every variant of the
/// same `Feature::ALL` it is composed from (see [`run_battery`]'s tail).
#[must_use]
pub fn battery_check_ids() -> Vec<&'static str> {
    let mut ids: Vec<&'static str> = Feature::ALL.into_iter().map(conformance_check_id).collect();
    ids.push(EXPECTED_WARNINGS_CHECK_ID);
    ids
}

/// Knobs for a conformance run. (`ValidationOptions` keeps `level`; this is its two-directional
/// sibling and deliberately not a field on it — a battery is a different, on-demand run.)
#[derive(Clone, Debug)]
pub struct ConformanceOptions {
    /// Absences whose "works anyway" is known and dispositioned.
    ///
    /// **Both directions of the lifecycle are enforced**, which is the whole point:
    /// a [`CheckStatus::Warn`] *not* in this set is promoted to [`CheckStatus::Fail`] (a new
    /// under-claim must be triaged, not accumulated), and an entry in it whose warning **no longer
    /// fires** is reported as an error of its own — the unfulfilled-`#[expect]` rule one level up.
    /// A stale expectation outliving its reason is the same rot as a stale suppression, and without
    /// the second direction warnings silt up until nobody reads them: the same terminal state as
    /// not emitting them at all.
    ///
    /// Staleness is judged **only against the artifact this run tested**: an entry naming another
    /// artifact is somebody else's run's business, not evidence that this one is stale.
    pub expected_warnings: BTreeSet<(Feature, ArtifactId)>,
    /// The wall-clock budget for the **whole battery**. Per-check deadlines stay (each probe keeps
    /// its own), and this bounds their sum: a kit that doubles its check count doubles the
    /// visibility of "fails loudly per check, hangs per battery". Exceeding it is
    /// [`ConformanceError::BatteryBudgetExceeded`] — a typed error naming the budget, never a hang.
    pub battery_budget: Duration,
}

impl Default for ConformanceOptions {
    fn default() -> Self {
        ConformanceOptions {
            expected_warnings: BTreeSet::new(),
            battery_budget: DEFAULT_BATTERY_BUDGET,
        }
    }
}

/// Why a conformance run could not produce a report at all.
///
/// The distinction [`crate::validate`] already draws: a *check* outcome is data in the report, and
/// the outer `Err` is "the battery could not run" — a caller mistake or an exceeded budget.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ConformanceError {
    /// The battery as a whole outran [`ConformanceOptions::battery_budget`].
    BatteryBudgetExceeded {
        /// The budget that was exceeded.
        budget: Duration,
        /// The check ids that had completed when the budget expired — so the report of the hang
        /// says where it hung, which a bare timeout never does.
        completed: Vec<&'static str>,
    },
    /// The positive control does not declare `feature`, so there is no control to pair the absence
    /// probe with. Refused before anything boots rather than degraded into an unverifiable run.
    ControlDoesNotDeclare {
        /// The feature the candidate declares absent and the control must declare present.
        feature: Feature,
        /// The control artifact's label.
        control: ArtifactId,
    },
    /// The candidate and the control are the same artifact — a "control" that is the thing under
    /// test proves nothing at all.
    ControlIsCandidate {
        /// The label both subjects carry.
        id: ArtifactId,
    },
}

impl fmt::Display for ConformanceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConformanceError::BatteryBudgetExceeded { budget, completed } => write!(
                f,
                "the conformance battery exceeded its {}s battery_budget; {} check(s) completed \
                 first: [{}]. The budget bounds the battery as a whole (per-check deadlines are \
                 unchanged), so this is a wedged or under-budgeted probe, never a hang.",
                budget.as_secs(),
                completed.len(),
                completed.join(", ")
            ),
            ConformanceError::ControlDoesNotDeclare { feature, control } => write!(
                f,
                "the positive control \"{control}\" does not declare `{}`, so the absence probe \
                 for it would have no control — and an absence probe without a positive control is \
                 a constant that certifies everything (§10.6). Give the battery a control artifact \
                 that declares the feature.",
                feature.name()
            ),
            ConformanceError::ControlIsCandidate { id } => write!(
                f,
                "the candidate and the positive control are both \"{id}\": an artifact cannot be \
                 its own control, since the pair exists to show the probe can answer \"works\" for \
                 something other than the thing under test."
            ),
        }
    }
}

impl std::error::Error for ConformanceError {}

/// The substrate a claim is measured on: the backend and the host, **without** the artifact under
/// test.
///
/// Computed by `vmcell`'s one intersection site ([`FeatureSet::intersect`], F6) rather than by
/// reading descriptor fields here — a second reader of `VmmCapabilities` is exactly the divergence
/// F6 exists to prevent. The artifact is left out on purpose: §10.6 judges a claim against the
/// *declaration*, never against a computed set that already contains it.
#[derive(Clone, Debug)]
pub struct Substrate {
    backend: String,
    features: FeatureSet,
}

impl Substrate {
    /// The substrate of `backend`/`caps`, with `host` as the host axis (`None` = not probed, which
    /// removes nothing — the F1 distinction between an absent facility and an unasked question).
    #[must_use]
    pub fn new(backend: &str, caps: &VmmCapabilities, host: Option<&HostDeclaration>) -> Self {
        Substrate {
            backend: backend.to_string(),
            features: FeatureSet::intersect(backend, caps, host, &[]),
        }
    }

    /// The substrate a live `vmm` offers on this host (the host axis is probed).
    #[must_use]
    pub fn of<V: Vmm>(vmm: &V) -> Self {
        let host = HostDeclaration::probe();
        Substrate::new(vmm.id(), &vmm.capabilities(), Some(&host))
    }

    /// The backend's id.
    #[must_use]
    pub fn backend(&self) -> &str {
        &self.backend
    }

    /// `None` when the substrate can exercise `feature`; `Some(removal)` naming who cannot and why.
    #[must_use]
    pub fn removal(&self, feature: Feature) -> Option<&Removal> {
        self.features.why_absent(feature)
    }
}

/// Everything one paired check observed, before it is judged — the input [`judge`] is a **pure**
/// function of.
///
/// The control is a required field, not an option: that is how "an absence probe and its positive
/// control are one check" is made structural rather than conventional. A caller cannot construct an
/// observation without saying what the control did.
#[derive(Clone, Debug)]
pub struct PairedObservation<'a> {
    /// The feature under test.
    pub feature: Feature,
    /// The artifact whose declaration is the claim under test.
    pub artifact: &'a ArtifactId,
    /// That declaration: `Some(true)` present, `Some(false)` absent, `None` no stance.
    pub declared: Option<bool>,
    /// The substrate's own verdict — `Some` when the backend/host cannot exercise the feature.
    pub substrate: Option<&'a Removal>,
    /// What the probe observed against [`Self::artifact`].
    pub candidate: &'a ProbeOutcome,
    /// What the **same** probe observed against the positive control.
    pub control: &'a ProbeOutcome,
    /// The positive control's label (named in every message, so a reader can re-run it).
    pub control_id: &'a ArtifactId,
}

/// The four-leg verdict (see this module's table) — pure, so the whole acceptance matrix is a unit
/// test.
#[must_use]
pub fn judge(obs: &PairedObservation<'_>) -> CheckStatus {
    let Some(declared) = obs.declared else {
        // No stance is not a claim, and a conformance check judges claims. Skip keeps its shipped
        // meaning ("the check did not run, and that is not a pass").
        return CheckStatus::Skip(format!(
            "artifact \"{}\" declares no stance on `{}`; a conformance check judges a declaration, \
             and there is none to judge",
            obs.artifact,
            obs.feature.name()
        ));
    };

    if declared {
        // ── The present direction ─────────────────────────────────────────────────────────────
        if let Some(removal) = obs.substrate {
            // Leg 2: the claim is decidably contradicted by the substrate's own descriptor. Not a
            // Skip: nothing is undecided here — the backend states it cannot, so the artifact's
            // claim cannot hold on this cell, and §7.4 provenance names who says so.
            return CheckStatus::Fail(explain_broken_claim(
                obs.feature,
                obs.artifact.as_str(),
                Some(removal),
                "the substrate's own descriptor removes it, so the declared feature cannot work here",
            ));
        }
        return match obs.candidate {
            // Leg 1.
            ProbeOutcome::Works => CheckStatus::Pass,
            ProbeOutcome::DoesNotWork(why) => CheckStatus::Fail(explain_broken_claim(
                obs.feature,
                obs.artifact.as_str(),
                None,
                why,
            )),
            ProbeOutcome::NotRun(why) => CheckStatus::Unverified(explain_undecidable(
                obs.feature,
                obs.artifact.as_str(),
                why,
            )),
        };
    }

    // ── The absence direction ─────────────────────────────────────────────────────────────────
    if let Some(removal) = obs.substrate {
        // The substrate cannot exercise the claim at all, so neither the probe nor its control can
        // say anything about the artifact. This is precisely the shipped `Skip`, and §10.6 keeps it
        // that way: the new states never absorb the old one's meaning.
        return CheckStatus::Skip(format!(
            "the substrate cannot exercise `{}` ({removal}), so this artifact's absence \
             declaration cannot be measured here — the positive control would fail for the \
             substrate's reason, not the artifact's",
            obs.feature.name()
        ));
    }

    // THE POSITIVE CONTROL. Everything below this line is only meaningful because the control
    // demonstrated that the probe can answer "works" on this substrate, for an artifact other than
    // the one under test. Without it, "the probe said absent" is indistinguishable from "the probe
    // always says absent" — the constant that certifies everything.
    match obs.control {
        ProbeOutcome::Works => {}
        ProbeOutcome::DoesNotWork(why) => {
            return CheckStatus::Unverified(explain_undecidable(
                obs.feature,
                obs.artifact.as_str(),
                &format!(
                    "the positive control \"{}\" could not demonstrate the feature on this \
                     substrate ({why}), so \"it did not work for the artifact under test\" is not \
                     evidence of an absence",
                    obs.control_id
                ),
            ));
        }
        ProbeOutcome::NotRun(why) => {
            return CheckStatus::Unverified(explain_undecidable(
                obs.feature,
                obs.artifact.as_str(),
                &format!(
                    "the positive control \"{}\" was not run ({why}), and an absence with no \
                     control is not a measurement",
                    obs.control_id
                ),
            ));
        }
    }

    match obs.candidate {
        // Leg 4: the under-claim. The control proves the probe discriminates, and the artifact
        // that says it cannot, does.
        ProbeOutcome::Works => CheckStatus::Warn(explain_underclaim(
            obs.feature,
            obs.artifact.as_str(),
            obs.control_id.as_str(),
        )),
        // Leg 3: a verified absence — the only Pass an absence declaration can earn.
        ProbeOutcome::DoesNotWork(_) => CheckStatus::Pass,
        ProbeOutcome::NotRun(why) => {
            CheckStatus::Unverified(explain_undecidable(obs.feature, obs.artifact.as_str(), why))
        }
    }
}

/// The shipped probe: boots real VMs through [`crate::checks`].
///
/// Each decidable arm answers in all three [`ProbeOutcome`] states, and the state that matters most
/// is `NotRun`: a candidate that could not be configured, could not start, or never handed shakes was
/// never asked about the feature, so it must not be reported as a measured absence (docs/90 M8 —
/// `judge` reads a measured absence against an absence declaration as the one `Pass` an absence can
/// earn, and the positive control cannot catch it because the control is a *different* artifact and
/// boots fine). `crate::checks::ProbeStop` is where the two are split.
///
/// FAKE-BLIND AXIS (AGENTS.md rule 4): this type is the one piece of the battery a fake cannot
/// fully exercise — `crate::checks::snapshot_restore_probe` needs a real guest to hand shake, so a
/// fake-driven run reaches only its setup arms (`NotRun`), never `Works` or the measured
/// `DoesNotWork`. Its *dispatch* is unit-gated ([`probe_plan`]), its setup/measurement split by
/// `the_snapshot_probe_classifies_setup_before_the_attempt_and_measurement_after` (a source scan,
/// like the m9 one beside it); its *execution* is covered only by the live `#[ignore]`d conformance
/// legs in `tests/smoke.rs`, which `just test-validator` selects — one per decidable plan
/// ([`ProbePlan::SnapshotRoundTrip`] and [`ProbePlan::XattrReadback`]).
///
/// What the xattr leg does **not** cover, stated rather than implied: the artifacts the validator
/// suite has on hand are packed under [`vmcell::artifact::XattrPolicy::Strip`] (that is what
/// `rootfs.default` declares), so the live leg drives the probe's `DoesNotWork` answer and its
/// control pairing, never its `Works` answer. The `Works` side is proved against a real
/// `Preserve`-packed image by `crates/vmcell/tests/xattr_policy.rs`, one crate over, which packs
/// one and reads the attributes back through the same applet.
#[derive(Clone, Copy, Debug)]
pub struct LiveProbe<'a, V: Vmm> {
    vmm: &'a V,
}

impl<'a, V: Vmm> LiveProbe<'a, V> {
    /// A probe that boots on `vmm`.
    #[must_use]
    pub fn new(vmm: &'a V) -> Self {
        LiveProbe { vmm }
    }
}

impl<V: Vmm> FeatureProbe for LiveProbe<'_, V> {
    async fn probe(&self, feature: Feature, subject: &ConformanceSubject) -> ProbeOutcome {
        match probe_plan(feature) {
            // Not `snapshot_restore_roundtrip().map_err(DoesNotWork)`: that mapping is what made an
            // unbootable artifact a verified absence (M8). The probe form draws the setup line.
            ProbePlan::SnapshotRoundTrip => {
                crate::checks::snapshot_restore_probe(self.vmm, &subject.artifacts).await
            }
            ProbePlan::XattrReadback => {
                crate::checks::xattr_preserved_probe(self.vmm, &subject.artifacts).await
            }
            ProbePlan::Undecidable(why) => ProbeOutcome::NotRun(why.to_string()),
        }
    }
}

/// Runs the two-directional battery for `candidate`, using `control` as the positive control for
/// every absence probe, and returns the report.
///
/// # Errors
/// - [`ConformanceError::ControlIsCandidate`] / [`ConformanceError::ControlDoesNotDeclare`] —
///   refused **before** anything boots, because a battery with no usable control cannot produce an
///   honest absence verdict.
/// - [`ConformanceError::BatteryBudgetExceeded`] — the whole battery outran
///   [`ConformanceOptions::battery_budget`], naming the checks that had completed.
pub async fn run_battery<P: FeatureProbe>(
    probe: &P,
    substrate: &Substrate,
    candidate: &ConformanceSubject,
    control: &ConformanceSubject,
    opts: &ConformanceOptions,
) -> Result<ValidationReport, ConformanceError> {
    if candidate.id == control.id {
        return Err(ConformanceError::ControlIsCandidate {
            id: candidate.id.clone(),
        });
    }
    // Refuse before booting anything: every feature whose absence this run must MEASURE needs a
    // control that declares it. Checked up front so a two-hour battery does not die on its last
    // check for a reason visible in its first millisecond.
    for feature in Feature::ALL {
        let needs_control =
            candidate.stance(feature) == Some(false) && substrate.removal(feature).is_none();
        if needs_control && control.stance(feature) != Some(true) {
            return Err(ConformanceError::ControlDoesNotDeclare {
                feature,
                control: control.id.clone(),
            });
        }
    }

    // The battery-wide budget. `outcomes` lives outside the timed future so the typed error can
    // name what had completed when the budget expired — a bare timeout that says only "too slow"
    // is the thing this replaces. `RefCell` (not a lock) because the whole battery is one task.
    let outcomes = std::cell::RefCell::new(Vec::<CheckOutcome>::new());
    let warned = std::cell::RefCell::new(BTreeSet::<(Feature, ArtifactId)>::new());
    let battery = battery_inner(probe, substrate, candidate, control, &outcomes, &warned);
    if tokio::time::timeout(opts.battery_budget, battery)
        .await
        .is_err()
    {
        return Err(ConformanceError::BatteryBudgetExceeded {
            budget: opts.battery_budget,
            completed: outcomes.borrow().iter().map(|o| o.id).collect(),
        });
    }

    let mut outcomes = outcomes.into_inner();
    let warned = warned.into_inner();
    apply_warning_lifecycle(&mut outcomes, &warned, candidate, &opts.expected_warnings);
    // The roster is complete BY CONSTRUCTION here, not by a fill tail: `battery_inner` judges every
    // `Feature::ALL` variant and `apply_warning_lifecycle` always pushes its own id, and
    // `battery_check_ids` is composed from that same `Feature::ALL` — so no path returns `Ok` with a
    // short roster. A `fill_unrecorded` tail stood here claiming a red-on-inverse it could not have
    // (docs/90): deleting it changed nothing, because nothing ever reached it. The property is real
    // and is gated where it actually lives —
    // `the_battery_reports_its_whole_roster_whatever_is_declared`, red on a `battery_inner` arm that
    // skips a feature instead of judging it.
    Ok(ValidationReport { outcomes })
}

/// The battery proper: one paired check per feature, recording into `outcomes` as it goes so the
/// budget's typed error can name what completed.
async fn battery_inner<P: FeatureProbe>(
    probe: &P,
    substrate: &Substrate,
    candidate: &ConformanceSubject,
    control: &ConformanceSubject,
    outcomes: &std::cell::RefCell<Vec<CheckOutcome>>,
    warned: &std::cell::RefCell<BTreeSet<(Feature, ArtifactId)>>,
) {
    for feature in Feature::ALL {
        let id = conformance_check_id(feature);
        let declared = candidate.stance(feature);
        let substrate_removal = substrate.removal(feature);

        // A probe runs only for a feature the artifact actually spoke about, and the CONTROL probe
        // runs only where an absence must be measured — that is where the cost lives and where the
        // pairing is load-bearing. `NotRun` is the honest placeholder everywhere else; it never
        // reads as either answer.
        let measurable = declared.is_some() && substrate_removal.is_none();
        let candidate_outcome = if measurable {
            probe.probe(feature, candidate).await
        } else {
            ProbeOutcome::NotRun("the claim was not measurable on this substrate".to_string())
        };
        let control_outcome = if measurable && declared == Some(false) {
            // THE POSITIVE CONTROL for the absence probe above. Deleting this call — or feeding
            // the candidate's own outcome in as the control — makes every absence verdict a bare
            // probe result again, and both
            // `four_leg_verified_absence_is_a_pass_because_the_control_works` and
            // `an_absence_whose_control_fails_is_unverified_never_a_pass` redden (verified by
            // running exactly those two deletions).
            probe.probe(feature, control).await
        } else {
            ProbeOutcome::NotRun("no absence to control for".to_string())
        };

        let status = judge(&PairedObservation {
            feature,
            artifact: &candidate.id,
            declared,
            substrate: substrate_removal,
            candidate: &candidate_outcome,
            control: &control_outcome,
            control_id: &control.id,
        });
        if matches!(status, CheckStatus::Warn(_)) {
            warned.borrow_mut().insert((feature, candidate.id.clone()));
        }
        outcomes
            .borrow_mut()
            .push(CheckOutcome::judged(id, Level::Full, status));
    }
}

/// The note a promoted warning carries — why an under-claim that nobody dispositioned is a failure
/// even though under-claiming itself is not.
fn promote_unexpected_warning(feature: Feature, artifact: &ArtifactId, warning: &str) -> String {
    format!(
        "{warning}\n  triage: this under-claim is NOT in `expected_warnings`, so it is promoted to \
         a failure. A new under-claim is either a declaration to fix or a fact to disposition — \
         add ({}, \"{artifact}\") to `expected_warnings` once it is the latter, and the run goes \
         back to a warning.",
        feature.name()
    )
}

/// Both directions of the expected-warning lifecycle (see
/// [`ConformanceOptions::expected_warnings`]).
///
/// Kept separate from the battery so it is a pure, KVM-free function over a report: the two
/// directions are one law, and the second one (a stale expectation) is the half that every
/// warning-suppression mechanism in the industry forgets.
fn apply_warning_lifecycle(
    outcomes: &mut Vec<CheckOutcome>,
    warned: &BTreeSet<(Feature, ArtifactId)>,
    candidate: &ConformanceSubject,
    expected: &BTreeSet<(Feature, ArtifactId)>,
) {
    for feature in Feature::ALL {
        let key = (feature, candidate.id.clone());
        if warned.contains(&key) && !expected.contains(&key) {
            let id = conformance_check_id(feature);
            for outcome in outcomes.iter_mut().filter(|o| o.id == id) {
                if let CheckStatus::Warn(warning) = &outcome.status {
                    outcome.status = CheckStatus::Fail(promote_unexpected_warning(
                        feature,
                        &candidate.id,
                        warning,
                    ));
                }
            }
        }
    }

    // The other direction. Only this run's artifact is judged: an expectation naming a different
    // artifact was not tested here, and calling it stale would make every per-artifact run redden
    // on its siblings' entries.
    let stale: Vec<String> = expected
        .iter()
        .filter(|(feature, artifact)| {
            *artifact == candidate.id && !warned.contains(&(*feature, artifact.clone()))
        })
        .map(|(feature, artifact)| format!("({}, \"{artifact}\")", feature.name()))
        .collect();
    let status = if stale.is_empty() {
        CheckStatus::Pass
    } else {
        CheckStatus::Fail(format!(
            "{} expected warning(s) did not fire for artifact \"{}\": [{}]. An expectation that \
             outlives its reason is the same rot as a stale `#[expect]` suppression: the artifact \
             may have been fixed (delete the entry) or the probe may have stopped measuring \
             (fix the probe) — either way it must not sit there certifying nothing.",
            stale.len(),
            candidate.id,
            stale.join(", ")
        ))
    };
    outcomes.push(CheckOutcome::judged(
        EXPECTED_WARNINGS_CHECK_ID,
        Level::Full,
        status,
    ));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::HashMap;
    use vmcell::feature::Source;

    /// A probe scripted per `(feature, artifact label)` — the seam that makes the entire four-leg
    /// matrix runnable on a machine with no KVM, no artifacts and no backend binary.
    ///
    /// It also *records* every call, which is what lets the tests assert the two structural
    /// properties a recording-free fake could not: that the positive control is really probed on
    /// the absence path (delete that call and `four_leg_*` reddens), and that the pre-flight
    /// refusals happen before anything boots (zero calls).
    #[derive(Default)]
    struct ScriptedProbe {
        answers: HashMap<(Feature, String), ProbeOutcome>,
        calls: RefCell<Vec<(Feature, String)>>,
        /// When set, the probe never returns — the wedged-check case the battery budget exists for.
        stall: bool,
    }

    impl ScriptedProbe {
        fn with(answers: &[(Feature, &str, ProbeOutcome)]) -> Self {
            ScriptedProbe {
                answers: answers
                    .iter()
                    .map(|(f, id, o)| ((*f, (*id).to_string()), o.clone()))
                    .collect(),
                ..ScriptedProbe::default()
            }
        }
        fn stalling() -> Self {
            ScriptedProbe {
                stall: true,
                ..ScriptedProbe::default()
            }
        }
        fn calls(&self) -> Vec<(Feature, String)> {
            self.calls.borrow().clone()
        }
    }

    impl FeatureProbe for ScriptedProbe {
        async fn probe(&self, feature: Feature, subject: &ConformanceSubject) -> ProbeOutcome {
            let key = (feature, subject.id.to_string());
            // The borrow ends before any await: a `RefCell` guard held across a suspension point is
            // a panic waiting for the first concurrent poll.
            self.calls.borrow_mut().push(key.clone());
            if self.stall {
                // A check that never answers — not one that answers slowly. Only the battery-wide
                // budget can end this run, which is the property under test.
                let () = std::future::pending().await;
            }
            self.answers.get(&key).cloned().unwrap_or_else(|| {
                ProbeOutcome::DoesNotWork(format!("scripted: no answer for {key:?}"))
            })
        }
    }

    /// The M8 gate's probe: the **real** [`LiveProbe`] for the candidate, a scripted `Works` for the
    /// positive control.
    ///
    /// Half-and-half on purpose. The candidate side must be the shipped probe, because the thing
    /// under test is how it classifies its own setup failure — the one thing [`ScriptedProbe`]
    /// cannot express, since it hands out outcomes directly. The control side must be `Works`, which
    /// no fake backend can produce (it needs a guest that hands shakes), and scripting it is
    /// faithful to the case that matters: a healthy control beside a candidate that cannot boot is
    /// exactly the run M8 turned green.
    struct RealCandidateWorkingControl<'a, V: Vmm> {
        live: LiveProbe<'a, V>,
        candidate: String,
    }

    impl<V: Vmm> FeatureProbe for RealCandidateWorkingControl<'_, V> {
        async fn probe(&self, feature: Feature, subject: &ConformanceSubject) -> ProbeOutcome {
            if subject.id.as_str() == self.candidate {
                self.live.probe(feature, subject).await
            } else {
                ProbeOutcome::Works
            }
        }
    }

    fn subject(label: &str, stances: &[(Feature, bool)]) -> ConformanceSubject {
        let mut declaration = FeatureDeclaration::baseline(Source::Rootfs(label.to_string()));
        for (feature, stance) in stances {
            declaration.stances.insert(*feature, *stance);
        }
        ConformanceSubject {
            id: ArtifactId::new(label),
            artifacts: ArtifactSet::new("/nonexistent/vmlinux", "/nonexistent/rootfs.erofs"),
            declaration,
        }
    }

    /// A substrate that can do everything the fake backend advertises, with the host axis stated
    /// (never probed): a test whose verdict depended on `/sys/module/kvm_intel/parameters/nested`
    /// would pass or fail by machine.
    fn capable_substrate() -> Substrate {
        let caps = vmcell::vmm::Vmm::capabilities(&vmcell::vmm::FakeVmm::default());
        Substrate::new("fake", &caps, Some(&HostDeclaration { nested_virt: true }))
    }

    /// The same substrate with one capability taken away — the "incapable backend" leg. Derived by
    /// mutating the descriptor rather than by writing a fresh literal, so a new `VmmCapabilities`
    /// field cannot silently change what this test means.
    fn substrate_without(feature: Feature) -> Substrate {
        let mut caps = vmcell::vmm::Vmm::capabilities(&vmcell::vmm::FakeVmm::default());
        match feature {
            Feature::SnapshotRestore => caps.snapshot_restore = false,
            other => panic!("this helper only removes SnapshotRestore, not {other}"),
        }
        Substrate::new("fake", &caps, Some(&HostDeclaration { nested_virt: true }))
    }

    fn status_of<'a>(report: &'a ValidationReport, id: &str) -> &'a CheckStatus {
        &report
            .outcomes
            .iter()
            .find(|o| o.id == id)
            .unwrap_or_else(|| panic!("the report must carry {id}: {:?}", report.outcomes))
            .status
    }

    /// The battery, with the candidate declaring `snapshot_restore` (present or absent) and the
    /// control always declaring it — the shape all four legs share.
    async fn run_leg(
        substrate: &Substrate,
        candidate_stance: bool,
        answers: &[(Feature, &str, ProbeOutcome)],
        opts: &ConformanceOptions,
    ) -> (
        Result<ValidationReport, ConformanceError>,
        Vec<(Feature, String)>,
    ) {
        let probe = ScriptedProbe::with(answers);
        let candidate = subject(
            "under-test",
            &[(Feature::SnapshotRestore, candidate_stance)],
        );
        let control = subject("known-good", &[(Feature::SnapshotRestore, true)]);
        let report = run_battery(&probe, substrate, &candidate, &control, opts).await;
        (report, probe.calls())
    }

    // ── The check-id vocabulary ───────────────────────────────────────────────────────────────

    // F6 held up in this crate: a check id is composed from `Feature::name()`, so the id vocabulary
    // cannot drift from the feature vocabulary and a consumer filtering by id can compute the id
    // from the feature. RED on the inverse: hand-spell one id (`"conformance.snapshots"`) and this
    // reddens naming it.
    #[test]
    fn check_ids_are_composed_from_the_feature_name() {
        for feature in Feature::ALL {
            assert_eq!(
                conformance_check_id(feature),
                format!("conformance.{}", feature.name()),
                "the paired check id for {feature} must be composed from its feature name"
            );
        }
        let roster = battery_check_ids();
        let unique: BTreeSet<&&str> = roster.iter().collect();
        assert_eq!(unique.len(), roster.len(), "ids must be unique: {roster:?}");
        assert_eq!(roster.len(), Feature::ALL.len() + 1, "{roster:?}");
        assert!(roster.contains(&EXPECTED_WARNINGS_CHECK_ID));
    }

    // ── The four legs (design §10.6's acceptance shape), each through `run_battery` ────────────

    // LEG 1: the declaring artifact on a capable backend, and it works → Pass.
    #[tokio::test]
    async fn four_leg_declared_and_working_is_a_pass() {
        let (report, calls) = run_leg(
            &capable_substrate(),
            true,
            &[(Feature::SnapshotRestore, "under-test", ProbeOutcome::Works)],
            &ConformanceOptions::default(),
        )
        .await;
        let report = report.expect("the battery runs");
        assert_eq!(
            status_of(&report, "conformance.snapshot_restore"),
            &CheckStatus::Pass
        );
        assert!(
            report.is_ok(),
            "{:?}",
            report.failures().collect::<Vec<_>>()
        );
        // The present direction needs no control boot: the claim is measured directly, and a
        // battery that booted twice per check would double the cost of the cheap half.
        assert_eq!(
            calls,
            vec![(Feature::SnapshotRestore, "under-test".to_string())],
            "only the candidate is probed when the claim is a presence claim"
        );
    }

    // LEG 2: the declaring artifact on an INCAPABLE backend → Fail naming the backend (§7.4
    // provenance). Not a skip: nothing is undecided, the backend's own descriptor says it cannot,
    // so the artifact's claim cannot hold on this cell — and the reader is told who says so.
    #[tokio::test]
    async fn four_leg_declared_on_an_incapable_backend_fails_naming_the_backend() {
        let (report, calls) = run_leg(
            &substrate_without(Feature::SnapshotRestore),
            true,
            &[(Feature::SnapshotRestore, "under-test", ProbeOutcome::Works)],
            &ConformanceOptions::default(),
        )
        .await;
        let report = report.expect("the battery runs");
        let CheckStatus::Fail(msg) = status_of(&report, "conformance.snapshot_restore") else {
            panic!(
                "a declared feature the substrate cannot provide is a failure, got {:?}",
                status_of(&report, "conformance.snapshot_restore")
            );
        };
        assert!(
            msg.contains(Feature::SnapshotRestore.name()),
            "the feature name is composed from the vocabulary, never hand-spelled: {msg}"
        );
        assert!(
            msg.contains("backend \"fake\""),
            "§7.4 provenance: the message must name WHO removed the feature: {msg}"
        );
        assert!(!report.is_ok(), "a broken claim fails the run");
        assert!(
            calls.is_empty(),
            "no VM is booted for a claim the substrate already answers: {calls:?}"
        );
    }

    // LEG 3: a non-declaring artifact that genuinely cannot → Pass (a VERIFIED absence), and the
    // positive control is what makes it one. THE DELETE-THE-CONTROL GATE: remove the control probe
    // in `battery_inner` (or pass the candidate's own outcome as the control) and this test goes
    // red, because the control's `Works` is the only thing separating "measured absent" from "the
    // probe always says absent".
    #[tokio::test]
    async fn four_leg_verified_absence_is_a_pass_because_the_control_works() {
        let (report, calls) = run_leg(
            &capable_substrate(),
            false,
            &[
                (
                    Feature::SnapshotRestore,
                    "under-test",
                    ProbeOutcome::DoesNotWork("the restored guest never came back".into()),
                ),
                (Feature::SnapshotRestore, "known-good", ProbeOutcome::Works),
            ],
            &ConformanceOptions::default(),
        )
        .await;
        let report = report.expect("the battery runs");
        assert_eq!(
            status_of(&report, "conformance.snapshot_restore"),
            &CheckStatus::Pass,
            "an absence the probe measured, with a working control, is a verified absence"
        );
        assert!(report.is_ok());
        assert_eq!(
            calls,
            vec![
                (Feature::SnapshotRestore, "under-test".to_string()),
                (Feature::SnapshotRestore, "known-good".to_string()),
            ],
            "the absence path must probe the artifact AND its positive control"
        );
    }

    // LEG 4: a non-declaring artifact that in fact CAN → Warn. This leg is the control for leg 3:
    // a probe that answered "absent" unconditionally would make leg 3 pass and this one pass too,
    // and the battery would certify anything. Dispositioned here, so the run stays green.
    #[tokio::test]
    async fn four_leg_underclaim_is_a_warning_not_a_failure() {
        let opts = ConformanceOptions {
            expected_warnings: [(Feature::SnapshotRestore, ArtifactId::new("under-test"))]
                .into_iter()
                .collect(),
            ..ConformanceOptions::default()
        };
        let (report, _) = run_leg(
            &capable_substrate(),
            false,
            &[
                (Feature::SnapshotRestore, "under-test", ProbeOutcome::Works),
                (Feature::SnapshotRestore, "known-good", ProbeOutcome::Works),
            ],
            &opts,
        )
        .await;
        let report = report.expect("the battery runs");
        let CheckStatus::Warn(msg) = status_of(&report, "conformance.snapshot_restore") else {
            panic!(
                "a declared-absent feature that works is an under-claim, got {:?}",
                status_of(&report, "conformance.snapshot_restore")
            );
        };
        assert!(msg.contains(Feature::SnapshotRestore.name()), "{msg}");
        assert!(
            msg.contains("known-good"),
            "the warning must name the positive control that makes it a measurement: {msg}"
        );
        assert!(
            report.is_ok() && report.warnings().count() == 1,
            "an under-claim is a documentation defect, not a failed run: {:?}",
            report.outcomes
        );
    }

    // The fifth row, and the reason the pair is one check: with a control that could NOT
    // demonstrate the feature, "the artifact could not either" is not evidence of anything. It must
    // be Unverified — never the Pass leg 3 earns.
    #[tokio::test]
    async fn an_absence_whose_control_fails_is_unverified_never_a_pass() {
        let (report, _) = run_leg(
            &capable_substrate(),
            false,
            &[
                (
                    Feature::SnapshotRestore,
                    "under-test",
                    ProbeOutcome::DoesNotWork("no snapshot".into()),
                ),
                (
                    Feature::SnapshotRestore,
                    "known-good",
                    ProbeOutcome::DoesNotWork("the host is out of disk".into()),
                ),
            ],
            &ConformanceOptions::default(),
        )
        .await;
        let report = report.expect("the battery runs");
        let CheckStatus::Unverified(msg) = status_of(&report, "conformance.snapshot_restore")
        else {
            panic!(
                "an absence with a broken control is undecided, got {:?}",
                status_of(&report, "conformance.snapshot_restore")
            );
        };
        assert!(
            msg.contains("known-good") && msg.contains("out of disk"),
            "the message must name the control and why it could not decide: {msg}"
        );
        assert_eq!(report.unverified().count(), 1);
        assert!(
            report.is_ok(),
            "an undecidable absence is not a failure — but it is not a pass either"
        );
        assert_eq!(
            report
                .outcomes
                .iter()
                .filter(|o| matches!(o.status, CheckStatus::Pass))
                .filter(|o| o.id == "conformance.snapshot_restore")
                .count(),
            0
        );
    }

    // A declaration nobody made is not a claim, so it is a Skip with its reason — the shipped
    // state, whose meaning the two new ones must not absorb (§10.6).
    #[test]
    fn no_stance_is_a_skip_not_a_pass() {
        let artifact = ArtifactId::new("under-test");
        let control = ArtifactId::new("known-good");
        let status = judge(&PairedObservation {
            feature: Feature::XattrPreserved,
            artifact: &artifact,
            declared: None,
            substrate: None,
            candidate: &ProbeOutcome::Works,
            control: &ProbeOutcome::Works,
            control_id: &control,
        });
        let CheckStatus::Skip(reason) = status else {
            panic!("no declaration means nothing to judge, got {status:?}");
        };
        assert!(reason.contains(Feature::XattrPreserved.name()), "{reason}");
    }

    // ── The roster ────────────────────────────────────────────────────────────────────────────

    // The whole roster on every path that produces a report: whatever the artifacts declare, and
    // whatever the substrate can do, a consumer diffing against a baseline sees states change, never
    // checks appear and vanish.
    //
    // The battery gets this BY CONSTRUCTION — `battery_inner` judges every `Feature::ALL` variant,
    // and `battery_check_ids` is composed from the same array — so the property lives in the loop,
    // not in a fill tail. (A `fill_unrecorded` tail used to sit at the end of `run_battery` with a
    // red-on-inverse claim it could not have: nothing ever reached it, so deleting it changed
    // nothing. docs/90.) RED on the inverse, verified here: make `battery_inner` `continue` on the
    // arm it does not probe — the shape a "skip the cheap ones" edit takes — and the ids it stops
    // judging vanish from the report.
    #[tokio::test]
    async fn the_battery_reports_its_whole_roster_whatever_is_declared() {
        // Two paths, because they are the two ways an arm reaches no probe at all: nothing declared,
        // and declared on a substrate that cannot exercise it (the `Skip` arm).
        let no_stance = subject("under-test", &[]);
        let declared = subject("under-test", &[(Feature::SnapshotRestore, true)]);
        let control = subject("known-good", &[(Feature::SnapshotRestore, true)]);
        for (candidate, substrate, path) in [
            (&no_stance, capable_substrate(), "nothing declared"),
            (
                &declared,
                substrate_without(Feature::SnapshotRestore),
                "declared on an incapable substrate",
            ),
        ] {
            let probe = ScriptedProbe::with(&[]);
            let report = run_battery(
                &probe,
                &substrate,
                candidate,
                &control,
                &ConformanceOptions::default(),
            )
            .await
            .expect("the battery runs");

            let ids: Vec<&str> = report.outcomes.iter().map(|o| o.id).collect();
            assert_eq!(ids, battery_check_ids(), "{path}: {ids:?}");
            assert!(
                probe.calls().is_empty(),
                "{path} costs no boots: {:?}",
                probe.calls()
            );
        }
    }

    // ── The battery budget (design §17's gap, closed) ─────────────────────────────────────────

    // A wedged check trips the BATTERY-WIDE budget as a typed error naming it — the property the
    // per-check deadlines cannot provide ("fails loudly per check, hangs per battery"). The outer
    // `timeout` is this test's own harness bound: if the budget ever stops binding, this fails in
    // five seconds instead of wedging the suite forever.
    //
    // Real time, deliberately: `start_paused` would auto-advance the clock past the budget and
    // prove nothing about wall-clock behavior.
    #[tokio::test]
    async fn a_wedged_check_trips_the_battery_budget_typed_and_never_hangs() {
        let probe = ScriptedProbe::stalling();
        let candidate = subject("under-test", &[(Feature::SnapshotRestore, true)]);
        let control = subject("known-good", &[(Feature::SnapshotRestore, true)]);
        let opts = ConformanceOptions {
            battery_budget: Duration::from_millis(50),
            ..ConformanceOptions::default()
        };
        let outcome = tokio::time::timeout(
            Duration::from_secs(5),
            run_battery(&probe, &capable_substrate(), &candidate, &control, &opts),
        )
        .await
        .expect("the battery must return on its own budget, not on this harness timeout");

        let Err(ConformanceError::BatteryBudgetExceeded { budget, completed }) = outcome else {
            panic!("a wedged probe must trip the budget, got {outcome:?}");
        };
        assert_eq!(budget, Duration::from_millis(50));
        // `snapshot_restore` is the first feature in the vocabulary and the one that wedged, so
        // nothing completed. The field exists so the error says WHERE it hung.
        assert!(
            completed.is_empty(),
            "the wedge is on the first check: {completed:?}"
        );
        let rendered = ConformanceError::BatteryBudgetExceeded { budget, completed }.to_string();
        assert!(
            rendered.contains("battery_budget") && rendered.contains("0s"),
            "the typed error names the budget it exceeded: {rendered}"
        );
    }

    // ── The expected-warning lifecycle, in BOTH directions ────────────────────────────────────

    // Direction one: a NEW under-claim nobody triaged is promoted to a failure. Without this a
    // warning is advisory forever and the kit's second direction is decoration.
    #[tokio::test]
    async fn an_untriaged_underclaim_is_promoted_to_a_failure() {
        let (report, _) = run_leg(
            &capable_substrate(),
            false,
            &[
                (Feature::SnapshotRestore, "under-test", ProbeOutcome::Works),
                (Feature::SnapshotRestore, "known-good", ProbeOutcome::Works),
            ],
            &ConformanceOptions::default(),
        )
        .await;
        let report = report.expect("the battery runs");
        let CheckStatus::Fail(msg) = status_of(&report, "conformance.snapshot_restore") else {
            panic!(
                "an un-dispositioned under-claim must fail, got {:?}",
                status_of(&report, "conformance.snapshot_restore")
            );
        };
        assert!(
            msg.contains("under-claim") && msg.contains("expected_warnings"),
            "the promotion must keep the explanation AND say how to disposition it: {msg}"
        );
        assert_eq!(
            report.warnings().count(),
            0,
            "it is a failure now, not a warning"
        );
        assert!(!report.is_ok());
    }

    // Direction two: an expectation whose warning NO LONGER FIRES is itself an error — the
    // unfulfilled-`#[expect]` rule one level up. Without it, expectations accumulate until nobody
    // reads them, which is the same terminal state as not emitting warnings at all.
    #[tokio::test]
    async fn an_expectation_that_no_longer_fires_is_an_error() {
        let opts = ConformanceOptions {
            expected_warnings: [(Feature::SnapshotRestore, ArtifactId::new("under-test"))]
                .into_iter()
                .collect(),
            ..ConformanceOptions::default()
        };
        // The artifact was FIXED: it now genuinely cannot snapshot, so the under-claim is gone.
        let (report, _) = run_leg(
            &capable_substrate(),
            false,
            &[
                (
                    Feature::SnapshotRestore,
                    "under-test",
                    ProbeOutcome::DoesNotWork("the declaration is true now".into()),
                ),
                (Feature::SnapshotRestore, "known-good", ProbeOutcome::Works),
            ],
            &opts,
        )
        .await;
        let report = report.expect("the battery runs");
        assert_eq!(
            status_of(&report, "conformance.snapshot_restore"),
            &CheckStatus::Pass,
            "the artifact itself is fine — it is the stale expectation that is not"
        );
        let CheckStatus::Fail(msg) = status_of(&report, EXPECTED_WARNINGS_CHECK_ID) else {
            panic!(
                "a stale expectation is an error, got {:?}",
                status_of(&report, EXPECTED_WARNINGS_CHECK_ID)
            );
        };
        assert!(
            msg.contains(Feature::SnapshotRestore.name()) && msg.contains("under-test"),
            "the error must name the entry to delete: {msg}"
        );
        assert!(!report.is_ok());
    }

    // The positive control for BOTH directions above: an expectation that fires leaves the warning
    // a warning and the lifecycle check green — so neither assertion above is about a check that
    // can only ever fail.
    #[tokio::test]
    async fn an_expectation_that_fires_keeps_the_run_green() {
        let opts = ConformanceOptions {
            expected_warnings: [(Feature::SnapshotRestore, ArtifactId::new("under-test"))]
                .into_iter()
                .collect(),
            ..ConformanceOptions::default()
        };
        let (report, _) = run_leg(
            &capable_substrate(),
            false,
            &[
                (Feature::SnapshotRestore, "under-test", ProbeOutcome::Works),
                (Feature::SnapshotRestore, "known-good", ProbeOutcome::Works),
            ],
            &opts,
        )
        .await;
        let report = report.expect("the battery runs");
        assert_eq!(
            status_of(&report, EXPECTED_WARNINGS_CHECK_ID),
            &CheckStatus::Pass
        );
        assert_eq!(report.warnings().count(), 1);
        assert!(report.is_ok());
    }

    // Staleness is judged against THIS run's artifact only: an expectation about a sibling artifact
    // was not tested here, and calling it stale would make every per-artifact run redden on
    // entries it never had a chance to fire.
    #[tokio::test]
    async fn an_expectation_for_another_artifact_is_not_stale_here() {
        let opts = ConformanceOptions {
            expected_warnings: [(
                Feature::SnapshotRestore,
                ArtifactId::new("some-other-artifact"),
            )]
            .into_iter()
            .collect(),
            ..ConformanceOptions::default()
        };
        let (report, _) = run_leg(
            &capable_substrate(),
            true,
            &[(Feature::SnapshotRestore, "under-test", ProbeOutcome::Works)],
            &opts,
        )
        .await;
        let report = report.expect("the battery runs");
        assert_eq!(
            status_of(&report, EXPECTED_WARNINGS_CHECK_ID),
            &CheckStatus::Pass
        );
    }

    // ── The pre-flight refusals: a battery with no usable control never boots anything ────────

    #[tokio::test]
    async fn a_control_that_is_the_candidate_is_refused_before_any_boot() {
        let probe = ScriptedProbe::with(&[]);
        let candidate = subject("same", &[(Feature::SnapshotRestore, false)]);
        let control = subject("same", &[(Feature::SnapshotRestore, true)]);
        let err = run_battery(
            &probe,
            &capable_substrate(),
            &candidate,
            &control,
            &ConformanceOptions::default(),
        )
        .await
        .expect_err("an artifact cannot be its own control");
        assert!(
            matches!(err, ConformanceError::ControlIsCandidate { .. }),
            "{err:?}"
        );
        assert!(
            probe.calls().is_empty(),
            "refused before booting: {:?}",
            probe.calls()
        );
    }

    #[tokio::test]
    async fn a_control_that_does_not_declare_the_feature_is_refused_before_any_boot() {
        let probe = ScriptedProbe::with(&[]);
        let candidate = subject("under-test", &[(Feature::SnapshotRestore, false)]);
        // A control with no stance is not a control: nothing says the probe should answer "works".
        let control = subject("known-good", &[]);
        let err = run_battery(
            &probe,
            &capable_substrate(),
            &candidate,
            &control,
            &ConformanceOptions::default(),
        )
        .await
        .expect_err("an absence probe needs a control that declares the feature");
        let ConformanceError::ControlDoesNotDeclare { feature, control } = &err else {
            panic!("{err:?}");
        };
        assert_eq!(*feature, Feature::SnapshotRestore);
        assert_eq!(control.as_str(), "known-good");
        assert!(
            err.to_string().contains(Feature::SnapshotRestore.name()),
            "{err}"
        );
        assert!(
            probe.calls().is_empty(),
            "a two-hour battery must not die on its last check for a reason visible in its first \
             millisecond: {:?}",
            probe.calls()
        );
    }

    // A candidate that declares the feature PRESENT needs no control, so the same control artifact
    // is accepted — the positive control for the refusal above (it is about the absence path, not
    // about controls in general).
    #[tokio::test]
    async fn a_presence_claim_needs_no_control_declaration() {
        let probe =
            ScriptedProbe::with(&[(Feature::SnapshotRestore, "under-test", ProbeOutcome::Works)]);
        let candidate = subject("under-test", &[(Feature::SnapshotRestore, true)]);
        let control = subject("known-good", &[]);
        let report = run_battery(
            &probe,
            &capable_substrate(),
            &candidate,
            &control,
            &ConformanceOptions::default(),
        )
        .await
        .expect("a presence claim is measured directly");
        assert_eq!(
            status_of(&report, "conformance.snapshot_restore"),
            &CheckStatus::Pass
        );
    }

    // ── The probe plan, and the nested-virt lesson ────────────────────────────────────────────

    // The one feature→probe mapping. The nested-virt arm is the recorded lesson from vmcell's own
    // matrix: `kvm-ok` is NOT causal (`-cpu host` exposes VMX unconditionally), so a naive
    // `/dev/kvm` probe would report "works" for every artifact and turn every nested-virt absence
    // declaration into a Warn. RED on the inverse: map `NestedVirt` to a probe and this reddens.
    #[test]
    fn nested_virt_absence_is_undecidable_and_says_why() {
        assert_eq!(
            probe_plan(Feature::SnapshotRestore),
            ProbePlan::SnapshotRoundTrip,
            "snapshot absence IS decidable — by attempting a snapshot (§10.6)"
        );
        let ProbePlan::Undecidable(why) = probe_plan(Feature::NestedVirt) else {
            panic!("a nested-virt absence probe must be undecidable or causal, never /dev/kvm");
        };
        assert!(
            why.contains("module parameter") && why.contains("nested_virt_disabled"),
            "the reason must point at the causal signal — the guest KVM module parameter vmcell's \
             own matrix leg reads, not `/dev/kvm`: {why}"
        );
        assert!(
            why.contains("-cpu host"),
            "the reason must state WHY the obvious probe is not causal: {why}"
        );
    }

    // §18 delta 7's promotion, as a plan assertion: the applet made the question askable, so the
    // kit must stop saying it has no probe. The `NO_PROBE_YET` half is the discriminating one —
    // a variant that merely gained a name would still carry the old reason.
    //
    // RED on the inverse: re-map `XattrPreserved` onto `ProbePlan::Undecidable(NO_PROBE_YET)`.
    #[test]
    fn the_xattr_stance_is_decided_by_an_in_guest_readback() {
        assert_eq!(
            probe_plan(Feature::XattrPreserved),
            ProbePlan::XattrReadback,
            "the `xattr` applet (§4.7, §18 delta 7) put a reader in the guest, so this feature is \
             no longer undecidable — a kit that keeps saying `NO_PROBE_YET` for a question it can \
             now answer is the accepted-but-not-honored shape"
        );
        // Non-vacuity: the promotion must not have been a blanket one. A feature with genuinely no
        // probe still says so, and still says WHY.
        assert_eq!(
            probe_plan(Feature::ProcConfigGz),
            ProbePlan::Undecidable(NO_PROBE_YET),
            "promoting one feature must not promote the roster"
        );
    }

    // `LiveProbe`'s own wiring, as far as a fake can reach it: an `Undecidable` plan must produce
    // `NotRun` carrying its stated reason, and a decidable plan must actually CALL the shipped
    // check — reporting what that check answered, not a blanket verdict.
    //
    // `fail_create` is what keeps this fast: the snapshot probe fails at `MicroVm::start` in
    // milliseconds, before the 60-second steward handshake it would otherwise wait out. It is also
    // why the two answers here are both `NotRun`: a candidate that never started never exercised the
    // feature (docs/90 M8), and this arm used to report it as `DoesNotWork` — a *measured* absence,
    // which `judge` turns into a Pass for an absence declaration. The measured `DoesNotWork` and the
    // `Works` side both need a guest that hands shakes, which is the live
    // `conformance_live_underclaim_warns_with_its_positive_control` leg in `tests/smoke.rs`
    // (FAKE-BLIND AXIS, AGENTS.md rule 4); the setup/measurement split itself is source-scanned in
    // `crate::checks`.
    #[tokio::test]
    async fn the_live_probe_maps_an_undecidable_plan_and_a_setup_failure_to_notrun() {
        let vmm = vmcell::vmm::FakeVmm::with_faults(vmcell::vmm::FaultMenu {
            fail_create: true,
            ..vmcell::vmm::FaultMenu::default()
        });
        let probe = LiveProbe::new(&vmm);
        let subject = subject("under-test", &[]);

        let undecidable = probe.probe(Feature::NestedVirt, &subject).await;
        let ProbeOutcome::NotRun(why) = &undecidable else {
            panic!("an undecidable plan must not answer about the data plane: {undecidable:?}");
        };
        assert_eq!(why, NESTED_VIRT_UNDECIDABLE);

        let decidable = probe.probe(Feature::SnapshotRestore, &subject).await;
        let ProbeOutcome::NotRun(why) = &decidable else {
            panic!(
                "a backend that cannot even create a VM never exercised snapshot support, so it \
                 measured nothing: {decidable:?}"
            );
        };
        assert!(
            !why.is_empty(),
            "the undecided verdict is what the report's evidence line quotes"
        );
        assert_ne!(
            why, NESTED_VIRT_UNDECIDABLE,
            "the decidable plan must report the shipped check's own reason, not the undecidable \
             plan's — otherwise this leg would pass with the two arms swapped"
        );
    }

    // M8, END TO END, through the REAL probe: an artifact that declares an absence and cannot boot
    // at all must be `Unverified`, never the `Pass` a *verified* absence earns. The kit's own
    // four-leg matrix structurally cannot see this — `ScriptedProbe` supplies outcomes directly, so
    // the setup failure the shipped probe has to classify never happens — which is why this leg
    // drives `LiveProbe` on the candidate side, against a backend that cannot create a VM.
    //
    // RED on the inverse (verified): restore the mapping `LiveProbe` shipped with
    // (`snapshot_restore_roundtrip(...).map_err(ProbeOutcome::DoesNotWork)`) and the verdict becomes
    // `Pass` — an unbootable artifact certified as a verified absence, with the healthy control
    // keeping the run green.
    #[tokio::test]
    async fn an_unbootable_candidate_is_unverified_never_a_verified_absence() {
        let vmm = vmcell::vmm::FakeVmm::with_faults(vmcell::vmm::FaultMenu {
            fail_create: true,
            ..vmcell::vmm::FaultMenu::default()
        });
        let probe = RealCandidateWorkingControl {
            live: LiveProbe::new(&vmm),
            candidate: "under-test".to_string(),
        };
        let candidate = subject("under-test", &[(Feature::SnapshotRestore, false)]);
        let control = subject("known-good", &[(Feature::SnapshotRestore, true)]);
        let report = run_battery(
            &probe,
            &capable_substrate(),
            &candidate,
            &control,
            &ConformanceOptions::default(),
        )
        .await
        .expect("the battery runs");

        let status = status_of(&report, "conformance.snapshot_restore");
        let CheckStatus::Unverified(why) = status else {
            panic!(
                "an absence declared by an artifact that never booted is undecided, got {status:?}"
            );
        };
        assert!(
            why.contains(Feature::SnapshotRestore.name()),
            "the undecided verdict names the feature it could not decide: {why}"
        );
        assert_eq!(report.unverified().count(), 1, "{:?}", report.outcomes);
        assert!(
            report.is_ok(),
            "an undecidable absence is not a failed run — but it is not a pass either: {:?}",
            report.failures().collect::<Vec<_>>()
        );
    }

    // An undecidable feature is Unverified in BOTH directions — never a Pass, and (in the absence
    // direction) never a Warn either: blaming an artifact for a measurement this kit cannot make is
    // exactly the naive-`/dev/kvm` failure one step later. Driven with the probe answering the way
    // `LiveProbe` does for an `Undecidable` plan: `NotRun`.
    #[tokio::test]
    async fn an_undecidable_feature_is_unverified_in_both_directions() {
        for stance in [true, false] {
            let probe = ScriptedProbe::with(&[
                (
                    Feature::NestedVirt,
                    "under-test",
                    ProbeOutcome::NotRun(NESTED_VIRT_UNDECIDABLE.to_string()),
                ),
                (
                    Feature::NestedVirt,
                    "known-good",
                    ProbeOutcome::NotRun(NESTED_VIRT_UNDECIDABLE.to_string()),
                ),
            ]);
            let candidate = subject("under-test", &[(Feature::NestedVirt, stance)]);
            let control = subject("known-good", &[(Feature::NestedVirt, true)]);
            let report = run_battery(
                &probe,
                &capable_substrate(),
                &candidate,
                &control,
                &ConformanceOptions::default(),
            )
            .await
            .expect("the battery runs");
            let status = status_of(&report, "conformance.nested_virt");
            let CheckStatus::Unverified(why) = status else {
                panic!(
                    "an unmeasurable nested-virt claim (declared = {stance}) must be Unverified, \
                     got {status:?}"
                );
            };
            assert!(why.contains("-cpu host"), "{why}");
            assert!(report.is_ok(), "an undecided claim is not a failed run");
        }
    }
}
