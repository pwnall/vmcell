//! The orphan sweeps — the start-up pass and the **periodic** one (design §11.4, The VM registry and
//! the start-up sweep; §17, Open gaps and future capabilities: "A fully-automatic periodic orphan
//! sweeper").
//!
//! The daemon **owns** its VMs and releases their resources on `Drop`/`shutdown` — but a hard-killed
//! daemon (SIGKILL, power loss) never runs those, leaking netns/cgroup/scratch keyed by the dead VMs'
//! vmids — and, for a crashed segment host, segids. On the next boot, before it creates any VM, the
//! daemon reclaims that residue by driving `vmcell`'s `sweep_orphans` with **both** live sets empty
//! (nothing is live yet in *this* process), so every orphan whose trailing id is not currently owned —
//! in its own id space (vmids for `-net-`/`-vm-`, segids for `-seg-`, §6.5, VM-to-VM segments) — is
//! deleted. This is the crash-recovery counterpart to owning-and-Drop, not a replacement for it.
//!
//! **The empty live sets are no longer the whole argument.** §11.4 used to reason "nothing is live
//! at start-up, so the empty set can never sweep a resource in use" — false on a host running a
//! second process with the same `resource_prefix`, whose live set this one cannot see and whose
//! running VMs were therefore reaped (recorded: a live `vmcell-net-207`, and a `vmcell-seg-1`
//! deleted under its members). What closes that is the *other* half of the sweep's liveness test:
//! `sweep_orphans` asks the cross-process id-claim registry the shared allocators write
//! (`vmcell::orchestrator::IdClaim`) about every candidate the live sets do not cover, and removes
//! only ids no live process claims — retaining, never reaping, when the registry cannot be read.
//! The prefix isolation §11.4 relies on (`F2`) stays the coarse guarantee; this is the fine one,
//! and it holds *within* a shared prefix.
//!
//! # The periodic pass, and the two things that make it safe
//!
//! A start-up sweep only reclaims what a *previous* daemon left; residue produced while this daemon
//! runs — a VMM killed by the OOM killer, a `create` that failed between resource creation and the
//! registry insert — survives until the next restart. The periodic pass ([`PeriodicSweeper`]) closes
//! that, and it is exactly where a liveness-blind reap would do damage: at start-up nothing of ours
//! is live, while a periodic pass runs against a table full of running VMs.
//!
//! Two protections, deliberately independent, because the first one has a hole the second covers:
//!
//! 1. **The live set** ([`LiveIds::vmids`]), read from the registry immediately before each pass. It
//!    is authoritative for every VM the table holds — and structurally blind to a VM that is
//!    *being launched right now*, whose resources exist but whose slot is not inserted yet (§11.3,
//!    The artifact store, records the same window on the artifact side).
//! 2. **The in-flight deferral** ([`LiveIds::launches_in_flight`]): a pass that starts while any
//!    launch is in flight is **skipped entirely** and logged, rather than run against a live set it
//!    knows to be incomplete. Skipping costs one cadence of retained residue; the alternative
//!    reaps a booting VM's netns.
//!
//! The cross-process id-claim registry sits under both, but only for a **claim-registered**
//! allocator: `vmcell` records at [`vmcell::orchestrator::IdClaim`] that a *hermetic* allocator
//! registers nowhere and so is protected by nothing. The daemon's launcher builds
//! `vmcell::HostEnv::shared()` for exactly this reason, and
//! `the_daemon_launcher_uses_the_claim_registered_allocator` is the call-site gate that keeps it
//! true.

use crate::error::DaemonError;
use async_trait::async_trait;
use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;
use vmcell::metrics::CgroupFs;
use vmcell::net::tap::Netlink;
use vmcell::orchestrator::OrphanScanner;

/// What a sweep pass reclaimed, for logging.
pub type SweepReport = vmcell::orchestrator::SweepReport;

/// The default periodic cadence: one pass every five minutes.
///
/// Orphan residue is a *leak*, never a correctness fault — the resources it holds are a netns, a
/// cgroup slice and a scratch dir per dead VM — so the cadence is chosen to keep the standing leak
/// bounded without putting a privileged `readdir` of three trees on a tight loop.
pub const DEFAULT_SWEEP_INTERVAL: Duration = Duration::from_secs(300);

/// The floor a configured cadence may not go below.
///
/// A pass walks `/var/run/netns`, the cgroup tree and the scratch base, and every candidate it does
/// not reclaim costs a claim-registry `stat`. Below this the sweep would spend more of the host than
/// the residue it reclaims — and, more importantly, a sub-second cadence turns the in-flight
/// deferral into a busy loop of skipped passes. A smaller value is **refused at construction**,
/// never silently rounded up (AGENTS.md: every accepted input is honored or rejected).
pub const MIN_SWEEP_INTERVAL: Duration = Duration::from_secs(30);

/// How often the periodic orphan sweeper runs, or that it is off.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SweepSchedule {
    /// No periodic pass; only the start-up sweep runs.
    Disabled,
    /// One pass every interval (at least [`MIN_SWEEP_INTERVAL`]).
    Every(Duration),
}

impl SweepSchedule {
    /// Parses an operator-supplied cadence in seconds: `0` means **explicitly off**, anything at or
    /// above [`MIN_SWEEP_INTERVAL`] is the cadence, and anything between is refused.
    ///
    /// The three arms are deliberately distinct: "off" is a choice an operator can state, but a
    /// cadence *below* the floor is a value the daemon cannot honor as written, so it is a start-up
    /// error rather than a quiet promotion to the floor (a promoted value makes the daemon's
    /// behavior disagree with its own command line).
    ///
    /// # Errors
    /// [`DaemonError::BadRequest`] for a non-zero value below [`MIN_SWEEP_INTERVAL`], naming the
    /// floor and the way to turn the sweeper off.
    pub fn from_secs(secs: u64) -> Result<Self, DaemonError> {
        if secs == 0 {
            return Ok(Self::Disabled);
        }
        let want = Duration::from_secs(secs);
        if want < MIN_SWEEP_INTERVAL {
            return Err(DaemonError::BadRequest(format!(
                "periodic sweep interval {secs}s is below the {}s floor; pass 0 to disable the \
                 periodic sweeper explicitly",
                MIN_SWEEP_INTERVAL.as_secs()
            )));
        }
        Ok(Self::Every(want))
    }

    /// The configured cadence, or `None` when the sweeper is off.
    #[must_use]
    pub const fn interval(self) -> Option<Duration> {
        match self {
            Self::Disabled => None,
            Self::Every(d) => Some(d),
        }
    }
}

/// What this process knows to be live when a sweep pass starts.
///
/// Both id spaces are carried even though the daemon creates no segments (`segids` is always empty
/// for it): the sweep checks the two classes against **different** id spaces, and a struct that
/// carried only vmids would invite a future segment-owning caller to pass them into the wrong one.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LiveIds {
    /// The vmids of every VM the registry currently holds.
    pub vmids: BTreeSet<u32>,
    /// The segids this process owns (empty for the daemon, which creates no segments — §6.5,
    /// VM-to-VM segments; the cross-process claim registry is what protects another process's).
    pub segids: BTreeSet<u32>,
    /// How many VM launches are in flight — resources that exist (or are about to) under ids the
    /// table above does **not** yet list. Non-zero defers the whole pass.
    pub launches_in_flight: usize,
}

/// Where a sweep pass reads the live-id snapshot from — the registry in production, a fixed value in
/// the unit gates.
#[async_trait]
pub trait LiveIdSource: Send + Sync {
    /// The live ids and in-flight launch count, sampled as one snapshot.
    ///
    /// One call, not three getters: the pass must not see a vmid set from before an insert together
    /// with an in-flight count from after it.
    async fn live_ids(&self) -> LiveIds;
}

/// The result of one pass: what it reclaimed, or why it did not run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SweepOutcome {
    /// The pass was skipped because a launch was in flight (see the module docs).
    Deferred {
        /// How many launches were in flight when the pass started.
        launches_in_flight: usize,
    },
    /// The pass ran; the report names what it removed and what it declined to remove.
    Swept(SweepReport),
}

impl SweepOutcome {
    /// The report, or `None` for a deferred pass.
    #[must_use]
    pub const fn report(&self) -> Option<&SweepReport> {
        match self {
            Self::Deferred { .. } => None,
            Self::Swept(r) => Some(r),
        }
    }
}

/// The **one** sweep law in this crate: decide whether to run, then drive `vmcell`'s
/// [`sweep_orphans`](vmcell::orchestrator::sweep_orphans) with this process's live sets.
///
/// Both the start-up pass and the periodic one go through here, so the deferral rule, the id-space
/// pairing and the seams are stated once. The seams are parameters rather than constructed inside,
/// which is what lets the gates drive a real pass — including its retention arm — with no
/// privileged host state.
pub fn sweep_pass(
    scanner: &dyn OrphanScanner,
    netlink: &dyn Netlink,
    cgroup_fs: &dyn CgroupFs,
    live: &LiveIds,
) -> SweepOutcome {
    if live.launches_in_flight > 0 {
        return SweepOutcome::Deferred {
            launches_in_flight: live.launches_in_flight,
        };
    }
    SweepOutcome::Swept(vmcell::orchestrator::sweep_orphans(
        scanner,
        netlink,
        cgroup_fs,
        &live.vmids,
        &live.segids,
    ))
}

/// The **one** renderer for a pass's outcome, shared by the start-up and periodic passes so a
/// retention is as visible in one as in the other.
///
/// Retentions are logged at `warn` and reclamations at `info`: a retention means this host is
/// carrying residue the sweep deliberately declined to touch (a live sibling, or a claim registry it
/// could not read), which is the line an operator needs to see; reclaiming is the sweep working.
pub fn log_sweep_outcome(pass: &str, outcome: &SweepOutcome) {
    match outcome {
        SweepOutcome::Deferred { launches_in_flight } => {
            tracing::info!(
                pass,
                launches_in_flight,
                "vmcelld: orphan sweep deferred — a VM launch is in flight, so the live-vmid set is \
                 incomplete; the next pass will run"
            );
        }
        SweepOutcome::Swept(report) => {
            if !report.netns.is_empty()
                || !report.segment_netns.is_empty()
                || !report.cgroup_slices.is_empty()
                || !report.scratch_dirs.is_empty()
                || !report.member_taps.is_empty()
            {
                tracing::info!(
                    pass,
                    netns = report.netns.len(),
                    segment_netns = report.segment_netns.len(),
                    cgroup_slices = report.cgroup_slices.len(),
                    scratch_dirs = report.scratch_dirs.len(),
                    member_taps = report.member_taps.len(),
                    "vmcelld: orphan sweep reclaimed leaked resources"
                );
            }
            if !report.retained.is_empty() {
                tracing::warn!(
                    pass,
                    retained = report.retained.len(),
                    detail = %report.retained.join(", "),
                    "vmcelld: orphan sweep RETAINED resources whose id a live process claims (or \
                     whose claim could not be read); they are not this daemon's to reclaim"
                );
            }
        }
    }
}

/// Reclaims leaked netns / segment netns / cgroup slices / scratch dirs whose names carry
/// `resource_prefix`, from a previously-crashed daemon.
///
/// Called once at start-up with empty live-vmid **and** live-segid sets (before this daemon has any
/// VM or segment), so what it deletes is decided by the id-claim registry: a resource whose id a
/// live process still claims — another daemon, a `vmcell` CLI run, a test — is **retained**, as is
/// one whose claim cannot be read. A retained *segment* namespace still has its dead members' taps
/// reclaimed, which is what keeps a recycled vmid from meeting a stale tap the exclusive
/// `TUNSETIFF` now refuses to adopt.
///
/// The prefix MUST be the one the daemon's VMs are named with (design) or the
/// sweep matches nothing; both come from `vmcelld`'s single `--resource-prefix`. Requires the
/// privileged caps the daemon holds (netns delete needs `CAP_NET_ADMIN`). Per-resource failures are
/// logged by `sweep_orphans`, not fatal.
#[must_use]
pub fn startup_sweep(resource_prefix: &str) -> SweepReport {
    // The empty snapshot IS the start-up condition: no VM, no segment, no launch in flight. Going
    // through `sweep_pass` rather than calling `sweep_orphans` a second time is what keeps the
    // deferral rule and the id-space pairing one law (`the_sweep_law_has_one_call_site`).
    match sweep_pass(
        // `HostOrphanScanner::new` is what carries the host claim registries into the sweep: it
        // reads them from the same constants `VmidAllocator::shared`/`SegmentIdAllocator::shared`
        // claim into, so the writer and the reader cannot drift onto two directories.
        &vmcell::orchestrator::HostOrphanScanner::new(resource_prefix),
        &vmcell::net::tap::RtNetlink,
        &vmcell::metrics::DefaultCgroupFs,
        &LiveIds::default(),
    ) {
        SweepOutcome::Swept(report) => report,
        // Unreachable by construction — `LiveIds::default()` has no launch in flight — but a
        // start-up sweep that silently became a no-op is exactly the shape this file exists to
        // prevent, so say so rather than returning an empty report that reads as "nothing to do".
        outcome @ SweepOutcome::Deferred { .. } => {
            log_sweep_outcome("startup", &outcome);
            SweepReport::default()
        }
    }
}

/// One pass of the periodic sweeper, as a seam.
///
/// Production is [`HostSweepPass`], which drives the real privileged host. The seam exists because
/// the **scheduler** — when a pass runs, what live set it is handed, whether it stops — is logic in
/// its own right, and the only alternative way to exercise it would be to let a unit test sweep this
/// developer's actual `/var/run/netns`. A gate that cannot be written without destroying the host it
/// runs on is a gate nobody writes.
#[async_trait]
pub trait SweepPass: Send + Sync {
    /// Runs one pass against `live` and returns what it did.
    async fn run(&self, live: LiveIds) -> SweepOutcome;
}

/// The production [`SweepPass`]: [`sweep_pass`] against the real scanner, netlink and cgroup seams.
///
/// Each pass runs on a blocking worker (`spawn_blocking`): a pass is synchronous privileged file and
/// netlink I/O, and running it on a runtime worker would stall every in-flight request behind a
/// `readdir` of the cgroup tree.
#[derive(Debug, Clone)]
pub struct HostSweepPass {
    /// The `--resource-prefix` whose names this sweeper's passes match.
    prefix: String,
}

impl HostSweepPass {
    /// A pass over the resources named with `prefix` — which MUST be the prefix the daemon's VMs
    /// are created with, or the sweep matches nothing.
    #[must_use]
    pub fn new(prefix: impl Into<String>) -> Self {
        Self {
            prefix: prefix.into(),
        }
    }
}

#[async_trait]
impl SweepPass for HostSweepPass {
    async fn run(&self, live: LiveIds) -> SweepOutcome {
        let prefix = self.prefix.clone();
        match tokio::task::spawn_blocking(move || {
            sweep_pass(
                &vmcell::orchestrator::HostOrphanScanner::new(&prefix),
                &vmcell::net::tap::RtNetlink,
                &vmcell::metrics::DefaultCgroupFs,
                &live,
            )
        })
        .await
        {
            Ok(outcome) => outcome,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "vmcelld: a periodic orphan sweep pass did not complete; the next pass will retry"
                );
                // Not a `Swept(default)`: an empty report reads as "there was nothing to reclaim",
                // and a pass that never ran must not say that. `Deferred` is the honest shape — the
                // pass did not happen and the next one will.
                SweepOutcome::Deferred {
                    launches_in_flight: 0,
                }
            }
        }
    }
}

/// The periodic orphan sweeper: a background task running one [`SweepPass`] per cadence tick
/// against the live ids read from its [`LiveIdSource`] (design §17, Open gaps and future
/// capabilities).
///
/// **Teardown is ownership.** The handle is held by the caller and the task is aborted on `Drop`, so
/// the sweeper cannot outlive the registry it reads its live set from — a sweeper that kept ticking
/// against a dropped registry would see an empty live set and reap the VMs the registry is in the
/// middle of tearing down.
#[must_use = "the sweeper stops when this handle is dropped"]
pub struct PeriodicSweeper {
    handle: tokio::task::JoinHandle<()>,
}

impl PeriodicSweeper {
    /// Spawns the sweeper over the real host, or returns `None` when the schedule is
    /// [`SweepSchedule::Disabled`].
    ///
    /// Must be called from inside a tokio runtime.
    #[must_use]
    pub fn spawn(
        resource_prefix: impl Into<String>,
        schedule: SweepSchedule,
        live: Arc<dyn LiveIdSource>,
    ) -> Option<Self> {
        let prefix = resource_prefix.into();
        let interval = schedule.interval()?;
        tracing::info!(
            interval_secs = interval.as_secs(),
            resource_prefix = %prefix,
            "vmcelld: periodic orphan sweeper armed"
        );
        Some(Self::spawn_with(
            Arc::new(HostSweepPass::new(prefix)),
            interval,
            live,
        ))
    }

    /// The scheduler itself, over an injected pass — the shape the unit gates drive.
    fn spawn_with(
        pass: Arc<dyn SweepPass>,
        interval: Duration,
        live: Arc<dyn LiveIdSource>,
    ) -> Self {
        let handle = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            // The first tick of a tokio interval completes IMMEDIATELY; the start-up sweep has just
            // run, so this one is consumed here and the first real pass lands one full interval
            // later, rather than sweeping twice in a row at boot.
            ticker.tick().await;
            loop {
                ticker.tick().await;
                // The live set is sampled per pass, immediately before it — never once at spawn,
                // which would freeze the set as it was when the daemon had no VMs at all.
                let outcome = pass.run(live.live_ids().await).await;
                log_sweep_outcome("periodic", &outcome);
            }
        });
        Self { handle }
    }
}

impl Drop for PeriodicSweeper {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use vmcell::orchestrator::{IdClaim, IdSpace};

    /// A scanner that enumerates exactly what it was handed, and answers the claim registry from a
    /// map. `NoLiveOwner` is the default for an id nobody planted, which reproduces the
    /// registry-less shape the sweep behaves liveness-blind under.
    struct FakeScanner {
        netns: Vec<String>,
        claims: Vec<(IdSpace, u32, IdClaim)>,
    }

    impl OrphanScanner for FakeScanner {
        fn scan_netns(&self) -> Vec<String> {
            self.netns.clone()
        }
        fn scan_segment_netns(&self) -> Vec<String> {
            Vec::new()
        }
        fn scan_cgroup_slices(&self) -> Vec<String> {
            Vec::new()
        }
        fn scan_scratch_dirs(&self) -> Vec<std::path::PathBuf> {
            Vec::new()
        }
        fn id_claim(&self, space: IdSpace, id: u32) -> IdClaim {
            self.claims
                .iter()
                .find(|(s, i, _)| *s == space && *i == id)
                .map_or(IdClaim::NoLiveOwner, |(_, _, c)| *c)
        }
    }

    /// Records the netns deletions a pass performs; every other seam method is unreachable in these
    /// gates and says so rather than silently succeeding.
    #[derive(Default)]
    struct FakeNetlink {
        deleted: Mutex<Vec<String>>,
    }

    impl FakeNetlink {
        fn deleted(&self) -> Vec<String> {
            self.deleted.lock().expect("fake netlink lock").clone()
        }
    }

    impl Netlink for FakeNetlink {
        fn add_netns(&self, _name: &str) -> vmcell::Result<()> {
            unreachable!("a sweep never creates a namespace")
        }
        fn setup_tap(&self, _netns: &str, _tap: &str, _vmid: u32) -> vmcell::Result<()> {
            unreachable!("a sweep never creates a tap")
        }
        fn create_bridge(
            &self,
            _netns: &str,
            _bridge: &str,
            _gateway: std::net::Ipv4Addr,
            _prefix_len: u8,
        ) -> vmcell::Result<()> {
            unreachable!("a sweep never creates a bridge")
        }
        fn setup_tap_on_bridge(
            &self,
            _netns: &str,
            _tap: &str,
            _bridge: &str,
        ) -> vmcell::Result<()> {
            unreachable!("a sweep never creates a member tap")
        }
        fn delete_link(&self, _netns: &str, _link: &str) -> vmcell::Result<()> {
            unreachable!("no segment namespace is scanned in these gates")
        }
        fn delete_netns(&self, name: &str) -> vmcell::Result<()> {
            self.deleted
                .lock()
                .expect("fake netlink lock")
                .push(name.to_string());
            Ok(())
        }
        fn setup_tproxy_routing(&self, _netns: &str) -> vmcell::Result<()> {
            unreachable!("a sweep never programs routing")
        }
    }

    /// A cgroup backend that records nothing because these gates plant no slices — an actual
    /// deletion here would mean the scanner returned something it was not given.
    #[derive(Debug, Default)]
    struct FakeCgroupFs;

    impl CgroupFs for FakeCgroupFs {
        fn create_slice(
            &self,
            _name: &str,
            _limits: &vmcell::config::ResourceLimits,
        ) -> vmcell::Result<()> {
            unreachable!("a sweep never creates a slice")
        }
        fn delete_slice(&self, name: &str) -> vmcell::Result<()> {
            unreachable!("no cgroup slice is scanned in these gates, yet {name} was deleted")
        }
        fn read_stats(&self, _name: &str) -> vmcell::Result<vmcell::ResourceUsage> {
            unreachable!("a sweep never reads stats")
        }
        fn add_task(&self, _name: &str, _pid: u32) -> vmcell::Result<()> {
            unreachable!("a sweep never moves a task")
        }
    }

    fn scanner(netns: &[&str], claims: &[(IdSpace, u32, IdClaim)]) -> FakeScanner {
        FakeScanner {
            netns: netns.iter().map(|s| (*s).to_string()).collect(),
            claims: claims.to_vec(),
        }
    }

    // The cadence is an accepted input, so it is honored or REJECTED at construction: 0 is the
    // explicit off switch, the floor and anything above it is the cadence, and a value between is a
    // start-up error naming the floor. RED on the inverse: a `from_secs` that clamps to the floor
    // (the middle arm becomes `Ok`) or that treats 0 as "use the default" (the first arm becomes
    // `Every`).
    #[test]
    fn a_cadence_below_the_floor_is_refused_and_zero_is_the_explicit_off_switch() {
        assert_eq!(
            SweepSchedule::from_secs(0).expect("0 disables"),
            SweepSchedule::Disabled
        );
        assert_eq!(SweepSchedule::Disabled.interval(), None);

        let floor = MIN_SWEEP_INTERVAL.as_secs();
        assert_eq!(
            SweepSchedule::from_secs(floor).expect("the floor itself is accepted"),
            SweepSchedule::Every(MIN_SWEEP_INTERVAL)
        );
        assert_eq!(
            SweepSchedule::from_secs(DEFAULT_SWEEP_INTERVAL.as_secs())
                .expect("the default is accepted")
                .interval(),
            Some(DEFAULT_SWEEP_INTERVAL)
        );

        let err = SweepSchedule::from_secs(floor - 1).expect_err("below the floor is refused");
        let msg = err.message();
        assert!(
            msg.contains(&floor.to_string()) && msg.contains("disable"),
            "the refusal must name the floor and the way to turn the sweeper off: {msg}"
        );
    }

    // The in-flight deferral (module docs, protection 2). A pass that starts while a launch is in
    // flight removes NOTHING, because the live set it would run against is knowingly incomplete —
    // the booting VM's vmid is not in the table yet. The second half is the positive control: the
    // very same scanner, netlink and live set with the count at zero DOES reclaim, so the first half
    // cannot pass by the sweep being inert.
    //
    // RED on the inverse: drop the `launches_in_flight > 0` arm from `sweep_pass` and the deferred
    // leg reclaims `vmcell-net-42` — exactly the booting VM's namespace.
    #[test]
    fn a_pass_defers_while_a_launch_is_in_flight_and_sweeps_when_none_is() {
        let netlink = FakeNetlink::default();
        let live = LiveIds {
            launches_in_flight: 1,
            ..LiveIds::default()
        };
        let outcome = sweep_pass(
            &scanner(&["vmcell-net-42"], &[]),
            &netlink,
            &FakeCgroupFs,
            &live,
        );
        assert_eq!(
            outcome,
            SweepOutcome::Deferred {
                launches_in_flight: 1
            }
        );
        assert!(outcome.report().is_none(), "a deferred pass has no report");
        assert!(
            netlink.deleted().is_empty(),
            "a deferred pass must not delete anything: {:?}",
            netlink.deleted()
        );

        // Positive control: same inputs, no launch in flight.
        let netlink = FakeNetlink::default();
        let outcome = sweep_pass(
            &scanner(&["vmcell-net-42"], &[]),
            &netlink,
            &FakeCgroupFs,
            &LiveIds::default(),
        );
        assert_eq!(netlink.deleted(), vec!["vmcell-net-42".to_string()]);
        assert_eq!(
            outcome.report().expect("a run pass has a report").netns,
            vec!["vmcell-net-42".to_string()]
        );
    }

    // Protection 1: a vmid the registry holds is never reclaimed. The leg is non-vacuous because the
    // SAME scan reclaims `-43` beside it: a sweep that never ran, or a scanner that enumerated
    // nothing, fails the positive half. (The own-live-set arm deliberately records no `retained`
    // entry — `vmcell`'s `may_reclaim` reports only what the CLAIM REGISTRY held back, since the
    // caller already knows its own live ids. The retention record itself is asserted in the sibling
    // gate below, which is where it is the only available evidence.)
    //
    // RED on the inverse: pass `&BTreeSet::new()` instead of `live.vmids` into `sweep_orphans` (the
    // liveness-blind shape) and the live VM's namespace is deleted.
    #[test]
    fn a_vmid_the_registry_holds_is_retained_and_recorded_while_a_dead_one_is_reclaimed() {
        let netlink = FakeNetlink::default();
        let live = LiveIds {
            vmids: BTreeSet::from([42]),
            ..LiveIds::default()
        };
        let outcome = sweep_pass(
            &scanner(&["vmcell-net-42", "vmcell-net-43"], &[]),
            &netlink,
            &FakeCgroupFs,
            &live,
        );
        assert_eq!(netlink.deleted(), vec!["vmcell-net-43".to_string()]);
        let report = outcome.report().expect("a run pass has a report");
        assert_eq!(report.netns, vec!["vmcell-net-43".to_string()]);
        assert!(
            !report.netns.iter().any(|n| n == "vmcell-net-42"),
            "the live VM's namespace must survive the pass: {:?}",
            report.netns
        );
    }

    // The cross-process half: an id NO table in this process knows about, claimed by a live sibling,
    // is retained — and so is one whose claim could not be read. This is what makes the periodic
    // pass safe on a host sharing a `--resource-prefix`, and it proves `sweep_pass` forwards the
    // scanner it was handed rather than substituting a claim-blind one.
    //
    // RED on the inverse: have `sweep_pass` build its own `HostOrphanScanner` (or any scanner taking
    // the trait's `NoLiveOwner` default) and both namespaces are deleted.
    #[test]
    fn an_id_a_live_sibling_claims_is_retained_even_though_this_process_knows_nothing_about_it() {
        let netlink = FakeNetlink::default();
        let outcome = sweep_pass(
            &scanner(
                &["vmcell-net-7", "vmcell-net-8", "vmcell-net-9"],
                &[
                    (IdSpace::Vmid, 7, IdClaim::LiveOwner),
                    (IdSpace::Vmid, 8, IdClaim::Undeterminable),
                ],
            ),
            &netlink,
            &FakeCgroupFs,
            &LiveIds::default(),
        );
        assert_eq!(
            netlink.deleted(),
            vec!["vmcell-net-9".to_string()],
            "only the unclaimed id is reclaimed"
        );
        let retained = &outcome.report().expect("a run pass has a report").retained;
        assert!(
            retained.iter().any(|r| r.contains("vmcell-net-7"))
                && retained.iter().any(|r| r.contains("vmcell-net-8")),
            "both a live claim and an unreadable one are retained AND recorded: {retained:?}"
        );
    }

    /// A [`SweepPass`] that records the live set it was handed, and never touches a host.
    #[derive(Default)]
    struct RecordingPass {
        seen: Mutex<Vec<LiveIds>>,
    }

    #[async_trait]
    impl SweepPass for RecordingPass {
        async fn run(&self, live: LiveIds) -> SweepOutcome {
            self.seen.lock().expect("recording pass lock").push(live);
            SweepOutcome::Swept(SweepReport::default())
        }
    }

    /// A live-id source whose answer the test can change between ticks.
    struct SettableLive(Mutex<LiveIds>);

    #[async_trait]
    impl LiveIdSource for SettableLive {
        async fn live_ids(&self) -> LiveIds {
            self.0.lock().expect("settable live lock").clone()
        }
    }

    // The SCHEDULER, on a virtual clock: the cadence, the live-set sampling, and the stop-on-drop.
    // Four facts, none of which the `sweep_pass` unit gates above can see:
    //
    //   1. no pass runs before the first interval elapses — the start-up sweep has just run, and a
    //      tokio `interval`'s first tick completes IMMEDIATELY, so a loop that did not consume it
    //      would sweep twice at boot;
    //   2. a pass runs on each subsequent tick;
    //   3. the live set is re-sampled per pass, so a VM created after the sweeper armed is protected
    //      (the second pass sees vmid 5, which did not exist at spawn);
    //   4. dropping the handle stops it — teardown is ownership, and a sweeper outliving its
    //      registry would sweep against an empty live set.
    //
    // RED on the inverse: delete the pre-loop `ticker.tick().await` (fact 1 fails, one pass at t=0);
    // hoist `live.live_ids()` out of the loop (fact 3 fails, the second pass sees an empty set);
    // remove the `Drop` impl (fact 4 fails, a fourth pass lands after the drop).
    /// Lets the spawned scheduler task make progress: one `yield_now` covers a single `.await`, and
    /// a pass crosses several (the tick, the live-id read, the pass itself). Yielding a bounded
    /// number of times is deterministic on the single-threaded test runtime — no sleeping, no
    /// wall-clock, no flake.
    async fn settle() {
        for _ in 0..32 {
            tokio::task::yield_now().await;
        }
    }

    #[tokio::test(start_paused = true)]
    async fn the_scheduler_waits_a_full_interval_resamples_live_ids_and_stops_when_dropped() {
        let pass = Arc::new(RecordingPass::default());
        let live = Arc::new(SettableLive(Mutex::new(LiveIds::default())));
        let interval = Duration::from_secs(300);
        let sweeper = PeriodicSweeper::spawn_with(pass.clone(), interval, live.clone());
        // Let the task start and build its ticker at t=0, so the cadence below is measured from the
        // spawn rather than from wherever the first poll happened to land.
        settle().await;

        // Fact 1a: the interval's own immediate first tick produced NO pass.
        assert_eq!(
            pass.seen.lock().expect("lock").len(),
            0,
            "a tokio interval's first tick fires immediately; the loop must consume it"
        );

        // Fact 1b: still nothing, most of an interval in.
        tokio::time::advance(interval - Duration::from_secs(1)).await;
        settle().await;
        assert_eq!(
            pass.seen.lock().expect("lock").len(),
            0,
            "the start-up sweep already covered t=0; the first periodic pass is one interval later"
        );

        // Fact 2: the first pass lands on the first full interval.
        tokio::time::advance(Duration::from_secs(2)).await;
        settle().await;
        assert_eq!(pass.seen.lock().expect("lock").len(), 1);

        // Fact 3: a VM created AFTER the sweeper armed is in the next pass's live set.
        live.0.lock().expect("lock").vmids.insert(5);
        tokio::time::advance(interval).await;
        settle().await;
        let seen = pass.seen.lock().expect("lock").clone();
        assert_eq!(seen.len(), 2);
        assert!(
            seen.first().is_some_and(|l| l.vmids.is_empty()),
            "the first pass saw the empty registry: {seen:?}"
        );
        assert!(
            seen.get(1).is_some_and(|l| l.vmids.contains(&5)),
            "and the second saw the VM created since — the set is sampled PER PASS: {seen:?}"
        );

        // Fact 4: the task stops with its handle.
        drop(sweeper);
        tokio::time::advance(interval * 3).await;
        settle().await;
        assert_eq!(
            pass.seen.lock().expect("lock").len(),
            2,
            "a dropped sweeper runs no further passes"
        );
    }

    /// Production (non-test, non-comment) lines of this crate's sources, as `(file, line no, text)`.
    /// A zero-file scan is a **misconfigured gate**, never a green verdict.
    fn production_lines() -> Vec<(String, usize, String)> {
        production_lines_under(&std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src"))
    }

    /// The scan itself, over an arbitrary root — so the **empty-tree** leg below can drive the
    /// misconfigured-gate arm, which is the only arm a scan pointed at the real tree can never
    /// exercise.
    fn production_lines_under(src: &std::path::Path) -> Vec<(String, usize, String)> {
        let mut files = Vec::new();
        collect_rust_sources(src, &mut files);
        assert!(
            files.len() >= 8,
            "the scan found {} sources under {src:?} — it is pointed at nothing, which is a \
             misconfigured gate, not a pass",
            files.len()
        );
        let mut out = Vec::new();
        for file in files {
            let text = std::fs::read_to_string(&file)
                .unwrap_or_else(|e| panic!("read {}: {e}", file.display()));
            let label = file
                .file_name()
                .map_or_else(String::new, |n| n.to_string_lossy().to_string());
            let mut in_tests = false;
            for (i, line) in text.lines().enumerate() {
                if line.starts_with("mod tests") || line.starts_with("#[cfg(test)]") {
                    in_tests = true;
                }
                let trimmed = line.trim_start();
                if in_tests || trimmed.starts_with("//") {
                    continue;
                }
                out.push((label.clone(), i + 1, line.to_string()));
            }
        }
        out
    }

    // The zero-file arm: a scan pointed at a tree with no sources is a MISCONFIGURED GATE and must
    // fail loud, never print a green verdict over an empty corpus (AGENTS.md; eight bans in this repo
    // wore exactly that green until a review pass swept it). This is the only leg that can reach the
    // arm, because the real scan is anchored on `CARGO_MANIFEST_DIR`.
    //
    // RED on the inverse: drop the `files.len() >= 8` assertion and this returns an empty vec, which
    // would make BOTH call-site scans above pass vacuously.
    #[test]
    #[should_panic(expected = "pointed at nothing")]
    fn the_source_scan_treats_an_empty_tree_as_a_misconfigured_gate() {
        let empty = tempfile::tempdir().expect("tempdir");
        let _lines = production_lines_under(empty.path());
    }

    fn collect_rust_sources(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        let entries =
            std::fs::read_dir(dir).unwrap_or_else(|e| panic!("read {}: {e}", dir.display()));
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                collect_rust_sources(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs")
                // `bridge/*tests.rs` are `#[cfg(test)] mod` bodies in their own files, so they carry
                // no in-file `#[cfg(test)]` marker to skip on. Excluded by name, or their contents
                // would be read as production and could hide a real call site behind test text.
                && !path
                    .file_name()
                    .is_some_and(|n| n.to_string_lossy().ends_with("tests.rs"))
            {
                out.push(path);
            }
        }
    }

    // ONE LAW, ONE PREDICATE (AGENTS.md): `vmcell::orchestrator::sweep_orphans` is called from
    // exactly one production place in this crate — `sweep_pass` — so the in-flight deferral and the
    // vmid/segid pairing cannot be bypassed by a second, direct call. This is the call-site scan
    // beside the unit gates above: a green `a_pass_defers_...` standing next to a second caller that
    // never asks is precisely the shape the convention exists to catch.
    //
    // RED on the inverse: restore `startup_sweep`'s own direct `sweep_orphans(...)` call and the
    // count is 2.
    #[test]
    fn the_sweep_law_has_one_call_site() {
        let callers: Vec<(String, usize)> = production_lines()
            .into_iter()
            .filter(|(_, _, line)| line.contains("sweep_orphans("))
            .map(|(file, no, _)| (file, no))
            .collect();
        assert_eq!(
            callers.len(),
            1,
            "`sweep_orphans(` must be called from exactly one production site (sweep_pass); found \
             {callers:?}"
        );
        assert_eq!(
            callers.first().map(|(f, _)| f.as_str()),
            Some("sweep.rs"),
            "the one call site lives in sweep.rs: {callers:?}"
        );
    }

    // The claim-registry protection under both live-set protections is real only for a
    // CLAIM-REGISTERED allocator: `vmcell` records at `IdClaim` that a hermetic one registers
    // nowhere, so nothing vouches for its ids. The daemon's launcher must therefore build
    // `HostEnv::shared()`, and this is that call-site scan — the periodic sweeper's safety argument
    // reads a fact in another file, so the fact needs a gate here.
    //
    // RED on the inverse: change `MicroVmLauncher::new` to `HostEnv::hermetic()`.
    #[test]
    fn the_daemon_launcher_uses_the_claim_registered_allocator() {
        let shared: Vec<(String, usize)> = production_lines()
            .into_iter()
            .filter(|(_, _, line)| line.contains("HostEnv::"))
            .map(|(file, no, line)| {
                assert!(
                    line.contains("HostEnv::shared"),
                    "{file}:{no} builds a HostEnv that is not `shared()`; the periodic sweeper's \
                     liveness protection is absent by construction for a hermetic allocator: {line}"
                );
                (file, no)
            })
            .collect();
        assert_eq!(
            shared.len(),
            1,
            "exactly one production `HostEnv::` construction is expected (the launcher's): {shared:?}"
        );
    }
}
