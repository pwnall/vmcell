//! Start-up orphan sweep (design §11.4, The VM registry and the start-up sweep).
//!
//! The daemon **owns** its VMs and releases their resources on `Drop`/`shutdown` — but a hard-killed
//! daemon (SIGKILL, power loss) never runs those, leaking netns/cgroup/scratch keyed by the dead VMs'
//! vmids — and, for a crashed segment host, segids. On the next boot, before it creates any VM, the
//! daemon reclaims that residue by driving `vmcell`'s `sweep_orphans` with **both** live sets empty
//! (nothing is live yet in *this* process), so every orphan whose trailing id is not currently owned —
//! in its own id space (vmids for `-net-`/`-vm-`, segids for `-seg-`, §6.5) — is deleted. This is
//! the crash-recovery counterpart to owning-and-Drop, not a replacement for it.
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

/// What the start-up sweep reclaimed, for logging.
pub type SweepReport = vmcell::orchestrator::SweepReport;

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
    vmcell::orchestrator::sweep_orphans(
        // `HostOrphanScanner::new` is what carries the host claim registries into the sweep: it
        // reads them from the same constants `VmidAllocator::shared`/`SegmentIdAllocator::shared`
        // claim into, so the writer and the reader cannot drift onto two directories.
        &vmcell::orchestrator::HostOrphanScanner::new(resource_prefix),
        &vmcell::net::tap::RtNetlink,
        &vmcell::metrics::DefaultCgroupFs,
        &std::collections::BTreeSet::new(),
        &std::collections::BTreeSet::new(),
    )
}
