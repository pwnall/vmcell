//! Start-up orphan sweep (design v21 §D4).
//!
//! The daemon **owns** its VMs and releases their resources on `Drop`/`shutdown` — but a hard-killed
//! daemon (SIGKILL, power loss) never runs those, leaking netns/cgroup/scratch keyed by the dead VMs'
//! vmids. On the next boot, before it creates any VM, the daemon reclaims that residue by driving
//! `vmcell`'s `sweep_orphans` with an **empty** live set (nothing is live yet at start-up), so every
//! orphan whose trailing vmid is not currently owned is deleted. This is the crash-recovery counterpart
//! to owning-and-Drop, not a replacement for it.

/// What the start-up sweep reclaimed, for logging.
pub type SweepReport = vmcell::orchestrator::SweepReport;

/// Reclaims leaked netns / cgroup slices / scratch dirs from a previously-crashed daemon.
///
/// Called once at start-up with an empty live-vmid set (before any VM exists), so it only ever deletes
/// genuine orphans. Requires the privileged caps the daemon already holds (netns delete needs
/// `CAP_NET_ADMIN`). Failures on individual resources are logged by `sweep_orphans`, not fatal.
#[must_use]
pub fn startup_sweep() -> SweepReport {
    vmcell::orchestrator::sweep_orphans(
        &vmcell::orchestrator::HostOrphanScanner,
        &vmcell::net::tap::RtNetlink,
        &vmcell::metrics::DefaultCgroupFs,
        &std::collections::BTreeSet::new(),
    )
}
