//! Start-up orphan sweep (design §11.4, The VM registry and the start-up sweep).
//!
//! The daemon **owns** its VMs and releases their resources on `Drop`/`shutdown` — but a hard-killed
//! daemon (SIGKILL, power loss) never runs those, leaking netns/cgroup/scratch keyed by the dead VMs'
//! vmids — and, for a crashed segment host, segids. On the next boot, before it creates any VM, the
//! daemon reclaims that residue by driving `vmcell`'s `sweep_orphans` with **both** live sets empty
//! (nothing is live yet at start-up), so every orphan whose trailing id is not currently owned —
//! in its own id space (vmids for `-net-`/`-vm-`, segids for `-seg-`, §6.5) — is deleted. This is
//! the crash-recovery counterpart to owning-and-Drop, not a replacement for it.

/// What the start-up sweep reclaimed, for logging.
pub type SweepReport = vmcell::orchestrator::SweepReport;

/// Reclaims leaked netns / segment netns / cgroup slices / scratch dirs whose names carry
/// `resource_prefix`, from a previously-crashed daemon.
///
/// Called once at start-up with empty live-vmid **and** live-segid sets (before any VM or segment
/// exists), so it only ever deletes
/// genuine orphans. The prefix MUST be the one the daemon's VMs are named with (design) or the
/// sweep matches nothing; both come from `vmcelld`'s single `--resource-prefix`. Requires the
/// privileged caps the daemon holds (netns delete needs `CAP_NET_ADMIN`). Per-resource failures are
/// logged by `sweep_orphans`, not fatal.
#[must_use]
pub fn startup_sweep(resource_prefix: &str) -> SweepReport {
    vmcell::orchestrator::sweep_orphans(
        &vmcell::orchestrator::HostOrphanScanner::new(resource_prefix),
        &vmcell::net::tap::RtNetlink,
        &vmcell::metrics::DefaultCgroupFs,
        &std::collections::BTreeSet::new(),
        &std::collections::BTreeSet::new(),
    )
}
