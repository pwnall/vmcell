use crate::agent::AgentClient;
use crate::config::VmConfig;
use crate::env::HostEnv;
use crate::error::Result;
use crate::metrics::ResourceUsage;
use crate::net::NetNamespace;
#[cfg(feature = "net-unprivileged")]
use crate::net::SmoltcpProcess;
use crate::proxy::{EgressProxy, ProxyConfig};
use crate::vmm::{PerVmResources, VmInstance, Vmm};
use std::sync::{Arc, Mutex};
use tracing::info;

/// Bounded budget for the post-boot control-plane health-gate (`start`). A healthy
/// transport answers well within this, so only a wedged one spends the whole budget
/// before triggering a re-spawn. Sized above a healthy QEMU cold time-to-ready
/// (~0.7 s p50) with margin, well under the 10 s agent deadline it prevents.
const CONTROL_PLANE_PROBE_BUDGET: std::time::Duration = std::time::Duration::from_secs(4);

/// Max control-plane re-spawns in `start` before failing loud. QEMU's vhost-user
/// vsock bring-up wedges ~11% of boots *independently*, so N re-spawns cut the
/// residual to ~0.11^(N+1); 4 → ~1.6e-5 per VM (CH/FC never enter this path).
const MAX_CONTROL_PLANE_RESPAWNS: u32 = 4;

/// A trait for providing time.
pub trait Clock: Send + Sync {
    /// Returns the current time.
    fn now(&self) -> std::time::SystemTime;
}

/// A real clock that uses the system time.
pub struct RealClock;
impl Clock for RealClock {
    fn now(&self) -> std::time::SystemTime {
        std::time::SystemTime::now()
    }
}

/// A fake clock for testing.
pub struct FakeClock {
    /// The simulated current time.
    pub time: std::time::SystemTime,
}
impl Clock for FakeClock {
    fn now(&self) -> std::time::SystemTime {
        self.time
    }
}

/// A guard that releases the CID when dropped.
#[derive(Debug)]
pub struct CidGuard {
    /// The unique guest CID.
    pub cid: u32,
    allocator: std::sync::Arc<crate::vmm::CidAllocator>,
}

impl Drop for CidGuard {
    fn drop(&mut self) {
        self.allocator.release(self.cid);
    }
}

/// The **one** search-order law both id allocators use: the ids `1..=max`, rotated so the search
/// **starts** at a clock-seeded offset.
///
/// Non-critical to correctness — every allocator scans the whole space and takes the first free id
/// regardless of where it starts — but load-bearing on a shared host: an unseeded scan makes every
/// process try id 1 first, so every process picks the *same* first id, names the same host
/// resources after it, and a liveness-blind sweep in one run reaps another's live namespace. The
/// segment-id allocator shipped without this and every vmcell process on the host therefore chose
/// `vmcell-seg-1` (verified live: one process's start-up sweep reaped another's running segment).
/// Written once so the two allocators cannot drift.
///
/// The clock is the injected [`Clock`] seam rather than `SystemTime::now()` (ORCH-8), so the seed
/// is deterministic under a `FakeClock`.
fn seeded_id_order(clock: &dyn Clock, max: u32) -> impl Iterator<Item = u32> {
    let seed = clock
        .now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos();
    let start = seed % max;
    (0..max).map(move |i| (start + i) % max + 1)
}

/// The **one** cross-process id-claim law, shared by [`VmidAllocator`] and
/// [`SegmentIdAllocator`] (§6.5, VM-to-VM segments; the H1 fix, extracted and parameterized by
/// lock directory).
///
/// It is deliberately id-space-**agnostic**: nothing here knows whether the `u32` it claims is a
/// vmid or a segid — the id space's range and lock directory belong to the owning allocator.
/// Extracting it means the exactly-one-winner race gate covers both allocators instead of one,
/// and a second copy (the historical failure mode) cannot diverge.
#[derive(Clone, Debug)]
struct FsIdClaim {
    /// When set, cross-process reservations are recorded as lock files in this directory. `None`
    /// (the hermetic default) means in-process-only.
    dir: Option<std::path::PathBuf>,
}

impl FsIdClaim {
    /// Attempts to claim `id` in the cross-process lock directory.
    ///
    /// Returns `true` when there is no cross-process locking configured (hermetic
    /// mode) or the claim succeeded; `false` when another **live** process already
    /// holds it.
    ///
    /// Correctness under contention (H-ORCH-4): the whole read→decide→(re)claim runs
    /// while holding an **exclusive advisory lock** (`flock`) on a per-id
    /// coordination file, so at most one claimer of a given id executes it at a
    /// time — the liveness check and the claim are atomic against every other
    /// claimer, closing the reclaim TOCTOU (an unconditional rename-by-path after a
    /// snapshot read could dual-claim; so could a rename-back that clobbers a third
    /// racer's fresh claim). The kernel releases the `flock` when its holder dies, so
    /// a crashed *coordinator* cannot wedge the id; a lock file left by a crashed
    /// *owner* still carries its pid, so the next claimer (under the coordination
    /// lock) sees `/proc/<pid>` is absent and reclaims it. The lock file is created
    /// *already carrying* the owner pid (never the old create-then-write two-step
    /// that could leave an empty, unreclaimable lock).
    fn try_claim(&self, id: u32) -> bool {
        use std::os::unix::io::AsRawFd;
        let Some(dir) = &self.dir else {
            return true;
        };
        let _ = std::fs::create_dir_all(dir);
        let lock_path = dir.join(format!("{id}.lock"));

        // Serialize every cross-process claim/reclaim of THIS id on an exclusive
        // advisory lock over a per-id coordination file. `flock` on two distinct
        // open file descriptions is mutually exclusive even within one process, so
        // this serializes threads (the blessed-runner suite) *and* processes.
        let coord_path = dir.join(format!("{id}.coord"));
        let Ok(coord) = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(&coord_path)
        else {
            // Cannot coordinate → refuse rather than risk a dual-claim.
            return false;
        };
        // SAFETY: `flock(2)` on the valid open fd of `coord`; `coord` is borrowed for
        // the whole scope so the fd stays open, and the exclusive lock is released
        // when `coord` (its owning `File`) is dropped at the end of this function.
        if unsafe { libc::flock(coord.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return false;
        }

        // Under the coordination lock. A lock file that exists blocks the claim only
        // while its owner is alive; a dead/empty (crashed-owner) lock is reclaimed.
        if lock_path.exists() {
            let owner_alive = std::fs::read_to_string(&lock_path)
                .ok()
                .and_then(|c| c.trim().parse::<u32>().ok())
                .is_some_and(|pid| std::path::Path::new(&format!("/proc/{pid}")).exists());
            if owner_alive {
                return false;
            }
            let _ = std::fs::remove_file(&lock_path);
        }
        // The path is free and we exclusively hold the coordination lock: claim it.
        Self::atomic_claim(dir, &lock_path, id)
    }

    /// Creates `lock_path` as a fresh hard link to a temp file already containing
    /// our pid. `hard_link` fails if `lock_path` exists, giving mutual exclusion,
    /// and the winning lock is never observably empty. The temp is always removed.
    fn atomic_claim(dir: &std::path::Path, lock_path: &std::path::Path, id: u32) -> bool {
        let tmp = dir.join(format!("{id}.lock.{}.tmp", std::process::id()));
        if std::fs::write(&tmp, std::process::id().to_string()).is_err() {
            let _ = std::fs::remove_file(&tmp);
            return false;
        }
        let linked = std::fs::hard_link(&tmp, lock_path).is_ok();
        let _ = std::fs::remove_file(&tmp);
        linked
    }

    /// Releases the cross-process lock for `id`, if any.
    ///
    /// A failed removal is warned, not swallowed (docs/78 §6): the lock file carries THIS process's
    /// pid, so `try_claim`'s liveness check reclaims it only once this process exits — until then
    /// the id is wedged for every other process on the host, with the log line as the only clue.
    /// `NotFound` is the benign double-release (in-process `active` already dropped it) and stays
    /// silent.
    fn release(&self, id: u32) {
        if let Some(dir) = &self.dir {
            let lock_path = dir.join(format!("{id}.lock"));
            if let Err(e) = std::fs::remove_file(&lock_path)
                && e.kind() != std::io::ErrorKind::NotFound
            {
                tracing::warn!(
                    "failed to release cross-process id lock {}: {}",
                    lock_path.display(),
                    e
                );
            }
        }
    }
}

/// Allocates unique VM IDs for the orchestrator.
///
/// `new()` is hermetic: it tracks reservations only in-process, so two
/// independent allocators in the same process never interfere (this is what
/// unit tests rely on). The design injects a single shared `Arc<VmidAllocator>`
/// per process, so in-process uniqueness is sufficient there. Use
/// [`VmidAllocator::shared`] for cross-process uniqueness on a real host, where
/// several runner processes may share host-global resources keyed by VMID
/// (netns, tap, cgroup, socket paths, CID, MAC, IP).
#[derive(Clone)]
pub struct VmidAllocator {
    /// Set of allocated VMIDs. Mutex-poison recovery via `into_inner()` is sound
    /// throughout: every critical section is a single `BTreeSet` insert/remove/
    /// contains with no intermediate invariant, so the set is always valid after
    /// any panic point (N-ORCH-3).
    active: Arc<Mutex<std::collections::BTreeSet<u32>>>,
    /// The shared cross-process claim law ([`FsIdClaim`]), parameterized with this allocator's
    /// lock directory (`/tmp/vmcell-vmid` for [`VmidAllocator::shared`]; `None` = hermetic).
    claim: FsIdClaim,
    /// Injected clock used **only** to seed the search start (a hermetic,
    /// non-critical randomization that spreads the first-tried vmid across
    /// processes). Injected rather than reading `SystemTime::now()` directly so
    /// this seam is consistent with the rest of the file (ORCH-8) and the seed
    /// is deterministic under a `FakeClock` in tests.
    ///
    /// The `+ RefUnwindSafe` bound keeps `VmidAllocator` (and any public type that
    /// embeds it, e.g. `artifact::SnapshotStage`) `UnwindSafe`/`RefUnwindSafe`: a
    /// bare `dyn Clock` trait object is not unwind-safe, so storing one silently
    /// drops those auto-traits from the public surface. Both `Clock` impls
    /// (`RealClock`, `FakeClock`) satisfy it, so the bound is free here.
    clock: Arc<dyn Clock + std::panic::RefUnwindSafe>,
}

impl std::fmt::Debug for VmidAllocator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The injected `Clock` is not `Debug`; omit it (it is a non-critical seed
        // source, never part of the allocator's identity).
        f.debug_struct("VmidAllocator")
            .field("active", &self.active)
            .field("lock_dir", &self.claim.dir)
            .finish_non_exhaustive()
    }
}

impl Default for VmidAllocator {
    fn default() -> Self {
        Self::new()
    }
}

impl VmidAllocator {
    /// Creates a new, hermetic VMID allocator (in-process reservations only).
    #[must_use]
    pub fn new() -> Self {
        Self::with_clock(Arc::new(RealClock))
    }

    /// Creates a hermetic allocator seeded from an injected [`Clock`] (ORCH-8).
    /// Used by the unit tests to make the search-start seed deterministic; the
    /// public constructors seed from [`RealClock`].
    fn with_clock(clock: Arc<dyn Clock + std::panic::RefUnwindSafe>) -> Self {
        Self {
            active: Arc::new(Mutex::new(std::collections::BTreeSet::new())),
            claim: FsIdClaim { dir: None },
            clock,
        }
    }

    /// Creates a VMID allocator that additionally enforces cross-process
    /// uniqueness via lock files under `/tmp/vmcell-vmid`. Crashed-owner
    /// reservations are reclaimed by an owner-liveness check (`/proc/<pid>`), so
    /// a crash does not erode capacity permanently.
    #[must_use]
    pub fn shared() -> Self {
        Self::shared_at("/tmp/vmcell-vmid")
    }

    /// Like [`VmidAllocator::shared`] but with an injectable lock directory, so the
    /// cross-process claim/reclaim path is unit-testable (H-ORCH-4). `shared()`
    /// delegates here with the production `/tmp/vmcell-vmid` path.
    #[must_use]
    pub fn shared_at(dir: impl Into<std::path::PathBuf>) -> Self {
        Self {
            active: Arc::new(Mutex::new(std::collections::BTreeSet::new())),
            claim: FsIdClaim {
                dir: Some(dir.into()),
            },
            clock: Arc::new(RealClock),
        }
    }

    /// Allocates and returns the next available unique VMID.
    ///
    /// # Errors
    /// Returns an error if all 254 VMIDs are currently in use.
    pub fn allocate(&self) -> Result<u32> {
        let mut active = self.active.lock().unwrap_or_else(|e| e.into_inner());
        // The one seeded search order (ORCH-8), shared with `SegmentIdAllocator`.
        for vmid in seeded_id_order(&*self.clock, 254) {
            if !active.contains(&vmid) && self.claim.try_claim(vmid) {
                active.insert(vmid);
                return Ok(vmid);
            }
        }
        Err(crate::error::Error::Exhaustion(
            "No available VMIDs (limit 254)".to_string(),
        ))
    }

    /// Reserves a specific VMID, honoring a caller-supplied `cfg.vmid`.
    ///
    /// # Errors
    /// Returns [`crate::error::Error::Config`] if `vmid` is out of the `1..=254`
    /// range, or [`crate::error::Error::Exhaustion`] if it is already reserved
    /// (in-process or by another live process).
    pub fn reserve(&self, vmid: u32) -> Result<u32> {
        if !(1..=254).contains(&vmid) {
            return Err(crate::error::Error::Config(format!(
                "vmid {vmid} out of range (must be 1..=254)"
            )));
        }
        let mut active = self.active.lock().unwrap_or_else(|e| e.into_inner());
        if active.contains(&vmid) {
            return Err(crate::error::Error::Exhaustion(format!(
                "VMID {vmid} already reserved"
            )));
        }
        if !self.claim.try_claim(vmid) {
            return Err(crate::error::Error::Exhaustion(format!(
                "VMID {vmid} already in use by another process"
            )));
        }
        active.insert(vmid);
        Ok(vmid)
    }

    /// Releases a previously allocated VMID.
    pub fn release(&self, vmid: u32) {
        let mut active = self.active.lock().unwrap_or_else(|e| e.into_inner());
        active.remove(&vmid);
        self.claim.release(vmid);
    }
}

/// A guard that releases the VMID when dropped.
#[derive(Debug)]
pub struct VmidGuard {
    /// The unique virtual machine ID.
    pub vmid: u32,
    allocator: VmidAllocator,
}

impl Drop for VmidGuard {
    fn drop(&mut self) {
        self.allocator.release(self.vmid);
    }
}

/// Allocates unique **segment** ids (§6.5, VM-to-VM segments), `1..=`[`crate::net::MAX_SEGMENT_ID`].
///
/// A sibling of [`VmidAllocator`] over the **same** (private) `FsIdClaim` law — it does not re-implement
/// cross-process claiming, only parameterizes it with its own lock directory
/// (`/tmp/vmcell-segid`, the deliberate un-prefixed bare-`/tmp` cross-process rendezvous the vmid
/// allocator already uses). Segment ids live in their **own** id space: a leaked `-seg-` netns is
/// liveness-checked against segids, never vmids ([`sweep_orphans`]).
///
/// `new()` is hermetic (in-process only); [`SegmentIdAllocator::shared`] adds the cross-process
/// lock files.
#[derive(Clone)]
pub struct SegmentIdAllocator {
    /// Set of allocated segment ids. Mutex-poison recovery via `into_inner()` is sound: every
    /// critical section is a single `BTreeSet` insert/remove/contains with no intermediate
    /// invariant.
    active: Arc<Mutex<std::collections::BTreeSet<u32>>>,
    /// The shared cross-process claim law, parameterized with this allocator's lock directory.
    claim: FsIdClaim,
    /// The injected clock that seeds the search start, through the one [`seeded_id_order`] law
    /// [`VmidAllocator`] uses. Same `+ RefUnwindSafe` bound and same reason: a bare `dyn Clock`
    /// silently strips `UnwindSafe`/`RefUnwindSafe` from every public type embedding this one
    /// (here, [`crate::env::HostEnv`]).
    clock: Arc<dyn Clock + std::panic::RefUnwindSafe>,
}

impl std::fmt::Debug for SegmentIdAllocator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The injected `Clock` is not `Debug`; it is a non-critical seed source, never part of the
        // allocator's identity.
        f.debug_struct("SegmentIdAllocator")
            .field("active", &self.active)
            .field("lock_dir", &self.claim.dir)
            .finish_non_exhaustive()
    }
}

impl Default for SegmentIdAllocator {
    fn default() -> Self {
        Self::new()
    }
}

impl SegmentIdAllocator {
    /// Creates a hermetic segment-id allocator (in-process reservations only).
    #[must_use]
    pub fn new() -> Self {
        Self::with_clock(Arc::new(RealClock))
    }

    /// A hermetic allocator seeded from an injected [`Clock`]. The public constructors seed from
    /// [`RealClock`].
    fn with_clock(clock: Arc<dyn Clock + std::panic::RefUnwindSafe>) -> Self {
        Self {
            active: Arc::new(Mutex::new(std::collections::BTreeSet::new())),
            claim: FsIdClaim { dir: None },
            clock,
        }
    }

    /// Test-only: replaces the search-start seed clock (keeping the lock directory), so a unit
    /// test can make two allocators start their search at the same place — the determinism the
    /// production seed deliberately removes.
    #[cfg(test)]
    pub(crate) fn with_seed_clock(
        mut self,
        clock: Arc<dyn Clock + std::panic::RefUnwindSafe>,
    ) -> Self {
        self.clock = clock;
        self
    }

    /// Creates a segment-id allocator that additionally enforces cross-process uniqueness via lock
    /// files under `/tmp/vmcell-segid` — the same recorded cross-process-rendezvous exception as
    /// `/tmp/vmcell-vmid` (deliberate, not swept).
    #[must_use]
    pub fn shared() -> Self {
        Self::shared_at("/tmp/vmcell-segid")
    }

    /// Like [`SegmentIdAllocator::shared`] but with an injectable lock directory, so the
    /// cross-process claim/reclaim path is unit-testable without touching `/tmp/vmcell-segid`.
    #[must_use]
    pub fn shared_at(dir: impl Into<std::path::PathBuf>) -> Self {
        Self {
            active: Arc::new(Mutex::new(std::collections::BTreeSet::new())),
            claim: FsIdClaim {
                dir: Some(dir.into()),
            },
            clock: Arc::new(RealClock),
        }
    }

    /// Allocates the next available segment id.
    ///
    /// The search **starts** at a clock-seeded offset, through the one `seeded_id_order` law the
    /// vmid allocator uses (private, so it is named rather than linked): an unseeded scan hands
    /// every process on the host segid 1, so every process names its namespace `<prefix>-seg-1`
    /// and a liveness-blind sweep reaps a live one.
    ///
    /// # Errors
    /// Returns [`crate::error::Error::Exhaustion`] when all
    /// [`crate::net::MAX_SEGMENT_ID`] ids are in use.
    pub fn allocate(&self) -> Result<u32> {
        let mut active = self.active.lock().unwrap_or_else(|e| e.into_inner());
        for segid in seeded_id_order(&*self.clock, crate::net::MAX_SEGMENT_ID) {
            if !active.contains(&segid) && self.claim.try_claim(segid) {
                active.insert(segid);
                return Ok(segid);
            }
        }
        Err(crate::error::Error::Exhaustion(format!(
            "No available segment ids (limit {})",
            crate::net::MAX_SEGMENT_ID
        )))
    }

    /// Releases a previously allocated segment id.
    pub fn release(&self, segid: u32) {
        let mut active = self.active.lock().unwrap_or_else(|e| e.into_inner());
        active.remove(&segid);
        self.claim.release(segid);
    }
}

/// A guard that releases the segment id when dropped.
#[derive(Debug)]
pub struct SegmentIdGuard {
    /// The allocated segment id.
    pub segid: u32,
    allocator: SegmentIdAllocator,
}

impl SegmentIdGuard {
    /// Claims one segment id from `allocator`, returning the guard that releases it on drop.
    ///
    /// # Errors
    /// Propagates [`SegmentIdAllocator::allocate`]'s exhaustion error.
    pub fn claim(allocator: &SegmentIdAllocator) -> Result<Self> {
        Ok(Self {
            segid: allocator.allocate()?,
            allocator: allocator.clone(),
        })
    }
}

impl Drop for SegmentIdGuard {
    fn drop(&mut self) {
        self.allocator.release(self.segid);
    }
}

/// Represents a fully managed test VM, including its associated resources and VMM instance.
#[derive(Debug)]
#[non_exhaustive]
pub struct MicroVm<V: Vmm> {
    /// The internal unique ID assigned to this VM.
    vmid: Option<VmidGuard>,
    /// The underlying VMM instance running the VM.
    instance: Option<V::Instance>,
    /// The network namespace associated with this VM, if any. Always `None` for a **segment**
    /// member: it has no per-VM namespace (§6.5) — reach the segment's through
    /// [`MicroVm::segment`].
    netns: Option<NetNamespace>,
    /// This VM's segment membership guard, if it joined one (§6.5). Holds an `Arc` clone of the
    /// [`NetSegment`](crate::net::NetSegment), which is what makes "never delete a netns under a
    /// live VMM" structural.
    segment: Option<crate::net::SegmentMember>,
    #[cfg(feature = "net-unprivileged")]
    /// The smoltcp userspace networking process associated with this VM, if any.
    smoltcp: Option<SmoltcpProcess>,
    /// The egress proxy associated with this VM, if any.
    proxy: Option<EgressProxy>,
    /// The name of the cgroup for this VM.
    cgroup_name: Option<String>,
    /// The process-wide seam bundle this VM was spawned with (§9.3, The public API
    /// surface; design §18, Delta register: changes from the validated v27 build,
    /// deltas 1–2). Holds the [`CgroupFs`](crate::metrics::CgroupFs) its slice is
    /// deleted through on teardown and the [`Clock`] that drives the first
    /// post-restore resync in [`MicroVm::agent`]. Replaces the former standalone
    /// `cgroup_fs` field (a subset of what `env` already carries).
    env: HostEnv,
    /// The cached agent client connection, if any.
    agent_client: Option<AgentClient>,
    /// Whether the VM was restored from a snapshot.
    restored: bool,
    /// Whether the one-shot post-restore CSPRNG reseed actually applied (the
    /// `ResyncAck.reseed_applied` field, set by the native in-agent resync) on the
    /// first post-restore [`MicroVm::agent`] call. `None` until that resync runs;
    /// `Some(false)` when the best-effort reseed could not be applied (e.g.
    /// `/dev/hwrng` missing). Lets a restore test assert the reseed was applied
    /// rather than inferring it from two `/dev/urandom` reads differing.
    restore_reseed_applied: Option<bool>,
    /// The CID guard.
    cid: Option<CidGuard>,
    /// The per-VM scratch-directory guard. Created early in `start()`/`restore()`
    /// (before networking) so a partway construction failure still reclaims it,
    /// and dropped LAST on teardown — after the instance, smoltcp, and daemons
    /// whose sockets live inside it are gone.
    tmp_dir: Option<crate::vmm::VmTempDir>,
    /// Per-VM hot-path timing knobs captured from the [`VmConfig`] at
    /// construction, so `agent()`'s connect cadence and `shutdown()`'s grace
    /// window honor the caller-selected profile rather than hard-coded constants.
    timeouts: crate::config::Timeouts,
    /// `true` when the VM boots a custom `init=` (§5.3, The kernel command line) that replaces the vmcell
    /// guest agent, so there is **no** vsock control plane. Set from `cfg.init` at
    /// construction; makes [`MicroVm::agent`] fail loud immediately rather than hang
    /// connecting to a listener that will never answer.
    control_plane_disabled: bool,
}

/// A guard that deletes the cgroup slice on drop unless disarmed.
///
/// Created in `setup_env` immediately after the slice is created so that any
/// later failure during VM construction (CID allocation, `create`, `boot`,
/// `restore`, `resume`) releases the slice — mirroring `CidGuard`/`VmidGuard`.
/// On success it is disarmed and `MicroVm::Drop` takes over deletion (preserving
/// the documented teardown order).
#[derive(Debug)]
struct CgroupGuard {
    name: String,
    fs: Arc<dyn crate::metrics::CgroupFs>,
    armed: bool,
}

impl CgroupGuard {
    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for CgroupGuard {
    fn drop(&mut self) {
        if self.armed
            && let Err(e) = self.fs.delete_slice(&self.name)
        {
            tracing::warn!("failed to delete leaked cgroup slice {}: {}", self.name, e);
        }
    }
}

/// Transient holder for the resources `setup_env` allocates before the VMM
/// instance exists. On the happy path each resource is `take()`n into `MicroVm` (and
/// the `cgroup_guard` disarmed) before the instance is built; on any mid-construction
/// failure (`create`/`boot`/`restore`/`resume`) the **explicit [`Drop`]** below
/// releases the un-taken resources through the shared [`release_net_before_netns`]
/// helper — the SAME ordered net teardown `teardown_post_instance` uses (design §18,
/// Delta register: changes from the validated v27 build, delta 7, L1, §9.4,
/// Timeouts and the lifecycle nuances). Making the order explicit (not a fragile field-declaration
/// order) means a field reorder can no longer silently delete the netns before the
/// proxy running inside it. `cid_guard` is `Option` so the success path can `take()`
/// it out (a field of a type that implements `Drop` cannot be moved out).
struct EnvSetup {
    proxy: Option<EgressProxy>,
    #[cfg(feature = "net-unprivileged")]
    smoltcp: Option<SmoltcpProcess>,
    netns: Option<NetNamespace>,
    /// This VM's segment slot + tap, when it is a member (§6.5). Released through the same shared
    /// [`release_net_before_netns`] helper as every other net resource.
    segment: Option<crate::net::SegmentMember>,
    cgroup_guard: CgroupGuard,
    cid_guard: Option<CidGuard>,
    res: PerVmResources,
}

/// The single ordered net teardown both the success path ([`MicroVm::teardown_post_instance`]) and
/// the mid-`start()` error path ([`EnvSetup`]'s [`Drop`]) route through (design §18, Delta register:
/// changes from the validated v27 build, delta 7, L1, §9.4, Timeouts and the lifecycle nuances).
/// The egress proxy and the smoltcp NAT hold sockets/threads INSIDE the netns, so they are
/// released BEFORE the netns is deleted — deleting a netns while a process still holds interfaces in
/// it hangs/leaks. One helper, never a second copy: a field reorder cannot silently invert this.
fn release_net_before_netns(
    proxy: &mut Option<EgressProxy>,
    #[cfg(feature = "net-unprivileged")] smoltcp: &mut Option<SmoltcpProcess>,
    netns: &mut Option<NetNamespace>,
    segment: &mut Option<crate::net::SegmentMember>,
) {
    #[cfg(feature = "net-unprivileged")]
    drop(smoltcp.take());
    drop(proxy.take());
    // `NetNamespace::Drop` performs the single idempotent teardown, surfacing a genuine failure via
    // the NET-8 warning; dropping the taken value tears it down exactly once.
    drop(netns.take());
    // §6.5 (VM-to-VM segments): a member releases its SLOT and its TAP here — never the segment
    // namespace, which dies with the last `NetSegment` Arc holder (this guard holds one, so the
    // namespace necessarily outlives the VMM this teardown already reaped). The segment path
    // leaves `netns == None`, so the take above is a no-op for it; the order is still one law.
    drop(segment.take());
}

impl Drop for EnvSetup {
    fn drop(&mut self) {
        // Mid-`start()` error path: release the net resources (proxy/smoltcp before the netns)
        // through the shared helper, then the struct's own fields drop in declaration order —
        // `cgroup_guard` (armed → deletes the slice) before `cid_guard` (releases the CID). On the
        // success path these were `take()`n / disarmed, so this is a no-op. Same net → cgroup → cid
        // order as `teardown_post_instance`.
        release_net_before_netns(
            &mut self.proxy,
            #[cfg(feature = "net-unprivileged")]
            &mut self.smoltcp,
            &mut self.netns,
            &mut self.segment,
        );
    }
}

/// Minimal guest-resync seam the one-shot post-restore resync needs.
///
/// Implemented for the real [`AgentClient`] (a single native `resync` round-trip)
/// and for a recording fake in the unit tests, so the resync's mandatory-clock
/// fail-loud + retry contract (M-RESTORE-1) can be exercised without a live guest.
trait GuestResync {
    /// Runs the native post-restore resync in the guest and returns its outcome.
    async fn resync(
        &mut self,
        unix_secs: u64,
        unix_nanos: u32,
        mac: Option<[u8; 6]>,
        ipv4: Option<crate::agent::protocol::Ipv4Reconfig>,
    ) -> Result<crate::agent::ResyncOutcome>;
}

impl GuestResync for AgentClient {
    async fn resync(
        &mut self,
        unix_secs: u64,
        unix_nanos: u32,
        mac: Option<[u8; 6]>,
        ipv4: Option<crate::agent::protocol::Ipv4Reconfig>,
    ) -> Result<crate::agent::ResyncOutcome> {
        // Resolves to the inherent `AgentClient::resync` (inherent methods win
        // over the same-named trait method), so this delegates rather than
        // recursing.
        self.resync(unix_secs, unix_nanos, mac, ipv4).await
    }
}

/// Parses a canonical `xx:xx:xx:xx:xx:xx` MAC string into its six bytes.
///
/// The restore resync carries the MAC as raw bytes on the wire, but
/// [`crate::net::mac_math`] centralizes the vmid→MAC mapping as a string; this
/// converts without duplicating that mapping. Returns `None` on a malformed
/// string (wrong group count or a non-hex octet).
fn parse_mac_bytes(s: &str) -> Option<[u8; 6]> {
    let mut parts = s.split(':');
    let mut out = [0u8; 6];
    for slot in &mut out {
        *slot = u8::from_str_radix(parts.next()?, 16).ok()?;
    }
    // Reject a 7th (or longer) group so a malformed string can't masquerade.
    if parts.next().is_some() {
        return None;
    }
    Some(out)
}

/// Runs the one-shot post-restore guest resync when `*restored` is set, clearing
/// the flag **only after** the mandatory clock resync succeeds.
///
/// M-RESTORE-1: a snapshot resumes at the frozen instant, so the guest clock,
/// CSPRNG state, and network identity must be refreshed on **every** restore
/// (§8.2, Restore correctness: a restored VM is not a fresh VM). This now drives a single **native** in-agent resync round-trip
/// (§8.2, Restore correctness: a restored VM is not a fresh VM) instead of three subprocess execs. The round-trip is propagated
/// (`?`) so a transient transport failure leaves `*restored` **set** and the next
/// `agent()` call retries the whole resync, instead of being cleared up front (the
/// bug, which permanently skipped clock/RNG/MAC resync after one transient error).
/// The clock resync is mandatory and fail-loud: a `Some(clock_error)` in the ack
/// returns a typed `Err` **before** the flag is cleared (identical semantics to
/// the old non-zero-`date`-exit path). `*reseed_applied` records whether the
/// best-effort CSPRNG reseed actually applied, so a caller can assert the reseed
/// ran rather than inferring it from two `/dev/urandom` reads differing.
async fn maybe_resync_after_restore<E: GuestResync>(
    restored: &mut bool,
    reseed_applied: &mut Option<bool>,
    exec: &mut E,
    clock: &dyn Clock,
    vmid: u32,
) -> Result<()> {
    if !*restored {
        return Ok(());
    }

    // Host instant for the mandatory clock resync (§8.2, Restore correctness: a restored VM is not a fresh VM): the guest cannot fix a
    // frozen RTC from inside. Carried as whole secs + sub-second nanos on the wire.
    // L-ORCH-4: a pre-1970 host clock must fail loud — the mandatory resync is the
    // one step the design insists never silently degrades, so `unwrap_or_default()`
    // (which would push epoch-0 into the guest) is a typed error here instead.
    let since_epoch = clock
        .now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| {
            crate::error::Error::Agent(
                "host clock is before the Unix epoch; refusing to resync guest to 1970".into(),
            )
        })?;
    let unix_secs = since_epoch.as_secs();
    let unix_nanos = since_epoch.subsec_nanos();

    // ORCH-1 / §8.2 (Restore correctness: a restored VM is not a fresh VM): MAC rotation is the ONLY in-guest identity change the restore
    // path performs — applied natively via `SIOCSIFHWADDR` (no in-guest netlink),
    // keeping the zero-netlink-in-PID-1 contract (§3.4, The guest: vmcell-guest-agent as PID 1).
    // `mac_math` centralizes the vmid→MAC mapping as a string; convert it to the
    // six bytes the wire protocol carries without duplicating that mapping.
    let mac_str = crate::net::mac_math(vmid)
        .map_err(|e| crate::error::Error::Agent(format!("mac math: {e}")))?;
    let mac = parse_mac_bytes(&mac_str).ok_or_else(|| {
        crate::error::Error::Agent(format!("mac math produced an unparseable MAC: {mac_str}"))
    })?;

    // H-VMM-1: the IP address IS rotated on restore (superseding the old §8.2
    // (Restore correctness: a restored VM is not a fresh VM)
    // "do not rotate the guest IP" note). A snapshot is a *zygote* — resumed into
    // many concurrent children, each needing a distinct network identity — so the
    // vmid rotates and the guest's frozen `ip=` no longer matches its rotated
    // host-side tap/`/30`. Derive the new `/30` from the same centralized
    // `ip_math` the host wiring uses: the guest takes `guest_ip`, its default route
    // goes via `host_ip` (the gateway). Applied natively in-guest (SIOCSIFADDR +
    // route ioctls, no netlink), exactly like the MAC above.
    let (host_ip, guest_ip, _cidr) = crate::net::ip_math(vmid)
        .map_err(|e| crate::error::Error::Agent(format!("ip math: {e}")))?;
    let ipv4 = crate::agent::protocol::Ipv4Reconfig {
        addr: guest_ip.octets(),
        // The `/30` point-to-point prefix `ip_math` produces.
        prefix_len: 30,
        gateway: host_ip.octets(),
    };

    tracing::info!(
        "Automatically resyncing guest after restore to host time {}.{:09}",
        unix_secs,
        unix_nanos
    );

    // One native round-trip. Propagated with `?` so a transient transport failure
    // leaves `*restored` set and the next agent() call retries the whole resync.
    let outcome = exec
        .resync(unix_secs, unix_nanos, Some(mac), Some(ipv4))
        .await?;

    if let Some(err) = outcome.clock_error {
        // ORCH-3 / M-RESTORE-1: the clock resync is mandatory (§8.2, Restore correctness: a restored VM is not a fresh VM) — a guest-side
        // clock-set failure is a *surfaced, typed* failure, not a warning. We
        // return here **before** clearing `*restored`, so the flag stays set and
        // the next `agent()` call retries the whole resync (identical to the old
        // non-zero-exit path). Clearing it here (silent-Ok-on-failure) would leave
        // time-sensitive restored tests seeing a frozen wall clock (§7.1, What is read and enforced, defect).
        return Err(crate::error::Error::Agent(format!(
            "mandatory post-restore clock resync failed: {err}"
        )));
    }

    // Best-effort CSPRNG reseed: whether it applied is recorded so a restore test
    // can assert it ran; a not-applied reseed never keeps `restored` set.
    *reseed_applied = Some(outcome.reseed_applied);

    // MAC rotation is best-effort; a not-applied rotation is logged, not fatal.
    if !outcome.mac_applied {
        tracing::warn!("restore MAC rotation did not apply in the guest");
    }

    // IP rotation is best-effort here (a non-networked restored VM has no eth0);
    // for a tap-networked VM a not-applied rotation means dead egress, so log it.
    if !outcome.ip_applied {
        tracing::warn!("restore IP rotation did not apply in the guest");
    }

    // Clear `restored` ONLY now — after the mandatory clock resync above
    // succeeded (M-RESTORE-1). The RNG/MAC steps are best-effort and never keep
    // the flag set.
    *restored = false;
    Ok(())
}

impl<V: Vmm> MicroVm<V> {
    /// Gets the internal unique ID assigned to this VM.
    ///
    /// # Panics
    /// Panics if the VMID is missing.
    pub fn vmid(&self) -> u32 {
        self.vmid.as_ref().expect("vmid missing").vmid
    }

    /// Gets a reference to the underlying VMM instance.
    ///
    /// # Panics
    /// Panics if the instance is missing.
    pub fn instance(&self) -> &V::Instance {
        self.instance.as_ref().expect("instance missing")
    }

    /// Gets a mutable reference to the underlying VMM instance.
    ///
    /// **`pub(crate)` (design §18, Delta register: changes from the validated v27 build, delta 6, the M-ORCH-5 finding):** exposing the raw
    /// [`VmInstance`](crate::vmm::VmInstance) publicly let a caller bypass the orchestrator's
    /// ordered teardown and identity bookkeeping — a footgun with no legitimate external use.
    /// External callers reach for the safe [`MicroVm`] methods instead ([`kill`](MicroVm::kill) for
    /// a hard teardown; [`snapshot`](MicroVm::snapshot) — which additionally invalidates the cached
    /// [`AgentClient`], the EXP-E fix — never `instance().snapshot()`; `instance()` for read-only
    /// probes).
    ///
    /// # Panics
    /// Panics if the instance is missing.
    pub(crate) fn instance_mut(&mut self) -> &mut V::Instance {
        self.instance.as_mut().expect("instance missing")
    }

    /// Force-kills the underlying VMM process **now**, skipping the graceful shutdown handshake.
    ///
    /// Unlike [`shutdown`](MicroVm::shutdown) (graceful, consuming), this leaves the `MicroVm`
    /// alive, so a caller/test can then inspect residue or drive the daemon's orphan sweep against a
    /// process that died without its ordered teardown. The remaining per-VM resources are still
    /// released by `Drop` in the documented order. The safe public entry point that replaces the
    /// former `instance_mut().kill()` (delta 6). A hard kill that skips `Drop` entirely is reclaimed
    /// by the daemon's start-up sweep (AGENTS.md).
    ///
    /// # Errors
    /// Returns an error if the VMM process cannot be killed.
    ///
    /// # Panics
    /// Panics if the instance is missing (e.g. after `shutdown`).
    pub async fn kill(&mut self) -> Result<()> {
        self.instance_mut().kill().await
    }

    /// Gets the network namespace associated with this VM, if any.
    ///
    /// Always `None` for a **segment** member — a member has no per-VM namespace; its tap lives in
    /// the segment's (§6.5). Use [`MicroVm::segment`] to reach that one (e.g. for
    /// `nsenter --net=<path> tc qdisc … netem`).
    pub fn netns(&self) -> Option<&NetNamespace> {
        self.netns.as_ref()
    }

    /// Gets the VM-to-VM segment this VM is a member of, if any (§6.5, VM-to-VM segments).
    ///
    /// The only route to a member's namespace path, bridge name, and gateway — [`MicroVm::netns`]
    /// returns `None` on this path.
    pub fn segment(&self) -> Option<&crate::net::NetSegment> {
        self.segment
            .as_ref()
            .map(crate::net::SegmentMember::segment)
    }

    /// Gets this VM's place in its segment (namespace, tap, segid, slot), if it is a member.
    pub fn segment_membership(&self) -> Option<&crate::net::SegmentMembership> {
        self.segment
            .as_ref()
            .map(crate::net::SegmentMember::membership)
    }

    #[cfg(feature = "net-unprivileged")]
    /// Gets the smoltcp userspace networking process associated with this VM, if any.
    pub fn smoltcp(&self) -> Option<&SmoltcpProcess> {
        self.smoltcp.as_ref()
    }

    /// Gets the egress proxy associated with this VM, if any.
    pub fn proxy(&self) -> Option<&EgressProxy> {
        self.proxy.as_ref()
    }

    async fn setup_env(
        vmid: u32,
        tmp_dir: &std::path::Path,
        cfg: &VmConfig,
        env: &HostEnv,
    ) -> Result<EnvSetup> {
        let mut netns = None;
        #[cfg(feature = "net-unprivileged")]
        let mut smoltcp = None;
        let mut proxy = None;
        let mut tap_name = None;
        let mut netns_name = None;
        let mut segment_member: Option<crate::net::SegmentMember> = None;
        let mut res_segment: Option<crate::net::SegmentMembership> = None;
        // `mut`: reassigned on the `net-unprivileged` leg below, which `host-common` always enables
        // (and this fn only compiles under `host-common`), so the binding is unconditionally mutated.
        let mut vhost_user_socket = None;

        match &cfg.net {
            crate::config::NetConfig::Privileged { egress } => {
                // `egress` is consumed below only under `feature = "proxy"`; the
                // discard silences the unused binding when the proxy is compiled
                // out (it is a config selector, not a resource). `host_services_port`
                // is not a privileged-path field any more (design §18, Delta register: changes from the validated v27 build, delta 4).
                let _ = egress;
                let ns = NetNamespace::create(
                    &cfg.resource_prefix,
                    vmid,
                    Box::new(crate::net::tap::RtNetlink),
                )?;
                tap_name = Some(ns.tap_name.clone());
                netns_name = Some(ns.name.clone());

                if let crate::config::Egress::Filtered(proxy_cfg) = egress {
                    #[cfg(feature = "proxy")]
                    {
                        // Privileged egress front-end: the nft TPROXY ruleset
                        // (`tproxy to :<port>`, emitted below) redirects the guest's
                        // tcp/80,443 into this listener, so it MUST be an
                        // `IP_TRANSPARENT` socket for the kernel to deliver the
                        // redirected connections and preserve the original
                        // destination (H-PROXY-1). `start_transparent` fails loud if
                        // `IP_TRANSPARENT` cannot be set (e.g. missing CAP_NET_ADMIN)
                        // rather than silently degrading to a non-transparent bind
                        // that TPROXY cannot deliver to. NOTE: hudsucker is an
                        // explicit-proxy MITM (expects CONNECT/absolute-form), so a
                        // fully transparent HTTP MITM additionally needs absolute-form
                        // reconstruction from the recovered destination; that is
                        // tracked as follow-up — see implementation-notes.md.
                        let px = EgressProxy::start_transparent(crate::proxy::ProxyConfig {
                            port: 0,
                            netns: Some(crate::naming::netns_name(&cfg.resource_prefix, vmid)),
                            doubles: proxy_cfg.doubles.clone(),
                            blocked_domains: proxy_cfg.blocked_domains.clone(),
                        })
                        .await?;
                        ns.emit_proxy_rules(px.port, &crate::net::tap::DefaultNftApplier)?;
                        proxy = Some(px);
                    }
                }

                netns = Some(ns);
            }
            crate::config::NetConfig::Unprivileged {
                egress,
                host_services_port,
            } => {
                let _ = host_services_port;
                let mut _proxy_port = 0;

                if let crate::config::Egress::Filtered(proxy_cfg) = egress {
                    #[cfg(feature = "proxy")]
                    {
                        let px = EgressProxy::start(ProxyConfig {
                            port: 0,
                            netns: None,
                            doubles: proxy_cfg.doubles.clone(),
                            blocked_domains: proxy_cfg.blocked_domains.clone(),
                        })
                        .await?;
                        _proxy_port = px.port;
                        proxy = Some(px);
                    }
                }
                #[cfg(feature = "net-unprivileged")]
                {
                    // Consolidated into the per-VM scratch dir so the NAT socket is
                    // owned and reclaimed with everything else. The same path is
                    // handed to BOTH the smoltcp helper (which binds/unlinks it) and
                    // the VMM (via `vhost_user_socket`) so both sides agree.
                    let socket_path = tmp_dir.join("smoltcp.sock");
                    let mut ports = vec![];
                    let proxy_port_opt = if _proxy_port > 0 {
                        Some(_proxy_port)
                    } else {
                        None
                    };
                    if let Some(p) = host_services_port {
                        ports.push(*p);
                    }
                    // Register the egress proxy's port as a permanent forward-port so a guest
                    // configured with `http_proxy=<gateway>:<proxy_port>` reaches it: permanent
                    // listeners are pre-armed and re-armed (unlike the dynamic SYN-intercept
                    // path), which the explicit-proxy egress tests rely on.
                    if let Some(p) = proxy_port_opt {
                        ports.push(p);
                    }
                    let p = SmoltcpProcess::start(vmid, ports, proxy_port_opt, socket_path.clone());
                    vhost_user_socket = Some(socket_path);
                    smoltcp = Some(p);
                }
            }
            crate::config::NetConfig::Segment { segment } => {
                // §6.5 (VM-to-VM segments): a member has NO per-VM netns. Its tap is created in
                // the *segment's* namespace and enslaved to the bridge; `netns_name` therefore
                // names the segment, and `build_vmm_cmd`'s pre-exec `setns` needs no change.
                // The member holds an `Arc` clone of the segment, so the namespace cannot be
                // removed while this VM lives.
                let member = segment.claim_member(vmid)?;
                tap_name = Some(member.membership().tap_name.clone());
                netns_name = Some(member.membership().netns.clone());
                res_segment = Some(member.membership().clone());
                segment_member = Some(member);
            }
            crate::config::NetConfig::None => {}
        }

        // Fail-loud post-condition, one law (`net_uses_tap`): the tap-datapath question the config
        // answers and the resources actually allocated must agree, so every backend can keep
        // keying its device wiring on `res.tap_name` alone.
        crate::config::assert_tap_wiring_matches(&cfg.net, tap_name.is_some())?;

        // §13 (Cross-cutting invariants) sibling placement: create the per-VM slice as a sibling of the
        // supervisor's own leaf, using the shared, unit-tested line-based parser
        // in `metrics` (M-ORCH-4/H-HOST-3) — not an inline `split("0::")` over the
        // whole file, which folds trailing lines into the path on a hybrid v1/v2
        // hierarchy.
        let cgroup_name = crate::metrics::vm_slice_name(&cfg.resource_prefix, vmid);

        env.cgroups.create_slice(&cgroup_name, &cfg.limits)?;
        // Armed immediately: any failure below (CID allocation, create/boot/
        // restore/resume in the caller) now releases the slice instead of
        // leaking it.
        let cgroup_guard = CgroupGuard {
            name: cgroup_name.clone(),
            fs: env.cgroups.clone(),
            armed: true,
        };

        let cids = env.cids.clone();
        let guest_cid = cids.allocate()?;
        let cid_guard = CidGuard {
            cid: guest_cid,
            allocator: cids,
        };

        let res = PerVmResources {
            cgroup_name,
            tap_name,
            netns_name,
            segment: res_segment,
            vhost_user_socket,
            vmid,
            guest_cid,
            tmp_dir: tmp_dir.to_path_buf(),
        };

        Ok(EnvSetup {
            res,
            cid_guard: Some(cid_guard),
            cgroup_guard,
            netns,
            segment: segment_member,
            #[cfg(feature = "net-unprivileged")]
            smoltcp,
            proxy,
        })
    }

    /// Starts a new VM with the given configuration.
    ///
    /// # Errors
    /// Returns an error if network setup, proxy start, or VM boot fails.
    ///
    /// # Examples
    /// ```rust
    /// # use std::path::PathBuf;
    /// # use vmcell::{HostEnv, MicroVm};
    /// # use vmcell::config::{VmConfig, RootfsSource};
    /// # use vmcell::vmm::cloud_hypervisor::CloudHypervisor;
    /// # async fn run() {
    /// let vmm = CloudHypervisor::new("cloud-hypervisor");
    /// // Erofs is the supported, snapshot-compatible rootfs; a virtio-fs *rootfs*
    /// // is rejected by every backend, so the example uses erofs (L-ORCH-1).
    /// let cfg = VmConfig::builder(PathBuf::from("/vmlinux"), RootfsSource::Erofs { image: PathBuf::from("/rootfs.erofs") }).build().unwrap();
    /// // One process-wide seam bundle, built once and threaded by reference (§9.3, The public API surface).
    /// let env = HostEnv::shared().unwrap();
    /// let vm = MicroVm::start(&vmm, cfg, &env).await.unwrap();
    /// # }
    /// ```
    pub async fn start(vmm: &V, cfg: VmConfig, env: &HostEnv) -> Result<Self> {
        // Honor an explicitly-configured VMID by reserving it through the
        // allocator; otherwise allocate the next free one.
        let vmid_value = match cfg.vmid {
            Some(v) => env.vmids.reserve(v)?,
            None => env.vmids.allocate()?,
        };
        let vmid = VmidGuard {
            vmid: vmid_value,
            allocator: env.vmids.clone(),
        };
        // Create the single owned per-VM scratch dir EARLY — before networking —
        // so its guard reclaims it even if setup or create/boot fails partway, and
        // so the smoltcp NAT socket can live inside it.
        let tmp_dir = crate::vmm::VmTempDir::create(&cfg.resource_prefix, vmid.vmid).await?;
        let mut staged = Self::setup_env(vmid.vmid, tmp_dir.path(), &cfg, env).await?;

        let mut instance = vmm.create(&cfg, &staged.res, &*env.cgroups).await?;
        info!("Booting instance...");
        instance.boot().await?;
        info!("Instance booted.");

        // Post-boot control-plane health-gate. Default (CH/FC) is a no-op: their
        // vsock is internal to the VMM and cannot half-initialize. QEMU's vsock is an
        // external `vhost-device-vsock` daemon over a `vhost-user-vsock` virtqueue
        // whose bring-up races (~11% of boots wedge the data path for the VM's life;
        // docs/benchmark-results.md "QEMU agent-timeout flake"). `verify_control_plane`
        // probes it with a bounded budget; a wedged VM is re-spawned rather than
        // handed back to reveal the wedge ~10 s later as an agent-connect timeout. A
        // healthy transport answers well within the budget, so this adds no wait on
        // the common path. Re-spawn recreates on the SAME per-VM resources
        // (netns/tap/cgroup/CID/dir); `spawn_qemu` pre-cleans stale sockets.
        // A custom `init=` (§5.3, The kernel command line) replaces the guest agent, so there is no agent vsock
        // transport to health-gate — skip the probe (which QEMU uses to catch a wedged
        // `vhost-device-vsock` bring-up); otherwise a custom-init QEMU VM would re-spawn
        // to exhaustion against a listener that never comes up. CH/FC probes are no-ops.
        if cfg.init.is_none() {
            let clamped = cfg.timeouts.clamped();
            let mut respawns = 0u32;
            while let Err(e) = instance
                .verify_control_plane(CONTROL_PLANE_PROBE_BUDGET, &clamped)
                .await
            {
                if respawns >= MAX_CONTROL_PLANE_RESPAWNS {
                    return Err(crate::error::Error::Vmm(format!(
                        "guest control plane did not come up after {MAX_CONTROL_PLANE_RESPAWNS} \
                         re-spawns: {e}"
                    )));
                }
                respawns += 1;
                tracing::warn!(
                    "control-plane bring-up failed (re-spawn {respawns}/{MAX_CONTROL_PLANE_RESPAWNS}): {e}"
                );
                // `Drop` reaps the VMM process group + external daemon and unlinks their
                // sockets before the fresh spawn re-binds them.
                drop(instance);
                instance = vmm.create(&cfg, &staged.res, &*env.cgroups).await?;
                instance.boot().await?;
            }
        }
        // Success: ownership of the slice transfers to the returned MicroVm,
        // whose Drop deletes it in the documented teardown order.
        staged.cgroup_guard.disarm();
        Ok(Self {
            vmid: Some(vmid),
            instance: Some(instance),
            netns: staged.netns.take(),
            segment: staged.segment.take(),
            #[cfg(feature = "net-unprivileged")]
            smoltcp: staged.smoltcp.take(),
            proxy: staged.proxy.take(),
            cgroup_name: Some(staged.res.cgroup_name.clone()),
            env: env.clone(),
            agent_client: None,
            restored: false,
            restore_reseed_applied: None,
            cid: staged.cid_guard.take(),
            tmp_dir: Some(tmp_dir),
            // M-ORCH-3: re-clamp at the orchestrator boundary. The builder/presets
            // clamp, but `Timeouts`' fields are `pub`, so a caller can mutate
            // `cfg.timeouts` after `build()` down to a busy-spin; clamping here
            // guarantees the connect/accept/grace cadences honor their floors.
            timeouts: cfg.timeouts.clamped(),
            control_plane_disabled: cfg.init.is_some(),
        })
    }

    /// Restores a single VM from a snapshot directory with the given configuration.
    ///
    /// This is the **single-use** restore path: it hands the backend the caller's
    /// `snapshot_dir` directly, and the CH backend rewrites that dir's
    /// `config.json` in place (FC reads its per-dir sidecar), so restoring more
    /// than one VM from one dir — or restoring concurrently — races and corrupts
    /// it (§8.1, The warm-snapshot path and the eligibility law). To mint *many* identical VMs from one suspend image without that
    /// hazard, capture a [`Zygote`](crate::Zygote) and use its copy-on-write
    /// fan-out (or [`MicroVm::restore_cow`] for a single CoW clone), which restores
    /// each clone from its own private copy and leaves the master untouched (§8.4, The zygote fan-out and the OverlayStore seam).
    ///
    /// # Errors
    /// Returns an error if network setup, proxy start, or VM restore fails.
    ///
    /// # Examples
    /// ```rust
    /// # use std::path::PathBuf;
    /// # use vmcell::{HostEnv, MicroVm};
    /// # use vmcell::config::{VmConfig, RootfsSource};
    /// # use vmcell::vmm::cloud_hypervisor::CloudHypervisor;
    /// # async fn run() {
    /// let vmm = CloudHypervisor::new("cloud-hypervisor");
    /// let cfg = VmConfig::builder(PathBuf::from("/vmlinux"), RootfsSource::Erofs { image: PathBuf::from("/rootfs.erofs") }).build().unwrap();
    /// let env = HostEnv::shared().unwrap();
    /// let snap_dir = PathBuf::from("/tmp/snap");
    /// let vm = MicroVm::restore(&vmm, &snap_dir, cfg, &env).await.unwrap();
    /// # }
    /// ```
    pub async fn restore(
        vmm: &V,
        snapshot_dir: &std::path::Path,
        cfg: VmConfig,
        env: &HostEnv,
    ) -> Result<Self> {
        // Single-use restore does not copy the dir (`cow = false`); the caller's dir
        // is restored in place.
        Self::restore_inner(vmm, snapshot_dir, cfg, env, false)
            .await
            .map(|(vm, _cow)| vm)
    }

    /// Restores one clone from a zygote suspend image, copy-on-write-copying the
    /// suspend data into this clone's own scratch dir **before** restore so the
    /// master image is never mutated and concurrent clones never race on the
    /// backend's in-place `config.json` rewrite (§8.4, The zygote fan-out and the OverlayStore seam). Returns the clone and
    /// whether the copy used a block-level reflink or a full byte copy
    /// ([`CowSupport`](crate::CowSupport)).
    ///
    /// This is the low-level primitive behind [`Zygote::spawn_clone`](crate::Zygote::spawn_clone); most
    /// callers want [`Zygote`](crate::Zygote), which owns the immutable master and
    /// gates concurrent fan-out on the backend capability. A single CoW clone
    /// works on any snapshot backend; concurrent fan-out needs
    /// `capabilities().restore_rotates_host_paths` (§2.5, The capability matrix) — enforced by
    /// [`Zygote::spawn_clones`](crate::Zygote::spawn_clones), not here.
    ///
    /// The copy-on-write copy of the suspend directory is materialized through the
    /// injected [`OverlayStore`](crate::overlay::OverlayStore) seam (§13, Cross-cutting invariants) —
    /// [`ReflinkOverlayStore`](crate::overlay::ReflinkOverlayStore) in production;
    /// a recording double in tests. The store is the single clone-materialization
    /// law, so a caller can swap the backing store (e.g. a shared content-addressed
    /// overlay pool) without touching this path.
    ///
    /// # Errors
    /// Returns an error if the copy-on-write copy, network setup, proxy start, or
    /// VM restore fails. The eligibility re-checks of [`MicroVm::restore`] apply
    /// identically (a clone with a vhost-user device is
    /// [`Error::Unsupported`](crate::error::Error::Unsupported)).
    pub async fn restore_cow(
        vmm: &V,
        zygote_dir: &std::path::Path,
        cfg: VmConfig,
        env: &HostEnv,
    ) -> Result<(Self, crate::reflink::CowSupport)> {
        // CoW clone (`cow = true`): the suspend dir is copied through `env.overlay`
        // (invariant S4) into this VM's scratch dir before restore, so the master
        // image is never mutated and concurrent clones never race on the backend's
        // in-place `config.json` rewrite.
        Self::restore_inner(vmm, zygote_dir, cfg, env, true).await
    }

    /// Shared body of [`MicroVm::restore`] (single-use, `cow = false`) and
    /// [`MicroVm::restore_cow`] (`cow = true`). When `cow`, the snapshot dir is
    /// copy-on-write-copied into this VM's scratch dir through the process-wide
    /// `env.overlay` store first and the backend restores from that private copy;
    /// otherwise the caller's dir is used directly. The returned
    /// [`CowSupport`](crate::reflink::CowSupport) is only meaningful in the CoW case
    /// (the single-use path returns `FullCopy` as an ignored placeholder). One store
    /// for the whole process — no second injection path (invariant S4).
    async fn restore_inner(
        vmm: &V,
        snapshot_dir: &std::path::Path,
        cfg: VmConfig,
        env: &HostEnv,
        cow: bool,
    ) -> Result<(Self, crate::reflink::CowSupport)> {
        // §2.5 (The capability matrix) boundary 2 (ORCH-4): the restore-path re-check of the
        // snapshot-eligibility law returns `Error::Unsupported { vmm, feature }`
        // (a capability rejection a caller can match on), NOT the generic
        // `Error::Config` — a config a snapshot-eligible VMM cannot honor is an
        // unsupported capability, not a malformed config. The arms themselves live in the ONE
        // config-only predicate `clone_ineligible_feature` (below), the designated home shared
        // with the zygote fan-out's fail-fast gate: the two open-coded copies had already needed
        // lock-step edits and had drifted (docs/78 S1), so only the *wrapping* refusal — the
        // per-boundary prose and the vmm id — stays here.
        if let Some(feature) = clone_ineligible_feature(&cfg) {
            return Err(crate::error::Error::Unsupported {
                vmm: vmm.id().to_string(),
                feature: format!("snapshot restore with {feature}"),
            });
        }

        let vmid_value = match cfg.vmid {
            Some(v) => env.vmids.reserve(v)?,
            None => env.vmids.allocate()?,
        };
        let vmid = VmidGuard {
            vmid: vmid_value,
            allocator: env.vmids.clone(),
        };
        // Create the single owned per-VM scratch dir EARLY (see `start()`).
        let tmp_dir = crate::vmm::VmTempDir::create(&cfg.resource_prefix, vmid.vmid).await?;

        // Zygote fan-out (§8.4, The zygote fan-out and the OverlayStore seam): a clone restores from its OWN copy of the
        // suspend image, never the shared master. The CH backend rewrites the
        // snapshot's `config.json` in place per restore (FC reads a per-dir
        // sidecar), so restoring N clones from one dir races and corrupts it
        // (§8.1, The warm-snapshot path and the eligibility law); a per-clone copy removes the race AND keeps the zygote master
        // immutable (§13, Cross-cutting invariants). The copy lives INSIDE this VM's scratch dir, so the
        // `tmp_dir` guard's Drop reclaims it with everything else (teardown order,
        // §13, Cross-cutting invariants). On a reflink-capable filesystem the copy is a near-instant
        // block-level clone; otherwise it degrades to a full byte copy — reported
        // as `CowSupport`. The single-use `restore` path (`cow == false`) hands
        // the caller's dir to the backend directly, preserving its documented
        // in-place rewrite behavior.
        let (effective_dir, cow_support) = if cow {
            let clone_dir = tmp_dir.path().join("zygote-snapshot");
            // Materialize the private copy through the process-wide OverlayStore
            // seam (`env.overlay`, invariant S4 — one store for the whole process,
            // no second injection path). A full byte copy can be large, so run it
            // on a blocking thread — the store's methods are synchronous by design
            // (object-safe as `dyn`), and this keeps a big copy off the async
            // runtime, the same discipline the bare function used.
            let store = env.overlay.clone();
            let src = snapshot_dir.to_path_buf();
            let dst = clone_dir.clone();
            let support = tokio::task::spawn_blocking(move || store.clone_tree(&src, &dst))
                .await
                .map_err(|e| {
                    crate::error::Error::Io(std::io::Error::other(format!(
                        "overlay clone task panicked: {e}"
                    )))
                })??;
            (std::borrow::Cow::Owned(clone_dir), support)
        } else {
            (
                std::borrow::Cow::Borrowed(snapshot_dir),
                crate::reflink::CowSupport::FullCopy,
            )
        };

        let mut staged = Self::setup_env(vmid.vmid, tmp_dir.path(), &cfg, env).await?;

        info!("Restoring instance...");
        let mut instance = vmm
            .restore(&effective_dir, &cfg, &staged.res, &*env.cgroups)
            .await?;
        info!("Resuming instance...");
        instance.resume().await?;
        info!("Instance resumed.");
        staged.cgroup_guard.disarm();
        let vm = Self {
            vmid: Some(vmid),
            instance: Some(instance),
            netns: staged.netns.take(),
            segment: staged.segment.take(),
            #[cfg(feature = "net-unprivileged")]
            smoltcp: staged.smoltcp.take(),
            proxy: staged.proxy.take(),
            cgroup_name: Some(staged.res.cgroup_name.clone()),
            env: env.clone(),
            agent_client: None,
            restored: true,
            restore_reseed_applied: None,
            cid: staged.cid_guard.take(),
            tmp_dir: Some(tmp_dir),
            // M-ORCH-3: re-clamp at the orchestrator boundary. The builder/presets
            // clamp, but `Timeouts`' fields are `pub`, so a caller can mutate
            // `cfg.timeouts` after `build()` down to a busy-spin; clamping here
            // guarantees the connect/accept/grace cadences honor their floors.
            timeouts: cfg.timeouts.clamped(),
            control_plane_disabled: cfg.init.is_some(),
        };
        Ok((vm, cow_support))
    }

    /// Gets the agent client, connecting (and waiting for the connection) on
    /// first use.
    ///
    /// On the **first** call after a snapshot restore this also performs the
    /// one-shot guest resync — clock, CSPRNG reseed, and network identity (§8.2, Restore correctness: a restored VM is not a fresh VM);
    /// see `maybe_resync_after_restore` (private). The `restored` flag is cleared only
    /// after the mandatory clock resync succeeds, so a transient first-exec
    /// failure retries on the next call rather than permanently skipping the
    /// resync (M-RESTORE-1).
    ///
    /// # Panics
    /// Panics if the VM instance is missing.
    ///
    /// # Errors
    /// Returns an error if the agent connection or handshake fails or times out,
    /// or if the mandatory post-restore clock resync round-trip fails.
    pub async fn agent(
        &mut self,
        timeout: Option<std::time::Duration>,
    ) -> Result<&mut AgentClient> {
        // Fail loud, not hang: a custom `init=` (§5.3, The kernel command line) replaces the vmcell guest agent,
        // so there is no vsock control plane — no `Ready` handshake, `exec`, or resync.
        // Returning immediately here beats blocking for the full connect timeout on a
        // listener that will never answer (§13, Cross-cutting invariants, fail-loud).
        if self.control_plane_disabled {
            return Err(crate::error::Error::Agent(
                "the vsock control plane is unavailable: this VM boots a custom init= that \
                 replaces the vmcell guest agent (no Ready handshake, exec, or resync). Observe \
                 it via the serial log, a shared directory, an extra block device, or networking."
                    .into(),
            ));
        }
        if self.agent_client.is_none() {
            // Connect over the instance's own endpoint, so a snapshot-eligible QEMU
            // on the in-kernel AF_VSOCK transport (§2.4, QEMU q35 — the fallback and most-proven nester) is reached by CID while
            // CH/FC/QEMU-external stay on their AF_UNIX path — one connect law.
            let instance = self.instance.as_ref().expect("instance missing");
            let client = AgentClient::connect_endpoint(
                &instance.vsock_endpoint(),
                timeout.unwrap_or(std::time::Duration::from_secs(10)),
                &self.timeouts,
                &crate::vmm::RealSerialLog {
                    path: instance.serial_log().to_path_buf(),
                },
            )
            .await?;
            self.agent_client = Some(client);
        }

        if self.restored {
            // No explicit reconnect here: this `agent()` is the first call after
            // restore (agent_client started `None`), so the `connect()` above
            // already IS the post-restore connection. CH re-creates the vhost-vsock
            // device on `--restore`, so the guest's pre-snapshot listener goes deaf;
            // the guest agent re-binds its listener on idle (see `serve_vsock` in
            // vmcell-guest-agent), and `AgentClient::connect` retries with backoff
            // until that fresh listener accepts. A second, overlapping connect would
            // be redundant.
            let vmid = self.vmid.as_ref().expect("vmid missing").vmid;
            // The clock that drives the mandatory post-restore resync comes from the
            // `HostEnv` captured at construction (design §18, Delta register: changes from the validated v27 build, delta 1 — `agent()` no
            // longer takes a clock seam). Clone the `Arc` first so this immutable
            // borrow of `self.env` ends before `self.agent_client` is borrowed `&mut`.
            let clock = self.env.clock.clone();
            // The client is guaranteed present: it was cached above if `None`
            // (N-ORCH-1 — the prior `ok_or_else` error arm was unreachable).
            let client = self
                .agent_client
                .as_mut()
                .expect("agent_client was populated above");
            // M-RESTORE-1: clears `self.restored` only after the mandatory clock
            // resync succeeds, so a transient failure retries the full resync on the
            // next call instead of being silently dropped.
            if let Err(e) = maybe_resync_after_restore(
                &mut self.restored,
                &mut self.restore_reseed_applied,
                client,
                &*clock,
                vmid,
            )
            .await
            {
                // H-ORCH-2: a transient resync transport failure marks the cached
                // client desynced, and nothing ever auto-reconnects it — so leaving
                // it cached wedges *every* future `agent()` on `ensure_synced`.
                // Evict it here so the next call re-connects and retries the whole
                // resync, honoring the M-RESTORE-1 retry contract.
                self.agent_client = None;
                return Err(e);
            }
        }

        Ok(self
            .agent_client
            .as_mut()
            .expect("agent_client was populated above"))
    }

    /// Opens a fresh control-plane connection for **interactive sessions** — PTY /
    /// pipe sessions, streaming stdin, and multiplexed concurrent execs
    /// (§3.2, The host side: AgentClient and SessionMux) — returning a [`SessionMux`](crate::agent::session::SessionMux).
    ///
    /// This dials a *second* vsock connection to the guest agent, independent of
    /// the cached one-shot [`agent`](MicroVm::agent) client, so one-shot exec and
    /// sessions never share a stream. The returned mux owns that connection;
    /// dropping it closes the connection, and the guest tears down every session it
    /// opened (§13, Cross-cutting invariants). Takes `&self` (no caching) — a caller may hold several
    /// muxes if it wants isolated connections.
    ///
    /// # Panics
    /// Panics if the VM instance is missing (e.g. after shutdown).
    ///
    /// # Errors
    /// Returns an [`Error::Agent`](crate::error::Error::Agent) immediately when
    /// this VM boots a custom `init=` that replaces the guest agent (no control
    /// plane, §5.3, The kernel command line), or if the connection or `Ready` handshake does not complete
    /// within `timeout`.
    pub async fn connect_sessions(
        &self,
        timeout: Option<std::time::Duration>,
    ) -> Result<crate::agent::session::SessionMux> {
        if self.control_plane_disabled {
            return Err(crate::error::Error::Agent(
                "the vsock control plane is unavailable: this VM boots a custom init= that \
                 replaces the vmcell guest agent (no interactive sessions). Observe it via the \
                 serial log, a shared directory, an extra block device, or networking."
                    .into(),
            ));
        }
        let instance = self.instance.as_ref().expect("instance missing");
        crate::agent::session::SessionMux::connect_endpoint(
            &instance.vsock_endpoint(),
            timeout.unwrap_or(std::time::Duration::from_secs(10)),
            &self.timeouts,
            &crate::vmm::RealSerialLog {
                path: instance.serial_log().to_path_buf(),
            },
        )
        .await
    }

    /// Dials a **raw byte stream** to a guest AF_VSOCK listener on `port`
    /// (§3.2, The host side: AgentClient and SessionMux — the raw vsock dial), returning a
    /// [`VsockDial`](crate::agent::VsockDial). The guest process on the other end
    /// owns its own protocol: no framing, no `Ready` handshake, no guest agent.
    ///
    /// **Independent of the control plane, by design.** Unlike [`agent`](Self::agent)
    /// and [`connect_sessions`](Self::connect_sessions), this does *not* refuse when
    /// a custom `init=` replaced the guest agent (§5.3, The kernel command line): the vsock
    /// **device** is attached unconditionally on every backend — CH's `vsock` create
    /// payload field, Firecracker's `PUT /vsock`, QEMU's device/daemon block, and
    /// crosvm's `--vsock cid=` are all straight-line, none reads `cfg.init` — so a
    /// custom-init guest that binds a vsock port is reachable even though the agent
    /// is absent. That is precisely FR-V3's cheapest shape: an in-guest listener
    /// reachable from the host with no IP stack, on every backend and both operating
    /// modes.
    ///
    /// The endpoint is re-derived from the instance on every call (its port
    /// overridden with `port`), never cached: Firecracker's restore replaces the
    /// instance's vsock path with the snapshot's baked one, so a cached endpoint
    /// would go stale across a restore.
    ///
    /// Three caveats (§3.2, The host side: AgentClient and SessionMux):
    /// - **A host half-close is not portable.** `VsockDial::shutdown()` forwards to
    ///   the guest on Cloud Hypervisor and crosvm, but on Firecracker and QEMU it
    ///   tears the connection down and silently discards a reply the guest had not
    ///   yet flushed. Drain the reply before half-closing; the per-backend
    ///   measurements and the portable protocol rule are on
    ///   [`VsockDial`](crate::agent::VsockDial), stated once there.
    /// - A *user* listener gets no post-restore re-bind service. Only the guest
    ///   agent re-binds after a restore re-creates the vhost-vsock device
    ///   (§3.4, The guest: vmcell-guest-agent as PID 1), so dial afresh after a restore.
    /// - On the non-rotating backends (Firecracker, crosvm — `restore_rotates_host_paths`
    ///   false, §2.6, The capability matrix) the endpoint after a restore is the **baked**
    ///   path/CID, exactly as the agent connect already handles.
    ///
    /// # Panics
    /// Panics if the VM instance is missing (e.g. after shutdown).
    ///
    /// # Errors
    /// Fails **fast and typed** rather than retrying — the caller already brought
    /// this VM up, so "nobody listens on that port" is an answer, not a reason to
    /// wait: [`Error::Agent`](crate::error::Error::Agent) naming the port when the
    /// vsock bridge closes the connection without an `OK` line (the CH/FC in-VMM
    /// muxer's dead-port signal), [`Error::Timeout`](crate::error::Error::Timeout)
    /// naming the port when a bridge accepts the `CONNECT` and never answers
    /// (bounded by `Timeouts::connect_ok_read`) or when the whole dial exceeds
    /// `timeout`, and [`Error::Io`](crate::error::Error::Io) — errno intact — when
    /// the transport socket cannot be opened, which on the AF_VSOCK transport is the
    /// kernel's own connect error for a port with no guest listener.
    pub async fn dial_vsock(
        &self,
        port: u32,
        timeout: std::time::Duration,
    ) -> Result<crate::agent::VsockDial> {
        let instance = self.instance.as_ref().expect("instance missing");
        crate::agent::VsockDial::connect_endpoint(
            &instance.vsock_endpoint(),
            port,
            timeout,
            &self.timeouts,
        )
        .await
    }

    /// Whether the one-shot post-restore CSPRNG reseed actually applied (the
    /// `ResyncAck.reseed_applied` ack field) on the first post-restore
    /// [`MicroVm::agent`] call.
    ///
    /// `None` before that resync has run; `Some(true)` when the reseed (the native
    /// in-agent `/dev/hwrng`→`/dev/urandom` 32-byte copy) succeeded; `Some(false)`
    /// when the best-effort reseed could not be applied. A restore test asserts
    /// `Some(true)` instead of inferring the reseed from two `/dev/urandom` reads
    /// differing (which can pass coincidentally even when the reseed silently
    /// failed).
    #[must_use]
    pub fn restore_reseed_applied(&self) -> Option<bool> {
        self.restore_reseed_applied
    }

    /// Retrieves resource usage metrics for the VM.
    ///
    /// # Errors
    /// Returns an error if metrics collection fails.
    pub async fn usage(&self) -> Result<ResourceUsage> {
        if let Some(cg_name) = &self.cgroup_name {
            self.env.cgroups.read_stats(cg_name)
        } else {
            // No cgroup is attached, so no requested limit is being enforced —
            // surface that honestly (`mem_limit_enforced: false`) rather than handing
            // back an all-zero usage that implies a measured, enforced state
            // (§7.1, What is read and enforced, rule 3 / H-FAILLOUD-1). `ResourceUsage::default()` already has
            // the flag `false`; spell it out so the intent cannot silently drift.
            Ok(ResourceUsage {
                mem_limit_enforced: false,
                ..ResourceUsage::default()
            })
        }
    }

    /// Pauses the running VM.
    ///
    /// Promoted to a first-class `MicroVm` method in v15 (§9.3, The public API surface) — previously
    /// reachable only via the raw instance accessor (now `pub(crate)`, delta 6) — so
    /// the library, CLI, and daemon share one lifecycle-verb surface. Required before
    /// [`MicroVm::snapshot`] when driving the pause→snapshot→resume cycle by hand.
    ///
    /// # Errors
    /// Returns an error if the backend fails to pause the VM.
    pub async fn pause(&mut self) -> Result<()> {
        self.instance_mut().pause().await
    }

    /// Resumes a paused VM (after [`MicroVm::pause`] or a snapshot restore).
    ///
    /// Promoted to a first-class `MicroVm` method in v15 (§9.3, The public API surface).
    ///
    /// # Errors
    /// Returns an error if the backend fails to resume the VM.
    pub async fn resume(&mut self) -> Result<()> {
        self.instance_mut().resume().await
    }

    /// Writes a snapshot of the VM into `dir` (the backend pauses internally, writes
    /// the snapshot, then resumes).
    ///
    /// Promoted to a first-class `MicroVm` method in v15 (§9.3, The public API surface). Snapshot-eligible
    /// VMs only: a vhost-user device (virtio-fs data share or unprivileged net) is
    /// rejected at `VmConfig::build()` (the §2.5, The capability matrix, law), and a backend that does not
    /// advertise `snapshot_restore` returns [`crate::error::Error::Unsupported`].
    ///
    /// On success, any cached agent connection is invalidated: the next
    /// [`MicroVm::agent`] call transparently reconnects, so the resumed VM
    /// stays usable on every backend at the cost of at most one cheap
    /// reconnect.
    ///
    /// # Errors
    /// Returns an error if the backend fails to snapshot,
    /// [`crate::error::Error::Unsupported`] on a backend without snapshot support, or
    /// [`crate::error::Error::Unsupported`] when this VM boots a custom `init=` (its restored
    /// clones could never run the mandatory post-restore resync).
    pub async fn snapshot(&mut self, dir: &std::path::Path) -> Result<()> {
        // docs/78 M2: refuse to *write* an image whose restore can never be correct. A custom
        // `init=` replaces the vmcell guest agent, so the mandatory post-restore resync (clock,
        // CSPRNG reseed, MAC/IP rotation, §8.2) is structurally unreachable for every clone minted
        // from this image. `build()` rejects `init` + `snapshotting`, but a VM built WITHOUT
        // `snapshotting` can still reach this method (and `Zygote::suspend` routes straight
        // through it), so the eligibility law needs its guard at this boundary too — the earliest
        // point that refuses the bad artifact instead of the N restores of it.
        // `control_plane_disabled` is the retained `cfg.init.is_some()`; the config-only arms live
        // in `clone_ineligible_feature`, which needs a `VmConfig` a live `MicroVm` no longer owns.
        if self.control_plane_disabled {
            return Err(crate::error::Error::Unsupported {
                // Not a backend refusal: this boundary is the orchestrator's own eligibility law
                // (the `zygote`/`in-process-virtiofsd` precedent — a non-backend boundary names
                // itself rather than blaming the VMM).
                vmm: "orchestrator".to_string(),
                feature: "snapshot of a VM with a custom init (VmConfig::init) that replaces the \
                          guest agent — the mandatory post-restore resync (§8.2) needs it"
                    .to_string(),
            });
        }
        self.instance_mut().snapshot(dir).await?;
        // Firecracker severs established vsock connections across its internal
        // pause/snapshot/resume cycle (Cloud Hypervisor keeps them alive), so a
        // cached `AgentClient` on the resumed VM would fail its very next
        // request with "Connection dropped". Invalidate uniformly: it costs at
        // most one cheap reconnect on the next `agent()` call — the guest
        // listener accepts it, since the accept loop is independent of the
        // severed per-connection fd — and makes the post-snapshot VM usable on
        // every backend instead of only CH. On an `Err` above we leave the
        // client alone (the `?` returns early): the snapshot didn't happen, so
        // the connection state is whatever it already was.
        self.agent_client = None;
        Ok(())
    }

    /// Releases every per-VM resource that must be torn down **after** the VMM
    /// instance, in the one canonical order:
    /// smoltcp NAT → egress proxy → netns → cgroup → CID → VMID → scratch dir.
    ///
    /// Both [`shutdown`](Self::shutdown) (after the graceful async
    /// `request_shutdown` + `kill`) and [`Drop`] route through this single
    /// helper so the two teardown paths **cannot diverge** (ORCH-2): the old
    /// `shutdown()` deleted the netns *before* dropping the egress proxy, which
    /// on the privileged path runs *inside* that netns — removing a netns while
    /// a process still holds interfaces/sockets in it hangs or leaks (the
    /// AGENTS.md teardown-order invariant). Every field is `take()`n, so a
    /// second call (e.g. `Drop` running after `shutdown()` already ran) is a
    /// no-op.
    fn teardown_post_instance(&mut self) {
        // The egress proxy and the smoltcp NAT hold sockets/threads INSIDE the netns, so they are
        // released before the netns is deleted — through the SAME shared helper `EnvSetup`'s Drop
        // uses (delta 7), so the success and mid-`start()` error paths cannot diverge on this order.
        release_net_before_netns(
            &mut self.proxy,
            #[cfg(feature = "net-unprivileged")]
            &mut self.smoltcp,
            &mut self.netns,
            &mut self.segment,
        );
        // The cgroup backend lives on the captured `HostEnv` (no longer a standalone
        // `cgroup_fs` field); `cgroup_name.take()` is the once-only guard so a second
        // teardown (Drop after shutdown) is a no-op.
        // A failed delete leaves a live slice keyed by this vmid, which the orphan sweep only
        // reclaims on the next process start-up — so it is warned like every sibling teardown
        // site (`CgroupGuard::drop`, `sweep_orphans`), never silently discarded (docs/78 §6,
        // `teardown-cgroup-delete-silently-discarded`). Teardown is still best-effort: the
        // failure is not propagated (`Drop` cannot, and `shutdown()` guarantees teardown
        // regardless, M-ORCH-2).
        if let Some(cg_name) = self.cgroup_name.take()
            && let Err(e) = self.env.cgroups.delete_slice(&cg_name)
        {
            tracing::warn!("failed to delete cgroup slice {}: {}", cg_name, e);
        }
        drop(self.cid.take());
        drop(self.vmid.take());
        // The per-VM scratch dir goes LAST: the instance (VMM process group +
        // virtiofsd/vhost-vsock daemons) and the smoltcp process — all dropped
        // above — own sockets that live inside it, so removing it any earlier
        // would race a live process still holding a socket there.
        drop(self.tmp_dir.take());
    }

    /// Shuts down the VM and cleans up associated resources.
    ///
    /// # Errors
    /// Currently always returns `Ok(())`. The graceful `request_shutdown` and the
    /// `kill` fallback are best-effort and their failures are **logged**, not
    /// propagated (M-ORCH-2): teardown is guaranteed by
    /// `teardown_post_instance` (private) and `Drop`
    /// regardless of either RPC's outcome, so surfacing an error would offer the
    /// caller no additional recovery. The `Result` return is retained so a future
    /// fallible-teardown step can be added without a signature break.
    pub async fn shutdown(mut self) -> Result<()> {
        if let Some(mut inst) = self.instance.take() {
            // ORCH-7: give the guest a bounded grace window to flush and power off
            // after the shutdown request, before the SIGKILL fallback — an immediate
            // `kill()` grants ~0 flush time. The window opens at RPC-*send*, with a
            // one-poll-step post-ack floor (the clamp below): the deadline is
            // computed BEFORE `request_shutdown`, so the RPC's own round trip
            // spends the grace instead of silently extending it. Rather than
            // *always* sleeping the whole window (the placeholder ORCH-7 shipped),
            // poll the now-realized `VmInstance::has_exited` and return as soon as
            // the guest has actually powered off, capping at
            // `self.timeouts.shutdown_grace`. The force-kill below is still the
            // guaranteed fallback for a guest that never exits on its own.
            let poll_step = shutdown_poll_step(self.timeouts.shutdown_grace);
            let mut grace_deadline = tokio::time::Instant::now() + self.timeouts.shutdown_grace;
            // Best-effort: an already-powered-off guest fails this benignly, so a
            // failure is logged at debug (not surfaced) — the force-kill below is
            // the guarantee (M-ORCH-2).
            if let Err(e) = inst.request_shutdown().await {
                tracing::debug!("graceful shutdown request failed (will force-kill): {}", e);
            }
            // Post-ack floor: the shutdown RPC has no timeout
            // (`vmm::unix_api_request`), so an RPC stalled for >= the grace would
            // arrive here with the deadline already past and skip the poll loop
            // entirely — ~0 post-ack flush time, the exact anti-pattern the ORCH-7
            // grace exists to prevent. Clamping the deadline to now + one poll
            // step guarantees >= 1 `has_exited` check after the guest acknowledged
            // the shutdown.
            grace_deadline = grace_deadline.max(tokio::time::Instant::now() + poll_step);
            while tokio::time::Instant::now() < grace_deadline {
                if inst.has_exited().await {
                    break;
                }
                tokio::time::sleep(poll_step).await;
            }

            // Force-kill + reap the process group so no zombie/EBUSY blocks the
            // netns teardown below. This is the guaranteed fallback, so a failure
            // is a genuine concern — log at warn (M-ORCH-2). `Drop` still runs the
            // ordered teardown regardless.
            if let Err(e) = inst.kill().await {
                tracing::warn!("force-kill during shutdown failed: {}", e);
            }
            // Instance fully torn down here (end of scope) BEFORE the shared
            // post-instance teardown deletes the netns it held interfaces in.
        }

        // ORCH-2: everything after the instance goes through the ONE shared
        // ordered helper, so `shutdown()` and `Drop` cannot diverge — in
        // particular the proxy/smoltcp NAT are released before the netns.
        self.teardown_post_instance();
        Ok(())
    }
}

impl<V: Vmm> Drop for MicroVm<V> {
    fn drop(&mut self) {
        // Teardown order: VMM instance (process group + virtiofsd/vhost-vsock
        // daemons) FIRST, then the shared post-instance teardown
        // (proxy/smoltcp → netns → cgroup → cid → vmid → scratch dir). Routing
        // through the same helper as `shutdown()` keeps the two paths identical
        // (ORCH-2).
        drop(self.instance.take());
        self.teardown_post_instance();
    }
}

/// The **one** config-only snapshot-eligibility predicate (§13, Cross-cutting invariants).
///
/// Returns the offending feature when `cfg` can never take part in a snapshot/restore cycle, and
/// `None` when it is eligible; the caller wraps the returned fragment in its own typed
/// [`Error::Unsupported`](crate::error::Error::Unsupported). This is the designated home for the
/// arms `MicroVm::restore_inner`'s boundary-2 re-check and the zygote fan-out's fail-fast gate
/// (`zygote::check_clone_eligible`) had open-coded twice — the pair had already needed lock-step
/// edits and had drifted arm-for-arm (docs/78 S1), and every new arm (custom init, host USB) would
/// have been a third copy. **Both boundaries now read this function**, so an arm can never reach
/// one and miss the other; the drift it was extracted from is exactly what let a custom-init
/// config be fanned out into clones whose mandatory resync is unreachable.
///
/// **Config-only by construction**: it takes nothing but a `&VmConfig`, so it runs before any
/// per-VM resource — or any copy-on-write clone of a suspend image — is minted. The
/// resources-in-hand checks stay at their own boundaries.
///
/// The fragments name the `VmConfig` field they refuse (§7.2, capability honesty: a typed refusal
/// names the feature it is about, not a paraphrase), so a caller matching on the message can tell
/// which input to drop.
pub(crate) fn clone_ineligible_feature(cfg: &VmConfig) -> Option<&'static str> {
    if matches!(cfg.net, crate::config::NetConfig::Unprivileged { .. }) {
        // A vhost-user-net device is not migratable, so it is not snapshot-eligible.
        return Some("unprivileged (vhost-user-net) networking");
    }
    // §6.5 (VM-to-VM segments): restore-time slot/addressing semantics for a member are
    // unspecified in v30, so a restore onto a segment is a typed capability refusal, not a
    // silently mis-addressed member — and a fan-out would dual-claim one member slot besides.
    // `build()` already refuses the pair; this is what a hand-built config cannot slip past.
    if matches!(cfg.net, crate::config::NetConfig::Segment { .. }) {
        return Some("vm-to-vm segment membership (§6.5)");
    }
    // A virtio-fs data share is served by virtiofsd (a vhost-user device), which a
    // snapshot-eligible VM must not attach (§12.1). Enforced in code, not just docs.
    if !cfg.shares.is_empty() {
        return Some("a virtio-fs data share (vhost-user device)");
    }
    // docs/78 M2: a custom `init=` REPLACES the vmcell guest agent, and the mandatory
    // post-restore resync — clock, CSPRNG reseed, MAC/IP rotation (§8.2) — runs *through* that
    // agent. `build()` rejects `init` + `snapshotting`, but nothing rejected *restoring* (or
    // fanning out) such a config: the clone would come up on a frozen clock with a correlated
    // CSPRNG and a stale MAC/IP, and `agent()` fails loud, so the resync is structurally
    // unreachable. Config-only and identical at both boundaries, hence an arm here.
    if cfg.init.is_some() {
        return Some("a custom init (VmConfig::init) that replaces the guest agent");
    }
    // docs/78 M4: a passed-through host USB device is host state living OUTSIDE guest RAM — the
    // migration stream carries the guest's view of the xhci controller but not the device behind
    // it. `build()` rejects `usb_host_devices` + `snapshotting`, but the delta-9 premise that
    // "every backend's `restore()` rejects a non-snapshotting config" is empirically FALSE (no
    // backend's `restore()` reads `cfg.snapshotting`), so a `{InKernel, snapshotting: false}`
    // config carrying USB devices reached restore with the USB argv and without the backends'
    // `require_usb_host_devices` precheck (QEMU) or was silently dropped (CH/FC/crosvm). The law
    // is config-only and boundary-independent — a host USB device is no more restorable than it
    // is snapshottable, and a zygote over one would fan out N guests fighting over one device —
    // so it belongs in the shared predicate rather than beside it.
    if !cfg.usb_host_devices.is_empty() {
        return Some("host USB passthrough (VmConfig::usb_host_devices)");
    }
    None
}

/// Derives `shutdown()`'s `has_exited` poll cadence from the configured grace
/// ceiling: <= 50 ms -> 5 ms, <= 150 ms -> 10 ms, else 20 ms. A short
/// `throughput`-profile grace (50 ms) on the old fixed 20 ms grid quantized up
/// to ~60 ms even when ceiling-bound, and an in-window exit paid up to 20 ms of
/// detection latency; the 5 ms floor is at most ~10 wakeups in a 50 ms window —
/// finer detection, not a busy-spin. (Deliberate deviation from the §9.4, Timeouts
/// and the lifecycle nuances "the poll step stays 20 ms" note — recorded in `implementation-notes.md`.)
fn shutdown_poll_step(grace: std::time::Duration) -> std::time::Duration {
    use std::time::Duration;
    if grace <= Duration::from_millis(50) {
        Duration::from_millis(5)
    } else if grace <= Duration::from_millis(150) {
        Duration::from_millis(10)
    } else {
        Duration::from_millis(20)
    }
}

/// Parses the trailing id from a vmcell resource identifier — the last `-`-separated numeric
/// token. Works for every vmcell resource name: `vmcell-net-<vmid>`, a `vmcell-vm-<vmid>` cgroup
/// slice (even nested under a `<base>/…` prefix), a `vmcell-vm-<pid>-<vmid>` scratch dir, and a
/// `vmcell-seg-<segid>` segment namespace. Returns `None` when the tail is not a `u32`, so a
/// foreign entry is never swept.
///
/// Deliberately **id-space-neutral** in name (it was `trailing_vmid`): it parses
/// `vmcell-seg-7` as `7` exactly as happily as `vmcell-net-7`, so the *caller* must check each
/// class against its own live set. Checking a segid against live vmids fails **open** — a dead
/// segid colliding with a live vmid would never be reclaimed (§6.5, law F2).
fn trailing_id(name: &str) -> Option<u32> {
    name.rsplit('-').next()?.parse().ok()
}

/// Read-only enumeration seam for the orphan sweeper ([`sweep_orphans`]).
///
/// A hard crash (SIGKILL/OOM) bypasses [`MicroVm`]'s `Drop`, leaking
/// host-global resources keyed by vmid — network namespaces, per-VM cgroup
/// slices, and per-VM scratch directories — that a later vmid then collides
/// with (ORCH-6, a standing B1 gap: teardown was previously RAII-only). The
/// sweeper lists candidates through this trait so it can be exercised with a
/// recording fake (no privileged host state); removal then goes through the
/// injected [`Netlink`](crate::net::tap::Netlink)/[`CgroupFs`](crate::metrics::CgroupFs)
/// seams so only non-live ids are reclaimed, in the canonical teardown order.
pub trait OrphanScanner: Send + Sync {
    /// Names of every network namespace matching the `vmcell-net-*` prefix.
    fn scan_netns(&self) -> Vec<String>;
    /// Names of every **segment** namespace matching the `vmcell-seg-*` prefix (§6.5).
    ///
    /// A separate method, not a merge into [`OrphanScanner::scan_netns`], because the two classes
    /// are liveness-checked against **different id spaces** — segids here, vmids there.
    fn scan_segment_netns(&self) -> Vec<String>;
    /// Names (paths relative to the cgroup-v2 root, as [`CgroupFs`](crate::metrics::CgroupFs)
    /// expects) of every per-VM cgroup slice matching `vmcell-vm-*`.
    fn scan_cgroup_slices(&self) -> Vec<String>;
    /// Per-VM scratch directories whose basename matches `vmcell-vm-*`.
    fn scan_scratch_dirs(&self) -> Vec<std::path::PathBuf>;
}

/// The production [`OrphanScanner`]: enumerates `/var/run/netns`, the cgroup-v2
/// mount at `/sys/fs/cgroup`, and the per-VM scratch base
/// ([`std::env::temp_dir`]).
///
/// Host-facing (privileged) — this real path reads privileged host state and is
/// **correct-by-construction, not KVM/privilege-validated here**; the unit tests
/// drive [`sweep_orphans`] through a recording fake instead. Deeply-nested
/// delegated cgroup slices are found by a bounded recursive walk.
///
/// Matches names by the **same prefix** the VM naming uses ([`crate::naming`]) — an operator running
/// `vmcelld --resource-prefix acme` sweeps `acme-*`, never `vmcell-*` from another tool. Build it with
/// [`HostOrphanScanner::new`] (the default prefix reproduces the historical `vmcell-*` behavior).
#[derive(Debug, Clone)]
pub struct HostOrphanScanner {
    /// The resource prefix; netns are matched by `<prefix>-net-`, cgroup slices and scratch dirs by
    /// `<prefix>-vm-`.
    prefix: String,
}

impl Default for HostOrphanScanner {
    fn default() -> Self {
        Self::new(crate::naming::DEFAULT_RESOURCE_PREFIX)
    }
}

impl HostOrphanScanner {
    /// Builds a scanner that matches resources named with `prefix` (§13, Cross-cutting invariants). Use
    /// [`crate::naming::DEFAULT_RESOURCE_PREFIX`] for the historical `vmcell-*` names.
    #[must_use]
    pub fn new(prefix: impl Into<String>) -> Self {
        Self {
            prefix: prefix.into(),
        }
    }

    /// Bounded recursive walk of the cgroup-v2 tree under `root`, collecting the paths (relative to
    /// `/sys/fs/cgroup`) of directories named `<vm_prefix>*` (`vm_prefix` = `<prefix>-vm-`).
    fn walk_cgroup_slices(
        vm_prefix: &str,
        root: &std::path::Path,
        rel: &str,
        depth: u8,
        out: &mut Vec<String>,
    ) {
        if depth == 0 {
            return;
        }
        let Ok(entries) = std::fs::read_dir(root) else {
            return;
        };
        for entry in entries.flatten() {
            if !entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                continue;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            let child_rel = if rel.is_empty() {
                name.clone()
            } else {
                format!("{rel}/{name}")
            };
            if name.starts_with(vm_prefix) {
                out.push(child_rel);
                // A per-VM slice has no matching children; no need to descend.
                continue;
            }
            Self::walk_cgroup_slices(vm_prefix, &entry.path(), &child_rel, depth - 1, out);
        }
    }
}

impl OrphanScanner for HostOrphanScanner {
    fn scan_netns(&self) -> Vec<String> {
        let netns_prefix = crate::naming::netns_sweep_prefix(&self.prefix);
        let Ok(dir) = std::fs::read_dir("/var/run/netns") else {
            return Vec::new();
        };
        dir.flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with(&netns_prefix))
            .collect()
    }

    fn scan_segment_netns(&self) -> Vec<String> {
        let seg_prefix = crate::naming::segment_netns_sweep_prefix(&self.prefix);
        let Ok(dir) = std::fs::read_dir("/var/run/netns") else {
            return Vec::new();
        };
        dir.flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with(&seg_prefix))
            .collect()
    }

    fn scan_cgroup_slices(&self) -> Vec<String> {
        let vm_prefix = crate::naming::vm_resource_sweep_prefix(&self.prefix);
        let mut out = Vec::new();
        Self::walk_cgroup_slices(
            &vm_prefix,
            std::path::Path::new("/sys/fs/cgroup"),
            "",
            4,
            &mut out,
        );
        out
    }

    fn scan_scratch_dirs(&self) -> Vec<std::path::PathBuf> {
        let vm_prefix = crate::naming::vm_resource_sweep_prefix(&self.prefix);
        let base = std::env::temp_dir();
        let Ok(dir) = std::fs::read_dir(&base) else {
            return Vec::new();
        };
        dir.flatten()
            .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
            .map(|e| e.path())
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with(&vm_prefix))
            })
            .collect()
    }
}

/// What a [`sweep_orphans`] pass reclaimed, returned for logging and tests.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SweepReport {
    /// Per-VM network namespaces removed (in sweep order).
    pub netns: Vec<String>,
    /// **Segment** namespaces removed (in sweep order, §6.5) — reclaimed against live *segids*,
    /// never live vmids.
    pub segment_netns: Vec<String>,
    /// Cgroup slices removed (in sweep order).
    pub cgroup_slices: Vec<String>,
    /// Per-VM scratch directories removed (in sweep order).
    pub scratch_dirs: Vec<std::path::PathBuf>,
}

/// Reclaims orphaned per-VM host resources left by a crashed run (ORCH-6).
///
/// Enumerates candidates through the injected [`OrphanScanner`] and removes each
/// one whose trailing id is **not** live in **its own id space** — per-VM namespaces, cgroup
/// slices, and scratch dirs against `live_vmids`; segment namespaces (§6.5) against
/// `live_segids` — so a resource still owned by a running VM or segment is never swept, through
/// the injected
/// [`Netlink`](crate::net::tap::Netlink) (netns) and
/// [`CgroupFs`](crate::metrics::CgroupFs) (cgroup slice) seams, plus a direct
/// scratch-dir `remove_dir_all`. Removal follows the canonical teardown order —
/// **netns → cgroup → scratch dir** (an orphan has no live instance or proxy, so
/// that is the relevant tail of the AGENTS.md order). Returns a [`SweepReport`]
/// of what was reclaimed. Intended to run once at process/suite start (a leaked
/// netns collides with a later vmid: `netns add … Operation not permitted`).
///
/// The real host paths (netns delete, cgroup rmdir) are privileged and are
/// **not** KVM/privilege-validated here; the unit tests exercise the ordering,
/// live-skip, and per-seam delegation through recording fakes.
pub fn sweep_orphans(
    scanner: &dyn OrphanScanner,
    netlink: &dyn crate::net::tap::Netlink,
    cgroup_fs: &dyn crate::metrics::CgroupFs,
    live_vmids: &std::collections::BTreeSet<u32>,
    live_segids: &std::collections::BTreeSet<u32>,
) -> SweepReport {
    let mut report = SweepReport::default();

    for name in scanner.scan_netns() {
        let Some(vmid) = trailing_id(&name) else {
            continue;
        };
        if live_vmids.contains(&vmid) {
            continue; // still owned by a live VM — never sweep it
        }
        match netlink.delete_netns(&name) {
            Ok(()) => report.netns.push(name),
            Err(e) => tracing::warn!("sweep_orphans: failed to delete netns {}: {}", name, e),
        }
    }

    // §6.5 (VM-to-VM segments): the `-seg-` class against its OWN id space. Checking it against
    // `live_vmids` would fail open — a leaked segid that happens to equal a live vmid would be
    // spared forever, and a live segment whose id equals no live vmid would be destroyed under
    // its members.
    for name in scanner.scan_segment_netns() {
        let Some(segid) = trailing_id(&name) else {
            continue;
        };
        if live_segids.contains(&segid) {
            continue;
        }
        match netlink.delete_netns(&name) {
            Ok(()) => report.segment_netns.push(name),
            Err(e) => tracing::warn!(
                "sweep_orphans: failed to delete segment netns {}: {}",
                name,
                e
            ),
        }
    }

    for name in scanner.scan_cgroup_slices() {
        let Some(vmid) = trailing_id(&name) else {
            continue;
        };
        if live_vmids.contains(&vmid) {
            continue;
        }
        match cgroup_fs.delete_slice(&name) {
            Ok(()) => report.cgroup_slices.push(name),
            Err(e) => {
                tracing::warn!(
                    "sweep_orphans: failed to delete cgroup slice {}: {}",
                    name,
                    e
                );
            }
        }
    }

    for dir in scanner.scan_scratch_dirs() {
        let Some(vmid) = dir
            .file_name()
            .and_then(|n| n.to_str())
            .and_then(trailing_id)
        else {
            continue;
        };
        if live_vmids.contains(&vmid) {
            continue;
        }
        match std::fs::remove_dir_all(&dir) {
            Ok(()) => report.scratch_dirs.push(dir),
            // Already gone (a racing Drop reclaimed it) is success, not a leak.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => report.scratch_dirs.push(dir),
            Err(e) => tracing::warn!(
                "sweep_orphans: failed to remove scratch dir {}: {}",
                dir.display(),
                e
            ),
        }
    }

    report
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_allocate_vmid() {
        let alloc = VmidAllocator::new();
        let vmid1 = alloc.allocate().unwrap();
        let vmid2 = alloc.allocate().unwrap();
        assert_ne!(vmid1, vmid2);
        assert!((1..=254).contains(&vmid1));
        alloc.release(vmid1);
        alloc.release(vmid2);
    }

    #[test]
    fn test_allocate_vmid_exhaustion() {
        let alloc = VmidAllocator::new();
        let mut vmids = Vec::new();
        while let Ok(id) = alloc.allocate() {
            vmids.push(id);
        }
        assert!(alloc.allocate().is_err());
        for id in vmids {
            alloc.release(id);
        }
    }

    // CONFIG-ERROR-ORCH-6. Buggy impl: a process-global `/tmp/vmcell-vmid-*.lock`
    // namespace couples two in-process allocators, so exhausting one (or a
    // leaked lock from a crashed run) would make the other fail to allocate.
    #[test]
    fn test_vmid_allocators_are_independent() {
        let a = VmidAllocator::new();
        let b = VmidAllocator::new();
        // Exhaust `a` entirely.
        while a.allocate().is_ok() {}
        assert!(a.allocate().is_err());
        // `b` must be completely unaffected.
        let mut from_b = Vec::new();
        for _ in 0..254 {
            from_b.push(
                b.allocate()
                    .expect("independent allocator must not be coupled"),
            );
        }
        assert_eq!(from_b.len(), 254);
    }

    // H-ORCH-4: the cross-process lock dir is now injectable (`shared_at`), so the
    // claim/reclaim path is testable at all. A live cross-process owner blocks the
    // claim; releasing frees it. (On unmodified code there is no seam to inject a
    // hermetic dir, so this test cannot even be written against `shared()`.)
    #[test]
    fn shared_at_conflict_between_live_owners() {
        let dir = tempfile::tempdir().expect("tempdir");
        let a = VmidAllocator::shared_at(dir.path());
        let b = VmidAllocator::shared_at(dir.path());
        assert_eq!(a.reserve(9).expect("a claims 9"), 9);
        // `b` has a distinct in-process set; only the fs lock rejects it, and only
        // because our pid is alive.
        assert!(
            matches!(b.reserve(9), Err(crate::error::Error::Exhaustion(_))),
            "a live cross-process owner must block the claim"
        );
        a.release(9);
        assert_eq!(b.reserve(9).expect("b claims after release"), 9);
        b.release(9);
    }

    // H-ORCH-4: an EMPTY lock (a process that crashed between the old non-atomic
    // create and its separate pid-write) must be reclaimable — RED on the old
    // code, which required a parseable pid to reclaim and so leaked that vmid
    // forever. A dead owner's lock is likewise reclaimable, and a successful claim
    // leaves a parseable pid (the atomic create-with-content).
    #[test]
    fn shared_at_reclaims_empty_and_dead_locks() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path();

        std::fs::write(path.join("5.lock"), b"").expect("seed empty lock");
        // Drives the EXTRACTED claim core directly (v30 §18 delta 8): `VmidAllocator` and
        // `SegmentIdAllocator` both route through it, so this one gate covers both id spaces.
        let a = FsIdClaim {
            dir: Some(path.to_path_buf()),
        };
        assert!(
            a.try_claim(5),
            "an empty (crashed-mid-claim) lock must reclaim"
        );
        let content = std::fs::read_to_string(path.join("5.lock")).unwrap();
        assert_eq!(
            content.trim().parse::<u32>().unwrap(),
            std::process::id(),
            "a claimed lock must carry the owner pid atomically"
        );

        // `/proc/4294967295` can never exist, so this owner is definitively dead.
        std::fs::write(path.join("6.lock"), u32::MAX.to_string()).unwrap();
        let b = FsIdClaim {
            dir: Some(path.to_path_buf()),
        };
        assert!(b.try_claim(6), "a dead owner's lock must be reclaimable");
    }

    // v30 §18 delta 8: BOTH allocators claim through the one extracted core, in their OWN lock
    // directories. Buggy impl guarded: a `SegmentIdAllocator` that skipped the cross-process claim
    // (an in-process-only set) hands out an id another process already holds — the assertion that
    // a live-owner lock blocks it reddens. The positive control is the neighbouring id.
    #[test]
    fn both_allocators_claim_through_the_one_cross_process_core() {
        let vmid_dir = tempfile::tempdir().expect("tempdir");
        let segid_dir = tempfile::tempdir().expect("tempdir");

        // Seed a lock owned by a LIVE process (ourselves) in each id space.
        std::fs::write(
            vmid_dir.path().join("1.lock"),
            std::process::id().to_string(),
        )
        .unwrap();
        std::fs::write(
            segid_dir.path().join("1.lock"),
            std::process::id().to_string(),
        )
        .unwrap();

        let vmids = VmidAllocator::shared_at(vmid_dir.path());
        assert!(
            vmids.reserve(1).is_err(),
            "a live owner's vmid lock must block the claim"
        );
        assert!(
            vmids.reserve(2).is_ok(),
            "positive control: a free vmid claims"
        );

        // A fixed seed clock, so the two allocators below start their search at the same place and
        // the reclaim assertion is about the lock file, not about where the scan began.
        let seed = || -> Arc<dyn Clock + std::panic::RefUnwindSafe> {
            Arc::new(FakeClock {
                time: std::time::UNIX_EPOCH + std::time::Duration::new(11, 123_456_789),
            })
        };
        let segids = SegmentIdAllocator::shared_at(segid_dir.path()).with_seed_clock(seed());
        let first = segids.allocate().expect("a free segid must allocate");
        assert_ne!(
            first, 1,
            "segid 1 is held by a live owner and must be skipped"
        );
        assert!(
            segid_dir.path().join(format!("{first}.lock")).exists(),
            "a claimed segid must leave its cross-process lock file"
        );
        segids.release(first);
        assert!(
            !segid_dir.path().join(format!("{first}.lock")).exists(),
            "releasing a segid must remove its lock file"
        );
        // The two id spaces are independent: the same numeric id is free in the other dir.
        assert_eq!(
            SegmentIdAllocator::shared_at(segid_dir.path())
                .with_seed_clock(seed())
                .allocate()
                .unwrap(),
            first
        );
    }

    // v30 §18 delta 8, review fix: the SEGID search start is clock-seeded, through the same one
    // `seeded_id_order` law the vmid search uses.
    //
    // Buggy impl guarded — the shipped delta-8 code: an unseeded `1..=MAX` scan hands **every**
    // vmcell process on the host segid 1, so every process names its namespace `vmcell-seg-1`;
    // another run's liveness-blind start-up sweep then reaps a live segment (reproduced live: a
    // member's `netns get failed: Can not open netns /var/run/netns/vmcell-seg-1` mid-test). With
    // the bug restored both allocators below return 1 and the first assertion reddens.
    #[test]
    fn segment_id_search_start_is_clock_seeded_like_the_vmid_search() {
        let at = |nanos: u32| -> Arc<dyn Clock + std::panic::RefUnwindSafe> {
            Arc::new(FakeClock {
                time: std::time::UNIX_EPOCH + std::time::Duration::new(7, nanos),
            })
        };

        let a = SegmentIdAllocator::new()
            .with_seed_clock(at(5_000_000))
            .allocate()
            .expect("a fresh allocator allocates");
        let b = SegmentIdAllocator::new()
            .with_seed_clock(at(9_000_000))
            .allocate()
            .expect("a fresh allocator allocates");
        assert_ne!(
            a, b,
            "two processes' fresh segid allocators must not deterministically pick the same id"
        );

        // One law, not a second copy: the vmid allocator on the same seed starts in the same
        // place (both id spaces are 254 wide).
        assert_eq!(
            VmidAllocator::with_clock(at(5_000_000))
                .allocate()
                .expect("vmid allocates"),
            a,
            "both allocators must order their search through the ONE seeded law"
        );

        // Seeding rotates the search; it never shrinks it. Every id stays reachable, so the
        // exhaustion limit is unchanged.
        let order: Vec<u32> =
            seeded_id_order(&*at(9_000_000), crate::net::MAX_SEGMENT_ID).collect();
        assert_eq!(order.len(), crate::net::MAX_SEGMENT_ID as usize);
        let unique: std::collections::BTreeSet<u32> = order.into_iter().collect();
        assert_eq!(
            unique,
            (1..=crate::net::MAX_SEGMENT_ID).collect::<std::collections::BTreeSet<u32>>(),
            "the seeded order must be a permutation of the whole id space"
        );
    }

    // v30 §18 delta 8: exhaustion is typed, at exactly the documented limit.
    #[test]
    fn segment_id_allocator_exhausts_typed_at_the_limit() {
        let alloc = SegmentIdAllocator::new();
        let mut held = Vec::new();
        for _ in 0..crate::net::MAX_SEGMENT_ID {
            held.push(alloc.allocate().expect("within the limit"));
        }
        held.sort_unstable();
        assert_eq!(held.first(), Some(&1));
        assert_eq!(held.last(), Some(&crate::net::MAX_SEGMENT_ID));
        assert!(
            matches!(alloc.allocate(), Err(crate::error::Error::Exhaustion(_))),
            "the {}th segment id must be a typed Exhaustion",
            crate::net::MAX_SEGMENT_ID + 1
        );
    }

    // H-ORCH-4 (H1): the read→decide→claim must be atomic against other claimers of
    // the same vmid. With a pre-existing dead lock and >=2 concurrent reclaimers
    // landing on it (the multi-runner case `shared_at` exists for), exactly ONE must
    // win. Any impl that decides reclaimability without holding the per-vmid
    // coordination `flock` races: a naive exists-then-claim lets two racers both see
    // the dead lock and claim, and the earlier rename-and-restore steal lets a third
    // racer claim the momentarily-free path (empirically 3 winners). The
    // single-threaded siblings above cannot exercise the interleave.
    #[test]
    fn shared_at_concurrent_reclaimers_have_exactly_one_winner() {
        const THREADS: usize = 8;
        const TRIALS: usize = 200;
        const VMID: u32 = 7;
        let dir = tempfile::tempdir().expect("tempdir");
        let lock_path = dir.path().join(format!("{VMID}.lock"));
        for _ in 0..TRIALS {
            // Seed a definitively-dead owner: /proc/4294967295 can never exist.
            std::fs::write(&lock_path, u32::MAX.to_string()).expect("seed dead lock");
            let barrier = std::sync::Barrier::new(THREADS);
            let wins = std::sync::atomic::AtomicUsize::new(0);
            std::thread::scope(|s| {
                for _ in 0..THREADS {
                    s.spawn(|| {
                        // Each thread has its OWN allocator (distinct in-process set)
                        // sharing only the lock dir — the cross-process shape.
                        let alloc = FsIdClaim {
                            dir: Some(dir.path().to_path_buf()),
                        };
                        barrier.wait();
                        if alloc.try_claim(VMID) {
                            wins.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        }
                    });
                }
            });
            assert_eq!(
                wins.load(std::sync::atomic::Ordering::Relaxed),
                1,
                "exactly one reclaimer may win a dead lock across {THREADS} racers"
            );
            // Clean up between trials so the next trial re-seeds a fresh dead lock.
            let _ = std::fs::remove_file(&lock_path);
        }
    }

    // CONFIG-ERROR-ORCH-5 / DESIGN-DIVERGENCE-4. Buggy impl: reserve() does not
    // exist / does not honor a specific VMID, or fails to reject conflicts and
    // out-of-range values.
    #[test]
    fn test_reserve_specific_vmid_and_conflicts() {
        let alloc = VmidAllocator::new();
        assert_eq!(alloc.reserve(42).unwrap(), 42);
        // Second reservation of the same id conflicts.
        assert!(matches!(
            alloc.reserve(42),
            Err(crate::error::Error::Exhaustion(_))
        ));
        // A plain allocate must skip the reserved id.
        for _ in 0..253 {
            assert_ne!(alloc.allocate().unwrap(), 42);
        }
        // Out-of-range reservations are Config errors.
        assert!(matches!(
            alloc.reserve(0),
            Err(crate::error::Error::Config(_))
        ));
        assert!(matches!(
            alloc.reserve(255),
            Err(crate::error::Error::Config(_))
        ));
    }

    // ORCH-8. The search-start seed comes from the INJECTED clock, not
    // `SystemTime::now()` directly. On an empty allocator `allocate()` returns
    // exactly the seeded start `(subsec_nanos % 254) + 1`, so a fixed `FakeClock`
    // makes the first allocation deterministic. Buggy impl (seeding from
    // `SystemTime::now()`) ignores the injected clock and returns a wall-clock
    // value instead — reddening these exact-value assertions.
    #[test]
    fn test_vmid_allocate_seed_uses_injected_clock() {
        let at = |ns: u32| -> Arc<dyn Clock + std::panic::RefUnwindSafe> {
            Arc::new(FakeClock {
                time: std::time::UNIX_EPOCH + std::time::Duration::new(0, ns),
            })
        };
        let a = VmidAllocator::with_clock(at(1000));
        assert_eq!(a.allocate().unwrap(), (1000 % 254) + 1);
        // A different fixed time yields a different starting vmid → the seed is
        // genuinely clock-derived, not a constant.
        let b = VmidAllocator::with_clock(at(2000));
        assert_eq!(b.allocate().unwrap(), (2000 % 254) + 1);
    }

    // ---- Full teardown-order assertion (design §13, Cross-cutting invariants) ----
    //
    // The design mandates asserting the FULL `MicroVm::Drop` order — VMM instance
    // (which owns the VMM process group AND its virtiofsd/vhost-vsock daemons) ->
    // netns -> cgroup — via recording fakes, on both normal drop and panic. The
    // integration-level `assert_instance_before_cgroup` in tests/lifecycle.rs can
    // only observe `instance -> cgroup` (its FakeVmm runs `network_disabled`, and an
    // integration test cannot inject a recording netns). These in-crate unit tests
    // construct `MicroVm` directly so a recording netns participates, pinning the
    // load-bearing `instance -> netns` edge: a netns torn down BEFORE the VMM stops
    // holding interfaces in it hangs/leaks (AGENTS.md teardown order). virtiofsd and
    // the tmpfs overlay are internal to the VMM instance's own `Drop`, so they are
    // not separately observable at this seam layer — see the alignment-pass note in
    // implementation-notes.md.
    #[cfg(feature = "net-privileged")]
    struct TimelineNetlink {
        log: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    }
    #[cfg(feature = "net-privileged")]
    impl crate::net::tap::Netlink for TimelineNetlink {
        fn add_netns(&self, _name: &str) -> Result<()> {
            Ok(())
        }
        fn setup_tap(
            &self,
            _netns: &str,
            _tap: &str,
            _vmid: u32,
        ) -> Result<Option<tun_tap::Iface>> {
            Ok(None)
        }
        fn create_bridge(
            &self,
            _netns: &str,
            _bridge: &str,
            _gateway: std::net::Ipv4Addr,
            _prefix_len: u8,
        ) -> Result<()> {
            Ok(())
        }
        fn setup_tap_on_bridge(&self, _netns: &str, _tap: &str, _bridge: &str) -> Result<()> {
            Ok(())
        }
        fn delete_link(&self, _netns: &str, link: &str) -> Result<()> {
            // The segment member's slot release: the event the segment teardown path orders
            // against (it has no `netns_delete` — a member never removes the segment namespace).
            self.log
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(format!("segment_slot_release:{link}"));
            Ok(())
        }
        fn delete_netns(&self, _name: &str) -> Result<()> {
            self.log
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push("netns_delete".to_string());
            Ok(())
        }
        fn setup_tproxy_routing(&self, _netns: &str) -> Result<()> {
            Ok(())
        }
    }

    #[cfg(feature = "net-privileged")]
    #[derive(Clone)]
    struct TimelineCgroupFs {
        log: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    }
    #[cfg(feature = "net-privileged")]
    impl std::fmt::Debug for TimelineCgroupFs {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("TimelineCgroupFs")
        }
    }
    #[cfg(feature = "net-privileged")]
    impl crate::metrics::CgroupFs for TimelineCgroupFs {
        fn create_slice(&self, _name: &str, _limits: &crate::config::ResourceLimits) -> Result<()> {
            Ok(())
        }
        fn delete_slice(&self, _name: &str) -> Result<()> {
            self.log
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push("cgroup_delete".to_string());
            Ok(())
        }
        fn read_stats(&self, _name: &str) -> Result<ResourceUsage> {
            Ok(ResourceUsage::default())
        }
        fn add_task(&self, _name: &str, _pid: u32) -> Result<()> {
            Ok(())
        }
    }

    // Builds a `MicroVm` whose instance-drop, netns-teardown, and cgroup-delete all
    // record into one shared timeline, so their relative order is observable.
    #[cfg(feature = "net-privileged")]
    fn micro_vm_for_order_test(
        log: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    ) -> MicroVm<crate::vmm::FakeVmm> {
        let instance = crate::vmm::FakeVmInstance {
            vsock_path: std::path::PathBuf::from("/tmp/vmcell-order-vsock.sock"),
            serial: std::path::PathBuf::from("/tmp/vmcell-order-serial.log"),
            calls: log.clone(),
            faults: Default::default(),
            control_plane_probes: Default::default(),
        };
        let netns =
            NetNamespace::create("vmcell", 7, Box::new(TimelineNetlink { log: log.clone() }))
                .expect("fake netns create must succeed with a recording netlink");
        MicroVm::<crate::vmm::FakeVmm> {
            vmid: None,
            instance: Some(instance),
            netns: Some(netns),
            segment: None,
            #[cfg(feature = "net-unprivileged")]
            smoltcp: None,
            proxy: None,
            cgroup_name: Some("vmcell-vm-7".to_string()),
            env: HostEnv {
                cgroups: std::sync::Arc::new(TimelineCgroupFs { log }),
                ..HostEnv::for_unit_tests()
            },
            agent_client: None,
            restored: false,
            restore_reseed_applied: None,
            cid: None,
            tmp_dir: None,
            timeouts: crate::config::Timeouts::default(),
            control_plane_disabled: false,
        }
    }

    // Asserts the full teardown order: instance drop -> netns delete -> cgroup
    // delete. Goes red on the inverse — e.g. `MicroVm::Drop` deleting the cgroup or
    // the netns before dropping the instance (the documented hang/leak).
    #[cfg(feature = "net-privileged")]
    fn assert_full_teardown_order(log: &[String]) {
        let idx = |needle: &str| {
            log.iter()
                .position(|c| c == needle)
                .unwrap_or_else(|| panic!("{needle} not recorded; timeline: {log:?}"))
        };
        let instance = idx("drop");
        let netns = idx("netns_delete");
        let cgroup = idx("cgroup_delete");
        assert!(
            instance < netns && netns < cgroup,
            "teardown must be instance -> netns -> cgroup; got timeline: {log:?}"
        );
    }

    #[cfg(feature = "net-privileged")]
    #[test]
    fn test_drop_order_full_chain_normal() {
        let log = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        {
            let _vm = micro_vm_for_order_test(log.clone());
        }
        let calls = log.lock().unwrap_or_else(|e| e.into_inner());
        assert_full_teardown_order(&calls);
    }

    #[cfg(feature = "net-privileged")]
    #[test]
    fn test_drop_order_full_chain_on_panic() {
        let log = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let log_in = log.clone();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _vm = micro_vm_for_order_test(log_in);
            panic!("simulate panic inside scope");
        }));
        assert!(result.is_err(), "the closure must have panicked");
        let calls = log.lock().unwrap_or_else(|e| e.into_inner());
        assert_full_teardown_order(&calls);
    }

    // Delta 7 gate (§18, Delta register: changes from the validated v27 build, L1): the mid-`start()` error path — `EnvSetup`'s **explicit** `Drop` —
    // emits the SAME ordered net → cgroup teardown as the success path, routed through the one
    // shared `release_net_before_netns` helper (never a second copy). Build an `EnvSetup` with a
    // recording netns + cgroup and drop it; the netns must be deleted BEFORE the cgroup slice, just
    // like `assert_full_teardown_order` requires of the success/panic paths. RED on the inverse (a
    // field reorder, or a hand-copied order that deletes the netns after the cgroup / the proxy
    // after the netns).
    #[cfg(feature = "net-privileged")]
    #[test]
    fn env_setup_drop_releases_netns_before_cgroup_like_the_success_path() {
        let log = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        {
            let netns =
                NetNamespace::create("vmcell", 8, Box::new(TimelineNetlink { log: log.clone() }))
                    .expect("recording netns create must succeed");
            let staged = EnvSetup {
                proxy: None,
                #[cfg(feature = "net-unprivileged")]
                smoltcp: None,
                netns: Some(netns),
                segment: None,
                cgroup_guard: CgroupGuard {
                    name: "vmcell-vm-8".to_string(),
                    fs: std::sync::Arc::new(TimelineCgroupFs { log: log.clone() }),
                    armed: true,
                },
                cid_guard: Some(CidGuard {
                    cid: 3,
                    allocator: std::sync::Arc::new(crate::vmm::CidAllocator::new()),
                }),
                res: PerVmResources {
                    cgroup_name: "vmcell-vm-8".to_string(),
                    tap_name: None,
                    netns_name: None,
                    segment: None,
                    vhost_user_socket: None,
                    vmid: 8,
                    guest_cid: 3,
                    tmp_dir: std::env::temp_dir().join("vmcell-envsetup-drop-order-test"),
                },
            };
            drop(staged);
        }
        let calls = log.lock().unwrap_or_else(|e| e.into_inner());
        let idx = |needle: &str| {
            calls
                .iter()
                .position(|c| c == needle)
                .unwrap_or_else(|| panic!("{needle} not recorded; timeline: {calls:?}"))
        };
        assert!(
            idx("netns_delete") < idx("cgroup_delete"),
            "the error-path EnvSetup::drop must release the netns before the cgroup slice — the same \
             order as the success path (delta 7): {calls:?}"
        );
    }

    // v30 §18 delta 8 (L1): a SEGMENT MEMBER's teardown goes through the same one ordered helper.
    // The segment path has no per-VM netns, so `netns_delete` is absent from the timeline
    // entirely — the orderable event is the member's slot release (its tap delete). Asserts:
    // instance drop -> segment slot release -> cgroup delete, and that the member never deletes
    // the segment namespace (which would kill every sibling VM's datapath).
    //
    // Buggy impl guarded: a `teardown_post_instance` that dropped `self.segment` before the
    // instance (or after the cgroup) reorders the timeline; a member `Drop` that deleted the
    // namespace records `delete_netns` while the segment handle is still alive.
    //
    // FAKE-BLIND AXIS: `TimelineNetlink` never touches the kernel, so the real bridge creation,
    // enslavement, and namespace removal are invisible here — `tests/segment.rs`'s live
    // `segment_last_holder_teardown_leaves_no_residue` leg is what covers those, and its
    // `segment_duplicate_vmid_is_refused_without_touching_the_live_member` sibling covers the
    // ownership question a name-only recorder cannot pose (whose tap is `<prefix>-tap-<vmid>` in a
    // SHARED namespace).
    #[cfg(feature = "net-privileged")]
    #[test]
    fn segment_member_teardown_releases_its_slot_between_instance_and_cgroup() {
        let log = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let env = HostEnv {
            cgroups: std::sync::Arc::new(TimelineCgroupFs { log: log.clone() }),
            ..HostEnv::for_unit_tests()
        };
        let segment = crate::net::NetSegment::with_netlink_for_test(
            "vmcell",
            &env,
            Box::new(TimelineNetlink { log: log.clone() }),
        )
        .expect("hermetic segment creates");
        let member = segment.claim_member(7).expect("member slot");
        let tap = member.membership().tap_name.clone();

        {
            let instance = crate::vmm::FakeVmInstance {
                vsock_path: std::path::PathBuf::from("/tmp/vmcell-seg-order-vsock.sock"),
                serial: std::path::PathBuf::from("/tmp/vmcell-seg-order-serial.log"),
                calls: log.clone(),
                faults: Default::default(),
                control_plane_probes: Default::default(),
            };
            let _vm = MicroVm::<crate::vmm::FakeVmm> {
                vmid: None,
                instance: Some(instance),
                netns: None,
                segment: Some(member),
                #[cfg(feature = "net-unprivileged")]
                smoltcp: None,
                proxy: None,
                cgroup_name: Some("vmcell-vm-7".to_string()),
                env: env.clone(),
                agent_client: None,
                restored: false,
                restore_reseed_applied: None,
                cid: None,
                tmp_dir: None,
                timeouts: crate::config::Timeouts::default(),
                control_plane_disabled: false,
            };
        }

        let calls = log.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let idx = |needle: &str| {
            calls
                .iter()
                .position(|c| c == needle)
                .unwrap_or_else(|| panic!("{needle} not recorded; timeline: {calls:?}"))
        };
        assert!(
            idx("drop") < idx(&format!("segment_slot_release:{tap}")),
            "the VMM instance must be reaped before its segment slot is released: {calls:?}"
        );
        assert!(
            idx(&format!("segment_slot_release:{tap}")) < idx("cgroup_delete"),
            "the segment slot must be released before the cgroup slice: {calls:?}"
        );
        assert!(
            !calls.iter().any(|c| c.starts_with("netns_delete")),
            "a member must NEVER delete the segment namespace while the segment lives: {calls:?}"
        );
        // The slot is back on the free list, and the namespace only goes when the LAST handle does.
        assert!(
            segment.active_slots().is_empty(),
            "the member's slot must return to the segment's free list"
        );
        drop(segment);
        assert!(
            log.lock()
                .unwrap_or_else(|e| e.into_inner())
                .iter()
                .any(|c| c == "netns_delete"),
            "the last segment handle must delete the namespace"
        );
    }

    /// A CgroupFs fake that records create/delete calls, used to prove the
    /// slice is released on a construction failure.
    #[derive(Debug, Default, Clone)]
    struct RecordingCgroupFs {
        created: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
        deleted: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    }

    impl crate::metrics::CgroupFs for RecordingCgroupFs {
        fn create_slice(&self, name: &str, _limits: &crate::config::ResourceLimits) -> Result<()> {
            self.created
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(name.to_string());
            Ok(())
        }
        fn delete_slice(&self, name: &str) -> Result<()> {
            self.deleted
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(name.to_string());
            Ok(())
        }
        fn read_stats(&self, _name: &str) -> Result<ResourceUsage> {
            Ok(ResourceUsage::default())
        }
        fn add_task(&self, _name: &str, _pid: u32) -> Result<()> {
            Ok(())
        }
    }

    /// A CgroupFs fake whose `delete_slice` always fails, so the **success-path** teardown's
    /// error branch is reachable (`RecordingCgroupFs` can never take it).
    #[derive(Debug, Default, Clone)]
    struct DeleteFailCgroupFs;

    impl crate::metrics::CgroupFs for DeleteFailCgroupFs {
        fn create_slice(&self, _name: &str, _limits: &crate::config::ResourceLimits) -> Result<()> {
            Ok(())
        }
        fn delete_slice(&self, name: &str) -> Result<()> {
            Err(crate::error::Error::Cgroup(format!(
                "cannot delete {name}: device or resource busy"
            )))
        }
        fn read_stats(&self, _name: &str) -> Result<ResourceUsage> {
            Ok(ResourceUsage::default())
        }
        fn add_task(&self, _name: &str, _pid: u32) -> Result<()> {
            Ok(())
        }
    }

    // docs/78 §6 (`teardown-cgroup-delete-silently-discarded`). The success-path
    // `delete_slice` was the ONE teardown site with no log, so a slice that survives teardown
    // (busy cgroup, revoked delegation) leaked with zero operator-visible trace until the next
    // process start-up's orphan sweep. Assert the warn, and — as the sibling sites do — that the
    // failure is NOT propagated: teardown stays best-effort.
    //
    // Red on the inverse: restore the bare `let _ = self.env.cgroups.delete_slice(&cg_name)` and
    // `logs_contain` goes false.
    #[tokio::test]
    #[tracing_test::traced_test]
    async fn teardown_warns_when_the_cgroup_slice_cannot_be_deleted() {
        let vmm = crate::vmm::FakeVmm::default();
        let env = HostEnv {
            cgroups: std::sync::Arc::new(DeleteFailCgroupFs),
            ..HostEnv::for_unit_tests()
        };
        let vm = MicroVm::start(&vmm, erofs_cfg(), &env)
            .await
            .expect("the VM starts");
        vm.shutdown()
            .await
            .expect("a failed slice delete must not fail teardown (best-effort, M-ORCH-2)");
        assert!(
            logs_contain("failed to delete cgroup slice"),
            "the success-path teardown must warn like every sibling teardown site"
        );
    }

    // docs/78 §6, the sibling half: `FsIdClaim::release`'s discard. The lock file carries THIS
    // process's pid, so a failed removal wedges the id for every other process until this one
    // exits — the log line is the only clue. A directory at the lock path makes `remove_file`
    // fail (EISDIR) without any privileged setup.
    //
    // Red on the inverse: restore the bare `let _ = std::fs::remove_file(&lock_path)` and
    // `logs_contain` goes false. The benign-`NotFound` half is asserted alongside, so the warn
    // cannot be "fixed" by logging every release.
    #[test]
    #[tracing_test::traced_test]
    fn id_claim_release_warns_when_the_lock_cannot_be_removed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let claim = FsIdClaim {
            dir: Some(dir.path().to_path_buf()),
        };

        // Never-claimed id: the removal fails `NotFound`, which is the benign double-release.
        claim.release(1);
        assert!(
            !logs_contain("failed to release cross-process id lock"),
            "a NotFound release is the benign double-release and stays silent"
        );

        std::fs::create_dir(dir.path().join("2.lock")).expect("stand-in for an unremovable lock");
        claim.release(2);
        assert!(
            logs_contain("failed to release cross-process id lock"),
            "a lock that survives release wedges the id and must be warned"
        );
    }

    /// A VMM whose `create`/`restore` always fail, to exercise the error path
    /// after the cgroup slice has been created.
    #[derive(Debug)]
    struct CreateFailVmm;

    impl Vmm for CreateFailVmm {
        type Instance = crate::vmm::FakeVmInstance;

        async fn create(
            &self,
            _cfg: &VmConfig,
            _res: &PerVmResources,
            _cgroups: &dyn crate::metrics::CgroupFs,
        ) -> Result<Self::Instance> {
            Err(crate::error::Error::Vmm("create failed".into()))
        }

        async fn restore(
            &self,
            _snapshot_dir: &std::path::Path,
            _cfg: &VmConfig,
            _res: &PerVmResources,
            _cgroups: &dyn crate::metrics::CgroupFs,
        ) -> Result<Self::Instance> {
            Err(crate::error::Error::Vmm("restore failed".into()))
        }

        fn capabilities(&self) -> crate::vmm::VmmCapabilities {
            crate::vmm::VmmCapabilities {
                snapshot_restore: true,
                lazy_restore: false,
                virtio_fs_shares: true,
                unprivileged_vhost_user_net: true,
                nested_virt: true,
                virtio_console: true,
                restore_rotates_host_paths: true,
                disk_io_throttle: true,
                usb_host_passthrough: false,
            }
        }

        fn id(&self) -> &str {
            "createfail"
        }
    }

    fn erofs_cfg() -> VmConfig {
        VmConfig::builder(
            std::path::PathBuf::from("/vmlinux"),
            crate::config::RootfsSource::Erofs {
                image: std::path::PathBuf::from("/rootfs.erofs"),
            },
        )
        .network_disabled()
        .build()
        .expect("valid config")
    }

    // CONFIG-ERROR-ORCH-2. Buggy impl: setup_env returns the slice as a bare
    // String with no RAII guard, so a create/boot failure leaks it (the slice
    // is created but never deleted).
    #[tokio::test]
    async fn test_cgroup_slice_deleted_on_create_failure() {
        let vmm = CreateFailVmm;
        let cfg = erofs_cfg();
        let recorder = RecordingCgroupFs::default();
        let env = HostEnv {
            cgroups: std::sync::Arc::new(recorder.clone()),
            ..HostEnv::for_unit_tests()
        };
        let res = MicroVm::<CreateFailVmm>::start(&vmm, cfg, &env).await;
        assert!(res.is_err(), "create failure must propagate");
        let created = recorder.created.lock().unwrap_or_else(|e| e.into_inner());
        let deleted = recorder.deleted.lock().unwrap_or_else(|e| e.into_inner());
        assert!(
            !created.is_empty(),
            "a slice should have been created in setup_env"
        );
        assert_eq!(
            *created, *deleted,
            "every created slice must be deleted on the failure path"
        );
    }

    // Delta 9 (§18, Delta register: changes from the validated v27 build): the `FakeVmm` fault menu drives the orchestrator's mid-`start()` failure paths
    // at the `Vmm`/`VmInstance` seam itself (not only through the surrounding seams). A scripted
    // `create` OR `boot` failure must propagate AND leave zero residue — every cgroup slice created
    // in `setup_env` is deleted on the error path (the `CgroupGuard`). RED on the inverse (a slice
    // created without a RAII guard leaks on the fault).
    #[tokio::test]
    async fn fault_menu_mid_start_faults_tear_down_ordered() {
        use crate::vmm::{FakeVmm, FaultMenu};
        for faults in [
            FaultMenu {
                fail_create: true,
                ..Default::default()
            },
            FaultMenu {
                fail_boot: true,
                ..Default::default()
            },
        ] {
            let vmm = FakeVmm::with_faults(faults);
            let recorder = RecordingCgroupFs::default();
            let env = HostEnv {
                cgroups: std::sync::Arc::new(recorder.clone()),
                ..HostEnv::for_unit_tests()
            };
            let res = MicroVm::start(&vmm, erofs_cfg(), &env).await;
            assert!(res.is_err(), "a scripted mid-start fault must propagate");
            let created = recorder.created.lock().unwrap_or_else(|e| e.into_inner());
            let deleted = recorder.deleted.lock().unwrap_or_else(|e| e.into_inner());
            assert!(!created.is_empty(), "setup_env should have created a slice");
            assert_eq!(
                *created, *deleted,
                "every created slice must be deleted on the fault path"
            );
        }
    }

    // Delta 9: a scripted `restore` fault leaves zero residue on the restore path, exactly like the
    // start path (the shared `restore_inner` teardown).
    #[tokio::test]
    async fn fault_menu_fail_restore_tears_down() {
        use crate::vmm::{FakeVmm, FaultMenu};
        let vmm = FakeVmm::with_faults(FaultMenu {
            fail_restore: true,
            ..Default::default()
        });
        let recorder = RecordingCgroupFs::default();
        let env = HostEnv {
            cgroups: std::sync::Arc::new(recorder.clone()),
            ..HostEnv::for_unit_tests()
        };
        let res = MicroVm::restore(
            &vmm,
            std::path::Path::new("/tmp/fake-snap"),
            erofs_cfg(),
            &env,
        )
        .await;
        assert!(res.is_err(), "a scripted restore fault must propagate");
        let created = recorder.created.lock().unwrap_or_else(|e| e.into_inner());
        let deleted = recorder.deleted.lock().unwrap_or_else(|e| e.into_inner());
        assert!(!created.is_empty(), "setup_env should have created a slice");
        assert_eq!(
            *created, *deleted,
            "every created slice must be deleted on the fault path"
        );
    }

    // Delta 9: a scripted `resume` fault fires AFTER a live instance is built (restore()
    // succeeded), on the restore->resume path where cgroup/netns side effects already
    // exist and the guards are still armed (the cgroup_guard is disarmed only AFTER a
    // successful resume). It must still leave zero cgroup residue — a distinct teardown
    // path the fail_restore test cannot reach (there no instance is ever built). RED on
    // the inverse (disarming/omitting the CgroupGuard before resume: created != deleted).
    #[tokio::test]
    async fn fault_menu_fail_resume_tears_down() {
        use crate::vmm::{FakeVmm, FaultMenu};
        let vmm = FakeVmm::with_faults(FaultMenu {
            fail_resume: true,
            ..Default::default()
        });
        let recorder = RecordingCgroupFs::default();
        let env = HostEnv {
            cgroups: std::sync::Arc::new(recorder.clone()),
            ..HostEnv::for_unit_tests()
        };
        let res = MicroVm::restore(
            &vmm,
            std::path::Path::new("/tmp/fake-snap"),
            erofs_cfg(),
            &env,
        )
        .await;
        assert!(res.is_err(), "a scripted resume fault must propagate");
        let created = recorder.created.lock().unwrap_or_else(|e| e.into_inner());
        let deleted = recorder.deleted.lock().unwrap_or_else(|e| e.into_inner());
        assert!(!created.is_empty(), "setup_env should have created a slice");
        assert_eq!(
            *created, *deleted,
            "every created slice must be deleted when resume fails after restore"
        );
    }

    // Delta 9: `readiness_delay` is honored inside boot()/verify_control_plane() — drive
    // it so it is not dead surface. A small delay must be observable end-to-end: start()
    // still succeeds but takes at least the delay. RED on the inverse (boot/verify ignore
    // readiness_delay: start() returns near-instantly, elapsed < the delay).
    #[tokio::test]
    async fn fault_menu_readiness_delay_is_honored() {
        use crate::vmm::{FakeVmm, FaultMenu};
        let delay = std::time::Duration::from_millis(50);
        let vmm = FakeVmm::with_faults(FaultMenu {
            readiness_delay: Some(delay),
            ..Default::default()
        });
        let env = HostEnv {
            cgroups: std::sync::Arc::new(crate::metrics::FakeCgroupFs::new()),
            ..HostEnv::for_unit_tests()
        };
        let t0 = std::time::Instant::now();
        MicroVm::start(&vmm, erofs_cfg(), &env)
            .await
            .expect("start must still succeed with a readiness delay");
        let elapsed = t0.elapsed();
        assert!(
            elapsed >= delay,
            "readiness_delay must be honored in boot/verify_control_plane: elapsed {elapsed:?} < {delay:?}"
        );
    }

    // Delta 9: a control socket wedged for the first N probes is recovered by `start()`'s respawn
    // loop — the exact QEMU vhost-user-vsock bring-up flake the loop exists for. `wedge=2` succeeds
    // on the 3rd spawn; assert the fake was `create`d 3 times. RED on the inverse (no respawn:
    // `start()` returns the wedged VM or fails on the first probe).
    #[tokio::test]
    async fn fault_menu_wedged_control_plane_respawns_then_recovers() {
        use crate::vmm::{FakeVmm, FaultMenu};
        let vmm = FakeVmm::with_faults(FaultMenu {
            wedge_control_plane_for: 2,
            ..Default::default()
        });
        let env = HostEnv {
            cgroups: std::sync::Arc::new(crate::metrics::FakeCgroupFs::new()),
            ..HostEnv::for_unit_tests()
        };
        MicroVm::start(&vmm, erofs_cfg(), &env)
            .await
            .expect("start must recover after the control plane un-wedges");
        let calls = vmm.calls.lock().unwrap_or_else(|e| e.into_inner());
        let creates = calls.iter().filter(|c| c.as_str() == "create").count();
        assert_eq!(
            creates, 3,
            "wedge_control_plane_for=2 → recover on the 3rd spawn: {calls:?}"
        );
    }

    // Delta 9: a permanently-wedged control socket fails LOUD after the bounded respawns, never
    // hanging or handing back a half-wired VM. RED on the inverse (unbounded respawn / silent
    // success).
    #[tokio::test]
    async fn fault_menu_permanently_wedged_fails_after_max_respawns() {
        use crate::vmm::{FakeVmm, FaultMenu};
        let vmm = FakeVmm::with_faults(FaultMenu {
            wedge_control_plane_for: (MAX_CONTROL_PLANE_RESPAWNS as usize) + 5,
            ..Default::default()
        });
        let env = HostEnv {
            cgroups: std::sync::Arc::new(crate::metrics::FakeCgroupFs::new()),
            ..HostEnv::for_unit_tests()
        };
        let err = MicroVm::start(&vmm, erofs_cfg(), &env)
            .await
            .expect_err("a permanently wedged control plane must fail loud");
        assert!(
            err.to_string().contains("control plane did not come up"),
            "expected the bounded-respawn fail-loud, got: {err}"
        );
    }

    // THE DELEGATION GATE. A KVM-free unit test must not require the host cgroup tree to be
    // delegated to the test process. `HostEnv::hermetic()` wires the real sysfs `DefaultCgroupFs`,
    // so every fake-VMM start through it `mkdir`s `/sys/fs/cgroup/<base>/<prefix>-vm-<vmid>`: green
    // on a developer box (a systemd user session IS delegated) and `EACCES` on a GitHub hosted
    // runner (`system.slice/hosted-compute-agent.service` is not), where 21 of these tests were red
    // while all 781 passed locally. `HostEnv::for_unit_tests()` is the fix; this is what pins it.
    //
    // The assertion is environment-independent, which is the point — it fails on the un-fixed code
    // in BOTH environments:
    //   * on a delegated host, `..DefaultCgroupFs` really creates the slice, so assert 3 fires;
    //   * on a non-delegated host, `start` returns Cgroup("… Permission denied"), so assert 1 fires
    //     (reproduce with `just test-unit-undelegated`).
    // Red-on-inverse is expressible despite `hermetic()` being `#[cfg(not(test))]` here: substitute
    // `cgroups: Arc::new(crate::metrics::DefaultCgroupFs)` over this env and both halves bite.
    //
    // The expected slice name is NOT composed here. It comes from `metrics::vm_slice_name`, the one
    // law `setup_env` itself calls — a test-local `format!("{base}/{leaf}")` would be a second copy
    // of the composition inside the very test meant to catch drift in it (AGENTS: "Recompute
    // expected resource names through `vmcell::naming`, never a test-local `format!`").
    #[tokio::test]
    async fn unit_test_env_start_creates_no_slice_in_the_host_cgroup_tree() {
        let vmm = crate::vmm::FakeVmm::default();
        let env = HostEnv::for_unit_tests();
        // 1. Starts on ANY host, delegated or not.
        let vm = MicroVm::start(&vmm, erofs_cfg(), &env)
            .await
            .expect("a fake-VMM start must not need host cgroup delegation");
        let name = crate::metrics::vm_slice_name(crate::naming::DEFAULT_RESOURCE_PREFIX, vm.vmid());

        // 2. POSITIVE CONTROL. Absence proves nothing unless the product really would have created
        // a slice by exactly this name, so drive the same start over a recorder and check it did.
        // Without this, assert 3 would still pass if `setup_env` stopped creating cgroups at all.
        let recorder = RecordingCgroupFs::default();
        let control = HostEnv {
            cgroups: std::sync::Arc::new(recorder.clone()),
            ..HostEnv::for_unit_tests()
        };
        let control_vm = MicroVm::start(&vmm, erofs_cfg(), &control)
            .await
            .expect("control start");
        let expected = crate::metrics::vm_slice_name(
            crate::naming::DEFAULT_RESOURCE_PREFIX,
            control_vm.vmid(),
        );
        let created = recorder
            .created
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        assert!(
            created.contains(&expected),
            "the control must record a create for {expected}, else the absence below is vacuous: {created:?}"
        );

        // 3. THE GATE: the `for_unit_tests()` start left nothing behind in the host cgroup tree.
        let path = format!("/sys/fs/cgroup/{name}");
        assert!(
            !std::path::Path::new(&path).exists(),
            "a unit-test start must create no slice in the host cgroup tree ({path})"
        );
    }

    // CONFIG-ERROR-ORCH-5. Buggy impl: start() ignores cfg.vmid and always
    // allocates a fresh VMID.
    #[tokio::test]
    async fn test_start_honors_cfg_vmid() {
        let vmm = crate::vmm::FakeVmm::default();
        let mut cfg = erofs_cfg();
        cfg.vmid = Some(7);
        let env = HostEnv::for_unit_tests();
        let vm = MicroVm::start(&vmm, cfg, &env)
            .await
            .expect("start should succeed with fakes");
        assert_eq!(vm.vmid(), 7);
    }

    // CONFIG-ERROR-ORCH-5. Buggy impl: start() does not reserve cfg.vmid through
    // the allocator, so a conflicting explicit VMID is not detected.
    #[tokio::test]
    async fn test_start_rejects_vmid_conflict() {
        let vmm = crate::vmm::FakeVmm::default();
        let mut cfg = erofs_cfg();
        cfg.vmid = Some(7);
        let env = HostEnv::for_unit_tests();
        // Someone already holds VMID 7 on this shared allocator.
        env.vmids.reserve(7).expect("pre-reservation");
        let res = MicroVm::start(&vmm, cfg, &env).await;
        assert!(
            matches!(res, Err(crate::error::Error::Exhaustion(_))),
            "a conflicting explicit VMID must be rejected"
        );
    }

    // M-ORCH-3: the builder/presets clamp, but `Timeouts`' fields are `pub`, so a
    // post-`build()` mutation can drive a correctness floor to zero (a busy-spin on
    // PID 1's connect/accept loop). start() must re-clamp at the boundary. RED on
    // the inverse (no re-clamp at start): the zeroed floors survive onto the VM.
    #[tokio::test]
    async fn timeouts_reclamped_at_start_guards_pub_field_mutation() {
        use std::time::Duration;
        let vmm = crate::vmm::FakeVmm::default();
        let mut cfg = erofs_cfg();
        cfg.timeouts.connect_backoff_floor = Duration::ZERO;
        cfg.timeouts.guest_accept_poll = Duration::ZERO;
        cfg.timeouts.api_socket_poll = Duration::ZERO;
        let env = HostEnv::for_unit_tests();
        let vm = MicroVm::start(&vmm, cfg, &env)
            .await
            .expect("start with fakes");
        assert!(vm.timeouts.connect_backoff_floor >= Duration::from_millis(1));
        assert!(vm.timeouts.guest_accept_poll >= Duration::from_millis(1));
        assert!(vm.timeouts.api_socket_poll >= Duration::from_millis(1));
    }

    // C1 / CONFIG-ERROR-ORCH-1. Buggy impl: restore() only guards a virtio-fs
    // rootfs and unprivileged net, letting a virtio-fs data Share (a vhost-user
    // device) through onto the snapshot path.
    #[tokio::test]
    async fn test_restore_rejects_data_shares() {
        let vmm = crate::vmm::FakeVmm::default();
        // A non-snapshotting config with a data share builds fine.
        let cfg = VmConfig::builder(
            std::path::PathBuf::from("/vmlinux"),
            crate::config::RootfsSource::Erofs {
                image: std::path::PathBuf::from("/rootfs.erofs"),
            },
        )
        .network_disabled()
        .with_share(crate::config::Share::new(
            "data",
            "/tmp/data",
            crate::config::Access::ReadOnly,
            crate::config::CachePolicy::Auto,
        ))
        .build()
        .expect("valid config");
        let env = HostEnv::for_unit_tests();
        let res = MicroVm::restore(&vmm, std::path::Path::new("/fake/snap"), cfg, &env).await;
        // ORCH-4 / §2.5 (The capability matrix) boundary 2: a vhost-user device on the restore path is an
        // `Unsupported` capability rejection, not a generic `Config` error.
        assert!(matches!(res, Err(crate::error::Error::Unsupported { .. })));
    }

    // C1 / ORCH-4 / §2.5 boundary 2 (M5b). Sibling of test_restore_rejects_data_shares:
    // the OTHER vhost-user arm — unprivileged (vhost-user-net) networking — must be
    // rejected on the restore path as an `Unsupported` capability, not a `Config`
    // error. A non-snapshotting unprivileged config builds fine (config.rs only
    // rejects Unprivileged+snapshotting when `snapshotting` is set), so the
    // rejection must come from restore_inner's boundary-2 re-check. Buggy impl (that
    // arm removed/weakened) lets an unprivileged-net config onto the snapshot path —
    // reddening this exact-variant assertion.
    #[tokio::test]
    async fn test_restore_rejects_unprivileged_net() {
        let vmm = crate::vmm::FakeVmm::default();
        let cfg = VmConfig::builder(
            std::path::PathBuf::from("/vmlinux"),
            crate::config::RootfsSource::Erofs {
                image: std::path::PathBuf::from("/rootfs.erofs"),
            },
        )
        .net(crate::config::NetConfig::Unprivileged {
            egress: crate::config::Egress::Open,
            host_services_port: None,
        })
        .build()
        .expect("valid non-snapshotting unprivileged config");
        let env = HostEnv::for_unit_tests();
        let res = MicroVm::restore(&vmm, std::path::Path::new("/fake/snap"), cfg, &env).await;
        assert!(matches!(res, Err(crate::error::Error::Unsupported { .. })));
    }

    /// A snapshot-ineligible config differing from the eligible baseline in exactly one field.
    /// Every arm of the shared predicate is reachable from a config that `build()` accepts — the
    /// combinations `build()` rejects are the *snapshotting* ones, and the whole point of docs/78
    /// M2/M4 is that a NON-snapshotting config reaches the restore/clone boundaries.
    fn ineligible_cfg(
        mutate: impl FnOnce(crate::config::VmConfigBuilder) -> crate::config::VmConfigBuilder,
    ) -> VmConfig {
        mutate(
            VmConfig::builder(
                std::path::PathBuf::from("/vmlinux"),
                crate::config::RootfsSource::Erofs {
                    image: std::path::PathBuf::from("/rootfs.erofs"),
                },
            )
            .network_disabled(),
        )
        .build()
        .expect("a non-snapshotting config with a single create-only input builds")
    }

    // docs/78 S1 + M2 + M4: the ONE config-only snapshot-eligibility predicate `restore_inner`
    // calls (and `zygote::check_clone_eligible` is to be routed through). Pins every arm's exact
    // feature fragment (each boundary composes it into its own typed refusal, so the fragment is
    // what a caller matches on) and the eligible positive control.
    //
    // Red on the inverse: delete any arm and its config returns `None` here — which is exactly
    // how the custom-init (M2) and host-USB (M4) inputs used to reach `restore()`.
    //
    // The `NetConfig::Segment` arm is deliberately absent: `NetSegmentRef` cannot be constructed
    // without a real segment namespace (privileged, KVM-free but netns-requiring), so it is
    // covered by the segment suite's restore leg, not here.
    #[test]
    fn clone_ineligible_feature_covers_every_config_only_arm() {
        // Positive control: the eligible baseline every arm is a one-field delta from.
        assert_eq!(
            clone_ineligible_feature(&erofs_cfg()),
            None,
            "a plain erofs, no-network config is snapshot-eligible"
        );

        let unprivileged = ineligible_cfg(|b| {
            b.net(crate::config::NetConfig::Unprivileged {
                egress: crate::config::Egress::Open,
                host_services_port: None,
            })
        });
        assert_eq!(
            clone_ineligible_feature(&unprivileged),
            Some("unprivileged (vhost-user-net) networking")
        );

        let share = ineligible_cfg(|b| {
            b.with_share(crate::config::Share::new(
                "data",
                "/tmp/data",
                crate::config::Access::ReadOnly,
                crate::config::CachePolicy::Auto,
            ))
        });
        assert_eq!(
            clone_ineligible_feature(&share),
            Some("a virtio-fs data share (vhost-user device)")
        );

        // M2: a custom init replaces the agent the mandatory post-restore resync runs through.
        let custom_init = ineligible_cfg(|b| b.init("/bin/workload"));
        assert_eq!(
            clone_ineligible_feature(&custom_init),
            Some("a custom init (VmConfig::init) that replaces the guest agent")
        );

        // M4: a passed-through host device is not in the migration stream.
        let usb = ineligible_cfg(|b| {
            b.with_usb_host_device(crate::config::UsbHostDevice::new(0x1d6b, 0x0002))
        });
        assert_eq!(
            clone_ineligible_feature(&usb),
            Some("host USB passthrough (VmConfig::usb_host_devices)")
        );
    }

    // docs/78 M2, restore boundary. `build()` rejects `init` + `snapshotting`, but a custom-init
    // config with `snapshotting` OFF builds and used to sail through `restore_inner` — producing a
    // clone whose mandatory S2 resync (clock, CSPRNG reseed, MAC/IP rotation) is structurally
    // unreachable, because `agent()` fails loud on a VM with no guest agent. It must be a typed
    // capability refusal naming the field, with the positive control proving the very same restore
    // succeeds once `init` is dropped.
    //
    // Red on the inverse: remove the `cfg.init` arm from `clone_ineligible_feature` and this
    // restore returns `Ok`.
    #[tokio::test]
    async fn restore_rejects_a_custom_init_config() {
        let vmm = crate::vmm::FakeVmm::default();
        let env = HostEnv::for_unit_tests();
        let err = MicroVm::restore(
            &vmm,
            std::path::Path::new("/fake/snap"),
            ineligible_cfg(|b| b.init("/bin/workload")),
            &env,
        )
        .await
        .expect_err("restoring a custom-init config must be refused");
        match err {
            crate::error::Error::Unsupported { feature, .. } => assert!(
                feature.contains("custom init (VmConfig::init)"),
                "the refusal must name the offending field, got {feature:?}"
            ),
            other => panic!("expected a typed capability refusal, got {other:?}"),
        }

        // Positive control (the allowed path reaches the same target): the identical restore
        // without `init` succeeds, so the test is not passing on an unrelated failure.
        MicroVm::restore(&vmm, std::path::Path::new("/fake/snap"), erofs_cfg(), &env)
            .await
            .expect("the same restore without a custom init must succeed");
    }

    // docs/78 M2, clone boundary. The zygote fan-out must refuse the same config: a custom-init
    // master would mint N clones that can never resync (frozen clock, correlated CSPRNG, stale
    // MAC/IP). Accepts the refusal at EITHER zygote boundary — `from_snapshot_dir`'s fail-fast
    // config gate or the per-clone restore — because the fail-fast gate is the honest home for it
    // once `zygote::check_clone_eligible` routes through the shared predicate (docs/78 S1; that
    // rewiring is the one edit outside this change's file set).
    //
    // Red on the inverse: with the `cfg.init` arm gone, `spawn_clone` returns `Ok` with a live
    // agent-less clone.
    #[tokio::test]
    async fn zygote_clone_rejects_a_custom_init_config() {
        let vmm = crate::vmm::FakeVmm::default();
        let env = HostEnv::for_unit_tests();
        let master = tempfile::tempdir().expect("tempdir");
        std::fs::write(master.path().join("state"), b"snapshot").expect("write master state");

        let err = match crate::Zygote::from_snapshot_dir(
            master.path(),
            ineligible_cfg(|b| b.init("/bin/workload")),
        )
        .await
        {
            Err(e) => e,
            Ok(zygote) => zygote
                .spawn_clone(&vmm, &env)
                .await
                .expect_err("a custom-init zygote must not mint a clone"),
        };
        match err {
            crate::error::Error::Unsupported { feature, .. } => assert!(
                feature.contains("custom init (VmConfig::init)"),
                "the refusal must name the offending field, got {feature:?}"
            ),
            other => panic!("expected a typed capability refusal, got {other:?}"),
        }

        // Positive control: the same master and the same seams mint a clone for the eligible
        // config, so the refusal above is about `init` and nothing else.
        crate::Zygote::from_snapshot_dir(master.path(), erofs_cfg())
            .await
            .expect("an eligible zygote constructs")
            .spawn_clone(&vmm, &env)
            .await
            .expect("an eligible config must still fan out");
    }

    // docs/78 M2, snapshot boundary. The image is refused where it is WRITTEN, not only where it
    // is restored: `Zygote::suspend` routes straight through `MicroVm::snapshot`, which had no
    // guard at all, so a custom-init VM could produce a master image that is unusable by
    // construction. `control_plane_disabled` is the retained `cfg.init.is_some()`.
    //
    // Red on the inverse: drop the guard and the snapshot succeeds (the `FakeVmm` instance records
    // a "snapshot" call and returns `Ok`).
    #[tokio::test]
    async fn snapshot_refuses_a_custom_init_vm() {
        let vmm = crate::vmm::FakeVmm::default();
        let env = HostEnv::for_unit_tests();
        let dir = tempfile::tempdir().expect("tempdir");

        let mut custom_init =
            MicroVm::start(&vmm, ineligible_cfg(|b| b.init("/bin/workload")), &env)
                .await
                .expect("a custom-init VM starts (the control-plane probe is skipped for it)");
        let err = custom_init
            .snapshot(dir.path())
            .await
            .expect_err("snapshotting a custom-init VM must be refused");
        match err {
            crate::error::Error::Unsupported { feature, .. } => assert!(
                feature.contains("custom init (VmConfig::init)"),
                "the refusal must name the offending field, got {feature:?}"
            ),
            other => panic!("expected a typed capability refusal, got {other:?}"),
        }

        // Positive control: the same call on an agent-carrying VM writes the snapshot.
        let mut eligible = MicroVm::start(&vmm, erofs_cfg(), &env)
            .await
            .expect("the eligible VM starts");
        eligible
            .snapshot(dir.path())
            .await
            .expect("an eligible VM must still snapshot");
    }

    // docs/78 M4. The delta-9 record's premise — "every backend's `restore()` rejects a
    // non-snapshotting config, so USB cannot reach it" — is empirically FALSE: no backend's
    // `restore()` reads `cfg.snapshotting`. `{VsockTransport::InKernel, snapshotting: false}` +
    // USB devices is exactly the config that builds (only snapshotting+USB is rejected), passes
    // QEMU's `uses_in_kernel_vsock` restore gate, and is spawned with the USB argv WITHOUT the
    // `require_usb_host_devices` precheck — the measured silent-empty-xhci failure mode. The one
    // orchestrator boundary refuses it for every backend at once.
    //
    // Red on the inverse: remove the `usb_host_devices` arm and this restore returns `Ok`.
    #[tokio::test]
    async fn restore_rejects_usb_host_devices_on_a_non_snapshotting_config() {
        let vmm = crate::vmm::FakeVmm::default();
        let env = HostEnv::for_unit_tests();
        let with_usb = ineligible_cfg(|b| {
            b.vsock_transport(crate::config::VsockTransport::InKernel)
                .with_usb_host_device(crate::config::UsbHostDevice::new(0x1d6b, 0x0002))
        });
        assert!(
            !with_usb.snapshotting,
            "the reachable shape is the NON-snapshotting one (build() rejects snapshotting+USB)"
        );
        let err = MicroVm::restore(&vmm, std::path::Path::new("/fake/snap"), with_usb, &env)
            .await
            .expect_err("restoring a config carrying host USB devices must be refused");
        match err {
            crate::error::Error::Unsupported { feature, .. } => assert!(
                feature.contains("usb_host_devices"),
                "the refusal must name the offending field, got {feature:?}"
            ),
            other => panic!("expected a typed capability refusal, got {other:?}"),
        }

        // Positive control: the same in-kernel-vsock config restores once the USB devices are
        // dropped — the refusal is about the devices, not the transport.
        MicroVm::restore(
            &vmm,
            std::path::Path::new("/fake/snap"),
            ineligible_cfg(|b| b.vsock_transport(crate::config::VsockTransport::InKernel)),
            &env,
        )
        .await
        .expect("the same restore without USB devices must succeed");
    }

    /// A recording guest-resync fake for the post-restore resync tests. Fails the
    /// first `fail_first_n` calls (modelling a just-rebound, still-flaky vsock),
    /// then records the single `resync` call and returns a configurable
    /// [`crate::agent::ResyncOutcome`] (drives the clock-fail-loud path via
    /// `clock_error`, and the reseed-applied observability via the bool).
    #[derive(Default)]
    struct FakeGuestResync {
        /// The `(unix_secs, unix_nanos, mac)` of each resync call that was not
        /// forced to fail.
        recorded: Vec<(u64, u32, Option<[u8; 6]>)>,
        /// The `ipv4` argument of each recorded call (H-VMM-1).
        recorded_ipv4: Vec<Option<crate::agent::protocol::Ipv4Reconfig>>,
        calls: usize,
        fail_first_n: usize,
        /// The outcome returned once a call is allowed to succeed.
        outcome: crate::agent::ResyncOutcome,
    }

    impl GuestResync for FakeGuestResync {
        async fn resync(
            &mut self,
            unix_secs: u64,
            unix_nanos: u32,
            mac: Option<[u8; 6]>,
            ipv4: Option<crate::agent::protocol::Ipv4Reconfig>,
        ) -> Result<crate::agent::ResyncOutcome> {
            self.calls += 1;
            if self.calls <= self.fail_first_n {
                return Err(crate::error::Error::Agent(
                    "transient post-restore drop".into(),
                ));
            }
            self.recorded.push((unix_secs, unix_nanos, mac));
            self.recorded_ipv4.push(ipv4);
            Ok(self.outcome.clone())
        }
    }

    fn fixed_clock() -> FakeClock {
        FakeClock {
            time: std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000),
        }
    }

    // M-RESTORE-1. A transient failure of the post-restore resync round-trip (the
    // mandatory clock resync rides inside it) must NOT clear `restored`; the next
    // call must retry the full resync. Buggy impl (clearing `restored` up front,
    // then a hard `?` on the resync) leaves `restored == false` after the failure,
    // so the resync — clock, RNG reseed, MAC — never runs again. This goes red on
    // that inverse: it asserts the flag stays set after the failed pass and that
    // the resync runs (once, natively) on the retry.
    #[tokio::test]
    async fn test_resync_retries_after_transient_first_exec_failure() {
        let clock = fixed_clock();
        let mut restored = true;
        let mut reseed = None;
        let mut exec = FakeGuestResync {
            fail_first_n: 1,
            outcome: crate::agent::ResyncOutcome {
                clock_error: None,
                reseed_applied: true,
                mac_applied: true,
                ip_applied: true,
            },
            ..FakeGuestResync::default()
        };

        let first =
            maybe_resync_after_restore(&mut restored, &mut reseed, &mut exec, &clock, 5).await;
        assert!(first.is_err(), "transient resync failure must propagate");
        assert!(
            restored,
            "restored must stay set after a transient failure so the resync retries"
        );
        assert!(
            reseed.is_none(),
            "no reseed result recorded on the failed pass"
        );
        assert!(
            exec.recorded.is_empty(),
            "the failed resync must not have recorded a call"
        );

        // Retry: the guest is reachable now; the resync runs and only then is the
        // flag cleared.
        let second =
            maybe_resync_after_restore(&mut restored, &mut reseed, &mut exec, &clock, 5).await;
        assert!(second.is_ok(), "the retried resync must succeed");
        assert!(
            !restored,
            "restored is cleared only AFTER the mandatory clock resync succeeds"
        );
        assert_eq!(
            reseed,
            Some(true),
            "the reseed applied on the successful pass"
        );
        // Exactly ONE native resync round-trip ran on the retry, replacing the 3
        // subprocess execs. Reddens if the resync silently no-ops or spawns execs.
        assert_eq!(
            exec.recorded.len(),
            1,
            "the native resync is a single round-trip"
        );
        let (secs, nanos, mac) = exec.recorded[0];
        // It carried the host wall-clock instant (from the injected clock)...
        assert_eq!(secs, 1_700_000_000, "resync must carry the host unix_secs");
        assert_eq!(nanos, 0, "resync must carry the host sub-second nanos");
        // ...and the per-vmid MAC as BYTES (vmid 5 -> 02:00:00:00:00:05), not a
        // stringly `ip link set` argv. Reddens on a wrong vmid→MAC mapping.
        assert_eq!(
            mac,
            Some([0x02, 0x00, 0x00, 0x00, 0x00, 0x05]),
            "resync must carry the vmid->MAC mapping as bytes"
        );
        // H-VMM-1: ...and the rotated `/30` IPv4 identity, derived from the SAME
        // `ip_math` the host wiring uses (vmid 5 -> octet 6 -> guest 10.200.6.2,
        // gateway 10.200.6.1, /30). Reddens if the IP is not rotated (the old
        // "guest keeps its frozen ip=" behavior sent `None` here).
        assert_eq!(
            exec.recorded_ipv4[0],
            Some(crate::agent::protocol::Ipv4Reconfig {
                addr: [10, 200, 6, 2],
                prefix_len: 30,
                gateway: [10, 200, 6, 1],
            }),
            "resync must carry the rotated /30 guest IP + gateway"
        );
    }

    // Test-discipline (c): the typed "reseed applied" result must report
    // Some(false) when the guest reports the best-effort reseed did not apply (e.g.
    // /dev/hwrng missing), so a restore test can assert the reseed actually applied
    // instead of inferring it from two /dev/urandom reads differing. Buggy impl
    // (always recording Some(true), or never recording) goes red.
    #[tokio::test]
    async fn test_resync_records_reseed_not_applied_on_nonzero_exit() {
        let clock = fixed_clock();
        let mut restored = true;
        let mut reseed = None;
        let mut exec = FakeGuestResync {
            outcome: crate::agent::ResyncOutcome {
                clock_error: None,
                reseed_applied: false,
                mac_applied: true,
                ip_applied: true,
            },
            ..FakeGuestResync::default()
        };
        maybe_resync_after_restore(&mut restored, &mut reseed, &mut exec, &clock, 5)
            .await
            .expect("clock resync succeeds; the reseed is best-effort");
        assert_eq!(
            reseed,
            Some(false),
            "a not-applied reseed must be surfaced as Some(false)"
        );
        assert!(
            !restored,
            "a best-effort reseed failure must NOT keep restored set (the clock resync succeeded)"
        );
    }

    // The resync is a no-op when the VM was not restored: no round-trip is issued
    // and no reseed result is recorded. Guards against running the resync on a cold
    // boot.
    #[tokio::test]
    async fn test_resync_is_noop_when_not_restored() {
        let clock = fixed_clock();
        let mut restored = false;
        let mut reseed = None;
        let mut exec = FakeGuestResync::default();
        maybe_resync_after_restore(&mut restored, &mut reseed, &mut exec, &clock, 5)
            .await
            .unwrap();
        assert!(exec.recorded.is_empty(), "no resync when not restored");
        assert_eq!(reseed, None);
    }

    // ORCH-3 / M-RESTORE-1. A guest-reported failure of the mandatory clock resync
    // (`ResyncAck.clock_error = Some(..)`) must be surfaced as a typed failure —
    // NOT swallowed while `restored` is cleared as if it succeeded. Buggy impl
    // (ignore clock_error + `*restored = false`) returns `Ok(())`, clears
    // `restored`, and never retries, so a time-sensitive restored test silently
    // sees a frozen wall clock. This reddens on that inverse: it asserts the Err is
    // returned, `restored` stays set (so the next agent() call retries), and the
    // best-effort reseed result was NOT recorded past the failed mandatory step.
    #[tokio::test]
    async fn test_resync_clock_nonzero_exit_is_surfaced() {
        let clock = fixed_clock();
        let mut restored = true;
        let mut reseed = None;
        let mut exec = FakeGuestResync {
            outcome: crate::agent::ResyncOutcome {
                clock_error: Some("clock_settime: EPERM".into()),
                reseed_applied: false,
                mac_applied: false,
                ip_applied: false,
            },
            ..FakeGuestResync::default()
        };
        let res =
            maybe_resync_after_restore(&mut restored, &mut reseed, &mut exec, &clock, 5).await;
        assert!(
            matches!(res, Err(crate::error::Error::Agent(_))),
            "a guest clock-resync error must be a surfaced, typed failure, not Ok"
        );
        assert!(
            restored,
            "restored must STAY set after a failed mandatory clock resync so it retries"
        );
        assert_eq!(
            reseed, None,
            "the reseed result must not be recorded once the mandatory clock resync failed"
        );
        // The single native resync was attempted, but the fail-loud clock error
        // stops it before the reseed outcome is recorded.
        assert_eq!(
            exec.recorded.len(),
            1,
            "the resync round-trip was attempted once"
        );
    }

    /// A `CgroupFs` whose `read_stats` reports a configurable `mem_limit_enforced`,
    /// so `usage()` can be shown to surface the real enforcement state rather than
    /// a rosy constant.
    #[derive(Debug, Clone)]
    struct EnforcementCgroupFs {
        enforced: bool,
    }

    impl crate::metrics::CgroupFs for EnforcementCgroupFs {
        fn create_slice(&self, _name: &str, _limits: &crate::config::ResourceLimits) -> Result<()> {
            Ok(())
        }
        fn delete_slice(&self, _name: &str) -> Result<()> {
            Ok(())
        }
        fn read_stats(&self, _name: &str) -> Result<ResourceUsage> {
            Ok(ResourceUsage {
                mem_limit_enforced: self.enforced,
                ..ResourceUsage::default()
            })
        }
        fn add_task(&self, _name: &str, _pid: u32) -> Result<()> {
            Ok(())
        }
    }

    async fn start_with_cgroup(fs: EnforcementCgroupFs) -> MicroVm<crate::vmm::FakeVmm> {
        let vmm = crate::vmm::FakeVmm::default();
        let env = HostEnv {
            cgroups: std::sync::Arc::new(fs),
            ..HostEnv::for_unit_tests()
        };
        MicroVm::start(&vmm, erofs_cfg(), &env)
            .await
            .expect("start should succeed with fakes")
    }

    // H-FAILLOUD-1 (surfacing). When the cgroup reports limits NOT enforced (an
    // undelegated controller — the VM is effectively running unbounded), usage()
    // must surface mem_limit_enforced=false. Buggy impl that returns
    // ResourceUsage::default() unconditionally (ignoring read_stats) or hardcodes
    // true goes red here, while the inverse (enforced) test below stays green —
    // proving usage() reflects the real flag, not a constant.
    #[tokio::test]
    async fn test_usage_surfaces_unenforced_limits_honestly() {
        let vm = start_with_cgroup(EnforcementCgroupFs { enforced: false }).await;
        let usage = vm.usage().await.unwrap();
        assert!(
            !usage.mem_limit_enforced,
            "usage() must honestly surface that the requested limits are NOT enforced"
        );
    }

    #[tokio::test]
    async fn test_usage_surfaces_enforced_limits() {
        let vm = start_with_cgroup(EnforcementCgroupFs { enforced: true }).await;
        let usage = vm.usage().await.unwrap();
        assert!(
            usage.mem_limit_enforced,
            "usage() must surface enforced limits as true (control for the false case)"
        );
    }

    // H-FAILLOUD-1 (surfacing). The no-cgroup-attached branch (orchestrator
    // usage() else arm) must report mem_limit_enforced=false, not imply an all-zero,
    // measured-and-enforced usage. Buggy impl returning a usage with the flag
    // forced true (or omitting the field's honest default) goes red.
    #[tokio::test]
    async fn test_usage_without_cgroup_reports_unenforced() {
        let vm: MicroVm<crate::vmm::FakeVmm> = MicroVm {
            vmid: None,
            instance: None,
            netns: None,
            segment: None,
            #[cfg(feature = "net-unprivileged")]
            smoltcp: None,
            proxy: None,
            cgroup_name: None,
            env: HostEnv::for_unit_tests(),
            agent_client: None,
            restored: false,
            restore_reseed_applied: None,
            cid: None,
            tmp_dir: None,
            timeouts: crate::config::Timeouts::default(),
            control_plane_disabled: false,
        };
        let usage = vm.usage().await.unwrap();
        assert!(
            !usage.mem_limit_enforced,
            "with no cgroup attached, usage() must report limits as unenforced"
        );
    }

    // v15 §9.3 (The public API surface): pause/resume/snapshot are promoted to first-class MicroVm methods.
    // Each must FORWARD to the underlying VmInstance. The FakeVmInstance records every
    // call it receives, so the inverse — a no-op MicroVm method that silently does not
    // delegate — leaves the corresponding instance call unrecorded and goes red here.
    #[tokio::test]
    async fn test_microvm_lifecycle_verbs_delegate_to_instance() {
        let mut vm = start_with_cgroup(EnforcementCgroupFs { enforced: true }).await;
        vm.pause().await.expect("pause");
        vm.snapshot(std::path::Path::new("/tmp/vmcell-snap-test"))
            .await
            .expect("snapshot");
        vm.resume().await.expect("resume");
        let calls = vm.instance().calls.lock().expect("calls lock").clone();
        assert!(
            calls.contains(&"pause".to_string()),
            "MicroVm::pause must delegate to the instance: {calls:?}"
        );
        assert!(
            calls.contains(&"snapshot".to_string()),
            "MicroVm::snapshot must delegate to the instance: {calls:?}"
        );
        assert!(
            calls.contains(&"resume".to_string()),
            "MicroVm::resume must delegate to the instance: {calls:?}"
        );
    }

    // Builds a `MicroVm` around `instance` with a live cached `AgentClient`
    // seeded over one end of a socketpair, so a test can observe whether a
    // lifecycle verb invalidates the cache. Returns the peer end too: dropping
    // it would only half-close the stream, but keeping it alive makes the
    // "connection state untouched" reading of the Err-path test literal.
    fn vm_with_seeded_agent_client<V: Vmm>(
        instance: V::Instance,
    ) -> (MicroVm<V>, tokio::net::UnixStream) {
        let (local, peer) = tokio::net::UnixStream::pair().expect("socketpair");
        let vm = MicroVm::<V> {
            vmid: None,
            instance: Some(instance),
            netns: None,
            segment: None,
            #[cfg(feature = "net-unprivileged")]
            smoltcp: None,
            proxy: None,
            cgroup_name: None,
            env: HostEnv::for_unit_tests(),
            agent_client: Some(AgentClient::from_stream_for_tests(local)),
            restored: false,
            restore_reseed_applied: None,
            cid: None,
            tmp_dir: None,
            timeouts: crate::config::Timeouts::default(),
            control_plane_disabled: false,
        };
        (vm, peer)
    }

    // FC severs established vsock connections across its internal
    // pause/snapshot/resume cycle (CH keeps them alive), so a cached
    // `AgentClient` is dead on the resumed VM. `MicroVm::snapshot()`
    // self-guards by dropping the cache after a successful backend snapshot;
    // the next `agent()` call reconnects. RED on the inverse — a `snapshot()`
    // that forgets the invalidation leaves `agent_client` populated here.
    #[tokio::test]
    async fn test_snapshot_success_invalidates_cached_agent_client() {
        let instance = crate::vmm::FakeVmInstance {
            vsock_path: std::path::PathBuf::from("/tmp/vmcell-snap-inval-vsock.sock"),
            serial: std::path::PathBuf::from("/tmp/vmcell-snap-inval-serial.log"),
            calls: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
            faults: Default::default(),
            control_plane_probes: Default::default(),
        };
        let (mut vm, _peer) = vm_with_seeded_agent_client::<crate::vmm::FakeVmm>(instance);
        vm.snapshot(std::path::Path::new("/tmp/vmcell-snap-inval"))
            .await
            .expect("the fake snapshot succeeds");
        assert!(
            vm.agent_client.is_none(),
            "a successful snapshot() must invalidate the cached agent client \
             (FC severs established vsock connections across pause/snapshot/resume)"
        );
    }

    // A VMM/instance pair whose `snapshot()` always fails, to pin the Err path
    // of `MicroVm::snapshot()`: the snapshot did not happen, so the cached
    // agent connection must be left exactly as it was. `create`/`restore` are
    // unreachable — the test constructs the `MicroVm` directly, like the
    // teardown-order and grace tests.
    struct SnapFailVmm;

    impl Vmm for SnapFailVmm {
        type Instance = SnapFailInstance;

        async fn create(
            &self,
            _cfg: &VmConfig,
            _res: &PerVmResources,
            _cgroups: &dyn crate::metrics::CgroupFs,
        ) -> Result<Self::Instance> {
            unreachable!("snapshot Err-path test constructs MicroVm directly")
        }

        async fn restore(
            &self,
            _snapshot_dir: &std::path::Path,
            _cfg: &VmConfig,
            _res: &PerVmResources,
            _cgroups: &dyn crate::metrics::CgroupFs,
        ) -> Result<Self::Instance> {
            unreachable!("snapshot Err-path test constructs MicroVm directly")
        }

        fn capabilities(&self) -> crate::vmm::VmmCapabilities {
            unreachable!("MicroVm::snapshot() delegates without querying capabilities")
        }

        fn id(&self) -> &str {
            "snapfail"
        }
    }

    struct SnapFailInstance {
        vsock: std::path::PathBuf,
        serial: std::path::PathBuf,
    }

    impl VmInstance for SnapFailInstance {
        async fn boot(&mut self) -> Result<()> {
            Ok(())
        }
        async fn request_shutdown(&mut self) -> Result<()> {
            Ok(())
        }
        async fn kill(&mut self) -> Result<()> {
            Ok(())
        }
        async fn has_exited(&mut self) -> bool {
            true
        }
        async fn pause(&mut self) -> Result<()> {
            Ok(())
        }
        async fn resume(&mut self) -> Result<()> {
            Ok(())
        }
        async fn snapshot(&mut self, _dir: &std::path::Path) -> Result<()> {
            Err(crate::error::Error::Vmm("snapshot failed".into()))
        }
        fn vsock_path(&self) -> &std::path::Path {
            &self.vsock
        }
        fn guest_cid(&self) -> u32 {
            3
        }
        fn serial_log(&self) -> &std::path::Path {
            &self.serial
        }
    }

    // The Err path of `MicroVm::snapshot()` leaves the cached client alone:
    // no snapshot happened, so the connection state is whatever it already
    // was. RED on an unconditional invalidation (dropping the cache before or
    // regardless of the backend result).
    #[tokio::test]
    async fn test_snapshot_failure_keeps_cached_agent_client() {
        let instance = SnapFailInstance {
            vsock: std::path::PathBuf::from("/tmp/vmcell-snap-fail-vsock.sock"),
            serial: std::path::PathBuf::from("/tmp/vmcell-snap-fail-serial.log"),
        };
        let (mut vm, _peer) = vm_with_seeded_agent_client::<SnapFailVmm>(instance);
        let result = vm
            .snapshot(std::path::Path::new("/tmp/vmcell-snap-fail"))
            .await;
        assert!(result.is_err(), "the failing fake must surface its error");
        assert!(
            vm.agent_client.is_some(),
            "a failed snapshot() must leave the cached agent client in place \
             (the snapshot didn't happen, so the connection is untouched)"
        );
    }

    // ORCH-5 (B1/B6). Dropping a `MicroVm` that holds a REAL `Some(cid)` /
    // `Some(vmid)` guard must return BOTH ids to their allocators. The existing
    // drop-order builder sets `cid: None, vmid: None`, so its guard-Drop release
    // paths are no-ops; `test_allocate_vmid` exercises `release()` directly, not
    // guard-Drop. This builds the guards, captures the ids, drops the VM, and
    // asserts the SAME ids are handed back out. The no-op-release inverse (a
    // `Drop`/guard that does not call `release()`) reddens: the CID re-allocation
    // would skip `cid` and the VMID re-reservation would fail `Exhaustion`.
    #[test]
    fn test_drop_returns_cid_and_vmid_to_allocators() {
        let cid_alloc = std::sync::Arc::new(crate::vmm::CidAllocator::new());
        let vmid_alloc = VmidAllocator::new();
        let cid = cid_alloc.allocate().expect("cid"); // lowest free = 3
        let vmid = vmid_alloc.reserve(9).expect("vmid");

        let vm: MicroVm<crate::vmm::FakeVmm> = MicroVm {
            vmid: Some(VmidGuard {
                vmid,
                allocator: vmid_alloc.clone(),
            }),
            instance: None,
            netns: None,
            segment: None,
            #[cfg(feature = "net-unprivileged")]
            smoltcp: None,
            proxy: None,
            cgroup_name: None,
            env: HostEnv::for_unit_tests(),
            agent_client: None,
            restored: false,
            restore_reseed_applied: None,
            cid: Some(CidGuard {
                cid,
                allocator: cid_alloc.clone(),
            }),
            tmp_dir: None,
            timeouts: crate::config::Timeouts::default(),
            control_plane_disabled: false,
        };
        drop(vm);

        assert_eq!(
            cid_alloc.allocate().expect("cid re-alloc"),
            cid,
            "the CID must be returned to the allocator on guard-Drop"
        );
        assert!(
            vmid_alloc.reserve(vmid).is_ok(),
            "the VMID must be returned to the allocator on guard-Drop"
        );
    }

    // ---- ORCH-6: orphan sweeper (recording fakes) ----

    struct FakeOrphanScanner {
        netns: Vec<String>,
        segment_netns: Vec<String>,
        cgroups: Vec<String>,
        scratch: Vec<std::path::PathBuf>,
    }
    impl OrphanScanner for FakeOrphanScanner {
        fn scan_netns(&self) -> Vec<String> {
            self.netns.clone()
        }
        fn scan_segment_netns(&self) -> Vec<String> {
            self.segment_netns.clone()
        }
        fn scan_cgroup_slices(&self) -> Vec<String> {
            self.cgroups.clone()
        }
        fn scan_scratch_dirs(&self) -> Vec<std::path::PathBuf> {
            self.scratch.clone()
        }
    }

    #[cfg(feature = "net-privileged")]
    struct RecordingSweepNetlink {
        log: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    }
    #[cfg(feature = "net-privileged")]
    impl crate::net::tap::Netlink for RecordingSweepNetlink {
        fn add_netns(&self, _name: &str) -> Result<()> {
            Ok(())
        }
        fn setup_tap(
            &self,
            _netns: &str,
            _tap: &str,
            _vmid: u32,
        ) -> Result<Option<tun_tap::Iface>> {
            Ok(None)
        }
        fn create_bridge(
            &self,
            _netns: &str,
            _bridge: &str,
            _gateway: std::net::Ipv4Addr,
            _prefix_len: u8,
        ) -> Result<()> {
            Ok(())
        }
        fn setup_tap_on_bridge(&self, _netns: &str, _tap: &str, _bridge: &str) -> Result<()> {
            Ok(())
        }
        fn delete_link(&self, _netns: &str, _link: &str) -> Result<()> {
            Ok(())
        }
        fn delete_netns(&self, name: &str) -> Result<()> {
            self.log
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(format!("netns:{name}"));
            Ok(())
        }
        fn setup_tproxy_routing(&self, _netns: &str) -> Result<()> {
            Ok(())
        }
    }

    #[derive(Clone)]
    struct RecordingSweepCgroupFs {
        log: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    }
    impl std::fmt::Debug for RecordingSweepCgroupFs {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("RecordingSweepCgroupFs")
        }
    }
    impl crate::metrics::CgroupFs for RecordingSweepCgroupFs {
        fn create_slice(&self, _name: &str, _limits: &crate::config::ResourceLimits) -> Result<()> {
            Ok(())
        }
        fn delete_slice(&self, name: &str) -> Result<()> {
            self.log
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(format!("cgroup:{name}"));
            Ok(())
        }
        fn read_stats(&self, _name: &str) -> Result<ResourceUsage> {
            Ok(ResourceUsage::default())
        }
        fn add_task(&self, _name: &str, _pid: u32) -> Result<()> {
            Ok(())
        }
    }

    // ORCH-6. `sweep_orphans` must reclaim ONLY resources whose trailing id is
    // not live IN ITS OWN ID SPACE, in the canonical teardown order (netns -> segment netns ->
    // cgroup -> scratch dir), through the injected Netlink/CgroupFs seams. Seeds the scanner with
    // an orphan (vmid 3) and a live (vmid 7) entry of each kind. Reddens on: sweeping
    // a live id (no-skip), skipping an orphan, or reordering netns-vs-cgroup.
    //
    // v30 §18 delta 8 leg (the WRONG-ID-SPACE inverse): `vmcell-seg-7` is planted while vmid 7 is
    // live and segid 7 is NOT. `trailing_id` parses it as 7 just as happily as `vmcell-net-7`, so
    // a sweep that checked the `-seg-` class against `live_vmids` would spare it forever (failing
    // OPEN) — the assertion that it IS reclaimed reddens on exactly that bug. Its mirror
    // (`vmcell-seg-9`, live segid 9, no live vmid 9) reddens on the opposite miswiring, which
    // would destroy a live segment under its members.
    #[cfg(feature = "net-privileged")]
    #[test]
    fn test_sweep_orphans_reclaims_only_dead_ids_in_order() {
        let log = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let nl = RecordingSweepNetlink { log: log.clone() };
        let cg = RecordingSweepCgroupFs { log: log.clone() };
        let live: std::collections::BTreeSet<u32> = [7].into_iter().collect();
        let live_segids: std::collections::BTreeSet<u32> = [9].into_iter().collect();

        // Real scratch dirs so removal is observable on disk (unique per process).
        let base = std::env::temp_dir();
        let pid = std::process::id();
        let orphan_dir = base.join(format!("vmcell-vm-{pid}-3"));
        let live_dir = base.join(format!("vmcell-vm-{pid}-7"));
        std::fs::create_dir_all(&orphan_dir).expect("orphan dir");
        std::fs::create_dir_all(&live_dir).expect("live dir");

        let scanner = FakeOrphanScanner {
            netns: vec!["vmcell-net-3".into(), "vmcell-net-7".into()],
            segment_netns: vec!["vmcell-seg-7".into(), "vmcell-seg-9".into()],
            cgroups: vec!["base/vmcell-vm-3".into(), "base/vmcell-vm-7".into()],
            scratch: vec![orphan_dir.clone(), live_dir.clone()],
        };

        let report = sweep_orphans(&scanner, &nl, &cg, &live, &live_segids);

        // Only the dead (vmid 3) resources were swept; the live (vmid 7) kept.
        assert_eq!(report.netns, vec!["vmcell-net-3".to_string()]);
        assert_eq!(report.cgroup_slices, vec!["base/vmcell-vm-3".to_string()]);
        assert_eq!(report.scratch_dirs, vec![orphan_dir.clone()]);
        assert!(
            !orphan_dir.exists(),
            "the orphan scratch dir must be removed"
        );
        assert!(live_dir.exists(), "the live scratch dir must be kept");

        // The segment class against SEGIDS: segid 7 is dead (vmid 7 being live is irrelevant),
        // segid 9 is live.
        assert_eq!(
            report.segment_netns,
            vec!["vmcell-seg-7".to_string()],
            "a leaked segment must be reclaimed against live SEGIDS, not live vmids"
        );

        // Every netns delete precedes every cgroup delete, and only orphans were
        // deleted through the injected seams.
        let calls = log.lock().unwrap_or_else(|e| e.into_inner()).clone();
        assert_eq!(
            calls,
            vec![
                "netns:vmcell-net-3".to_string(),
                "netns:vmcell-seg-7".to_string(),
                "cgroup:base/vmcell-vm-3".to_string(),
            ],
            "sweep must delete only the orphans, netns before cgroup: {calls:?}"
        );

        let _ = std::fs::remove_dir_all(&live_dir);
    }

    // ---- ORCH-2: shutdown() tears down the proxy BEFORE the netns ----
    //
    // The old `shutdown()` deleted the netns before dropping the egress proxy that
    // runs inside it. Route both `shutdown()` and `Drop` through one shared
    // ordered helper so they cannot diverge. This drives the REAL `shutdown()`
    // path with a real loopback `EgressProxy`, a recording netns, and a recording
    // cgroup. The recording netns, at delete time, probes whether the proxy's port
    // is already free: `EgressProxy::Drop` synchronously joins its thread (freeing
    // the port), so in the correct order the port is free ("proxy_gone") by the
    // time the netns is deleted. The inverse (netns removed while the proxy still
    // listens) makes the probe find the port bound ("proxy_present") -> red.
    #[cfg(all(feature = "net-privileged", feature = "proxy"))]
    struct ShutdownOrderNetlink {
        log: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
        proxy_port: u16,
    }
    #[cfg(all(feature = "net-privileged", feature = "proxy"))]
    impl crate::net::tap::Netlink for ShutdownOrderNetlink {
        fn add_netns(&self, _name: &str) -> Result<()> {
            Ok(())
        }
        fn setup_tap(
            &self,
            _netns: &str,
            _tap: &str,
            _vmid: u32,
        ) -> Result<Option<tun_tap::Iface>> {
            Ok(None)
        }
        fn delete_netns(&self, name: &str) -> Result<()> {
            let mut log = self.log.lock().unwrap_or_else(|e| e.into_inner());
            log.push(format!("netns_delete:{name}"));
            // If the proxy's port is bindable now, the proxy was torn down BEFORE
            // this netns delete (correct order); if still bound, the netns is being
            // removed while the proxy runs inside it (the ORCH-2 bug).
            let probe = std::net::TcpListener::bind(("127.0.0.1", self.proxy_port));
            log.push(if probe.is_ok() {
                "proxy_gone".to_string()
            } else {
                "proxy_present".to_string()
            });
            Ok(())
        }
        fn create_bridge(
            &self,
            _netns: &str,
            _bridge: &str,
            _gateway: std::net::Ipv4Addr,
            _prefix_len: u8,
        ) -> Result<()> {
            Ok(())
        }
        fn setup_tap_on_bridge(&self, _netns: &str, _tap: &str, _bridge: &str) -> Result<()> {
            Ok(())
        }
        fn delete_link(&self, _netns: &str, _link: &str) -> Result<()> {
            Ok(())
        }
        fn setup_tproxy_routing(&self, _netns: &str) -> Result<()> {
            Ok(())
        }
    }

    #[cfg(all(feature = "net-privileged", feature = "proxy"))]
    #[tokio::test]
    async fn test_shutdown_tears_down_proxy_before_netns() {
        let proxy = EgressProxy::start(ProxyConfig::default())
            .await
            .expect("real loopback proxy must start");
        let port = proxy.port;
        let log = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));

        let netns = NetNamespace::create(
            "vmcell",
            11,
            Box::new(ShutdownOrderNetlink {
                log: log.clone(),
                proxy_port: port,
            }),
        )
        .expect("fake netns create");

        let instance = crate::vmm::FakeVmInstance {
            vsock_path: std::path::PathBuf::from("/tmp/vmcell-shutdown-vsock.sock"),
            serial: std::path::PathBuf::from("/tmp/vmcell-shutdown-serial.log"),
            calls: log.clone(),
            faults: Default::default(),
            control_plane_probes: Default::default(),
        };

        let vm = MicroVm::<crate::vmm::FakeVmm> {
            vmid: None,
            instance: Some(instance),
            netns: Some(netns),
            segment: None,
            #[cfg(feature = "net-unprivileged")]
            smoltcp: None,
            proxy: Some(proxy),
            cgroup_name: Some("vmcell-vm-11".to_string()),
            env: HostEnv {
                cgroups: std::sync::Arc::new(TimelineCgroupFs { log: log.clone() }),
                ..HostEnv::for_unit_tests()
            },
            agent_client: None,
            restored: false,
            restore_reseed_applied: None,
            cid: None,
            tmp_dir: None,
            timeouts: crate::config::Timeouts::default(),
            control_plane_disabled: false,
        };

        vm.shutdown().await.expect("shutdown ok");

        let calls = log.lock().unwrap_or_else(|e| e.into_inner()).clone();
        assert!(
            calls.iter().any(|c| c == "proxy_gone"),
            "the proxy must be torn down BEFORE the netns is deleted: {calls:?}"
        );
        assert!(
            !calls.iter().any(|c| c == "proxy_present"),
            "the netns must NOT be deleted while the proxy still runs inside it: {calls:?}"
        );
        let idx = |needle: &str| calls.iter().position(|c| c == needle);
        let drop_i = idx("drop").expect("instance drop recorded");
        let netns_i = idx("netns_delete:vmcell-net-11").expect("netns delete recorded");
        let cg_i = idx("cgroup_delete").expect("cgroup delete recorded");
        assert!(
            drop_i < netns_i && netns_i < cg_i,
            "shutdown() teardown must be instance -> netns -> cgroup: {calls:?}"
        );
        // ORCH-7: request_shutdown precedes the SIGKILL fallback (the grace sits
        // between them).
        let rs_i = idx("request_shutdown").expect("request_shutdown recorded");
        let kill_i = idx("kill").expect("kill recorded");
        assert!(
            rs_i < kill_i,
            "request_shutdown must precede the SIGKILL fallback: {calls:?}"
        );
    }

    // ---- EXP-D (ORCH-7 refinement): grace-deadline placement + adaptive poll step ----
    //
    // A driven fake whose `request_shutdown` RPC blocks for a configurable time
    // and whose `has_exited` answer is scripted (always `false` here — a guest
    // that never exits on its own), recording every call into a shared timeline.
    // `create`/`restore` are unreachable: these tests construct the `MicroVm`
    // directly, like the teardown-order tests above.
    struct GraceVmm;

    impl Vmm for GraceVmm {
        type Instance = GraceInstance;

        async fn create(
            &self,
            _cfg: &VmConfig,
            _res: &PerVmResources,
            _cgroups: &dyn crate::metrics::CgroupFs,
        ) -> Result<Self::Instance> {
            unreachable!("grace tests construct MicroVm directly")
        }

        async fn restore(
            &self,
            _snapshot_dir: &std::path::Path,
            _cfg: &VmConfig,
            _res: &PerVmResources,
            _cgroups: &dyn crate::metrics::CgroupFs,
        ) -> Result<Self::Instance> {
            unreachable!("grace tests construct MicroVm directly")
        }

        fn capabilities(&self) -> crate::vmm::VmmCapabilities {
            unreachable!("shutdown() never queries capabilities")
        }

        fn id(&self) -> &str {
            "grace-fake"
        }
    }

    struct GraceInstance {
        calls: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
        // How long the fake shutdown RPC blocks before acknowledging.
        rpc_delay: std::time::Duration,
        vsock: std::path::PathBuf,
        serial: std::path::PathBuf,
    }

    impl VmInstance for GraceInstance {
        async fn boot(&mut self) -> Result<()> {
            Ok(())
        }
        async fn request_shutdown(&mut self) -> Result<()> {
            self.calls
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push("request_shutdown".to_string());
            tokio::time::sleep(self.rpc_delay).await;
            Ok(())
        }
        async fn kill(&mut self) -> Result<()> {
            self.calls
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push("kill".to_string());
            Ok(())
        }
        async fn has_exited(&mut self) -> bool {
            self.calls
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push("has_exited".to_string());
            false
        }
        async fn pause(&mut self) -> Result<()> {
            Ok(())
        }
        async fn resume(&mut self) -> Result<()> {
            Ok(())
        }
        async fn snapshot(&mut self, _dir: &std::path::Path) -> Result<()> {
            Ok(())
        }
        fn vsock_path(&self) -> &std::path::Path {
            &self.vsock
        }
        fn guest_cid(&self) -> u32 {
            3
        }
        fn serial_log(&self) -> &std::path::Path {
            &self.serial
        }
    }

    fn grace_vm(
        rpc_delay: std::time::Duration,
        grace: std::time::Duration,
        calls: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    ) -> MicroVm<GraceVmm> {
        MicroVm::<GraceVmm> {
            vmid: None,
            instance: Some(GraceInstance {
                calls,
                rpc_delay,
                vsock: std::path::PathBuf::from("/tmp/vmcell-grace-vsock.sock"),
                serial: std::path::PathBuf::from("/tmp/vmcell-grace-serial.log"),
            }),
            netns: None,
            segment: None,
            #[cfg(feature = "net-unprivileged")]
            smoltcp: None,
            proxy: None,
            cgroup_name: None,
            env: HostEnv::for_unit_tests(),
            agent_client: None,
            restored: false,
            restore_reseed_applied: None,
            cid: None,
            tmp_dir: None,
            timeouts: crate::config::Timeouts {
                shutdown_grace: grace,
                ..crate::config::Timeouts::default()
            },
            control_plane_disabled: false,
        }
    }

    // §5.3 (The kernel command line): a custom `init=` replaces the guest agent, so `agent()` must fail LOUD
    // immediately (a typed `Error::Agent` naming the cause) instead of blocking for the
    // full connect timeout on a listener that will never answer (§13, Cross-cutting invariants, fail-loud).
    // Inverse: drop the `control_plane_disabled` early-return in `agent()` and this
    // either hangs (the 1 s timeout) or returns a connect error, not the custom-init
    // one — reddening the message assertion.
    #[tokio::test]
    async fn agent_fails_loud_when_control_plane_disabled() {
        let mut vm = MicroVm::<crate::vmm::FakeVmm> {
            vmid: None,
            instance: Some(crate::vmm::FakeVmInstance {
                vsock_path: std::path::PathBuf::from("/tmp/vmcell-noagent-vsock.sock"),
                serial: std::path::PathBuf::from("/tmp/vmcell-noagent-serial.log"),
                calls: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
                faults: Default::default(),
                control_plane_probes: Default::default(),
            }),
            netns: None,
            segment: None,
            #[cfg(feature = "net-unprivileged")]
            smoltcp: None,
            proxy: None,
            cgroup_name: None,
            env: HostEnv::for_unit_tests(),
            agent_client: None,
            restored: false,
            restore_reseed_applied: None,
            cid: None,
            tmp_dir: None,
            timeouts: crate::config::Timeouts::default(),
            control_plane_disabled: true,
        };
        let err = vm
            .agent(Some(std::time::Duration::from_secs(1)))
            .await
            .expect_err("agent() must fail loud when a custom init disabled the control plane");
        assert!(
            matches!(err, crate::error::Error::Agent(_)),
            "expected a typed Agent error, got {err:?}"
        );
        assert!(
            err.to_string().contains("custom init"),
            "the error must name the custom-init cause: {err}"
        );
    }

    // §3.2 (The host side: AgentClient and SessionMux) / §18 delta 7: `dial_vsock` must NOT copy
    // `agent()`'s custom-init guard. The vsock DEVICE is attached unconditionally by
    // every backend (none reads `cfg.init`), so a custom-init guest that binds a vsock
    // port is reachable even with no agent anywhere — that is the whole point of the
    // raw dial. This drives the real transport (a mock bridge on a UDS) through a VM
    // whose `control_plane_disabled` is TRUE and asserts the dial reached the wire:
    // the bridge saw a `CONNECT` for the DIALED port, and the handle came back.
    // Red-on-inverse: adding the `control_plane_disabled` early-return to
    // `dial_vsock` makes this fail with the custom-init Agent error instead.
    #[tokio::test]
    async fn dial_vsock_bypasses_the_custom_init_guard() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let sock = std::env::temp_dir().join(format!(
            "vmcell-dialguard-{}-{:?}.sock",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_file(&sock);
        let listener = tokio::net::UnixListener::bind(&sock).expect("bind mock vsock bridge");

        // The mock bridge: read the CONNECT line byte-by-byte, answer OK, and hold the
        // connection open (returned, not dropped) so the dialed handle stays valid.
        let bridge = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut line = String::new();
            loop {
                let mut byte = [0u8; 1];
                match stream.read(&mut byte).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {
                        line.push(byte[0] as char);
                        if byte[0] == b'\n' {
                            break;
                        }
                    }
                }
            }
            stream.write_all(b"OK 7000\n").await.expect("write OK");
            (line, stream)
        });

        let vm = MicroVm::<crate::vmm::FakeVmm> {
            vmid: None,
            instance: Some(crate::vmm::FakeVmInstance {
                vsock_path: sock.clone(),
                serial: std::path::PathBuf::from("/dev/null"),
                calls: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
                faults: Default::default(),
                control_plane_probes: Default::default(),
            }),
            netns: None,
            segment: None,
            #[cfg(feature = "net-unprivileged")]
            smoltcp: None,
            proxy: None,
            cgroup_name: None,
            env: HostEnv::for_unit_tests(),
            agent_client: None,
            restored: false,
            restore_reseed_applied: None,
            cid: None,
            tmp_dir: None,
            timeouts: crate::config::Timeouts::default(),
            // The VM boots a custom init=: no agent, no control plane — and the dial
            // must work anyway.
            control_plane_disabled: true,
        };

        let dialed = vm.dial_vsock(7000, std::time::Duration::from_secs(5)).await;
        // Asserted BEFORE joining the bridge: a `dial_vsock` that short-circuits on
        // `control_plane_disabled` never connects, so joining first would hang the
        // inverse instead of failing it.
        assert!(
            dialed.is_ok(),
            "dial_vsock must reach the transport on a custom-init VM (the vsock device \
             is attached unconditionally); got {dialed:?}"
        );
        let (line, _held) = bridge.await.expect("mock bridge task");
        assert_eq!(
            line, "CONNECT 7000\n",
            "the dial must CONNECT to the port the caller asked for, not the agent's"
        );
        let _ = std::fs::remove_file(&sock);
    }

    // EXP-D (c): the adaptive step's exact thresholds — <= 50 ms -> 5 ms,
    // <= 150 ms -> 10 ms, else 20 ms — with both sides of each boundary pinned
    // so an off-by-one (`<` vs `<=`) goes red.
    #[test]
    fn test_shutdown_poll_step_thresholds() {
        use std::time::Duration;
        let step = |ms| shutdown_poll_step(Duration::from_millis(ms));
        assert_eq!(step(1), Duration::from_millis(5));
        assert_eq!(step(50), Duration::from_millis(5));
        assert_eq!(step(51), Duration::from_millis(10));
        assert_eq!(step(150), Duration::from_millis(10));
        assert_eq!(step(151), Duration::from_millis(20));
        assert_eq!(step(250), Duration::from_millis(20));
    }

    // EXP-D (a)+(b): the grace window opens at RPC-send with a one-poll-step
    // post-ack floor. `request_shutdown` has no timeout, so this fake stalls the
    // RPC for ~grace-length (60 ms >= the 50 ms grace): the pre-RPC deadline has
    // already passed by the time the ack arrives. The clamp must still grant
    // >= 1 `has_exited` poll after the ack — RED on a naive pre-RPC deadline
    // without the post-RPC clamp (the loop is skipped: zero polls, ~0 post-ack
    // flush). The elapsed bound additionally pins the deadline *placement*:
    // computing it after the RPC (the old code) would hold this never-exiting
    // guest for rpc_delay + grace ~= 110 ms, while the fixed placement returns
    // after ~rpc_delay + one 5 ms poll step (~65 ms).
    // L-ORCH-5: `start_paused` makes tokio time deterministic — every delay in the
    // fake and the shutdown loop is a `tokio::time::sleep`, so virtual time
    // advances exactly by the scheduled durations with no wall-clock jitter. The
    // elapsed measurement uses `tokio::time::Instant` (virtual), so the bounds
    // pin the deadline arithmetic exactly instead of racing the host scheduler.
    #[tokio::test(start_paused = true)]
    async fn test_shutdown_stalled_rpc_still_gets_post_ack_poll() {
        let calls = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let vm = grace_vm(
            std::time::Duration::from_millis(60),
            std::time::Duration::from_millis(50),
            calls.clone(),
        );
        let started = tokio::time::Instant::now();
        vm.shutdown().await.expect("shutdown ok");
        let elapsed = started.elapsed();

        let log = calls.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let idx = |needle: &str| log.iter().position(|c| c == needle);
        let rs_i = idx("request_shutdown").expect("request_shutdown recorded");
        let kill_i = idx("kill").expect("kill recorded");
        let post_ack_polls = log
            .iter()
            .enumerate()
            .filter(|(i, c)| c.as_str() == "has_exited" && *i > rs_i && *i < kill_i)
            .count();
        assert!(
            post_ack_polls >= 1,
            "a stalled shutdown RPC must still yield >= 1 post-ack has_exited poll \
             before the force-kill: {log:?}"
        );
        assert!(
            elapsed < std::time::Duration::from_millis(95),
            "the grace window must open at RPC-send, not restart at RPC-return \
             (60 ms RPC + 50 ms grace would be ~110 ms): {elapsed:?}"
        );
    }

    // EXP-D (c): a 50 ms grace derives a 5 ms poll step, so a never-exiting
    // guest holds shutdown() for the grace ceiling plus at most one step
    // (~[50, 55) ms). RED on the old fixed 20 ms step: its 0/20/40 grid's final
    // sleep cannot land before 60 ms (tokio sleeps never wake early), outside
    // the < 60 ms bound. The poll count is the jitter-robust second signal: a
    // 5 ms step fits >= 4 polls into the window even under heavy scheduler
    // noise, while the 20 ms grid gets at most 3.
    // L-ORCH-5: deterministic tokio time (see the sibling test above).
    #[tokio::test(start_paused = true)]
    async fn test_shutdown_grace_50ms_polls_finely_and_returns_on_time() {
        let calls = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let vm = grace_vm(
            std::time::Duration::ZERO,
            std::time::Duration::from_millis(50),
            calls.clone(),
        );
        let started = tokio::time::Instant::now();
        vm.shutdown().await.expect("shutdown ok");
        let elapsed = started.elapsed();

        assert!(
            elapsed >= std::time::Duration::from_millis(50),
            "a never-exiting guest must be granted the full grace ceiling: {elapsed:?}"
        );
        assert!(
            elapsed < std::time::Duration::from_millis(60),
            "a 50 ms grace must not be quantized onto a coarser poll grid: {elapsed:?}"
        );
        let log = calls.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let polls = log.iter().filter(|c| c.as_str() == "has_exited").count();
        assert!(
            polls >= 4,
            "a 50 ms grace must poll on a 5 ms step (>= 4 polls), not the coarse \
             20 ms grid (exactly 3): {polls} polls, {log:?}"
        );
    }
}
