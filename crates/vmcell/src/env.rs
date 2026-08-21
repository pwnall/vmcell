//! The process-wide seam bundle (`HostEnv`).
//!
//! Every injected seam that is process-global — or that every VM in a process shares — lives in one
//! struct, built **once** per process and passed by reference to every spawn entry point
//! ([`MicroVm::start`](crate::MicroVm::start)/[`restore`](crate::MicroVm::restore)/
//! [`restore_cow`](crate::MicroVm::restore_cow), [`Zygote::spawn_clone`](crate::Zygote::spawn_clone)/
//! [`spawn_clones`](crate::Zygote::spawn_clones), [`Lineage::fork`](crate::Lineage::fork)/
//! [`fork_many`](crate::Lineage::fork_many)).
//!
//! Bundling the allocators with the `CgroupFs`, `Clock`, and `OverlayStore` seams gives every spawn
//! **one** parameter instead of the three-to-five positional injected arguments that grew by one per
//! feature, removes the per-clone `make_cgroups` closures from the fan-out APIs, and lets `steward()`
//! drop its clock seam (the post-restore resync reads the clock captured here at construction). This
//! bundle is directed by design §18 (Delta register: changes from the validated v27 build) (deltas
//! 1–2) and is the one breaking change of the 0.10 pass.
//!
//! The allocators are process-global **by design**: under `cargo test`'s in-process parallelism,
//! per-test allocators hand concurrent tests identical IDs and collide on temp-dir paths and socket
//! names. [`HostEnv::shared`] is the productized pair (the daemon is its natural single home, §11.1,
//! What it adds, and where it sits);
//! [`HostEnv::hermetic`] gives in-process allocators to a **single-process** caller — `vmcell run`,
//! both artifact builders, `bench-vm`, the validator harness — while keeping the same real host
//! seams. It is hermetic in its *allocators*, not in its host effects: a VM started through it gets
//! a real cgroup slice, so it needs the host cgroup tree delegated to the calling process. A caller
//! that wants a seam faked assigns the field (every field is `pub`); `vmcell`'s own unit tests use
//! the `#[cfg(test)]` `for_unit_tests()` bundle instead, which is why `hermetic()` is
//! `#[cfg(not(test))]` here.
//!
//! One law follows (invariant S4): **every** copy-on-write clone materializes through
//! [`HostEnv::overlay`] — there is no second way to inject a store that could drift from the one the
//! rest of the process uses.

use std::sync::Arc;

use crate::metrics::{CgroupFs, DefaultCgroupFs};
use crate::orchestrator::{Clock, RealClock, SegmentIdAllocator, VmidAllocator};
use crate::overlay::{OverlayStore, ReflinkOverlayStore};
use crate::vmm::CidAllocator;

/// The process-wide seam bundle passed by reference to every VM-spawning entry point.
///
/// Build one at start-up ([`shared`](HostEnv::shared) for a multi-process host,
/// [`hermetic`](HostEnv::hermetic) for a single-process one) and thread `&env` everywhere. The
/// fields are `pub` so a caller can substitute a recording fake for any single seam; because the
/// struct is `#[non_exhaustive]`, a crate outside `vmcell` assigns the field after construction
/// rather than using functional-update syntax.
///
/// `#[non_exhaustive]`: this bundle is designed to **grow** — a new process-global seam is added as a
/// field here, not as a new positional argument on every spawn signature.
#[derive(Clone)]
#[non_exhaustive]
pub struct HostEnv {
    /// The CID allocator (guest vsock context IDs, `vmm::MIN_GUEST_CID..=vmm::MAX_GUEST_CID`).
    pub cids: Arc<CidAllocator>,
    /// The VMID allocator (`1..=net::MAX_VMID`; `shared()` for cross-process uniqueness, `new()` hermetic).
    pub vmids: VmidAllocator,
    /// The segment-id allocator (`1..=254`, §6.5 VM-to-VM segments) — its **own** id space, over
    /// the same cross-process claim law as `vmids` (an additive field: this bundle grows by field,
    /// never by a new positional argument).
    pub segids: SegmentIdAllocator,
    /// The cgroup-v2 backend every VM's slice is created/limited/read through.
    pub cgroups: Arc<dyn CgroupFs>,
    /// The clock that drives the mandatory first post-restore resync (§8.2, Restore correctness: a
    /// restored VM is not a fresh VM). The `+ RefUnwindSafe`
    /// bound keeps `HostEnv` (and anything embedding it) `UnwindSafe`/`RefUnwindSafe` — a bare
    /// `dyn Clock` trait object silently drops those auto-traits; both `Clock` impls satisfy it.
    pub clock: Arc<dyn Clock + std::panic::RefUnwindSafe>,
    /// The seam every copy-on-write clone materializes through (invariant S4, §8.4, The zygote
    /// fan-out and the OverlayStore seam).
    pub overlay: Arc<dyn OverlayStore>,
}

impl std::fmt::Debug for HostEnv {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `Clock` is not `Debug` (it is a minimal `Send + Sync` seam), so the bundle prints its
        // `Debug`-able seams and elides the clock rather than deriving.
        f.debug_struct("HostEnv")
            .field("cids", &self.cids)
            .field("vmids", &self.vmids)
            .field("segids", &self.segids)
            .field("cgroups", &self.cgroups)
            .field("overlay", &self.overlay)
            .finish_non_exhaustive()
    }
}

impl HostEnv {
    /// The production bundle: a cross-process [`VmidAllocator::shared`] (so several processes on one
    /// host draw distinct VMIDs), a fresh [`CidAllocator`], the real sysfs [`DefaultCgroupFs`], a
    /// [`RealClock`], and the default [`ReflinkOverlayStore`].
    ///
    /// # Errors
    /// Currently infallible, but returns [`Result`](crate::Result) so a future fallible start-up
    /// probe (e.g. the §11, The control-plane daemon (vmcelld) daemon's one-time host-capability
    /// check) can be folded in without a
    /// signature break.
    pub fn shared() -> crate::Result<Self> {
        Ok(Self {
            cids: Arc::new(CidAllocator::new()),
            vmids: VmidAllocator::shared(),
            segids: SegmentIdAllocator::shared(),
            cgroups: Arc::new(DefaultCgroupFs),
            clock: Arc::new(RealClock),
            overlay: Arc::new(ReflinkOverlayStore),
        })
    }

    /// The **in-process** bundle: [`VmidAllocator::new`] and friends instead of the cross-process
    /// `/tmp` claim files, so a single-process tool draws its ids without the rendezvous — plus the
    /// same real [`DefaultCgroupFs`]/[`RealClock`]/[`ReflinkOverlayStore`] host seams `shared()`
    /// uses. It is hermetic in its **allocators**, not in its host effects: a VM started through it
    /// gets a real cgroup slice, real reflink clones, and the real clock. That is what the shipping
    /// single-process callers want — `vmcell run`, both artifact builders, `bench-vm`, and the
    /// validator harness — and it is why this constructor keeps the real seams.
    ///
    /// A caller that wants a *seam* faked substitutes it field-by-field (the fields are `pub`, and
    /// the struct is `#[non_exhaustive]`, so a downstream crate assigns after construction rather
    /// than using functional-update syntax):
    ///
    /// ```text
    /// let mut env = HostEnv::hermetic();
    /// env.cgroups = Arc::new(MyCgroupFs);   // assign, don't `..HostEnv::hermetic()`
    /// ```
    ///
    /// `vmcell`'s own unit tests do not call this — see the `#[cfg(not(test))]` note at the
    /// definition.
    //
    // `#[cfg(not(test))]` is deliberate and is a GATE, not an accident. This constructor wires the
    // real sysfs `DefaultCgroupFs`, so any lib unit test that reaches `MicroVm::start` through it
    // needs the host cgroup tree DELEGATED to the test process: `setup_env` composes
    // `<base-from-/proc/self/cgroup>/<prefix>-vm-<vmid>` and `create_dir_all`s it under
    // /sys/fs/cgroup. A systemd user session is delegated, so it works on a developer box; a GitHub
    // hosted runner sits under `system.slice/hosted-compute-agent.service`, which is not, so 21
    // KVM-free unit tests failed there with `Cgroup("create cgroup …: Permission denied (os error
    // 13)")` while every one of them passed locally. Hiding the constructor from the crate's own
    // test build turns that green-here/red-in-CI landmine into a compile error naming
    // `for_unit_tests()`. Integration tests under crates/vmcell/tests/, doctests, and every
    // downstream crate link the non-test lib and see it exactly as before, so the public API and
    // `cargo semver-checks` are unchanged.
    #[cfg(not(test))]
    #[must_use]
    pub fn hermetic() -> Self {
        Self {
            cids: Arc::new(CidAllocator::new()),
            vmids: VmidAllocator::new(),
            segids: SegmentIdAllocator::new(),
            cgroups: Arc::new(DefaultCgroupFs),
            clock: Arc::new(RealClock),
            overlay: Arc::new(ReflinkOverlayStore),
        }
    }
}

#[cfg(test)]
impl HostEnv {
    /// The bundle every `vmcell` lib unit test starts from: `hermetic()`'s in-process allocators,
    /// with the real sysfs cgroup backend replaced by the in-process [`crate::metrics::FakeCgroupFs`]
    /// so a KVM-free test creates nothing in the host cgroup tree and needs no delegation.
    ///
    /// The other two host seams stay REAL on purpose. `ReflinkOverlayStore` really writes: the
    /// lineage `create_dir_all` was invisible to every fake-driven test until it did (AGENTS rule
    /// 4), and `RealClock` is what the post-restore resync reads. Only the cgroup seam is swapped,
    /// because it is the only one that needs a *privilege* the test host may not have granted.
    ///
    /// `usage()` through this env returns `FakeCgroupFs`'s modelled counters, not host truth — a
    /// test that must assert real enforcement belongs in the live `tests/metrics_limits.rs`
    /// battery. A test that asserts on the seam itself substitutes its own recorder over this one.
    pub(crate) fn for_unit_tests() -> Self {
        Self {
            cids: Arc::new(CidAllocator::new()),
            vmids: VmidAllocator::new(),
            segids: SegmentIdAllocator::new(),
            cgroups: Arc::new(crate::metrics::FakeCgroupFs::new()),
            clock: Arc::new(RealClock),
            overlay: Arc::new(ReflinkOverlayStore),
        }
    }
}
