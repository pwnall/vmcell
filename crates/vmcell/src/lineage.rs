//! Fork/branch lineage: handles over the zygote fan-out that record provenance.
//!
//! The zygote fan-out (§9.4) mints many identical VMs from one immutable suspend
//! image, flat: no recorded parent→child relationship, and no first-class way to
//! freeze a clone that has *diverged* (run some work) into a **new** fork point.
//! This module adds that layer (§21.4):
//!
//! - A [`Lineage`] is **the lineage handle** — an immutable snapshot node carrying
//!   its identity ([`LineageId`]), parent, generation, and ancestry.
//! - [`Lineage::fork`] mints a live child VM (a copy-on-write clone at this node);
//!   [`Lineage::branch`] freezes a running descendant into a **new** node whose
//!   parent is this one. A chain `root → b1 → b2` is a tree of provenance, each
//!   node itself a self-contained single-snapshot zygote.
//!
//! Every node is a flat, complete snapshot (no backing chain, §21.3), so a restore
//! never walks lineage depth, and `fork`/`branch` invent **no** new identity,
//! eligibility, or copy-on-write logic — they delegate to [`Zygote`], which is the
//! one home for all of it (AGENTS.md "one law, one predicate").

use crate::config::VmConfig;
use crate::error::Result;
use crate::metrics::CgroupFs;
use crate::orchestrator::{MicroVm, VmidAllocator};
use crate::overlay::OverlayStore;
use crate::reflink::CowSupport;
use crate::vmm::{CidAllocator, Vmm};
use crate::zygote::Zygote;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

/// A stable identity for one node in a fork lineage — the snapshot a set of clones
/// descend from.
///
/// Monotonic per [`LineageAllocator`]; `Copy`/`Ord`/`Hash` so it slots into sets
/// and maps for lineage bookkeeping.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct LineageId(u64);

impl LineageId {
    /// The raw monotonic value.
    #[must_use]
    pub fn get(self) -> u64 {
        self.0
    }
}

impl std::fmt::Display for LineageId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "L{}", self.0)
    }
}

/// Hands out monotonically increasing [`LineageId`]s.
///
/// `Clone` over an inner `Arc<AtomicU64>`, so **one** allocator shared across a
/// whole tree (and across trees) yields globally distinct ids — pass the same
/// allocator to every root and it flows into each node's branches.
#[derive(Clone, Debug)]
pub struct LineageAllocator(Arc<AtomicU64>);

impl LineageAllocator {
    /// A fresh allocator whose first id is `L1`.
    #[must_use]
    pub fn new() -> Self {
        Self(Arc::new(AtomicU64::new(1)))
    }

    /// The next distinct id.
    fn next(&self) -> LineageId {
        LineageId(self.0.fetch_add(1, Ordering::Relaxed))
    }

    /// Whether two handles are the **same** allocator (share the inner counter).
    /// Ids from distinct allocators may collide by coincidence (each starts at
    /// `L1`), so a lineage-id comparison is only meaningful within one family.
    fn is_same(&self, other: &LineageAllocator) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Default for LineageAllocator {
    fn default() -> Self {
        Self::new()
    }
}

/// A node in a fork/branch lineage — **the lineage handle** (§21.4).
///
/// Immutable: an immutable suspended snapshot (wrapped [`Zygote`]) plus the
/// ancestry that produced it. [`fork`](Lineage::fork) mints a live child VM at this
/// node; [`branch`](Lineage::branch) freezes a running descendant into a **new**
/// node whose parent is this one, so `root → b1 → b2` is a tree of provenance. All
/// copy-on-write and fan-out mechanics delegate to [`Zygote`] — there is no second
/// copy of the clone logic.
///
/// Cheap to clone (`Arc`-backed ancestry; [`Zygote`] is `Clone`), so a caller holds
/// the handles it cares about and asks each to fork/branch.
#[derive(Clone, Debug)]
pub struct Lineage {
    /// This node's identity.
    id: LineageId,
    /// The node this one branched from; `None` at a root.
    parent: Option<LineageId>,
    /// Depth from the root (0 = root); strictly increases along a branch chain.
    generation: u32,
    /// `root .. parent` inclusive (this node excluded). A root's is empty.
    ancestry: Arc<[LineageId]>,
    /// Shared across the whole tree so branches draw distinct ids.
    allocator: LineageAllocator,
    /// The immutable suspended snapshot (master dir + eligible config + the
    /// [`OverlayStore`] its clones materialize through).
    zygote: Zygote,
}

impl Lineage {
    /// Roots a lineage by **suspending** a live, agent-ready VM into `dir`
    /// (generation 0, no parent).
    ///
    /// `cfg` must be the snapshot-eligible config `vm` was created with; `store` is
    /// the [`OverlayStore`] this lineage's clones materialize their copy-on-write
    /// copies through (§21.2). `dir` is **created if it does not exist** (the
    /// backend writes the suspend image into it); the caller owns its lifecycle.
    ///
    /// # Errors
    /// [`Error::Unsupported`](crate::error::Error::Unsupported) if `cfg` is not
    /// snapshot-eligible (a vhost-user device, §12.1); [`Error::Io`](crate::error::Error::Io)
    /// if `dir` cannot be created; otherwise any error from taking the snapshot.
    pub async fn fork_from_vm<V: Vmm>(
        vm: &mut MicroVm<V>,
        cfg: VmConfig,
        dir: impl Into<PathBuf>,
        allocator: LineageAllocator,
        store: Arc<dyn OverlayStore>,
    ) -> Result<Self> {
        let dir = dir.into();
        // The backend writes the suspend image into `dir`, which must exist first
        // (both CH and FC fail-loud on a missing destination dir). A suspend into a
        // fresh location is the common case, so create it for the caller.
        tokio::fs::create_dir_all(&dir)
            .await
            .map_err(crate::error::Error::Io)?;
        let zygote = Zygote::suspend(vm, cfg, dir)
            .await?
            .with_overlay_store(store);
        Ok(Self::root(zygote, allocator))
    }

    /// Adopts an already-built snapshot directory (e.g. a `SnapshotStage` artifact,
    /// §11.1) as a lineage root.
    ///
    /// # Errors
    /// [`Error::Io`](crate::error::Error::Io) if `dir` is not an existing directory,
    /// or [`Error::Unsupported`](crate::error::Error::Unsupported) if `cfg` is not
    /// snapshot-eligible (§12.1).
    pub async fn from_snapshot_dir(
        dir: impl Into<PathBuf>,
        cfg: VmConfig,
        allocator: LineageAllocator,
        store: Arc<dyn OverlayStore>,
    ) -> Result<Self> {
        let zygote = Zygote::from_snapshot_dir(dir, cfg)
            .await?
            .with_overlay_store(store);
        Ok(Self::root(zygote, allocator))
    }

    fn root(zygote: Zygote, allocator: LineageAllocator) -> Self {
        let id = allocator.next();
        Self {
            id,
            parent: None,
            generation: 0,
            ancestry: Arc::from(Vec::new()),
            allocator,
            zygote,
        }
    }

    /// This node's identity.
    #[must_use]
    pub fn id(&self) -> LineageId {
        self.id
    }

    /// The node this one branched from; `None` at a root.
    #[must_use]
    pub fn parent(&self) -> Option<LineageId> {
        self.parent
    }

    /// Depth from the root (0 = root).
    #[must_use]
    pub fn generation(&self) -> u32 {
        self.generation
    }

    /// The ancestry `root .. parent` inclusive (this node excluded); empty at a
    /// root.
    #[must_use]
    pub fn ancestry(&self) -> &[LineageId] {
        &self.ancestry
    }

    /// Whether `self` is a (strict) ancestor of `other` — i.e. `other` descends from
    /// `self` in the **same** lineage family. Antisymmetric and transitive by
    /// construction (§12.25).
    ///
    /// Two nodes minted by **distinct** [`LineageAllocator`]s are always
    /// incomparable (never a false-positive ancestry), even if their ids collide by
    /// coincidence — the comparison first checks the nodes share an allocator, then
    /// that `self.id` appears in `other`'s ancestry.
    #[must_use]
    pub fn is_ancestor_of(&self, other: &Lineage) -> bool {
        self.allocator.is_same(&other.allocator) && other.ancestry.contains(&self.id)
    }

    /// The immutable master snapshot directory of this node.
    #[must_use]
    pub fn master_dir(&self) -> &Path {
        self.zygote.master_dir()
    }

    /// The snapshot-eligible config this node's clones restore with.
    #[must_use]
    pub fn config(&self) -> &VmConfig {
        self.zygote.config()
    }

    /// Best-effort probe of whether this node's filesystem gives cheap block-level
    /// copy-on-write for its clones (§9.4).
    #[must_use]
    pub fn probe_cow_support(&self) -> CowSupport {
        self.zygote.probe_cow_support()
    }

    /// **fork():** mints ONE live child VM — a copy-on-write clone at this node.
    ///
    /// Delegates to [`Zygote::spawn_clone`]; works on any snapshot backend. The
    /// returned VM is live and resumed, with a fresh vmid (hence distinct IP/MAC,
    /// §9.2); its first `agent()` call runs the mandatory post-restore resync.
    ///
    /// # Errors
    /// Any error from the copy-on-write copy, network setup, or restore (§9.4).
    pub async fn fork<V: Vmm>(
        &self,
        vmm: &V,
        cid_alloc: Arc<CidAllocator>,
        vmid_alloc: VmidAllocator,
        cgroup_fs: Box<dyn CgroupFs>,
    ) -> Result<MicroVm<V>> {
        self.zygote
            .spawn_clone(vmm, cid_alloc, vmid_alloc, cgroup_fs)
            .await
    }

    /// Mints `count` live children **concurrently** at this node.
    ///
    /// Delegates to [`Zygote::spawn_clones`], so the §9.4 all-or-nothing teardown
    /// and the concurrent-fan-out gate on `restore_rotates_host_paths` apply
    /// unchanged.
    ///
    /// # Errors
    /// [`Error::Unsupported`](crate::error::Error::Unsupported) when `count > 1` and
    /// the backend does not rotate host paths on restore (§9.4); otherwise the
    /// first clone error.
    pub async fn fork_many<V, F>(
        &self,
        vmm: &V,
        count: usize,
        cid_alloc: Arc<CidAllocator>,
        vmid_alloc: VmidAllocator,
        make_cgroups: F,
    ) -> Result<Vec<MicroVm<V>>>
    where
        V: Vmm,
        F: FnMut() -> Box<dyn CgroupFs>,
    {
        self.zygote
            .spawn_clones(vmm, count, cid_alloc, vmid_alloc, make_cgroups)
            .await
    }

    /// **branch():** freezes a RUNNING descendant `child` into a **new** lineage
    /// node whose parent is this node (generation + 1, ancestry extended by this
    /// node's id).
    ///
    /// Snapshots `child` into `dir` and returns the new node; `child` stays live and
    /// the caller owns `dir`'s lifecycle (like a zygote master, §12.12). `dir` is
    /// **created if it does not exist**. The new node shares this node's
    /// [`OverlayStore`], so a whole lineage uses one seam. Snapshot-eligibility
    /// (§12.1) is re-checked through the same `check_clone_eligible` predicate the
    /// zygote uses (one law).
    ///
    /// # Errors
    /// [`Error::Unsupported`](crate::error::Error::Unsupported) if this node's config
    /// is not snapshot-eligible; [`Error::Io`](crate::error::Error::Io) if `dir`
    /// cannot be created; otherwise any error from snapshotting `child`.
    pub async fn branch<V: Vmm>(
        &self,
        child: &mut MicroVm<V>,
        dir: impl Into<PathBuf>,
    ) -> Result<Lineage> {
        // Freeze the child into a NEW immutable master. The backend writes the
        // suspend image into `dir`, which must exist first (both CH and FC fail-loud
        // on a missing destination) — create it for the caller.
        let dir = dir.into();
        tokio::fs::create_dir_all(&dir)
            .await
            .map_err(crate::error::Error::Io)?;
        // `Zygote::suspend` re-checks eligibility (§12.1) and snapshots the child;
        // propagate this node's overlay store so the whole lineage uses one seam.
        let zygote = Zygote::suspend(child, self.zygote.config().clone(), dir)
            .await?
            .with_overlay_store(self.zygote.overlay_store());
        let id = self.allocator.next();
        // ancestry(child) = ancestry(self) ++ [self.id]  — root..parent inclusive.
        let mut ancestry = self.ancestry.to_vec();
        ancestry.push(self.id);
        Ok(Self {
            id,
            parent: Some(self.id),
            // `saturating_add` rather than `+ 1`: depth is a `u32`, so it cannot
            // panic on a pathological 4-billion-deep chain (it caps instead). Ids
            // are a `u64` monotonic counter — practically inexhaustible.
            generation: self.generation.saturating_add(1),
            ancestry: Arc::from(ancestry),
            allocator: self.allocator.clone(),
            zygote,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RootfsSource;
    use crate::metrics::FakeCgroupFs;
    use crate::overlay::RecordingOverlayStore;
    use crate::vmm::FakeVmm;

    // One process-global VMID allocator shared across these tests: fork() mints real
    // per-VM scratch dirs keyed on vmid, so fresh per-test allocators would collide
    // under `cargo test`'s in-process parallelism (§10.2, same reason as the zygote
    // tests). nextest runs each test in its own process, so this is inert there.
    static SHARED_VMIDS: std::sync::OnceLock<VmidAllocator> = std::sync::OnceLock::new(); // allow-global-state: process-global VMID allocator; §10.2 requires one shared allocator per test-runner process to avoid concurrent-test scratch-dir collisions
    fn shared_vmids() -> VmidAllocator {
        SHARED_VMIDS.get_or_init(VmidAllocator::new).clone()
    }

    fn erofs_cfg() -> VmConfig {
        VmConfig::builder(
            PathBuf::from("/vmlinux"),
            RootfsSource::Erofs {
                image: PathBuf::from("/rootfs.erofs"),
            },
        )
        .network_disabled()
        .build()
        .expect("valid config")
    }

    fn write_master(dir: &Path) {
        std::fs::create_dir_all(dir).expect("mk master");
        std::fs::write(dir.join("config.json"), b"{\"vsock\":{\"cid\":3}}").expect("cfg");
        std::fs::write(dir.join("mem_file"), vec![0u8; 2048]).expect("mem");
    }

    fn recording_store() -> Arc<dyn OverlayStore> {
        Arc::new(RecordingOverlayStore::new())
    }

    // The allocator hands out distinct ids. The inverse (returning a constant) would
    // let two nodes share an id and corrupt `is_ancestor_of`.
    #[test]
    fn allocator_hands_out_distinct_ids() {
        let a = LineageAllocator::new();
        let ids: std::collections::HashSet<LineageId> = (0..8).map(|_| a.next()).collect();
        assert_eq!(ids.len(), 8, "every id must be distinct");
    }

    // A root has generation 0, no parent, and an empty ancestry (§12.25). The
    // inverse (a non-zero root generation, or a non-empty ancestry) reddens.
    #[tokio::test]
    async fn root_has_generation_zero_no_parent_empty_ancestry() {
        let root_dir = tempfile::tempdir().expect("tempdir");
        let master = root_dir.path().join("root");
        write_master(&master);
        let lineage = Lineage::from_snapshot_dir(
            master,
            erofs_cfg(),
            LineageAllocator::new(),
            recording_store(),
        )
        .await
        .expect("root lineage");
        assert_eq!(lineage.generation(), 0);
        assert_eq!(lineage.parent(), None);
        assert!(lineage.ancestry().is_empty());
    }

    // fork() materializes the clone through the injected OverlayStore into a PRIVATE
    // dir, never the master (§12.24). The inverse — a restore path that skips the
    // seam and hands the backend the master directly — records zero clone_into calls
    // (or a dst == master), reddening both asserts.
    #[tokio::test]
    async fn fork_materializes_through_overlay_store_into_private_dir() {
        let root_dir = tempfile::tempdir().expect("tempdir");
        let master = root_dir.path().join("root");
        write_master(&master);
        let store = RecordingOverlayStore::new();
        let store_arc: Arc<dyn OverlayStore> = Arc::new(store.clone());
        let lineage = Lineage::from_snapshot_dir(
            master.clone(),
            erofs_cfg(),
            LineageAllocator::new(),
            store_arc,
        )
        .await
        .expect("root lineage");

        let vmm = FakeVmm::default();
        let vm = lineage
            .fork(
                &vmm,
                Arc::new(CidAllocator::new()),
                shared_vmids(),
                Box::new(FakeCgroupFs::new()),
            )
            .await
            .expect("fork one child");
        let _ = vm.vmid();

        let calls = store.calls();
        assert_eq!(calls.len(), 1, "fork must materialize exactly one CoW copy");
        let (src, dst) = &calls[0];
        assert_eq!(src, &master, "the copy source must be the master (§12.24)");
        assert_ne!(
            dst, &master,
            "the copy dst must be a PRIVATE dir, never the master"
        );
        assert!(
            dst.ends_with("zygote-snapshot"),
            "the dst must be the per-VM CoW copy, got {}",
            dst.display()
        );
    }

    // branch() extends the lineage: the new node's parent is the branched node, its
    // generation is +1, and its ancestry is the parent's ancestry plus the parent
    // (§12.25). The inverse (parent None, generation unchanged, ancestry not
    // extended) reddens each assert.
    #[tokio::test]
    async fn branch_extends_lineage() {
        let root_dir = tempfile::tempdir().expect("tempdir");
        let master = root_dir.path().join("root");
        write_master(&master);
        let root = Lineage::from_snapshot_dir(
            master,
            erofs_cfg(),
            LineageAllocator::new(),
            recording_store(),
        )
        .await
        .expect("root lineage");

        let vmm = FakeVmm::default();
        let mut child = root
            .fork(
                &vmm,
                Arc::new(CidAllocator::new()),
                shared_vmids(),
                Box::new(FakeCgroupFs::new()),
            )
            .await
            .expect("fork a child to branch");

        let b1_dir = root_dir.path().join("b1");
        let b1 = root.branch(&mut child, b1_dir).await.expect("branch");
        assert_eq!(
            b1.parent(),
            Some(root.id()),
            "branch parent is the branched node"
        );
        assert_eq!(b1.generation(), 1, "branch generation is parent + 1");
        assert_eq!(b1.ancestry(), &[root.id()], "branch ancestry is [root]");
        assert!(
            root.is_ancestor_of(&b1),
            "root is an ancestor of its branch"
        );
        assert!(
            !b1.is_ancestor_of(&root),
            "is_ancestor_of is antisymmetric (§12.25)"
        );
        assert_ne!(b1.id(), root.id(), "a branch has a distinct id");
    }

    // A 3-node chain root → b1 → b2: generations 0/1/2, ancestries []/[root]/
    // [root,b1], and is_ancestor_of is transitive (root ancestor of b2). No node is
    // its own ancestor (§12.25). The inverse of the ancestry-extension rule breaks
    // the transitive check.
    #[tokio::test]
    async fn three_node_chain_generations_and_ancestry() {
        let root_dir = tempfile::tempdir().expect("tempdir");
        let master = root_dir.path().join("root");
        write_master(&master);
        let alloc = LineageAllocator::new();
        let root = Lineage::from_snapshot_dir(master, erofs_cfg(), alloc, recording_store())
            .await
            .expect("root");
        let vmm = FakeVmm::default();
        let cids = Arc::new(CidAllocator::new());

        let mut c0 = root
            .fork(
                &vmm,
                cids.clone(),
                shared_vmids(),
                Box::new(FakeCgroupFs::new()),
            )
            .await
            .expect("fork c0");
        let b1 = root
            .branch(&mut c0, root_dir.path().join("b1"))
            .await
            .expect("branch b1");

        let mut c1 = b1
            .fork(
                &vmm,
                cids.clone(),
                shared_vmids(),
                Box::new(FakeCgroupFs::new()),
            )
            .await
            .expect("fork c1");
        let b2 = b1
            .branch(&mut c1, root_dir.path().join("b2"))
            .await
            .expect("branch b2");

        assert_eq!(
            (root.generation(), b1.generation(), b2.generation()),
            (0, 1, 2)
        );
        assert_eq!(root.ancestry(), &[] as &[LineageId]);
        assert_eq!(b1.ancestry(), &[root.id()]);
        assert_eq!(b2.ancestry(), &[root.id(), b1.id()]);

        // Transitivity + antisymmetry + no-self-ancestor (§12.25).
        assert!(root.is_ancestor_of(&b1) && root.is_ancestor_of(&b2));
        assert!(b1.is_ancestor_of(&b2));
        assert!(!b2.is_ancestor_of(&root) && !b2.is_ancestor_of(&b1));
        assert!(!root.is_ancestor_of(&root), "no node is its own ancestor");
    }

    // fork_from_vm roots a lineage by suspending a live VM (generation 0). Exercises
    // the suspend path (not just from_snapshot_dir) and confirms the rooted node
    // then branches correctly.
    #[tokio::test]
    async fn fork_from_vm_roots_a_lineage() {
        let vmm = FakeVmm::default();
        let vm_dir = tempfile::tempdir().expect("tempdir");
        let mut vm = MicroVm::start(
            &vmm,
            erofs_cfg(),
            Arc::new(CidAllocator::new()),
            shared_vmids(),
            Box::new(FakeCgroupFs::new()),
        )
        .await
        .expect("start a live VM");

        let root = Lineage::fork_from_vm(
            &mut vm,
            erofs_cfg(),
            vm_dir.path().join("root"),
            LineageAllocator::new(),
            recording_store(),
        )
        .await
        .expect("root a lineage from a live VM");
        assert_eq!(root.generation(), 0);
        assert_eq!(root.parent(), None);
    }

    // Eligibility is re-checked at the lineage boundary via the shared predicate: a
    // vhost-user config (a data share) is rejected at construction (§12.1), before
    // any snapshot. The inverse (skipping the check) would mint an unrestorable node.
    #[tokio::test]
    async fn ineligible_config_rejected_at_construction() {
        let root_dir = tempfile::tempdir().expect("tempdir");
        let master = root_dir.path().join("root");
        write_master(&master);
        let cfg = VmConfig::builder(
            PathBuf::from("/vmlinux"),
            RootfsSource::Erofs {
                image: PathBuf::from("/rootfs.erofs"),
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
        .expect("valid non-snapshotting config with a share");
        let res =
            Lineage::from_snapshot_dir(master, cfg, LineageAllocator::new(), recording_store())
                .await;
        assert!(
            matches!(res, Err(crate::error::Error::Unsupported { .. })),
            "a vhost-user device must be rejected at construction, got {res:?}"
        );
    }

    // Nodes minted by DISTINCT allocators are incomparable even when their ids
    // collide (both allocators start at L1). Here `a` (tree 1, id L1) must NOT be
    // reported as an ancestor of `b1` (tree 2, ancestry [L1]) — the ids coincide,
    // but the families differ. The inverse — a bare `other.ancestry.contains(id)`
    // without the allocator-identity guard — returns a spurious `true` here.
    #[tokio::test]
    async fn is_ancestor_of_is_false_across_distinct_allocators() {
        let root = tempfile::tempdir().expect("tempdir");
        let m1 = root.path().join("t1");
        write_master(&m1);
        let m2 = root.path().join("t2");
        write_master(&m2);

        let a =
            Lineage::from_snapshot_dir(m1, erofs_cfg(), LineageAllocator::new(), recording_store())
                .await
                .expect("tree 1 root");
        // Tree 2: root → fork a child → branch it, so b1's ancestry is [tree2-root],
        // whose id collides with `a`'s (both L1 from independent allocators).
        let t2 =
            Lineage::from_snapshot_dir(m2, erofs_cfg(), LineageAllocator::new(), recording_store())
                .await
                .expect("tree 2 root");
        assert_eq!(
            a.id(),
            t2.id(),
            "distinct allocators both start at L1 — ids collide"
        );
        let vmm = FakeVmm::default();
        let mut child = t2
            .fork(
                &vmm,
                Arc::new(CidAllocator::new()),
                shared_vmids(),
                Box::new(FakeCgroupFs::new()),
            )
            .await
            .expect("fork in tree 2");
        let b1 = t2
            .branch(&mut child, root.path().join("t2-b1"))
            .await
            .expect("branch in tree 2");
        assert_eq!(
            b1.ancestry(),
            &[t2.id()],
            "b1 ancestry is the (colliding) id"
        );
        assert!(
            !a.is_ancestor_of(&b1),
            "a node from a DIFFERENT allocator family must never be an ancestor (§12.25), \
             even when ids collide"
        );
    }

    // §12.24 for repeated forks at one node: EVERY clone materializes through the
    // store into its OWN private dir. Two forks must record two DISTINCT dsts, both
    // non-master. The inverse — a restore path that reused one clone dir — records a
    // duplicate dst and reddens the distinctness assert.
    #[tokio::test]
    async fn repeated_forks_each_use_a_distinct_private_copy() {
        let root_dir = tempfile::tempdir().expect("tempdir");
        let master = root_dir.path().join("root");
        write_master(&master);
        let store = RecordingOverlayStore::new();
        let store_arc: Arc<dyn OverlayStore> = Arc::new(store.clone());
        let lineage = Lineage::from_snapshot_dir(
            master.clone(),
            erofs_cfg(),
            LineageAllocator::new(),
            store_arc,
        )
        .await
        .expect("root lineage");
        let vmm = FakeVmm::default();
        let cids = Arc::new(CidAllocator::new());
        for _ in 0..2 {
            lineage
                .fork(
                    &vmm,
                    cids.clone(),
                    shared_vmids(),
                    Box::new(FakeCgroupFs::new()),
                )
                .await
                .expect("fork");
        }
        let calls = store.calls();
        assert_eq!(
            calls.len(),
            2,
            "each fork materializes exactly one CoW copy"
        );
        let dsts: std::collections::HashSet<_> = calls.iter().map(|(_, d)| d.clone()).collect();
        assert_eq!(
            dsts.len(),
            2,
            "two forks must use two DISTINCT private dirs (§12.24)"
        );
        for (src, dst) in &calls {
            assert_eq!(src, &master, "every copy source is the master");
            assert_ne!(dst, &master, "every copy dst is private, never the master");
        }
    }

    // fork_many (the concurrent path) materializes EACH clone through the store into
    // its own private dir and hands each a distinct vmid. Covers the §12.24 seam on
    // the fan-out path, delegated to Zygote::spawn_clones (the gate/all-or-nothing
    // are its own tests). The inverse (a fan-out that bypassed the store) records
    // zero calls.
    #[tokio::test]
    async fn fork_many_materializes_each_clone_through_the_store() {
        let root_dir = tempfile::tempdir().expect("tempdir");
        let master = root_dir.path().join("root");
        write_master(&master);
        let store = RecordingOverlayStore::new();
        let store_arc: Arc<dyn OverlayStore> = Arc::new(store.clone());
        let lineage = Lineage::from_snapshot_dir(
            master.clone(),
            erofs_cfg(),
            LineageAllocator::new(),
            store_arc,
        )
        .await
        .expect("root lineage");
        let vmm = FakeVmm::default(); // rotates host paths → concurrent fan-out allowed
        let clones = lineage
            .fork_many(
                &vmm,
                3,
                Arc::new(CidAllocator::new()),
                shared_vmids(),
                || Box::new(FakeCgroupFs::new()),
            )
            .await
            .expect("fork_many of 3");
        assert_eq!(clones.len(), 3);
        let vmids: std::collections::HashSet<u32> = clones.iter().map(|c| c.vmid()).collect();
        assert_eq!(vmids.len(), 3, "each clone gets a distinct vmid");
        let calls = store.calls();
        assert_eq!(
            calls.len(),
            3,
            "each clone materializes through the store (§12.24)"
        );
        let dsts: std::collections::HashSet<_> = calls.iter().map(|(_, d)| d.clone()).collect();
        assert_eq!(dsts.len(), 3, "each clone into its OWN private dir");
    }

    // branch() must leave the child VM live and usable (the documented contract):
    // it takes `&mut child` (never consumes it), and snapshot resumes it. Proven by
    // branching the SAME child twice into two sibling nodes. The inverse (consuming
    // or tearing down the child) would not compile / would panic on reuse.
    #[tokio::test]
    async fn branch_leaves_child_usable_for_further_branches() {
        let root_dir = tempfile::tempdir().expect("tempdir");
        let master = root_dir.path().join("root");
        write_master(&master);
        let root = Lineage::from_snapshot_dir(
            master,
            erofs_cfg(),
            LineageAllocator::new(),
            recording_store(),
        )
        .await
        .expect("root");
        let vmm = FakeVmm::default();
        let mut child = root
            .fork(
                &vmm,
                Arc::new(CidAllocator::new()),
                shared_vmids(),
                Box::new(FakeCgroupFs::new()),
            )
            .await
            .expect("fork a child");
        let vmid_before = child.vmid();

        let b1 = root
            .branch(&mut child, root_dir.path().join("b1"))
            .await
            .expect("first branch");
        // The child survived the first branch — its identity is intact and it can be
        // branched again into a sibling node.
        assert_eq!(
            child.vmid(),
            vmid_before,
            "branch must not change the live child's identity"
        );
        let b1b = root
            .branch(&mut child, root_dir.path().join("b1b"))
            .await
            .expect("second branch");

        assert_ne!(
            b1.id(),
            b1b.id(),
            "two branches of one child are distinct nodes"
        );
        assert_eq!(b1.parent(), Some(root.id()));
        assert_eq!(b1b.parent(), Some(root.id()));
        assert_eq!((b1.generation(), b1b.generation()), (1, 1));
    }

    // branch() creates the target dir (incl. parents) if it does not exist — both CH
    // and FC fail-loud on a missing snapshot destination, a footgun the live
    // integration test caught. The inverse (dropping the `create_dir_all`) leaves
    // the dir absent, reddening the `is_dir` assert.
    #[tokio::test]
    async fn branch_creates_a_missing_target_dir() {
        let root_dir = tempfile::tempdir().expect("tempdir");
        let master = root_dir.path().join("root");
        write_master(&master);
        let root = Lineage::from_snapshot_dir(
            master,
            erofs_cfg(),
            LineageAllocator::new(),
            recording_store(),
        )
        .await
        .expect("root");
        let vmm = FakeVmm::default();
        let mut child = root
            .fork(
                &vmm,
                Arc::new(CidAllocator::new()),
                shared_vmids(),
                Box::new(FakeCgroupFs::new()),
            )
            .await
            .expect("fork a child");
        // A nested, non-existent destination: branch must create it and its parents.
        let fresh = root_dir.path().join("nested/deeper/b1");
        assert!(
            !fresh.exists(),
            "precondition: the target dir does not exist yet"
        );
        let _b1 = root
            .branch(&mut child, &fresh)
            .await
            .expect("branch into a fresh dir");
        assert!(
            fresh.is_dir(),
            "branch must create the target dir (and parents) if absent"
        );
    }
}
