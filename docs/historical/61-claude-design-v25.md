# vmcell — Design Document (v25 amendment): the OverlayStore seam and fork/branch lineage

> **v25 (this revision) — single-snapshot copy-on-write clone as an injectable seam, plus fork()/branch()
> with lineage handles.** A focused amendment layered on the v23 unified design
> (`docs/59-claude-design-v23.md`) and the v24 privileged-window amendment (`docs/60-claude-design-v24.md`),
> in the same shape v21/v22/v24 were: the base architecture is unchanged, and this document adds one
> component — **Part VIII / §21** — graduating the roadmap item "Single-snapshot copy-on-write clone +
> fork()/branch() with lineage handles (new injectable OverlayStore seam)" (`docs/todo.md`) from
> forward-work to **built and gated**.
>
> **What was already built (stated up front, honestly).** The *single-snapshot copy-on-write clone* itself
> already ships and is designed: the **zygote fan-out** (§9.4) mints N identical VMs from one suspend image
> by reflink-copy-on-write-copying the suspend directory per clone and restoring each private copy —
> `Zygote::{suspend, from_snapshot_dir, spawn_clone, spawn_clones}`, `MicroVm::restore_cow`, the
> `reflink.rs` primitive, `CowSupport::{Reflink, FullCopy}`, and invariant **§12.12** (a zygote master is
> immutable; clones restore from private CoW copies). v25 does **not** re-implement that. It adds the two
> genuinely missing pieces the roadmap item names:
>
> 1. **An injectable `OverlayStore` seam.** Today the CoW copy is a bare free function (`reflink.rs`) the
>    orchestrator calls directly — the one clone-materialization step in the system that is *not* a faked,
>    swappable seam like `Netlink`/`NftApplier`/`CgroupFs`/`VmEngine`. v25 lifts it behind
>    `overlay::OverlayStore` (trait + `ReflinkOverlayStore` production impl + a recording test double),
>    injected into every CoW restore path. This makes the clone step unit-testable with **no reflink
>    filesystem**, and lets a future backing store (a shared content-addressed overlay pool, a network
>    store) drop in without touching the orchestrator — the exact seam discipline every other
>    load-bearing edge already follows.
> 2. **`fork()`/`branch()` with lineage handles.** Today the fan-out is *flat*: one immutable master, many
>    independent clones, no recorded parent→child relationship and no way to freeze a clone that has *done
>    work* into a new fork point. v25 adds a **`Lineage`** handle (the "lineage handle") — an immutable
>    snapshot node carrying its identity, parent, generation, and ancestry — with `fork` (mint a live child
>    VM from a node) and `branch` (freeze a running descendant into a **new** node whose parent is this
>    one). A chain `root → b1 → b2` is a *tree of provenance*, each node itself a self-contained
>    single-snapshot zygote. The handle reuses `Zygote` for all CoW/fan-out mechanics — **no second copy of
>    load-bearing logic** (AGENTS.md "one law, one predicate").
>
> **Amends:** **§9.4** (the CoW copy now goes through the injected `OverlayStore`; the fan-out grows a
> lineage layer), **§10.2** (three additive modules — `overlay`, `lineage` — and `MicroVm::restore_cow`
> gains an `OverlayStore` parameter), **§12** (new invariants **§12.24–§12.25**), **§14** (new gates),
> **§16/§17** (the roadmap item moves to built). Version bumps: `vmcell` **0.7.0 → 0.8.0** — one breaking
> change (`restore_cow` gains the `Arc<dyn OverlayStore>` seam parameter, the sole in-tree caller is the
> daemon launcher), which for a `0.x` crate is a **minor** bump and therefore `cargo semver-checks`-clean;
> the new `overlay::{OverlayStore, ReflinkOverlayStore}` and `lineage::{Lineage, LineageId,
> LineageAllocator}` surface is additive. `vmcell-daemon` passes the production `ReflinkOverlayStore` at its
> `restore_cow` call site (the seam is injectable to the daemon too; injecting a non-default store there is
> §21.8 forward work).

---

## Part VIII — Copy-on-write clone as a seam, and fork/branch lineage

## 21. The OverlayStore seam and the Lineage handle

### 21.1 What already ships, and what §21 adds

The per-VM speed lever is warm snapshot + restore (§9.1); the *density* lever for "many identical VMs from
one boot" is the **zygote fan-out** (§9.4), and it is built: `Zygote` owns an immutable master snapshot dir
and mints clones, each restoring from its **own** reflink-copy-on-write copy of the suspend directory so
the master is never mutated (§12.12) and concurrent clones never race on the backend's single-use in-place
`config.json` rewrite (§9.1). That *is* the "single-snapshot copy-on-write clone." §21 does not rebuild it.

Two pieces the roadmap item names were missing, and §21 supplies them:

- **The CoW copy was not a seam.** Every other host-mutating edge in vmcell is an injectable trait with a
  production impl and a recording test double — `Netlink`/`NftApplier` (`net/tap.rs`), `CgroupFs`
  (`metrics.rs`), `OrphanScanner`, the daemon's `VmEngine`. The clone-materialization step alone was a
  bare `reflink::clone_tree_cow` free function the orchestrator called directly, so the only way to test
  the CoW path was to actually reflink on a real filesystem, and there was no injection point for an
  alternative store. §21.2 lifts it behind `overlay::OverlayStore`.
- **The fan-out had no lineage.** `spawn_clones(n)` is a flat fan-out from a fixed master; a clone is a
  standalone `MicroVm` with no recorded parent, and there is no first-class way to freeze a clone that has
  diverged (run some work) into a *new* fork point that further clones descend from. §21.4 adds the
  `Lineage` handle and `fork`/`branch`.

### 21.2 The OverlayStore seam (one clone-materialization law, injected)

```rust
// vmcell::overlay
/// How a snapshot/suspend directory is copy-on-write-cloned into a clone's own
/// private, independent copy. The one seam every CoW restore path materializes a
/// clone through (§21.2) — swappable and fakeable exactly like `CgroupFs`.
pub trait OverlayStore: Send + Sync + std::fmt::Debug {
    /// CoW-clones the snapshot directory `src` into a fresh private copy at `dst`.
    /// `dst` must not exist. The copy is a faithful, INDEPENDENT copy: writing it
    /// never touches `src` (the master), which is the §12.12 immutability contract.
    /// Reports whether it was a block-level reflink or a full byte copy.
    fn clone_tree(&self, src: &Path, dst: &Path) -> Result<CowSupport>;
    /// Best-effort probe of whether `dir`'s filesystem gives cheap block-level CoW,
    /// for an up-front cost signal before minting a pool. Side-effect-free.
    fn probe(&self, dir: &Path) -> CowSupport;
}

/// The production store: reflink where the filesystem supports it (XFS/Btrfs/
/// bcachefs → `FICLONE`), full byte copy otherwise. Wraps the `reflink.rs`
/// primitive (which owns the one `FICLONE` ioctl inside the vetted `reflink-copy`
/// crate — `#![forbid(unsafe_code)]` still holds; no `unsafe` enters the tree).
#[derive(Clone, Copy, Debug, Default)]
pub struct ReflinkOverlayStore;
impl OverlayStore for ReflinkOverlayStore { /* clone_tree_cow_blocking / probe_reflink */ }
```

**Scope — the seam clones the *suspend directory*, not a rootfs disk.** In vmcell's snapshot-eligible model
the rootfs is a **shared erofs RO base** (one host-cached copy for all guests, no per-VM copy, §5.1) plus a
fresh **in-guest tmpfs overlay** (§5.1) — there is no host-side writable rootfs upper to copy. The only
per-clone writable host state is the **suspend/snapshot directory** (the guest-RAM memory file + the
backend's `config.json`/sidecar). So `OverlayStore` is scoped precisely to CoW-cloning *that directory*; it
deliberately does not reach into per-backend block-device attachment (which would import the vhost-user and
qcow2-backing-chain complexity a snapshot-eligible VM does not have). This keeps the seam small and its one
job crisp.

**Injection — the CgroupFs pattern exactly.** The trait is `Send + Sync + Debug` with **synchronous**
methods (so it is object-safe as `Arc<dyn OverlayStore>` and derivable-`Debug`), and the orchestrator runs
`clone_tree` on a **blocking thread** (`spawn_blocking`) so a large full-copy never stalls the async
runtime — the same discipline the old free function used, now at the seam boundary. `MicroVm::restore_cow`
takes an `Arc<dyn OverlayStore>`; `Zygote` and `Lineage` hold one (default `ReflinkOverlayStore`,
overridable via `with_overlay_store`) and thread it through. The recording test double
(`RecordingOverlayStore`) records every `(src, dst)` it is asked to clone and returns a configurable
`CowSupport`, so a test proves the restore path materializes each clone through the seam **into a private
dst, never the master** — with no reflink filesystem and no VMM.

### 21.3 One snapshot per restore, not a backing chain

A branch is a **flat, self-contained single snapshot**, and copy-on-write happens at the **host-filesystem**
layer (reflink of that one directory), *not* as a qcow2/overlayfs backing chain. This is deliberate and
load-bearing:

- **Restore stays O(1) in lineage depth.** If `branch` layered a new overlay over its parent's image, a
  depth-`k` restore would have to assemble `k` backing layers and the backend would have to walk them —
  fragile across CH/FC snapshot formats, and a correctness hazard (a restored VM resumes at an exact
  instruction; a mis-assembled backing chain is silent corruption, §9.2). Instead, `branch` writes a
  **complete** new suspend image from the diverged guest (the memory file tracks guest RAM exactly, §9.1,
  independent of depth), and `fork` reflink-copies that one directory. Depth costs disk (one guest-RAM
  image per branch node the caller keeps), never restore complexity.
- **Backend-agnostic.** Every node is exactly the kind of directory the warm tier and `Zygote` already
  restore; no backend learns about lineage. The `restore_rotates_host_paths` fan-out gate (§9.4) and the
  §12.1 eligibility law apply per node unchanged.

The reflink CoW between a node and its live children is where sharing pays off: a pool forked from one node
costs ≈N×dirtied pages on a reflink filesystem (§9.4 cost model); the lineage adds a *second* axis (depth)
whose cost is one full image per retained branch point, reported honestly, never hidden behind a chain.

### 21.4 fork() / branch() and the Lineage handle

```rust
// vmcell::lineage
/// A stable identity for one node in a fork lineage (a snapshot a set of clones
/// descend from). Monotonic per `LineageAllocator`; `Copy`/`Ord`/`Hash`.
pub struct LineageId(u64);

/// Hands out monotonically increasing `LineageId`s. `Clone` over an inner
/// `Arc<AtomicU64>` so one allocator shared across a whole tree (and across trees)
/// gives globally distinct ids.
pub struct LineageAllocator(/* Arc<AtomicU64> */);

/// A node in a fork/branch lineage — THE lineage handle. Immutable: an immutable
/// suspended snapshot (a `Zygote`) plus the ancestry that produced it. `fork`
/// mints a live child VM (a CoW clone at this node); `branch` freezes a running
/// descendant into a NEW node whose parent is this one, so `root → b1 → b2` is a
/// tree of provenance. Delegates all CoW/fan-out mechanics to `Zygote` — no second
/// copy of the clone logic.
pub struct Lineage {
    id: LineageId,
    parent: Option<LineageId>,     // None at the root (generation 0)
    generation: u32,               // strictly increases along a branch chain
    ancestry: Arc<[LineageId]>,    // root .. parent inclusive (this node excluded)
    // + the shared allocator and the wrapped Zygote (master dir, eligible cfg, OverlayStore)
}

impl Lineage {
    /// Roots a lineage by suspending a live, agent-ready VM into `dir` (generation
    /// 0, no parent), which is created if absent. `store` is the OverlayStore its
    /// clones materialize through.
    pub async fn fork_from_vm<V: Vmm>(vm: &mut MicroVm<V>, cfg: VmConfig, dir: impl Into<PathBuf>,
        allocator: LineageAllocator, store: Arc<dyn OverlayStore>) -> Result<Self>;
    /// Adopts an existing snapshot dir (e.g. a `SnapshotStage` artifact, §11.1) as a root node.
    pub async fn from_snapshot_dir(dir: impl Into<PathBuf>, cfg: VmConfig,
        allocator: LineageAllocator, store: Arc<dyn OverlayStore>) -> Result<Self>;

    pub fn id(&self) -> LineageId;
    pub fn parent(&self) -> Option<LineageId>;
    pub fn generation(&self) -> u32;
    pub fn ancestry(&self) -> &[LineageId];             // root .. parent
    pub fn is_ancestor_of(&self, other: &Lineage) -> bool;
    pub fn master_dir(&self) -> &Path;
    pub fn probe_cow_support(&self) -> CowSupport;

    /// fork(): mint ONE live child VM — a CoW clone at this node (delegates to
    /// `Zygote::spawn_clone`). Works on any snapshot backend.
    pub async fn fork<V: Vmm>(&self, vmm: &V, cids: Arc<CidAllocator>, vmids: VmidAllocator,
        cgroups: Box<dyn CgroupFs>) -> Result<MicroVm<V>>;
    /// Concurrent fan-out at this node (delegates to `Zygote::spawn_clones`; the
    /// §9.4 `restore_rotates_host_paths` gate applies unchanged).
    pub async fn fork_many<V, F>(&self, vmm: &V, count: usize, cids: Arc<CidAllocator>,
        vmids: VmidAllocator, make_cgroups: F) -> Result<Vec<MicroVm<V>>> where /* … */;

    /// branch(): freeze a RUNNING descendant `child` into a NEW lineage node whose
    /// parent is this node (generation + 1, ancestry extended by this node's id).
    /// Snapshots `child` into `dir` (created if absent) and returns the new node;
    /// `child` stays live and the caller owns `dir`'s lifecycle. Re-validates
    /// snapshot-eligibility (§12.1) via the same `check_clone_eligible` predicate.
    pub async fn branch<V: Vmm>(&self, child: &mut MicroVm<V>, dir: impl Into<PathBuf>) -> Result<Lineage>;
}
```

**Why `Lineage` is the handle and not a field on `MicroVm`.** The lineage relationship is caller-visible
provenance, not per-VM runtime state, and threading it as a value keeps it out of the 300-line `MicroVm`
struct and its nine construction sites (each an opportunity to forget a field). A `Lineage` is cheap to
clone (`Arc`-backed ancestry, `Zygote` is `Clone`), so a caller holds the handles it cares about and asks
each to `fork`/`branch`. `branch(child, dir)` takes the running descendant explicitly — the caller passes
the node the child was forked from — which is exactly the git-branch mental model: *you* say where the
branch diverges from.

**The tree, concretely.** `fork_from_vm` → node `root` (gen 0). `root.fork()` → a live VM; run work in it;
`root.branch(vm, dir_b1)` → node `b1` (gen 1, parent `root`, ancestry `[root]`). `b1.fork()` → a live VM;
`b1.branch(vm, dir_b2)` → node `b2` (gen 2, parent `b1`, ancestry `[root, b1]`). Each of `root`/`b1`/`b2`
is a complete zygote that can be forked, concurrently and repeatedly, independent of the others — the
snapshots are immutable, so the tree is safe to fan out from any node.

### 21.5 Identity and eligibility reuse — no new laws

fork/branch invent **no** new identity or eligibility logic; they reuse the existing ones so a bug is fixed
once:

- **Per-clone identity.** Every forked child is a `Zygote` clone, so it draws a fresh vmid from the shared
  `VmidAllocator` (hence a distinct `/30`/MAC/IP via `ip_math`/`mac_math`, §9.2) and runs the mandatory
  post-restore resync (clock/entropy/MAC/IP) on its first `agent()` call. Two children of the same node —
  or of two different nodes — never collide on the host, exactly as fan-out siblings do not.
- **Eligibility.** `branch` and `fork_from_vm` re-check snapshot-eligibility through the same
  `check_clone_eligible` predicate the zygote uses (no vhost-user device: no virtio-fs rootfs, no
  unprivileged-vhost-user-net, no data shares, §12.1) — a typed `Error::Unsupported`, at construction,
  before any snapshot or copy is minted.
- **Concurrency gate.** `fork_many` is `Zygote::spawn_clones`, so the concurrent-fan-out gate on
  `restore_rotates_host_paths` (§9.4) is the same single source of truth — a concurrent fan-out on a
  verbatim-rebind backend (Firecracker) is the same typed `Error::Unsupported`; a single `fork` is always
  fine. A **sequential** lineage chain (fork one, branch it, fork one, …) works on every backend, which is
  precisely the "single-lineage" shape Firecracker supports (`restore_rotates_host_paths: false`, §3.2).

### 21.6 Cross-cutting invariants added

Folded into §12 (numbering continues from §12.23):

- **§12.24 — Every CoW clone is materialized through the injected `OverlayStore`, into a private copy,
  never the master.** No restore path copies a suspend directory except by calling
  `OverlayStore::clone_tree(master, private_dst)`, where `private_dst` lives inside the clone's own scratch
  dir (reclaimed by the §12.10 teardown) and is distinct from the master. The seam is the single
  clone-materialization law; the reflink ioctl and its fallback stay inside `reflink.rs` (one impl). Owner:
  `overlay::OverlayStore` + `MicroVm::restore_inner`. Gate: the `RecordingOverlayStore` test asserting the
  restore path calls `clone_tree` once per clone with a private, non-master `dst` (red if a restore is
  handed the master); the `ReflinkOverlayStore` faithful-and-independent-copy test (writing the clone never
  mutates the master); the probe-agrees-with-actual-clone test.

- **§12.25 — A lineage is immutable and acyclic; a branch's ancestry is its parent's plus its parent,
  generation strictly increases, and no node is its own ancestor.** `branch` produces a node with
  `parent = Some(self.id)`, `generation = self.generation + 1`, and `ancestry = self.ancestry ++ [self.id]`
  (root..parent inclusive); a root has `parent = None`, `generation = 0`, empty ancestry. `is_ancestor_of`
  is antisymmetric and transitive by construction, and **cross-family-safe**: it first checks the two nodes
  share a `LineageAllocator` (`Arc::ptr_eq`), then that `self.id` is in `other`'s ancestry — so two nodes
  minted by distinct allocators are never a false-positive ancestry even when their ids collide (each
  allocator starts at `L1`). Each node's
  snapshot is an immutable master (§12.12 extends to branch nodes), so the tree never mutates a node under
  a live descendant. Owner: `lineage::Lineage`. Gate: the ancestry-construction unit test
  (root → b1 → b2 generations/parents/ancestries), the `is_ancestor_of` antisymmetry test, the
  no-self-ancestor test, and the `LineageAllocator` distinct-ids test — all red on the corresponding
  inverse.

### 21.7 Quality gates (added to §14)

- **Unit / pure (KVM-free, root-free, in `just ci`):**
  - `overlay`: `ReflinkOverlayStore::clone_tree` produces a faithful, independent copy (write-clone
    ≠ mutate-master); rejects a missing/non-dir `src` and a pre-existing `dst`; preserves symlinks;
    `probe` agrees with an actual clone's `CowSupport` on the test filesystem; `RecordingOverlayStore`
    records `(src, dst)` and honors its configured `CowSupport`.
  - `lineage`: `LineageAllocator` hands out distinct ids; a root has gen 0 / no parent / empty ancestry;
    `branch` yields parent == the branched node, gen + 1, ancestry extended; a 3-node chain has the right
    generations/parents/ancestries; `is_ancestor_of` is antisymmetric and transitive; no node is its own
    ancestor; ineligible-config (`branch`/`fork_from_vm` on a vhost-user config) is `Error::Unsupported` at
    construction.
- **Integration against the recording fakes (KVM-free, in `just ci`):** with a `RecordingVmm` +
  `RecordingOverlayStore`, `Lineage::fork` materializes the clone through the seam into a **private**
  dir (asserted from the recorder), the clone gets a distinct vmid, and the master is byte-unchanged;
  `Lineage::branch` snapshots the child and returns a node with the correct lineage metadata;
  `fork_many` inherits the §9.4 all-or-nothing teardown and the concurrent-fan-out gate (reused from
  `Zygote`, already gated).
- **Host-validated (KVM, `just test-privileged`, DONE 2026-07-06 — `tests/lineage.rs`):** a live `fork`
  clone from a lineage node boots, `exec`s (data-plane output asserted), and has guest MAC ==
  `mac_math(vmid)`; a `branch` of a **diverged** running clone (one that wrote a marker into tmpfs)
  produces a node whose `fork` **sees** the marker while a `fork` from the root does **not** — a data-plane
  positive/negative divergence control. Green on CH + FC (QEMU skips visibly, no snapshot). See §21.8.

### 21.8 What ships now, and the honest forward work

**Shipped and gated in v25:** the `overlay::OverlayStore` seam (trait + `ReflinkOverlayStore` +
`RecordingOverlayStore`) threaded into `MicroVm::restore_cow`/`restore_inner` and held by `Zygote`; the
`lineage::{Lineage, LineageId, LineageAllocator}` handle with `fork`/`fork_many`/`branch`/`fork_from_vm`,
delegating to `Zygote`; invariants §12.24–§12.25 with their red-on-inverse gates; the daemon launcher
passing the production `ReflinkOverlayStore` at its `restore_cow` call site. The zygote fan-out (§9.4) and
§12.12 are unchanged beneath the new seam.

**KVM-host validation — DONE (2026-07-06).** Both operating-mode suites are green on this KVM host under the
delegated scope: `just test-privileged` **87 passed / 5 skipped** (the new `tests/lineage.rs`
`fork_branch_lineage` live test on CH + FC, plus `zygote_fan_out` / `snapshot_restore` /
`extra_block_survives_snapshot` exercising `restore_cow` through the new seam on real micro-VMs) and
`just test-unprivileged` **4 passed**. Running the live suite (not just static review) caught a real
`branch`/`fork_from_vm` bug — a missing destination-dir create, invisible to the `FakeVmm` unit gate —
now fixed and unit-guarded (`implementation-notes.md` (e)).

**Forward work (each a real edge, not a hedge):**

- **A non-reflink `OverlayStore`.** The seam exists precisely to admit one: a shared content-addressed
  overlay pool (dedup identical suspend images across lineages), or a store that keeps branch-node images
  on a cheaper tier. v25 ships only `ReflinkOverlayStore`; the fake proves the injection point.
- **Daemon-injected store + a fork/branch control-plane verb.** The daemon uses `restore_cow` for
  restore-by-name today and passes the default store; exposing `Lineage` fork/branch over the HTTP/`VmEngine`
  surface (a `POST /v1/vms/{id}/branch`, a `fork` verb) and letting the operator pick the store are the
  natural next increment (the library API is the foundation).
- **Lineage-aware orphan sweep.** The start-up sweep (§18.4) reclaims netns/tap/cgroup/scratch by prefix;
  branch-node *master* directories are caller-owned (like zygote masters) and are not swept. A store that
  owns branch-node image lifecycle would add a reclaim path here.
- **CoW between a branch node and its parent image.** `branch` writes a complete new suspend image
  (correctness over depth, §21.3); a store could reflink the unchanged pages of the new image against the
  parent's at snapshot time, trading the depth cost for reflink sharing — an `OverlayStore` refinement,
  not a restore-path change.

---

## Amendments to the base document (v23/v24)

- **§2.2 (key decisions)** — add a row: **Copy-on-write clone as a seam + lineage** | The zygote CoW copy
  (§9.4) is lifted behind an injectable `OverlayStore` (trait + `ReflinkOverlayStore` + recording double,
  the `CgroupFs` pattern), and a `Lineage` handle adds `fork` (mint a live child) / `branch` (freeze a
  running descendant into a new node) over the existing `Zygote`, with immutable, acyclic lineage
  (§12.24–§12.25). Each node is a flat single snapshot (no backing chain, §21.3).
- **§9.4 (zygote fan-out)** — the per-clone CoW copy is now materialized through the injected
  `OverlayStore::clone_tree` (production `ReflinkOverlayStore` wraps the same `reflink.rs` primitive), and
  the fan-out grows the §21.4 lineage layer (`Lineage` over `Zygote`). The cost model and the
  `restore_rotates_host_paths` concurrent-fan-out gate are unchanged.
- **§10.2 (public API)** — three additive items: `pub mod overlay` (`OverlayStore`, `ReflinkOverlayStore`)
  and `pub mod lineage` (`Lineage`, `LineageId`, `LineageAllocator`); `MicroVm::restore_cow` gains a final
  `overlay_store: Arc<dyn OverlayStore>` parameter (the one breaking change — 0.x minor bump,
  semver-checks-clean); `Zygote` gains `with_overlay_store` (default `ReflinkOverlayStore`). `Zygote`'s
  `spawn_clone`/`spawn_clones` signatures are unchanged (the store comes from the handle).
- **§12** — new invariants **§12.24–§12.25** (§21.6); §12.12 (master immutability) explicitly extends to
  branch nodes.
- **§14** — new gates (§21.7).
- **§16 (open decisions)** — the "single-snapshot CoW clone + fork/branch + OverlayStore" item moves from
  forward-work to: "OverlayStore seam + `Lineage` fork/branch built and gated (§21); a non-reflink store
  and a control-plane fork/branch verb are the remaining increments (§21.8)."
- **§17 (future capabilities) / `docs/todo.md`** — strike "Single-snapshot copy-on-write clone +
  fork()/branch() with lineage handles (new injectable OverlayStore seam)" from the build-later list; it is
  §21.
