//! The VM registry — the daemon's **owned**, in-process table of live VMs (design §11.4, The VM registry and the start-up sweep).
//!
//! The daemon is the single owner of every VM it starts: it holds the `MicroVm` handle (through the
//! [`VmHandle`] seam), so the VMM process and its netns/tap/cgroup/scratch stay alive as long as the
//! handle is held, and **`Drop` releases them** in order (§13, Cross-cutting invariants; the invariant is preserved, not
//! abandoned). `destroy` is the graceful path (`MicroVm::shutdown`); dropping the registry (daemon
//! exit) runs each VM's ordered `Drop`. A hard-killed daemon leaks resources, which the **start-up
//! orphan sweep** (`vmcell::orchestrator::sweep_orphans`, wired in `vmcelld`) reclaims on the next boot.
//!
//! Each VM sits behind its own async mutex, so ops on **different** VMs run concurrently while ops on
//! **one** VM serialize on its single vsock control channel. The immutable identity of a VM (id, vmid,
//! the artifact names it pins) is read lock-free and its observable **status** (lifecycle state plus
//! the snapshot prefix being written) sits behind a tiny sync lock; the async per-VM lock holds
//! **only the handle**, so a long op — a snapshot writes guest RAM under it — never blocks a status
//! read, and `GET /v1/vms` never queues behind one VM's snapshot.

use crate::artifact_store::ArtifactStore;
use crate::dto::{
    CreateVmRequest, ExecOutcomeDto, ExecRequestDto, ResourceUsageDto, SnapshotInfo,
    StewardPlacementDto, VmId, VmInfo, VmState,
};
use crate::error::{DaemonError, DaemonResult};
use crate::launcher::{LaunchSpec, VmHandle, VmLauncher};
use crate::name::validate_artifact_name;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::Mutex;

/// One owned VM. The identity fields are immutable (set once at create) so a pin check reads them
/// lock-free; the observable status sits behind a tiny sync lock ([`VmSlot::status`]) and only the
/// VM **handle** — the single vsock control channel — sits behind the async [`VmSlot::inner`].
struct VmSlot {
    id: VmId,
    vmid: u32,
    kernel: String,
    rootfs: String,
    /// The extra-disk artifact names this VM pins (design §11.4, The VM registry and the start-up sweep) — read lock-free by
    /// the delete-in-use guard, like `kernel`/`rootfs`.
    extra_disks: Vec<String>,
    vcpus: u8,
    mem_mib: u32,
    /// The observable status, deliberately **outside** `inner` (finding
    /// `snapshotting-state-unobservable-and-list-blocks`): a snapshot holds `inner` for the whole
    /// guest-RAM write, so a state read that took `inner` could never observe `Snapshotting` and
    /// made `GET /v1/vms` — which reads every slot — block behind one VM's snapshot. Held only for
    /// the few instructions of a read/assignment and **never across an `.await`**.
    status: std::sync::Mutex<SlotStatus>,
    inner: Mutex<VmInner>,
}

/// The lock-free-readable half of a slot: what `info`/`list`/`require_state`/`pins` need.
#[derive(Debug)]
struct SlotStatus {
    /// The lifecycle state reported by `GET /v1/vms{,/id}` and enforced by
    /// [`VmSlot::require_state`].
    state: VmState,
    /// `Some(prefix)` while a snapshot is writing into `<artifacts-dir>/<prefix>/` — the pin that
    /// makes `delete_artifact_if_unused` refuse the prefix for the write's duration (finding
    /// `snapshot-prefix-unpinned-during-the-write`, where a racing delete `remove_dir_all`'d the
    /// prefix and the snapshot still returned 200 with an empty file list).
    snapshot_prefix: Option<String>,
}

struct VmInner {
    /// `None` once torn down (a racing op that cloned the `Arc` before removal then sees `None`).
    handle: Option<Box<dyn VmHandle>>,
}

impl VmSlot {
    /// The status lock, poison-tolerant (a panicking holder leaves a consistent two-field struct).
    fn status(&self) -> std::sync::MutexGuard<'_, SlotStatus> {
        self.status
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The current lifecycle state (no `inner` hold — see [`VmSlot::status`]).
    fn state(&self) -> VmState {
        self.status().state
    }

    fn set_state(&self, state: VmState) {
        self.status().state = state;
    }

    /// The ONE lifecycle-state transition every completed op uses: move `from` -> `to`, and leave the
    /// state alone if it is no longer `from`.
    ///
    /// The conditional is what honors the **one-way `Destroying` door**. A destroy marks `Destroying`
    /// in place and then waits for the handle lock the op holds (see [`Registry::teardown_slot`]), so
    /// an op that finishes afterwards and assigned its own result unconditionally would re-advertise a
    /// VM whose teardown is already parked behind it and let a new op in behind that. It applies to
    /// every op that moves the state, not just the snapshot it was first written for: a `pause` that
    /// lands after a destroy would otherwise publish `Paused` over `Destroying`.
    fn transition_from(&self, from: VmState, to: VmState) {
        let mut status = self.status();
        if status.state == from {
            status.state = to;
        }
    }

    /// The one state predicate every op shares: `Conflict` (409) unless the VM is in `want`.
    fn require_state(&self, want: VmState, id: &VmId) -> DaemonResult<()> {
        let state = self.state();
        if state == want {
            Ok(())
        } else {
            Err(DaemonError::Conflict(format!(
                "vm {id} is {state:?}, not {want:?}"
            )))
        }
    }

    /// Whether this VM pins `artifact_name` as its kernel, rootfs, one of its extra disks, or the
    /// snapshot prefix it is writing **right now** — the single delete-in-use predicate (design
    /// §11.3, The artifact store; §11.4, The VM registry and the start-up sweep). Every caller
    /// (`is_artifact_in_use`, `delete_artifact_if_unused`) shares this one law — never a second copy.
    fn pins(&self, artifact_name: &str) -> bool {
        self.kernel == artifact_name
            || self.rootfs == artifact_name
            || self.extra_disks.iter().any(|d| d == artifact_name)
            || self.status().snapshot_prefix.as_deref() == Some(artifact_name)
    }

    fn info(&self) -> VmInfo {
        VmInfo {
            id: self.id.clone(),
            state: self.state(),
            vmid: self.vmid,
            kernel: self.kernel.clone(),
            rootfs: self.rootfs.clone(),
            vcpus: self.vcpus,
            mem_mib: self.mem_mib,
        }
    }
}

/// Holds a VM's snapshot-prefix pin for the duration of the write and releases it on **every** exit
/// path — success, an early `?`, or a panic — so a failed snapshot can never leave an artifact name
/// permanently undeletable (finding `snapshot-prefix-unpinned-during-the-write`).
struct SnapshotPin<'a> {
    slot: &'a VmSlot,
}

impl<'a> SnapshotPin<'a> {
    /// Claims the pin. Taken **before** the prefix directory exists, so there is no window in which
    /// the directory is on disk and unpinned.
    fn claim(slot: &'a VmSlot, prefix: &str) -> Self {
        slot.status().snapshot_prefix = Some(prefix.to_string());
        Self { slot }
    }
}

impl Drop for SnapshotPin<'_> {
    fn drop(&mut self) {
        self.slot.status().snapshot_prefix = None;
    }
}

/// The result of a create: the VM's info plus, if the request carried an inline `command`, the
/// captured exec outcome.
#[derive(Debug)]
pub struct CreatedVm {
    /// The created VM's metadata.
    pub info: VmInfo,
    /// The inline command's outcome, if any.
    pub exec: Option<ExecOutcomeDto>,
}

/// The daemon's owned VM registry: launches VMs, holds their handles, and drives ops through them.
pub struct Registry {
    launcher: Box<dyn VmLauncher>,
    artifacts: ArtifactStore,
    vms: Mutex<HashMap<VmId, Arc<VmSlot>>>,
    counter: AtomicU64,
    seed: u64,
}

impl Registry {
    /// Builds a registry over a `launcher` and the artifact store. `seed` diversifies the opaque VM
    /// ids so they are not a bare guessable counter.
    #[must_use]
    pub fn new(launcher: Box<dyn VmLauncher>, artifacts: ArtifactStore, seed: u64) -> Self {
        Self {
            launcher,
            artifacts,
            vms: Mutex::new(HashMap::new()),
            counter: AtomicU64::new(1),
            seed,
        }
    }

    /// Read access to the artifact store (for the artifact HTTP handlers).
    #[must_use]
    pub fn artifacts(&self) -> &ArtifactStore {
        &self.artifacts
    }

    fn mint_id(&self) -> VmId {
        let n = self.counter.fetch_add(1, Ordering::Relaxed);
        let suffix = splitmix64(self.seed ^ n);
        VmId(format!("vm-{n}-{suffix:016x}"))
    }

    /// Resolves a kernel/rootfs artifact name to an existing file path, or a typed error.
    fn resolve_existing(&self, name: &str, role: &str) -> DaemonResult<PathBuf> {
        let path = self.artifacts.path_for(name)?; // validates the name (invariant §13, Cross-cutting invariants)
        if !path.is_file() {
            return Err(DaemonError::BadRequest(format!(
                "{role} artifact {name:?} does not exist in the store; upload it first"
            )));
        }
        Ok(path)
    }

    async fn slot(&self, id: &VmId) -> DaemonResult<Arc<VmSlot>> {
        self.vms
            .lock()
            .await
            .get(id)
            .cloned()
            .ok_or_else(|| DaemonError::NotFound(format!("no vm {id}")))
    }

    /// Creates and boots a VM the registry then **owns** (design §11.5, The HTTP REST API and its OpenAPI document). With a `command`, also
    /// execs it; with `ephemeral`, tears it down after — the `run` one-shot.
    ///
    /// # Errors
    /// [`DaemonError::BadRequest`]/[`DaemonError::InvalidName`] for a bad/absent artifact, else the
    /// mapped launch/exec error.
    pub async fn create(&self, req: CreateVmRequest) -> DaemonResult<CreatedVm> {
        let kernel_path = self.resolve_existing(&req.kernel, "kernel")?;
        let rootfs_path = self.resolve_existing(&req.rootfs, "rootfs")?;
        if let Some(cmd) = &req.command
            && cmd.is_empty()
        {
            return Err(DaemonError::BadRequest("command must be non-empty".into()));
        }
        // Fail loud early on a snapshot-ineligible request (design §13, Cross-cutting invariants), rather than deferring to
        // the config builder's `Error`.
        if req.snapshotting && !req.net.snapshot_eligible() {
            return Err(DaemonError::BadRequest(format!(
                "snapshotting requires a snapshot-eligible net mode (no vhost-user device); {:?} is not eligible",
                req.net
            )));
        }
        // Fail loud early on a placement the daemon cannot own (design §11.5, §18 delta 10), at the
        // daemon's OWN boundary rather than deferring to the config builder — see
        // `resolve_steward_placement` for why deferring would be a different rule.
        let steward_placement = resolve_steward_placement(&req)?;
        // Resolve a `restore_from` prefix to its snapshot directory in the store (the same validated
        // single-component join as any artifact, invariant §13, Cross-cutting invariants).
        let restore_from = match &req.restore_from {
            Some(prefix) => {
                validate_artifact_name(prefix)?;
                let dir = self.artifacts.dir().join(prefix);
                if !dir.is_dir() {
                    return Err(DaemonError::BadRequest(format!(
                        "no snapshot to restore at prefix {prefix:?}; snapshot a VM there first"
                    )));
                }
                Some(dir)
            }
            None => None,
        };
        // Resolve each extra-disk artifact name to a read-only BlockDevice (the store is
        // immutable, §11.4, The VM registry and the start-up sweep), translating any io_limit (§4.6, Extra virtio-blk devices and disk-I/O throttling). The names are pinned on the
        // slot below so `is_artifact_in_use` refuses to delete a disk a live VM uses.
        let mut extra_disks = Vec::with_capacity(req.extra_disks.len());
        for spec in &req.extra_disks {
            let path = self.resolve_existing(&spec.name, "disk")?;
            let mut disk = vmcell::BlockDevice::read_only(path);
            if let Some(limit) = &spec.io_limit {
                disk = disk.with_io_limit(vmcell::config::DiskIoLimit::new(
                    limit.bandwidth_bytes_per_sec,
                    limit.iops,
                ));
            }
            extra_disks.push(disk);
        }
        let pinned_disks: Vec<String> = req.extra_disks.iter().map(|d| d.name.clone()).collect();

        let spec = LaunchSpec {
            kernel: kernel_path,
            rootfs: rootfs_path,
            vcpus: req.vcpus,
            mem_mib: req.mem_mib,
            net: req.net,
            snapshotting: req.snapshotting,
            restore_from,
            extra_disks,
            extra_kernel_args: req.extra_kernel_args.clone(),
            init: req.init.as_deref().map(PathBuf::from),
            steward_placement,
        };
        let handle = self.launcher.launch(&spec).await?;
        let id = self.mint_id();
        let slot = Arc::new(VmSlot {
            id: id.clone(),
            vmid: handle.vmid(),
            kernel: req.kernel.clone(),
            rootfs: req.rootfs.clone(),
            extra_disks: pinned_disks,
            vcpus: req.vcpus,
            mem_mib: req.mem_mib,
            status: std::sync::Mutex::new(SlotStatus {
                state: VmState::Ready,
                snapshot_prefix: None,
            }),
            inner: Mutex::new(VmInner {
                handle: Some(handle),
            }),
        });
        let info = slot.info();
        self.vms.lock().await.insert(id.clone(), slot);

        let Some(cmd) = req.command else {
            return Ok(CreatedVm { info, exec: None });
        };
        let outcome = self.exec(&id, ExecRequestDto::new(cmd)).await;
        // Tear down when the request asked for a one-shot (regardless of the exec result — the
        // `ephemeral` contract) AND whenever the exec itself FAILED, because `create` is one
        // operation: the error reply carries no `CreateVmResponse`, so a kept VM would be a booted,
        // resource-holding cell whose id the caller never received and cannot destroy (finding
        // `create-leaks-the-vm-a-failed-inline-exec-abandons`). A command that RAN and exited
        // non-zero is an `Ok` outcome and keeps its VM, as `ephemeral: false` asks.
        // A teardown error is logged, never masked over the exec outcome the caller asked for.
        if (req.ephemeral || outcome.is_err())
            && let Err(e) = self.destroy(&id).await
        {
            tracing::warn!(vm = %id, error = %e, "teardown after inline exec failed");
        }
        Ok(CreatedVm {
            info,
            exec: Some(outcome?),
        })
    }

    /// Lists every owned VM, sorted by id. Each slot's info is read off its sync status lock, so a
    /// VM in the middle of a snapshot (holding its `inner` for the whole write) neither blocks this
    /// call nor hides behind a stale `Ready`.
    pub async fn list(&self) -> Vec<VmInfo> {
        let mut out: Vec<VmInfo> = self.vms.lock().await.values().map(|s| s.info()).collect();
        out.sort_by(|a, b| a.id.0.cmp(&b.id.0));
        out
    }

    /// Reads one VM's info.
    ///
    /// # Errors
    /// [`DaemonError::NotFound`] if there is no such VM.
    pub async fn get(&self, id: &VmId) -> DaemonResult<VmInfo> {
        Ok(self.slot(id).await?.info())
    }

    /// Runs a command in a `Ready` VM.
    ///
    /// # Errors
    /// [`DaemonError::NotFound`] (gone) / [`DaemonError::Conflict`] (not `Ready`) / mapped exec error.
    pub async fn exec(&self, id: &VmId, req: ExecRequestDto) -> DaemonResult<ExecOutcomeDto> {
        let slot = self.slot(id).await?;
        // Check the state BEFORE queueing on the handle lock: an exec against a snapshotting VM
        // must 409 promptly. Waiting for `inner` first meant the snapshot had already finished and
        // reset the state to `Ready` by the time the check ran, so the promised conflict never
        // fired (finding `snapshotting-state-unobservable-and-list-blocks`).
        slot.require_state(VmState::Ready, id)?;
        let mut inner = slot.inner.lock().await;
        // Re-check under the handle lock: the state can move while we queue (a destroy, or a
        // snapshot that started in the gap). Same predicate, no second copy of the law.
        slot.require_state(VmState::Ready, id)?;
        handle_mut(&mut inner, id)?.exec(req).await
    }

    /// Samples a VM's resource usage.
    ///
    /// # Errors
    /// [`DaemonError::NotFound`] / mapped read error.
    pub async fn stats(&self, id: &VmId) -> DaemonResult<ResourceUsageDto> {
        let slot = self.slot(id).await?;
        let mut inner = slot.inner.lock().await;
        handle_mut(&mut inner, id)?.usage().await
    }

    /// Pauses a `Ready` VM's vCPUs, returning the VM's updated info (design §11.5, The HTTP REST API
    /// and its OpenAPI document; the [`VmHandle::pause`] half has
    /// shipped since the seam was written).
    ///
    /// # Errors
    /// [`DaemonError::NotFound`] (gone) / [`DaemonError::Conflict`] (not `Ready` — already paused,
    /// snapshotting, or being destroyed) / the mapped backend error.
    pub async fn pause(&self, id: &VmId) -> DaemonResult<VmInfo> {
        self.drive_vcpus(id, VcpuVerb::Pause).await
    }

    /// Resumes a `Paused` VM's vCPUs, returning the VM's updated info.
    ///
    /// # Errors
    /// [`DaemonError::NotFound`] (gone) / [`DaemonError::Conflict`] (not `Paused`) / the mapped
    /// backend error.
    pub async fn resume(&self, id: &VmId) -> DaemonResult<VmInfo> {
        self.drive_vcpus(id, VcpuVerb::Resume).await
    }

    /// The one state machine both vCPU verbs run (one law, one predicate — a second copy would be
    /// two chances to get the `Destroying` door or the re-check wrong).
    ///
    /// It is deliberately the **same** shape `exec` and `snapshot` use, because the hazards are the
    /// same ones:
    ///
    /// * the required state is checked BEFORE queueing on the handle lock, so a verb aimed at a
    ///   snapshotting or dying VM gets its 409 promptly instead of after a multi-second guest-RAM
    ///   write (finding `snapshotting-state-unobservable-and-list-blocks`);
    /// * it is re-checked UNDER the lock, because the state can move while the call queues — the
    ///   same predicate, never a second copy;
    /// * the new state is published only on success and only through [`VmSlot::transition_from`], so
    ///   a failed pause leaves a still-`Ready` VM (a state derived from the handle, not a hopeful
    ///   label) and a pause that lands behind a parked teardown does not reopen the VM.
    ///
    /// The residual, stated rather than hidden: a backend that pauses the guest and *then* fails its
    /// reply leaves the daemon reporting `Ready` for a stopped guest. The alternative — recording the
    /// state a failed call asked for — makes the label a wish on every path, so the honest one is
    /// kept and the client's remedy is the ordinary one: retry, or destroy.
    async fn drive_vcpus(&self, id: &VmId, verb: VcpuVerb) -> DaemonResult<VmInfo> {
        let slot = self.slot(id).await?;
        slot.require_state(verb.from(), id)?;
        let mut inner = slot.inner.lock().await;
        slot.require_state(verb.from(), id)?;
        verb.drive(handle_mut(&mut inner, id)?).await?;
        slot.transition_from(verb.from(), verb.to());
        Ok(slot.info())
    }

    /// Writes a warm snapshot of a `Ready` VM into the artifact store under `artifact_prefix/`,
    /// returning the (sorted) file names written. The prefix is **create-only**, like every other
    /// name in the store: an existing one is refused, not written into. For the duration of the
    /// write the prefix is **pinned** on the slot, so the delete-in-use guard refuses it.
    ///
    /// # Errors
    /// [`DaemonError::InvalidName`] for a bad or reserved prefix, [`DaemonError::AlreadyExists`]
    /// for a prefix the store already holds, [`DaemonError::NotFound`]/[`DaemonError::Conflict`],
    /// [`DaemonError::Internal`] if the written directory cannot be read back, or the mapped
    /// snapshot error (`Unsupported` for an ineligible config, design §13, Cross-cutting invariants).
    pub async fn snapshot(&self, id: &VmId, artifact_prefix: &str) -> DaemonResult<SnapshotInfo> {
        // The prefix names a subdirectory of the artifact store — validate it as a single safe
        // component (invariant §13, Cross-cutting invariants) so a snapshot cannot escape the store.
        validate_artifact_name(artifact_prefix)?;
        let out_dir = self.artifacts.dir().join(artifact_prefix);

        // Resolve the VM and assert `Ready` BEFORE any filesystem mutation, so a NotFound/Conflict
        // rejection leaves zero residue (the "mid-op faults leave zero residue" discipline). Only
        // then create the snapshot dir, under the per-VM lock.
        let slot = self.slot(id).await?;
        slot.require_state(VmState::Ready, id)?;
        let mut inner = slot.inner.lock().await;
        slot.require_state(VmState::Ready, id)?;
        // `create_dir`, NOT `create_dir_all`: the store is create-only (design §11.3, The artifact
        // store) and a snapshot prefix is part of that namespace, so an existing prefix is a 409,
        // never a write into a populated directory. The old `create_dir_all` let a second snapshot
        // overwrite part of an older one file-by-file, and a `restore_from` copy racing that write
        // read a torn mix of the two lineages (finding `snapshot-prefix-silent-reuse`). The
        // EEXIST check is the kernel's, so it is atomic against a concurrent snapshot to the same
        // prefix — no check-then-act window. Free the name with DELETE /v1/artifacts/{prefix},
        // which removes a snapshot prefix dir (`ArtifactStore::delete`).
        //
        // PIN the prefix first (released by `Drop` on every exit path): `delete_artifact_if_unused`
        // holds only the `vms` lock and this op holds only `slot.inner`, so without the pin the two
        // did not exclude each other — a delete could `remove_dir_all` the prefix mid-write and the
        // snapshot still reported 200 (finding `snapshot-prefix-unpinned-during-the-write`).
        // Claimed BEFORE `create_dir` so the directory is never on disk unpinned.
        let _pin = SnapshotPin::claim(&slot, artifact_prefix);
        std::fs::create_dir(&out_dir).map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                DaemonError::AlreadyExists(format!(
                    "snapshot prefix {artifact_prefix:?} already exists in the artifact store \
                     (the store has no update; delete it, then snapshot again)"
                ))
            } else {
                DaemonError::Internal(format!("cannot create snapshot dir {out_dir:?}: {e}"))
            }
        })?;
        // The state is set only once the handle is in hand, so a torn-down VM cannot leave the slot
        // stuck in `Snapshotting` on the `?` path.
        let result = match handle_mut(&mut inner, id) {
            Ok(handle) => {
                slot.set_state(VmState::Snapshotting);
                let r = handle.snapshot(&out_dir).await;
                // Still live whether or not the snapshot succeeded — through the one transition
                // helper, so the `Destroying` door stays one-way.
                slot.transition_from(VmState::Snapshotting, VmState::Ready);
                r
            }
            Err(e) => Err(e),
        };
        if result.is_err() {
            // A failed snapshot leaves no residue: drop the dir we just created if it is empty
            // (a partial-write backend leaves files; `remove_dir` then fails with ENOTEMPTY and
            // those files are preserved for diagnosis — logged, never silently discarded).
            if let Err(e) = std::fs::remove_dir(&out_dir) {
                tracing::debug!(dir = ?out_dir, error = %e, "failed snapshot: prefix dir kept (not empty)");
            }
        }
        result?;

        // Enumerate the artifacts CH wrote into the snapshot dir, so a later restore can name them.
        // Fail loud: this read used to be `.unwrap_or_default()`, which turned a vanished prefix
        // (deleted mid-write) or an unreadable dir into a 200 with `files: []` — a snapshot the
        // caller believes exists (finding `snapshot-prefix-unpinned-during-the-write`, second half).
        let rd = std::fs::read_dir(&out_dir).map_err(|e| {
            DaemonError::Internal(format!("cannot read back snapshot dir {out_dir:?}: {e}"))
        })?;
        let mut files = Vec::new();
        for entry in rd {
            let entry = entry.map_err(|e| {
                DaemonError::Internal(format!(
                    "cannot read snapshot dir entry in {out_dir:?}: {e}"
                ))
            })?;
            let name = entry.file_name().into_string().map_err(|raw| {
                DaemonError::Internal(format!(
                    "snapshot file name {raw:?} in {out_dir:?} is not valid UTF-8"
                ))
            })?;
            files.push(name);
        }
        files.sort(); // deterministic order (readdir order is filesystem-dependent)
        Ok(SnapshotInfo {
            artifact_prefix: artifact_prefix.to_string(),
            files,
        })
    }

    /// Destroys a VM: marks it `Destroying` (so no new op is admitted), runs its graceful ordered
    /// teardown (`MicroVm::shutdown`), and drops it from the table.
    ///
    /// An op racing a teardown is refused by the state, not by the VM's absence: it sees
    /// `Destroying` and gets a prompt [`DaemonError::Conflict`] until the teardown completes, then
    /// [`DaemonError::NotFound`]. The slot leaves the table **last**, with the handle lock already
    /// held, so an in-flight snapshot's prefix stays pinned for the whole teardown — see the private
    /// `teardown_slot`, the one ordered helper this and `shutdown_all` share.
    ///
    /// # Errors
    /// [`DaemonError::NotFound`] if there is no such VM; a teardown failure is propagated.
    pub async fn destroy(&self, id: &VmId) -> DaemonResult<()> {
        let slot = self.slot(id).await?;
        self.teardown_slot(&slot).await
    }

    /// The one ordered per-slot teardown [`Registry::destroy`] and [`Registry::shutdown_all`] share
    /// (AGENTS.md: teardown is ownership, through **one** ordered helper — never a second copy).
    ///
    /// All three steps are load-bearing, in this order:
    ///
    /// 1. mark `Destroying` **in place**, so a racing op sees a doomed VM rather than a `Ready` one;
    /// 2. take the handle lock — which is where a teardown *waits*, for as long as an in-flight
    ///    snapshot holds it (a multi-second guest-RAM write);
    /// 3. remove the slot from `self.vms`, with the handle already in hand.
    ///
    /// Step 3 used to be step 1, and that **unpinned the VM for the whole of step 2**: the
    /// delete-in-use scan reads pins — kernel, rootfs, extra disks, and the snapshot prefix being
    /// written right now — only through this table, so a `DELETE /v1/artifacts/<prefix>` landing in
    /// that window found a pin-free table, returned 204, and `remove_dir_all`'d the directory the VMM
    /// was still writing into (finding `destroy-unpins-an-in-flight-snapshot-prefix`).
    ///
    /// Lock order here is `inner` → `vms`; no other path holds `vms` across an `await` on `inner`
    /// (`slot()` drops the map guard before returning), so the pair cannot cycle.
    ///
    /// A teardown **cancelled** while parked (an HTTP client that disconnects) leaves the slot in the
    /// table as `Destroying` with its handle intact: accounted for in `GET /v1/vms`, refusing new ops,
    /// and completed by a retried `DELETE` or by `shutdown_all` — recovery stays retryable rather than
    /// silently dropping a live VM out of the registry.
    async fn teardown_slot(&self, slot: &Arc<VmSlot>) -> DaemonResult<()> {
        slot.set_state(VmState::Destroying);
        let mut inner = slot.inner.lock().await;
        // `None` is legitimate: a concurrent destroy of the same id got here first. Ids are minted
        // once and never reused, so the entry under this id can only ever be this slot.
        if self.vms.lock().await.remove(&slot.id).is_none() {
            tracing::debug!(vm = %slot.id, "slot already removed by a concurrent teardown");
        }
        match inner.handle.take() {
            Some(h) => h.shutdown().await,
            None => Ok(()),
        }
    }

    /// Whether any owned VM pins `artifact_name` as its kernel, rootfs, or one of its
    /// extra disks (design §11.4, The VM registry and the start-up sweep) — read lock-free off the immutable slot fields
    /// (design §11.3, The artifact store; the delete-in-use guard).
    pub async fn is_artifact_in_use(&self, artifact_name: &str) -> bool {
        self.vms
            .lock()
            .await
            .values()
            .any(|s| s.pins(artifact_name))
    }

    /// Atomically deletes an artifact iff no live VM pins it. The in-use check and the file delete
    /// run under a **single** hold of the `vms` lock, closing the delete-side check-then-act TOCTOU
    /// the former two-step (`is_artifact_in_use` then `artifacts.delete`) had: a `create` that has
    /// already inserted its pinning slot is seen and refused. Residual, accepted (single-tenant)
    /// narrow window: `create` resolves the artifact and launches the VM **before** it takes this
    /// lock to insert its slot (see `create`), so a `create` that has resolved-and-launched but not
    /// yet inserted is not yet visible here and its on-disk artifact can still be deleted out from
    /// under it. Closing that would require re-checking the resolved set under this lock after
    /// launch; it is recorded rather than fixed (design §11.3, The artifact store; the delete-in-use
    /// guard).
    ///
    /// # Errors
    /// [`DaemonError::InUse`] if a live VM pins it; [`DaemonError::InvalidName`]/[`DaemonError::NotFound`]/
    /// [`DaemonError::Internal`] from the store delete.
    pub async fn delete_artifact_if_unused(&self, artifact_name: &str) -> DaemonResult<()> {
        // Hold the vms lock across BOTH the in-use check and the file delete — the atomicity that
        // closes the check-then-act window against a concurrent `create` (which re-takes this lock
        // to insert its pinning slot).
        let vms = self.vms.lock().await;
        if vms.values().any(|s| s.pins(artifact_name)) {
            return Err(DaemonError::InUse(format!(
                "artifact {artifact_name:?} is pinned by a live VM; destroy the VM first"
            )));
        }
        self.artifacts.delete(artifact_name)?;
        drop(vms);
        Ok(())
    }

    /// Graceful ordered teardown of every VM (a clean daemon shutdown). Each VM runs its own
    /// `MicroVm::shutdown`; independent VMs have no ordering constraint between them. (A hard kill
    /// skips this and relies on the next boot's orphan sweep.)
    pub async fn shutdown_all(&self) {
        // CLONE the slot list rather than draining the table: each slot leaves it through
        // `teardown_slot`, which keeps its pins visible until its handle lock is held (a VM still
        // writing a snapshot when the daemon is asked to stop is exactly that case).
        let slots: Vec<Arc<VmSlot>> = self.vms.lock().await.values().cloned().collect();
        for slot in slots {
            if let Err(e) = self.teardown_slot(&slot).await {
                tracing::warn!(vm = %slot.id, error = %e, "VM shutdown during daemon teardown failed");
            }
        }
    }

    /// The number of owned VMs.
    pub async fn len(&self) -> usize {
        self.vms.lock().await.len()
    }

    /// Whether the registry owns no VMs.
    pub async fn is_empty(&self) -> bool {
        self.len().await == 0
    }
}

/// Which vCPU-lifecycle verb [`Registry::drive_vcpus`] is running. The pair share one state machine
/// and differ in exactly three facts — the state they require, the state they publish, and the handle
/// call — so those three live here and the machine lives once.
#[derive(Debug, Clone, Copy)]
enum VcpuVerb {
    /// `Ready` -> `Paused`.
    Pause,
    /// `Paused` -> `Ready`.
    Resume,
}

impl VcpuVerb {
    /// The state the VM must be in for this verb to be admitted.
    const fn from(self) -> VmState {
        match self {
            Self::Pause => VmState::Ready,
            Self::Resume => VmState::Paused,
        }
    }

    /// The state a successful call publishes.
    const fn to(self) -> VmState {
        match self {
            Self::Pause => VmState::Paused,
            Self::Resume => VmState::Ready,
        }
    }

    /// Drives the verb through the VM handle.
    async fn drive(self, handle: &mut Box<dyn VmHandle>) -> DaemonResult<()> {
        match self {
            Self::Pause => handle.pause().await,
            Self::Resume => handle.resume().await,
        }
    }
}

fn handle_mut<'a>(inner: &'a mut VmInner, id: &VmId) -> DaemonResult<&'a mut Box<dyn VmHandle>> {
    inner
        .handle
        .as_mut()
        .ok_or_else(|| DaemonError::NotFound(format!("vm {id} has been torn down")))
}

/// Resolves the steward placement a create request declares, refusing the one the daemon cannot own
/// (design §5.3, The kernel command line / §11.5, The HTTP REST API and its OpenAPI document; §18
/// delta 10).
///
/// **This is the daemon's one placement law.** The pre-v33 rule was "no `init=` over REST", with the
/// rationale that the daemon owns every VM it creates through the vsock control plane and could not
/// `exec` or `stats` a VM whose init replaced the steward. v33 scoped the rule by that same
/// rationale: `Service { port }` keeps the control plane, so a custom init is now expressible, and
/// only the rationale's surviving half — a placement with **no** steward — stays unexpressible.
/// [`StewardPlacementDto::control_plane_retained`] is that half, stated once.
///
/// Two ways a client can ask for a stewardless cell, and both are a **400**:
///
/// 1. Naming `"none"` outright.
/// 2. Naming a custom `init` and no placement. The daemon does not guess: `VmConfigBuilder::build()`
///    *derives* `StewardPlacement::None` from `init: Some`, so a daemon that forwarded the init and
///    left the placement unset would silently produce exactly the placement this rule keeps off
///    REST — and the failure would surface downstream in `MicroVm::steward` as a *steward* error,
///    which is a different rule, a different message, and a 500-shaped one. Note this reads
///    `req.init` for request COMPLETENESS, never to derive a placement (C8): the answer here is a
///    refusal, not a placement inferred from an init spelling.
///
/// Everything else the library already refuses fail-loud with its own message, mapped to 400 by
/// `DaemonError::from(vmcell::Error::Config)`: `Pid1` beside a custom init, and a `Service` port of
/// `0`/`u32::MAX`. Re-checking those here would be a second copy that can diverge.
fn resolve_steward_placement(req: &CreateVmRequest) -> DaemonResult<StewardPlacementDto> {
    let Some(declared) = req.steward_placement else {
        if req.init.is_some() {
            return Err(DaemonError::BadRequest(
                "a custom `init` over REST must declare `steward_placement` — \
                 {\"service\":{\"port\":N}}, the port the guest's own init starts the steward on. \
                 The daemon owns every VM it creates through the vsock control plane, and an \
                 undeclared placement beside an `init` means StewardPlacement::None: no steward to \
                 exec, stats, snapshot or destroy the VM through. Use the vmcell library directly \
                 for a stewardless VM."
                    .to_string(),
            ));
        }
        // No init, no placement: the pre-v33 default. Stated explicitly here so the launcher can
        // hand the builder an explicit placement on every path (see `LaunchSpec::steward_placement`).
        return Ok(StewardPlacementDto::Pid1);
    };
    if !declared.control_plane_retained() {
        return Err(DaemonError::BadRequest(format!(
            "steward_placement {declared:?} is not expressible over REST: the daemon owns every VM \
             it creates through the vsock control plane, and this placement has no steward to exec, \
             stats, snapshot or destroy the VM through. Declare \"pid1\" (the vmcell steward is \
             PID 1) or {{\"service\":{{\"port\":N}}}} (the guest's own init starts it); use the \
             vmcell library directly for a stewardless VM."
        )));
    }
    Ok(declared)
}

/// splitmix64 — a tiny, well-mixed integer hash so VM ids are not a bare guessable counter.
fn splitmix64(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = x;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dto::NetMode;
    use async_trait::async_trait;
    use std::sync::atomic::AtomicUsize;

    /// What a fake `snapshot` does beyond writing its one state file — the effects the fs-blind
    /// default cannot exercise (AGENTS.md: name what the fake cannot see, then drive it).
    #[derive(Clone, Default)]
    enum SnapshotBehavior {
        /// Write `state.json` and return.
        #[default]
        Normal,
        /// Signal `entered`, then block until `release` is notified — the in-flight window a
        /// concurrent delete / `get` / `list` / `exec` races against.
        Blocked(Arc<HandleGate>),
        /// Remove the snapshot directory before returning `Ok` — exactly what a racing
        /// `delete_artifact_if_unused` did to an unpinned prefix, so the read-back must fail loud
        /// instead of reporting `files: []`.
        RemovesDir,
    }

    /// What a fake `pause` does — the vCPU verbs' own fault menu (AGENTS.md: every fault-menu arm is
    /// driven by a test). `resume` needs no arms of its own: the state machine both verbs run is one
    /// function, so an arm proven on `pause` is proven for `resume`.
    #[derive(Clone, Default)]
    enum PauseBehavior {
        /// Succeed.
        #[default]
        Normal,
        /// Fail the backend call, so the "state moves only on success" law can be driven.
        Fails,
        /// Signal `entered`, then block until `release` — the in-flight window a concurrent destroy
        /// races against (the one-way `Destroying` door).
        Blocked(Arc<HandleGate>),
    }

    /// The rendezvous a `Blocked` handle op uses: `entered` fires when the backend call starts,
    /// `release` lets it finish. `Notify` stores one permit, so neither side can miss the other.
    /// Shared by the snapshot and pause fault arms — one rendezvous to reason about, not two.
    #[derive(Default)]
    struct HandleGate {
        entered: tokio::sync::Notify,
        release: tokio::sync::Notify,
    }

    /// A recording fake handle — no KVM. Counts execs + shutdowns.
    struct FakeHandle {
        vmid: u32,
        shutdowns: Arc<AtomicUsize>,
        snapshot_behavior: SnapshotBehavior,
        /// Fails every `exec` with a transport-shaped error — the fault a `create` carrying an
        /// inline command must not leak its VM through. A non-zero *exit* is a different thing (an
        /// `Ok` outcome), so this arm is the only way to drive the error path.
        fail_exec: bool,
        pause_behavior: PauseBehavior,
        /// Counts the `pause`/`resume` calls that actually reached the handle — the fake's own data
        /// plane. Without it a registry that moved the state and never called the backend would pass
        /// every state assertion below.
        vcpu_calls: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl VmHandle for FakeHandle {
        fn vmid(&self) -> u32 {
            self.vmid
        }
        async fn exec(&mut self, req: ExecRequestDto) -> DaemonResult<ExecOutcomeDto> {
            if self.fail_exec {
                return Err(DaemonError::Internal(
                    "fake exec: the steward connection died mid-call".to_string(),
                ));
            }
            Ok(ExecOutcomeDto::from_bytes(
                0,
                req.argv.join(" ").as_bytes(),
                b"",
            ))
        }
        async fn usage(&mut self) -> DaemonResult<ResourceUsageDto> {
            Ok(ResourceUsageDto {
                mem_peak_mib: 1,
                mem_current_mib: 1,
                cpu_usec: 1,
                io_read_bytes: 0,
                io_write_bytes: 0,
                mem_limit_enforced: true,
                mem_read_ok: true,
                cpu_read_ok: true,
                io_read_ok: true,
            })
        }
        /// Writes one file into the snapshot dir, tagged with this VM's vmid. The fake is
        /// otherwise fs-blind (AGENTS.md: name what the fake cannot see); this one byte of real
        /// filesystem effect is what lets the prefix-reuse gate below prove that a refused second
        /// snapshot did not overwrite the first VM's state.
        async fn snapshot(&mut self, dir: &std::path::Path) -> DaemonResult<()> {
            if let SnapshotBehavior::Blocked(gate) = &self.snapshot_behavior {
                gate.entered.notify_one();
                gate.release.notified().await;
            }
            std::fs::write(dir.join("state.json"), format!("vmid={}", self.vmid))
                .map_err(|e| DaemonError::Internal(format!("fake snapshot write failed: {e}")))?;
            if matches!(self.snapshot_behavior, SnapshotBehavior::RemovesDir) {
                std::fs::remove_dir_all(dir).map_err(|e| {
                    DaemonError::Internal(format!("fake snapshot dir removal failed: {e}"))
                })?;
            }
            Ok(())
        }
        async fn pause(&mut self) -> DaemonResult<()> {
            self.vcpu_calls.fetch_add(1, Ordering::SeqCst);
            match &self.pause_behavior {
                PauseBehavior::Normal => Ok(()),
                PauseBehavior::Fails => Err(DaemonError::Internal(
                    "fake pause: the VMM control socket refused the pause".to_string(),
                )),
                PauseBehavior::Blocked(gate) => {
                    gate.entered.notify_one();
                    gate.release.notified().await;
                    Ok(())
                }
            }
        }
        async fn resume(&mut self) -> DaemonResult<()> {
            self.vcpu_calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        async fn shutdown(self: Box<Self>) -> DaemonResult<()> {
            self.shutdowns.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    /// The `LaunchSpec`s a [`FakeLauncher`] was handed, in order.
    ///
    /// The fake used to take `_spec: &LaunchSpec` and discard it, which made every registry-level
    /// assertion about a request FIELD vacuous: nothing in the tree observed what the registry
    /// actually put in the spec. `CreateVmRequest` → `LaunchSpec` is one of the two unobserved hops
    /// on a new field's path (the other is the broker bridge, gated in `bridge/tests.rs`).
    type LaunchLog = Arc<std::sync::Mutex<Vec<LaunchSpec>>>;

    struct FakeLauncher {
        next_vmid: AtomicU64,
        shutdowns: Arc<AtomicUsize>,
        snapshot_behavior: SnapshotBehavior,
        fail_exec: bool,
        pause_behavior: PauseBehavior,
        vcpu_calls: Arc<AtomicUsize>,
        launches: LaunchLog,
    }

    #[async_trait]
    impl VmLauncher for FakeLauncher {
        async fn launch(&self, spec: &LaunchSpec) -> DaemonResult<Box<dyn VmHandle>> {
            self.launches.lock().expect("launch log").push(spec.clone());
            Ok(Box::new(FakeHandle {
                vmid: self.next_vmid.fetch_add(1, Ordering::SeqCst) as u32,
                shutdowns: self.shutdowns.clone(),
                snapshot_behavior: self.snapshot_behavior.clone(),
                fail_exec: self.fail_exec,
                pause_behavior: self.pause_behavior.clone(),
                vcpu_calls: self.vcpu_calls.clone(),
            }))
        }
    }

    fn registry() -> (Registry, Arc<AtomicUsize>, tempfile::TempDir) {
        let (reg, shutdowns, _log, dir) = registry_capturing(SnapshotBehavior::Normal);
        (reg, shutdowns, dir)
    }

    fn registry_with(
        snapshot_behavior: SnapshotBehavior,
    ) -> (Registry, Arc<AtomicUsize>, tempfile::TempDir) {
        let (reg, shutdowns, _log, dir) = registry_capturing(snapshot_behavior);
        (reg, shutdowns, dir)
    }

    /// A registry over a **capturing** [`FakeLauncher`], handing back the log of every
    /// [`LaunchSpec`] the registry built.
    fn registry_capturing(
        snapshot_behavior: SnapshotBehavior,
    ) -> (Registry, Arc<AtomicUsize>, LaunchLog, tempfile::TempDir) {
        registry_faulty(Faults {
            snapshot: snapshot_behavior,
            ..Faults::default()
        })
    }

    /// The fake handle's whole fault menu, in one value with a `Default` — so a test names only the
    /// arm it drives and a new arm does not touch every call site.
    #[derive(Clone, Default)]
    struct Faults {
        snapshot: SnapshotBehavior,
        fail_exec: bool,
        pause: PauseBehavior,
        /// The counter the fake handle bumps on every vCPU verb. The caller keeps a clone, which is
        /// how a test asserts the backend was actually driven rather than only the state relabelled.
        vcpu_calls: Arc<AtomicUsize>,
    }

    /// The one registry builder, over the fake's whole fault menu.
    fn registry_faulty(
        faults: Faults,
    ) -> (Registry, Arc<AtomicUsize>, LaunchLog, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let artifacts =
            ArtifactStore::open(dir.path().join("artifacts"), 1 << 20).expect("artifacts");
        artifacts.create("vmlinux", b"kernel").expect("kernel");
        artifacts.create("rootfs.erofs", b"rootfs").expect("rootfs");
        let shutdowns = Arc::new(AtomicUsize::new(0));
        let launches: LaunchLog = Arc::default();
        let launcher = FakeLauncher {
            next_vmid: AtomicU64::new(1),
            shutdowns: shutdowns.clone(),
            snapshot_behavior: faults.snapshot,
            fail_exec: faults.fail_exec,
            pause_behavior: faults.pause,
            vcpu_calls: faults.vcpu_calls,
            launches: launches.clone(),
        };
        let reg = Registry::new(Box::new(launcher), artifacts, 0xdead_beef);
        (reg, shutdowns, launches, dir)
    }

    fn create_req() -> CreateVmRequest {
        CreateVmRequest::create("vmlinux", "rootfs.erofs")
    }

    #[tokio::test]
    async fn create_registers_ready_then_destroy_tears_down_and_clears() {
        let (reg, shutdowns, _d) = registry();
        let created = reg.create(create_req()).await.expect("create");
        assert_eq!(created.info.state, VmState::Ready);
        assert_eq!(reg.len().await, 1);

        reg.destroy(&created.info.id).await.expect("destroy");
        assert_eq!(shutdowns.load(Ordering::SeqCst), 1, "graceful teardown ran");
        assert!(reg.is_empty().await, "entry cleared after destroy");
        assert!(matches!(
            reg.get(&created.info.id).await,
            Err(DaemonError::NotFound(_))
        ));
    }

    #[tokio::test]
    async fn exec_returns_data_plane_output_and_requires_ready() {
        let (reg, _s, _d) = registry();
        let created = reg.create(create_req()).await.expect("create");
        let out = reg
            .exec(
                &created.info.id,
                ExecRequestDto::new(vec!["echo".into(), "hi".into()]),
            )
            .await
            .expect("exec");
        assert_eq!(out.stdout().expect("decode"), b"echo hi");
    }

    #[tokio::test]
    async fn ephemeral_run_execs_then_tears_down() {
        let (reg, shutdowns, _d) = registry();
        let req = CreateVmRequest::run("vmlinux", "rootfs.erofs", vec!["echo".into(), "hi".into()]);
        let created = reg.create(req).await.expect("run");
        assert_eq!(
            created.exec.expect("outcome").stdout().expect("decode"),
            b"echo hi"
        );
        assert!(reg.is_empty().await, "ephemeral VM torn down");
        assert_eq!(shutdowns.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn create_rejects_missing_artifact() {
        let (reg, _s, _d) = registry();
        let mut req = create_req();
        req.kernel = "nope".into();
        assert!(matches!(
            reg.create(req).await,
            Err(DaemonError::BadRequest(_))
        ));
    }

    #[tokio::test]
    async fn is_artifact_in_use_tracks_pins_and_shutdown_all_tears_down() {
        let (reg, shutdowns, _d) = registry();
        reg.create(create_req()).await.expect("a");
        reg.create(create_req()).await.expect("b");
        assert!(reg.is_artifact_in_use("vmlinux").await, "kernel pinned");
        assert!(!reg.is_artifact_in_use("other").await);
        reg.shutdown_all().await;
        assert_eq!(shutdowns.load(Ordering::SeqCst), 2, "every VM torn down");
        assert!(reg.is_empty().await);
        assert!(!reg.is_artifact_in_use("vmlinux").await, "pins released");
    }

    // §11.4 (The VM registry and the start-up sweep): an extra-disk artifact is resolved and PINNED by the live VM, so the
    // delete-in-use guard refuses it; the pin releases on teardown. Buggy impl:
    // `is_artifact_in_use` ignores extra disks and the disk is deletable out from
    // under the running VM.
    #[tokio::test]
    async fn create_with_extra_disk_resolves_and_pins_it() {
        let (reg, _s, _d) = registry();
        reg.artifacts()
            .create("data.img", b"diskbytes")
            .expect("seed disk artifact");
        let created = reg
            .create(create_req().with_extra_disk("data.img"))
            .await
            .expect("create with extra disk");
        assert!(
            reg.is_artifact_in_use("data.img").await,
            "an extra disk a live VM uses must be pinned"
        );
        reg.destroy(&created.info.id).await.expect("destroy");
        assert!(
            !reg.is_artifact_in_use("data.img").await,
            "the extra-disk pin releases on teardown"
        );
    }

    // §11.4 (The VM registry and the start-up sweep): a missing extra-disk artifact is a fail-loud BadRequest at create (the same
    // "upload it first" contract as kernel/rootfs), not a late launch error.
    #[tokio::test]
    async fn create_rejects_missing_extra_disk_artifact() {
        let (reg, _s, _d) = registry();
        assert!(
            matches!(
                reg.create(create_req().with_extra_disk("nope.img")).await,
                Err(DaemonError::BadRequest(_))
            ),
            "a missing extra-disk artifact must fail loud"
        );
    }

    // §11.5, the snapshot-eligibility refusal at the DAEMON's own boundary: `snapshotting: true`
    // beside a net mode that attaches a vhost-user device is a 400 before any launch, naming the net
    // mode the client typed — deferring to `VmConfigBuilder` would instead name a vhost-user device
    // the client never mentioned, and would report a client error as a launch failure. Neither this
    // guard nor `NetMode::snapshot_eligible` had a test anywhere (finding T5).
    //
    // RED on the inverse: delete the guard from `create` (or invert the predicate) — the request
    // reaches the launcher, which the empty-log assertion catches.
    #[tokio::test]
    async fn snapshotting_on_an_ineligible_net_mode_is_refused_at_the_daemon_boundary() {
        let (reg, _s, log, _d) = registry_capturing(SnapshotBehavior::Normal);
        let err = reg
            .create(
                create_req()
                    .with_net(NetMode::Unprivileged)
                    .with_snapshotting(true),
            )
            .await
            .expect_err("the smoltcp NAT is a vhost-user device: not snapshot-eligible");
        assert_eq!(
            err.kind().status_code(),
            400,
            "a client error, refused before the launch: {}",
            err.message()
        );
        assert!(
            err.message().contains("Unprivileged"),
            "the refusal must name the net mode the CLIENT typed: {}",
            err.message()
        );
        assert!(
            log.lock().expect("log").is_empty(),
            "a refused request must never reach the launcher"
        );

        // Positive control 1: the same net mode without `snapshotting` boots — the refusal is about
        // the pair, not about the NAT.
        reg.create(create_req().with_net(NetMode::Unprivileged))
            .await
            .expect("the unprivileged NAT boots fine when no snapshot is asked for");
        // Positive control 2: `snapshotting` with either eligible mode boots — the refusal is about
        // the net mode, not about `snapshotting`.
        for net in [NetMode::None, NetMode::Privileged] {
            reg.create(create_req().with_net(net).with_snapshotting(true))
                .await
                .unwrap_or_else(|e| panic!("{net:?} is snapshot-eligible: {}", e.message()));
        }
        let specs = log.lock().expect("log");
        assert_eq!(
            specs.len(),
            3,
            "every positive control reached the launcher"
        );
        assert!(
            specs.iter().filter(|s| s.snapshotting).count() == 2,
            "the accepted `snapshotting` flag reaches the launcher"
        );
    }

    // A `create` whose inline command fails at the TRANSPORT level (not a non-zero exit, which is an
    // `Ok` outcome) must leave no VM behind: the error reply carries no `CreateVmResponse`, so a kept
    // VM is a booted, resource-holding cell whose id the caller never received and cannot destroy
    // (finding `create-leaks-the-vm-a-failed-inline-exec-abandons`).
    //
    // RED on the inverse (tear down only `if req.ephemeral`): the registry still owns the VM and
    // `shutdowns` stays 0.
    #[tokio::test]
    async fn a_create_whose_inline_exec_fails_leaves_no_vm_behind() {
        let (reg, shutdowns, _log, _d) = registry_faulty(Faults {
            fail_exec: true,
            ..Faults::default()
        });
        let mut req = create_req();
        req.command = Some(vec!["echo".into(), "hi".into()]);
        req.ephemeral = false; // the caller asked to KEEP the VM
        let err = reg
            .create(req)
            .await
            .expect_err("the failing exec must surface");
        assert!(matches!(err, DaemonError::Internal(_)), "got {err:?}");
        assert!(
            reg.is_empty().await,
            "a create that returns an error must own no VM: its id never reached the caller"
        );
        assert_eq!(
            shutdowns.load(Ordering::SeqCst),
            1,
            "the abandoned VM is torn down through the ordered teardown, not leaked"
        );

        // Positive control: the same non-ephemeral create with a WORKING exec keeps its VM, so the
        // teardown above is about the failure and not about `command` itself.
        let (reg, shutdowns, _log, _d) = registry_faulty(Faults::default());
        let mut req = create_req();
        req.command = Some(vec!["echo".into(), "kept".into()]);
        let created = reg.create(req).await.expect("create + inline exec");
        assert_eq!(
            created.exec.expect("outcome").stdout().expect("decode"),
            b"echo kept"
        );
        assert_eq!(reg.len().await, 1, "a successful inline exec keeps its VM");
        assert_eq!(shutdowns.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn snapshot_writes_into_the_artifact_store_and_rejects_bad_prefix() {
        let (reg, _s, _d) = registry();
        let created = reg.create(create_req()).await.expect("create");
        // The fake handle writes nothing, but the dir is created and enumerated.
        let info = reg
            .snapshot(&created.info.id, "snap1")
            .await
            .expect("snapshot");
        assert_eq!(info.artifact_prefix, "snap1");
        assert_eq!(
            info.files,
            vec!["state.json".to_string()],
            "the files the backend wrote are enumerated"
        );
        assert!(matches!(
            reg.snapshot(&created.info.id, "../escape").await,
            Err(DaemonError::InvalidName(_))
        ));
    }

    // §11.3 (The artifact store) create-only, applied to snapshot prefixes: a second snapshot to an
    // EXISTING prefix is refused (409 AlreadyExists) and the first snapshot's bytes are untouched —
    // the old `create_dir_all` wrote a second VM's state into the populated dir file-by-file, which
    // a racing `restore_from` copy could read as a torn mix of two lineages (finding
    // `snapshot-prefix-silent-reuse`). Then the positive control: DELETE frees the prefix and the
    // same name is snapshot-able again, this time carrying the SECOND VM's state. RED on the
    // inverse (`create_dir_all`): the refusal never happens and `state.json` reads `vmid=2`.
    #[tokio::test]
    async fn snapshot_refuses_an_existing_prefix_and_preserves_the_first() {
        let (reg, _s, _d) = registry();
        let first = reg.create(create_req()).await.expect("first vm");
        let second = reg.create(create_req()).await.expect("second vm");
        let state = reg.artifacts().dir().join("snap1").join("state.json");

        reg.snapshot(&first.info.id, "snap1")
            .await
            .expect("first snapshot");
        let original = std::fs::read_to_string(&state).expect("first snapshot state");
        assert_eq!(original, format!("vmid={}", first.info.vmid));

        let err = reg
            .snapshot(&second.info.id, "snap1")
            .await
            .expect_err("a populated prefix must be refused");
        assert!(matches!(err, DaemonError::AlreadyExists(_)), "got {err:?}");
        assert_eq!(err.kind().status_code(), 409, "a taken prefix is a 409");
        assert_eq!(
            std::fs::read_to_string(&state).expect("state survives"),
            original,
            "the refused snapshot must not have written into the populated prefix"
        );

        // A prefix colliding with an uploaded FILE artifact is refused the same way (the prefix and
        // artifact namespaces are one).
        assert!(matches!(
            reg.snapshot(&second.info.id, "vmlinux").await,
            Err(DaemonError::AlreadyExists(_))
        ));

        // Positive control: the prefix is freeable, and re-snapshotting then succeeds.
        reg.delete_artifact_if_unused("snap1")
            .await
            .expect("delete frees the snapshot prefix");
        assert!(
            !reg.artifacts().dir().join("snap1").exists(),
            "the prefix dir is gone after delete"
        );
        reg.snapshot(&second.info.id, "snap1")
            .await
            .expect("the freed prefix is snapshot-able again");
        assert_eq!(
            std::fs::read_to_string(&state).expect("second snapshot state"),
            format!("vmid={}", second.info.vmid),
            "the re-snapshot carries the second VM's state"
        );
    }

    // A snapshot against a MISSING VM returns NotFound and leaves NO residue dir — a live (real-fs)
    // gate the fs-blind FakeHandle cannot cover on its own. RED on the pre-fix ordering
    // (`create_dir_all` before the slot lookup), which creates `snap-missing/` before returning
    // NotFound; a leftover empty dir would shadow a later artifact/snapshot of the same name.
    #[tokio::test]
    async fn snapshot_on_missing_vm_leaves_no_residue_dir() {
        let (reg, _s, _d) = registry();
        let residue = reg.artifacts().dir().join("snap-missing");
        let err = reg
            .snapshot(&VmId("vm-nope".to_string()), "snap-missing")
            .await
            .expect_err("snapshot on a missing VM must fail");
        assert!(matches!(err, DaemonError::NotFound(_)));
        assert!(
            !residue.exists(),
            "a rejected snapshot must leave no residue dir (it would shadow a later artifact)"
        );
    }

    // §11.3 (The artifact store), the delete-in-use guard, atomic form: an artifact a live VM pins
    // is refused (InUse) and the file survives; after teardown the same delete succeeds and the file
    // is gone (positive control). RED on the inverse (a delete that ignores the pin, or one that
    // deletes the file before checking) — the file would vanish out from under the running VM.
    #[tokio::test]
    async fn delete_artifact_if_unused_refuses_pinned_then_allows_after_teardown() {
        let (reg, _s, _d) = registry();
        reg.artifacts()
            .create("del-me", b"bytes")
            .expect("seed disk");
        let created = reg
            .create(create_req().with_extra_disk("del-me"))
            .await
            .expect("create pinning del-me");
        assert!(
            matches!(
                reg.delete_artifact_if_unused("del-me").await,
                Err(DaemonError::InUse(_))
            ),
            "delete must refuse an artifact a live VM pins"
        );
        assert!(
            reg.artifacts().exists("del-me"),
            "refused delete leaves the file"
        );
        reg.destroy(&created.info.id).await.expect("destroy");
        reg.delete_artifact_if_unused("del-me")
            .await
            .expect("delete after teardown");
        assert!(
            !reg.artifacts().exists("del-me"),
            "unpinned delete removes the file"
        );
    }

    // The reserved `.sha256` suffix is refused on the snapshot verb too, because it lives in
    // `validate_artifact_name` — the validator EVERY name-taking path uses (finding
    // `snapshot-skips-the-reserved-sidecar-predicate`). Before the fold, `snapshot(&id,
    // "rootfs.sha256")` returned Ok and created a directory that `info`/`list`/`delete` all hid,
    // permanently breaking uploads of `rootfs`. RED on the inverse (a `validate_artifact_name`
    // without the suffix arm): the prefix is accepted and the directory appears.
    #[tokio::test]
    async fn snapshot_rejects_a_reserved_sidecar_prefix() {
        let (reg, _s, _d) = registry();
        let created = reg.create(create_req()).await.expect("create");
        let err = reg
            .snapshot(&created.info.id, "k.sha256")
            .await
            .expect_err("a reserved sidecar prefix must be refused");
        assert!(matches!(err, DaemonError::InvalidName(_)), "got {err:?}");
        assert_eq!(err.kind().status_code(), 400);
        assert!(
            !reg.artifacts().dir().join("k.sha256").exists(),
            "the refused prefix must leave no directory (it would be undeletable via the API)"
        );
        // Positive control: the same stem without the reserved suffix still snapshots.
        let info = reg
            .snapshot(&created.info.id, "k")
            .await
            .expect("a non-reserved prefix snapshots");
        assert_eq!(info.files, vec!["state.json".to_string()]);
    }

    // §11.3/§11.4, the delete-in-use guard extended to an IN-FLIGHT snapshot prefix (finding
    // `snapshot-prefix-unpinned-during-the-write`): with the backend write blocked mid-snapshot, a
    // delete of the prefix is refused (409 InUse) and the directory survives; when the write
    // finishes the pin releases and the same delete succeeds (positive control). RED on the inverse
    // (a `pins` that ignores `snapshot_prefix`): the delete returns Ok and `remove_dir_all`s the
    // prefix out from under the running snapshot.
    #[tokio::test]
    async fn delete_refuses_a_prefix_a_snapshot_is_writing_then_allows_it_after() {
        let gate = Arc::new(HandleGate::default());
        let (reg, _s, _d) = registry_with(SnapshotBehavior::Blocked(gate.clone()));
        let reg = Arc::new(reg);
        let created = reg.create(create_req()).await.expect("create");
        let prefix_dir = reg.artifacts().dir().join("snap-live");

        let snap_reg = reg.clone();
        let id = created.info.id.clone();
        let snap = tokio::spawn(async move { snap_reg.snapshot(&id, "snap-live").await });
        gate.entered.notified().await; // the backend write is now in flight

        let err = reg
            .delete_artifact_if_unused("snap-live")
            .await
            .expect_err("a prefix being written must be pinned");
        assert!(matches!(err, DaemonError::InUse(_)), "got {err:?}");
        assert_eq!(err.kind().status_code(), 409);
        assert!(
            prefix_dir.is_dir(),
            "the refused delete must leave the in-flight snapshot dir"
        );

        gate.release.notify_one();
        let info = snap.await.expect("join").expect("snapshot");
        assert_eq!(info.files, vec!["state.json".to_string()]);

        // Positive control: the pin releases with the write, so the same delete now succeeds.
        reg.delete_artifact_if_unused("snap-live")
            .await
            .expect("the prefix is deletable once the write is done");
        assert!(!prefix_dir.exists(), "prefix gone after the delete");
    }

    // The same pin, now against a DESTROY parked on the handle lock (finding
    // `destroy-unpins-an-in-flight-snapshot-prefix`): a teardown waits for the in-flight snapshot to
    // release `inner`, and for that whole wait the VM — and therefore its prefix pin — must stay
    // visible to the delete-in-use scan, which reads pins only through `self.vms`. A racing op is
    // refused by the `Destroying` STATE rather than by the VM's absence, promptly.
    //
    // RED on the pre-fix order (remove from `self.vms` before awaiting `inner`): the scan finds a
    // pin-free table, the delete returns Ok and `remove_dir_all`s the directory the backend is still
    // writing into — the `InUse` assertion fails, and so does the snapshot's read-back.
    #[tokio::test]
    async fn a_destroy_parked_on_the_handle_lock_keeps_the_snapshot_prefix_pinned() {
        let gate = Arc::new(HandleGate::default());
        let (reg, shutdowns, _d) = registry_with(SnapshotBehavior::Blocked(gate.clone()));
        let reg = Arc::new(reg);
        let created = reg.create(create_req()).await.expect("create");
        let prefix_dir = reg.artifacts().dir().join("snap-doomed");
        let budget = std::time::Duration::from_millis(500);

        let snap_reg = reg.clone();
        let snap_id = created.info.id.clone();
        let snap = tokio::spawn(async move { snap_reg.snapshot(&snap_id, "snap-doomed").await });
        gate.entered.notified().await; // the guest-RAM write holds `inner`

        let kill_reg = reg.clone();
        let kill_id = created.info.id.clone();
        let kill = tokio::spawn(async move { kill_reg.destroy(&kill_id).await });
        // Rendezvous on the teardown having CLAIMED the slot: `Destroying` with the fix, gone
        // outright with the pre-fix removal. Either way it cannot proceed past the held handle lock,
        // so the assertions below run inside the window this finding is about.
        tokio::time::timeout(budget, async {
            loop {
                match reg.get(&created.info.id).await {
                    Ok(info) if info.state != VmState::Destroying => tokio::task::yield_now().await,
                    _ => return,
                }
            }
        })
        .await
        .expect("the destroy must claim the slot promptly rather than queue invisibly");

        let err = reg
            .delete_artifact_if_unused("snap-doomed")
            .await
            .expect_err("a prefix being written stays pinned while its VM is torn down");
        assert!(matches!(err, DaemonError::InUse(_)), "got {err:?}");
        assert_eq!(err.kind().status_code(), 409);
        assert!(
            prefix_dir.is_dir(),
            "the refused delete must leave the in-flight snapshot dir"
        );

        // A racing op is refused by the state, and promptly — it must not queue behind the teardown.
        let exec_err = tokio::time::timeout(
            budget,
            reg.exec(&created.info.id, ExecRequestDto::new(vec!["echo".into()])),
        )
        .await
        .expect("an op against a doomed VM must not queue behind its teardown")
        .expect_err("a VM being torn down accepts no further ops");
        assert!(
            matches!(exec_err, DaemonError::Conflict(_)),
            "a doomed VM is a 409 while the teardown runs, got {exec_err:?}"
        );

        gate.release.notify_one();
        let info = snap
            .await
            .expect("join snapshot")
            .expect("the snapshot the delete could not touch completes");
        assert_eq!(
            info.files,
            vec!["state.json".to_string()],
            "its bytes were never removed under it"
        );
        kill.await.expect("join destroy").expect("destroy");
        assert_eq!(shutdowns.load(Ordering::SeqCst), 1, "the teardown ran once");
        assert!(
            reg.is_empty().await,
            "the slot leaves the table WITH the teardown"
        );

        // Positive control: with the VM gone the pin is gone, so the same delete now succeeds.
        reg.delete_artifact_if_unused("snap-doomed")
            .await
            .expect("an unpinned prefix is deletable");
        assert!(!prefix_dir.exists(), "prefix gone after the delete");
    }

    // The second half of the same finding: the snapshot dir read-back is FAIL-LOUD. The fake
    // removes the directory before returning (exactly what a racing delete did to an unpinned
    // prefix), and the caller must see an Internal error naming the prefix — not the 200 with
    // `files: []` that `.unwrap_or_default()` produced for a snapshot that no longer exists. RED on
    // the inverse (restore `.unwrap_or_default()`): the call returns Ok.
    #[tokio::test]
    async fn snapshot_read_back_failure_surfaces_instead_of_an_empty_file_list() {
        let (reg, _s, _d) = registry_with(SnapshotBehavior::RemovesDir);
        let created = reg.create(create_req()).await.expect("create");
        let err = reg
            .snapshot(&created.info.id, "snap-gone")
            .await
            .expect_err("a vanished snapshot dir must fail loud");
        assert!(matches!(err, DaemonError::Internal(_)), "got {err:?}");
        assert_eq!(err.kind().status_code(), 500);
        assert!(
            err.message().contains("snap-gone"),
            "the error must name the prefix: {}",
            err.message()
        );
    }

    // §11.4 + the `require_state` contract (finding
    // `snapshotting-state-unobservable-and-list-blocks`): while one VM writes a snapshot, its state
    // is OBSERVABLE as `Snapshotting`, `get`/`list` return promptly (no head-of-line blocking
    // across VMs), and an `exec` against it is a prompt 409. RED on the inverse (state back inside
    // `VmInner`, `require_state` after the `inner` lock): every one of these waits for the whole
    // snapshot — the timeouts fire — and the state read back is a stale `Ready`.
    #[tokio::test]
    async fn snapshotting_state_is_observable_and_blocks_neither_reads_nor_other_vms() {
        let gate = Arc::new(HandleGate::default());
        let (reg, _s, _d) = registry_with(SnapshotBehavior::Blocked(gate.clone()));
        let reg = Arc::new(reg);
        let busy = reg.create(create_req()).await.expect("vm a");
        let idle = reg.create(create_req()).await.expect("vm b");

        let snap_reg = reg.clone();
        let id = busy.info.id.clone();
        let snap = tokio::spawn(async move { snap_reg.snapshot(&id, "snap-state").await });
        gate.entered.notified().await;

        let budget = std::time::Duration::from_millis(500);
        let info = tokio::time::timeout(budget, reg.get(&busy.info.id))
            .await
            .expect("get must not queue behind the snapshot")
            .expect("get");
        assert_eq!(
            info.state,
            VmState::Snapshotting,
            "the documented Snapshotting state must be observable"
        );

        let list = tokio::time::timeout(budget, reg.list())
            .await
            .expect("list must not queue behind one VM's snapshot");
        assert_eq!(list.len(), 2);
        assert!(
            list.iter()
                .any(|v| v.id == busy.info.id && v.state == VmState::Snapshotting),
            "the snapshotting VM reports its state in the listing"
        );
        assert!(
            list.iter()
                .any(|v| v.id == idle.info.id && v.state == VmState::Ready),
            "the OTHER VM is listed as Ready — no head-of-line blocking"
        );

        let err = tokio::time::timeout(
            budget,
            reg.exec(&busy.info.id, ExecRequestDto::new(vec!["echo".into()])),
        )
        .await
        .expect("exec must not queue behind the snapshot")
        .expect_err("exec against a snapshotting VM must conflict");
        assert_eq!(err.kind().status_code(), 409, "{}", err.message());

        // Positive control: the idle VM still execs while its neighbour snapshots.
        let out = tokio::time::timeout(
            budget,
            reg.exec(
                &idle.info.id,
                ExecRequestDto::new(vec!["echo".into(), "ok".into()]),
            ),
        )
        .await
        .expect("the idle VM's exec must not queue behind another VM's snapshot")
        .expect("exec");
        assert_eq!(out.stdout().expect("decode"), b"echo ok");

        gate.release.notify_one();
        snap.await.expect("join").expect("snapshot");
        assert_eq!(
            reg.get(&busy.info.id).await.expect("get").state,
            VmState::Ready,
            "the state returns to Ready after the write"
        );
    }

    #[tokio::test]
    async fn minted_ids_are_unique_and_prefixed() {
        let (reg, _s, _d) = registry();
        let a = reg.create(create_req()).await.expect("a");
        let b = reg.create(create_req()).await.expect("b");
        assert_ne!(a.info.id, b.info.id);
        assert!(a.info.id.0.starts_with("vm-"));
    }

    // ---- v33 delta 10: daemon placement exposure (design §11.5, §18 delta 10) ----

    // The second unobserved hop, now observed: what the REST client sent reaches `LaunchSpec`
    // field-for-field. Driven ASYMMETRICALLY (init `Some` with placement `Some`, then placement
    // `Some` with init `None`) so a field dropped in the middle of the chain shows up — the shape a
    // both-`Some` fixture cannot see.
    //
    // RED on the inverse: drop `init: req.init...` from the `LaunchSpec` literal in `create` (the
    // first leg's init assertion fails), or hardcode `steward_placement: StewardPlacementDto::Pid1`
    // there (the port assertion fails).
    #[tokio::test]
    async fn create_forwards_init_and_placement_to_the_launch_spec() {
        let (reg, _s, log, _d) = registry_capturing(SnapshotBehavior::Normal);

        reg.create(create_req().with_service_init(
            "/vmcell-tools/mini-init",
            StewardPlacementDto::Service { port: 5100 },
        ))
        .await
        .expect("Service + custom init is exactly what delta 10 exposes");
        // Sibling `None`: a placement with no init (the library's deliberately legal combination).
        reg.create(
            create_req().with_steward_placement(StewardPlacementDto::Service { port: 5000 }),
        )
        .await
        .expect("Service with no init composes");
        // Neither named: the pre-v33 shape, resolved to an EXPLICIT Pid1 so the builder's
        // derivation is never reached.
        reg.create(create_req()).await.expect("default create");

        let specs = log.lock().expect("log");
        assert_eq!(specs.len(), 3, "three creates, three specs");
        assert_eq!(
            specs[0].init.as_deref(),
            Some(std::path::Path::new("/vmcell-tools/mini-init")),
            "the custom init must reach the launcher"
        );
        assert_eq!(
            specs[0].steward_placement,
            StewardPlacementDto::Service { port: 5100 },
            "the declared port must reach the launcher unchanged"
        );
        assert_eq!(specs[1].init, None, "the sibling stays absent");
        assert_eq!(
            specs[1].steward_placement,
            StewardPlacementDto::Service { port: 5000 }
        );
        assert_eq!(specs[2].init, None);
        assert_eq!(
            specs[2].steward_placement,
            StewardPlacementDto::Pid1,
            "an unnamed placement resolves to an EXPLICIT Pid1 — the whole point of the \
             non-optional LaunchSpec field"
        );
    }

    // §18 delta 10's refusal, both spellings, each a 400 that names the rule — with the `Service`
    // positive control proving the refusal is about the placement and not about custom inits.
    //
    // RED on the inverse: delete the `resolve_steward_placement` call from `Registry::create`. Both
    // negative legs then succeed (the fake launcher never builds a config), which is precisely the
    // silent-`None` outcome the check exists to prevent.
    #[tokio::test]
    async fn a_stewardless_placement_is_refused_400_however_it_is_spelled() {
        let (reg, _s, log, _d) = registry_capturing(SnapshotBehavior::Normal);

        for (leg, req) in [
            (
                "named outright",
                create_req().with_steward_placement(StewardPlacementDto::None),
            ),
            (
                "a custom init with no placement",
                CreateVmRequest {
                    init: Some("/sbin/init".to_string()),
                    ..create_req()
                },
            ),
        ] {
            let err = reg
                .create(req)
                .await
                .expect_err("a stewardless cell is not expressible over REST");
            assert_eq!(
                err.kind().status_code(),
                400,
                "{leg}: a client error, never a 500 — {}",
                err.message()
            );
            assert!(
                err.message().contains("control plane"),
                "{leg}: the refusal must name the rule's surviving half, got: {}",
                err.message()
            );
        }
        assert!(
            log.lock().expect("log").is_empty(),
            "a refused placement must never reach the launcher"
        );

        // Positive control: the SAME custom init, with a placement that keeps the control plane,
        // creates. Without this the negative legs would also pass if `create` rejected every init.
        reg.create(
            create_req()
                .with_service_init("/sbin/init", StewardPlacementDto::Service { port: 5100 }),
        )
        .await
        .expect("a custom init WITH a Service placement is exactly what delta 10 exposes");
        assert_eq!(
            log.lock().expect("log").len(),
            1,
            "the positive control did reach the launcher"
        );
    }

    // ---- the vCPU verbs: `POST /v1/vms/{id}/pause` and `/resume` (design §11.5, The HTTP REST API
    // and its OpenAPI document; §17, Open gaps and future capabilities — "Pause/resume routes") ----

    /// A registry whose fake handle runs `pause` under `pause_behavior` and counts every vCPU-verb
    /// call that reached the backend. The counter is what keeps the state assertions honest: a
    /// registry that relabelled the slot and never called the handle would satisfy every one of them.
    fn registry_vcpu(pause: PauseBehavior) -> (Registry, Arc<AtomicUsize>, tempfile::TempDir) {
        let faults = Faults {
            pause,
            ..Faults::default()
        };
        let calls = faults.vcpu_calls.clone();
        let (reg, _shutdowns, _log, dir) = registry_faulty(faults);
        (reg, calls, dir)
    }

    // The happy path, both directions, asserted through the OBSERVABLE state (`get`, i.e. what
    // `GET /v1/vms/{id}` serves) and through the fake's call counter, not just the returned value.
    // RED on the inverse (a `pause` that returns `slot.info()` without moving the state, or one that
    // never reaches the handle): the `get` assertion or the counter goes red.
    #[tokio::test]
    async fn pause_moves_ready_to_paused_and_resume_moves_back() {
        let (reg, calls, _d) = registry_vcpu(PauseBehavior::Normal);
        let created = reg.create(create_req()).await.expect("create");
        let id = &created.info.id;
        assert_eq!(reg.get(id).await.expect("get").state, VmState::Ready);

        let paused = reg.pause(id).await.expect("pause a Ready vm");
        assert_eq!(
            paused.state,
            VmState::Paused,
            "the reply carries the new state"
        );
        assert_eq!(
            reg.get(id).await.expect("get").state,
            VmState::Paused,
            "and `GET /v1/vms/{{id}}` observes it"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1, "the backend pause ran");

        let resumed = reg.resume(id).await.expect("resume a Paused vm");
        assert_eq!(resumed.state, VmState::Ready);
        assert_eq!(reg.get(id).await.expect("get").state, VmState::Ready);
        assert_eq!(calls.load(Ordering::SeqCst), 2, "the backend resume ran");
    }

    // The refusals a paused VM owes, each with its POSITIVE CONTROL after the resume (AGENTS.md: a
    // negative result needs a positive control, or "refuses everything" would pass).
    //
    // `snapshot` is on the list deliberately: `MicroVm::snapshot` pauses internally and RESUMES when
    // it is done, so snapshotting a paused VM would silently restart the guest behind the daemon's
    // own state. Refusing keeps the one-state-machine story true.
    //
    // RED on the inverse (drop the `require_state` in `drive_vcpus`, or give `snapshot`/`exec` a
    // `want` of anything but `Ready`): the paused VM answers instead of conflicting.
    #[tokio::test]
    async fn a_paused_vm_refuses_exec_pause_and_snapshot_and_resumes_back_into_all_three() {
        let (reg, _calls, _d) = registry_vcpu(PauseBehavior::Normal);
        let created = reg.create(create_req()).await.expect("create");
        let id = &created.info.id;
        reg.pause(id).await.expect("pause");

        for (verb, err) in [
            (
                "exec",
                reg.exec(id, ExecRequestDto::new(vec!["echo".into(), "hi".into()]))
                    .await
                    .expect_err("exec on a paused vm"),
            ),
            ("pause", reg.pause(id).await.expect_err("second pause")),
            (
                "snapshot",
                reg.snapshot(id, "snap-paused")
                    .await
                    .expect_err("snapshot of a paused vm"),
            ),
        ] {
            assert!(
                matches!(err, DaemonError::Conflict(_)),
                "{verb} on a paused VM must be a Conflict, got {err:?}"
            );
            assert_eq!(err.kind().status_code(), 409, "{verb} is a 409");
            assert!(
                err.message().contains("Paused"),
                "{verb}'s message names the state that refused it: {}",
                err.message()
            );
        }
        assert!(
            !reg.artifacts().dir().join("snap-paused").exists(),
            "the refused snapshot must leave no prefix dir behind"
        );

        // Positive controls: all three work again after the resume.
        reg.resume(id).await.expect("resume");
        assert_eq!(
            reg.exec(id, ExecRequestDto::new(vec!["echo".into(), "hi".into()]))
                .await
                .expect("exec after resume")
                .stdout()
                .expect("decode"),
            b"echo hi"
        );
        reg.snapshot(id, "snap-paused")
            .await
            .expect("snapshot after resume");
        reg.pause(id).await.expect("pause after resume");
    }

    // The mirror refusal: resume is admitted only from `Paused`. RED on the inverse (a `resume` that
    // takes `VmState::Ready` as its `from`): a running VM is "resumed" and the backend is driven for
    // nothing.
    #[tokio::test]
    async fn resume_of_a_running_vm_is_conflict() {
        let (reg, calls, _d) = registry_vcpu(PauseBehavior::Normal);
        let created = reg.create(create_req()).await.expect("create");
        let err = reg
            .resume(&created.info.id)
            .await
            .expect_err("resume of a Ready vm");
        assert!(matches!(err, DaemonError::Conflict(_)), "got {err:?}");
        assert_eq!(err.kind().status_code(), 409);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "a refused verb must not reach the backend at all"
        );
        // Positive control: the verb is not simply broken.
        reg.pause(&created.info.id).await.expect("pause");
        reg.resume(&created.info.id).await.expect("resume");
    }

    // "Derived from the handle, not a hopeful label" (design §11.4, The VM registry and the start-up
    // sweep): a pause the BACKEND refused leaves the VM `Ready`, and the positive control proves that
    // `Ready` is real rather than a stale label — the VM still execs.
    //
    // RED on the inverse (publishing `verb.to()` before driving the handle, or ignoring its error):
    // the VM reads `Paused` while its guest is still running, and every later `exec` 409s against a
    // cell that would have answered.
    #[tokio::test]
    async fn a_backend_pause_failure_leaves_the_vm_ready_and_usable() {
        let (reg, calls, _d) = registry_vcpu(PauseBehavior::Fails);
        let created = reg.create(create_req()).await.expect("create");
        let id = &created.info.id;

        let err = reg.pause(id).await.expect_err("the backend refuses");
        assert!(matches!(err, DaemonError::Internal(_)), "got {err:?}");
        assert_eq!(calls.load(Ordering::SeqCst), 1, "the backend was driven");
        assert_eq!(
            reg.get(id).await.expect("get").state,
            VmState::Ready,
            "a failed pause must not publish a state the guest is not in"
        );
        assert_eq!(
            reg.exec(id, ExecRequestDto::new(vec!["echo".into(), "ok".into()]))
                .await
                .expect("the still-Ready vm execs")
                .stdout()
                .expect("decode"),
            b"echo ok"
        );
    }

    // The one-way `Destroying` door, on the vCPU path (the law `transition_from` states once, first
    // learned on the snapshot path): a destroy marks `Destroying` in place and parks on the handle
    // lock the in-flight pause holds. When that pause completes it must NOT publish `Paused` over
    // `Destroying` — that would re-advertise a VM whose teardown is already parked behind it and let
    // a new op in behind that.
    //
    // RED on the inverse (`slot.set_state(verb.to())` unconditionally in `drive_vcpus`): the pause
    // returns `Paused` for a VM being torn down, and the doomed VM is admitted for further ops.
    #[tokio::test]
    async fn a_pause_landing_behind_a_parked_teardown_does_not_reopen_the_vm() {
        let gate = Arc::new(HandleGate::default());
        let (reg, _calls, _d) = registry_vcpu(PauseBehavior::Blocked(gate.clone()));
        let reg = Arc::new(reg);
        let created = reg.create(create_req()).await.expect("create");
        let id = created.info.id.clone();
        let budget = std::time::Duration::from_millis(500);

        let pause_reg = reg.clone();
        let pause_id = id.clone();
        let pause = tokio::spawn(async move { pause_reg.pause(&pause_id).await });
        gate.entered.notified().await; // the backend pause is now in flight, holding `inner`

        let destroy_reg = reg.clone();
        let destroy_id = id.clone();
        let destroy = tokio::spawn(async move { destroy_reg.destroy(&destroy_id).await });

        // Wait until the teardown has marked the slot in place and parked on the handle lock.
        let deadline = tokio::time::Instant::now() + budget;
        loop {
            assert!(
                tokio::time::Instant::now() < deadline,
                "the teardown never reached `Destroying` within {budget:?}"
            );
            if reg
                .get(&id)
                .await
                .is_ok_and(|i| i.state == VmState::Destroying)
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }

        gate.release.notify_one();
        let info = pause
            .await
            .expect("join")
            .expect("the pause itself succeeded");
        assert_eq!(
            info.state,
            VmState::Destroying,
            "a pause completing behind a parked teardown reports the doomed state, never `Paused`"
        );
        tokio::time::timeout(budget, destroy)
            .await
            .expect("the teardown completes once the pause releases the handle")
            .expect("join")
            .expect("destroy");
        assert!(reg.is_empty().await, "the VM is gone");
    }

    // The call-site scan for the one-way `Destroying` door (AGENTS.md: a gate binds the CALL SITES,
    // not just the extracted predicate). `transition_from` is the law; `set_state` is the
    // unconditional assignment it is built on, and only two callers may use it — the snapshot's
    // `Snapshotting` claim (which holds the handle lock and is what a teardown then parks behind) and
    // `teardown_slot`'s `Destroying` mark (the door itself). Every other op publishes its result
    // through `transition_from`.
    //
    // RED on the inverse: add a third `set_state` call — e.g. `drive_vcpus` publishing `Paused`
    // unconditionally, the exact shape `a_pause_landing_behind_a_parked_teardown_does_not_reopen_the_vm`
    // catches at runtime. Two gates for one law is deliberate: the runtime one proves the behavior,
    // this one proves no NEW op quietly reintroduces the shape somewhere the runtime gate is not
    // looking.
    #[test]
    fn only_the_snapshot_claim_and_the_teardown_mark_assign_a_state_unconditionally() {
        let src = include_str!("registry.rs");
        let prod = src
            .split("\n#[cfg(test)]\n")
            .next()
            .expect("the production half of this file");
        let sites: Vec<&str> = prod
            .lines()
            .map(|l| l.split("//").next().unwrap_or(""))
            .filter(|code| code.contains("set_state(") && !code.contains("fn set_state"))
            .map(str::trim)
            .collect();
        assert_eq!(
            sites.len(),
            2,
            "exactly two unconditional state assignments may exist — the `Snapshotting` claim and \
             the `Destroying` mark. Everything else publishes through `transition_from`, which is \
             what keeps `Destroying` a ONE-WAY door. Found: {sites:#?}"
        );
        assert!(
            sites.iter().any(|s| s.contains("VmState::Snapshotting")),
            "the snapshot claim must be one of them: {sites:#?}"
        );
        assert!(
            sites.iter().any(|s| s.contains("VmState::Destroying")),
            "the teardown mark must be the other: {sites:#?}"
        );
    }

    // A paused VM is still an OWNED VM: it holds its VMM process, netns/tap, cgroup and scratch dir,
    // so it still PINS its artifacts and must still be destroyable — otherwise pausing a cell would
    // be a way to leak one. `stats` reads the cgroup and needs no particular state, so it keeps
    // working too. RED on the inverse (a `pins` that skips paused slots, or a `destroy` that
    // requires `Ready`): the delete succeeds under a live VM, or the paused VM cannot be reclaimed.
    #[tokio::test]
    async fn a_paused_vm_still_pins_its_artifacts_stats_and_can_be_destroyed() {
        let (reg, _calls, _d) = registry_vcpu(PauseBehavior::Normal);
        reg.artifacts()
            .create("paused-disk", b"bytes")
            .expect("seed disk");
        let created = reg
            .create(create_req().with_extra_disk("paused-disk"))
            .await
            .expect("create");
        let id = &created.info.id;
        reg.pause(id).await.expect("pause");

        assert!(
            matches!(
                reg.delete_artifact_if_unused("paused-disk").await,
                Err(DaemonError::InUse(_))
            ),
            "a paused VM still pins its disks"
        );
        assert!(reg.artifacts().exists("paused-disk"), "the file survives");
        reg.stats(id).await.expect("stats work on a paused vm");

        reg.destroy(id).await.expect("a paused vm is destroyable");
        assert!(reg.is_empty().await, "the paused VM is gone after destroy");
        // Positive control: the pin released with the VM.
        reg.delete_artifact_if_unused("paused-disk")
            .await
            .expect("delete after teardown");
        assert!(!reg.artifacts().exists("paused-disk"));
    }
}

/// **Delta 10's daemon-side call-site scan** (design §18 delta 10; the register's "a gate binds the
/// call sites, not just the extracted predicate" convention).
///
/// `vmcell`'s own `c8_call_site_gate` builds its corpus from `include_str!("orchestrator.rs")` +
/// `include_str!("config.rs")`, so it structurally cannot see this crate — and `vmcell-daemon` is not
/// one of the two `cargo semver-checks` contract crates either. Neither existing gate would catch a
/// daemon that re-derived control-plane availability from `req.init`, which is the conflation v33
/// removed at seven library sites and would re-enter here on the platform's third entry surface.
#[cfg(test)]
mod delta10_call_site_gate {
    /// The daemon's request-handling sources, comment-stripped, as `(file, line, code)`.
    fn production_lines() -> Vec<(&'static str, usize, String)> {
        let mut out = Vec::new();
        for (name, body) in [
            ("registry.rs", include_str!("registry.rs")),
            ("launcher.rs", include_str!("launcher.rs")),
            ("dto.rs", include_str!("dto.rs")),
            ("server.rs", include_str!("server.rs")),
        ] {
            // Production only: the `#[cfg(test)]` modules below legitimately name `init` and every
            // placement variant while driving them.
            let prod = body.split("\n#[cfg(test)]\n").next().unwrap_or(body);
            for (i, l) in prod.lines().enumerate() {
                let code = l.split("//").next().unwrap_or("");
                if !code.trim().is_empty() {
                    out.push((name, i + 1, code.to_string()));
                }
            }
        }
        assert!(
            out.len() > 900,
            "the scan found only {} production lines — it is not reading the sources, so every \
             assertion below would pass vacuously",
            out.len()
        );
        out
    }

    /// **C8, daemon side: `req.init` decides init IDENTITY only.**
    ///
    /// Exactly two production sites may read it — the `LaunchSpec` move (identity, forwarded to
    /// `VmConfigBuilder::init`) and `resolve_steward_placement`'s completeness refusal, which
    /// answers "this request is incomplete", never "therefore the placement is X". A third reader
    /// deriving reachability from an init spelling is this law's violation, and it is the exact
    /// shape v33 removed from the library.
    #[test]
    fn req_init_is_never_read_to_decide_a_placement() {
        let readers: Vec<String> = production_lines()
            .into_iter()
            .filter(|(_, _, code)| {
                code.contains("req.init")
                    || code.contains("spec.init")
                    || code.contains(".init.is_")
            })
            .map(|(f, l, code)| format!("{f}:{l}: {}", code.trim()))
            .collect();
        assert!(
            readers.len() >= 2,
            "the scan matched {} init readers — the daemon must forward an init and refuse an \
             undeclared placement, so a scan finding fewer is not reading the code: {readers:#?}",
            readers.len()
        );
        for r in &readers {
            assert!(
                r.contains("init: req.init.as_deref().map(PathBuf::from)")  // the LaunchSpec move
                    || r.contains("if req.init.is_some()")                  // the completeness refusal
                    || r.contains("if let Some(init) = &spec.init")          // the builder call site
                    || r.contains("builder.init(init.clone())"),
                "delta 10 / C8: `{r}` reads `init` for something other than init IDENTITY. \
                 Control-plane availability is `StewardPlacementDto::control_plane_retained()` \
                 over the DECLARED `steward_placement`; deriving it from an `init` spelling is the \
                 conflation v33 removed at seven library sites."
            );
        }
    }

    /// **The daemon always hands the builder an explicit placement.**
    ///
    /// `VmConfigBuilder::build()` derives `StewardPlacement::None` when `init` is `Some` and no
    /// placement is named — the one placement REST must not express. The daemon keeps that
    /// derivation unreachable by calling `.steward_placement(...)` unconditionally, which is only
    /// true while `LaunchSpec::steward_placement` is not an `Option` and the call is not inside a
    /// conditional. Both halves are asserted, because a later "tidy-up" to
    /// `if let Some(p) = spec.steward_placement` compiles and silently re-opens the derivation.
    #[test]
    fn the_builder_is_always_handed_an_explicit_placement() {
        let lines = production_lines();
        let calls: Vec<&(&str, usize, String)> = lines
            .iter()
            .filter(|(_, _, c)| c.contains(".steward_placement(steward_placement("))
            .collect();
        assert_eq!(
            calls.len(),
            1,
            "exactly one production site may name the placement on the builder chain; found \
             {calls:#?}"
        );
        // The field it reads cannot be optional — the load-bearing half. `Option` there makes
        // `if let Some(p) = spec.steward_placement` compile, and that conditional is exactly how
        // `build()`'s derivation gets back in.
        assert!(
            lines.iter().any(|(f, _, c)| *f == "launcher.rs"
                && c.contains("pub steward_placement: StewardPlacementDto")),
            "`LaunchSpec::steward_placement` must stay non-optional: an `Option` there re-opens \
             `build()`'s `init: Some` ⇒ `StewardPlacement::None` derivation at the type level"
        );
        // …and no production site guards the placement behind a conditional, whichever way it is
        // spelled.
        for (f, l, c) in &lines {
            assert!(
                !(c.contains("steward_placement") && (c.contains("if ") || c.contains("match "))),
                "the placement must reach the builder UNCONDITIONALLY — {f}:{l}: `{}` guards it",
                c.trim()
            );
        }
    }

    /// **The REST placement law is stated once.**
    ///
    /// `control_plane_retained()` is read at exactly one production site (the registry's refusal).
    /// A second reader is a second copy of the rule — the shape every duplicated law in this tree
    /// has already diverged into.
    #[test]
    fn the_rest_placement_law_has_one_call_site() {
        let sites: Vec<String> = production_lines()
            .into_iter()
            .filter(|(f, _, c)| c.contains("control_plane_retained()") && *f != "dto.rs")
            .map(|(f, l, c)| format!("{f}:{l}: {}", c.trim()))
            .collect();
        assert_eq!(
            sites.len(),
            1,
            "one law, one predicate, one call site (the definition in dto.rs is excluded); found \
             {sites:#?}"
        );
        assert!(
            sites[0].starts_with("registry.rs:"),
            "the refusal belongs at the daemon's own boundary, before `LaunchSpec`: {sites:#?}"
        );
    }
}
