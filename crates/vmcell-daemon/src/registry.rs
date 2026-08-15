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
    CreateVmRequest, ExecOutcomeDto, ExecRequestDto, ResourceUsageDto, SnapshotInfo, VmId, VmInfo,
    VmState,
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
        if req.ephemeral {
            // Tear down regardless of the exec result (the one-shot contract); a teardown error is
            // logged, never masked over the exec outcome the caller asked for.
            if let Err(e) = self.destroy(&id).await {
                tracing::warn!(vm = %id, error = %e, "ephemeral teardown failed");
            }
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
                slot.set_state(VmState::Ready); // still live whether or not the snapshot succeeded
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

    /// Destroys a VM: removes it from the table (so no new op finds it), marks it `Destroying`, and
    /// runs its graceful ordered teardown (`MicroVm::shutdown`).
    ///
    /// # Errors
    /// [`DaemonError::NotFound`] if there is no such VM; a teardown failure is propagated.
    pub async fn destroy(&self, id: &VmId) -> DaemonResult<()> {
        let slot = {
            let mut map = self.vms.lock().await;
            map.remove(id)
        }
        .ok_or_else(|| DaemonError::NotFound(format!("no vm {id}")))?;
        let mut inner = slot.inner.lock().await;
        slot.set_state(VmState::Destroying);
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
        let slots: Vec<Arc<VmSlot>> = {
            let mut map = self.vms.lock().await;
            map.drain().map(|(_, s)| s).collect()
        };
        for slot in slots {
            let mut inner = slot.inner.lock().await;
            slot.set_state(VmState::Destroying);
            if let Some(h) = inner.handle.take()
                && let Err(e) = h.shutdown().await
            {
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

fn handle_mut<'a>(inner: &'a mut VmInner, id: &VmId) -> DaemonResult<&'a mut Box<dyn VmHandle>> {
    inner
        .handle
        .as_mut()
        .ok_or_else(|| DaemonError::NotFound(format!("vm {id} has been torn down")))
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
        Blocked(Arc<SnapshotGate>),
        /// Remove the snapshot directory before returning `Ok` — exactly what a racing
        /// `delete_artifact_if_unused` did to an unpinned prefix, so the read-back must fail loud
        /// instead of reporting `files: []`.
        RemovesDir,
    }

    /// The rendezvous a `Blocked` snapshot uses: `entered` fires when the backend write starts,
    /// `release` lets it finish. `Notify` stores one permit, so neither side can miss the other.
    #[derive(Default)]
    struct SnapshotGate {
        entered: tokio::sync::Notify,
        release: tokio::sync::Notify,
    }

    /// A recording fake handle — no KVM. Counts execs + shutdowns.
    struct FakeHandle {
        vmid: u32,
        shutdowns: Arc<AtomicUsize>,
        snapshot_behavior: SnapshotBehavior,
    }

    #[async_trait]
    impl VmHandle for FakeHandle {
        fn vmid(&self) -> u32 {
            self.vmid
        }
        async fn exec(&mut self, req: ExecRequestDto) -> DaemonResult<ExecOutcomeDto> {
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
            Ok(())
        }
        async fn resume(&mut self) -> DaemonResult<()> {
            Ok(())
        }
        async fn shutdown(self: Box<Self>) -> DaemonResult<()> {
            self.shutdowns.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    struct FakeLauncher {
        next_vmid: AtomicU64,
        shutdowns: Arc<AtomicUsize>,
        snapshot_behavior: SnapshotBehavior,
    }

    #[async_trait]
    impl VmLauncher for FakeLauncher {
        async fn launch(&self, _spec: &LaunchSpec) -> DaemonResult<Box<dyn VmHandle>> {
            Ok(Box::new(FakeHandle {
                vmid: self.next_vmid.fetch_add(1, Ordering::SeqCst) as u32,
                shutdowns: self.shutdowns.clone(),
                snapshot_behavior: self.snapshot_behavior.clone(),
            }))
        }
    }

    fn registry() -> (Registry, Arc<AtomicUsize>, tempfile::TempDir) {
        registry_with(SnapshotBehavior::Normal)
    }

    fn registry_with(
        snapshot_behavior: SnapshotBehavior,
    ) -> (Registry, Arc<AtomicUsize>, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let artifacts =
            ArtifactStore::open(dir.path().join("artifacts"), 1 << 20).expect("artifacts");
        artifacts.create("vmlinux", b"kernel").expect("kernel");
        artifacts.create("rootfs.erofs", b"rootfs").expect("rootfs");
        let shutdowns = Arc::new(AtomicUsize::new(0));
        let launcher = FakeLauncher {
            next_vmid: AtomicU64::new(1),
            shutdowns: shutdowns.clone(),
            snapshot_behavior,
        };
        let reg = Registry::new(Box::new(launcher), artifacts, 0xdead_beef);
        (reg, shutdowns, dir)
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
        let gate = Arc::new(SnapshotGate::default());
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
        let gate = Arc::new(SnapshotGate::default());
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
}
