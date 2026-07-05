//! The VM registry — the daemon's **owned**, in-process table of live VMs (design §18.4).
//!
//! The daemon is the single owner of every VM it starts: it holds the `MicroVm` handle (through the
//! [`VmHandle`] seam), so the VMM process and its netns/tap/cgroup/scratch stay alive as long as the
//! handle is held, and **`Drop` releases them** in order (§12.10 — the invariant is preserved, not
//! abandoned). `destroy` is the graceful path (`MicroVm::shutdown`); dropping the registry (daemon
//! exit) runs each VM's ordered `Drop`. A hard-killed daemon leaks resources, which the **start-up
//! orphan sweep** (`vmcell::orchestrator::sweep_orphans`, wired in `vmcelld`) reclaims on the next boot.
//!
//! Each VM sits behind its own async mutex, so ops on **different** VMs run concurrently while ops on
//! **one** VM serialize on its single vsock control channel. The immutable identity of a VM (id, vmid,
//! the artifact names it pins) is read lock-free; only the handle + lifecycle state are behind the
//! per-VM lock.

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
/// lock-free; the mutable handle + state sit behind [`VmSlot::inner`].
struct VmSlot {
    id: VmId,
    vmid: u32,
    kernel: String,
    rootfs: String,
    /// The extra-disk artifact names this VM pins (design §19.4) — read lock-free by
    /// the delete-in-use guard, like `kernel`/`rootfs`.
    extra_disks: Vec<String>,
    vcpus: u8,
    mem_mib: u32,
    inner: Mutex<VmInner>,
}

struct VmInner {
    /// `None` once torn down (a racing op that cloned the `Arc` before removal then sees `None`).
    handle: Option<Box<dyn VmHandle>>,
    state: VmState,
}

impl VmSlot {
    async fn info(&self) -> VmInfo {
        VmInfo {
            id: self.id.clone(),
            state: self.inner.lock().await.state,
            vmid: self.vmid,
            kernel: self.kernel.clone(),
            rootfs: self.rootfs.clone(),
            vcpus: self.vcpus,
            mem_mib: self.mem_mib,
        }
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
        let path = self.artifacts.path_for(name)?; // validates the name (invariant §12.13)
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

    /// Creates and boots a VM the registry then **owns** (design §18.5.1). With a `command`, also
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
        // Fail loud early on a snapshot-ineligible request (design §12.1), rather than deferring to
        // the config builder's `Error`.
        if req.snapshotting && !req.net.snapshot_eligible() {
            return Err(DaemonError::BadRequest(format!(
                "snapshotting requires a snapshot-eligible net mode (no vhost-user device); {:?} is not eligible",
                req.net
            )));
        }
        // Resolve a `restore_from` prefix to its snapshot directory in the store (the same validated
        // single-component join as any artifact, invariant §12.13).
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
        // immutable, §19.4), translating any io_limit (§19.5). The names are pinned on the
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
            inner: Mutex::new(VmInner {
                handle: Some(handle),
                state: VmState::Ready,
            }),
        });
        let info = slot.info().await;
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

    /// Lists every owned VM, sorted by id.
    pub async fn list(&self) -> Vec<VmInfo> {
        let slots: Vec<Arc<VmSlot>> = self.vms.lock().await.values().cloned().collect();
        let mut out = Vec::with_capacity(slots.len());
        for slot in slots {
            out.push(slot.info().await);
        }
        out.sort_by(|a, b| a.id.0.cmp(&b.id.0));
        out
    }

    /// Reads one VM's info.
    ///
    /// # Errors
    /// [`DaemonError::NotFound`] if there is no such VM.
    pub async fn get(&self, id: &VmId) -> DaemonResult<VmInfo> {
        Ok(self.slot(id).await?.info().await)
    }

    /// Runs a command in a `Ready` VM.
    ///
    /// # Errors
    /// [`DaemonError::NotFound`] (gone) / [`DaemonError::Conflict`] (not `Ready`) / mapped exec error.
    pub async fn exec(&self, id: &VmId, req: ExecRequestDto) -> DaemonResult<ExecOutcomeDto> {
        let slot = self.slot(id).await?;
        let mut inner = slot.inner.lock().await;
        require_state(&inner, VmState::Ready, id)?;
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
    /// returning the file names written.
    ///
    /// # Errors
    /// [`DaemonError::InvalidName`] for a bad prefix, [`DaemonError::NotFound`]/[`DaemonError::Conflict`],
    /// or the mapped snapshot error (`Unsupported` for an ineligible config, design §12.1).
    pub async fn snapshot(&self, id: &VmId, artifact_prefix: &str) -> DaemonResult<SnapshotInfo> {
        // The prefix names a subdirectory of the artifact store — validate it as a single safe
        // component (invariant §12.13) so a snapshot cannot escape the store.
        validate_artifact_name(artifact_prefix)?;
        let out_dir = self.artifacts.dir().join(artifact_prefix);
        std::fs::create_dir_all(&out_dir).map_err(|e| {
            DaemonError::Internal(format!("cannot create snapshot dir {out_dir:?}: {e}"))
        })?;

        let slot = self.slot(id).await?;
        let mut inner = slot.inner.lock().await;
        require_state(&inner, VmState::Ready, id)?;
        inner.state = VmState::Snapshotting;
        let result = handle_mut(&mut inner, id)?.snapshot(&out_dir).await;
        inner.state = VmState::Ready; // still live whether or not the snapshot succeeded
        result?;

        // Enumerate the artifacts CH wrote into the snapshot dir, so a later restore can name them.
        let files = std::fs::read_dir(&out_dir)
            .map(|rd| {
                rd.flatten()
                    .filter_map(|e| e.file_name().into_string().ok())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
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
        inner.state = VmState::Destroying;
        match inner.handle.take() {
            Some(h) => h.shutdown().await,
            None => Ok(()),
        }
    }

    /// Whether any owned VM pins `artifact_name` as its kernel, rootfs, or one of its
    /// extra disks (design §19.4) — read lock-free off the immutable slot fields
    /// (design §18.3.2, the delete-in-use guard).
    pub async fn is_artifact_in_use(&self, artifact_name: &str) -> bool {
        self.vms.lock().await.values().any(|s| {
            s.kernel == artifact_name
                || s.rootfs == artifact_name
                || s.extra_disks.iter().any(|d| d == artifact_name)
        })
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
            inner.state = VmState::Destroying;
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

fn require_state(inner: &VmInner, want: VmState, id: &VmId) -> DaemonResult<()> {
    if inner.state == want {
        Ok(())
    } else {
        Err(DaemonError::Conflict(format!(
            "vm {id} is {:?}, not {want:?}",
            inner.state
        )))
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

    /// A recording fake handle — no KVM. Counts execs + shutdowns.
    struct FakeHandle {
        vmid: u32,
        shutdowns: Arc<AtomicUsize>,
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
                limits_enforced: true,
                mem_read_ok: true,
                cpu_read_ok: true,
                io_read_ok: true,
            })
        }
        async fn snapshot(&mut self, _dir: &std::path::Path) -> DaemonResult<()> {
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
    }

    #[async_trait]
    impl VmLauncher for FakeLauncher {
        async fn launch(&self, _spec: &LaunchSpec) -> DaemonResult<Box<dyn VmHandle>> {
            Ok(Box::new(FakeHandle {
                vmid: self.next_vmid.fetch_add(1, Ordering::SeqCst) as u32,
                shutdowns: self.shutdowns.clone(),
            }))
        }
    }

    fn registry() -> (Registry, Arc<AtomicUsize>, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let artifacts =
            ArtifactStore::open(dir.path().join("artifacts"), 1 << 20).expect("artifacts");
        artifacts.create("vmlinux", b"kernel").expect("kernel");
        artifacts.create("rootfs.erofs", b"rootfs").expect("rootfs");
        let shutdowns = Arc::new(AtomicUsize::new(0));
        let launcher = FakeLauncher {
            next_vmid: AtomicU64::new(1),
            shutdowns: shutdowns.clone(),
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

    // §19.4: an extra-disk artifact is resolved and PINNED by the live VM, so the
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

    // §19.4: a missing extra-disk artifact is a fail-loud BadRequest at create (the same
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
        assert!(matches!(
            reg.snapshot(&created.info.id, "../escape").await,
            Err(DaemonError::InvalidName(_))
        ));
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
