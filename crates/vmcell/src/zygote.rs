//! Zygote suspend/resume fan-out: mint many identical VMs from one suspend image.
//!
//! Booting a guest kernel to "steward-ready" is the dominant per-VM cost (§16, Performance).
//! When a workload needs *many* identical VMs — a warm serverless pool, a fan-out
//! of agent sandboxes, a batch of test cells — paying that boot cost per VM is
//! wasteful. The **zygote** pattern pays it once:
//!
//! 1. Boot one VM to steward-ready and **suspend** it — a snapshot captured while
//!    paused. That frozen image is the *zygote* ([`Zygote::suspend`]).
//! 2. To mint a clone, **copy-on-write-copy** the zygote's suspend/resume data
//!    into the clone's own scratch dir, then restore + resume from that private
//!    copy ([`Zygote::spawn_clone`]). On a reflink-capable host filesystem the
//!    copy is a near-instant block-level clone; otherwise a full byte copy
//!    ([`CowSupport`]).
//! 3. Each clone gets a **fresh identity** — its own vmid (hence a distinct
//!    IP/MAC, §8.2, Restore correctness: a restored VM is not a fresh VM), its own netns/cgroup/vsock socket, and the mandatory
//!    post-restore resync (clock/entropy/MAC/IP) on its first `steward()` call — so
//!    concurrent clones never collide on the host.
//!
//! Because each clone restores from its **own** copy, the zygote master is never
//! mutated (§13, Cross-cutting invariants) and N clones never race on the backend's single-use in-place
//! `config.json` rewrite (§8.1, The warm-snapshot path and the eligibility law). Concurrent fan-out therefore requires a backend
//! that rotates host paths per restore (`restore_rotates_host_paths`, §2.5, The capability matrix): CH
//! does (its restore config rewrite moves every host path into the clone's own
//! scratch dir), Firecracker does not (it re-binds the vsock UDS baked into the
//! binary snapshot state verbatim, so two concurrent FC clones would fight over
//! one socket path). [`Zygote::spawn_clones`] enforces this — a concurrent
//! fan-out on a non-rotating backend is a typed [`Error::Unsupported`], not a
//! confusing socket collision.

use crate::config::VmConfig;
use crate::env::HostEnv;
use crate::error::{Error, Result};
use crate::orchestrator::MicroVm;
use crate::overlay::{OverlayStore, ReflinkOverlayStore};
use crate::reflink::CowSupport;
use crate::vmm::Vmm;
use std::path::{Path, PathBuf};

/// A suspended VM image from which many identical clones are minted cheaply.
///
/// A `Zygote` owns an **immutable** snapshot directory (the *master*) plus the
/// snapshot-eligible [`VmConfig`] its clones restore with. Cloning never mutates
/// the master — each clone restores from its own copy-on-write copy (§8.4, The zygote fan-out and the OverlayStore seam). The
/// master's directory lifecycle is the caller's (typically a pipeline snapshot
/// artifact); dropping a `Zygote` does **not** delete it.
///
/// The zygote ignores any [`VmConfig::vmid`] on the config it was built with:
/// every clone is allocated a **fresh** vmid so clones get distinct IP/MAC
/// identities and never collide (§8.2, Restore correctness: a restored VM is not a fresh VM). Pass the process-wide [`HostEnv`] to the
/// spawn methods so N clones draw N distinct ids and share one `OverlayStore` (S4).
#[derive(Debug, Clone)]
pub struct Zygote {
    /// The immutable master snapshot dir. Clones CoW-copy from it; it is never
    /// written.
    master_dir: PathBuf,
    /// The snapshot-eligible config clones restore with (with `vmid` cleared so
    /// each clone allocates a fresh one).
    cfg: VmConfig,
}

impl Zygote {
    /// Captures a zygote by **suspending** a booted, steward-ready VM.
    ///
    /// Snapshots `vm` into `master_dir` via [`MicroVm::snapshot`] (which pauses,
    /// writes, and resumes the VM, and invalidates its cached steward connection so
    /// it stays usable), then returns a `Zygote` that mints clones from the frozen
    /// image. `cfg` must be the (snapshot-eligible) config `vm` was created with —
    /// it is what each clone restores with. The caller still owns `vm` and may
    /// shut it down once the zygote is captured.
    ///
    /// `master_dir` is **created if absent** (with any missing parents) and is
    /// **create-only**: a destination that already holds anything is refused, never
    /// written into — `prepare_snapshot_dest` is the one predicate every
    /// suspend/branch destination goes through (private, so no rustdoc link).
    ///
    /// # Errors
    /// [`Error::Unsupported`] if `cfg` is not snapshot-eligible (carries a
    /// vhost-user device — a virtio-fs data share or unprivileged networking,
    /// §13, Cross-cutting invariants); [`Error::Io`] with
    /// [`ErrorKind::AlreadyExists`](std::io::ErrorKind::AlreadyExists) if
    /// `master_dir` is a non-empty directory, or any other I/O error creating it;
    /// otherwise any error from taking the snapshot.
    pub async fn suspend<V: Vmm>(
        vm: &mut MicroVm<V>,
        cfg: VmConfig,
        master_dir: impl Into<PathBuf>,
    ) -> Result<Self> {
        let master_dir = master_dir.into();
        // Eligibility BEFORE the directory is touched, so a refused suspend leaves
        // zero residue (the "mid-op faults leave zero residue" discipline).
        check_clone_eligible(&cfg)?;
        prepare_snapshot_dest(&master_dir).await?;
        vm.snapshot(&master_dir).await?;
        Ok(Self::from_parts(master_dir, cfg))
    }

    /// Adopts an already-built zygote snapshot directory (e.g. the `SnapshotStage`
    /// pipeline artifact, §10.1, Artifacts produced) plus the config its clones restore with.
    ///
    /// `master_dir` must be an existing directory. The config's `vmid` is cleared
    /// (each clone allocates a fresh one).
    ///
    /// # Errors
    /// [`Error::Io`] if `master_dir` is not an existing directory, or
    /// [`Error::Unsupported`] if `cfg` is not snapshot-eligible (§13, Cross-cutting invariants).
    pub async fn from_snapshot_dir(master_dir: impl Into<PathBuf>, cfg: VmConfig) -> Result<Self> {
        let master_dir = master_dir.into();
        check_clone_eligible(&cfg)?;
        let meta = tokio::fs::metadata(&master_dir).await.map_err(Error::Io)?;
        if !meta.is_dir() {
            return Err(Error::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("zygote master is not a directory: {}", master_dir.display()),
            )));
        }
        Ok(Self::from_parts(master_dir, cfg))
    }

    fn from_parts(master_dir: PathBuf, mut cfg: VmConfig) -> Self {
        // Clones always get a fresh vmid; the zygote's own vmid (if any) describes
        // the ancestor, not its children (§8.4, The zygote fan-out and the OverlayStore seam).
        cfg.vmid = None;
        Self { master_dir, cfg }
    }

    /// The immutable master snapshot directory.
    #[must_use]
    pub fn master_dir(&self) -> &Path {
        &self.master_dir
    }

    /// The config clones restore with (its `vmid` is `None`).
    #[must_use]
    pub fn config(&self) -> &VmConfig {
        &self.cfg
    }

    /// Best-effort probe, **through the [`HostEnv`]'s [`OverlayStore`] seam**, of
    /// whether this master's clones will be cheap block-level copies, for an
    /// up-front cost signal before minting a pool. A `FullCopy` result means every
    /// clone will pay a full byte copy of the suspend image (§8.4, The zygote fan-out and the OverlayStore seam).
    ///
    /// This is the packaged form of the design's `env.overlay.probe(zygote.master_dir())`
    /// (§8.4) and the form to use: the cost signal is answered by the **same** store
    /// [`spawn_clone`](Zygote::spawn_clone)/[`spawn_clones`](Zygote::spawn_clones)
    /// will materialize the clones with (invariant S4), so an injected store can
    /// never be contradicted by a filesystem probe run behind its back.
    #[must_use]
    pub fn probe_cow_support_in(&self, env: &HostEnv) -> CowSupport {
        // docs/78 `overlay-probe-not-side-effect-free`, seam half: the cost signal used
        // to call `reflink::probe_reflink(&self.master_dir)` directly, which left
        // `OverlayStore::probe` with no production caller and answered for the host
        // filesystem even when the caller had injected a different store. One law: the
        // store that clones is the store that reports what cloning costs.
        env.overlay.probe(&self.master_dir)
    }

    /// Best-effort probe of whether the master's filesystem supports reflink under
    /// the **default production store** ([`ReflinkOverlayStore`], the one
    /// [`HostEnv::shared`](crate::HostEnv::shared) carries).
    ///
    /// Prefer [`probe_cow_support_in`](Zygote::probe_cow_support_in), which asks the
    /// store the caller actually clones with. This env-less form is only correct for
    /// a caller running the default store, and reports for it explicitly rather than
    /// silently (§8.4, The zygote fan-out and the OverlayStore seam).
    #[must_use]
    pub fn probe_cow_support(&self) -> CowSupport {
        // Routed through the trait, not through `reflink::probe_reflink`, so there is
        // exactly ONE way the cost signal is computed (docs/78
        // `overlay-probe-not-side-effect-free`): this method names the store it answers
        // for instead of bypassing the seam.
        ReflinkOverlayStore.probe(&self.master_dir)
    }

    /// Mints **one** clone: copy-on-write-copies the master image and restores +
    /// resumes from the private copy.
    ///
    /// A single clone works on any snapshot backend (the copy is harmless where a
    /// backend re-binds baked paths, as long as no sibling is live). For a
    /// *concurrent* pool use [`Zygote::spawn_clones`], which gates on the backend
    /// capability. The returned VM is live and resumed; its first `steward()` call
    /// runs the mandatory post-restore resync (§8.2, Restore correctness: a restored VM is not a fresh VM).
    ///
    /// # Errors
    /// Any error from the copy-on-write copy, network setup, or restore (§8.4, The zygote fan-out and the OverlayStore seam).
    pub async fn spawn_clone<V: Vmm>(&self, vmm: &V, env: &HostEnv) -> Result<MicroVm<V>> {
        let (vm, cow) = MicroVm::restore_cow(vmm, &self.master_dir, self.cfg.clone(), env).await?;
        tracing::debug!(
            cow = ?cow,
            master = %self.master_dir.display(),
            "spawned zygote clone"
        );
        Ok(vm)
    }

    /// Mints `count` clones **concurrently**, each from its own copy-on-write copy
    /// of the master image, and returns them once all are live and resumed.
    ///
    /// Each clone draws its vmid/CID and its cgroup backend from the process-wide
    /// [`HostEnv`], and materializes its private copy-on-write copy through
    /// `env.overlay` (invariant S4) — so the clones get distinct vmids (hence
    /// distinct IP/MAC) and CIDs from one shared, process-global source.
    ///
    /// **All-or-nothing:** if any clone fails, the ones that already came up are
    /// torn down (their ordered `Drop`, §13, Cross-cutting invariants) and the first error is returned —
    /// no half-built pool leaks.
    ///
    /// # Errors
    /// [`Error::Unsupported`] when `count > 1` and the backend does not rotate
    /// host paths on restore (`restore_rotates_host_paths == false`, e.g.
    /// Firecracker) — concurrent clones would fight over one baked host path
    /// (§8.4, The zygote fan-out and the OverlayStore seam). Otherwise, the first clone error (copy, network, or restore).
    pub async fn spawn_clones<V: Vmm>(
        &self,
        vmm: &V,
        count: usize,
        env: &HostEnv,
    ) -> Result<Vec<MicroVm<V>>> {
        if count == 0 {
            return Ok(Vec::new());
        }
        // Fan-out gate (§8.4, The zygote fan-out and the OverlayStore seam): a backend that re-binds baked host paths verbatim
        // (`restore_rotates_host_paths == false`) cannot give two *concurrent*
        // clones distinct vsock paths — CoW-copying the dir does not change the
        // path baked into the binary snapshot state. Fail loud and typed rather
        // than let the clones collide on one socket. (A single clone via
        // `spawn_clone` is still fine; `count == 1` here is allowed on any
        // backend.)
        if count > 1 && !vmm.capabilities().restore_rotates_host_paths {
            return Err(Error::Unsupported {
                vmm: vmm.id().to_string(),
                feature: "concurrent zygote fan-out (backend re-binds baked host paths verbatim; \
                          §9.4, use one clone at a time, or the CH tier)"
                    .to_string(),
            });
        }

        // Restore all clones concurrently. Each draws its own fresh vmid/CID from
        // the shared allocators in `env` (internally synchronized) and materializes
        // its private CoW copy through `env.overlay` — one store for the whole
        // process, no per-clone injection (invariant S4).
        let futs =
            (0..count).map(|_| MicroVm::restore_cow(vmm, &self.master_dir, self.cfg.clone(), env));
        let results = futures::future::join_all(futs).await;

        // All-or-nothing: gather the live clones; on the first error, drop the
        // successes (ordered teardown, §13, Cross-cutting invariants) and surface it — never a partial,
        // leaking pool.
        let mut vms = Vec::with_capacity(count);
        let mut reflinked = 0usize;
        let mut first_err: Option<Error> = None;
        for r in results {
            match r {
                Ok((vm, cow)) => {
                    if cow.is_reflink() {
                        reflinked += 1;
                    }
                    vms.push(vm);
                }
                Err(e) => {
                    if first_err.is_none() {
                        first_err = Some(e);
                    }
                }
            }
        }
        if let Some(e) = first_err {
            // Dropping `vms` tears each clone down in the documented order.
            drop(vms);
            return Err(e);
        }
        tracing::info!(
            count,
            reflinked,
            full_copied = count - reflinked,
            master = %self.master_dir.display(),
            "spawned zygote clone pool"
        );
        Ok(vms)
    }
}

/// Prepares `dir` as a snapshot destination and refuses a populated one — **the one
/// predicate** every suspend/branch destination in this crate goes through
/// ([`Zygote::suspend`], and therefore [`Lineage::fork_from_vm`](crate::Lineage::fork_from_vm)
/// and [`Lineage::branch`](crate::Lineage::branch), which delegate to it).
///
/// Creates `dir` (and any missing parents) when absent; accepts an existing but
/// **empty** directory (callers that pre-create their own scratch dir); refuses
/// anything else. A snapshot image is written file-by-file into its destination, so
/// re-snapshotting into a populated master overwrites *part* of it and leaves a torn
/// mix of two lineages — a clone restored from that image is neither. The daemon's
/// equivalent path already refuses this (`create_dir` + EEXIST ⇒ 409, finding
/// `snapshot-prefix-silent-reuse`); the library's did not, which is what this closes.
///
/// The `create_dir` EEXIST test is the kernel's, so the common "fresh destination"
/// case is atomic against a concurrent suspend to the same path. The
/// empty-directory arm is check-then-act by necessity — the contract has always let
/// a caller pre-create the directory — and is the caller's to serialize.
///
/// # Errors
/// [`Error::Io`] with [`ErrorKind::AlreadyExists`](std::io::ErrorKind::AlreadyExists)
/// if `dir` exists and is not empty, with
/// [`ErrorKind::InvalidInput`](std::io::ErrorKind::InvalidInput) if it exists and is
/// not a directory, or the underlying error if it cannot be created or read.
async fn prepare_snapshot_dest(dir: &Path) -> Result<()> {
    // Parents first, then the destination itself with a NON-recursive `create_dir`, so
    // the "already there" answer comes from the kernel rather than a racy pre-check.
    if let Some(parent) = dir.parent().filter(|p| !p.as_os_str().is_empty()) {
        tokio::fs::create_dir_all(parent).await.map_err(Error::Io)?;
    }
    match tokio::fs::create_dir(dir).await {
        Ok(()) => return Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(Error::Io(e)),
    }

    let meta = tokio::fs::metadata(dir).await.map_err(Error::Io)?;
    if !meta.is_dir() {
        return Err(Error::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("snapshot destination is not a directory: {}", dir.display()),
        )));
    }
    let mut entries = tokio::fs::read_dir(dir).await.map_err(Error::Io)?;
    if entries.next_entry().await.map_err(Error::Io)?.is_some() {
        return Err(Error::Io(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            format!(
                "snapshot destination {} already holds an image — a suspend/branch never \
                 overwrites one (delete it, or pick a fresh directory)",
                dir.display()
            ),
        )));
    }
    Ok(())
}

/// Fail-fast snapshot-eligibility check for a clone config (the config-only subset
/// of the §13 (Cross-cutting invariants) law; the per-clone restore boundary re-checks with the resources
/// in hand). Rejecting here avoids minting copy-on-write copies for a pool that
/// could never restore.
fn check_clone_eligible(cfg: &VmConfig) -> Result<()> {
    // docs/78 S1, second half: this gate USED to open-code its own arm list beside
    // `orchestrator::clone_ineligible_feature`, and the pair had already diverged — the custom-init
    // (M2) and host-USB (M4) arms landed in the orchestrator's copy only, so a zygote fan-out of a
    // custom-init config was still minted and only refused later, per clone, at the restore
    // boundary. One law, one predicate: the config-only subset lives in exactly one function and
    // this boundary reads it, so a new arm can never reach one boundary and miss the other.
    let feature = crate::orchestrator::clone_ineligible_feature(cfg);
    match feature {
        Some(f) => Err(Error::Unsupported {
            vmm: "zygote".to_string(),
            feature: format!(
                "zygote clone with {f} — snapshot-eligible VMs have no vhost-user device (§12.1)"
            ),
        }),
        None => Ok(()),
    }
}

/// **The one** process-global VMID allocator the clone-minting unit tests share — this
/// module's fan-out tests *and* [`lineage`](crate::lineage)'s, which mint clones through
/// the very same [`Zygote`] machinery.
///
/// Under `cargo test`'s in-process thread parallelism, separate allocators hand concurrent
/// tests overlapping vmids that then collide on the process-global `vmcell-vm-{pid}-{vmid}`
/// scratch dir and on the per-clone CoW target inside it (`zygote clone target already
/// exists: …/zygote-snapshot`). §9.3 (The public API surface) mandates ONE shared allocator
/// per test-runner process for exactly this reason — and until this consolidation there were
/// **two**, one per module, so the invariant both modules' comments claimed was false across
/// the module boundary. Worse than merely "two": `seeded_id_order` seeds from the clock, so
/// two allocators built moments apart walk the *same* order and collide head-on.
///
/// nextest runs each test in its own process, so this is inert there; it only de-flakes
/// `cargo test --lib`. CID sharing is unneeded — the scratch dir is keyed on vmid only, and
/// the fake instances never open a real vsock.
#[cfg(test)]
pub(crate) fn shared_test_vmids() -> crate::orchestrator::VmidAllocator {
    static SHARED_VMIDS: std::sync::OnceLock<crate::orchestrator::VmidAllocator> =
        std::sync::OnceLock::new(); // allow-global-state: THE process-global VMID allocator for the clone-minting unit tests; §9.3 (The public API surface) requires one shared allocator per test-runner process to avoid concurrent-test scratch-dir collisions
    SHARED_VMIDS
        .get_or_init(crate::orchestrator::VmidAllocator::new)
        .clone()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RootfsSource;
    use crate::metrics::CgroupFs;
    use crate::orchestrator::VmidAllocator;
    use crate::vmm::{FakeVmInstance, PerVmResources, VmmCapabilities};
    use std::collections::HashSet;
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    // Every `HostEnv` below draws from the ONE allocator above (see its doc for why one, and
    // why it lives at module scope rather than in here).
    fn shared_vmids() -> VmidAllocator {
        super::shared_test_vmids()
    }

    /// A recording fake backend for the fan-out unit tests. It records the exact
    /// directory each restore is handed (so a test can prove every clone restored
    /// from its OWN private copy, never the shared master); lets a test set
    /// `restore_rotates_host_paths` (so the concurrent-fan-out gate is exercisable
    /// without a real Firecracker); can **inject a restore failure** on the first
    /// restore call (to drive the all-or-nothing partial-failure teardown); and
    /// gives every minted instance a **shared** call recorder so a test can observe
    /// each clone's `resume`/`drop` (the ordered-teardown-zero-residue assertion).
    #[derive(Debug)]
    struct RecordingVmm {
        restore_dirs: Arc<Mutex<Vec<PathBuf>>>,
        /// Shared across every `FakeVmInstance` this backend mints, so a test sees
        /// all clones' recorded calls (`resume`, `drop`, …) in one timeline.
        instance_calls: Arc<Mutex<Vec<String>>>,
        rotates: bool,
        /// When true, the **first** restore call fails, modelling one clone in a
        /// fan-out dying after its siblings came up.
        fail_first_restore: bool,
        restore_count: Arc<AtomicUsize>,
    }

    impl RecordingVmm {
        fn new(rotates: bool) -> Self {
            Self {
                restore_dirs: Arc::new(Mutex::new(Vec::new())),
                instance_calls: Arc::new(Mutex::new(Vec::new())),
                rotates,
                fail_first_restore: false,
                restore_count: Arc::new(AtomicUsize::new(0)),
            }
        }

        /// A backend whose first restore call fails (all others succeed).
        fn failing_first(rotates: bool) -> Self {
            Self {
                fail_first_restore: true,
                ..Self::new(rotates)
            }
        }
    }

    impl Vmm for RecordingVmm {
        type Instance = FakeVmInstance;

        async fn create(
            &self,
            _cfg: &VmConfig,
            _res: &PerVmResources,
            _cgroups: &dyn CgroupFs,
        ) -> Result<Self::Instance> {
            // Clones only ever call restore().
            Err(Error::Vmm(
                "RecordingVmm::create is not used by clones".into(),
            ))
        }

        async fn restore(
            &self,
            snapshot_dir: &Path,
            _cfg: &VmConfig,
            _res: &PerVmResources,
            _cgroups: &dyn CgroupFs,
        ) -> Result<Self::Instance> {
            // Inject a failure on the first restore call (atomically exactly one
            // caller wins the 0), leaving the rest to succeed.
            if self.fail_first_restore && self.restore_count.fetch_add(1, Ordering::SeqCst) == 0 {
                return Err(Error::Vmm("injected restore failure".into()));
            }
            self.restore_dirs
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(snapshot_dir.to_path_buf());
            Ok(FakeVmInstance {
                vsock_path: snapshot_dir.join("vsock.sock"),
                serial: snapshot_dir.join("serial.log"),
                calls: self.instance_calls.clone(),
                faults: Default::default(),
                control_plane_probes: Default::default(),
            })
        }

        fn capabilities(&self) -> VmmCapabilities {
            VmmCapabilities {
                snapshot_restore: true,
                lazy_restore: false,
                virtio_fs_shares: true,
                unprivileged_vhost_user_net: true,
                nested_virt: true,
                virtio_console: true,
                restore_rotates_host_paths: self.rotates,
                disk_io_throttle: true,
                usb_host_passthrough: false,
            }
        }

        fn id(&self) -> &str {
            "recording"
        }
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

    /// Writes a plausible zygote master snapshot dir with a couple of files.
    fn write_master(dir: &Path) {
        std::fs::create_dir_all(dir).expect("mk master");
        std::fs::write(dir.join("config.json"), b"{\"vsock\":{\"cid\":3}}").expect("cfg");
        std::fs::write(dir.join("mem_file"), vec![0u8; 2048]).expect("mem");
    }

    // The headline fan-out property: N clones each restore from their OWN private
    // copy of the master (never the shared master dir), and each gets a distinct
    // vmid. The buggy inverse — handing the master dir to every restore (the
    // single-use race, §8.1, The warm-snapshot path and the eligibility law) — goes red because every recorded restore dir would
    // equal the master and they would not be distinct.
    #[tokio::test]
    async fn fan_out_restores_each_clone_from_its_own_cow_copy() {
        let root = tempfile::tempdir().expect("tempdir");
        let master = root.path().join("zygote");
        write_master(&master);
        let master_before = std::fs::read(master.join("config.json")).expect("read master");

        let vmm = RecordingVmm::new(true);
        let zygote = Zygote::from_snapshot_dir(master.clone(), erofs_cfg())
            .await
            .expect("build zygote");
        let env = HostEnv {
            vmids: shared_vmids(),
            ..HostEnv::for_unit_tests()
        };

        let clones = zygote
            .spawn_clones(&vmm, 4, &env)
            .await
            .expect("fan-out of 4 clones");
        assert_eq!(clones.len(), 4);

        // Distinct vmids => distinct network identity (IP/MAC) per clone (§8.2, Restore correctness: a restored VM is not a fresh VM).
        let vmids: HashSet<u32> = clones.iter().map(|c| c.vmid()).collect();
        assert_eq!(vmids.len(), 4, "each clone must get a distinct vmid");

        // Each restore saw a DISTINCT dir, none of which is the master.
        let dirs = vmm.restore_dirs.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(dirs.len(), 4);
        let unique: HashSet<&PathBuf> = dirs.iter().collect();
        assert_eq!(unique.len(), 4, "clones must not share a restore dir");
        for d in dirs.iter() {
            assert_ne!(
                d, &master,
                "a clone must never restore from the master (§12.12)"
            );
            assert!(
                d.ends_with("zygote-snapshot"),
                "clone restore dir should be the per-VM CoW copy, got {}",
                d.display()
            );
        }

        // The master is untouched by the fan-out (immutability, §13, Cross-cutting invariants).
        assert_eq!(
            std::fs::read(master.join("config.json")).expect("read master after"),
            master_before
        );
    }

    // The concurrent-fan-out gate (§8.4, The zygote fan-out and the OverlayStore seam): a backend that re-binds baked host paths
    // verbatim (`restore_rotates_host_paths == false`, e.g. Firecracker) cannot run
    // >1 concurrent clone. The inverse — letting them through — would collide on one
    // baked socket path. A single clone is still allowed.
    #[tokio::test]
    async fn concurrent_fan_out_gated_on_rotating_backend() {
        let root = tempfile::tempdir().expect("tempdir");
        let master = root.path().join("zygote");
        write_master(&master);

        let vmm = RecordingVmm::new(false); // does NOT rotate host paths (FC-like)
        let zygote = Zygote::from_snapshot_dir(master, erofs_cfg())
            .await
            .expect("build zygote");
        let env = HostEnv {
            vmids: shared_vmids(),
            ..HostEnv::for_unit_tests()
        };

        // > 1 concurrent clone is rejected, typed.
        let many = zygote.spawn_clones(&vmm, 3, &env).await;
        assert!(
            matches!(many, Err(Error::Unsupported { .. })),
            "concurrent fan-out on a non-rotating backend must be Unsupported, got {many:?}"
        );

        // Exactly one clone is fine even without host-path rotation.
        let one = zygote
            .spawn_clones(&vmm, 1, &env)
            .await
            .expect("a single clone is allowed on any backend");
        assert_eq!(one.len(), 1);
    }

    // count == 0 is a no-op that never touches the backend.
    #[tokio::test]
    async fn fan_out_zero_is_empty() {
        let root = tempfile::tempdir().expect("tempdir");
        let master = root.path().join("zygote");
        write_master(&master);
        let vmm = RecordingVmm::new(true);
        let zygote = Zygote::from_snapshot_dir(master, erofs_cfg())
            .await
            .expect("build zygote");
        let env = HostEnv {
            vmids: shared_vmids(),
            ..HostEnv::for_unit_tests()
        };
        let clones = zygote
            .spawn_clones(&vmm, 0, &env)
            .await
            .expect("zero clones");
        assert!(clones.is_empty());
        assert!(
            vmm.restore_dirs
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .is_empty()
        );
    }

    // A single CoW clone comes up and restores from a private copy, not the master.
    #[tokio::test]
    async fn single_clone_uses_private_copy() {
        let root = tempfile::tempdir().expect("tempdir");
        let master = root.path().join("zygote");
        write_master(&master);
        let vmm = RecordingVmm::new(true);
        let zygote = Zygote::from_snapshot_dir(master.clone(), erofs_cfg())
            .await
            .expect("build zygote");
        let env = HostEnv {
            vmids: shared_vmids(),
            ..HostEnv::for_unit_tests()
        };
        let vm = zygote.spawn_clone(&vmm, &env).await.expect("single clone");
        let _ = vm.vmid();
        let dirs = vmm.restore_dirs.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(dirs.len(), 1);
        assert_ne!(dirs[0], master, "single clone must use a private CoW copy");
    }

    // Fail-fast eligibility: a config carrying a vhost-user device (a data share)
    // is rejected at zygote construction, before any copy is minted. The inverse —
    // building the zygote and only failing at the Nth restore — wastes N copies.
    #[tokio::test]
    async fn ineligible_config_rejected_at_construction() {
        let root = tempfile::tempdir().expect("tempdir");
        let master = root.path().join("zygote");
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
        let res = Zygote::from_snapshot_dir(master, cfg).await;
        assert!(
            matches!(res, Err(Error::Unsupported { .. })),
            "a vhost-user device must be rejected at construction, got {res:?}"
        );
    }

    // v30 §18 delta 8: a `Zygote` over a SEGMENT config must be refused at the config-only gate,
    // not after minting the copy-on-write copies (and never at the per-clone restore, where the
    // fan-out would already have dual-claimed one member slot). Buggy impl guarded: without the
    // `Segment` arm in `check_clone_eligible`, this returns `Ok` and the failure surfaces N copies
    // later. Positive control: the same config with no segment is accepted.
    #[tokio::test]
    async fn segment_config_rejected_at_zygote_construction() {
        let root = tempfile::tempdir().expect("tempdir");
        let master = root.path().join("zygote");
        write_master(&master);
        let (_seg, _env, _calls) = crate::net::segment::testing::fake_segment("vmcell");
        let cfg = VmConfig::builder(
            PathBuf::from("/vmlinux"),
            RootfsSource::Erofs {
                image: PathBuf::from("/rootfs.erofs"),
            },
        )
        .net(crate::config::NetConfig::Segment {
            segment: _seg.clone(),
        })
        .build()
        .expect("a non-snapshotting segment config builds");
        let res = Zygote::from_snapshot_dir(master.clone(), cfg).await;
        assert!(
            matches!(&res, Err(Error::Unsupported { feature, .. }) if feature.contains("segment")),
            "a segment member must be rejected at zygote construction, got {res:?}"
        );

        // Positive control: the identical master with a non-segment config is accepted.
        assert!(
            Zygote::from_snapshot_dir(master, erofs_cfg()).await.is_ok(),
            "the same master must still accept an eligible config"
        );
    }

    // docs/78 S1 (second half) + M2/M4: this gate reads `orchestrator::clone_ineligible_feature`,
    // so the arms that landed there — a custom `init=` (which replaces the very steward the
    // mandatory post-restore resync runs through) and a passed-through host USB device (host state
    // outside the migration stream) — are refused HERE, before any copy-on-write copy is minted,
    // not N clones later at the per-clone restore boundary.
    //
    // Red on the inverse: restore this gate's old open-coded three-arm list (unprivileged /
    // segment / shares) and both legs return `Ok` — the exact drift S1 was filed against. The
    // positive control keeps it non-vacuous.
    #[tokio::test]
    async fn custom_init_and_usb_configs_rejected_at_zygote_construction() {
        let root = tempfile::tempdir().expect("tempdir");
        let master = root.path().join("zygote");
        write_master(&master);

        let custom_init = VmConfig::builder(
            PathBuf::from("/vmlinux"),
            RootfsSource::Erofs {
                image: PathBuf::from("/rootfs.erofs"),
            },
        )
        .network_disabled()
        .init("/bin/workload")
        .build()
        .expect("a non-snapshotting custom-init config builds");
        let res = Zygote::from_snapshot_dir(master.clone(), custom_init).await;
        assert!(
            matches!(&res, Err(Error::Unsupported { feature, .. }) if feature.contains("custom init")),
            "a custom-init config must be rejected at zygote construction, got {res:?}"
        );

        let usb = VmConfig::builder(
            PathBuf::from("/vmlinux"),
            RootfsSource::Erofs {
                image: PathBuf::from("/rootfs.erofs"),
            },
        )
        .network_disabled()
        .with_usb_host_device(crate::config::UsbHostDevice::new(0x1d6b, 0x0002))
        .build()
        .expect("a non-snapshotting USB config builds");
        let res = Zygote::from_snapshot_dir(master.clone(), usb).await;
        assert!(
            matches!(&res, Err(Error::Unsupported { feature, .. }) if feature.contains("USB")),
            "a host-USB config must be rejected at zygote construction, got {res:?}"
        );

        // Positive control: the identical master with an eligible config is accepted.
        assert!(
            Zygote::from_snapshot_dir(master, erofs_cfg()).await.is_ok(),
            "the same master must still accept an eligible config"
        );
    }

    // docs/78 `overlay-probe-not-side-effect-free`, SEAM half: the up-front CoW cost
    // signal must be answered by the store the caller injected — the same store the
    // fan-out will materialize clones with (S4) — not by a filesystem probe run behind
    // that store's back. Host-independent by construction: the fake is configured with
    // the OPPOSITE of what this filesystem really reports, so the two answers are
    // always distinguishable, on reflink and non-reflink hosts alike. The pre-fix body
    // (`crate::reflink::probe_reflink(&self.master_dir)`) reddens on both assertions —
    // it returns the filesystem's answer and the seam records no probe at all.
    #[tokio::test]
    async fn probe_cow_support_routes_through_the_injected_seam() {
        let root = tempfile::tempdir().expect("tempdir");
        let master = root.path().join("zygote");
        write_master(&master);

        // What the real filesystem under this tempdir says, via the production store.
        let real = ReflinkOverlayStore.probe(&master);
        // …and a store that disagrees with it, whatever it said.
        let dissenting = if real.is_reflink() {
            CowSupport::FullCopy
        } else {
            CowSupport::Reflink
        };
        let store = crate::overlay::RecordingOverlayStore::with_report(dissenting);
        let env = HostEnv {
            overlay: Arc::new(store.clone()),
            vmids: shared_vmids(),
            ..HostEnv::for_unit_tests()
        };

        let zygote = Zygote::from_snapshot_dir(master.clone(), erofs_cfg())
            .await
            .expect("build zygote");

        let got = zygote.probe_cow_support_in(&env);
        assert_eq!(
            got, dissenting,
            "the cost signal must be the INJECTED store's answer, not the filesystem's ({real:?})"
        );
        assert_eq!(
            store.probe_calls(),
            vec![master.clone()],
            "the seam must have been asked exactly once, about the master dir"
        );

        // The env-less form is the documented default-store reading, and says so by
        // agreeing with the production store rather than with the injected one.
        assert_eq!(
            zygote.probe_cow_support(),
            real,
            "the env-less form answers for the default ReflinkOverlayStore"
        );
        assert_eq!(
            store.probe_calls().len(),
            1,
            "the env-less form must NOT reach the injected seam"
        );

        // The probe leaves the immutable master untouched (docs/78, side-effect half —
        // asserted here too because this is the caller that probes a *master*).
        let mut entries: Vec<String> = std::fs::read_dir(&master)
            .expect("read master")
            .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
            .collect();
        entries.sort();
        assert_eq!(
            entries,
            vec!["config.json".to_string(), "mem_file".to_string()],
            "probing must not write into the immutable master"
        );
    }

    // m4, `Zygote::suspend` leg: a snapshot destination is CREATE-ONLY, exactly like the
    // daemon's artifact-store prefix (`create_dir` + EEXIST ⇒ 409, finding
    // `snapshot-prefix-silent-reuse`). Suspending onto a populated master used to write the
    // new image file-by-file over the old one, leaving a torn mix of two lineages that no
    // clone can restore correctly. `FakeVmInstance::snapshot` is fs-blind, so the gate
    // supplies the residue itself and proves it SURVIVES the refusal.
    //
    // RED on the inverse (delete the `prepare_snapshot_dest` call in `suspend`): the second
    // suspend returns `Ok` and `expect_err` panics.
    //
    // Positive controls, both arms the predicate accepts: a NON-EXISTENT destination (created,
    // with parents) and an existing but EMPTY one (the pre-create contract `bench-vm` and the
    // live zygote suite rely on).
    #[tokio::test]
    async fn suspend_refuses_a_populated_master_dir() {
        let root = tempfile::tempdir().expect("tempdir");
        let vmm = crate::vmm::FakeVmm::default();
        let env = HostEnv {
            vmids: shared_vmids(),
            ..HostEnv::for_unit_tests()
        };
        let mut vm = MicroVm::start(&vmm, erofs_cfg(), &env)
            .await
            .expect("start a live VM");

        // A populated destination — a previous node's image — is refused, typed.
        let populated = root.path().join("populated");
        write_master(&populated);
        let before = std::fs::read(populated.join("config.json")).expect("read the existing image");
        let err = Zygote::suspend(&mut vm, erofs_cfg(), &populated)
            .await
            .expect_err("suspending onto a populated master must be refused");
        match err {
            Error::Io(e) => assert_eq!(
                e.kind(),
                std::io::ErrorKind::AlreadyExists,
                "the refusal must be AlreadyExists, got {e:?}"
            ),
            other => panic!("expected a typed Io(AlreadyExists) refusal, got {other:?}"),
        }
        assert_eq!(
            std::fs::read(populated.join("config.json")).expect("the existing image survives"),
            before,
            "the refused suspend must not have written into the populated master"
        );

        // Positive control 1: a fresh (nested, non-existent) destination is created and used.
        let fresh = root.path().join("nested/deeper/master");
        let z = Zygote::suspend(&mut vm, erofs_cfg(), &fresh)
            .await
            .expect("a fresh destination must still suspend");
        assert_eq!(z.master_dir(), fresh, "the master is the requested dir");
        assert!(
            fresh.is_dir(),
            "suspend creates the destination and parents"
        );

        // Positive control 2: an existing but EMPTY destination is accepted (the caller may
        // pre-create its own scratch dir).
        let empty = root.path().join("empty");
        std::fs::create_dir(&empty).expect("pre-create an empty destination");
        Zygote::suspend(&mut vm, erofs_cfg(), &empty)
            .await
            .expect("an existing EMPTY destination must still suspend");

        // And a destination that is a FILE is a typed InvalidInput, not a silent overwrite.
        let as_file = root.path().join("a-file");
        std::fs::write(&as_file, b"not a dir").expect("write file");
        let err = Zygote::suspend(&mut vm, erofs_cfg(), &as_file)
            .await
            .expect_err("a non-directory destination must be refused");
        assert!(
            matches!(&err, Error::Io(e) if e.kind() == std::io::ErrorKind::InvalidInput),
            "expected Io(InvalidInput), got {err:?}"
        );
    }

    // A non-directory master is a hard error (from_snapshot_dir).
    #[tokio::test]
    async fn missing_master_dir_errors() {
        let root = tempfile::tempdir().expect("tempdir");
        let res = Zygote::from_snapshot_dir(root.path().join("nope"), erofs_cfg()).await;
        assert!(
            matches!(res, Err(Error::Io(_))),
            "missing master must Io-error"
        );
    }

    // All-or-nothing (§8.4, The zygote fan-out and the OverlayStore seam / §13, Cross-cutting invariants): when one clone in a fan-out fails, the ones
    // that already came up are torn down in order and the error is surfaced — no
    // half-built pool leaks. Injects a failure on the first restore of a 4-clone
    // fan-out; the other 3 come up (each records `resume`) and must then all be
    // dropped (each records `drop`). The inverse — replacing `drop(vms)` with
    // `mem::forget(vms)` (leak) or returning `Ok(vms)` (partial pool) — goes red:
    // the leak drops zero of the 3, and the partial pool returns `Ok`.
    #[tokio::test]
    async fn fan_out_is_all_or_nothing_when_a_clone_fails() {
        let root = tempfile::tempdir().expect("tempdir");
        let master = root.path().join("zygote");
        write_master(&master);

        let vmm = RecordingVmm::failing_first(true);
        let zygote = Zygote::from_snapshot_dir(master, erofs_cfg())
            .await
            .expect("build zygote");

        let env = HostEnv {
            vmids: shared_vmids(),
            ..HostEnv::for_unit_tests()
        };
        let res = zygote.spawn_clones(&vmm, 4, &env).await;
        assert!(
            matches!(res, Err(Error::Vmm(_))),
            "the injected restore failure must surface as the pool error, got {res:?}"
        );

        let calls = vmm.instance_calls.lock().unwrap_or_else(|e| e.into_inner());
        let resumes = calls.iter().filter(|c| c.as_str() == "resume").count();
        let drops = calls.iter().filter(|c| c.as_str() == "drop").count();
        // At least one sibling came up (so the teardown path was genuinely
        // exercised). We assert the INVARIANT, not an exact count: with fresh
        // per-test allocators a concurrent test can occasionally steal a vmid and
        // reduce the success count, but every clone that resumed must have been
        // torn down. `drops == resumes` is the zero-residue proof; the inverse
        // (`mem::forget(vms)`) yields drops == 0 ≠ resumes and goes red, and a
        // partial-pool `Ok(vms)` fails the `Err` assertion above.
        assert!(
            resumes >= 1,
            "at least one sibling clone must have come up to exercise teardown; timeline: {calls:?}"
        );
        assert_eq!(
            drops, resumes,
            "every clone that came up must be torn down on the failure path (no leak); \
             timeline: {calls:?}"
        );
    }

    // Fail-fast eligibility, Unprivileged-net arm: rejected at construction. The
    // inverse (deleting the net arm) goes red.
    #[tokio::test]
    async fn unprivileged_net_rejected_at_construction() {
        let root = tempfile::tempdir().expect("tempdir");
        let master = root.path().join("zygote");
        write_master(&master);
        let mut cfg = VmConfig::builder(
            PathBuf::from("/vmlinux"),
            RootfsSource::Erofs {
                image: PathBuf::from("/rootfs.erofs"),
            },
        )
        .build()
        .expect("erofs config builds");
        cfg.net = crate::config::NetConfig::Unprivileged {
            egress: crate::config::Egress::Open,
            host_services_port: None,
        };
        let res = Zygote::from_snapshot_dir(master, cfg).await;
        assert!(
            matches!(res, Err(Error::Unsupported { .. })),
            "unprivileged (vhost-user-net) networking must be rejected at construction, got {res:?}"
        );
    }
}
