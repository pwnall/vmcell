//! Zygote suspend/resume fan-out: mint many identical VMs from one suspend image.
//!
//! Booting a guest kernel to "agent-ready" is the dominant per-VM cost (§16, Performance).
//! When a workload needs *many* identical VMs — a warm serverless pool, a fan-out
//! of agent sandboxes, a batch of test cells — paying that boot cost per VM is
//! wasteful. The **zygote** pattern pays it once:
//!
//! 1. Boot one VM to agent-ready and **suspend** it — a snapshot captured while
//!    paused. That frozen image is the *zygote* ([`Zygote::suspend`]).
//! 2. To mint a clone, **copy-on-write-copy** the zygote's suspend/resume data
//!    into the clone's own scratch dir, then restore + resume from that private
//!    copy ([`Zygote::spawn_clone`]). On a reflink-capable host filesystem the
//!    copy is a near-instant block-level clone; otherwise a full byte copy
//!    ([`CowSupport`]).
//! 3. Each clone gets a **fresh identity** — its own vmid (hence a distinct
//!    IP/MAC, §8.2, Restore correctness: a restored VM is not a fresh VM), its own netns/cgroup/vsock socket, and the mandatory
//!    post-restore resync (clock/entropy/MAC/IP) on its first `agent()` call — so
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
    /// Captures a zygote by **suspending** a booted, agent-ready VM.
    ///
    /// Snapshots `vm` into `master_dir` via [`MicroVm::snapshot`] (which pauses,
    /// writes, and resumes the VM, and invalidates its cached agent connection so
    /// it stays usable), then returns a `Zygote` that mints clones from the frozen
    /// image. `cfg` must be the (snapshot-eligible) config `vm` was created with —
    /// it is what each clone restores with. The caller still owns `vm` and may
    /// shut it down once the zygote is captured.
    ///
    /// # Errors
    /// [`Error::Unsupported`] if `cfg` is not snapshot-eligible (carries a
    /// vhost-user device — a virtio-fs data share or unprivileged networking,
    /// §13, Cross-cutting invariants); otherwise any error from taking the snapshot.
    pub async fn suspend<V: Vmm>(
        vm: &mut MicroVm<V>,
        cfg: VmConfig,
        master_dir: impl Into<PathBuf>,
    ) -> Result<Self> {
        let master_dir = master_dir.into();
        check_clone_eligible(&cfg)?;
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

    /// Best-effort probe of whether the master's filesystem supports reflink, for
    /// an up-front cost signal before minting a pool. A `FullCopy` result means
    /// every clone will pay a full byte copy of the suspend image (§8.4, The zygote fan-out and the OverlayStore seam).
    #[must_use]
    pub fn probe_cow_support(&self) -> CowSupport {
        crate::reflink::probe_reflink(&self.master_dir)
    }

    /// Mints **one** clone: copy-on-write-copies the master image and restores +
    /// resumes from the private copy.
    ///
    /// A single clone works on any snapshot backend (the copy is harmless where a
    /// backend re-binds baked paths, as long as no sibling is live). For a
    /// *concurrent* pool use [`Zygote::spawn_clones`], which gates on the backend
    /// capability. The returned VM is live and resumed; its first `agent()` call
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

    // A process-global VMID allocator shared across these fan-out tests. Under
    // `cargo test`'s in-process thread parallelism, fresh per-test allocators hand
    // concurrent tests overlapping low vmids that then collide on the
    // process-global `vmcell-vm-{pid}-{vmid}` scratch dir (idempotent
    // `create_dir_all`) and on the per-clone CoW target inside it — the design
    // mandates ONE shared allocator per test-runner process for exactly this reason
    // (§9.3, The public API surface). nextest runs each test in its own process, so this is inert there;
    // it only de-flakes `cargo test --lib`. CID sharing is unneeded — the scratch
    // dir is keyed on vmid only, and the fake instance never opens a real vsock.
    static SHARED_VMIDS: std::sync::OnceLock<VmidAllocator> = std::sync::OnceLock::new(); // allow-global-state: process-global VMID allocator; §9.3 (The public API surface) requires one shared allocator per test-runner process to avoid concurrent-test scratch-dir collisions
    fn shared_vmids() -> VmidAllocator {
        SHARED_VMIDS.get_or_init(VmidAllocator::new).clone()
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
            ..HostEnv::hermetic()
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
            ..HostEnv::hermetic()
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
            ..HostEnv::hermetic()
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
            ..HostEnv::hermetic()
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
    // so the arms that landed there — a custom `init=` (which replaces the very agent the
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
            ..HostEnv::hermetic()
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
