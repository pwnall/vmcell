//! The `VmLauncher`/`VmHandle` seam in front of `MicroVm::start` (design §11.4, The VM registry and the start-up sweep / §15, Testing strategy).
//!
//! The registry drives VMs through these traits, not `MicroVm` directly, so its logic (id minting,
//! the state machine, ordered teardown, in-use pinning) is unit-testable against a recording **fake**
//! with no KVM or root — the same "injectable side-effect trait with a real impl and a recording
//! fake" discipline the library uses (design §9.8, Testability seams). The real [`MicroVmLauncher`] is a thin
//! adapter; all the tested logic lives in the registry above it.

use crate::dto::{ExecOutcomeDto, ExecRequestDto, NetMode, ResourceUsageDto, StewardPlacementDto};
use crate::error::{DaemonError, DaemonResult};
use crate::scratch::{VmScratch, reclaim_orphan_scratch, scratch_base};
use async_trait::async_trait;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use vmcell::overlay::OverlayStore;

/// A resolved request to boot one VM — absolute artifact paths (the names already resolved against
/// the store, invariant §13, Cross-cutting invariants) plus the config knobs.
#[derive(Debug, Clone)]
pub struct LaunchSpec {
    /// Absolute path to the `vmlinux` kernel image.
    pub kernel: PathBuf,
    /// Absolute path to the erofs rootfs image.
    pub rootfs: PathBuf,
    /// vCPU count.
    pub vcpus: u8,
    /// Guest RAM in MiB.
    pub mem_mib: u32,
    /// Guest networking mode.
    pub net: NetMode,
    /// Whether the VM is snapshot-eligible.
    pub snapshotting: bool,
    /// When `Some`, restore from this snapshot directory (a copy of the named artifact snapshot)
    /// instead of a cold boot.
    pub restore_from: Option<PathBuf>,
    /// Extra virtio-blk devices (design §4.6, Extra virtio-blk devices and disk-I/O throttling),
    /// with the artifact names already resolved to absolute **store** paths and any `io_limit`
    /// translated (§4.6, Extra virtio-blk devices and disk-I/O throttling).
    ///
    /// Deliberately [`ExtraDisk`] and not `vmcell::BlockDevice`: a `BlockDevice` names the image the
    /// guest is handed, and for a writable disk that image does not exist yet — the launcher
    /// materializes it (see [`ExtraDisk::writable`]). Carrying the store path in a device the guest
    /// will be handed would make "the artifact, attached read-write" a representable state, which is
    /// the one thing this feature must never produce.
    pub extra_disks: Vec<ExtraDisk>,
    /// Append-only extra kernel command-line arguments (design §5.3, The kernel command line).
    pub extra_kernel_args: Vec<String>,
    /// Guest path of a custom `init=` — **init identity only** (design §3.5, Guest placement: PID 1
    /// or a service). Not an artifact name: it names a binary inside the rootfs image, so the
    /// registry does not resolve it against the store.
    pub init: Option<PathBuf>,
    /// Where this cell's steward runs (design §3.5; invariant C8).
    ///
    /// Deliberately **not** an `Option`: the registry always resolves a placement
    /// (`Registry::create`), so the launcher always hands `VmConfigBuilder` an explicit one and the
    /// builder's *derivation* — which answers `StewardPlacement::None` when an `init` is set and no
    /// placement is named — is structurally unreachable from the daemon. That derivation is the one
    /// placement REST does not express, so making it unreachable is worth the non-optional field.
    pub steward_placement: StewardPlacementDto,
}

/// One extra virtio-blk device a launch attaches, named by its **store artifact path** plus how the
/// guest gets to see it (design §11.5, The HTTP REST API and its OpenAPI document).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtraDisk {
    /// Absolute path of the store artifact backing this device. The store is create-only and
    /// immutable, so this file is never handed to a guest read-write.
    pub source: PathBuf,
    /// `true` ⇒ the guest gets a **private copy-on-attach copy** of [`source`](ExtraDisk::source) in
    /// this VM's own scratch directory, which it may write and which dies with the VM; `false` ⇒ the
    /// artifact itself, read-only and shared with every other cell using it.
    pub writable: bool,
    /// Optional I/O rate limit (disk-I/O fault injection, §4.6, Extra virtio-blk devices and
    /// disk-I/O throttling). Independent of `writable`: a copy can be throttled too.
    pub io_limit: Option<vmcell::config::DiskIoLimit>,
}

/// An owned, live VM the registry holds. Ops borrow `&mut self` (one vsock control channel per VM,
/// so ops on ONE VM serialize — correct, design §11.4, The VM registry and the start-up sweep); `shutdown` consumes it (ordered teardown).
#[async_trait]
pub trait VmHandle: Send {
    /// The internal network VMID octet (informational; the registry exposes an opaque id instead).
    fn vmid(&self) -> u32;
    /// Runs a command over vsock and returns the captured outcome.
    async fn exec(&mut self, req: ExecRequestDto) -> DaemonResult<ExecOutcomeDto>;
    /// Samples resource usage from the cgroup slice.
    async fn usage(&mut self) -> DaemonResult<ResourceUsageDto>;
    /// Writes a warm snapshot into `dir` (snapshot-eligible configs only).
    async fn snapshot(&mut self, dir: &Path) -> DaemonResult<()>;
    /// Pauses the guest (CPUs stopped). Mirrors the library `VmInstance` seam; reached over REST by
    /// `POST /v1/vms/{id}/pause`, whose state machine is
    /// [`Registry::pause`](crate::registry::Registry::pause) (design §11.5, The HTTP REST API and its
    /// OpenAPI document).
    ///
    /// Every host resource stays held — the VMM process, its netns/tap, its cgroup, its scratch dir —
    /// so a paused VM still pins its artifacts and still costs its slice. Only the vCPUs stop.
    async fn pause(&mut self) -> DaemonResult<()>;
    /// Resumes a paused guest (`POST /v1/vms/{id}/resume`).
    async fn resume(&mut self) -> DaemonResult<()>;
    /// Graceful ordered teardown (then verify-gone). Consumes the handle.
    async fn shutdown(self: Box<Self>) -> DaemonResult<()>;
}

/// Boots a [`VmHandle`] from a [`LaunchSpec`]. The registry holds one launcher.
#[async_trait]
pub trait VmLauncher: Send + Sync {
    /// Boots a VM to steward-ready and returns its handle.
    async fn launch(&self, spec: &LaunchSpec) -> DaemonResult<Box<dyn VmHandle>>;
}

/// The real launcher: wraps `MicroVm::start` on the Cloud Hypervisor backend, holding the daemon's
/// process-global allocators (design §18, Delta register: changes from the validated v27 build; the daemon is finally the single home for the
/// process-global `VmidAllocator`/`CidAllocator`).
pub struct MicroVmLauncher {
    vmm: vmcell::CloudHypervisor,
    /// The process-wide seam bundle (allocators + cgroup/clock/overlay), built once — the daemon is
    /// its natural single home (design §18, Delta register: changes from the validated v27 build, deltas 1–2). Threaded by reference to every spawn.
    env: vmcell::HostEnv,
    /// The prefix every VM's swept host resources are named with (must match the start-up sweep's,
    /// design).
    resource_prefix: String,
    /// Where this daemon's per-VM writable-disk scratch directories live — beside the artifact
    /// store, so a copy-on-attach copy can actually reflink (see [`crate::scratch`]).
    scratch_base: PathBuf,
    /// Disambiguates concurrent creates' scratch directory names within this process; the pid in
    /// the name disambiguates processes.
    scratch_seq: AtomicU64,
}

impl MicroVmLauncher {
    /// Builds a launcher over the `cloud-hypervisor` binary at `ch_bin`, with a process-wide
    /// [`HostEnv`](vmcell::HostEnv) (cross-process VMID allocator, real sysfs cgroup backend,
    /// reflink overlay store), `resource_prefix` for VM resource naming (use
    /// [`vmcell::naming::DEFAULT_RESOURCE_PREFIX`] for the default `vmcell-*` names), and
    /// `artifacts_dir` — the store directory whose reserved [`crate::scratch`] subdirectory holds
    /// per-VM writable-disk copies.
    ///
    /// Two start-up effects, both here because this constructor runs once per daemon process and
    /// **before** it owns any VM: the scratch base is created (so a create's first writable disk is
    /// not also the first news that the directory cannot be made), and writable-disk scratch left by
    /// a hard-killed predecessor is reclaimed — the counterpart to
    /// [`crate::sweep::startup_sweep`] for the one resource keyed on the daemon's pid rather than a
    /// vmid.
    ///
    /// # Errors
    /// Returns [`DaemonError::Internal`] if the process-wide `HostEnv` cannot be built (currently
    /// infallible; the fallible signature future-proofs a start-up host-capability probe, §11.2, Privilege and blessing),
    /// or if the writable-disk scratch base cannot be created.
    pub fn new(
        ch_bin: String,
        resource_prefix: impl Into<String>,
        artifacts_dir: &Path,
    ) -> DaemonResult<Self> {
        // Probe the host's capabilities ONCE at start-up (design §7.2 rule 1, The fail-loud capability contract and HostCapabilities / §18 delta 8, Delta register: changes from the validated v27 build), so the
        // daemon logs exactly what it can enforce — a missing controller or netns is a visible boot
        // signal, not a silent per-VM no-op later.
        let caps = vmcell::HostCapabilities::probe();
        tracing::info!(
            cap_net_admin = caps.cap_net_admin,
            cap_sys_admin = caps.cap_sys_admin,
            kvm = caps.kvm_accessible,
            netns = caps.netns_reachable,
            domain_leaf = caps.domain_leaf,
            memory_enforceable = caps.memory_limit_enforceable(),
            "vmcelld host capabilities probed at start-up"
        );
        let scratch_base = scratch_base(artifacts_dir);
        std::fs::create_dir_all(&scratch_base).map_err(|e| {
            DaemonError::Internal(format!(
                "cannot create the writable-disk scratch base {}: {e}",
                scratch_base.display()
            ))
        })?;
        let reclaimed = reclaim_orphan_scratch(&scratch_base);
        if !reclaimed.is_empty() {
            tracing::info!(
                removed = reclaimed.removed.len(),
                retained = reclaimed.retained.len(),
                "vmcelld: reclaimed writable-disk scratch from a prior daemon"
            );
        }
        Ok(Self {
            vmm: vmcell::CloudHypervisor::new(ch_bin),
            env: vmcell::HostEnv::shared()
                .map_err(|e| DaemonError::Internal(format!("cannot build host env: {e}")))?,
            resource_prefix: resource_prefix.into(),
            scratch_base,
            scratch_seq: AtomicU64::new(0),
        })
    }
}

/// Materializes one launch's extra disks: the **one** place a `vmcell::BlockDevice` is composed in
/// this daemon, and therefore the one place the copy-on-attach law lives (design §11.5, The HTTP
/// REST API and its OpenAPI document).
///
/// The law, in one sentence: **a disk the guest may write is a private copy in this VM's own
/// scratch directory; the store artifact is only ever attached read-only.** Both halves are here so
/// neither can be spelled differently somewhere else — the read-only arm hands back
/// [`ExtraDisk::source`] verbatim (no copy, nothing to clean up, several cells share the one file),
/// and the writable arm clones it through the injected [`OverlayStore`] seam (invariant S4: every
/// copy-on-write clone materializes through `env.overlay`, never a second path) into a fresh scratch
/// directory whose guard is returned with the devices.
///
/// The returned [`VmScratch`] is `Some` **iff** some disk was writable, and it owns the copies: an
/// error on any later disk drops it on the way out, so a half-materialized launch leaves nothing
/// behind. Its `CowSupport` is logged per disk rather than assumed — a `FullCopy` host pays a real
/// byte copy of every image and an operator should be able to see that in the log.
///
/// Synchronous and potentially large (a byte copy of a disk image), so [`MicroVmLauncher::launch`]
/// calls it on a blocking thread — the same discipline the orchestrator applies to `clone_tree`.
///
/// # Errors
/// [`DaemonError::Internal`] if the scratch directory or a copy cannot be made. The refusal carries
/// the store artifact's name, so a client that asked for a writable disk on a full filesystem learns
/// which one.
fn attach_extra_disks(
    disks: &[ExtraDisk],
    scratch_base: &Path,
    seq: u64,
    overlay: &dyn OverlayStore,
) -> DaemonResult<(Vec<vmcell::BlockDevice>, Option<VmScratch>)> {
    let mut scratch: Option<VmScratch> = None;
    let mut devices = Vec::with_capacity(disks.len());
    for (index, disk) in disks.iter().enumerate() {
        let device = if disk.writable {
            // Created on first need, so a launch with only read-only disks mints no directory at
            // all — and so the guard, once created, covers every copy that follows it.
            let dir = match &scratch {
                Some(s) => s,
                None => scratch.insert(VmScratch::create(scratch_base, seq)?),
            };
            // The store name is a validated single component, so it is a safe file name; the index
            // keeps the copies distinct and in attachment order (`/dev/vdb`, `/dev/vdc`, …).
            let file_name = disk
                .source
                .file_name()
                .unwrap_or_else(|| std::ffi::OsStr::new("disk"));
            let copy = dir.path().join(format!(
                "{index}-{}",
                std::path::Path::new(file_name).display()
            ));
            let support = overlay.clone_file(&disk.source, &copy).map_err(|e| {
                DaemonError::Internal(format!(
                    "cannot make a writable copy of extra disk {}: {e}",
                    disk.source.display()
                ))
            })?;
            tracing::debug!(
                source = %disk.source.display(),
                copy = %copy.display(),
                reflink = support.is_reflink(),
                "materialized a writable copy-on-attach extra disk"
            );
            vmcell::BlockDevice::read_write(copy)
        } else {
            vmcell::BlockDevice::read_only(disk.source.clone())
        };
        devices.push(match disk.io_limit {
            Some(limit) => device.with_io_limit(limit),
            None => device,
        });
    }
    Ok((devices, scratch))
}

/// Converts a `vmcell::ResourceUsage` to its wire DTO (field-for-field, including the honest
/// `*_read_ok` flags, design §7.2, The fail-loud capability contract and HostCapabilities).
#[must_use]
pub fn usage_to_dto(u: &vmcell::ResourceUsage) -> ResourceUsageDto {
    ResourceUsageDto {
        mem_peak_mib: u.mem_peak_mib,
        mem_current_mib: u.mem_current_mib,
        cpu_usec: u.cpu_usec,
        io_read_bytes: u.io_read_bytes,
        io_write_bytes: u.io_write_bytes,
        mem_limit_enforced: u.mem_limit_enforced,
        mem_read_ok: u.mem_read_ok,
        cpu_read_ok: u.cpu_read_ok,
        io_read_ok: u.io_read_ok,
    }
}

/// The real live-VM handle wrapping a `MicroVm`.
///
/// Field order is **teardown order** and is load-bearing: Rust drops fields in declaration order, so
/// the VM (and with it the VMM process holding the disk copies open) goes first and the scratch
/// directory second. That is the same order [`VmHandle::shutdown`] takes explicitly, so the graceful
/// path and the panic/`Drop` path release in one order — never two (§13, Cross-cutting invariants).
struct MicroVmHandle {
    vm: vmcell::MicroVm<vmcell::CloudHypervisor>,
    /// This VM's writable-disk copies, `Some` only when it asked for one. Dropping it removes the
    /// directory and every copy in it.
    scratch: Option<VmScratch>,
}

#[async_trait]
impl VmHandle for MicroVmHandle {
    fn vmid(&self) -> u32 {
        self.vm.vmid()
    }

    async fn exec(&mut self, req: ExecRequestDto) -> DaemonResult<ExecOutcomeDto> {
        if req.argv.is_empty() {
            return Err(DaemonError::BadRequest(
                "exec argv must be non-empty".to_string(),
            ));
        }
        let mut er = vmcell::ExecRequest::new(req.argv).with_env(req.env);
        if let Some(cwd) = req.cwd {
            er = er.with_cwd(cwd);
        }
        if let Some(secs) = req.timeout_secs {
            er = er.with_timeout(Duration::from_secs(secs));
        }
        let steward = self.vm.steward(None).await?;
        let outcome = steward.exec(er).await?;
        Ok(ExecOutcomeDto::from_bytes(
            outcome.code,
            &outcome.stdout,
            &outcome.stderr,
        ))
    }

    async fn usage(&mut self) -> DaemonResult<ResourceUsageDto> {
        Ok(usage_to_dto(&self.vm.usage().await?))
    }

    async fn snapshot(&mut self, dir: &Path) -> DaemonResult<()> {
        self.vm.snapshot(dir).await?;
        Ok(())
    }

    async fn pause(&mut self) -> DaemonResult<()> {
        self.vm.pause().await?;
        Ok(())
    }

    async fn resume(&mut self) -> DaemonResult<()> {
        self.vm.resume().await?;
        Ok(())
    }

    async fn shutdown(self: Box<Self>) -> DaemonResult<()> {
        let Self { vm, scratch } = *self;
        // ORDERED: the VMM process (which has the disk copies open) is gone before the copies are
        // removed — removing them first would unlink files a live hypervisor is writing. The
        // `let … = ` binding is what makes the order explicit rather than incidental to where `?`
        // happens to be, and the copies are released on the ERROR path too: a shutdown that fails
        // must not also leak a disk image.
        let outcome = vm.shutdown().await;
        drop(scratch);
        outcome?;
        Ok(())
    }
}

/// Maps the daemon's [`NetMode`] to a `vmcell::NetConfig`. Egress is `Open` (no interception proxy);
/// filtered egress is a future knob (design §6.2, NetConfig and the two datapaths/H-NET-4).
fn net_config(mode: NetMode) -> vmcell::config::NetConfig {
    use vmcell::config::{Egress, NetConfig};
    match mode {
        NetMode::None => NetConfig::None,
        NetMode::Privileged => NetConfig::Privileged {
            egress: Egress::Open,
        },
        NetMode::Unprivileged => NetConfig::Unprivileged {
            egress: Egress::Open,
            host_services_port: None,
        },
    }
}

/// Maps the daemon's [`StewardPlacementDto`] to a `vmcell::config::StewardPlacement` — the same
/// mirror-and-convert shape [`net_config`] uses, and for the same reason: `vmcell::config` carries no
/// serde derives, and `dto.rs` compiles without the `server` feature (so it cannot name a `vmcell`
/// type at all). Total: the DTO's refusable variant maps through, and the *refusal* is the
/// registry's (design §11.5, The HTTP REST API and its OpenAPI document; §18 delta 10).
fn steward_placement(p: StewardPlacementDto) -> vmcell::config::StewardPlacement {
    use vmcell::config::StewardPlacement as P;
    match p {
        StewardPlacementDto::Pid1 => P::Pid1,
        StewardPlacementDto::Service { port } => P::Service { port },
        StewardPlacementDto::None => P::None,
    }
}

/// Builds the `VmConfig` a [`LaunchSpec`] describes — the whole config-knob surface of the daemon,
/// extracted from [`MicroVmLauncher::launch`] so it is reachable **without KVM**: every knob the
/// REST API exposes is honored here, and a unit test can read the resolved config back rather than
/// booting a VM to find out.
///
/// # Errors
/// A bad knob (a nonexistent path can't happen — the registry resolved them — but an
/// empty/duplicate/over-cap `io_limit`, a reserved kernel arg, an unsafe `init` token, a `Pid1`
/// placement beside a custom init, or a reserved `Service` port) surfaces as the library's typed
/// `Error::Config`, mapped to 400.
///
/// `extra_disks` are the **materialized** devices from [`attach_extra_disks`] — the images the guest
/// is actually handed — rather than `spec.extra_disks`, because a writable disk's image is a copy
/// that does not exist until the launch makes it.
fn vm_config(
    spec: &LaunchSpec,
    resource_prefix: &str,
    extra_disks: &[vmcell::BlockDevice],
) -> DaemonResult<vmcell::config::VmConfig> {
    let mut builder = vmcell::config::VmConfig::builder(
        spec.kernel.clone(),
        vmcell::config::RootfsSource::Erofs {
            image: spec.rootfs.clone(),
        },
    )
    .vcpus(spec.vcpus)
    .mem_mib(spec.mem_mib)
    .net(net_config(spec.net))
    .snapshotting(spec.snapshotting)
    .resource_prefix(resource_prefix)
    // ALWAYS explicit (design §18 delta 10): naming the placement unconditionally is what keeps
    // `VmConfigBuilder::build()`'s `init: Some` ⇒ `StewardPlacement::None` derivation unreachable
    // from the daemon. `Pid1` here is byte-identical to naming nothing, so the default cell's
    // cmdline is unchanged.
    .steward_placement(steward_placement(spec.steward_placement));
    if let Some(init) = &spec.init {
        // Init IDENTITY only (C8). The placement above already said whether a steward is reachable;
        // this says which binary is PID 1.
        builder = builder.init(init.clone());
    }
    for disk in extra_disks {
        builder = builder.with_extra_disk(disk.clone());
    }
    for arg in &spec.extra_kernel_args {
        builder = builder.with_kernel_arg(arg.clone());
    }
    Ok(builder.build()?)
}

#[async_trait]
impl VmLauncher for MicroVmLauncher {
    async fn launch(&self, spec: &LaunchSpec) -> DaemonResult<Box<dyn VmHandle>> {
        // Materialize the extra disks BEFORE the config is built: a writable disk's image is a copy
        // this launch makes, so its path does not exist until now. A copy can be a whole disk image,
        // so it runs on a blocking thread rather than on the async runtime — the discipline the
        // `OverlayStore` seam documents for `clone_tree`, applied to its file-level door.
        let disks = spec.extra_disks.clone();
        let base = self.scratch_base.clone();
        let seq = self.scratch_seq.fetch_add(1, Ordering::Relaxed);
        let overlay = self.env.overlay.clone();
        let (extra_disks, scratch) =
            tokio::task::spawn_blocking(move || attach_extra_disks(&disks, &base, seq, &*overlay))
                .await
                .map_err(|e| {
                    DaemonError::Internal(format!("extra-disk materialization panicked: {e}"))
                })??;

        let cfg = vm_config(spec, &self.resource_prefix, &extra_disks)?;

        // Restore from a snapshot (via CoW so the named artifact is preserved and re-restorable,
        // design §8.4, The zygote fan-out and the OverlayStore seam) or cold-boot. Both then bring the steward up: for a cold boot that confirms
        // it booted; for a restore it drives the mandatory first post-restore resync (design §13, Cross-cutting invariants).
        let mut vm = if let Some(dir) = &spec.restore_from {
            // Restore named artifacts through the process-wide overlay store carried on `self.env`
            // (invariant S4), so the store snapshot stays re-restorable.
            let (vm, _cow) = vmcell::MicroVm::restore_cow(&self.vmm, dir, cfg, &self.env).await?;
            vm
        } else {
            vmcell::MicroVm::start(&self.vmm, cfg, &self.env).await?
        };
        // A registered VM in `Ready` is genuinely ready (design §11.4, The VM registry and the start-up sweep "derived from the handle").
        vm.steward(None).await?;
        // The scratch guard moves into the handle here and nowhere earlier: every `?` above drops
        // it, so a launch that fails after the copies were made leaves no copy behind.
        Ok(Box::new(MicroVmHandle { vm, scratch }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dto::StewardPlacementDto as D;
    use vmcell::config::StewardPlacement as P;

    /// The pre-delta spec: no init, no declared placement (the registry resolves an unnamed
    /// placement to an explicit `Pid1`).
    fn spec() -> LaunchSpec {
        LaunchSpec {
            kernel: PathBuf::from("/artifacts/vmlinux"),
            rootfs: PathBuf::from("/artifacts/rootfs.erofs"),
            vcpus: 2,
            mem_mib: 512,
            net: NetMode::None,
            snapshotting: false,
            restore_from: None,
            extra_disks: Vec::new(),
            extra_kernel_args: Vec::new(),
            init: None,
            steward_placement: D::Pid1,
        }
    }

    /// The resources a cmdline comparison needs; the values are irrelevant as long as both sides
    /// see the same ones.
    fn resources() -> vmcell::vmm::PerVmResources {
        vmcell::vmm::PerVmResources {
            cgroup_name: "vmcell-vm-7".to_string(),
            tap_name: None,
            netns_name: None,
            segment: None,
            vhost_user_socket: None,
            vmid: 7,
            guest_cid: 3,
            tmp_dir: PathBuf::from("/tmp/vmcell-vm-test-7"),
        }
    }

    // §18 delta 10: the launcher HONORS both new knobs. This is the third hop on the field's path
    // (`LaunchSpec` → `VmConfigBuilder`) and the one the fakes are blind to — `FakeLauncher` never
    // builds a config, so without this the chain is proven only as far as the spec.
    //
    // Asserted on the RESOLVED config, and on the cmdline the guest actually receives, because the
    // declared port only matters if it reaches the guest as `vmcell_steward_port=`.
    //
    // RED on the inverse: delete `.steward_placement(...)` from the builder chain — `build()` then
    // DERIVES `StewardPlacement::None` from the custom init, and both the placement assertion and
    // the port-token assertion fail. Delete the `.init(...)` call and the init assertion fails.
    #[test]
    fn the_launcher_honors_a_declared_init_and_placement() {
        let cfg = vm_config(
            &LaunchSpec {
                init: Some(PathBuf::from("/vmcell-tools/mini-init")),
                steward_placement: D::Service { port: 5100 },
                ..spec()
            },
            "vmcell",
            &[],
        )
        .expect("Service composes with a custom init");
        assert_eq!(cfg.steward_placement, P::Service { port: 5100 });
        assert_eq!(
            cfg.init.as_deref(),
            Some(Path::new("/vmcell-tools/mini-init"))
        );
        assert_eq!(
            cfg.steward_placement.steward_port(),
            Some(5100),
            "the control plane the daemon owns the VM through is at the declared port"
        );
        let cmdline =
            vmcell::config::build_kernel_cmdline(&cfg, &resources(), "").expect("cmdline");
        assert!(
            cmdline.contains("init=/vmcell-tools/mini-init"),
            "the custom init must reach the guest: {cmdline}"
        );
        assert!(
            cmdline.contains("vmcell_steward_port=5100"),
            "the declared port must reach the guest: {cmdline}"
        );
    }

    // The pay-for-what-you-use floor, daemon side: naming the placement unconditionally must not
    // move a byte for a cell that declared nothing. The library pins explicit-`Pid1` ≡ derived
    // default (`default_placement_emits_a_byte_identical_cmdline`); this pins that the DAEMON's
    // resolution lands on that same arm, which is the half a daemon-side default of `Service` or a
    // stray port would break.
    //
    // RED on the inverse: hand the builder a placement the spec did not name — e.g. hardcode
    // `.steward_placement(P::Service { port: 5100 })` in `vm_config` — and the cmdline grows a
    // `vmcell_steward_port=5100` token the pre-delta one never had. The placement assertion above
    // the comparison is the second half: a `Service { port: 5000 }` substitution moves no byte (the
    // default port emits no token) and only an equality on the placement itself catches it.
    #[test]
    fn a_spec_that_declares_nothing_builds_the_pre_delta_config() {
        let cfg = vm_config(&spec(), "vmcell", &[]).expect("builds");
        assert_eq!(cfg.steward_placement, P::Pid1);
        assert!(cfg.init.is_none());

        let baseline = vmcell::config::VmConfig::builder(
            PathBuf::from("/artifacts/vmlinux"),
            vmcell::config::RootfsSource::Erofs {
                image: PathBuf::from("/artifacts/rootfs.erofs"),
            },
        )
        .vcpus(2)
        .mem_mib(512)
        .net(vmcell::config::NetConfig::None)
        .snapshotting(false)
        .resource_prefix("vmcell")
        .build()
        .expect("the pre-delta chain, naming no placement at all");
        assert_eq!(
            vmcell::config::build_kernel_cmdline(&cfg, &resources(), "").expect("cmdline"),
            vmcell::config::build_kernel_cmdline(&baseline, &resources(), "").expect("cmdline"),
            "a default REST create's cmdline must be byte-identical to the pre-delta one"
        );
    }

    // The daemon's REST placement law IS C8's availability question, asked on this side of the
    // wire. `dto.rs` cannot state it that way — it compiles without the `server` feature and so
    // cannot name a `vmcell` type at all — so the parity is pinned HERE, variant-for-variant.
    //
    // `mirror_of`'s exhaustive `match` on the LIBRARY enum is the second half: a fourth
    // `StewardPlacement` variant becomes a compile error in this file rather than a placement that
    // is silently unexpressible over REST.
    //
    // RED on the inverse: flip `control_plane_retained` for any variant, or map
    // `D::Service{port}` to `P::Pid1` in `steward_placement`.
    #[test]
    fn the_rest_placement_law_matches_c8_availability_variant_for_variant() {
        fn mirror_of(p: P) -> D {
            match p {
                P::Pid1 => D::Pid1,
                P::Service { port } => D::Service { port },
                P::None => D::None,
            }
        }
        for dto in [
            D::Pid1,
            D::Service { port: 5000 },
            D::Service { port: 5100 },
            D::None,
        ] {
            let lib = steward_placement(dto);
            assert_eq!(
                dto.control_plane_retained(),
                lib.steward_port().is_some(),
                "the daemon's REST rule and C8's availability question must agree on {dto:?}"
            );
            assert_eq!(mirror_of(lib), dto, "the mirror must round-trip {dto:?}");
        }
        // Non-vacuity: the law must actually separate the variants (a predicate that is constantly
        // true would satisfy every assertion above except this one).
        assert!(D::Pid1.control_plane_retained() && !D::None.control_plane_retained());
    }

    // The library's refusals reach REST as 400s without a second daemon-side copy (design §11.5:
    // "a bad knob … surfaces as the library's `Error::Config`, mapped to 400").
    //
    // RED on the inverse: map `vmcell::Error::Config` to `DaemonError::Internal` in `error.rs`.
    #[test]
    fn contradictory_placement_knobs_surface_as_400_from_the_library() {
        for (what, bad) in [
            (
                "Pid1 beside a custom init",
                LaunchSpec {
                    init: Some(PathBuf::from("/sbin/init")),
                    steward_placement: D::Pid1,
                    ..spec()
                },
            ),
            (
                "an AF_VSOCK-reserved Service port",
                LaunchSpec {
                    steward_placement: D::Service { port: 0 },
                    ..spec()
                },
            ),
            (
                "snapshotting beside a non-Pid1 placement",
                LaunchSpec {
                    snapshotting: true,
                    steward_placement: D::Service { port: 5100 },
                    ..spec()
                },
            ),
        ] {
            let err = vm_config(&bad, "vmcell", &[]).expect_err(what);
            assert_eq!(
                err.kind().status_code(),
                400,
                "{what} is a client error: {}",
                err.message()
            );
        }
    }

    /// A store artifact on disk, with distinctive bytes so a copy can be told from a stub.
    ///
    /// It takes the composed PATH, not a `(dir, name)` pair, so the join happens at the call site
    /// against a string LITERAL. `scripts/ban-artifact-path-join.sh` (rubric B12 / invariant P3)
    /// bans `dir.join(<bare identifier>)` anywhere in this crate but sanctions a literal join,
    /// and it scans the crate's tests too — deliberately, since a helper that grows a
    /// client-supplied name later would otherwise be invisible to it. Narrowing the gate to
    /// production would have been the "edit the example to stay green" inversion; this is the
    /// shape the gate actually asks for.
    fn seed_artifact(path: PathBuf, byte: u8) -> PathBuf {
        std::fs::write(&path, vec![byte; 512])
            .unwrap_or_else(|e| panic!("seed {}: {e}", path.display()));
        path
    }

    // **THE COPY-ON-ATTACH LAW** (§11.5), KVM-free and end to end through the real
    // `ReflinkOverlayStore`: a read-only disk attaches the STORE ARTIFACT verbatim, a writable one
    // attaches a COPY under this VM's scratch directory — never the artifact — and the copy carries
    // the artifact's bytes.
    //
    // The last assertion is the one that matters: `readonly == false` on a device whose image is the
    // store path is precisely the defect this whole feature must not ship, and it is asserted over
    // EVERY returned device rather than the writable one, so a future third arm cannot slip past.
    //
    // RED on the inverse: `vmcell::BlockDevice::read_write(disk.source.clone())` in the writable arm
    // (the artifact handed out writable) — the scratch-containment assertion and the "the artifact
    // is untouched" assertion below both fail.
    #[test]
    fn a_writable_disk_attaches_a_private_copy_and_a_read_only_one_attaches_the_artifact() {
        let store = tempfile::tempdir().expect("tempdir");
        let shared = seed_artifact(store.path().join("shared.img"), 0xAA);
        let source = seed_artifact(store.path().join("scratch.img"), 0xBB);
        let base = crate::scratch::scratch_base(store.path());

        let disks = vec![
            ExtraDisk {
                source: shared.clone(),
                writable: false,
                io_limit: None,
            },
            ExtraDisk {
                source: source.clone(),
                writable: true,
                io_limit: Some(vmcell::config::DiskIoLimit::iops(128)),
            },
        ];
        let (devices, scratch) =
            attach_extra_disks(&disks, &base, 0, &vmcell::ReflinkOverlayStore).expect("attach");
        let scratch = scratch.expect("a writable disk mints a scratch dir");

        assert_eq!(devices.len(), 2, "attachment order is preserved");
        assert_eq!(devices[0].image, shared, "a read-only disk IS the artifact");
        assert!(devices[0].readonly);
        assert!(devices[0].io_limit.is_none());

        assert!(!devices[1].readonly, "the writable disk is writable");
        assert!(
            devices[1].image.starts_with(scratch.path()),
            "a writable disk's image must live in the VM's scratch dir, got {:?}",
            devices[1].image
        );
        assert_eq!(
            std::fs::read(&devices[1].image).expect("read the copy"),
            vec![0xBBu8; 512],
            "the copy carries the artifact's bytes"
        );
        assert_eq!(
            devices[1].io_limit,
            Some(vmcell::config::DiskIoLimit::iops(128)),
            "an io_limit rides along on a writable disk too"
        );

        // THE INVARIANT, over every device: nothing writable is ever backed by a store artifact.
        for (i, dev) in devices.iter().enumerate() {
            assert!(
                dev.readonly || dev.image.starts_with(scratch.path()),
                "device {i} is writable but backed by {:?}, which is not this VM's scratch",
                dev.image
            );
        }

        // And the guest's write cannot reach the store: rewrite the copy, the artifact stands.
        std::fs::write(&devices[1].image, vec![0xCCu8; 512]).expect("the guest writes");
        assert_eq!(
            std::fs::read(&source).expect("read artifact"),
            vec![0xBBu8; 512],
            "the store artifact must be byte-identical after the guest writes its copy"
        );
    }

    // A launch with only read-only disks mints NO scratch directory: the pay-for-what-you-use floor,
    // and the reason `VmScratch` is created lazily rather than per launch.
    //
    // RED on the inverse: create the guard unconditionally at the top of `attach_extra_disks`.
    #[test]
    fn a_launch_without_a_writable_disk_mints_no_scratch() {
        let store = tempfile::tempdir().expect("tempdir");
        let img = seed_artifact(store.path().join("data.img"), 0x11);
        let base = crate::scratch::scratch_base(store.path());
        for disks in [
            Vec::new(),
            vec![ExtraDisk {
                source: img,
                writable: false,
                io_limit: None,
            }],
        ] {
            let (_devices, scratch) =
                attach_extra_disks(&disks, &base, 0, &vmcell::ReflinkOverlayStore).expect("attach");
            assert!(
                scratch.is_none(),
                "no writable disk, no scratch directory to own"
            );
        }
        assert!(
            !base.exists() || std::fs::read_dir(&base).into_iter().flatten().count() == 0,
            "and nothing was left under the scratch base"
        );
    }

    // RESIDUE, the fake-blind axis the registry's `FakeLauncher` structurally cannot see: the copies
    // exist while the guard is held and are GONE when it drops — asserted in that order, so a
    // materialization that copied nothing could not pass. This is the KVM-free half of the live
    // `writable_extra_disk_*` legs in `crates/vmcelld/tests/integration.rs`.
    //
    // RED on the inverse: delete `impl Drop for VmScratch`.
    #[test]
    fn a_finished_or_failed_launch_leaves_no_copy_behind() {
        let store = tempfile::tempdir().expect("tempdir");
        let img = seed_artifact(store.path().join("scratch.img"), 0x22);
        let base = crate::scratch::scratch_base(store.path());
        let disks = vec![ExtraDisk {
            source: img,
            writable: true,
            io_limit: None,
        }];

        let (devices, scratch) =
            attach_extra_disks(&disks, &base, 0, &vmcell::ReflinkOverlayStore).expect("attach");
        let copy = devices[0].image.clone();
        let dir = scratch.as_ref().expect("scratch").path().to_path_buf();
        assert!(copy.is_file(), "the copy exists while the launch owns it");

        // The `?`-on-a-later-step path: every early return in `launch` drops this guard.
        drop(scratch);
        assert!(!copy.exists(), "the copy is gone with the guard");
        assert!(!dir.exists(), "and so is the directory that held it");
    }

    // The seam, not the filesystem: the copy is materialized through the injected
    // `OverlayStore` (invariant S4), so a store substituted on `HostEnv::overlay` is what runs. A
    // refusing store must make the LAUNCH fail loud — never fall back to a host-filesystem copy
    // behind the injected store's back, which is the second materialization path S4 forbids.
    //
    // RED on the inverse: call `std::fs::copy` in the writable arm instead of `overlay.clone_file`.
    #[test]
    fn the_copy_goes_through_the_overlay_seam_and_a_refusal_fails_loud() {
        /// A store with the pre-H1 shape: the directory door only, so `clone_file` takes the trait's
        /// refusing default.
        #[derive(Debug)]
        struct TreeOnlyStore;
        impl OverlayStore for TreeOnlyStore {
            fn clone_tree(&self, _src: &Path, _dst: &Path) -> vmcell::Result<vmcell::CowSupport> {
                unreachable!("the writable-disk path never clones a tree")
            }
            fn probe(&self, _dir: &Path) -> vmcell::CowSupport {
                vmcell::CowSupport::FullCopy
            }
        }

        let store = tempfile::tempdir().expect("tempdir");
        let img = seed_artifact(store.path().join("scratch.img"), 0x33);
        let base = crate::scratch::scratch_base(store.path());
        let disks = vec![ExtraDisk {
            source: img,
            writable: true,
            io_limit: None,
        }];
        let err = attach_extra_disks(&disks, &base, 0, &TreeOnlyStore)
            .expect_err("a store with no file door cannot materialize a writable disk");
        assert_eq!(
            err.kind().status_code(),
            500,
            "a store that cannot copy is the daemon's problem, not the client's: {}",
            err.message()
        );
        assert!(
            err.message().contains("scratch.img"),
            "the refusal must name the disk it could not copy: {}",
            err.message()
        );
    }

    // **THE CALL-SITE SCAN** (AGENTS.md: "a gate binds the call sites, not just the extracted
    // predicate"). The law — a guest-writable extra disk is a private copy, never the store artifact
    // — is enforceable only while `attach_extra_disks` is the ONE place this crate composes a
    // `vmcell::BlockDevice`. A second composition anywhere else (a "quick fix" in `registry.rs`
    // handing `BlockDevice::read_write(store_path)` straight to the builder) type-checks, boots, and
    // silently lets one cell's write reach every other cell's fixture.
    //
    // RED on the inverse: add `let _d = vmcell::BlockDevice::read_write(spec.source.clone());` to
    // `Registry::create`.
    //
    // It carries its own corpus rather than borrowing `registry.rs`'s delta-10 scanner's, because
    // the two ask different questions of different files: that one reads the four request-handling
    // sources for `init` readers, and this one must also read `scratch.rs` and `bridge.rs` —
    // precisely because neither composes a device today and this is what keeps that true.
    #[test]
    fn block_devices_are_composed_in_exactly_one_place() {
        let mut lines_scanned = 0usize;
        let mut sites: Vec<String> = Vec::new();
        let corpus = [
            ("launcher.rs", include_str!("launcher.rs")),
            ("registry.rs", include_str!("registry.rs")),
            ("server.rs", include_str!("server.rs")),
            ("bridge.rs", include_str!("bridge.rs")),
            ("scratch.rs", include_str!("scratch.rs")),
        ];
        for (name, body) in corpus {
            // Production only: the `#[cfg(test)]` modules legitimately build devices to assert on.
            let prod = body.split("\n#[cfg(test)]\n").next().unwrap_or(body);
            for (i, line) in prod.lines().enumerate() {
                let code = line.split("//").next().unwrap_or("");
                lines_scanned += 1;
                if code.contains("BlockDevice::") {
                    sites.push(format!("{name}:{}: {}", i + 1, code.trim()));
                }
            }
        }
        // A scan that read nothing — an empty corpus, or a `#[cfg(test)]` split that swallowed every
        // production line — is `gate misconfigured`, never a green verdict on nothing.
        assert_eq!(
            corpus.len(),
            5,
            "the scan must read all five daemon sources"
        );
        assert!(
            lines_scanned > 1000,
            "the scan read only {lines_scanned} production lines — it is not reading the sources, \
             so every assertion below would pass vacuously"
        );
        assert_eq!(
            sites.len(),
            2,
            "exactly two production `BlockDevice::` compositions are expected — the read-only and \
             the copy-on-attach arms of `attach_extra_disks`; found {sites:#?}"
        );
        for site in &sites {
            assert!(
                site.starts_with("launcher.rs:"),
                "every extra-disk device is composed in the one materialization tail: {sites:#?}"
            );
        }
        assert!(
            sites.iter().any(|s| s.contains("read_write"))
                && sites.iter().any(|s| s.contains("read_only")),
            "…and both arms must be there, so a scan that matched only one shape is not the law: \
             {sites:#?}"
        );
    }

    // The materialized devices reach the CONFIG the VMM is built from — the hop between
    // `attach_extra_disks` and the guest that no other test covers, and the one a `vm_config` that
    // kept reading `spec.extra_disks` would silently break (it would attach the store artifacts,
    // read-only, and the writable disk would simply not exist).
    //
    // RED on the inverse: iterate `&spec.extra_disks` in `vm_config` — it no longer type-checks,
    // which is itself the point of `LaunchSpec` carrying `ExtraDisk` rather than `BlockDevice`; the
    // reachable inverse is passing `&[]` at the call site, and both assertions below fail.
    #[test]
    fn the_materialized_devices_reach_the_vm_config() {
        let devices = vec![
            vmcell::BlockDevice::read_only("/artifacts/shared.img"),
            vmcell::BlockDevice::read_write("/artifacts/.vmcell-scratch/disks-1-0/1-scratch.img"),
        ];
        let cfg = vm_config(&spec(), "vmcell", &devices).expect("builds");
        assert_eq!(
            cfg.extra_disks, devices,
            "every materialized device must reach the config, in attachment order"
        );
        assert!(
            !cfg.extra_disks[1].readonly,
            "and the writable one must still be writable when the VMM reads it"
        );
    }
}
