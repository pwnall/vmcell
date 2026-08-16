//! The `VmLauncher`/`VmHandle` seam in front of `MicroVm::start` (design §11.4, The VM registry and the start-up sweep / §15, Testing strategy).
//!
//! The registry drives VMs through these traits, not `MicroVm` directly, so its logic (id minting,
//! the state machine, ordered teardown, in-use pinning) is unit-testable against a recording **fake**
//! with no KVM or root — the same "injectable side-effect trait with a real impl and a recording
//! fake" discipline the library uses (design §9.8, Testability seams). The real [`MicroVmLauncher`] is a thin
//! adapter; all the tested logic lives in the registry above it.

use crate::dto::{ExecOutcomeDto, ExecRequestDto, NetMode, ResourceUsageDto, StewardPlacementDto};
use crate::error::{DaemonError, DaemonResult};
use async_trait::async_trait;
use std::path::{Path, PathBuf};
use std::time::Duration;

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
    /// Extra read-only virtio-blk devices (design §4.6, Extra virtio-blk devices and disk-I/O throttling), with the artifact names already
    /// resolved to absolute paths and any `io_limit` translated (§4.6, Extra virtio-blk devices and disk-I/O throttling).
    pub extra_disks: Vec<vmcell::BlockDevice>,
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
    /// Pauses the guest (CPUs stopped). Mirrors the library `VmInstance` seam; the daemon pause/resume
    /// **routes** are future work (design future-work, "Pause/resume routes") — not yet reachable over REST.
    async fn pause(&mut self) -> DaemonResult<()>;
    /// Resumes a paused guest. Route-unwired (see `pause`).
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
}

impl MicroVmLauncher {
    /// Builds a launcher over the `cloud-hypervisor` binary at `ch_bin`, with a process-wide
    /// [`HostEnv`](vmcell::HostEnv) (cross-process VMID allocator, real sysfs cgroup backend,
    /// reflink overlay store), and `resource_prefix` for VM resource naming (use
    /// [`vmcell::naming::DEFAULT_RESOURCE_PREFIX`] for the default `vmcell-*` names).
    ///
    /// # Errors
    /// Returns [`DaemonError::Internal`] if the process-wide `HostEnv` cannot be built (currently
    /// infallible; the fallible signature future-proofs a start-up host-capability probe, §11.2, Privilege and blessing).
    pub fn new(ch_bin: String, resource_prefix: impl Into<String>) -> DaemonResult<Self> {
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
        Ok(Self {
            vmm: vmcell::CloudHypervisor::new(ch_bin),
            env: vmcell::HostEnv::shared()
                .map_err(|e| DaemonError::Internal(format!("cannot build host env: {e}")))?,
            resource_prefix: resource_prefix.into(),
        })
    }
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
struct MicroVmHandle {
    vm: vmcell::MicroVm<vmcell::CloudHypervisor>,
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
        self.vm.shutdown().await?;
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
fn vm_config(spec: &LaunchSpec, resource_prefix: &str) -> DaemonResult<vmcell::config::VmConfig> {
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
    for disk in &spec.extra_disks {
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
        let cfg = vm_config(spec, &self.resource_prefix)?;

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
        Ok(Box::new(MicroVmHandle { vm }))
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
        let cfg = vm_config(&spec(), "vmcell").expect("builds");
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
            let err = vm_config(&bad, "vmcell").expect_err(what);
            assert_eq!(
                err.kind().status_code(),
                400,
                "{what} is a client error: {}",
                err.message()
            );
        }
    }
}
