//! The `VmLauncher`/`VmHandle` seam in front of `MicroVm::start` (design §11.4, The VM registry and the start-up sweep / §15, Testing strategy).
//!
//! The registry drives VMs through these traits, not `MicroVm` directly, so its logic (id minting,
//! the state machine, ordered teardown, in-use pinning) is unit-testable against a recording **fake**
//! with no KVM or root — the same "injectable side-effect trait with a real impl and a recording
//! fake" discipline the library uses (design §9.8, Testability seams). The real [`MicroVmLauncher`] is a thin
//! adapter; all the tested logic lives in the registry above it.

use crate::dto::{ExecOutcomeDto, ExecRequestDto, NetMode, ResourceUsageDto};
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
    /// Pauses the guest (CPUs stopped).
    async fn pause(&mut self) -> DaemonResult<()>;
    /// Resumes a paused guest.
    async fn resume(&mut self) -> DaemonResult<()>;
    /// Graceful ordered teardown (then verify-gone). Consumes the handle.
    async fn shutdown(self: Box<Self>) -> DaemonResult<()>;
}

/// Boots a [`VmHandle`] from a [`LaunchSpec`]. The registry holds one launcher.
#[async_trait]
pub trait VmLauncher: Send + Sync {
    /// Boots a VM to agent-ready and returns its handle.
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
        let agent = self.vm.agent(None).await?;
        let outcome = agent.exec(er).await?;
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

#[async_trait]
impl VmLauncher for MicroVmLauncher {
    async fn launch(&self, spec: &LaunchSpec) -> DaemonResult<Box<dyn VmHandle>> {
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
        .resource_prefix(&self.resource_prefix);
        for disk in &spec.extra_disks {
            builder = builder.with_extra_disk(disk.clone());
        }
        for arg in &spec.extra_kernel_args {
            builder = builder.with_kernel_arg(arg.clone());
        }
        // Bad extra-disk / extra-arg knobs (a nonexistent path can't happen — the
        // registry resolved them — but an empty/duplicate/over-cap io_limit or a
        // reserved kernel arg) surface here as a typed config error mapped to 400.
        let cfg = builder.build()?;

        // Restore from a snapshot (via CoW so the named artifact is preserved and re-restorable,
        // design §8.4, The zygote fan-out and the OverlayStore seam) or cold-boot. Both then bring the agent up: for a cold boot that confirms
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
        vm.agent(None).await?;
        Ok(Box::new(MicroVmHandle { vm }))
    }
}
