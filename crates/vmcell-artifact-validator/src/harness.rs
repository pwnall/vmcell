//! Reusable VM-boot and host-capability primitives, **extracted** from vmcell's
//! `tests/common/mod.rs` so the validator and the integration tests share one implementation
//! (design v20; AGENTS.md "don't triplicate; extract"). The test crate re-exports these.

use std::path::PathBuf;

use vmcell::orchestrator::VmidAllocator;
use vmcell::vmm::CidAllocator;
use vmcell::{MicroVm, VmConfig, Vmm};

/// The built `vmlinux` artifact path (`VMCELL_KERNEL` or `target/vmcell-artifacts/vmlinux`),
/// asserting it exists — the tests' known-good kernel.
///
/// # Panics
/// Panics if the resolved `vmlinux` artifact does not exist (build it first: `vmcell build`).
#[must_use]
pub fn get_vmlinux() -> PathBuf {
    let p = vmcell::artifact::kernel_path();
    assert!(p.exists(), "vmlinux artifact missing at {p:?}");
    p
}

/// The built erofs rootfs artifact path (`VMCELL_ROOTFS` or the default), asserting it exists.
///
/// # Panics
/// Panics if the resolved rootfs artifact does not exist (build it first: `vmcell build`).
#[must_use]
pub fn get_rootfs() -> PathBuf {
    let p = vmcell::artifact::rootfs_path();
    assert!(p.exists(), "rootfs artifact missing at {p:?}");
    p
}

/// The Cloud Hypervisor binary (`VMCELL_CH_BIN` or `cloud-hypervisor`).
#[must_use]
pub fn ch_bin() -> String {
    std::env::var("VMCELL_CH_BIN").unwrap_or_else(|_| "cloud-hypervisor".to_string())
}

/// The Firecracker binary (`VMCELL_FC_BIN` or `firecracker`).
#[must_use]
pub fn fc_bin() -> String {
    std::env::var("VMCELL_FC_BIN").unwrap_or_else(|_| "firecracker".to_string())
}

/// The QEMU binary (`VMCELL_QEMU_BIN` or `qemu-system-x86_64`).
#[must_use]
pub fn qemu_bin() -> String {
    std::env::var("VMCELL_QEMU_BIN").unwrap_or_else(|_| "qemu-system-x86_64".to_string())
}

/// Probes the process's **effective** capability set for capability `bit` via `/proc/self/status`
/// `CapEff:` — the §12.8-consistent gate: the capability runner grants caps ambiently without a
/// full-root uid, so a `geteuid()==0` gate checks the wrong thing.
#[must_use]
pub fn has_effective_cap(bit: u32) -> bool {
    let Ok(status) = std::fs::read_to_string("/proc/self/status") else {
        return false;
    };
    for line in status.lines() {
        if let Some(hex) = line.strip_prefix("CapEff:") {
            if let Ok(bits) = u64::from_str_radix(hex.trim(), 16) {
                return bits & (1u64 << bit) != 0;
            }
        }
    }
    false
}

/// Whether the process holds effective `CAP_NET_ADMIN` (bit 12) — needed for the privileged
/// tap/netns network path.
#[must_use]
pub fn has_cap_net_admin() -> bool {
    has_effective_cap(12)
}

/// Whether the process holds effective `CAP_SYS_ADMIN` (bit 21) — needed for `virtiofsd` to enter
/// its `--sandbox namespace` (mount namespace). Without it, a virtio-fs share cannot mount, so the
/// shares check skips rather than fails.
#[must_use]
pub fn has_cap_sys_admin() -> bool {
    has_effective_cap(21)
}

/// Whether `/dev/kvm` is present and openable read-write — the hard precondition for booting a
/// VM. Existence alone is insufficient (it can exist but be inaccessible), so this opens it.
#[must_use]
pub fn has_kvm() -> bool {
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/kvm")
        .is_ok()
}

/// Whether the **memory** cgroup-v2 controller is delegated into this process's subtree — the
/// precondition for the per-VM memory-limit contract (§7). Best-effort: reads the current
/// cgroup base from `/proc/self/cgroup` (via vmcell's canonical parser) and checks that base's
/// `cgroup.subtree_control` advertises `memory`. A non-delegated host → the metrics checks skip
/// with reason rather than fail.
#[must_use]
pub fn cgroup_memory_delegated() -> bool {
    let Ok(cgroup) = std::fs::read_to_string("/proc/self/cgroup") else {
        return false;
    };
    let Some(base) = vmcell::metrics::cgroup_base_from_proc(&cgroup) else {
        // Empty base = root cgroup; check the root subtree_control.
        return std::fs::read_to_string("/sys/fs/cgroup/cgroup.subtree_control")
            .map(|s| s.split_whitespace().any(|c| c == "memory"))
            .unwrap_or(false);
    };
    std::fs::read_to_string(format!("/sys/fs/cgroup/{base}/cgroup.subtree_control"))
        .map(|s| s.split_whitespace().any(|c| c == "memory"))
        .unwrap_or(false)
}

/// Boots a VM from `cfg` with fresh in-process allocators + the default cgroup fs, returning
/// the handle or the boot error (the validator maps a boot failure to a `Fail` outcome rather
/// than panicking).
///
/// # Errors
/// Propagates any [`vmcell::Error`] from [`MicroVm::start`].
pub async fn try_start_vm<V: Vmm>(vmm: &V, cfg: VmConfig) -> vmcell::Result<MicroVm<V>> {
    let cid_alloc = std::sync::Arc::new(CidAllocator::new());
    let vmid_alloc = VmidAllocator::new();
    MicroVm::start(
        vmm,
        cfg,
        cid_alloc,
        vmid_alloc,
        Box::new(vmcell::metrics::DefaultCgroupFs),
    )
    .await
}

/// Boots a VM from `cfg`, panicking on failure — the ergonomic form the integration tests use
/// (a boot failure there *is* a test failure). The validator uses [`try_start_vm`] instead.
///
/// # Panics
/// Panics if the VM fails to start.
pub async fn start_vm<V: Vmm>(vmm: &V, cfg: VmConfig) -> MicroVm<V> {
    try_start_vm(vmm, cfg)
        .await
        .expect("start_vm: VM failed to start")
}
