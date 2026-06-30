#![allow(dead_code)]

use std::path::PathBuf;

pub fn get_vmlinux() -> PathBuf {
    let p = vmcell::artifact::kernel_path();
    assert!(p.exists(), "vmlinux artifact missing at {:?}", p);
    p
}

pub fn get_rootfs() -> PathBuf {
    let p = vmcell::artifact::rootfs_path();
    assert!(p.exists(), "rootfs artifact missing at {:?}", p);
    p
}

#[allow(dead_code)]
pub fn ch_bin() -> String {
    std::env::var("VMCELL_CH_BIN").unwrap_or_else(|_| "cloud-hypervisor".to_string())
}

#[allow(dead_code)]
pub fn fc_bin() -> String {
    std::env::var("VMCELL_FC_BIN").unwrap_or_else(|_| "firecracker".to_string())
}

#[allow(dead_code)]
pub fn qemu_bin() -> String {
    std::env::var("VMCELL_QEMU_BIN").unwrap_or_else(|_| "qemu-system-x86_64".to_string())
}

/// Probes the process's *effective* capability set for `CAP_NET_ADMIN`.
///
/// This is the §12.8-consistent way to gate privileged-networking tests: the
/// capability runner grants `CAP_NET_ADMIN` ambiently without making the test a
/// full root process, so a `geteuid() == 0` gate both over-demands (refuses a
/// correctly-capability-granted run) and checks the wrong thing (uid, not the
/// effective cap). Parsing `CapEff` keeps this dependency-free across features.
pub fn has_cap_net_admin() -> bool {
    // CAP_NET_ADMIN is capability bit 12.
    const CAP_NET_ADMIN_BIT: u32 = 12;
    let Ok(status) = std::fs::read_to_string("/proc/self/status") else {
        return false;
    };
    for line in status.lines() {
        if let Some(hex) = line.strip_prefix("CapEff:") {
            if let Ok(bits) = u64::from_str_radix(hex.trim(), 16) {
                return bits & (1u64 << CAP_NET_ADMIN_BIT) != 0;
            }
        }
    }
    false
}

/// Recomputes the cgroup-v2 slice name the orchestrator assigns to a VM, so a
/// residue check can target the *actual* (possibly systemd-/runner-nested) path
/// `/sys/fs/cgroup/<name>` rather than the un-nested `vmcell-vm-<vmid>` guess. This
/// mirrors `orchestrator::MicroVm::setup_env` exactly; if the two diverge the
/// residue assertion silently passes, so they must stay in lockstep.
pub fn computed_cgroup_name(vmid: u32) -> String {
    let mut name = format!("vmcell-vm-{}", vmid);
    if let Ok(cgroup_str) = std::fs::read_to_string("/proc/self/cgroup") {
        if let Some(path) = cgroup_str.trim().split("0::").nth(1) {
            let mut base = path.trim_start_matches('/');
            if base.ends_with("/supervisor") {
                base = base.trim_end_matches("/supervisor");
            }
            if !base.is_empty() {
                name = format!("{}/vmcell-vm-{}", base, vmid);
            }
        }
    }
    name
}

/// Reaps orphaned `vmcell-net-*` network namespaces before a privileged/netns test.
///
/// Avoids a leaked namespace from a prior aborted run colliding with this run's
/// vmid. Runs under the capability runner (no `sudo`); safe because the
/// privileged suite serializes netns tests (`serial-host`). Logs what it removed.
pub fn clean_vmcell_netns() {
    let removed = vmcell::net::cleanup_orphan_netns("vmcell-net-");
    if !removed.is_empty() {
        println!(
            "clean_vmcell_netns: reaped orphaned namespaces: {:?}",
            removed
        );
    }
}

use vmcell::*;

pub async fn start_vm<V: Vmm>(vmm: &V, cfg: VmConfig) -> MicroVm<V> {
    let cid_alloc = std::sync::Arc::new(vmcell::vmm::CidAllocator::new());
    let vmid_alloc = vmcell::orchestrator::VmidAllocator::new();
    MicroVm::start(
        vmm,
        cfg,
        cid_alloc,
        vmid_alloc,
        Box::new(vmcell::metrics::DefaultCgroupFs),
    )
    .await
    .expect("start_vm: VM failed to start")
}

#[macro_export]
macro_rules! require_cap {
    ($caps:expr, $field:ident, $vmm:expr) => {
        if !$caps.$field {
            if vmcell::vmm::Vmm::id(&$vmm) == "cloud-hypervisor" {
                panic!("SKIP == PASS ERROR: Primary backend (cloud-hypervisor) MUST support capability `{}`", stringify!($field));
            } else {
                println!("SKIP: backend `{}` lacks capability `{}`", vmcell::vmm::Vmm::id(&$vmm), stringify!($field));
                return;
            }
        }
    };
}

#[macro_export]
macro_rules! vmm_matrix_test {
    ($name:ident, |$vmm:ident| $body:block) => {
        mod $name {
            #[allow(unused_imports)]
            use super::*;

            #[cfg(feature = "cloud-hypervisor")]
            #[tokio::test]
            #[ignore = "needs KVM"]
            async fn cloud_hypervisor() {
                let $vmm =
                    vmcell::vmm::cloud_hypervisor::CloudHypervisor::new(super::common::ch_bin());
                $body
            }

            #[cfg(feature = "firecracker")]
            #[tokio::test]
            #[ignore = "needs KVM"]
            async fn firecracker() {
                let $vmm = vmcell::vmm::firecracker::Firecracker::new(super::common::fc_bin());
                $body
            }

            #[cfg(feature = "qemu")]
            #[tokio::test]
            #[ignore = "needs KVM"]
            async fn qemu() {
                let $vmm = vmcell::vmm::qemu::Qemu::new(super::common::qemu_bin());
                $body
            }
        }
    };
}
