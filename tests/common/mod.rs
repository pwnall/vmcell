#![allow(dead_code)]

use std::path::PathBuf;

pub fn get_vmlinux() -> Option<PathBuf> {
    let p = std::env::var("IMP_KERNEL")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/tmp/imp-artifacts/vmlinux"));
    if p.exists() { Some(p) } else { None }
}

pub fn get_rootfs() -> Option<PathBuf> {
    let p = std::env::var("IMP_ROOTFS")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/tmp/imp-artifacts/rootfs.erofs"));
    if p.exists() { Some(p) } else { None }
}

#[allow(dead_code)]
pub fn ch_bin() -> String {
    std::env::var("IMP_CH_BIN").unwrap_or_else(|_| "cloud-hypervisor".to_string())
}

#[allow(dead_code)]
pub fn fc_bin() -> String {
    std::env::var("IMP_FC_BIN").unwrap_or_else(|_| "firecracker".to_string())
}

#[allow(dead_code)]
pub fn qemu_bin() -> String {
    std::env::var("IMP_QEMU_BIN").unwrap_or_else(|_| "qemu-system-x86_64".to_string())
}

use imp_testing::*;

pub async fn start_vm<V: Vmm>(vmm: &V, cfg: VmConfig) -> TestVm<V> {
    let cid_alloc = imp_testing::vmm::CidAllocator::new();
    let vmid_alloc = imp_testing::orchestrator::VmidAllocator::new();
    TestVm::start(vmm, cfg, &cid_alloc, vmid_alloc)
        .await
        .expect("start_vm: VM failed to start")
}

#[macro_export]
macro_rules! require_cap {
    ($caps:expr, $field:ident) => {
        if !$caps.$field {
            eprintln!("SKIP: backend lacks capability `{}`", stringify!($field));
            return;
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
                let $vmm = imp_testing::CloudHypervisor::new();
                $body
            }

            #[cfg(feature = "firecracker")]
            #[tokio::test]
            #[ignore = "needs KVM"]
            async fn firecracker() {
                let $vmm = imp_testing::Firecracker::new();
                $body
            }

            #[cfg(feature = "qemu")]
            #[tokio::test]
            #[ignore = "needs KVM"]
            async fn qemu() {
                let $vmm = imp_testing::Qemu::new();
                $body
            }
        }
    };
}
