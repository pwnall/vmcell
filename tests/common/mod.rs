#![allow(dead_code)]

use std::path::PathBuf;

pub fn get_vmlinux() -> PathBuf {
    let p = std::env::var("IMP_KERNEL")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/tmp/imp-artifacts/vmlinux"));
    assert!(p.exists(), "vmlinux artifact missing at {:?}", p);
    p
}

pub fn get_rootfs() -> PathBuf {
    let p = std::env::var("IMP_ROOTFS")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/tmp/imp-artifacts/rootfs.erofs"));
    assert!(p.exists(), "rootfs artifact missing at {:?}", p);
    p
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
    let cid_alloc = std::sync::Arc::new(imp_testing::vmm::CidAllocator::new());
    let vmid_alloc = imp_testing::orchestrator::VmidAllocator::new();
    TestVm::start(
        vmm,
        cfg,
        cid_alloc,
        vmid_alloc,
        Box::new(imp_testing::metrics::DefaultCgroupFs),
    )
    .await
    .expect("start_vm: VM failed to start")
}

#[macro_export]
macro_rules! require_cap {
    ($caps:expr, $field:ident, $vmm:expr) => {
        if !$caps.$field {
            if imp_testing::vmm::Vmm::id(&$vmm) == "cloud-hypervisor" {
                panic!("SKIP == PASS ERROR: Primary backend (cloud-hypervisor) MUST support capability `{}`", stringify!($field));
            } else {
                println!("SKIP: backend `{}` lacks capability `{}`", imp_testing::vmm::Vmm::id(&$vmm), stringify!($field));
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
                let $vmm = imp_testing::vmm::cloud_hypervisor::CloudHypervisor::new(
                    super::common::ch_bin(),
                );
                $body
            }

            #[cfg(feature = "firecracker")]
            #[tokio::test]
            #[ignore = "needs KVM"]
            async fn firecracker() {
                let $vmm = imp_testing::vmm::firecracker::Firecracker::new(super::common::fc_bin());
                $body
            }

            #[cfg(feature = "qemu")]
            #[tokio::test]
            #[ignore = "needs KVM"]
            async fn qemu() {
                let $vmm = imp_testing::vmm::qemu::Qemu::new(super::common::qemu_bin());
                $body
            }
        }
    };
}
