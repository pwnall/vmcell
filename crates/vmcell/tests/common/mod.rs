#![allow(dead_code)]

//! Shared integration-test harness. The generally-reusable VM-boot + capability primitives were
//! **extracted** into `vmcell_artifact_validator::harness` (design §5.4, The guest-kernel contract and the bootstrap seed / §8.5, Lineage: fork and branch) so the artifact
//! validator and these tests share one implementation; they are re-exported here so the existing
//! `common::…` call sites keep working. The genuinely test-only helpers (skip manifest, netns/nft
//! residue tooling) and the `vmm_matrix_test!` / `require_cap!` macros stay here.

// Extracted, now shared with the validator (single source of truth). Each test binary uses a
// different subset, so allow the re-export to be partially unused per binary.
#[allow(unused_imports)]
pub use vmcell_artifact_validator::harness::{
    ch_bin, fc_bin, get_rootfs, get_vmlinux, has_cap_net_admin, qemu_bin, start_vm,
};

/// Recomputes the cgroup-v2 slice name the orchestrator assigns to a VM, so a residue check can
/// target the *actual* (possibly systemd-/runner-nested) path. Test-only (residue tooling).
pub fn computed_cgroup_name(vmid: u32) -> String {
    if let Ok(cgroup_str) = std::fs::read_to_string("/proc/self/cgroup")
        && let Some(base) = vmcell::metrics::cgroup_base_from_proc(&cgroup_str)
    {
        return format!("{base}/vmcell-vm-{vmid}");
    }
    format!("vmcell-vm-{vmid}")
}

/// Records a capability-driven test skip to a durable, run-scoped manifest so the skip is an
/// auditable artifact rather than an invisible nextest pass (H-TEST-3). Best-effort by design.
pub fn record_capability_skip(vmm: &str, capability: &str) {
    use std::io::Write as _;
    let path = std::env::var_os("VMCELL_SKIP_MANIFEST")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            std::env::temp_dir().join(format!("vmcell-skips-{}.txt", std::process::id()))
        });
    let line = format!("SKIP {vmm} {capability}\n");
    match std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        Ok(mut f) => {
            if let Err(e) = f.write_all(line.as_bytes()) {
                eprintln!(
                    "record_capability_skip: append to {} failed: {e}",
                    path.display()
                );
            }
        }
        Err(e) => eprintln!(
            "record_capability_skip: open {} failed: {e}",
            path.display()
        ),
    }
}

/// Reaps orphaned `vmcell-net-*` network namespaces before a privileged/netns test. Test-only.
pub fn clean_vmcell_netns() {
    // Match by the same one-law filter the VM naming produces (default prefix), not a hard-coded string.
    let netns_prefix = vmcell::naming::netns_sweep_prefix(vmcell::naming::DEFAULT_RESOURCE_PREFIX);
    let removed = vmcell::net::cleanup_orphan_netns(&netns_prefix);
    if !removed.is_empty() {
        println!("clean_vmcell_netns: reaped orphaned namespaces: {removed:?}");
    }
}

/// Reads the applied nftables ruleset for `table` inside network namespace `netns` from the host
/// (the host-observable side of the H-PROXY-1 TPROXY check). Test-only.
pub fn nft_list_table_in_netns(netns: &str, table: &str) -> Option<String> {
    let out = std::process::Command::new("ip")
        .args(["netns", "exec", netns, "nft", "list", "table"])
        .args(table.split_whitespace())
        .output()
        .ok()?;
    if out.status.success() {
        Some(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        None
    }
}

#[macro_export]
macro_rules! require_cap {
    ($caps:expr, $field:ident, $vmm:expr) => {
        if !$caps.$field {
            if vmcell::vmm::Vmm::id(&$vmm) == "cloud-hypervisor" {
                panic!("SKIP == PASS ERROR: Primary backend (cloud-hypervisor) MUST support capability `{}`", stringify!($field));
            } else {
                $crate::common::record_capability_skip(
                    vmcell::vmm::Vmm::id(&$vmm),
                    stringify!($field),
                );
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
                let $vmm = vmcell_firecracker::Firecracker::new(super::common::fc_bin());
                $body
            }

            #[cfg(feature = "qemu")]
            #[tokio::test]
            #[ignore = "needs KVM"]
            async fn qemu() {
                let $vmm = vmcell_qemu::Qemu::new(super::common::qemu_bin());
                $body
            }
        }
    };
}
