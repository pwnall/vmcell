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
/// `/sys/fs/cgroup/<name>` rather than the un-nested `vmcell-vm-<vmid>` guess. The
/// base-path derivation is delegated to `vmcell::metrics::cgroup_base_from_proc`
/// — the SAME canonical parser `orchestrator::MicroVm::setup_env` uses (H-HOST-3)
/// — so this cannot drift from the orchestrator and make the residue assertion
/// silently pass against a path that was never created.
pub fn computed_cgroup_name(vmid: u32) -> String {
    if let Ok(cgroup_str) = std::fs::read_to_string("/proc/self/cgroup") {
        if let Some(base) = vmcell::metrics::cgroup_base_from_proc(&cgroup_str) {
            return format!("{}/vmcell-vm-{}", base, vmid);
        }
    }
    format!("vmcell-vm-{}", vmid)
}

/// Records a capability-driven test skip to a durable, run-scoped manifest so the
/// skip becomes an auditable artifact rather than a nextest-captured (therefore
/// invisible) stdout line on a passing test — the "skip == pass" hazard H-TEST-3
/// names. The manifest path comes from `VMCELL_SKIP_MANIFEST` when set (a final CI
/// step can point it at a known file and diff the collected skips against the
/// expected set); otherwise it falls back to a per-process file under the temp
/// dir. The load-bearing red-on-inverse guard for a capability going dark is the
/// per-flag capability-honesty pin in each test file; this manifest is the audit
/// trail on top of that.
///
/// Best-effort by design: a manifest-write failure must never turn a legitimate
/// capability skip into a hard test failure, so the I/O errors are surfaced via
/// `eprintln!` and then intentionally not propagated.
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
        // Intentional discard of the write result: recording is best-effort, so a
        // failed append is logged but must not mask the capability skip as failure.
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

/// Reads the applied nftables ruleset for `table` inside network namespace
/// `netns` from the host, returning the `nft list table` stdout on success.
///
/// This is the host-observable side of the H-PROXY-1 / TEST-1 security check:
/// the privileged transparent-egress path is only "filtered" if the kernel in
/// the VM's netns actually carries the TPROXY ruleset. Reading the *applied*
/// ruleset (not the rendered string) reddens on an implementation that emits no
/// ruleset at all (fully-open default egress) — the `nft list table` fails, so
/// this returns `None`. Runs under the capability runner (`ip netns exec` needs
/// CAP_SYS_ADMIN, `nft` needs CAP_NET_ADMIN — both held on the privileged
/// suite); `nft` is present on any host where the privileged path can apply
/// rules in the first place.
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
                // H-TEST-3: a bare `println!` + `return` is scored by nextest as a
                // silent PASS (a passing test's stdout is captured and discarded),
                // so a capability regression that darkens an FC/QEMU leg would leave
                // no trace. Record the skip to a run-scoped manifest so it is a
                // durable, auditable artifact. The actual red-on-inverse guard for a
                // flag flipping is the per-flag capability-honesty pin in each test
                // file (runs in the default, non-KVM suite).
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
