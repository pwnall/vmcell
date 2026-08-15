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
    ch_bin, crosvm_bin, fc_bin, get_rootfs, get_vmlinux, has_cap_net_admin, qemu_bin, start_vm,
};

/// Recomputes the cgroup-v2 slice name the orchestrator assigns to a VM, so a residue check can
/// target the *actual* (possibly systemd-/runner-nested) path. Test-only (residue tooling).
///
/// F2 / d3: the whole composition — leaf **and** sibling placement — is delegated to
/// `vmcell::naming::vm_slice_name`, the one law. This helper used to re-type the `{base}/{leaf}`
/// join, which made it a second copy of the very rule the residue checks exist to catch drift in;
/// the law is now `pub`, so there is nothing left to copy.
pub fn computed_cgroup_name(vmid: u32) -> String {
    vmcell::naming::vm_slice_name(vmcell::naming::DEFAULT_RESOURCE_PREFIX, vmid)
}

/// The environment variable that keeps a [`TempTree`] on disk for post-mortem inspection.
///
/// Strictly parsed at construction (AGENTS.md "every accepted input is honored or rejected"):
/// unset / `""` / `"0"` remove the tree, `"1"` keeps it, anything else panics.
pub const KEEP_TEMP_ENV: &str = "VMCELL_KEEP_TEST_TEMP";

/// Owns a test-created scratch path under [`std::env::temp_dir`] so its `Drop` removes the whole
/// tree — on the success path **and** on panic.
///
/// The defect this closes: every scratch path here used to be cleaned by a trailing
/// `let _ = std::fs::remove_dir_all(&dir)` at the bottom of the test body, which an assertion
/// panic (or a `.expect()` on a live-VM step) skips entirely — and a nextest retry re-runs the
/// same test, so one flaky live test leaked once per attempt. `tests/snapshot_restore.rs` had no
/// removal at all: its ~129 MB guest-RAM snapshot dir accumulated per run per backend until the
/// host `/tmp` hit its quota and the daemon suite went red on `Disk quota exceeded`. Ownership
/// owns cleanup, so the cleanup cannot be skipped by a control-flow path nobody thought about.
///
/// Names are **unchanged** from the hand-rolled sites (tests and operators grep for them); the
/// helper only takes over the *ownership*. The path stays under `std::env::temp_dir()` so it
/// tracks `TMPDIR` and matches where `vmm::VmTempDir` puts the per-VM scratch dir the residue
/// checks in `tests/lifecycle.rs` assert against.
///
/// Set `VMCELL_KEEP_TEST_TEMP=1` ([`KEEP_TEMP_ENV`]) to keep the tree for post-mortem inspection
/// after a failing live test; the drop then prints the retained path instead of removing it.
pub struct TempTree {
    path: std::path::PathBuf,
    keep: bool,
}

impl TempTree {
    /// Owns `<temp_dir>/<name>` **without** creating it, after removing any residue already there.
    ///
    /// For paths the code under test creates itself — a snapshot directory, a lineage scratch
    /// tree, a mock-server UDS socket — where pre-creating would mask the creation behavior (or,
    /// for a socket, break the `bind`).
    pub fn reserve(name: &str) -> Self {
        let path = std::env::temp_dir().join(Self::checked_name(name));
        remove_tree(&path).unwrap_or_else(|e| {
            panic!(
                "TempTree::reserve: clearing residue at {} failed: {e}",
                path.display()
            )
        });
        Self {
            path,
            keep: keep_requested(),
        }
    }

    /// [`TempTree::reserve`] plus `create_dir_all`, for the sites that need the directory to exist
    /// before the test writes into it.
    pub fn create(name: &str) -> Self {
        let tree = Self::reserve(name);
        std::fs::create_dir_all(&tree.path)
            .unwrap_or_else(|e| panic!("TempTree::create: {} failed: {e}", tree.path.display()));
        tree
    }

    /// The owned path.
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }

    /// A path inside the owned tree; it dies with the owner.
    pub fn join(&self, rel: impl AsRef<std::path::Path>) -> std::path::PathBuf {
        self.path.join(rel)
    }

    /// Keeps the tree on drop regardless of the environment — the explicit, per-site form of the
    /// [`KEEP_TEMP_ENV`] opt-in, and what lets the gate drive the retention branch without
    /// mutating the process-global environment.
    pub fn retain(mut self) -> Self {
        self.keep = true;
        self
    }

    /// Rejects a name that would put the tree somewhere other than one child of the temp dir — an
    /// empty, `..`-bearing or separator-bearing name turns the `Drop` below into a
    /// `remove_dir_all` of a directory the test does not own. The `vmcell-` prefix keeps every
    /// test scratch path inside the one namespace an operator can sweep by hand.
    fn checked_name(name: &str) -> &str {
        let want = format!("{}-", vmcell::naming::DEFAULT_RESOURCE_PREFIX);
        assert!(
            name.starts_with(&want),
            "TempTree name {name:?} must start with {want:?} so it stays in the sweepable namespace"
        );
        assert!(
            std::path::Path::new(name).components().count() == 1
                && !name.contains(std::path::MAIN_SEPARATOR)
                && !name.contains('\0'),
            "TempTree name {name:?} must be a single path component under the temp dir"
        );
        name
    }
}

impl Drop for TempTree {
    fn drop(&mut self) {
        if self.keep {
            eprintln!(
                "TempTree: retention requested ({KEEP_TEMP_ENV}=1 or `retain()`), keeping {} for \
                 post-mortem inspection",
                self.path.display()
            );
            return;
        }
        // Best-effort *and* loud: a `Drop` cannot propagate, and panicking here would mask the
        // test's own failure, so a removal error is reported rather than swallowed.
        if let Err(e) = remove_tree(&self.path) {
            eprintln!("TempTree: removing {} failed: {e}", self.path.display());
        }
    }
}

/// Removes `path` whether it is a directory tree, a file, or a socket; absent is success.
fn remove_tree(path: &std::path::Path) -> std::io::Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(md) if md.is_dir() => std::fs::remove_dir_all(path),
        Ok(_) => std::fs::remove_file(path),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// Whether [`KEEP_TEMP_ENV`] asks for the tree to be retained.
fn keep_requested() -> bool {
    keep_from_env_value(std::env::var_os(KEEP_TEMP_ENV).as_deref())
}

/// The strict parse of a [`KEEP_TEMP_ENV`] value, split out so the gate can drive it directly
/// instead of mutating the process-global environment out from under the rest of the binary.
/// Unset / `""` / `"0"` remove; `"1"` keeps; anything else is REJECTED (fail loud) rather than
/// silently read as "remove".
pub fn keep_from_env_value(value: Option<&std::ffi::OsStr>) -> bool {
    match value {
        None => false,
        Some(v) => match v.to_str() {
            Some("") | Some("0") => false,
            Some("1") => true,
            other => panic!("{KEEP_TEMP_ENV} must be unset, \"0\" or \"1\"; got {other:?}"),
        },
    }
}

/// Records a capability-driven test skip to a durable, run-scoped manifest so the skip is an
/// auditable artifact rather than an invisible nextest pass (H-TEST-3). Best-effort by design.
///
/// The manifest is deliberately **not** a [`TempTree`]: it is the run's audit artifact, read after
/// the suite exits (`just`'s recipes point `VMCELL_SKIP_MANIFEST` at a durable path), so an owner
/// that deleted it would delete the evidence.
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

/// Reaps orphaned `vmcell-net-*` **and** `vmcell-seg-*` network namespaces before a
/// privileged/netns test. Test-only.
///
/// v30 §18 delta 8: the segment class needs its **own** sweep call. `cleanup_orphan_netns` filters
/// by a literal starts-with prefix, and `netns_sweep_prefix` is `vmcell-net-` — so before this,
/// a leaked `vmcell-seg-*` was reaped by nothing at all (not this helper, not
/// `HostOrphanScanner::scan_netns`), and an aborted segment test poisoned the next run's segid.
pub fn clean_vmcell_netns() {
    // Match by the same one-law filters the naming produces (default prefix), not hard-coded
    // strings. Both classes, because the two stems are deliberately distinct.
    for prefix in [
        vmcell::naming::netns_sweep_prefix(vmcell::naming::DEFAULT_RESOURCE_PREFIX),
        vmcell::naming::segment_netns_sweep_prefix(vmcell::naming::DEFAULT_RESOURCE_PREFIX),
    ] {
        let removed = vmcell::net::cleanup_orphan_netns(&prefix);
        if !removed.is_empty() {
            println!("clean_vmcell_netns: reaped orphaned namespaces: {removed:?}");
        }
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

            #[cfg(feature = "crosvm")]
            #[tokio::test]
            #[ignore = "needs KVM"]
            async fn crosvm() {
                let $vmm = vmcell_crosvm::Crosvm::new(super::common::crosvm_bin());
                $body
            }
        }
    };
}
