//! Reusable VM-boot and host-capability primitives, **extracted** from vmcell's
//! `tests/common/mod.rs` so the validator and the integration tests share one implementation
//! (design; AGENTS.md "don't triplicate; extract"). The test crate re-exports these.

use std::path::PathBuf;

use vmcell::{MicroVm, VmConfig, Vmm};

/// The **two-step route** every getter failure names (design §10.4, The downstream toolkit
/// contract) — stated once, appended by [`fail_loud`] to all three failure messages.
///
/// [`vmcell::artifact::ensure_test_artifacts`] is the *vmcell workspace's* test bootstrap: its
/// fingerprint hashes the steward source closure out of the vmcell tree, so it structurally
/// cannot build in a consumer workspace. Its own messages therefore name vmcell-checkout-only
/// fixes (`cargo run -p vmcell-cli …`, "steward binary source missing at …"), which is a dead
/// end for a downstream caller. §10.4 specifies the substitution instead: overlay-driven *build*
/// through the toolkit, getter-driven *consumption* through the env contract — so the route out is
/// part of the refusal, not something a consumer has to already know.
///
/// It rides every failure rather than only the ones that look downstream, because "am I
/// downstream?" has no honest local predicate: this example workspace lives *inside* the vmcell
/// checkout, so the source-root ascent finds vmcell's tree and any presence test would answer
/// "in-workspace" for a genuinely downstream-shaped consumer. In the vmcell workspace itself this
/// only adds a sentence to an already-failing path.
const TWO_STEP_ROUTE: &str = "\n  Consuming vmcell as a dependency? The workspace artifact \
     bootstrap cannot run against your checkout. Two steps instead: (1) BUILD — kernels through \
     the toolkit (`vmcell::artifact::build_labelled_kernel`, or `vmcell build-kernels --pins \
     <overlay>` from a vmcell checkout), the rootfs with that checkout's `vmcell build` / \
     `vmcell oci2-erofs`; (2) CONSUME — point `VMCELL_KERNEL` and `VMCELL_ROOTFS` at those outputs \
     (`VMCELL_ROOTFS` makes the bootstrap a full no-op). See design §10.4 / the README's \
     \"Consuming vmcell as a dependency\" section.";

/// The one refusal composer for the getters: the concrete problem, then [`TWO_STEP_ROUTE`].
///
/// One law, one predicate — three call sites (the bootstrap failure and the two existence checks)
/// that each formatted their own message would drift, and §10.4's promise is about *every* way the
/// getters can refuse, not just the one a reader happens to hit.
fn fail_loud(problem: &str) -> String {
    format!("{problem}{TWO_STEP_ROUTE}")
}

/// The built `vmlinux` artifact path (`VMCELL_KERNEL` or `target/vmcell-artifacts/vmlinux`),
/// asserting it exists — the tests' known-good kernel.
///
/// First calls [`vmcell::artifact::ensure_test_artifacts`], which builds the steward /
/// guest-tools / rootfs **at most once per session** (hash-gated) and fails loud with a one-command
/// fix if the kernel is not pre-built — so a source edit to the steward, tools, or packer no longer
/// silently runs against a stale rootfs.
///
/// Downstream (§10.4) it has exactly two behaviors: with `VMCELL_KERNEL` + `VMCELL_ROOTFS` set —
/// the documented downstream configuration, in which `VMCELL_ROOTFS` no-ops the bootstrap — it
/// returns the named path after an existence check; without them it fails loud naming
/// the two-step route (build through the toolkit, then point the two variables at the outputs),
/// never a silent bootstrap attempt against a consumer's cargo checkout.
///
/// # Panics
/// Panics if the kernel is missing or the auto-build fails, naming the two-step route.
#[must_use]
pub fn get_vmlinux() -> PathBuf {
    ensure_artifacts_or_panic();
    let p = vmcell::artifact::kernel_path();
    assert!(
        p.exists(),
        "{}",
        fail_loud(&format!("vmlinux artifact missing at {p:?}"))
    );
    p
}

/// The built erofs rootfs artifact path (`VMCELL_ROOTFS` or the default), asserting it exists.
///
/// Auto-builds via [`vmcell::artifact::ensure_test_artifacts`] first, and has the same two
/// downstream behaviors (see [`get_vmlinux`]).
///
/// # Panics
/// Panics if the rootfs is missing or the auto-build fails, naming the two-step route.
#[must_use]
pub fn get_rootfs() -> PathBuf {
    ensure_artifacts_or_panic();
    let p = vmcell::artifact::rootfs_path();
    assert!(
        p.exists(),
        "{}",
        fail_loud(&format!("rootfs artifact missing at {p:?}"))
    );
    p
}

/// Runs the at-most-once, hash-gated artifact build; a failure (missing kernel, or a build error)
/// aborts the test with the underlying message plus the downstream route — the fail-loud contract
/// these getters have always had, now with an actionable instruction instead of a bare "artifact
/// missing". Rendered via `assert!` (not a bare `panic!`) to match the getters' existing pattern
/// and the crate's lints.
fn ensure_artifacts_or_panic() {
    let outcome = vmcell::artifact::ensure_test_artifacts();
    assert!(
        outcome.is_ok(),
        "{}",
        fail_loud(
            &outcome
                .as_ref()
                .err()
                .map(ToString::to_string)
                .unwrap_or_default()
        )
    );
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

/// The crosvm binary (`VMCELL_CROSVM_BIN` or `crosvm`).
#[must_use]
pub fn crosvm_bin() -> String {
    std::env::var("VMCELL_CROSVM_BIN").unwrap_or_else(|_| "crosvm".to_string())
}

/// Probes the process's **effective** capability set for capability `bit` via `/proc/self/status`
/// `CapEff:` — the §13 (Cross-cutting invariants)-consistent gate: the capability runner grants caps ambiently without a
/// full-root uid, so a `geteuid()==0` gate checks the wrong thing.
#[must_use]
pub fn has_effective_cap(bit: u32) -> bool {
    let Ok(status) = std::fs::read_to_string("/proc/self/status") else {
        return false;
    };
    for line in status.lines() {
        if let Some(hex) = line.strip_prefix("CapEff:")
            && let Ok(bits) = u64::from_str_radix(hex.trim(), 16)
        {
            return bits & (1u64 << bit) != 0;
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
/// precondition for the per-VM memory-limit contract (§7, Resource monitoring and limits). Best-effort: reads the current
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
    let env = vmcell::HostEnv::hermetic();
    MicroVm::start(vmm, cfg, &env).await
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
