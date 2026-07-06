//! fork()/branch() lineage integration test (§21.4).
//!
//! Boots one VM to agent-ready, roots a [`Lineage`] by suspending it, then
//! exercises the fork/branch handle on real micro-VMs and asserts on the **data
//! plane** (exec output), not proxy signals:
//!
//! - `Lineage::fork` mints a live child (a CoW clone materialized through the
//!   injected `OverlayStore` seam, §12.24); it execs correctly and gets a distinct
//!   vmid / `mac_math(vmid)` identity (§9.2).
//! - `Lineage::branch` freezes a **diverged** running child (one that wrote a
//!   marker file into its tmpfs) into a new node; a fork from that node **sees the
//!   marker** while a fork from the root does **not** — proving branch captured the
//!   child's current state, and that the lineage is a real tree of provenance
//!   (§12.25), not a flat re-clone of the original.
//!
//! `#[ignore = "needs KVM"]` via `vmm_matrix_test!`; skips backends without
//! `snapshot_restore` visibly (H-TEST-3), never silently. Every fork here is a
//! **single** clone, so the chain works on both the host-path-rotating (CH) and
//! verbatim-rebind (FC) tiers — the sequential single-lineage shape both support.

use std::sync::Arc;
use vmcell::agent::protocol::ExecRequest;
use vmcell::config::{Egress, NetConfig, RootfsSource, VmConfig};
use vmcell::lineage::{Lineage, LineageAllocator};
use vmcell::metrics::DefaultCgroupFs;
use vmcell::orchestrator::{MicroVm, RealClock, VmidAllocator};
use vmcell::overlay::OverlayStore;
use vmcell::vmm::{CidAllocator, VmInstance, Vmm};
use vmcell::ReflinkOverlayStore;

mod common;

vmm_matrix_test!(fork_branch_lineage, |vmm| {
    require_cap!(vmcell::vmm::Vmm::capabilities(&vmm), snapshot_restore, vmm);
    fork_branch_lineage_impl(&vmm).await;
});

async fn fork_branch_lineage_impl<V: Vmm>(vmm: &V) {
    common::clean_vmcell_netns();
    if !common::has_cap_net_admin() {
        panic!(
            "SKIP: fork/branch lineage needs CAP_NET_ADMIN for privileged tap networking; \
             not present in the effective capability set"
        );
    }

    let kernel = common::get_vmlinux();
    let rootfs = common::get_rootfs();
    // Snapshot-eligible base: erofs rootfs, privileged tap net, no vhost-user (§12.1).
    let base_cfg = || {
        let mut cfg = VmConfig::builder(
            kernel.clone(),
            RootfsSource::Erofs {
                image: rootfs.clone(),
            },
        )
        .build()
        .expect("valid base config");
        cfg.net = NetConfig::Privileged {
            egress: Egress::Open,
            host_services_port: None,
        };
        cfg
    };

    let id = uuid::Uuid::new_v4();
    let scratch = std::env::temp_dir().join(format!("vmcell-lineage-{}-{}", std::process::id(), id));
    // `fork_from_vm` / `branch` create these dirs themselves — do NOT pre-create
    // them, so the test also proves that dir-creation behavior.
    let root_dir = scratch.join("root");
    let b1_dir = scratch.join("b1");

    let cid_alloc = Arc::new(CidAllocator::new());
    let vmid_alloc = VmidAllocator::new();
    let store: Arc<dyn OverlayStore> = Arc::new(ReflinkOverlayStore);
    let alloc = LineageAllocator::new();

    // 1. Boot a base VM to agent-ready, then ROOT a lineage by suspending it.
    let mut base = MicroVm::start(
        vmm,
        base_cfg(),
        cid_alloc.clone(),
        vmid_alloc.clone(),
        Box::new(DefaultCgroupFs),
    )
    .await
    .expect("start base VM");
    if let Err(e) = base.agent(None, &RealClock).await {
        let log = std::fs::read_to_string(base.instance().serial_log()).unwrap_or_default();
        println!("BASE SERIAL LOG:\n{log}");
        panic!("base agent connect failed: {e}");
    }
    let root = Lineage::fork_from_vm(&mut base, base_cfg(), &root_dir, alloc, store)
        .await
        .expect("root a lineage by suspending the base VM");
    base.shutdown().await.expect("shutdown base VM");
    assert_eq!(root.generation(), 0, "root is generation 0");
    assert_eq!(root.parent(), None, "root has no parent");
    println!("lineage root CoW support: {:?}", root.probe_cow_support());

    // 2. fork() a child from the root; exec on the DATA PLANE; then DIVERGE it by
    //    writing a marker into its tmpfs.
    let mut child = fork_one(&root, vmm, &cid_alloc, &vmid_alloc, "root-child").await;
    let hello = exec(&mut child, &["echo", "hello"]).await;
    assert_eq!(hello.0, 0, "forked child exec must succeed");
    assert_eq!(hello.1.trim(), "hello", "forked child data plane");

    // The child's guest MAC equals mac_math(its vmid) after the post-restore resync.
    let child_vmid = child.vmid();
    let mac = exec(&mut child, &["cat", "/sys/class/net/eth0/address"]).await;
    assert_eq!(
        mac.1.trim(),
        vmcell::net::mac_math(child_vmid).expect("mac_math"),
        "forked child guest MAC must equal mac_math(vmid={child_vmid})"
    );

    let wrote = exec(&mut child, &["sh", "-c", "echo diverged > /tmp/marker"]).await;
    assert_eq!(wrote.0, 0, "writing the divergence marker must succeed");
    let readback = exec(&mut child, &["cat", "/tmp/marker"]).await;
    assert_eq!(readback.1.trim(), "diverged", "marker must be present in the diverged child");

    // 3. branch() the DIVERGED child into a new node b1 (child stays live). Assert
    //    the lineage metadata (§12.25).
    let b1 = root
        .branch(&mut child, &b1_dir)
        .await
        .expect("branch the diverged child into a new lineage node");
    assert_eq!(b1.generation(), 1, "branch is generation 1");
    assert_eq!(b1.parent(), Some(root.id()), "branch parent is the root");
    assert_eq!(b1.ancestry(), &[root.id()], "branch ancestry is [root]");
    assert!(root.is_ancestor_of(&b1), "root is an ancestor of its branch");
    // The child survived the branch (branch takes &mut, never consumes it).
    assert_eq!(child.vmid(), child_vmid, "branch must not disturb the live child's identity");
    child.shutdown().await.expect("shutdown the branched child");

    // 4. THE PROOF: a fork from b1 SEES the marker (branch captured the diverged
    //    state); a fork from the ROOT does NOT (root is the pre-divergence image).
    //    Kept SEQUENTIAL (each fork torn down before the next) so the chain also
    //    holds on the verbatim-rebind (FC) tier, where two live restores from one
    //    baked-path lineage would collide (§9.4) — the single-lineage shape.
    let mut from_branch = fork_one(&b1, vmm, &cid_alloc, &vmid_alloc, "b1-child").await;
    let seen = exec(&mut from_branch, &["cat", "/tmp/marker"]).await;
    assert_eq!(seen.0, 0, "a fork from the branch must find the marker (exit 0)");
    assert_eq!(
        seen.1.trim(),
        "diverged",
        "a fork from the branch inherits the diverged state captured by branch()"
    );
    from_branch.shutdown().await.expect("shutdown branch fork");

    let mut from_root = fork_one(&root, vmm, &cid_alloc, &vmid_alloc, "root-child-2").await;
    let absent = exec(&mut from_root, &["cat", "/tmp/marker"]).await;
    assert_ne!(
        absent.0, 0,
        "a fork from the ROOT must NOT see the marker — root is the pre-divergence image (negative control)"
    );
    from_root.shutdown().await.expect("shutdown root fork");
    let _ = std::fs::remove_dir_all(&scratch);
}

/// Forks one live clone from `node`, brings its agent up (fail-loud with the serial
/// log on failure), and returns it.
async fn fork_one<V: Vmm>(
    node: &Lineage,
    vmm: &V,
    cid_alloc: &Arc<CidAllocator>,
    vmid_alloc: &VmidAllocator,
    label: &str,
) -> MicroVm<V> {
    let mut vm = node
        .fork(
            vmm,
            cid_alloc.clone(),
            vmid_alloc.clone(),
            Box::new(DefaultCgroupFs),
        )
        .await
        .unwrap_or_else(|e| panic!("fork {label} failed: {e}"));
    let log_path = vm.instance().serial_log().to_path_buf();
    if let Err(e) = vm.agent(None, &RealClock).await {
        let log = std::fs::read_to_string(&log_path).unwrap_or_default();
        println!("{label} SERIAL LOG:\n{log}");
        panic!("{label} agent connect failed: {e}");
    }
    vm
}

/// Execs `argv` and returns `(exit_code, stdout_string)`.
async fn exec<V: Vmm>(vm: &mut MicroVm<V>, argv: &[&str]) -> (i32, String) {
    let out = vm
        .agent(None, &RealClock)
        .await
        .expect("agent")
        .exec(ExecRequest::new(argv.iter().map(|s| (*s).to_string()).collect()))
        .await
        .expect("exec");
    (out.code, String::from_utf8_lossy(&out.stdout).to_string())
}
