use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use vmcell::MicroVm;
use vmcell::config::{RootfsSource, VmConfig};
use vmcell::vmm::VmInstance;
use vmcell::vmm::cloud_hypervisor::CloudHypervisor;

mod common;

/// A `CgroupFs` seam that records every create/delete into a shared timeline.
///
/// Two modes: `with_log` shares the `FakeVmm`'s call vector so cgroup teardown is
/// interleaved with the VMM-instance `drop` event (lets us assert teardown
/// *order*); `new` gives an isolated, no-op-but-recording fake so the FakeVmm
/// orchestration tests stay hermetic (no real `/sys/fs/cgroup` writes) without
/// polluting the VMM call timeline.
#[derive(Debug, Clone)]
struct RecordingCgroupFs {
    log: Arc<Mutex<Vec<String>>>,
}

impl RecordingCgroupFs {
    fn new() -> Self {
        Self {
            log: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn with_log(log: Arc<Mutex<Vec<String>>>) -> Self {
        Self { log }
    }
}

impl vmcell::metrics::CgroupFs for RecordingCgroupFs {
    fn create_slice(
        &self,
        name: &str,
        _limits: &vmcell::config::ResourceLimits,
    ) -> vmcell::error::Result<()> {
        self.log
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(format!("cgroup_create:{}", name));
        Ok(())
    }
    fn delete_slice(&self, name: &str) -> vmcell::error::Result<()> {
        self.log
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(format!("cgroup_delete:{}", name));
        Ok(())
    }
    fn read_stats(&self, _name: &str) -> vmcell::error::Result<vmcell::metrics::ResourceUsage> {
        Ok(vmcell::metrics::ResourceUsage::default())
    }
    fn add_task(&self, _name: &str, _pid: u32) -> vmcell::error::Result<()> {
        Ok(())
    }
}

#[tokio::test]
#[ignore = "needs KVM"]
async fn test_lifecycle_force_kill_ch() {
    let vmm = CloudHypervisor::new(common::ch_bin());
    test_lifecycle_force_kill_impl(&vmm).await;
}

#[cfg(feature = "firecracker")]
#[tokio::test]
#[ignore = "needs KVM"]
async fn test_lifecycle_force_kill_fc() {
    let vmm = vmcell::vmm::firecracker::Firecracker::new(common::fc_bin());
    test_lifecycle_force_kill_impl(&vmm).await;
}

#[cfg(feature = "qemu")]
#[tokio::test]
#[ignore = "needs KVM"]
async fn test_lifecycle_force_kill_qemu() {
    let vmm = vmcell::vmm::qemu::Qemu::new(common::qemu_bin());
    test_lifecycle_force_kill_impl(&vmm).await;
}

async fn test_lifecycle_force_kill_impl<V: vmcell::vmm::Vmm>(vmm: &V) {
    let vmlinux = common::get_vmlinux();
    let rootfs = common::get_rootfs();

    let cfg = VmConfig::builder(vmlinux, RootfsSource::Erofs { image: rootfs })
        .network_disabled()
        .build()
        .unwrap();

    let cid_alloc = std::sync::Arc::new(vmcell::vmm::CidAllocator::new());
    let vmid_alloc = vmcell::orchestrator::VmidAllocator::new();
    let mut vm = MicroVm::start(
        vmm,
        cfg,
        cid_alloc.clone(),
        vmid_alloc,
        Box::new(vmcell::metrics::DefaultCgroupFs),
    )
    .await
    .expect("Failed to start VM");

    vm.instance_mut().kill().await.expect("Failed to kill VM");
}

// TESTS-LIFECYCLE-5: drive the FakeVmm-backed orchestrator across a start and a
// restore cycle on SHARED allocators, asserting CID/VMID allocation order,
// uniqueness, release-on-shutdown, and the agent connect timeout branch. All
// non-KVM; uses a hermetic recording cgroup seam (no real /sys/fs/cgroup writes).
#[tokio::test]
async fn test_lifecycle_fake_vmm() {
    use vmcell::vmm::FakeVmm;
    let fake = FakeVmm::default();

    let cfg = VmConfig::builder(
        "/fake/kernel",
        RootfsSource::Erofs {
            image: PathBuf::from("/fake/rootfs"),
        },
    )
    .network_disabled()
    .build()
    .unwrap();

    let cid_alloc = std::sync::Arc::new(vmcell::vmm::CidAllocator::new());
    let vmid_alloc = vmcell::orchestrator::VmidAllocator::new();

    // --- cycle 1: cold start ---
    let vm = MicroVm::start(
        &fake,
        cfg.clone(),
        cid_alloc.clone(),
        vmid_alloc.clone(),
        Box::new(RecordingCgroupFs::new()),
    )
    .await
    .expect("Failed to start fake VM");

    // Check that create and boot were called
    {
        let calls = fake.calls.lock().unwrap();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0], "create");
        assert_eq!(calls[1], "boot");
    }

    let vmid1 = vm.vmid();
    assert!(
        (1..=254).contains(&vmid1),
        "vmid must be a valid /30 host id"
    );
    // start() allocated the lowest guest CID (3); the next free is therefore 4. A
    // buggy orchestrator that never allocated a CID would hand back 3 here.
    let probe = cid_alloc.allocate().expect("cid available");
    assert_eq!(
        probe, 4,
        "start() must have taken guest CID 3, leaving 4 next"
    );
    cid_alloc.release(probe);

    // Shutdown should call request_shutdown, kill, then drop the instance.
    vm.shutdown().await.expect("Failed to shutdown");

    // The FakeVmInstance records calls in the same shared vector
    {
        let calls = fake.calls.lock().unwrap();
        assert_eq!(calls[2], "request_shutdown");
        assert_eq!(calls[3], "kill");
        assert_eq!(calls[4], "drop");
    }
    // Drop released BOTH the CID and the VMID back to their allocators (the
    // no-op-release bug would leave them held).
    assert_eq!(
        cid_alloc.allocate().expect("cid available"),
        3,
        "shutdown must release guest CID 3"
    );
    cid_alloc.release(3);
    assert!(
        vmid_alloc.reserve(vmid1).is_ok(),
        "shutdown must release VMID {}",
        vmid1
    );
    vmid_alloc.release(vmid1);

    // --- cycle 2: restore, reusing the shared allocators ---
    let mut restore_vm = MicroVm::restore(
        &fake,
        std::path::Path::new("/fake/snap"),
        cfg.clone(),
        cid_alloc.clone(),
        vmid_alloc.clone(),
        Box::new(RecordingCgroupFs::new()),
    )
    .await
    .expect("Failed to restore fake VM");

    {
        let calls = fake.calls.lock().unwrap();
        assert_eq!(calls[5], "restore");
        assert_eq!(calls[6], "resume");
    }

    let vmid2 = restore_vm.vmid();
    assert!((1..=254).contains(&vmid2));
    // A fresh VMID allocation must not collide with the live restored VM's VMID.
    let probe_vmid = vmid_alloc.allocate().expect("vmid available");
    assert_ne!(probe_vmid, vmid2, "a live VMID must not be re-handed-out");
    vmid_alloc.release(probe_vmid);
    // restore() also took the lowest free guest CID (3 again, cycle 1's was freed).
    let probe_cid = cid_alloc.allocate().expect("cid available");
    assert_eq!(probe_cid, 4, "restore() must have taken guest CID 3");
    cid_alloc.release(probe_cid);

    // Retry/timeout branch: the fake instance's vsock path does not exist, so the
    // agent connect loop must exhaust its deadline and surface a typed Timeout —
    // not hang (would trip the nextest timeout) and not falsely report success.
    let agent_res = restore_vm
        .agent(
            Some(std::time::Duration::from_secs(1)),
            &vmcell::orchestrator::RealClock,
        )
        .await;
    assert!(
        matches!(&agent_res, Err(vmcell::Error::Timeout(_))),
        "agent() over an unreachable fake vsock must time out (is_err={})",
        agent_res.is_err()
    );

    restore_vm.shutdown().await.expect("Failed to shutdown");
}

// TESTS-LIFECYCLE-3: a panic inside the VM scope must leave ZERO host residue.
// Uses privileged networking so netns + tap teardown is exercised, and targets
// the ACTUAL computed cgroup path (possibly nested under systemd/the capability
// runner) rather than the un-nested guess that made the old check trivially true.
// Serialization comes from the nextest `serial-host` group (TESTS-LIFECYCLE-7),
// not an ad-hoc `#[serial_test::serial]`.
#[tokio::test]
#[ignore = "needs KVM + CAP_NET_ADMIN (privileged tap networking)"]
async fn test_lifecycle_panic_residue_ch() {
    // Privileged tap networking needs CAP_NET_ADMIN; gate on the effective set.
    if !common::has_cap_net_admin() {
        panic!(
            "SKIP: panic-residue test needs CAP_NET_ADMIN for privileged tap networking; \
             not present in the effective capability set"
        );
    }

    // Reap orphaned vmcell-net-* namespaces from prior aborted runs (no sudo; the
    // capability runner has CAP_SYS_ADMIN + CAP_DAC_OVERRIDE).
    common::clean_vmcell_netns();

    let vmm = CloudHypervisor::new(common::ch_bin());
    let vmlinux = common::get_vmlinux();
    let rootfs = common::get_rootfs();

    let mut cfg = VmConfig::builder(vmlinux, RootfsSource::Erofs { image: rootfs })
        .build()
        .unwrap();
    cfg.net = vmcell::config::NetConfig::Privileged {
        egress: vmcell::config::Egress::Open,
        host_services_port: None,
    };

    let cid_alloc = std::sync::Arc::new(vmcell::vmm::CidAllocator::new());
    let vmid_alloc = vmcell::orchestrator::VmidAllocator::new();

    let (vmid, guest_cid, vsock_path) = {
        let vm = MicroVm::start(
            &vmm,
            cfg,
            cid_alloc.clone(),
            vmid_alloc.clone(),
            Box::new(vmcell::metrics::DefaultCgroupFs),
        )
        .await
        .expect("Failed to start VM");

        let vmid = vm.vmid();
        let guest_cid = vm.instance().guest_cid();
        let vsock_path = vm.instance().vsock_path().to_path_buf();

        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let _vm = vm;
            panic!("simulate panic inside scope");
        }));

        // Scope ends, but vm was already dropped during the panic unwind.
        (vmid, guest_cid, vsock_path)
    };

    // Give drop side effects a moment (process-group reap, netns delete).
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    // 1. Cgroup slice: target the ACTUAL computed name. A leak under the real
    //    (nested) path made the old `vmcell-vm-{vmid}` check pass trivially.
    let cg_path = format!("/sys/fs/cgroup/{}", common::computed_cgroup_name(vmid));
    assert!(
        !std::path::Path::new(&cg_path).exists(),
        "cgroup slice leaked at {}",
        cg_path
    );

    // 2. Named netns removed (its tap dies with it).
    let netns_path = format!("/var/run/netns/vmcell-net-{}", vmid);
    assert!(
        !std::path::Path::new(&netns_path).exists(),
        "netns leaked at {}",
        netns_path
    );

    // 3. The tap must not have been leaked onto the host.
    let host_tap = format!("/sys/class/net/imp-tap-{}", vmid);
    assert!(
        !std::path::Path::new(&host_tap).exists(),
        "tap interface leaked on host at {}",
        host_tap
    );

    // 4. The per-VM vsock socket (in the VM temp dir) is removed by the instance Drop.
    assert!(
        !vsock_path.exists(),
        "vsock socket leaked at {}",
        vsock_path.display()
    );

    // 4b. E3: the per-VM `/tmp/vmcell-vm-{pid}-{vmid}` DIRECTORY itself (holding
    //     serial.log, and api.sock.lock for CH) must also be removed on teardown —
    //     not just the vsock socket inside it. The leak fix landed in vmm/mod.rs
    //     (remove_vm_tmp_dir); without it `/tmp` grows one dir per VM, unbounded.
    //     The pid/vmid naming mirrors `vmm::create_vm_tmp_dir`.
    let per_vm_dir =
        std::env::temp_dir().join(format!("vmcell-vm-{}-{}", std::process::id(), vmid));
    assert!(
        !per_vm_dir.exists(),
        "per-VM temp dir leaked at {}",
        per_vm_dir.display()
    );

    // 5. CID released back to the allocator (Drop releases the real instance).
    assert_eq!(
        cid_alloc.allocate().expect("cid available"),
        guest_cid,
        "guest CID {} was not released on Drop",
        guest_cid
    );
    cid_alloc.release(guest_cid);

    // 6. VMID released back to the allocator on Drop.
    assert!(
        vmid_alloc.reserve(vmid).is_ok(),
        "VMID {} was not released on Drop",
        vmid
    );
    vmid_alloc.release(vmid);
}

/// Asserts the teardown order recorded in `log`: the VMM instance `drop` event
/// must precede the cgroup-slice `delete` — the documented order (VMM process
/// group -> netns/cgroup). Reordering Drop (deleting the cgroup before tearing
/// down the VMM, the documented hang/leak) flips these indices and fails.
fn assert_instance_before_cgroup(log: &[String]) {
    let drop_idx = log
        .iter()
        .position(|c| c == "drop")
        .unwrap_or_else(|| panic!("instance drop not recorded; timeline: {:?}", log));
    let cg_del_idx = log
        .iter()
        .position(|c| c.starts_with("cgroup_delete"))
        .unwrap_or_else(|| panic!("cgroup delete not recorded; timeline: {:?}", log));
    assert!(
        drop_idx < cg_del_idx,
        "VMM instance must be torn down before the cgroup slice; got timeline: {:?}",
        log
    );
}

// TESTS-LIFECYCLE-4: ordered teardown on a NORMAL drop. A shared recording cgroup
// seam writes into the SAME timeline as the FakeVmInstance's drop event, so the
// relative ORDER is observable and asserted (not just "drop happened").
//
// Limitation (noted): netns ordering is not reachable here. `setup_env` builds a
// real `NetNamespace` via the concrete `RtNetlink` only for Privileged net (needs
// CAP_NET_ADMIN), and there is no public seam to inject a recording netns from an
// integration test. The reachable, load-bearing invariant — VMM instance before
// cgroup — is asserted here; the real-VM panic-residue test covers actual netns
// cleanup.
#[tokio::test]
async fn test_lifecycle_fake_vmm_drop_order_normal() {
    use vmcell::vmm::FakeVmm;
    let fake = FakeVmm::default();
    let log = fake.calls.clone();

    let cfg = VmConfig::builder(
        "/fake/kernel",
        RootfsSource::Erofs {
            image: PathBuf::from("/fake/rootfs"),
        },
    )
    .network_disabled()
    .build()
    .unwrap();

    let cid_alloc = std::sync::Arc::new(vmcell::vmm::CidAllocator::new());
    let vmid_alloc = vmcell::orchestrator::VmidAllocator::new();

    {
        let _vm = MicroVm::start(
            &fake,
            cfg,
            cid_alloc.clone(),
            vmid_alloc,
            Box::new(RecordingCgroupFs::with_log(log.clone())),
        )
        .await
        .expect("Failed to start fake VM");
        // _vm is dropped here, at the end of the scope.
    }

    let calls = log.lock().unwrap();
    assert!(
        calls.contains(&"drop".to_string()),
        "FakeVmInstance drop should have been called"
    );
    assert_instance_before_cgroup(&calls);
}

// TESTS-LIFECYCLE-4: the same ordered teardown must hold when the VM is dropped
// during a PANIC unwind.
#[tokio::test]
async fn test_lifecycle_fake_vmm_drop_order_on_panic() {
    use vmcell::vmm::FakeVmm;
    let fake = FakeVmm::default();
    let log = fake.calls.clone();

    let cfg = VmConfig::builder(
        "/fake/kernel",
        RootfsSource::Erofs {
            image: PathBuf::from("/fake/rootfs"),
        },
    )
    .network_disabled()
    .build()
    .unwrap();

    let cid_alloc = std::sync::Arc::new(vmcell::vmm::CidAllocator::new());
    let vmid_alloc = vmcell::orchestrator::VmidAllocator::new();
    let cgroup_log = log.clone();

    let _ = tokio::spawn(async move {
        let _vm = MicroVm::start(
            &fake,
            cfg,
            cid_alloc.clone(),
            vmid_alloc,
            Box::new(RecordingCgroupFs::with_log(cgroup_log)),
        )
        .await
        .expect("Failed to start fake VM");
        panic!("simulate panic inside scope");
    })
    .await;

    let calls = log.lock().unwrap();
    // Verify drop was called on panic, AND that it preceded the cgroup teardown.
    assert!(
        calls.contains(&"drop".to_string()),
        "FakeVmInstance drop should have been called on panic"
    );
    assert_instance_before_cgroup(&calls);
}

// UNPRIVILEGED NAMING: a KVM-but-unprivileged smoke test of the unprivileged smoltcp NAT
// path (NetConfig::Unprivileged / vhost-user-net). Its NAME carries `unprivileged` and
// `smoltcp` so `just test-unprivileged` (filter `test(unprivileged) | test(smoltcp)`)
// selects it. #[ignore]'d for the default suite (needs KVM); runs WITHOUT
// privilege on a KVM host.
#[cfg(feature = "net-unprivileged")]
#[tokio::test]
#[ignore = "needs KVM (unprivileged smoltcp NAT); selected by `just test-unprivileged`"]
async fn test_lifecycle_unprivileged_smoltcp() {
    let vmm = CloudHypervisor::new(common::ch_bin());
    let caps = vmcell::vmm::Vmm::capabilities(&vmm);
    if !caps.unprivileged_vhost_user_net {
        panic!(
            "SKIP: backend `{}` lacks unprivileged vhost-user-net (unprivileged smoltcp) support",
            vmcell::vmm::Vmm::id(&vmm)
        );
    }

    let vmlinux = common::get_vmlinux();
    let rootfs = common::get_rootfs();

    let mut cfg = VmConfig::builder(vmlinux, RootfsSource::Erofs { image: rootfs })
        .build()
        .unwrap();
    cfg.net = vmcell::config::NetConfig::Unprivileged {
        egress: vmcell::config::Egress::Open,
        host_services_port: None,
    };

    let cid_alloc = std::sync::Arc::new(vmcell::vmm::CidAllocator::new());
    let vmid_alloc = vmcell::orchestrator::VmidAllocator::new();
    let mut vm = MicroVm::start(
        &vmm,
        cfg,
        cid_alloc.clone(),
        vmid_alloc,
        Box::new(vmcell::metrics::DefaultCgroupFs),
    )
    .await
    .expect("Failed to start unprivileged VM");

    let vmid = vm.vmid();
    // The unprivileged NAT exposes its vhost-user socket at this path.
    let sock_path = format!("/tmp/imp-smoltcp-{}.sock", vmid);

    let agent = match vm
        .agent(
            Some(std::time::Duration::from_secs(120)),
            &vmcell::orchestrator::RealClock,
        )
        .await
    {
        Ok(a) => a,
        Err(e) => {
            let log = std::fs::read_to_string(vm.instance().serial_log()).unwrap_or_default();
            panic!(
                "Failed to connect to agent over unprivileged networking: {}\nSERIAL LOG:\n{}",
                e, log
            );
        }
    };

    // eth0 is configured by the kernel ip= cmdline (zero-netlink PID 1); the
    // smoltcp NAT carries its traffic. Confirm the interface came up.
    let operstate = agent
        .exec(vmcell::ExecRequest::new(vec![
            "cat".into(),
            "/sys/class/net/eth0/operstate".into(),
        ]))
        .await
        .expect("exec failed");
    assert_eq!(
        operstate.code,
        0,
        "reading eth0 operstate failed: {:?}",
        String::from_utf8_lossy(&operstate.stderr)
    );
    let state = String::from_utf8_lossy(&operstate.stdout)
        .trim()
        .to_string();
    assert!(
        state == "up" || state == "unknown",
        "eth0 should be up over the unprivileged NAT, got operstate {:?}",
        state
    );

    let outcome = agent
        .exec(vmcell::ExecRequest::new(vec!["true".into()]))
        .await
        .expect("exec failed");
    assert_eq!(
        outcome.code, 0,
        "guest exec over the unprivileged vsock should succeed"
    );

    vm.shutdown()
        .await
        .expect("Failed to shutdown unprivileged VM");

    // Unprivileged teardown drops the SmoltcpProcess, whose vhost Listener unlinks the
    // NAT socket on drop. A leak here means teardown skipped the smoltcp process.
    assert!(
        !std::path::Path::new(&sock_path).exists(),
        "unprivileged smoltcp NAT socket {} must be cleaned up after shutdown",
        sock_path
    );
}
