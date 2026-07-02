use vmcell::agent::protocol::ExecRequest;
use vmcell::config::{RootfsSource, VmConfig};
use vmcell::orchestrator::MicroVm;
use vmcell::vmm::VmInstance;

mod common;

vmm_matrix_test!(snapshot_restore, |vmm| {
    require_cap!(vmcell::vmm::Vmm::capabilities(&vmm), snapshot_restore, vmm);
    test_snapshot_restore_impl(&vmm).await;
});

async fn test_snapshot_restore_impl<V: vmcell::vmm::Vmm>(vmm: &V) {
    // Reap any orphaned vmcell-net-* namespaces from a prior aborted run so this
    // privileged-tap test's vmid cannot collide with a leak (no sudo needed; the
    // capability runner holds CAP_SYS_ADMIN + CAP_DAC_OVERRIDE).
    common::clean_vmcell_netns();

    let kernel = common::get_vmlinux();
    let rootfs_image = common::get_rootfs();

    let id = uuid::Uuid::new_v4();
    let snapshot_dir = std::env::temp_dir().join(format!(
        "vmcell-test-snapshot-restore-{}-{}",
        std::process::id(),
        id
    ));
    if snapshot_dir.exists() {
        std::fs::remove_dir_all(&snapshot_dir).unwrap();
    }

    let cid_alloc = std::sync::Arc::new(vmcell::vmm::CidAllocator::new());
    let vmid_alloc = vmcell::orchestrator::VmidAllocator::new();

    // 1. Create a VM and take a snapshot
    {
        // TESTS-LIFECYCLE-6: gate on the effective CAP_NET_ADMIN (the §12.8
        // capability runner grants it ambiently), not euid==0.
        if !common::has_cap_net_admin() {
            panic!(
                "SKIP: snapshot/restore needs CAP_NET_ADMIN for privileged tap networking; \
                 not present in the effective capability set"
            );
        }

        let mut cfg = VmConfig::builder(
            kernel.clone(),
            RootfsSource::Erofs {
                image: rootfs_image.clone(),
            },
        )
        .build()
        .unwrap();
        cfg.net = vmcell::config::NetConfig::Privileged {
            egress: vmcell::config::Egress::Open,
            host_services_port: None,
        };

        let mut vm = MicroVm::start(
            vmm,
            cfg,
            cid_alloc.clone(),
            vmid_alloc.clone(),
            Box::new(vmcell::metrics::DefaultCgroupFs),
        )
        .await
        .expect("Failed to start VM");

        let agent = match vm.agent(None, &vmcell::orchestrator::RealClock).await {
            Ok(a) => a,
            Err(e) => {
                let log = std::fs::read_to_string(vm.instance().serial_log()).unwrap_or_default();
                println!("SERIAL LOG:\n{}", log);
                panic!("Failed to connect to agent: {}", e);
            }
        };

        // Capture pre-snapshot MAC
        let mac_out = agent
            .exec(ExecRequest::new(vec![
                "cat".into(),
                "/sys/class/net/eth0/address".into(),
            ]))
            .await
            .unwrap();
        assert_eq!(
            mac_out.code,
            0,
            "Failed to get MAC address: {:?}",
            String::from_utf8_lossy(&mac_out.stderr)
        );
        let pre_mac = String::from_utf8_lossy(&mac_out.stdout).trim().to_string();

        let time_out = agent
            .exec(ExecRequest::new(vec!["date".into(), "+%s".into()]))
            .await
            .unwrap();
        assert_eq!(
            time_out.code,
            0,
            "Failed to get time: {:?}",
            String::from_utf8_lossy(&time_out.stderr)
        );
        let pre_time: i64 = String::from_utf8_lossy(&time_out.stdout)
            .trim()
            .parse()
            .unwrap();

        let original_cid = vm.instance().guest_cid();

        std::fs::create_dir_all(&snapshot_dir).unwrap();
        vm.instance_mut()
            .snapshot(&snapshot_dir)
            .await
            .expect("Failed to create snapshot");

        // TESTS-LIFECYCLE-2: capture a reference CSPRNG sample. `snapshot()`
        // auto-resumes the VM, so its `/dev/urandom` state is exactly what the
        // snapshot froze. A restore that does NOT reseed will resume from this
        // identical frozen state and replay these same bytes; the orchestrator's
        // native post-restore reseed (a 32-byte /dev/hwrng → /dev/urandom copy in
        // the agent's `handle_resync`, design 44 §5) is what must perturb them.
        // NOTE: the test never issues its own reseed — it only
        // reads /dev/urandom here and after restore and asserts they differ.
        let ref_rng = vm
            .agent(None, &vmcell::orchestrator::RealClock)
            .await
            .unwrap()
            .exec(ExecRequest::new(vec![
                "head".into(),
                "-c".into(),
                "32".into(),
                "/dev/urandom".into(),
            ]))
            .await
            .unwrap();
        assert_eq!(
            ref_rng.code,
            0,
            "reference /dev/urandom read failed: {:?}",
            String::from_utf8_lossy(&ref_rng.stderr)
        );
        assert_eq!(
            ref_rng.stdout.len(),
            32,
            "expected 32 bytes of reference entropy"
        );
        std::fs::write(snapshot_dir.join("pre_urandom.bin"), &ref_rng.stdout).unwrap();

        let original_vmid = vm.vmid();
        let original_vsock = vm.instance().vsock_path().to_str().unwrap().to_string();
        vm.shutdown().await.expect("Failed to shutdown VM");

        // Write test state so it can be asserted in block 2
        std::fs::write(snapshot_dir.join("pre_mac.txt"), pre_mac).unwrap();
        std::fs::write(snapshot_dir.join("pre_time.txt"), pre_time.to_string()).unwrap();
        std::fs::write(
            snapshot_dir.join("original_cid.txt"),
            original_cid.to_string(),
        )
        .unwrap();
        std::fs::write(snapshot_dir.join("original_vsock.txt"), original_vsock).unwrap();
        std::fs::write(
            snapshot_dir.join("original_vmid.txt"),
            original_vmid.to_string(),
        )
        .unwrap();
    }

    // Sleep to ensure the host clock advances past the guest's suspended clock
    tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;

    // 2. Restore from snapshot
    {
        let mut cfg = VmConfig::builder(
            kernel.clone(),
            RootfsSource::Erofs {
                image: rootfs_image.clone(),
            },
        )
        .build()
        .unwrap();
        cfg.net = vmcell::config::NetConfig::Privileged {
            egress: vmcell::config::Egress::Open,
            host_services_port: None,
        };

        // M-TEST-RESTORE: hold the ORIGINAL vmid so the allocator is forced to hand
        // the restored VM a DIFFERENT one. MAC (`mac_math(vmid)`) and the vsock path
        // (`vmcell-vm-{pid}-{vmid}`) are pure functions of the vmid; the original VM was
        // already torn down (freeing its vmid), so without this the allocator could
        // re-hand the same vmid and the rotation asserts would pass on a no-op (or
        // fail spuriously ~1/254). Reserving it guarantees new_vmid != original_vmid.
        let original_vmid: u32 = std::fs::read_to_string(snapshot_dir.join("original_vmid.txt"))
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        vmid_alloc
            .reserve(original_vmid)
            .expect("original vmid is free after block 1 shutdown; reserving forces a new vmid");

        let mut vm = MicroVm::restore(
            vmm,
            &snapshot_dir,
            cfg,
            cid_alloc.clone(),
            vmid_alloc,
            Box::new(vmcell::metrics::DefaultCgroupFs),
        )
        .await
        .expect("Failed to restore VM");

        let new_vmid = vm.vmid();
        assert_ne!(
            new_vmid, original_vmid,
            "the restored VM must receive a vmid distinct from the held original"
        );

        // TESTS-LIFECYCLE-1: build the FakeClock BEFORE the first post-restore
        // agent() call. The orchestrator fires its one-shot clock resync on the
        // FIRST agent() after restore (it then flips `restored` to false), so the
        // injected clock is only consulted if it drives that first call. The old
        // code drove the first call with RealClock and the FakeClock on a later
        // (restored==false) call, making the FakeClock dead.
        let pre_time: i64 = std::fs::read_to_string(snapshot_dir.join("pre_time.txt"))
            .unwrap()
            .parse()
            .unwrap();
        let fake_time_secs = (pre_time + 1000) as u64;
        let fake_clock = vmcell::orchestrator::FakeClock {
            time: std::time::UNIX_EPOCH + std::time::Duration::from_secs(fake_time_secs),
        };

        // This implicitly tests vsock reconnect and CID rotation because the agent
        // client connects using the restored VM's newly allocated CID. It is also
        // the first post-restore agent() call, so it carries the one-shot clock
        // resync — driven here by the injected FakeClock.
        let log_path = vm.instance().serial_log().to_path_buf();
        let agent_res = vm.agent(None, &fake_clock).await;
        if agent_res.is_err() {
            let log = std::fs::read_to_string(&log_path).unwrap_or_default();
            println!("SERIAL LOG ON ERROR:\n{}", log);
            panic!("Failed to connect to agent: {:?}", agent_res.err().unwrap());
        }
        let result = agent_res
            .unwrap()
            .exec(ExecRequest::new(vec![
                "echo".to_string(),
                "restored".to_string(),
            ]))
            .await
            .unwrap();
        if String::from_utf8_lossy(&result.stdout).trim() != "restored" {
            let log = std::fs::read_to_string(vm.instance().serial_log()).unwrap();
            println!("SERIAL LOG:\n{}", log);
            panic!("Exec failed. Outcome: {:?}", result);
        }

        let original_cid: u32 = std::fs::read_to_string(snapshot_dir.join("original_cid.txt"))
            .unwrap()
            .parse()
            .unwrap();
        let new_cid = vm.instance().guest_cid();
        // The restore re-allocates a host-side guest CID (the agent reconnected
        // over it above). The design's "restored clones don't collide" guarantee is
        // enforced by the allocator's UNIQUENESS for *concurrent* live CIDs (see
        // vmm::tests::test_cid_allocator_prop), NOT by forcing a different number on
        // a *sequential* restore — here the original VM was already torn down, so
        // the allocator may legitimately hand its freed CID back. Assert the real
        // contract: a valid, live guest CID.
        let _ = original_cid;
        assert!(
            (3..=254).contains(&new_cid),
            "restored VM must have a valid guest CID, got {new_cid}"
        );

        let original_vsock =
            std::fs::read_to_string(snapshot_dir.join("original_vsock.txt")).unwrap();
        let new_vsock = vm.instance().vsock_path().to_str().unwrap();
        assert_ne!(
            original_vsock, new_vsock,
            "Vsock path should be rotated after restore"
        );
        // M-TEST-RESTORE: assert the REAL socket path embeds the rotated vmid
        // (vmcell-vm-{pid}-{new_vmid}), not merely that it differs — proving the path
        // reflects the new identity rather than a coincidental string difference.
        assert!(
            new_vsock.contains(&format!("vmcell-vm-{}-{}", std::process::id(), new_vmid)),
            "restored vsock path {} must embed the rotated vmid {}",
            new_vsock,
            new_vmid
        );

        let pre_mac = std::fs::read_to_string(snapshot_dir.join("pre_mac.txt")).unwrap();
        let mac_out = vm
            .agent(None, &vmcell::orchestrator::RealClock)
            .await
            .unwrap()
            .exec(ExecRequest::new(vec![
                "cat".into(),
                "/sys/class/net/eth0/address".into(),
            ]))
            .await
            .unwrap();
        assert_eq!(
            mac_out.code,
            0,
            "Failed to get post-snapshot MAC address: {:?}",
            String::from_utf8_lossy(&mac_out.stderr)
        );
        let post_mac = String::from_utf8_lossy(&mac_out.stdout).trim().to_string();
        assert!(!pre_mac.is_empty(), "MAC address should not be empty");
        // M-TEST-RESTORE: assert the IN-GUEST MAC equals mac_math(new_vmid) — the
        // positive identity proving the rotation set the correct new value. If the
        // rotation did not run, the guest keeps mac_math(original_vmid), which differs
        // from mac_math(new_vmid) (new != original, enforced above), so this goes red.
        // `assert_ne!(pre, post)` alone can pass on a no-op when a re-handed vmid
        // happens to yield an identical MAC.
        let expected_mac = vmcell::net::mac_math(new_vmid).expect("mac_math(new_vmid)");
        assert_eq!(
            post_mac, expected_mac,
            "post-restore guest MAC must equal mac_math(new_vmid={})",
            new_vmid
        );
        assert_ne!(
            pre_mac, post_mac,
            "MAC address should be rotated after restore"
        );

        // TESTS-LIFECYCLE-1: the resync on the first post-restore agent() call set
        // the guest clock from the injected FakeClock (≈ pre_time + 1000s), NOT
        // from real wall-clock time. `restored` is already false, so this read does
        // not re-trigger a resync.
        let time_out = vm
            .agent(None, &vmcell::orchestrator::RealClock)
            .await
            .unwrap()
            .exec(ExecRequest::new(vec!["date".into(), "+%s".into()]))
            .await
            .unwrap();
        assert_eq!(
            time_out.code,
            0,
            "Failed to get post-snapshot time: {:?}",
            String::from_utf8_lossy(&time_out.stderr)
        );
        let post_time: i64 = String::from_utf8_lossy(&time_out.stdout)
            .trim()
            .parse()
            .unwrap();
        // Equals the injected clock value, allowing a few seconds of guest ticking
        // between the resync and this read. A resync that ignored the injected
        // Clock (e.g. used RealClock) would land ≈1000s lower, near `pre_time`, and
        // fail the lower bound.
        assert!(
            post_time >= fake_time_secs as i64 && post_time < fake_time_secs as i64 + 30,
            "clock resync must set the guest clock to the INJECTED FakeClock time (≈{}), got {}; \
             a resync that ignored the injected Clock would land near real wall-clock time (≈{})",
            fake_time_secs,
            post_time,
            pre_time
        );

        // TESTS-LIFECYCLE-2 (reseed isolation): assert the orchestrator's TYPED
        // "reseed applied" result. The reseed (head -c 32 /dev/hwrng > /dev/urandom)
        // is best-effort and warn-and-continue, so inferring it solely from two
        // /dev/urandom reads differing can pass coincidentally even when the reseed
        // silently failed. `restore_reseed_applied()` is set on the first
        // post-restore agent() call (already made above) and records whether the
        // reseed command actually ran and returned exit 0 — Some(false)/None on a
        // silent failure flips this red. This is the control vs. the byte-difference
        // treatment asserted below.
        assert_eq!(
            vm.restore_reseed_applied(),
            Some(true),
            "the post-restore CSPRNG reseed must have APPLIED (exit 0); a silent \
             best-effort failure would leave the restored VM replaying predictable RNG state"
        );

        // TESTS-LIFECYCLE-2: assert the orchestrator's restore-path reseed
        // perturbed the frozen CSPRNG state captured in block 1. The test issues NO
        // reseed of its own. If the orchestrator reseed is deleted, the restored VM
        // replays the snapshot-frozen state and produces BYTE-IDENTICAL output,
        // failing this assert_ne.
        let pre_urandom = std::fs::read(snapshot_dir.join("pre_urandom.bin")).unwrap();
        let post_rng = vm
            .agent(None, &vmcell::orchestrator::RealClock)
            .await
            .unwrap()
            .exec(ExecRequest::new(vec![
                "head".into(),
                "-c".into(),
                "32".into(),
                "/dev/urandom".into(),
            ]))
            .await
            .unwrap();
        assert_eq!(
            post_rng.code,
            0,
            "post-restore /dev/urandom read failed: {:?}",
            String::from_utf8_lossy(&post_rng.stderr)
        );
        assert_eq!(post_rng.stdout.len(), 32, "expected 32 bytes of entropy");
        assert_eq!(
            pre_urandom.len(),
            32,
            "reference entropy sample missing/short"
        );
        assert_ne!(
            pre_urandom, post_rng.stdout,
            "post-restore CSPRNG output must differ from the snapshot-frozen reference: the \
             orchestrator's restore-path reseed (head -c 32 /dev/hwrng > /dev/urandom) must \
             perturb it. Identical bytes mean the reseed did not run and the restored VM is \
             replaying predictable RNG state."
        );

        vm.shutdown().await.expect("Failed to shutdown restored VM");
    }
}
