use imp_testing::agent::protocol::ExecRequest;
use imp_testing::config::{RootfsSource, VmConfig};
use imp_testing::orchestrator::TestVm;
use imp_testing::vmm::VmInstance;

mod common;

vmm_matrix_test!(snapshot_restore, |vmm| {
    require_cap!(
        imp_testing::vmm::Vmm::capabilities(&vmm),
        snapshot_restore,
        vmm
    );
    test_snapshot_restore_impl(&vmm).await;
});

async fn test_snapshot_restore_impl<V: imp_testing::vmm::Vmm>(vmm: &V) {
    let kernel = common::get_vmlinux();
    let rootfs_image = common::get_rootfs();

    let id = uuid::Uuid::new_v4();
    let snapshot_dir = std::env::temp_dir().join(format!(
        "imp-test-snapshot-restore-{}-{}",
        std::process::id(),
        id
    ));
    if snapshot_dir.exists() {
        std::fs::remove_dir_all(&snapshot_dir).unwrap();
    }

    let cid_alloc = std::sync::Arc::new(imp_testing::vmm::CidAllocator::new());
    let vmid_alloc = imp_testing::orchestrator::VmidAllocator::new();

    // 1. Create a VM and take a snapshot
    {
        if unsafe { libc::geteuid() } != 0 {
            panic!("Skipping test: requires root privileges for privileged networking");
        }

        let mut cfg = VmConfig::builder(
            kernel.clone(),
            RootfsSource::Erofs {
                image: rootfs_image.clone(),
            },
        )
        .build()
        .unwrap();
        cfg.net = imp_testing::config::NetConfig::Privileged {
            egress: imp_testing::config::Egress::Open,
            host_services_port: None,
        };

        let mut vm = TestVm::start(
            vmm,
            cfg,
            cid_alloc.clone(),
            vmid_alloc.clone(),
            Box::new(imp_testing::metrics::DefaultCgroupFs),
        )
        .await
        .expect("Failed to start VM");

        let agent = match vm.agent(None, &imp_testing::orchestrator::RealClock).await {
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
        cfg.net = imp_testing::config::NetConfig::Privileged {
            egress: imp_testing::config::Egress::Open,
            host_services_port: None,
        };

        let mut vm = TestVm::restore(
            vmm,
            &snapshot_dir,
            cfg,
            cid_alloc.clone(),
            vmid_alloc,
            Box::new(imp_testing::metrics::DefaultCgroupFs),
        )
        .await
        .expect("Failed to restore VM");

        // This implicitly tests vsock reconnect and CID rotation because the agent
        // client connects using the restored VM's newly allocated CID.
        let log_path = vm.instance().serial_log().to_path_buf();
        let agent_res = vm.agent(None, &imp_testing::orchestrator::RealClock).await;
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
        assert_ne!(original_cid, new_cid, "CID should be rotated after restore");

        let original_vsock =
            std::fs::read_to_string(snapshot_dir.join("original_vsock.txt")).unwrap();
        let new_vsock = vm.instance().vsock_path().to_str().unwrap();
        assert_ne!(
            original_vsock, new_vsock,
            "Vsock path should be rotated after restore"
        );

        let pre_mac = std::fs::read_to_string(snapshot_dir.join("pre_mac.txt")).unwrap();
        let mac_out = vm
            .agent(None, &imp_testing::orchestrator::RealClock)
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
        assert_ne!(
            pre_mac, post_mac,
            "MAC address should be rotated after restore"
        );

        let pre_time: i64 = std::fs::read_to_string(snapshot_dir.join("pre_time.txt"))
            .unwrap()
            .parse()
            .unwrap();

        let fake_time_secs = (pre_time + 1000) as u64;
        let fake_clock = imp_testing::orchestrator::FakeClock {
            time: std::time::UNIX_EPOCH + std::time::Duration::from_secs(fake_time_secs),
        };

        let agent_client = vm.agent(None, &fake_clock).await.unwrap();

        let time_out = agent_client
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

        assert_eq!(
            post_time, fake_time_secs as i64,
            "Clock resync should strictly set guest clock to the injected FakeClock time"
        );

        let rng_out = agent_client
            .exec(ExecRequest::new(vec![
                "sh".into(),
                "-c".into(),
                "head -c 32 /dev/hwrng > /dev/urandom".into(),
            ]))
            .await
            .unwrap();
        assert_eq!(
            rng_out.code,
            0,
            "RNG reseed should succeed by reading from /dev/hwrng into /dev/urandom: {:?}",
            String::from_utf8_lossy(&rng_out.stderr)
        );

        vm.shutdown().await.expect("Failed to shutdown restored VM");
    }
}
