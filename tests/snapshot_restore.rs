use imp_testing::agent::protocol::ExecRequest;
use imp_testing::config::{RootfsSource, VmConfig};
use imp_testing::orchestrator::TestVm;
use imp_testing::vmm::VmInstance;
use imp_testing::vmm::cloud_hypervisor::CloudHypervisor;
use std::path::PathBuf;

mod common;

#[tokio::test]
#[serial_test::serial]
#[ignore]
async fn test_snapshot_restore_ch() {
    let ch_binary =
        std::env::var("CLOUD_HYPERVISOR_PATH").unwrap_or_else(|_| "cloud-hypervisor".into());
    let vmm = CloudHypervisor::new(ch_binary);
    test_snapshot_restore_impl(&vmm).await;
}

#[cfg(feature = "firecracker")]
#[tokio::test]
#[serial_test::serial]
#[ignore]
async fn test_snapshot_restore_fc() {
    let vmm = imp_testing::vmm::firecracker::Firecracker::new(common::fc_bin());
    test_snapshot_restore_impl(&vmm).await;
}

#[cfg(feature = "qemu")]
#[tokio::test]
#[serial_test::serial]
#[ignore]
async fn test_snapshot_restore_qemu() {
    let vmm = imp_testing::vmm::qemu::Qemu::new(common::qemu_bin());
    test_snapshot_restore_impl(&vmm).await;
}

async fn test_snapshot_restore_impl<V: imp_testing::vmm::Vmm>(vmm: &V) {
    if !vmm.capabilities().snapshot_restore {
        println!("Skipping snapshot restore test because VMM does not support it");
        return;
    }
    let kernel = PathBuf::from(
        std::env::var("IMP_KERNEL").unwrap_or_else(|_| "/tmp/imp-artifacts/vmlinux".into()),
    );
    let rootfs_image = PathBuf::from(
        std::env::var("IMP_ROOTFS").unwrap_or_else(|_| "/tmp/imp-artifacts/rootfs.erofs".into()),
    );

    static COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let id = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let snapshot_dir = std::env::temp_dir().join(format!(
        "imp-test-snapshot-restore-{}-{}",
        std::process::id(),
        id
    ));
    if snapshot_dir.exists() {
        std::fs::remove_dir_all(&snapshot_dir).unwrap();
    }

    let cid_alloc = imp_testing::vmm::CidAllocator::new();
    let vmid_alloc = imp_testing::orchestrator::VmidAllocator::new();

    // 1. Create a VM and take a snapshot
    {
        if unsafe { libc::geteuid() } != 0 {
            println!("Skipping test: requires root privileges for privileged networking");
            return;
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

        let mut vm = TestVm::start(vmm, cfg, &cid_alloc, vmid_alloc.clone(), Box::new(imp_testing::metrics::DefaultCgroupFs::default()))
            .await
            .expect("Failed to start VM");

        let agent = match vm.agent(None).await {
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

        // Capture pre-snapshot time
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

        let rng_out = agent
            .exec(ExecRequest::new(vec![
                "sh".into(),
                "-c".into(),
                "head -c 32 /dev/urandom | base64".into(),
            ]))
            .await
            .unwrap();
        assert_eq!(
            rng_out.code,
            0,
            "Failed to get RNG: {:?}",
            String::from_utf8_lossy(&rng_out.stderr)
        );
        let pre_rng = String::from_utf8_lossy(&rng_out.stdout).trim().to_string();

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
        std::fs::write(snapshot_dir.join("pre_rng.txt"), pre_rng).unwrap();
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

        let mut vm = TestVm::restore(vmm, &snapshot_dir, cfg, &cid_alloc, vmid_alloc, Box::new(imp_testing::metrics::DefaultCgroupFs::default()))
            .await
            .expect("Failed to restore VM");

        // This implicitly tests vsock reconnect and CID rotation because the agent
        // client connects using the restored VM's newly allocated CID.
        let log_path = vm.instance().serial_log().to_path_buf();
        let agent_res = vm.agent(None).await;
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
            .agent(None)
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
        let time_out = vm
            .agent(None)
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
        assert!(
            post_time >= pre_time + 2,
            "Clock should have resynced forward (pre: {}, post: {})",
            pre_time,
            post_time
        );

        let pre_rng = std::fs::read_to_string(snapshot_dir.join("pre_rng.txt")).unwrap();
        let rng_out = vm
            .agent(None)
            .await
            .unwrap()
            .exec(ExecRequest::new(vec![
                "sh".into(),
                "-c".into(),
                "head -c 32 /dev/urandom | base64".into(),
            ]))
            .await
            .unwrap();
        assert_eq!(
            rng_out.code,
            0,
            "Failed to get post-snapshot RNG: {:?}",
            String::from_utf8_lossy(&rng_out.stderr)
        );
        let post_rng = String::from_utf8_lossy(&rng_out.stdout).trim().to_string();
        assert_ne!(
            pre_rng, post_rng,
            "RNG entropy should be reseeded after restore"
        );

        vm.shutdown().await.expect("Failed to shutdown restored VM");
    }
}
