use imp_testing::agent::protocol::ExecRequest;
use imp_testing::config::{RootfsSource, VmConfig};
use imp_testing::orchestrator::TestVm;
use imp_testing::vmm::VmInstance;
use imp_testing::vmm::cloud_hypervisor::CloudHypervisor;
use std::path::PathBuf;

mod common;

#[tokio::test]
#[ignore]
async fn test_snapshot_restore_ch() {
    let ch_binary =
        std::env::var("CLOUD_HYPERVISOR_PATH").unwrap_or_else(|_| "cloud-hypervisor".into());
    let vmm = CloudHypervisor::new(ch_binary);
    test_snapshot_restore_impl(&vmm).await;
}

#[cfg(feature = "firecracker")]
#[tokio::test]
#[ignore]
async fn test_snapshot_restore_fc() {
    let vmm = imp_testing::vmm::firecracker::Firecracker::new(common::fc_bin());
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

    let snapshot_dir = std::env::temp_dir().join("imp-test-snapshot-restore");
    if snapshot_dir.exists() {
        std::fs::remove_dir_all(&snapshot_dir).unwrap();
    }

    let cid_alloc = imp_testing::vmm::CidAllocator::new();
    let vmid_alloc = std::sync::Arc::new(imp_testing::orchestrator::VmidAllocator::new());

    // 1. Create a VM and take a snapshot
    {
        let cfg = VmConfig::builder(
            kernel.clone(),
            RootfsSource::Erofs {
                image: rootfs_image.clone(),
            },
        )
        .network_disabled()
        .build()
        .unwrap();

        let mut vm = TestVm::start(vmm, cfg, &cid_alloc, vmid_alloc.clone())
            .await
            .expect("Failed to start VM");

        let agent = match vm.agent().await {
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
        let pre_mac = String::from_utf8_lossy(&mac_out.stdout).trim().to_string();

        // Capture pre-snapshot time
        let time_out = agent
            .exec(ExecRequest::new(vec!["date".into(), "+%s".into()]))
            .await
            .unwrap();
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

        vm.shutdown().await.expect("Failed to shutdown VM");

        // Write test state so it can be asserted in block 2
        std::fs::write(snapshot_dir.join("pre_mac.txt"), pre_mac).unwrap();
        std::fs::write(snapshot_dir.join("pre_time.txt"), pre_time.to_string()).unwrap();
        std::fs::write(
            snapshot_dir.join("original_cid.txt"),
            original_cid.to_string(),
        )
        .unwrap();
    }

    // Sleep to ensure the host clock advances past the guest's suspended clock
    tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;

    // 2. Restore from snapshot
    {
        let cfg = VmConfig::builder(
            kernel.clone(),
            RootfsSource::Erofs {
                image: rootfs_image.clone(),
            },
        )
        .network_disabled()
        .build()
        .unwrap();

        let mut vm = TestVm::restore(vmm, &snapshot_dir, cfg, &cid_alloc, vmid_alloc)
            .await
            .expect("Failed to restore VM");

        // This implicitly tests vsock reconnect and CID rotation because the agent
        // client connects using the restored VM's newly allocated CID.
        let result = vm
            .agent()
            .await
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

        // Resync the clock manually via agent
        let host_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        vm.agent()
            .await
            .unwrap()
            .exec(ExecRequest::new(vec![
                "date".into(),
                "-s".into(),
                format!("@{}", host_time),
            ]))
            .await
            .unwrap();

        let original_cid: u32 = std::fs::read_to_string(snapshot_dir.join("original_cid.txt"))
            .unwrap()
            .parse()
            .unwrap();
        let new_cid = vm.instance().guest_cid();
        assert_ne!(original_cid, new_cid, "CID should be rotated after restore");

        let pre_mac = std::fs::read_to_string(snapshot_dir.join("pre_mac.txt")).unwrap();
        let mac_out = vm
            .agent()
            .await
            .unwrap()
            .exec(ExecRequest::new(vec![
                "cat".into(),
                "/sys/class/net/eth0/address".into(),
            ]))
            .await
            .unwrap();
        let post_mac = String::from_utf8_lossy(&mac_out.stdout).trim().to_string();
        if !pre_mac.is_empty() {
            assert_ne!(
                pre_mac, post_mac,
                "MAC address should be rotated after restore"
            );
        }

        let pre_time: i64 = std::fs::read_to_string(snapshot_dir.join("pre_time.txt"))
            .unwrap()
            .parse()
            .unwrap();
        let time_out = vm
            .agent()
            .await
            .unwrap()
            .exec(ExecRequest::new(vec!["date".into(), "+%s".into()]))
            .await
            .unwrap();
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

        vm.shutdown().await.expect("Failed to shutdown restored VM");
    }
}
