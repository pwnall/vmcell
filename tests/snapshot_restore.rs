use imp_testing::agent::protocol::ExecRequest;
use imp_testing::config::{RootfsSource, VmConfig};
use imp_testing::orchestrator::TestVm;
use imp_testing::vmm::VmInstance;
use imp_testing::vmm::cloud_hypervisor::CloudHypervisor;
use std::path::PathBuf;

#[tokio::test]
async fn test_snapshot_restore() {
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

    let ch_binary =
        std::env::var("CLOUD_HYPERVISOR_PATH").unwrap_or_else(|_| "cloud-hypervisor".into());
    let vmm = CloudHypervisor::new(ch_binary);

    // 1. Create a VM and take a snapshot
    {
        let cfg = VmConfig::builder(
            kernel.clone(),
            RootfsSource::Erofs {
                image: rootfs_image.clone(),
            },
        )
        .network_disabled()
        .build().unwrap();

        let mut vm = TestVm::start(&vmm, cfg).await.expect("Failed to start VM");

        let mut agent = match vm.agent().await {
            Ok(a) => a,
            Err(e) => {
                let log = std::fs::read_to_string(vm.instance().serial_log()).unwrap_or_default();
                println!("SERIAL LOG:\n{}", log);
                panic!("Failed to connect to agent: {}", e);
            }
        };
        let _ = agent
            .exec(ExecRequest::new(vec!["true".to_string()]))
            .await
            .unwrap();

        std::fs::create_dir_all(&snapshot_dir).unwrap();
        vm.instance_mut()
            .snapshot(&snapshot_dir)
            .await
            .expect("Failed to create snapshot");

        vm.shutdown().await.expect("Failed to shutdown VM");
    }

    // 2. Restore from snapshot
    {
        let mut cfg = VmConfig::builder(
            kernel.clone(),
            RootfsSource::Erofs {
                image: rootfs_image.clone(),
            },
        )
        .network_disabled()
        .build().unwrap();

        let mut vm = TestVm::restore(&vmm, &snapshot_dir, cfg)
            .await
            .expect("Failed to restore VM");

        let mut agent = vm
            .agent()
            .await
            .expect("Failed to connect to agent after restore");
        let result = agent
            .exec(ExecRequest::new(vec!["echo".to_string(), "restored".to_string()]))
            .await
            .unwrap();
        if String::from_utf8_lossy(&result.stdout).trim() != "restored" {
            let log = std::fs::read_to_string(vm.instance().serial_log()).unwrap();
            println!("SERIAL LOG:\n{}", log);
            panic!("Exec failed. Outcome: {:?}", result);
        }

        vm.shutdown().await.expect("Failed to shutdown restored VM");
    }
}
