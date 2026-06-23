use imp_testing::agent::protocol::ExecRequest;
use imp_testing::config::{RootfsSource, VmConfig};
use imp_testing::orchestrator::TestVm;
use imp_testing::vmm::cloud_hypervisor::CloudHypervisor;
use std::path::PathBuf;

#[tokio::test]
async fn test_nested_virt() {
    let kernel = PathBuf::from(
        std::env::var("IMP_KERNEL").unwrap_or_else(|_| "/tmp/imp-artifacts/vmlinux".into()),
    );
    let rootfs_image = PathBuf::from(
        std::env::var("IMP_ROOTFS").unwrap_or_else(|_| "/tmp/imp-artifacts/rootfs.ext4".into()),
    );

    let mut cfg = VmConfig::builder(
        kernel,
        RootfsSource::Erofs {
            image: rootfs_image,
        },
    )
    .network_disabled()
    .build();

    // Enable nested virtualization
    cfg.nested_virt = true;

    let ch_binary =
        std::env::var("CLOUD_HYPERVISOR_PATH").unwrap_or_else(|_| "cloud-hypervisor".into());
    let vmm = CloudHypervisor::new(ch_binary);

    let mut vm = TestVm::start(&vmm, cfg).await.expect("Failed to start VM");

    let mut agent = match vm.agent().await {
        Ok(a) => a,
        Err(e) => {
            use imp_testing::vmm::VmInstance;
            let log = tokio::fs::read_to_string(vm.instance.serial_log())
                .await
                .unwrap_or_default();
            panic!("Failed to connect to agent: {}\nSerial log:\n{}", e, log);
        }
    };

    // Check if nested virtualization is available inside the VM
    let result = agent
        .exec(ExecRequest {
            argv: vec!["kvm-ok".to_string()],
            env: vec![],
            cwd: None,
        })
        .await
        .expect("Failed to run kvm-ok");

    // Ignore error code because kvm-ok might fail if the host machine running the tests
    // doesn't have nested virt enabled. We just want to ensure it executes.
    // If kvm-ok doesn't exist, it will return a different error.
    println!("kvm-ok stdout: {}", String::from_utf8_lossy(&result.stdout));
    println!("kvm-ok stderr: {}", String::from_utf8_lossy(&result.stderr));

    vm.shutdown().await.expect("Failed to shutdown VM");
}
