use imp_testing::agent::protocol::ExecRequest;
use imp_testing::config::{RootfsSource, VmConfig};
use imp_testing::orchestrator::TestVm;

use std::path::PathBuf;

mod common;

vmm_matrix_test!(nested_virt, |vmm| {
    require_cap!(imp_testing::vmm::Vmm::capabilities(&vmm), nested_virt, vmm);
    test_nested_virt_impl(&vmm).await;
});

async fn test_nested_virt_impl<V: imp_testing::vmm::Vmm>(vmm: &V) {
    let kernel = PathBuf::from(
        std::env::var("IMP_KERNEL").unwrap_or_else(|_| "/tmp/imp-artifacts/vmlinux".into()),
    );
    let rootfs_image = PathBuf::from(
        std::env::var("IMP_ROOTFS").unwrap_or_else(|_| "/tmp/imp-artifacts/rootfs.erofs".into()),
    );

    let mut cfg = VmConfig::builder(
        kernel,
        RootfsSource::Erofs {
            image: rootfs_image,
        },
    )
    .network_disabled()
    .build()
    .unwrap();

    // Enable nested virtualization
    cfg.nested_virt = true;

    let cid_alloc = std::sync::Arc::new(imp_testing::vmm::CidAllocator::new());
    let vmid_alloc = imp_testing::orchestrator::VmidAllocator::new();
    let mut vm = TestVm::start(
        vmm,
        cfg,
        cid_alloc.clone(),
        vmid_alloc,
        Box::new(imp_testing::metrics::DefaultCgroupFs),
    )
    .await
    .expect("Failed to start VM");

    let agent = match vm.agent(None, &imp_testing::orchestrator::RealClock).await {
        Ok(a) => a,
        Err(e) => {
            use imp_testing::vmm::VmInstance;
            let log = tokio::fs::read_to_string(vm.instance().serial_log())
                .await
                .unwrap_or_default();
            panic!("Failed to connect to agent: {}\nSerial log:\n{}", e, log);
        }
    };

    // Check if nested virtualization is available inside the VM
    let result = agent
        .exec(ExecRequest::new(vec!["kvm-ok".to_string()]))
        .await
        .expect("Failed to run kvm-ok");

    println!("kvm-ok stdout: {}", String::from_utf8_lossy(&result.stdout));
    println!("kvm-ok stderr: {}", String::from_utf8_lossy(&result.stderr));

    assert_eq!(
        result.code, 0,
        "kvm-ok returned non-zero code, meaning nested virt is unavailable"
    );

    vm.shutdown().await.expect("Failed to shutdown VM");
}
