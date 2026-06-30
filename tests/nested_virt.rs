use vmcell::agent::protocol::ExecRequest;
use vmcell::config::{RootfsSource, VmConfig};
use vmcell::orchestrator::MicroVm;

mod common;

vmm_matrix_test!(nested_virt, |vmm| {
    require_cap!(vmcell::vmm::Vmm::capabilities(&vmm), nested_virt, vmm);
    test_nested_virt_impl(&vmm).await;
});

async fn test_nested_virt_impl<V: vmcell::vmm::Vmm>(vmm: &V) {
    let kernel = common::get_vmlinux();
    let rootfs_image = common::get_rootfs();

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

    let agent = match vm.agent(None, &vmcell::orchestrator::RealClock).await {
        Ok(a) => a,
        Err(e) => {
            use vmcell::vmm::VmInstance;
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
