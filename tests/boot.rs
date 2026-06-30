use vmcell::MicroVm;
use vmcell::config::{RootfsSource, VmConfig};
use vmcell::vmm::VmInstance;

mod common;

vmm_matrix_test!(boot, |vmm| {
    test_boot_impl(&vmm).await;
});

async fn test_boot_impl<V: vmcell::vmm::Vmm>(vmm: &V) {
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
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    let log = std::fs::read_to_string(vm.instance().serial_log()).unwrap_or_default();
    println!("SERIAL LOG:\n{}", log);

    let serial_log = vm.instance().serial_log().to_path_buf();

    let mut booted = false;
    for _ in 0..100 {
        if serial_log.exists() {
            let log_content = tokio::fs::read_to_string(&serial_log)
                .await
                .unwrap_or_default();
            if log_content.contains("Linux version") {
                booted = true;
                break;
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    assert!(booted, "VM failed to boot (did not see expected log line)");

    let agent = vm
        .agent(
            Some(std::time::Duration::from_secs(60)),
            &vmcell::orchestrator::RealClock,
        )
        .await
        .expect("Failed to connect to agent");

    let outcome = agent
        .exec(vmcell::agent::ExecRequest::new(vec![
            "echo".to_string(),
            "hello from guest".to_string(),
        ]))
        .await
        .expect("exec failed");

    assert_eq!(outcome.code, 0, "exec returned non-zero code");
    let stdout = String::from_utf8_lossy(&outcome.stdout);
    assert!(
        stdout.contains("hello from guest"),
        "expected stdout to contain 'hello from guest', got: {}",
        stdout
    );

    vm.shutdown().await.expect("Failed to shutdown VM");
}
