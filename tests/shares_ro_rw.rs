use imp_testing::config::{Access, CachePolicy, RootfsSource, Share, VmConfig};
use imp_testing::vmm::VmInstance;

mod common;

// Part C: use the mandated `vmm_matrix_test!` + `require_cap!` harness instead of
// hand-rolled per-backend fns with a bare `return`-skip. `require_cap!` keeps the
// primary CH path unexempted (a CH cap miss panics) and emits one consistent
// skip-with-reason for FC/QEMU when `virtio_fs_shares` is unsupported. The macro
// also stamps each generated test `#[ignore = "needs KVM"]`.
vmm_matrix_test!(shares_ro_rw, |vmm| {
    require_cap!(
        imp_testing::vmm::Vmm::capabilities(&vmm),
        virtio_fs_shares,
        vmm
    );
    test_shares_ro_rw_impl(&vmm).await;
});

async fn test_shares_ro_rw_impl<V: imp_testing::vmm::Vmm>(backend: &V) {
    let id = uuid::Uuid::new_v4();
    let tmp = std::env::temp_dir().join(format!("imp-test-shares-{}-{}", std::process::id(), id));
    let in_dir = tmp.join("in");
    let out_dir = tmp.join("out");
    std::fs::create_dir_all(&in_dir).unwrap();
    std::fs::create_dir_all(&out_dir).unwrap();

    std::fs::write(in_dir.join("input.txt"), "hello world").unwrap();

    let vmlinux = common::get_vmlinux();
    let rootfs = common::get_rootfs();

    let _cfg = VmConfig::builder(vmlinux, RootfsSource::Erofs { image: rootfs })
        .with_share(Share::new(
            "imp-in",
            &in_dir,
            Access::ReadOnly,
            CachePolicy::Never,
        ))
        .with_share(Share::new(
            "imp-out",
            &out_dir,
            Access::ReadWrite,
            CachePolicy::Never,
        ))
        .network_disabled()
        .build()
        .unwrap();

    let cid_alloc = std::sync::Arc::new(imp_testing::vmm::CidAllocator::new());
    let vmid_alloc = imp_testing::orchestrator::VmidAllocator::new();
    let mut vm = imp_testing::TestVm::start(
        backend,
        _cfg,
        cid_alloc.clone(),
        vmid_alloc,
        Box::new(imp_testing::metrics::DefaultCgroupFs),
    )
    .await
    .expect("Failed to start VM");

    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    let mut client = imp_testing::agent::AgentClient::connect(
        vm.instance().vsock_path(),
        5000,
        std::time::Duration::from_secs(10),
        &imp_testing::vmm::RealSerialLog {
            path: vm.instance().serial_log().to_path_buf(),
        },
    )
    .await
    .expect("Failed to connect to agent");

    // Verify read from RO share
    let res = client
        .exec(imp_testing::agent::protocol::ExecRequest::new(vec![
            "cat".into(),
            "/imp-in/input.txt".into(),
        ]))
        .await
        .expect("Exec failed");
    if res.code != 0 {
        let log = std::fs::read_to_string(vm.instance().serial_log()).unwrap_or_default();
        panic!(
            "cat failed: {}\nSerial log: {}",
            String::from_utf8_lossy(&res.stderr),
            log
        );
    }
    assert_eq!(res.stdout, b"hello world");

    // Verify write to RO share fails
    let res = client
        .exec(imp_testing::agent::protocol::ExecRequest::new(vec![
            "sh".into(),
            "-c".into(),
            "echo fail > /imp-in/test.txt".into(),
        ]))
        .await
        .expect("Exec failed");
    assert_ne!(res.code, 0);

    // Verify write to RW share succeeds
    let res = client
        .exec(imp_testing::agent::protocol::ExecRequest::new(vec![
            "sh".into(),
            "-c".into(),
            "echo success > /imp-out/output.txt".into(),
        ]))
        .await
        .expect("Exec failed");
    assert_eq!(res.code, 0);

    let output = std::fs::read_to_string(out_dir.join("output.txt")).unwrap();
    assert_eq!(output, "success\n");

    imp_testing::vmm::VmInstance::kill(vm.instance_mut())
        .await
        .unwrap();
    let _ = std::fs::remove_dir_all(tmp);
}
