use imp_testing::config::{Access, CachePolicy, RootfsSource, Share, VmConfig};
use imp_testing::vmm::VmInstance;
use imp_testing::vmm::cloud_hypervisor::CloudHypervisor;
use std::path::PathBuf;

mod common;

#[tokio::test]
#[ignore]
async fn test_shares_ro_rw_ch() {
    let vmm = CloudHypervisor::new(common::ch_bin());
    test_shares_ro_rw_impl(&vmm).await;
}

#[cfg(feature = "firecracker")]
#[tokio::test]
#[ignore]
async fn test_shares_ro_rw_fc() {
    let vmm = imp_testing::vmm::firecracker::Firecracker::new(common::fc_bin());
    if !imp_testing::vmm::Vmm::capabilities(&vmm).virtio_fs_shares {
        println!("Skipping: virtio-fs shares not supported");
        return;
    }
    test_shares_ro_rw_impl(&vmm).await;
}

#[cfg(feature = "qemu")]
#[tokio::test]
#[ignore]
async fn test_shares_ro_rw_qemu() {
    let vmm = imp_testing::vmm::qemu::Qemu::new(common::qemu_bin());
    if !imp_testing::vmm::Vmm::capabilities(&vmm).virtio_fs_shares {
        println!("Skipping: virtio-fs shares not supported");
        return;
    }
    test_shares_ro_rw_impl(&vmm).await;
}

async fn test_shares_ro_rw_impl<V: imp_testing::vmm::Vmm>(backend: &V) {
    static COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let id = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let tmp = std::env::temp_dir().join(format!("imp-test-shares-{}-{}", std::process::id(), id));
    let in_dir = tmp.join("in");
    let out_dir = tmp.join("out");
    std::fs::create_dir_all(&in_dir).unwrap();
    std::fs::create_dir_all(&out_dir).unwrap();

    std::fs::write(in_dir.join("input.txt"), "hello world").unwrap();

    let vmlinux = PathBuf::from("/tmp/imp-artifacts/vmlinux");
    let rootfs = PathBuf::from("/tmp/imp-artifacts/rootfs.erofs");
    if !vmlinux.exists() || !rootfs.exists() {
        println!("Artifacts not found, skipping shares test");
        return;
    }

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

    let cid_alloc = imp_testing::vmm::CidAllocator::new();
    let vmid_alloc = imp_testing::orchestrator::VmidAllocator::new();
    let mut vm = imp_testing::TestVm::start(backend, _cfg, &cid_alloc, vmid_alloc)
        .await
        .expect("Failed to start VM");

    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    let mut client = imp_testing::agent::AgentClient::connect(
        vm.instance().vsock_path(),
        5000,
        std::time::Duration::from_secs(10),
        vm.instance().serial_log(),
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
