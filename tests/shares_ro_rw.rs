use imp_testing::config::{Access, CachePolicy, RootfsSource, Share, VmConfig};
use imp_testing::vmm::VmInstance;
use imp_testing::vmm::cloud_hypervisor::CloudHypervisor;
use std::path::PathBuf;

#[tokio::test]
async fn test_shares_ro_rw() {
    let tmp = std::env::temp_dir().join(format!("imp-test-shares-{}", std::process::id()));
    let in_dir = tmp.join("in");
    let out_dir = tmp.join("out");
    std::fs::create_dir_all(&in_dir).unwrap();
    std::fs::create_dir_all(&out_dir).unwrap();

    std::fs::write(in_dir.join("input.txt"), "hello world").unwrap();

    let _vmm = CloudHypervisor::new("cloud-hypervisor");

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
        .build().unwrap();

    let mut vmm = imp_testing::TestVm::start(&_vmm, _cfg)
        .await
        .expect("Failed to start VM");

    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    let mut client = imp_testing::agent::AgentClient::connect(vmm.instance().vsock_path(), 5000)
        .await
        .expect("Failed to connect to agent");

    // Verify read from RO share
    let res = client
        .exec(imp_testing::agent::protocol::ExecRequest::new(vec!["cat".into(), "/imp-in/input.txt".into()]))
        .await
        .expect("Exec failed");
    if res.code != 0 {
        let log = std::fs::read_to_string(vmm.instance().serial_log()).unwrap_or_default();
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

    imp_testing::vmm::VmInstance::kill(vmm.instance_mut())
        .await
        .unwrap();
    let _ = std::fs::remove_dir_all(tmp);
}
