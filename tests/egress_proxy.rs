use imp_testing::TestVm;
use imp_testing::agent::protocol::ExecRequest;
use imp_testing::config::{Egress, RootfsSource, VmConfig};
use imp_testing::vmm::cloud_hypervisor::CloudHypervisor;
use std::path::PathBuf;

#[tokio::test]
async fn test_egress_proxy() {

    let ch = CloudHypervisor::new("cloud-hypervisor");
    let vmlinux = PathBuf::from("/tmp/imp-artifacts/vmlinux");
    let rootfs = PathBuf::from("/tmp/imp-artifacts/rootfs.ext4");

    let mut cfg = VmConfig::builder(
        vmlinux,
        RootfsSource::Erofs {
                image: rootfs,
            },
    )
    .build();
    // Rootless with passt fails with cloud-hypervisor due to an accept4 seccomp issue in passt leading to EBADF.
    cfg.net = imp_testing::config::NetConfig::Privileged {
        egress: imp_testing::config::Egress::AllowAll,
        host_services: vec![],
    };

    let mut vm = TestVm::start(&ch, cfg).await.expect("Failed to start VM");

    println!("Connecting agent...");
    let mut agent = vm.agent().await.unwrap();
    println!("Agent connected.");

    let proxy_port = vm.proxy.as_ref().unwrap().port;

    let _ = agent.exec(ExecRequest { argv: vec!["ip".into(), "a".into()], env: vec![], cwd: None }).await;
    let _ = agent.exec(ExecRequest { argv: vec!["ip".into(), "route".into()], env: vec![], cwd: None }).await;

    let outcome = agent
        .exec(ExecRequest {
            argv: vec![
                "curl".into(),
                "-4".into(),
                "-v".into(),
                "--max-time".into(),
                "5".into(),
                "--resolve".into(),
                "example.com:80:1.2.3.4".into(),
                "http://example.com".into(),
            ],
            env: vec![
                ("http_proxy".to_string(), format!("http://10.200.{}.1:{}", vm.vmid, proxy_port)),
            ],
            cwd: None,
        })
        .await
        .expect("Failed to execute curl");

    println!("curl stdout: {}", String::from_utf8_lossy(&outcome.stdout));
    println!("curl stderr: {}", String::from_utf8_lossy(&outcome.stderr));

    assert_eq!(outcome.code, 0);

    let stderr = String::from_utf8_lossy(&outcome.stderr);

    assert!(
        stderr.contains("Connected to example.com (1.2.3.4) port 80"),
        "Did not intercept: {}",
        stderr
    );

    vm.shutdown().await.expect("Shutdown failed");
}
