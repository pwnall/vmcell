use imp_testing::TestVm;
use imp_testing::agent::protocol::ExecRequest;
use imp_testing::config::{Egress, ProxyConfig, RootfsSource, VmConfig};
use imp_testing::vmm::cloud_hypervisor::CloudHypervisor;
use imp_testing::proxy::doubles::TestDouble;
use hudsucker::Body;
use hyper::Response;
use std::path::PathBuf;

#[tokio::test]
#[ignore]
async fn test_egress_proxy() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("hudsucker=debug,imp_testing=debug,hyper=debug")
        .try_init();

    let ch = CloudHypervisor::new("cloud-hypervisor");
    let vmlinux = PathBuf::from("/tmp/imp-artifacts/vmlinux");
    let rootfs = PathBuf::from("/tmp/imp-artifacts/rootfs.erofs");

    let mut cfg = VmConfig::builder(vmlinux, RootfsSource::Erofs { image: rootfs }).build().unwrap();
    let mut proxy_cfg = ProxyConfig::default();
    proxy_cfg.doubles = std::sync::Arc::new(vec![
        TestDouble {
            matcher: Box::new(|req| {
                req.method() != hyper::Method::CONNECT && req.uri().host() == Some("example.com")
            }),
            responder: Box::new(|_req| {
                Response::builder()
                    .status(200)
                    .body(Body::from("MITM SUCCESS!"))
                    .unwrap()
            }),
        }
    ]);

    cfg.net = imp_testing::config::NetConfig::Rootless {
        egress: Egress::Filtered(proxy_cfg),
        host_services: false,
    };
    let cid_alloc = imp_testing::vmm::CidAllocator::new();
    let mut vm = TestVm::start(&ch, cfg, &cid_alloc).await.expect("Failed to start VM");

    println!("Connecting agent...");
    let mut agent = vm.agent().await.unwrap();
    println!("Agent connected.");

    let proxy_port = vm.proxy().as_ref().unwrap().port;

    let _ = agent
        .exec(ExecRequest::new(vec!["ip".into(), "a".into()]))
        .await;
    let _ = agent
        .exec(ExecRequest::new(vec!["ip".into(), "route".into()]))
        .await;

    // Give the network some time to come up
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    let outcome = agent
        .exec(ExecRequest::new(vec![
                "curl".into(),
                "-4".into(),
                "-v".into(),
                "--max-time".into(),
                "5".into(),
                "--resolve".into(),
                "example.com:443:1.2.3.4".into(),
                "https://example.com".into(),
            ]).with_env(vec![
                (
                    "http_proxy".to_string(),
                    format!("http://10.200.{}.1:{}", vm.vmid(), proxy_port),
                ),
                (
                    "https_proxy".to_string(),
                    format!("http://10.200.{}.1:{}", vm.vmid(), proxy_port),
                ),
            ]))
        .await
        .expect("Failed to execute curl");

    println!("curl stdout: {}", String::from_utf8_lossy(&outcome.stdout));
    println!("curl stderr: {}", String::from_utf8_lossy(&outcome.stderr));

    assert_eq!(outcome.code, 0);

    let stderr = String::from_utf8_lossy(&outcome.stderr);

    assert!(
        outcome.stdout.starts_with(b"MITM SUCCESS!"),
        "Did not receive MITM intercepted body: {}",
        String::from_utf8_lossy(&outcome.stdout)
    );

    vm.shutdown().await.expect("Shutdown failed");
}
