use hudsucker::Body;
use hyper::Response;
use imp_testing::TestVm;
use imp_testing::agent::protocol::ExecRequest;
use imp_testing::config::{Egress, ProxyConfig, RootfsSource, VmConfig};
use imp_testing::proxy::doubles::TestDouble;
use imp_testing::vmm::cloud_hypervisor::CloudHypervisor;
use std::path::PathBuf;

mod common;

#[tokio::test]
#[ignore]
async fn test_egress_proxy_ch() {
    let vmm = CloudHypervisor::new(common::ch_bin());
    test_egress_proxy_impl(&vmm).await;
}

#[cfg(feature = "firecracker")]
#[tokio::test]
#[ignore]
async fn test_egress_proxy_fc() {
    let vmm = imp_testing::vmm::firecracker::Firecracker::new(common::fc_bin());
    if !imp_testing::vmm::Vmm::capabilities(&vmm).rootless_vhost_user_net {
        println!("Skipping: vhost-user-net not supported");
        return;
    }
    test_egress_proxy_impl(&vmm).await;
}

#[cfg(feature = "qemu")]
#[tokio::test]
#[ignore]
async fn test_egress_proxy_qemu() {
    let vmm = imp_testing::vmm::qemu::Qemu::new(common::qemu_bin());
    if !imp_testing::vmm::Vmm::capabilities(&vmm).rootless_vhost_user_net {
        println!("Skipping: vhost-user-net not supported");
        return;
    }
    test_egress_proxy_impl(&vmm).await;
}

async fn test_egress_proxy_impl<V: imp_testing::vmm::Vmm>(vmm: &V) {
    let _ = env_logger::builder().is_test(true).try_init();
    let _ = tracing_subscriber::fmt()
        .with_env_filter("hudsucker=debug,imp_testing=debug,hyper=debug,vhost_user_backend=trace,vhost=trace,vhost_device_vsock=trace")
        .with_test_writer()
        .try_init();

    let vmlinux = PathBuf::from("/tmp/imp-artifacts/vmlinux");
    let rootfs = PathBuf::from("/tmp/imp-artifacts/rootfs.erofs");

    let mut cfg = VmConfig::builder(vmlinux, RootfsSource::Erofs { image: rootfs })
        .build()
        .unwrap();
    let mut proxy_cfg = ProxyConfig::default();
    proxy_cfg.blocked_domains = vec!["blocked.com".to_string()];
    proxy_cfg.doubles = std::sync::Arc::new(vec![TestDouble {
        matcher: Box::new(|req| {
            req.method() != hyper::Method::CONNECT && req.uri().host() == Some("example.com")
        }),
        responder: Box::new(|_req| {
            Response::builder()
                .status(200)
                .body(Body::from("MITM SUCCESS!"))
                .unwrap()
        }),
    }]);

    cfg.net = imp_testing::config::NetConfig::Rootless {
        egress: Egress::Filtered(proxy_cfg),
        host_services: false,
    };
    let cid_alloc = imp_testing::vmm::CidAllocator::new();
    let vmid_alloc = std::sync::Arc::new(imp_testing::orchestrator::VmidAllocator::new());
    let mut vm = TestVm::start(vmm, cfg, &cid_alloc, vmid_alloc)
        .await
        .expect("Failed to start VM");

    let proxy_port = vm.proxy().as_ref().unwrap().port;
    let vmid = vm.vmid();

    println!("Connecting agent...");
    let agent = vm.agent().await.unwrap();
    println!("Agent connected.");
    
    let out1 = agent
        .exec(ExecRequest::new(vec![
            "/sbin/ip".into(),
            "link".into(),
            "set".into(),
            "eth0".into(),
            "up".into(),
        ]))
        .await
        .unwrap();
    println!(
        "ip link set eth0 up: {}",
        String::from_utf8_lossy(&out1.stderr)
    );

    let out2 = agent
        .exec(ExecRequest::new(vec![
            "/sbin/ip".into(),
            "addr".into(),
            "add".into(),
            format!("10.200.{}.2/30", vmid),
            "dev".into(),
            "eth0".into(),
        ]))
        .await
        .unwrap();
    println!("ip addr add: {}", String::from_utf8_lossy(&out2.stderr));

    let out3 = agent
        .exec(ExecRequest::new(vec![
            "/sbin/ip".into(),
            "route".into(),
            "add".into(),
            "default".into(),
            "via".into(),
            format!("10.200.{}.1", vmid),
        ]))
        .await
        .unwrap();
    println!("ip route add: {}", String::from_utf8_lossy(&out3.stderr));

    let out_a = agent
        .exec(ExecRequest::new(vec!["ip".into(), "a".into()]))
        .await
        .unwrap();
    println!("IP A:\n{}", String::from_utf8_lossy(&out_a.stdout));

    let out_r = agent
        .exec(ExecRequest::new(vec!["ip".into(), "route".into()]))
        .await
        .unwrap();
    println!("IP ROUTE:\n{}", String::from_utf8_lossy(&out_r.stdout));

    // Give the network some time to come up
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    let outcome = agent
        .exec(
            ExecRequest::new(vec![
                "/usr/bin/curl".into(),
                "-4".into(),
                "-k".into(), // Accept MITM certificate for transparent TLS interception
                "-v".into(),
                "--max-time".into(),
                "5".into(),
                "--resolve".into(),
                "example.com:443:1.2.3.4".into(),
                "https://example.com".into(),
            ])
            .with_env(vec![
                (
                    "http_proxy".to_string(),
                    format!("http://10.200.{}.1:{}", vmid, proxy_port),
                ),
                (
                    "https_proxy".to_string(),
                    format!("http://10.200.{}.1:{}", vmid, proxy_port),
                ),
            ]),
        )
        .await
        .expect("Failed to execute curl");

    println!("curl stdout: {}", String::from_utf8_lossy(&outcome.stdout));
    println!("curl stderr: {}", String::from_utf8_lossy(&outcome.stderr));

    assert_eq!(outcome.code, 0);

    let _stderr = String::from_utf8_lossy(&outcome.stderr);

    assert!(
        outcome.stdout.starts_with(b"MITM SUCCESS!"),
        "Did not receive MITM intercepted body: {}",
        String::from_utf8_lossy(&outcome.stdout)
    );

    let blocked_outcome = agent
        .exec(
            ExecRequest::new(vec![
                "/usr/bin/curl".into(),
                "-4".into(),
                "-k".into(),
                "-v".into(),
                "--max-time".into(),
                "5".into(),
                "--resolve".into(),
                "blocked.com:443:1.2.3.4".into(),
                "https://blocked.com".into(),
            ])
            .with_env(vec![
                (
                    "http_proxy".to_string(),
                    format!("http://10.200.{}.1:{}", vmid, proxy_port),
                ),
                (
                    "https_proxy".to_string(),
                    format!("http://10.200.{}.1:{}", vmid, proxy_port),
                ),
            ]),
        )
        .await
        .expect("Failed to execute curl");

    let blocked_stderr = String::from_utf8_lossy(&blocked_outcome.stderr);
    let blocked_stdout = String::from_utf8_lossy(&blocked_outcome.stdout);
    assert!(
        blocked_stderr.contains("403 Forbidden")
            || blocked_stderr.contains("Blocked")
            || blocked_stdout.contains("403 Forbidden")
            || blocked_stdout.contains("Blocked"),
        "Did not receive 403 Forbidden for blocked domain: {}",
        blocked_stderr
    );

    vm.shutdown().await.expect("Shutdown failed");
}
