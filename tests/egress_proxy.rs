use hudsucker::Body;
use hyper::Response;
use imp_testing::TestVm;
use imp_testing::agent::protocol::ExecRequest;
use imp_testing::config::{Egress, ProxyConfig, RootfsSource, VmConfig};
use imp_testing::proxy::doubles::TestDouble;

mod common;

vmm_matrix_test!(egress_proxy, |vmm| {
    require_cap!(
        imp_testing::vmm::Vmm::capabilities(&vmm),
        unprivileged_vhost_user_net,
        vmm
    );
    test_egress_proxy_impl(&vmm).await;
});

async fn test_egress_proxy_impl<V: imp_testing::vmm::Vmm>(vmm: &V) {
    let _ = env_logger::builder().is_test(true).try_init();
    let _ = tracing_subscriber::fmt()
        .with_env_filter("hudsucker=debug,imp_testing=debug,hyper=debug,vhost_user_backend=trace,vhost=trace,vhost_device_vsock=trace")
        .with_test_writer()
        .try_init();

    let vmlinux = common::get_vmlinux();
    let rootfs = common::get_rootfs();

    let mut cfg = VmConfig::builder(vmlinux, RootfsSource::Erofs { image: rootfs })
        .build()
        .unwrap();
    let mut proxy_cfg = ProxyConfig::default();
    proxy_cfg.blocked_domains = vec!["blocked.com".to_string()];
    proxy_cfg.doubles = std::sync::Arc::new(std::sync::RwLock::new(vec![TestDouble {
        matcher: Box::new(|req| {
            req.method() != hyper::Method::CONNECT && req.uri().host() == Some("example.com")
        }),
        responder: Box::new(|_req| {
            Response::builder()
                .status(200)
                .body(Body::from("MITM SUCCESS!"))
                .unwrap()
        }),
    }]));

    let host_port = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    };

    let python_server = std::process::Command::new("python3")
        .arg("-m")
        .arg("http.server")
        .arg(host_port.to_string())
        .spawn()
        .unwrap();

    struct Cleanup(std::process::Child);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let _cleanup = Cleanup(python_server);

    cfg.net = imp_testing::config::NetConfig::Rootless {
        egress: Egress::Filtered(proxy_cfg),
        host_services_port: Some(host_port),
    };
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

    let proxy_port = vm.proxy().as_ref().unwrap().port;
    let vmid = vm.vmid();
    // Gateway IP uses the centralized (vmid % 254) + 1 octet math, not the raw
    // vmid (an off-by-one that reaches no host).
    let (gateway_ip, _g, _c) = imp_testing::net::ip_math(vmid).expect("ip_math");
    let gateway = gateway_ip.to_string();

    println!("Connecting agent...");
    let agent = vm
        .agent(None, &imp_testing::orchestrator::RealClock)
        .await
        .unwrap();
    println!("Agent connected.");

    let out_a = agent
        .exec(ExecRequest::new(vec!["ip".into(), "a".into()]))
        .await
        .unwrap();
    assert_eq!(
        out_a.code,
        0,
        "ip a failed: {:?}",
        String::from_utf8_lossy(&out_a.stderr)
    );
    println!("IP A:\n{}", String::from_utf8_lossy(&out_a.stdout));

    let out_r = agent
        .exec(ExecRequest::new(vec!["ip".into(), "route".into()]))
        .await
        .unwrap();
    assert_eq!(
        out_r.code,
        0,
        "ip route failed: {:?}",
        String::from_utf8_lossy(&out_r.stderr)
    );
    println!("IP ROUTE:\n{}", String::from_utf8_lossy(&out_r.stdout));

    // Give the network some time to come up
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    let outcome = agent
        .exec(
            ExecRequest::new(vec![
                "curl".into(),
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
                    format!("http://{}:{}", gateway, proxy_port),
                ),
                (
                    "https_proxy".to_string(),
                    format!("http://{}:{}", gateway, proxy_port),
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
                "curl".into(),
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
                    format!("http://{}:{}", gateway, proxy_port),
                ),
                (
                    "https_proxy".to_string(),
                    format!("http://{}:{}", gateway, proxy_port),
                ),
            ]),
        )
        .await
        .expect("Failed to execute curl");

    let blocked_stderr = String::from_utf8_lossy(&blocked_outcome.stderr);
    let blocked_stdout = String::from_utf8_lossy(&blocked_outcome.stdout);
    assert!(
        blocked_stderr.contains("403") && blocked_stdout.contains("Blocked by Imp Proxy"),
        "Did not receive 403 Forbidden for blocked domain: {}\nSTDOUT: {}",
        blocked_stderr,
        blocked_stdout
    );

    // Plain-HTTP host-service proxying (TESTS-FEATURES-6): an absolute-form GET to the local
    // host service through the proxy. This is NOT a CONNECT — the genuine CONNECT tunnel is
    // asserted separately, below, via the host-observable request log.
    let plain_http_outcome = agent
        .exec(
            ExecRequest::new(vec![
                "curl".into(),
                "-4".into(),
                "-v".into(),
                "--max-time".into(),
                "5".into(),
                format!("http://127.0.0.1:{}", host_port), // local server reached via the proxy
            ])
            .with_env(vec![(
                "http_proxy".to_string(),
                format!("http://{}:{}", gateway, proxy_port),
            )]),
        )
        .await
        .expect("Failed to execute plain-HTTP proxied curl");

    assert_eq!(
        plain_http_outcome.code,
        0,
        "plain-HTTP host-service proxying failed: {}",
        String::from_utf8_lossy(&plain_http_outcome.stderr)
    );

    // Drop agent so we can borrow vm immutably
    let _ = agent;

    // EgressProxy records requests. Let's see if we can query it.
    let requests = vm.proxy().unwrap().requests();
    assert!(
        requests
            .iter()
            .any(|r| r.contains("example.com") && r.contains("GET")),
        "Proxy should observe guest intended destination"
    );

    // Real CONNECT assertion (TESTS-FEATURES-6): the guest's HTTPS request to example.com is
    // tunneled through the proxy as an HTTP CONNECT, which the handler records and forwards
    // (returns Request for Method::CONNECT) before MITM'ing it. A handler that stops letting
    // CONNECT fall through would break the MITM above AND drop this CONNECT log entry.
    assert!(
        requests
            .iter()
            .any(|r| r.starts_with("CONNECT") && r.contains("example.com")),
        "Proxy should observe a CONNECT tunnel for the intended HTTPS destination, got: {:?}",
        requests
    );

    vm.shutdown().await.expect("Shutdown failed");
}

// ROOTLESS NAMING. A `rootless`-named test exercising the rootless egress path
// (`NetConfig::Rootless` + the smoltcp NAT + the egress proxy). It needs KVM and CH's
// unprivileged vhost-user-net, but NO host privilege, so `just test-rootless` (which selects
// `test(rootless)`) can run it unprivileged. `#[ignore]`d out of the default suite, with a
// visible capability skip-with-reason rather than a silent skip==pass.
#[cfg(feature = "cloud-hypervisor")]
#[tokio::test]
#[ignore = "rootless egress: needs KVM + unprivileged vhost-user-net; selected by `just test-rootless`"]
async fn test_egress_proxy_rootless() {
    let vmm = imp_testing::vmm::cloud_hypervisor::CloudHypervisor::new(common::ch_bin());
    if !imp_testing::vmm::Vmm::capabilities(&vmm).unprivileged_vhost_user_net {
        println!(
            "SKIP: cloud-hypervisor lacks unprivileged_vhost_user_net — cannot exercise the rootless egress path"
        );
        return;
    }
    // test_egress_proxy_impl configures NetConfig::Rootless + Egress::Filtered internally.
    test_egress_proxy_impl(&vmm).await;
}
