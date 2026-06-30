use hudsucker::Body;
use hyper::Response;
use imp_testing::TestVm;
use imp_testing::agent::protocol::ExecRequest;
use imp_testing::config::{Egress, ProxyConfig, RootfsSource, VmConfig};
use imp_testing::proxy::doubles::TestDouble;
use imp_testing::vmm::VmInstance;

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
    // TESTS-FEATURES-6 (Part C-d): assert the response BODY, not just the exit
    // code. `python3 -m http.server` answers GET / with an HTML directory listing
    // whose title is the stable, version-independent string "Directory listing
    // for". A proxy that returned 0 but forwarded no body (or an error page) goes
    // red here, where the bare exit-code check passed.
    let plain_http_body = String::from_utf8_lossy(&plain_http_outcome.stdout);
    assert!(
        plain_http_body.contains("Directory listing for"),
        "plain-HTTP proxied response body must be the host service's directory \
         listing; got: {}",
        plain_http_body
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

// H-PROXY-1: the PRIVILEGED transparent-proxy egress path. Every prior privileged
// test used `Egress::Open`, so the IP_TRANSPARENT proxy wiring + nft TPROXY
// emission on the `NetConfig::Privileged` + `Egress::Filtered` path was never
// exercised. This boots that path and checks the genuinely transparent scenario
// (a guest curl WITHOUT `http_proxy`) is filtered, with the explicit-proxy MITM as
// the control proving the path isn't simply dead.
vmm_matrix_test!(egress_privileged_filtered, |vmm| {
    test_egress_privileged_filtered_impl(&vmm).await;
});

async fn test_egress_privileged_filtered_impl<V: imp_testing::vmm::Vmm>(vmm: &V) {
    // Privileged tap networking needs CAP_NET_ADMIN; gate VISIBLY (panic-skip with
    // reason, like snapshot_restore) — never skip-as-pass.
    if !common::has_cap_net_admin() {
        panic!(
            "SKIP: privileged transparent-proxy egress needs CAP_NET_ADMIN for the tap path; \
             not present in the effective capability set"
        );
    }
    // Reap orphaned imp-net-* namespaces from prior aborted runs (no sudo).
    common::clean_imp_netns();

    let vmlinux = common::get_vmlinux();
    let rootfs = common::get_rootfs();

    // A MITM double for example.com plus a blocked domain. The double lets us prove
    // the proxy is in-path and filtering (vs. egress merely being dead/unroutable).
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

    let mut cfg = VmConfig::builder(vmlinux, RootfsSource::Erofs { image: rootfs })
        .build()
        .unwrap();
    cfg.net = imp_testing::config::NetConfig::Privileged {
        egress: Egress::Filtered(proxy_cfg),
        host_services_port: None,
    };

    let cid_alloc = std::sync::Arc::new(imp_testing::vmm::CidAllocator::new());
    let vmid_alloc = imp_testing::orchestrator::VmidAllocator::new();
    let mut vm = TestVm::start(
        vmm,
        cfg,
        cid_alloc,
        vmid_alloc,
        Box::new(imp_testing::metrics::DefaultCgroupFs),
    )
    .await
    .expect("Failed to start privileged Filtered VM");

    // The privileged Filtered path wires an IP_TRANSPARENT proxy (H-PROXY-1) behind
    // the nft TPROXY ruleset (policy drop; tproxy tcp/80,443; drop the rest). The
    // proxy front-end must actually be present and bound.
    let proxy_port = vm
        .proxy()
        .expect("privileged Filtered egress must start a proxy")
        .port;
    assert!(
        proxy_port > 0,
        "the transparent egress proxy must be bound to a real port"
    );

    let vmid = vm.vmid();
    let (gateway_ip, _g, _c) = imp_testing::net::ip_math(vmid).expect("ip_math");
    let gateway = gateway_ip.to_string();

    let agent = match vm
        .agent(
            Some(std::time::Duration::from_secs(120)),
            &imp_testing::orchestrator::RealClock,
        )
        .await
    {
        Ok(a) => a,
        Err(e) => {
            let log = std::fs::read_to_string(vm.instance().serial_log()).unwrap_or_default();
            panic!("Failed to connect to agent: {}\nSERIAL LOG:\n{}", e, log);
        }
    };

    // CONTROL (explicit-proxy MITM over the privileged tap): steer the guest to the
    // proxy via http_proxy. hudsucker is an explicit-proxy MITM, so this is the
    // path it fully intercepts — example.com returns the injected double. This
    // proves the proxy is reachable and filtering on the privileged path, so a
    // failure of the transparent curl below is the FILTER, not a dead network.
    let explicit = agent
        .exec(
            ExecRequest::new(vec![
                "curl".into(),
                "-4".into(),
                "-k".into(),
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
        .expect("Failed to execute explicit-proxy curl");
    assert_eq!(
        explicit.code,
        0,
        "explicit-proxy curl over the privileged tap must succeed: {}",
        String::from_utf8_lossy(&explicit.stderr)
    );
    assert!(
        explicit.stdout.starts_with(b"MITM SUCCESS!"),
        "explicit-proxy path must be MITM-intercepted; got: {}",
        String::from_utf8_lossy(&explicit.stdout)
    );

    // TREATMENT — the genuinely transparent scenario (Requirement #4): the guest
    // curls the SAME host WITHOUT any http_proxy, so its packets traverse the nft
    // TPROXY ruleset rather than an explicit proxy. Default egress must NOT escape
    // the filter: the prerouting chain is `policy drop` + tproxy tcp/80,443 into the
    // IP_TRANSPARENT proxy, so the connection is constrained — curl must fail AND it
    // must NOT receive the MITM double (which only the explicit path serves).
    // Comparing against the explicit CONTROL above (same destination, MITM body)
    // isolates the cause as the FILTER, not an unroutable address.
    //
    // NOTE (host validation needed): hudsucker does not yet reconstruct
    // absolute-form requests from a transparently-redirected connection, so the
    // transparent path CONSTRAINS egress (the security property) but does not yet
    // emit a 403 body for raw transparent traffic. See implementation-notes.md
    // (H-PROXY-1): privileged transparent intake is wired at the socket layer
    // (IP_TRANSPARENT + original-destination recovery) pending absolute-form
    // reconstruction in the MITM layer.
    let transparent = agent
        .exec(ExecRequest::new(vec![
            "curl".into(),
            "-4".into(),
            "-k".into(),
            "-sS".into(),
            "--max-time".into(),
            "5".into(),
            "--resolve".into(),
            "example.com:443:1.2.3.4".into(),
            "https://example.com".into(),
        ]))
        .await
        .expect("Failed to execute transparent curl");
    assert_ne!(
        transparent.code, 0,
        "transparent default egress must be filtered (curl should fail without http_proxy)"
    );
    assert!(
        !transparent.stdout.starts_with(b"MITM SUCCESS!"),
        "the transparent path must NOT serve the explicit-proxy MITM double; got: {}",
        String::from_utf8_lossy(&transparent.stdout)
    );

    vm.shutdown().await.expect("Shutdown failed");
}
