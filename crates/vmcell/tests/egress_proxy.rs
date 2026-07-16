use hudsucker::Body;
use hyper::Response;
use vmcell::MicroVm;
use vmcell::agent::protocol::ExecRequest;
use vmcell::config::{Egress, ProxyConfig, RootfsSource, VmConfig};
use vmcell::proxy::doubles::TestDouble;
use vmcell::vmm::VmInstance;

mod common;

vmm_matrix_test!(egress_proxy, |vmm| {
    require_cap!(
        vmcell::vmm::Vmm::capabilities(&vmm),
        unprivileged_vhost_user_net,
        vmm
    );
    test_egress_proxy_impl(&vmm).await;
});

// H-TEST-3: capability-honesty pin for `unprivileged_vhost_user_net`. `require_cap!`
// gates egress_proxy on this flag; a nextest skip is an INVISIBLE pass, so if a
// backend's `unprivileged_vhost_user_net` flipped false the egress leg would go
// dark silently. This non-KVM pin fixes the documented value per backend so the
// flip reddens here in the default suite. Inverse: flip any asserted value.
#[test]
fn capability_honesty_unprivileged_vhost_user_net() {
    #[cfg(feature = "cloud-hypervisor")]
    assert!(
        vmcell::vmm::Vmm::capabilities(&vmcell::vmm::cloud_hypervisor::CloudHypervisor::new(
            common::ch_bin()
        ))
        .unprivileged_vhost_user_net,
        "CH (primary) must support unprivileged_vhost_user_net; a false silently skips egress_proxy::cloud_hypervisor"
    );
    #[cfg(feature = "firecracker")]
    assert!(
        !vmcell::vmm::Vmm::capabilities(&vmcell_firecracker::Firecracker::new(common::fc_bin()))
            .unprivileged_vhost_user_net,
        "FC must NOT advertise unprivileged_vhost_user_net; a true here hides a real gap"
    );
    #[cfg(feature = "qemu")]
    assert!(
        vmcell::vmm::Vmm::capabilities(&vmcell_qemu::Qemu::new(common::qemu_bin()))
            .unprivileged_vhost_user_net,
        "QEMU must support unprivileged_vhost_user_net; a false silently skips egress_proxy::qemu"
    );
}

async fn test_egress_proxy_impl<V: vmcell::vmm::Vmm>(vmm: &V) {
    let _ = env_logger::builder().is_test(true).try_init();
    let _ = tracing_subscriber::fmt()
        .with_env_filter("hudsucker=debug,vmcell=debug,hyper=debug,vhost_user_backend=trace,vhost=trace,vhost_device_vsock=trace")
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

    cfg.net = vmcell::config::NetConfig::Unprivileged {
        egress: Egress::Filtered(proxy_cfg),
        host_services_port: Some(host_port),
    };
    let env = vmcell::HostEnv::hermetic();
    let mut vm = MicroVm::start(vmm, cfg, &env)
        .await
        .expect("Failed to start VM");

    let proxy_port = vm.proxy().as_ref().unwrap().port;
    let vmid = vm.vmid();
    // Gateway IP uses the centralized (vmid % 254) + 1 octet math, not the raw
    // vmid (an off-by-one that reaches no host).
    let (gateway_ip, _g, _c) = vmcell::net::ip_math(vmid).expect("ip_math");
    let gateway = gateway_ip.to_string();

    println!("Connecting agent...");
    let agent = vm.agent(None).await.unwrap();
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
                    format!("http://{gateway}:{proxy_port}"),
                ),
                (
                    "https_proxy".to_string(),
                    format!("http://{gateway}:{proxy_port}"),
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
                    format!("http://{gateway}:{proxy_port}"),
                ),
                (
                    "https_proxy".to_string(),
                    format!("http://{gateway}:{proxy_port}"),
                ),
            ]),
        )
        .await
        .expect("Failed to execute curl");

    let blocked_stderr = String::from_utf8_lossy(&blocked_outcome.stderr);
    let blocked_stdout = String::from_utf8_lossy(&blocked_outcome.stdout);
    assert!(
        blocked_stderr.contains("403") && blocked_stdout.contains("Blocked by vmcell Proxy"),
        "Did not receive 403 Forbidden for blocked domain: {blocked_stderr}\nSTDOUT: {blocked_stdout}"
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
                format!("http://{gateway}:{proxy_port}"),
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
         listing; got: {plain_http_body}"
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
        "Proxy should observe a CONNECT tunnel for the intended HTTPS destination, got: {requests:?}"
    );

    // L-TEST-2: the guest-visible 403 above proves the block reached the guest, but
    // NOT that the proxy recorded it. Assert the host-observable '403 BLOCKED
    // blocked.com' log entry so the end-to-end wiring (hudsucker dispatch -> handler
    // -> shared request log) is covered at the integration level, not just in the
    // unit double. Inverse: a handler that blocks but skips the log append drops
    // this entry and reddens here.
    assert!(
        requests
            .iter()
            .any(|r| r.starts_with("403 BLOCKED") && r.contains("blocked.com")),
        "Proxy should record a '403 BLOCKED' entry for the blocked domain; got: {requests:?}"
    );

    vm.shutdown().await.expect("Shutdown failed");
}

// UNPRIVILEGED NAMING. A `unprivileged`-named test exercising the unprivileged egress path
// (`NetConfig::Unprivileged` + the smoltcp NAT + the egress proxy). It needs KVM and CH's
// unprivileged vhost-user-net, but NO host privilege, so `just test-unprivileged` (which selects
// `test(unprivileged)`) can run it unprivileged. `#[ignore]`d out of the default suite, with a
// visible capability skip-with-reason rather than a silent skip==pass.
#[cfg(feature = "cloud-hypervisor")]
#[tokio::test]
#[ignore = "unprivileged egress: needs KVM + unprivileged vhost-user-net; selected by `just test-unprivileged`"]
async fn test_egress_proxy_unprivileged() {
    let vmm = vmcell::vmm::cloud_hypervisor::CloudHypervisor::new(common::ch_bin());
    // TEST-2: the CH primary path must NOT be exempted from the capability
    // check. `require_cap!` HARD-FAILS (panics) for cloud-hypervisor rather than
    // the previous `println!("SKIP…"); return;`, so a CH capability-descriptor
    // regression (the flag flipping to false) makes the very test
    // `just test-unprivileged` selects fail loudly instead of passing green.
    require_cap!(
        vmcell::vmm::Vmm::capabilities(&vmm),
        unprivileged_vhost_user_net,
        vmm
    );
    // test_egress_proxy_impl configures NetConfig::Unprivileged + Egress::Filtered internally.
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

async fn test_egress_privileged_filtered_impl<V: vmcell::vmm::Vmm>(vmm: &V) {
    // Privileged tap networking needs CAP_NET_ADMIN; gate VISIBLY (panic-skip with
    // reason, like snapshot_restore) — never skip-as-pass.
    if !common::has_cap_net_admin() {
        panic!(
            "SKIP: privileged transparent-proxy egress needs CAP_NET_ADMIN for the tap path; \
             not present in the effective capability set"
        );
    }
    // Reap orphaned vmcell-net-* namespaces from prior aborted runs (no sudo).
    common::clean_vmcell_netns();

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
    cfg.net = vmcell::config::NetConfig::Privileged {
        egress: Egress::Filtered(proxy_cfg),
    };

    let env = vmcell::HostEnv::hermetic();
    let mut vm = MicroVm::start(vmm, cfg, &env)
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
    let (gateway_ip, _g, _c) = vmcell::net::ip_math(vmid).expect("ip_math");
    let gateway = gateway_ip.to_string();

    let agent = match vm.agent(Some(std::time::Duration::from_secs(120))).await {
        Ok(a) => a,
        Err(e) => {
            let log = std::fs::read_to_string(vm.instance().serial_log()).unwrap_or_default();
            panic!("Failed to connect to agent: {e}\nSERIAL LOG:\n{log}");
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
                    format!("http://{gateway}:{proxy_port}"),
                ),
                (
                    "https_proxy".to_string(),
                    format!("http://{gateway}:{proxy_port}"),
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
    // curls WITHOUT any http_proxy, so its packets traverse the nft TPROXY
    // ruleset rather than an explicit proxy.
    //
    // LOAD-BEARING SECURITY ASSERTION (TEST-1). The prior version gated the
    // security property on `assert_ne!(transparent.code, 0)` against the
    // black-hole `1.2.3.4:443`. That is FILTER-INDEPENDENT: curl fails for
    // network-unreachability whether or not any egress ruleset exists, so an
    // implementation emitting NO ruleset (fully-open default egress) passed the
    // old assertion unchanged. Instead, assert the HOST-OBSERVABLE *applied* nft
    // ruleset in the VM's netns — the transparent path is "filtered" iff the
    // kernel actually carries the default-drop TPROXY ruleset. This reddens on
    // the exact inverse the finding names: an impl that emits no ruleset makes
    // `nft list table ip proxy` fail (returns None -> panic below); an
    // accept-all policy drops the `policy drop` substring -> assert red.
    let netns = format!("vmcell-net-{vmid}");
    let ruleset = common::nft_list_table_in_netns(&netns, "ip proxy").unwrap_or_else(|| {
        panic!(
            "privileged transparent egress must apply an nft ruleset in netns {netns}; \
             `nft list table ip proxy` returned no table — fully-open egress is a security \
             regression, not a pass"
        )
    });
    assert!(
        ruleset.contains("policy drop"),
        "egress prerouting chain must default-drop (no fully-open egress); applied ruleset:\n{ruleset}"
    );
    // M-TEST-4: bind the TPROXY target to the LIVE proxy port, not any `tproxy to :`.
    // A bare substring match accepts a ruleset wired to a dead/wrong port; asserting
    // the exact `tproxy to :{proxy_port}` reddens on such a composition bug.
    assert!(
        ruleset.contains(&format!("tproxy to :{proxy_port}")),
        "egress ruleset must TPROXY-redirect web traffic to the live proxy port {proxy_port}; \
         applied ruleset:\n{ruleset}"
    );
    assert!(
        ruleset.contains("vmcell-drop"),
        "egress ruleset must carry the catch-all drop for non-web traffic; applied ruleset:\n{ruleset}"
    );

    // Behavioral corroboration (SECONDARY, not the security gate): a transparent
    // curl (no http_proxy) must NOT be served the explicit-proxy MITM double —
    // that double is only returned on the explicit CONNECT/absolute-form path
    // proven by the CONTROL above. This is deliberately not load-bearing (it is
    // filter-independent, per the note above); the applied-ruleset check is.
    //
    // NOTE (host validation needed): hudsucker does not yet reconstruct
    // absolute-form requests from a transparently-redirected connection, so the
    // transparent path CONSTRAINS egress (the ruleset asserted above) but does
    // not yet emit a 403 body for raw transparent traffic. See
    // implementation-notes.md (H-PROXY-1): privileged transparent intake is
    // wired at the socket layer (IP_TRANSPARENT + original-destination recovery)
    // pending absolute-form reconstruction in the MITM layer.
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
    assert!(
        !transparent.stdout.starts_with(b"MITM SUCCESS!"),
        "the transparent path must NOT serve the explicit-proxy MITM double; got: {}",
        String::from_utf8_lossy(&transparent.stdout)
    );

    vm.shutdown().await.expect("Shutdown failed");
}
