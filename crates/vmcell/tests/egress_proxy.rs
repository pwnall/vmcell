use hudsucker::Body;
use hyper::Response;
use vmcell::MicroVm;
use vmcell::config::{Egress, ProxyConfig, RootfsSource, VmConfig};
use vmcell::proxy::cassette::CassetteOptions;
use vmcell::proxy::doubles::TestDouble;
use vmcell::steward::protocol::ExecRequest;
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

    println!("Connecting steward...");
    let steward = vm.steward(None).await.unwrap();
    println!("Steward connected.");

    let out_a = steward
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

    let out_r = steward
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

    let outcome = steward
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

    let blocked_outcome = steward
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
    let plain_http_outcome = steward
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

    // Drop steward so we can borrow vm immutably
    let _ = steward;

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

    let steward = match vm.steward(Some(std::time::Duration::from_secs(120))).await {
        Ok(a) => a,
        Err(e) => {
            let log = std::fs::read_to_string(vm.instance().serial_log()).unwrap_or_default();
            panic!("Failed to connect to steward: {e}\nSERIAL LOG:\n{log}");
        }
    };

    // CONTROL (explicit-proxy MITM over the privileged tap): steer the guest to the
    // proxy via http_proxy. hudsucker is an explicit-proxy MITM, so this is the
    // path it fully intercepts — example.com returns the injected double. This
    // proves the proxy is reachable and filtering on the privileged path, so a
    // failure of the transparent curl below is the FILTER, not a dead network.
    let explicit = steward
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
    let netns = vmcell::naming::netns_name(vmcell::naming::DEFAULT_RESOURCE_PREFIX, vmid);
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
    // The catch-all drop, recomputed through the real name composer (never a test-local
    // `format!`). It carries no `log prefix` any more: netfilter discards the syslog LOG target in
    // a non-init netns unless the host-global `net.netfilter.nf_log_all_netns` is 1, so the old
    // `vmcell-drop` marker asserted the presence of a diagnostic that never emitted a line
    // (`tproxy-drop-log-never-emitted`). The rule itself — the security property — is what is
    // asserted here.
    let tap = vmcell::naming::tap_name(vmcell::naming::DEFAULT_RESOURCE_PREFIX, vmid);
    assert!(
        ruleset.contains(&format!("iifname \"{tap}\" drop")),
        "egress ruleset must carry the catch-all drop for non-web traffic; applied ruleset:\n{ruleset}"
    );

    // Behavioral corroboration (SECONDARY, not the security gate — the applied-ruleset check above
    // is): a transparent curl (no http_proxy) is now FULLY MITM'd, so it is served the same double
    // the explicit-proxy CONTROL got.
    //
    // THIS ASSERTION IS INVERTED FROM WHAT IT USED TO BE, and the inversion is the point. It used
    // to read `!starts_with("MITM SUCCESS!")` with a note that "hudsucker does not yet reconstruct
    // absolute-form requests from a transparently-redirected connection" — §6.4's recorded
    // limitation. `proxy::transparent::serve_intake` closes it: the ClientHello's SNI names the
    // destination, and the connection reaches hudsucker behind a synthesized CONNECT. Leaving the
    // old assertion in place would have made this suite red on the very fix it was describing.
    //
    // UNRUN BY THE CHANGE THAT WROTE IT: this leg needs CAP_NET_ADMIN and the blessed privileged
    // runner. The identical intake is exercised live on the unprivileged NAT by
    // `test_transparent_mitm_and_cassettes_unprivileged` (same `serve_intake`, same SNI recovery,
    // same synthesized CONNECT); what only THIS leg can prove is the privileged half of
    // `transparent::connect_port` — that a TPROXY-preserved original destination is the port the
    // synthesized CONNECT names.
    let transparent = steward
        .exec(ExecRequest::new(vec![
            "curl".into(),
            "-4".into(),
            "-k".into(),
            "-sS".into(),
            "--max-time".into(),
            "15".into(),
            "--resolve".into(),
            "example.com:443:1.2.3.4".into(),
            "https://example.com".into(),
        ]))
        .await
        .expect("Failed to execute transparent curl");
    assert!(
        transparent.stdout.starts_with(b"MITM SUCCESS!"),
        "the transparent TPROXY path must now be fully MITM-intercepted (SNI + synthesized \
         CONNECT), not merely constrained; got: {} / {}",
        String::from_utf8_lossy(&transparent.stdout),
        String::from_utf8_lossy(&transparent.stderr)
    );

    vm.shutdown().await.expect("Shutdown failed");
}

// ---------------------------------------------------------------------------
// §6.4's two closed gaps, on the one live path a reviewer without the blessed
// runner can actually execute: FULL MITM ON THE TRANSPARENT INTAKE, and
// SNAPSHOT-AND-REPLAY CASSETTES.
// ---------------------------------------------------------------------------

/// Runs `curl` in the guest with no proxy environment at all, so its packets take the
/// transparent path (the unprivileged NAT's L4 interception, §6.4) rather than an explicit
/// proxy. `--resolve` stands in for DNS, which the NAT does not forward.
async fn transparent_curl(
    steward: &mut vmcell::steward::StewardClient,
    host: &str,
    port: u16,
    url: &str,
) -> vmcell::steward::protocol::ExecOutcome {
    steward
        .exec(ExecRequest::new(vec![
            "curl".into(),
            "-4".into(),
            "-k".into(),
            "-sS".into(),
            "--max-time".into(),
            "15".into(),
            "--resolve".into(),
            format!("{host}:{port}:1.2.3.4"),
            url.into(),
        ]))
        .await
        .expect("transparent curl could not be executed in the guest")
}

/// Runs `curl` in the guest steered at the proxy explicitly — the intake `hudsucker` always
/// understood, used here as the positive control and as the cassette legs' transport.
async fn proxied_curl(
    steward: &mut vmcell::steward::StewardClient,
    gateway: &str,
    proxy_port: u16,
    url: &str,
) -> vmcell::steward::protocol::ExecOutcome {
    steward
        .exec(
            ExecRequest::new(vec![
                "curl".into(),
                "-4".into(),
                "-k".into(),
                "-sS".into(),
                "--max-time".into(),
                "15".into(),
                url.into(),
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
        .expect("explicit-proxy curl could not be executed in the guest")
}

// UNPRIVILEGED NAMING (`just test-unprivileged` selects `test(unprivileged)`).
//
// PART B — FULL MITM ON THE TRANSPARENT PATH (§6.4). Before this, a guest that curled a raw
// 80/443 destination got its egress *constrained* and nothing more: `hudsucker` is an
// explicit-proxy MITM, so an origin-form `GET /` (no absolute URI) and a raw TLS ClientHello
// (no HTTP at all) both named a destination the proxy could not recover. The three treatment
// legs below assert the fix on the DATA PLANE — the intercepted body reaching the guest — with
// the explicit-proxy leg as the control proving the proxy was reachable either way.
//
// PART A — SNAPSHOT-AND-REPLAY CASSETTES (§6.4). Recorded against a real host service, then
// replayed with that service KILLED: the recorded body reaching the guest over a dead upstream
// is the assertion, and the dead-upstream curl in between is the control proving the replay is
// not just the network still working.
//
// RED ON THE INVERSE, per leg: drop `transparent::reconstruct_absolute_uri` and the plain-HTTP
// leg gets no double (its URI stays `/`); drop the ClientHello/SNI intake and the TLS leg dies
// with hudsucker's "unexpected eof" (the failure §6.4 recorded); drop the `handle_response`
// capture and the replay leg misses; make a miss fall through to the upstream and the miss leg
// gets a transport error instead of the typed 504.
#[cfg(feature = "cloud-hypervisor")]
#[tokio::test]
#[ignore = "unprivileged transparent MITM + cassettes: needs KVM + unprivileged vhost-user-net; selected by `just test-unprivileged`"]
async fn test_transparent_mitm_and_cassettes_unprivileged() {
    let vmm = vmcell::vmm::cloud_hypervisor::CloudHypervisor::new(common::ch_bin());
    // TEST-2: the CH primary path is not exempt from the capability check — `require_cap!` panics
    // for cloud-hypervisor rather than skipping green.
    require_cap!(
        vmcell::vmm::Vmm::capabilities(&vmm),
        unprivileged_vhost_user_net,
        vmm
    );

    let _ = env_logger::builder().is_test(true).try_init();

    let vmlinux = common::get_vmlinux();
    let rootfs = common::get_rootfs();

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

    // A real host service to record a real interaction against. Its own `Drop` kills it, so the
    // fixture owns its cleanup on the panic path too.
    let host_port = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    };
    struct Cleanup(Option<std::process::Child>);
    impl Cleanup {
        fn kill_now(&mut self) {
            if let Some(mut child) = self.0.take() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }
    impl Drop for Cleanup {
        fn drop(&mut self) {
            self.kill_now();
        }
    }
    let mut host_service = Cleanup(Some(
        std::process::Command::new("python3")
            .arg("-m")
            .arg("http.server")
            .arg(host_port.to_string())
            .spawn()
            .expect("python3 -m http.server"),
    ));
    // The cassette lives in a fixture tree that cleans itself up on the panic path as well.
    let cassette_dir = tempfile::tempdir().expect("cassette tempdir");
    let cassette = cassette_dir.path().join("egress.jsonl");

    let mut cfg = VmConfig::builder(vmlinux, RootfsSource::Erofs { image: rootfs })
        .build()
        .unwrap();
    cfg.net = vmcell::config::NetConfig::Unprivileged {
        egress: Egress::Filtered(proxy_cfg),
        host_services_port: Some(host_port),
    };

    let env = vmcell::HostEnv::hermetic();
    let mut vm = MicroVm::start(&vmm, cfg, &env).await.expect("VM start");
    let proxy_port = vm.proxy().expect("Filtered egress starts a proxy").port;
    let vmid = vm.vmid();
    let (gateway_ip, _g, _c) = vmcell::net::ip_math(vmid).expect("ip_math");
    let gateway = gateway_ip.to_string();

    let steward = vm.steward(None).await.expect("steward connects");
    // The NAT needs a moment after the guest's addresses come up, exactly as the sibling test does.
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    // ---- CONTROL: the explicit-proxy intake, which always worked. A failure here means the
    // proxy is unreachable, so the transparent legs below would be measuring the wrong thing.
    let control = proxied_curl(steward, &gateway, proxy_port, "http://example.com/").await;
    assert!(
        control.stdout.starts_with(b"MITM SUCCESS!"),
        "CONTROL (explicit proxy) must be MITM-intercepted; got: {} / {}",
        String::from_utf8_lossy(&control.stdout),
        String::from_utf8_lossy(&control.stderr)
    );

    // ---- TREATMENT 1: transparent PLAIN HTTP. No proxy env at all: the guest opens a raw
    // connection to port 80 and sends an ORIGIN-FORM request line. The destination exists only
    // in the `Host` header, which is what `reconstruct_absolute_uri` recovers.
    let plain = transparent_curl(steward, "example.com", 80, "http://example.com/").await;
    assert!(
        plain.stdout.starts_with(b"MITM SUCCESS!"),
        "the transparent plain-HTTP intake must be MITM-intercepted (Host-header reconstruction); \
         got: {} / {}",
        String::from_utf8_lossy(&plain.stdout),
        String::from_utf8_lossy(&plain.stderr)
    );

    // ---- TREATMENT 2: transparent TLS. Nothing in the stream is HTTP; the destination exists
    // only in the ClientHello's SNI, which the intake reads before handing the connection to
    // hudsucker behind a synthesized CONNECT.
    let tls = transparent_curl(steward, "example.com", 443, "https://example.com/").await;
    assert!(
        tls.stdout.starts_with(b"MITM SUCCESS!"),
        "the transparent TLS intake must be MITM-intercepted (SNI + synthesized CONNECT); \
         got: {} / {}",
        String::from_utf8_lossy(&tls.stdout),
        String::from_utf8_lossy(&tls.stderr)
    );

    // ---- TREATMENT 3: the DENY LIST now applies to transparent traffic, which is the security
    // half of the same fix — before it, a raw `GET /` + `Host: blocked.com` named no host for
    // `is_blocked` to test at all.
    let blocked = transparent_curl(steward, "blocked.com", 80, "http://blocked.com/").await;
    assert!(
        String::from_utf8_lossy(&blocked.stdout).contains("Blocked by vmcell Proxy"),
        "a transparently-reconstructed blocked host must be denied in-guest; got: {} / {}",
        String::from_utf8_lossy(&blocked.stdout),
        String::from_utf8_lossy(&blocked.stderr)
    );
    // And its TLS twin: the SNI names a blocked host, so the synthesized CONNECT is refused and
    // there is no tunnel — a transport failure in-guest, not a served page.
    let blocked_tls = transparent_curl(steward, "blocked.com", 443, "https://blocked.com/").await;
    assert_ne!(
        blocked_tls.code,
        0,
        "a transparent TLS connection to a blocked host must fail, not tunnel; got: {} / {}",
        String::from_utf8_lossy(&blocked_tls.stdout),
        String::from_utf8_lossy(&blocked_tls.stderr)
    );

    // ---- PART A: RECORD. The host service is a real upstream, so this is a real forwarded
    // interaction — a double's answer would make the replay below a tautology.
    vm.proxy()
        .expect("proxy")
        .record_cassette(&cassette, CassetteOptions::default())
        .expect("recording opens the cassette");
    let steward = vm.steward(None).await.expect("steward");
    let recorded = proxied_curl(
        steward,
        &gateway,
        proxy_port,
        &format!("http://127.0.0.1:{host_port}/"),
    )
    .await;
    let recorded_body = String::from_utf8_lossy(&recorded.stdout).to_string();
    assert!(
        recorded_body.contains("Directory listing for"),
        "the recorded leg must actually reach the host service; got: {recorded_body}"
    );
    let cassette_text = std::fs::read_to_string(&cassette).expect("cassette written to disk");
    assert!(
        cassette_text.contains(&format!("GET http://127.0.0.1:{host_port}/")),
        "the cassette must hold the interaction's key: {cassette_text}"
    );
    assert!(
        cassette_text.contains("Directory listing for"),
        "the cassette must hold the RESPONSE BODY, which is what `record_to`'s request-line log \
         could not: {cassette_text}"
    );

    // ---- THE NEGATIVE CONTROL FOR REPLAY: kill the upstream and prove it is gone. Without this,
    // a green replay leg is equally explained by "the network still works".
    host_service.kill_now();
    let dead = proxied_curl(
        steward,
        &gateway,
        proxy_port,
        &format!("http://127.0.0.1:{host_port}/"),
    )
    .await;
    assert!(
        !String::from_utf8_lossy(&dead.stdout).contains("Directory listing for"),
        "the host service must be DEAD before replay, or the replay leg proves nothing; got: {}",
        String::from_utf8_lossy(&dead.stdout)
    );

    // ---- PART A: REPLAY. Same request, no upstream at all, and the RECORDED BODY reaches the
    // guest. This is the assertion the whole feature exists for.
    vm.proxy()
        .expect("proxy")
        .replay_cassette(&cassette, CassetteOptions::default())
        .expect("replay loads the cassette");
    let steward = vm.steward(None).await.expect("steward");
    let replayed = proxied_curl(
        steward,
        &gateway,
        proxy_port,
        &format!("http://127.0.0.1:{host_port}/"),
    )
    .await;
    assert!(
        String::from_utf8_lossy(&replayed.stdout).contains("Directory listing for"),
        "the replayed interaction's BODY must reach the guest with the upstream dead; got: {} / {}",
        String::from_utf8_lossy(&replayed.stdout),
        String::from_utf8_lossy(&replayed.stderr)
    );

    // ---- A MISS IS LOUD, and never a fall-through: a path the cassette never recorded is a typed
    // 504 whose body names the miss, and the miss is retained as host-side data.
    let missed = proxied_curl(
        steward,
        &gateway,
        proxy_port,
        &format!("http://127.0.0.1:{host_port}/never-recorded"),
    )
    .await;
    assert!(
        String::from_utf8_lossy(&missed.stdout).contains("cassette miss"),
        "an unrecorded request must be answered by a loud cassette miss; got: {} / {}",
        String::from_utf8_lossy(&missed.stdout),
        String::from_utf8_lossy(&missed.stderr)
    );

    let misses = vm.proxy().expect("proxy").cassette_misses();
    assert_eq!(
        misses.iter().map(|m| m.key.clone()).collect::<Vec<_>>(),
        vec![format!("GET http://127.0.0.1:{host_port}/never-recorded")],
        "the miss must be retained as typed data, and ONLY the unrecorded request may miss"
    );

    // The host-observable record of the whole sequence.
    let requests = vm.proxy().expect("proxy").requests();
    for expected in ["CASSETTE RECORDED", "CASSETTE HIT", "504 CASSETTE MISS"] {
        assert!(
            requests.iter().any(|r| r.starts_with(expected)),
            "the request log must carry a `{expected}` entry; got: {requests:?}"
        );
    }
    assert!(
        requests.iter().any(|r| r == "GET http://example.com/"),
        "the transparent plain-HTTP request must be logged under its RECONSTRUCTED absolute URI \
         (an un-reconstructed one logs as `GET /`); got: {requests:?}"
    );
    assert!(
        requests
            .iter()
            .any(|r| r.starts_with("403 BLOCKED") && r.contains("blocked.com")),
        "the transparent deny must be recorded host-side; got: {requests:?}"
    );

    vm.shutdown().await.expect("Shutdown failed");
}
