use std::process::Command;
use vmcell::MicroVm;
use vmcell::agent::protocol::ExecRequest;
use vmcell::config::{RootfsSource, VmConfig};

mod common;

// TESTS-FEATURES-5. Uses the mandated `vmm_matrix_test!` / `require_cap!` harness and
// `common::get_vmlinux()`/`get_rootfs()` (env-overridable, asserted-present) instead of the
// per-backend hand-rolled tests and hardcoded `/tmp/vmcell-artifacts` paths.
vmm_matrix_test!(host_endpoint, |vmm| {
    require_cap!(
        vmcell::vmm::Vmm::capabilities(&vmm),
        unprivileged_vhost_user_net,
        vmm
    );
    test_host_endpoint_impl(&vmm).await;
});

async fn test_host_endpoint_impl<V: vmcell::vmm::Vmm>(vmm: &V) {
    let _ = env_logger::builder().is_test(true).try_init();
    let vmlinux = common::get_vmlinux();
    let rootfs = common::get_rootfs();

    let mut cfg = VmConfig::builder(vmlinux, RootfsSource::Erofs { image: rootfs })
        .build()
        .unwrap();
    let port = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    };
    cfg.net = vmcell::config::NetConfig::Unprivileged {
        egress: vmcell::config::Egress::Open,
        host_services_port: Some(port),
    };

    let cid_alloc = std::sync::Arc::new(vmcell::vmm::CidAllocator::new());
    let vmid_alloc = vmcell::orchestrator::VmidAllocator::new();
    let mut vm = MicroVm::start(
        vmm,
        cfg,
        cid_alloc.clone(),
        vmid_alloc,
        Box::new(vmcell::metrics::DefaultCgroupFs),
    )
    .await
    .expect("Failed to start VM");

    // The guest gateway IP uses the centralized (vmid % 254) + 1 octet math, not
    // the raw vmid — using the raw vmid is an off-by-one that reaches no host.
    let (host_ip, _guest_ip, _cidr) = vmcell::net::ip_math(vm.vmid()).expect("ip_math");
    let host_ip = host_ip.to_string();

    let child = Command::new("python3")
        .args([
            "-m",
            "http.server",
            &port.to_string(),
            "--bind",
            "127.0.0.1",
        ])
        .spawn()
        .expect("Failed to start http.server");

    // Own the http.server child so its `Drop` reaps it even if an assertion below
    // panics (e.g. the agent-connect `.expect(...)` on the line following) — a bare
    // late `child.kill()` leaks the host process on the panic path (AGENTS.md
    // "ownership owns cleanup — on panic"; audit E2, docs/41). Mirrors egress_proxy.rs.
    struct Cleanup(std::process::Child);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let _cleanup = Cleanup(child);

    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    // The IP-PNP contract (guest eth0 carries its (vmid%254)+1 /30 address, zero-netlink, via
    // the `ip=` cmdline) is the extracted `checks::net_ip_pnp` the validator runs (§8.3/§12.3).
    vmcell_artifact_validator::checks::net_ip_pnp(&mut vm)
        .await
        .expect("guest IP-PNP must configure eth0");

    // Give network time to settle, then exercise the NAT host-service forward (a vmcell
    // networking feature, not an artifact property — kept inline here).
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    let agent = vm
        .agent(None, &vmcell::orchestrator::RealClock)
        .await
        .expect("Failed to connect to agent");

    let outcome = agent
        .exec(ExecRequest::new(vec![
            "curl".into(),
            "--max-time".into(),
            "5".into(),
            "-v".into(),
            format!("http://{}:{}/", host_ip, port),
        ]))
        .await
        .expect("Exec failed");

    // `_cleanup`'s `Drop` reaps the http.server (on both the success and panic paths).

    assert_eq!(
        outcome.code,
        0,
        "curl failed: {:?}",
        String::from_utf8_lossy(&outcome.stderr)
    );
    let stdout = String::from_utf8_lossy(&outcome.stdout);
    // TEST-4: assert the specific, stable directory-listing title (as
    // egress_proxy.rs does) rather than a loose "Directory listing" || "html"
    // that an error page or a stray "<html>" body would satisfy.
    assert!(
        stdout.contains("Directory listing for"),
        "Output did not contain the host service's directory listing: {stdout}"
    );

    vm.shutdown().await.expect("Shutdown failed");
}
