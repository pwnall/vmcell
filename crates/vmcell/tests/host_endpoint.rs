use std::process::Command;
use vmcell::MicroVm;
use vmcell::agent::protocol::ExecRequest;
use vmcell::config::{Egress, NetConfig, RootfsSource, VmConfig};

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

/// Owns a host-side child so its `Drop` reaps it even if an assertion panics — a bare late
/// `child.kill()` leaks the host process on the panic path (AGENTS.md "ownership owns cleanup —
/// on panic"; audit E2, docs/41). Mirrors egress_proxy.rs.
struct Cleanup(std::process::Child);
impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// What one leg observed: the in-guest `curl` exit code and stdout.
struct DialResult {
    code: i32,
    stdout: String,
    stderr: String,
}

/// Boots a VM whose networking is `Unprivileged { egress, host_services_port: Some(port) }`,
/// proves its guest networking came up, and dials the host endpoint at
/// `<this VM's host IP>:<port>` from inside the guest.
///
/// The two legs differ in **exactly one field**, `egress` — that is what makes the pair a
/// controlled comparison rather than two unrelated configurations.
///
/// `cfg.net` is assigned directly, not through `.net(…)` on the builder, because
/// `VmConfigBuilder::build` now REFUSES `Blocked` + `host_services_port` (F1: an input no
/// datapath reads is rejected, not silently ignored). `VmConfig`'s fields are public, so that
/// refusal binds the builder, not the struct — and the datapath must honor `Blocked` however the
/// config was assembled. Assembling it here therefore does two things at once: it keeps the two
/// legs identical but for the variant, and it exercises the defense-in-depth half of M1 (the NAT
/// registering no forward and refusing the dial) rather than only the boundary half.
///
/// The gateway address is recomputed through `vmcell::net::ip_math` — the centralized
/// `(vmid % 254) + 1` octet math, never the raw vmid (an off-by-one that reaches no host) and
/// never a test-local `format!`. Each leg gets its own vmid, so each dials its own `/30`
/// gateway; the host service behind it is the same listener on the same port.
async fn dial_host_endpoint<V: vmcell::vmm::Vmm>(vmm: &V, egress: Egress, port: u16) -> DialResult {
    let mut cfg = VmConfig::builder(
        common::get_vmlinux(),
        RootfsSource::Erofs {
            image: common::get_rootfs(),
        },
    )
    .build()
    .unwrap();
    cfg.net = NetConfig::Unprivileged {
        egress,
        host_services_port: Some(port),
    };

    let env = vmcell::HostEnv::hermetic();
    let mut vm = MicroVm::start(vmm, cfg, &env)
        .await
        .expect("Failed to start VM");

    let (host_ip, _guest_ip, _cidr) = vmcell::net::ip_math(vm.vmid()).expect("ip_math");

    // Let the guest finish bringing `eth0` up before reading it. Load-bearing on QEMU, whose
    // virtio-net link is still `state down` the instant the agent answers — without this the
    // IP-PNP check below fails with `eth0 is not up` on that backend alone.
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    // The IP-PNP contract (guest eth0 carries its (vmid%254)+1 /30 address, zero-netlink, via
    // the `ip=` cmdline) is the extracted `checks::net_ip_pnp` the validator runs
    // (§5.3, The kernel command line / §13, Cross-cutting invariants).
    //
    // It is also this test's control for the NEGATIVE leg: it proves the guest's datapath is up
    // and addressed under `Blocked` too, so a refused dial below is the egress policy refusing
    // it — not a VM that simply has no network.
    vmcell_artifact_validator::checks::net_ip_pnp(&mut vm)
        .await
        .expect("guest IP-PNP must configure eth0");

    // Give network time to settle, then exercise the NAT host-service forward (a vmcell
    // networking feature, not an artifact property — kept inline here).
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    let agent = vm.agent(None).await.expect("Failed to connect to agent");

    // The in-guest `curl` is vmcell's own shim, which REJECTS any flag it cannot honor, so this
    // argv cannot be silently neutered (AGENTS.md "never neuter the property under test").
    let outcome = agent
        .exec(ExecRequest::new(vec![
            "curl".into(),
            "--max-time".into(),
            "5".into(),
            "-v".into(),
            format!("http://{host_ip}:{port}/"),
        ]))
        .await
        .expect("Exec failed");

    vm.shutdown().await.expect("Shutdown failed");

    DialResult {
        code: outcome.code,
        stdout: String::from_utf8_lossy(&outcome.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&outcome.stderr).into_owned(),
    }
}

/// The §6.3 host-endpoint mechanism, and finding `M1`'s live leg: the SAME in-guest dial to the
/// host endpoint succeeds under [`Egress::Open`] and fails under [`Egress::Blocked`].
///
/// `Blocked`'s rustdoc promises "all egress traffic is blocked", but on the unprivileged arm it
/// used to share `Open`'s empty else-path in `setup_env`: the `host_services_port` forward was
/// still registered and the NAT still dialled out on the guest's behalf, so the variant was a
/// third spelling of `Open`. The KVM-free tests can only reach the *decision*
/// (`nat_egress_plan`'s port list + `NatEgressPolicy`); whether a guest packet actually fails to
/// reach the host is observable only here.
///
/// Both legs boot the same rootfs/kernel with the same `host_services_port`, run the same `curl`
/// against the same host listener, and differ in exactly one config field. RED ON THE INVERSE,
/// observed: folding `Egress::Blocked` back into `nat_egress_plan`'s `Open` arm — the pre-fix
/// shared else-path — makes the `Blocked` leg's `curl` return 0 with the directory listing.
/// (Flipping only the `NatEgressPolicy` to `Allow` does NOT redden it: with no forward port
/// registered there is no mapping for the NAT to dial through, so the port-registration half of
/// the fix is what this leg observes. The policy half is gated by
/// `net::smoltcp::backend::tests::blocked_egress_opens_no_outbound_connection`.)
///
/// Positive control (AGENTS.md "a negative security result needs a positive control"): the `Open`
/// leg must genuinely reach the endpoint — asserted on the server's own directory-listing title
/// (TEST-4), not on a loose "html" that an error page would satisfy — so a refusal below cannot
/// be a broken fixture, a dead listener or a wrong address.
async fn test_host_endpoint_impl<V: vmcell::vmm::Vmm>(vmm: &V) {
    let _ = env_logger::builder().is_test(true).try_init();

    let port = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    };
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
    // `_cleanup`'s `Drop` reaps the http.server on both the success and panic paths.
    let _cleanup = Cleanup(child);
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    // ---- positive control: `Open` + a host services port reaches the endpoint ----------------
    let open = dial_host_endpoint(vmm, Egress::Open, port).await;
    assert_eq!(
        open.code, 0,
        "curl failed under Egress::Open: {}",
        open.stderr
    );
    // TEST-4: assert the specific, stable directory-listing title (as egress_proxy.rs does)
    // rather than a loose "Directory listing" || "html" that an error page or a stray "<html>"
    // body would satisfy.
    assert!(
        open.stdout.contains("Directory listing for"),
        "Output did not contain the host service's directory listing: {}",
        open.stdout
    );

    // ---- the M1 assertion: the same dial is refused under `Blocked` --------------------------
    let blocked = dial_host_endpoint(vmm, Egress::Blocked, port).await;
    assert_ne!(
        blocked.code, 0,
        "`Egress::Blocked` promises that all egress is blocked, but the in-guest dial to the \
         host endpoint SUCCEEDED — it is behaving as a third spelling of `Open` (M1). stdout: {}",
        blocked.stdout
    );
    assert!(
        !blocked.stdout.contains("Directory listing for"),
        "`Egress::Blocked` let the host service's response through: {}",
        blocked.stdout
    );
}
