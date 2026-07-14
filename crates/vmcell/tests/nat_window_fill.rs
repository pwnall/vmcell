use std::io::Write;
use std::process::Command;
use vmcell::MicroVm;
use vmcell::agent::protocol::ExecRequest;
use vmcell::config::{RootfsSource, VmConfig};

mod common;

// M5a / invariant #5 (design §6.2): the host→guest pump bounds every host-stream
// read to the smoltcp socket's free TX room (`host_read_budget`) so `send_slice`
// enqueues the WHOLE read. A >64 KiB host→guest transfer FILLS the guest TX
// buffer/receive window; the pre-fix unbounded 8 KiB read silently dropped the
// unsent tail, corrupting the stream. This is the window-filling data-plane gate
// design §6.2 claims exists. It needs a live smoltcp device (the fakes move no
// real bytes), so it runs on the unprivileged suite via `require_cap!`. RED on the
// inverse: revert smoltcp.rs's `host_read_budget`-bounded read to the unbounded
// `try_read(&mut buf)` and the 512 KiB body's tail is dropped on some tick, so the
// guest digest diverges from the host digest.
vmm_matrix_test!(nat_window_fill, |vmm| {
    require_cap!(
        vmcell::vmm::Vmm::capabilities(&vmm),
        unprivileged_vhost_user_net,
        vmm
    );
    test_nat_window_fill_impl(&vmm).await;
});

async fn test_nat_window_fill_impl<V: vmcell::vmm::Vmm>(vmm: &V) {
    let _ = env_logger::builder().is_test(true).try_init();
    let vmlinux = common::get_vmlinux();
    let rootfs = common::get_rootfs();

    // A >64 KiB deterministic body: 512 KiB overruns the 64 KiB smoltcp TX buffer
    // many times over, so the pre-fix unbounded read drops a tail on some tick.
    let dir = tempfile::tempdir().expect("tempdir");
    let body: Vec<u8> = (0..512u64 * 1024)
        .map(|i| i.wrapping_mul(2654435761) as u8)
        .collect();
    let file_path = dir.path().join("big.bin");
    std::fs::File::create(&file_path)
        .and_then(|mut f| f.write_all(&body))
        .expect("write big.bin");

    // Host-side digest of the exact bytes served (same algorithm the guest runs).
    let host_digest = {
        let out = Command::new("md5sum")
            .arg(&file_path)
            .output()
            .expect("host md5sum");
        assert!(out.status.success(), "host md5sum failed");
        String::from_utf8_lossy(&out.stdout)
            .split_whitespace()
            .next()
            .expect("md5 hex")
            .to_string()
    };

    let mut cfg = VmConfig::builder(vmlinux, RootfsSource::Erofs { image: rootfs })
        .build()
        .unwrap();
    let host_port = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    };
    cfg.net = vmcell::config::NetConfig::Unprivileged {
        egress: vmcell::config::Egress::Open,
        host_services_port: Some(host_port),
    };

    let env = vmcell::HostEnv::hermetic();
    let mut vm = MicroVm::start(vmm, cfg, &env)
        .await
        .expect("Failed to start VM");

    // The guest gateway IP uses the centralized (vmid % 254) + 1 octet math.
    let (host_ip, _guest_ip, _cidr) = vmcell::net::ip_math(vm.vmid()).expect("ip_math");
    let host_ip = host_ip.to_string();

    // Serve the temp dir over HTTP; own the child so Drop reaps it on any panic
    // (AGENTS.md "ownership owns cleanup — on panic"; mirrors host_endpoint.rs).
    let child = Command::new("python3")
        .args([
            "-m",
            "http.server",
            &host_port.to_string(),
            "--bind",
            "127.0.0.1",
            "--directory",
            dir.path().to_str().unwrap(),
        ])
        .spawn()
        .expect("Failed to start http.server");
    struct Cleanup(std::process::Child);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let _cleanup = Cleanup(child);

    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    vmcell_artifact_validator::checks::net_ip_pnp(&mut vm)
        .await
        .expect("guest IP-PNP must configure eth0");
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    let agent = vm.agent(None).await.expect("Failed to connect to agent");

    // Download the >64 KiB body through the NAT and digest it IN-GUEST. If the
    // host→guest pump drops any tail (the pre-fix unbounded read), the guest body
    // is truncated and its md5 differs from the host's.
    let outcome = agent
        .exec(ExecRequest::new(vec![
            "sh".into(),
            "-c".into(),
            format!("curl --max-time 20 -s http://{host_ip}:{host_port}/big.bin | md5sum"),
        ]))
        .await
        .expect("Exec failed");

    assert_eq!(
        outcome.code,
        0,
        "guest curl|md5sum failed: {:?}",
        String::from_utf8_lossy(&outcome.stderr)
    );
    let guest_digest = String::from_utf8_lossy(&outcome.stdout)
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_string();

    assert_eq!(
        guest_digest, host_digest,
        "host->guest NAT stream corrupted: the >64 KiB body's digest differs \
         (guest {guest_digest} != host {host_digest}); the send_slice tail was dropped"
    );

    vm.shutdown().await.expect("Shutdown failed");
}
