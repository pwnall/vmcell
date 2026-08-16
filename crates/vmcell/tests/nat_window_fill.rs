use std::io::Write;
use std::process::Command;
use vmcell::MicroVm;
use vmcell::config::{RootfsSource, VmConfig};
use vmcell::steward::protocol::ExecRequest;

mod common;

// Owns a spawned host helper so its `Drop` reaps it even if an assertion between
// spawn and teardown panics (AGENTS.md "ownership owns cleanup — on panic";
// mirrors host_endpoint.rs). One copy for both legs of this file.
struct Cleanup(std::process::Child);
impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

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
    let _cleanup = Cleanup(child);

    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    vmcell_artifact_validator::checks::net_ip_pnp(&mut vm)
        .await
        .expect("guest IP-PNP must configure eth0");
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    let steward = vm
        .steward(None)
        .await
        .expect("Failed to connect to steward");

    // Download the >64 KiB body through the NAT and digest it IN-GUEST. If the
    // host→guest pump drops any tail (the pre-fix unbounded read), the guest body
    // is truncated and its md5 differs from the host's.
    let outcome = steward
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

// A backpressuring HTTP sink: it accepts ONE connection, reads the body 1 KiB at
// a time with a pause between reads, and runs with an 8 KiB `SO_RCVBUF` so the
// advertised window stays small. Together those make the NAT's `try_write` into
// this connection return SHORT counts (and `WouldBlock`) instead of swallowing
// every offered span whole — which is what drives B1's "consume exactly what the
// host took" arm. It prints `<md5> <received> <content-length>` when done.
const BACKPRESSURING_SINK_PY: &str = r#"
import hashlib, socket, sys, time

port = int(sys.argv[1])
srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8192)
srv.bind(("127.0.0.1", port))
srv.listen(8)
conn, _ = srv.accept()
conn.settimeout(180)
buf = b""
while b"\r\n\r\n" not in buf:
    chunk = conn.recv(256)
    if not chunk:
        break
    buf += chunk
head, _, body = buf.partition(b"\r\n\r\n")
length = 0
for line in head.split(b"\r\n"):
    if line.lower().startswith(b"content-length:"):
        length = int(line.split(b":", 1)[1])
digest = hashlib.md5()
digest.update(body)
got = len(body)
while got < length:
    chunk = conn.recv(1024)
    if not chunk:
        break
    digest.update(chunk)
    got += len(chunk)
    time.sleep(0.0005)
conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
conn.close()
sys.stdout.write("%s %d %d\n" % (digest.hexdigest(), got, length))
sys.stdout.flush()
"#;

// B1 (`nat-guest-to-host-wrap-panic`) / M13 (`nat-no-guest-to-host-window-gate`):
// the GUEST→HOST half of the same pump, which nothing in the suite moved more
// than ~1 KiB through — which is why B1 shipped. The guest uploads 1 MiB, i.e.
// sixteen full passes over the 65536-byte smoltcp RX ring, so on many ticks the
// queued data straddles the ring wrap; the sink backpressures, so short
// `try_write` returns actually occur. Digest-compared end to end: the guest md5s
// the file it uploads, the sink md5s the bytes it received.
//
// RED on the inverse: restore the pre-fix `peek_slice` + `recv(|_| (written, ()))`
// shape and `RingBuffer::dequeue_many_with`'s `assert!(size <= max_size)` fires on
// the first wrap-crossing tick, killing the `run_network` thread. The vhost thread
// survives, so the device stays attached and the upload simply stalls: curl exits
// 28 (or the digests/lengths disagree), never 0. The KVM-free half of this gate is
// smoltcp.rs's `guest_to_host_drain_consumes_only_the_contiguous_span` (the fakes
// move no real bytes, so the ring wrap is invisible to them).
vmm_matrix_test!(nat_window_fill_upload, |vmm| {
    require_cap!(
        vmcell::vmm::Vmm::capabilities(&vmm),
        unprivileged_vhost_user_net,
        vmm
    );
    test_nat_window_fill_upload_impl(&vmm).await;
});

async fn test_nat_window_fill_upload_impl<V: vmcell::vmm::Vmm>(vmm: &V) {
    let _ = env_logger::builder().is_test(true).try_init();
    let vmlinux = common::get_vmlinux();
    let rootfs = common::get_rootfs();

    // 1 MiB = 16 × the 65536-byte smoltcp RX ring, so the wrap is crossed many
    // times over even if a tick drains the whole ring.
    const UPLOAD_BYTES: usize = 1024 * 1024;

    let dir = tempfile::tempdir().expect("tempdir");
    let sink_py = dir.path().join("backpressuring_sink.py");
    std::fs::File::create(&sink_py)
        .and_then(|mut f| f.write_all(BACKPRESSURING_SINK_PY.as_bytes()))
        .expect("write sink script");
    let sink_out = dir.path().join("sink.out");

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

    // The sink's line goes to a file so the child stays owned by `Cleanup` (a
    // `wait_with_output` would move it out of the panic-path reaper).
    let child = Command::new("python3")
        .arg(&sink_py)
        .arg(host_port.to_string())
        .stdout(std::fs::File::create(&sink_out).expect("create sink.out"))
        .spawn()
        .expect("Failed to start the backpressuring sink");
    let _cleanup = Cleanup(child);

    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    vmcell_artifact_validator::checks::net_ip_pnp(&mut vm)
        .await
        .expect("guest IP-PNP must configure eth0");
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    let steward = vm
        .steward(None)
        .await
        .expect("Failed to connect to steward");

    // Build the body in-guest, digest it there, then POST it through the NAT.
    // `-H 'Expect:'` suppresses curl's 100-continue round trip (a fixed 1 s stall
    // on bodies > 1 KiB); the trailing `%{http_code}` proves the sink replied.
    let outcome = steward
        .exec(
            ExecRequest::new(vec![
                "sh".into(),
                "-c".into(),
                format!(
                    "dd if=/dev/urandom of=/tmp/up.bin bs=65536 count={blocks} 2>/dev/null && \
                     md5sum /tmp/up.bin | cut -d' ' -f1 && \
                     curl --max-time 120 -s -o /dev/null -w '%{{http_code}}' -H 'Expect:' \
                     --data-binary @/tmp/up.bin http://{host_ip}:{host_port}/upload",
                    blocks = UPLOAD_BYTES / 65536,
                ),
            ])
            .with_timeout(std::time::Duration::from_secs(180)),
        )
        .await
        .expect("Exec failed");

    assert_eq!(
        outcome.code,
        0,
        "guest upload failed (curl exit 28 = the guest->host pump stalled): {:?} / {:?}",
        String::from_utf8_lossy(&outcome.stdout),
        String::from_utf8_lossy(&outcome.stderr)
    );
    let stdout = String::from_utf8_lossy(&outcome.stdout);
    let mut fields = stdout.split_whitespace();
    let guest_digest = fields.next().unwrap_or("").to_string();
    let http_code = fields.next().unwrap_or("").to_string();
    assert_eq!(
        http_code, "200",
        "sink did not complete the upload: {stdout}"
    );

    // The sink prints only after it has read `Content-Length` bytes and replied;
    // give it a moment to flush and exit after curl saw the response.
    let mut sink_line = String::new();
    for _ in 0..100 {
        sink_line = std::fs::read_to_string(&sink_out).unwrap_or_default();
        if !sink_line.trim().is_empty() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    let mut sink_fields = sink_line.split_whitespace();
    let sink_digest = sink_fields.next().unwrap_or("").to_string();
    let received: usize = sink_fields.next().unwrap_or("0").parse().unwrap_or(0);
    let declared: usize = sink_fields.next().unwrap_or("0").parse().unwrap_or(0);

    assert_eq!(
        declared, UPLOAD_BYTES,
        "the guest declared a body of {declared} bytes, not {UPLOAD_BYTES}"
    );
    assert_eq!(
        received, UPLOAD_BYTES,
        "guest->host NAT stream truncated: the sink received {received} of \
         {UPLOAD_BYTES} bytes"
    );
    assert_eq!(
        sink_digest, guest_digest,
        "guest->host NAT stream corrupted: the 1 MiB body's digest differs \
         (sink {sink_digest} != guest {guest_digest}); the RX-ring wrap was \
         mis-consumed"
    );

    vm.shutdown().await.expect("Shutdown failed");
}
