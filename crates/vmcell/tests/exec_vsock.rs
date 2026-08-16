use futures::{SinkExt, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixListener;
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use vmcell::steward::StewardClient;
use vmcell::steward::protocol::{ExecRequest, Message};

#[tokio::test]
async fn test_exec_vsock_mock() {
    // OWNED (`common::TempTree`): the mock-server socket used to be removed by a trailing
    // `remove_file` that any panicking assert below skips. The path has no UUID, so a leaked
    // socket from a same-pid prior run would break the `bind`; the guard removes it on the panic
    // path too.
    let sock_guard =
        common::TempTree::reserve(&format!("vmcell-test-vsock-{}", std::process::id()));
    let tmp = sock_guard.path().to_path_buf();
    let listener = UnixListener::bind(&tmp).expect("Failed to bind UDS");

    let vsock_path = tmp.clone();

    // Spawn server to mock CloudHypervisor UDS vsock and the steward
    let server_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();

        // 1. Read CONNECT <port>\n
        let mut resp = String::new();
        loop {
            let mut byte = [0; 1];
            let n = stream.read(&mut byte).await.unwrap();
            if n == 0 {
                break;
            }
            resp.push(byte[0] as char);
            if byte[0] == b'\n' {
                break;
            }
        }
        assert_eq!(resp, "CONNECT 5000\n");

        // 2. Send OK <port>\n
        stream.write_all(b"OK 5000\n").await.unwrap();

        // 3. Start framed protocol
        let mut framed = Framed::new(stream, LengthDelimitedCodec::new());

        // 4. Send Ready
        let ready_msg = postcard::to_stdvec(&Message::Ready).unwrap();
        framed.send(ready_msg.into()).await.unwrap();

        // 5. Expect Exec
        let msg_bytes = framed.next().await.unwrap().unwrap();
        let msg: Message = postcard::from_bytes(&msg_bytes).unwrap();
        match msg {
            Message::Exec(req) => {
                assert_eq!(req.argv[0], "echo");
                assert_eq!(req.argv[1], "hello");
            }
            _ => panic!("Expected Exec message"),
        }

        // 6. Send Stdout
        let stdout_msg = postcard::to_stdvec(&Message::Stdout(b"hello\n".to_vec())).unwrap();
        framed.send(stdout_msg.into()).await.unwrap();

        // 7. Send Exit
        let exit_msg = postcard::to_stdvec(&Message::Exit(0)).unwrap();
        framed.send(exit_msg.into()).await.unwrap();
    });

    let mut client = StewardClient::connect(
        &vsock_path,
        5000,
        std::time::Duration::from_secs(2),
        &vmcell::config::Timeouts::default(),
        &vmcell::vmm::RealSerialLog {
            path: std::path::PathBuf::from("/dev/null"),
        },
    )
    .await
    .expect("Failed to connect");

    let outcome = client
        .exec(ExecRequest::new(vec!["echo".into(), "hello".into()]))
        .await
        .expect("Exec failed");

    assert_eq!(outcome.code, 0);
    assert_eq!(outcome.stdout, b"hello\n");

    server_task.await.unwrap();
}

/// Mock-server helper: accept the UDS connection, complete the `CONNECT`/`OK`
/// handshake, wrap the stream in a `LengthDelimitedCodec` capped at `frame_max`
/// (the value the guest agrees on), and send the initial `Ready` frame.
async fn accept_with_ready(
    listener: UnixListener,
    frame_max: usize,
) -> Framed<tokio::net::UnixStream, LengthDelimitedCodec> {
    let (stream, _) = listener.accept().await.unwrap();
    handshake_ready(stream, frame_max).await
}

/// Completes the `CONNECT`/`OK` handshake on an ALREADY-ACCEPTED stream and sends
/// the initial `Ready` frame, returning the framed stream. Unlike
/// [`accept_with_ready`] this does not consume a `UnixListener`, so a server task
/// can accept multiple connections on one listener — needed by the reconnect test,
/// whose recovery opens a second connection to the same path.
async fn handshake_ready(
    mut stream: tokio::net::UnixStream,
    frame_max: usize,
) -> Framed<tokio::net::UnixStream, LengthDelimitedCodec> {
    let mut resp = String::new();
    loop {
        let mut byte = [0u8; 1];
        let n = stream.read(&mut byte).await.unwrap();
        if n == 0 {
            break;
        }
        resp.push(byte[0] as char);
        if byte[0] == b'\n' {
            break;
        }
    }
    assert_eq!(resp, "CONNECT 5000\n");
    stream.write_all(b"OK 5000\n").await.unwrap();
    let mut codec = LengthDelimitedCodec::new();
    codec.set_max_frame_length(frame_max);
    let mut framed = Framed::new(stream, codec);
    let ready = postcard::to_stdvec(&Message::Ready).unwrap();
    framed.send(ready.into()).await.unwrap();
    framed
}

fn serial_log() -> vmcell::vmm::RealSerialLog {
    vmcell::vmm::RealSerialLog {
        path: std::path::PathBuf::from("/dev/null"),
    }
}

// H-AGENT-1: after an exec() timeout desyncs the stream, a subsequent put_file
// must fail loud rather than read the exec's stale, late-arriving Exit(0) frame
// as its own ack. RED on the buggy put_file (no `desynced` guard): it would read
// the stale Exit(0) and wrongly return Ok.
#[tokio::test]
async fn exec_timeout_desyncs_subsequent_put_file() {
    let sock_guard =
        common::TempTree::reserve(&format!("vmcell-desync-exec-{}", std::process::id()));
    let tmp = sock_guard.path().to_path_buf();
    let listener = UnixListener::bind(&tmp).expect("bind UDS");
    let vsock_path = tmp.clone();

    let server = tokio::spawn(async move {
        let mut framed = accept_with_ready(listener, 16 * 1024 * 1024).await;
        // Read the Exec, then answer only AFTER the client's short timeout fires,
        // with a stale Exit(0) that a desync-ignoring put_file would misread.
        let _ = framed.next().await.unwrap().unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        let _ = framed
            .send(postcard::to_stdvec(&Message::Exit(0)).unwrap().into())
            .await;
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    });

    let mut client = StewardClient::connect(
        &vsock_path,
        5000,
        std::time::Duration::from_secs(2),
        &vmcell::config::Timeouts::default(),
        &serial_log(),
    )
    .await
    .expect("connect");

    let exec_res = client
        .exec(
            ExecRequest::new(vec!["sleep".into(), "30".into()])
                .with_timeout(std::time::Duration::from_millis(50)),
        )
        .await;
    assert!(exec_res.is_err(), "exec must time out");

    let put_res = client.put_file("/tmp/x", b"data", None).await;
    assert!(
        put_res.is_err(),
        "put_file on a desynced stream must fail loud, not read the stale Exit(0) as its ack"
    );

    server.abort();
}

// H-AGENT-1 (symmetric): after a put_file() timeout desyncs the stream, the next
// exec() must fail loud rather than read the put_file's stale Exit(0) ack as its
// own result. RED on the buggy put_file (it never set `desynced`): exec would
// proceed and return Ok(code 0) from the stale frame.
#[tokio::test]
async fn put_file_timeout_desyncs_subsequent_exec() {
    let sock_guard =
        common::TempTree::reserve(&format!("vmcell-desync-put-{}", std::process::id()));
    let tmp = sock_guard.path().to_path_buf();
    let listener = UnixListener::bind(&tmp).expect("bind UDS");
    let vsock_path = tmp.clone();

    let server = tokio::spawn(async move {
        let mut framed = accept_with_ready(listener, 16 * 1024 * 1024).await;
        // Read the PutFile, then send its ack only after the client's short
        // timeout fires; a desync-ignoring exec would misread it as its Exit.
        let _ = framed.next().await.unwrap().unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        let _ = framed
            .send(postcard::to_stdvec(&Message::Exit(0)).unwrap().into())
            .await;
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    });

    let mut client = StewardClient::connect(
        &vsock_path,
        5000,
        std::time::Duration::from_secs(2),
        &vmcell::config::Timeouts::default(),
        &serial_log(),
    )
    .await
    .expect("connect");

    let put_res = client
        .put_file(
            "/tmp/x",
            b"data",
            Some(std::time::Duration::from_millis(50)),
        )
        .await;
    assert!(put_res.is_err(), "put_file must time out");

    let exec_res = client
        .exec(ExecRequest::new(vec!["echo".into(), "hi".into()]))
        .await;
    assert!(
        exec_res.is_err(),
        "exec on a desynced stream must fail loud, not read the stale put_file ack as its result"
    );

    server.abort();
}

// LOW (asymmetric frame caps): the host codec must accept a frame larger than
// tokio_util's 8 MiB LengthDelimitedCodec default — up to the 16 MiB cap the
// guest enforces. RED on the buggy host codec (`LengthDelimitedCodec::new()`,
// 8 MiB): decoding this frame errors and exec returns Err.
#[tokio::test]
async fn host_codec_accepts_frame_above_default_8mib() {
    let payload = vec![0xABu8; 8 * 1024 * 1024 + 64 * 1024];
    let expected = payload.clone();

    let sock_guard = common::TempTree::reserve(&format!("vmcell-bigframe-{}", std::process::id()));
    let tmp = sock_guard.path().to_path_buf();
    let listener = UnixListener::bind(&tmp).expect("bind UDS");
    let vsock_path = tmp.clone();

    let server = tokio::spawn(async move {
        let mut framed = accept_with_ready(listener, vmcell::steward::MAX_FRAME_BYTES).await;
        let _ = framed.next().await.unwrap().unwrap(); // Exec
        framed
            .send(
                postcard::to_stdvec(&Message::Stdout(payload))
                    .unwrap()
                    .into(),
            )
            .await
            .unwrap();
        framed
            .send(postcard::to_stdvec(&Message::Exit(0)).unwrap().into())
            .await
            .unwrap();
    });

    let mut client = StewardClient::connect(
        &vsock_path,
        5000,
        std::time::Duration::from_secs(2),
        &vmcell::config::Timeouts::default(),
        &serial_log(),
    )
    .await
    .expect("connect");

    let outcome = client
        .exec(ExecRequest::new(vec!["big".into()]))
        .await
        .expect("exec must receive a >8 MiB frame the guest is allowed to send");
    assert_eq!(outcome.code, 0);
    assert_eq!(outcome.stdout.len(), expected.len());
    assert_eq!(outcome.stdout, expected);

    server.await.unwrap();
}

// M-GUEST-4: the connect loop must FAST-FAIL when the serial log shows a kernel
// panic (mod.rs:100-101), not spin to the deadline. RED on a buggy connect that
// drops the panic check: with a nonexistent socket it would retry until the full
// timeout elapses and then return `Timeout`, so BOTH the error variant and the
// elapsed-time bound below flip.
#[tokio::test]
async fn connect_panic_in_serial_log_fails_fast() {
    // A socket path that does NOT exist: connect must return via the panic check
    // (which precedes `UnixStream::connect`), so it never depends on this path.
    let sock_guard =
        common::TempTree::reserve(&format!("vmcell-nopath-{}.sock", std::process::id()));
    let vsock_path = sock_guard.path().to_path_buf();

    let serial = vmcell::vmm::FakeSerialLog { panicked: true };

    // Generous timeout: a fast-fail returns in well under a second; a connect that
    // ignored the panic would loop the whole 10s before timing out.
    let timeout = std::time::Duration::from_secs(10);
    let start = std::time::Instant::now();
    let res = StewardClient::connect(
        &vsock_path,
        5000,
        timeout,
        &vmcell::config::Timeouts::default(),
        &serial,
    )
    .await;
    let elapsed = start.elapsed();

    assert!(
        matches!(&res, Err(vmcell::Error::Steward(_))),
        "connect must fail with Error::Steward on a panicked serial log, got {res:?}"
    );
    assert!(
        elapsed < std::time::Duration::from_secs(1),
        "connect must FAST-FAIL on a serial-log panic (returned in {elapsed:?}); a connect \
         that ignored the panic check would spin to the {timeout:?} deadline"
    );
}

// M-GUEST-4: a mid-exchange STREAM ERROR (not a timeout) must also mark the stream
// desynced — the `Ok(Err)` arm of `finish_request` (mod.rs:257-259), distinct from
// the `Elapsed` arm the two timeout tests above exercise. The server reads the Exec
// then closes the connection before any Exit, so the client's exec ends in an error,
// not an `Elapsed`. RED on a buggy `finish_request` that sets `desynced` only on the
// timeout arm: the follow-up request would NOT fail loud with "reconnect required".
#[tokio::test]
async fn stream_error_desyncs_subsequent_request() {
    let sock_guard = common::TempTree::reserve(&format!("vmcell-streamerr-{}", std::process::id()));
    let tmp = sock_guard.path().to_path_buf();
    let listener = UnixListener::bind(&tmp).expect("bind UDS");
    let vsock_path = tmp.clone();

    let server = tokio::spawn(async move {
        let mut framed = accept_with_ready(listener, vmcell::steward::MAX_FRAME_BYTES).await;
        let _ = framed.next().await; // read the Exec frame
        drop(framed); // close mid-exchange (no Exit) -> client exec errors, not a timeout
    });

    let mut client = StewardClient::connect(
        &vsock_path,
        5000,
        std::time::Duration::from_secs(2),
        &vmcell::config::Timeouts::default(),
        &serial_log(),
    )
    .await
    .expect("connect");

    // No per-request timeout override: the error arrives from the closed stream, so
    // this exercises the error path, NOT an `Elapsed` timeout.
    let exec_res = client
        .exec(ExecRequest::new(vec!["echo".into(), "hi".into()]))
        .await;
    assert!(
        exec_res.is_err(),
        "exec must error when the server closes the stream mid-exchange"
    );

    let next = client
        .exec(ExecRequest::new(vec!["echo".into(), "again".into()]))
        .await;
    assert!(
        matches!(&next, Err(vmcell::Error::Steward(m)) if m.contains("reconnect required")),
        "a mid-exchange stream error must desync the stream so the next request fails loud; \
         got {next:?}"
    );

    server.await.unwrap();
}

// M-GUEST-4: reconnect() must CLEAR the desynced flag (mod.rs:224) so requests work
// again after recovery. RED on a buggy reconnect that swaps the stream but leaves
// `desynced = true`: the post-reconnect exec would fail `ensure_synced()` with
// "reconnect required" instead of succeeding.
#[tokio::test]
async fn reconnect_clears_desynced() {
    let sock_guard = common::TempTree::reserve(&format!("vmcell-reconnect-{}", std::process::id()));
    let tmp = sock_guard.path().to_path_buf();
    let listener = UnixListener::bind(&tmp).expect("bind UDS");
    let vsock_path = tmp.clone();

    let server = tokio::spawn(async move {
        // Connection 1: handshake, read the Exec, then close (EOF) so the client's
        // exec ends without an Exit frame -> Err -> desynced = true.
        let (s1, _) = listener.accept().await.unwrap();
        let mut f1 = handshake_ready(s1, vmcell::steward::MAX_FRAME_BYTES).await;
        let _ = f1.next().await; // Exec
        drop(f1);

        // Connection 2 (the reconnect): handshake on the SAME listener, then answer
        // the exec with Stdout + Exit(0). The single retained listener is why this
        // test uses `handshake_ready` rather than the listener-consuming
        // `accept_with_ready`.
        let (s2, _) = listener.accept().await.unwrap();
        let mut f2 = handshake_ready(s2, vmcell::steward::MAX_FRAME_BYTES).await;
        let _ = f2.next().await.unwrap().unwrap(); // Exec
        f2.send(
            postcard::to_stdvec(&Message::Stdout(b"ok\n".to_vec()))
                .unwrap()
                .into(),
        )
        .await
        .unwrap();
        f2.send(postcard::to_stdvec(&Message::Exit(0)).unwrap().into())
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    });

    let mut client = StewardClient::connect(
        &vsock_path,
        5000,
        std::time::Duration::from_secs(2),
        &vmcell::config::Timeouts::default(),
        &serial_log(),
    )
    .await
    .expect("connect");

    // Cause a desync: the server closes conn 1 mid-exchange.
    let first = client
        .exec(ExecRequest::new(vec!["echo".into(), "x".into()]))
        .await;
    assert!(
        first.is_err(),
        "exec must error when the server closes the stream mid-exchange (desyncs)"
    );
    // Confirm the stream is genuinely desynced before recovery.
    let blocked = client
        .exec(ExecRequest::new(vec!["echo".into(), "y".into()]))
        .await;
    assert!(
        matches!(&blocked, Err(vmcell::Error::Steward(m)) if m.contains("reconnect required")),
        "a request on the desynced stream must fail loud before reconnect; got {blocked:?}"
    );

    // reconnect() must clear the desync so the next exec succeeds.
    client
        .reconnect(
            &vsock_path,
            5000,
            std::time::Duration::from_secs(2),
            &vmcell::config::Timeouts::default(),
            &serial_log(),
        )
        .await
        .expect("reconnect");

    let after = client
        .exec(ExecRequest::new(vec!["echo".into(), "z".into()]))
        .await
        .expect("exec after reconnect must succeed (reconnect must clear `desynced`)");
    assert_eq!(
        after.code, 0,
        "post-reconnect exec must return the server's Exit(0), proving the stream is back in sync"
    );

    server.await.unwrap();
}

// ---------------------------------------------------------------------------
// §3.2 (The host side) — the raw vsock dial (`MicroVm::dial_vsock`), v30 delta 7.
// ---------------------------------------------------------------------------

/// Reads one `\n`-terminated line from a mock bridge's accepted stream, byte by
/// byte — the dial writes exactly one `CONNECT` line and then hands the socket to
/// its caller, so a buffered read here could consume the caller's first payload.
async fn read_connect_line(stream: &mut tokio::net::UnixStream) -> String {
    let mut line = String::new();
    loop {
        let mut byte = [0u8; 1];
        match stream.read(&mut byte).await {
            Ok(0) | Err(_) => return line,
            Ok(_) => {
                line.push(byte[0] as char);
                if byte[0] == b'\n' {
                    return line;
                }
            }
        }
    }
}

/// Returns an OWNED (`common::TempTree`) mock-bridge socket path: the guard's `Drop` removes it on
/// the success path and on the panic path, replacing the trailing `remove_file` each caller carried.
fn dial_socket_path(tag: &str) -> common::TempTree {
    common::TempTree::reserve(&format!("vmcell-dial-{tag}-{}.sock", std::process::id()))
}

// The raw dial's happy path over the hybrid AF_UNIX bridge, KVM-free: the mock
// bridge asserts the CONNECT line names the DIALED port (7000) rather than the
// endpoint's steward port (5000), and the byte stream round-trips in both directions.
// The exchange uses the PORTABLE order — write, drain the reply, only then
// half-close — the same order the live matrix leg and the `VsockDial` rustdoc
// prescribe, so no shipped test models the non-portable idiom.
// RED on: a dial that skips the prologue (the bridge's assert), one that dials the
// endpoint's own port (the port assert), or one that returns a handle whose
// AsyncRead/AsyncWrite forwarding is broken (the payload assert).
//
// WHAT THIS FAKE CANNOT SEE: the mock bridge is a plain `UnixStream`, so a host
// `shutdown()` here is a real half-close that a real VMM bridge may not forward.
// The three shipped bridges disagree on exactly that (Firecracker discards the
// guest's pending reply, QEMU races it) and no socketpair can show it — that axis
// belongs to the live legs `dial_vsock_echo` (portable order, all four backends)
// and `dial_vsock_host_half_close_forwards_*` (the two backends where it works).
#[tokio::test]
async fn dial_vsock_round_trips_bytes_over_the_hybrid_bridge() {
    let sock_guard = dial_socket_path("echo");
    let sock = sock_guard.path().to_path_buf();
    let listener = UnixListener::bind(&sock).expect("bind mock bridge");

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept");
        let line = read_connect_line(&mut stream).await;
        stream.write_all(b"OK 7000\n").await.expect("write OK");

        let mut seen = Vec::new();
        let mut buf = [0u8; 512];
        loop {
            let n = stream.read(&mut buf).await.expect("read payload");
            if n == 0 {
                break; // the client half-closed
            }
            seen.extend_from_slice(&buf[..n]);
            stream.write_all(&buf[..n]).await.expect("echo");
        }
        // Half-close back so the client observes EOF in the other direction too.
        stream.shutdown().await.expect("server shutdown");
        (line, seen)
    });

    let mut dial = vmcell::VsockDial::connect_endpoint(
        &vmcell::vmm::VsockEndpoint::Unix {
            path: sock.clone(),
            port: 5000,
        },
        7000,
        std::time::Duration::from_secs(5),
        &vmcell::config::Timeouts::default(),
    )
    .await
    .expect("raw dial must complete the hybrid prologue");

    let payload = b"ping over the raw vsock dial".to_vec();
    dial.write_all(&payload).await.expect("write");
    // Drain first (the portable order): the reply's length is known, so the read is
    // bounded without needing an EOF to terminate it.
    let mut back = vec![0u8; payload.len()];
    dial.read_exact(&mut back).await.expect("read echo");
    // Only now half-close, and confirm the stream ends cleanly with nothing left.
    dial.shutdown().await.expect("client half-close");
    let mut tail = Vec::new();
    dial.read_to_end(&mut tail).await.expect("read to EOF");
    assert!(
        tail.is_empty(),
        "nothing may follow the drained reply: {tail:?}"
    );

    let (line, seen) = server.await.expect("mock bridge task");
    assert_eq!(
        line, "CONNECT 7000\n",
        "the dial must CONNECT to the port the caller asked for, not the steward's 5000"
    );
    assert_eq!(seen, payload, "the guest side must receive every byte sent");
    assert_eq!(
        back, payload,
        "every echoed byte must come back to the host"
    );
}

// The dead-port signal CH's and Firecracker's in-VMM muxers send: accept the
// CONNECT, then close with no `OK` line. The dial must interpret it — a typed
// `Error::Steward` NAMING THE PORT — and return immediately, instead of reusing the
// steward connect's retry-until-deadline loop.
// RED on a dial built on `connect_framed`'s loop: both the variant (it would be
// `Error::Timeout`) and the elapsed bound (it would spin the full 10 s) flip.
#[tokio::test]
async fn dial_vsock_dead_port_fails_fast_with_a_typed_error() {
    let sock_guard = dial_socket_path("deadport");
    let sock = sock_guard.path().to_path_buf();
    let listener = UnixListener::bind(&sock).expect("bind mock bridge");

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept");
        let line = read_connect_line(&mut stream).await;
        drop(stream); // "no guest listener on that port"
        line
    });

    let budget = std::time::Duration::from_secs(10);
    let started = std::time::Instant::now();
    let res = vmcell::VsockDial::connect_endpoint(
        &vmcell::vmm::VsockEndpoint::Unix {
            path: sock.clone(),
            port: 5000,
        },
        7001,
        budget,
        &vmcell::config::Timeouts::default(),
    )
    .await;
    let elapsed = started.elapsed();

    assert_eq!(server.await.expect("mock bridge task"), "CONNECT 7001\n");
    assert!(
        matches!(&res, Err(vmcell::Error::Steward(m))
            if m.contains("no guest vsock listener") && m.contains("7001")),
        "an EOF before the OK line must be a typed no-listener error naming the port, got {res:?}"
    );
    assert!(
        elapsed < std::time::Duration::from_secs(1),
        "the dial must FAIL FAST on a dead port (took {elapsed:?}); a dial reusing the \
         steward connect's retry loop would spin to the {budget:?} deadline"
    );
}

// The other refusal shape, QEMU's external `vhost-device-vsock` daemon on a dead
// port: it accepts the CONNECT and simply never answers. That must run out the
// bounded per-byte read (`Timeouts::connect_ok_read`) into a typed `Error::Timeout`
// naming the port — distinct from the EOF case above, and still far inside the
// overall budget.
// RED on a dial with an unbounded `OK`-line read: it would hang to the 10 s budget
// (the elapsed bound), and RED on one that folds the hang into the no-listener
// `Error::Steward` (the variant assert).
#[tokio::test]
async fn dial_vsock_accept_and_hang_times_out_typed() {
    let sock_guard = dial_socket_path("hang");
    let sock = sock_guard.path().to_path_buf();
    let listener = UnixListener::bind(&sock).expect("bind mock bridge");

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept");
        let line = read_connect_line(&mut stream).await;
        (line, stream) // held open, never answered
    });

    let budget = std::time::Duration::from_secs(10);
    let started = std::time::Instant::now();
    let res = vmcell::VsockDial::connect_endpoint(
        &vmcell::vmm::VsockEndpoint::Unix {
            path: sock.clone(),
            port: 5000,
        },
        7002,
        budget,
        &vmcell::config::Timeouts::default(),
    )
    .await;
    let elapsed = started.elapsed();
    let (line, _held) = server.await.expect("mock bridge task");

    assert_eq!(line, "CONNECT 7002\n");
    assert!(
        matches!(&res, Err(vmcell::Error::Timeout(m)) if m.contains("7002")),
        "an accepted-and-hung bridge must be a typed timeout naming the port, got {res:?}"
    );
    assert!(
        elapsed < std::time::Duration::from_secs(1),
        "the per-byte read budget must bound the hang (took {elapsed:?}), far inside the \
         {budget:?} dial budget"
    );
}

mod common;

/// The live dial legs' shared fixtures, compiled only when at least one backend
/// feature is on (with none, `vmm_matrix_test!` expands to nothing and these would
/// be dead code).
#[cfg(any(
    feature = "cloud-hypervisor",
    feature = "firecracker",
    feature = "qemu",
    feature = "crosvm"
))]
use dial_live_fixtures::{dial_with_retry, start_vm_with_echo_server};

#[cfg(any(
    feature = "cloud-hypervisor",
    feature = "firecracker",
    feature = "qemu",
    feature = "crosvm"
))]
mod dial_live_fixtures {
    use super::common;

    /// Boots a VM and leaves the `echo-server` applet listening on vsock `port`.
    ///
    /// The listener is started through the steward and outlives the exec: the shell exits
    /// immediately, and the backgrounded server is reparented to the steward (PID 1) and
    /// keeps listening.
    ///
    /// # Panics
    /// Panics if the VM will not start or the applet cannot be backgrounded.
    pub async fn start_vm_with_echo_server<V: vmcell::vmm::Vmm>(
        vmm: &V,
        port: u32,
    ) -> vmcell::MicroVm<V> {
        let cfg = vmcell::config::VmConfig::builder(
            common::get_vmlinux(),
            vmcell::config::RootfsSource::Erofs {
                image: common::get_rootfs(),
            },
        )
        .network_disabled()
        .build()
        .unwrap();

        let env = vmcell::HostEnv::hermetic();
        let mut vm = vmcell::MicroVm::start(vmm, cfg, &env)
            .await
            .expect("Failed to start VM");

        let steward = vm
            .steward(None)
            .await
            .expect("Failed to connect to steward");
        let started = steward
            .exec(vmcell::steward::ExecRequest::new(vec![
                "sh".into(),
                "-c".into(),
                format!(
                    "/vmcell-tools/echo-server --vsock {port} </dev/null >/tmp/echo.log 2>&1 &"
                ),
            ]))
            .await
            .expect("spawning the echo-server must succeed");
        assert_eq!(
            started.code,
            0,
            "backgrounding the echo-server failed: {}",
            String::from_utf8_lossy(&started.stderr)
        );
        vm
    }

    /// Dials `port` on `vm`, retrying only the CONNECT (never an assertion) while the
    /// in-guest listener races the host — shared by every live dial leg so the retry
    /// cadence exists once.
    ///
    /// # Panics
    /// Panics if no attempt succeeds inside the window, naming the last error.
    pub async fn dial_with_retry<V: vmcell::vmm::Vmm>(
        vm: &vmcell::MicroVm<V>,
        port: u32,
        attempts: u32,
    ) -> vmcell::VsockDial {
        let mut last_err = None;
        for _ in 0..attempts {
            match vm.dial_vsock(port, std::time::Duration::from_secs(2)).await {
                Ok(d) => return d,
                Err(e) => {
                    last_err = Some(e);
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
            }
        }
        panic!(
            "dial_vsock must reach the in-guest listener on port {port} within \
         {attempts} attempts; last error: {last_err:?}"
        );
    }
}

// The live raw-dial matrix leg (§18 delta 7's named gate): a REAL in-guest listener
// — the `echo-server` guest-tools applet — reached from the host with no IP stack,
// on whichever endpoint arm the backend uses (AF_UNIX bridge on CH/FC/QEMU-default,
// in-kernel AF_VSOCK on crosvm). Asserts the data plane (every byte back), the
// portable half of EOF propagation, and that a port nobody listens on is a fast
// typed error.
//
// It asserts the PORTABLE contract only — write, drain the reply, then half-close —
// because the other order is not portable: measured 2026-08-11, a host `shutdown()`
// before draining loses the guest's reply outright on Firecracker (0/5) and races it
// on QEMU (2/5), while working on Cloud Hypervisor and crosvm (5/5 each). The
// earlier shape of this test asserted that non-portable order and was therefore RED
// on Firecracker and flaky on QEMU — the false design premise, not a test bug. The
// direction that DOES work everywhere is pinned here; the direction that works on
// two backends is pinned by the two `dial_vsock_host_half_close_forwards_*` legs
// below, so a regression on either is caught rather than papered over.
vmm_matrix_test!(dial_vsock_echo, |vmm| {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let vm = start_vm_with_echo_server(&vmm, 7000).await;

    // The listener races the dial; retry the CONNECT (not the assertions) briefly.
    let mut dial = dial_with_retry(&vm, 7000, 50).await;

    // The data plane, in the portable order: the reply's length is known, so it is
    // drained with a bounded `read_exact` that needs no EOF to terminate it.
    // RED if the applet echoes short, echoes something else, or the dial's
    // AsyncRead/AsyncWrite forwarding breaks.
    let payload = b"raw vsock dial round trip".to_vec();
    dial.write_all(&payload).await.expect("write to the guest");
    let mut back = vec![0u8; payload.len()];
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        dial.read_exact(&mut back),
    )
    .await
    .expect("the guest's echo must arrive well inside 10s")
    .expect("read the guest's echo");
    assert_eq!(
        back, payload,
        "the in-guest echo-server must return every byte over the raw dial"
    );

    // The portable half of EOF propagation: once the host half-closes a drained
    // connection, the stream ends — cleanly, promptly, with nothing trailing.
    // RED, measured, on a guest that never ends the connection (the applet's
    // `Ok(0) => return` replaced by a sleep loop): CH and crosvm both failed here on
    // the 10 s bound.
    // WHAT THIS CANNOT SEE, also measured: (a) on Firecracker and QEMU the host's
    // own `shutdown()` tears the connection down, so those two stayed GREEN under
    // that same mutation — the host supplies the EOF the guest withheld; and (b) it
    // cannot tell the applet's explicit `shutdown_write` from the connection simply
    // being dropped — deleting the half-close left all four backends green, because
    // the drop that follows closes the socket anyway. The half-close *itself* is
    // pinned KVM-free, where the peer can be held open, by
    // `echo_connection_half_closes_while_the_connection_stays_open` in
    // vmcell-guest-tools.
    dial.shutdown().await.expect("host half-close");
    let mut tail = Vec::new();
    let ended = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        dial.read_to_end(&mut tail),
    )
    .await
    .expect("the stream must end after the host half-closes, not hang");
    assert_eq!(
        ended.expect("read to EOF"),
        0,
        "nothing may follow an already-drained reply, got {tail:?}"
    );

    // A port with no listener: typed and fast, never a hang. The two transports
    // report it differently — the hybrid bridge answers by closing the stream
    // without an OK line (a typed Steward error naming the port), while the in-kernel
    // AF_VSOCK transport surfaces the kernel's own connect error.
    let hybrid = matches!(
        vmcell::vmm::VmInstance::vsock_endpoint(vm.instance()),
        vmcell::vmm::VsockEndpoint::Unix { .. }
    );
    let started_at = std::time::Instant::now();
    let dead = vm
        .dial_vsock(7999, std::time::Duration::from_secs(10))
        .await;
    let elapsed = started_at.elapsed();
    if hybrid {
        assert!(
            matches!(&dead, Err(vmcell::Error::Steward(m)) if m.contains("7999")),
            "a dead port on the hybrid bridge must be a typed no-listener error naming it, got {dead:?}"
        );
    } else {
        assert!(
            matches!(&dead, Err(vmcell::Error::Io(_))),
            "a dead port on AF_VSOCK must surface the kernel's connect error, got {dead:?}"
        );
    }
    assert!(
        elapsed < std::time::Duration::from_secs(3),
        "a dead port must fail fast (took {elapsed:?}), not run out the 10s budget"
    );

    vm.shutdown().await.expect("Shutdown failed");
});

// The OTHER direction — the one the `VsockDial` rustdoc says works on exactly two of
// the four backends — asserted positively on each of those two, so the doc's claim
// is a gate and not prose.
//
// The idiom: write, half-close WITHOUT draining, then read to EOF. The reply must
// still arrive in full. Deliberately NOT a matrix leg: it is red on Firecracker
// (measured 0/5 on 2026-08-11) and racy on QEMU (2/5), where the bridge translates
// the host's `SHUT_WR` into a connection teardown that discards whatever the guest
// had not yet flushed. Asserting it there is what made the delta's first live gate
// red; asserting it only here is what makes the per-backend claim checkable.
//
// RED if Cloud Hypervisor's in-VMM muxer or crosvm's in-kernel AF_VSOCK transport
// stops forwarding the half-close — the exact regression the rustdoc table would
// then be lying about. If it ever goes GREEN on Firecracker or QEMU, the table is
// stale in the safe direction and should be re-measured, not assumed.
#[cfg(any(feature = "cloud-hypervisor", feature = "crosvm"))]
async fn assert_host_half_close_forwards<V: vmcell::vmm::Vmm>(vmm: &V) {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let vm = start_vm_with_echo_server(vmm, 7000).await;
    let mut dial = dial_with_retry(&vm, 7000, 50).await;

    let payload = b"half-close is the only signal".to_vec();
    dial.write_all(&payload).await.expect("write to the guest");
    dial.shutdown().await.expect("host half-close");

    let mut back = Vec::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        dial.read_to_end(&mut back),
    )
    .await
    .expect("the drain after a half-close must not hang")
    .expect("read the guest's echo");
    assert_eq!(
        back, payload,
        "this backend must forward the host's half-close to the guest AND still \
         deliver the reply — that is what the VsockDial half-close table claims for \
         it; on Firecracker/QEMU this same exchange yields an empty read"
    );

    vm.shutdown().await.expect("Shutdown failed");
}

#[cfg(feature = "cloud-hypervisor")]
#[tokio::test]
#[ignore = "needs KVM"]
async fn dial_vsock_host_half_close_forwards_on_cloud_hypervisor() {
    let vmm = vmcell::vmm::cloud_hypervisor::CloudHypervisor::new(common::ch_bin());
    assert_host_half_close_forwards(&vmm).await;
}

// Named `…_on_crosvm` so the opt-in `just test-crosvm` recipe's `test(crosvm)`
// filter selects it: this is the in-kernel AF_VSOCK arm, the only one of the four
// with no host-side bridge to lose the half-close in.
#[cfg(feature = "crosvm")]
#[tokio::test]
#[ignore = "needs KVM"]
async fn dial_vsock_host_half_close_forwards_on_crosvm() {
    let vmm = vmcell_crosvm::Crosvm::new(common::crosvm_bin());
    assert_host_half_close_forwards(&vmm).await;
}

// §18 delta 7's guard-bypass gate, validated LIVE rather than presumed: boot with
// `init=` pointing at the echo-server applet itself, so there is no vmcell guest
// steward anywhere in the guest, and dial it raw. The vsock DEVICE is attached
// unconditionally by every backend (none reads `cfg.init`), which is what makes the
// bypass sound — and `steward()` refusing on the same VM is the positive control that
// the control plane really is absent.
//
// CH-only, like `tests/custom_init.rs`: this is a host-side cmdline + host-side dial
// feature, so one primary-backend data-plane proof suffices; QEMU's external
// vsock-daemon bring-up would only add non-standard-boot flake (and a custom init
// cannot combine with `snapshotting`, so the AF_VSOCK arm is not reachable here
// anyway — the matrix leg above covers it).
//
// The `--` token is the kernel's own hand-off: every cmdline token after it is
// passed to init as argv, which is how the applet learns its port with no steward to
// exec it.
#[cfg(feature = "cloud-hypervisor")]
#[tokio::test]
#[ignore = "needs KVM"]
async fn dial_vsock_reaches_a_custom_init_guest_with_no_steward() {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let vmm = vmcell::vmm::cloud_hypervisor::CloudHypervisor::new(common::ch_bin());
    let cfg = vmcell::config::VmConfig::builder(
        common::get_vmlinux(),
        vmcell::config::RootfsSource::Erofs {
            image: common::get_rootfs(),
        },
    )
    .init("/vmcell-tools/echo-server")
    .with_kernel_arg("--")
    .with_kernel_arg("--vsock")
    .with_kernel_arg("7000")
    .network_disabled()
    .build()
    .unwrap();

    let mut vm = common::start_vm(&vmm, cfg).await;

    // Positive control that there is genuinely NO control plane on this VM.
    let no_steward = vm
        .steward(Some(std::time::Duration::from_secs(2)))
        .await
        .expect_err("a custom-init VM has no steward");
    assert!(
        matches!(&no_steward, vmcell::Error::Steward(m) if m.contains("custom init")),
        "expected the fail-loud custom-init error, got {no_steward:?}"
    );

    // The raw dial must still reach the guest: the vsock device is attached
    // unconditionally, and the applet is PID 1.
    let mut dial = dial_with_retry(&vm, 7000, 100).await;

    // The portable order (drain, then half-close), even though this leg only ever
    // runs on Cloud Hypervisor: the half-close idiom is asserted in exactly one
    // place — `assert_host_half_close_forwards` — so this test stays about the
    // guard bypass and cannot quietly re-introduce the non-portable pattern.
    let payload = b"no steward, still dialable".to_vec();
    dial.write_all(&payload).await.expect("write to the guest");
    let mut back = vec![0u8; payload.len()];
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        dial.read_exact(&mut back),
    )
    .await
    .expect("the echo must arrive well inside 10s")
    .expect("read the echo");
    assert_eq!(
        back, payload,
        "the custom-init echo-server must echo over the raw dial with no steward present"
    );

    vm.kill().await.unwrap();
}

vmm_matrix_test!(put_file, |vmm| {
    let kernel = common::get_vmlinux();
    let rootfs_image = common::get_rootfs();

    let cfg = vmcell::config::VmConfig::builder(
        kernel,
        vmcell::config::RootfsSource::Erofs {
            image: rootfs_image,
        },
    )
    .network_disabled()
    .build()
    .unwrap();

    let env = vmcell::HostEnv::hermetic();
    let mut vm = vmcell::MicroVm::start(&vmm, cfg, &env)
        .await
        .expect("Failed to start VM");

    let steward = vm
        .steward(None)
        .await
        .expect("Failed to connect to steward");

    steward
        .put_file("/tmp/hello.txt", b"hello world from test", None)
        .await
        .expect("put_file failed");

    let outcome = steward
        .exec(ExecRequest::new(vec![
            "cat".into(),
            "/tmp/hello.txt".into(),
        ]))
        .await
        .expect("Exec failed");

    assert_eq!(outcome.code, 0);
    assert_eq!(
        outcome.stdout, b"hello world from test",
        "Round-trip file contents must match"
    );

    vm.shutdown().await.expect("Shutdown failed");
});
