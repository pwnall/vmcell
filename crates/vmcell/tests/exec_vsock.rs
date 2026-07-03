use futures::{SinkExt, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixListener;
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use vmcell::agent::AgentClient;
use vmcell::agent::protocol::{ExecRequest, Message};

#[tokio::test]
async fn test_exec_vsock_mock() {
    let tmp = std::env::temp_dir().join(format!("vmcell-test-vsock-{}", std::process::id()));
    let _ = std::fs::remove_file(&tmp);
    let listener = UnixListener::bind(&tmp).expect("Failed to bind UDS");

    let vsock_path = tmp.clone();

    // Spawn server to mock CloudHypervisor UDS vsock and the guest agent
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

    let mut client = AgentClient::connect(
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
    let _ = std::fs::remove_file(&tmp);
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
    let tmp = std::env::temp_dir().join(format!("vmcell-desync-exec-{}", std::process::id()));
    let _ = std::fs::remove_file(&tmp);
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

    let mut client = AgentClient::connect(
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
    let _ = std::fs::remove_file(&tmp);
}

// H-AGENT-1 (symmetric): after a put_file() timeout desyncs the stream, the next
// exec() must fail loud rather than read the put_file's stale Exit(0) ack as its
// own result. RED on the buggy put_file (it never set `desynced`): exec would
// proceed and return Ok(code 0) from the stale frame.
#[tokio::test]
async fn put_file_timeout_desyncs_subsequent_exec() {
    let tmp = std::env::temp_dir().join(format!("vmcell-desync-put-{}", std::process::id()));
    let _ = std::fs::remove_file(&tmp);
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

    let mut client = AgentClient::connect(
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
    let _ = std::fs::remove_file(&tmp);
}

// LOW (asymmetric frame caps): the host codec must accept a frame larger than
// tokio_util's 8 MiB LengthDelimitedCodec default — up to the 16 MiB cap the
// guest enforces. RED on the buggy host codec (`LengthDelimitedCodec::new()`,
// 8 MiB): decoding this frame errors and exec returns Err.
#[tokio::test]
async fn host_codec_accepts_frame_above_default_8mib() {
    let payload = vec![0xABu8; 8 * 1024 * 1024 + 64 * 1024];
    let expected = payload.clone();

    let tmp = std::env::temp_dir().join(format!("vmcell-bigframe-{}", std::process::id()));
    let _ = std::fs::remove_file(&tmp);
    let listener = UnixListener::bind(&tmp).expect("bind UDS");
    let vsock_path = tmp.clone();

    let server = tokio::spawn(async move {
        let mut framed = accept_with_ready(listener, vmcell::agent::MAX_FRAME_BYTES).await;
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

    let mut client = AgentClient::connect(
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
    let _ = std::fs::remove_file(&tmp);
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
    let vsock_path =
        std::env::temp_dir().join(format!("vmcell-nopath-{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&vsock_path);

    let serial = vmcell::vmm::FakeSerialLog { panicked: true };

    // Generous timeout: a fast-fail returns in well under a second; a connect that
    // ignored the panic would loop the whole 10s before timing out.
    let timeout = std::time::Duration::from_secs(10);
    let start = std::time::Instant::now();
    let res = AgentClient::connect(
        &vsock_path,
        5000,
        timeout,
        &vmcell::config::Timeouts::default(),
        &serial,
    )
    .await;
    let elapsed = start.elapsed();

    assert!(
        matches!(&res, Err(vmcell::Error::Agent(_))),
        "connect must fail with Error::Agent on a panicked serial log, got {res:?}"
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
    let tmp = std::env::temp_dir().join(format!("vmcell-streamerr-{}", std::process::id()));
    let _ = std::fs::remove_file(&tmp);
    let listener = UnixListener::bind(&tmp).expect("bind UDS");
    let vsock_path = tmp.clone();

    let server = tokio::spawn(async move {
        let mut framed = accept_with_ready(listener, vmcell::agent::MAX_FRAME_BYTES).await;
        let _ = framed.next().await; // read the Exec frame
        drop(framed); // close mid-exchange (no Exit) -> client exec errors, not a timeout
    });

    let mut client = AgentClient::connect(
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
        matches!(&next, Err(vmcell::Error::Agent(m)) if m.contains("reconnect required")),
        "a mid-exchange stream error must desync the stream so the next request fails loud; \
         got {next:?}"
    );

    server.await.unwrap();
    let _ = std::fs::remove_file(&tmp);
}

// M-GUEST-4: reconnect() must CLEAR the desynced flag (mod.rs:224) so requests work
// again after recovery. RED on a buggy reconnect that swaps the stream but leaves
// `desynced = true`: the post-reconnect exec would fail `ensure_synced()` with
// "reconnect required" instead of succeeding.
#[tokio::test]
async fn reconnect_clears_desynced() {
    let tmp = std::env::temp_dir().join(format!("vmcell-reconnect-{}", std::process::id()));
    let _ = std::fs::remove_file(&tmp);
    let listener = UnixListener::bind(&tmp).expect("bind UDS");
    let vsock_path = tmp.clone();

    let server = tokio::spawn(async move {
        // Connection 1: handshake, read the Exec, then close (EOF) so the client's
        // exec ends without an Exit frame -> Err -> desynced = true.
        let (s1, _) = listener.accept().await.unwrap();
        let mut f1 = handshake_ready(s1, vmcell::agent::MAX_FRAME_BYTES).await;
        let _ = f1.next().await; // Exec
        drop(f1);

        // Connection 2 (the reconnect): handshake on the SAME listener, then answer
        // the exec with Stdout + Exit(0). The single retained listener is why this
        // test uses `handshake_ready` rather than the listener-consuming
        // `accept_with_ready`.
        let (s2, _) = listener.accept().await.unwrap();
        let mut f2 = handshake_ready(s2, vmcell::agent::MAX_FRAME_BYTES).await;
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

    let mut client = AgentClient::connect(
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
        matches!(&blocked, Err(vmcell::Error::Agent(m)) if m.contains("reconnect required")),
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
    let _ = std::fs::remove_file(&tmp);
}

mod common;

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

    let cid_alloc = std::sync::Arc::new(vmcell::vmm::CidAllocator::new());
    let vmid_alloc = vmcell::orchestrator::VmidAllocator::new();
    let mut vm = vmcell::MicroVm::start(
        &vmm,
        cfg,
        cid_alloc,
        vmid_alloc,
        Box::new(vmcell::metrics::DefaultCgroupFs),
    )
    .await
    .expect("Failed to start VM");

    let agent = vm
        .agent(None, &vmcell::orchestrator::RealClock)
        .await
        .expect("Failed to connect to agent");

    agent
        .put_file("/tmp/hello.txt", b"hello world from test", None)
        .await
        .expect("put_file failed");

    let outcome = agent
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
