//! The §17 port-forward bridge's data-plane battery: a host TCP listener relaying into a guest
//! AF_VSOCK port (`vmcell::steward::forward`).
//!
//! Shaped after `tests/nat_window_fill.rs`, the tree's other byte-relay battery: window-filling and
//! over-[`MAX_FRAME_BYTES`] payloads, moved **in both directions**, digest-compared, against a peer
//! that backpressures. The NAT's version needs a live guest because its datapath is a vhost-user
//! device; this one has a KVM-free half because the forwarder's guest side is a *socket* — the fake
//! hybrid bridge below is byte-identical to what Cloud Hypervisor's and Firecracker's in-VMM muxers
//! expose (an AF_UNIX socket that answers `CONNECT <port>` with `OK <port>`).
//!
//! WHAT THE FAKE BRIDGE CANNOT SEE, stated rather than implied: it is a plain `UnixStream`, so a
//! host `shutdown()` on it is a real half-close that the guest observes. Two of the four shipped
//! bridges disagree — Firecracker discards the guest's pending reply, QEMU races it — and no
//! socketpair can show that. Which is exactly why the forwarder's default never issues one; the
//! `EndOfStream` legs below pin *which* operation each arm performs, and `VsockDial`'s measured
//! table (not a fake) is what says what each backend then does with it.

use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use vmcell::steward::MAX_FRAME_BYTES;
use vmcell::steward::forward::{EndOfStream, ForwardOptions, PortForward};
use vmcell::vmm::VsockEndpoint;

mod common;

/// A window-filling payload: 1 MiB is many times every socket buffer and receive window on the
/// path, so a mishandled count cannot hide inside one buffer.
const WINDOW_FILLING_BYTES: usize = 1024 * 1024;

/// An order-sensitive digest (FNV-1a 64), so a dropped, duplicated or reordered span is visible.
/// Local to this binary: an integration test cannot see this crate's optional `sha2`, and the point
/// is corruption detection, not cryptography.
fn digest(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// A deterministic body of `len` bytes.
fn body(len: usize) -> Vec<u8> {
    (0..len as u64)
        .map(|i| i.wrapping_mul(2_654_435_761) as u8)
        .collect()
}

/// Polls `cond` until it holds or `budget` elapses; returns whether it held.
///
/// An `Instant` budget over the whole wait, not a fixed number of sleeps: a residue assertion that
/// can only ever be "not yet" is not an assertion.
async fn wait_until(budget: Duration, mut cond: impl FnMut() -> bool) -> bool {
    let deadline = std::time::Instant::now() + budget;
    while std::time::Instant::now() < deadline {
        if cond() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    cond()
}

// ---------------------------------------------------------------------------
// The fake hybrid vsock bridge — the guest side of every KVM-free leg.
// ---------------------------------------------------------------------------

/// What the fake bridge does with a connection once its prologue has completed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Guest {
    /// Echo every byte back, in small paced chunks so the forwarder's writes into it return SHORT
    /// counts and `WouldBlock` — the backpressuring peer the count law needs.
    PacedEcho,
    /// Echo every byte back as fast as it can (for the multi-megabyte legs, where pacing every
    /// 4 KiB would dominate the run).
    FastEcho,
    /// Read whatever arrives and answer, once, after a delay — then stay open forever. The shape
    /// that distinguishes "the guest saw EOF" from "the guest was told nothing".
    DelayedReply,
    /// Accept and then say nothing at all, forever.
    Silent,
    /// Answer the `CONNECT` with nothing at all and close: the CH/FC in-VMM muxer's dead-port
    /// signal.
    DeadPort,
    /// Sleep past a tight `connect_ok_read` before answering `OK`.
    SlowOk,
}

/// What one bridge connection observed, for the assertions that are about the *guest's* view.
#[derive(Debug, Default)]
struct Observed {
    /// Whether the host **half-closed** — read returned `Ok(0)` *and* a probe write still
    /// succeeded, so the connection itself is alive.
    ///
    /// The distinction is the whole point of the `EndOfStream` legs and a fixture that skipped it
    /// was verifiably useless: a plain "read returned 0" flag also goes true when the relay is torn
    /// down at the end of the connection, so the `ForwardHalfClose` leg passed against a build whose
    /// `ForwardHalfClose` arm did nothing at all. On AF_UNIX a write after the peer's `SHUT_WR`
    /// succeeds and a write after its `close` is `EPIPE`, which is exactly the question being asked.
    saw_half_close: std::sync::atomic::AtomicBool,
    /// Whether the connection ended (EOF or error) — the residue signal for "the relay let go".
    ended: std::sync::atomic::AtomicBool,
    /// Bytes received from the host, and their digest.
    received: std::sync::atomic::AtomicU64,
    digest: std::sync::Mutex<u64>,
    /// Connections accepted.
    accepted: std::sync::atomic::AtomicU64,
}

impl Observed {
    fn saw_half_close(&self) -> bool {
        self.saw_half_close
            .load(std::sync::atomic::Ordering::Relaxed)
    }
    fn ended(&self) -> bool {
        self.ended.load(std::sync::atomic::Ordering::Relaxed)
    }
    fn received(&self) -> u64 {
        self.received.load(std::sync::atomic::Ordering::Relaxed)
    }
    fn accepted(&self) -> u64 {
        self.accepted.load(std::sync::atomic::Ordering::Relaxed)
    }
}

/// A running fake bridge: its socket path, what it saw, and the task that serves it.
struct Bridge {
    guard: common::TempTree,
    observed: std::sync::Arc<Observed>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Bridge {
    /// A test's own fixtures are residue too, on the panic path as much as the success path.
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Bridge {
    /// Binds a bridge whose *n*-th connection is served by `behaviors[min(n, len-1)]`.
    fn spawn(tag: &str, port: u32, behaviors: &'static [Guest]) -> Self {
        let guard =
            common::TempTree::reserve(&format!("vmcell-forward-{tag}-{}.sock", std::process::id()));
        let path = guard.path().to_path_buf();
        let listener = tokio::net::UnixListener::bind(&path).expect("bind fake bridge");
        let observed = std::sync::Arc::new(Observed::default());
        let task = tokio::spawn(serve_bridge(
            listener,
            port,
            behaviors,
            std::sync::Arc::clone(&observed),
        ));
        Self {
            guard,
            observed,
            task,
        }
    }

    /// The endpoint a `PortForward` dials — the same shape `VmInstance::vsock_endpoint` returns for
    /// Cloud Hypervisor, Firecracker and a default QEMU.
    fn endpoint(&self) -> VsockEndpoint {
        VsockEndpoint::Unix {
            path: self.guard.path().to_path_buf(),
            port: 5000,
        }
    }
}

/// Reads one `\n`-terminated line byte by byte — a buffered read here would swallow the payload the
/// forwarder sends immediately after its `CONNECT`.
///
/// A local copy of `tests/exec_vsock.rs`'s helper on purpose: each integration test binary is its own
/// crate, and the shared `tests/common` module is deliberately not where one-file fixtures live.
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

async fn serve_bridge(
    listener: tokio::net::UnixListener,
    port: u32,
    behaviors: &'static [Guest],
    observed: std::sync::Arc<Observed>,
) {
    loop {
        let Ok((mut stream, _)) = listener.accept().await else {
            return;
        };
        let index = observed
            .accepted
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed) as usize;
        let behavior = *behaviors
            .get(index)
            .or_else(|| behaviors.last())
            .expect("a bridge needs at least one behavior");
        let observed = std::sync::Arc::clone(&observed);
        tokio::spawn(async move {
            let line = read_connect_line(&mut stream).await;
            assert_eq!(
                line,
                format!("CONNECT {port}\n"),
                "the forwarder must dial the port it was configured with"
            );
            if behavior == Guest::DeadPort {
                drop(stream); // no `OK`: the muxer's "nobody listens there"
                return;
            }
            if behavior == Guest::SlowOk {
                tokio::time::sleep(Duration::from_millis(600)).await;
            }
            if stream
                .write_all(format!("OK {port}\n").as_bytes())
                .await
                .is_err()
            {
                return;
            }
            serve_connection(stream, behavior, &observed).await;
            observed
                .ended
                .store(true, std::sync::atomic::Ordering::Relaxed);
        });
    }
}

async fn serve_connection(
    mut stream: tokio::net::UnixStream,
    behavior: Guest,
    observed: &Observed,
) {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    let mut buf = vec![0u8; 4096];
    let mut replied = false;
    loop {
        let read = match stream.read(&mut buf).await {
            Ok(0) => {
                // Half-close or teardown? Ask the socket: a write after the peer's `SHUT_WR`
                // succeeds; a write after its `close` is `EPIPE`. The probe byte is harmless — every
                // behavior that can reach here has already sent whatever its client reads.
                if stream.write_all(b"\0").await.is_ok() {
                    observed
                        .saw_half_close
                        .store(true, std::sync::atomic::Ordering::Relaxed);
                }
                break;
            }
            Ok(n) => n,
            Err(_) => break,
        };
        let chunk = &buf[..read];
        for byte in chunk {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
        observed
            .received
            .fetch_add(read as u64, std::sync::atomic::Ordering::Relaxed);
        *observed.digest.lock().expect("digest lock") = hash;
        match behavior {
            Guest::PacedEcho => {
                if stream.write_all(chunk).await.is_err() {
                    break;
                }
                tokio::time::sleep(Duration::from_micros(200)).await;
            }
            Guest::FastEcho => {
                if stream.write_all(chunk).await.is_err() {
                    break;
                }
            }
            Guest::DelayedReply => {
                if !replied {
                    replied = true;
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    if stream.write_all(b"reply").await.is_err() {
                        break;
                    }
                }
            }
            Guest::Silent | Guest::DeadPort | Guest::SlowOk => {}
        }
    }
    // Half-close back, so a host client observes a clean EOF in the portable direction too.
    let _ = stream.shutdown().await;
}

/// Drives one full-duplex exchange of `payload` through `addr` and returns what came back.
///
/// Both directions concurrently, because that is what a relay is: a sequential write-then-read would
/// deadlock on any payload larger than the sum of the buffers on the path — and would not test the
/// window-filling case at all.
async fn round_trip(addr: std::net::SocketAddr, payload: Vec<u8>) -> Vec<u8> {
    try_round_trip(addr, payload)
        .await
        .expect("the round trip must complete")
}

/// The fallible form. It exists because the live leg's readiness probe RETRIES: a probe whose
/// failure is a panic inside a spawned task cannot be retried, it can only take the test down with
/// it — which is what the first cut of the live leg did, on its very first attempt, before the
/// in-guest listener was up.
async fn try_round_trip(addr: std::net::SocketAddr, payload: Vec<u8>) -> std::io::Result<Vec<u8>> {
    let stream = tokio::net::TcpStream::connect(addr).await?;
    let (mut reader, mut writer) = tokio::io::split(stream);
    let want = payload.len();
    let sender = tokio::spawn(async move {
        writer.write_all(&payload).await?;
        writer.flush().await?;
        Ok::<_, std::io::Error>(writer) // held open: this leg is about bytes, not about EOF
    });
    let receiver = tokio::spawn(async move {
        let mut back = vec![0u8; want];
        reader.read_exact(&mut back).await?;
        Ok::<_, std::io::Error>(back)
    });
    let writer = sender.await.map_err(std::io::Error::other)??;
    let back = receiver.await.map_err(std::io::Error::other)??;
    drop(writer);
    Ok(back)
}

// ---------------------------------------------------------------------------
// The data plane, both directions, against a backpressuring peer.
// ---------------------------------------------------------------------------

// The window-filling leg. 1 MiB host→guest and the same 1 MiB guest→host, through a peer that reads
// 4 KiB at a time and pauses between echoes, so the forwarder's writes into the guest return SHORT
// counts and its reads return partial buffers on nearly every iteration.
//
// RED ON THE INVERSE (both arms driven): in `pump`, write `&buf` instead of `buf.get(..read)` and the
// guest receives ~64 KiB per iteration, so its digest and its byte count both diverge; replace
// `write_all` with a single `write` and the tail of every partial write is dropped, so the echoed
// digest diverges.
#[tokio::test]
async fn port_forward_moves_a_window_filling_payload_in_both_directions() {
    let bridge = Bridge::spawn("window", 7000, &[Guest::PacedEcho]);
    let forward = PortForward::bind(
        "127.0.0.1:0".parse().expect("literal"),
        bridge.endpoint(),
        7000,
        ForwardOptions::default(),
    )
    .await
    .expect("bind the forwarder");

    let payload = body(WINDOW_FILLING_BYTES);
    let sent = digest(&payload);
    // 30 s against a healthy path that takes well under a second, so a broken count is a red
    // ASSERTION here rather than a `TIMEOUT` verdict from the harness 60 s later.
    let back = tokio::time::timeout(
        Duration::from_secs(30),
        round_trip(forward.local_addr(), payload.clone()),
    )
    .await
    .expect(
        "the round trip did not complete in 30 s: a relay that drops the tail of a partial write \
         truncates the echo, so the read never finishes",
    );

    assert_eq!(back.len(), payload.len(), "the echo must be whole");
    assert_eq!(
        digest(&back),
        sent,
        "guest->host relay corrupted: the echoed digest differs"
    );
    assert_eq!(
        bridge.observed.received(),
        payload.len() as u64,
        "host->guest relay truncated: the guest received {} of {} bytes",
        bridge.observed.received(),
        payload.len()
    );
    assert_eq!(
        *bridge.observed.digest.lock().expect("digest lock"),
        sent,
        "host->guest relay corrupted: the guest's digest differs"
    );
    assert_eq!(
        forward.bytes_to_guest(),
        payload.len() as u64,
        "the forwarder must count every byte it relayed to the guest"
    );
    assert_eq!(
        forward.bytes_to_host(),
        payload.len() as u64,
        "the forwarder must count every byte it relayed to the host"
    );
    assert_eq!(forward.accepted_total(), 1);
    assert_eq!(forward.dial_failures(), 0);
    forward.close().await.expect("graceful teardown");
}

// The over-`MAX_FRAME_BYTES` leg, in both directions. The control plane's 16 MiB frame cap is a
// property of the FRAMED protocol; a forward is a raw byte pipe and must carry a payload larger than
// it with no cap, no chunking artifact and no truncation. `MAX_FRAME_BYTES + 4096` rather than a
// round number so an off-by-one at the boundary is visible.
//
// RED ON THE INVERSE: any cap or frame-shaped assumption introduced into the relay (or the count
// bugs above) shows up as a length or digest difference here.
#[tokio::test]
async fn port_forward_moves_a_payload_larger_than_max_frame_bytes_in_both_directions() {
    let bridge = Bridge::spawn("oversize", 7000, &[Guest::FastEcho]);
    let forward = PortForward::bind(
        "127.0.0.1:0".parse().expect("literal"),
        bridge.endpoint(),
        7000,
        ForwardOptions::default(),
    )
    .await
    .expect("bind the forwarder");

    let payload = body(MAX_FRAME_BYTES + 4096);
    let sent = digest(&payload);
    let back = tokio::time::timeout(
        Duration::from_secs(30),
        round_trip(forward.local_addr(), payload.clone()),
    )
    .await
    .expect(
        "the oversize round trip did not complete in 30 s: a truncated relay never finishes the \
         read",
    );

    assert_eq!(
        back.len(),
        payload.len(),
        "a payload larger than MAX_FRAME_BYTES must cross whole"
    );
    assert_eq!(digest(&back), sent, "the oversize echo's digest differs");
    assert_eq!(
        bridge.observed.received(),
        payload.len() as u64,
        "the guest side must receive every byte of an oversize payload"
    );
    assert_eq!(
        *bridge.observed.digest.lock().expect("digest lock"),
        sent,
        "the oversize host->guest digest differs"
    );
    forward.close().await.expect("graceful teardown");
}

// ---------------------------------------------------------------------------
// The half-close decision — the crux, and the one the type makes explicit.
// ---------------------------------------------------------------------------

// THE PORTABLE DEFAULT. The host client half-closes its write side; the guest must NOT see an EOF,
// because on Firecracker and QEMU forwarding one discards whatever the guest had not yet flushed —
// silently. The guest's delayed reply still reaches the client, which is the whole point: nothing
// was signalled to the guest, and nothing was lost.
//
// RED ON THE INVERSE: make `client_to_guest` call `half_close_guest_write_side` unconditionally (or
// flip `EndOfStream`'s `#[default]`) and `saw_half_close` goes true.
#[tokio::test]
async fn a_client_half_close_is_not_forwarded_into_the_guest_by_default() {
    let bridge = Bridge::spawn("drain", 7000, &[Guest::DelayedReply]);
    let forward = PortForward::bind(
        "127.0.0.1:0".parse().expect("literal"),
        bridge.endpoint(),
        7000,
        ForwardOptions::default().with_drain_budget(Duration::from_secs(3)),
    )
    .await
    .expect("bind the forwarder");

    let stream = tokio::net::TcpStream::connect(forward.local_addr())
        .await
        .expect("connect");
    let (mut reader, mut writer) = tokio::io::split(stream);
    writer.write_all(b"request").await.expect("write request");
    writer.shutdown().await.expect("client half-close");

    let mut back = [0u8; 5];
    tokio::time::timeout(Duration::from_secs(2), reader.read_exact(&mut back))
        .await
        .expect("the guest's reply must arrive after the client half-closed")
        .expect("read reply");
    assert_eq!(&back, b"reply");

    assert!(
        !bridge.observed.saw_half_close(),
        "DrainThenClose must NOT half-close the guest: on Firecracker and QEMU that discards the \
         reply this leg just read"
    );
    assert_eq!(
        bridge.observed.received(),
        7,
        "the request must have landed"
    );
    forward.close().await.expect("graceful teardown");
}

// THE OPT-IN ARM. The same exchange with `ForwardHalfClose` selected: the guest DOES observe the
// EOF. What this fake cannot show — and does not claim — is what Firecracker and QEMU then do with
// the reply; `VsockDial`'s table carries that measurement, and choosing this arm is choosing those
// backends out.
//
// RED ON THE INVERSE: route the `ForwardHalfClose` arm to a no-op and `saw_half_close` stays false —
// verified, and it is what exposed the fixture flaw described on `Observed::saw_half_close`.
//
// NOT DRIVEN LIVE, deliberately: the arm's whole content is one `VsockDial::shutdown()`, whose live
// per-backend behavior is already pinned by `tests/exec_vsock.rs`'s
// `dial_vsock_host_half_close_forwards_on_cloud_hypervisor` / `…_on_crosvm` legs — and a live leg
// here would have to run on the matrix's Firecracker and QEMU arms, where the operation is measured
// to lose the reply. vmcell advertises no capability flag for that difference (design §3.2), so
// there is nothing for such a leg to branch on; the honest coverage is the operation's own legs plus
// this one, which pins WHICH operation each arm performs.
#[tokio::test]
async fn forwarding_a_half_close_is_opt_in_and_reaches_the_guest() {
    let bridge = Bridge::spawn("halfclose", 7000, &[Guest::DelayedReply]);
    let forward = PortForward::bind(
        "127.0.0.1:0".parse().expect("literal"),
        bridge.endpoint(),
        7000,
        ForwardOptions::default()
            .with_end_of_stream(EndOfStream::ForwardHalfClose)
            .with_drain_budget(Duration::from_secs(3)),
    )
    .await
    .expect("bind the forwarder");

    let stream = tokio::net::TcpStream::connect(forward.local_addr())
        .await
        .expect("connect");
    let (mut reader, mut writer) = tokio::io::split(stream);
    writer.write_all(b"request").await.expect("write request");
    writer.shutdown().await.expect("client half-close");

    assert!(
        wait_until(Duration::from_secs(3), || bridge.observed.saw_half_close()).await,
        "ForwardHalfClose must half-close the guest side — and half-close it, not close it: the \
         flag is only set when the guest side is still writable afterwards"
    );
    // The positive control for the negative above: this fake bridge (unlike two real ones) still
    // delivers its reply after the EOF, so the leg above cannot be passing because replies never
    // arrive.
    let mut back = [0u8; 5];
    tokio::time::timeout(Duration::from_secs(2), reader.read_exact(&mut back))
        .await
        .expect("the fake bridge still answers after an EOF")
        .expect("read reply");
    assert_eq!(&back, b"reply");
    forward.close().await.expect("graceful teardown");
}

// The drain is a DEADLINE, not a hope: a guest that never answers and never closes must not hold a
// half-closed connection open forever. Bounded on both sides — it must not close early either, or
// the "drain" would be a truncation.
//
// RED ON THE INVERSE: drop the `timeout_at(drain_deadline, …)` in `relay_connection` and the client
// waits forever (this leg times out at 30 s instead of ~1 s).
#[tokio::test]
async fn the_drain_budget_bounds_a_connection_whose_guest_never_answers() {
    let bridge = Bridge::spawn("silent", 7000, &[Guest::Silent]);
    let drain = Duration::from_millis(800);
    let forward = PortForward::bind(
        "127.0.0.1:0".parse().expect("literal"),
        bridge.endpoint(),
        7000,
        ForwardOptions::default().with_drain_budget(drain),
    )
    .await
    .expect("bind the forwarder");

    let stream = tokio::net::TcpStream::connect(forward.local_addr())
        .await
        .expect("connect");
    let (mut reader, mut writer) = tokio::io::split(stream);
    writer.write_all(b"anyone there?").await.expect("write");
    writer.shutdown().await.expect("client half-close");

    let started = std::time::Instant::now();
    let mut tail = Vec::new();
    tokio::time::timeout(Duration::from_secs(30), reader.read_to_end(&mut tail))
        .await
        .expect("the connection must end at the drain deadline, not hang")
        .expect("read to EOF");
    let elapsed = started.elapsed();

    assert!(tail.is_empty(), "a silent guest sends nothing: {tail:?}");
    assert!(
        elapsed >= drain,
        "the connection closed after {elapsed:?}, before its {drain:?} drain — that is a \
         truncation, not a drain"
    );
    assert!(
        elapsed < drain + Duration::from_secs(5),
        "the connection ran {elapsed:?} past a {drain:?} drain budget"
    );
    forward.close().await.expect("graceful teardown");
}

// ---------------------------------------------------------------------------
// Teardown is ownership: no listener, no task, no residue.
// ---------------------------------------------------------------------------

// The GRACEFUL path. On return from `close()` the ordered teardown has completed, so the port is
// rebindable IMMEDIATELY (no polling — that is what "awaited" buys), the client's connection is
// closed, and the guest side saw its connection go away.
//
// RED ON THE INVERSE: make `close()` drop the accept handle instead of awaiting it and the rebind
// races the teardown; make `accept_loop` return without `connections.shutdown()` and the relay
// outlives the forwarder, so neither EOF arrives.
#[tokio::test]
async fn close_completes_the_ordered_teardown_before_it_returns() {
    let bridge = Bridge::spawn("close", 7000, &[Guest::FastEcho]);
    let forward = PortForward::bind(
        "127.0.0.1:0".parse().expect("literal"),
        bridge.endpoint(),
        7000,
        ForwardOptions::default(),
    )
    .await
    .expect("bind the forwarder");
    let addr = forward.local_addr();

    let mut client = tokio::net::TcpStream::connect(addr).await.expect("connect");
    client.write_all(b"ping").await.expect("write");
    let mut back = [0u8; 4];
    client.read_exact(&mut back).await.expect("echo");
    assert_eq!(
        &back, b"ping",
        "the relay must be live before it is torn down"
    );
    assert_eq!(forward.active_connections(), 1);

    forward.close().await.expect("graceful teardown");

    // No listener: the port is free the instant `close()` returns.
    let rebound = tokio::net::TcpListener::bind(addr).await;
    assert!(
        rebound.is_ok(),
        "the listening socket outlived close(): {rebound:?}"
    );
    drop(rebound);

    // No relay: both ends of the forwarded connection are closed.
    let mut tail = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut tail))
        .await
        .expect("the client's connection must be closed by the teardown")
        .expect("read to EOF");
    assert!(tail.is_empty(), "unexpected trailing bytes: {tail:?}");
    assert!(
        wait_until(Duration::from_secs(5), || bridge.observed.ended()).await,
        "the guest-side connection outlived the forwarder"
    );
}

// The PANIC path — `Drop`, which cannot await. It runs the same ordered teardown and returns; the
// residue therefore has to be gone within a bounded window rather than instantly. A leaked listener
// or a detached relay never goes away, so this is not a weaker assertion, only a later one.
//
// RED ON THE INVERSE: remove `Drop`'s `signal_teardown()` call and every assertion below fails —
// the accept loop keeps the port, the relay keeps echoing, and the active count never falls.
#[tokio::test]
async fn dropping_the_forwarder_leaves_no_listener_and_no_relay() {
    let bridge = Bridge::spawn("drop", 7000, &[Guest::FastEcho]);
    let forward = PortForward::bind(
        "127.0.0.1:0".parse().expect("literal"),
        bridge.endpoint(),
        7000,
        ForwardOptions::default(),
    )
    .await
    .expect("bind the forwarder");
    let addr = forward.local_addr();

    let mut client = tokio::net::TcpStream::connect(addr).await.expect("connect");
    client.write_all(b"ping").await.expect("write");
    let mut back = [0u8; 4];
    client.read_exact(&mut back).await.expect("echo");
    assert_eq!(forward.active_connections(), 1);

    drop(forward);

    let mut tail = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut tail))
        .await
        .expect("a dropped forwarder must close the connections it was relaying")
        .expect("read to EOF");
    assert!(tail.is_empty(), "unexpected trailing bytes: {tail:?}");
    assert!(
        wait_until(Duration::from_secs(5), || bridge.observed.ended()).await,
        "the guest-side connection outlived the dropped forwarder"
    );
    let mut rebound = None;
    let freed = wait_until(Duration::from_secs(5), || {
        rebound = std::net::TcpListener::bind(addr).ok();
        rebound.is_some()
    })
    .await;
    assert!(freed, "the listening socket outlived the dropped forwarder");
}

// ---------------------------------------------------------------------------
// A long-lived forwarder survives what one connection does to it.
// ---------------------------------------------------------------------------

// A dead guest port is an ANSWER, not a reason to die: the first connection's dial fails (the muxer
// closes without `OK`), the client learns immediately, and the forwarder keeps serving — the second
// connection echoes. Counted, so "it kept serving" is not inferred from the absence of a failure.
//
// RED ON THE INVERSE: return from `accept_loop` on a relay error and the second connect is refused.
#[tokio::test]
async fn a_dead_guest_port_closes_one_connection_and_the_forwarder_keeps_serving() {
    let bridge = Bridge::spawn("deadport", 7000, &[Guest::DeadPort, Guest::FastEcho]);
    let forward = PortForward::bind(
        "127.0.0.1:0".parse().expect("literal"),
        bridge.endpoint(),
        7000,
        ForwardOptions::default(),
    )
    .await
    .expect("bind the forwarder");

    let mut doomed = tokio::net::TcpStream::connect(forward.local_addr())
        .await
        .expect("connect");
    let mut tail = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), doomed.read_to_end(&mut tail))
        .await
        .expect("a failed dial must close the client's connection promptly")
        .expect("read to EOF");
    assert!(tail.is_empty());
    assert!(
        wait_until(Duration::from_secs(5), || forward.dial_failures() == 1).await,
        "the failed dial must be counted, not swallowed"
    );

    // The positive control: the same forwarder, one connection later, still works.
    let back = tokio::time::timeout(
        Duration::from_secs(10),
        round_trip(forward.local_addr(), b"still here".to_vec()),
    )
    .await
    .expect("the forwarder must still be serving");
    assert_eq!(&back, b"still here");
    assert_eq!(forward.accepted_total(), 2);
    assert_eq!(
        bridge.observed.accepted(),
        2,
        "both connections must have reached the guest bridge — the second one is the control"
    );
    forward.close().await.expect("graceful teardown");
}

// The connection budget bounds the WHOLE connection — an idle one included — with its positive
// control beside it: the same fixture with no budget stays open past the same wall clock. Without
// the control this leg would pass just as well against a forwarder that closes everything.
//
// RED ON THE INVERSE: ignore `connection_budget` in `relay_connection` and the budgeted connection
// outlives its budget exactly like the control.
#[tokio::test]
async fn a_connection_budget_bounds_the_whole_connection() {
    let bridge = Bridge::spawn("budget", 7000, &[Guest::Silent]);
    let budget = Duration::from_secs(1);
    let forward = PortForward::bind(
        "127.0.0.1:0".parse().expect("literal"),
        bridge.endpoint(),
        7000,
        ForwardOptions::default()
            .with_dial_timeout(Duration::from_millis(500))
            .with_connection_budget(Some(budget)),
    )
    .await
    .expect("bind the forwarder");

    let mut client = tokio::net::TcpStream::connect(forward.local_addr())
        .await
        .expect("connect");
    let started = std::time::Instant::now();
    let mut tail = Vec::new();
    tokio::time::timeout(Duration::from_secs(20), client.read_to_end(&mut tail))
        .await
        .expect("the budget must end an idle connection")
        .expect("read to EOF");
    assert!(
        started.elapsed() >= budget,
        "the connection ended after {:?}, before its {budget:?} budget",
        started.elapsed()
    );

    // THE POSITIVE CONTROL: no budget, same everything else, still open well past it.
    let control = PortForward::bind(
        "127.0.0.1:0".parse().expect("literal"),
        bridge.endpoint(),
        7000,
        ForwardOptions::default(),
    )
    .await
    .expect("bind the control forwarder");
    let mut control_client = tokio::net::TcpStream::connect(control.local_addr())
        .await
        .expect("connect control");
    let mut byte = [0u8; 1];
    let idle = tokio::time::timeout(budget * 3, control_client.read(&mut byte)).await;
    assert!(
        idle.is_err(),
        "the unbudgeted control connection must still be open: {idle:?}"
    );

    forward.close().await.expect("graceful teardown");
    control.close().await.expect("graceful teardown");
}

// The `Timeouts` a caller hands the forwarder are the ones the dial's prologue actually reads, with
// its own positive control: the same slow bridge succeeds once the window is wide enough. An
// accepted input that is ignored is the defect class this leg exists for.
//
// RED ON THE INVERSE: pass `Timeouts::default()` to `VsockDial::connect_endpoint` instead of
// `target.options.timeouts` and the tight leg stops failing.
#[tokio::test]
async fn the_configured_connect_ok_window_is_the_one_the_dial_uses() {
    let bridge = Bridge::spawn("slowok", 7000, &[Guest::SlowOk, Guest::SlowOk]);
    let mut tight = vmcell::config::Timeouts::default();
    tight.connect_ok_read = Duration::from_millis(50);
    let forward = PortForward::bind(
        "127.0.0.1:0".parse().expect("literal"),
        bridge.endpoint(),
        7000,
        ForwardOptions::default().with_timeouts(tight),
    )
    .await
    .expect("bind the forwarder");

    let mut client = tokio::net::TcpStream::connect(forward.local_addr())
        .await
        .expect("connect");
    let mut tail = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), client.read_to_end(&mut tail))
        .await
        .expect("a prologue past connect_ok_read must fail the dial, not hang")
        .expect("read to EOF");
    assert!(
        wait_until(Duration::from_secs(5), || forward.dial_failures() == 1).await,
        "the timed-out prologue must be counted as a dial failure"
    );
    forward.close().await.expect("graceful teardown");

    // THE POSITIVE CONTROL: the same 600 ms bridge, a window that admits it, and bytes flow.
    let mut roomy = vmcell::config::Timeouts::default();
    roomy.connect_ok_read = Duration::from_secs(3);
    let patient = PortForward::bind(
        "127.0.0.1:0".parse().expect("literal"),
        bridge.endpoint(),
        7000,
        ForwardOptions::default().with_timeouts(roomy),
    )
    .await
    .expect("bind the patient forwarder");
    let mut client = tokio::net::TcpStream::connect(patient.local_addr())
        .await
        .expect("connect");
    client.write_all(b"hi").await.expect("write");
    // `SlowOk` echoes nothing, so the proof the dial COMPLETED is that the guest received the bytes.
    assert!(
        wait_until(Duration::from_secs(10), || bridge.observed.received() == 2).await,
        "the patient forwarder's dial must complete and relay: dial_failures={}",
        patient.dial_failures()
    );
    assert_eq!(patient.dial_failures(), 0);
    patient.close().await.expect("graceful teardown");
}

// `dial_timeout` bounds the WHOLE dial, which is a different budget from `connect_ok_read` above:
// the same 600 ms bridge, a window wide enough for its `OK` line, and an outer budget too small for
// it. Without this leg the knob would be shipped, documented, and never once the thing that decided
// an outcome.
//
// RED ON THE INVERSE: hand `VsockDial::connect_endpoint` a hardcoded budget instead of
// `target.options.dial_timeout` and the dial succeeds, so `dial_failures()` stays 0.
#[tokio::test]
async fn the_dial_timeout_bounds_the_whole_dial() {
    let bridge = Bridge::spawn("dialbudget", 7000, &[Guest::SlowOk]);
    let mut roomy = vmcell::config::Timeouts::default();
    roomy.connect_ok_read = Duration::from_secs(3);
    let forward = PortForward::bind(
        "127.0.0.1:0".parse().expect("literal"),
        bridge.endpoint(),
        7000,
        ForwardOptions::default()
            .with_timeouts(roomy)
            .with_dial_timeout(Duration::from_millis(200)),
    )
    .await
    .expect("bind the forwarder");

    let mut client = tokio::net::TcpStream::connect(forward.local_addr())
        .await
        .expect("connect");
    let started = std::time::Instant::now();
    let mut tail = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), client.read_to_end(&mut tail))
        .await
        .expect("a dial past its budget must close the client's connection, not hang")
        .expect("read to EOF");
    assert!(tail.is_empty());
    assert!(
        wait_until(Duration::from_secs(5), || forward.dial_failures() == 1).await,
        "the over-budget dial must be counted"
    );
    assert!(
        started.elapsed() < Duration::from_millis(600),
        "the dial ran {:?}, past its 200 ms budget and into the bridge's 600 ms delay",
        started.elapsed()
    );
    forward.close().await.expect("graceful teardown");
}

// ---------------------------------------------------------------------------
// The LIVE leg: a real guest listener, reached over plain TCP.
// ---------------------------------------------------------------------------

/// The in-guest vsock port the live leg's `echo-server` listens on.
#[cfg(any(
    feature = "cloud-hypervisor",
    feature = "firecracker",
    feature = "qemu",
    feature = "crosvm"
))]
const LIVE_GUEST_PORT: u32 = 7100;

/// Boots a cell and leaves the `echo-server` applet listening on [`LIVE_GUEST_PORT`].
///
/// The listener is started through the steward and outlives the exec: the shell exits and the
/// backgrounded server is reparented to the steward (PID 1). The same fixture shape
/// `tests/exec_vsock.rs`'s live dial legs use — each integration test binary is its own crate, so
/// the fixture is local rather than shared.
#[cfg(any(
    feature = "cloud-hypervisor",
    feature = "firecracker",
    feature = "qemu",
    feature = "crosvm"
))]
async fn start_vm_with_echo_server<V: vmcell::vmm::Vmm>(vmm: &V) -> vmcell::MicroVm<V> {
    let cfg = vmcell::config::VmConfig::builder(
        common::get_vmlinux(),
        vmcell::config::RootfsSource::Erofs {
            image: common::get_rootfs(),
        },
    )
    .network_disabled()
    .build()
    .expect("the live fixture's config must build");

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
                "/vmcell-tools/echo-server --vsock {LIVE_GUEST_PORT} </dev/null \
                 >/tmp/echo.log 2>&1 &"
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

// THE LIVE LEG, and the one that proves the feature rather than the plumbing: a host tool that
// knows nothing about vsock reaches an in-guest listener over `127.0.0.1:<port>`.
//
// Named `…unprivileged…` so `just test-unprivileged`'s
// `-E 'kind(test) & (test(unprivileged) | test(smoltcp))'` selects it — and so the privileged
// suite's `!(unprivileged|smoltcp)` does NOT: it needs no elevation at all (the vsock device is
// attached on every path, in both operating modes), so running it unprivileged is the honest place
// for it. `--features qemu` adds the QEMU arm, whose transport is the external
// `vhost-device-vsock` daemon rather than an in-VMM muxer.
//
// It carries the same two payloads as the KVM-free legs, in both directions, against the real
// `echo-server` applet: the window-filling one and one larger than `MAX_FRAME_BYTES` (the control
// plane's frame cap, which a raw forward must not inherit). Digest-compared end to end, so a
// truncated or reordered relay is a failure and not a slow test.
//
// RED ON THE INVERSE: every `pump` inverse the KVM-free legs drive reddens this one too; so does a
// forwarder that dials the endpoint's own port instead of the configured one (nothing listens on
// 5000-as-echo, so the round trip never completes).
#[cfg(any(
    feature = "cloud-hypervisor",
    feature = "firecracker",
    feature = "qemu",
    feature = "crosvm"
))]
vmm_matrix_test!(port_forward_unprivileged, |vmm| {
    live_port_forward_impl(&vmm).await;
});

#[cfg(any(
    feature = "cloud-hypervisor",
    feature = "firecracker",
    feature = "qemu",
    feature = "crosvm"
))]
async fn live_port_forward_impl<V: vmcell::vmm::Vmm>(vmm: &V) {
    use vmcell::vmm::VmInstance as _;

    let vm = start_vm_with_echo_server(vmm).await;
    let forward = PortForward::bind(
        "127.0.0.1:0".parse().expect("literal"),
        vm.instance().vsock_endpoint(),
        LIVE_GUEST_PORT,
        ForwardOptions::default(),
    )
    .await
    .expect("bind the forwarder at the live cell");
    let addr = forward.local_addr();

    // The in-guest listener races the host, and a forward dials PER CONNECTION, so the retry is a
    // fresh TCP connection rather than a re-dial of a connection already handed out.
    let mut ready = false;
    for _ in 0..50 {
        match tokio::time::timeout(
            Duration::from_secs(2),
            try_round_trip(addr, b"ready?".to_vec()),
        )
        .await
        {
            Ok(Ok(back)) => {
                assert_eq!(&back, b"ready?", "the guest echo must be byte-exact");
                ready = true;
                break;
            }
            // A dial into a port nobody is listening on yet: the forwarder closes the client's
            // connection (ECONNRESET at this end), counts a dial failure, and keeps serving. The
            // retry is a FRESH TCP connection, because a forward dials per connection.
            Ok(Err(_)) | Err(_) => tokio::time::sleep(Duration::from_millis(200)).await,
        }
    }
    assert!(
        ready,
        "the forwarder never reached the in-guest echo-server on vsock port {LIVE_GUEST_PORT}"
    );
    // Baselines taken AFTER readiness: the retries above legitimately count accepted connections,
    // dial failures and the probe's own bytes, so what this leg asserts about is the delta.
    let base_to_guest = forward.bytes_to_guest();
    let base_to_host = forward.bytes_to_host();
    let base_failures = forward.dial_failures();

    for (what, len) in [
        ("window-filling", WINDOW_FILLING_BYTES),
        ("over MAX_FRAME_BYTES", MAX_FRAME_BYTES + 4096),
    ] {
        let payload = body(len);
        let sent = digest(&payload);
        let started = std::time::Instant::now();
        let back =
            tokio::time::timeout(Duration::from_secs(120), round_trip(addr, payload.clone()))
                .await
                .unwrap_or_else(|_| {
                    panic!("the {what} round trip through the guest did not complete")
                });
        assert_eq!(
            back.len(),
            payload.len(),
            "the {what} echo came back short ({} of {} bytes)",
            back.len(),
            payload.len()
        );
        assert_eq!(
            digest(&back),
            sent,
            "the {what} payload came back corrupted through the live forward"
        );
        eprintln!(
            "port_forward live: {what} ({} bytes) round-tripped in {:?}",
            payload.len(),
            started.elapsed()
        );
    }

    let moved = (WINDOW_FILLING_BYTES + MAX_FRAME_BYTES + 4096) as u64;
    assert_eq!(
        forward.bytes_to_guest() - base_to_guest,
        moved,
        "every byte the host sent must be counted on the way in"
    );
    assert_eq!(
        forward.bytes_to_host() - base_to_host,
        moved,
        "every echoed byte must be counted on the way out"
    );
    assert_eq!(
        forward.dial_failures(),
        base_failures,
        "no dial may fail once the in-guest listener is up"
    );

    forward.close().await.expect("graceful teardown");
    // The listening socket is gone the moment `close()` returns, at a live cell as much as at a fake
    // bridge.
    let rebound = tokio::net::TcpListener::bind(addr).await;
    assert!(
        rebound.is_ok(),
        "the listening socket outlived close(): {rebound:?}"
    );
    drop(rebound);

    vm.shutdown().await.expect("Shutdown failed");
}
