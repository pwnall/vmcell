//! The steward's unit suite.
//!
//! Moved wholesale out of `main.rs` by v33 delta 5 (the library split), deliberately as **one
//! module** rather than scattered per-module `mod tests`: every one of these tests already read
//! the whole file through `use super::*`, and re-homing 25 tests across six new modules in the
//! same change would have made a mechanical move indistinguishable from a rewrite. The
//! reservation/epoch suite in particular is pid-reuse correctness that is placement-independent
//! and must carry over intact — §18 delta 5's gate says so in as many words.

use crate::exec::*;
use crate::options::*;
use crate::serve::*;
use crate::session::*;
use crate::{ReaperCoordinator, ServeContext};

use std::collections::HashMap;
use std::io::Read;
use std::os::fd::OwnedFd;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use vmcell_protocol::{self as protocol, MAX_FRAME_BYTES, Message, SessionId};
use vsock::VsockStream;

/// A hermetic [`ServeContext`] for tests that drive the serving path directly.
///
/// Built through the same struct production uses, with the shipped defaults, so a field added to
/// the seam is a compile error here rather than a silently-untested one.
fn test_ctx() -> Arc<ServeContext> {
    Arc::new(ServeContext {
        reaper: Arc::new(ReaperCoordinator::new()),
        tools_dir: std::path::PathBuf::from(crate::DEFAULT_TOOLS_DIR),
        connections: Arc::new(ConnectionRegistry::new()),
        shutdown: Arc::new(AtomicBool::new(false)),
    })
}

// Guards the boot mount-plan decode (`<tag>:<guest_path>:<ro|rw>`). Buggy impls
// this catches: ignoring the access mode (mounting a declared-`ro` share `rw` —
// a real isolation break), and ignoring the guest_path (always mounting at
// `/<tag>` instead of the host-chosen mount point).
#[test]
fn parse_share_mounts_decodes_tag_path_and_access() {
    let cmdline =
        "console=ttyS0 vmcell_share=data-in:/data-in:ro vmcell_vmid=7 vmcell_share=out:/srv/out:rw";
    let mounts = parse_share_mounts(cmdline);
    assert_eq!(mounts.len(), 2);
    assert_eq!(mounts[0].tag, "data-in");
    assert_eq!(mounts[0].mount_point, "/data-in");
    assert!(mounts[0].read_only, "ro share must mount read-only");
    assert_eq!(mounts[1].tag, "out");
    assert_eq!(
        mounts[1].mount_point, "/srv/out",
        "the custom guest_path must be honoured, not derived from the tag"
    );
    assert!(!mounts[1].read_only, "rw share must mount read-write");
}

// Too few fields, an unknown access mode, and an empty tag/mount point are each
// dropped, not mounted — a corrupt boot line must not synthesize a share.
#[test]
fn parse_share_mounts_skips_malformed_tokens() {
    let cmdline = "vmcell_share=notag vmcell_share=t:/m:xx vmcell_share=:/m:ro \
                   vmcell_share=t::ro vmcell_share=ok:/ok:ro";
    let mounts = parse_share_mounts(cmdline);
    assert_eq!(mounts.len(), 1);
    assert_eq!(mounts[0].tag, "ok");
    assert_eq!(mounts[0].mount_point, "/ok");
    assert!(mounts[0].read_only);
}

#[test]
fn parse_share_mounts_empty_when_no_tokens() {
    assert!(parse_share_mounts("console=ttyS0 root=/dev/vda ro").is_empty());
    assert!(parse_share_mounts("").is_empty());
}

// §5.3 (The kernel command line): the guest-tuning cmdline tokens are UNTRUSTED and must be clamped into
// `[floor, ceil]`, falling back to the compiled default when absent/garbage.
// The clamp is load-bearing: an un-clamped parse would let
// `vmcell_accept_poll_ms=0` busy-spin PID 1's bind-retry loop (0ms sleep; since
// OPP-2 this token paces only the bind-failure retry — the accept wait itself
// is event-driven).
#[test]
fn parse_ms_clamps_and_defaults() {
    use std::time::Duration;
    let key = "vmcell_accept_poll_ms=";
    // Absent → the compiled default.
    assert_eq!(
        parse_ms("console=ttyS0 ro", key, 20, 1, 10_000),
        Duration::from_millis(20)
    );
    // An in-range value is honored verbatim.
    assert_eq!(
        parse_ms("vmcell_accept_poll_ms=7 ro", key, 20, 1, 10_000),
        Duration::from_millis(7)
    );
    // 0 is clamped UP to the floor (1) — the busy-spin guard. RED on an
    // un-clamped parse that would return 0.
    assert_eq!(
        parse_ms("vmcell_accept_poll_ms=0", key, 20, 1, 10_000),
        Duration::from_millis(1),
        "0 must clamp to the floor so it cannot busy-spin PID 1"
    );
    // Above the ceiling is clamped DOWN.
    assert_eq!(
        parse_ms("vmcell_accept_poll_ms=999999", key, 20, 1, 10_000),
        Duration::from_millis(10_000)
    );
    // Non-numeric garbage → the default (not a partial/zero parse).
    assert_eq!(
        parse_ms("vmcell_accept_poll_ms=abc", key, 20, 1, 10_000),
        Duration::from_millis(20)
    );
    // Overflowing `u64` → the default (parse fails, not saturates).
    assert_eq!(
        parse_ms(
            "vmcell_accept_poll_ms=99999999999999999999999999",
            key,
            20,
            1,
            10_000
        ),
        Duration::from_millis(20)
    );
    // The FIRST parseable token wins (matches the strip_prefix+parse contract).
    assert_eq!(
        parse_ms(
            "vmcell_accept_poll_ms=x vmcell_accept_poll_ms=9",
            key,
            20,
            1,
            10_000
        ),
        Duration::from_millis(9)
    );
}

// OPP-2: the pure deadline policy behind the event-driven accept loop. Only a
// REAL accept restarts the re-bind idle window; a spurious POLLIN→WouldBlock
// wakeup or an EINTR'd poll leaves the deadline exactly where it was. RED on
// an impl that resets the deadline on either (`SpuriousReadable => now +
// rebind_idle`): a post-restore deaf listener never yields a real accept but
// its poll can still wake, so a resetting policy re-arms the window forever
// and the §8.2 (Restore correctness: a restored VM is not a fresh VM) re-bind never fires.
#[test]
fn spurious_wakeup_and_eintr_do_not_reset_the_deadline() {
    let start = Instant::now();
    let idle = Duration::from_millis(250);
    let deadline = start + idle;
    // 200 ms into the window, so a buggy reset would move the deadline.
    let now = start + Duration::from_millis(200);
    assert_eq!(
        next_deadline(deadline, now, idle, AcceptOutcome::SpuriousReadable),
        deadline,
        "a spurious POLLIN→WouldBlock wakeup must not extend the re-bind deadline"
    );
    assert_eq!(
        next_deadline(deadline, now, idle, AcceptOutcome::Interrupted),
        deadline,
        "an EINTR'd poll (PID 1 takes SIGCHLD) must not extend the re-bind deadline"
    );
    // Only a successful accept restarts the idle window — anchored at `now`,
    // not at the old deadline.
    assert_eq!(
        next_deadline(deadline, now, idle, AcceptOutcome::Accepted),
        now + idle,
        "a real accept must restart the idle window from now"
    );
}

// The remaining-window math the poll timeout is derived from. RED on an impl
// returning `Some(ZERO)` at the deadline (fed through the 1 ms poll-timeout
// floor, the deaf listener would re-poll forever instead of re-binding) or one
// that underflows/panics once `now` passes the deadline.
#[test]
fn remaining_idle_counts_down_and_expires_exactly_at_deadline() {
    let now = Instant::now();
    let deadline = now + Duration::from_millis(250);
    // Mid-window: the exact Instant-based remainder, no cadence quantization.
    assert_eq!(
        remaining_idle(deadline, now),
        Some(Duration::from_millis(250))
    );
    assert_eq!(
        remaining_idle(deadline, now + Duration::from_millis(100)),
        Some(Duration::from_millis(150))
    );
    // Exactly at the deadline the window is expired — None (re-bind), not
    // Some(ZERO) (another poll).
    assert_eq!(remaining_idle(deadline, deadline), None);
    // Past the deadline: saturating, still None.
    assert_eq!(
        remaining_idle(deadline, deadline + Duration::from_millis(40)),
        None
    );
}

// The poll(2) timeout clamp. RED if the 1 ms floor is dropped: a sub-ms
// remainder truncates to 0 = "return immediately" and PID 1 busy-spins until
// the deadline check catches up.
#[test]
fn poll_timeout_floors_at_one_ms_and_never_exceeds_remaining() {
    // A sub-millisecond remainder floors to 1 ms (tv_nsec = 1_000_000), never 0.
    let ts = poll_timeout(Duration::from_micros(300));
    assert_eq!(
        (ts.tv_sec, ts.tv_nsec),
        (0, 1_000_000),
        "a sub-millisecond remainder must floor to 1 ms, not truncate to 0"
    );
    assert_eq!(poll_timeout(Duration::from_millis(1)).tv_nsec, 1_000_000);
    // Whole-ms truncation: never over the remaining window by a full tick.
    assert_eq!(poll_timeout(Duration::from_micros(2500)).tv_nsec, 2_000_000);
    let ts = poll_timeout(Duration::from_millis(250));
    assert_eq!((ts.tv_sec, ts.tv_nsec), (0, 250_000_000));
    // Absurdly large windows saturate instead of wrapping negative (a negative
    // timeout would mean "block forever" and the re-bind would never fire).
    let ts = poll_timeout(Duration::from_secs(u64::MAX));
    assert_eq!(ts.tv_sec, i64::MAX / 1_000);
    assert_eq!(ts.tv_nsec, (i64::MAX % 1_000) * 1_000_000);
    assert!(ts.tv_sec > 0 && ts.tv_nsec >= 0, "must not wrap negative");
}

// The (secs, nanos) → Timespec mapping the mandatory post-restore clock set
// consumes. RED on a units swap (secs↔nanos) or a truncating nanos cast.
#[test]
fn resync_timespec_maps_fields() {
    let ts = resync_timespec(1_700_000_000, 123_456_789);
    assert_eq!(ts.tv_sec, 1_700_000_000, "unix_secs must map to tv_sec");
    assert_eq!(ts.tv_nsec, 123_456_789, "unix_nanos must map to tv_nsec");
    assert_ne!(
        ts.tv_sec, 123_456_789,
        "a secs↔nanos swap must not put the nanos in tv_sec"
    );
    // The full u32 nanos range maps without overflow/truncation.
    let ts_max = resync_timespec(0, u32::MAX);
    assert_eq!(ts_max.tv_sec, 0);
    assert_eq!(ts_max.tv_nsec, u32::MAX as i64);
}

// docs/78 §6 (`uncapped-frame-debug-renders`), the guest half — the one whose
// blast radius is the PERSISTED serial artifact. The renderer itself is pinned
// where the law lives (`vmcell_protocol::capped_debug`, beside
// `MAX_FRAME_BYTES`); this pins the guest's line: a host frame at the FULL
// `MAX_FRAME_BYTES` still produces a log line of a few hundred bytes, carrying
// the truncation marker and the frame's true wire size.
//
// RED on the inverse: restore `format!("… message {msg:?}; …")` in
// `unexpected_frame_warning` and the length bound below fails by ~50 MB (and the
// marker assert with it). The remaining gap — that the dispatch arm calls this
// function — is not unit-reachable: `serve_loop` takes a concrete `VsockStream`
// and a `VsockStream`-typed `Writer`.
#[test]
fn unexpected_frame_warning_is_capped_not_frame_sized() {
    // A host→guest frame at the cap: the largest thing the dispatch loop can
    // ever hand this line.
    let msg = Message::Stdin {
        session: SessionId(0),
        data: vec![7u8; MAX_FRAME_BYTES - 16],
    };
    let frame_bytes = postcard::to_stdvec(&msg).expect("encode").len();
    let line = unexpected_frame_warning(frame_bytes, &msg);

    assert!(
        line.len() <= 1024,
        "a 16 MiB frame must still log as a short line, got {} bytes",
        line.len()
    );
    assert!(
        line.contains(protocol::DEBUG_TRUNCATED_MARKER),
        "a truncated render must say so: {line}"
    );
    assert!(
        line.contains(&format!("{frame_bytes} byte frame")),
        "the line must quote the frame's wire size: {line}"
    );
    assert!(
        line.contains("Stdin { session: SessionId(0)"),
        "the cap must keep enough to identify the frame: {line}"
    );

    // A small frame is reported in full — the cap must not cost an ordinary
    // desync report its detail.
    let small = Message::Ready;
    let small_line = unexpected_frame_warning(1, &small);
    assert!(small_line.contains("Ready"), "{small_line}");
    assert!(!small_line.contains(protocol::DEBUG_TRUNCATED_MARKER));
}

// AGENT-3: the guest's hand-rolled framing is the load-bearing interop with
// the host's `tokio_util::codec::LengthDelimitedCodec`, but the default suite
// otherwise only ever runs the codec on both ends. These KVM-free tests pin
// the two directions against the REAL codec plus the shared `MAX_FRAME_BYTES`
// cap, so a wrong endianness, an off-by-the-prefix, or a cap mismatch reddens
// here instead of only on a KVM host.
use bytes::{Bytes, BytesMut};
use tokio_util::codec::{Decoder, Encoder, LengthDelimitedCodec};

#[test]
fn send_framed_is_decoded_by_real_length_delimited_codec() {
    // Frame with the guest and decode with the host's codec. RED on a
    // little-endian prefix, an off-by-one prefix, or a length that excludes
    // the header: the codec mis-reads the length and returns None/wrong bytes.
    let payload = b"hello framing interop \x00\x01\xfe\xff world".to_vec();
    let mut wire = Vec::new();
    send_framed(&mut wire, &payload).expect("send_framed");

    // Exact wire contract: 4-byte big-endian length prefix, then the payload.
    assert_eq!(&wire[..4], &(payload.len() as u32).to_be_bytes());
    assert_eq!(&wire[4..], &payload[..]);

    let mut codec = LengthDelimitedCodec::new();
    let mut src = BytesMut::from(&wire[..]);
    let frame = codec
        .decode(&mut src)
        .expect("codec decode")
        .expect("a complete frame");
    assert_eq!(&frame[..], &payload[..]);
    assert!(src.is_empty(), "codec must consume exactly one guest frame");
}

#[test]
fn read_framed_decodes_a_real_length_delimited_codec_frame() {
    // Encode with the host's codec and decode with the guest. RED on the same
    // inverses in the read direction (LE prefix / off-by-one / wrong cap).
    let payload = b"round trip the other way \xde\xad\xbe\xef".to_vec();
    let mut codec = LengthDelimitedCodec::new();
    let mut encoded = BytesMut::new();
    codec
        .encode(Bytes::from(payload.clone()), &mut encoded)
        .expect("codec encode");

    let mut cursor = std::io::Cursor::new(encoded.to_vec());
    let decoded = read_framed(&mut cursor).expect("read_framed");
    assert_eq!(decoded, payload);
}

#[test]
fn send_framed_rejects_frame_over_max_frame_bytes() {
    // L-GUEST-2: the encode side enforces the shared cap too, so an over-cap
    // frame is rejected at the source rather than sent with a truncated (or,
    // above u32::MAX, wrapped) length prefix the host then mis-decodes. RED if
    // the encode-side check is dropped: `send_framed` would return Ok and write
    // the frame, leaving the sink non-empty.
    let data = vec![0u8; MAX_FRAME_BYTES + 1];
    let mut sink = Vec::new();
    let err = send_framed(&mut sink, &data).expect_err("over-cap frame must be rejected");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    assert!(
        sink.is_empty(),
        "an over-cap frame must be rejected before any byte is written"
    );
}

#[test]
fn send_framed_accepts_frame_at_exactly_max_frame_bytes() {
    // The boundary is allowed (`>` cap, not `>=`), symmetric with the decode
    // path. A frame at exactly the cap is framed with the 4-byte length prefix
    // + payload. RED if the encode cap is tightened off-by-one (it would then
    // reject the boundary as InvalidData).
    let data = vec![0xA5u8; MAX_FRAME_BYTES];
    let mut sink = Vec::new();
    send_framed(&mut sink, &data).expect("a frame at exactly the cap must be accepted");
    assert_eq!(sink.len(), 4 + MAX_FRAME_BYTES);
    assert_eq!(&sink[..4], &(MAX_FRAME_BYTES as u32).to_be_bytes());
}

#[test]
fn read_framed_rejects_frame_over_max_frame_bytes() {
    // A header declaring more than the shared cap is rejected as InvalidData
    // *before* the body is read. RED if the cap check is dropped or loosened
    // (it would then try to allocate/read an over-cap body instead).
    let over = MAX_FRAME_BYTES as u32 + 1;
    let mut wire = Vec::new();
    wire.extend_from_slice(&over.to_be_bytes());
    // Body deliberately absent: the cap must trip on the header alone.
    let mut cursor = std::io::Cursor::new(wire);
    let err = read_framed(&mut cursor).expect_err("over-cap frame must be rejected");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
}

#[test]
fn read_framed_accepts_frame_at_exactly_max_frame_bytes() {
    // The boundary itself is allowed (`>` cap, not `>=`). With the header at
    // exactly MAX and no body, read_framed passes the cap check and then fails
    // on the missing body (UnexpectedEof) — NOT InvalidData. RED if the cap is
    // tightened off-by-one (it would reject the boundary as InvalidData) or
    // wired to a smaller constant.
    let mut wire = Vec::new();
    wire.extend_from_slice(&(MAX_FRAME_BYTES as u32).to_be_bytes());
    let mut cursor = std::io::Cursor::new(wire);
    let err = read_framed(&mut cursor).expect_err("short body must error");
    assert_eq!(
        err.kind(),
        std::io::ErrorKind::UnexpectedEof,
        "a frame at exactly the cap must pass the cap check, not be rejected as too large"
    );
}

// §3 (The control plane: vsock, the host clients, and the steward) / §3.3 (Interactive-session wire semantics): the rows→ws_row, cols→ws_col field mapping the PTY
// winsize install consumes. RED on a rows↔cols swap (mirrors
// `resync_timespec_maps_fields`), without a live PTY.
#[test]
fn winsize_from_maps_rows_and_cols() {
    let ws = winsize_from(40, 100);
    assert_eq!(ws.ws_row, 40, "rows must map to ws_row");
    assert_eq!(ws.ws_col, 100, "cols must map to ws_col");
    assert_ne!(
        ws.ws_row, 100,
        "a rows↔cols swap must not put cols in ws_row"
    );
    // Pixel dims are unset (character-cell terminal).
    assert_eq!(ws.ws_xpixel, 0);
    assert_eq!(ws.ws_ypixel, 0);
}

// §3.3 (Interactive-session wire semantics): `child_path` is the ONE PATH law shared by handle_exec and
// run_session — it must prepend the tools dir so the guest-helper shims
// (ip/curl/kvm-ok) resolve. RED if a session path dropped the prefix.
#[test]
fn child_path_prepends_the_tools_dir() {
    let tools = std::path::Path::new(crate::DEFAULT_TOOLS_DIR);
    // A request-provided PATH is honored, with the tools dir ahead of it.
    assert_eq!(
        child_path(tools, Some("/usr/bin:/bin".to_string())),
        "/vmcell-tools:/usr/bin:/bin"
    );
    // An empty base falls back to the standard system dirs, still tools-dir first.
    assert_eq!(
        child_path(tools, Some(String::new())),
        "/vmcell-tools:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    );
    assert!(
        child_path(tools, Some("/opt/bin".to_string())).starts_with("/vmcell-tools:"),
        "the guest-tools dir must be first on PATH"
    );
}

// v33 delta 5: the tools dir is a DECLARED seam, not a literal. The law above is "the tools dir is
// first"; this leg is what makes that statement true of the declaration rather than of the string
// `/vmcell-tools`. RED on re-hardcoding the path at either branch of `child_path` — which is
// exactly how a seam gets quietly un-seamed, since the default-valued tests above stay green.
#[test]
fn child_path_honors_a_declared_tools_dir_on_both_branches() {
    let tools = std::path::Path::new("/opt/acme-handler");
    assert_eq!(
        child_path(tools, Some("/usr/bin".to_string())),
        "/opt/acme-handler:/usr/bin"
    );
    assert_eq!(
        child_path(tools, Some(String::new())),
        "/opt/acme-handler:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    );
    assert!(
        !child_path(tools, None).contains("/vmcell-tools"),
        "a declared tools dir must REPLACE the default, not sit beside it"
    );
}

// AGENT-3 extended to the channelized session frames (§3.3, Interactive-session wire semantics): a
// guest-encoded `SessionStdout{id, payload}` frames through `send_framed`,
// decodes through the host's REAL LengthDelimitedCodec, and postcard-decodes
// back to the same Message — proving the id-keyed frames cross the hand-rolled
// framing boundary intact. RED on a framing/endianness/cap regression.
#[test]
fn session_frame_round_trips_through_real_codec() {
    let msg = Message::SessionStdout {
        session: SessionId(7),
        data: b"multiplexed \x00\x01\xfe\xff output".to_vec(),
    };
    let encoded = postcard::to_stdvec(&msg).expect("postcard encode");
    let mut wire = Vec::new();
    send_framed(&mut wire, &encoded).expect("send_framed");

    let mut codec = LengthDelimitedCodec::new();
    let mut src = BytesMut::from(&wire[..]);
    let frame = codec
        .decode(&mut src)
        .expect("codec decode")
        .expect("a complete frame");
    let decoded: Message = postcard::from_bytes(&frame).expect("postcard decode");
    assert_eq!(
        decoded, msg,
        "session frame must round-trip through the codec"
    );
    assert!(src.is_empty(), "codec must consume exactly one guest frame");
}

/// Registers a live session handle over `sink` in a fresh table, for the M6
/// stdin-queue gates. `pid` is 0 — these tests never take the kill/teardown
/// path, so no signal is ever sent.
fn stdin_test_session(sink: StdinSink) -> (Sessions, SessionId) {
    let id = SessionId(0);
    let sessions: Sessions = Arc::new(Mutex::new(HashMap::new()));
    sessions
        .lock()
        .unwrap()
        .insert(id, SessionHandle::new(id, Some(sink), None, 0));
    (sessions, id)
}

// M6 (`guest-dispatch-blocking-stdin-wedge`), KVM-free half of the gate: the
// DISPATCH side of a session's stdin must never block, and `StdinEof` must be
// sequenced through the same queue as the bytes.
//
// (1) 128 KiB — twice a full pipe — is routed at a child that is not reading;
//     `route_stdin`/`route_stdin_eof` must still return promptly. RED on the
//     pre-fix inline `write_all`: the routing thread parks on the full pipe,
//     the 5 s wait elapses and the assert fires (the live leg
//     `session_stdin_flood_does_not_wedge_the_connection` in
//     crates/vmcell/tests/session.rs covers the consequences — an undispatched
//     `CloseSession` and the skipped C3 teardown).
// (2) Only THEN is the pipe drained: every queued byte must arrive, in order,
//     before EOF. RED if `StdinEof` closed the sink out of band (a short read)
//     or if a post-EOF write were still delivered (a long read).
#[test]
fn route_stdin_does_not_block_on_a_full_pipe_and_eof_follows_every_byte() {
    let (mut reader, writer) = std::io::pipe().expect("pipe");
    let (sessions, id) = stdin_test_session(StdinSink::Pipe(writer.into()));

    const N: usize = 128 * 1024;
    let payload: Vec<u8> = (0..N).map(|i| (i % 251) as u8).collect();
    let expected = payload.clone();
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let routed = std::thread::spawn(move || {
        route_stdin(&sessions, id, payload);
        route_stdin_eof(&sessions, id);
        // A write after EOF: the writer drops it (stdin is closed) — it must
        // never reach the child, and must not panic the thread.
        route_stdin(&sessions, id, b"AFTER-EOF".to_vec());
        // Drop the table (and with it the handle's queue sender) so the writer
        // thread ends once drained; the JoinHandle inside it is detached here,
        // exactly as it is when a session's waiter removes its own entry.
        done_tx.send(()).expect("signal");
    });
    done_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("routing a full pipe's worth of stdin must NOT block the dispatch loop (M6)");
    routed.join().expect("routing thread");

    let mut got = Vec::new();
    reader.read_to_end(&mut got).expect("read to EOF");
    assert_eq!(
        got.len(),
        N,
        "every queued byte must be written before StdinEof closes the pipe, and no post-EOF byte after it"
    );
    assert_eq!(got, expected, "the streamed bytes must arrive verbatim");
}

// M6: a stdin writer parked on a full pipe must give up once its session is
// flagged closing, so `SessionHandle::shutdown_stdin`'s join — run by
// `teardown_sessions` for every still-open session — is BOUNDED. RED on the
// inverse (drop the `closing` check in `write_stdin_sink`): the thread stays
// parked on the pipe forever and the `is_finished` assert fires (5 s), instead
// of hanging teardown. `_reader` stays alive throughout: dropping it would
// EPIPE the write and make the gate vacuous.
#[test]
fn stdin_writer_gives_up_on_closing_so_teardown_join_is_bounded() {
    let (_reader, writer) = std::io::pipe().expect("pipe");
    let (tx, rx) = std::sync::mpsc::channel();
    let closing = Arc::new(AtomicBool::new(false));
    let thread = spawn_stdin_writer(
        SessionId(3),
        Some(StdinSink::Pipe(writer.into())),
        rx,
        Arc::clone(&closing),
    );

    // 512 KiB at a reader that never reads: the writer parks on the full pipe.
    tx.send(StdinItem::Data(vec![7u8; 512 * 1024]))
        .expect("queue stdin");
    std::thread::sleep(Duration::from_millis(200));
    assert!(
        !thread.is_finished(),
        "the writer must actually be parked on the full pipe, or this gate is vacuous"
    );

    // The teardown sequence, minus the blocking join (so a regression reddens
    // rather than hangs): flag closing, drop the last queue sender.
    closing.store(true, Ordering::Relaxed);
    drop(tx);
    let deadline = Instant::now() + Duration::from_secs(5);
    while !thread.is_finished() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(
        thread.is_finished(),
        "a writer parked on a full stdin must give up within one STDIN_POLL_SLICE of `closing`"
    );
    thread.join().expect("writer thread");
}

/// A connected pair for driving the real `VsockStream` type without a vsock
/// device: `VsockStream` is a thin `OwnedFd` wrapper whose `Read`/`Write` are
/// plain `recv`/`send`, so an `AF_UNIX` socketpair drives it verbatim. The
/// second half is the "host" end the test reads frames from.
fn vsock_pair() -> (VsockStream, std::os::unix::net::UnixStream) {
    let (steward, host) = std::os::unix::net::UnixStream::pair().expect("socketpair");
    (VsockStream::from(OwnedFd::from(steward)), host)
}

/// Decodes one framed [`Message`] from the host end of a [`vsock_pair`].
fn read_msg(host: &mut std::os::unix::net::UnixStream) -> Message {
    let mut len = [0u8; 4];
    host.read_exact(&mut len).expect("frame length");
    let mut body = vec![0u8; u32::from_be_bytes(len) as usize];
    host.read_exact(&mut body).expect("frame body");
    postcard::from_bytes(&body).expect("decode")
}

/// A live child in its own process group, for the paths that `kill_group` it.
/// Using a real child keeps `kill_group` honest — a made-up pid would either
/// be a no-op (vacuous) or, at pid 0, kill the test runner's own group.
fn spawn_group_child() -> std::process::Child {
    let mut cmd = Command::new("sleep");
    cmd.arg("60");
    cmd.process_group(0);
    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::null());
    cmd.stderr(Stdio::null());
    cmd.spawn().expect("spawn a test child")
}

// m13 — "every recover-by-rebind path is rate-limited" is now a fact about ONE
// predicate instead of a claim each arm had to remember; the POLLERR arm did
// not, and the comment two arms over said it did.
//
// RED on the inverse (`RecoveryReason::ListenerFailed => Duration::ZERO`, the
// pre-fix POLLERR arm): the loop re-binds a broken listener with no pause.
#[test]
fn every_listener_failure_recovery_is_rate_limited() {
    let poll = Duration::from_millis(37);
    for reason in [
        RecoveryReason::ListenerFailed,
        RecoveryReason::PollFailed,
        RecoveryReason::AcceptFailed,
        RecoveryReason::ThreadRefused,
    ] {
        assert_eq!(
            recovery_backoff(reason, poll),
            poll,
            "{reason:?} must be rate-limited (L-GUEST-4)"
        );
    }
    assert_eq!(
        recovery_backoff(RecoveryReason::IdleWindowElapsed, poll),
        Duration::ZERO,
        "the idle exit is not a failure — it already waited rebind_idle"
    );
}

// The classification the back-off law is applied to. `POLLERR`/`POLLHUP`/
// `POLLNVAL` each mean the listener itself is gone (the post-restore deaf
// device), never "a connection is ready" — a live reproduction would need a
// broken vhost-vsock device, so this is where those arms are pinned.
#[test]
fn classify_poll_maps_every_wake() {
    use rustix::event::PollFlags;
    assert_eq!(
        classify_poll(Ok(0), PollFlags::empty()),
        PollAction::Repoll,
        "a timeout re-polls the remainder"
    );
    assert_eq!(classify_poll(Ok(1), PollFlags::IN), PollAction::Accept);
    for bad in [PollFlags::ERR, PollFlags::HUP, PollFlags::NVAL] {
        assert_eq!(
            classify_poll(Ok(1), PollFlags::IN | bad),
            PollAction::Recover(RecoveryReason::ListenerFailed),
            "{bad:?} is a listener failure even alongside POLLIN"
        );
    }
    assert_eq!(
        classify_poll(Err(rustix::io::Errno::INTR), PollFlags::empty()),
        PollAction::Interrupted,
        "EINTR must not consume the idle window"
    );
    assert_eq!(
        classify_poll(Err(rustix::io::Errno::NOMEM), PollFlags::empty()),
        PollAction::Recover(RecoveryReason::PollFailed)
    );
}

// m12 — PID 1's listener must survive the OS refusing a thread. The accepted
// connection is handed off through `dispatch_connection`, which REPORTS the
// refusal; `std::thread::spawn` panics on it, and that panic unwinds the
// detached listener thread with nobody observing it — the control plane stops
// accepting with no exit and no supervisor.
//
// The refusal is real, not simulated: a 64 TiB thread stack cannot be mapped,
// so `pthread_create` returns EAGAIN — the same errno a `RLIMIT_NPROC` famine
// gives — without touching a process-wide rlimit.
//
// RED on the inverse (`std::thread::spawn(move || …)` in `dispatch_connection`):
// this test panics with "failed to spawn thread: … (os error 11)".
#[test]
fn dispatch_connection_reports_a_refused_thread_instead_of_panicking() {
    let ctx = test_ctx();

    let (steward_side, host_side) = vsock_pair();
    let refused = dispatch_connection(
        std::thread::Builder::new().stack_size(1 << 46),
        steward_side,
        &ctx,
    )
    .expect_err("an unmappable thread stack must be refused, not spawned");
    assert_eq!(
        refused.kind(),
        std::io::ErrorKind::WouldBlock,
        "EAGAIN is the thread-famine refusal: {refused}"
    );
    drop(host_side);

    // Positive control: the same call with an ordinary builder does spawn, so
    // the assertion above is about the refusal and not about a broken helper.
    let (steward_side, host_side) = vsock_pair();
    dispatch_connection(
        std::thread::Builder::new().name("vmcell-vsock-conn-test".to_string()),
        steward_side,
        &ctx,
    )
    .expect("an ordinary builder must spawn the connection thread");
    drop(host_side);
}

// m31 — re-registering a LIVE session id must not unregister the live session.
// The pre-fix insert displaced it, and the displaced session's waiter then
// removed `id` from the table — i.e. the *new* session's entry — so the new
// session's Stdin/Winsize/CloseSession silently stopped resolving while its
// child ran on.
//
// RED on the inverse (`table.insert(id, handle)` returning `Ok(())`): the table
// holds the second pid and the refusal never happens.
#[test]
fn register_session_refuses_a_duplicate_live_id() {
    let sessions: Sessions = Arc::new(Mutex::new(HashMap::new()));
    let id = SessionId(9);

    let live = SessionHandle::new(id, None, None, 4242);
    assert!(
        register_session(&sessions, id, live).is_ok(),
        "the first registration must succeed"
    );

    let duplicate = SessionHandle::new(id, None, None, 5353);
    let rejected = register_session(&sessions, id, duplicate)
        .expect_err("a duplicate live id must be refused");
    assert_eq!(
        rejected.pid, 5353,
        "the REJECTED handle comes back so the caller can abandon it"
    );
    rejected.shutdown_stdin();

    let table = sessions.lock().expect("sessions");
    assert_eq!(
        table.get(&id).map(|h| h.pid),
        Some(4242),
        "the live session must survive the duplicate untouched"
    );
}

// m32 — a post-spawn failure (the PTY-master clone, or the refused duplicate
// above) must not leak the reaper reservation its spawn took: nothing else ever
// consumes it (these paths spawn no waiter) and the reservation map has no
// prune. The one abandon helper releases it, kills the child's group, and
// reports the failure through the terminal-frame convention.
//
// RED on the inverse (drop `reaper.cancel_reservation(pid)` from
// `abandon_spawned_session`): `pending_reservations` stays at 1.
#[test]
fn abandoning_a_spawned_session_releases_its_reaper_reservation() {
    let reaper = Arc::new(ReaperCoordinator::new());
    let (steward_side, mut host_side) = vsock_pair();
    let writer: Writer = Arc::new(Mutex::new(steward_side));
    let session = SessionId(11);

    let mut child = spawn_group_child();
    let pid = child.id();
    let epoch = reaper.pre_spawn_epoch();
    reaper.reserve(pid, epoch);
    assert_eq!(
        reaper.pending_reservations(),
        1,
        "the spawn's reservation must exist before the abandon, or this gate is vacuous"
    );

    abandon_spawned_session(
        &writer,
        session,
        &reaper,
        pid,
        "pty master clone failed: test",
    );

    assert_eq!(
        reaper.pending_reservations(),
        0,
        "an abandoned session must release the reservation nothing else will consume"
    );

    // The child's group was actually killed (not merely marked), and the host
    // got the one open-failure convention: stderr then exit 127.
    let status = child.wait().expect("reap the killed child");
    assert!(
        !status.success(),
        "the abandoned session's process group must be killed: {status:?}"
    );
    match read_msg(&mut host_side) {
        Message::SessionStderr { session: s, data } => {
            assert_eq!(s, session);
            assert!(
                String::from_utf8_lossy(&data).contains("pty master clone failed"),
                "the failure must name itself: {:?}",
                String::from_utf8_lossy(&data)
            );
        }
        other => panic!("expected SessionStderr, got {other:?}"),
    }
    assert_eq!(
        read_msg(&mut host_side),
        Message::SessionExit { session, code: 127 },
        "an open failure ends with the 127 terminal frame"
    );
}

// ---------------------------------------------------------------------------
// v33 delta 5: placement, the declared port, and the service-mode shutdown seam
// ---------------------------------------------------------------------------

// §3.5: the three per-mode differences are PARAMETERS of the placement, and each is read from
// exactly one predicate. Pinning them here means a fourth difference has to be added as a
// predicate rather than as an `if placement == Pid1` sprinkled through `run`.
//
// RED on the inverse of any arm — most importantly `needs_child_subreaper` answering true for
// `Pid1` (harmless but wrong) or false for `Service` (a hung `exec` the host reads as a timeout).
#[test]
fn placement_parameterizes_the_three_per_mode_differences() {
    assert!(GuestPlacement::Pid1.assembles_the_filesystem());
    assert!(!GuestPlacement::Service.assembles_the_filesystem());

    assert!(!GuestPlacement::Pid1.needs_child_subreaper());
    assert!(GuestPlacement::Service.needs_child_subreaper());

    assert_eq!(
        GuestPlacement::Pid1.default_sigterm_policy(),
        SigtermPolicy::PowerOff
    );
    assert_eq!(
        GuestPlacement::Service.default_sigterm_policy(),
        SigtermPolicy::Shutdown
    );
}

// The defaults a caller gets for free must be the shipped ones, and the SIGTERM policy must follow
// the placement rather than a constant — a `StewardOptions::new(Service)` that defaulted to
// `PowerOff` would mean `systemctl stop` powers off the machine.
#[test]
fn steward_options_defaults_follow_the_placement() {
    let pid1 = StewardOptions::new(GuestPlacement::Pid1);
    assert_eq!(pid1.vsock_port, vmcell_protocol::STEWARD_VSOCK_PORT);
    assert_eq!(pid1.tools_dir, std::path::Path::new(DEFAULT_TOOLS_DIR));
    assert_eq!(pid1.tuning, Tuning::default());
    assert_eq!(pid1.on_sigterm, SigtermPolicy::PowerOff);
    assert_eq!(pid1.max_reaped_statuses, crate::DEFAULT_MAX_REAPED_STATUSES);

    let service = StewardOptions::new(GuestPlacement::Service);
    assert_eq!(service.on_sigterm, SigtermPolicy::Shutdown);
    // Everything else is placement-blind, which is the point: one code path, one set of defaults.
    assert_eq!(service.vsock_port, pid1.vsock_port);
    assert_eq!(service.tools_dir, pid1.tools_dir);
    assert_eq!(service.tuning, pid1.tuning);
}

// §3.5: the `vmcell_steward_port=` parse is STRICT-or-default-with-a-logged-warning, deliberately
// unlike its silently-forgiving `parse_ms` siblings. The asymmetry is the assertion: a garbage
// tuning token costs a cadence, a garbage port token costs the whole control plane, and the two
// must not share a policy.
//
// RED on routing the token through `parse_ms` (which would clamp `0` up to a "valid" port and
// answer `Absent`-like defaults for garbage, collapsing the two outcomes an operator needs apart).
#[test]
fn the_steward_port_token_is_parsed_strictly() {
    assert_eq!(
        parse_steward_port("console=ttyS0 ro quiet"),
        StewardPortToken::Absent,
        "no token at all is the DEFAULT-port case, not a malformed one"
    );
    assert_eq!(
        parse_steward_port("console=ttyS0 vmcell_steward_port=5100 ro"),
        StewardPortToken::Valid(5100)
    );
    for bad in ["", "abc", "-1", "5100x", "99999999999999999999"] {
        assert_eq!(
            parse_steward_port(&format!("ro vmcell_steward_port={bad} quiet")),
            StewardPortToken::Invalid(bad.to_string()),
            "{bad:?} must be REJECTED, not silently clamped into a plausible port"
        );
    }
    // The AF_VSOCK reserved values the host's own `build()` refuses. Both sides must share one
    // validity domain, or a config the host accepts is one the guest cannot bind.
    for reserved in ["0", "4294967295"] {
        assert_eq!(
            parse_steward_port(&format!("vmcell_steward_port={reserved}")),
            StewardPortToken::Invalid(reserved.to_string()),
            "{reserved} is reserved by AF_VSOCK and is refused host-side at build()"
        );
    }
}

// The cmdline is the one channel carrying all three tunables, so `apply_cmdline` is where a
// declared value actually reaches the running steward. This is the guest half of the F1 defect the
// delta-4 premise sweep found on the host half: before this, a declared non-default port was
// emitted by the host, dialed by the host, and bound by nobody.
#[test]
fn apply_cmdline_honors_the_declared_port_and_the_tuning_tokens() {
    let mut opts = StewardOptions::new(GuestPlacement::Service);
    opts.apply_cmdline(
        "console=ttyS0 vmcell_steward_port=5100 vmcell_accept_poll_ms=7 \
         vmcell_rebind_idle_ms=500 ro",
    );
    assert_eq!(opts.vsock_port, 5100, "the declared port must be BOUND");
    assert_eq!(opts.tuning.accept_poll, Duration::from_millis(7));
    assert_eq!(opts.tuning.rebind_idle, Duration::from_millis(500));

    // A malformed port falls back to the default rather than to a plausible-but-wrong value — and
    // leaves the tuning tokens beside it untouched, so one bad token cannot poison the others.
    let mut opts = StewardOptions::new(GuestPlacement::Service);
    opts.apply_cmdline("vmcell_steward_port=nope vmcell_accept_poll_ms=9");
    assert_eq!(opts.vsock_port, vmcell_protocol::STEWARD_VSOCK_PORT);
    assert_eq!(opts.tuning.accept_poll, Duration::from_millis(9));

    // An absent token leaves the default in place, which is what makes a `Pid1` cell's cmdline
    // byte-identical to v32's (the host emits no token for the default port).
    let mut opts = StewardOptions::new(GuestPlacement::Pid1);
    opts.apply_cmdline("console=ttyS0 ro");
    assert_eq!(opts.vsock_port, vmcell_protocol::STEWARD_VSOCK_PORT);
    assert_eq!(opts.tuning, Tuning::default());
}

// Law C3 on the service-mode shutdown path needs a registry, because the `Sessions` table is
// created per connection inside `serve_connection` and is reachable from nowhere else. Before v33
// that was fine — the only SIGTERM policy was power-off, which reaches no session at all.
//
// RED on a registry that leaks (the ticket not deregistering, so a shutdown sweeps freed tables)
// and on `teardown_all` not draining (the residue law C3 forbids).
#[test]
fn the_connection_registry_publishes_and_reclaims_each_connection() {
    let registry = Arc::new(ConnectionRegistry::new());
    assert_eq!(registry.len(), 0);

    let a: Sessions = Arc::new(Mutex::new(HashMap::new()));
    let b: Sessions = Arc::new(Mutex::new(HashMap::new()));
    let ticket_a = registry.register(Arc::clone(&a));
    let ticket_b = registry.register(Arc::clone(&b));
    assert_eq!(registry.len(), 2, "both live connections must be visible");

    // `teardown_all` reports what it swept and leaves the tables drained, which is the C3 residue
    // assertion in its KVM-free form (the live leg asserts the process groups are actually gone).
    assert_eq!(registry.teardown_all(), 2);
    assert!(a.lock().expect("lock").is_empty());
    assert!(b.lock().expect("lock").is_empty());

    drop(ticket_a);
    assert_eq!(registry.len(), 1, "a dropped ticket must deregister");
    drop(ticket_b);
    assert_eq!(
        registry.len(),
        0,
        "the registry must not outlive the connections it names"
    );
    assert_eq!(
        registry.teardown_all(),
        0,
        "a shutdown after every connection closed sweeps nothing"
    );
}

// The shutdown seam itself: `serve_vsock` was an unconditional `loop {}` with no exit condition,
// so "stop accepting, tear down, exit" had nothing to hook. This drives the real listener thread
// and requires it to RETURN when the flag is set.
//
// RED on removing either shutdown check in `serve_vsock` (the outer bind-retry one or the inner
// poll one): the thread never returns and `recv_timeout` reddens instead of the suite hanging —
// the in-crate idiom `reserve_after_fast_child_already_drained_delivers_status` established for
// exactly this failure shape.
#[test]
fn the_shutdown_flag_stops_the_vsock_listener() {
    let ctx = test_ctx();
    let listener_ctx = Arc::clone(&ctx);
    // A short rebind window so the flag is observed promptly; `accept_poll` paces the bind-retry
    // path, which is the arm this test actually exercises when AF_VSOCK is unavailable (no KVM
    // needed either way — both arms check the flag).
    let tuning = Tuning {
        accept_poll: Duration::from_millis(5),
        rebind_idle: Duration::from_millis(20),
    };
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        serve_vsock(&listener_ctx, vmcell_protocol::STEWARD_VSOCK_PORT, tuning);
        let _ = tx.send(());
    });

    ctx.shutdown.store(true, Ordering::SeqCst);
    rx.recv_timeout(Duration::from_secs(5))
        .expect("the listener must observe the shutdown flag and RETURN, not loop forever");
}

// The `Pid1` floor, stated as a test rather than as a comment: a steward that names no placement
// gets exactly the pre-v33 behavior. The shutdown flag exists in both modes but is only ever SET
// by the service path, so `Pid1`'s listener is the same unconditional loop it always was.
#[test]
fn the_pid1_path_never_sets_the_shutdown_flag() {
    let ctx = test_ctx();
    assert!(
        !ctx.shutdown.load(Ordering::SeqCst),
        "the flag starts clear in both placements"
    );
    assert_eq!(
        StewardOptions::new(GuestPlacement::Pid1).on_sigterm,
        SigtermPolicy::PowerOff,
        "and `Pid1`'s SIGTERM policy never reaches the shutdown arm that sets it"
    );
}
