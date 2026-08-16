//! The vsock control plane: the listener, the accept loop, one thread per accepted connection,
//! the frame router, and law C3's session teardown.
//!
//! Placement-blind by construction (design §3.5): `Ready` is still the first frame of every
//! accepted connection, the framing/session/resync semantics do not vary, and the single-writer
//! discipline (law C4) holds in both modes. What v33 added here is a **shutdown seam** — a
//! service-mode steward must be able to stop accepting and exit, which the pre-v33 unconditional
//! `loop {}` had no hook for — and the [`ConnectionRegistry`], without which "tear down live
//! sessions on SIGTERM" had no way to reach a table that is created per connection.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use vmcell_protocol::{self as protocol, MAX_FRAME_BYTES, Message, SessionId};
use vsock::{VsockAddr, VsockListener, VsockStream};

use crate::ServeContext;
use crate::exec::{handle_exec, handle_put_file, handle_resync};
use crate::options::Tuning;
use crate::session::{
    SessionHandle, close_session, kill_group, route_stdin, route_stdin_eof, route_winsize,
    run_session,
};

/// The single per-connection writer (§13, Cross-cutting invariants): every frame — the initial `Ready`,
/// one-shot exec/put-file/resync output, and all interactive-session frames from
/// every pump/waiter thread — is emitted through this one `send_framed` under one
/// lock, so no two threads write the vsock concurrently and multiplexed session
/// frames never interleave-corrupt on the wire. The write half is a `try_clone`d
/// handle sharing the socket with the read half the dispatch loop owns.
pub(crate) type Writer = Arc<Mutex<VsockStream>>;

/// The per-connection session table: `SessionId` → its live [`SessionHandle`]
/// (§3, The control plane: vsock, the host clients, and the steward). The dispatch loop inserts on `OpenSession` and looks up on
/// `Stdin`/`Winsize`/`CloseSession`; each session's waiter thread removes its own
/// entry on exit; connection teardown drains and kills whatever is left (§13, Cross-cutting invariants).
pub(crate) type Sessions = Arc<Mutex<HashMap<SessionId, SessionHandle>>>;

/// Binds the `CID_ANY:port` listener in non-blocking mode.
///
/// Returns `None` on failure so the caller can retry — PID 1 must never give up
/// the control plane.
fn bind_vsock_listener(port: u32) -> Option<VsockListener> {
    let addr = VsockAddr::new(0xFFFFFFFF, port); // VMADDR_CID_ANY
    match VsockListener::bind(&addr) {
        Ok(listener) => {
            if let Err(e) = listener.set_nonblocking(true) {
                tracing::warn!(
                    "vmcell-steward: vsock set_nonblocking failed: {}; cannot poll for re-bind",
                    e
                );
            }
            Some(listener)
        }
        Err(e) => {
            tracing::error!("vmcell-steward: failed to bind vsock: {}", e);
            None
        }
    }
}

/// One iteration's outcome in the accept loop, as seen by the re-bind deadline
/// policy ([`next_deadline`]).
#[derive(Clone, Copy, Debug)]
pub(crate) enum AcceptOutcome {
    /// `accept()` returned a live connection.
    Accepted,
    /// `poll(2)` reported `POLLIN` but `accept()` said `WouldBlock` — a spurious
    /// wakeup.
    SpuriousReadable,
    /// `poll(2)` returned `EINTR` (PID 1 takes `SIGCHLD`; `poll` is never
    /// auto-restarted by `SA_RESTART`).
    Interrupted,
}

/// The re-bind deadline policy for one accept-loop iteration: only a **real**
/// accept restarts the idle window; a spurious wakeup or `EINTR` leaves the
/// deadline untouched.
///
/// The untouched-deadline half is the load-bearing part (§8.2, Restore correctness: a restored VM is not a fresh VM / §13, Cross-cutting invariants): a
/// post-restore *deaf* listener never delivers a real accept, but `poll` can
/// still wake (signals, stray revents). If those wakes extended the deadline,
/// the idle window would never elapse and the listener would never re-bind.
pub(crate) fn next_deadline(
    deadline: Instant,
    now: Instant,
    rebind_idle: Duration,
    outcome: AcceptOutcome,
) -> Instant {
    match outcome {
        AcceptOutcome::Accepted => now + rebind_idle,
        AcceptOutcome::SpuriousReadable | AcceptOutcome::Interrupted => deadline,
    }
}

/// Remaining time in the re-bind idle window, or `None` once the deadline has
/// been reached — the caller must then re-bind, not poll again.
///
/// Saturating: a `now` past the deadline yields `None`, never an underflow
/// panic. Exactly-at-deadline is `None`, not `Some(ZERO)` — a zero remainder
/// fed to [`poll_timeout_ms`] would be floored back up to 1 ms and the deaf
/// listener would keep polling forever instead of re-binding.
pub(crate) fn remaining_idle(deadline: Instant, now: Instant) -> Option<Duration> {
    let remaining = deadline.saturating_duration_since(now);
    (remaining > Duration::ZERO).then_some(remaining)
}

/// Clamps a remaining idle window into the whole-millisecond timeout `poll(2)`
/// takes: floored at 1 ms and otherwise truncated so it never overshoots the
/// remaining window by a full tick.
///
/// The 1 ms floor is a correctness floor, like the `parse_ms` clamp: a
/// sub-millisecond remainder truncated to `0` means "return immediately", which
/// busy-spins PID 1 until the deadline check catches up. Overshooting a sub-ms
/// remainder by <1 ms is harmless — the deadline itself is enforced on
/// [`Instant`]s by [`remaining_idle`], not by the poll timeout.
pub(crate) fn poll_timeout(remaining: Duration) -> rustix::time::Timespec {
    // Whole-millisecond clamp, floored at 1 ms — both are correctness bounds (see the doc above),
    // now expressed as the `Timespec` that rustix 1.x `poll(2)` takes (it was a raw `i32` ms count
    // on 0.38). `try_from` saturates the millisecond count at `i64::MAX` instead of wrapping, and
    // the 1 ms floor keeps a sub-ms remainder from truncating to 0 (which would busy-spin PID 1).
    let ms = i64::try_from(remaining.as_millis())
        .unwrap_or(i64::MAX)
        .max(1);
    rustix::time::Timespec {
        tv_sec: ms / 1_000,
        tv_nsec: (ms % 1_000) * 1_000_000,
    }
}

/// Why the accept loop is pausing or dropping its listener — the input to the one
/// back-off law, [`recovery_backoff`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RecoveryReason {
    /// The idle window elapsed with no accepted connection: re-bind onto the
    /// *current* vhost-vsock device (§8.2). Not a failure.
    IdleWindowElapsed,
    /// `poll(2)` reported the listener itself failed (`POLLERR`/`POLLHUP`/`POLLNVAL`).
    ListenerFailed,
    /// `poll(2)` failed with an errno other than `EINTR`.
    PollFailed,
    /// `accept(2)` failed with something other than `EAGAIN`.
    AcceptFailed,
    /// The OS refused a thread for an accepted connection.
    ThreadRefused,
}

/// L-GUEST-4: how long the accept loop pauses before recovering.
///
/// **One predicate, so "every recover-by-rebind path is rate-limited" is a fact
/// about this `match` instead of a claim each arm had to remember** — the
/// `POLLERR` arm did not, and the comment two arms over said it did. Every
/// *failure* pauses `accept_poll`: a persistent listener failure, poll errno,
/// accept errno, or thread famine would otherwise spin bind→poll→fail with no
/// pause at all. The idle-window exit is not a failure and needs no extra pause —
/// it just waited `rebind_idle`.
pub(crate) fn recovery_backoff(reason: RecoveryReason, accept_poll: Duration) -> Duration {
    match reason {
        RecoveryReason::IdleWindowElapsed => Duration::ZERO,
        RecoveryReason::ListenerFailed
        | RecoveryReason::PollFailed
        | RecoveryReason::AcceptFailed
        | RecoveryReason::ThreadRefused => accept_poll,
    }
}

/// What one `poll(2)` wake means for the accept loop.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PollAction {
    /// Timed out inside the idle window: re-poll with the recomputed remainder.
    Repoll,
    /// `EINTR` (PID 1 takes `SIGCHLD` and `poll` is never auto-restarted): re-poll,
    /// deadline untouched.
    Interrupted,
    /// The listener is readable: `accept`.
    Accept,
    /// Drop this listener and re-bind, after [`recovery_backoff`].
    Recover(RecoveryReason),
}

/// Classifies one `poll(2)` return plus its `revents`.
///
/// Pure, so every arm is unit-tested — including the `POLLERR` one, whose live
/// reproduction would need a broken vhost-vsock device.
pub(crate) fn classify_poll(
    polled: Result<usize, rustix::io::Errno>,
    revents: rustix::event::PollFlags,
) -> PollAction {
    use rustix::event::PollFlags;
    match polled {
        Ok(0) => PollAction::Repoll,
        Ok(_) if revents.intersects(PollFlags::ERR | PollFlags::HUP | PollFlags::NVAL) => {
            PollAction::Recover(RecoveryReason::ListenerFailed)
        }
        Ok(_) => PollAction::Accept,
        Err(rustix::io::Errno::INTR) => PollAction::Interrupted,
        Err(_) => PollAction::Recover(RecoveryReason::PollFailed),
    }
}

/// Serves one accepted connection and logs how it ended — the body of the
/// per-connection thread, named so the accept arm stays one line.
fn serve_connection_logged(stream: VsockStream, ctx: &Arc<ServeContext>) {
    if let Err(e) = serve_connection(stream, ctx) {
        // A clean host disconnect surfaces as `read_framed`'s `UnexpectedEof` (the
        // length prefix's `read_exact` hits EOF between requests): that is the
        // normal end of a connection, not a fault, so log it at info. Reserve error
        // level for genuine protocol/transport failures (L-GUEST-10).
        let clean_eof = e
            .downcast_ref::<std::io::Error>()
            .is_some_and(|io| io.kind() == std::io::ErrorKind::UnexpectedEof);
        if clean_eof {
            tracing::info!("vmcell-steward: host closed the connection");
        } else {
            tracing::error!("vmcell-steward: handle_connection error: {}", e);
        }
    }
}

/// Hands `stream` to its own thread, or returns the OS's refusal so the caller can
/// back off and keep serving.
///
/// `std::thread::spawn` **panics** when `pthread_create` fails (`EAGAIN` under
/// `RLIMIT_NPROC`/`threads-max`, `ENOMEM`). In the accept loop that panic unwinds
/// the *detached* listener thread, which nobody joins: PID 1's control plane would
/// vanish with no exit code, no kernel panic, and no supervisor — the one C1
/// failure mode the "never exit" rule cannot catch, because the process does not
/// exit. `Builder::spawn` reports the refusal instead.
///
/// `builder` is the seam: production passes a named `Builder`, and the unit test
/// passes one with an unsatisfiable stack size to drive the real `EAGAIN` refusal,
/// so the shipped path carries no `#[cfg(test)]` branch.
pub(crate) fn dispatch_connection(
    builder: std::thread::Builder,
    stream: VsockStream,
    ctx: &Arc<ServeContext>,
) -> std::io::Result<()> {
    let conn_ctx = Arc::clone(ctx);
    builder
        .spawn(move || serve_connection_logged(stream, &conn_ctx))
        .map(drop)
}

/// Serves the vsock control plane, re-binding the listener across snapshot
/// restores.
///
/// After a CH/Firecracker `--restore` the vhost-vsock device is re-created and
/// the listener bound before the snapshot goes deaf — it never yields the host's
/// post-restore reconnect (and the stale connection may never EOF), so a
/// bound-once listener wedges the warm-restore path forever. We therefore
/// re-`bind` whenever the listener has been idle for `rebind_idle`, which
/// re-attaches it to the *current* device. Re-binding is harmless during normal
/// operation: already-accepted connections keep their own fds, and the fresh
/// listener re-binds the same `CID_ANY:port` on the live device. Each
/// accepted connection is served on its own thread so a parked stale connection
/// never blocks new accepts.
///
/// The wait is event-driven (OPP-2): instead of `accept` → `WouldBlock` →
/// `sleep(accept_poll)` (a mean ~half-interval of added latency on *every*
/// connect), the loop blocks in `poll(2)` on the listener fd for `POLLIN` with
/// the **remaining re-bind window** as the timeout, so a host connection wakes
/// the steward sub-millisecond while the idle window still elapses exactly as
/// before. The deadline is `Instant`-based ([`remaining_idle`]) and only a real
/// accept restarts it ([`next_deadline`]); `EINTR` and spurious wakeups re-poll
/// with the recomputed remainder. `accept_poll` paces only failure recovery (see
/// [`ACCEPT_POLL`] and [`recovery_backoff`], the one predicate that decides which
/// exits are rate-limited). Any poll-level listener failure
/// (`POLLERR`/`POLLHUP`/`POLLNVAL`, or an errno other than `EINTR`) is logged
/// and treated like the deaf-listener case — re-bind, never exit; an OS that
/// refuses a connection thread costs that one connection, not the loop
/// ([`dispatch_connection`]). PID 1 must never give up the control plane.
pub(crate) fn serve_vsock(ctx: &Arc<ServeContext>, port: u32, tuning: Tuning) {
    let Tuning {
        accept_poll,
        rebind_idle,
    } = tuning;
    use rustix::event::{PollFd, PollFlags};

    loop {
        // The shutdown seam (v33 delta 5). Under `Pid1` this flag is never set and the loop is the
        // unconditional `loop {}` it has always been; under `Service` it is how "stop accepting"
        // becomes an actual exit rather than an aspiration. Checked at BOTH loop levels: the outer
        // one covers the bind-retry path, the inner one the poll path, and a flag observed at only
        // one of them leaves a shutdown wedged behind whichever loop it is not in.
        if ctx.shutdown.load(Ordering::SeqCst) {
            tracing::info!("vmcell-steward: vsock listener stopping (shutdown requested)");
            return;
        }
        let Some(listener) = bind_vsock_listener(port) else {
            // Bind-failure retry cadence, still floor-clamped by `parse_ms` so a
            // cmdline `0` cannot busy-spin PID 1.
            std::thread::sleep(accept_poll);
            continue;
        };
        tracing::info!("vmcell-steward: listening on vsock port {}", port);

        // Idle window starts at the (re)bind; only a successful accept restarts
        // it. Once it elapses with no accepted connection — or an arm below
        // `break`s on a listener-level failure — fall out, drop this listener,
        // and re-bind on the current device (§8.2, Restore correctness: a restored VM is not a fresh VM).
        let mut deadline = Instant::now() + rebind_idle;
        // The one exit reason: every path out of the accept loop names why it is
        // leaving, and the single back-off below rate-limits it (L-GUEST-4).
        let mut reason = RecoveryReason::IdleWindowElapsed;
        while let Some(remaining) = remaining_idle(deadline, Instant::now()) {
            if ctx.shutdown.load(Ordering::SeqCst) {
                tracing::info!("vmcell-steward: vsock listener stopping (shutdown requested)");
                return;
            }
            let mut fds = [PollFd::new(&listener, PollFlags::IN)];
            // rustix 1.x `poll` takes `Option<&Timespec>`; `Some(&ts)` preserves the finite
            // timeout — `None` would block forever and defeat the idle-rebind deadline.
            let timeout = poll_timeout(remaining);
            let polled = rustix::event::poll(&mut fds, Some(&timeout));
            match classify_poll(polled, fds[0].revents()) {
                // Timed out: loop back — the recomputed remainder hits zero (or
                // re-polls a sub-ms tail once) and triggers the re-bind.
                PollAction::Repoll => {}
                PollAction::Interrupted => {
                    deadline = next_deadline(
                        deadline,
                        Instant::now(),
                        rebind_idle,
                        AcceptOutcome::Interrupted,
                    );
                }
                // Fail loud, then recover: a listener-level failure is treated like
                // the deaf-listener case — re-bind rather than exit.
                PollAction::Recover(r) => {
                    tracing::warn!(
                        "vmcell-steward: vsock listener re-binding ({:?}): poll {:?}, revents {:?}",
                        r,
                        polled,
                        fds[0].revents()
                    );
                    reason = r;
                    break;
                }
                // POLLIN: the (still non-blocking) listener should have a
                // connection ready.
                PollAction::Accept => match listener.accept() {
                    Ok((s, _)) => {
                        deadline = next_deadline(
                            deadline,
                            Instant::now(),
                            rebind_idle,
                            AcceptOutcome::Accepted,
                        );
                        tracing::info!("vmcell-steward: accepted connection");
                        let builder =
                            std::thread::Builder::new().name("vmcell-vsock-conn".to_string());
                        if let Err(e) = dispatch_connection(builder, s, ctx) {
                            // The OS refused a thread. C1: never exit, never die —
                            // the connection is dropped (its fd closes, so the host
                            // sees a reset instead of a silent hang) and the loop
                            // keeps serving, paced so a sustained thread famine
                            // cannot spin accept→spawn-fail.
                            tracing::error!(
                                "vmcell-steward: the OS refused a connection thread: {}; dropping this connection and continuing to serve",
                                e
                            );
                            std::thread::sleep(recovery_backoff(
                                RecoveryReason::ThreadRefused,
                                accept_poll,
                            ));
                        }
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        // Spurious wakeup: re-poll with the recomputed
                        // remainder. MUST NOT restart the idle window — a
                        // deaf listener has to run out the clock and re-bind.
                        deadline = next_deadline(
                            deadline,
                            Instant::now(),
                            rebind_idle,
                            AcceptOutcome::SpuriousReadable,
                        );
                    }
                    Err(e) => {
                        tracing::info!("vmcell-steward: accept error: {}; re-binding", e);
                        reason = RecoveryReason::AcceptFailed;
                        break;
                    }
                },
            }
        }
        // The ONE recovery pause: whichever way the accept loop ended, its reason
        // decides the rate limit, so no arm can re-bind without one (L-GUEST-4).
        std::thread::sleep(recovery_backoff(reason, accept_poll));
    }
}

/// Postcard-encodes and frames one [`Message`] through the single per-connection
/// [`Writer`] (§13, Cross-cutting invariants). Locking mirrors the reaper's poison policy (recover the
/// guard rather than propagate a poison panic through PID 1).
pub(crate) fn send_msg(writer: &Writer, msg: &Message) -> std::io::Result<()> {
    let bytes = postcard::to_stdvec(msg).map_err(std::io::Error::other)?;
    let mut stream = writer.lock().unwrap_or_else(|e| e.into_inner());
    send_framed(&mut *stream, &bytes)
}

/// Serves one accepted connection: sends `Ready`, runs the dispatch loop, and —
/// however the loop ends — tears down every session it left open (§13, Cross-cutting invariants).
///
/// The stream is split into a read half (owned by [`serve_loop`]) and a
/// `try_clone`d write half behind the single [`Writer`], so a session pump can
/// emit output while the loop is blocked reading the next frame, without two
/// threads ever writing the socket at once (§13, Cross-cutting invariants).
fn serve_connection(
    stream: VsockStream,
    ctx: &Arc<ServeContext>,
) -> Result<(), Box<dyn std::error::Error>> {
    let writer: Writer = Arc::new(Mutex::new(stream.try_clone()?));
    let sessions: Sessions = Arc::new(Mutex::new(HashMap::new()));
    let mut read_stream = stream;

    // Publish this connection's table for the duration of the connection, so a service-mode
    // shutdown can honor law C3 on it. The ticket deregisters on drop, including on the `?` below
    // and on a panic — the registry must never outlive the connections it names, or a shutdown
    // would iterate freed tables.
    let _ticket = ctx.connections.register(Arc::clone(&sessions));

    send_msg(&writer, &Message::Ready)?;
    let result = serve_loop(&mut read_stream, &writer, &sessions, ctx);
    // Connection owns its sessions (§13, Cross-cutting invariants): before returning, kill every
    // still-open session's process group so no interactive session outlives the
    // connection that opened it. Draining the table also drops each handle,
    // closing its stdin pipe / PTY master fds.
    teardown_sessions(&sessions);
    result
}

/// Every live connection's session table, so a service-mode shutdown can honor law C3 on tables
/// that are created **per connection** and reachable from nowhere else (design §3.5).
///
/// Before v33 this had no reason to exist: the only SIGTERM policy was `power_off_never_returns`,
/// which reaches no session at all — teardown happened solely on the connection's own exit path.
/// A `Service` steward exits instead, and an exit that leaves a session's process group alive is
/// exactly the residue law C3 forbids.
#[derive(Debug, Default)]
pub(crate) struct ConnectionRegistry {
    live: Mutex<HashMap<u64, Sessions>>,
    next_id: std::sync::atomic::AtomicU64,
}

/// Deregisters one connection's session table when it drops.
///
/// RAII rather than a paired call, for the same reason the rest of the crate prefers it: the
/// register/deregister pair spans a `?`, a panic, and three `return`s, and the one form that
/// cannot be forgotten on any of them is a guard.
pub(crate) struct ConnectionTicket {
    registry: Arc<ConnectionRegistry>,
    id: u64,
}

impl Drop for ConnectionTicket {
    fn drop(&mut self) {
        self.registry
            .live
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&self.id);
    }
}

impl ConnectionRegistry {
    /// An empty registry.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Publishes `sessions` until the returned ticket drops.
    pub(crate) fn register(self: &Arc<Self>, sessions: Sessions) -> ConnectionTicket {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.live
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(id, sessions);
        ConnectionTicket {
            registry: Arc::clone(self),
            id,
        }
    }

    /// Tears down every registered connection's sessions, returning how many tables were swept.
    ///
    /// The tables are collected under the lock and torn down **outside** it, mirroring
    /// [`teardown_sessions`]'s own discipline: `kill_group` is a syscall, and holding the registry
    /// lock across it would serialize shutdown behind the slowest process group. Racing a
    /// connection's own teardown is harmless — the second drain finds an empty table.
    pub(crate) fn teardown_all(&self) -> usize {
        let tables: Vec<Sessions> = {
            let live = self.live.lock().unwrap_or_else(|e| e.into_inner());
            live.values().map(Arc::clone).collect()
        };
        for sessions in &tables {
            teardown_sessions(sessions);
        }
        tables.len()
    }

    /// How many connections are currently registered. Diagnostics and tests only.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.live.lock().unwrap_or_else(|e| e.into_inner()).len()
    }
}

/// The desync warn line for a control-plane frame the host must never send, built
/// where a test can reach it (docs/78 §6, `uncapped-frame-debug-renders`).
///
/// This line lands on the **persisted** serial-console artifact, and `msg` is a
/// host-chosen frame bounded only by [`MAX_FRAME_BYTES`] (16 MiB) — an uncapped
/// `{msg:?}` writes that, several times over in decimal, into an artifact every later
/// run reads. The render therefore goes through the shared
/// [`protocol::capped_debug`], which also *stops* the formatter at the cap, so PID 1
/// does no frame-sized work for a log line. The frame's wire size beside it is the
/// number a desync report actually needs, and it is free at the call site.
///
/// It is a function, not an inline `warn!`, because the dispatch loop it is called
/// from takes a concrete `VsockStream` and cannot be driven from a unit test — this
/// is the reachable seam its gate asserts on.
pub(crate) fn unexpected_frame_warning(frame_bytes: usize, msg: &Message) -> String {
    format!(
        "vmcell-steward: unexpected control-plane message ({frame_bytes} byte frame): {}; closing connection to resync",
        protocol::capped_debug(msg)
    )
}

/// The per-connection dispatch loop: reads one framed [`Message`] at a time and
/// routes it. It never blocks on a running child — one-shot `Exec` is still
/// synchronous (drains to `Exit` before the next read, the one-shot contract),
/// while `OpenSession` spawns a session and returns immediately so many sessions
/// multiplex over the one connection (§3, The control plane: vsock, the host clients, and the steward).
fn serve_loop(
    read_stream: &mut VsockStream,
    writer: &Writer,
    sessions: &Sessions,
    ctx: &Arc<ServeContext>,
) -> Result<(), Box<dyn std::error::Error>> {
    loop {
        let req_bytes = read_framed(read_stream)?;
        let msg: Message = postcard::from_bytes(&req_bytes)?;

        match msg {
            Message::Exec(req) => handle_exec(req, writer, ctx)?,
            Message::PutFile { dst, bytes } => handle_put_file(&dst, &bytes, writer)?,
            Message::Resync {
                unix_secs,
                unix_nanos,
                mac,
                ipv4,
            } => handle_resync(unix_secs, unix_nanos, mac, ipv4, writer)?,
            // Interactive-session control (§3, The control plane: vsock, the host clients, and the steward). These never fail the
            // connection: a bad open reports `SessionExit(127)` to the host, and a
            // frame for an unknown/closed session is dropped at debug — the session
            // simply already ended.
            Message::OpenSession { session, spec } => {
                run_session(session, spec, writer, sessions, ctx);
            }
            Message::Stdin { session, data } => route_stdin(sessions, session, data),
            Message::StdinEof { session } => route_stdin_eof(sessions, session),
            Message::Winsize {
                session,
                rows,
                cols,
            } => route_winsize(sessions, session, rows, cols),
            Message::CloseSession { session } => close_session(sessions, session),
            // Ready/Stdout/Stderr/Exit and the guest→host session frames are
            // guest→host only; receiving one means the peer desynced. Log it loudly
            // and close the connection so the host reconnects on a fresh stream,
            // rather than silently swallowing it and looping on a skewed stream
            // (AGENT-5).
            other => {
                tracing::warn!("{}", unexpected_frame_warning(req_bytes.len(), &other));
                return Ok(());
            }
        }
    }
}

/// Kills every still-open session's process group and drops its fds (§13, Cross-cutting invariants),
/// invoked once the connection's dispatch loop has ended for any reason.
pub(crate) fn teardown_sessions(sessions: &Sessions) {
    // Drain under the lock, then kill and join OUTSIDE it: joining a stdin writer
    // thread while holding the table lock would block every still-running waiter
    // thread's own removal (M6).
    let drained: Vec<(SessionId, SessionHandle)> = {
        let mut table = sessions.lock().unwrap_or_else(|e| e.into_inner());
        table.drain().collect()
    };
    for (id, handle) in drained {
        tracing::info!(
            "vmcell-steward: connection ending; killing session {:?} (pid {})",
            id,
            handle.pid
        );
        // Kill first: the dead child releases the pipe read end / PTY slave, so a
        // writer thread parked on a full stdin fails immediately (EPIPE/EIO) and
        // the join below is prompt; `closing` bounds the residual case (M6).
        kill_group(handle.pid);
        handle.shutdown_stdin();
    }
}

// Generic over `Write`/`Read` (not just `VsockStream`) so the hand-rolled
// framing — the load-bearing interop with the host's `tokio_util`
// `LengthDelimitedCodec` — can be round-tripped against the real codec in a
// KVM-free unit test (AGENT-3); `VsockStream` satisfies both bounds.
pub(crate) fn send_framed<W: Write>(stream: &mut W, data: &[u8]) -> std::io::Result<()> {
    // Enforce the shared cap on the ENCODE side too (L-GUEST-2), mirroring the
    // host codec and the guest decode path. Without this, a `data.len()` above
    // `u32::MAX` would silently truncate through `as u32` and the host would
    // decode a wrong length; even below that, sending an over-cap frame the host
    // rejects only wastes a round-trip. Fail loud at the source instead.
    if data.len() > MAX_FRAME_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "frame too large",
        ));
    }
    // `data.len() <= MAX_FRAME_BYTES` (checked just above) < u32::MAX, so this never truncates; the
    // saturating fallback is dead but keeps the narrowing honest (a bogus over-cap length would be
    // sent as u32::MAX, which the host rejects — never a silently-wrong small length).
    let len = u32::try_from(data.len()).unwrap_or(u32::MAX);
    stream.write_all(&len.to_be_bytes())?;
    stream.write_all(data)?;
    Ok(())
}

pub(crate) fn read_framed<R: Read>(stream: &mut R) -> std::io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    // Shared cap with the host codec (see `MAX_FRAME_BYTES`); both ends agree so
    // neither silently drops a frame the other was willing to send.
    if len > MAX_FRAME_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "message too large",
        ));
    }
    let mut data = vec![0u8; len];
    stream.read_exact(&mut data)?;
    Ok(data)
}
