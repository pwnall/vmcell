//! Host-side interactive-session multiplexer (§3, The control plane: vsock, the host clients, and the steward).
//!
//! [`SessionMux`] owns its **own** vsock connection to the steward — separate
//! from the one-shot [`StewardClient`], so the two never share a
//! stream — and multiplexes many concurrent [`Session`]s over it, each keyed by a
//! [`SessionId`]. It reuses the one [`StewardClient`]
//! connect/handshake law (§13, Cross-cutting invariants), then splits the framed stream into a background
//! reader task (demuxes guest→host
//! `SessionStdout`/`SessionStderr`/`SessionExit` to per-session channels) and a
//! writer task (serializes every host→guest frame — the host mirror of the guest's
//! single-writer discipline, §13, Cross-cutting invariants). Dropping the `SessionMux` closes the
//! connection, which the guest observes as the read-loop end that triggers
//! connection-owns-its-sessions teardown (§13, Cross-cutting invariants), so a forgotten `close()` still
//! cannot leak guest processes.

use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures::stream::{SplitSink, SplitStream};
use futures::{SinkExt, StreamExt};
// Only the KVM-free demux tests construct raw sockets now; the live transport goes
// through `ControlStream` (AF_UNIX or AF_VSOCK).
#[cfg(test)]
use tokio::net::UnixStream;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::codec::{Framed, LengthDelimitedCodec};

use super::{ControlStream, StewardClient, encode_frame};
use crate::error::{Error, Result};
use crate::vmm::VsockEndpoint;
use vmcell_protocol::{
    ExecOutcome, ExecRequest, Message, PtyConfig, SessionId, SessionSpec, capped_debug,
};

type FramedStream = Framed<ControlStream, LengthDelimitedCodec>;
type FrameSink = SplitSink<FramedStream, ::bytes::Bytes>;
/// `SessionId` → the sender feeding that session's [`Session::recv`] channel, or
/// `None` once the reader task's terminal step has **closed** the registry (M5).
/// Closing is one critical section that both drops every live session sender (so
/// a pending `recv()` wakes with `None` instead of hanging) and makes the closure
/// observable to [`SessionMux::open`], which then returns the documented typed
/// error rather than registering into a map nothing will ever read from.
///
/// This `Option` is the connection's **one shared closed-flag** (§17, Open gaps and future capabilities):
/// the reader's terminal step is its only writer, and every host→guest path reads
/// it under this same lock before enqueueing a frame — [`SessionMux::open`] (which
/// needs the map anyway) and [`Session::send`], the one helper behind
/// `write_stdin`/`close_stdin`/`resize`/`close`. There is no second flag to drift:
/// a `Session` holds a clone of this `Arc`, not a copy of the state.
type Registry = Arc<Mutex<Option<HashMap<SessionId, mpsc::UnboundedSender<SessionEvent>>>>>;

/// An output or terminal event delivered to a [`Session`] (§3, The control plane: vsock, the host clients, and the steward).
///
/// A session yields zero-or-more `Stdout`/`Stderr` events then exactly one `Exit`
/// — after which [`Session::recv`] returns `None` (§13, Cross-cutting invariants). A PTY session merges
/// its output into `Stdout`, so it never yields `Stderr`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SessionEvent {
    /// Standard output (or merged PTY output) bytes.
    Stdout(Vec<u8>),
    /// Standard error bytes (pipe sessions only).
    Stderr(Vec<u8>),
    /// The session's exit code — its terminal event.
    Exit(i32),
}

/// Ergonomic builder for a [`SessionSpec`] (§3.3, Interactive-session wire semantics).
///
/// A thin convenience over `SessionSpec { command: ExecRequest{..}, pty }`: set the
/// argv, then optionally an environment, working directory, kill deadline, and
/// PTY window size. `pty(rows, cols)` makes it a controlling-terminal session;
/// leaving it unset yields a pipe session with streamable stdin.
#[derive(Debug, Clone)]
pub struct SessionSpecBuilder {
    command: ExecRequest,
    pty: Option<PtyConfig>,
}

impl SessionSpecBuilder {
    /// Starts a pipe session spec for `argv` (`argv[0]` is the program).
    #[must_use]
    pub fn new(argv: Vec<String>) -> Self {
        Self {
            command: ExecRequest::new(argv),
            pty: None,
        }
    }

    /// Sets the environment variables.
    #[must_use]
    pub fn env(mut self, env: Vec<(String, String)>) -> Self {
        self.command = self.command.with_env(env);
        self
    }

    /// Sets the working directory.
    #[must_use]
    pub fn cwd(mut self, cwd: impl Into<String>) -> Self {
        self.command = self.command.with_cwd(cwd);
        self
    }

    /// Sets an optional kill deadline. Unset (the default) means the session is
    /// **persistent** — bounded by [`Session::close`], the child exiting, or the
    /// connection closing (§3.3, Interactive-session wire semantics), not a timeout.
    #[must_use]
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.command = self.command.with_timeout(timeout);
        self
    }

    /// Requests a PTY with the given initial window size (controlling terminal,
    /// `isatty()` true in-guest, resizable via [`Session::resize`]).
    #[must_use]
    pub fn pty(mut self, rows: u16, cols: u16) -> Self {
        self.pty = Some(PtyConfig { rows, cols });
        self
    }

    /// Builds the [`SessionSpec`].
    #[must_use]
    pub fn build(self) -> SessionSpec {
        let mut spec = SessionSpec::new(self.command);
        if let Some(pty) = self.pty {
            spec = spec.with_pty(pty.rows, pty.cols);
        }
        spec
    }
}

/// A multiplexing connection to the steward for interactive sessions
/// (§3, The control plane: vsock, the host clients, and the steward). See the [module docs](self).
#[derive(Debug)]
pub struct SessionMux {
    /// Outgoing frames to the writer task (host mirror of the single-writer law).
    write_tx: mpsc::UnboundedSender<::bytes::Bytes>,
    registry: Registry,
    next_id: AtomicU64,
    reader: JoinHandle<()>,
    writer: JoinHandle<()>,
}

impl SessionMux {
    /// Connects a fresh session-multiplexing connection to the steward, using
    /// the same connect/handshake law as [`StewardClient`]
    /// (§13, Cross-cutting invariants).
    ///
    /// # Errors
    /// Returns an error if the connection or `Ready` handshake does not complete
    /// within `timeout` (or a guest panic is detected while waiting).
    pub async fn connect(
        vsock_path: &Path,
        port: u32,
        timeout: Duration,
        timeouts: &crate::config::Timeouts,
        serial_log: &dyn crate::vmm::SerialLog,
    ) -> Result<Self> {
        Self::connect_endpoint(
            &VsockEndpoint::Unix {
                path: vsock_path.to_path_buf(),
                port,
            },
            timeout,
            timeouts,
            serial_log,
        )
        .await
    }

    /// Connects a session multiplexer over an explicit [`VsockEndpoint`] — the
    /// transport-generic entry the orchestrator uses so a snapshot-eligible QEMU on
    /// the AF_VSOCK transport (§2.4, QEMU q35 — the fallback and most-proven nester) opens sessions the same way as an
    /// AF_UNIX backend. The public [`SessionMux::connect`] is the AF_UNIX wrapper.
    ///
    /// # Errors
    /// As [`SessionMux::connect`].
    pub(crate) async fn connect_endpoint(
        endpoint: &VsockEndpoint,
        timeout: Duration,
        timeouts: &crate::config::Timeouts,
        serial_log: &dyn crate::vmm::SerialLog,
    ) -> Result<Self> {
        let framed = StewardClient::connect_framed(endpoint, timeout, timeouts, serial_log).await?;
        Ok(Self::from_framed(framed))
    }

    /// Wraps an already-connected framed stream: splits it and spawns the reader +
    /// writer tasks. Shared by [`SessionMux::connect`] and the KVM-free demux test.
    fn from_framed(framed: FramedStream) -> Self {
        let (sink, stream) = framed.split();
        let registry: Registry = Arc::new(Mutex::new(Some(HashMap::new())));
        let (write_tx, write_rx) = mpsc::unbounded_channel();
        let reader = tokio::spawn(reader_task(stream, Arc::clone(&registry)));
        let writer = tokio::spawn(writer_task(sink, write_rx));
        Self {
            write_tx,
            registry,
            next_id: AtomicU64::new(0),
            reader,
            writer,
        }
    }

    /// Opens a new interactive session: allocates a [`SessionId`], registers its
    /// event channel, sends `OpenSession`, and returns the [`Session`] handle.
    ///
    /// There is no open-ack round-trip: the single ordered stream guarantees the
    /// guest processes this `OpenSession` before any `Stdin`/`Winsize` the caller
    /// sends next (§3.3, Interactive-session wire semantics). A failed open surfaces as the session's
    /// `SessionEvent::Exit(127)`.
    ///
    /// # Errors
    /// Returns [`Error::Steward`] if the underlying connection has already closed.
    pub async fn open(&self, spec: SessionSpec) -> Result<Session> {
        let id = SessionId(self.next_id.fetch_add(1, Ordering::Relaxed));
        // Encode + `MAX_FRAME_BYTES`-check BEFORE touching the registry, so an
        // over-cap spec (huge argv/env) fails loud with zero registry residue.
        let frame = encode_frame(&Message::OpenSession { session: id, spec })?;
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        {
            // M5: check-closed and insert in ONE critical section, against the
            // same lock the reader's terminal step takes the registry through. A
            // dead reader (peer close, decode desync) is therefore observable
            // here and fails loud per the `# Errors` contract above; pre-fix the
            // insert landed in an abandoned map and — because the writer task
            // only dies on its NEXT transport failure — the `OpenSession` still
            // enqueued, leaving `recv()`/`wait()` pending forever with no error.
            let mut reg = self.registry.lock().unwrap_or_else(|e| e.into_inner());
            let Some(sessions) = reg.as_mut() else {
                return Err(Error::Steward("session connection is closed".into()));
            };
            sessions.insert(id, event_tx);
        }
        // Insert-before-send keeps the guest's first output routable; on a send
        // failure remove the entry we just inserted so nothing is orphaned. (An
        // open that races the reader's close instead has its sender dropped by
        // that close, so its `recv()` yields `None` — never a hang.)
        if self.write_tx.send(frame).is_err() {
            if let Some(sessions) = self
                .registry
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .as_mut()
            {
                sessions.remove(&id);
            }
            return Err(Error::Steward("session connection is closed".into()));
        }
        Ok(Session {
            id,
            event_rx,
            write_tx: self.write_tx.clone(),
            // The SHARED closed-flag, not a copy of it: `Session::send` reads the
            // very `Option` the reader's terminal step takes to `None`.
            registry: Arc::clone(&self.registry),
            exited: false,
        })
    }

    /// Convenience: opens a session from an argv-and-options [`SessionSpecBuilder`].
    ///
    /// # Errors
    /// As [`SessionMux::open`].
    pub async fn open_spec(&self, builder: SessionSpecBuilder) -> Result<Session> {
        self.open(builder.build()).await
    }
}

#[cfg(test)]
impl SessionMux {
    /// Test-only: the number of live per-session registry entries, so the KVM-free
    /// orphan gate can assert a failed `open` leaves zero residue.
    fn registry_len(&self) -> usize {
        self.registry
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .map_or(0, HashMap::len)
    }

    /// Test-only: await the reader task's completion, so the M5 gate can assert
    /// on the state the reader's *terminal* step leaves behind (registry closed)
    /// without racing it. Replaces the handle with a finished one so `Drop`'s
    /// abort still has something to abort.
    async fn await_reader_for_test(&mut self) {
        let reader = std::mem::replace(&mut self.reader, tokio::spawn(async {}));
        reader.await.expect("the reader task must not panic");
    }

    /// Test-only: deterministically kill the writer task so its `write_rx` is
    /// dropped, making a subsequent `write_tx.send` fail. Awaiting the aborted
    /// handle guarantees the task has unwound (and thus dropped the receiver)
    /// before we return, so the send-failure branch of `open`/`send` is reachable
    /// without a race.
    async fn kill_writer_for_test(&mut self) {
        self.writer.abort();
        let old = std::mem::replace(&mut self.writer, tokio::spawn(async {}));
        #[expect(
            clippy::let_underscore_must_use,
            reason = "awaiting an aborted JoinHandle: the Cancelled error IS the wanted outcome, since the point is that the task has unwound"
        )]
        let _ = old.await;
    }
}

impl Drop for SessionMux {
    fn drop(&mut self) {
        // Abort both tasks so the split sink AND stream drop, closing the
        // connection even while `Session` handles still hold `write_tx` clones.
        // The guest sees the read-loop EOF and tears down its sessions (§13, Cross-cutting invariants).
        self.reader.abort();
        self.writer.abort();
    }
}

/// A handle to one interactive session on a [`SessionMux`] (§3, The control plane: vsock, the host clients, and the steward).
///
/// Send input with [`write_stdin`](Session::write_stdin) /
/// [`close_stdin`](Session::close_stdin), resize a PTY with
/// [`resize`](Session::resize), terminate with [`close`](Session::close), and read
/// output/exit with [`recv`](Session::recv) or drain to completion with
/// [`wait`](Session::wait).
#[derive(Debug)]
pub struct Session {
    id: SessionId,
    event_rx: mpsc::UnboundedReceiver<SessionEvent>,
    write_tx: mpsc::UnboundedSender<::bytes::Bytes>,
    /// The mux's shared closed-flag (the [`Registry`] `Option`), read by
    /// [`Session::send`] before every enqueue.
    registry: Registry,
    exited: bool,
}

impl Session {
    /// This session's id.
    #[must_use]
    pub fn id(&self) -> SessionId {
        self.id
    }

    // The mutating methods are `async` (though the current unbounded send does not
    // await) so a future switch to a bounded, backpressuring channel (§17, Open gaps and future capabilities) is not
    // an API break.

    /// Streams stdin bytes to the running command (pipe: to its stdin; PTY: as
    /// terminal input).
    ///
    /// # Errors
    /// Returns [`Error::Steward`] if the connection has closed.
    pub async fn write_stdin(&self, data: &[u8]) -> Result<()> {
        self.send(Message::Stdin {
            session: self.id,
            data: data.to_vec(),
        })
    }

    /// Closes the session's stdin (pipe: the child reads EOF; PTY: a no-op — end
    /// input in-band or with [`close`](Session::close)).
    ///
    /// # Errors
    /// Returns [`Error::Steward`] if the connection has closed.
    pub async fn close_stdin(&self) -> Result<()> {
        self.send(Message::StdinEof { session: self.id })
    }

    /// Resizes a PTY session's window (`SIGWINCH`); a no-op for a pipe session.
    ///
    /// # Errors
    /// Returns [`Error::Steward`] if the connection has closed.
    pub async fn resize(&self, rows: u16, cols: u16) -> Result<()> {
        self.send(Message::Winsize {
            session: self.id,
            rows,
            cols,
        })
    }

    /// Terminates the session (`SIGKILL`s its process group in-guest). The
    /// resulting exit still arrives as the session's terminal [`SessionEvent::Exit`].
    ///
    /// # Errors
    /// Returns [`Error::Steward`] if the connection has closed.
    pub async fn close(&self) -> Result<()> {
        self.send(Message::CloseSession { session: self.id })
    }

    /// The one host→guest enqueue behind all four mutators above — so the
    /// closed-check exists once, not four times (§13, Cross-cutting invariants).
    ///
    /// Check-closed and enqueue happen in ONE critical section, against the same
    /// lock the reader task's terminal step closes the [`Registry`] through (and
    /// the same one [`SessionMux::open`] checks). That is what makes the window
    /// *close* rather than narrow: either the flag is already `None` and this
    /// fails loud per every caller's `# Errors` contract, or the frame is
    /// enqueued while the connection is still open. Observing only `write_tx` —
    /// which dies one transport failure LATER — returned `Ok(())` for a no-op
    /// write across that whole window (§17, Open gaps and future capabilities).
    fn send(&self, msg: Message) -> Result<()> {
        // Encode + `MAX_FRAME_BYTES`-check BEFORE the lock: an over-cap frame is
        // a caller error, not a connection state, and it must not hold the lock
        // the reader delivers guest output through.
        let frame = encode_frame(&msg)?;
        let closed_flag = self.registry.lock().unwrap_or_else(|e| e.into_inner());
        if closed_flag.is_none() {
            return Err(Error::Steward("session connection is closed".into()));
        }
        self.write_tx
            .send(frame)
            .map_err(|_| Error::Steward("session connection is closed".into()))
    }

    /// Receives the next session event, or `None` once the terminal
    /// [`SessionEvent::Exit`] has been delivered or the connection closed.
    pub async fn recv(&mut self) -> Option<SessionEvent> {
        if self.exited {
            return None;
        }
        let ev = self.event_rx.recv().await;
        if matches!(ev, None | Some(SessionEvent::Exit(_))) {
            self.exited = true;
        }
        ev
    }

    /// Drains the session to its exit, collecting output into an [`ExecOutcome`]
    /// (a convenience for non-interactive use; a PTY session's merged output lands
    /// in `stdout`). The exit code defaults to `-1` if the stream ends without an
    /// `Exit` (the connection dropped mid-session).
    pub async fn wait(&mut self) -> ExecOutcome {
        let mut outcome = ExecOutcome::default();
        while let Some(ev) = self.recv().await {
            match ev {
                SessionEvent::Stdout(d) => outcome.stdout.extend(d),
                SessionEvent::Stderr(d) => outcome.stderr.extend(d),
                SessionEvent::Exit(code) => {
                    outcome.code = code;
                    break;
                }
            }
        }
        outcome
    }
}

/// Delivers a demuxed event to its session's channel, dropping (at debug) a frame
/// for an unknown/closed session — e.g. a stray frame after `SessionExit` (§13, Cross-cutting invariants).
fn deliver(registry: &Registry, session: SessionId, ev: SessionEvent) {
    let reg = registry.lock().unwrap_or_else(|e| e.into_inner());
    // A closed registry (`None`, M5) routes nowhere — the same debug-drop as an
    // unknown session, never a panic: only the reader task delivers, and it does
    // so strictly before its own terminal close, so this arm is belt-and-braces.
    if let Some(tx) = reg.as_ref().and_then(|sessions| sessions.get(&session)) {
        // The session's own event channel. A send fails only when the `Session` handle was
        // dropped while a frame was still in flight — the else-arm below already debug-drops the
        // same class for an unknown/closed session, and this is that case one instant later.
        #[expect(
            clippy::let_underscore_must_use,
            reason = "the Session handle was dropped mid-flight; the else-arm below debug-drops the identical class"
        )]
        let _ = tx.send(ev);
    } else {
        tracing::debug!(
            "session frame for unknown/closed session {:?}; dropping",
            session
        );
    }
}

/// The background reader task: decodes each guest→host frame and routes it to the
/// matching session, removing a session's channel on its terminal `SessionExit`.
async fn reader_task(mut stream: SplitStream<FramedStream>, registry: Registry) {
    while let Some(frame) = stream.next().await {
        let bytes = match frame {
            Ok(b) => b,
            Err(e) => {
                tracing::debug!("session reader transport ended: {}", e);
                break;
            }
        };
        let msg: Message = match postcard::from_bytes(&bytes) {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!("session reader decode error: {}; closing", e);
                break;
            }
        };
        match msg {
            Message::SessionStdout { session, data } => {
                deliver(&registry, session, SessionEvent::Stdout(data));
            }
            Message::SessionStderr { session, data } => {
                deliver(&registry, session, SessionEvent::Stderr(data));
            }
            Message::SessionExit { session, code } => {
                deliver(&registry, session, SessionEvent::Exit(code));
                if let Some(sessions) = registry.lock().unwrap_or_else(|e| e.into_inner()).as_mut()
                {
                    sessions.remove(&session);
                }
            }
            // A late `Ready` (shouldn't occur — the handshake consumed the first)
            // is ignored; any other frame is a host→guest control frame the guest
            // should never send, so log it (a protocol desync) and keep going.
            // docs/78 §6: the frame is guest-chosen and `MAX_FRAME_BYTES` (16 MiB)
            // big, so the render goes through the shared `capped_debug`; the wire
            // length beside it is the number a desync report actually needs, and it
            // is free here (the frame is still in hand).
            Message::Ready => {}
            other => tracing::warn!(
                "session reader: unexpected guest frame ({} byte frame): {}",
                bytes.len(),
                capped_debug(&other)
            ),
        }
    }
    // The connection ended: CLOSE the registry (M5) — one critical section that
    // takes it to `None`. Dropping the map drops every session sender, so pending
    // `recv()`s wake with `None` rather than hanging, AND the `None` is what a
    // later `open()` sees, so it fails loud instead of handing back a session no
    // frame can ever reach. A `clear()` did only the first half. The senders drop
    // outside the lock, so a waking `recv()` never contends with the guard.
    let closed = registry.lock().unwrap_or_else(|e| e.into_inner()).take();
    drop(closed);
}

/// The background writer task: serializes every host→guest frame onto the one
/// sink (the host single-writer law, §13, Cross-cutting invariants).
async fn writer_task(mut sink: FrameSink, mut rx: mpsc::UnboundedReceiver<::bytes::Bytes>) {
    // Frames are already encoded and `MAX_FRAME_BYTES`-checked at the boundary
    // (`encode_frame`), so this task is a pure sink: the only failure is a genuine
    // transport EOF, which ends the loop.
    while let Some(frame) = rx.recv().await {
        if let Err(e) = sink.send(frame).await {
            tracing::debug!("session writer transport ended: {}", e);
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn codec() -> LengthDelimitedCodec {
        let mut c = LengthDelimitedCodec::new();
        c.set_max_frame_length(vmcell_protocol::MAX_FRAME_BYTES);
        c
    }

    // §13 (Cross-cutting invariants) / §3.3 (Interactive-session wire semantics): the multiplexing demux. Two sessions over one connection;
    // the guest (here a hand-driven UnixStream peer) emits INTERLEAVED, id-keyed
    // frames plus a STRAY frame after a session's SessionExit. Each `Session`
    // handle must receive exactly and only its own frames, in order, ending at its
    // Exit; the post-exit stray must be dropped. RED on a demux that ignores the
    // id (cross-delivery) or delivers after exit. KVM-free (UnixStream::pair).
    #[tokio::test]
    async fn demux_routes_interleaved_frames_per_session_and_drops_post_exit() {
        let (client_io, server_io) = UnixStream::pair().expect("unix pair");
        let mux = SessionMux::from_framed(Framed::new(ControlStream::Unix(client_io), codec()));
        let mut guest = Framed::new(server_io, codec());

        // Open two sessions; the guest peer sees OpenSession{0}, OpenSession{1}.
        let mut s0 = mux
            .open(SessionSpec::new(ExecRequest::new(vec!["a".into()])))
            .await
            .expect("open s0");
        let mut s1 = mux
            .open(SessionSpec::new(ExecRequest::new(vec!["b".into()])))
            .await
            .expect("open s1");
        assert_eq!(s0.id(), SessionId(0));
        assert_eq!(s1.id(), SessionId(1));
        for expect in [SessionId(0), SessionId(1)] {
            let frame = guest.next().await.expect("open frame").expect("io");
            match postcard::from_bytes::<Message>(&frame).expect("decode") {
                Message::OpenSession { session, .. } => assert_eq!(session, expect),
                other => panic!("expected OpenSession, got {other:?}"),
            }
        }

        // Interleave output for both sessions, a terminal exit for each, and a
        // stray frame for session 0 AFTER its exit.
        let script = [
            Message::SessionStdout {
                session: SessionId(0),
                data: b"a1".to_vec(),
            },
            Message::SessionStdout {
                session: SessionId(1),
                data: b"b1".to_vec(),
            },
            Message::SessionStderr {
                session: SessionId(1),
                data: b"b-err".to_vec(),
            },
            Message::SessionStdout {
                session: SessionId(0),
                data: b"a2".to_vec(),
            },
            Message::SessionExit {
                session: SessionId(0),
                code: 7,
            },
            Message::SessionStdout {
                session: SessionId(0),
                data: b"LATE".to_vec(),
            },
            Message::SessionStdout {
                session: SessionId(1),
                data: b"b2".to_vec(),
            },
            Message::SessionExit {
                session: SessionId(1),
                code: 0,
            },
        ];
        for msg in script {
            let bytes = postcard::to_stdvec(&msg).expect("encode");
            guest
                .send(::bytes::Bytes::from(bytes))
                .await
                .expect("guest send");
        }

        // Session 0: only its own frames, ending at Exit(7); the stray "LATE" after
        // exit is never delivered.
        assert_eq!(s0.recv().await, Some(SessionEvent::Stdout(b"a1".to_vec())));
        assert_eq!(s0.recv().await, Some(SessionEvent::Stdout(b"a2".to_vec())));
        assert_eq!(s0.recv().await, Some(SessionEvent::Exit(7)));
        assert_eq!(s0.recv().await, None, "no frame is delivered after Exit");

        // Session 1: its own stdout/stderr, ending at Exit(0). No "a"/"LATE" bytes.
        assert_eq!(s1.recv().await, Some(SessionEvent::Stdout(b"b1".to_vec())));
        assert_eq!(
            s1.recv().await,
            Some(SessionEvent::Stderr(b"b-err".to_vec()))
        );
        assert_eq!(s1.recv().await, Some(SessionEvent::Stdout(b"b2".to_vec())));
        assert_eq!(s1.recv().await, Some(SessionEvent::Exit(0)));
        assert_eq!(s1.recv().await, None);
    }

    // docs/78 §6 (`uncapped-frame-debug-renders`), the session-reader half. The
    // renderer is pinned where the law lives (`vmcell_protocol::capped_debug`, beside
    // `MAX_FRAME_BYTES`); what this pins is that THIS SITE routes through it — the
    // pre-fix line was a bare `{:?}` on a guest-chosen frame.
    //
    // The reader runs ON THIS THREAD (not through `from_framed`'s `tokio::spawn`), so
    // its warn is emitted inside the test's tracing span and `logs_assert` sees it;
    // the peer's write + close is queued first, so the task runs to EOF and returns.
    // RED on the inverse (restore `"… unexpected guest frame {:?}", other`): the line
    // grows to ~100 KB of `[7, 7, …]` decimal and the length bound fails; RED too on
    // a site that drops the frame length or the truncation marker.
    #[tokio::test]
    #[tracing_test::traced_test]
    async fn unexpected_guest_frame_is_logged_capped_not_frame_sized() {
        let (client_io, server_io) = UnixStream::pair().expect("unix pair");
        let mut guest = Framed::new(server_io, codec());

        // `Stdin` is host→guest only: a guest that sends one is the desync this arm
        // reports. 32 KiB of payload renders to ~100 KB of decimal `Debug`.
        let stray = Message::Stdin {
            session: SessionId(0),
            data: vec![7u8; 32 * 1024],
        };
        let stray_bytes = postcard::to_stdvec(&stray).expect("encode the stray frame");
        let stray_len = stray_bytes.len();
        guest
            .send(::bytes::Bytes::from(stray_bytes))
            .await
            .expect("guest send");
        drop(guest);

        let (_sink, stream) = Framed::new(ControlStream::Unix(client_io), codec()).split();
        let registry: Registry = Arc::new(Mutex::new(Some(HashMap::new())));
        reader_task(stream, registry).await;

        logs_assert(|lines: &[&str]| {
            let line = lines
                .iter()
                .find(|l| l.contains("unexpected guest frame"))
                .ok_or_else(|| "the desync warn is missing entirely".to_string())?;
            if line.len() > 1024 {
                return Err(format!(
                    "the desync log line is frame-sized ({} bytes): {}",
                    line.len(),
                    line.chars().take(200).collect::<String>()
                ));
            }
            if !line.contains(vmcell_protocol::DEBUG_TRUNCATED_MARKER) {
                return Err(format!("a truncated render must say so: {line}"));
            }
            if !line.contains(&format!("{stray_len} byte frame")) {
                return Err(format!("the line must quote the frame's wire size: {line}"));
            }
            Ok(())
        });
    }

    // The `wait()` convenience drains to Exit, collecting output. RED if wait
    // stops early or misattributes streams.
    #[tokio::test]
    async fn wait_collects_output_until_exit() {
        let (client_io, server_io) = UnixStream::pair().expect("unix pair");
        let mux = SessionMux::from_framed(Framed::new(ControlStream::Unix(client_io), codec()));
        let mut guest = Framed::new(server_io, codec());

        let mut s = mux
            .open(SessionSpec::new(ExecRequest::new(vec!["c".into()])))
            .await
            .expect("open");
        let _ = guest.next().await.expect("open frame").expect("io");

        for msg in [
            Message::SessionStdout {
                session: SessionId(0),
                data: b"hello ".to_vec(),
            },
            Message::SessionStdout {
                session: SessionId(0),
                data: b"world".to_vec(),
            },
            Message::SessionExit {
                session: SessionId(0),
                code: 3,
            },
        ] {
            let bytes = postcard::to_stdvec(&msg).expect("encode");
            guest.send(::bytes::Bytes::from(bytes)).await.expect("send");
        }

        let outcome = s.wait().await;
        assert_eq!(outcome.code, 3);
        assert_eq!(outcome.stdout, b"hello world");
        assert!(outcome.stderr.is_empty());
    }

    // M1 / M5d: an over-cap host→guest write must fail loud at the Session boundary
    // (typed Error::Steward, matching the `# Errors` doc) and MUST NOT wedge the mux
    // writer for other sessions. RED on the pre-fix code: the over-cap write returns
    // Ok(()) (first assert fails) and the writer task dies on the encode-cap error in
    // sink.send, so session 1's follow-up frame never reaches the guest peer (the
    // `guest.next()` below times out). KVM-free (UnixStream::pair). Contrast the
    // one-shot accept-below-cap gate host_codec_accepts_frame_above_default_8mib.
    #[tokio::test]
    async fn oversize_write_stdin_fails_loud_and_does_not_wedge_mux() {
        let (client_io, server_io) = UnixStream::pair().expect("unix pair");
        let mux = SessionMux::from_framed(Framed::new(ControlStream::Unix(client_io), codec()));
        let mut guest = Framed::new(server_io, codec());

        let s0 = mux
            .open(SessionSpec::new(ExecRequest::new(vec!["a".into()])))
            .await
            .expect("open s0");
        let s1 = mux
            .open(SessionSpec::new(ExecRequest::new(vec!["b".into()])))
            .await
            .expect("open s1");
        // Drain the two OpenSession frames the guest peer sees.
        for _ in 0..2 {
            let _ = guest.next().await.expect("open frame").expect("io");
        }

        // An encoded Message::Stdin whose data is MAX_FRAME_BYTES bytes exceeds the
        // cap once postcard adds its variant/id/length overhead: must fail loud.
        let oversize = vec![0u8; vmcell_protocol::MAX_FRAME_BYTES];
        let err = s0
            .write_stdin(&oversize)
            .await
            .expect_err("an over-cap write_stdin must fail loud, not return Ok(())");
        assert!(
            matches!(err, Error::Steward(_)),
            "over-cap write must surface as Error::Steward (matching the `# Errors` doc); got {err:?}"
        );

        // The writer task must still be alive: a small write on ANOTHER session
        // reaches the guest peer. Pre-fix, the writer died on the over-cap frame, so
        // this frame never arrives and the `next()` below times out.
        s1.write_stdin(b"ping")
            .await
            .expect("a small write after an over-cap write must still succeed");
        let frame = tokio::time::timeout(std::time::Duration::from_secs(5), guest.next())
            .await
            .expect("the mux writer must not be wedged by the earlier over-cap write")
            .expect("a frame")
            .expect("io");
        match postcard::from_bytes::<Message>(&frame).expect("decode") {
            Message::Stdin { session, data } => {
                assert_eq!(session, SessionId(1));
                assert_eq!(data, b"ping".to_vec());
            }
            other => panic!("expected Stdin for session 1, got {other:?}"),
        }
    }

    // session-open-orphan: a mid-open failure (here an over-cap OpenSession spec,
    // the reachable failure once encode happens at the boundary) must leave ZERO
    // registry residue. RED on the pre-fix open (insert-before-any-check, no
    // cleanup): the id-0 entry survives the failed open, so registry_len() == 1.
    #[tokio::test]
    async fn open_failure_leaves_no_registry_orphan() {
        let (client_io, _server_io) = UnixStream::pair().expect("unix pair");
        let mux = SessionMux::from_framed(Framed::new(ControlStream::Unix(client_io), codec()));
        assert_eq!(mux.registry_len(), 0);

        // An argv large enough that the encoded OpenSession exceeds MAX_FRAME_BYTES.
        let big = String::from_utf8(vec![b'x'; vmcell_protocol::MAX_FRAME_BYTES]).unwrap();
        let err = mux
            .open(SessionSpec::new(ExecRequest::new(vec![big])))
            .await
            .expect_err("an over-cap OpenSession must fail loud");
        assert!(matches!(err, Error::Steward(_)), "got {err:?}");
        assert_eq!(
            mux.registry_len(),
            0,
            "a failed open must leave no orphaned registry entry"
        );
    }

    /// M5 shared leg: `open()` on a mux whose reader has ended must fail loud with
    /// the documented `Error::Steward`, promptly (the timeout turns a regression into
    /// a RED test rather than a hung one) and with zero registry residue.
    async fn assert_open_refused(mux: &SessionMux, what: &str) {
        let err = tokio::time::timeout(
            Duration::from_secs(5),
            mux.open(SessionSpec::new(ExecRequest::new(vec!["a".into()]))),
        )
        .await
        .expect("open must return promptly once the connection is closed")
        .expect_err("open after the reader exited must fail loud, not hand back a hung session");
        assert!(
            matches!(err, Error::Steward(_)),
            "open after {what} must be Error::Steward (the `# Errors` contract); got {err:?}"
        );
        assert_eq!(
            mux.registry_len(),
            0,
            "a refused open must leave no registry entry"
        );
    }

    // M5 (`sessionmux-open-after-reader-exit-hangs`), reader-exit path 1 — PEER
    // CLOSE: after transport EOF, `open()` must fail loud, and a session opened
    // BEFORE the close must wake from `recv()` with `None` instead of pending
    // forever. RED on the pre-fix pair (reader terminal step `clear()`s instead of
    // closing the registry; `open` inserts unconditionally): the writer task is
    // still alive, so the `OpenSession` enqueues, `open` returns Ok, and the
    // `expect_err` fires. KVM-free (UnixStream::pair).
    #[tokio::test]
    async fn open_after_peer_close_fails_loud_and_pending_recv_wakes() {
        let (client_io, server_io) = UnixStream::pair().expect("unix pair");
        let mut mux = SessionMux::from_framed(Framed::new(ControlStream::Unix(client_io), codec()));
        let mut guest = Framed::new(server_io, codec());
        let mut early = mux
            .open(SessionSpec::new(ExecRequest::new(vec!["early".into()])))
            .await
            .expect("open while live");
        // Drain the `OpenSession` frame BEFORE closing, so the writer task has
        // flushed it and is parked on its channel — alive at the moment of the
        // refused `open` below. That is the state the M5 hang needs (the writer
        // dies only on its NEXT transport failure); closing with a frame still
        // in flight would kill the writer too and make this gate pass vacuously
        // through `open`'s send-failure branch.
        let _ = guest.next().await.expect("open frame").expect("io");
        drop(guest);
        mux.await_reader_for_test().await;
        assert!(
            !mux.write_tx.is_closed(),
            "the writer must still be alive — the M5 hang needs a live writer to enqueue into"
        );
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(5), early.recv())
                .await
                .expect("a pending recv must wake when the connection closes"),
            None,
            "a session live at connection close ends its stream, it does not hang"
        );
        assert_open_refused(&mux, "peer close").await;
    }

    // M5, reader-exit path 2 — DECODE DESYNC: a garbage frame breaks the reader out
    // of its loop while the WRITER task is untouched and still alive, which is
    // exactly why the pre-fix `open` happily enqueued a frame into an abandoned
    // registry and left `recv()`/`wait()` pending forever. RED on the same inverse
    // as the peer-close leg. KVM-free.
    #[tokio::test]
    async fn open_after_decode_desync_fails_loud() {
        let (client_io, server_io) = UnixStream::pair().expect("unix pair");
        let mut mux = SessionMux::from_framed(Framed::new(ControlStream::Unix(client_io), codec()));
        let mut guest = Framed::new(server_io, codec());
        // An unterminated postcard varint: never a decodable `Message`.
        guest
            .send(::bytes::Bytes::from_static(&[0xFF, 0xFF, 0xFF, 0xFF]))
            .await
            .expect("guest send");
        mux.await_reader_for_test().await;
        assert!(
            !mux.write_tx.is_closed(),
            "the writer must still be alive — the M5 hang needs a live writer to enqueue into"
        );
        assert_open_refused(&mux, "a decode desync").await;
    }

    // session-open-orphan (send-failure branch): when the WRITER channel is closed
    // (the writer task died), `open` inserts the registry entry, the send fails, and
    // the entry must be removed before returning Err — zero residue. Uses a small
    // in-cap spec so encode_frame succeeds and control reaches the send() branch
    // (the over-cap test above stops at encode, before the insert). RED on the
    // inverse (delete the remove-on-send-failure block): registry_len() == 1.
    #[tokio::test]
    async fn open_send_failure_leaves_no_registry_orphan() {
        let (client_io, _server_io) = UnixStream::pair().expect("unix pair");
        let mut mux = SessionMux::from_framed(Framed::new(ControlStream::Unix(client_io), codec()));
        // Kill the writer so write_tx.send() fails deterministically.
        mux.kill_writer_for_test().await;
        assert_eq!(mux.registry_len(), 0);

        let err = mux
            .open(SessionSpec::new(ExecRequest::new(vec!["a".into()])))
            .await
            .expect_err("open must fail once the writer channel is closed");
        assert!(matches!(err, Error::Steward(_)), "got {err:?}");
        assert_eq!(
            mux.registry_len(),
            0,
            "a failed send must remove the just-inserted entry (no orphan)"
        );
    }

    /// §17 (Open gaps and future capabilities) shared setup for the closed-flag legs: a mux whose
    /// reader task has ended (peer close) while its WRITER TASK IS STILL ALIVE, plus
    /// one `Session` opened before that close.
    ///
    /// The live writer is the whole reason each leg is non-vacuous. Pre-fix, the
    /// four mutators observed only `write_tx`, which dies one transport failure
    /// LATER: the frame enqueued into a channel nothing would ever drain and the
    /// method returned `Ok(())`. The `OpenSession` frame is drained by the peer
    /// BEFORE the close so the writer is parked on its channel rather than
    /// failing on an in-flight frame — otherwise the legs would pass through the
    /// pre-existing send-failure branch and prove nothing.
    async fn session_on_closed_connection() -> (SessionMux, Session) {
        let (client_io, server_io) = UnixStream::pair().expect("unix pair");
        let mut mux = SessionMux::from_framed(Framed::new(ControlStream::Unix(client_io), codec()));
        let mut guest = Framed::new(server_io, codec());
        let session = mux
            .open(SessionSpec::new(ExecRequest::new(vec!["a".into()])))
            .await
            .expect("open while live");
        let _ = guest.next().await.expect("open frame").expect("io");
        drop(guest);
        mux.await_reader_for_test().await;
        assert!(
            !mux.write_tx.is_closed(),
            "the writer must still be alive — a closed writer channel would make every leg vacuous"
        );
        (mux, session)
    }

    // §17 (Open gaps and future capabilities), closed-flag leg 1 of 4 — `write_stdin`. Each mutator
    // gets its OWN leg with its OWN fresh connection: sharing one would let the
    // first call kill the writer and leave legs 2..4 passing through the
    // send-failure branch — a flag set before the method has bound anything.
    // RED on the inverse (drop the `closed_flag.is_none()` check in `Session::send`):
    // the enqueue succeeds and `expect_err` fires. KVM-free (UnixStream::pair).
    #[tokio::test]
    async fn write_stdin_after_registry_close_fails_loud() {
        let (mux, s) = session_on_closed_connection().await;
        let err = s
            .write_stdin(b"ping")
            .await
            .expect_err("write_stdin on a closed connection must fail loud, not return Ok(())");
        assert!(
            matches!(err, Error::Steward(_)),
            "the `# Errors` contract promises Error::Steward; got {err:?}"
        );
        assert!(
            !mux.write_tx.is_closed(),
            "the refusal came from the flag, not a dead writer"
        );
    }

    // §17 (Open gaps and future capabilities), closed-flag leg 2 of 4 — `close_stdin`. Same inverse.
    #[tokio::test]
    async fn close_stdin_after_registry_close_fails_loud() {
        let (mux, s) = session_on_closed_connection().await;
        let err = s
            .close_stdin()
            .await
            .expect_err("close_stdin on a closed connection must fail loud, not return Ok(())");
        assert!(
            matches!(err, Error::Steward(_)),
            "the `# Errors` contract promises Error::Steward; got {err:?}"
        );
        assert!(
            !mux.write_tx.is_closed(),
            "the refusal came from the flag, not a dead writer"
        );
    }

    // §17 (Open gaps and future capabilities), closed-flag leg 3 of 4 — `resize`. Same inverse.
    #[tokio::test]
    async fn resize_after_registry_close_fails_loud() {
        let (mux, s) = session_on_closed_connection().await;
        let err = s
            .resize(24, 80)
            .await
            .expect_err("resize on a closed connection must fail loud, not return Ok(())");
        assert!(
            matches!(err, Error::Steward(_)),
            "the `# Errors` contract promises Error::Steward; got {err:?}"
        );
        assert!(
            !mux.write_tx.is_closed(),
            "the refusal came from the flag, not a dead writer"
        );
    }

    // §17 (Open gaps and future capabilities), closed-flag leg 4 of 4 — `close`. Same inverse.
    #[tokio::test]
    async fn close_after_registry_close_fails_loud() {
        let (mux, s) = session_on_closed_connection().await;
        let err = s
            .close()
            .await
            .expect_err("close on a closed connection must fail loud, not return Ok(())");
        assert!(
            matches!(err, Error::Steward(_)),
            "the `# Errors` contract promises Error::Steward; got {err:?}"
        );
        assert!(
            !mux.write_tx.is_closed(),
            "the refusal came from the flag, not a dead writer"
        );
    }

    // §13 (Cross-cutting invariants), the CALL-SITE half of the closed-flag law: the four legs above
    // pin the predicate, and this pins that every mutator still goes THROUGH it. A
    // fifth mutator (or a "fast path" in an existing one) that touched `write_tx`
    // directly would enqueue without reading the flag and re-open exactly the
    // window §17 (Open gaps and future capabilities) recorded — with all four legs still green, because
    // they only ever drive the four methods that exist today. KVM-free: it reads
    // this file's own source.
    //
    // RED on the inverse: move `self.write_tx.send(frame)` up into `write_stdin`
    // (two occurrences), or add a mutator that sends directly (one occurrence
    // before `fn send`).
    #[test]
    fn every_session_mutator_enqueues_through_the_one_closed_checking_helper() {
        let src = include_str!("session.rs");
        let start = src
            .find("impl Session {")
            .expect("the `impl Session` block must exist");
        let block_len = src[start..]
            .find("\n}\n")
            .expect("the `impl Session` block must be terminated");
        let block = &src[start..start + block_len];
        let send_at = block
            .find("fn send(&self, msg: Message)")
            .expect("`Session::send` is the one enqueue helper");
        let sites: Vec<usize> = block
            .match_indices("self.write_tx")
            .map(|(i, _)| i)
            .collect();
        assert_eq!(
            sites.len(),
            1,
            "`impl Session` must touch `self.write_tx` exactly once — inside `send`, after the \
             closed-flag check; found {} site(s)",
            sites.len()
        );
        assert!(
            sites[0] > send_at,
            "the one `self.write_tx` site must be inside `Session::send`, not in a mutator that \
             would bypass the closed-flag check"
        );
    }

    // The POSITIVE CONTROL for the four legs above: on a LIVE connection the same
    // four mutators return Ok and their frames actually reach the guest peer, in
    // order. Without it, a closed-flag stuck at `closed` (or a `send` that refuses
    // unconditionally) would keep all four legs green while breaking every session.
    // RED on a flag that is set anywhere but the reader's terminal step.
    #[tokio::test]
    async fn session_writes_reach_the_peer_while_the_connection_is_live() {
        let (client_io, server_io) = UnixStream::pair().expect("unix pair");
        let mux = SessionMux::from_framed(Framed::new(ControlStream::Unix(client_io), codec()));
        let mut guest = Framed::new(server_io, codec());
        let s = mux
            .open(SessionSpec::new(ExecRequest::new(vec!["a".into()])))
            .await
            .expect("open while live");
        let _ = guest.next().await.expect("open frame").expect("io");

        s.write_stdin(b"ping")
            .await
            .expect("write_stdin on a live connection");
        s.close_stdin()
            .await
            .expect("close_stdin on a live connection");
        s.resize(24, 80).await.expect("resize on a live connection");
        s.close().await.expect("close on a live connection");

        let id = s.id();
        for expected in [
            Message::Stdin {
                session: id,
                data: b"ping".to_vec(),
            },
            Message::StdinEof { session: id },
            Message::Winsize {
                session: id,
                rows: 24,
                cols: 80,
            },
            Message::CloseSession { session: id },
        ] {
            let frame = tokio::time::timeout(Duration::from_secs(5), guest.next())
                .await
                .expect("a live-connection write must reach the peer")
                .expect("a frame")
                .expect("io");
            assert_eq!(
                postcard::from_bytes::<Message>(&frame).expect("decode"),
                expected
            );
        }
    }
}
