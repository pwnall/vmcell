//! Host-side interactive-session multiplexer (§3, The control plane: vsock, the host clients, and the guest agent).
//!
//! [`SessionMux`] owns its **own** vsock connection to the guest agent — separate
//! from the one-shot [`AgentClient`], so the two never share a
//! stream — and multiplexes many concurrent [`Session`]s over it, each keyed by a
//! [`SessionId`]. It reuses the one [`AgentClient`]
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
use tokio::net::UnixStream;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::codec::{Framed, LengthDelimitedCodec};

use super::AgentClient;
use crate::error::{Error, Result};
use vmcell_protocol::{
    ExecOutcome, ExecRequest, MAX_FRAME_BYTES, Message, PtyConfig, SessionId, SessionSpec,
};

/// Encodes a host→guest frame and enforces the shared `MAX_FRAME_BYTES` cap at
/// the send boundary, the host mirror of the guest agent's `send_framed`
/// encode-side check (§13, Cross-cutting invariants). An over-cap frame fails
/// loud here — before it can reach the writer task, whose codec would otherwise
/// reject it and silently kill host→guest input for every session on the mux.
fn encode_frame(msg: &Message) -> Result<::bytes::Bytes> {
    let bytes = postcard::to_stdvec(msg)?;
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(Error::Agent(format!(
            "session frame exceeds MAX_FRAME_BYTES ({} > {MAX_FRAME_BYTES})",
            bytes.len()
        )));
    }
    Ok(::bytes::Bytes::from(bytes))
}

type FramedStream = Framed<UnixStream, LengthDelimitedCodec>;
type FrameSink = SplitSink<FramedStream, ::bytes::Bytes>;
/// `SessionId` → the sender feeding that session's [`Session::recv`] channel.
type Registry = Arc<Mutex<HashMap<SessionId, mpsc::UnboundedSender<SessionEvent>>>>;

/// An output or terminal event delivered to a [`Session`] (§3, The control plane: vsock, the host clients, and the guest agent).
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

/// A multiplexing connection to the guest agent for interactive sessions
/// (§3, The control plane: vsock, the host clients, and the guest agent). See the [module docs](self).
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
    /// Connects a fresh session-multiplexing connection to the guest agent, using
    /// the same connect/handshake law as [`AgentClient`]
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
        let framed =
            AgentClient::connect_framed(vsock_path, port, timeout, timeouts, serial_log).await?;
        Ok(Self::from_framed(framed))
    }

    /// Wraps an already-connected framed stream: splits it and spawns the reader +
    /// writer tasks. Shared by [`SessionMux::connect`] and the KVM-free demux test.
    fn from_framed(framed: FramedStream) -> Self {
        let (sink, stream) = framed.split();
        let registry: Registry = Arc::new(Mutex::new(HashMap::new()));
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
    /// Returns [`Error::Agent`] if the underlying connection has already closed.
    pub async fn open(&self, spec: SessionSpec) -> Result<Session> {
        let id = SessionId(self.next_id.fetch_add(1, Ordering::Relaxed));
        // Encode + `MAX_FRAME_BYTES`-check BEFORE touching the registry, so an
        // over-cap spec (huge argv/env) fails loud with zero registry residue.
        let frame = encode_frame(&Message::OpenSession { session: id, spec })?;
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        self.registry
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(id, event_tx);
        // Insert-before-send keeps the guest's first output routable; on a send
        // failure remove the entry we just inserted so nothing is orphaned.
        if self.write_tx.send(frame).is_err() {
            self.registry
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&id);
            return Err(Error::Agent("session connection is closed".into()));
        }
        Ok(Session {
            id,
            event_rx,
            write_tx: self.write_tx.clone(),
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
            .len()
    }

    /// Test-only: deterministically kill the writer task so its `write_rx` is
    /// dropped, making a subsequent `write_tx.send` fail. Awaiting the aborted
    /// handle guarantees the task has unwound (and thus dropped the receiver)
    /// before we return, so the send-failure branch of `open`/`send` is reachable
    /// without a race.
    async fn kill_writer_for_test(&mut self) {
        self.writer.abort();
        let old = std::mem::replace(&mut self.writer, tokio::spawn(async {}));
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

/// A handle to one interactive session on a [`SessionMux`] (§3, The control plane: vsock, the host clients, and the guest agent).
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
    /// Returns [`Error::Agent`] if the connection has closed.
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
    /// Returns [`Error::Agent`] if the connection has closed.
    pub async fn close_stdin(&self) -> Result<()> {
        self.send(Message::StdinEof { session: self.id })
    }

    /// Resizes a PTY session's window (`SIGWINCH`); a no-op for a pipe session.
    ///
    /// # Errors
    /// Returns [`Error::Agent`] if the connection has closed.
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
    /// Returns [`Error::Agent`] if the connection has closed.
    pub async fn close(&self) -> Result<()> {
        self.send(Message::CloseSession { session: self.id })
    }

    fn send(&self, msg: Message) -> Result<()> {
        let frame = encode_frame(&msg)?;
        self.write_tx
            .send(frame)
            .map_err(|_| Error::Agent("session connection is closed".into()))
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
    if let Some(tx) = reg.get(&session) {
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
                registry
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .remove(&session);
            }
            // A late `Ready` (shouldn't occur — the handshake consumed the first)
            // is ignored; any other frame is a host→guest control frame the guest
            // should never send, so log it (a protocol desync) and keep going.
            Message::Ready => {}
            other => tracing::warn!("session reader: unexpected guest frame {:?}", other),
        }
    }
    // The connection ended: drop every session sender so pending `recv()`s wake
    // with `None` rather than hanging.
    registry.lock().unwrap_or_else(|e| e.into_inner()).clear();
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
        let mux = SessionMux::from_framed(Framed::new(client_io, codec()));
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

    // The `wait()` convenience drains to Exit, collecting output. RED if wait
    // stops early or misattributes streams.
    #[tokio::test]
    async fn wait_collects_output_until_exit() {
        let (client_io, server_io) = UnixStream::pair().expect("unix pair");
        let mux = SessionMux::from_framed(Framed::new(client_io, codec()));
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
    // (typed Error::Agent, matching the `# Errors` doc) and MUST NOT wedge the mux
    // writer for other sessions. RED on the pre-fix code: the over-cap write returns
    // Ok(()) (first assert fails) and the writer task dies on the encode-cap error in
    // sink.send, so session 1's follow-up frame never reaches the guest peer (the
    // `guest.next()` below times out). KVM-free (UnixStream::pair). Contrast the
    // one-shot accept-below-cap gate host_codec_accepts_frame_above_default_8mib.
    #[tokio::test]
    async fn oversize_write_stdin_fails_loud_and_does_not_wedge_mux() {
        let (client_io, server_io) = UnixStream::pair().expect("unix pair");
        let mux = SessionMux::from_framed(Framed::new(client_io, codec()));
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
            matches!(err, Error::Agent(_)),
            "over-cap write must surface as Error::Agent (matching the `# Errors` doc); got {err:?}"
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
        let mux = SessionMux::from_framed(Framed::new(client_io, codec()));
        assert_eq!(mux.registry_len(), 0);

        // An argv large enough that the encoded OpenSession exceeds MAX_FRAME_BYTES.
        let big = String::from_utf8(vec![b'x'; vmcell_protocol::MAX_FRAME_BYTES]).unwrap();
        let err = mux
            .open(SessionSpec::new(ExecRequest::new(vec![big])))
            .await
            .expect_err("an over-cap OpenSession must fail loud");
        assert!(matches!(err, Error::Agent(_)), "got {err:?}");
        assert_eq!(
            mux.registry_len(),
            0,
            "a failed open must leave no orphaned registry entry"
        );
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
        let mut mux = SessionMux::from_framed(Framed::new(client_io, codec()));
        // Kill the writer so write_tx.send() fails deterministically.
        mux.kill_writer_for_test().await;
        assert_eq!(mux.registry_len(), 0);

        let err = mux
            .open(SessionSpec::new(ExecRequest::new(vec!["a".into()])))
            .await
            .expect_err("open must fail once the writer channel is closed");
        assert!(matches!(err, Error::Agent(_)), "got {err:?}");
        assert_eq!(
            mux.registry_len(),
            0,
            "a failed send must remove the just-inserted entry (no orphan)"
        );
    }
}
