//! Guest agent communication and client implementation (host side).
//!
//! This module provides the host-side `AgentClient` that talks to the guest agent
//! over vsock. The framed wire protocol and the framing bound live in the shared
//! [`vmcell_protocol`] crate; the PID-1 reaper coordination lives in the
//! `vmcell-guest-agent` member crate. Re-exporting the protocol here keeps the
//! public `vmcell::agent::protocol` / `vmcell::{ExecOutcome, ExecRequest}` surface
//! stable across the v15 workspace split (§9.1, Workspace layout).

/// The framed wire protocol shared by the host and the guest agent.
pub use vmcell_protocol as protocol;
pub use vmcell_protocol::{
    ExecOutcome, ExecRequest, MAX_FRAME_BYTES, PtyConfig, SessionId, SessionSpec,
};

/// Host-side interactive-session multiplexer (§3.2, The host side: AgentClient and SessionMux): PTY / pipe sessions,
/// streaming stdin, window resize, and multiplexed concurrent execs over one
/// connection, beside the one-shot [`AgentClient`].
#[cfg(feature = "host-common")]
pub mod session;
#[cfg(feature = "host-common")]
pub use session::{Session, SessionEvent, SessionMux, SessionSpecBuilder};

#[cfg(feature = "host-common")]
use crate::error::{Error, Result};
#[cfg(feature = "host-common")]
use vmcell_protocol::Message;

#[cfg(feature = "host-common")]
use crate::vmm::VsockEndpoint;
#[cfg(feature = "host-common")]
use futures::{SinkExt, StreamExt};
#[cfg(feature = "host-common")]
use std::path::Path;
#[cfg(feature = "host-common")]
use tokio::io::AsyncWriteExt;
#[cfg(feature = "host-common")]
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
#[cfg(feature = "host-common")]
use tokio::net::UnixStream;
#[cfg(feature = "host-common")]
use tokio_util::codec::{Framed, LengthDelimitedCodec};

/// The concrete control-plane byte stream: a host **AF_UNIX** socket (the hybrid
/// `CONNECT`/`OK` transport Cloud Hypervisor, Firecracker, and QEMU's default
/// external `vhost-device-vsock` daemon expose) or a host **AF_VSOCK** socket (a
/// snapshot-eligible QEMU on the in-kernel `vhost-vsock-pci` device, §2.4, QEMU q35 — the fallback and most-proven nester).
///
/// Kept a single concrete enum — rather than genericizing `AgentClient<S>` — so
/// `Framed<ControlStream, LengthDelimitedCodec>` stays **one** type and neither
/// [`AgentClient`] nor [`session::SessionMux`] grows a type parameter that would
/// ripple into every orchestrator signature. `Framed`'s `Sink`/`Stream` impls only
/// need [`AsyncRead`] + [`AsyncWrite`], which this enum forwards to the active arm,
/// so every request/exec path is transparent to the transport.
#[cfg(feature = "host-common")]
#[derive(Debug)]
pub(crate) enum ControlStream {
    /// AF_UNIX transport (hybrid `CONNECT <port>`/`OK` handshake before framing).
    Unix(UnixStream),
    /// AF_VSOCK transport (direct in-kernel vhost-vsock; no prologue before framing).
    Vsock(tokio_vsock::VsockStream),
}

#[cfg(feature = "host-common")]
impl AsyncRead for ControlStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            ControlStream::Unix(s) => std::pin::Pin::new(s).poll_read(cx, buf),
            ControlStream::Vsock(s) => std::pin::Pin::new(s).poll_read(cx, buf),
        }
    }
}

#[cfg(feature = "host-common")]
impl AsyncWrite for ControlStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match self.get_mut() {
            ControlStream::Unix(s) => std::pin::Pin::new(s).poll_write(cx, buf),
            ControlStream::Vsock(s) => std::pin::Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            ControlStream::Unix(s) => std::pin::Pin::new(s).poll_flush(cx),
            ControlStream::Vsock(s) => std::pin::Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            ControlStream::Unix(s) => std::pin::Pin::new(s).poll_shutdown(cx),
            ControlStream::Vsock(s) => std::pin::Pin::new(s).poll_shutdown(cx),
        }
    }
}

// `tokio_vsock::VsockStream` is not auto-`UnwindSafe`/`RefUnwindSafe`, but a transport
// socket carries no panic-observable invariant — no more than tokio's `UnixStream`,
// which *is* both. Asserting them here keeps the public `AgentClient` (and
// `SessionMux`) exactly as unwind-safe as before the AF_VSOCK arm was added, so
// swapping the concrete stream type stays a non-breaking change for downstream callers.
#[cfg(feature = "host-common")]
impl std::panic::UnwindSafe for ControlStream {}
#[cfg(feature = "host-common")]
impl std::panic::RefUnwindSafe for ControlStream {}

/// The hybrid `CONNECT <port>`/`OK` prologue port for `endpoint`, or `None` when the
/// transport needs no prologue.
///
/// AF_UNIX bridges (CH/FC/QEMU's external `vhost-device-vsock` daemon) require the
/// Firecracker-style hybrid handshake before the guest's first frame; the in-kernel
/// AF_VSOCK transport (§2.4, QEMU q35 — the fallback and most-proven nester) has no bridge, so `None` — the guest's first
/// framed message is already `Ready`. One predicate so the two connect paths
/// (one-shot and session mux) can never disagree on which transport handshakes.
#[cfg(feature = "host-common")]
fn hybrid_prologue_port(endpoint: &VsockEndpoint) -> Option<u32> {
    match endpoint {
        VsockEndpoint::Unix { port, .. } => Some(*port),
        VsockEndpoint::Vsock { .. } => None,
    }
}

/// Opens the raw transport socket for `endpoint` — AF_UNIX or AF_VSOCK — wrapping it
/// as a [`ControlStream`]. The single point where the two transports diverge at the
/// socket layer; everything above the returned stream is transport-agnostic.
#[cfg(feature = "host-common")]
async fn connect_control_stream(endpoint: &VsockEndpoint) -> std::io::Result<ControlStream> {
    match endpoint {
        VsockEndpoint::Unix { path, .. } => {
            Ok(ControlStream::Unix(UnixStream::connect(path).await?))
        }
        VsockEndpoint::Vsock { cid, port } => {
            let addr = tokio_vsock::VsockAddr::new(*cid, *port);
            Ok(ControlStream::Vsock(
                tokio_vsock::VsockStream::connect(addr).await?,
            ))
        }
    }
}

/// The per-step outcome of a native post-restore [`AgentClient::resync`]
/// (§8.2, Restore correctness: a restored VM is not a fresh VM).
///
/// Mirrors the guest's `ResyncAck`: `clock_error` is `Some(msg)` iff the
/// mandatory guest clock set failed (the orchestrator treats that as a hard,
/// retryable failure — M-RESTORE-1), and the best-effort `reseed_applied` /
/// `mac_applied` flags report whether the CSPRNG reseed and MAC rotation took
/// effect in the guest.
#[cfg(feature = "host-common")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct ResyncOutcome {
    /// `Some(err)` iff the mandatory guest `CLOCK_REALTIME` set failed.
    pub clock_error: Option<String>,
    /// Whether the best-effort guest CSPRNG reseed applied.
    pub reseed_applied: bool,
    /// Whether the best-effort guest `eth0` MAC rotation applied.
    pub mac_applied: bool,
    /// Whether the best-effort guest `eth0` IPv4 + default-route rotation applied
    /// (H-VMM-1 — the restore/zygote vmid rotation).
    pub ip_applied: bool,
}

#[cfg(feature = "host-common")]
/// A client for communicating with the guest agent over vsock.
#[derive(Debug)]
pub struct AgentClient {
    stream: Framed<ControlStream, LengthDelimitedCodec>,
    /// Set when a request times out or the framed stream desynchronizes
    /// mid-exchange. A desynced stream may still hold a late frame from the
    /// abandoned request, so reusing it would read stale data and silently
    /// return a wrong result. Further requests fail loud until
    /// [`AgentClient::reconnect`] re-establishes the stream.
    desynced: bool,
}

/// How a request closure failed, with respect to whether the framed stream is
/// still safe to reuse.
///
/// [`AgentClient::finish_request`] marks the stream desynced only for a
/// [`RequestFailure::Transport`] (or a timeout); a [`RequestFailure::Clean`]
/// leaves it in sync, so a protocol-complete application failure never forces a
/// spurious reconnect (L-GUEST-1).
#[cfg(feature = "host-common")]
enum RequestFailure {
    /// The exchange completed structurally — one request, one fully received and
    /// decoded response — but the application reported failure (e.g. `put_file`'s
    /// non-zero `Exit`). The stream stays in sync.
    Clean(Error),
    /// A send, decode, or transport failure, or a stream that ended
    /// mid-exchange: a late or partial frame may still be in flight, so the
    /// stream must be marked desynced until a reconnect.
    Transport(Error),
}

#[cfg(feature = "host-common")]
impl AgentClient {
    /// Connects to the guest agent on the specified vsock path and port.
    ///
    /// # Errors
    /// Returns an error if the connection fails or the handshake is unsuccessful.
    ///
    /// # Examples
    /// ```rust
    /// # use vmcell::agent::AgentClient;
    /// # use std::path::Path;
    /// # use std::time::Duration;
    /// # async fn run() {
    /// let serial = vmcell::vmm::RealSerialLog { path: std::path::PathBuf::from("/dev/null") };
    /// let client = AgentClient::connect(Path::new("/tmp/vsock"), 5000, Duration::from_secs(10), &vmcell::config::Timeouts::default(), &serial).await.unwrap();
    /// # }
    /// ```
    pub async fn connect(
        vsock_path: &Path,
        port: u32,
        timeout: std::time::Duration,
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

    /// Connects to the guest agent over an explicit [`VsockEndpoint`] — the
    /// transport-generic entry the orchestrator uses so a snapshot-eligible QEMU on
    /// the AF_VSOCK transport (§2.4, QEMU q35 — the fallback and most-proven nester) is reached the same way as an AF_UNIX
    /// backend. The public [`AgentClient::connect`] is the AF_UNIX convenience
    /// wrapper over this.
    ///
    /// # Errors
    /// As [`AgentClient::connect`].
    pub async fn connect_endpoint(
        endpoint: &VsockEndpoint,
        timeout: std::time::Duration,
        timeouts: &crate::config::Timeouts,
        serial_log: &dyn crate::vmm::SerialLog,
    ) -> Result<Self> {
        let stream = Self::connect_framed(endpoint, timeout, timeouts, serial_log).await?;
        Ok(Self {
            stream,
            desynced: false,
        })
    }

    /// Connects the raw framed control-plane stream, retrying with backoff until
    /// the guest answers `Ready` (the one connect/handshake law, §13, Cross-cutting invariants).
    ///
    /// Split out of [`AgentClient::connect_endpoint`] so the session multiplexer
    /// ([`session::SessionMux`]) opens its own connection through the **same**
    /// handshake with exactly one implementation (AGENTS.md "one law, one
    /// predicate"). The prologue branches on the endpoint: an AF_UNIX endpoint
    /// speaks the fragile hybrid handshake — the byte-by-byte `OK` line (never a
    /// buffered reader, which would swallow the first framed payload) — while an
    /// AF_VSOCK endpoint (a snapshot-eligible QEMU on the in-kernel `vhost-vsock`
    /// transport, §2.4, QEMU q35 — the fallback and most-proven nester) has no bridge and thus no prologue: it connects
    /// and the guest's first frame **is** `Ready`. The framed `Ready` read after the
    /// prologue is identical on both transports.
    ///
    /// # Errors
    /// Returns [`Error::Timeout`] if no `Ready` handshake completes within
    /// `timeout`, or [`Error::Agent`] if a kernel panic is detected in the serial
    /// log while waiting.
    pub(crate) async fn connect_framed(
        endpoint: &VsockEndpoint,
        timeout: std::time::Duration,
        timeouts: &crate::config::Timeouts,
        serial_log: &dyn crate::vmm::SerialLog,
    ) -> Result<Framed<ControlStream, LengthDelimitedCodec>> {
        let deadline = tokio::time::Instant::now() + timeout;
        // Poll floor while the VMM host-side socket is still absent. Kept small
        // because a failed local connect is cheap, so a tighter cadence narrows the
        // gap between "guest became ready" and "host noticed" without busy-spinning
        // (the deadline + panic checks still run every iteration).
        let mut backoff = timeouts.connect_backoff_floor;

        loop {
            if tokio::time::Instant::now() > deadline {
                return Err(Error::Timeout("Agent connection timed out".into()));
            }

            // Watch serial log for kernel panic
            if serial_log.contains_panic() {
                return Err(Error::Agent("Panic detected in serial log".into()));
            }

            let mut stream = match connect_control_stream(endpoint).await {
                Ok(s) => {
                    // The transport socket is up, so we are now in the "guest still
                    // booting / not yet listening" regime, where the right cadence
                    // is a tight fixed poll — not the exponential backoff that only
                    // makes sense while the socket was absent. Reset to the floor so
                    // a few socket-absent iterations can't inflate the guest-ready
                    // detection gap (EXP-HOST-BACKOFF-RESET).
                    backoff = timeouts.connect_backoff_floor;
                    s
                }
                Err(e) => {
                    tracing::trace!("Agent connect control-stream connect failed: {}", e);
                    tokio::time::sleep(backoff).await;
                    backoff = std::cmp::min(backoff * 2, timeouts.connect_backoff_cap);
                    continue;
                }
            };

            // AF_UNIX bridges (CH/FC/QEMU's external `vhost-device-vsock` daemon)
            // speak the Firecracker-style hybrid `CONNECT <port>`/`OK` prologue; the
            // in-kernel AF_VSOCK transport has no bridge, so there is no prologue and
            // the guest's first framed message is already `Ready`.
            if let Some(port) = hybrid_prologue_port(endpoint) {
                let connect_msg = format!("CONNECT {port}\n");
                if let Err(e) = stream.write_all(connect_msg.as_bytes()).await {
                    tracing::trace!("Agent connect write_all failed: {}", e);
                    continue;
                }

                let mut resp = String::new();
                let mut ok = false;
                loop {
                    let mut byte = [0; 1];
                    use tokio::io::AsyncReadExt;
                    if let Ok(Ok(1)) =
                        tokio::time::timeout(timeouts.connect_ok_read, stream.read(&mut byte)).await
                    {
                        resp.push(byte[0] as char);
                        if byte[0] == b'\n' {
                            ok = resp.starts_with("OK ");
                            break;
                        }
                    } else {
                        break;
                    }
                }
                if !ok {
                    tracing::trace!("Agent connect failed! resp was: {:?}", resp);
                    tokio::time::sleep(backoff).await;
                    continue;
                }
            }

            let mut codec = LengthDelimitedCodec::new();
            // Align the host frame cap with the guest's (the codec default is
            // only 8 MiB), so neither side silently drops a frame the other sent.
            codec.set_max_frame_length(MAX_FRAME_BYTES);
            let mut framed = Framed::new(stream, codec);

            let ready_result =
                tokio::time::timeout(std::time::Duration::from_secs(2), framed.next()).await;
            let ready = match ready_result {
                Ok(Some(Ok(bytes))) => bytes,
                other => {
                    tracing::trace!("Agent connect framed.next() returned: {:?}", other);
                    continue;
                }
            };

            let msg: Message = match postcard::from_bytes(&ready) {
                Ok(m) => m,
                Err(e) => {
                    tracing::trace!("Agent connect postcard error: {:?}, bytes: {:?}", e, ready);
                    continue;
                }
            };

            match msg {
                Message::Ready => {
                    return Ok(framed);
                }
                other => {
                    tracing::trace!("Agent connect received unexpected message: {:?}", other);
                    continue;
                }
            }
        }
    }

    /// Builds a client directly over an already-connected stream, bypassing the
    /// CONNECT handshake, for unit tests that only need a `Some(AgentClient)`
    /// to observe cache-invalidation behavior (e.g. `MicroVm::snapshot()`
    /// dropping its cached client). Uses the same codec configuration as
    /// [`AgentClient::connect`] and starts in-sync (`desynced: false`).
    /// `#[cfg(test)]` + `pub(crate)` so no test-only constructor ships in the
    /// public surface.
    #[cfg(test)]
    pub(crate) fn from_stream_for_tests(stream: UnixStream) -> Self {
        let mut codec = LengthDelimitedCodec::new();
        // Mirror `connect`: align the host frame cap with the guest's.
        codec.set_max_frame_length(MAX_FRAME_BYTES);
        Self {
            stream: Framed::new(ControlStream::Unix(stream), codec),
            desynced: false,
        }
    }

    /// Reconnects to the guest agent.
    ///
    /// # Errors
    /// Returns an error if the connection fails or times out.
    ///
    /// Parameter order mirrors [`AgentClient::connect`]
    /// (`vsock_path, port, timeout, timeouts, serial_log`) so the two cannot be
    /// transposed at a call site (N-GUEST-3).
    pub async fn reconnect(
        &mut self,
        vsock_path: &Path,
        port: u32,
        timeout: std::time::Duration,
        timeouts: &crate::config::Timeouts,
        serial_log: &dyn crate::vmm::SerialLog,
    ) -> Result<()> {
        let new_client = Self::connect(vsock_path, port, timeout, timeouts, serial_log).await?;
        self.stream = new_client.stream;
        // A fresh stream is back in sync, so clear any prior desync state.
        self.desynced = false;
        Ok(())
    }

    /// Fails loud if a prior request left the framed stream desynchronized.
    ///
    /// Every request method calls this first so a stale in-flight frame from an
    /// abandoned (timed-out or errored) exchange can never be read as the next
    /// request's response. Recovery is via [`AgentClient::reconnect`].
    fn ensure_synced(&self) -> Result<()> {
        if self.desynced {
            return Err(Error::Agent(
                "agent connection desynchronized by a prior timeout; reconnect required".into(),
            ));
        }
        Ok(())
    }

    /// Resolves a `timeout`-wrapped request result, marking the stream desynced
    /// only when the failure could have left a stale frame in flight.
    ///
    /// The closure reports its failure as a [`RequestFailure`]. A
    /// [`RequestFailure::Transport`] (a send/decode/connection error, or a stream
    /// that ended mid-exchange) or a `timeout` (`Elapsed`) leaves the framed
    /// stream in an unknown state — a late frame may still be in flight — so the
    /// next request must fail loud via [`AgentClient::ensure_synced`] until a
    /// [`AgentClient::reconnect`]. A [`RequestFailure::Clean`] — a
    /// protocol-complete application failure whose full response frame was
    /// received and decoded (e.g. `put_file`'s non-zero `Exit`) — leaves the
    /// stream in sync and does **not** desync it, so a clean per-request failure
    /// never forces a spurious reconnect (L-GUEST-1). Shared by every request
    /// method so none can diverge from this protocol.
    fn finish_request<T>(
        desynced: &mut bool,
        result: std::result::Result<
            std::result::Result<T, RequestFailure>,
            tokio::time::error::Elapsed,
        >,
        timeout_msg: &'static str,
    ) -> Result<T> {
        match result {
            Ok(Ok(value)) => Ok(value),
            // Protocol-complete application failure: the stream is still in sync,
            // so surface the error WITHOUT desyncing (L-GUEST-1).
            Ok(Err(RequestFailure::Clean(e))) => Err(e),
            // Send/decode/transport failure, or a stream that ended mid-exchange:
            // a stale frame may still be in flight, so desync.
            Ok(Err(RequestFailure::Transport(e))) => {
                *desynced = true;
                Err(e)
            }
            Err(_) => {
                *desynced = true;
                Err(Error::Timeout(timeout_msg.into()))
            }
        }
    }

    /// Executes a command inside the guest VM and waits for the result.
    ///
    /// # Errors
    /// Returns an error if the request cannot be sent or the outcome cannot be received.
    pub async fn exec(&mut self, mut cmd: ExecRequest) -> Result<ExecOutcome> {
        self.ensure_synced()?;
        // Propagate the effective timeout into the request so the guest always
        // installs a kill thread. A `None` timeout would let the guest child
        // outlive this abandoned wait and leak.
        let timeout = cmd.timeout.unwrap_or(protocol::DEFAULT_EXEC_TIMEOUT);
        cmd.timeout = Some(timeout);

        let result = tokio::time::timeout(timeout, async {
            let msg = Message::Exec(cmd);
            let bytes =
                postcard::to_stdvec(&msg).map_err(|e| RequestFailure::Transport(e.into()))?;

            self.stream
                .send(::bytes::Bytes::from(bytes))
                .await
                .map_err(|e| RequestFailure::Transport(Error::Io(e)))?;

            let mut outcome = ExecOutcome::default();

            while let Some(res) = self.stream.next().await {
                let bytes: ::bytes::BytesMut =
                    res.map_err(|e| RequestFailure::Transport(Error::Io(e)))?;
                let msg: Message = postcard::from_bytes(&bytes)
                    .map_err(|e| RequestFailure::Transport(e.into()))?;

                match msg {
                    Message::Stdout(data) => {
                        outcome.stdout.extend(data);
                    }
                    Message::Stderr(data) => {
                        outcome.stderr.extend(data);
                    }
                    Message::Exit(code) => {
                        outcome.code = code;
                        return Ok(outcome);
                    }
                    // L-GUEST-10: an unexpected message on the exec stream (a
                    // protocol mismatch or a stray control frame) is surfaced at
                    // `warn`, not silently dropped — a silent `_ => {}` would hide
                    // a desync where the guest and host disagree on the protocol.
                    other => {
                        tracing::warn!("unexpected message on exec stream (ignored): {:?}", other);
                    }
                }
            }

            // Stream ended without Exit: the connection dropped mid-exchange, so
            // the stream is desynced (Transport), not a clean application failure.
            Err(RequestFailure::Transport(Error::Agent(
                "Connection dropped during exec".into(),
            )))
        })
        .await;

        Self::finish_request(&mut self.desynced, result, "Agent exec timed out")
    }

    /// Uploads a file to the guest VM.
    ///
    /// # Errors
    /// Returns an error if the file transfer fails, times out, or the stream is
    /// already desynchronized by a prior request (in which case a
    /// [`AgentClient::reconnect`] is required before further requests). Like
    /// [`AgentClient::exec`], a send/decode error or timeout here marks the
    /// stream desynced so the next request fails loud rather than reading this
    /// exchange's stale frame as its own response.
    pub async fn put_file(
        &mut self,
        dst: &str,
        bytes: &[u8],
        timeout: Option<std::time::Duration>,
    ) -> Result<()> {
        self.ensure_synced()?;
        let timeout = timeout.unwrap_or(std::time::Duration::from_secs(10));
        let result = tokio::time::timeout(timeout, async {
            let msg = Message::PutFile {
                dst: dst.to_string(),
                bytes: bytes.to_vec(),
            };
            let msg_bytes =
                postcard::to_stdvec(&msg).map_err(|e| RequestFailure::Transport(e.into()))?;
            self.stream
                .send(::bytes::Bytes::from(msg_bytes))
                .await
                .map_err(|e| RequestFailure::Transport(Error::Io(e)))?;

            // Wait for ack
            if let Some(res) = self.stream.next().await {
                let res_bytes: ::bytes::BytesMut =
                    res.map_err(|e| RequestFailure::Transport(Error::Io(e)))?;
                let resp_msg: Message = postcard::from_bytes(&res_bytes)
                    .map_err(|e| RequestFailure::Transport(e.into()))?;
                match resp_msg {
                    Message::Exit(0) => Ok(()),
                    // A protocol-complete application failure: the guest ran the
                    // put_file, it failed, and sent a full Exit(c) ack. The stream
                    // is in sync, so report the failure WITHOUT desyncing so the
                    // next request need not force a spurious reconnect (L-GUEST-1).
                    Message::Exit(c) => Err(RequestFailure::Clean(Error::Agent(format!(
                        "put_file failed with code {c}"
                    )))),
                    _ => Err(RequestFailure::Transport(Error::Agent(
                        "unexpected response to put_file".into(),
                    ))),
                }
            } else {
                Err(RequestFailure::Transport(Error::Agent(
                    "connection closed during put_file".into(),
                )))
            }
        })
        .await;

        Self::finish_request(&mut self.desynced, result, "put_file timed out")
    }

    /// Performs the one-shot native post-restore resync (§8.2, Restore correctness: a restored VM is not a fresh VM): sets the
    /// guest clock to the host instant, best-effort reseeds the guest CSPRNG, and
    /// best-effort rotates the guest `eth0` MAC — one request, one ack — replacing
    /// the three post-restore subprocess execs (`date` / `head` / `ip`).
    ///
    /// # Errors
    /// Returns an error if the request cannot be sent, the ack cannot be received
    /// or decoded, the exchange times out, or the stream is already
    /// desynchronized by a prior request (a [`AgentClient::reconnect`] is then
    /// required). Like the other request methods, any send/decode error or timeout
    /// marks the stream desynced so the next request fails loud. Note a
    /// `Some(clock_error)` in the returned [`ResyncOutcome`] is **not** an `Err`
    /// here — the transport succeeded; the caller decides how to treat the
    /// mandatory-clock failure.
    pub async fn resync(
        &mut self,
        unix_secs: u64,
        unix_nanos: u32,
        mac: Option<[u8; 6]>,
        ipv4: Option<protocol::Ipv4Reconfig>,
    ) -> Result<ResyncOutcome> {
        self.ensure_synced()?;
        let result = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            let msg = Message::Resync {
                unix_secs,
                unix_nanos,
                mac,
                ipv4,
            };
            let msg_bytes =
                postcard::to_stdvec(&msg).map_err(|e| RequestFailure::Transport(e.into()))?;
            self.stream
                .send(::bytes::Bytes::from(msg_bytes))
                .await
                .map_err(|e| RequestFailure::Transport(Error::Io(e)))?;

            // Await exactly one ack frame.
            if let Some(res) = self.stream.next().await {
                let res_bytes: ::bytes::BytesMut =
                    res.map_err(|e| RequestFailure::Transport(Error::Io(e)))?;
                let resp_msg: Message = postcard::from_bytes(&res_bytes)
                    .map_err(|e| RequestFailure::Transport(e.into()))?;
                match resp_msg {
                    Message::ResyncAck {
                        clock_error,
                        reseed_applied,
                        mac_applied,
                        ip_applied,
                    } => Ok(ResyncOutcome {
                        clock_error,
                        reseed_applied,
                        mac_applied,
                        ip_applied,
                    }),
                    _ => Err(RequestFailure::Transport(Error::Agent(
                        "unexpected response to resync".into(),
                    ))),
                }
            } else {
                Err(RequestFailure::Transport(Error::Agent(
                    "connection closed during resync".into(),
                )))
            }
        })
        .await;

        Self::finish_request(&mut self.desynced, result, "resync timed out")
    }
}

#[cfg(all(test, feature = "host-common"))]
mod tests {
    use super::{AgentClient, Error, RequestFailure, VsockEndpoint, hybrid_prologue_port};

    // The transport-dispatch law: an AF_UNIX endpoint speaks the hybrid
    // `CONNECT <port>`/`OK` prologue (so `Some(port)`), while the in-kernel AF_VSOCK
    // transport has no bridge and takes the **no-CONNECT** branch (`None`). This is
    // the KVM-free pin that a snapshot-eligible QEMU on AF_VSOCK does not emit a
    // `CONNECT` line the guest's real vsock listener would never consume. RED on the
    // buggy inverse (a Vsock arm returning `Some`, which would hang every AF_VSOCK
    // connect on a handshake the guest never answers).
    #[test]
    fn hybrid_prologue_only_for_af_unix() {
        assert_eq!(
            hybrid_prologue_port(&VsockEndpoint::Unix {
                path: std::path::PathBuf::from("/tmp/vsock.sock"),
                port: 5000,
            }),
            Some(5000),
            "AF_UNIX must speak the hybrid CONNECT/OK handshake",
        );
        assert_eq!(
            hybrid_prologue_port(&VsockEndpoint::Vsock {
                cid: 42,
                port: 5000
            }),
            None,
            "AF_VSOCK must take the no-CONNECT branch (guest's first frame is Ready)",
        );
    }

    // L-GUEST-1: finish_request desyncs only when a stale frame could still be in
    // flight. A `Clean` failure — a protocol-complete application error whose full
    // ack frame was received and decoded (e.g. put_file's non-zero Exit) — leaves
    // the stream in sync, so the next request must NOT be forced through a
    // reconnect. RED on the pre-fix finish_request, which set `desynced` on ANY
    // `Ok(Err(_))`: this test's `assert!(!desynced)` would then fail.
    #[test]
    fn finish_request_clean_failure_does_not_desync() {
        let mut desynced = false;
        let result: std::result::Result<
            std::result::Result<(), RequestFailure>,
            tokio::time::error::Elapsed,
        > = Ok(Err(RequestFailure::Clean(Error::Agent(
            "put_file failed with code 1".into(),
        ))));
        let out = AgentClient::finish_request(&mut desynced, result, "unused");
        assert!(
            out.is_err(),
            "a clean application failure must still surface as an error"
        );
        assert!(
            !desynced,
            "a protocol-complete application failure must NOT desync the stream"
        );
    }

    // The other half of the contract: a `Transport` failure (send/decode/
    // connection loss, or a mid-exchange stream end) still desyncs, so the next
    // request fails loud until a reconnect. RED if the fix over-corrects and stops
    // desyncing on transport errors.
    #[test]
    fn finish_request_transport_failure_desyncs() {
        let mut desynced = false;
        let result: std::result::Result<
            std::result::Result<(), RequestFailure>,
            tokio::time::error::Elapsed,
        > = Ok(Err(RequestFailure::Transport(Error::Io(
            std::io::Error::from(std::io::ErrorKind::BrokenPipe),
        ))));
        let out = AgentClient::finish_request(&mut desynced, result, "unused");
        assert!(out.is_err());
        assert!(
            desynced,
            "a transport failure must desync the stream so the next request fails loud"
        );
    }
}
