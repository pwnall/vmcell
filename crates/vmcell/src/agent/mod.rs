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
use vmcell_protocol::{Message, capped_debug};

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

/// The upper bound on the hybrid prologue's acknowledgement line, in bytes.
///
/// The `OK <port>\n` line a bridge sends is a dozen bytes; the cap exists so a
/// broken or hostile bridge that streams bytes without ever sending a newline
/// cannot grow the accumulator without bound (the same validate-before-allocate
/// discipline `MAX_FRAME_BYTES` applies to the framed plane, §13, Cross-cutting invariants).
#[cfg(feature = "host-common")]
const MAX_PROLOGUE_LINE_BYTES: usize = 256;

/// How the hybrid `CONNECT <port>`/`OK` prologue failed, at the granularity its two
/// callers interpret differently (§3.2, The host side: AgentClient and SessionMux).
///
/// [`AgentClient::connect_framed`] folds every arm into "retry after a backoff" —
/// it exists to outwait a *booting* agent. [`VsockDial`] maps each arm to its own
/// typed, fail-fast error ([`dial_prologue_error`]): a raw dial is issued against a
/// VM the caller already brought up, so "nobody listens on that port" must surface
/// immediately instead of spinning to the deadline.
#[cfg(feature = "host-common")]
#[derive(Debug)]
enum PrologueError {
    /// The `CONNECT <port>` line could not be written to the bridge.
    Write(std::io::Error),
    /// Reading the acknowledgement line failed at the transport level.
    Read(std::io::Error),
    /// The bridge closed the connection before a complete line arrived — the
    /// in-VMM muxer's "no guest listener on that port" signal (CH/FC).
    Eof {
        /// The partial line received before the close (often empty).
        partial: String,
    },
    /// The per-byte read budget (`Timeouts::connect_ok_read`) elapsed with the line
    /// still incomplete — an accepted-and-hung bridge (QEMU's external
    /// `vhost-device-vsock` daemon on a dead port).
    ReadTimeout {
        /// The partial line received before the budget elapsed (often empty).
        partial: String,
    },
    /// A complete line arrived that was not an `OK …` acknowledgement, or a line
    /// that ran past [`MAX_PROLOGUE_LINE_BYTES`] without a newline.
    Refused {
        /// The line the bridge sent (newline included when it sent one).
        line: String,
    },
}

#[cfg(feature = "host-common")]
impl std::fmt::Display for PrologueError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Write(e) => write!(f, "CONNECT line write failed: {e}"),
            Self::Read(e) => write!(f, "OK line read failed: {e}"),
            Self::Eof { partial } => {
                write!(f, "stream closed before an OK line (partial {partial:?})")
            }
            Self::ReadTimeout { partial } => write!(
                f,
                "no OK line within the per-byte read budget (partial {partial:?})"
            ),
            Self::Refused { line } => write!(f, "bridge answered {line:?} instead of an OK line"),
        }
    }
}

/// Speaks the Firecracker-style hybrid `CONNECT <port>`/`OK` prologue on `stream`.
///
/// The **one** implementation of the handshake (§13, Cross-cutting invariants — one law, one
/// predicate): the framed control-plane connect ([`AgentClient::connect_framed`],
/// shared by [`session::SessionMux`]) and the raw dial ([`VsockDial`]) both go
/// through it, so the fragile part of the wire can never exist in two versions.
///
/// The acknowledgement line is read **byte by byte** — never through a buffered
/// reader, which would swallow the first framed payload that follows the newline —
/// and every single-byte read is bounded by `ok_read`, so a bridge that accepts and
/// then hangs is a bounded failure rather than a wedge.
#[cfg(feature = "host-common")]
async fn hybrid_connect_prologue(
    stream: &mut ControlStream,
    port: u32,
    ok_read: std::time::Duration,
) -> std::result::Result<(), PrologueError> {
    let connect_msg = format!("CONNECT {port}\n");
    stream
        .write_all(connect_msg.as_bytes())
        .await
        .map_err(PrologueError::Write)?;

    let mut resp = String::new();
    loop {
        let mut byte = [0; 1];
        use tokio::io::AsyncReadExt;
        match tokio::time::timeout(ok_read, stream.read(&mut byte)).await {
            Err(_elapsed) => return Err(PrologueError::ReadTimeout { partial: resp }),
            Ok(Err(e)) => return Err(PrologueError::Read(e)),
            Ok(Ok(0)) => return Err(PrologueError::Eof { partial: resp }),
            Ok(Ok(_)) => {
                resp.push(byte[0] as char);
                if byte[0] == b'\n' {
                    return if resp.starts_with("OK ") {
                        Ok(())
                    } else {
                        Err(PrologueError::Refused { line: resp })
                    };
                }
                if resp.len() >= MAX_PROLOGUE_LINE_BYTES {
                    return Err(PrologueError::Refused { line: resp });
                }
            }
        }
    }
}

/// The typed, fail-fast interpretation of a failed prologue for the **raw dial**
/// (§3.2, The host side: AgentClient and SessionMux) — the one place the refusal signals are given
/// meaning, so `dial_vsock`'s error contract lives beside the handshake that
/// produces it and is unit-testable without a VM.
///
/// `EOF` before an `OK` line is the in-VMM muxer's dead-port signal (a typed
/// [`Error::Agent`] naming the port); an accepted-and-hung bridge runs out the
/// per-byte budget into a typed [`Error::Timeout`] naming the port; a transport
/// error surfaces as [`Error::Io`], errno intact.
#[cfg(feature = "host-common")]
fn dial_prologue_error(port: u32, ok_read: std::time::Duration, err: PrologueError) -> Error {
    match err {
        PrologueError::Write(e) | PrologueError::Read(e) => Error::Io(e),
        PrologueError::Eof { partial } => Error::Agent(format!(
            "no guest vsock listener on port {port}: the vsock bridge closed the connection \
             without an OK line (received {partial:?})"
        )),
        PrologueError::ReadTimeout { partial } => Error::Timeout(format!(
            "no guest vsock listener answered on port {port}: the vsock bridge accepted the \
             CONNECT and sent no OK line within {ok_read:?} (received {partial:?})"
        )),
        PrologueError::Refused { line } => Error::Agent(format!(
            "guest vsock port {port} refused: the vsock bridge answered {line:?} instead of an \
             OK line"
        )),
    }
}

/// The same [`VsockEndpoint`] with its port replaced by `port`.
///
/// The one place a caller-chosen guest port is spliced into an instance's endpoint
/// (§3.2, The host side: AgentClient and SessionMux), so the raw dial's transport dispatch is exactly
/// [`hybrid_prologue_port`]'s and the AF_VSOCK arm dials the requested port rather
/// than the agent's. Exhaustive on both arms — [`VsockEndpoint`] is deliberately not
/// `#[non_exhaustive]`, so a future transport breaks this at compile time instead of
/// silently keeping the agent port.
#[cfg(feature = "host-common")]
fn endpoint_on_port(endpoint: &VsockEndpoint, port: u32) -> VsockEndpoint {
    match endpoint {
        VsockEndpoint::Unix { path, .. } => VsockEndpoint::Unix {
            path: path.clone(),
            port,
        },
        VsockEndpoint::Vsock { cid, .. } => VsockEndpoint::Vsock { cid: *cid, port },
    }
}

/// A raw byte stream to a guest AF_VSOCK listener (§3.2, The host side: AgentClient and SessionMux — the raw vsock
/// dial): the guest process on the other end owns its own protocol, so there is no
/// framing, no `Ready` handshake, and no guest-agent involvement.
///
/// Obtained from [`MicroVm::dial_vsock`](crate::MicroVm::dial_vsock), or from
/// [`VsockDial::connect_endpoint`] by a caller that already holds the endpoint.
/// Read and write it through [`tokio::io::AsyncReadExt`] /
/// [`tokio::io::AsyncWriteExt`].
///
/// # Half-close is not portable — drain the reply *before* `shutdown()`
///
/// The **guest→host** direction is portable: when the guest half-closes its write
/// side or exits, the host's read returns `0`, on every backend.
///
/// The **host→guest** direction is not. Calling [`shutdown()`](tokio::io::AsyncWriteExt::shutdown)
/// half-closes the host's write side, and whether the guest sees a clean EOF *and
/// can still answer* is a property of the backend's vsock bridge, not of this API.
/// Measured on the live matrix on 2026-08-11 (Cloud Hypervisor 54.0.0, Firecracker
/// 1.16.0, QEMU 10.2.1, crosvm), writing a request, calling `shutdown()`, then
/// draining the guest's echo:
///
/// | backend | host-side transport | reply after the host's `shutdown()` |
/// | --- | --- | --- |
/// | Cloud Hypervisor | in-VMM hybrid muxer over AF_UNIX | arrives — 5/5 |
/// | crosvm | in-kernel AF_VSOCK (no bridge) | arrives — 5/5 |
/// | Firecracker | in-VMM hybrid muxer over AF_UNIX | **discarded** — 0/5 |
/// | QEMU | external `vhost-device-vsock` daemon over AF_UNIX | **races** the teardown — 2/5 |
///
/// On Firecracker and QEMU the host's `SHUT_WR` on the bridge socket is translated
/// into a teardown of the whole vsock connection, so anything the guest had not
/// already put on the wire is lost. **The loss is silent**: the host's next read
/// returns `Ok(0)` — an ordinary clean EOF — not an error, so a caller cannot tell
/// a complete reply from a truncated one after the fact.
///
/// The portable rule, therefore: **treat `shutdown()` as end-of-conversation, never
/// as an in-band "your turn" signal.** Frame the guest protocol so the host knows
/// when a reply is complete without needing the EOF — a length prefix, a delimiter,
/// or a fixed size — read the reply to completion, and only then half-close or drop
/// the handle. That order works identically on all four backends. A caller that
/// truly needs half-close-as-signal is choosing Cloud Hypervisor or crosvm, and
/// should say so; vmcell does not advertise the difference as a capability flag
/// (see `docs/implementation-notes.md`, the delta-7 record) precisely because the
/// drain-first order removes the need to branch on it.
///
/// A public newtype over the crate's transport enum rather than a public enum: the
/// two-arm `ControlStream` stays `pub(crate)` and non-generic, so adding a transport
/// is not a breaking change for a downstream holding this handle. It is
/// [`std::panic::UnwindSafe`] and [`std::panic::RefUnwindSafe`] for the same reason
/// the inner stream is — a transport socket carries no panic-observable invariant —
/// which a plain newtype (no interior mutability) inherits automatically.
#[cfg(feature = "host-common")]
#[derive(Debug)]
pub struct VsockDial(ControlStream);

#[cfg(feature = "host-common")]
impl VsockDial {
    /// Dials a raw byte stream to `port` over `endpoint`'s transport.
    ///
    /// `endpoint` is the VM instance's own endpoint (its AF_UNIX bridge path or its
    /// AF_VSOCK CID); `port` replaces the endpoint's own port, so the same call
    /// reaches an arbitrary guest listener on either transport. On an AF_UNIX
    /// bridge the hybrid `CONNECT <port>`/`OK` prologue runs first — the very same
    /// handshake implementation the framed control-plane connect uses; on the
    /// in-kernel AF_VSOCK transport there is no bridge and thus no prologue.
    ///
    /// Unlike [`AgentClient::connect_endpoint`] this does **not** retry: that retry
    /// loop exists to outwait a booting agent and folds "nobody listens" into a
    /// terminal timeout, whereas a dial is issued against a VM the caller already
    /// brought up. Refusal signals are interpreted and returned fast and typed.
    ///
    /// # Errors
    /// - [`Error::Agent`] naming the port when the vsock bridge closes the
    ///   connection without an `OK` line (the CH/FC in-VMM muxer's dead-port
    ///   signal) or answers something other than `OK`.
    /// - [`Error::Timeout`] naming the port when the bridge accepts the `CONNECT`
    ///   and never answers (QEMU's external daemon on a dead port), bounded by
    ///   `timeouts.connect_ok_read`, or when the whole dial exceeds `timeout`.
    /// - [`Error::Io`] when the transport socket cannot be opened — including the
    ///   kernel's own AF_VSOCK connect error (`ECONNRESET` for a port with no guest
    ///   listener), errno intact.
    pub async fn connect_endpoint(
        endpoint: &VsockEndpoint,
        port: u32,
        timeout: std::time::Duration,
        timeouts: &crate::config::Timeouts,
    ) -> Result<Self> {
        let endpoint = endpoint_on_port(endpoint, port);
        let dial = async {
            let mut stream = connect_control_stream(&endpoint).await.map_err(|e| {
                tracing::trace!("vsock dial to port {port} could not open the transport: {e}");
                Error::Io(e)
            })?;
            if let Some(prologue_port) = hybrid_prologue_port(&endpoint) {
                hybrid_connect_prologue(&mut stream, prologue_port, timeouts.connect_ok_read)
                    .await
                    .map_err(|e| {
                        tracing::trace!("vsock dial prologue on port {prologue_port} failed: {e}");
                        dial_prologue_error(prologue_port, timeouts.connect_ok_read, e)
                    })?;
            }
            Ok(Self(stream))
        };
        match tokio::time::timeout(timeout, dial).await {
            Ok(res) => res,
            Err(_elapsed) => Err(Error::Timeout(format!(
                "raw vsock dial to guest port {port} did not complete within {timeout:?}"
            ))),
        }
    }
}

#[cfg(feature = "host-common")]
impl AsyncRead for VsockDial {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
    }
}

#[cfg(feature = "host-common")]
impl AsyncWrite for VsockDial {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.get_mut().0).poll_write(cx, buf)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().0).poll_flush(cx)
    }

    /// Half-closes the host's write side.
    ///
    /// What the *guest* observes is backend-dependent, and on two of the four
    /// backends this discards a reply the guest had not yet flushed — see the
    /// half-close table on [`VsockDial`] before using it as an in-band signal.
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
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

/// Why one [`AgentClient::connect_framed_once`] attempt failed, and therefore how
/// the retry loop paces the next one.
///
/// Only [`ConnectAttemptError::Socket`] — the VMM's host-side socket still absent —
/// grows the backoff; every other arm means the socket was up, so the loop resets to
/// the tight poll floor (EXP-HOST-BACKOFF-RESET).
#[cfg(feature = "host-common")]
enum ConnectAttemptError {
    /// The transport socket itself could not be opened.
    Socket(std::io::Error),
    /// The socket was up but the hybrid `CONNECT`/`OK` prologue did not complete.
    Prologue(PrologueError),
    /// Socket and prologue completed, but the guest's first frame was not a
    /// decodable `Ready` (the agent is still booting).
    Ready(String),
}

#[cfg(feature = "host-common")]
impl std::fmt::Display for ConnectAttemptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Socket(e) => write!(f, "control-stream connect failed: {e}"),
            Self::Prologue(e) => write!(f, "hybrid prologue failed: {e}"),
            Self::Ready(m) => write!(f, "no Ready handshake: {m}"),
        }
    }
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

            match Self::connect_framed_once(endpoint, timeouts).await {
                Ok(framed) => return Ok(framed),
                // ONE retry cadence for every failure arm. Before v30 only two of the
                // five arms slept at all — a failed `CONNECT` write, a non-decodable
                // first frame, a postcard error, and a non-`Ready` message each
                // `continue`d with no pause, busy-spinning to the deadline on exactly
                // the shapes a dead or half-open bridge produces (§18 delta 7).
                Err(ConnectAttemptError::Socket(e)) => {
                    tracing::trace!("Agent connect control-stream connect failed: {}", e);
                    tokio::time::sleep(backoff).await;
                    backoff = std::cmp::min(backoff * 2, timeouts.connect_backoff_cap);
                }
                Err(e) => {
                    tracing::trace!("Agent connect attempt failed: {}", e);
                    // The transport socket was up, so we are in the "guest still
                    // booting / not yet listening" regime, where the right cadence is
                    // a tight fixed poll — not the exponential backoff that only makes
                    // sense while the socket was absent. Reset to the floor so a few
                    // socket-absent iterations can't inflate the guest-ready detection
                    // gap (EXP-HOST-BACKOFF-RESET).
                    backoff = timeouts.connect_backoff_floor;
                    tokio::time::sleep(backoff).await;
                }
            }
        }
    }

    /// One attempt of the [`AgentClient::connect_framed`] loop: open the transport,
    /// speak the prologue the transport needs, and read the guest's first frame.
    ///
    /// Split out so the retry *cadence* lives in exactly one place (the caller) and
    /// every failure shape is a typed value rather than a bare `continue` — the
    /// pre-v30 shape, where four of the five failure arms silently skipped the
    /// backoff.
    async fn connect_framed_once(
        endpoint: &VsockEndpoint,
        timeouts: &crate::config::Timeouts,
    ) -> std::result::Result<Framed<ControlStream, LengthDelimitedCodec>, ConnectAttemptError> {
        let mut stream = connect_control_stream(endpoint)
            .await
            .map_err(ConnectAttemptError::Socket)?;

        // AF_UNIX bridges (CH/FC/QEMU's external `vhost-device-vsock` daemon)
        // speak the Firecracker-style hybrid `CONNECT <port>`/`OK` prologue; the
        // in-kernel AF_VSOCK transport has no bridge, so there is no prologue and
        // the guest's first framed message is already `Ready`.
        if let Some(port) = hybrid_prologue_port(endpoint) {
            hybrid_connect_prologue(&mut stream, port, timeouts.connect_ok_read)
                .await
                .map_err(ConnectAttemptError::Prologue)?;
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
                return Err(ConnectAttemptError::Ready(format!(
                    "framed.next() returned: {}",
                    capped_debug(&other)
                )));
            }
        };

        // Both diagnostics below quote *frame-sized* values (a raw frame, a decoded
        // `Message` that may carry one), and this runs once per retry while the
        // guest boots — so they are capped, never rendered in full.
        let msg: Message = postcard::from_bytes(&ready).map_err(|e| {
            ConnectAttemptError::Ready(format!(
                "postcard error: {e:?}, {} bytes, starting {}",
                ready.len(),
                capped_debug(&&ready[..])
            ))
        })?;

        match msg {
            Message::Ready => Ok(framed),
            other => Err(ConnectAttemptError::Ready(format!(
                "received unexpected message: {}",
                capped_debug(&other)
            ))),
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
                    // docs/78 §6: the frame is guest-chosen and `MAX_FRAME_BYTES`
                    // (16 MiB) big, so the render goes through the shared
                    // `capped_debug`; the wire length beside it is the number a
                    // desync report actually needs, and it costs nothing here.
                    other => {
                        tracing::warn!(
                            "unexpected message on exec stream (ignored, {} byte frame): {}",
                            bytes.len(),
                            capped_debug(&other)
                        );
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
    use super::{
        AgentClient, ControlStream, Error, ExecRequest, LengthDelimitedCodec, MAX_FRAME_BYTES,
        MAX_PROLOGUE_LINE_BYTES, Message, PrologueError, RequestFailure, SessionId, VsockDial,
        VsockEndpoint, dial_prologue_error, endpoint_on_port, hybrid_connect_prologue,
        hybrid_prologue_port, protocol,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Reads one `\n`-terminated line from a mock bridge's end of a socket pair,
    /// byte by byte (the client under test writes exactly one line, so a buffered
    /// read would be free to consume more than the test intends to observe).
    async fn read_line(stream: &mut tokio::net::UnixStream) -> String {
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

    // §3.2 (The host side: AgentClient and SessionMux): the extracted prologue is the ONE
    // implementation of the fragile hybrid handshake, shared by the framed connect and
    // the raw dial. This drives the accept-and-answer path end to end over a real
    // socket pair and asserts BOTH halves of the wire: the exact `CONNECT <port>` line
    // the bridge receives (the dialed port, not the agent's), and that an `OK` line is
    // accepted. RED on a prologue that writes the wrong port, omits the line, or
    // accepts a non-`OK` answer.
    #[tokio::test]
    async fn prologue_writes_connect_line_and_accepts_ok() {
        let (client, mut server) = tokio::net::UnixStream::pair().expect("socketpair");
        let task = tokio::spawn(async move {
            let line = read_line(&mut server).await;
            server.write_all(b"OK 7000\n").await.expect("write OK");
            (line, server)
        });

        let mut stream = ControlStream::Unix(client);
        let res =
            hybrid_connect_prologue(&mut stream, 7000, std::time::Duration::from_millis(500)).await;
        let (line, _server) = task.await.expect("mock bridge task");

        assert_eq!(
            line, "CONNECT 7000\n",
            "the prologue must CONNECT to the dialed port"
        );
        assert!(res.is_ok(), "an OK line must be accepted, got {res:?}");
    }

    // The dead-port signal CH's and Firecracker's in-VMM muxers actually send: accept
    // the CONNECT, then close without an `OK` line. It must be a DISTINCT, typed
    // outcome from "the bridge is hanging" — that distinction is what lets the raw
    // dial fail fast instead of folding into a timeout. RED on a prologue that
    // collapses EOF into the same arm as an elapsed read budget.
    #[tokio::test]
    async fn prologue_eof_without_ok_is_typed_eof() {
        let (client, mut server) = tokio::net::UnixStream::pair().expect("socketpair");
        let task = tokio::spawn(async move {
            let line = read_line(&mut server).await;
            drop(server); // the muxer's "no listener on that port" answer
            line
        });

        let mut stream = ControlStream::Unix(client);
        let res =
            hybrid_connect_prologue(&mut stream, 7000, std::time::Duration::from_secs(5)).await;
        assert_eq!(task.await.expect("mock bridge task"), "CONNECT 7000\n");
        assert!(
            matches!(res, Err(PrologueError::Eof { .. })),
            "a close before any OK line must be a typed Eof, got {res:?}"
        );
    }

    // QEMU's external `vhost-device-vsock` daemon on a dead port: it accepts the
    // CONNECT and simply never answers. The per-byte `connect_ok_read` budget is what
    // bounds that, and it must surface as its own arm (a timeout), not as an EOF. RED
    // on a prologue with an unbounded read: this test would hang instead of failing.
    #[tokio::test]
    async fn prologue_accept_and_hang_is_typed_read_timeout() {
        let (client, mut server) = tokio::net::UnixStream::pair().expect("socketpair");
        let task = tokio::spawn(async move {
            let line = read_line(&mut server).await;
            (line, server) // held open, never answered
        });

        let mut stream = ControlStream::Unix(client);
        let started = std::time::Instant::now();
        let res =
            hybrid_connect_prologue(&mut stream, 7000, std::time::Duration::from_millis(50)).await;
        let elapsed = started.elapsed();
        let (line, _server) = task.await.expect("mock bridge task");

        assert_eq!(line, "CONNECT 7000\n");
        assert!(
            matches!(res, Err(PrologueError::ReadTimeout { .. })),
            "an accepted-and-hung bridge must be a typed ReadTimeout, got {res:?}"
        );
        assert!(
            elapsed < std::time::Duration::from_secs(1),
            "the read budget must bound the hang (took {elapsed:?})"
        );
    }

    // A complete line that is not an acknowledgement is a refusal, not a success:
    // the pre-extraction code's `resp.starts_with("OK ")` check is the property, and
    // it stays exact. BOTH refusal shapes the comment claims are driven here —
    // `ERR …` (a bridge saying no) and `OKAY …` (the prefix trap: a line that starts
    // with the letters `OK` but is a different word, which only the trailing SPACE
    // in `"OK "` rejects).
    // RED on a prologue that treats any complete line as success, and RED on the
    // narrower `resp.starts_with("OK")` — which passes `ERR` correctly but lets
    // `OKAY` through as an acknowledgement.
    #[tokio::test]
    async fn prologue_non_ok_line_is_refused() {
        for answer in ["ERR connection refused\n", "OKAY but not an ack\n"] {
            let (client, mut server) = tokio::net::UnixStream::pair().expect("socketpair");
            let task = tokio::spawn(async move {
                let line = read_line(&mut server).await;
                server
                    .write_all(answer.as_bytes())
                    .await
                    .expect("write the refusal line");
                (line, server)
            });

            let mut stream = ControlStream::Unix(client);
            let res =
                hybrid_connect_prologue(&mut stream, 7000, std::time::Duration::from_millis(500))
                    .await;
            let (_line, _server) = task.await.expect("mock bridge task");
            assert!(
                matches!(&res, Err(PrologueError::Refused { line }) if line == answer),
                "{answer:?} must be refused, carrying verbatim what was received: {res:?}"
            );
        }
    }

    // docs/78 §6 (`uncapped-frame-debug-renders`), the exec-stream half. The renderer
    // itself is pinned where the law lives (`vmcell_protocol::capped_debug`'s unit
    // tests, beside `MAX_FRAME_BYTES`); what this pins is that THIS SITE routes
    // through it — the pre-fix line was a bare `{:?}` on a guest-chosen frame, so a
    // desync could put megabytes of guest bytes into the host log. The connect-loop
    // `Ready` diagnostics above share the same one helper.
    //
    // The guest peer queues its frames BEFORE `exec` runs: a socketpair buffers
    // both, so the exchange needs no second task. RED on the inverse (restore
    // `"… (ignored): {:?}", other`): the warn line grows to ~100 KB of `[7, 7, …]`
    // decimal and the length bound below fails; RED too on a site that drops the
    // frame length or the truncation marker.
    #[tokio::test]
    #[tracing_test::traced_test]
    async fn unexpected_exec_frame_is_logged_capped_not_frame_sized() {
        use futures::SinkExt as _;

        let (client_io, server_io) = tokio::net::UnixStream::pair().expect("socketpair");
        let mut client = AgentClient::from_stream_for_tests(client_io);

        let mut codec = LengthDelimitedCodec::new();
        codec.set_max_frame_length(MAX_FRAME_BYTES);
        let mut guest = tokio_util::codec::Framed::new(server_io, codec);

        // A host→guest-only frame (the guest must never send `Stdin`) whose payload
        // alone is 32 KiB, then the terminal `Exit` so `exec` returns normally.
        let stray = Message::Stdin {
            session: SessionId(0),
            data: vec![7u8; 32 * 1024],
        };
        let stray_bytes = postcard::to_stdvec(&stray).expect("encode the stray frame");
        let stray_len = stray_bytes.len();
        guest
            .send(::bytes::Bytes::from(stray_bytes))
            .await
            .expect("queue the stray frame");
        guest
            .send(::bytes::Bytes::from(
                postcard::to_stdvec(&Message::Exit(0)).expect("encode Exit"),
            ))
            .await
            .expect("queue Exit");

        let outcome = client
            .exec(ExecRequest::new(vec!["true".into()]))
            .await
            .expect("a stray frame is logged and ignored, never fatal");
        assert_eq!(outcome.code, 0, "the terminal Exit still resolves the exec");

        logs_assert(|lines: &[&str]| {
            let line = lines
                .iter()
                .find(|l| l.contains("unexpected message on exec stream"))
                .ok_or_else(|| "the desync warn is missing entirely".to_string())?;
            if line.len() > 1024 {
                return Err(format!(
                    "the desync log line is frame-sized ({} bytes): {}",
                    line.len(),
                    line.chars().take(200).collect::<String>()
                ));
            }
            if !line.contains(protocol::DEBUG_TRUNCATED_MARKER) {
                return Err(format!("a truncated render must say so: {line}"));
            }
            if !line.contains(&format!("{stray_len} byte frame")) {
                return Err(format!("the line must quote the frame's wire size: {line}"));
            }
            Ok(())
        });
    }

    // Validate-before-allocate (§13, Cross-cutting invariants): a bridge that streams bytes and never
    // sends a newline must hit `MAX_PROLOGUE_LINE_BYTES` and refuse, not grow the
    // accumulator without bound. RED on an uncapped loop: this test would run until
    // the read budget elapsed and report ReadTimeout instead of Refused.
    #[tokio::test]
    async fn prologue_caps_the_acknowledgement_line() {
        let flood = vec![b'x'; MAX_PROLOGUE_LINE_BYTES * 2];
        let (client, mut server) = tokio::net::UnixStream::pair().expect("socketpair");
        let task = tokio::spawn(async move {
            let line = read_line(&mut server).await;
            // Best-effort: the client stops reading at the cap, so a large write can
            // legitimately fail on a closed peer once the test completes.
            let _sent = server.write_all(&flood).await;
            (line, server)
        });

        let mut stream = ControlStream::Unix(client);
        let res =
            hybrid_connect_prologue(&mut stream, 7000, std::time::Duration::from_secs(5)).await;
        let (_line, _server) = task.await.expect("mock bridge task");
        assert!(
            matches!(&res, Err(PrologueError::Refused { line }) if line.len() >= MAX_PROLOGUE_LINE_BYTES),
            "an unterminated line must be capped and refused, got {res:?}"
        );
    }

    // §3.2 (The host side: AgentClient and SessionMux): the raw dial's typed interpretation of each
    // refusal signal — the property that makes a dead port an immediate, matchable
    // answer instead of a retry-until-Timeout. Every arm must NAME THE PORT (the
    // error enum has no dedicated no-listener variant, so the message is the only
    // thing that distinguishes it from any other Agent error). RED on a mapping that
    // folds EOF into Timeout (or vice versa), or that drops the port.
    #[test]
    fn dial_prologue_error_interprets_each_refusal_typed() {
        let budget = std::time::Duration::from_millis(150);

        let eof = dial_prologue_error(
            7000,
            budget,
            PrologueError::Eof {
                partial: String::new(),
            },
        );
        assert!(
            matches!(&eof, Error::Agent(m) if m.contains("no guest vsock listener") && m.contains("7000")),
            "EOF before an OK line must be a typed no-listener Agent error naming the port: {eof:?}"
        );

        let hung = dial_prologue_error(
            7001,
            budget,
            PrologueError::ReadTimeout {
                partial: String::new(),
            },
        );
        assert!(
            matches!(&hung, Error::Timeout(m) if m.contains("7001")),
            "an accepted-and-hung bridge must be a typed Timeout naming the port: {hung:?}"
        );

        let refused = dial_prologue_error(
            7002,
            budget,
            PrologueError::Refused {
                line: "ERR nope\n".into(),
            },
        );
        assert!(
            matches!(&refused, Error::Agent(m) if m.contains("7002") && m.contains("ERR nope")),
            "a non-OK answer must name the port and what was received: {refused:?}"
        );

        let io = dial_prologue_error(
            7003,
            budget,
            PrologueError::Write(std::io::Error::from(std::io::ErrorKind::BrokenPipe)),
        );
        assert!(
            matches!(&io, Error::Io(e) if e.kind() == std::io::ErrorKind::BrokenPipe),
            "a transport failure must surface as Io with its errno intact: {io:?}"
        );
    }

    // §3.2 (The host side: AgentClient and SessionMux): the caller-chosen guest port is spliced into
    // the instance's endpoint in ONE place, and it must reach the transport that
    // actually carries it — the CONNECT line on AF_UNIX, the connect address on
    // AF_VSOCK — while everything else (bridge path, guest CID) is preserved. RED on
    // an override that keeps the agent's port, which would silently dial the control
    // plane instead of the requested listener.
    #[test]
    fn endpoint_on_port_overrides_only_the_port() {
        let unix = endpoint_on_port(
            &VsockEndpoint::Unix {
                path: std::path::PathBuf::from("/run/vmcell/vsock.sock"),
                port: 5000,
            },
            7000,
        );
        assert_eq!(
            unix,
            VsockEndpoint::Unix {
                path: std::path::PathBuf::from("/run/vmcell/vsock.sock"),
                port: 7000,
            }
        );
        // The dispatch law still sees an AF_UNIX endpoint, so the dial speaks the
        // prologue for the OVERRIDDEN port.
        assert_eq!(hybrid_prologue_port(&unix), Some(7000));

        let vsock = endpoint_on_port(
            &VsockEndpoint::Vsock {
                cid: 42,
                port: 5000,
            },
            7000,
        );
        assert_eq!(
            vsock,
            VsockEndpoint::Vsock {
                cid: 42,
                port: 7000
            }
        );
        assert_eq!(hybrid_prologue_port(&vsock), None);
    }

    // The `VsockDial` newtype must stay exactly as unwind-safe as the `ControlStream`
    // it wraps (the manual assertions above it), so a downstream holding one across a
    // `catch_unwind` boundary keeps compiling. A plain newtype inherits both; adding
    // an interior-mutability field would silently take them away. RED on such a field.
    #[test]
    fn vsock_dial_preserves_unwind_safety() {
        fn assert_unwind_safe<T: std::panic::UnwindSafe + std::panic::RefUnwindSafe + Send>() {}
        assert_unwind_safe::<VsockDial>();
    }

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
