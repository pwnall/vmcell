//! Steward communication and client implementation (host side).
//!
//! This module provides the host-side `StewardClient` that talks to the steward
//! over vsock. The framed wire protocol and the framing bound live in the shared
//! [`vmcell_protocol`] crate; the PID-1 reaper coordination lives in the
//! `vmcell-steward` member crate. Re-exporting the protocol here keeps the
//! public `vmcell::steward::protocol` / `vmcell::{ExecOutcome, ExecRequest}` surface
//! stable across the v15 workspace split (§9.1, Workspace layout).

/// The framed wire protocol shared by the host and the steward.
pub use vmcell_protocol as protocol;
pub use vmcell_protocol::{
    ExecOutcome, ExecRequest, MAX_FRAME_BYTES, PtyConfig, SessionId, SessionSpec,
};

/// Host-side interactive-session multiplexer (§3.2, The host side: StewardClient and SessionMux): PTY / pipe sessions,
/// streaming stdin, window resize, and multiplexed concurrent execs over one
/// connection, beside the one-shot [`StewardClient`].
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
/// Kept a single concrete enum — rather than genericizing `StewardClient<S>` — so
/// `Framed<ControlStream, LengthDelimitedCodec>` stays **one** type and neither
/// [`StewardClient`] nor [`session::SessionMux`] grows a type parameter that would
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
// which *is* both. Asserting them here keeps the public `StewardClient` (and
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

/// Encodes a host→guest frame and enforces the shared `MAX_FRAME_BYTES` cap at the
/// send boundary — the host mirror of the steward's `send_framed` encode-side
/// check (§13, Cross-cutting invariants).
///
/// **One law, one predicate**: every host→guest frame is built here, on the
/// [`SessionMux`](session::SessionMux) path *and* on the one-shot request path
/// ([`StewardClient::exec`], [`StewardClient::put_file`], [`StewardClient::resync`]). The
/// one-shot path used to encode inline with no cap check (m8): the codec still refused
/// the frame, so the stream stayed byte-clean, but the failure surfaced as an opaque
/// `Error::Io` **and** desynced a stream that nothing had been written to — against
/// [`StewardClient::finish_request`]'s own "desync only if a stale frame could be in
/// flight" contract. Callers therefore encode BEFORE entering the request closure, so
/// an over-cap or unencodable message is a typed, non-desyncing failure.
///
/// # Errors
/// [`Error::Steward`] when the encoded frame exceeds `MAX_FRAME_BYTES`, or the postcard
/// error when the message cannot be encoded at all.
#[cfg(feature = "host-common")]
pub(crate) fn encode_frame(msg: &Message) -> Result<::bytes::Bytes> {
    let bytes = postcard::to_stdvec(msg)?;
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(Error::Steward(format!(
            "frame exceeds MAX_FRAME_BYTES ({} > {MAX_FRAME_BYTES})",
            bytes.len()
        )));
    }
    Ok(::bytes::Bytes::from(bytes))
}

/// The upper bound on the hybrid prologue's acknowledgement line, in bytes.
///
/// The `OK <port>\n` line a bridge sends is a dozen bytes; the cap exists so a
/// broken or hostile bridge that streams bytes without ever sending a newline
/// cannot grow the accumulator without bound (the same validate-before-allocate
/// discipline `MAX_FRAME_BYTES` applies to the framed plane, §13, Cross-cutting invariants).
#[cfg(feature = "host-common")]
const MAX_PROLOGUE_LINE_BYTES: usize = 256;

/// Per-attempt cap on the guest's first framed message (`Ready`) during a connect.
///
/// One attempt of [`StewardClient::connect_framed_once`] waits at most this long for the
/// handshake frame before the retry loop re-checks the serial log and tries again — and
/// **never** longer than the caller's own connect deadline, which clamps it (m10).
#[cfg(feature = "host-common")]
const READY_FRAME_READ: std::time::Duration = std::time::Duration::from_secs(2);

/// What the host was doing when it consulted the guest's console — the `op` half of
/// [`Error::GuestKernelFault`](crate::error::Error::GuestKernelFault), in the host's own words.
///
/// One const for all three expiry/abort arms of [`StewardClient::connect_framed`], so a reader
/// grepping a failure message lands on one spelling rather than three near-misses.
#[cfg(feature = "host-common")]
const STEWARD_HANDSHAKE_OP: &str = "steward vsock handshake";

/// The host's own timeout message, kept when the console says nothing about the guest.
///
/// Byte-identical to the string [`StewardClient::connect_framed`] has always returned, so a
/// caller matching on the timeout text sees no change on the path where nothing changed.
#[cfg(feature = "host-common")]
const STEWARD_CONNECT_TIMED_OUT: &str = "Steward connection timed out";

/// How the hybrid `CONNECT <port>`/`OK` prologue failed, at the granularity its two
/// callers interpret differently (§3.2, The host side: StewardClient and SessionMux).
///
/// [`StewardClient::connect_framed`] folds every arm into "retry after a backoff" —
/// it exists to outwait a *booting* steward. [`VsockDial`] maps each arm to its own
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
/// predicate): the framed control-plane connect ([`StewardClient::connect_framed`],
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
/// (§3.2, The host side: StewardClient and SessionMux) — the one place the refusal signals are given
/// meaning, so `dial_vsock`'s error contract lives beside the handshake that
/// produces it and is unit-testable without a VM.
///
/// `EOF` before an `OK` line is the in-VMM muxer's dead-port signal (a typed
/// [`Error::Steward`] naming the port); an accepted-and-hung bridge runs out the
/// per-byte budget into a typed [`Error::Timeout`] naming the port; a transport
/// error surfaces as [`Error::Io`], errno intact.
#[cfg(feature = "host-common")]
fn dial_prologue_error(port: u32, ok_read: std::time::Duration, err: PrologueError) -> Error {
    match err {
        PrologueError::Write(e) | PrologueError::Read(e) => Error::Io(e),
        PrologueError::Eof { partial } => Error::Steward(format!(
            "no guest vsock listener on port {port}: the vsock bridge closed the connection \
             without an OK line (received {partial:?})"
        )),
        PrologueError::ReadTimeout { partial } => Error::Timeout(format!(
            "no guest vsock listener answered on port {port}: the vsock bridge accepted the \
             CONNECT and sent no OK line within {ok_read:?} (received {partial:?})"
        )),
        PrologueError::Refused { line } => Error::Steward(format!(
            "guest vsock port {port} refused: the vsock bridge answered {line:?} instead of an \
             OK line"
        )),
    }
}

/// The same [`VsockEndpoint`] with its port replaced by `port`.
///
/// The one place a caller-chosen guest port is spliced into an instance's endpoint
/// (§3.2, The host side: StewardClient and SessionMux), so the raw dial's transport dispatch is exactly
/// [`hybrid_prologue_port`]'s and the AF_VSOCK arm dials the requested port rather
/// than the steward's. Exhaustive on both arms — [`VsockEndpoint`] is deliberately not
/// `#[non_exhaustive]`, so a future transport breaks this at compile time instead of
/// silently keeping the steward port.
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

/// The endpoint a [`StewardClient`] recovery must re-dial: the one recorded at connect time, or the
/// caller-supplied AF_UNIX coordinates when the recorded transport is the one they can address.
///
/// **One predicate** for both recovery entry points — [`StewardClient::reconnect`] (the AF_UNIX
/// coordinate form) and [`StewardClient::reconnect_endpoint`] (the transport-generic one) — because
/// the pre-fix `reconnect` composed `VsockEndpoint::Unix { path, port }` unconditionally. An
/// AF_VSOCK client (a snapshot-eligible QEMU on the in-kernel transport, §2.4, QEMU q35 — the fallback and most-proven nester,
/// and every crosvm cell) therefore had **no** working recovery at all: its reconnect dialed an
/// AF_UNIX path belonging to a different transport, while [`StewardClient::ensure_synced`] kept
/// pointing every later request at that recovery.
///
/// Coordinates may **re-address** an AF_UNIX client but never **re-family** it: a restore on a
/// rotating backend legitimately hands the same VM a fresh bridge path
/// ([`VmmCapabilities::restore_rotates_host_paths`](crate::vmm::VmmCapabilities::restore_rotates_host_paths)),
/// so a supplied path is honored on that transport, while a supplied path against an AF_VSOCK client
/// names a transport it does not speak and is refused rather than dialed.
///
/// # Errors
/// [`Error::Steward`] when AF_UNIX coordinates are supplied for a client connected over AF_VSOCK
/// (which has no bridge path), or when neither a recorded endpoint nor supplied coordinates say
/// where to re-dial.
#[cfg(feature = "host-common")]
fn recovery_endpoint(
    recorded: Option<&VsockEndpoint>,
    supplied: Option<(&Path, u32)>,
) -> Result<VsockEndpoint> {
    match (recorded, supplied) {
        // No coordinates: re-dial exactly what this client is connected over — the transport-generic
        // recovery, and the only recovery an AF_VSOCK client has.
        (Some(recorded), None) => Ok(recorded.clone()),
        (None, None) => Err(Error::Steward(
            "this steward client records no endpoint (it was built over an injected stream), so \
             there is nothing to re-dial"
                .into(),
        )),
        (
            Some(VsockEndpoint::Vsock {
                cid,
                port: vsock_port,
            }),
            Some(_),
        ) => Err(Error::Steward(format!(
            "this steward client is connected over AF_VSOCK (cid {cid}, port {vsock_port}), which \
             has no AF_UNIX bridge path: recover it with StewardClient::reconnect_endpoint, which \
             re-dials the recorded endpoint"
        ))),
        // An AF_UNIX client (or an injected-stream client, which records nothing to contradict):
        // the supplied bridge path is honored, rotated or not.
        (Some(VsockEndpoint::Unix { .. }) | None, Some((path, port))) => Ok(VsockEndpoint::Unix {
            path: path.to_path_buf(),
            port,
        }),
    }
}

/// A raw byte stream to a guest AF_VSOCK listener (§3.2, The host side: StewardClient and SessionMux — the raw vsock
/// dial): the guest process on the other end owns its own protocol, so there is no
/// framing, no `Ready` handshake, and no steward involvement.
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
    /// Unlike [`StewardClient::connect_endpoint`] this does **not** retry: that retry
    /// loop exists to outwait a booting steward and folds "nobody listens" into a
    /// terminal timeout, whereas a dial is issued against a VM the caller already
    /// brought up. Refusal signals are interpreted and returned fast and typed.
    ///
    /// # Errors
    /// - [`Error::Steward`] naming the port when the vsock bridge closes the
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

/// The per-step outcome of a native post-restore [`StewardClient::resync`]
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
/// A client for communicating with the steward over vsock.
#[derive(Debug)]
pub struct StewardClient {
    stream: Framed<ControlStream, LengthDelimitedCodec>,
    /// The endpoint this client was connected over, so the recovery path re-dials the
    /// **same transport family** ([`recovery_endpoint`]). `None` only for the
    /// `#[cfg(test)]` injected-stream constructors, which were handed a socket rather
    /// than an endpoint and therefore have nothing to re-dial.
    endpoint: Option<VsockEndpoint>,
    /// Set when a request times out or the framed stream desynchronizes
    /// mid-exchange. A desynced stream may still hold a late frame from the
    /// abandoned request, so reusing it would read stale data and silently
    /// return a wrong result. Further requests fail loud until
    /// [`StewardClient::reconnect`] — or, on the AF_VSOCK transport,
    /// [`StewardClient::reconnect_endpoint`] — re-establishes the stream.
    desynced: bool,
}

/// Why one [`StewardClient::connect_framed_once`] attempt failed, and therefore how
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
    /// decodable `Ready` (the steward is still booting).
    Ready(String),
    /// The caller's connect deadline elapsed *inside* this attempt (m10). Every step of
    /// an attempt is bounded by that absolute deadline, so this is terminal: the loop
    /// returns [`Error::Timeout`] immediately rather than sleeping a backoff it has no
    /// budget for.
    Deadline,
}

#[cfg(feature = "host-common")]
impl std::fmt::Display for ConnectAttemptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Socket(e) => write!(f, "control-stream connect failed: {e}"),
            Self::Prologue(e) => write!(f, "hybrid prologue failed: {e}"),
            Self::Ready(m) => write!(f, "no Ready handshake: {m}"),
            Self::Deadline => write!(f, "the connect deadline elapsed mid-attempt"),
        }
    }
}

/// How a request closure failed, with respect to whether the framed stream is
/// still safe to reuse.
///
/// [`StewardClient::finish_request`] marks the stream desynced only for a
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
impl StewardClient {
    /// Connects to the steward on the specified vsock path and port.
    ///
    /// # Errors
    /// Returns an error if the connection fails or the handshake is unsuccessful.
    ///
    /// # Examples
    /// ```rust
    /// # use vmcell::steward::StewardClient;
    /// # use std::path::Path;
    /// # use std::time::Duration;
    /// # async fn run() {
    /// let serial = vmcell::vmm::RealSerialLog { path: std::path::PathBuf::from("/dev/null") };
    /// let client = StewardClient::connect(Path::new("/tmp/vsock"), 5000, Duration::from_secs(10), &vmcell::config::Timeouts::default(), &serial).await.unwrap();
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

    /// Connects to the steward over an explicit [`VsockEndpoint`] — the
    /// transport-generic entry the orchestrator uses so a snapshot-eligible QEMU on
    /// the AF_VSOCK transport (§2.4, QEMU q35 — the fallback and most-proven nester) is reached the same way as an AF_UNIX
    /// backend. The public [`StewardClient::connect`] is the AF_UNIX convenience
    /// wrapper over this.
    ///
    /// # Errors
    /// As [`StewardClient::connect`].
    pub async fn connect_endpoint(
        endpoint: &VsockEndpoint,
        timeout: std::time::Duration,
        timeouts: &crate::config::Timeouts,
        serial_log: &dyn crate::vmm::SerialLog,
    ) -> Result<Self> {
        let stream = Self::connect_framed(endpoint, timeout, timeouts, serial_log).await?;
        Ok(Self {
            stream,
            // Recorded here so a later recovery re-dials THIS transport family, not a hardcoded
            // AF_UNIX path (`recovery_endpoint`).
            endpoint: Some(endpoint.clone()),
            desynced: false,
        })
    }

    /// Connects the raw framed control-plane stream, retrying with backoff until
    /// the guest answers `Ready` (the one connect/handshake law, §13, Cross-cutting invariants).
    ///
    /// Split out of [`StewardClient::connect_endpoint`] so the session multiplexer
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
    /// Returns [`Error::GuestKernelFault`](crate::error::Error::GuestKernelFault) if the guest's
    /// serial console proves the guest kernel died — immediately once the console shows the kernel
    /// has **stopped** (waiting longer cannot help), and on budget expiry for any fault class,
    /// including the advisory ones that do not stop a kernel. Otherwise returns
    /// [`Error::Timeout`] if no `Ready` handshake completes within `timeout`: a console that is
    /// healthy, empty or unreadable leaves the host's own timeout in place, so a wedged bridge or a
    /// busy host still reports itself (§5.4, The guest-kernel contract and the bootstrap seed).
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
                // The budget expired: ask the console whether the GUEST is the reason before
                // reporting the host's own timeout (`expiry_error` — a healthy or unreadable
                // console still yields `Error::Timeout`).
                return Err(crate::vmm::fault::expiry_error(
                    serial_log,
                    STEWARD_HANDSHAKE_OP,
                    STEWARD_CONNECT_TIMED_OUT,
                ));
            }

            // The guest kernel has STOPPED: no later poll can succeed, so fail now — and fail with
            // the CAUSE the console names, not with `Panic` for every death. `halted()` is the
            // orthogonal question to `kind()`: a KASAN report that ended in a panic aborts here
            // (halted) while reporting the KASAN (the cause). A console that shows only an
            // advisory lockdep splat does NOT abort — the kernel kept running, and §5.5 ships
            // LOCKDEP kernels on purpose — it merely re-labels the timeout above if the wait
            // eventually expires.
            if let Some(guest_fault) = serial_log.classify_fault()
                && guest_fault.halted()
            {
                return Err(guest_fault.into_error(STEWARD_HANDSHAKE_OP));
            }

            // The deadline is passed IN, not merely checked between attempts: every
            // await inside an attempt is bounded by it, so the connect cannot overrun
            // the caller's budget (m10).
            match Self::connect_framed_once(endpoint, timeouts, deadline).await {
                Ok(framed) => return Ok(framed),
                // Terminal: the attempt consumed the whole budget, so there is nothing
                // left to back off into.
                Err(ConnectAttemptError::Deadline) => {
                    // Same expiry law as the loop-top check: one implementation, both arms.
                    return Err(crate::vmm::fault::expiry_error(
                        serial_log,
                        STEWARD_HANDSHAKE_OP,
                        STEWARD_CONNECT_TIMED_OUT,
                    ));
                }
                // ONE retry cadence for every failure arm. Before v30 only two of the
                // five arms slept at all — a failed `CONNECT` write, a non-decodable
                // first frame, a postcard error, and a non-`Ready` message each
                // `continue`d with no pause, busy-spinning to the deadline on exactly
                // the shapes a dead or half-open bridge produces (§18 delta 7).
                Err(ConnectAttemptError::Socket(e)) => {
                    tracing::trace!("Steward connect control-stream connect failed: {}", e);
                    tokio::time::sleep(backoff).await;
                    backoff = std::cmp::min(backoff * 2, timeouts.connect_backoff_cap);
                }
                Err(e) => {
                    tracing::trace!("Steward connect attempt failed: {}", e);
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

    /// One attempt of the [`StewardClient::connect_framed`] loop: open the transport,
    /// speak the prologue the transport needs, and read the guest's first frame.
    ///
    /// Split out so the retry *cadence* lives in exactly one place (the caller) and
    /// every failure shape is a typed value rather than a bare `continue` — the
    /// pre-v30 shape, where four of the five failure arms silently skipped the
    /// backoff.
    ///
    /// `deadline` is the **caller's** absolute connect deadline, and it bounds every
    /// await here — the transport connect, the prologue, and the `Ready` frame read —
    /// outer-bounds-inner (m10). Before that, the deadline was only checked *between*
    /// attempts while the attempt itself ran unbounded (a hardcoded 2 s frame read plus
    /// an unbounded connect), so a single attempt could overrun the caller's whole
    /// timeout.
    async fn connect_framed_once(
        endpoint: &VsockEndpoint,
        timeouts: &crate::config::Timeouts,
        deadline: tokio::time::Instant,
    ) -> std::result::Result<Framed<ControlStream, LengthDelimitedCodec>, ConnectAttemptError> {
        let mut stream =
            match tokio::time::timeout_at(deadline, connect_control_stream(endpoint)).await {
                Ok(res) => res.map_err(ConnectAttemptError::Socket)?,
                Err(_elapsed) => return Err(ConnectAttemptError::Deadline),
            };

        // AF_UNIX bridges (CH/FC/QEMU's external `vhost-device-vsock` daemon)
        // speak the Firecracker-style hybrid `CONNECT <port>`/`OK` prologue; the
        // in-kernel AF_VSOCK transport has no bridge, so there is no prologue and
        // the guest's first framed message is already `Ready`.
        if let Some(port) = hybrid_prologue_port(endpoint) {
            // `connect_ok_read` bounds each single-byte read; the caller's deadline
            // bounds the prologue as a whole, because a bridge that dribbles a byte just
            // under that per-read budget (up to `MAX_PROLOGUE_LINE_BYTES` of them) would
            // otherwise run far past the caller's timeout.
            match tokio::time::timeout_at(
                deadline,
                hybrid_connect_prologue(&mut stream, port, timeouts.connect_ok_read),
            )
            .await
            {
                Ok(res) => res.map_err(ConnectAttemptError::Prologue)?,
                Err(_elapsed) => return Err(ConnectAttemptError::Deadline),
            }
        }

        let mut codec = LengthDelimitedCodec::new();
        // Align the host frame cap with the guest's (the codec default is
        // only 8 MiB), so neither side silently drops a frame the other sent.
        codec.set_max_frame_length(MAX_FRAME_BYTES);
        let mut framed = Framed::new(stream, codec);

        // Per-attempt cap on the `Ready` read, clamped by the caller's deadline: an
        // attempt that started with less than `READY_FRAME_READ` left must not overrun
        // it (m10). Whichever bound bites, the elapse is reported as the one that
        // actually applied, so the retry loop can tell "still booting" from "out of
        // budget".
        let ready_at = std::cmp::min(deadline, tokio::time::Instant::now() + READY_FRAME_READ);
        let ready_result = tokio::time::timeout_at(ready_at, framed.next()).await;
        let ready = match ready_result {
            Ok(Some(Ok(bytes))) => bytes,
            Err(_elapsed) if tokio::time::Instant::now() >= deadline => {
                return Err(ConnectAttemptError::Deadline);
            }
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
    /// CONNECT handshake, for unit tests that only need a `Some(StewardClient)`
    /// to observe cache-invalidation behavior (e.g. `MicroVm::snapshot()`
    /// dropping its cached client). Uses the same codec configuration as
    /// [`StewardClient::connect`] and starts in-sync (`desynced: false`).
    /// `#[cfg(test)]` + `pub(crate)` so no test-only constructor ships in the
    /// public surface. Records **no** endpoint: it was handed a socket, not an
    /// address, so a recovery on it has nothing of its own to re-dial.
    #[cfg(test)]
    pub(crate) fn from_stream_for_tests(stream: UnixStream) -> Self {
        Self::from_stream_and_endpoint_for_tests(stream, None)
    }

    /// As [`StewardClient::from_stream_for_tests`], but recording `endpoint` as the endpoint the
    /// recovery path must re-dial.
    ///
    /// Lets a unit test present the shape of a live AF_VSOCK client — a recorded
    /// [`VsockEndpoint::Vsock`] — without an AF_VSOCK socket, because what
    /// [`recovery_endpoint`] must get right is *which endpoint the recovery dials*, not the kernel's
    /// vsock. KVM-free by construction, which is the point: the AF_VSOCK transport is only reachable
    /// live on a snapshot-eligible QEMU or crosvm cell.
    #[cfg(test)]
    pub(crate) fn from_stream_and_endpoint_for_tests(
        stream: UnixStream,
        endpoint: Option<VsockEndpoint>,
    ) -> Self {
        let mut codec = LengthDelimitedCodec::new();
        // Mirror `connect`: align the host frame cap with the guest's.
        codec.set_max_frame_length(MAX_FRAME_BYTES);
        Self {
            stream: Framed::new(ControlStream::Unix(stream), codec),
            endpoint,
            desynced: false,
        }
    }

    /// Reconnects to the steward over an AF_UNIX bridge — the coordinate form, mirroring
    /// [`StewardClient::connect`].
    ///
    /// The coordinates are checked against the transport this client was **connected over**
    /// (`recovery_endpoint`, the one law both recoveries share) instead of being dialed
    /// unconditionally: a client on the in-kernel
    /// AF_VSOCK transport has no bridge path at all, and dialing one anyway is how its recovery used
    /// to fail silently. Such a client recovers through [`StewardClient::reconnect_endpoint`], which
    /// is also the form to prefer for an AF_UNIX client that still has its original path.
    ///
    /// # Errors
    /// Returns an error if the connection fails or times out, or [`Error::Steward`] if this client is
    /// connected over AF_VSOCK, which `vsock_path`/`port` cannot address.
    ///
    /// Parameter order mirrors [`StewardClient::connect`]
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
        let endpoint = recovery_endpoint(self.endpoint.as_ref(), Some((vsock_path, port)))?;
        self.redial(endpoint, timeout, timeouts, serial_log).await
    }

    /// Reconnects over the [`VsockEndpoint`] this client recorded at connect time — the
    /// transport-generic recovery, of which [`StewardClient::reconnect`] is the AF_UNIX
    /// coordinate wrapper.
    ///
    /// This is the recovery for an AF_VSOCK control plane (a snapshot-eligible QEMU, §2.4, QEMU q35 — the fallback and most-proven nester,
    /// or any crosvm cell): it re-dials the recorded `(cid, port)` through the same
    /// `connect_framed` the first connect used, so the per-transport prologue —
    /// hybrid `CONNECT`/`OK` on AF_UNIX, none on AF_VSOCK — comes from the one implementation.
    ///
    /// # Errors
    /// Returns an error if the connection fails or times out, or [`Error::Steward`] if this client
    /// records no endpoint (only an injected-stream test client does).
    pub async fn reconnect_endpoint(
        &mut self,
        timeout: std::time::Duration,
        timeouts: &crate::config::Timeouts,
        serial_log: &dyn crate::vmm::SerialLog,
    ) -> Result<()> {
        let endpoint = recovery_endpoint(self.endpoint.as_ref(), None)?;
        self.redial(endpoint, timeout, timeouts, serial_log).await
    }

    /// Re-establishes the framed stream over `endpoint` — the one body both recovery entry points
    /// share, so neither can diverge on what a successful recovery resets.
    async fn redial(
        &mut self,
        endpoint: VsockEndpoint,
        timeout: std::time::Duration,
        timeouts: &crate::config::Timeouts,
        serial_log: &dyn crate::vmm::SerialLog,
    ) -> Result<()> {
        let stream = Self::connect_framed(&endpoint, timeout, timeouts, serial_log).await?;
        self.stream = stream;
        // A fresh stream is back in sync, so clear any prior desync state — and only now that the
        // connect has succeeded, so a failed recovery leaves the next attempt able to retry.
        self.desynced = false;
        self.endpoint = Some(endpoint);
        Ok(())
    }

    /// Whether a prior request left the framed stream desynchronized, so every further
    /// request on it fails [`StewardClient::ensure_synced`] until a reconnect.
    ///
    /// Exists so the **owner** of a cached client can act on that state instead of handing
    /// the dead handle back forever: `MicroVm::steward` evicts a desynced cached client and
    /// reconnects (finding `M7` — a single exec timeout used to kill one-shot
    /// `exec`/`put_file`/`resync` on that VM permanently, because `reconnect` had no
    /// non-test caller in the tree).
    pub(crate) fn is_desynced(&self) -> bool {
        self.desynced
    }

    /// Fails loud if a prior request left the framed stream desynchronized.
    ///
    /// Every request method calls this first so a stale in-flight frame from an
    /// abandoned (timed-out or errored) exchange can never be read as the next
    /// request's response. Recovery is via [`StewardClient::reconnect`] /
    /// [`StewardClient::reconnect_endpoint`], or — for the orchestrator's cached client — the
    /// eviction [`StewardClient::is_desynced`] drives.
    fn ensure_synced(&self) -> Result<()> {
        if self.desynced {
            return Err(Error::Steward(
                "steward connection desynchronized by a prior timeout; reconnect required".into(),
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
    /// next request must fail loud via [`StewardClient::ensure_synced`] until a
    /// [`StewardClient::reconnect`]. A [`RequestFailure::Clean`] — a
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
    /// A request that cannot be encoded, or whose encoded frame exceeds
    /// `MAX_FRAME_BYTES`, is rejected by `encode_frame` **before** anything is written,
    /// so it is a typed [`Error::Steward`] that leaves the stream in sync (m8).
    pub async fn exec(&mut self, mut cmd: ExecRequest) -> Result<ExecOutcome> {
        self.ensure_synced()?;
        // Propagate the effective timeout into the request so the guest always
        // installs a kill thread. A `None` timeout would let the guest child
        // outlive this abandoned wait and leak.
        let timeout = cmd.timeout.unwrap_or(protocol::DEFAULT_EXEC_TIMEOUT);
        cmd.timeout = Some(timeout);

        // Encode + cap-check BEFORE the exchange starts (m8): nothing has been written,
        // so an over-cap request is a typed failure that leaves the stream in sync
        // instead of an opaque `Error::Io` that desyncs a byte-clean stream.
        let frame = encode_frame(&Message::Exec(cmd))?;

        let result = tokio::time::timeout(timeout, async {
            self.stream
                .send(frame)
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
            Err(RequestFailure::Transport(Error::Steward(
                "Connection dropped during exec".into(),
            )))
        })
        .await;

        Self::finish_request(&mut self.desynced, result, "Steward exec timed out")
    }

    /// Uploads a file to the guest VM.
    ///
    /// # Errors
    /// Returns an error if the file transfer fails, times out, or the stream is
    /// already desynchronized by a prior request (in which case a
    /// [`StewardClient::reconnect`] is required before further requests). Like
    /// [`StewardClient::exec`], a send/decode error or timeout here marks the
    /// stream desynced so the next request fails loud rather than reading this
    /// exchange's stale frame as its own response — but a file whose encoded frame
    /// exceeds `MAX_FRAME_BYTES` is rejected by `encode_frame` before the exchange
    /// starts, so that failure is typed and does **not** desync (m8).
    pub async fn put_file(
        &mut self,
        dst: &str,
        bytes: &[u8],
        timeout: Option<std::time::Duration>,
    ) -> Result<()> {
        self.ensure_synced()?;
        let timeout = timeout.unwrap_or(std::time::Duration::from_secs(10));
        // Encode + cap-check BEFORE the exchange starts (m8) — a file one byte over the
        // cap must fail loud and typed, with the stream still usable.
        let frame = encode_frame(&Message::PutFile {
            dst: dst.to_string(),
            bytes: bytes.to_vec(),
        })?;

        let result = tokio::time::timeout(timeout, async {
            self.stream
                .send(frame)
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
                    Message::Exit(c) => Err(RequestFailure::Clean(Error::Steward(format!(
                        "put_file failed with code {c}"
                    )))),
                    _ => Err(RequestFailure::Transport(Error::Steward(
                        "unexpected response to put_file".into(),
                    ))),
                }
            } else {
                Err(RequestFailure::Transport(Error::Steward(
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
    /// desynchronized by a prior request (a [`StewardClient::reconnect`] is then
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
        // Encode + cap-check BEFORE the exchange starts, like the other one-shot
        // requests (m8), so every host→guest frame is built by the one predicate.
        let frame = encode_frame(&Message::Resync {
            unix_secs,
            unix_nanos,
            mac,
            ipv4,
        })?;

        let result = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            self.stream
                .send(frame)
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
                    _ => Err(RequestFailure::Transport(Error::Steward(
                        "unexpected response to resync".into(),
                    ))),
                }
            } else {
                Err(RequestFailure::Transport(Error::Steward(
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
        ControlStream, Error, ExecRequest, LengthDelimitedCodec, MAX_FRAME_BYTES,
        MAX_PROLOGUE_LINE_BYTES, Message, PrologueError, RequestFailure, SessionId, StewardClient,
        VsockDial, VsockEndpoint, dial_prologue_error, endpoint_on_port, hybrid_connect_prologue,
        hybrid_prologue_port, protocol, recovery_endpoint,
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

    /// Binds a mock vsock bridge on `path` and serves every accepted connection with
    /// `answer`, which receives the freshly accepted stream. The join handle is dropped
    /// with the runtime at the end of the test.
    fn spawn_mock_bridge<F, Fut>(path: &std::path::Path, answer: F)
    where
        F: Fn(tokio::net::UnixStream) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        let listener = tokio::net::UnixListener::bind(path).expect("bind mock bridge");
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(answer(stream));
            }
        });
    }

    /// Serves one mock-bridge connection the way a booting steward does: answer the hybrid
    /// prologue, send the `Ready` frame, then hold the connection open (the client keeps the stream
    /// after the handshake, so returning here would look like an immediate EOF).
    async fn serve_ready(mut stream: tokio::net::UnixStream) {
        use futures::SinkExt as _;

        let _line = read_line(&mut stream).await;
        if stream.write_all(b"OK 5000\n").await.is_err() {
            return;
        }
        let mut codec = LengthDelimitedCodec::new();
        codec.set_max_frame_length(MAX_FRAME_BYTES);
        let mut framed = tokio_util::codec::Framed::new(stream, codec);
        let ready =
            ::bytes::Bytes::from(postcard::to_stdvec(&Message::Ready).expect("encode Ready"));
        if framed.send(ready).await.is_err() {
            return;
        }
        std::future::pending::<()>().await;
    }

    // The recovery-endpoint law: a reconnect re-dials the transport the client is CONNECTED over.
    // AF_UNIX coordinates may re-address an AF_UNIX client (a restore on a rotating backend hands
    // the same VM a fresh bridge path), but they cannot address an AF_VSOCK client at all.
    //
    // RED on the inverse (the shipped pre-fix `reconnect`, which composed
    // `VsockEndpoint::Unix { path, port }` unconditionally): the AF_VSOCK legs return an AF_UNIX
    // endpoint instead of the recorded one, and the refusal leg returns `Ok`.
    #[test]
    fn recovery_endpoint_redials_the_recorded_transport() {
        let path = std::path::PathBuf::from("/run/vmcell/vsock.sock");
        let vsock = VsockEndpoint::Vsock {
            cid: 42,
            port: 5000,
        };
        let unix = VsockEndpoint::Unix {
            path: path.clone(),
            port: 5000,
        };

        assert_eq!(
            recovery_endpoint(Some(&vsock), None).expect("an AF_VSOCK client must be recoverable"),
            vsock,
            "the recovery must re-dial the recorded AF_VSOCK endpoint, not an AF_UNIX path"
        );
        assert_eq!(
            recovery_endpoint(Some(&unix), None).expect("an AF_UNIX client must be recoverable"),
            unix
        );

        // The AF_UNIX coordinate form cannot express an AF_VSOCK client, so it must fail loud and
        // name the entry point that can — never dial the path it was handed.
        let err = recovery_endpoint(Some(&vsock), Some((&path, 5000)))
            .expect_err("AF_UNIX coordinates must not recover an AF_VSOCK client");
        assert!(
            matches!(&err, Error::Steward(m)
                if m.contains("AF_VSOCK") && m.contains("reconnect_endpoint")),
            "the refusal must name the transport and the recovery that works: {err:?}"
        );

        assert_eq!(
            recovery_endpoint(Some(&unix), Some((&path, 5000)))
                .expect("matching coordinates must be accepted"),
            unix
        );

        // Same family, rotated path: honored, because that is exactly what a restore on a
        // `restore_rotates_host_paths` backend hands the same VM.
        let rotated = std::path::PathBuf::from("/run/vmcell/vsock-2.sock");
        assert_eq!(
            recovery_endpoint(Some(&unix), Some((&rotated, 5000)))
                .expect("an AF_UNIX client may be re-addressed on its own transport"),
            VsockEndpoint::Unix {
                path: rotated,
                port: 5000
            }
        );

        // An injected-stream client records no endpoint, so the caller's coordinates are all there
        // is — and with neither, the recovery fails loud instead of dialing something invented.
        assert_eq!(
            recovery_endpoint(None, Some((&path, 5000))).expect("coordinates are all there is"),
            unix
        );
        assert!(matches!(
            recovery_endpoint(None, None),
            Err(Error::Steward(_))
        ));
    }

    // The call-site half of the law above, which the pure test structurally cannot see: that the
    // two recovery entry points on the client actually route through it. The AF_VSOCK client is
    // presented by its RECORDED endpoint over an injected stream, so this runs KVM-free — the live
    // AF_VSOCK transport exists only on a snapshot-eligible QEMU or a crosvm cell.
    //
    // RED on the inverse (restore `Self::connect(vsock_path, port, …)` in `reconnect`): the
    // AF_VSOCK client's reconnect returns `Ok` after dialing the AF_UNIX bridge, so both the typed
    // refusal and the `seen == 0` assertion fail.
    #[tokio::test]
    async fn an_af_vsock_client_is_never_recovered_over_the_af_unix_bridge() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let dir = tempfile::tempdir().expect("tempdir");
        let sock = dir.path().join("vsock.sock");
        let seen = std::sync::Arc::new(AtomicUsize::new(0));
        let bridge_seen = std::sync::Arc::clone(&seen);
        spawn_mock_bridge(&sock, move |stream| {
            let seen = std::sync::Arc::clone(&bridge_seen);
            async move {
                seen.fetch_add(1, Ordering::SeqCst);
                serve_ready(stream).await;
            }
        });
        let budget = std::time::Duration::from_millis(300);
        let timeouts = crate::config::Timeouts::default();
        let serial = crate::vmm::FakeSerialLog { panicked: false };

        // A client whose control plane is the in-kernel AF_VSOCK transport.
        let (client_io, _guest_io) = tokio::net::UnixStream::pair().expect("socketpair");
        let mut vsock_client = StewardClient::from_stream_and_endpoint_for_tests(
            client_io,
            Some(VsockEndpoint::Vsock {
                cid: 42,
                port: 5000,
            }),
        );
        let err = vsock_client
            .reconnect(&sock, 5000, budget, &timeouts, &serial)
            .await
            .expect_err("AF_UNIX coordinates must not recover an AF_VSOCK client");
        assert!(
            matches!(&err, Error::Steward(m)
                if m.contains("AF_VSOCK") && m.contains("reconnect_endpoint")),
            "the refusal must be typed and name the recovery that works: {err:?}"
        );

        // The transport-generic recovery dials the recorded `(cid, port)`: it cannot succeed here
        // (no VM with cid 42), but it must fail on the AF_VSOCK dial — never by reaching the
        // AF_UNIX bridge, which is live and answering throughout.
        vsock_client
            .reconnect_endpoint(budget, &timeouts, &serial)
            .await
            .expect_err("there is no guest at cid 42");
        assert_eq!(
            seen.load(Ordering::SeqCst),
            0,
            "an AF_VSOCK client's recovery must never dial the AF_UNIX bridge"
        );

        // Positive control: the very same bridge recovers an AF_UNIX client, so the negative above
        // is a refusal to dial and not an unreachable mock. The injected-stream client records no
        // endpoint, so its first recovery takes the coordinate form...
        let (client_io, _guest_io) = tokio::net::UnixStream::pair().expect("socketpair");
        let mut unix_client = StewardClient::from_stream_for_tests(client_io);
        unix_client
            .reconnect(&sock, 5000, budget, &timeouts, &serial)
            .await
            .expect("the AF_UNIX bridge must recover an AF_UNIX client");
        assert_eq!(
            seen.load(Ordering::SeqCst),
            1,
            "the positive control must have reached the bridge"
        );
        // ...and having recovered, the client now records that endpoint, so the generic recovery
        // works on it too (a recovery that did not record would fail loud here).
        unix_client
            .reconnect_endpoint(budget, &timeouts, &serial)
            .await
            .expect("a recovered client must record the endpoint it re-dialed");
        assert_eq!(
            seen.load(Ordering::SeqCst),
            2,
            "the generic recovery must re-dial the recorded AF_UNIX endpoint"
        );
    }

    // Guards m8: an over-cap one-shot request fails loud with the typed cap error
    // BEFORE anything reaches the wire, and does NOT desync a stream nothing was
    // written to — the client stays usable, and the guest sees only the in-cap frame.
    // Inverse (encode inline inside the request closure, no cap check): the codec
    // refuses the frame as an opaque `Error::Io`, `finish_request` marks the stream
    // desynced, and the follow-up `put_file` fails with "reconnect required".
    #[tokio::test]
    async fn over_cap_one_shot_request_is_typed_and_leaves_the_client_in_sync() {
        use futures::{SinkExt as _, StreamExt as _};

        let (client_io, server_io) = tokio::net::UnixStream::pair().expect("socketpair");
        let mut client = StewardClient::from_stream_for_tests(client_io);

        // The guest: read exactly one frame, ack it, and hand the frame back so the
        // test can prove WHICH request reached the wire.
        let guest = tokio::spawn(async move {
            let mut codec = LengthDelimitedCodec::new();
            codec.set_max_frame_length(MAX_FRAME_BYTES);
            let mut framed = tokio_util::codec::Framed::new(server_io, codec);
            let first = framed
                .next()
                .await
                .expect("the guest must receive a frame")
                .expect("a decodable frame");
            framed
                .send(::bytes::Bytes::from(
                    postcard::to_stdvec(&Message::Exit(0)).expect("encode Exit"),
                ))
                .await
                .expect("ack the put_file");
            first
        });

        let err = client
            .put_file("/over", &vec![0u8; MAX_FRAME_BYTES], None)
            .await
            .expect_err("an over-cap put_file must fail loud");
        assert!(
            matches!(&err, Error::Steward(m) if m.contains("MAX_FRAME_BYTES")),
            "expected the typed over-cap error, got {err:?}"
        );

        // Nothing was written, so the stream is still in sync: the very next request
        // must go through rather than demanding a reconnect.
        client
            .put_file("/small", b"hello", Some(std::time::Duration::from_secs(10)))
            .await
            .expect("an over-cap rejection must not desync a byte-clean stream");

        let first = guest.await.expect("guest task");
        let msg: Message = postcard::from_bytes(&first).expect("decode the guest's frame");
        assert!(
            matches!(&msg, Message::PutFile { dst, bytes } if dst == "/small" && bytes == b"hello"),
            "the over-cap frame must never have reached the wire, got {}",
            protocol::capped_debug(&msg)
        );
    }

    // Guards m10: `connect_framed`'s deadline must bound the whole ATTEMPT, not just the
    // gaps between attempts. The bridge answers the prologue and then never sends the
    // `Ready` frame, which used to park the attempt on a hardcoded 2 s read unrelated to
    // the caller's budget. With a 300 ms budget the call must return a typed Timeout
    // inside the wall-clock guard.
    // Inverse (restore `timeout(Duration::from_secs(2), framed.next())` and await
    // `connect_framed_once` bare): the call returns after ~2 s and the guard reddens.
    #[tokio::test]
    async fn connect_framed_deadline_bounds_a_wedged_ready_read() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sock = dir.path().join("vsock.sock");
        spawn_mock_bridge(&sock, |mut stream| async move {
            let _line = read_line(&mut stream).await;
            if stream.write_all(b"OK 5000\n").await.is_err() {
                return;
            }
            // Accepted, acknowledged — and then silent: no `Ready` frame, ever.
            std::future::pending::<()>().await;
        });

        let budget = std::time::Duration::from_millis(300);
        let started = std::time::Instant::now();
        let res = StewardClient::connect_framed(
            &VsockEndpoint::Unix {
                path: sock,
                port: 5000,
            },
            budget,
            &crate::config::Timeouts::default(),
            &crate::vmm::FakeSerialLog { panicked: false },
        )
        .await;
        let elapsed = started.elapsed();

        assert!(
            matches!(&res, Err(Error::Timeout(_))),
            "a bridge that never sends Ready must surface a typed Timeout, got {:?}",
            res.map(|_| "connected")
        );
        assert!(
            elapsed < std::time::Duration::from_secs(1),
            "the connect must be bounded by its caller's {budget:?} deadline, took {elapsed:?}"
        );
    }

    // The prologue half of m10: a bridge that dribbles one byte just under the per-read
    // `connect_ok_read` budget never trips that budget, so before the deadline was
    // propagated the prologue could run `MAX_PROLOGUE_LINE_BYTES` × `connect_ok_read`
    // (~38 s at the defaults) past the caller's timeout.
    // Inverse (await `hybrid_connect_prologue` bare inside the attempt): the call runs
    // for tens of seconds and the wall-clock guard reddens.
    #[tokio::test]
    async fn connect_framed_deadline_bounds_a_dribbling_prologue() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sock = dir.path().join("vsock.sock");
        spawn_mock_bridge(&sock, |mut stream| async move {
            let _line = read_line(&mut stream).await;
            // One byte per 50 ms — never a newline, and never slow enough to trip the
            // 150 ms per-read budget.
            loop {
                if stream.write_all(b"O").await.is_err() {
                    return;
                }
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        });

        let budget = std::time::Duration::from_millis(300);
        let started = std::time::Instant::now();
        let res = StewardClient::connect_framed(
            &VsockEndpoint::Unix {
                path: sock,
                port: 5000,
            },
            budget,
            &crate::config::Timeouts::default(),
            &crate::vmm::FakeSerialLog { panicked: false },
        )
        .await;
        let elapsed = started.elapsed();

        assert!(
            matches!(&res, Err(Error::Timeout(_))),
            "a dribbling bridge must surface a typed Timeout, got {:?}",
            res.map(|_| "connected")
        );
        assert!(
            elapsed < std::time::Duration::from_secs(1),
            "the prologue must be bounded by its caller's {budget:?} deadline, took {elapsed:?}"
        );
    }

    // §3.2 (The host side: StewardClient and SessionMux): the extracted prologue is the ONE
    // implementation of the fragile hybrid handshake, shared by the framed connect and
    // the raw dial. This drives the accept-and-answer path end to end over a real
    // socket pair and asserts BOTH halves of the wire: the exact `CONNECT <port>` line
    // the bridge receives (the dialed port, not the steward's), and that an `OK` line is
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
        let mut client = StewardClient::from_stream_for_tests(client_io);

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

    // §3.2 (The host side: StewardClient and SessionMux): the raw dial's typed interpretation of each
    // refusal signal — the property that makes a dead port an immediate, matchable
    // answer instead of a retry-until-Timeout. Every arm must NAME THE PORT (the
    // error enum has no dedicated no-listener variant, so the message is the only
    // thing that distinguishes it from any other Steward error). RED on a mapping that
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
            matches!(&eof, Error::Steward(m) if m.contains("no guest vsock listener") && m.contains("7000")),
            "EOF before an OK line must be a typed no-listener Steward error naming the port: {eof:?}"
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
            matches!(&refused, Error::Steward(m) if m.contains("7002") && m.contains("ERR nope")),
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

    // §3.2 (The host side: StewardClient and SessionMux): the caller-chosen guest port is spliced into
    // the instance's endpoint in ONE place, and it must reach the transport that
    // actually carries it — the CONNECT line on AF_UNIX, the connect address on
    // AF_VSOCK — while everything else (bridge path, guest CID) is preserved. RED on
    // an override that keeps the steward's port, which would silently dial the control
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
        > = Ok(Err(RequestFailure::Clean(Error::Steward(
            "put_file failed with code 1".into(),
        ))));
        let out = StewardClient::finish_request(&mut desynced, result, "unused");
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
        let out = StewardClient::finish_request(&mut desynced, result, "unused");
        assert!(out.is_err());
        assert!(
            desynced,
            "a transport failure must desync the stream so the next request fails loud"
        );
    }
}
