//! Guest agent communication and client implementation (host side).
//!
//! This module provides the host-side `AgentClient` that talks to the guest agent
//! over vsock. The framed wire protocol and the framing bound live in the shared
//! [`vmcell_protocol`] crate; the PID-1 reaper coordination lives in the
//! `vmcell-guest-agent` member crate. Re-exporting the protocol here keeps the
//! public `vmcell::agent::protocol` / `vmcell::{ExecOutcome, ExecRequest}` surface
//! stable across the v15 workspace split (§10.1).

/// The framed wire protocol shared by the host and the guest agent.
pub use vmcell_protocol as protocol;
pub use vmcell_protocol::{ExecOutcome, ExecRequest, MAX_FRAME_BYTES};

#[cfg(feature = "host-common")]
use crate::error::{Error, Result};
#[cfg(feature = "host-common")]
use vmcell_protocol::Message;

#[cfg(feature = "host-common")]
use futures::{SinkExt, StreamExt};
#[cfg(feature = "host-common")]
use std::path::Path;
#[cfg(feature = "host-common")]
use tokio::io::AsyncWriteExt;
#[cfg(feature = "host-common")]
use tokio::net::UnixStream;
#[cfg(feature = "host-common")]
use tokio_util::codec::{Framed, LengthDelimitedCodec};

/// The per-step outcome of a native post-restore [`AgentClient::resync`]
/// (design 44 §5).
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
}

#[cfg(feature = "host-common")]
/// A client for communicating with the guest agent over vsock.
#[derive(Debug)]
pub struct AgentClient {
    stream: Framed<UnixStream, LengthDelimitedCodec>,
    /// Set when a request times out or the framed stream desynchronizes
    /// mid-exchange. A desynced stream may still hold a late frame from the
    /// abandoned request, so reusing it would read stale data and silently
    /// return a wrong result. Further requests fail loud until
    /// [`AgentClient::reconnect`] re-establishes the stream.
    desynced: bool,
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
        let deadline = tokio::time::Instant::now() + timeout;
        // Poll floor while the VMM host-side socket is still absent. Kept small
        // because a failed local AF_UNIX connect is cheap, so a tighter cadence
        // narrows the gap between "guest became ready" and "host noticed" without
        // busy-spinning (the deadline + panic checks still run every iteration).
        let mut backoff = timeouts.connect_backoff_floor;

        loop {
            if tokio::time::Instant::now() > deadline {
                return Err(Error::Timeout("Agent connection timed out".into()));
            }

            // Watch serial log for kernel panic
            if serial_log.contains_panic() {
                return Err(Error::Agent("Panic detected in serial log".into()));
            }

            let mut stream = match UnixStream::connect(vsock_path).await {
                Ok(s) => {
                    // The VMM's host-side vsock socket is up, so we are now in the
                    // "guest still booting / not yet listening" regime, where the
                    // right cadence is a tight fixed poll — not the exponential
                    // backoff that only makes sense while the socket was absent.
                    // Reset to the floor so a few socket-absent iterations can't
                    // inflate the guest-ready detection gap (EXP-HOST-BACKOFF-RESET).
                    backoff = timeouts.connect_backoff_floor;
                    s
                }
                Err(e) => {
                    tracing::trace!("Agent connect UnixStream::connect failed: {}", e);
                    tokio::time::sleep(backoff).await;
                    backoff = std::cmp::min(backoff * 2, timeouts.connect_backoff_cap);
                    continue;
                }
            };

            let connect_msg = format!("CONNECT {}\n", port);
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
                    return Ok(Self {
                        stream: framed,
                        desynced: false,
                    });
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
            stream: Framed::new(stream, codec),
            desynced: false,
        }
    }

    /// Reconnects to the guest agent.
    ///
    /// # Errors
    /// Returns an error if the connection fails or times out.
    pub async fn reconnect(
        &mut self,
        vsock_path: &Path,
        port: u32,
        serial_log: &dyn crate::vmm::SerialLog,
        timeout: std::time::Duration,
        timeouts: &crate::config::Timeouts,
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
    /// on any send/decode error or timeout.
    ///
    /// A send/decode/connection error or a mid-exchange timeout leaves the framed
    /// stream in an unknown state (a late frame may still be in flight), so the
    /// next request must fail loud via [`AgentClient::ensure_synced`] until a
    /// [`AgentClient::reconnect`]. Shared by every request method so none can
    /// diverge from this protocol.
    fn finish_request<T>(
        desynced: &mut bool,
        result: std::result::Result<Result<T>, tokio::time::error::Elapsed>,
        timeout_msg: &'static str,
    ) -> Result<T> {
        match result {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(e)) => {
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
            let bytes = postcard::to_stdvec(&msg)?;

            self.stream
                .send(::bytes::Bytes::from(bytes))
                .await
                .map_err(Error::Io)?;

            let mut outcome = ExecOutcome::default();

            while let Some(res) = self.stream.next().await {
                let bytes: ::bytes::BytesMut = res.map_err(Error::Io)?;
                let msg: Message = postcard::from_bytes(&bytes)?;

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
                    _ => {}
                }
            }

            // If stream ends without Exit, treat it as connection drop
            Err(Error::Agent("Connection dropped during exec".into()))
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
            let msg_bytes = postcard::to_stdvec(&msg)?;
            self.stream
                .send(::bytes::Bytes::from(msg_bytes))
                .await
                .map_err(Error::Io)?;

            // Wait for ack
            if let Some(res) = self.stream.next().await {
                let res_bytes: ::bytes::BytesMut = res.map_err(Error::Io)?;
                let resp_msg: Message = postcard::from_bytes(&res_bytes)?;
                match resp_msg {
                    Message::Exit(0) => Ok(()),
                    Message::Exit(c) => {
                        Err(Error::Agent(format!("put_file failed with code {}", c)))
                    }
                    _ => Err(Error::Agent("unexpected response to put_file".into())),
                }
            } else {
                Err(Error::Agent("connection closed during put_file".into()))
            }
        })
        .await;

        Self::finish_request(&mut self.desynced, result, "put_file timed out")
    }

    /// Performs the one-shot native post-restore resync (design 44 §5): sets the
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
    ) -> Result<ResyncOutcome> {
        self.ensure_synced()?;
        let result = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            let msg = Message::Resync {
                unix_secs,
                unix_nanos,
                mac,
            };
            let msg_bytes = postcard::to_stdvec(&msg)?;
            self.stream
                .send(::bytes::Bytes::from(msg_bytes))
                .await
                .map_err(Error::Io)?;

            // Await exactly one ack frame.
            if let Some(res) = self.stream.next().await {
                let res_bytes: ::bytes::BytesMut = res.map_err(Error::Io)?;
                let resp_msg: Message = postcard::from_bytes(&res_bytes)?;
                match resp_msg {
                    Message::ResyncAck {
                        clock_error,
                        reseed_applied,
                        mac_applied,
                    } => Ok(ResyncOutcome {
                        clock_error,
                        reseed_applied,
                        mac_applied,
                    }),
                    _ => Err(Error::Agent("unexpected response to resync".into())),
                }
            } else {
                Err(Error::Agent("connection closed during resync".into()))
            }
        })
        .await;

        Self::finish_request(&mut self.desynced, result, "resync timed out")
    }
}
