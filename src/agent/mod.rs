//! Guest agent communication and client implementation.
//!
//! This module provides the client code required to communicate with the guest agent
//! running inside the virtual machine.

/// Protocol definition for communication with the guest agent.
pub mod protocol;

// Only the host-side `AgentClient` (host-common) uses these; the always-compiled guest-agent
// path (ReaperCoordinator etc.) must not pull them in, or `--features agent` fails `-D warnings`.
#[cfg(feature = "host-common")]
use crate::error::{Error, Result};
#[cfg(feature = "host-common")]
use protocol::Message;
pub use protocol::{ExecOutcome, ExecRequest};

use std::collections::{HashMap, HashSet};
use std::sync::{Condvar, Mutex};

/// Default upper bound on retained child exit statuses in a [`ReaperCoordinator`].
///
/// As PID 1, the guest agent reaps re-parented grandchildren that no exec
/// waiter will ever claim. Their statuses are pruned once this many newer
/// statuses have been recorded, so the status map cannot grow without bound.
pub const DEFAULT_MAX_REAPED_STATUSES: usize = 1024;

/// Maps a reaped child's termination into the exit code reported to the host.
///
/// A signal-terminated child reports `128 + signal` (shell convention, e.g.
/// `SIGKILL` (9) → 137), a normally-exited child reports its status, and an
/// indeterminate termination reports 1. This is the inverse of the
/// false-127 reaper bug: a process that ran to completion (or was killed)
/// must never be reported with the spawn-failure code 127.
#[must_use]
pub fn exit_code_from_termination(
    terminating_signal: Option<i32>,
    exit_status: Option<i32>,
) -> i32 {
    if let Some(signal) = terminating_signal {
        128 + signal
    } else {
        exit_status.unwrap_or(1)
    }
}

/// Coordinates the PID-1 zombie reaper with per-exec waiter threads.
///
/// The reaper thread records each reaped child's exit code keyed by pid via
/// [`ReaperCoordinator::record_exit`]; an exec waiter blocks in
/// [`ReaperCoordinator::wait_for`] until the status for its pid is recorded and
/// then claims it. A single WNOHANG reaper feeds every waiter, so no waiter can
/// steal another child's status (the false-127 race). Statuses for pids that no
/// waiter ever claims are bounded by a generation-based prune (see
/// [`DEFAULT_MAX_REAPED_STATUSES`]).
#[derive(Debug)]
pub struct ReaperCoordinator {
    inner: Mutex<ReaperInner>,
    available: Condvar,
    max_statuses: usize,
}

#[derive(Debug, Default)]
struct ReaperInner {
    /// `pid -> (exit code, generation at which it was recorded)`.
    statuses: HashMap<u32, (i32, u64)>,
    /// pids an exec waiter is currently blocked on; never pruned out from under
    /// the waiter.
    waiting: HashSet<u32>,
    /// Monotonic record counter used to age out unclaimed statuses.
    generation: u64,
}

impl ReaperCoordinator {
    /// Creates a coordinator with the default status bound.
    #[must_use]
    pub fn new() -> Self {
        Self::with_max_statuses(DEFAULT_MAX_REAPED_STATUSES)
    }

    /// Creates a coordinator retaining at most `max_statuses` unclaimed exit
    /// statuses (clamped to at least 1).
    #[must_use]
    pub fn with_max_statuses(max_statuses: usize) -> Self {
        Self {
            inner: Mutex::new(ReaperInner::default()),
            available: Condvar::new(),
            max_statuses: max_statuses.max(1),
        }
    }

    /// Records a reaped child's `code` for `pid` and wakes any waiter.
    ///
    /// Unclaimed statuses are pruned once `max_statuses` newer statuses have
    /// been recorded, so a flood of re-parented grandchildren cannot grow the
    /// map without bound. A status a waiter is currently blocked on is never
    /// pruned.
    pub fn record_exit(&self, pid: u32, code: i32) {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.generation = inner.generation.wrapping_add(1);
        let generation = inner.generation;
        inner.statuses.insert(pid, (code, generation));

        if inner.statuses.len() > self.max_statuses {
            let max = self.max_statuses as u64;
            let ReaperInner {
                statuses, waiting, ..
            } = &mut *inner;
            statuses.retain(|reaped_pid, (_, recorded)| {
                waiting.contains(reaped_pid) || generation.wrapping_sub(*recorded) < max
            });
        }
        drop(inner);
        self.available.notify_all();
    }

    /// Blocks until the exit status for `pid` is recorded, then claims and
    /// returns it.
    pub fn wait_for(&self, pid: u32) -> i32 {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.waiting.insert(pid);
        loop {
            if let Some((code, _)) = inner.statuses.remove(&pid) {
                inner.waiting.remove(&pid);
                return code;
            }
            inner = self
                .available
                .wait(inner)
                .unwrap_or_else(|e| e.into_inner());
        }
    }

    /// Number of recorded-but-unclaimed exit statuses (for diagnostics/tests).
    #[must_use]
    pub fn pending_statuses(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .statuses
            .len()
    }
}

impl Default for ReaperCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

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
    /// # use imp_testing::agent::AgentClient;
    /// # use std::path::Path;
    /// # use std::time::Duration;
    /// # async fn run() {
    /// let serial = imp_testing::vmm::RealSerialLog { path: std::path::PathBuf::from("/dev/null") };
    /// let client = AgentClient::connect(Path::new("/tmp/vsock"), 5000, Duration::from_secs(10), &serial).await.unwrap();
    /// # }
    /// ```
    pub async fn connect(
        vsock_path: &Path,
        port: u32,
        timeout: std::time::Duration,
        serial_log: &dyn crate::vmm::SerialLog,
    ) -> Result<Self> {
        let deadline = tokio::time::Instant::now() + timeout;
        let mut backoff = std::time::Duration::from_millis(50);

        loop {
            if tokio::time::Instant::now() > deadline {
                return Err(Error::Timeout("Agent connection timed out".into()));
            }

            // Watch serial log for kernel panic
            if serial_log.contains_panic() {
                return Err(Error::Agent("Panic detected in serial log".into()));
            }

            let mut stream = match UnixStream::connect(vsock_path).await {
                Ok(s) => s,
                Err(e) => {
                    tracing::trace!("Agent connect UnixStream::connect failed: {}", e);
                    tokio::time::sleep(backoff).await;
                    backoff = std::cmp::min(backoff * 2, std::time::Duration::from_millis(500));
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
                if let Ok(Ok(1)) = tokio::time::timeout(
                    std::time::Duration::from_millis(500),
                    stream.read(&mut byte),
                )
                .await
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

            let mut framed = Framed::new(stream, LengthDelimitedCodec::new());

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
    ) -> Result<()> {
        let new_client = Self::connect(vsock_path, port, timeout, serial_log).await?;
        self.stream = new_client.stream;
        // A fresh stream is back in sync, so clear any prior desync state.
        self.desynced = false;
        Ok(())
    }

    /// Executes a command inside the guest VM and waits for the result.
    ///
    /// # Errors
    /// Returns an error if the request cannot be sent or the outcome cannot be received.
    pub async fn exec(&mut self, mut cmd: ExecRequest) -> Result<ExecOutcome> {
        if self.desynced {
            return Err(Error::Agent(
                "agent connection desynchronized by a prior timeout; reconnect required".into(),
            ));
        }
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

        match result {
            Ok(Ok(outcome)) => Ok(outcome),
            Ok(Err(e)) => {
                // A send/decode/connection error leaves the framed stream in an
                // unknown state; force a reconnect before the next request.
                self.desynced = true;
                Err(e)
            }
            Err(_) => {
                // Timed out mid-exchange: a late Stdout/Exit frame from this
                // command may still be in flight, so the stream is desynced and
                // must not be reused (it would return stale, wrong results).
                self.desynced = true;
                Err(Error::Timeout("Agent exec timed out".into()))
            }
        }
    }

    /// Uploads a file to the guest VM.
    ///
    /// # Errors
    /// Returns an error if the file transfer fails.
    pub async fn put_file(
        &mut self,
        dst: &str,
        bytes: &[u8],
        timeout: Option<std::time::Duration>,
    ) -> Result<()> {
        tokio::time::timeout(
            timeout.unwrap_or(std::time::Duration::from_secs(10)),
            async {
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
            },
        )
        .await
        .map_err(|_| Error::Timeout("put_file timed out".into()))?
    }
}
