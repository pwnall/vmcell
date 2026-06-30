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

/// Maximum length, in bytes, of a single framed control-plane message.
///
/// Both ends of the vsock protocol must agree on this bound: the host
/// `AgentClient` configures its `LengthDelimitedCodec` with it (its 8 MiB
/// default would otherwise reject a frame the guest is willing to send) and the
/// guest agent's hand-rolled framing rejects anything larger. Keeping the two in
/// one constant prevents the asymmetric-cap class where one side silently drops
/// a frame the other accepts.
pub const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;

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
}

#[cfg(test)]
mod reaper_tests {
    //! Default-suite (KVM-free) tests for the false-127 reaper coordination.
    //! Each guards a specific documented inverse so the contract cannot silently
    //! regress; see §4.3 / AGENTS.md "PID-1 reaper vs. waiter".
    use super::{ReaperCoordinator, exit_code_from_termination};
    use std::sync::Arc;
    use std::time::Duration;

    #[test]
    fn signal_termination_maps_to_128_plus_signal_not_127() {
        // SIGKILL (9) → 137 by shell convention; SIGTERM (15) → 143. The
        // false-127 bug reported a killed/completed process as the
        // spawn-failure code 127. Inverse `128 + signal` → `127` goes red here.
        assert_eq!(exit_code_from_termination(Some(9), None), 137);
        assert_eq!(exit_code_from_termination(Some(15), None), 143);
        assert_ne!(
            exit_code_from_termination(Some(9), None),
            127,
            "a signal-killed child must never be reported as the spawn-failure 127"
        );
    }

    #[test]
    fn normal_exit_passes_through_status() {
        assert_eq!(exit_code_from_termination(None, Some(0)), 0);
        assert_eq!(exit_code_from_termination(None, Some(42)), 42);
    }

    #[test]
    fn indeterminate_termination_is_one_not_127() {
        // Neither signal nor exit status known: report 1, never 127. Inverse
        // `unwrap_or(1)` → `unwrap_or(127)` goes red here.
        assert_eq!(exit_code_from_termination(None, None), 1);
        assert_ne!(exit_code_from_termination(None, None), 127);
    }

    #[test]
    fn out_of_order_claims_return_each_pids_own_status() {
        let coord = ReaperCoordinator::new();
        coord.record_exit(100, 10);
        coord.record_exit(200, 20);
        coord.record_exit(300, 30);
        // Claim in a different order than recorded; each call gets ITS pid's
        // code, never another's. Inverse (return any recorded status) goes red.
        assert_eq!(coord.wait_for(200), 20);
        assert_eq!(coord.wait_for(100), 10);
        assert_eq!(coord.wait_for(300), 30);
        assert_eq!(coord.pending_statuses(), 0);
    }

    #[test]
    fn blocked_waiter_does_not_steal_another_pids_status() {
        let coord = Arc::new(ReaperCoordinator::new());
        let waiter = {
            let coord = Arc::clone(&coord);
            std::thread::spawn(move || coord.wait_for(42))
        };
        // Let the waiter register and park on pid 42.
        std::thread::sleep(Duration::from_millis(50));

        // Record an UNRELATED pid. A correct waiter must not wake-and-claim it
        // (the false-127 steal). Inverse (wait_for returns the first available
        // status) makes the waiter finish early with 99.
        coord.record_exit(7, 99);
        std::thread::sleep(Duration::from_millis(50));
        assert!(
            !waiter.is_finished(),
            "waiter for pid 42 must not steal pid 7's status"
        );

        // Record the real pid; the waiter claims exactly its own code.
        coord.record_exit(42, 5);
        assert_eq!(waiter.join().unwrap(), 5);
        // pid 7's status was never consumed by the wrong waiter.
        assert_eq!(coord.pending_statuses(), 1);
    }

    #[test]
    fn unclaimed_statuses_are_bounded_by_prune() {
        let coord = ReaperCoordinator::with_max_statuses(4);
        for pid in 0..100u32 {
            coord.record_exit(pid, pid as i32);
        }
        // Inverse (prune removed) leaves all 100 statuses; this asserts the bound.
        assert!(
            coord.pending_statuses() <= 4,
            "unclaimed reaped statuses must be bounded; got {}",
            coord.pending_statuses()
        );
    }

    #[test]
    fn blocked_waiter_survives_unrelated_reap_flood() {
        let coord = Arc::new(ReaperCoordinator::with_max_statuses(2));
        let waiter = {
            let coord = Arc::clone(&coord);
            std::thread::spawn(move || coord.wait_for(999))
        };
        std::thread::sleep(Duration::from_millis(50));

        // Drive many prunes with unrelated reaps while the waiter is parked, then
        // record its own status; it must still be delivered (not lost to prune).
        for pid in 0..50u32 {
            coord.record_exit(pid, 1);
        }
        coord.record_exit(999, 7);
        assert_eq!(waiter.join().unwrap(), 7);
    }
}
