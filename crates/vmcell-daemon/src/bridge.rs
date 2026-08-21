//! The setup-broker bridge — the privilege-separated `vmcelld` cutover (design §12.4, Layer 3 — the setup broker (network surface never holds caps)).
//!
//! `setns(CLONE_NEWNET)` needs `CAP_SYS_ADMIN` in the netns's owning user namespace, so an
//! unprivileged process can never perform the privileged VM operations (netns/tap/nft/cgroup +
//! the jailed VMM spawn). The cutover therefore forks a **broker child** that keeps the three caps
//! and **owns the [`Registry`]**, and drops **all** caps in the **parent** that serves the
//! network-facing HTTP API. The parent forwards every VM operation to the broker over a framed,
//! multiplexed RPC on the `socketpair`; a bug in the HTTP request parser can no longer reach the
//! caps, and the cap-holder never parses attacker-controlled network input (§12.4, Layer 3 — the setup broker (network surface never holds caps)).
//!
//! Artifact CRUD is **not** here: it is unprivileged file I/O under `--artifacts-dir` (same uid),
//! so the parent does it directly against its own [`ArtifactStore`](crate::artifact_store::ArtifactStore); only the delete-in-use guard
//! (which needs the live VM table) crosses to the broker — as the atomic
//! [`VmEngine::delete_artifact_if_unused`] (the check + delete under one `vms`-lock hold);
//! [`VmEngine::is_artifact_in_use`] is the read-only query variant sharing the same predicate.
//!
//! The RPC is multiplexed (each request carries a `u64` id; a background reader matches replies to
//! per-request `oneshot`s), so a long-running `exec` on one VM does not block ops on another — the
//! per-VM concurrency the [`Registry`] provides is preserved across the process boundary.

use crate::dto::{
    CreateVmRequest, CreateVmResponse, ErrorKind, ExecOutcomeDto, ExecRequestDto, ResourceUsageDto,
    SnapshotInfo, VmId, VmInfo,
};
use crate::error::{DaemonError, DaemonResult};
use crate::registry::Registry;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{Mutex, oneshot};

/// The bridge RPC frame cap. Generous because an `exec` reply carries the guest command's full
/// captured stdout/stderr; enforced before allocation on both ends (the internal channel is
/// trusted, but a corrupt length prefix must still not drive an unbounded allocation).
pub const MAX_BRIDGE_FRAME_BYTES: usize = 256 * 1024 * 1024;

/// What [`MAX_EXEC_CAPTURE_B64_BYTES`] holds back from [`MAX_BRIDGE_FRAME_BYTES`] for everything in
/// a capture-carrying reply that is **not** the capture: the 2-tuple, the `EngineReply` variant tag,
/// `ExecOutcomeDto`'s field names and `code`, and — on the `create` path — the whole [`VmInfo`],
/// whose `kernel`/`rootfs` are client-named artifacts bounded by `name::MAX_ARTIFACT_NAME_LEN`.
///
/// Far over the real envelope, because the slack costs a rounding error of the capture budget while
/// under-reserving costs the wedge class this ceiling exists to remove. The figure is not quoted
/// here — `capture_ceiling_tests::the_reserve_covers_the_real_reply_envelope` **measures** the
/// shipped envelope against this reserve, and prints it when it reddens.
const EXEC_REPLY_ENVELOPE_RESERVE: usize = 64 * 1024;

/// The ceiling on the **base64** capture one reply may carry — the exact quantity the frame cap
/// constrains, so the comparison in [`enforce_exec_capture_ceiling`] needs no rounding.
const MAX_EXEC_CAPTURE_B64_BYTES: usize = MAX_BRIDGE_FRAME_BYTES - EXEC_REPLY_ENVELOPE_RESERVE;

/// The one ceiling on a guest `exec` capture: the largest **raw** stdout+stderr an exec-carrying
/// reply may return, in bytes (design §17, Open gaps and future capabilities — "capping the guest
/// exec capture host-side").
///
/// **Derived, never a literal.** `stdout`/`stderr` cross the bridge base64'd (`ExecOutcomeDto`), so
/// the raw budget is the frame budget less the envelope reserve, times 3/4. Re-tuning
/// [`MAX_BRIDGE_FRAME_BYTES`] moves this with it, and
/// `capture_ceiling_tests::the_reserve_covers_the_real_reply_envelope` reddens if the derivation
/// stops fitting.
///
/// **Why a ceiling at all.** Without one, a command that captures more than the frame holds produced
/// a reply that the frame writer refused, which the reply-write fallback degrades into a typed 500 —
/// better than the hang it replaced, but it reads as a server bug when the truth is a client-side
/// quantity the client can act on. With it, the same run is a 413 naming the size, the ceiling and
/// the remedy.
///
/// **Refuse, not truncate.** A truncated capture the client cannot detect is the accepted-but-ignored
/// hazard (AGENTS.md, the `curl` shim): every downstream assertion on those bytes — a digest, a
/// parse, an exit-code-plus-output pair — silently reads a prefix as the whole. Flagging the
/// truncation instead would mean a new presence-attribute field on [`ExecOutcomeDto`], which is
/// single-sourced with `vmcell-daemon-client` and travels this JSON channel precisely because
/// `#[serde(skip_serializing_if)]` fields do not survive a non-self-describing codec (Appendix A
/// reversal 10) — a wire change owed to every consumer, for an outcome that is still lossy. A
/// refusal is lossless: the capture stays in the guest, and the command re-runs redirecting to a
/// file the client fetches.
pub const MAX_EXEC_CAPTURE_BYTES: usize = MAX_EXEC_CAPTURE_B64_BYTES / 4 * 3;

/// The one exec-capture ceiling check, applied by **every** reply that can carry a capture — the
/// `exec` verb and the inline `command` of `create` (a ceiling honored on one of the two verbs that
/// return an `ExecOutcomeDto` is not a ceiling).
///
/// It lives in the broker-side engine adapter rather than in [`dispatch`] or [`write_reply`] for two
/// reasons. The adapter is the one place both deployments pass through — the broker child's engine
/// **and** the single-process daemon's engine are this same `impl` — so the client sees one limit
/// whether or not the operator ran the cutover, instead of a limit that depends on the transport.
/// And it is the last point where the *cause* is still legible: by [`write_reply`] all that is left
/// is a byte count, indistinguishable from a broker that cannot serialize.
///
/// `context` names the operation and its VM so the reply is actionable: on the `create` path the VM
/// has already been created, and the refusal does not change its state.
///
/// # Errors
/// [`DaemonError::PayloadTooLarge`] — a 413 through the single [`DaemonError`] status mapping (the
/// same one the artifact-upload cap uses; no second mapping is introduced).
fn enforce_exec_capture_ceiling(context: &str, outcome: &ExecOutcomeDto) -> DaemonResult<()> {
    let encoded = outcome.stdout_b64.len() + outcome.stderr_b64.len();
    if encoded <= MAX_EXEC_CAPTURE_B64_BYTES {
        return Ok(());
    }
    // base64 is 4 characters per 3 bytes; `/ 4 * 3` is the raw size to within the two streams'
    // padding, which is why the figure is reported as approximate rather than exact.
    let captured = encoded / 4 * 3;
    Err(DaemonError::PayloadTooLarge(format!(
        "{context}: the command captured ~{captured} bytes of stdout+stderr, over the \
         {MAX_EXEC_CAPTURE_BYTES}-byte exec-capture ceiling (the {MAX_BRIDGE_FRAME_BYTES}-byte \
         bridge frame less its envelope reserve). The capture is refused rather than silently \
         truncated: re-run the command redirecting its output to a file in the guest and fetch \
         that file. The VM's own state is unchanged by this refusal."
    )))
}

/// How long a `ShutdownAll` waits for the dispatch jobs already in flight before the broker stops
/// serving (finding `shutdown-all-returns-while-dispatch-jobs-run`).
///
/// A `create` job that has launched its VMM but not yet inserted the slot is in **nobody's** table:
/// `Registry::shutdown_all` walks the table only, and `run_broker_child` `_exit`s the moment
/// [`serve_engine`] returns. Without this drain the VMM survives as an orphan pinning guest RAM and
/// `/dev/kvm` — on the **graceful** path, the one the broker's `SIG_IGN` design exists to let win.
/// Generous because the job being waited on is a whole VM boot; bounded because a wedged job must
/// never stop the daemon from exiting.
const SHUTDOWN_DRAIN_BUDGET: Duration = Duration::from_secs(60);

/// The parent-side ceiling on one forwarded **control** call (no guest work: list/get/stats and the
/// artifact guards). Bounds a *stalled* broker — one that is alive but not replying — which the
/// EOF drain in [`BrokerClientEngine::new`] cannot see because the socket never closes.
const BROKER_CONTROL_CALL_BUDGET: Duration = Duration::from_secs(60);

/// The parent-side ceiling on one forwarded **VM-lifecycle** call (create/exec/snapshot/destroy/
/// shutdown-all). Far larger than the control budget because these run real guest work — a boot, a
/// guest command, a guest-RAM-proportional snapshot write — and a legitimate slow op must not be
/// mistaken for a stall. It is the *floor* for an `exec`, never its ceiling — see [`call_budget`].
const BROKER_VM_CALL_BUDGET: Duration = Duration::from_secs(900);

/// How far an `exec`'s bridge budget must exceed the guest timeout the client asked for, so the
/// **guest's** timeout is always the one that fires: it covers the vsock round-trip, the guest-side
/// kill + output capture, and writing a reply that can carry the whole capture back.
const EXEC_BUDGET_MARGIN: Duration = Duration::from_secs(60);

/// The fallback horizon when `now + budget` would overflow the monotonic clock — reachable because
/// `ExecRequestDto::timeout_secs` is a client-supplied `u64` and `Instant + Duration` **panics** on
/// overflow (a client-triggered panic in the cap-dropped parent is a denial of service). A year is
/// past any real exec and inside tokio's timer range; a broker that dies is still covered by the
/// reader task's EOF drain, which needs no deadline at all.
const CALL_DEADLINE_HORIZON: Duration = Duration::from_secs(365 * 24 * 60 * 60);

// ---------------------------------------------------------------------------------------------
// The engine seam the HTTP handlers call — implemented locally by `Registry` (broker side) and by
// the forwarding `BrokerClientEngine` (parent side).
// ---------------------------------------------------------------------------------------------

/// The VM operations the daemon's HTTP handlers drive. In the broker cutover the handlers hold an
/// `Arc<dyn VmEngine>` that is a [`BrokerClientEngine`] (forwarding to the capped broker); in a
/// single-process daemon it is the [`Registry`] directly.
#[async_trait]
pub trait VmEngine: Send + Sync {
    /// Creates (and optionally execs/tears down) a VM.
    async fn create(&self, req: CreateVmRequest) -> DaemonResult<CreateVmResponse>;
    /// Lists every owned VM.
    async fn list(&self) -> DaemonResult<Vec<VmInfo>>;
    /// Reads one VM's info.
    async fn get(&self, id: &VmId) -> DaemonResult<VmInfo>;
    /// Runs a command in a `Ready` VM.
    async fn exec(&self, id: &VmId, req: ExecRequestDto) -> DaemonResult<ExecOutcomeDto>;
    /// Samples a VM's resource usage.
    async fn stats(&self, id: &VmId) -> DaemonResult<ResourceUsageDto>;
    /// Pauses a `Ready` VM's vCPUs, returning its updated info.
    async fn pause(&self, id: &VmId) -> DaemonResult<VmInfo>;
    /// Resumes a `Paused` VM's vCPUs, returning its updated info.
    async fn resume(&self, id: &VmId) -> DaemonResult<VmInfo>;
    /// Writes a warm snapshot into the store under `prefix/`.
    async fn snapshot(&self, id: &VmId, prefix: &str) -> DaemonResult<SnapshotInfo>;
    /// Destroys a VM (graceful ordered teardown).
    async fn destroy(&self, id: &VmId) -> DaemonResult<()>;
    /// Whether any live VM pins `name` (the delete-in-use guard).
    async fn is_artifact_in_use(&self, name: &str) -> DaemonResult<bool>;
    /// Atomically deletes an artifact iff no live VM pins it — the delete-in-use guard and the file
    /// delete run under one hold of the VM-table lock, closing the check-then-delete TOCTOU against
    /// a concurrent `create`. The engine owns both the VM table and the store, so this stays on the
    /// engine side (the parent's own `state.artifacts` points at the same dir).
    async fn delete_artifact_if_unused(&self, name: &str) -> DaemonResult<()>;
    /// Graceful ordered teardown of every VM (clean shutdown).
    async fn shutdown_all(&self);
}

#[async_trait]
impl VmEngine for Registry {
    async fn create(&self, req: CreateVmRequest) -> DaemonResult<CreateVmResponse> {
        let c = Registry::create(self, req).await?;
        if let Some(outcome) = c.exec.as_ref() {
            enforce_exec_capture_ceiling(
                &format!("the inline command in vm {}", c.info.id.0),
                outcome,
            )?;
        }
        Ok(CreateVmResponse {
            vm: c.info,
            exec: c.exec,
        })
    }
    async fn list(&self) -> DaemonResult<Vec<VmInfo>> {
        Ok(Registry::list(self).await)
    }
    async fn get(&self, id: &VmId) -> DaemonResult<VmInfo> {
        Registry::get(self, id).await
    }
    async fn exec(&self, id: &VmId, req: ExecRequestDto) -> DaemonResult<ExecOutcomeDto> {
        let outcome = Registry::exec(self, id, req).await?;
        enforce_exec_capture_ceiling(&format!("exec in vm {}", id.0), &outcome)?;
        Ok(outcome)
    }
    async fn stats(&self, id: &VmId) -> DaemonResult<ResourceUsageDto> {
        Registry::stats(self, id).await
    }
    async fn pause(&self, id: &VmId) -> DaemonResult<VmInfo> {
        Registry::pause(self, id).await
    }
    async fn resume(&self, id: &VmId) -> DaemonResult<VmInfo> {
        Registry::resume(self, id).await
    }
    async fn snapshot(&self, id: &VmId, prefix: &str) -> DaemonResult<SnapshotInfo> {
        Registry::snapshot(self, id, prefix).await
    }
    async fn destroy(&self, id: &VmId) -> DaemonResult<()> {
        Registry::destroy(self, id).await
    }
    async fn is_artifact_in_use(&self, name: &str) -> DaemonResult<bool> {
        Ok(Registry::is_artifact_in_use(self, name).await)
    }
    async fn delete_artifact_if_unused(&self, name: &str) -> DaemonResult<()> {
        Registry::delete_artifact_if_unused(self, name).await
    }
    async fn shutdown_all(&self) {
        Registry::shutdown_all(self).await;
    }
}

// ---------------------------------------------------------------------------------------------
// Wire protocol
// ---------------------------------------------------------------------------------------------

/// A serializable image of a [`DaemonError`] — carries the matchable [`ErrorKind`] (hence the HTTP
/// status) and the human message, so the error round-trips the broker boundary with its status
/// intact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireError {
    /// The error kind (determines the HTTP status).
    pub kind: ErrorKind,
    /// The human-readable message.
    pub message: String,
}

impl From<&DaemonError> for WireError {
    fn from(e: &DaemonError) -> Self {
        Self {
            kind: e.kind(),
            message: e.message(),
        }
    }
}

/// Reconstructs a [`DaemonError`] from its wire image, preserving the HTTP status. `InvalidName`
/// maps to `BadRequest` (both 400; the exact matchable variant is not needed across the boundary —
/// only the status + message reach the HTTP client).
#[must_use]
pub fn daemon_error_from_wire(w: WireError) -> DaemonError {
    match w.kind {
        ErrorKind::NotFound => DaemonError::NotFound(w.message),
        ErrorKind::AlreadyExists => DaemonError::AlreadyExists(w.message),
        ErrorKind::InUse => DaemonError::InUse(w.message),
        ErrorKind::Conflict => DaemonError::Conflict(w.message),
        ErrorKind::InvalidName | ErrorKind::BadRequest => DaemonError::BadRequest(w.message),
        ErrorKind::Unauthorized => DaemonError::Unauthorized(w.message),
        ErrorKind::Forbidden => DaemonError::Forbidden(w.message),
        ErrorKind::Unsupported => DaemonError::Unsupported(w.message),
        ErrorKind::PayloadTooLarge => DaemonError::PayloadTooLarge(w.message),
        ErrorKind::Internal => DaemonError::Internal(w.message),
    }
}

/// A VM operation forwarded from the parent to the broker.
#[derive(Debug, Serialize, Deserialize)]
enum EngineRequest {
    Create(CreateVmRequest),
    List,
    Get(VmId),
    Exec(VmId, ExecRequestDto),
    Stats(VmId),
    Pause(VmId),
    Resume(VmId),
    Snapshot(VmId, String),
    Destroy(VmId),
    IsArtifactInUse(String),
    DeleteArtifactIfUnused(String),
    ShutdownAll,
}

/// The broker's reply.
#[derive(Debug, Serialize, Deserialize)]
enum EngineReply {
    Created(CreateVmResponse),
    List(Vec<VmInfo>),
    Info(VmInfo),
    Exec(ExecOutcomeDto),
    Stats(ResourceUsageDto),
    Snapshot(SnapshotInfo),
    Destroyed,
    InUse(bool),
    ArtifactDeleted,
    ShutdownAllDone,
    Err(WireError),
}

/// Fuzz-only entry point onto the REQUEST decode [`serve_engine`] performs (non-default `fuzzing`
/// feature; see the feature's stanza in `Cargo.toml`). `frame` is one already-de-framed payload —
/// the bytes `read_frame` hands to `serde_json` after enforcing [`MAX_BRIDGE_FRAME_BYTES`].
///
/// `None` means the frame did not decode (the ordinary, expected outcome for arbitrary bytes; the
/// serve loop answers it with a typed `Err` reply). `Some` carries `(re-serialized bytes, the
/// decoded value's `Debug` render)`, so a caller can assert the presence-attribute round-trip the
/// forwarded DTOs need (`#[serde(skip_serializing_if)]` / `default`, Appendix A reversal 10)
/// without the private `EngineRequest` ever being nameable outside this crate. The `Debug` render is
/// what carries the VALUE across the boundary: comparing only the re-serialized bytes would miss a
/// field dropped on the FIRST encode, since the second encode drops it identically. An inner `Err`
/// is a value that decoded but will not re-encode — a finding, not an expected outcome.
#[cfg(feature = "fuzzing")]
#[must_use]
pub fn fuzz_decode_engine_request(frame: &[u8]) -> Option<serde_json::Result<(Vec<u8>, String)>> {
    let decoded = serde_json::from_slice::<(u64, EngineRequest)>(frame).ok()?;
    let rendered = format!("{decoded:?}");
    Some(serde_json::to_vec(&decoded).map(|bytes| (bytes, rendered)))
}

/// Fuzz-only entry point onto the REPLY decode the parent's reader task performs
/// ([`BrokerClientEngine::with_call_budget`]'s loop). Same shape and same round-trip contract as
/// [`fuzz_decode_engine_request`]; this is the downward direction (cap-holding child → cap-dropped
/// parent), which the request-side target does not cover.
#[cfg(feature = "fuzzing")]
#[must_use]
pub fn fuzz_decode_engine_reply(frame: &[u8]) -> Option<serde_json::Result<(Vec<u8>, String)>> {
    let decoded = serde_json::from_slice::<(u64, EngineReply)>(frame).ok()?;
    let rendered = format!("{decoded:?}");
    Some(serde_json::to_vec(&decoded).map(|bytes| (bytes, rendered)))
}

// ---------------------------------------------------------------------------------------------
// Framed async codec (length-prefixed JSON; over-cap rejected before allocation). JSON (not a
// non-self-describing format like postcard) because the reused DTOs carry `#[serde(skip_serializing_if)]`
// / `default` fields that only round-trip correctly in a self-describing format — and it is the same
// format the HTTP API itself speaks.
// ---------------------------------------------------------------------------------------------

/// The one write-side frame-length law: `payload`'s 4-byte big-endian length prefix, or an error if
/// it is over [`MAX_BRIDGE_FRAME_BYTES`]. [`write_frame`] and the pre-write check in
/// [`BrokerClientEngine::send_request`] both go through it, so the cap is stated once and an
/// over-cap payload is knowably rejected **before** any byte reaches the stream.
fn frame_len_prefix(payload: &[u8]) -> std::io::Result<[u8; 4]> {
    u32::try_from(payload.len())
        .ok()
        .filter(|_| payload.len() <= MAX_BRIDGE_FRAME_BYTES)
        .map(u32::to_be_bytes)
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "bridge frame {} exceeds cap {MAX_BRIDGE_FRAME_BYTES}",
                    payload.len()
                ),
            )
        })
}

async fn write_frame<W: AsyncWriteExt + Unpin>(w: &mut W, payload: &[u8]) -> std::io::Result<()> {
    let len = frame_len_prefix(payload)?;
    w.write_all(&len).await?;
    w.write_all(payload).await?;
    w.flush().await
}

async fn read_frame<R: AsyncReadExt + Unpin>(r: &mut R) -> std::io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_BRIDGE_FRAME_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("bridge frame length {len} exceeds cap {MAX_BRIDGE_FRAME_BYTES}"),
        ));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await?;
    Ok(buf)
}

// ---------------------------------------------------------------------------------------------
// Broker side: serve the engine over the socket
// ---------------------------------------------------------------------------------------------

async fn dispatch(engine: &dyn VmEngine, req: EngineRequest) -> EngineReply {
    let err = |e: &DaemonError| EngineReply::Err(WireError::from(e));
    match req {
        EngineRequest::Create(r) => match engine.create(r).await {
            Ok(v) => EngineReply::Created(v),
            Err(e) => err(&e),
        },
        EngineRequest::List => match engine.list().await {
            Ok(v) => EngineReply::List(v),
            Err(e) => err(&e),
        },
        EngineRequest::Get(id) => match engine.get(&id).await {
            Ok(v) => EngineReply::Info(v),
            Err(e) => err(&e),
        },
        EngineRequest::Exec(id, r) => match engine.exec(&id, r).await {
            Ok(v) => EngineReply::Exec(v),
            Err(e) => err(&e),
        },
        EngineRequest::Stats(id) => match engine.stats(&id).await {
            Ok(v) => EngineReply::Stats(v),
            Err(e) => err(&e),
        },
        // Both vCPU verbs answer with `Info` — the VM's state after the move — so a client reads the
        // state it reached rather than assuming it.
        EngineRequest::Pause(id) => match engine.pause(&id).await {
            Ok(v) => EngineReply::Info(v),
            Err(e) => err(&e),
        },
        EngineRequest::Resume(id) => match engine.resume(&id).await {
            Ok(v) => EngineReply::Info(v),
            Err(e) => err(&e),
        },
        EngineRequest::Snapshot(id, prefix) => match engine.snapshot(&id, &prefix).await {
            Ok(v) => EngineReply::Snapshot(v),
            Err(e) => err(&e),
        },
        EngineRequest::Destroy(id) => match engine.destroy(&id).await {
            Ok(()) => EngineReply::Destroyed,
            Err(e) => err(&e),
        },
        EngineRequest::IsArtifactInUse(name) => match engine.is_artifact_in_use(&name).await {
            Ok(v) => EngineReply::InUse(v),
            Err(e) => err(&e),
        },
        EngineRequest::DeleteArtifactIfUnused(name) => {
            match engine.delete_artifact_if_unused(&name).await {
                Ok(()) => EngineReply::ArtifactDeleted,
                Err(e) => err(&e),
            }
        }
        EngineRequest::ShutdownAll => {
            engine.shutdown_all().await;
            EngineReply::ShutdownAllDone
        }
    }
}

/// Writes one reply frame for request `id`, **degrading a reply that cannot be sent as-is into a
/// compact typed `Err` frame for the same id** rather than dropping it (M8,
/// `bridge-reply-drop-wedges-request`). Two failures are reachable: `serde_json` refusing the value,
/// and a payload over [`MAX_BRIDGE_FRAME_BYTES`] — an `exec` reply carries the guest command's whole
/// captured output. The parent's `rx.await` has no timeout, so a dropped reply wedges that HTTP
/// request **forever**; the fallback turns it into a `DaemonError::Internal` (500).
///
/// This stays the **backstop**, not the capture's ceiling: [`enforce_exec_capture_ceiling`] refuses
/// an oversized capture upstream with a typed, explained 413, so what still reaches here is a reply
/// that is over the cap for some *other* reason — where "the broker could not send its reply" is
/// the honest description and a 500 the honest status.
///
/// Encoding happens outside the write lock so a large reply does not serialize the multiplex.
async fn write_reply<W: AsyncWriteExt + Unpin>(wr: &Mutex<W>, id: u64, reply: EngineReply) {
    let sent = match serde_json::to_vec(&(id, reply)) {
        Ok(bytes) => {
            let mut w = wr.lock().await;
            write_frame(&mut *w, &bytes)
                .await
                .map_err(|e| format!("broker reply could not be written: {e}"))
        }
        Err(e) => Err(format!("broker reply could not be encoded: {e}")),
    };
    let Err(reason) = sent else { return };
    tracing::warn!(
        id,
        "broker: {reason}; replying with a typed internal error instead"
    );
    let fallback = EngineReply::Err(WireError {
        kind: ErrorKind::Internal,
        message: reason,
    });
    match serde_json::to_vec(&(id, fallback)) {
        Ok(bytes) => {
            let mut w = wr.lock().await;
            // The fallback frame is a few hundred bytes, so this write can only fail on a dead
            // socket — the parent is gone, and its reply reader already fails every in-flight
            // request on EOF, so there is no request left to wedge. Dropping it here is terminal.
            #[expect(
                clippy::let_underscore_must_use,
                reason = "terminal by construction: this write can only fail on a dead socket, whose EOF already failed every in-flight request"
            )]
            let _ = write_frame(&mut *w, &bytes).await;
        }
        // Unreachable in practice (an enum around two owned `String`s always encodes), but logged
        // rather than dropped so it can never become an invisible wedge.
        Err(e) => tracing::error!(id, "broker: cannot encode the fallback error frame: {e}"),
    }
}

/// Awaits every still-running dispatch job, bounded by `budget` measured from **now** (one deadline
/// for the whole drain, not one per job).
///
/// A job that is still running at the deadline is left detached and **named in a warning** — the
/// alternative, aborting it, is precisely the orphan the drain exists to prevent (a `create` killed
/// between `launch` and `insert` leaves the VMM behind).
async fn drain_dispatch_jobs(jobs: Vec<tokio::task::JoinHandle<()>>, budget: Duration) {
    if jobs.is_empty() {
        return;
    }
    let total = jobs.len();
    let deadline = tokio::time::Instant::now() + budget;
    let mut unfinished = 0usize;
    for job in jobs {
        match tokio::time::timeout_at(deadline, job).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => tracing::warn!("broker: a dispatch job did not complete cleanly: {e}"),
            Err(_) => unfinished += 1,
        }
    }
    if unfinished > 0 {
        tracing::warn!(
            total,
            unfinished,
            ?budget,
            "broker: dispatch jobs still running at the shutdown-drain deadline; VMs they were \
             starting may survive as orphans until the next start-up sweep"
        );
    }
}

/// Serves `engine` over `sock` until the peer closes it or a `ShutdownAll` is handled (after which
/// the broker returns so its caller can `_exit`). Each request is dispatched on its own task so a
/// long `exec` does not block other VMs' ops; replies carry the request id and are written behind a
/// shared write lock. Runs in the **broker** child (which holds the caps and owns the registry).
///
/// Both exits — the `ShutdownAll` and the peer-closed EOF — first **drain the dispatch jobs in
/// flight** (bounded by `SHUTDOWN_DRAIN_BUDGET`), so a `create` that is between
/// `MicroVmLauncher::launch` and the registry insert finishes and becomes visible to `shutdown_all`
/// / the registry `Drop` instead of leaving an orphaned VMM behind
/// (finding `shutdown-all-returns-while-dispatch-jobs-run`).
pub async fn serve_engine(engine: Arc<dyn VmEngine>, sock: tokio::net::UnixStream) {
    let (mut rd, wr) = sock.into_split();
    let wr = Arc::new(Mutex::new(wr));
    let mut jobs: Vec<tokio::task::JoinHandle<()>> = Vec::new();
    loop {
        let frame = match read_frame(&mut rd).await {
            Ok(f) => f,
            // Parent closed the channel (shutdown / crash): stop serving, after the drain below.
            Err(_) => break,
        };
        let (id, req) = match serde_json::from_slice::<(u64, EngineRequest)>(&frame) {
            Ok(v) => v,
            Err(e) => {
                // Mirror `write_reply`'s reply-side fallback: the parent's `call` is waiting on
                // this frame's id, so an undecodable request is answered with a typed `Err` for
                // that id rather than dropped (finding `serve-engine-drops-undecodable-requests`).
                // The id is the tuple's first element, so a permissive decode recovers it.
                match serde_json::from_slice::<(u64, serde_json::Value)>(&frame) {
                    Ok((id, _)) => {
                        tracing::warn!(id, "broker: undecodable request frame: {e}");
                        write_reply(
                            wr.as_ref(),
                            id,
                            EngineReply::Err(WireError {
                                kind: ErrorKind::Internal,
                                message: format!("broker could not decode the request: {e}"),
                            }),
                        )
                        .await;
                    }
                    // No id to answer to: nothing can be waiting on a frame we cannot identify.
                    Err(_) => tracing::warn!(
                        "broker: dropping an undecodable request frame with no recoverable id: {e}"
                    ),
                }
                continue;
            }
        };
        let shutdown = matches!(req, EngineRequest::ShutdownAll);
        let engine = engine.clone();
        let wr = wr.clone();
        let job = async move {
            let reply = dispatch(engine.as_ref(), req).await;
            write_reply(wr.as_ref(), id, reply).await;
        };
        if shutdown {
            // Drain FIRST: `shutdown_all` must see every VM an in-flight `create` is registering.
            drain_dispatch_jobs(std::mem::take(&mut jobs), SHUTDOWN_DRAIN_BUDGET).await;
            // Then run the shutdown inline (so its reply is written) and stop serving.
            job.await;
            return;
        }
        // Reap the handles of jobs that already finished, so a long-lived broker's list does not
        // grow without bound.
        jobs.retain(|h| !h.is_finished());
        jobs.push(tokio::spawn(job));
    }
    drain_dispatch_jobs(jobs, SHUTDOWN_DRAIN_BUDGET).await;
}

// ---------------------------------------------------------------------------------------------
// Parent side: the forwarding engine (multiplexed RPC client)
// ---------------------------------------------------------------------------------------------

type Pending = Arc<std::sync::Mutex<HashMap<u64, oneshot::Sender<EngineReply>>>>;

/// The per-request budget for a forwarded call — ONE pure function of the request, so no call site
/// picks its own ceiling. VM-lifecycle ops run real guest work and get at least
/// [`BROKER_VM_CALL_BUDGET`]; the control ops get [`BROKER_CONTROL_CALL_BUDGET`]. The match is
/// exhaustive on purpose: a new [`EngineRequest`] variant must choose a budget.
///
/// An `exec` **derives** its budget from the request instead of taking the fixed ceiling, because
/// `ExecRequestDto::timeout_secs` is an accepted input the guest honors: a fixed 900 s bridge budget
/// would 500 an `exec { timeout_secs: 3600 }` at fifteen minutes while the guest command kept
/// running — an outer deadline *smaller* than the legitimate inner one, and an accepted input
/// silently not honored. Deriving (rather than rejecting a long timeout with a 400) is the right
/// half of that choice: the client already owns the VM, a long build or test run is exactly what a
/// per-exec timeout is for, and the bridge has no business being the shorter of the two. The result
/// always exceeds `timeout_secs` by [`EXEC_BUDGET_MARGIN`], so the guest's own timeout fires first
/// and the client gets the real outcome instead of a bridge error. Saturating, so an absurd
/// `u64::MAX` cannot wrap into a *tiny* budget (the deadline it feeds is clamped in
/// [`deadline_from`]).
fn call_budget(req: &EngineRequest) -> Duration {
    match req {
        EngineRequest::Exec(_, r) => match r.timeout_secs {
            Some(secs) => Duration::from_secs(secs)
                .saturating_add(EXEC_BUDGET_MARGIN)
                .max(BROKER_VM_CALL_BUDGET),
            None => BROKER_VM_CALL_BUDGET,
        },
        // Pause/resume are VM-lifecycle, not control: each drives the VMM's own control socket AND
        // queues on the per-VM handle lock, which an in-flight snapshot holds for a whole guest-RAM
        // write. A control-sized budget would 500 a pause that is merely waiting its turn.
        EngineRequest::Create(_)
        | EngineRequest::Pause(_)
        | EngineRequest::Resume(_)
        | EngineRequest::Snapshot(..)
        | EngineRequest::Destroy(_)
        | EngineRequest::ShutdownAll => BROKER_VM_CALL_BUDGET,
        EngineRequest::List
        | EngineRequest::Get(_)
        | EngineRequest::Stats(_)
        | EngineRequest::IsArtifactInUse(_)
        | EngineRequest::DeleteArtifactIfUnused(_) => BROKER_CONTROL_CALL_BUDGET,
    }
}

/// `now + budget`, saturating at [`CALL_DEADLINE_HORIZON`] instead of **panicking** on the `Instant`
/// overflow a client-supplied `timeout_secs: u64::MAX` produces (`Instant + Duration` panics; this
/// runs in the cap-dropped, network-facing parent, so that panic is client-reachable).
fn deadline_from(budget: Duration) -> tokio::time::Instant {
    let now = tokio::time::Instant::now();
    now.checked_add(budget)
        .unwrap_or_else(|| now + CALL_DEADLINE_HORIZON)
}

/// The parent-side [`VmEngine`] that forwards each op to the broker over the framed RPC and awaits
/// its reply. A background task reads replies and resolves the matching per-request `oneshot`, so
/// concurrent HTTP requests are in flight together (multiplexed by request id).
pub struct BrokerClientEngine {
    /// The shared request writer, or `None` once the stream has been **torn down** — see
    /// [`BrokerClientEngine::send_request`]. A framed stream that lost a write part-way through a
    /// frame can never be handed to the next caller, so the slot is emptied instead (dropping the
    /// `OwnedWriteHalf` shuts the write half down).
    wr: Mutex<Option<tokio::net::unix::OwnedWriteHalf>>,
    pending: Pending,
    next_id: AtomicU64,
    /// Overrides [`call_budget`] for **every** call when set (see
    /// [`BrokerClientEngine::with_call_budget`]).
    budget: Option<Duration>,
}

impl BrokerClientEngine {
    /// Wraps the parent's end of the broker socket and spawns the reply reader. **Must be called
    /// inside a tokio runtime** (it spawns the reader task).
    #[must_use]
    pub fn new(sock: tokio::net::UnixStream) -> Arc<Self> {
        Self::with_call_budget(sock, None)
    }

    /// Like [`BrokerClientEngine::new`], but pins every call's deadline to `budget` instead of the
    /// per-request default (`call_budget`). The stalled-broker gate uses it to bound a call in
    /// milliseconds instead of minutes; an embedder can use it to tighten the ceiling.
    #[must_use]
    pub fn with_call_budget(sock: tokio::net::UnixStream, budget: Option<Duration>) -> Arc<Self> {
        let (mut rd, wr) = sock.into_split();
        let pending: Pending = Arc::new(std::sync::Mutex::new(HashMap::new()));
        let reader_pending = pending.clone();
        tokio::spawn(async move {
            loop {
                let frame = match read_frame(&mut rd).await {
                    Ok(f) => f,
                    Err(_) => break, // broker gone
                };
                if let Ok((id, reply)) = serde_json::from_slice::<(u64, EngineReply)>(&frame)
                    && let Some(tx) = reader_pending
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .remove(&id)
                {
                    // The oneshot receiver is the caller's `rx.await`, dropped when its request's deadline
                    // expired or its task was cancelled — `forget()` clears the slot on both paths. A reply
                    // with no receiver is a reply nobody is waiting for.
                    #[expect(
                        clippy::let_underscore_must_use,
                        reason = "the reply's oneshot receiver is gone only when the request already expired or was cancelled"
                    )]
                    let _ = tx.send(reply);
                }
            }
            // Broker connection closed: fail every in-flight request rather than hang it forever.
            let mut map = reader_pending
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            for (_, tx) in map.drain() {
                // Same channel, the connection-closed sweep: every remaining slot is failed so nothing
                // hangs. A receiver already gone needs no telling.
                #[expect(
                    clippy::let_underscore_must_use,
                    reason = "connection-closed sweep: a slot whose receiver already went away needs no failure delivered"
                )]
                let _ = tx.send(EngineReply::Err(WireError {
                    kind: ErrorKind::Internal,
                    message: "broker connection closed".to_string(),
                }));
            }
        });
        Arc::new(Self {
            wr: Mutex::new(Some(wr)),
            pending,
            next_id: AtomicU64::new(1),
            budget,
        })
    }

    /// Drops a request's slot from the multiplex table, so neither an error path nor an expired
    /// deadline leaves a stale sender behind.
    fn forget(&self, id: u64) {
        self.pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&id);
    }

    /// Encodes and writes one request frame, bounded by the call's `deadline`.
    ///
    /// The deadline covers **both** waiting for the shared writer and the write itself — but the two
    /// are bounded separately, because a write that has begun cannot simply be dropped. Wrapping
    /// lock-acquire + `write_frame` in one `timeout_at` lets the deadline expire *inside*
    /// `write_all`: the future is dropped after a partial frame, the lock is released, and the next
    /// request's bytes land **inside** the truncated frame — desyncing the framed stream and every
    /// later reply on it (the same hazard as discarding a partial `write` return).
    ///
    /// So a write that is cut short — by the deadline or by an I/O error, which is equally
    /// possibly-partial — **tears the stream down**: the writer is taken out of its slot and
    /// dropped, which shuts the write half down. The broker sees a clean EOF after the truncated
    /// frame, this side's reply reader then fails every in-flight request with its typed error, and
    /// later callers are refused outright instead of writing into a desynced stream.
    ///
    /// An over-cap payload is rejected **before** the lock is taken (through the same
    /// [`frame_len_prefix`] law `write_frame` uses), so one oversized request cannot tear down a
    /// healthy connection.
    async fn send_request(
        &self,
        id: u64,
        req: EngineRequest,
        deadline: tokio::time::Instant,
    ) -> DaemonResult<()> {
        let bytes = serde_json::to_vec(&(id, req))
            .map_err(|e| DaemonError::Internal(format!("broker encode: {e}")))?;
        frame_len_prefix(&bytes)
            .map_err(|e| DaemonError::PayloadTooLarge(format!("broker request: {e}")))?;
        let mut slot = tokio::time::timeout_at(deadline, self.wr.lock())
            .await
            .map_err(|_| {
                DaemonError::Internal(
                    "the broker write channel did not free up within the call budget".to_string(),
                )
            })?;
        let written = {
            let Some(w) = slot.as_mut() else {
                return Err(DaemonError::Internal(
                    "the broker stream was torn down after a partial frame write".to_string(),
                ));
            };
            tokio::time::timeout_at(deadline, write_frame(w, &bytes)).await
        };
        match written {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => {
                *slot = None;
                Err(DaemonError::Internal(format!(
                    "broker write: {e}; the broker stream was torn down (the frame may be partial)"
                )))
            }
            Err(_) => {
                *slot = None;
                Err(DaemonError::Internal(
                    "broker write did not complete within the call budget; the broker stream was \
                     torn down rather than left desynced by a partial frame"
                        .to_string(),
                ))
            }
        }
    }

    async fn call(&self, req: EngineRequest) -> DaemonResult<EngineReply> {
        // ONE deadline bounds the WHOLE call — waiting for the write lock, the framed write, and the
        // reply await — not the gaps between them. The reader task's EOF drain covers a broker that
        // *died*; this covers one that is alive and simply never answers, which no drain can see.
        let budget = self.budget.unwrap_or_else(|| call_budget(&req));
        let deadline = deadline_from(budget);
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        self.pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(id, tx);
        if let Err(e) = self.send_request(id, req, deadline).await {
            self.forget(id);
            return Err(e);
        }
        match tokio::time::timeout_at(deadline, rx).await {
            Ok(Ok(reply)) => Ok(reply),
            Ok(Err(_)) => Err(DaemonError::Internal(
                "broker dropped the request".to_string(),
            )),
            Err(_) => {
                self.forget(id);
                Err(DaemonError::Internal(format!(
                    "broker call timed out after {budget:?} (the broker is alive but not replying)"
                )))
            }
        }
    }
}

/// Maps an unexpected reply variant to an internal error (a reply that did not match the request).
fn unexpected(reply: &EngineReply) -> DaemonError {
    DaemonError::Internal(format!("broker returned an unexpected reply: {reply:?}"))
}

#[async_trait]
impl VmEngine for BrokerClientEngine {
    async fn create(&self, req: CreateVmRequest) -> DaemonResult<CreateVmResponse> {
        match self.call(EngineRequest::Create(req)).await? {
            EngineReply::Created(v) => Ok(v),
            EngineReply::Err(w) => Err(daemon_error_from_wire(w)),
            other => Err(unexpected(&other)),
        }
    }
    async fn list(&self) -> DaemonResult<Vec<VmInfo>> {
        match self.call(EngineRequest::List).await? {
            EngineReply::List(v) => Ok(v),
            EngineReply::Err(w) => Err(daemon_error_from_wire(w)),
            other => Err(unexpected(&other)),
        }
    }
    async fn get(&self, id: &VmId) -> DaemonResult<VmInfo> {
        match self.call(EngineRequest::Get(id.clone())).await? {
            EngineReply::Info(v) => Ok(v),
            EngineReply::Err(w) => Err(daemon_error_from_wire(w)),
            other => Err(unexpected(&other)),
        }
    }
    async fn exec(&self, id: &VmId, req: ExecRequestDto) -> DaemonResult<ExecOutcomeDto> {
        match self.call(EngineRequest::Exec(id.clone(), req)).await? {
            EngineReply::Exec(v) => Ok(v),
            EngineReply::Err(w) => Err(daemon_error_from_wire(w)),
            other => Err(unexpected(&other)),
        }
    }
    async fn stats(&self, id: &VmId) -> DaemonResult<ResourceUsageDto> {
        match self.call(EngineRequest::Stats(id.clone())).await? {
            EngineReply::Stats(v) => Ok(v),
            EngineReply::Err(w) => Err(daemon_error_from_wire(w)),
            other => Err(unexpected(&other)),
        }
    }
    async fn pause(&self, id: &VmId) -> DaemonResult<VmInfo> {
        match self.call(EngineRequest::Pause(id.clone())).await? {
            EngineReply::Info(v) => Ok(v),
            EngineReply::Err(w) => Err(daemon_error_from_wire(w)),
            other => Err(unexpected(&other)),
        }
    }
    async fn resume(&self, id: &VmId) -> DaemonResult<VmInfo> {
        match self.call(EngineRequest::Resume(id.clone())).await? {
            EngineReply::Info(v) => Ok(v),
            EngineReply::Err(w) => Err(daemon_error_from_wire(w)),
            other => Err(unexpected(&other)),
        }
    }
    async fn snapshot(&self, id: &VmId, prefix: &str) -> DaemonResult<SnapshotInfo> {
        match self
            .call(EngineRequest::Snapshot(id.clone(), prefix.to_string()))
            .await?
        {
            EngineReply::Snapshot(v) => Ok(v),
            EngineReply::Err(w) => Err(daemon_error_from_wire(w)),
            other => Err(unexpected(&other)),
        }
    }
    async fn destroy(&self, id: &VmId) -> DaemonResult<()> {
        match self.call(EngineRequest::Destroy(id.clone())).await? {
            EngineReply::Destroyed => Ok(()),
            EngineReply::Err(w) => Err(daemon_error_from_wire(w)),
            other => Err(unexpected(&other)),
        }
    }
    async fn is_artifact_in_use(&self, name: &str) -> DaemonResult<bool> {
        match self
            .call(EngineRequest::IsArtifactInUse(name.to_string()))
            .await?
        {
            EngineReply::InUse(v) => Ok(v),
            EngineReply::Err(w) => Err(daemon_error_from_wire(w)),
            other => Err(unexpected(&other)),
        }
    }
    async fn delete_artifact_if_unused(&self, name: &str) -> DaemonResult<()> {
        match self
            .call(EngineRequest::DeleteArtifactIfUnused(name.to_string()))
            .await?
        {
            EngineReply::ArtifactDeleted => Ok(()),
            EngineReply::Err(w) => Err(daemon_error_from_wire(w)),
            other => Err(unexpected(&other)),
        }
    }
    async fn shutdown_all(&self) {
        // Best-effort: ask the broker to tear every VM down gracefully. A transport error is
        // LOGGED, never swallowed silently (the reap on the child handle is the backstop, and the
        // next daemon's start-up sweep reclaims whatever the reap could not).
        if let Err(e) = self.call(EngineRequest::ShutdownAll).await {
            tracing::warn!(error = %e, "broker shutdown_all did not complete; relying on the child reap and the next start-up sweep");
        }
    }
}

#[cfg(test)]
mod deadline_tests;
#[cfg(test)]
mod shutdown_tests;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod write_reply_tests;

/// KVM-free gates for the exec-capture ceiling (design §17, Open gaps and future capabilities).
///
/// In-file rather than a sibling module because the law, its two call sites and the call-site scan
/// all live in `bridge.rs`, and the scan reads that file by `include_str!` of its own path.
#[cfg(test)]
mod capture_ceiling_tests {
    use super::*;
    use crate::dto::VmState;

    /// The source of `bridge.rs` itself — the text the call-site scan reads.
    const BRIDGE_SRC: &str = include_str!("bridge.rs");

    fn vminfo_at_the_name_ceiling() -> VmInfo {
        VmInfo {
            id: VmId("vm-0123456789abcdef".to_string()),
            state: VmState::Ready,
            vmid: u32::MAX,
            kernel: "k".repeat(crate::name::MAX_ARTIFACT_NAME_LEN),
            rootfs: "r".repeat(crate::name::MAX_ARTIFACT_NAME_LEN),
            vcpus: u8::MAX,
            mem_mib: u32::MAX,
        }
    }

    // The reserve is not a guess: the widest capture-carrying reply's envelope — a `Created` whose
    // `VmInfo` names two artifacts at the name ceiling, plus the frame's own 4-byte length prefix —
    // must fit inside `EXEC_REPLY_ENVELOPE_RESERVE`, and the ceiling must therefore be derived from
    // `MAX_BRIDGE_FRAME_BYTES` rather than stated as a literal.
    //
    // Inverse (red): shrink `EXEC_REPLY_ENVELOPE_RESERVE` below the measured envelope, or replace
    // `MAX_EXEC_CAPTURE_B64_BYTES` with a literal larger than the frame cap allows.
    #[test]
    fn the_reserve_covers_the_real_reply_envelope() {
        let created = EngineReply::Created(CreateVmResponse {
            vm: vminfo_at_the_name_ceiling(),
            exec: Some(ExecOutcomeDto {
                code: i32::MIN,
                stdout_b64: String::new(),
                stderr_b64: String::new(),
            }),
        });
        let envelope = serde_json::to_vec(&(u64::MAX, created))
            .expect("the reply envelope encodes")
            .len()
            + 4; // the length prefix `write_frame` puts in front of it
        assert!(
            envelope <= EXEC_REPLY_ENVELOPE_RESERVE,
            "the envelope reserve ({EXEC_REPLY_ENVELOPE_RESERVE}) must cover the widest \
             capture-carrying reply envelope ({envelope})"
        );
        // A capture exactly at the ceiling, plus that envelope, still fits the one frame cap.
        assert!(
            envelope + MAX_EXEC_CAPTURE_B64_BYTES <= MAX_BRIDGE_FRAME_BYTES,
            "a ceiling-sized capture must fit the frame cap"
        );
        // And the raw figure quoted to the client is the base64 budget's 3/4, not a fresh number.
        assert_eq!(MAX_EXEC_CAPTURE_BYTES, MAX_EXEC_CAPTURE_B64_BYTES / 4 * 3);
    }

    // The boundary, against the SHIPPED constants: a capture at the ceiling is accepted, and the
    // smallest capture over it is refused as a typed 413. One allocation, grown in place, so the
    // pair costs one ceiling-sized string rather than two.
    //
    // Inverse (red): drop the `encoded <= MAX_EXEC_CAPTURE_B64_BYTES` guard and the over-ceiling leg
    // returns `Ok`; make the guard `<` instead of `<=` and the at-ceiling leg reddens.
    #[test]
    fn a_capture_at_the_ceiling_is_accepted_and_one_over_it_is_a_typed_413() {
        let mut stdout_b64 = String::with_capacity(MAX_EXEC_CAPTURE_B64_BYTES + 4);
        stdout_b64.extend(std::iter::repeat_n('A', MAX_EXEC_CAPTURE_B64_BYTES - 4));
        let mut outcome = ExecOutcomeDto {
            code: 0,
            stdout_b64,
            // The ceiling is on the SUM: a capture split across the two streams is one reply.
            stderr_b64: "B".repeat(4),
        };
        enforce_exec_capture_ceiling("exec in vm vm-1", &outcome)
            .expect("a capture exactly at the ceiling must be accepted");

        outcome.stderr_b64.push('B');
        let err = enforce_exec_capture_ceiling("exec in vm vm-1", &outcome)
            .expect_err("one byte over the ceiling must be refused");
        assert_eq!(
            err.kind().status_code(),
            413,
            "an over-ceiling capture is a payload-too-large, not an internal error: {}",
            err.message()
        );
        let msg = err.message();
        assert!(
            msg.contains("vm-1") && msg.contains(&MAX_EXEC_CAPTURE_BYTES.to_string()),
            "the refusal names the VM and the ceiling: {msg}"
        );
        assert!(
            msg.contains("refused rather than silently truncated"),
            "the refusal states that nothing was truncated: {msg}"
        );
    }

    // The client can TELL: the typed refusal survives the codec it actually ships over (JSON), so
    // the parent reconstructs a 413 with the explanation intact instead of an opaque 500.
    //
    // Inverse (red): map the refusal to `ErrorKind::Internal` on the way out, or drop the message,
    // and the reconstructed status/message assertions redden.
    #[test]
    fn the_refusal_reaches_the_client_as_a_413_across_the_bridge_codec() {
        let outcome = ExecOutcomeDto {
            code: 0,
            stdout_b64: "A".repeat(MAX_EXEC_CAPTURE_B64_BYTES + 1),
            stderr_b64: String::new(),
        };
        let refusal = enforce_exec_capture_ceiling("exec in vm vm-7", &outcome)
            .expect_err("over the ceiling");
        let frame = serde_json::to_vec(&(9u64, EngineReply::Err(WireError::from(&refusal))))
            .expect("the refusal frame encodes");
        assert!(
            frame.len() < 4096,
            "the refusal frame must be compact, not the capture it refused: {}",
            frame.len()
        );
        let (id, reply) = serde_json::from_slice::<(u64, EngineReply)>(&frame)
            .expect("the refusal frame decodes");
        assert_eq!(id, 9, "the refusal answers the request that provoked it");
        let EngineReply::Err(wire) = reply else {
            panic!("expected a typed Err reply")
        };
        let seen = daemon_error_from_wire(wire);
        assert_eq!(seen.kind().status_code(), 413);
        assert_eq!(
            seen.message(),
            refusal.message(),
            "the explanation must survive the boundary intact"
        );
    }

    // The gate binds the CALL SITES, not just the predicate (AGENTS.md): every arm of the
    // broker-side engine adapter that can return an `ExecOutcomeDto` routes through the one law.
    //
    // Inverse (red): delete the `enforce_exec_capture_ceiling` call from either the `exec` or the
    // `create` arm and the count drops to one.
    #[test]
    fn both_capture_carrying_adapter_arms_route_through_the_one_ceiling() {
        // A zero-length scan is a misconfigured gate, never a green verdict.
        assert!(
            BRIDGE_SRC.len() > 10_000,
            "the call-site scan read nothing recognizable as bridge.rs"
        );
        let start = BRIDGE_SRC
            .find("impl VmEngine for Registry {")
            .expect("the broker-side engine adapter must be findable by the scan");
        let body = BRIDGE_SRC
            .get(start..)
            .and_then(|rest| rest.find("\n}\n").map(|end| &rest[..end]))
            .expect("the adapter block must be delimited");
        assert_eq!(
            body.matches("enforce_exec_capture_ceiling(").count(),
            2,
            "exactly the two capture-carrying arms (`create`'s inline command and `exec`) apply \
             the ceiling; adapter body:\n{body}"
        );
        for arm in ["Registry::create(self", "Registry::exec(self"] {
            assert!(
                body.contains(arm),
                "the scan must be looking at the real adapter (missing `{arm}`)"
            );
        }
    }
}
