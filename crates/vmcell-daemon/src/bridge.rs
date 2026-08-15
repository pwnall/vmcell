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
        Registry::exec(self, id, req).await
    }
    async fn stats(&self, id: &VmId) -> DaemonResult<ResourceUsageDto> {
        Registry::stats(self, id).await
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
/// captured output, so a large enough capture overflows the cap in [`write_frame`]. The parent's
/// `rx.await` has no timeout, so a dropped reply wedges that HTTP request **forever**; the fallback
/// turns it into a `DaemonError::Internal` (500). (Capping the exec capture host-side is the
/// separate recorded follow-up; this only makes the failure typed instead of a hang.)
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
        EngineRequest::Create(_)
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
                    let _ = tx.send(reply);
                }
            }
            // Broker connection closed: fail every in-flight request rather than hang it forever.
            let mut map = reader_pending
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            for (_, tx) in map.drain() {
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
