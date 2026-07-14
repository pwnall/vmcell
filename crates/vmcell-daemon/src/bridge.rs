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
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{Mutex, oneshot};

/// The bridge RPC frame cap. Generous because an `exec` reply carries the guest command's full
/// captured stdout/stderr; enforced before allocation on both ends (the internal channel is
/// trusted, but a corrupt length prefix must still not drive an unbounded allocation).
pub const MAX_BRIDGE_FRAME_BYTES: usize = 256 * 1024 * 1024;

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

// ---------------------------------------------------------------------------------------------
// Framed async codec (length-prefixed JSON; over-cap rejected before allocation). JSON (not a
// non-self-describing format like postcard) because the reused DTOs carry `#[serde(skip_serializing_if)]`
// / `default` fields that only round-trip correctly in a self-describing format — and it is the same
// format the HTTP API itself speaks.
// ---------------------------------------------------------------------------------------------

async fn write_frame<W: AsyncWriteExt + Unpin>(w: &mut W, payload: &[u8]) -> std::io::Result<()> {
    let len = u32::try_from(payload.len())
        .ok()
        .filter(|_| payload.len() <= MAX_BRIDGE_FRAME_BYTES)
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "bridge frame {} exceeds cap {MAX_BRIDGE_FRAME_BYTES}",
                    payload.len()
                ),
            )
        })?;
    w.write_all(&len.to_be_bytes()).await?;
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

/// Serves `engine` over `sock` until the peer closes it or a `ShutdownAll` is handled (after which
/// the broker returns so its caller can `_exit`). Each request is dispatched on its own task so a
/// long `exec` does not block other VMs' ops; replies carry the request id and are written behind a
/// shared write lock. Runs in the **broker** child (which holds the caps and owns the registry).
pub async fn serve_engine(engine: Arc<dyn VmEngine>, sock: tokio::net::UnixStream) {
    let (mut rd, wr) = sock.into_split();
    let wr = Arc::new(Mutex::new(wr));
    loop {
        let frame = match read_frame(&mut rd).await {
            Ok(f) => f,
            // Parent closed the channel (shutdown / crash): stop serving.
            Err(_) => return,
        };
        let Ok((id, req)) = serde_json::from_slice::<(u64, EngineRequest)>(&frame) else {
            tracing::warn!("broker: dropping an undecodable request frame");
            continue;
        };
        let shutdown = matches!(req, EngineRequest::ShutdownAll);
        let engine = engine.clone();
        let wr = wr.clone();
        let job = async move {
            let reply = dispatch(engine.as_ref(), req).await;
            if let Ok(bytes) = serde_json::to_vec(&(id, reply)) {
                let mut w = wr.lock().await;
                let _ = write_frame(&mut *w, &bytes).await;
            }
        };
        if shutdown {
            // Run inline (so the reply is written) and then stop serving — the broker exits next.
            job.await;
            return;
        }
        tokio::spawn(job);
    }
}

// ---------------------------------------------------------------------------------------------
// Parent side: the forwarding engine (multiplexed RPC client)
// ---------------------------------------------------------------------------------------------

type Pending = Arc<std::sync::Mutex<HashMap<u64, oneshot::Sender<EngineReply>>>>;

/// The parent-side [`VmEngine`] that forwards each op to the broker over the framed RPC and awaits
/// its reply. A background task reads replies and resolves the matching per-request `oneshot`, so
/// concurrent HTTP requests are in flight together (multiplexed by request id).
pub struct BrokerClientEngine {
    wr: Mutex<tokio::net::unix::OwnedWriteHalf>,
    pending: Pending,
    next_id: AtomicU64,
}

impl BrokerClientEngine {
    /// Wraps the parent's end of the broker socket and spawns the reply reader. **Must be called
    /// inside a tokio runtime** (it spawns the reader task).
    #[must_use]
    pub fn new(sock: tokio::net::UnixStream) -> Arc<Self> {
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
            wr: Mutex::new(wr),
            pending,
            next_id: AtomicU64::new(1),
        })
    }

    async fn call(&self, req: EngineRequest) -> DaemonResult<EngineReply> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        self.pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(id, tx);
        let bytes = serde_json::to_vec(&(id, req))
            .map_err(|e| DaemonError::Internal(format!("broker encode: {e}")))?;
        {
            let mut w = self.wr.lock().await;
            write_frame(&mut *w, &bytes)
                .await
                .map_err(|e| DaemonError::Internal(format!("broker write: {e}")))?;
        }
        rx.await
            .map_err(|_| DaemonError::Internal("broker dropped the request".to_string()))
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
        // Best-effort: ask the broker to tear every VM down gracefully; ignore transport errors
        // (the reap on the child handle is the backstop).
        let _ = self.call(EngineRequest::ShutdownAll).await;
    }
}

#[cfg(test)]
mod tests;
