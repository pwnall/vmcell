//! The axum HTTP server: state, router, handlers, and the bearer-auth layer (design v21 §D5/§D6).
//!
//! Handlers are thin adapters over the [`Registry`] and the artifact store; every failure returns a
//! typed [`DaemonError`] whose one `IntoResponse` maps it to a status + structured body (§D5.3). The
//! auth layer wraps every route except the two open ones (invariant §D9.3). The registry **owns** its
//! VMs (design v21 §D4): a clean shutdown calls `shutdown_all`, and dropping the state runs each VM's
//! ordered `Drop`; a hard kill relies on the next boot's start-up orphan sweep.

use crate::auth::{AuthPolicy, authorize};
use crate::dto::{
    ArtifactInfo, CreateVmRequest, CreateVmResponse, ExecOutcomeDto, ExecRequestDto,
    ResourceUsageDto, SnapshotInfo, SnapshotRequest, VmId, VmInfo,
};
use crate::error::{DaemonError, DaemonResult};
use crate::openapi::openapi_document;
use crate::registry::Registry;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Path as AxPath, Request, State};
use axum::http::{StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::{get, post, put};
use axum::{Json, Router};
use std::sync::Arc;

/// The shared handler state (cheaply `Clone` — everything is behind an `Arc` or is `Copy`).
#[derive(Clone)]
pub struct AppState {
    /// The owned VM registry + artifact store.
    pub registry: Arc<Registry>,
    /// The bearer-auth policy.
    pub auth: AuthPolicy,
    /// The per-upload body-size ceiling (bytes).
    pub max_artifact_bytes: usize,
}

/// Builds the full router: the authenticated routes behind the bearer layer, plus the two open
/// meta routes. The routes mounted here are exactly [`crate::openapi::API_ROUTES`] (invariant §D9.4).
pub fn build_router(state: AppState) -> Router {
    let max_body = state.max_artifact_bytes;
    let protected = Router::new()
        .route("/v1/artifacts", get(list_artifacts))
        .route(
            "/v1/artifacts/:name",
            put(create_artifact).get(get_artifact).delete(delete_artifact),
        )
        .route("/v1/vms", post(create_vm).get(list_vms))
        .route("/v1/vms/:id", get(get_vm).delete(destroy_vm))
        .route("/v1/vms/:id/exec", post(exec_vm))
        .route("/v1/vms/:id/stats", get(stats_vm))
        .route("/v1/vms/:id/snapshot", post(snapshot_vm))
        // Auth is a route-layer over exactly these routes — the open routes below are NOT wrapped
        // (invariant §D9.3: authenticated by default, two named opt-outs).
        .route_layer(middleware::from_fn_with_state(state.clone(), auth_layer))
        // Raise the body limit so a multi-MB kernel/rootfs upload is accepted; the store enforces the
        // real per-artifact cap. Applied only to the protected (upload-bearing) subtree.
        .layer(DefaultBodyLimit::max(max_body));

    let open = Router::new()
        .route("/healthz", get(health))
        .route("/openapi.json", get(openapi_handler));

    protected.merge(open).with_state(state)
}

/// The bearer-auth middleware: reads the `Authorization` header and enforces the policy, returning a
/// typed 401/403 before the handler runs. Applied to every protected route (invariant §D9.3).
async fn auth_layer(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Result<Response, DaemonError> {
    let header = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());
    authorize(&state.auth, header)?;
    Ok(next.run(req).await)
}

// ---- artifact handlers ----

async fn create_artifact(
    State(state): State<AppState>,
    AxPath(name): AxPath<String>,
    body: Bytes,
) -> DaemonResult<Json<ArtifactInfo>> {
    Ok(Json(state.registry.artifacts().create(&name, &body)?))
}

async fn list_artifacts(State(state): State<AppState>) -> DaemonResult<Json<Vec<ArtifactInfo>>> {
    Ok(Json(state.registry.artifacts().list()?))
}

async fn get_artifact(
    State(state): State<AppState>,
    AxPath(name): AxPath<String>,
) -> DaemonResult<Json<ArtifactInfo>> {
    Ok(Json(state.registry.artifacts().info(&name)?))
}

async fn delete_artifact(
    State(state): State<AppState>,
    AxPath(name): AxPath<String>,
) -> DaemonResult<StatusCode> {
    if state.registry.is_artifact_in_use(&name).await {
        return Err(DaemonError::InUse(format!(
            "artifact {name:?} is pinned by a live VM; destroy the VM first"
        )));
    }
    state.registry.artifacts().delete(&name)?;
    Ok(StatusCode::NO_CONTENT)
}

// ---- VM handlers ----

async fn create_vm(
    State(state): State<AppState>,
    Json(req): Json<CreateVmRequest>,
) -> DaemonResult<Json<CreateVmResponse>> {
    let created = state.registry.create(req).await?;
    Ok(Json(CreateVmResponse {
        vm: created.info,
        exec: created.exec,
    }))
}

async fn list_vms(State(state): State<AppState>) -> DaemonResult<Json<Vec<VmInfo>>> {
    Ok(Json(state.registry.list().await))
}

async fn get_vm(
    State(state): State<AppState>,
    AxPath(id): AxPath<String>,
) -> DaemonResult<Json<VmInfo>> {
    Ok(Json(state.registry.get(&VmId(id)).await?))
}

async fn exec_vm(
    State(state): State<AppState>,
    AxPath(id): AxPath<String>,
    Json(req): Json<ExecRequestDto>,
) -> DaemonResult<Json<ExecOutcomeDto>> {
    Ok(Json(state.registry.exec(&VmId(id), req).await?))
}

async fn stats_vm(
    State(state): State<AppState>,
    AxPath(id): AxPath<String>,
) -> DaemonResult<Json<ResourceUsageDto>> {
    Ok(Json(state.registry.stats(&VmId(id)).await?))
}

async fn snapshot_vm(
    State(state): State<AppState>,
    AxPath(id): AxPath<String>,
    Json(req): Json<SnapshotRequest>,
) -> DaemonResult<Json<SnapshotInfo>> {
    Ok(Json(
        state
            .registry
            .snapshot(&VmId(id), &req.artifact_prefix)
            .await?,
    ))
}

async fn destroy_vm(
    State(state): State<AppState>,
    AxPath(id): AxPath<String>,
) -> DaemonResult<StatusCode> {
    state.registry.destroy(&VmId(id)).await?;
    Ok(StatusCode::NO_CONTENT)
}

// ---- meta handlers (open) ----

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "ok" }))
}

async fn openapi_handler() -> Json<serde_json::Value> {
    Json(openapi_document())
}

/// Serves the API on `listener` until the process exits. The caller owns the [`Registry`] and is
/// responsible for a graceful `shutdown_all` on a clean exit (the owned VMs otherwise tear down when
/// the `Arc<Registry>` is dropped).
///
/// # Errors
/// Propagates a fatal `axum::serve` I/O error.
pub async fn serve(state: AppState, listener: tokio::net::TcpListener) -> std::io::Result<()> {
    axum::serve(listener, build_router(state).into_make_service()).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact_store::ArtifactStore;
    use crate::auth::ApiKey;
    use crate::launcher::{LaunchSpec, VmHandle, VmLauncher};
    use crate::registry::Registry;
    use axum::body::Body;
    use tower::ServiceExt as _;

    // These wiring tests exercise routing + auth only (no VM is ever launched), so the launcher just
    // needs to exist; `launch` errors if ever reached.
    struct UnusedLauncher;
    #[async_trait::async_trait]
    impl VmLauncher for UnusedLauncher {
        async fn launch(&self, _spec: &LaunchSpec) -> DaemonResult<Box<dyn VmHandle>> {
            Err(DaemonError::Internal(
                "launcher not used in wiring tests".into(),
            ))
        }
    }

    fn app() -> Router {
        let dir = Box::leak(Box::new(tempfile::tempdir().expect("tempdir")));
        let artifacts = ArtifactStore::open(dir.path().join("artifacts"), 1 << 20).expect("art");
        let registry = Registry::new(Box::new(UnusedLauncher), artifacts, 1);
        let state = AppState {
            registry: Arc::new(registry),
            auth: AuthPolicy::Key(ApiKey::from_secret(b"secret")),
            max_artifact_bytes: 1 << 20,
        };
        build_router(state)
    }

    async fn status_of(uri: &str, auth: Option<&str>) -> StatusCode {
        let mut b = Request::builder().uri(uri);
        if let Some(a) = auth {
            b = b.header(header::AUTHORIZATION, a);
        }
        let req = b.body(Body::empty()).expect("request");
        app().oneshot(req).await.expect("response").status()
    }

    // Open routes are reachable WITHOUT a token; protected routes are 401 without one, 403 with a
    // wrong one, and reachable with the right one. This is the wiring proof for invariant §D9.3.
    #[tokio::test]
    async fn healthz_is_open_and_vms_requires_auth() {
        assert_eq!(status_of("/healthz", None).await, StatusCode::OK);
        assert_eq!(status_of("/openapi.json", None).await, StatusCode::OK);
        // Protected route: no token → 401 (with a WWW-Authenticate challenge).
        assert_eq!(status_of("/v1/vms", None).await, StatusCode::UNAUTHORIZED);
        // Wrong token → 403.
        assert_eq!(
            status_of("/v1/vms", Some("Bearer wrong")).await,
            StatusCode::FORBIDDEN
        );
        // Right token → 200 (empty list).
        assert_eq!(
            status_of("/v1/vms", Some("Bearer secret")).await,
            StatusCode::OK
        );
    }

    // A route that is NOT in the table returns 404 — a cheap guard that we did not silently mount
    // something outside API_ROUTES.
    #[tokio::test]
    async fn unknown_route_is_404() {
        assert_eq!(
            status_of("/v1/nonsense", Some("Bearer secret")).await,
            StatusCode::NOT_FOUND
        );
    }
}
