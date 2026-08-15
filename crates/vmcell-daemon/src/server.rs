//! The axum HTTP server: state, router, handlers, and the bearer-auth layer (design §11.5, The HTTP REST API and its OpenAPI document / §11.6, Authentication — a bearer API key).
//!
//! Handlers are thin adapters over the [`Registry`](crate::registry::Registry) and the artifact store; every failure returns a
//! typed [`DaemonError`] whose one `IntoResponse` maps it to a status + structured body (§11.5, The HTTP REST API and its OpenAPI document). The
//! auth layer wraps every route except the two open ones (invariant §13, Cross-cutting invariants). The registry **owns** its
//! VMs (design §11.4, The VM registry and the start-up sweep): a clean shutdown calls `shutdown_all`, and dropping the state runs each VM's
//! ordered `Drop`; a hard kill relies on the next boot's start-up orphan sweep.

use crate::artifact_store::ArtifactStore;
use crate::auth::{AuthDecision, AuthPolicy, authorize};
use crate::bridge::VmEngine;
use crate::dto::{
    ArtifactInfo, CreateVmRequest, CreateVmResponse, ExecOutcomeDto, ExecRequestDto,
    ResourceUsageDto, SnapshotInfo, SnapshotRequest, VmId, VmInfo,
};
use crate::error::{DaemonError, DaemonResult};
use crate::openapi::{API_ROUTES, RouteDef, openapi_document};
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Path as AxPath, Request, State};
use axum::http::{StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::{MethodRouter, any, delete, get, post, put};
use axum::{Json, Router};
use std::sync::Arc;

/// The shared handler state (cheaply `Clone` — everything is behind an `Arc` or is `Copy`).
///
/// The **VM engine** and the **artifact store** are separate seams (design §12.4, Layer 3 — the setup broker (network surface never holds caps) / §13, Cross-cutting invariants): VM
/// operations go through the [`VmEngine`] (a [`crate::bridge::BrokerClientEngine`] forwarding to the
/// capped broker in the split cutover, or a [`crate::registry::Registry`] directly in a
/// single-process daemon), while artifact create/list/get is unprivileged file I/O the parent does
/// itself. Artifact **delete** crosses to the engine (`delete_artifact_if_unused`) so the
/// delete-in-use check and the file delete are atomic under one hold of the VM-table lock — the
/// engine's store points at the same `--artifacts-dir`.
#[derive(Clone)]
pub struct AppState {
    /// The VM engine (VM lifecycle ops + the delete-in-use guard).
    pub engine: Arc<dyn VmEngine>,
    /// The artifact store (unprivileged file CRUD under `--artifacts-dir`).
    pub artifacts: Arc<ArtifactStore>,
    /// The bearer-auth policy.
    pub auth: AuthPolicy,
    /// The per-upload body-size ceiling (bytes).
    pub max_artifact_bytes: usize,
}

/// The handler for one [`RouteDef`], or `None` when the table names a route this module does not
/// implement.
///
/// The one place a `(method, path)` pair from [`API_ROUTES`] becomes a handler. Because
/// [`build_router`] *folds over the table* rather than hand-listing routes, the mounted surface and
/// the served OpenAPI document are the same list **by construction** — the P5 parity claim used to
/// be a comment, and a route added to `build_router` alone was mounted, undocumented, and green
/// (finding `router-and-openapi-parity-compares-the-table-to-itself`).
fn method_router_for(route: &RouteDef) -> Option<MethodRouter<AppState>> {
    Some(match (route.method, route.path) {
        ("PUT", "/v1/artifacts/{name}") => put(create_artifact),
        ("GET", "/v1/artifacts") => get(list_artifacts),
        ("GET", "/v1/artifacts/{name}") => get(get_artifact),
        ("DELETE", "/v1/artifacts/{name}") => delete(delete_artifact),
        ("POST", "/v1/vms") => post(create_vm),
        ("GET", "/v1/vms") => get(list_vms),
        ("GET", "/v1/vms/{id}") => get(get_vm),
        ("DELETE", "/v1/vms/{id}") => delete(destroy_vm),
        ("POST", "/v1/vms/{id}/exec") => post(exec_vm),
        ("GET", "/v1/vms/{id}/stats") => get(stats_vm),
        ("POST", "/v1/vms/{id}/snapshot") => post(snapshot_vm),
        ("GET", "/healthz") => get(health),
        ("GET", "/openapi.json") => get(openapi_handler),
        _ => return None,
    })
}

/// The loud placeholder for a table row with no handler: a 500 that names the row. A daemon must
/// not panic while building its router, and `every_api_route_has_a_handler` reddens in CI long
/// before such a row could ship.
fn unwired(route: &RouteDef) -> MethodRouter<AppState> {
    let (method, path) = (route.method, route.path);
    any(move || async move {
        DaemonError::Internal(format!(
            "{method} {path} is listed in API_ROUTES but no handler is wired for it"
        ))
    })
}

/// Builds the full router by **folding over [`API_ROUTES`]**: each row is mounted with its own
/// method and path, into the authenticated subtree (behind the bearer layer) or the open one, as
/// the row's `authenticated` flag says. The mounted surface is therefore exactly the table the
/// OpenAPI document is generated from (invariant §13, Cross-cutting invariants) — structurally, not
/// by assertion.
pub fn build_router(state: AppState) -> Router {
    let max_body = state.max_artifact_bytes;
    let (protected, open) = API_ROUTES.iter().fold(
        (Router::new(), Router::new()),
        |(protected, open), route| {
            let handler = method_router_for(route).unwrap_or_else(|| unwired(route));
            if route.authenticated {
                (protected.route(route.path, handler), open)
            } else {
                (protected, open.route(route.path, handler))
            }
        },
    );

    let protected = protected
        // Auth is a route-layer over exactly the authenticated rows — the open subtree is NOT
        // wrapped (invariant §13, Cross-cutting invariants: authenticated by default, two named
        // opt-outs, and the row's own flag decides which subtree it landed in).
        .route_layer(middleware::from_fn_with_state(state.clone(), auth_layer))
        // Raise the body limit so a multi-MB kernel/rootfs upload is accepted; the store enforces the
        // real per-artifact cap. Applied only to the protected (upload-bearing) subtree.
        .layer(DefaultBodyLimit::max(max_body));

    protected.merge(open).with_state(state)
}

/// The bearer-auth middleware: reads the `Authorization` header and enforces the policy, returning a
/// typed 401/403 before the handler runs. Applied to every protected route (invariant §13, Cross-cutting invariants).
///
/// It is also the site of the `--allow-unauthenticated` **per-request** warn design §11.6
/// (Authentication — a bearer API key) promises: `vmcelld`'s one-time start-up warn scrolls out of a
/// long-running daemon's log, leaving an unprotected control plane with nothing in the record that
/// says so (finding `allow-unauthenticated-not-logged-per-request`). The decision itself stays in
/// the pure [`authorize`]; the layer only reacts to the returned [`AuthDecision`].
async fn auth_layer(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Result<Response, DaemonError> {
    let header = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());
    match authorize(&state.auth, header)? {
        AuthDecision::Authenticated => {}
        AuthDecision::UnauthenticatedBypass => {
            // WARN, with the request's identity, on EVERY request — not once at start-up. The
            // `unauthenticated_bypass` field is what the gate matches on.
            tracing::warn!(
                unauthenticated_bypass = true,
                method = %req.method(),
                path = %req.uri().path(),
                "request served with --allow-unauthenticated: the API is UNPROTECTED (design §11.6)"
            );
        }
    }
    Ok(next.run(req).await)
}

// ---- artifact handlers ----

async fn create_artifact(
    State(state): State<AppState>,
    AxPath(name): AxPath<String>,
    body: Bytes,
) -> DaemonResult<Json<ArtifactInfo>> {
    Ok(Json(state.artifacts.create(&name, &body)?))
}

async fn list_artifacts(State(state): State<AppState>) -> DaemonResult<Json<Vec<ArtifactInfo>>> {
    Ok(Json(state.artifacts.list()?))
}

async fn get_artifact(
    State(state): State<AppState>,
    AxPath(name): AxPath<String>,
) -> DaemonResult<Json<ArtifactInfo>> {
    Ok(Json(state.artifacts.info(&name)?))
}

async fn delete_artifact(
    State(state): State<AppState>,
    AxPath(name): AxPath<String>,
) -> DaemonResult<StatusCode> {
    // The delete-in-use guard needs the live VM table, which the engine owns; the check and the
    // delete must be ATOMIC or a concurrent `create` can pin the artifact in the gap and lose its
    // disk out from under a just-booted VM. So the whole check-and-delete crosses to the engine,
    // which runs both under one hold of the VM-table lock (the engine's store points at the same
    // `--artifacts-dir`). No separate `state.artifacts.delete` here — that reopened the TOCTOU.
    state.engine.delete_artifact_if_unused(&name).await?;
    Ok(StatusCode::NO_CONTENT)
}

// ---- VM handlers ----

async fn create_vm(
    State(state): State<AppState>,
    Json(req): Json<CreateVmRequest>,
) -> DaemonResult<Json<CreateVmResponse>> {
    Ok(Json(state.engine.create(req).await?))
}

async fn list_vms(State(state): State<AppState>) -> DaemonResult<Json<Vec<VmInfo>>> {
    Ok(Json(state.engine.list().await?))
}

async fn get_vm(
    State(state): State<AppState>,
    AxPath(id): AxPath<String>,
) -> DaemonResult<Json<VmInfo>> {
    Ok(Json(state.engine.get(&VmId(id)).await?))
}

async fn exec_vm(
    State(state): State<AppState>,
    AxPath(id): AxPath<String>,
    Json(req): Json<ExecRequestDto>,
) -> DaemonResult<Json<ExecOutcomeDto>> {
    Ok(Json(state.engine.exec(&VmId(id), req).await?))
}

async fn stats_vm(
    State(state): State<AppState>,
    AxPath(id): AxPath<String>,
) -> DaemonResult<Json<ResourceUsageDto>> {
    Ok(Json(state.engine.stats(&VmId(id)).await?))
}

async fn snapshot_vm(
    State(state): State<AppState>,
    AxPath(id): AxPath<String>,
    Json(req): Json<SnapshotRequest>,
) -> DaemonResult<Json<SnapshotInfo>> {
    Ok(Json(
        state
            .engine
            .snapshot(&VmId(id), &req.artifact_prefix)
            .await?,
    ))
}

async fn destroy_vm(
    State(state): State<AppState>,
    AxPath(id): AxPath<String>,
) -> DaemonResult<StatusCode> {
    state.engine.destroy(&VmId(id)).await?;
    Ok(StatusCode::NO_CONTENT)
}

// ---- meta handlers (open) ----

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "ok" }))
}

async fn openapi_handler() -> Json<serde_json::Value> {
    Json(openapi_document())
}

/// Serves the API on `listener` until the process exits. The caller owns the [`Registry`](crate::registry::Registry) and is
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
    use std::sync::atomic::{AtomicUsize, Ordering};
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
        app_with(AuthPolicy::Key(ApiKey::from_secret(b"secret")))
    }

    fn app_with(auth: AuthPolicy) -> Router {
        let dir = Box::leak(Box::new(tempfile::tempdir().expect("tempdir")));
        let art_dir = dir.path().join("artifacts");
        // The engine (registry) and the parent's artifact store are separate seams over the same
        // dir (design §12.4, Layer 3 — the setup broker (network surface never holds caps)) — the wiring tests only exercise routing/auth, so no VM is launched.
        let registry = Registry::new(
            Box::new(UnusedLauncher),
            ArtifactStore::open(&art_dir, 1 << 20).expect("registry store"),
            1,
        );
        let state = AppState {
            engine: Arc::new(registry),
            artifacts: Arc::new(ArtifactStore::open(&art_dir, 1 << 20).expect("parent store")),
            auth,
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
    // wrong one, and reachable with the right one. This is the wiring proof for invariant §13 (Cross-cutting invariants).
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

    /// A minimal `tracing::Subscriber` that counts WARN events carrying the
    /// `unauthenticated_bypass` field. Hand-rolled because the crate has no `tracing-subscriber`
    /// dev-dependency, and counting the events the layer actually emits is the only way to gate a
    /// claim about logging (a test that only asserts the [`AuthDecision`] value would still pass on
    /// a layer that ignores it).
    #[derive(Clone)]
    struct BypassWarnCounter(Arc<AtomicUsize>);

    /// Matches the field name rather than the message text, so a reworded warn does not go red.
    struct HasBypassField(bool);

    impl tracing::field::Visit for HasBypassField {
        fn record_debug(&mut self, field: &tracing::field::Field, _value: &dyn std::fmt::Debug) {
            // `record_bool` (and every other typed recorder) defaults to `record_debug`, so this
            // one arm sees the `unauthenticated_bypass = true` field.
            if field.name() == "unauthenticated_bypass" {
                self.0 = true;
            }
        }
    }

    impl tracing::Subscriber for BypassWarnCounter {
        fn enabled(&self, _meta: &tracing::Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _attrs: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}
        fn event(&self, event: &tracing::Event<'_>) {
            if *event.metadata().level() != tracing::Level::WARN {
                return;
            }
            let mut visitor = HasBypassField(false);
            event.record(&mut visitor);
            if visitor.0 {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }
        fn enter(&self, _span: &tracing::span::Id) {}
        fn exit(&self, _span: &tracing::span::Id) {}
    }

    async fn get_status(app: &Router, uri: &str, auth: Option<&str>) -> StatusCode {
        let mut b = Request::builder().uri(uri);
        if let Some(a) = auth {
            b = b.header(header::AUTHORIZATION, a);
        }
        let req = b.body(Body::empty()).expect("request");
        app.clone().oneshot(req).await.expect("response").status()
    }

    // §11.6 (Authentication — a bearer API key): the `--allow-unauthenticated` dev bypass is warned
    // about loudly on EVERY request, not once at start-up — a start-up warn scrolls out of a
    // long-running daemon's log (finding `allow-unauthenticated-not-logged-per-request`). Two
    // requests ⇒ two warns. RED on both buggy implementations: a layer that drops the warn (0), and
    // a start-up-only or `Once`-guarded warn (1).
    #[tokio::test]
    async fn unauthenticated_bypass_warns_on_every_request() {
        let warns = Arc::new(AtomicUsize::new(0));
        let app = app_with(AuthPolicy::Unauthenticated);
        let guard = tracing::subscriber::set_default(BypassWarnCounter(warns.clone()));
        for _ in 0..2 {
            assert_eq!(
                get_status(&app, "/v1/vms", None).await,
                StatusCode::OK,
                "the dev bypass still serves the request"
            );
        }
        drop(guard);
        assert_eq!(
            warns.load(Ordering::SeqCst),
            2,
            "one loud warn PER request under --allow-unauthenticated"
        );
    }

    // The positive control for the warn: a properly authenticated request must NOT emit the
    // unprotected-API warn (a layer that warns unconditionally would make the signal worthless).
    #[tokio::test]
    async fn authenticated_request_does_not_warn() {
        let warns = Arc::new(AtomicUsize::new(0));
        let app = app_with(AuthPolicy::Key(ApiKey::from_secret(b"secret")));
        let guard = tracing::subscriber::set_default(BypassWarnCounter(warns.clone()));
        assert_eq!(
            get_status(&app, "/v1/vms", Some("Bearer secret")).await,
            StatusCode::OK
        );
        drop(guard);
        assert_eq!(
            warns.load(Ordering::SeqCst),
            0,
            "no bypass warn when a key authenticated"
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

    /// Substitutes a probe value for every `{param}` segment, so a table path becomes a request URI.
    fn concrete_path(path: &str) -> String {
        path.split('/')
            .map(|seg| if seg.starts_with('{') { "probe" } else { seg })
            .collect::<Vec<_>>()
            .join("/")
    }

    async fn status_for(app: &Router, method: &str, uri: &str, auth: Option<&str>) -> StatusCode {
        let mut b = Request::builder().method(method).uri(uri);
        if let Some(a) = auth {
            b = b.header(header::AUTHORIZATION, a);
        }
        let req = b.body(Body::empty()).expect("request");
        app.clone().oneshot(req).await.expect("response").status()
    }

    // P5, router side (finding `router-and-openapi-parity-compares-the-table-to-itself`): EVERY row
    // of `API_ROUTES` is mounted with its own method and path, in the subtree its `authenticated`
    // flag names. An unmounted row answers 404; a row that landed in the open subtree by mistake
    // answers 200 without a token. The whole authenticated set is exercised here — before this, ten
    // of the eleven had no router-side auth coverage at all. RED on the inverse: drop a row's
    // handler (404), or flip a row to `authenticated: false` (200 instead of 401).
    #[tokio::test]
    async fn every_api_route_is_mounted_in_the_subtree_its_flag_names() {
        let app = app();
        for route in API_ROUTES {
            let uri = concrete_path(route.path);
            let no_token = status_for(&app, route.method, &uri, None).await;
            assert_ne!(
                no_token,
                StatusCode::NOT_FOUND,
                "{} {} is in API_ROUTES but is not mounted",
                route.method,
                route.path
            );
            if route.authenticated {
                assert_eq!(
                    no_token,
                    StatusCode::UNAUTHORIZED,
                    "{} {} must be behind the bearer layer",
                    route.method,
                    route.path
                );
                assert_eq!(
                    status_for(&app, route.method, &uri, Some("Bearer wrong")).await,
                    StatusCode::FORBIDDEN,
                    "{} {} must reject a wrong key",
                    route.method,
                    route.path
                );
            } else {
                assert_eq!(
                    no_token,
                    StatusCode::OK,
                    "{} {} is an open route and must serve without a token",
                    route.method,
                    route.path
                );
            }
        }
    }

    // Every row of the table names a real handler. RED on the inverse: add a row to `API_ROUTES`
    // without wiring it — the router would mount `unwired`'s loud 500 instead of a handler.
    #[test]
    fn every_api_route_has_a_handler() {
        for route in API_ROUTES {
            assert!(
                method_router_for(route).is_some(),
                "{} {} has no handler in `method_router_for`",
                route.method,
                route.path
            );
        }
    }

    // The structural half of P5: the router is a FOLD over the table and mounts nothing else, so a
    // route cannot be added here alone (the exact drift the old prose claim could not catch). Two
    // mount sites, one per subtree, both inside the fold. RED on the inverse: hand-add any
    // `.route(...)` call to the production half and the count goes to three.
    #[test]
    fn the_router_is_a_fold_over_the_route_table_and_mounts_nothing_else() {
        let src = include_str!("server.rs");
        let prod = src
            .split("#[cfg(test)]")
            .next()
            .expect("the production half of this file");
        assert!(
            prod.contains("API_ROUTES.iter().fold("),
            "build_router must be generated FROM the route table"
        );
        assert_eq!(
            prod.matches(".route(").count(),
            2,
            "exactly two mount sites — the protected and open arms of the fold — may exist; a \
             hand-written route would be mounted without a table row (and so without an OpenAPI \
             operation and possibly without auth)"
        );
    }
}
