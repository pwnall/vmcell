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
    ResourceUsageDto, SnapshotInfo, SnapshotRequest, StoreUsage, VmId, VmInfo,
};
use crate::error::{DaemonError, DaemonResult};
use crate::openapi::{API_ROUTES, RouteDef, openapi_document};
use crate::uds::UdsBinding;
use axum::body::HttpBody as _;
use axum::body::{Body, BodyDataStream};
use axum::extract::{DefaultBodyLimit, Path as AxPath, Request, State};
use axum::http::{HeaderMap, StatusCode, Version, header};
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::{MethodRouter, any, delete, get, post, put};
use axum::{Json, Router};
use futures::StreamExt as _;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::Instant;

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
        ("GET", "/v1/store") => get(store_usage),
        ("POST", "/v1/vms") => post(create_vm),
        ("GET", "/v1/vms") => get(list_vms),
        ("GET", "/v1/vms/{id}") => get(get_vm),
        ("DELETE", "/v1/vms/{id}") => delete(destroy_vm),
        ("POST", "/v1/vms/{id}/exec") => post(exec_vm),
        ("GET", "/v1/vms/{id}/stats") => get(stats_vm),
        ("POST", "/v1/vms/{id}/snapshot") => post(snapshot_vm),
        ("POST", "/v1/vms/{id}/pause") => post(pause_vm),
        ("POST", "/v1/vms/{id}/resume") => post(resume_vm),
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
    let credential = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());
    let decision = match authorize(&state.auth, credential) {
        Ok(decision) => decision,
        Err(refusal) => {
            // The refusal-deliverability law (see [`MAX_REFUSAL_DRAIN_BYTES`]), one layer OUT from
            // the store's own refusals: a 401/403 is decided here, before anything polls the body,
            // so a client streaming a multi-megabyte artifact at a mistyped key had its typed
            // status wiped by the RST and saw a transport error instead. Same two rules, same one
            // predicate, same one drain — but on [`DrainBudget::unauthenticated`], because this is
            // the ONE drain a caller can start without having proved anything about itself, and a
            // refusal it is owed is ~100 bytes long.
            let (parts, body) = req.into_parts();
            if !client_offered_to_withhold(parts.version, &parts.headers, &body) {
                drain_refused_body(body, DrainBudget::unauthenticated()).await;
            }
            return Err(refusal);
        }
    };
    match decision {
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

/// `PUT /v1/artifacts/{name}` — the **streaming** upload (design §11.7, The client library and CLI;
/// §17, Open gaps and future capabilities).
///
/// Takes the raw [`Body`] rather than `Bytes` on purpose: the `Bytes` extractor buffers the whole
/// request before the handler runs, so a 4 GiB rootfs upload was a 4 GiB allocation in the
/// network-facing parent — and the store then had to be handed a slice it could only get by
/// materializing it. With the body raw, [`stream_body_into_store`] moves the upload one chunk at a
/// time and the store hashes/caps/writes as it flows.
///
/// The [`DefaultBodyLimit`] layer this subtree carries is an extractor-side limit and therefore does
/// **not** apply here (nothing on this path buffers for it to bound); the per-upload ceiling is
/// enforced chunk by chunk by [`crate::artifact_store::ArtifactWriter::write_chunk`], from the same
/// `max_bytes` the store was opened with — a lower ceiling than the layer's, checked earlier, and one
/// that bounds the DISK as well as the memory.
///
/// The [`Version`] and the [`HeaderMap`] are extracted **before** the body — every extractor but the
/// last must be a `FromRequestParts`, and the body is what gets consumed — and they are here for
/// exactly one reader: [`client_offered_to_withhold`], the first of the two refusal rules
/// ([`MAX_REFUSAL_DRAIN_BYTES`]), which needs all three of the request parts hyper's own decision
/// needs.
async fn create_artifact(
    State(state): State<AppState>,
    AxPath(name): AxPath<String>,
    version: Version,
    headers: HeaderMap,
    body: Body,
) -> DaemonResult<Json<ArtifactInfo>> {
    Ok(Json(
        stream_body_into_store(
            &state.artifacts,
            &name,
            version,
            &headers,
            body,
            state.max_artifact_bytes,
        )
        .await?,
    ))
}

/// The ceiling on how many bytes of a body we are **refusing** the daemon reads and throws away so
/// that the refusal can actually reach the client: 64 MiB.
///
/// # Why a refused upload is read at all
///
/// A TCP peer that closes its read side while unread data is still sitting in its receive queue
/// sends **RST**, and an RST makes the peer's kernel *discard the client's receive buffer* —
/// including a response the server had already written and the client had already received but not
/// yet parsed. So the refusal the daemon provably sent is destroyed by the very close that follows
/// it, and the client surfaces a transport error instead of the typed status. hyper's own error
/// classification then refuses to retry: the head is already serialized, so `take_message()` yields
/// `None` and hyper-util calls it `TrySendError::Nope` rather than `Retryable`.
///
/// DEFECT HISTORY. `vmcelld`'s `a_large_artifact_streams_up_and_is_digested_over_its_whole_body`
/// streams a 24 MiB artifact and then re-uploads the SAME name expecting the typed 409. It failed on
/// the first attempt on every commit measured — nextest's retries usually masked it and CI exhausted
/// them once — against a daemon that was answering correctly the whole time. The 409 was written,
/// then annihilated.
///
/// # Why not `Expect: 100-continue` alone
///
/// The protocol's own answer is for the client to offer to withhold its body until the server says
/// go, and hyper's **server** implements that correctly and lazily: it parses the token in
/// `Server::parse` (`hyper-1.11.0/src/proto/h1/role.rs:317-321`), and emits
/// `HTTP/1.1 100 Continue` only from inside `poll_read_body` (`conn.rs:409-420`), i.e. only if a
/// handler actually polls the body — and explicitly SKIPS it when the handler answered first
/// (`poll_drain_or_close_read`, `conn.rs:849-864`). Measured against this exact stack: a client that
/// genuinely withholds gets the typed 409 20/20 with the server reading the request head and **zero
/// body bytes**, and never sees a `100 Continue` on the wire.
///
/// hyper's **client** has no such thing. `Client::parse` hardcodes `expect_continue: false`
/// (`role.rs:1173`), `Client::encode` never inspects the header (`role.rs:1195-1240`), and
/// `Dispatcher::poll_write` pumps body frames on the next loop iteration gated only on
/// `state.writing` (`dispatch.rs:347-437`); `grep -rni '100-continue\|expect_continue' reqwest-0.13.4/src`
/// returns nothing. Setting the header from `vmcell-daemon-client` is decorative — measured at 0/20
/// typed 409s, and 4 transport errors *with* the header against 3 without over 100 interleaved
/// iterations. That is why the header is honored as an OPTIMIZATION for clients that really
/// implement it (curl's `-T` does) and is not the mechanism.
///
/// # The honest cost
///
/// A body **larger** than this budget — or slower than [`MAX_REFUSAL_DRAIN_TIME`] — is not fully
/// drained, so the connection still dies with data unread, the RST still fires, and the client still
/// sees a transport error. That is the documented limit of this fix, not a bug in it: the remedy at
/// any size is for the client to send `Expect: 100-continue`, which buys the zero-byte refusal
/// above. Bandwidth is the only cost paid here — nothing is hashed, buffered past one chunk, or
/// written to disk.
const MAX_REFUSAL_DRAIN_BYTES: u64 = 64 * 1024 * 1024;

/// The wall-clock half of an authenticated refusal's bound: however slowly the client sends, one
/// refusal drain is over within this.
///
/// **A byte ceiling alone does not bound a drain.** A client that sends ONE byte and then nothing
/// else never reaches the ceiling, so the drain's next poll simply pends — and the daemon holds the
/// connection, its task and its buffers for as long as that client cares to keep dripping. The
/// drain therefore carries a deadline as well as a ceiling, and it is an [`Instant`] fixed at
/// construction that bounds the WHOLE drain rather than the gap between two of its polls (AGENTS.md,
/// "Deadlines are `Instant`, propagated outer-bounds-inner"): a per-chunk timeout restarts at every
/// dripped byte and bounds nothing at all.
///
/// 30 s is sized against the ceiling above — a client placing the whole 64 MiB inside it is sending
/// at ~2 MB/s — and a slower one pays exactly the cost the ceiling documents.
const MAX_REFUSAL_DRAIN_TIME: Duration = Duration::from_secs(30);

/// The byte ceiling for a refusal decided **before** the request authenticated: 1 MiB, sixty-four
/// times smaller than [`MAX_REFUSAL_DRAIN_BYTES`].
///
/// [`auth_layer`] refuses before any handler runs and before anything has established who is
/// sending, so its drain is the one an anonymous caller can start. Spending
/// `min(--max-artifact-bytes, 64 MiB)` of read bandwidth there would hand every such caller a
/// bandwidth sink; the refusal it is owed is a ~100-byte 401/403, and a client that hits one is
/// misconfigured, not mid-upload.
///
/// Not smaller, though: hyper absorbs up to `DEFAULT_MAX_BUFFER_SIZE` (~408 KiB,
/// `hyper-1.11.0/src/proto/h1/io.rs:22`) in the single `poll_read_body` its own
/// `poll_drain_or_close_read` performs (`conn.rs:847-864`), so a ceiling below that would buy
/// nothing the stack was not already doing.
const MAX_UNAUTHENTICATED_DRAIN_BYTES: u64 = 1024 * 1024;

/// The wall-clock half of the same, and the reason an anonymous slow-drip is released promptly
/// rather than eventually: 2 s.
const MAX_UNAUTHENTICATED_DRAIN_TIME: Duration = Duration::from_secs(2);

/// The bound on ONE refusal drain, in both of its dimensions — and the parameter that keeps
/// [`drain_data_stream`] the single drain for every refusal site, at whatever budget its site earns.
#[derive(Debug, Clone, Copy)]
struct DrainBudget {
    /// Bytes that may be read and discarded before the drain gives up.
    bytes: u64,
    /// The instant the WHOLE drain must be over by. Absolute, fixed at construction and never
    /// refreshed, so every poll in the loop is bounded by the same deadline.
    deadline: Instant,
}

impl DrainBudget {
    /// The budget for a refusal an **authenticated** request earned: no more than this upload could
    /// ever have been stored as, never more than [`MAX_REFUSAL_DRAIN_BYTES`], and over within
    /// [`MAX_REFUSAL_DRAIN_TIME`].
    ///
    /// The `min` is why a small `--max-artifact-bytes` also shrinks the refusal's bandwidth cost: a
    /// body past the per-upload cap was doomed to a 413 anyway, so discarding more of it than the
    /// store would ever have accepted buys nothing.
    ///
    /// Built **at** the refusal site, never carried down from the start of the request: a deadline
    /// minted when the head was parsed is already spent by the time a slow multi-gigabyte upload
    /// reaches the mid-stream cap, which is the site whose refusal most needs draining.
    fn authenticated(max_artifact_bytes: usize) -> Self {
        Self {
            bytes: u64::try_from(max_artifact_bytes)
                .unwrap_or(u64::MAX)
                .min(MAX_REFUSAL_DRAIN_BYTES),
            deadline: Instant::now() + MAX_REFUSAL_DRAIN_TIME,
        }
    }

    /// The budget for a refusal decided **before** authentication — [`auth_layer`]'s 401/403, the
    /// only drain an anonymous caller can start ([`MAX_UNAUTHENTICATED_DRAIN_BYTES`]).
    fn unauthenticated() -> Self {
        Self {
            bytes: MAX_UNAUTHENTICATED_DRAIN_BYTES,
            deadline: Instant::now() + MAX_UNAUTHENTICATED_DRAIN_TIME,
        }
    }
}

/// The ONE reading of `Expect: 100-continue`: did the client offer to withhold its body until the
/// server asks for it?
///
/// Matched **exactly as hyper matches it** — all THREE of hyper's conditions, not just the header —
/// because hyper's server is what acts on the offer, and a looser reading here skips the drain for a
/// client that is in fact already sending, which is the defect this whole path exists to fix,
/// reintroduced through the front door. hyper decides in two places:
///
/// * `hyper-1.11.0/src/proto/h1/role.rs:317-321` runs
///   `expect_continue = value.as_bytes().eq_ignore_ascii_case(b"100-continue")` inside the header
///   loop. Two consequences the obvious implementations get wrong: it is an **assignment**, not an
///   accumulation, so with several `Expect` headers the **last** one wins (an `any()`-style match
///   over `get_all` says "offer" where hyper says none); and the whole value must equal the token,
///   so `100-continue, foo` is **not** an offer (a `contains`-style match says "offer" where hyper
///   says none).
/// * `conn.rs:303-320` then applies two more conditions before hyper will hold a body back at all:
///   an **empty** body ignores the expectation outright ("ignoring expect-continue since body is
///   empty" — there is nothing to withhold), and the version must be **greater than HTTP/1.0**, so a
///   1.0 client's `Expect` is ignored and its body arrives unasked.
///
/// Emptiness is asked of the BODY rather than re-derived from `Content-Length`/`Transfer-Encoding`:
/// `Incoming::size_hint` is hyper's own `DecodedLength` (`incoming.rs:303-323`), so this reads
/// hyper's decision instead of being a second header parser free to disagree with it. A chunked
/// body — no exact size hint, the shape `vmcell-daemon-client` actually sends — is therefore not
/// empty, and the offer stands.
///
/// Every mistake here fails in the dangerous direction: the daemon skips the drain, the client sends
/// anyway, and the refusal is lost exactly as before.
fn client_offered_to_withhold(version: Version, headers: &HeaderMap, body: &Body) -> bool {
    let offered = headers
        .get_all(header::EXPECT)
        .iter()
        .next_back()
        .is_some_and(|value| value.as_bytes().eq_ignore_ascii_case(b"100-continue"));
    offered && body.size_hint().exact() != Some(0) && version > Version::HTTP_10
}

/// What ended a refusal drain — so the log (and the gate) can tell "the body ended inside the
/// budget, the refusal is deliverable" from "the ceiling was hit, the connection is about to die".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DrainEnd {
    /// The body ended within the budget: nothing is left unread, the close is a clean FIN, and the
    /// typed refusal reaches the client.
    Eof,
    /// The byte ceiling was reached first. Data is still unread at close, so the RST fires and the
    /// client still sees a transport error — the documented cost on [`MAX_REFUSAL_DRAIN_BYTES`].
    Budget,
    /// The wall-clock deadline came first: the client is still sending, or still claims to be, but
    /// slowly enough that continuing would be a hold rather than a courtesy. Same consequence as
    /// [`DrainEnd::Budget`] — bytes unread at close, RST, transport error.
    Deadline,
    /// The body itself failed mid-drain (the client went away). There is nothing left to read and
    /// nothing to deliver the refusal to.
    Failed,
}

/// The outcome of one refusal drain: how many bytes were discarded, and what stopped it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DrainOutcome {
    /// Bytes read off the wire and dropped. May exceed `budget` by at most the size of the one
    /// chunk that crossed it — a chunk is already off the socket by the time it is counted.
    bytes: u64,
    /// What ended the drain.
    end: DrainEnd,
}

/// Reads and **discards** at most `budget` bytes of a body the daemon has already decided to refuse,
/// so the refusal is deliverable ([`MAX_REFUSAL_DRAIN_BYTES`] carries the whole rationale).
///
/// Nothing is hashed, accumulated, or written: each chunk is dropped at the end of its iteration, so
/// the resident cost is one chunk however long the client keeps sending.
async fn drain_refused_body(body: Body, budget: DrainBudget) -> DrainOutcome {
    drain_data_stream(&mut body.into_data_stream(), budget).await
}

/// The one drain loop, shared by both refusal shapes: [`drain_refused_body`] for a body nothing has
/// polled yet, and the ingest loop's cap/quota arm for one already in flight.
async fn drain_data_stream(chunks: &mut BodyDataStream, budget: DrainBudget) -> DrainOutcome {
    let mut bytes: u64 = 0;
    let end = loop {
        if bytes >= budget.bytes {
            break DrainEnd::Budget;
        }
        // `timeout_at` against the budget's ABSOLUTE deadline, never a fresh per-chunk duration:
        // the same instant bounds every poll, so a client dripping one byte at a time cannot extend
        // the drain past it. A relative timeout here would restart at every byte and bound only the
        // gaps between them — the very shape AGENTS.md names.
        match tokio::time::timeout_at(budget.deadline, chunks.next()).await {
            Err(_elapsed) => break DrainEnd::Deadline,
            Ok(None) => break DrainEnd::Eof,
            Ok(Some(Ok(chunk))) => {
                // Counted, then dropped at the end of this iteration. Never hashed, never kept.
                bytes = bytes.saturating_add(u64::try_from(chunk.len()).unwrap_or(u64::MAX));
            }
            Ok(Some(Err(e))) => {
                // An explicit arm, not a bare `let _ =`: the client went away mid-drain, which ends
                // the drain and is worth a line, but is not itself the error we are reporting — the
                // refusal that started the drain is.
                tracing::debug!(
                    drained_bytes = bytes,
                    "the body of a refused request failed mid-drain: {e}"
                );
                break DrainEnd::Failed;
            }
        }
    };
    match end {
        // The two states in which the daemon KNOWS the refusal it just decided will not be
        // received: bytes are still unread at close, so the RST fires and the typed status is
        // destroyed. Both call sites discard the [`DrainOutcome`], so this line is the only place
        // that fact surfaces — it is an operator-visible event with a named remedy, not a debug
        // detail, and it is what tells an operator their `--max-artifact-bytes` (or a client) needs
        // changing rather than leaving them to diagnose a transport error twice.
        DrainEnd::Budget | DrainEnd::Deadline => tracing::warn!(
            drained_bytes = bytes,
            budget_bytes = budget.bytes,
            ?end,
            undeliverable_refusal = true,
            "a refused request's body outran the drain budget (see `end`: the byte ceiling or the \
             deadline): the connection closes with data unread, so the client will see a transport \
             error INSTEAD of the refusal — the remedy is for it to send `Expect: 100-continue`, \
             which is answered without reading a body at all"
        ),
        DrainEnd::Eof | DrainEnd::Failed => tracing::debug!(
            drained_bytes = bytes,
            budget_bytes = budget.bytes,
            ?end,
            "discarded the body of a refused request so the refusal is deliverable"
        ),
    }
    DrainOutcome { bytes, end }
}

/// The one ingest loop: drain `body` chunk by chunk into a create-only, atomic, digest-sidecar'd
/// store write.
///
/// Ordered so that **nothing is read INTO THE STORE before the name is cleared**:
/// `create_streaming` refuses a reserved `.sha256` suffix, an invalid name, an already-taken one, or
/// a full store before the first chunk is pulled, so no byte of a doomed request is ever hashed,
/// buffered or written to disk.
///
/// What a *refused* request costs is then decided by the two rules on
/// [`MAX_REFUSAL_DRAIN_BYTES`], because a refusal nobody can receive is not a refusal:
///
/// 1. the client offered to withhold (`Expect: 100-continue`) — answer having read **zero** body
///    bytes, which is also the state hyper needs to skip its own `100 Continue`;
/// 2. otherwise — read and **discard** up to `budget` bytes so the close is a clean FIN rather than
///    an RST that destroys the response.
///
/// **A torn upload publishes nothing.** Every failure path — a client that disconnects mid-body, a
/// chunk that crosses the cap, an I/O error — returns through `?`, which drops the
/// [`crate::artifact_store::ArtifactWriter`]; its temp file goes with it and the artifact's name was
/// never claimed (the claim is the rename inside `finish`). So there is no cleanup path here that
/// could itself be wrong.
///
/// # Errors
/// The store's typed errors (`InvalidName`/`BadRequest`/`AlreadyExists`/`PayloadTooLarge`/`Internal`),
/// plus [`DaemonError::BadRequest`] when the client's body fails mid-stream — the request was
/// incomplete, which is the client's condition to report, not a server fault.
async fn stream_body_into_store(
    store: &ArtifactStore,
    name: &str,
    version: Version,
    headers: &HeaderMap,
    body: Body,
    max_artifact_bytes: usize,
) -> DaemonResult<ArtifactInfo> {
    let mut writer = match store.create_streaming(name) {
        Ok(writer) => writer,
        Err(refusal) => {
            // Rule 1 / rule 2. The body is still UNPOLLED at this point, which is exactly why the
            // `Expect` arm is honest: hyper emits its `100 Continue` from inside `poll_read_body`
            // (`hyper-1.11.0/src/proto/h1/conn.rs:409-420`), so a refusal that never polls is one
            // the withholding client answers to with zero bytes and no interim response.
            if !client_offered_to_withhold(version, headers, &body) {
                drain_refused_body(body, DrainBudget::authenticated(max_artifact_bytes)).await;
            }
            return Err(refusal);
        }
    };
    let mut chunks = body.into_data_stream();
    while let Some(chunk) = chunks.next().await {
        let chunk = match chunk {
            Ok(chunk) => chunk,
            // The BODY failed, not the store: the stream is spent, there is nothing left to drain,
            // and polling a stream past its own error is not a contract hyper offers.
            Err(e) => {
                return Err(DaemonError::BadRequest(format!(
                    "the upload body for artifact {name:?} failed mid-stream after {} bytes: {e}",
                    writer.written()
                )));
            }
        };
        if let Err(refusal) = writer.write_chunk(&chunk) {
            // The cap/quota refusal — the same undeliverable-response defect, one state later. Here
            // the `Expect` offer is SPENT and is deliberately not consulted: hyper emitted the
            // `100 Continue` at the first poll above and the client is demonstrably sending, so
            // "it offered to withhold" is no longer true of the bytes still coming.
            //
            // The budget is a FRESH `DrainBudget::authenticated` rather than what is left of one —
            // a deliberate shift from the sketch in the plan, which spent `budget - writer.written()`
            // and so computed **zero** in the ordinary case (a body refused *at* the cap has already
            // consumed the whole budget), making this arm a no-op exactly where it is needed. The
            // bound stays honest: a refused upload costs at most `cap + budget` read bytes, versus
            // the `cap` the same client may already spend on the accept path — and a fresh DEADLINE
            // is the point of building it here, since one minted at the head of a slow
            // multi-gigabyte upload is long expired by the time the cap refuses.
            //
            // The writer goes first, and before the drain rather than after it: it owns an open
            // temp file holding everything received up to the cap, and the drain that follows may
            // run for the whole of `MAX_REFUSAL_DRAIN_TIME`. Dropping it here unlinks that file
            // (`NamedTempFile`'s `Drop`) before the wait instead of keeping up to
            // `--max-artifact-bytes` of a refused upload on disk throughout it.
            drop(writer);
            drain_data_stream(&mut chunks, DrainBudget::authenticated(max_artifact_bytes)).await;
            return Err(refusal);
        }
    }
    writer.finish()
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

/// `GET /v1/store` — the store's usage against its quota (design §17, Open gaps and future
/// capabilities). Served by the parent's own store handle: this is unprivileged file I/O, so it
/// never crosses to the engine.
async fn store_usage(State(state): State<AppState>) -> DaemonResult<Json<StoreUsage>> {
    Ok(Json(state.artifacts.usage()?))
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

/// `POST /v1/vms/{id}/pause` — stop the guest's vCPUs, leaving every host resource held. The reply
/// is the VM's info, so the client reads the state it moved to rather than inferring it.
async fn pause_vm(
    State(state): State<AppState>,
    AxPath(id): AxPath<String>,
) -> DaemonResult<Json<VmInfo>> {
    Ok(Json(state.engine.pause(&VmId(id)).await?))
}

/// `POST /v1/vms/{id}/resume` — restart a paused guest's vCPUs.
async fn resume_vm(
    State(state): State<AppState>,
    AxPath(id): AxPath<String>,
) -> DaemonResult<Json<VmInfo>> {
    Ok(Json(state.engine.resume(&VmId(id)).await?))
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

/// Serves the API on a **Unix-domain socket** — the same router, the same auth (design §17, Open
/// gaps and future capabilities; [`crate::uds`] owns the socket's location and permissions).
///
/// The router is [`build_router`], byte for byte the one [`serve`] mounts: auth is a property of the
/// route table, not of the transport, so the UDS is authenticated by exactly the same middleware
/// over exactly the same rows (the reasoning, including why the socket's `0700`/`0600` permissions
/// are defence in depth rather than a substitute for the key, is recorded in [`crate::uds`]).
///
/// Takes the [`UdsBinding`] whole and destructures it, so the unlink-on-drop guard lives for the
/// entire serve and the socket is removed when this returns — teardown is ownership.
///
/// # Errors
/// Propagates a fatal `axum::serve` I/O error.
pub async fn serve_uds(state: AppState, binding: UdsBinding) -> std::io::Result<()> {
    let UdsBinding { listener, guard } = binding;
    tracing::info!(socket = %guard.path().display(), "vmcelld serving on the control socket");
    let result = axum::serve(listener, build_router(state).into_make_service()).await;
    drop(guard);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact_store::ArtifactStore;
    use crate::auth::ApiKey;
    use crate::launcher::{LaunchSpec, VmHandle, VmLauncher};
    use crate::registry::Registry;
    use axum::body::Body;
    use axum::http::HeaderValue;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
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
        app_with_artifacts_dir(auth).0
    }

    /// The router **and** the artifacts directory behind it, so an upload gate can assert on the
    /// store the handler actually wrote into (and on the temp residue beside it).
    fn app_with_artifacts_dir(auth: AuthPolicy) -> (Router, std::path::PathBuf) {
        let (state, dir) = state_with(auth);
        (build_router(state), dir)
    }

    /// The [`AppState`] the router is built from — needed whole by the UDS gate, which serves it
    /// through [`serve_uds`] rather than through `oneshot`.
    fn state_with(auth: AuthPolicy) -> (AppState, std::path::PathBuf) {
        state_with_cap(auth, 1 << 20)
    }

    /// The same, with the per-upload cap as a knob. The cap is also the refusal-drain budget
    /// ([`DrainBudget::authenticated`]), and the cap gate has to size its body against hyper's own read
    /// buffer — `DEFAULT_MAX_BUFFER_SIZE`, 8192 + 4096*100 ≈ 408 KiB — which is what a server that
    /// does NOT drain can still absorb in the one `poll_read_body` that
    /// `poll_drain_or_close_read` gives it (`hyper-1.11.0/src/proto/h1/conn.rs:847-864`). A body
    /// whose tail fits that buffer is drained by hyper itself and discriminates nothing: the first
    /// cut of that gate used a 1.5 MiB body against a 1 MiB cap and stayed GREEN with the drain
    /// deleted.
    fn state_with_cap(
        auth: AuthPolicy,
        max_artifact_bytes: usize,
    ) -> (AppState, std::path::PathBuf) {
        let store_cap = u64::try_from(max_artifact_bytes).expect("a representable cap");
        let dir = Box::leak(Box::new(tempfile::tempdir().expect("tempdir")));
        let art_dir = dir.path().join("artifacts");
        // The engine (registry) and the parent's artifact store are separate seams over the same
        // dir (design §12.4, Layer 3 — the setup broker (network surface never holds caps)) — the wiring tests only exercise routing/auth, so no VM is launched.
        let registry = Registry::new(
            Box::new(UnusedLauncher),
            ArtifactStore::open(&art_dir, store_cap).expect("registry store"),
            1,
        );
        let state = AppState {
            engine: Arc::new(registry),
            artifacts: Arc::new(ArtifactStore::open(&art_dir, store_cap).expect("parent store")),
            auth,
            max_artifact_bytes,
        };
        (state, art_dir)
    }

    /// One HTTP/1.1 request over the control socket, hand-written onto the wire and read back whole.
    ///
    /// Hand-rolled deliberately: this crate has no HTTP *client*, and the point of the gate is that
    /// a real connection to a real socket reaches the same authenticated router — a `oneshot`
    /// against the `Router` value would prove nothing about the transport.
    async fn over_uds(path: &std::path::Path, target: &str, auth: Option<&str>) -> String {
        let mut sock = tokio::net::UnixStream::connect(path)
            .await
            .expect("connect to the control socket");
        let mut req = format!("GET {target} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n");
        if let Some(a) = auth {
            req.push_str(&format!("Authorization: {a}\r\n"));
        }
        req.push_str("\r\n");
        sock.write_all(req.as_bytes()).await.expect("write request");
        sock.flush().await.expect("flush");
        let mut out = String::new();
        sock.read_to_string(&mut out).await.expect("read response");
        out
    }

    // The UDS transport carries the SAME authenticated router as the TCP bind (design §17, Open gaps
    // and future capabilities; the decision is recorded in `crate::uds`). Asserted over a real
    // socket with real requests, not against a `Router` value:
    //
    //   * an open route answers without a token,
    //   * a protected route is 401 without one and 403 with a wrong one — the API key is NOT dropped
    //     because the transport is local,
    //   * the right token reaches the handler and returns its BODY (`[]`, the empty VM list), so the
    //     leg proves the request was served rather than merely admitted, and
    //   * the socket is unlinked when serving stops (teardown is ownership).
    //
    // RED on the inverse: have `serve_uds` build a router without the auth layer (or serve
    // `AuthPolicy::Unauthenticated` regardless of the state) — the 401 and 403 legs go 200.
    #[tokio::test]
    async fn the_uds_transport_serves_the_same_authenticated_router() {
        let (state, _art) = state_with(AuthPolicy::Key(ApiKey::from_secret(b"secret")));
        let rt_dir = tempfile::tempdir().expect("tempdir");
        let socket = crate::uds::uds_path_under_runtime_dir(Some(rt_dir.path().to_path_buf()))
            .expect("the socket path resolves under a runtime dir");
        let binding = crate::uds::bind_uds(&socket).expect("bind the control socket");
        let serving = tokio::spawn(serve_uds(state, binding));

        assert!(
            over_uds(&socket, "/healthz", None).await.contains("200 OK"),
            "an open route answers over the socket without a token"
        );
        assert!(
            over_uds(&socket, "/v1/vms", None).await.contains("401"),
            "a protected route still demands the bearer key on a local socket"
        );
        assert!(
            over_uds(&socket, "/v1/vms", Some("Bearer wrong"))
                .await
                .contains("403"),
            "a wrong key is still 403 on a local socket"
        );
        let ok = over_uds(&socket, "/v1/vms", Some("Bearer secret")).await;
        assert!(ok.contains("200 OK"), "the right key is served: {ok}");
        assert!(
            ok.trim_end().ends_with("[]"),
            "and the handler's own body comes back over the socket: {ok}"
        );

        serving.abort();
        // The abort drops the `UdsPathGuard` the serve was holding.
        while socket.exists() {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    }

    // `GET /v1/store` is authenticated like every other route and answers with the store's real
    // usage — the data plane, not just a status. Without it the quota is enforceable but not
    // observable, and a client's first news of a full store is a 413 on an upload it already began.
    //
    // RED on the inverse: drop the `("GET", "/v1/store")` arm from `method_router_for` and the row
    // falls through to the loud `unwired` 500 instead of 200.
    #[tokio::test]
    async fn the_store_usage_route_is_authenticated_and_reports_real_bytes() {
        let (app, art_dir) =
            app_with_artifacts_dir(AuthPolicy::Key(ApiKey::from_secret(b"secret")));
        std::fs::create_dir_all(&art_dir).expect("artifacts dir");
        std::fs::write(art_dir.join("k1"), b"0123456789").expect("plant an artifact");

        assert_eq!(
            get_status(&app, "/v1/store", None).await,
            StatusCode::UNAUTHORIZED,
            "the store report is not an open route"
        );

        let req = Request::builder()
            .uri("/v1/store")
            .header(header::AUTHORIZATION, "Bearer secret")
            .body(Body::empty())
            .expect("request");
        let resp = app.clone().oneshot(req).await.expect("response");
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .expect("body");
        let usage: StoreUsage = serde_json::from_slice(&body).expect("decode StoreUsage");
        assert_eq!(usage.used_bytes, 10, "the bytes actually on disk");
        assert_eq!(usage.artifact_count, 1);
        assert_eq!(usage.quota_bytes, None, "this store is unbounded");
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

    /// Makes the log gates in this file OBSERVABLE, and must be called by each of them before it
    /// installs its own counter.
    ///
    /// `tracing::subscriber::set_default` is thread-local, but a callsite's `Interest` is cached
    /// **process-wide** the first time that callsite is hit — and `cargo test` runs every test in ONE
    /// process. When exactly one dispatcher is registered, that cache is computed from whatever the
    /// REGISTERING THREAD's default happens to be (`tracing-core-0.1.36/src/callsite.rs:410-414`, the
    /// `Rebuilder::JustOne` arm, which resolves through `dispatcher::get_default`). So a sibling test
    /// that reaches the same `warn!` from a thread with no subscriber — every wire gate below does,
    /// through the drain's own budget arm — caches `Interest::never()` for the whole process, and the
    /// gate's event is then skipped before it is ever dispatched. Measured as a 1-in-26 failure of
    /// the undeliverable-refusal gate (`left: 0, right: 1`), and reproduced 4/4 by holding the
    /// gate's subscriber for 400 ms while a sibling registered the callsite.
    ///
    /// One process-wide, always-interested no-op subscriber removes the ambiguity: every dispatcher
    /// in the registry then answers `Interest::always()`, whichever thread registers the callsite
    /// first, and a gate's own scoped counter still wins on the thread that installed it. It records
    /// nothing — its `hits` counter is never read — and a global default is installed at most once,
    /// which the `Once` and the `expect` together assert.
    fn keep_log_gates_observable() {
        static INSTALLED: std::sync::Once = std::sync::Once::new();
        INSTALLED.call_once(|| {
            tracing::subscriber::set_global_default(WarnFieldCounter {
                field: "no field is named this, and this counter is never read",
                hits: Arc::new(AtomicUsize::new(0)),
            })
            .expect("this test process installs no other global tracing subscriber");
        });
    }

    /// A minimal `tracing::Subscriber` that counts WARN events carrying a NAMED field. Hand-rolled
    /// because the crate has no `tracing-subscriber` dev-dependency, and counting the events the
    /// code actually emits is the only way to gate a claim about logging (a test that only asserts
    /// the value a function returned would still pass on a caller that logs it at `debug`, or not at
    /// all). One counter serves both logging claims in this file — the `--allow-unauthenticated`
    /// bypass warn and the undeliverable-refusal warn — because a second copy of a subscriber is a
    /// second thing to keep right.
    #[derive(Clone)]
    struct WarnFieldCounter {
        /// The field whose presence on a WARN event is the claim.
        field: &'static str,
        /// How many such events were seen.
        hits: Arc<AtomicUsize>,
    }

    /// Matches the field name rather than the message text, so a reworded warn does not go red.
    struct HasField {
        want: &'static str,
        seen: bool,
    }

    impl tracing::field::Visit for HasField {
        fn record_debug(&mut self, field: &tracing::field::Field, _value: &dyn std::fmt::Debug) {
            // `record_bool` (and every other typed recorder) defaults to `record_debug`, so this
            // one arm sees a `<name> = true` field.
            if field.name() == self.want {
                self.seen = true;
            }
        }
    }

    impl tracing::Subscriber for WarnFieldCounter {
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
            let mut visitor = HasField {
                want: self.field,
                seen: false,
            };
            event.record(&mut visitor);
            if visitor.seen {
                self.hits.fetch_add(1, Ordering::SeqCst);
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
        keep_log_gates_observable();
        let warns = Arc::new(AtomicUsize::new(0));
        let app = app_with(AuthPolicy::Unauthenticated);
        let guard = tracing::subscriber::set_default(WarnFieldCounter {
            field: "unauthenticated_bypass",
            hits: warns.clone(),
        });
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
        keep_log_gates_observable();
        let warns = Arc::new(AtomicUsize::new(0));
        let app = app_with(AuthPolicy::Key(ApiKey::from_secret(b"secret")));
        let guard = tracing::subscriber::set_default(WarnFieldCounter {
            field: "unauthenticated_bypass",
            hits: warns.clone(),
        });
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

    // The vCPU routes are wired to the ENGINE, not to the loud `unwired` placeholder: an
    // authenticated `pause`/`resume` of an id no registry holds comes back as the engine's typed
    // 404, with its structured body — a row with no handler would answer the 500 `unwired` renders,
    // and a row mounted on the wrong verb would answer 204/200. RED on the inverse: drop either arm
    // from `method_router_for`.
    #[tokio::test]
    async fn the_vcpu_routes_reach_the_engine_and_render_its_typed_error() {
        let app = app();
        for path in ["/v1/vms/probe/pause", "/v1/vms/probe/resume"] {
            let req = Request::builder()
                .method("POST")
                .uri(path)
                .header(header::AUTHORIZATION, "Bearer secret")
                .body(Body::empty())
                .expect("request");
            let resp = app.clone().oneshot(req).await.expect("response");
            assert_eq!(
                resp.status(),
                StatusCode::NOT_FOUND,
                "{path} must reach the engine, which owns no such VM"
            );
            let body = axum::body::to_bytes(resp.into_body(), 64 * 1024)
                .await
                .expect("body");
            let parsed: serde_json::Value = serde_json::from_slice(&body).expect("error body");
            assert_eq!(parsed["error"], "not_found", "{path} body: {parsed}");
            assert!(
                parsed["message"]
                    .as_str()
                    .is_some_and(|m| m.contains("no vm probe")),
                "{path} must name the VM it could not find: {parsed}"
            );
        }
    }

    // ---- the streaming artifact upload (design §11.7, The client library and CLI; §17, Open gaps
    // and future capabilities — "Streaming upload (v1 reads the file into memory)") ----

    /// The temp files an in-flight upload leaves in the artifacts dir.
    fn temp_files(dir: &std::path::Path) -> usize {
        std::fs::read_dir(dir)
            .expect("readdir")
            .flatten()
            .filter(|e| {
                e.file_name()
                    .to_string_lossy()
                    .starts_with(crate::artifact_store::UPLOAD_TEMP_PREFIX)
            })
            .count()
    }

    fn upload_request(uri: &str, body: Body) -> Request<Body> {
        Request::builder()
            .method("PUT")
            .uri(uri)
            .header(header::AUTHORIZATION, "Bearer secret")
            .body(body)
            .expect("request")
    }

    // A body arriving in many chunks — more than any single buffer the handler holds — is stored
    // byte-exact and answered with the digest of what was stored. The chunk count is the point: the
    // handler never sees the whole body at once, and the digest is still right.
    //
    // RED on the inverse (`body: Bytes` + `store.create(&name, &body)`, the pre-streaming handler):
    // this still passes — buffering is not observable from outside — which is exactly why the
    // NON-buffering claim is gated separately, by the mid-flight residue leg below and by the
    // client's own `Path`-arm gate. What this leg proves is that the streaming path did not LOSE
    // anything: no dropped chunk, no reordered write, no digest computed over a prefix.
    #[tokio::test]
    async fn a_multi_chunk_upload_is_stored_byte_exact_and_digested() {
        let (app, dir) = app_with_artifacts_dir(AuthPolicy::Key(ApiKey::from_secret(b"secret")));
        let chunk: Vec<u8> = (0..64 * 1024).map(|i| (i % 251) as u8).collect();
        let chunks = 12; // 768 KiB, inside the 1 MiB per-upload cap this test app carries
        let expected: Vec<u8> = chunk
            .iter()
            .cycle()
            .take(chunk.len() * chunks)
            .copied()
            .collect();

        let stream = futures::stream::iter(
            std::iter::repeat_n(chunk.clone(), chunks)
                .map(Ok::<Vec<u8>, std::io::Error>)
                .collect::<Vec<_>>(),
        );
        let resp = app
            .clone()
            .oneshot(upload_request(
                "/v1/artifacts/rootfs",
                Body::from_stream(stream),
            ))
            .await
            .expect("response");
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .expect("body");
        let info: ArtifactInfo = serde_json::from_slice(&body).expect("ArtifactInfo");
        assert_eq!(info.size_bytes, expected.len() as u64);
        assert_eq!(
            info.sha256,
            crate::artifact_store::hex_sha256(&expected),
            "the reply's digest is the digest of what was sent"
        );
        assert_eq!(
            std::fs::read(dir.join("rootfs")).expect("read back"),
            expected,
            "and the stored bytes are the ones that were sent"
        );
        assert_eq!(
            temp_files(&dir),
            0,
            "no temp residue after a published upload"
        );
    }

    // The per-upload cap binds a STREAM: the request is refused at the chunk that crosses it, with
    // the typed 413 the buffered path already returned, and nothing is published. The client cannot
    // make the daemon fill its artifacts filesystem by simply never stopping.
    //
    // RED on the inverse (a cap checked only in `finish`, or only by the `DefaultBodyLimit` layer —
    // which does not apply to a raw-`Body` handler at all): the upload is accepted, or the temp file
    // grows past the ceiling before anything notices.
    #[tokio::test]
    async fn an_over_cap_streamed_upload_is_a_typed_413_with_nothing_published() {
        let (app, dir) = app_with_artifacts_dir(AuthPolicy::Key(ApiKey::from_secret(b"secret")));
        // 32 x 64 KiB = 2 MiB against this app's 1 MiB per-upload cap.
        let stream = futures::stream::iter(
            std::iter::repeat_n(vec![0u8; 64 * 1024], 32)
                .map(Ok::<Vec<u8>, std::io::Error>)
                .collect::<Vec<_>>(),
        );
        let resp = app
            .oneshot(upload_request(
                "/v1/artifacts/toobig",
                Body::from_stream(stream),
            ))
            .await
            .expect("response");
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
        let body = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .expect("body");
        let parsed: serde_json::Value = serde_json::from_slice(&body).expect("error body");
        assert_eq!(parsed["error"], "payload_too_large", "body: {parsed}");
        assert!(!dir.join("toobig").exists(), "nothing was published");
        assert_eq!(temp_files(&dir), 0, "and no residue was left behind");
    }

    // The torn upload, end to end: the client disconnects mid-body. The residue check runs in the
    // order AGENTS.md prescribes — the temp file is observed to EXIST while the body is still
    // arriving (from inside the stream itself), and afterwards it is gone — and the artifact was
    // never published under its real name.
    //
    // RED on the inverse (a handler that publishes what it received, or one that only removes its
    // temp file on the success path): `rootfs` exists after the tear, or a `.tmp…` file survives in
    // a store whose `list` deliberately hides it.
    #[tokio::test]
    async fn a_torn_upload_publishes_nothing_and_leaves_no_temp_behind() {
        let (app, dir) = app_with_artifacts_dir(AuthPolicy::Key(ApiKey::from_secret(b"secret")));
        let seen_mid_flight = Arc::new(std::sync::atomic::AtomicUsize::new(0));

        let probe_dir = dir.clone();
        let probe = seen_mid_flight.clone();
        let stream = futures::stream::unfold(0usize, move |i| {
            let probe_dir = probe_dir.clone();
            let probe = probe.clone();
            async move {
                match i {
                    // Mid-flight: the upload's bytes are on disk under a temp name, and the
                    // artifact's own name holds nothing.
                    2 => {
                        probe.store(temp_files(&probe_dir), Ordering::SeqCst);
                        assert!(
                            !probe_dir.join("rootfs").exists(),
                            "an in-flight upload must not be readable under its real name"
                        );
                        Some((Ok(vec![0xABu8; 64 * 1024]), i + 1))
                    }
                    // …and the client goes away.
                    4 => Some((
                        Err(std::io::Error::other("the client went away mid-upload")),
                        i + 1,
                    )),
                    _ if i > 4 => None,
                    _ => Some((Ok(vec![0xABu8; 64 * 1024]), i + 1)),
                }
            }
        });

        let resp = app
            .clone()
            .oneshot(upload_request(
                "/v1/artifacts/rootfs",
                Body::from_stream(stream),
            ))
            .await
            .expect("response");
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "an incomplete body is the client's condition to report"
        );
        assert_eq!(
            seen_mid_flight.load(Ordering::SeqCst),
            1,
            "the upload really was in flight, with its bytes in a temp file"
        );
        assert!(!dir.join("rootfs").exists(), "nothing was published");
        assert_eq!(
            temp_files(&dir),
            0,
            "and the temp file went with the request"
        );

        // Positive control: the torn upload burned nothing — the same name uploads cleanly after.
        let resp = app
            .oneshot(upload_request(
                "/v1/artifacts/rootfs",
                Body::from(b"whole".to_vec()),
            ))
            .await
            .expect("response");
        assert_eq!(resp.status(), StatusCode::OK, "the name is still free");
        assert_eq!(
            std::fs::read(dir.join("rootfs")).expect("read back"),
            b"whole"
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

    // ---- the refusal-drain gates: the two rules on `MAX_REFUSAL_DRAIN_BYTES` ----
    //
    // The gates below that take an `addr` are the only tests in this file that go through a REAL
    // SOCKET, and they have to: the defect they cover does not exist above the transport. The daemon wrote a correct 409,
    // then closed its read side with the client's 24 MiB body still unread; the kernel turned that
    // close into an RST; and an RST discards the client's receive buffer, destroying a response the
    // client had already received. A `oneshot` against the `Router` value cannot see any of that,
    // and neither can a `reqwest` client — so the gates own both ends of the wire.

    /// How long any single wire step may take before the gate calls it a stall. Generous: the happy
    /// paths finish in milliseconds, and every inverse this gate is written against fails by
    /// HANGING (a server that waits for a body the client is withholding), so the deadline is what
    /// turns that hang into a red test rather than a stuck suite.
    const GATE_DEADLINE: std::time::Duration = std::time::Duration::from_secs(10);

    /// A socket wrapper that counts every byte **the server** reads off the wire.
    ///
    /// This is the whole reason these gates accept and serve the connection themselves instead of
    /// calling [`serve`]: the invariant rule 1 protects is a NUMBER — a refusal answered having read
    /// zero body bytes — and a status-only assertion stays green on a server that drained the body
    /// first. `axum::serve` owns its accepted stream, so there is nowhere to put this counter.
    struct CountingIo<S> {
        inner: S,
        read: Arc<AtomicU64>,
    }

    impl<S: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for CountingIo<S> {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            let this = self.get_mut();
            let before = buf.filled().len();
            let polled = std::pin::Pin::new(&mut this.inner).poll_read(cx, buf);
            if polled.is_ready() {
                this.read
                    .fetch_add((buf.filled().len() - before) as u64, Ordering::SeqCst);
            }
            polled
        }
    }

    impl<S: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for CountingIo<S> {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            std::pin::Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
        }
        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.get_mut().inner).poll_flush(cx)
        }
        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
        }
        fn poll_write_vectored(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            bufs: &[std::io::IoSlice<'_>],
        ) -> std::task::Poll<std::io::Result<usize>> {
            std::pin::Pin::new(&mut self.get_mut().inner).poll_write_vectored(cx, bufs)
        }
        fn is_write_vectored(&self) -> bool {
            self.inner.is_write_vectored()
        }
    }

    /// Serves exactly ONE connection off a real loopback socket, counting the server's reads.
    ///
    /// The pieces are the ones `axum::serve` composes for an HTTP/1.1 connection
    /// (axum-0.8.9/src/serve/mod.rs:385-396) — `TokioIo`, `TowerToHyperService`, hyper's own
    /// connection server — so this drives the production stack rather than a lookalike. `axum::serve`
    /// wraps them in `hyper_util`'s `auto::Builder` so it can also answer h2c; the whole defect is
    /// HTTP/1.1-specific and `auto` hands an HTTP/1.1 connection to exactly this server.
    async fn spawn_counted_server(state: AppState) -> (std::net::SocketAddr, Arc<AtomicU64>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind a loopback port");
        let addr = listener.local_addr().expect("the bound address");
        let read = Arc::new(AtomicU64::new(0));
        let counted = read.clone();
        tokio::spawn(async move {
            let (stream, _peer) = listener
                .accept()
                .await
                .expect("accept the gate's connection");
            let io = hyper_util::rt::TokioIo::new(CountingIo {
                inner: stream,
                read: counted,
            });
            let service = hyper_util::service::TowerToHyperService::new(build_router(state));
            // A connection that ENDS IN AN ERROR is the point of the ceiling gate below (the server
            // closes with data unread and the peer RSTs), so this is logged rather than asserted on
            // — and matched explicitly rather than dropped with a bare `let _ =`.
            if let Err(e) = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, service)
                .await
            {
                tracing::debug!("the gate's connection ended: {e}");
            }
        });
        (addr, read)
    }

    /// Plants a real file under an artifact's name, so a PUT to it is a genuine 409.
    fn plant_artifact(art_dir: &std::path::Path, name: &str) {
        std::fs::create_dir_all(art_dir).expect("artifacts dir");
        std::fs::write(art_dir.join(name), b"planted by the gate").expect("plant the taken name");
    }

    fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        haystack.windows(needle.len()).position(|w| w == needle)
    }

    fn declared_content_length(head: &str) -> usize {
        head.lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.trim()
                    .eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().ok())?
            })
            .unwrap_or(0)
    }

    /// Reads exactly ONE HTTP/1.1 response — head plus its declared body — under [`GATE_DEADLINE`].
    ///
    /// Hand-rolled because the gate must not read past the response: two of these gates send a
    /// SECOND request on the same connection, and "did the connection survive" is the assertion that
    /// cannot pass by luck. A `read_to_end` would block forever on a healthy keep-alive connection.
    async fn read_one_response(sock: &mut tokio::net::TcpStream, what: &str) -> String {
        let read = async {
            let mut buf: Vec<u8> = Vec::new();
            loop {
                if let Some(head_end) = find_subslice(&buf, b"\r\n\r\n").map(|i| i + 4) {
                    let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
                    if buf.len() >= head_end + declared_content_length(&head) {
                        break;
                    }
                }
                let mut chunk = [0u8; 8192];
                let n = match sock.read(&mut chunk).await {
                    Ok(n) => n,
                    Err(e) => panic!("reading {what} failed: {e}"),
                };
                if n == 0 {
                    break; // EOF: whatever arrived is the whole of it.
                }
                buf.extend_from_slice(&chunk[..n]);
            }
            String::from_utf8_lossy(&buf).to_string()
        };
        match tokio::time::timeout(GATE_DEADLINE, read).await {
            Ok(resp) => resp,
            Err(_) => panic!(
                "{what} never arrived within {GATE_DEADLINE:?} — the server is still waiting for a \
                 body, which is what an unconditional drain does to a withheld request"
            ),
        }
    }

    /// Writes every byte or fails loud. A stall and an error are both real outcomes here — a server
    /// that stopped reading produces one or the other — and a gate must not swallow either.
    async fn write_all_or_fail(sock: &mut tokio::net::TcpStream, bytes: &[u8], what: &str) {
        match tokio::time::timeout(GATE_DEADLINE, sock.write_all(bytes)).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => panic!(
                "writing {what} failed after the server stopped reading: {e} — the refusal was not \
                 drained"
            ),
            Err(_) => panic!(
                "writing {what} stalled for {GATE_DEADLINE:?} — the server stopped reading, so the \
                 refusal was not drained"
            ),
        }
    }

    /// What hyper reads off the socket without the handler asking for a single byte: the one
    /// `poll_read_body` inside `poll_drain_or_close_read` (`hyper-1.11.0/src/proto/h1/conn.rs:847-864`)
    /// fills up to `DEFAULT_MAX_BUFFER_SIZE` (`proto/h1/io.rs:22` — 8192 + 4096*100, ≈408 KiB).
    ///
    /// So NO gate can assert a tighter bound than this on a client that actually put bytes on the
    /// wire: "the handler read zero body bytes" is observable as "the server read no more than
    /// hyper's own buffer", and the discrimination has to come from the body being much bigger.
    const HYPER_UNASKED_READ_BYTES: u64 = 512 * 1024;

    /// Pushes up to `total` bytes, tolerating a server that has stopped reading — a stall or an
    /// `EPIPE` is a REAL outcome for the gates that use this (rule 1 answers without reading the
    /// body at all, and the ceiling stops mid-body), so both end the push instead of failing it.
    async fn push_tolerating_a_stopped_reader(
        sock: &mut tokio::net::TcpStream,
        total: usize,
    ) -> usize {
        let block = vec![0x33u8; 64 * 1024];
        let mut sent = 0usize;
        while sent < total {
            match tokio::time::timeout(std::time::Duration::from_secs(1), sock.write_all(&block))
                .await
            {
                Ok(Ok(())) => sent += block.len(),
                _ => break,
            }
        }
        sent
    }

    /// Reads until the server closes (FIN) or resets (RST) the connection, under
    /// [`GATE_DEADLINE`], and returns whatever arrived — which may be nothing, because an RST
    /// discards the client's receive buffer, response and all.
    ///
    /// Panics if the connection is still OPEN at the deadline: "the daemon let go" is the
    /// assertion, and a daemon still holding a refused request's connection is the defect these
    /// gates were written against.
    async fn read_until_the_connection_ends(
        sock: &mut tokio::net::TcpStream,
        what: &str,
    ) -> String {
        let read = async {
            let mut buf: Vec<u8> = Vec::new();
            let mut chunk = [0u8; 8192];
            loop {
                match sock.read(&mut chunk).await {
                    // FIN or RST: both mean the daemon is done with this connection.
                    Ok(0) | Err(_) => break,
                    Ok(n) => buf.extend_from_slice(&chunk[..n]),
                }
            }
            String::from_utf8_lossy(&buf).to_string()
        };
        match tokio::time::timeout(GATE_DEADLINE, read).await {
            Ok(seen) => seen,
            Err(_) => panic!(
                "{what}: the connection was still open {GATE_DEADLINE:?} later — the daemon is \
                 HOLDING a request it already refused"
            ),
        }
    }

    /// A drain budget with an explicit byte ceiling and a deadline far enough out that the BYTE half
    /// is what binds. The two halves are gated separately, and mixing them makes both vacuous.
    fn byte_budget(bytes: u64) -> DrainBudget {
        DrainBudget {
            bytes,
            deadline: Instant::now() + std::time::Duration::from_secs(3600),
        }
    }

    fn upload_head(addr: std::net::SocketAddr, name: &str, len: usize, extra: &str) -> String {
        format!(
            "PUT /v1/artifacts/{name} HTTP/1.1\r\nHost: {addr}\r\nAuthorization: Bearer secret\r\n\
             Content-Length: {len}\r\n{extra}\r\n"
        )
    }

    // GATE A — the zero-bytes invariant, rule 1.
    //
    // A client that offered to withhold its body (`Expect: 100-continue`) and then sends NOTHING is
    // refused on the head alone: the server answers 409 having read the request head and ZERO body
    // bytes, and never emits the interim `100 Continue` — because hyper writes that only from inside
    // `poll_read_body` (`hyper-1.11.0/src/proto/h1/conn.rs:409-420`), so its absence on the wire is
    // hyper's own testimony that nothing polled the body.
    //
    // This is the invariant the early refusal in `create_streaming` exists to protect, and the one
    // the new drain would silently destroy. The assertion is on BYTES READ, not on the status: a
    // status-only check stays green on a server that drained first.
    //
    // RED on the inverse, three ways, none of them by luck:
    //   1. drop the `if !client_offered_to_withhold(…)` guard so the drain runs
    //      unconditionally — the handler polls the body, hyper emits `100 Continue`, and then waits
    //      for 24 MiB that will never come. The read hits `GATE_DEADLINE` and the test panics.
    //   2. move `create_streaming`'s `path.exists()` check into `finish` (drop the early refusal)
    //      — same observable, verified: the body is polled and `HTTP/1.1 100 Continue` comes back
    //      instead of the 409.
    //
    // A LOOSENED predicate is not caught here — a `contains`-style match still says "offer" for
    // this exact header — and is deliberately owned by the table gate below instead, which is where
    // the header's shape is the variable.
    //
    // LEG 2 is what makes the byte count DISCRIMINATE. On its own, leg 1's `server_read ==
    // head.len()` is a tautology: its client sends no body bytes, so the count holds whether or not
    // the drain ran (it passes under the unconditional-drain inverse — leg 1 goes red on the hang
    // and on the `100 Continue`, not on the number). Leg 2 sends the offer AND then pushes a body
    // anyway — what a non-withholding client does — so a drain that runs is visible in the count.
    #[tokio::test]
    async fn a_refusal_the_client_offered_to_withhold_reads_zero_body_bytes() {
        let (state, art_dir) = state_with(AuthPolicy::Key(ApiKey::from_secret(b"secret")));
        plant_artifact(&art_dir, "taken");
        let (addr, server_read) = spawn_counted_server(state).await;

        // 24 MiB declared — the size of the re-upload leg in `vmcelld`'s integration suite that
        // this whole change exists for — and not one byte of it is ever sent.
        let head = upload_head(addr, "taken", 25_165_824, "Expect: 100-continue\r\n");
        let mut sock = tokio::net::TcpStream::connect(addr)
            .await
            .expect("connect to the gate's server");
        write_all_or_fail(&mut sock, head.as_bytes(), "the request head").await;
        let resp = read_one_response(&mut sock, "the refusal").await;

        assert!(
            resp.starts_with("HTTP/1.1 409 Conflict"),
            "a taken name is refused on the head alone: {resp}"
        );
        assert!(
            resp.contains("\"error\":\"already_exists\""),
            "and it is the TYPED refusal, not a transport artifact: {resp}"
        );
        assert!(
            !resp.contains("100 Continue"),
            "hyper emits the interim response only from inside `poll_read_body`, so seeing one \
             means the body WAS polled: {resp}"
        );
        assert_eq!(
            server_read.load(Ordering::SeqCst),
            head.len() as u64,
            "the server answered having read the request head and ZERO body bytes"
        );
        // Keep-alive is RULE 2's property, not rule 1's, and the ledger entry says so: nothing read
        // the body, so hyper cannot reuse the connection — the daemon delivers the status and then
        // CLOSES. Asserted rather than assumed, because that qualification is the difference between
        // a true ledger line and a flattering one.
        let after = read_until_the_connection_ends(&mut sock, "the withheld refusal").await;
        assert!(
            after.is_empty(),
            "a refusal the client offered to withhold is delivered and then the connection closes — \
             there is nothing after it: {after}"
        );

        // LEG 2 — the same offer, and then the client sends anyway. The daemon must still refuse on
        // the head alone: nothing it read is body, so the count stays under what hyper's own
        // unasked read can absorb, four megabytes into a push.
        //
        // RED on the inverse: drop the `if !client_offered_to_withhold(…)` guard so the drain runs
        // unconditionally, and the server swallows its whole 1 MiB budget here — the count lands at
        // head + 1 MiB, twice the bound this leg allows.
        let (state, art_dir) = state_with(AuthPolicy::Key(ApiKey::from_secret(b"secret")));
        plant_artifact(&art_dir, "taken");
        let (addr, server_read) = spawn_counted_server(state).await;

        let head = upload_head(addr, "taken", 4 * 1024 * 1024, "Expect: 100-continue\r\n");
        let mut sock = tokio::net::TcpStream::connect(addr)
            .await
            .expect("connect to the gate's server");
        write_all_or_fail(&mut sock, head.as_bytes(), "the request head").await;
        // Tolerant: with rule 1 honored the server answers and closes WITHOUT reading this, so a
        // stall or an EPIPE here is the correct outcome, not a failure.
        let pushed = push_tolerating_a_stopped_reader(&mut sock, 4 * 1024 * 1024).await;
        assert!(
            pushed >= 1024 * 1024,
            "the leg is only meaningful if the client really put bytes on the wire for the server \
             to have (not) read: only {pushed} were accepted"
        );

        // Read to the end of the connection first, so the count is the server's FINAL one rather
        // than a snapshot racing its close-drain read.
        let seen = read_until_the_connection_ends(&mut sock, "the broken-promise leg").await;
        let read = server_read.load(Ordering::SeqCst);
        assert!(
            read < head.len() as u64 + HYPER_UNASKED_READ_BYTES,
            "the daemon read {read} bytes after refusing a withheld body on the head alone; the \
             head is {} and hyper's own unasked read can add at most {HYPER_UNASKED_READ_BYTES} — \
             anything more is the drain running for a client that offered to withhold",
            head.len()
        );
        assert!(
            !seen.contains("100 Continue"),
            "the body was never polled, so hyper never emitted its interim response: {seen}"
        );
        // The honest other half: the client broke its own promise, so there ARE unread bytes at
        // close and the RST may destroy the response it was about to read. Either it got the typed
        // 409 or it got nothing — never some other status.
        assert!(
            seen.is_empty() || seen.starts_with("HTTP/1.1 409 Conflict"),
            "a client that offers to withhold and then sends anyway gets the typed refusal or the \
             documented transport error, and nothing else: {seen}"
        );
    }

    // GATE B — the deliverable refusal, rule 2, at all three refusal sites.
    //
    // A client that made no offer, sending a body far larger than one socket buffer to a taken name,
    // gets the typed 409 DETERMINISTICALLY — first try, no retry — because the handler read and
    // discarded the body first. Two assertions carry it, and neither can pass by accident:
    //
    //   * the server's read count equals the head plus the WHOLE body: the drain ran to EOF; and
    //   * a SECOND request on the SAME connection is answered. Keep-alive survives only if the body
    //     reached EOF. Without the drain, hyper's `poll_drain_or_close_read` gets one cheap read,
    //     stays in `Reading::Body`, and calls `close_read()`, which disables keep-alive
    //     (`conn.rs:849-864`, `conn.rs:1056-1060`) — the second request is then unanswerable. That
    //     is a state-machine consequence, not a timing one. The `GET` coming back 200 is also the
    //     positive control that the artifact really is there, so the 409 is non-vacuous.
    //
    // RED on the inverse: delete the `drain_refused_body` call in `stream_body_into_store`'s
    // `create_streaming` error arm — today's behavior. The write of the body stalls or `EPIPE`s, the
    // byte count collapses to one cheap drain, and the second request is never answered.
    #[tokio::test]
    async fn a_refused_upload_is_drained_so_the_409_is_deliverable_and_the_connection_lives() {
        let (state, art_dir) = state_with(AuthPolicy::Key(ApiKey::from_secret(b"secret")));
        plant_artifact(&art_dir, "taken");
        let (addr, server_read) = spawn_counted_server(state).await;

        // 768 KiB: inside this app's 1 MiB budget, and comfortably past hyper's own ~408 KiB read
        // buffer — a smaller body is absorbed by the one `poll_read_body` that
        // `poll_drain_or_close_read` gives an undrained connection, and discriminates nothing.
        let body = vec![0x5Au8; 768 * 1024];
        let head = upload_head(addr, "taken", body.len(), "");
        let mut sock = tokio::net::TcpStream::connect(addr)
            .await
            .expect("connect to the gate's server");
        write_all_or_fail(&mut sock, head.as_bytes(), "the request head").await;
        write_all_or_fail(&mut sock, &body, "the 768 KiB body").await;
        let resp = read_one_response(&mut sock, "the refusal").await;

        assert!(
            resp.starts_with("HTTP/1.1 409 Conflict"),
            "the typed refusal arrives on the FIRST attempt: {resp}"
        );
        assert!(
            resp.contains("\"error\":\"already_exists\""),
            "and it is the typed body, not a transport error: {resp}"
        );
        assert_eq!(
            server_read.load(Ordering::SeqCst),
            (head.len() + body.len()) as u64,
            "the refused body was read to EOF and discarded — that is what makes the close a clean \
             FIN instead of an RST"
        );

        let probe = format!(
            "GET /v1/artifacts/taken HTTP/1.1\r\nHost: {addr}\r\nAuthorization: Bearer secret\r\n\r\n"
        );
        write_all_or_fail(&mut sock, probe.as_bytes(), "a second request").await;
        let second = read_one_response(&mut sock, "the second response").await;
        assert!(
            second.starts_with("HTTP/1.1 200 OK"),
            "keep-alive survives a drained refusal — and the artifact really is there, so the 409 \
             was not vacuous: {second}"
        );
    }

    // GATE B, chunked: the SHAPE THE PRODUCTION CLIENT ACTUALLY SENDS.
    //
    // `vmcell-daemon-client` uploads a file as `reqwest::Body::from(File)` → `wrap_stream`, whose
    // `size_hint().exact()` is `None`, so reqwest emits `Transfer-Encoding: chunked` and NO
    // `Content-Length` — the exact shape of the 24 MiB re-upload leg this whole change exists to
    // fix. Every other gate here declares a length, and the two forms are not the same code path:
    // the budget counts DECODED bytes while the wire carries chunk framing on top of them, and
    // nothing pinned that before this gate.
    //
    // RED on the inverse: delete the `drain_refused_body` call in `stream_body_into_store`'s
    // `create_streaming` arm — the push stalls or `EPIPE`s, the byte count collapses, and the
    // second request is never answered.
    #[tokio::test]
    async fn a_refused_chunked_upload_is_drained_so_the_409_is_deliverable() {
        let (state, art_dir) = state_with(AuthPolicy::Key(ApiKey::from_secret(b"secret")));
        plant_artifact(&art_dir, "taken");
        let (addr, server_read) = spawn_counted_server(state).await;

        // 12 x 64 KiB = 768 KiB DECODED: inside this app's 1 MiB budget and comfortably past
        // hyper's own ~408 KiB unasked read, for the same reason as the Content-Length gate above.
        let block = vec![0x77u8; 64 * 1024];
        let decoded = block.len() * 12;
        let mut wire: Vec<u8> = Vec::new();
        for _ in 0..12 {
            wire.extend_from_slice(format!("{:x}\r\n", block.len()).as_bytes());
            wire.extend_from_slice(&block);
            wire.extend_from_slice(b"\r\n");
        }
        wire.extend_from_slice(b"0\r\n\r\n");
        assert!(
            wire.len() > decoded,
            "the WIRE carries framing the budget does not count — that difference is what this \
             gate exists to pin"
        );

        let head = format!(
            "PUT /v1/artifacts/taken HTTP/1.1\r\nHost: {addr}\r\nAuthorization: Bearer secret\r\n\
             Transfer-Encoding: chunked\r\n\r\n"
        );
        let mut sock = tokio::net::TcpStream::connect(addr)
            .await
            .expect("connect to the gate's server");
        write_all_or_fail(&mut sock, head.as_bytes(), "the request head").await;
        write_all_or_fail(&mut sock, &wire, "the chunked body").await;
        let resp = read_one_response(&mut sock, "the refusal").await;

        assert!(
            resp.starts_with("HTTP/1.1 409 Conflict"),
            "a chunked refused upload gets its typed refusal on the FIRST attempt too: {resp}"
        );
        assert!(
            resp.contains("\"error\":\"already_exists\""),
            "and it is the typed body, not a transport error: {resp}"
        );
        assert_eq!(
            server_read.load(Ordering::SeqCst),
            (head.len() + wire.len()) as u64,
            "the drain consumed the whole WIRE form, framing included, while the budget counted \
             only the {decoded} decoded bytes inside it"
        );

        let probe = format!(
            "GET /v1/artifacts/taken HTTP/1.1\r\nHost: {addr}\r\nAuthorization: Bearer secret\r\n\r\n"
        );
        write_all_or_fail(&mut sock, probe.as_bytes(), "a second request").await;
        let second = read_one_response(&mut sock, "the second response").await;
        assert!(
            second.starts_with("HTTP/1.1 200 OK"),
            "keep-alive survives a drained chunked refusal — terminator consumed, decoder clean: \
             {second}"
        );
    }

    // GATE B, the auth layer: the same law one layer OUT. A 401/403 is decided before anything polls
    // the body, so a client streaming an artifact at a mistyped key had its typed status wiped by
    // the RST exactly like the 409. Same drain, same predicate, same keep-alive proof — and the
    // second request, with the RIGHT key, is the positive control that the layer still authenticates.
    //
    // RED on the inverse: remove the drain from `auth_layer`'s `Err` arm.
    #[tokio::test]
    async fn a_refused_credential_is_drained_so_the_403_is_deliverable() {
        let (state, _art_dir) = state_with(AuthPolicy::Key(ApiKey::from_secret(b"secret")));
        let (addr, server_read) = spawn_counted_server(state).await;

        // 768 KiB, for the same reason as the 409 gate above.
        let body = vec![0x11u8; 768 * 1024];
        let head = format!(
            "PUT /v1/artifacts/fresh HTTP/1.1\r\nHost: {addr}\r\nAuthorization: Bearer wrong\r\n\
             Content-Length: {}\r\n\r\n",
            body.len()
        );
        let mut sock = tokio::net::TcpStream::connect(addr)
            .await
            .expect("connect to the gate's server");
        write_all_or_fail(&mut sock, head.as_bytes(), "the request head").await;
        write_all_or_fail(&mut sock, &body, "the 768 KiB body").await;
        let resp = read_one_response(&mut sock, "the refusal").await;

        assert!(
            resp.starts_with("HTTP/1.1 403 Forbidden"),
            "a wrong key is the typed 403, delivered: {resp}"
        );
        assert!(
            resp.contains("\"error\":\"forbidden\""),
            "and it is the typed body: {resp}"
        );
        assert_eq!(
            server_read.load(Ordering::SeqCst),
            (head.len() + body.len()) as u64,
            "the auth layer drained the body it refused"
        );

        let probe =
            format!("GET /v1/vms HTTP/1.1\r\nHost: {addr}\r\nAuthorization: Bearer secret\r\n\r\n");
        write_all_or_fail(&mut sock, probe.as_bytes(), "a second request").await;
        let second = read_one_response(&mut sock, "the second response").await;
        assert!(
            second.starts_with("HTTP/1.1 200 OK"),
            "keep-alive survives, and the right key still authenticates on the same connection: \
             {second}"
        );
    }

    // GATE A, at the auth layer: RULE ONE at the refusal site one layer OUT, which is the half no
    // gate in this file could see. `a_refused_credential_is_drained_so_the_403_is_deliverable`
    // above proves rule 2 here, and `the_refusal_drain_laws_have_one_call_site_each` proves that
    // `auth_layer` CALLS `client_offered_to_withhold` — neither proves what the branch behind that
    // call does. A gate binds the CALL SITES, not just the extracted predicate (AGENTS.md, "The
    // delta register binds implementations"): with the guard inverted or absent here, a client that
    // offered to withhold its body at a mistyped key would be drained instead of refused on the
    // head alone, and every existing assertion in this file would stay green.
    //
    // Two legs, for the same reason [`a_refusal_the_client_offered_to_withhold_reads_zero_body_bytes`]
    // has two. Leg 1 sends the offer and NOTHING else: its typed 403 is deterministic (nothing is
    // left unread, so no RST can destroy it) but its byte count is a tautology. Leg 2 sends the
    // offer and then pushes anyway, which is what makes a drain that ran visible in the NUMBER —
    // `DrainBudget::unauthenticated` is `MAX_UNAUTHENTICATED_DRAIN_BYTES`, twice
    // [`HYPER_UNASKED_READ_BYTES`], so the bound genuinely discriminates rather than sitting above
    // both arms.
    //
    // RED on the inverse: drop the `if !client_offered_to_withhold(…)` guard in `auth_layer`'s
    // `Err` arm so the drain runs unconditionally. Leg 1 then reads `HTTP/1.1 100 Continue` where
    // the 403 belongs (hyper writes that only from inside `poll_read_body`, so it is hyper's own
    // testimony that the body WAS polled), and leg 2's count lands a megabyte past the bound.
    #[tokio::test]
    async fn a_refused_credential_that_offered_to_withhold_reads_zero_body_bytes() {
        let (state, _art_dir) = state_with(AuthPolicy::Key(ApiKey::from_secret(b"secret")));
        let (addr, server_read) = spawn_counted_server(state).await;

        // 24 MiB declared behind a WRONG key — the size of `vmcelld`'s integration re-upload — and
        // not one byte of it is ever sent.
        let head = format!(
            "PUT /v1/artifacts/fresh HTTP/1.1\r\nHost: {addr}\r\nAuthorization: Bearer wrong\r\n\
             Content-Length: 25165824\r\nExpect: 100-continue\r\n\r\n"
        );
        let mut sock = tokio::net::TcpStream::connect(addr)
            .await
            .expect("connect to the gate's server");
        write_all_or_fail(&mut sock, head.as_bytes(), "the request head").await;
        let resp = read_one_response(&mut sock, "the refusal").await;

        assert!(
            resp.starts_with("HTTP/1.1 403 Forbidden"),
            "a wrong key behind an offer to withhold is refused on the head alone: {resp}"
        );
        assert!(
            resp.contains("\"error\":\"forbidden\""),
            "and it is the TYPED refusal, not a transport artifact: {resp}"
        );
        assert!(
            !resp.contains("100 Continue"),
            "hyper emits the interim response only from inside `poll_read_body`, so seeing one \
             means the auth layer polled a body it had already refused: {resp}"
        );
        assert_eq!(
            server_read.load(Ordering::SeqCst),
            head.len() as u64,
            "the auth layer answered having read the request head and ZERO body bytes"
        );

        // LEG 2 — the same offer at the same wrong key, and then the client sends anyway. The
        // refusal must still be decided on the head alone: nothing the daemon read is body, so the
        // count stays under what hyper's own unasked read can absorb, four megabytes into a push.
        let (state, _art_dir) = state_with(AuthPolicy::Key(ApiKey::from_secret(b"secret")));
        let (addr, server_read) = spawn_counted_server(state).await;

        let head = format!(
            "PUT /v1/artifacts/fresh HTTP/1.1\r\nHost: {addr}\r\nAuthorization: Bearer wrong\r\n\
             Content-Length: 4194304\r\nExpect: 100-continue\r\n\r\n"
        );
        let mut sock = tokio::net::TcpStream::connect(addr)
            .await
            .expect("connect to the gate's server");
        write_all_or_fail(&mut sock, head.as_bytes(), "the request head").await;
        // Tolerant: with rule 1 honored the daemon answers and closes WITHOUT reading this, so a
        // stall or an EPIPE here is the correct outcome, not a failure.
        let pushed = push_tolerating_a_stopped_reader(&mut sock, 4 * 1024 * 1024).await;
        assert!(
            pushed >= 1024 * 1024,
            "the leg is only meaningful if the client really put bytes on the wire for the daemon \
             to have (not) read: only {pushed} were accepted"
        );

        // Read to the end of the connection first, so the count is the daemon's FINAL one rather
        // than a snapshot racing its close-drain read.
        let seen = read_until_the_connection_ends(&mut sock, "the broken-promise leg").await;
        let read = server_read.load(Ordering::SeqCst);
        assert!(
            read < head.len() as u64 + HYPER_UNASKED_READ_BYTES,
            "the daemon read {read} bytes after refusing a withheld body at a bad credential; the \
             head is {} and hyper's own unasked read can add at most {HYPER_UNASKED_READ_BYTES} — \
             anything more is the unauthenticated drain running for a client that offered to \
             withhold",
            head.len()
        );
        assert!(
            !seen.contains("100 Continue"),
            "the body was never polled, so hyper never emitted its interim response: {seen}"
        );
        // The honest other half: the client broke its own promise, so there ARE unread bytes at
        // close and the RST may destroy the response it was about to read. Either it got the typed
        // 403 or it got nothing — never some other status.
        assert!(
            seen.is_empty() || seen.starts_with("HTTP/1.1 403 Forbidden"),
            "a client that offers to withhold at a bad key and then sends anyway gets the typed \
             refusal or the documented transport error, and nothing else: {seen}"
        );
    }

    // GATE E — THE UNAUTHENTICATED HOLD. The drain's own hazard, and a NEW exposure the drain
    // itself created: a bound in BYTES is not a bound in TIME.
    //
    // A client that offers `Authorization: Bearer wrong`, declares a megabyte, and sends ONE byte
    // reaches no byte ceiling ever — so a drain bounded only by bytes waits on `chunks.next()`
    // forever, holding a connection, a task and its buffers for a caller that never authenticated.
    // Before the drain existed the daemon closed on the 401/403 immediately. The fix is the
    // budget's second dimension: an ABSOLUTE deadline (`MAX_UNAUTHENTICATED_DRAIN_TIME`, 2 s here)
    // that bounds the whole drain.
    //
    // RED on the inverse: drop the `timeout_at` (leave only `if bytes >= budget.bytes`) and this
    // gate hangs — `read_one_response` panics at `GATE_DEADLINE` with the daemon still holding the
    // connection, which is exactly the measured pre-fix behavior.
    #[tokio::test]
    async fn an_unauthenticated_slow_drip_is_released_and_its_connection_closed() {
        let (state, _art_dir) = state_with(AuthPolicy::Key(ApiKey::from_secret(b"secret")));
        let (addr, server_read) = spawn_counted_server(state).await;

        let head = format!(
            "PUT /v1/artifacts/fresh HTTP/1.1\r\nHost: {addr}\r\nAuthorization: Bearer wrong\r\n\
             Content-Length: 1048576\r\n\r\n"
        );
        let mut sock = tokio::net::TcpStream::connect(addr)
            .await
            .expect("connect to the gate's server");
        let started = std::time::Instant::now();
        write_all_or_fail(&mut sock, head.as_bytes(), "the request head").await;
        write_all_or_fail(&mut sock, b"x", "the one dripped byte").await;

        let resp = read_one_response(&mut sock, "the refusal").await;
        assert!(
            resp.starts_with("HTTP/1.1 403 Forbidden"),
            "the drip still gets its typed refusal — the deadline releases the client, it does not \
             swallow the answer: {resp}"
        );
        let seen = read_until_the_connection_ends(&mut sock, "the drip's connection").await;
        let held = started.elapsed();

        assert!(
            held < MAX_UNAUTHENTICATED_DRAIN_TIME * 4,
            "an anonymous client that sent ONE byte held the daemon for {held:?}; the \
             unauthenticated drain is bounded at {MAX_UNAUTHENTICATED_DRAIN_TIME:?}"
        );
        assert_eq!(
            server_read.load(Ordering::SeqCst),
            head.len() as u64 + 1,
            "and the daemon read exactly what arrived — the head and the one dripped byte"
        );
        assert!(
            seen.is_empty(),
            "nothing follows the refusal: the connection is closed, not held open for the megabyte \
             the client declared: {seen}"
        );
    }

    // GATE B, the cap: the THIRD refusal site, mid-stream. The store refuses at the chunk that
    // crosses `--max-artifact-bytes`, by which point the body is already in flight — so the `Expect`
    // offer is spent and this arm drains unconditionally. Without it, a 413 is exactly as
    // undeliverable as the 409 was, and no test in this file could see it: every other upload test
    // drives the router with `oneshot`, which has no transport to lose the response on.
    //
    // RED on the inverse: delete the `drain_data_stream` call in the `write_chunk` error arm — or
    // restore the sketch's `budget - writer.written()`, which computes ZERO here (the refusal
    // happens AT the cap, and the cap is the budget) and so drains nothing at all.
    #[tokio::test]
    async fn an_over_cap_upload_is_drained_past_the_cap_so_the_413_is_deliverable() {
        let cap = 4 * 1024 * 1024;
        let (state, art_dir) = state_with_cap(AuthPolicy::Key(ApiKey::from_secret(b"secret")), cap);
        let (addr, server_read) = spawn_counted_server(state).await;

        // 7 MiB against a 4 MiB per-upload cap. Both margins are deliberate: the ~3 MiB TAIL after
        // the refusal fits the 4 MiB budget (so the drain reaches EOF and the 413 lands), and it is
        // seven times hyper's own ~408 KiB read buffer (so a server that does NOT drain cannot
        // absorb it and the gate goes red). The first cut used 1.5 MiB against a 1 MiB cap and
        // stayed GREEN with the drain deleted — hyper drained the 0.5 MiB tail itself.
        let body = vec![0x22u8; 7 * 1024 * 1024];
        let head = upload_head(addr, "toobig", body.len(), "");
        let mut sock = tokio::net::TcpStream::connect(addr)
            .await
            .expect("connect to the gate's server");
        write_all_or_fail(&mut sock, head.as_bytes(), "the request head").await;
        write_all_or_fail(&mut sock, &body, "the 7 MiB body").await;
        let resp = read_one_response(&mut sock, "the refusal").await;

        assert!(
            resp.starts_with("HTTP/1.1 413 Payload Too Large"),
            "the cap refusal is delivered, first try: {resp}"
        );
        assert!(
            resp.contains("\"error\":\"payload_too_large\""),
            "and it is the typed body: {resp}"
        );
        assert_eq!(
            server_read.load(Ordering::SeqCst),
            (head.len() + body.len()) as u64,
            "the tail of an over-cap body is read to EOF and discarded"
        );
        assert!(
            !art_dir.join("toobig").exists(),
            "and nothing was published — the drain writes NOTHING, it only discards"
        );

        let probe = format!(
            "GET /v1/artifacts/toobig HTTP/1.1\r\nHost: {addr}\r\nAuthorization: Bearer secret\r\n\r\n"
        );
        write_all_or_fail(&mut sock, probe.as_bytes(), "a second request").await;
        let second = read_one_response(&mut sock, "the second response").await;
        assert!(
            second.starts_with("HTTP/1.1 404 Not Found"),
            "keep-alive survives, and the refused name is genuinely absent: {second}"
        );
    }

    // The mid-stream cap refusal UNLINKS its partially-written temp file before it starts draining.
    //
    // The writer holds an open `NamedTempFile` carrying everything received up to
    // `--max-artifact-bytes`, and the drain that follows it can run for the whole of
    // `MAX_REFUSAL_DRAIN_TIME`. Keeping the writer alive across that `.await` leaves up to a full
    // cap of a refused upload on disk for the duration — per refused upload, in a store that has a
    // quota — for no reason at all: the bytes are already doomed.
    //
    // The probe runs FROM INSIDE THE STREAM, at a chunk only the drain can poll (the ingest loop
    // returned at the previous one), so it observes the store DURING the drain rather than after
    // it — and it starts at `usize::MAX`, so "the probe never ran" is red too.
    //
    // RED on the inverse: remove the `drop(writer)` and the probe sees 1 temp file instead of 0.
    #[tokio::test]
    async fn the_cap_refusal_drops_its_temp_file_before_it_starts_draining() {
        let (state, art_dir) =
            state_with_cap(AuthPolicy::Key(ApiKey::from_secret(b"secret")), 64 * 1024);
        let app = build_router(state);
        let during_the_drain = Arc::new(AtomicUsize::new(usize::MAX));

        let probe_dir = art_dir.clone();
        let probe = during_the_drain.clone();
        let stream = futures::stream::unfold(0usize, move |i| {
            let probe_dir = probe_dir.clone();
            let probe = probe.clone();
            async move {
                match i {
                    // Chunk 0 fills the 64 KiB cap exactly; chunk 1 crosses it and is refused.
                    0 | 1 => Some((Ok::<Vec<u8>, std::io::Error>(vec![0u8; 64 * 1024]), i + 1)),
                    // Only the drain can pull this one — the ingest loop is gone.
                    2 => {
                        probe.store(temp_files(&probe_dir), Ordering::SeqCst);
                        Some((Ok(vec![0u8; 1024]), i + 1))
                    }
                    _ => None,
                }
            }
        });

        let resp = app
            .oneshot(upload_request(
                "/v1/artifacts/toobig",
                Body::from_stream(stream),
            ))
            .await
            .expect("response");
        assert_eq!(
            resp.status(),
            StatusCode::PAYLOAD_TOO_LARGE,
            "the cap refusal is what this gate is watching"
        );
        assert_eq!(
            during_the_drain.load(Ordering::SeqCst),
            0,
            "the partially-written temp file is unlinked BEFORE the drain, not after it — a \
             `usize::MAX` here means the drain never ran at all"
        );
        assert_eq!(temp_files(&art_dir), 0, "and nothing survives the request");
        assert!(!art_dir.join("toobig").exists(), "nothing was published");
    }

    // GATE C, the arithmetic half: the budget law, and the drain stopping AT it.
    //
    // RED on the inverse: drop the `.min(MAX_REFUSAL_DRAIN_BYTES)` (the ceiling leg fails), or drop
    // the `if bytes >= budget` break so the drain runs to EOF (the endless-body leg never returns
    // and the test hangs to its harness timeout).
    #[tokio::test]
    async fn the_refusal_drain_stops_at_its_budget_and_says_why() {
        assert_eq!(
            DrainBudget::authenticated(1 << 20).bytes,
            1 << 20,
            "under the ceiling the per-upload cap binds: never discard more than this upload could \
             ever have been stored as"
        );
        assert_eq!(
            DrainBudget::authenticated(usize::MAX).bytes,
            MAX_REFUSAL_DRAIN_BYTES,
            "past it the ceiling binds — `vmcelld`'s default --max-artifact-bytes is 4 GiB, and a \
             refusal must not become a 4 GiB bandwidth sink for anyone holding an API key"
        );
        assert_eq!(
            DrainBudget::authenticated(0).bytes,
            0,
            "and a zero cap drains nothing"
        );

        // The PRE-AUTH budget is tighter in BOTH dimensions than anything an authenticated request
        // can earn — that is the whole of its rationale, and neither half is optional.
        assert_eq!(
            DrainBudget::unauthenticated().bytes,
            MAX_UNAUTHENTICATED_DRAIN_BYTES
        );
        assert!(
            DrainBudget::unauthenticated().bytes < DrainBudget::authenticated(usize::MAX).bytes,
            "a caller that has not authenticated must not be able to spend the authenticated \
             ceiling: {} vs {}",
            DrainBudget::unauthenticated().bytes,
            DrainBudget::authenticated(usize::MAX).bytes
        );
        assert!(
            DrainBudget::unauthenticated().bytes > HYPER_UNASKED_READ_BYTES,
            "…and not so small that it buys nothing: below hyper's own unasked read the drain is \
             indistinguishable from doing nothing"
        );
        assert!(
            DrainBudget::unauthenticated().deadline < DrainBudget::authenticated(1 << 20).deadline,
            "and it is released sooner in time as well: {:?} vs {:?}",
            MAX_UNAUTHENTICATED_DRAIN_TIME,
            MAX_REFUSAL_DRAIN_TIME
        );

        // An ENDLESS body. The drain must stop, and must report WHY — `Budget` is the state in which
        // the connection still dies and the client still sees a transport error.
        let endless =
            futures::stream::repeat_with(|| Ok::<Vec<u8>, std::io::Error>(vec![0u8; 64 * 1024]));
        let outcome = drain_refused_body(Body::from_stream(endless), byte_budget(256 * 1024)).await;
        assert_eq!(
            outcome.bytes,
            256 * 1024,
            "the drain stops at the budget, whatever the client does"
        );
        assert_eq!(outcome.end, DrainEnd::Budget);

        // A body that ENDS inside the budget is the deliverable case, and it reports so.
        let outcome =
            drain_refused_body(Body::from(vec![7u8; 4096]), byte_budget(256 * 1024)).await;
        assert_eq!(outcome.bytes, 4096);
        assert_eq!(
            outcome.end,
            DrainEnd::Eof,
            "EOF inside the budget is what makes the close a clean FIN and the refusal deliverable"
        );
    }

    // GATE E, the arithmetic half: the deadline bounds the WHOLE drain, not the gap between two
    // chunks — AGENTS.md's "a budget checked only between iterations does not bound a wedged
    // connect, read, or write", as a number.
    //
    // The client here is a perfectly steady drip: one byte per second, forever. Under any per-chunk
    // timeout it is a healthy client that never times out; under an absolute deadline it is
    // released after two seconds having delivered two bytes. On a paused clock, so it costs
    // microseconds of real time.
    //
    // RED on the inverse: swap the `timeout_at(budget.deadline, …)` for a per-chunk
    // `tokio::time::timeout(MAX_UNAUTHENTICATED_DRAIN_TIME, …)` — the drip resets it at every byte,
    // the drain runs to the BYTE ceiling instead (8 KiB = 8192 dripped seconds), and both
    // assertions go red.
    #[tokio::test(start_paused = true)]
    async fn the_drain_deadline_bounds_the_whole_drain_not_the_gap_between_chunks() {
        let drip = futures::stream::unfold((), |()| async {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            Some((Ok::<Vec<u8>, std::io::Error>(vec![0u8; 1]), ()))
        });
        let budget = DrainBudget {
            bytes: 8 * 1024,
            deadline: Instant::now() + MAX_UNAUTHENTICATED_DRAIN_TIME,
        };

        let started = Instant::now();
        let outcome = drain_refused_body(Body::from_stream(drip), budget).await;
        let held = started.elapsed();

        assert_eq!(
            outcome.end,
            DrainEnd::Deadline,
            "the drip is ended by the clock, not by the ceiling it would never reach"
        );
        assert!(
            outcome.bytes <= MAX_UNAUTHENTICATED_DRAIN_TIME.as_secs() + 1,
            "one byte per second for {MAX_UNAUTHENTICATED_DRAIN_TIME:?} is a handful of bytes, not \
             the {} the ceiling would have allowed: {} were read",
            budget.bytes,
            outcome.bytes
        );
        assert!(
            held <= MAX_UNAUTHENTICATED_DRAIN_TIME + std::time::Duration::from_secs(1),
            "the WHOLE drain is over within its deadline; it took {held:?}"
        );
    }

    // The undeliverable refusal is WARNED about, not whispered. `DrainEnd::Budget`/`Deadline` is the
    // state in which the daemon KNOWS the client will not receive the status it just decided — the
    // RST is about to destroy it — and both call sites discard the `DrainOutcome`, so this log line
    // is the only place that fact reaches an operator. A `debug!` there is invisible in production.
    //
    // The deliverable leg is the positive control: a drain that warns on every refusal is a warn
    // nobody reads.
    //
    // `DrainEnd::Failed` — the client went away mid-drain — is the fourth arm and the one no other
    // gate reaches; it is an ERROR BRANCH, so it is driven here rather than recorded (AGENTS.md
    // rule 4). It must stay silent: there is no client left to deliver a refusal to, so nothing an
    // operator can act on happened.
    //
    // RED on the inverse: put the `Budget`/`Deadline` arm back at `debug!` (the second count goes
    // to 0), log every arm at `warn!` (the first goes to 1), or move `Failed` into the warn arm
    // beside `Budget`/`Deadline` (the third goes to 2).
    #[tokio::test]
    async fn an_undeliverable_refusal_is_warned_about_and_a_deliverable_one_is_not() {
        keep_log_gates_observable();
        let warns = Arc::new(AtomicUsize::new(0));
        let guard = tracing::subscriber::set_default(WarnFieldCounter {
            field: "undeliverable_refusal",
            hits: warns.clone(),
        });

        let outcome =
            drain_refused_body(Body::from(vec![7u8; 4096]), byte_budget(256 * 1024)).await;
        assert_eq!(outcome.end, DrainEnd::Eof);
        assert_eq!(
            warns.load(Ordering::SeqCst),
            0,
            "a refusal that IS deliverable is not an operator's problem"
        );

        let endless =
            futures::stream::repeat_with(|| Ok::<Vec<u8>, std::io::Error>(vec![0u8; 64 * 1024]));
        let outcome = drain_refused_body(Body::from_stream(endless), byte_budget(256 * 1024)).await;
        assert_eq!(outcome.end, DrainEnd::Budget);
        assert_eq!(
            warns.load(Ordering::SeqCst),
            1,
            "…and one that is NOT says so at WARN, with the budget it outran and the remedy"
        );

        // The torn body: one chunk, then the client's stream fails. The byte count is what keeps
        // this leg non-vacuous — a drain that never pulled the chunk would report zero and would be
        // asserting nothing about the arm it claims to reach.
        let torn = futures::stream::iter(vec![
            Ok::<Vec<u8>, std::io::Error>(vec![9u8; 128]),
            Err(std::io::Error::other("the client went away mid-drain")),
        ]);
        let outcome = drain_refused_body(Body::from_stream(torn), byte_budget(256 * 1024)).await;
        assert_eq!(
            outcome.end,
            DrainEnd::Failed,
            "a body that fails mid-drain ends on its own arm, not on the budget's"
        );
        assert_eq!(
            outcome.bytes, 128,
            "and the bytes it did discard before the failure are still reported"
        );
        assert_eq!(
            warns.load(Ordering::SeqCst),
            1,
            "…and it does NOT warn: the peer is gone, so there is no refusal left to be              undeliverable — the count is exactly where the budget leg left it"
        );
        drop(guard);
    }

    // GATE C, the wire half: past the budget the daemon does NOT keep reading, and the documented
    // cost is asserted rather than left to chance.
    //
    // A 16 MiB body — sixteen times this app's budget — against a taken name. The server's own read
    // count is the measurement, so the assertion does not depend on kernel socket-buffer sizes at
    // all: it bounds what the daemon consumed, not what the client managed to push. And the
    // connection is then CLOSED rather than held open, which is the honest other half — past the
    // ceiling the RST is back and the client may well see a transport error. That is the documented
    // limit of this fix (see `MAX_REFUSAL_DRAIN_BYTES`), and the remedy is `Expect: 100-continue`,
    // which gate A proves works at any size.
    //
    // RED on the inverse: remove the budget bound (drain to EOF unconditionally) and the daemon
    // reads all 16 MiB — this is the arm that keeps the fix from quietly becoming "the daemon reads
    // whatever you send it".
    #[tokio::test]
    async fn a_body_past_the_drain_budget_is_bounded_and_the_connection_is_closed() {
        let (state, art_dir) = state_with(AuthPolicy::Key(ApiKey::from_secret(b"secret")));
        plant_artifact(&art_dir, "taken");
        let (addr, server_read) = spawn_counted_server(state).await;

        let total = 16 * 1024 * 1024;
        let head = upload_head(addr, "taken", total, "");
        let mut sock = tokio::net::TcpStream::connect(addr)
            .await
            .expect("connect to the gate's server");
        write_all_or_fail(&mut sock, head.as_bytes(), "the request head").await;

        // Push until the socket stops accepting — a stall or an error both mean the daemon stopped
        // reading, which is the point.
        push_tolerating_a_stopped_reader(&mut sock, total).await;

        // The bound. `budget` is 1 MiB here; the slack covers the one chunk that crosses the budget
        // plus hyper's single cheap drain read on the way to `close_read`, both of which are hyper's
        // own read-buffer size (≤ 400 KiB) rather than anything this test controls.
        let budget = DrainBudget::authenticated(1 << 20).bytes;
        let slack = 1024 * 1024;
        let read = server_read.load(Ordering::SeqCst);
        assert!(
            read < head.len() as u64 + budget + slack,
            "the daemon read {read} bytes of a {total}-byte refused body; the budget is {budget} — \
             an unbounded drain would have read all of it"
        );

        // The other half of the ceiling's behavior, stated: the connection is closed, not held.
        // `read_until_the_connection_ends` panics if it is still open at `GATE_DEADLINE` — past the
        // budget the server must not sit holding a connection whose body it already refused.
        read_until_the_connection_ends(&mut sock, "the over-budget connection").await;
    }

    // GATE D — the predicate is hyper's, exactly: ALL THREE of its conditions.
    //
    // `hyper-1.11.0/src/proto/h1/role.rs:317-321` runs
    // `expect_continue = value.as_bytes().eq_ignore_ascii_case(b"100-continue")` inside the header
    // loop; `conn.rs:303-320` then ignores the expectation for an EMPTY body and requires the
    // version to be greater than HTTP/1.0 before it will hold a body back. Every wrong
    // implementation of any of the three fails in the DANGEROUS direction — it says "the client
    // offered to withhold" where hyper says it did not, so the daemon skips the drain, the client
    // sends anyway, and the refusal is lost exactly as it was before this change.
    //
    // RED on the inverse: a `contains("100-continue")` matcher (the multi-value row goes green when
    // it must be false); an `any()` over `get_all` (the last-header row); dropping the
    // `version > HTTP_10` conjunct (the HTTP/1.0 and HTTP/0.9 rows); dropping the size-hint conjunct
    // (the empty-body row). The version and body rows are why this gate reads the request PARTS and
    // not just the headers: the claim "matched exactly as hyper matches it" was false for both
    // before this pass, in the direction that loses refusals.
    #[test]
    fn the_expect_offer_is_read_exactly_as_hyper_reads_it() {
        fn expect_headers(values: &[&str]) -> HeaderMap {
            let mut headers = HeaderMap::new();
            for v in values {
                headers.append(
                    header::EXPECT,
                    HeaderValue::from_str(v).expect("a valid header value"),
                );
            }
            headers
        }

        /// The three body shapes hyper's `DecodedLength` collapses to, as `size_hint` reports them:
        /// declared-and-empty, declared-with-bytes, and chunked (no exact hint at all).
        #[derive(Clone, Copy, Debug)]
        enum Shape {
            Empty,
            Sized,
            Chunked,
        }

        fn body_of(shape: Shape) -> Body {
            match shape {
                Shape::Empty => Body::empty(),
                Shape::Sized => Body::from(vec![0u8; 16]),
                Shape::Chunked => {
                    Body::from_stream(futures::stream::iter(vec![Ok::<Vec<u8>, std::io::Error>(
                        vec![0u8; 16],
                    )]))
                }
            }
        }

        let cases: &[(Version, &[&str], Shape, bool, &str)] = &[
            (
                Version::HTTP_11,
                &[],
                Shape::Sized,
                false,
                "no Expect header at all is no offer",
            ),
            (
                Version::HTTP_11,
                &["100-continue"],
                Shape::Sized,
                true,
                "the token, exactly",
            ),
            (
                Version::HTTP_11,
                &["100-Continue"],
                Shape::Sized,
                true,
                "…case-insensitively, as hyper compares it",
            ),
            (
                Version::HTTP_11,
                &["100-CONTINUE"],
                Shape::Sized,
                true,
                "…in any case",
            ),
            (
                Version::HTTP_11,
                &["100-continue, foo"],
                Shape::Sized,
                false,
                "hyper compares the WHOLE value, so a multi-value Expect is not the token — a \
                 `contains`-style matcher says offer here and hyper says none",
            ),
            (
                Version::HTTP_11,
                &["something-else"],
                Shape::Sized,
                false,
                "an unknown expectation is no offer",
            ),
            (
                Version::HTTP_11,
                &[""],
                Shape::Sized,
                false,
                "an empty value is no offer",
            ),
            (
                Version::HTTP_11,
                &["foo", "100-continue"],
                Shape::Sized,
                true,
                "the LAST Expect header wins: hyper ASSIGNS per header rather than accumulating",
            ),
            (
                Version::HTTP_11,
                &["100-continue", "foo"],
                Shape::Sized,
                false,
                "…and it wins in the other direction too — an `any()` over `get_all` says offer \
                 here and hyper says none",
            ),
            (
                Version::HTTP_11,
                &["100-continue"],
                Shape::Chunked,
                true,
                "a chunked body has no exact size hint and is not empty, so the offer stands — and \
                 this is the shape `vmcell-daemon-client` actually sends",
            ),
            (
                Version::HTTP_11,
                &["100-continue"],
                Shape::Empty,
                false,
                "hyper IGNORES the expectation when the body is empty (conn.rs:303-306): there is \
                 nothing to withhold, so there is nothing to skip a drain for",
            ),
            (
                Version::HTTP_10,
                &["100-continue"],
                Shape::Sized,
                false,
                "hyper requires version > HTTP/1.0 (conn.rs:311): a 1.0 client's expectation is \
                 ignored, its body arrives unasked, and the daemon MUST drain it",
            ),
            (
                Version::HTTP_09,
                &["100-continue"],
                Shape::Sized,
                false,
                "…and below 1.0 likewise",
            ),
            (
                Version::HTTP_2,
                &["100-continue"],
                Shape::Sized,
                true,
                "…while anything above 1.0 keeps it: `gt(&Version::HTTP_10)` is the comparison",
            ),
        ];

        for (version, values, shape, expected, why) in cases {
            assert_eq!(
                client_offered_to_withhold(*version, &expect_headers(values), &body_of(*shape)),
                *expected,
                "{version:?} Expect: {values:?} body: {shape:?} — {why}"
            );
        }
    }

    // One law, one predicate — bound at the CALL SITES, not just at the extracted function. Both
    // laws live in one function each in this one file, so this in-source scan is their gate; a
    // `scripts/*.sh` ban would have no second crate to scan and would be a duplicate of this.
    //
    // RED on the inverse: a second site hand-reading the `Expect` header (the header/token counts
    // go to two), a hardcoded `64 * 1024 * 1024` at a call site instead of
    // `DrainBudget::authenticated` (the literal count goes to two), a refusal site that reaches for
    // the wrong budget (the two constructor counts move — measured: pointing `auth_layer` at the
    // authenticated budget reddens this and the slow-drip gate together), or a per-poll relative
    // timeout in place of the absolute deadline.
    #[test]
    fn the_refusal_drain_laws_have_one_call_site_each() {
        let src = include_str!("server.rs");
        let prod = src
            .split("#[cfg(test)]")
            .next()
            .expect("the production half of this file");
        // Comment lines are stripped so the laws' own rustdoc — which names both by design — is
        // never a false positive.
        let code = prod
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");

        // A scan that opens nothing is MISCONFIGURED, not green (docs/90 G4): the only way to find
        // no violation must be to have looked.
        assert!(
            code.contains("fn client_offered_to_withhold")
                && code.contains("struct DrainBudget")
                && code.contains("fn drain_data_stream"),
            "gate misconfigured: the production half of server.rs no longer defines the refusal \
             laws this scan exists to bind"
        );

        assert_eq!(
            code.matches("header::EXPECT").count(),
            1,
            "`Expect` is read in exactly one place — `client_offered_to_withhold`"
        );
        assert_eq!(
            code.matches("b\"100-continue\"").count(),
            1,
            "and the token is spelled in exactly one place, matched the way hyper matches it"
        );
        assert_eq!(
            code.matches("MAX_REFUSAL_DRAIN_BYTES").count(),
            2,
            "the authenticated ceiling is the const and its single use inside \
             `DrainBudget::authenticated`"
        );
        assert_eq!(
            code.matches("64 * 1024 * 1024").count(),
            1,
            "…so the number itself appears only in the const's own definition"
        );
        assert_eq!(
            code.matches("MAX_UNAUTHENTICATED_DRAIN_BYTES").count(),
            2,
            "and the anonymous ceiling likewise: the const and its single use inside \
             `DrainBudget::unauthenticated` — a refusal decided before authentication must not be \
             able to reach for the authenticated one"
        );
        assert_eq!(
            code.matches("MAX_REFUSAL_DRAIN_TIME").count(),
            2,
            "and each deadline likewise: the authenticated one is the const and its single use"
        );
        assert_eq!(
            code.matches("MAX_UNAUTHENTICATED_DRAIN_TIME").count(),
            2,
            "…the anonymous one the same — two budgets, four constants, no fifth ceiling pasted \
             anywhere"
        );
        assert_eq!(
            code.matches("DrainBudget::authenticated(").count(),
            2,
            "the authenticated budget is minted at EXACTLY the two refusal sites a request that \
             authenticated can reach — at the site, so the mid-stream cap's drain gets a fresh \
             deadline rather than one minted when the head was parsed"
        );
        assert_eq!(
            code.matches("DrainBudget::unauthenticated(").count(),
            1,
            "…and at exactly one site reachable without authenticating: `auth_layer`"
        );
        assert_eq!(
            code.matches("Instant::now()").count(),
            2,
            "one deadline is taken per budget constructor and nowhere else — a deadline refreshed \
             inside the loop would bound the gaps between polls instead of the drain"
        );
        assert_eq!(
            code.matches("timeout_at(").count(),
            1,
            "the deadline binds in exactly one place, and it is ABSOLUTE"
        );
        assert_eq!(
            code.matches("::timeout(").count(),
            0,
            "…never a relative per-poll timeout, which restarts at every dripped byte and bounds \
             nothing at all (AGENTS.md: a budget checked only between iterations does not bound a \
             wedged read)"
        );
        assert_eq!(
            code.matches("client_offered_to_withhold(").count(),
            3,
            "the definition plus EXACTLY the two refusal sites that can be answered before the body \
             is polled — `auth_layer` and `stream_body_into_store`'s `create_streaming` arm. The \
             third refusal site (the cap, mid-stream) deliberately does NOT consult it: by then \
             hyper has emitted its `100 Continue` and the client is already sending"
        );
    }
}
