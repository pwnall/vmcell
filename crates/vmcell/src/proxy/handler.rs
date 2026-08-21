//! The shipped egress handler: the transparent-intake reconstruction and the cassette, wrapped
//! around the [`ProxyHandler`] core (§6.4, The transparent egress proxy).
//!
//! # Why a wrapper and not more fields on `ProxyHandler`
//!
//! [`ProxyHandler`] is public, with public fields, so *any* added field is a breaking change
//! `cargo semver-checks` reports as major — and a major bump here would strand the fourteen sibling
//! manifests that pin `vmcell = "0.23.0"`. Composition costs nothing and buys the ordering below
//! explicitly instead of by statement order inside one function.
//!
//! # The order, and why it is that order
//!
//! 1. **Reconstruct** (transparent path only). An origin-form request gets its absolute URI back
//!    from the `Host` header *first*, so every decision below sees the destination the guest
//!    actually asked for. Doing this after the deny-list check is the bug that would let
//!    `GET / HTTP/1.1` + `Host: blocked.com` walk past the egress filter.
//! 2. **[`ProxyHandler`]**: deny-list, request log, `record_to` line log, test doubles. A double is
//!    an explicit instruction from the test that installed it and outranks a recording.
//! 3. **Cassette**. In replay mode the interaction is served from the file and the request never
//!    reaches an upstream; in record mode the key is remembered and the *response* is captured on
//!    the way back through [`HttpHandler::handle_response`].
//!
//! `hudsucker` clones the handler per request (`self.clone().proxy(req)`), so
//! [`EgressHandler::pending`] is per-request state, and the `handle_request` that set it is the same
//! instance whose `handle_response` reads it.

use crate::proxy::cassette::{CassetteError, CassetteState, RecordedInteraction, interaction_key};
use crate::proxy::doubles::{ProxyHandler, push_bounded};
use crate::proxy::transparent::reconstruct_absolute_uri;
use http_body_util::{BodyExt, Limited};
use hudsucker::{HttpContext, HttpHandler, RequestOrResponse};
use hyper::{Request, Response};
use std::sync::Arc;

/// Status served for a request whose destination could not be recovered — the transparent path's
/// "this names nothing" answer. A `400` because the *request* is the thing that is unusable.
const STATUS_UNNAMED: u16 = 400;

/// Status served for a cassette **miss** in replay mode. A `504` because the honest description is
/// "the upstream this proxy was standing in for did not answer" — and replay deliberately has no
/// upstream to fall through to.
const STATUS_MISS: u16 = 504;

/// Status served when recording could not capture the interaction (an over-cap body, an I/O
/// failure). Fail loud: a recording run that silently dropped an interaction produces a cassette
/// whose later replay misses for no visible reason.
const STATUS_RECORD_FAILED: u16 = 502;

/// The handler the proxy actually installs: [`ProxyHandler`] plus transparent-intake reconstruction
/// plus the cassette.
#[derive(Clone)]
pub(crate) struct EgressHandler {
    /// The deny-list / request-log / doubles core.
    pub inner: ProxyHandler,
    /// The proxy's cassette, in whichever mode it was put into (or none).
    pub cassette: Arc<std::sync::Mutex<Option<CassetteState>>>,
    /// The key of the request currently in flight, set in record mode by `handle_request` and taken
    /// by `handle_response`. Per-request, because `hudsucker` clones the handler per request.
    pending: Option<String>,
}

impl EgressHandler {
    /// Wraps `inner` with `cassette`.
    pub(crate) fn new(
        inner: ProxyHandler,
        cassette: Arc<std::sync::Mutex<Option<CassetteState>>>,
    ) -> Self {
        Self {
            inner,
            cassette,
            pending: None,
        }
    }

    /// Appends `entry` to the proxy's request log, the host-observable channel a test asserts on.
    fn log(&self, entry: String) {
        let mut log = self
            .inner
            .requests
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        push_bounded(&mut log, entry);
    }

    /// Step 1: give a transparently-redirected origin-form request its absolute URI back.
    ///
    /// Returns the request to carry on with, or the response that refuses it — `hudsucker`'s own
    /// either-type rather than a `Result`, because a `Response` is not an error and boxing one to
    /// satisfy `result_large_err` would say it was.
    fn reconstruct(&self, req: Request<hudsucker::Body>) -> RequestOrResponse {
        if req.method() == hyper::Method::CONNECT {
            return RequestOrResponse::Request(req);
        }
        let host_header = req
            .headers()
            .get(hyper::header::HOST)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        match reconstruct_absolute_uri(req.uri(), host_header.as_deref()) {
            Ok(None) => RequestOrResponse::Request(req),
            Ok(Some(absolute)) => {
                tracing::debug!("transparent intake: reconstructed {absolute}");
                let (mut parts, body) = req.into_parts();
                parts.uri = absolute;
                RequestOrResponse::Request(Request::from_parts(parts, body))
            }
            Err(e) => {
                self.log(format!("{STATUS_UNNAMED} UNNAMED {e}"));
                RequestOrResponse::Response(text_response(
                    STATUS_UNNAMED,
                    &format!("vmcell egress proxy: {e}\n"),
                ))
            }
        }
    }

    /// Step 3: consult the cassette.
    fn cassette_stage(&mut self, req: Request<hudsucker::Body>) -> RequestOrResponse {
        // A CONNECT is a tunnel, not an interaction: the requests inside it are what get recorded,
        // each with its own absolute URI, once hudsucker has terminated the TLS.
        if req.method() == hyper::Method::CONNECT {
            return RequestOrResponse::Request(req);
        }
        let mut slot = self.cassette.lock().unwrap_or_else(|e| e.into_inner());
        let Some(state) = slot.as_mut() else {
            return RequestOrResponse::Request(req);
        };
        let key = match interaction_key(req.method().as_str(), req.uri(), state.options()) {
            Ok(key) => key,
            Err(e) => {
                drop(slot);
                self.log(format!("{STATUS_UNNAMED} UNNAMED {e}"));
                return RequestOrResponse::Response(text_response(
                    STATUS_UNNAMED,
                    &format!("vmcell cassette: {e}\n"),
                ));
            }
        };
        if !state.is_replaying() {
            self.pending = Some(key);
            return RequestOrResponse::Request(req);
        }
        match state.take_hit(&key) {
            Ok(interaction) => {
                drop(slot);
                match replay_response(&interaction) {
                    Ok(res) => {
                        self.log(format!("CASSETTE HIT {key}"));
                        RequestOrResponse::Response(res)
                    }
                    Err(e) => {
                        self.log(format!("{STATUS_RECORD_FAILED} CASSETTE {e}"));
                        RequestOrResponse::Response(text_response(
                            STATUS_RECORD_FAILED,
                            &format!("vmcell cassette: {e}\n"),
                        ))
                    }
                }
            }
            Err(e) => {
                drop(slot);
                // A miss NEVER falls through to the real upstream: that is what would make a green
                // replay run prove nothing about what the cassette holds.
                tracing::error!("cassette miss: {e}");
                self.log(format!("{STATUS_MISS} CASSETTE MISS {key}"));
                RequestOrResponse::Response(text_response(
                    STATUS_MISS,
                    &format!("vmcell cassette: {e}\n"),
                ))
            }
        }
    }

    /// Captures the response for the in-flight recorded interaction, then hands it on unchanged.
    async fn record_response(
        &mut self,
        key: &str,
        res: Response<hudsucker::Body>,
    ) -> Response<hudsucker::Body> {
        let cap = {
            let slot = self.cassette.lock().unwrap_or_else(|e| e.into_inner());
            match slot.as_ref() {
                Some(state) => state.options().max_body_bytes,
                None => return res,
            }
        };
        let (mut parts, body) = res.into_parts();
        let status = parts.status.as_u16();
        let headers: Vec<(String, String)> = parts
            .headers
            .iter()
            .filter(|(name, _)| {
                crate::proxy::cassette::is_recordable_response_header(name.as_str())
            })
            .filter_map(|(name, value)| {
                value
                    .to_str()
                    .ok()
                    .map(|v| (name.as_str().to_string(), v.to_string()))
            })
            .collect();

        // `Limited` refuses past the cap instead of buffering an upstream-chosen number of bytes.
        let Ok(collected) = Limited::new(body, cap).collect().await else {
            let e = CassetteError::BodyTooLarge {
                key: key.to_string(),
                cap,
            };
            tracing::error!("cassette record failed: {e}");
            self.log(format!("{STATUS_RECORD_FAILED} CASSETTE {e}"));
            return text_response(STATUS_RECORD_FAILED, &format!("vmcell cassette: {e}\n"));
        };
        let bytes = collected.to_bytes();

        {
            let slot = self.cassette.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(state) = slot.as_ref()
                && let Err(e) = state.append(key, status, headers, &bytes)
            {
                drop(slot);
                tracing::error!("cassette record failed: {e}");
                self.log(format!("{STATUS_RECORD_FAILED} CASSETTE {e}"));
                return text_response(STATUS_RECORD_FAILED, &format!("vmcell cassette: {e}\n"));
            }
        }
        self.log(format!("CASSETTE RECORDED {key}"));

        // The body was buffered, so any framing header describing the *streamed* form is now a lie;
        // hyper recomputes both from the known-length body it is handed.
        parts.headers.remove(hyper::header::CONTENT_LENGTH);
        parts.headers.remove(hyper::header::TRANSFER_ENCODING);
        Response::from_parts(parts, hudsucker::Body::from(bytes))
    }
}

/// Builds a plain-text response, the one shape every refusal on this path takes.
fn text_response(status: u16, body: &str) -> Response<hudsucker::Body> {
    Response::builder()
        .status(status)
        .header(hyper::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(hudsucker::Body::from(body.to_string()))
        .unwrap_or_else(|_| {
            // A constant status and a constant header name cannot fail to build; this arm exists
            // only because `unwrap` is denied in production code.
            Response::new(hudsucker::Body::from(body.to_string()))
        })
}

/// Rebuilds a recorded interaction into the response the guest receives.
fn replay_response(
    interaction: &RecordedInteraction,
) -> std::result::Result<Response<hudsucker::Body>, CassetteError> {
    let bytes = interaction.body.to_bytes(&interaction.key)?;
    let mut builder = Response::builder().status(interaction.status);
    for (name, value) in &interaction.headers {
        builder = builder.header(name, value);
    }
    builder
        .body(hudsucker::Body::from(bytes))
        .map_err(|e| CassetteError::UndecodableBody {
            key: interaction.key.clone(),
            msg: e.to_string(),
        })
}

impl EgressHandler {
    /// The whole request pipeline — reconstruct, then [`ProxyHandler`], then the cassette — in one
    /// place that takes no [`HttpContext`].
    ///
    /// `hudsucker` marks [`HttpContext`] `#[non_exhaustive]` and exposes no constructor, so a unit
    /// test cannot call the trait method at all. Splitting the pipeline out is what makes the
    /// ordering above testable without booting a proxy; [`HttpHandler::handle_request`] is then a
    /// one-line adapter that cannot itself hold a decision.
    pub(crate) fn route(&mut self, req: Request<hudsucker::Body>) -> RequestOrResponse {
        let req = match self.reconstruct(req) {
            RequestOrResponse::Request(req) => req,
            RequestOrResponse::Response(res) => return RequestOrResponse::Response(res),
        };
        match self.inner.route_request(req) {
            RequestOrResponse::Response(res) => RequestOrResponse::Response(res),
            RequestOrResponse::Request(req) => self.cassette_stage(req),
        }
    }

    /// The response half of the pipeline: capture the in-flight recorded interaction, if any.
    pub(crate) async fn respond(
        &mut self,
        res: Response<hudsucker::Body>,
    ) -> Response<hudsucker::Body> {
        match self.pending.take() {
            Some(key) => self.record_response(&key, res).await,
            None => res,
        }
    }
}

impl HttpHandler for EgressHandler {
    async fn handle_request(
        &mut self,
        _ctx: &HttpContext,
        req: Request<hudsucker::Body>,
    ) -> RequestOrResponse {
        self.route(req)
    }

    async fn handle_response(
        &mut self,
        ctx: &HttpContext,
        res: Response<hudsucker::Body>,
    ) -> Response<hudsucker::Body> {
        let res = self.respond(res).await;
        self.inner.handle_response(ctx, res).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::cassette::CassetteOptions;

    fn handler(blocked: Vec<String>) -> EgressHandler {
        EgressHandler::new(
            ProxyHandler {
                doubles: Arc::new(std::sync::RwLock::new(Vec::new())),
                blocked_domains: blocked,
                requests: Arc::new(std::sync::Mutex::new(Vec::new())),
                record_path: Arc::new(std::sync::Mutex::new(None)),
            },
            Arc::new(std::sync::Mutex::new(None)),
        )
    }

    fn origin_form_get(path: &str, host: Option<&str>) -> Request<hudsucker::Body> {
        let mut b = Request::builder().method(hyper::Method::GET).uri(path);
        if let Some(host) = host {
            b = b.header(hyper::header::HOST, host);
        }
        b.body(hudsucker::Body::empty()).expect("request builds")
    }

    async fn body_string(res: Response<hudsucker::Body>) -> String {
        let bytes = res
            .into_body()
            .collect()
            .await
            .expect("body collects")
            .to_bytes();
        String::from_utf8_lossy(&bytes).to_string()
    }

    // THE TRANSPARENT-PATH FIX, at the handler: an origin-form request comes out of the pipeline
    // carrying its absolute URI, so the request log (and every decision above) names the real
    // destination. Buggy impl guarded: dropping the reconstruct step leaves the URI as `/v1`, and
    // the log assert reddens — which is exactly the pre-fix behavior §6.4 documented.
    #[tokio::test]
    async fn an_origin_form_request_is_reconstructed_before_anything_else_sees_it() {
        let mut h = handler(vec![]);
        match h.route(origin_form_get("/v1?b=2", Some("api.example.test"))) {
            RequestOrResponse::Request(req) => {
                assert_eq!(req.uri().to_string(), "http://api.example.test/v1?b=2");
            }
            RequestOrResponse::Response(_) => panic!("an unblocked request must be forwarded"),
        }
        let log = h.inner.requests.lock().unwrap_or_else(|e| e.into_inner());
        assert!(
            log.iter()
                .any(|r| r == "GET http://api.example.test/v1?b=2"),
            "the log must name the reconstructed destination: {log:?}"
        );
    }

    // ORDER MATTERS: the deny-list runs on the RECONSTRUCTED URI. Buggy impl guarded: reconstructing
    // after `ProxyHandler` (or not at all) leaves `is_blocked` with no host to test, and a raw
    // transparent `GET /` + `Host: blocked.com` walks straight past the egress filter.
    #[tokio::test]
    async fn the_deny_list_applies_to_a_transparently_reconstructed_host() {
        let mut h = handler(vec!["blocked.com".to_string()]);
        match h.route(origin_form_get("/secret", Some("blocked.com"))) {
            RequestOrResponse::Response(res) => assert_eq!(res.status(), 403),
            RequestOrResponse::Request(_) => {
                panic!("a transparently-reconstructed blocked host must be denied")
            }
        }
        // Positive control: the same shape to an allowed host is forwarded.
        let mut h = handler(vec!["blocked.com".to_string()]);
        match h.route(origin_form_get("/secret", Some("allowed.test"))) {
            RequestOrResponse::Request(_) => {}
            RequestOrResponse::Response(_) => panic!("an allowed host must be forwarded"),
        }
    }

    // A request that names no destination is refused loudly rather than forwarded to nowhere.
    #[tokio::test]
    async fn an_unnamed_transparent_request_is_refused() {
        let mut h = handler(vec![]);
        match h.route(origin_form_get("/v1", None)) {
            RequestOrResponse::Response(res) => {
                assert_eq!(res.status(), STATUS_UNNAMED);
                assert!(body_string(res).await.contains("no Host header"));
            }
            RequestOrResponse::Request(_) => panic!("a destination-less request must be refused"),
        }
    }

    // RECORD → REPLAY through the real handler and the real file, asserted on the BODY.
    //
    // Buggy impls guarded: dropping the `handle_response` capture writes no interaction, so the
    // replay leg misses; keying replay on something the recording did not use (a header, the raw
    // URI) misses too; serving a miss by forwarding upstream makes the miss leg return a forwarded
    // Request instead of the 504.
    #[tokio::test]
    async fn record_then_replay_serves_the_recorded_body_and_misses_loudly() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("c.jsonl");

        // RECORD: the request is forwarded, and the response passing back through is captured.
        let mut h = handler(vec![]);
        {
            let mut slot = h.cassette.lock().unwrap_or_else(|e| e.into_inner());
            *slot = Some(
                CassetteState::open_record(&path, CassetteOptions::default()).expect("record"),
            );
        }
        let req = origin_form_get("/v1?nonce=1", Some("api.example.test"));
        match h.route(req) {
            RequestOrResponse::Request(_) => {}
            RequestOrResponse::Response(_) => panic!("recording must forward, not synthesize"),
        }
        let upstream = Response::builder()
            .status(201)
            .header(hyper::header::CONTENT_TYPE, "application/json")
            .header(hyper::header::SET_COOKIE, "session=hunter2")
            .body(hudsucker::Body::from("{\"answer\":42}"))
            .expect("response builds");
        let passed_through = h.respond(upstream).await;
        assert_eq!(passed_through.status(), 201);
        assert_eq!(
            body_string(passed_through).await,
            "{\"answer\":42}",
            "recording must not disturb the body on its way to the guest"
        );
        let recorded = std::fs::read_to_string(&path).expect("cassette written");
        assert!(recorded.contains("api.example.test"), "{recorded}");
        assert!(
            !recorded.contains("hunter2"),
            "a non-allowlisted response header must never reach the artifact: {recorded}"
        );

        // REPLAY: a *different* nonce still hits (the key redacts it), and the BODY is served
        // without any upstream at all — `handle_request` answers it outright.
        let mut h = handler(vec![]);
        {
            let mut slot = h.cassette.lock().unwrap_or_else(|e| e.into_inner());
            *slot = Some(
                CassetteState::open_replay(&path, CassetteOptions::default()).expect("replay"),
            );
        }
        let req = origin_form_get("/v1?nonce=99", Some("api.example.test"));
        match h.route(req) {
            RequestOrResponse::Response(res) => {
                assert_eq!(res.status(), 201);
                assert_eq!(
                    res.headers()
                        .get(hyper::header::CONTENT_TYPE)
                        .and_then(|v| v.to_str().ok()),
                    Some("application/json")
                );
                assert_eq!(body_string(res).await, "{\"answer\":42}");
            }
            RequestOrResponse::Request(_) => panic!("replay must answer, never forward"),
        }

        // MISS: a path that was never recorded is a typed 504 and a retained miss — never a
        // fall-through to the network.
        let req = origin_form_get("/v2", Some("api.example.test"));
        match h.route(req) {
            RequestOrResponse::Response(res) => {
                assert_eq!(res.status(), STATUS_MISS);
                assert!(body_string(res).await.contains("cassette miss"));
            }
            RequestOrResponse::Request(_) => panic!("a miss must never reach the upstream"),
        }
        let slot = h.cassette.lock().unwrap_or_else(|e| e.into_inner());
        let misses = slot.as_ref().map(CassetteState::misses).unwrap_or_default();
        assert_eq!(misses.len(), 1, "{misses:?}");
        assert_eq!(
            misses.first().map(|m| m.key.as_str()),
            Some("GET http://api.example.test/v2")
        );
    }

    // An over-cap body is a loud 502 to the guest, not a silently truncated recording. Buggy impl
    // guarded: recording `Limited`'s partial collection would write a body the upstream never sent.
    #[tokio::test]
    async fn an_over_cap_response_body_fails_the_recording_loudly() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("c.jsonl");
        let mut h = handler(vec![]);
        {
            let mut slot = h.cassette.lock().unwrap_or_else(|e| e.into_inner());
            *slot = Some(
                CassetteState::open_record(
                    &path,
                    CassetteOptions::default().with_max_body_bytes(8),
                )
                .expect("record"),
            );
        }
        match h.route(origin_form_get("/big", Some("api.example.test"))) {
            RequestOrResponse::Request(_) => {}
            RequestOrResponse::Response(_) => panic!("recording must forward"),
        }
        let upstream = Response::builder()
            .status(200)
            .body(hudsucker::Body::from("x".repeat(64)))
            .expect("response builds");
        let res = h.respond(upstream).await;
        assert_eq!(res.status(), STATUS_RECORD_FAILED);
        assert!(body_string(res).await.contains("exceeds"));
        assert_eq!(
            std::fs::read_to_string(&path).expect("read"),
            "",
            "nothing may be written for a refused interaction"
        );
    }

    // With no cassette at all the handler is a pass-through: the whole facility is opt-in, and the
    // proxy's existing behavior is unchanged when nobody asked for a cassette.
    #[tokio::test]
    async fn no_cassette_means_no_change() {
        let mut h = handler(vec![]);
        match h.route(origin_form_get("/v1", Some("api.example.test"))) {
            RequestOrResponse::Request(_) => {}
            RequestOrResponse::Response(_) => panic!("must forward"),
        }
        let upstream = Response::builder()
            .status(200)
            .body(hudsucker::Body::from("body"))
            .expect("response builds");
        let res = h.respond(upstream).await;
        assert_eq!(res.status(), 200);
        assert_eq!(body_string(res).await, "body");
    }

    // A CONNECT is a tunnel, not an interaction: it must not consume a cassette entry, and it must
    // not be reconstructed. Buggy impl guarded: keying a CONNECT would burn the recorded entry the
    // request INSIDE the tunnel needs, so the real request would then miss.
    #[tokio::test]
    async fn a_connect_is_not_an_interaction() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("c.jsonl");
        std::fs::write(
            &path,
            "{\"format\":\"vmcell-cassette-v1\",\"key\":\"GET https://api.example.test/v1\",\"status\":200,\"body\":{\"encoding\":\"text\",\"data\":\"hi\"}}\n",
        )
        .expect("write");
        let mut h = handler(vec![]);
        {
            let mut slot = h.cassette.lock().unwrap_or_else(|e| e.into_inner());
            *slot = Some(
                CassetteState::open_replay(&path, CassetteOptions::default()).expect("replay"),
            );
        }
        let connect = Request::builder()
            .method(hyper::Method::CONNECT)
            .uri("api.example.test:443")
            .body(hudsucker::Body::empty())
            .expect("request builds");
        match h.route(connect) {
            RequestOrResponse::Request(_) => {}
            RequestOrResponse::Response(_) => panic!("a CONNECT must fall through to the tunnel"),
        }
        // The entry is still there for the request inside the tunnel.
        let absolute = Request::builder()
            .method(hyper::Method::GET)
            .uri("https://api.example.test/v1")
            .body(hudsucker::Body::empty())
            .expect("request builds");
        match h.route(absolute) {
            RequestOrResponse::Response(res) => assert_eq!(res.status(), 200),
            RequestOrResponse::Request(_) => panic!("the tunneled request must hit the cassette"),
        }
    }
}
