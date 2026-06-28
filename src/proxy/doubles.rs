#![forbid(unsafe_code)]

use hudsucker::{HttpContext, HttpHandler, RequestOrResponse};
use hyper::{Request, Response};
use std::sync::Arc;

/// A type alias for a test double matching function.
pub type Matcher = Box<dyn Fn(&Request<hudsucker::Body>) -> bool + Send + Sync>;
/// A type alias for a test double responder function.
pub type Responder =
    Box<dyn Fn(&Request<hudsucker::Body>) -> Response<hudsucker::Body> + Send + Sync>;

/// Represents a single mock route.
pub struct TestDouble {
    /// The matcher function that determines if this double applies.
    pub matcher: Matcher,
    /// The responder function that returns the mock response.
    pub responder: Responder,
}

impl std::fmt::Debug for TestDouble {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TestDouble").finish_non_exhaustive()
    }
}

/// The hudsucker HTTP handler that routes proxy requests.
#[derive(Clone)]
pub struct ProxyHandler {
    /// The configured test doubles.
    pub doubles: Arc<std::sync::RwLock<Vec<TestDouble>>>,
    /// Domains to block.
    pub blocked_domains: Vec<String>,
    /// Observed requests.
    pub requests: Arc<std::sync::Mutex<crate::proxy::RequestLog>>,
    /// Record to path.
    pub record_path: Arc<std::sync::Mutex<Option<std::path::PathBuf>>>,
}

/// Returns whether `host` is denied by the `blocked` deny list.
///
/// Matching is on DNS label boundaries: a host is blocked when it equals a
/// listed domain or is a strict subdomain of it (`sub.example.net` matches
/// `example.net`). Sibling labels such as `evil-example.net` or
/// `notexample.net` are *not* blocked — a bare `ends_with` over-blocks them.
fn is_blocked(host: &str, blocked: &[String]) -> bool {
    blocked
        .iter()
        .any(|domain| host == domain || host.ends_with(&format!(".{}", domain)))
}

impl ProxyHandler {
    /// Routes a single request, returning either a synthesized response (an
    /// egress block or a test double) or the request to forward upstream.
    fn route_request(&self, req: Request<hudsucker::Body>) -> RequestOrResponse {
        tracing::info!("Proxy intercepted request to: {}", req.uri());

        let host_str = req
            .uri()
            .host()
            .or_else(|| req.uri().authority().map(|a| a.host()));

        if let Some(host) = host_str {
            if is_blocked(host, &self.blocked_domains) {
                tracing::info!("Proxy blocking request to {}", host);
                // Record the denial so the most security-relevant events are
                // observable via `requests()`. Recover from a poisoned lock
                // instead of panicking on the request hot path.
                {
                    let mut reqs = self.requests.lock().unwrap_or_else(|e| e.into_inner());
                    reqs.push(format!("403 BLOCKED {}", host));
                }
                let response = Response::builder()
                    .status(403)
                    .body(hudsucker::Body::from(format!(
                        "Blocked by Imp Proxy: {}\n",
                        host
                    )))
                    .expect("Valid response builder");
                return RequestOrResponse::Response(response);
            }
        }

        let req_uri = format!("{} {}", req.method(), req.uri());
        {
            // Recover from a poisoned lock instead of panicking on the hot path.
            let mut reqs = self.requests.lock().unwrap_or_else(|e| e.into_inner());
            reqs.push(req_uri.clone());
        }

        // Snapshot the record path and drop the lock before any file I/O, so the
        // lock is never held across a blocking syscall.
        let record_path = self
            .record_path
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        if let Some(path) = record_path {
            use std::io::Write;
            match std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
            {
                Ok(mut f) => {
                    if let Err(e) = writeln!(f, "{}", req_uri) {
                        tracing::warn!("Failed to write cassette {}: {}", path.display(), e);
                    }
                }
                Err(e) => {
                    tracing::warn!("Failed to open cassette {}: {}", path.display(), e);
                }
            }
        }

        if req.method() == hyper::Method::CONNECT {
            return RequestOrResponse::Request(req);
        }

        // Match under the read guard to find the first matching double, then
        // re-acquire a fresh, short-lived guard to invoke its (arbitrary,
        // possibly panicking) responder. Recovering from poison via
        // `into_inner` means a panicking responder cannot brick the proxy;
        // splitting the match and the invocation into separate guard scopes
        // keeps each critical section minimal. Indices stay valid because
        // doubles are only ever appended, never removed.
        let matched = {
            let doubles = self.doubles.read().unwrap_or_else(|e| e.into_inner());
            doubles.iter().position(|double| (double.matcher)(&req))
        };
        if let Some(idx) = matched {
            let doubles = self.doubles.read().unwrap_or_else(|e| e.into_inner());
            if let Some(double) = doubles.get(idx) {
                tracing::info!("Proxy matched request, returning test double response");
                return RequestOrResponse::Response((double.responder)(&req));
            }
        }

        RequestOrResponse::Request(req)
    }
}

impl HttpHandler for ProxyHandler {
    async fn handle_request(
        &mut self,
        _ctx: &HttpContext,
        req: Request<hudsucker::Body>,
    ) -> RequestOrResponse {
        self.route_request(req)
    }

    async fn handle_response(
        &mut self,
        _ctx: &HttpContext,
        res: Response<hudsucker::Body>,
    ) -> Response<hudsucker::Body> {
        tracing::info!("Proxy forwarding response, status: {}", res.status());
        res
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn handler_with(blocked: Vec<String>, doubles: Vec<TestDouble>) -> ProxyHandler {
        ProxyHandler {
            doubles: Arc::new(std::sync::RwLock::new(doubles)),
            blocked_domains: blocked,
            requests: Arc::new(std::sync::Mutex::new(Vec::new())),
            record_path: Arc::new(std::sync::Mutex::new(None)),
        }
    }

    fn ok_double(status: u16) -> TestDouble {
        TestDouble {
            matcher: Box::new(|_| true),
            responder: Box::new(move |_| {
                Response::builder()
                    .status(status)
                    .body(hudsucker::Body::empty())
                    .expect("response builds")
            }),
        }
    }

    // Buggy impl guarded: a bare `host.ends_with(blocked)` over-blocks
    // `evil-example.net`/`notexample.net`, and an equality-only match misses
    // `sub.example.net`. Either inversion turns one of these asserts red.
    #[test]
    fn is_blocked_matches_label_boundaries() {
        let blocked = vec!["example.net".to_string()];
        assert!(is_blocked("example.net", &blocked));
        assert!(is_blocked("sub.example.net", &blocked));
        assert!(is_blocked("a.b.example.net", &blocked));
        assert!(!is_blocked("evil-example.net", &blocked));
        assert!(!is_blocked("notexample.net", &blocked));
        assert!(!is_blocked("example.net.evil.com", &blocked));
        assert!(!is_blocked("other.org", &blocked));
        assert!(!is_blocked("example.net", &[]));
    }

    // Buggy impl guarded: dropping the block-branch log entry (PROXY-2) makes
    // denials invisible. Removing the `403 BLOCKED` push turns this red.
    #[test]
    fn blocked_request_is_recorded_and_denied() {
        let handler = handler_with(vec!["blocked.com".to_string()], vec![]);
        let req = Request::builder()
            .uri("http://blocked.com/secret")
            .body(hudsucker::Body::empty())
            .expect("request builds");
        match handler.route_request(req) {
            RequestOrResponse::Response(resp) => assert_eq!(resp.status(), 403),
            RequestOrResponse::Request(_) => panic!("blocked host must be denied"),
        }
        let log = handler.requests.lock().unwrap_or_else(|e| e.into_inner());
        assert!(
            log.iter().any(|r| r == "403 BLOCKED blocked.com"),
            "denial not recorded in request log: {:?}",
            *log
        );
    }

    // Buggy impl guarded: matching test doubles before the CONNECT check would
    // synthesize a double response for a CONNECT request instead of forwarding
    // it. A `true` matcher must still be skipped for CONNECT.
    #[test]
    fn connect_falls_through_doubles() {
        let handler = handler_with(vec![], vec![ok_double(200)]);
        let req = Request::builder()
            .method(hyper::Method::CONNECT)
            .uri("http://example.com/")
            .body(hudsucker::Body::empty())
            .expect("request builds");
        match handler.route_request(req) {
            RequestOrResponse::Request(_) => {}
            RequestOrResponse::Response(_) => {
                panic!("CONNECT must fall through, not match a double")
            }
        }
    }

    // Guards the meaningfulness of the CONNECT test: a non-CONNECT request that
    // matches a double must return the double's response.
    #[test]
    fn non_connect_matches_double() {
        let handler = handler_with(vec![], vec![ok_double(201)]);
        let req = Request::builder()
            .method(hyper::Method::GET)
            .uri("http://example.com/")
            .body(hudsucker::Body::empty())
            .expect("request builds");
        match handler.route_request(req) {
            RequestOrResponse::Response(resp) => assert_eq!(resp.status(), 201),
            RequestOrResponse::Request(_) => panic!("matching double should respond"),
        }
    }
}
