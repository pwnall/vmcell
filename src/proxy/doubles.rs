use hudsucker::{HttpContext, HttpHandler, RequestOrResponse};
use hyper::{Request, Response};
use std::sync::Arc;

/// A type alias for a test double matching function.
pub type Matcher = Box<dyn Fn(&Request<hudsucker::Body>) -> bool + Send + Sync>;
/// A type alias for a test double responder function.
pub type Responder = Box<dyn Fn(&Request<hudsucker::Body>) -> Response<hudsucker::Body> + Send + Sync>;

/// Represents a single mock route.
pub struct TestDouble {
    /// The matcher function that determines if this double applies.
    pub matcher: Matcher,
    /// The responder function that returns the mock response.
    pub responder: Responder,
}

/// The hudsucker HTTP handler that routes proxy requests.
#[derive(Clone)]
pub struct ProxyHandler {
    /// The configured test doubles.
    pub doubles: Arc<Vec<TestDouble>>,
}

impl HttpHandler for ProxyHandler {
    async fn handle_request(
        &mut self,
        _ctx: &HttpContext,
        req: Request<hudsucker::Body>,
    ) -> RequestOrResponse {
        tracing::info!("Proxy intercepted request to: {}", req.uri());
        
        for double in self.doubles.iter() {
            if (double.matcher)(&req) {
                tracing::info!("Proxy matched request, returning test double response");
                let res = (double.responder)(&req);
                return RequestOrResponse::Response(res);
            }
        }

        // Apply a filter rule blocking example.net
        if let Some(host) = req.uri().host() {
            if host.ends_with("example.net") {
                tracing::info!("Proxy blocking request to {}", host);
                let response = Response::builder()
                    .status(403)
                    .body(hudsucker::Body::from("Blocked by Imp Proxy\n"))
                    .unwrap();
                return RequestOrResponse::Response(response);
            }
        }

        RequestOrResponse::Request(req)
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
