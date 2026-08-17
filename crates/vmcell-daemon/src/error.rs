//! The one daemon error type and its single HTTP-status mapping (design §11.5, The HTTP REST API and its OpenAPI document / §13, Cross-cutting invariants).
//!
//! Mirrors the `vmcell` error discipline (design §9.5, The error type): no `Error::Other(String)` catch-all —
//! the caller-relevant conditions are typed and matchable. Exactly one `IntoResponse` impl maps a
//! `DaemonError` to a status + a structured [`ErrorBody`] (one law, one predicate for the mapping),
//! so no handler hand-rolls a status. A wrapped `vmcell::Error` renders its `Display`, never its
//! `Debug` struct-dump (the L-BIN-4 lesson, design §14, Hard-won lessons).

use crate::dto::{ErrorBody, ErrorKind};
use crate::name::InvalidName;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};

/// The daemon's single error type. Each variant carries a human message and maps to exactly one
/// [`ErrorKind`] (hence one HTTP status).
#[derive(Debug)]
pub enum DaemonError {
    /// 404 — no such vm/artifact.
    NotFound(String),
    /// 409 — create over an existing artifact (the "no update" guard).
    AlreadyExists(String),
    /// 409 — delete an artifact a live VM pins.
    InUse(String),
    /// 409 — op against a VM in the wrong state.
    Conflict(String),
    /// 400 — an artifact name failed validation.
    InvalidName(InvalidName),
    /// 400 — malformed body / knob.
    BadRequest(String),
    /// 401 — missing/blank bearer credential.
    Unauthorized(String),
    /// 403 — a present but wrong bearer credential.
    Forbidden(String),
    /// 501 — an op the backend does not advertise.
    Unsupported(String),
    /// 413 — upload past the size cap.
    PayloadTooLarge(String),
    /// 500 — an internal error (wrapped, rendered as its `Display`).
    Internal(String),
}

impl DaemonError {
    /// The machine-matchable kind (and thus the HTTP status) for this error.
    #[must_use]
    pub fn kind(&self) -> ErrorKind {
        match self {
            Self::NotFound(_) => ErrorKind::NotFound,
            Self::AlreadyExists(_) => ErrorKind::AlreadyExists,
            Self::InUse(_) => ErrorKind::InUse,
            Self::Conflict(_) => ErrorKind::Conflict,
            Self::InvalidName(_) => ErrorKind::InvalidName,
            Self::BadRequest(_) => ErrorKind::BadRequest,
            Self::Unauthorized(_) => ErrorKind::Unauthorized,
            Self::Forbidden(_) => ErrorKind::Forbidden,
            Self::Unsupported(_) => ErrorKind::Unsupported,
            Self::PayloadTooLarge(_) => ErrorKind::PayloadTooLarge,
            Self::Internal(_) => ErrorKind::Internal,
        }
    }

    /// The human-readable message (never a `Debug` struct-dump).
    #[must_use]
    pub fn message(&self) -> String {
        match self {
            Self::NotFound(m)
            | Self::AlreadyExists(m)
            | Self::InUse(m)
            | Self::Conflict(m)
            | Self::BadRequest(m)
            | Self::Unauthorized(m)
            | Self::Forbidden(m)
            | Self::Unsupported(m)
            | Self::PayloadTooLarge(m)
            | Self::Internal(m) => m.clone(),
            Self::InvalidName(e) => e.to_string(),
        }
    }
}

impl std::fmt::Display for DaemonError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.kind().as_str(), self.message())
    }
}

impl std::error::Error for DaemonError {}

impl From<InvalidName> for DaemonError {
    fn from(e: InvalidName) -> Self {
        Self::InvalidName(e)
    }
}

impl From<serde_json::Error> for DaemonError {
    fn from(e: serde_json::Error) -> Self {
        Self::BadRequest(format!("malformed JSON body: {e}"))
    }
}

impl From<vmcell::Error> for DaemonError {
    /// Maps a `vmcell::Error` to the closest daemon kind. `Unsupported`/`CapabilityUnavailable`
    /// (the two matchable vmcell conditions, design §9.5, The error type) map to `Unsupported` (501); a
    /// `Config` validation failure is a **client** error (the request carried a bad knob — a
    /// reserved kernel arg, a `0` io_limit, `vcpus == 0`) so it maps to `BadRequest` (400), not a
    /// misleading 500; every other variant renders its `Display` under `Internal` (500) — never
    /// the `Debug` form.
    fn from(e: vmcell::Error) -> Self {
        match e {
            vmcell::Error::Unsupported { .. } | vmcell::Error::CapabilityUnavailable { .. } => {
                Self::Unsupported(e.to_string())
            }
            vmcell::Error::Config(_) => Self::BadRequest(e.to_string()),
            other => Self::Internal(other.to_string()),
        }
    }
}

impl IntoResponse for DaemonError {
    fn into_response(self) -> Response {
        let kind = self.kind();
        let status =
            StatusCode::from_u16(kind.status_code()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let body = ErrorBody {
            error: kind.as_str().to_string(),
            message: self.message(),
        };
        let mut resp = (status, axum::Json(body)).into_response();
        // RFC 7235: a 401 carries a `WWW-Authenticate` challenge naming the scheme.
        if kind == ErrorKind::Unauthorized {
            resp.headers_mut().insert(
                header::WWW_AUTHENTICATE,
                HeaderValue::from_static("Bearer realm=\"vmcelld\""),
            );
        }
        resp
    }
}

/// The daemon's `Result` alias.
pub type DaemonResult<T> = std::result::Result<T, DaemonError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_variant_maps_to_its_documented_status() {
        assert_eq!(DaemonError::NotFound("x".into()).kind().status_code(), 404);
        assert_eq!(
            DaemonError::AlreadyExists("x".into()).kind().status_code(),
            409
        );
        assert_eq!(DaemonError::InUse("x".into()).kind().status_code(), 409);
        assert_eq!(DaemonError::Conflict("x".into()).kind().status_code(), 409);
        assert_eq!(
            DaemonError::BadRequest("x".into()).kind().status_code(),
            400
        );
        assert_eq!(
            DaemonError::Unauthorized("x".into()).kind().status_code(),
            401
        );
        assert_eq!(DaemonError::Forbidden("x".into()).kind().status_code(), 403);
        assert_eq!(
            DaemonError::Unsupported("x".into()).kind().status_code(),
            501
        );
        assert_eq!(
            DaemonError::PayloadTooLarge("x".into())
                .kind()
                .status_code(),
            413
        );
        assert_eq!(DaemonError::Internal("x".into()).kind().status_code(), 500);
    }

    // A wrapped vmcell::Error renders its Display (the #[error] message), never the Debug
    // struct-dump — the L-BIN-4 guard applied to the daemon boundary.
    #[test]
    fn wrapped_vmcell_error_renders_display_not_debug() {
        let ve = vmcell::Error::Unsupported {
            vmm: "cloud-hypervisor".into(),
            feature: "snapshot".into(),
        };
        let de: DaemonError = ve.into();
        assert_eq!(de.kind(), ErrorKind::Unsupported);
        let msg = de.message();
        assert!(msg.contains("snapshot"), "human message: {msg}");
        assert!(
            !msg.contains("Unsupported {"),
            "must not be the Debug struct-dump: {msg}"
        );
    }

    // A vmcell `Config` validation failure is a client-supplied bad knob (a reserved
    // kernel arg, a 0 io_limit), so it maps to BadRequest (400) — not a misleading
    // Internal 500. Buggy impl: the `other => Internal` arm swallows Config as a 500.
    #[test]
    fn wrapped_config_error_maps_to_bad_request() {
        let ve = vmcell::Error::Config("mem_mib must be >= 64".into());
        let de: DaemonError = ve.into();
        assert_eq!(de.kind().status_code(), 400, "a bad config knob is a 400");
        assert!(de.message().contains("mem_mib"));
    }
}
