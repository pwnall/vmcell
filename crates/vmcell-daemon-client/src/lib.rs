//! A typed Rust client for `vmcelld` (design v21 §D7).
//!
//! The API mirrors the `vmcell` entry points as closely as the network boundary allows: `run` /
//! `create` / `exec` / `stats` / `snapshot` / `ls` / `destroy` map one-to-one to the CLI verbs, with
//! `kernel`/`rootfs` given as artifact **names** (not host paths). The one forced divergence the
//! integrator anticipated is that a host path becomes an **upload**: [`DaemonClient::upload_artifact`]
//! (design v21 §D8). DTOs are re-exported from `vmcell-daemon` (linked without its server stack), so a
//! request the client serializes and the daemon deserializes are the SAME type.
#![deny(missing_docs, rustdoc::broken_intra_doc_links)]
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)
)]

use std::path::{Path, PathBuf};
use url::Url;

// Re-export the wire schema so callers use one set of types with the daemon (design v21 §D7.1).
pub use vmcell_daemon::dto;
pub use vmcell_daemon::name;

use dto::{
    ArtifactInfo, CreateVmRequest, CreateVmResponse, ErrorBody, ErrorKind, ExecOutcomeDto,
    ExecRequestDto, ResourceUsageDto, SnapshotInfo, SnapshotRequest, VmId, VmInfo,
};

/// The bytes to upload as an artifact: either in-memory or a local file the client streams.
pub enum UploadBody {
    /// Raw bytes.
    Bytes(Vec<u8>),
    /// A local file path (read at send time).
    Path(PathBuf),
}

impl From<Vec<u8>> for UploadBody {
    fn from(b: Vec<u8>) -> Self {
        Self::Bytes(b)
    }
}
impl From<&Path> for UploadBody {
    fn from(p: &Path) -> Self {
        Self::Path(p.to_path_buf())
    }
}
impl From<PathBuf> for UploadBody {
    fn from(p: PathBuf) -> Self {
        Self::Path(p)
    }
}

impl UploadBody {
    fn into_bytes(self) -> Result<Vec<u8>, ClientError> {
        match self {
            Self::Bytes(b) => Ok(b),
            // v1 reads the file into memory; streaming a large image is a small follow-up
            // (`reqwest::Body::wrap_stream`), recorded in design v21 §D12.
            Self::Path(p) => std::fs::read(&p)
                .map_err(|e| ClientError::Io(format!("cannot read {}: {e}", p.display()))),
        }
    }
}

/// A client error. Server-side conditions are surfaced as the SAME matchable kinds the daemon names
/// (design v21 §D5.3), so a caller branches on `AlreadyExists`/`NotFound`/… rather than a raw status.
#[derive(Debug)]
pub enum ClientError {
    /// A typed error the daemon returned, with its kind and message.
    Api {
        /// The machine-matchable kind (`None` if the server sent an unknown kind string).
        kind: Option<ErrorKind>,
        /// The HTTP status code.
        status: u16,
        /// The human message.
        message: String,
    },
    /// A transport / connection failure.
    Transport(String),
    /// A response body that could not be decoded.
    Decode(String),
    /// A local I/O error (e.g. reading a file to upload).
    Io(String),
    /// A malformed base URL / path.
    Url(String),
}

impl ClientError {
    /// The daemon error kind, if this was a typed API error.
    #[must_use]
    pub fn kind(&self) -> Option<ErrorKind> {
        match self {
            Self::Api { kind, .. } => *kind,
            _ => None,
        }
    }
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Api {
                status, message, ..
            } => write!(f, "daemon error (HTTP {status}): {message}"),
            Self::Transport(m) => write!(f, "transport error: {m}"),
            Self::Decode(m) => write!(f, "decode error: {m}"),
            Self::Io(m) => write!(f, "io error: {m}"),
            Self::Url(m) => write!(f, "url error: {m}"),
        }
    }
}

impl std::error::Error for ClientError {}

/// A connection to one `vmcelld`.
pub struct DaemonClient {
    http: reqwest::Client,
    base: Url,
    api_key: String,
}

impl DaemonClient {
    /// Builds a client for the daemon at `base_url`, authenticating with `api_key`.
    ///
    /// # Errors
    /// [`ClientError::Url`] if the base URL cannot be normalized, [`ClientError::Transport`] if the
    /// HTTP client cannot be built.
    pub fn new(base_url: Url, api_key: impl Into<String>) -> Result<Self, ClientError> {
        // Ensure a trailing slash so `Url::join("v1/…")` extends rather than replaces the path.
        let mut base = base_url;
        if !base.path().ends_with('/') {
            let p = format!("{}/", base.path());
            base.set_path(&p);
        }
        let http = reqwest::Client::builder()
            .build()
            .map_err(|e| ClientError::Transport(e.to_string()))?;
        Ok(Self {
            http,
            base,
            api_key: api_key.into(),
        })
    }

    fn url(&self, path: &str) -> Result<Url, ClientError> {
        self.base
            .join(path)
            .map_err(|e| ClientError::Url(format!("{path}: {e}")))
    }

    // ---- artifact store (paths -> upload, the design v21 §D8 divergence) ----

    /// Uploads an artifact (create; the daemon rejects an existing name — "no update").
    ///
    /// # Errors
    /// [`ClientError`] on a bad name, an I/O failure reading the body, or the daemon's typed error
    /// (e.g. [`ErrorKind::AlreadyExists`]).
    pub async fn upload_artifact(
        &self,
        artifact_name: &str,
        body: impl Into<UploadBody>,
    ) -> Result<ArtifactInfo, ClientError> {
        // Validate client-side for a clear early error (the same predicate the daemon enforces).
        name::validate_artifact_name(artifact_name).map_err(|e| ClientError::Api {
            kind: Some(ErrorKind::InvalidName),
            status: 400,
            message: e.to_string(),
        })?;
        let bytes = body.into().into_bytes()?;
        let url = self.url(&format!("v1/artifacts/{artifact_name}"))?;
        self.send_json(self.http.put(url).body(bytes)).await
    }

    /// Lists artifacts.
    ///
    /// # Errors
    /// [`ClientError`] on transport/decode/daemon failure.
    pub async fn list_artifacts(&self) -> Result<Vec<ArtifactInfo>, ClientError> {
        let url = self.url("v1/artifacts")?;
        self.send_json(self.http.get(url)).await
    }

    /// Reads one artifact's metadata.
    ///
    /// # Errors
    /// [`ClientError`] (e.g. [`ErrorKind::NotFound`]).
    pub async fn get_artifact(&self, artifact_name: &str) -> Result<ArtifactInfo, ClientError> {
        let url = self.url(&format!("v1/artifacts/{artifact_name}"))?;
        self.send_json(self.http.get(url)).await
    }

    /// Deletes an artifact.
    ///
    /// # Errors
    /// [`ClientError`] (e.g. [`ErrorKind::InUse`] if a live VM pins it).
    pub async fn delete_artifact(&self, artifact_name: &str) -> Result<(), ClientError> {
        let url = self.url(&format!("v1/artifacts/{artifact_name}"))?;
        self.send_no_content(self.http.delete(url)).await
    }

    // ---- VM lifecycle (one-to-one with the vmcell CLI verbs) ----

    /// Creates a VM from a full request (design v21 §D5.1). Returns the VM info and, if `command`
    /// was set, the captured exec outcome.
    ///
    /// # Errors
    /// [`ClientError`] on a bad artifact reference or a launch failure.
    pub async fn create_vm(&self, req: CreateVmRequest) -> Result<CreateVmResponse, ClientError> {
        let url = self.url("v1/vms")?;
        self.send_json(self.http.post(url).json(&req)).await
    }

    /// `create`: boots a VM to agent-ready and keeps it (no inline command).
    ///
    /// # Errors
    /// [`ClientError`] on failure.
    pub async fn create(&self, kernel: &str, rootfs: &str) -> Result<VmInfo, ClientError> {
        let resp = self
            .create_vm(CreateVmRequest::create(kernel, rootfs))
            .await?;
        Ok(resp.vm)
    }

    /// `run`: boots a VM, execs `command`, tears it down, and returns the captured outcome.
    ///
    /// # Errors
    /// [`ClientError::Decode`] if the daemon omitted the exec outcome, else the daemon's error.
    pub async fn run(
        &self,
        kernel: &str,
        rootfs: &str,
        command: Vec<String>,
    ) -> Result<ExecOutcomeDto, ClientError> {
        let resp = self
            .create_vm(CreateVmRequest::run(kernel, rootfs, command))
            .await?;
        resp.exec
            .ok_or_else(|| ClientError::Decode("run response missing the exec outcome".into()))
    }

    /// `ls`: lists live VMs.
    ///
    /// # Errors
    /// [`ClientError`] on failure.
    pub async fn ls(&self) -> Result<Vec<VmInfo>, ClientError> {
        let url = self.url("v1/vms")?;
        self.send_json(self.http.get(url)).await
    }

    /// Gets one VM.
    ///
    /// # Errors
    /// [`ClientError`] (e.g. [`ErrorKind::NotFound`]).
    pub async fn get(&self, id: &VmId) -> Result<VmInfo, ClientError> {
        let url = self.url(&format!("v1/vms/{id}"))?;
        self.send_json(self.http.get(url)).await
    }

    /// `exec`: runs a command in a live VM.
    ///
    /// # Errors
    /// [`ClientError`] (e.g. [`ErrorKind::NotFound`] if the VM is gone).
    pub async fn exec(
        &self,
        id: &VmId,
        req: ExecRequestDto,
    ) -> Result<ExecOutcomeDto, ClientError> {
        let url = self.url(&format!("v1/vms/{id}/exec"))?;
        self.send_json(self.http.post(url).json(&req)).await
    }

    /// `stats`: samples a VM's resource usage.
    ///
    /// # Errors
    /// [`ClientError`] on failure.
    pub async fn stats(&self, id: &VmId) -> Result<ResourceUsageDto, ClientError> {
        let url = self.url(&format!("v1/vms/{id}/stats"))?;
        self.send_json(self.http.get(url)).await
    }

    /// `snapshot`: writes a warm snapshot into the artifact store under `artifact_prefix/`.
    ///
    /// # Errors
    /// [`ClientError`] on failure.
    pub async fn snapshot(
        &self,
        id: &VmId,
        artifact_prefix: &str,
    ) -> Result<SnapshotInfo, ClientError> {
        let url = self.url(&format!("v1/vms/{id}/snapshot"))?;
        let body = SnapshotRequest {
            artifact_prefix: artifact_prefix.to_string(),
        };
        self.send_json(self.http.post(url).json(&body)).await
    }

    /// `destroy` (== `rm`): tears a VM down.
    ///
    /// # Errors
    /// [`ClientError`] (e.g. [`ErrorKind::NotFound`]).
    pub async fn destroy(&self, id: &VmId) -> Result<(), ClientError> {
        let url = self.url(&format!("v1/vms/{id}"))?;
        self.send_no_content(self.http.delete(url)).await
    }

    // ---- transport helpers ----

    async fn send_json<T: serde::de::DeserializeOwned>(
        &self,
        rb: reqwest::RequestBuilder,
    ) -> Result<T, ClientError> {
        let resp = self.dispatch(rb).await?;
        let status = resp.status();
        if status.is_success() {
            resp.json::<T>()
                .await
                .map_err(|e| ClientError::Decode(e.to_string()))
        } else {
            Err(api_error(status.as_u16(), &self.read_body(resp).await))
        }
    }

    async fn send_no_content(&self, rb: reqwest::RequestBuilder) -> Result<(), ClientError> {
        let resp = self.dispatch(rb).await?;
        let status = resp.status();
        if status.is_success() {
            Ok(())
        } else {
            Err(api_error(status.as_u16(), &self.read_body(resp).await))
        }
    }

    async fn dispatch(
        &self,
        rb: reqwest::RequestBuilder,
    ) -> Result<reqwest::Response, ClientError> {
        rb.bearer_auth(&self.api_key)
            .send()
            .await
            .map_err(|e| ClientError::Transport(e.to_string()))
    }

    async fn read_body(&self, resp: reqwest::Response) -> String {
        resp.text().await.unwrap_or_default()
    }
}

/// Parses a non-2xx body into a typed [`ClientError::Api`], recovering the matchable kind from the
/// structured [`ErrorBody`] when present (else falling back to just the status).
fn api_error(status: u16, body: &str) -> ClientError {
    match serde_json::from_str::<ErrorBody>(body) {
        Ok(eb) => ClientError::Api {
            kind: ErrorKind::from_wire(&eb.error),
            status,
            message: eb.message,
        },
        Err(_) => ClientError::Api {
            kind: None,
            status,
            message: if body.is_empty() {
                format!("HTTP {status}")
            } else {
                body.to_string()
            },
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_url_gets_trailing_slash_and_joins() {
        let c = DaemonClient::new(Url::parse("http://127.0.0.1:8787").expect("url"), "k")
            .expect("client");
        assert_eq!(
            c.url("v1/vms").expect("join").as_str(),
            "http://127.0.0.1:8787/v1/vms"
        );
    }

    // The typed-error round-trip: a daemon ErrorBody parses back to the same matchable kind, so a
    // caller can branch on it (design v21 §D5.3). RED if the kind is dropped.
    #[test]
    fn api_error_recovers_matchable_kind() {
        let body = serde_json::to_string(&ErrorBody {
            error: "already_exists".into(),
            message: "artifact \"k\" already exists".into(),
        })
        .expect("json");
        let err = api_error(409, &body);
        assert_eq!(err.kind(), Some(ErrorKind::AlreadyExists));
        assert!(err.to_string().contains("already exists"));
    }

    #[test]
    fn api_error_falls_back_without_structured_body() {
        let err = api_error(502, "bad gateway");
        assert_eq!(err.kind(), None);
        assert!(matches!(err, ClientError::Api { status: 502, .. }));
    }

    #[test]
    fn upload_body_from_bytes_roundtrips() {
        let b = UploadBody::from(vec![1u8, 2, 3])
            .into_bytes()
            .expect("bytes");
        assert_eq!(b, vec![1, 2, 3]);
    }
}
