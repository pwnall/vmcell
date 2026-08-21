//! A typed Rust client for `vmcelld` (design §11.7, The client library and CLI).
//!
//! The API mirrors the `vmcell` entry points as closely as the network boundary allows: `run` /
//! `create` / `exec` / `stats` / `snapshot` / `ls` / `destroy` map one-to-one to the CLI verbs, with
//! `kernel`/`rootfs` given as artifact **names** (not host paths). The one forced divergence the
//! integrator anticipated is that a host path becomes an **upload**: [`DaemonClient::upload_artifact`]
//! (design §18, Delta register: changes from the validated v27 build). DTOs are re-exported from `vmcell-daemon` (linked without its server stack), so a
//! request the client serializes and the daemon deserializes are the SAME type.
//!
//! # Example: an upload and two round trips
//!
//! `no_run` — it needs a listening `vmcelld` and its API-key file. `just test-doc` compiles it, so
//! the verbs and DTOs below are the ones this client ships today.
//!
//! ```no_run
//! use std::path::Path;
//! use url::Url;
//! use vmcell_daemon_client::{DaemonClient, dto::ExecRequestDto};
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // The daemon takes its key from a perms-checked FILE, never from argv or the environment
//! // (design §11.6) — so console logs and process listings never carry it. A client holds the same
//! // secret; nothing in this crate enforces that, so the discipline is the caller's to keep.
//! let api_key = std::fs::read_to_string("/run/vmcell/api-key")?;
//! let client = DaemonClient::new(Url::parse("http://127.0.0.1:8787")?, api_key.trim())?;
//!
//! // The one forced divergence from the library API: the daemon addresses artifacts by NAME, so a
//! // host path becomes an upload. The store is create-only, so re-uploading a name is a typed
//! // `ErrorKind::AlreadyExists` rather than a silent overwrite.
//! client.upload_artifact("vmlinux", Path::new("/artifacts/vmlinux")).await?;
//! let rootfs = client
//!     .upload_artifact("rootfs.erofs", Path::new("/artifacts/rootfs.erofs"))
//!     .await?;
//! // The daemon hashes what it stored, so an upload can be verified without downloading it back.
//! assert_eq!(rootfs.sha256.len(), 64);
//!
//! // `run`: boot, exec, tear down — the one-shot verb, addressed by artifact name.
//! let outcome = client
//!     .run("vmlinux", "rootfs.erofs", vec!["/bin/echo".into(), "hi".into()])
//!     .await?;
//! assert_eq!(outcome.code, 0);
//!
//! // Or keep the cell: `create` / `exec` / `destroy` are one-to-one with the `vmcell` entry points.
//! let vm = client.create("vmlinux", "rootfs.erofs").await?;
//! let outcome = client
//!     .exec(&vm.id, ExecRequestDto::new(vec!["/bin/true".into()]))
//!     .await?;
//! assert_eq!(outcome.code, 0);
//! client.destroy(&vm.id).await?;
//! # Ok(())
//! # }
//! ```
//!
//! A server-side condition arrives as the same matchable [`dto::ErrorKind`] the daemon names, so a
//! caller branches on the kind and never on a raw status:
//!
//! ```no_run
//! # use vmcell_daemon_client::{ClientError, DaemonClient, dto::ErrorKind};
//! # async fn artifact_size(client: &DaemonClient) -> Result<Option<u64>, ClientError> {
//! match client.get_artifact("vmlinux").await {
//!     Ok(info) => Ok(Some(info.size_bytes)),
//!     Err(e) if e.kind() == Some(ErrorKind::NotFound) => Ok(None),
//!     Err(e) => Err(e),
//! }
//! # }
//! ```
#![deny(missing_docs, unsafe_op_in_unsafe_fn, rustdoc::broken_intra_doc_links)]
#![deny(unreachable_pub)] // pub-in-private-module API-surface honesty
#![deny(
    clippy::undocumented_unsafe_blocks,
    clippy::missing_safety_doc,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::multiple_unsafe_ops_per_block // one obligation per SAFETY comment
)]
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::panic,
        clippy::unreachable,
        clippy::todo,
        clippy::unimplemented,
        clippy::indexing_slicing,
        clippy::print_stdout,
        clippy::print_stderr,
        clippy::dbg_macro,
        // AGENTS.md "Fail loud": no bare `let _ =` on a `Result`. `let_underscore_must_use` is the
        // narrowest instrument rustc/clippy has for that rule — and it is deliberately BROADER on
        // one axis, firing on any `#[must_use]` expression (a detached `JoinHandle`, a discarded
        // `Instant`), which is the same defect one step out: the compiler said this matters and the
        // code said nothing back. Scoped `not(test)` like every lint in this block: the rule's
        // stated harms (a swallowed teardown failure, a lost write, a wedged session) are
        // production harms, and forcing a reason onto a test's `try_init()` would manufacture the
        // hollow suppressions AGENTS.md rule 2 calls theater. `crates/vmcell/tests/lint_roster.rs`
        // is the gate that this line exists in EVERY crate root, so a new crate cannot opt out by
        // being new.
        clippy::let_underscore_must_use,
        clippy::allow_attributes,               // B11: prefer #[expect] over #[allow] in prod code
        clippy::allow_attributes_without_reason  // B11: every suppression states why
    )
)]

use std::path::{Path, PathBuf};
use url::Url;

// Re-export the wire schema so callers use one set of types with the daemon (design §11.7, The client library and CLI).
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
    /// Turns this body into the `reqwest` body that will be written to the wire.
    ///
    /// The [`UploadBody::Path`] arm **streams**: the file is opened and handed to `reqwest` as a byte
    /// stream, so a multi-gigabyte kernel or rootfs is written chunk by chunk and never sits in the
    /// client's memory (design §11.7, The client library and CLI; §17, Open gaps and future
    /// capabilities — "Streaming upload (v1 reads the file into memory)"). v1 called `std::fs::read`
    /// here, which made the largest artifact a client could upload a function of its own RAM, and
    /// made a streaming server pointless: the buffering had already happened.
    ///
    /// The file is opened here rather than at [`UploadBody::from`] so the I/O error arrives at the
    /// call that can report it, and so a body built and never sent holds no file descriptor.
    ///
    /// # Errors
    /// [`ClientError::Io`] if the file cannot be opened.
    async fn into_reqwest_body(self) -> Result<reqwest::Body, ClientError> {
        match self {
            Self::Bytes(b) => Ok(reqwest::Body::from(b)),
            Self::Path(p) => {
                let file = tokio::fs::File::open(&p)
                    .await
                    .map_err(|e| ClientError::Io(format!("cannot open {}: {e}", p.display())))?;
                Ok(reqwest::Body::from(file))
            }
        }
    }
}

/// A client error. Server-side conditions are surfaced as the SAME matchable kinds the daemon names
/// (design §11.5, The HTTP REST API and its OpenAPI document), so a caller branches on `AlreadyExists`/`NotFound`/… rather than a raw status.
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

    /// The **one** place a caller-supplied name becomes part of a request path: `template`'s `{}` is
    /// replaced by `segment`, which [`validate_path_segment`] has cleared first. Every verb that
    /// names a resource goes through this — never `self.url(&format!(…))` with a caller string.
    fn resource_url(&self, kind: &str, segment: &str, template: &str) -> Result<Url, ClientError> {
        validate_path_segment(kind, segment)?;
        self.url(&template.replace("{}", segment))
    }

    /// The artifact-name URL: the daemon's **own** name law first (so a bad name is refused with the
    /// reason the daemon would have given, before a round trip), then the one path-segment join.
    fn artifact_url(&self, artifact_name: &str) -> Result<Url, ClientError> {
        name::validate_artifact_name(artifact_name).map_err(|e| ClientError::Api {
            kind: Some(ErrorKind::InvalidName),
            status: 400,
            message: e.to_string(),
        })?;
        self.resource_url("artifact name", artifact_name, "v1/artifacts/{}")
    }

    /// A VM-scoped URL. A [`VmId`] is an opaque server-minted string a caller can nonetheless spell
    /// itself (`VmId::from_str` is infallible), so it is caller-supplied input like any other and
    /// carries no name law of its own — [`validate_path_segment`] is the whole check.
    fn vm_url(&self, id: &VmId, template: &str) -> Result<Url, ClientError> {
        self.resource_url("vm id", &id.0, template)
    }

    // ---- artifact store (paths -> upload, the design §18, Delta register: changes from the validated v27 build divergence) ----

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
        // Validated client-side for a clear early error (the same predicate the daemon enforces) —
        // and before the file is opened, so a bad name costs no I/O.
        let url = self.artifact_url(artifact_name)?;
        let body = body.into().into_reqwest_body().await?;
        self.send_json(self.http.put(url).body(body)).await
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
        let url = self.artifact_url(artifact_name)?;
        self.send_json(self.http.get(url)).await
    }

    /// Deletes an artifact.
    ///
    /// # Errors
    /// [`ClientError`] (e.g. [`ErrorKind::InUse`] if a live VM pins it).
    pub async fn delete_artifact(&self, artifact_name: &str) -> Result<(), ClientError> {
        let url = self.artifact_url(artifact_name)?;
        self.send_no_content(self.http.delete(url)).await
    }

    // ---- VM lifecycle (one-to-one with the vmcell CLI verbs) ----

    /// Creates a VM from a full request (design §11.5, The HTTP REST API and its OpenAPI document). Returns the VM info and, if `command`
    /// was set, the captured exec outcome.
    ///
    /// # Errors
    /// [`ClientError`] on a bad artifact reference or a launch failure.
    pub async fn create_vm(&self, req: CreateVmRequest) -> Result<CreateVmResponse, ClientError> {
        let url = self.url("v1/vms")?;
        self.send_json(self.http.post(url).json(&req)).await
    }

    /// `create`: boots a VM to steward-ready and keeps it (no inline command).
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
        let url = self.vm_url(id, "v1/vms/{}")?;
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
        let url = self.vm_url(id, "v1/vms/{}/exec")?;
        self.send_json(self.http.post(url).json(&req)).await
    }

    /// `stats`: samples a VM's resource usage.
    ///
    /// # Errors
    /// [`ClientError`] on failure.
    pub async fn stats(&self, id: &VmId) -> Result<ResourceUsageDto, ClientError> {
        let url = self.vm_url(id, "v1/vms/{}/stats")?;
        self.send_json(self.http.get(url)).await
    }

    /// `pause`: stops a `Ready` VM's vCPUs, returning its updated info (design §11.5, The HTTP REST
    /// API and its OpenAPI document). Every host resource stays held, so the VM still pins its
    /// artifacts; `exec`/`snapshot` are refused with [`ErrorKind::Conflict`] until it is resumed.
    ///
    /// # Errors
    /// [`ClientError`] — [`ErrorKind::Conflict`] if the VM is not `Ready`, [`ErrorKind::NotFound`] if
    /// it is gone.
    pub async fn pause(&self, id: &VmId) -> Result<VmInfo, ClientError> {
        let url = self.vm_url(id, "v1/vms/{}/pause")?;
        self.send_json(self.http.post(url)).await
    }

    /// `resume`: restarts a `Paused` VM's vCPUs, returning its updated info.
    ///
    /// # Errors
    /// [`ClientError`] — [`ErrorKind::Conflict`] if the VM is not `Paused`.
    pub async fn resume(&self, id: &VmId) -> Result<VmInfo, ClientError> {
        let url = self.vm_url(id, "v1/vms/{}/resume")?;
        self.send_json(self.http.post(url)).await
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
        let url = self.vm_url(id, "v1/vms/{}/snapshot")?;
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
        let url = self.vm_url(id, "v1/vms/{}")?;
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

/// The ONE predicate a caller-supplied string passes before it becomes part of a request path
/// (design §11.7, The client library and CLI; the client-side half of the daemon's own
/// `resolve_artifact_path` law).
///
/// `Url::join` takes a **relative reference**, so an unvalidated segment does not produce a 404 — it
/// produces a request against a *different endpoint*: `delete_artifact("../vms/vm-1")` joins to
/// `DELETE /v1/vms/vm-1` and destroys a VM, `get("..")` reads the collection, and a `?`/`#` truncates
/// the path into a query or fragment. Every verb that names a resource therefore routes through
/// [`DaemonClient::resource_url`], which calls this first (finding
/// `client-joins-unvalidated-names-into-request-paths`).
///
/// An **allowlist** (`[A-Za-z0-9._~-]`, and never `.`/`..`), not a denylist of bad substrings: the
/// daemon's own name predicate makes the same choice for the same reason — a denylist is the
/// divergence trap where you always forget one spelling.
///
/// # Errors
/// [`ClientError::Api`] with [`ErrorKind::InvalidName`] and status 400 — the same shape the daemon
/// would have replied with, decided locally so the request never leaves the process.
fn validate_path_segment(kind: &str, value: &str) -> Result<(), ClientError> {
    let reject = |why: &str| {
        Err(ClientError::Api {
            kind: Some(ErrorKind::InvalidName),
            status: 400,
            message: format!("{kind} {value:?} {why}"),
        })
    };
    if value.is_empty() {
        return reject("must not be empty");
    }
    if value == "." || value == ".." {
        return reject("must not be `.` or `..` (it would climb the request path)");
    }
    if let Some(bad) = value
        .bytes()
        .find(|b| !(b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'~')))
    {
        return reject(&format!(
            "may only contain [A-Za-z0-9._~-] to be a single URL path segment; found byte {bad:#04x}"
        ));
    }
    Ok(())
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
    // caller can branch on it (design §11.5, The HTTP REST API and its OpenAPI document). RED if the kind is dropped.
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

    /// A client pointed at a port nothing listens on: any verb that actually SENDS returns
    /// `Transport`, so a `Transport` error in the tests below would prove the request left the
    /// process — the discriminator that makes "refused before the wire" a real assertion.
    fn offline_client() -> DaemonClient {
        DaemonClient::new(Url::parse("http://127.0.0.1:1/").expect("url"), "k").expect("client")
    }

    // Every verb that names a resource validates the name BEFORE joining it into the request path
    // (finding `client-joins-unvalidated-names-into-request-paths`): `Url::join` resolves a relative
    // reference, so `../vms/<id>` on an artifact verb is not a 404 — it is a DELETE against a VM.
    //
    // Driven verb-by-verb rather than through the predicate alone, because the defect was per-call-
    // site: `upload_artifact` validated and the other seven did not. RED on the inverse (revert any
    // one verb to `self.url(&format!(…))`): that verb returns `Transport` (it reached the wire) or
    // `Url`, never `InvalidName`.
    #[tokio::test]
    async fn every_resource_verb_refuses_a_traversing_name_before_the_wire() {
        let c = offline_client();
        let escape_name = "../vms/vm-1";
        let escape_id = VmId("../artifacts/vmlinux".to_string());

        let mut refused: Vec<(&str, ClientError)> = Vec::new();
        refused.push((
            "upload_artifact",
            c.upload_artifact(escape_name, vec![1u8])
                .await
                .expect_err("upload"),
        ));
        refused.push((
            "get_artifact",
            c.get_artifact(escape_name).await.expect_err("get_artifact"),
        ));
        refused.push((
            "delete_artifact",
            c.delete_artifact(escape_name)
                .await
                .expect_err("delete_artifact"),
        ));
        refused.push(("get", c.get(&escape_id).await.expect_err("get")));
        refused.push((
            "exec",
            c.exec(&escape_id, ExecRequestDto::new(vec!["true".into()]))
                .await
                .expect_err("exec"),
        ));
        refused.push(("stats", c.stats(&escape_id).await.expect_err("stats")));
        refused.push(("pause", c.pause(&escape_id).await.expect_err("pause")));
        refused.push(("resume", c.resume(&escape_id).await.expect_err("resume")));
        refused.push((
            "snapshot",
            c.snapshot(&escape_id, "snap1").await.expect_err("snapshot"),
        ));
        refused.push(("destroy", c.destroy(&escape_id).await.expect_err("destroy")));

        assert_eq!(refused.len(), 10, "every resource-naming verb is covered");
        for (verb, err) in &refused {
            assert_eq!(
                err.kind(),
                Some(ErrorKind::InvalidName),
                "{verb} must refuse the name locally, got {err:?}"
            );
        }

        // The unreachable-base control: a verb whose path carries no caller string DOES reach the
        // wire, so the refusals above are about the validation and not about the offline client.
        assert!(
            matches!(
                c.ls().await.expect_err("no daemon there"),
                ClientError::Transport(_)
            ),
            "a path with no caller-supplied segment is sent, and fails as transport"
        );
    }

    // The segment predicate's own inverses and its positive control: the real minted id shape and the
    // real artifact names must pass, or the gate above would be satisfied by a client that refuses
    // everything.
    #[test]
    fn path_segment_predicate_rejects_only_unsafe_segments() {
        for bad in [
            "",
            ".",
            "..",
            "a/b",
            "/abs",
            "../escape",
            "a?q=1",
            "a#frag",
            "a%2fb",
            "a b",
            "a\\b",
        ] {
            assert!(
                validate_path_segment("vm id", bad).is_err(),
                "must reject {bad:?}"
            );
        }
        for good in [
            "vm-1-0123456789abcdef", // the minted VmId shape
            "vmlinux",
            "rootfs.erofs",
            "snap_2024",
            "k1",
        ] {
            assert!(
                validate_path_segment("vm id", good).is_ok(),
                "must accept {good:?}"
            );
        }
    }

    // The call-site scan (AGENTS.md: a gate binds the call SITES, not just the extracted predicate).
    // Every verb's URL is either a literal collection path or one of the two checked helpers, so the
    // shape the finding describes — a caller string interpolated straight into a path — cannot come
    // back without reddening here.
    #[test]
    fn no_verb_interpolates_a_caller_string_into_a_request_path() {
        const SRC: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/lib.rs"));
        let prod = SRC.split("\n#[cfg(test)]\n").next().unwrap_or(SRC);
        let mut checked_joins = 0;
        let mut segment_predicate_call_sites = 0;
        for (i, line) in prod.lines().enumerate() {
            let code = line.split("//").next().unwrap_or("");
            if ["self.resource_url(", "self.artifact_url(", "self.vm_url("]
                .iter()
                .any(|call| code.contains(call))
            {
                checked_joins += 1;
            }
            if code.contains("validate_path_segment(") && !code.contains("fn validate_path_segment")
            {
                segment_predicate_call_sites += 1;
            }
            assert!(
                !(code.contains("format!(\"v1/") || code.contains("self.url(&format!")),
                "lib.rs:{}: a request path built by interpolation — route the segment through \
                 `resource_url`/`artifact_url` so it is validated first: {}",
                i + 1,
                code.trim()
            );
        }
        assert!(
            checked_joins >= 11,
            "the scan found only {checked_joins} checked joins — it is not reading the verbs"
        );
        assert_eq!(
            segment_predicate_call_sites, 1,
            "one law, one call site: only `resource_url` may call the segment predicate"
        );
    }

    // ---- the streaming upload (design §11.7, The client library and CLI; §17, Open gaps and future
    // capabilities — "Streaming upload (v1 reads the file into memory)") ----

    /// What a one-shot loopback server saw: the request head (headers verbatim) and the decoded body.
    struct SeenRequest {
        head: String,
        body: Vec<u8>,
    }

    /// Serves exactly ONE HTTP/1.1 request on `listener`, decoding either framing (chunked or
    /// content-length), answering with a JSON [`ArtifactInfo`], and returning what it received.
    ///
    /// Hand-rolled because the point of the gate is the bytes and headers the client actually put on
    /// the wire — an HTTP library on this side would hide exactly the framing under test.
    async fn serve_one_upload(listener: tokio::net::TcpListener) -> SeenRequest {
        use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _};

        let (sock, _) = listener.accept().await.expect("accept");
        let (rd, mut wr) = sock.into_split();
        let mut rd = tokio::io::BufReader::new(rd);

        let mut head = String::new();
        loop {
            let mut line = String::new();
            let n = rd.read_line(&mut line).await.expect("read head line");
            assert!(n > 0, "the client closed before finishing the request head");
            if line == "\r\n" {
                break;
            }
            head.push_str(&line);
        }

        let lower = head.to_ascii_lowercase();
        let mut body = Vec::new();
        if lower.contains("transfer-encoding: chunked") {
            loop {
                let mut size_line = String::new();
                rd.read_line(&mut size_line).await.expect("chunk size");
                let size = usize::from_str_radix(size_line.trim(), 16).expect("hex chunk size");
                if size == 0 {
                    break;
                }
                let mut chunk = vec![0u8; size];
                rd.read_exact(&mut chunk).await.expect("chunk body");
                body.extend_from_slice(&chunk);
                let mut crlf = [0u8; 2];
                rd.read_exact(&mut crlf).await.expect("chunk CRLF");
            }
        } else if let Some(len) = lower
            .lines()
            .find_map(|l| l.strip_prefix("content-length:"))
            .and_then(|v| v.trim().parse::<usize>().ok())
        {
            body = vec![0u8; len];
            rd.read_exact(&mut body).await.expect("sized body");
        }

        let reply = serde_json::to_vec(&ArtifactInfo {
            name: "rootfs.erofs".to_string(),
            size_bytes: body.len() as u64,
            sha256: "0".repeat(64),
        })
        .expect("encode reply");
        wr.write_all(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
                reply.len()
            )
            .as_bytes(),
        )
        .await
        .expect("write head");
        wr.write_all(&reply).await.expect("write body");
        wr.flush().await.expect("flush");

        SeenRequest { head, body }
    }

    /// A fixture file of `len` pseudo-random-ish bytes, in a temp dir that cleans itself up on the
    /// panic path as well as the success path (AGENTS.md: a test's own fixtures are residue too).
    fn fixture_file(len: usize) -> (tempfile::TempDir, PathBuf, Vec<u8>) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("rootfs.erofs");
        let bytes: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
        std::fs::write(&path, &bytes).expect("write fixture");
        (dir, path, bytes)
    }

    async fn upload_against_a_local_server(
        body: impl Into<UploadBody>,
    ) -> (ArtifactInfo, SeenRequest) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let server = tokio::spawn(serve_one_upload(listener));
        let client = DaemonClient::new(
            Url::parse(&format!("http://{addr}")).expect("url"),
            "test-key",
        )
        .expect("client");
        let info = client
            .upload_artifact("rootfs.erofs", body)
            .await
            .expect("upload");
        (info, server.await.expect("server join"))
    }

    // The file arm STREAMS, proven on the wire: the request carries `Transfer-Encoding: chunked` and
    // no `Content-Length`, which is precisely what a body of unknown length looks like — and the
    // bytes that arrive are the file's, byte for byte, over a body far larger than one chunk.
    //
    // RED on the inverse (`UploadBody::Path => std::fs::read(&p)`, the v1 implementation): the whole
    // file is in memory before the request starts, so reqwest knows its length and sends a sized
    // body — the `chunked` assertion fails and the `Content-Length` one does too. That is the only
    // externally visible difference between reading a file and streaming it, which is why the gate
    // is written on the framing rather than on the payload alone.
    #[tokio::test]
    async fn a_file_upload_is_streamed_to_the_wire_and_arrives_byte_exact() {
        let (_dir, path, bytes) = fixture_file(512 * 1024);
        let (info, seen) = upload_against_a_local_server(path.as_path()).await;

        let lower = seen.head.to_ascii_lowercase();
        assert!(
            lower.contains("transfer-encoding: chunked"),
            "a streamed file body is chunked; head was:\n{}",
            seen.head
        );
        assert!(
            !lower.contains("content-length:"),
            "a streamed body cannot know its length up front; head was:\n{}",
            seen.head
        );
        assert_eq!(seen.body, bytes, "the file's bytes arrive unchanged");
        assert_eq!(info.size_bytes, bytes.len() as u64);
    }

    // The positive control for the framing assertion above: the in-memory arm IS sized, so the gate
    // is reading a real property of the body rather than something true of every request this client
    // makes. Same verb, same server, one variable changed.
    #[tokio::test]
    async fn a_byte_upload_is_sent_as_a_sized_body() {
        let bytes: Vec<u8> = (0..64 * 1024).map(|i| (i % 251) as u8).collect();
        let (_info, seen) = upload_against_a_local_server(bytes.clone()).await;
        let lower = seen.head.to_ascii_lowercase();
        assert!(
            lower.contains(&format!("content-length: {}", bytes.len())),
            "an in-memory body knows its length; head was:\n{}",
            seen.head
        );
        assert!(!lower.contains("transfer-encoding: chunked"));
        assert_eq!(seen.body, bytes);
    }

    // The file arm reports its I/O failure as the client's own typed error, at the call that can act
    // on it — and before anything reaches the wire.
    #[tokio::test]
    async fn a_missing_upload_file_is_a_typed_io_error() {
        let c = offline_client();
        let err = c
            .upload_artifact(
                "rootfs.erofs",
                Path::new("/nonexistent/vmcell-upload-fixture"),
            )
            .await
            .expect_err("a missing file must fail");
        assert!(
            matches!(err, ClientError::Io(_)),
            "expected an Io error, got {err:?}"
        );
        assert!(err.to_string().contains("vmcell-upload-fixture"));
    }
}
