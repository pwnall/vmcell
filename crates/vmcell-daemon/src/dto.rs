//! The request/response wire types (DTOs) — the schema shared by the daemon server and the
//! `vmcell-daemon-client` (design §11.5, The HTTP REST API and its OpenAPI document/§11.7, The client library and CLI). Compiled with **no** feature gate so a request the
//! client serializes and the server deserializes are the SAME Rust type — the wire schema is
//! single-sourced (invariant: one law, one predicate for the schema).
//!
//! Every field carries a `#[serde(default)]` where a future field is likely, so an older client and
//! a newer server (or vice versa) stay compatible additively — the `#[non_exhaustive]`-in-spirit rule
//! for a JSON API.

use base64::Engine as _;
use serde::{Deserialize, Serialize};

/// An opaque, server-minted VM handle id (design §11.4, The VM registry and the start-up sweep). Readable prefix + randomness so ids are
/// unguessable and never reused within a process. NOT the network VMID (that is an internal octet).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct VmId(pub String);

impl std::fmt::Display for VmId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::str::FromStr for VmId {
    type Err = std::convert::Infallible;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(s.to_string()))
    }
}

/// The lifecycle state of a registered VM (design §11.4, The VM registry and the start-up sweep). Derived from the handle, not a hopeful
/// label — `Ready` means the agent handshake succeeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VmState {
    /// Booting; the agent has not yet handshaked.
    Booting,
    /// Booted and agent-ready — accepts `exec`.
    Ready,
    /// Paused (CPUs stopped) via `pause`.
    Paused,
    /// A snapshot is in progress.
    Snapshotting,
    /// Teardown in progress; no further ops accepted.
    Destroying,
}

/// Metadata for one artifact in the store (`GET /v1/artifacts`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactInfo {
    /// The artifact name (a validated single path component).
    pub name: String,
    /// Size on disk in bytes.
    pub size_bytes: u64,
    /// Lowercase hex SHA-256 of the file contents (computed with the library's one hasher), so a
    /// client can verify an upload round-tripped intact.
    pub sha256: String,
}

/// The guest networking mode for a created VM (design §11.5, The HTTP REST API and its OpenAPI document). The daemon holds the caps for the
/// privileged path, so all three are available.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum NetMode {
    /// No guest networking (the default; snapshot-eligible).
    #[default]
    None,
    /// Privileged tap + netns with a `/30` and a default route (needs `CAP_NET_ADMIN`, which the
    /// daemon holds). Snapshot-eligible (no vhost-user device).
    Privileged,
    /// Unprivileged in-process smoltcp NAT (vhost-user-net). **Not** snapshot-eligible.
    Unprivileged,
}

impl NetMode {
    /// Whether a VM with this net mode can be snapshotted (no vhost-user device, design §13, Cross-cutting invariants).
    #[must_use]
    pub const fn snapshot_eligible(self) -> bool {
        !matches!(self, Self::Unprivileged)
    }
}

/// The wire form of a [`vmcell::DiskIoLimit`](vmcell::config::DiskIoLimit) — disk-I/O
/// fault injection (design §4.6, Extra virtio-blk devices and disk-I/O throttling). At least one cap must be set and any set cap must
/// be `> 0`; the library's `build()` enforces both fail-loud.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct DiskIoLimitDto {
    /// Read+write bandwidth cap in bytes/second (`None` = unlimited).
    #[serde(default)]
    pub bandwidth_bytes_per_sec: Option<u64>,
    /// Read+write IOPS cap (`None` = unlimited).
    #[serde(default)]
    pub iops: Option<u64>,
}

/// An extra virtio-blk device for a created VM (design §11, The control-plane daemon (vmcelld)), backed by an artifact
/// in the store. The store is **immutable** (create-only, no update), so an extra disk
/// is attached **read-only** — a shared store artifact must not be mutated out from
/// under other VMs (a writable-scratch-from-artifact copy is forward work). An optional
/// `io_limit` injects disk-I/O faults (§4.6, Extra virtio-blk devices and disk-I/O throttling).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtraDiskSpec {
    /// Artifact name of the disk image (resolved against the store like `kernel`/`rootfs`).
    pub name: String,
    /// Optional I/O rate limit (disk-I/O fault injection).
    #[serde(default)]
    pub io_limit: Option<DiskIoLimitDto>,
}

/// Create-and-boot a VM (`POST /v1/vms`). Mirrors `vmcell run`/`create` (design §11.5, The HTTP REST API and its OpenAPI document), but
/// `kernel`/`rootfs` are artifact **names** resolved against the daemon's store — never host paths.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateVmRequest {
    /// Artifact name of the `vmlinux` direct-boot kernel.
    pub kernel: String,
    /// Artifact name of the erofs root filesystem image.
    pub rootfs: String,
    /// vCPU count.
    #[serde(default = "default_vcpus")]
    pub vcpus: u8,
    /// Guest RAM in MiB.
    #[serde(default = "default_mem_mib")]
    pub mem_mib: u32,
    /// Guest networking mode (default `None`).
    #[serde(default)]
    pub net: NetMode,
    /// Boot a **snapshot-eligible** VM (so it can later be snapshotted). Rejected fail-loud with a
    /// non-eligible config (e.g. `net: unprivileged`, design §13, Cross-cutting invariants).
    #[serde(default)]
    pub snapshotting: bool,
    /// Restore from a snapshot in the artifact store under this prefix (written by
    /// `POST /v1/vms/{id}/snapshot`) instead of a cold boot. The named snapshot is **preserved** (the
    /// daemon copies it before restore), so it can be restored more than once.
    #[serde(default)]
    pub restore_from: Option<String>,
    /// Present ⇒ `run` semantics: exec this command over vsock and capture the outcome. Absent ⇒
    /// `create` semantics: boot to agent-ready and register.
    #[serde(default)]
    pub command: Option<Vec<String>>,
    /// With `command`, tear the VM down after the exec (the `run` one-shot) instead of keeping it in
    /// the registry. Ignored when `command` is absent.
    #[serde(default)]
    pub ephemeral: bool,
    /// Extra read-only virtio-blk devices from the store, enumerated in the guest as
    /// `/dev/vdb`, `/dev/vdc`, … (design §11, The control-plane daemon (vmcelld)). A live VM pins these artifacts (delete
    /// is refused while in use). Optionally throttled for disk-I/O fault injection (§4.6, Extra virtio-blk devices and disk-I/O throttling).
    #[serde(default)]
    pub extra_disks: Vec<ExtraDiskSpec>,
    /// Append-only extra kernel command-line arguments (design §5.3, The kernel command line). Cannot
    /// override a boot token vmcell owns — rejected fail-loud at build. (A custom `init=`
    /// override is deliberately **not** exposed here: it replaces the guest agent, so the
    /// daemon — which owns the VM through the vsock control plane — could not `exec` or
    /// `stats` it. Use the library directly for a custom-init VM.)
    #[serde(default)]
    pub extra_kernel_args: Vec<String>,
}

const fn default_vcpus() -> u8 {
    2
}
const fn default_mem_mib() -> u32 {
    512
}

impl CreateVmRequest {
    /// Builds a minimal `create` request (boot-and-keep) from two artifact names.
    #[must_use]
    pub fn create(kernel: impl Into<String>, rootfs: impl Into<String>) -> Self {
        Self {
            kernel: kernel.into(),
            rootfs: rootfs.into(),
            vcpus: default_vcpus(),
            mem_mib: default_mem_mib(),
            net: NetMode::None,
            snapshotting: false,
            restore_from: None,
            command: None,
            ephemeral: false,
            extra_disks: Vec::new(),
            extra_kernel_args: Vec::new(),
        }
    }

    /// Sets the guest networking mode (builder-style).
    #[must_use]
    pub fn with_net(mut self, net: NetMode) -> Self {
        self.net = net;
        self
    }

    /// Attaches an extra read-only disk artifact by name (builder-style, §11, The control-plane daemon (vmcelld)).
    #[must_use]
    pub fn with_extra_disk(mut self, name: impl Into<String>) -> Self {
        self.extra_disks.push(ExtraDiskSpec {
            name: name.into(),
            io_limit: None,
        });
        self
    }

    /// Appends one append-only extra kernel arg (builder-style, §5.3, The kernel command line).
    #[must_use]
    pub fn with_kernel_arg(mut self, arg: impl Into<String>) -> Self {
        self.extra_kernel_args.push(arg.into());
        self
    }

    /// Marks the VM snapshot-eligible so it can later be snapshotted (builder-style).
    #[must_use]
    pub fn with_snapshotting(mut self, snapshotting: bool) -> Self {
        self.snapshotting = snapshotting;
        self
    }

    /// Restores from the snapshot under `artifact_prefix` instead of a cold boot (builder-style).
    #[must_use]
    pub fn restoring_from(mut self, artifact_prefix: impl Into<String>) -> Self {
        self.restore_from = Some(artifact_prefix.into());
        self
    }

    /// Builds a one-shot `run` request (boot, exec `command`, tear down).
    #[must_use]
    pub fn run(kernel: impl Into<String>, rootfs: impl Into<String>, command: Vec<String>) -> Self {
        Self {
            command: Some(command),
            ephemeral: true,
            ..Self::create(kernel, rootfs)
        }
    }
}

/// A registered VM's metadata (`GET /v1/vms`, `GET /v1/vms/{id}`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VmInfo {
    /// The opaque handle id.
    pub id: VmId,
    /// Current lifecycle state.
    pub state: VmState,
    /// The internal network VMID octet allocation (informational).
    pub vmid: u32,
    /// The kernel artifact name it booted from.
    pub kernel: String,
    /// The rootfs artifact name it booted from.
    pub rootfs: String,
    /// vCPU count.
    pub vcpus: u8,
    /// Guest RAM in MiB.
    pub mem_mib: u32,
}

/// The response to `POST /v1/vms` (design §11.5, The HTTP REST API and its OpenAPI document). Always carries the VM's info; when the request
/// included a `command`, also carries the captured `exec` outcome (and, if `ephemeral`, the VM has
/// already been torn down).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateVmResponse {
    /// The created VM's metadata.
    pub vm: VmInfo,
    /// The captured outcome of the inline `command`, if one was given.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exec: Option<ExecOutcomeDto>,
}

/// Run a command in a VM (`POST /v1/vms/{id}/exec`). Maps to `vmcell::ExecRequest`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecRequestDto {
    /// The command line (`["ls", "-l"]`). Must be non-empty.
    pub argv: Vec<String>,
    /// Environment variables to set.
    #[serde(default)]
    pub env: Vec<(String, String)>,
    /// Optional working directory.
    #[serde(default)]
    pub cwd: Option<String>,
    /// Optional per-exec timeout in seconds; `None` ⇒ the guest default.
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

impl ExecRequestDto {
    /// Builds a request from just an argv (no env/cwd/timeout).
    #[must_use]
    pub fn new(argv: Vec<String>) -> Self {
        Self {
            argv,
            env: Vec::new(),
            cwd: None,
            timeout_secs: None,
        }
    }
}

/// The captured result of an exec (`ExecOutcome` over the wire). `stdout`/`stderr` are **base64** so
/// arbitrary binary output round-trips exactly (a JSON string can't hold raw bytes, and a
/// `from_utf8_lossy` would silently corrupt binary — the "assert on the data plane" rule needs the
/// exact bytes).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecOutcomeDto {
    /// Process exit code (`-1` sentinel = no exit observed).
    pub code: i32,
    /// Base64-encoded standard output.
    pub stdout_b64: String,
    /// Base64-encoded standard error.
    pub stderr_b64: String,
}

impl ExecOutcomeDto {
    /// Encodes captured byte streams into the DTO.
    #[must_use]
    pub fn from_bytes(code: i32, stdout: &[u8], stderr: &[u8]) -> Self {
        let engine = base64::engine::general_purpose::STANDARD;
        Self {
            code,
            stdout_b64: engine.encode(stdout),
            stderr_b64: engine.encode(stderr),
        }
    }

    /// Decodes the captured standard output.
    ///
    /// # Errors
    /// Returns a base64 decode error if the field is malformed (a corrupt/forged response).
    pub fn stdout(&self) -> Result<Vec<u8>, base64::DecodeError> {
        base64::engine::general_purpose::STANDARD.decode(&self.stdout_b64)
    }

    /// Decodes the captured standard error.
    ///
    /// # Errors
    /// Returns a base64 decode error if the field is malformed.
    pub fn stderr(&self) -> Result<Vec<u8>, base64::DecodeError> {
        base64::engine::general_purpose::STANDARD.decode(&self.stderr_b64)
    }
}

/// Resource usage (`GET /v1/vms/{id}/stats`). Mirrors `vmcell::ResourceUsage` field-for-field,
/// including the honest `*_read_ok` capability flags (design §7.2, The fail-loud capability contract and HostCapabilities; a flag reflects empirically
/// validated behavior, not a hopeful default).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceUsageDto {
    /// Peak memory usage in MiB.
    pub mem_peak_mib: u64,
    /// Current memory usage in MiB.
    pub mem_current_mib: u64,
    /// CPU usage in microseconds.
    pub cpu_usec: u64,
    /// Bytes read from disk/block devices.
    pub io_read_bytes: u64,
    /// Bytes written to disk/block devices.
    pub io_write_bytes: u64,
    /// Whether the memory controller is delegated (the hard cap took effect).
    pub mem_limit_enforced: bool,
    /// Whether the memory reads succeeded.
    pub mem_read_ok: bool,
    /// Whether the CPU reads succeeded.
    pub cpu_read_ok: bool,
    /// Whether the IO reads succeeded.
    pub io_read_ok: bool,
}

/// The body of `POST /v1/vms/{id}/snapshot` — the artifact-store subdirectory prefix to write under.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotRequest {
    /// A safe single-component name; the snapshot lands under `<artifacts-dir>/<artifact_prefix>/`.
    pub artifact_prefix: String,
}

/// The result of a `POST /v1/vms/{id}/snapshot` — the artifact names the snapshot landed under, so a
/// later `create` can restore by name (design §11.5, The HTTP REST API and its OpenAPI document).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotInfo {
    /// The artifact-store subdirectory prefix the snapshot was written under.
    pub artifact_prefix: String,
    /// The individual artifact names written (config, memory, state, …).
    pub files: Vec<String>,
}

/// A structured error body (design §11.5, The HTTP REST API and its OpenAPI document). `error` is the machine-matchable kind
/// ([`ErrorKind`]); `message` is the human `Display` — never a `Debug` struct-dump.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorBody {
    /// The machine-matchable error kind (snake_case).
    pub error: String,
    /// The human-readable message.
    pub message: String,
}

/// The machine-matchable error kinds carried in [`ErrorBody::error`] and mapped to HTTP status by
/// the server (design §11.5, The HTTP REST API and its OpenAPI document). Kept as a small enum with a stable string form so the client can
/// branch on the same conditions the server names — matchability across the boundary.
///
/// `Serialize`/`Deserialize` are used only by the internal setup-broker `WireError` (postcard over
/// the broker socket, §12.4, Layer 3 — the setup broker (network surface never holds caps)) — not by any JSON response, which carries `kind.as_str()` as a string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ErrorKind {
    /// 404 — no such vm/artifact.
    NotFound,
    /// 409 — create over an existing artifact (the "no update" guard).
    AlreadyExists,
    /// 409 — delete an artifact a live VM pins.
    InUse,
    /// 409 — op against a VM in the wrong state.
    Conflict,
    /// 400 — an artifact name failed validation.
    InvalidName,
    /// 400 — malformed body / knob.
    BadRequest,
    /// 401 — missing/blank bearer credential.
    Unauthorized,
    /// 403 — a present but wrong bearer credential.
    Forbidden,
    /// 501 — an op the backend does not advertise.
    Unsupported,
    /// 413 — upload past the size cap.
    PayloadTooLarge,
    /// 500 — an internal error (wrapped, rendered as its `Display`).
    Internal,
}

impl ErrorKind {
    /// The stable snake_case wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotFound => "not_found",
            Self::AlreadyExists => "already_exists",
            Self::InUse => "in_use",
            Self::Conflict => "conflict",
            Self::InvalidName => "invalid_name",
            Self::BadRequest => "bad_request",
            Self::Unauthorized => "unauthorized",
            Self::Forbidden => "forbidden",
            Self::Unsupported => "unsupported",
            Self::PayloadTooLarge => "payload_too_large",
            Self::Internal => "internal",
        }
    }

    /// The HTTP status code this kind maps to.
    #[must_use]
    pub const fn status_code(self) -> u16 {
        match self {
            Self::NotFound => 404,
            Self::AlreadyExists | Self::InUse | Self::Conflict => 409,
            Self::InvalidName | Self::BadRequest => 400,
            Self::Unauthorized => 401,
            Self::Forbidden => 403,
            Self::Unsupported => 501,
            Self::PayloadTooLarge => 413,
            Self::Internal => 500,
        }
    }

    /// Parses the wire string back to a kind (`None` for an unknown/forged value — the client then
    /// falls back to the status code).
    #[must_use]
    pub fn from_wire(s: &str) -> Option<Self> {
        Some(match s {
            "not_found" => Self::NotFound,
            "already_exists" => Self::AlreadyExists,
            "in_use" => Self::InUse,
            "conflict" => Self::Conflict,
            "invalid_name" => Self::InvalidName,
            "bad_request" => Self::BadRequest,
            "unauthorized" => Self::Unauthorized,
            "forbidden" => Self::Forbidden,
            "unsupported" => Self::Unsupported,
            "payload_too_large" => Self::PayloadTooLarge,
            "internal" => Self::Internal,
            _ => return None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Binary output must survive the round-trip exactly — the data-plane rule. A NUL and a
    // high byte would be mangled by a String/from_utf8_lossy representation.
    #[test]
    fn exec_outcome_roundtrips_binary_exactly() {
        let out = b"\x00\x01\xff\xfehello\n";
        let err = b"oops\xc3\x28"; // invalid UTF-8
        let dto = ExecOutcomeDto::from_bytes(7, out, err);
        assert_eq!(dto.code, 7);
        assert_eq!(dto.stdout().expect("decode"), out);
        assert_eq!(dto.stderr().expect("decode"), err);
    }

    // The kind string form and the status map are 1:1 and stable — a client parses the string, a
    // server maps to status. RED on any drift (a renamed string or a changed code).
    #[test]
    fn error_kind_string_and_status_are_stable() {
        for k in [
            ErrorKind::NotFound,
            ErrorKind::AlreadyExists,
            ErrorKind::InUse,
            ErrorKind::Conflict,
            ErrorKind::InvalidName,
            ErrorKind::BadRequest,
            ErrorKind::Unauthorized,
            ErrorKind::Forbidden,
            ErrorKind::Unsupported,
            ErrorKind::PayloadTooLarge,
            ErrorKind::Internal,
        ] {
            assert_eq!(ErrorKind::from_wire(k.as_str()), Some(k), "roundtrip {k:?}");
        }
        assert_eq!(ErrorKind::AlreadyExists.status_code(), 409);
        assert_eq!(ErrorKind::Unauthorized.status_code(), 401);
        assert_eq!(ErrorKind::Forbidden.status_code(), 403);
        assert_eq!(ErrorKind::from_wire("bogus"), None);
    }

    // Additive compatibility: an older client that omits the new fields still deserializes, and
    // defaults apply (a JSON with only kernel+rootfs boots a default create).
    #[test]
    fn create_request_applies_defaults() {
        let req: CreateVmRequest =
            serde_json::from_str(r#"{"kernel":"k","rootfs":"r"}"#).expect("parse");
        assert_eq!(req.vcpus, 2);
        assert_eq!(req.mem_mib, 512);
        assert_eq!(req.command, None);
        assert!(!req.ephemeral);
        // v22 additive fields default empty (an older client omitting them still parses).
        assert!(req.extra_disks.is_empty());
        assert!(req.extra_kernel_args.is_empty());
    }

    // §11 (The control-plane daemon (vmcelld))/§4.6 (Extra virtio-blk devices and disk-I/O throttling): an extra-disk spec with an io_limit parses, and the io_limit fields
    // default to None (bandwidth-only / iops-only / unlimited all expressible).
    #[test]
    fn extra_disk_spec_parses_with_io_limit() {
        let req: CreateVmRequest = serde_json::from_str(
            r#"{"kernel":"k","rootfs":"r","extra_disks":[
                 {"name":"data.img"},
                 {"name":"slow.img","io_limit":{"bandwidth_bytes_per_sec":1048576}}
               ],"extra_kernel_args":["mitigations=off"]}"#,
        )
        .expect("parse");
        assert_eq!(req.extra_disks.len(), 2);
        assert_eq!(req.extra_disks[0].name, "data.img");
        assert_eq!(req.extra_disks[0].io_limit, None);
        assert_eq!(
            req.extra_disks[1].io_limit,
            Some(DiskIoLimitDto {
                bandwidth_bytes_per_sec: Some(1_048_576),
                iops: None,
            })
        );
        assert_eq!(req.extra_kernel_args, vec!["mitigations=off"]);
    }
}
