//! The request/response wire types (DTOs) — the schema shared by the daemon server and the
//! `vmcell-daemon-client` (design §11.5, The HTTP REST API and its OpenAPI document/§11.7, The client library and CLI). Compiled with **no** feature gate so a request the
//! client serializes and the server deserializes are the SAME Rust type — the wire schema is
//! single-sourced (invariant: one law, one predicate for the schema).
//!
//! Additive/optional fields carry `#[serde(default)]`, so an older client that omits them and a
//! newer server (or vice versa) stay compatible additively — the `#[non_exhaustive]`-in-spirit rule
//! for a JSON API. The genuinely required inputs (`kernel`/`rootfs`, `argv`) are **not** defaulted:
//! omitting them is a parse error, never a silent default.

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
/// label — `Ready` means the steward handshake succeeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VmState {
    /// Booting; the steward has not yet handshaked.
    Booting,
    /// Booted and steward-ready — accepts `exec`.
    Ready,
    /// Paused (vCPUs stopped) via `POST /v1/vms/{id}/pause`; every host resource is still held, so
    /// the VM still pins its artifacts. `exec`, `snapshot` and a second `pause` are refused with a
    /// 409 until `POST /v1/vms/{id}/resume`; `destroy` and `stats` still work.
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

/// What the artifact store is holding, and against what ceiling (`GET /v1/store`, design §11.3, The
/// artifact store; §17, Open gaps and future capabilities).
///
/// Exists so the quota is **observable** rather than only enforceable: without it a client's first
/// news of a full store is a 413 on an upload it already started. `quota_bytes` is a plain `Option`
/// with **no** `skip_serializing_if`, so `null` is always on the wire — deliberately not a presence
/// attribute, which is the DTO shape that has bitten this project before (Appendix A reversal 10);
/// there is nothing here for a non-self-describing codec to collapse.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoreUsage {
    /// Bytes on disk under the artifacts directory — artifacts, digest sidecars, snapshot prefixes
    /// and any residue alike, because that is what the quota bounds.
    pub used_bytes: u64,
    /// The configured whole-store quota, or `null` when the store is unbounded.
    pub quota_bytes: Option<u64>,
    /// How many listable artifacts the store holds (sidecars and residue excluded).
    pub artifact_count: u64,
    /// How many snapshot prefix directories the store holds.
    pub snapshot_prefix_count: u64,
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

/// Where a created VM's steward runs (design §3.5, Guest placement: PID 1 or a service/§11.5, The HTTP REST API and its OpenAPI document; §18 delta 10).
///
/// The daemon-side **mirror** of `vmcell::config::StewardPlacement`, declared here rather than
/// derived on the library type for two reasons. `vmcell::config` carries no `Serialize` at all —
/// deliberately, so the library's configuration surface is not also a wire schema — and this module
/// is compiled **without** the `server` feature for `vmcell-daemon-client`, which does not link
/// `vmcell` at all. So the wire form lives here and converts at the launcher, exactly as [`NetMode`]
/// does.
///
/// Deliberately **not** `Default`: "the client named no placement" is [`CreateVmRequest`]'s
/// `Option::None`, and resolving that is the registry's one job (it is where an undeclared placement
/// beside a custom `init` is refused). A `Default` here would make `unwrap_or_default()` look
/// correct at a call site that must not exist.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StewardPlacementDto {
    /// The kernel starts the steward as PID 1 (`"pid1"`) — the daemon's behavior before v33, now
    /// sayable. Cannot be combined with [`CreateVmRequest::init`]: the kernel cannot start the
    /// steward as PID 1 if `init=` names something else (the library refuses the pair, 400).
    Pid1,
    /// The guest's own init starts the steward and the daemon dials `port`
    /// (`{"service":{"port":5100}}`). This is what makes a custom [`CreateVmRequest::init`] — a
    /// distro image, systemd, another init system — expressible over REST at all: the vsock control
    /// plane the daemon owns its VMs through survives it.
    Service {
        /// The vsock port the guest's steward listens on (5000 is the default the guest binds when
        /// no `vmcell_steward_port=` token is emitted). `0` and `u32::MAX` are reserved by AF_VSOCK
        /// and refused fail-loud at config build (400).
        port: u32,
    },
    /// No steward anywhere (`"none"`).
    ///
    /// Representable **so that it can be refused by name**: the daemon owns every VM it creates
    /// through the vsock control plane, so this is the one placement REST does not express (design
    /// §5.3, The kernel command line — the surviving half of the pre-v33 "no `init=` over REST"
    /// rule). Refused 400 by the registry; use the `vmcell` library directly for a stewardless VM.
    None,
}

impl StewardPlacementDto {
    /// Whether this placement keeps the vsock control plane the daemon owns its VMs through — the
    /// **one** predicate the daemon's REST placement rule is written in terms of (design §11.5, The
    /// HTTP REST API and its OpenAPI document).
    ///
    /// It is C8's availability question (`StewardPlacement::steward_port().is_some()`) asked on this
    /// side of the wire; `the_rest_placement_law_matches_c8_availability_variant_for_variant` in
    /// `launcher.rs` pins the two together variant-for-variant, because only that module links
    /// `vmcell`.
    #[must_use]
    pub const fn control_plane_retained(self) -> bool {
        !matches!(self, Self::None)
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
    /// `create` semantics: boot to steward-ready and register.
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
    /// override a boot token vmcell owns — rejected fail-loud at build. `init=` is one of those
    /// owned tokens: state it in the dedicated [`init`](Self::init) field, which carries the
    /// placement the daemon needs beside it.
    #[serde(default)]
    pub extra_kernel_args: Vec<String>,
    /// Guest path of a custom `init=` — **init identity only** (design §3.5, Guest placement: PID 1
    /// or a service; §5.3, The kernel command line; §18 delta 10).
    ///
    /// Absent ⇒ the vmcell steward is PID 1, the pre-v33 shape. Present ⇒ the named binary is PID 1
    /// instead, and [`steward_placement`](Self::steward_placement) must say where the steward runs:
    /// the daemon owns every VM it creates through the vsock control plane and will not guess. It
    /// pairs with [`StewardPlacementDto::Service`]; with [`StewardPlacementDto::Pid1`] it is the one
    /// contradictory pair the library refuses (400).
    ///
    /// A guest path, **not** an artifact name: it names a binary inside the rootfs image, so it is
    /// not resolved against the store. The library validates it as a single safe cmdline token.
    ///
    /// This field is what scoped the pre-v33 "no `init=` over REST" rule. Its rationale — the daemon
    /// could not `exec` or `stats` a VM whose init replaced the steward — is repaired by `Service`
    /// placement, and survives only as [`StewardPlacementDto::None`]'s refusal.
    #[serde(default)]
    pub init: Option<String>,
    /// Where this VM's steward runs (design §3.5, Guest placement: PID 1 or a service; §18 delta 10).
    ///
    /// Absent ⇒ [`StewardPlacementDto::Pid1`] when no [`init`](Self::init) is named (the pre-v33
    /// default, byte-identical), and a **400** when one is: the daemon refuses to guess a placement
    /// for a custom init, because the library's own derivation would answer
    /// `StewardPlacement::None` — the one placement REST does not express.
    #[serde(default)]
    pub steward_placement: Option<StewardPlacementDto>,
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
            init: None,
            steward_placement: None,
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

    /// Declares a custom guest `init=` **and** where the steward runs beside it (builder-style,
    /// design §18 delta 10).
    ///
    /// The two are set together on purpose: a custom init with no declared placement is a 400, so a
    /// setter that took only the init would build a request that cannot succeed.
    #[must_use]
    pub fn with_service_init(
        mut self,
        init: impl Into<String>,
        placement: StewardPlacementDto,
    ) -> Self {
        self.init = Some(init.into());
        self.steward_placement = Some(placement);
        self
    }

    /// Declares the steward placement without a custom init (builder-style).
    ///
    /// `Pid1` restates the default; `Service { port }` with no `init` is the library's deliberately
    /// legal combination (the steward is still PID 1, the host just treats it as a service).
    #[must_use]
    pub fn with_steward_placement(mut self, placement: StewardPlacementDto) -> Self {
        self.steward_placement = Some(placement);
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

/// Declares [`ErrorKind`] **and** everything derived from it — the roster [`ErrorKind::ALL`] the
/// served OpenAPI schema is generated from, the stable wire strings, and the HTTP status map — from
/// one per-variant row.
///
/// This macro is the mechanism, not sugar. A hand-written `ALL` beside a hand-written enum is a
/// second literal list nothing forces complete: a 12th kind added to the enum alone compiled clean
/// and shipped absent from the served `ErrorBody.error` enum (an exhaustive `match` in a test
/// forces the *match arm*, never the roster; a `len()` assert cannot see what was never added).
/// Here a variant cannot exist without its wire string and status, so it cannot exist outside `ALL`
/// — and writing a bare `RateLimited,` row is a macro-expansion (compile) error.
macro_rules! error_kinds {
    ($( $(#[$meta:meta])* $variant:ident => $wire:literal, $status:literal; )+) => {
        /// The machine-matchable error kinds carried in [`ErrorBody::error`] and mapped to HTTP
        /// status by the server (design §11.5, The HTTP REST API and its OpenAPI document). Kept as
        /// a small enum with a stable string form so the client can branch on the same conditions
        /// the server names — matchability across the boundary.
        ///
        /// Declared through the `error_kinds!` macro together with [`ErrorKind::ALL`], so a kind
        /// cannot ship undocumented.
        ///
        /// `Serialize`/`Deserialize` are used only by the internal setup-broker `WireError` (JSON
        /// over the broker socket, §12.4, Layer 3 — the setup broker (network surface never holds
        /// caps)) — not by any JSON response, which carries `kind.as_str()` as a string.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
        pub enum ErrorKind {
            $( $(#[$meta])* $variant, )+
        }

        impl ErrorKind {
            /// Every kind, in declaration order — the single roster, expanded from the same rows as
            /// the enum itself, so it structurally cannot omit a variant. The served OpenAPI
            /// document generates the `ErrorBody.error` enum from this (design §11.5).
            pub const ALL: &'static [Self] = &[ $( Self::$variant, )+ ];

            /// The stable snake_case wire string.
            #[must_use]
            pub const fn as_str(self) -> &'static str {
                match self { $( Self::$variant => $wire, )+ }
            }

            /// The HTTP status code this kind maps to.
            #[must_use]
            pub const fn status_code(self) -> u16 {
                match self { $( Self::$variant => $status, )+ }
            }
        }
    };
}

error_kinds! {
    /// 404 — no such vm/artifact.
    NotFound => "not_found", 404;
    /// 409 — create over an existing artifact (the "no update" guard).
    AlreadyExists => "already_exists", 409;
    /// 409 — delete an artifact a live VM pins.
    InUse => "in_use", 409;
    /// 409 — op against a VM in the wrong state.
    Conflict => "conflict", 409;
    /// 400 — an artifact name failed validation.
    InvalidName => "invalid_name", 400;
    /// 400 — malformed body / knob.
    BadRequest => "bad_request", 400;
    /// 401 — missing/blank bearer credential.
    Unauthorized => "unauthorized", 401;
    /// 403 — a present but wrong bearer credential.
    Forbidden => "forbidden", 403;
    /// 501 — an op the backend does not advertise.
    Unsupported => "unsupported", 501;
    /// 413 — upload past the size cap.
    PayloadTooLarge => "payload_too_large", 413;
    /// 500 — an internal error (wrapped, rendered as its `Display`).
    Internal => "internal", 500;
}

impl ErrorKind {
    /// Parses the wire string back to a kind (`None` for an unknown/forged value — the client then
    /// falls back to the status code).
    ///
    /// Resolved by scanning [`ErrorKind::ALL`] through [`ErrorKind::as_str`] rather than a second
    /// string table: the former hand-written `match` ended in `_ => None`, which turned a kind with
    /// no arm into a silent "unknown" instead of a compile error.
    #[must_use]
    pub fn from_wire(s: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|k| k.as_str() == s)
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
    // server maps to status. RED on any drift (a renamed string or a changed code). Driven off
    // `ErrorKind::ALL`, the roster the OpenAPI schema is generated from.
    //
    // Roster COMPLETENESS is not this test's job and never could be: it is the `error_kinds!` macro
    // that owns it, by expanding the enum and `ALL` from the same rows (an exhaustive `match` here
    // would only force a match arm — a 12th kind absent from `ALL` still compiled and shipped
    // undocumented). The `len()` assert below is the *deliberate-change* tripwire: a roster edit is
    // a contract event and must be acknowledged, not slipped in.
    #[test]
    fn error_kind_string_and_status_are_stable() {
        for k in ErrorKind::ALL.iter().copied() {
            assert_eq!(ErrorKind::from_wire(k.as_str()), Some(k), "roundtrip {k:?}");
        }
        assert_eq!(
            ErrorKind::ALL.len(),
            11,
            "the roster the OpenAPI error schema is generated from"
        );
        assert_eq!(ErrorKind::AlreadyExists.status_code(), 409);
        assert_eq!(ErrorKind::Unauthorized.status_code(), 401);
        assert_eq!(ErrorKind::Forbidden.status_code(), 403);
        assert_eq!(ErrorKind::from_wire("bogus"), None);
    }

    // The snapshot-eligibility predicate itself (finding T5: a repo-wide grep found the definition
    // and one call site, and no test anywhere). `Unprivileged` is the one mode that attaches a
    // vhost-user device, which is what the eligibility law is about (§8.1) — the wire spelling is
    // asserted beside it, because that string is what a client actually types.
    //
    // Roster completeness is not this test's job (see the `ErrorKind::ALL` note above — an array
    // literal cannot force a new variant into itself); what it holds is that every mode in the
    // roster has a STATED expectation, so flipping the predicate reddens. RED on the inverse: drop
    // the `!` in `snapshot_eligible`, or widen it to `Privileged`.
    #[test]
    fn snapshot_eligible_is_exactly_the_net_modes_with_no_vhost_user_device() {
        for (net, wire) in [
            (NetMode::None, "none"),
            (NetMode::Privileged, "privileged"),
            (NetMode::Unprivileged, "unprivileged"),
        ] {
            let want = match net {
                // No device at all / a tap the VMM owns: nothing vhost-user in the config.
                NetMode::None | NetMode::Privileged => true,
                // The in-process smoltcp NAT IS a vhost-user-net device.
                NetMode::Unprivileged => false,
            };
            assert_eq!(net.snapshot_eligible(), want, "{net:?}");
            assert_eq!(
                serde_json::to_value(net).expect("encode"),
                serde_json::Value::String(wire.to_string()),
                "the wire spelling a client types"
            );
        }
        assert_eq!(NetMode::default(), NetMode::None, "the default is eligible");
    }

    // `StoreUsage`'s `quota_bytes` is an `Option` WITHOUT `skip_serializing_if`, so it is not a
    // presence attribute at all: `null` is always on the wire and both codecs see the same shape.
    // Both inhabitants round-trip, and the unbounded one is asserted to SERIALIZE the key rather
    // than omit it — an omitted key is the shape that decodes identically here and differently on a
    // non-self-describing codec (Appendix A reversal 10).
    //
    // RED on the inverse: add `#[serde(skip_serializing_if = "Option::is_none")]` to `quota_bytes`
    // and the "quota_bytes" containment check fails on the unbounded leg.
    #[test]
    fn store_usage_round_trips_with_and_without_a_quota() {
        for usage in [
            StoreUsage {
                used_bytes: 4096,
                quota_bytes: Some(1 << 30),
                artifact_count: 3,
                snapshot_prefix_count: 1,
            },
            StoreUsage {
                used_bytes: 0,
                quota_bytes: None,
                artifact_count: 0,
                snapshot_prefix_count: 0,
            },
        ] {
            let json = serde_json::to_string(&usage).expect("encode");
            assert!(
                json.contains("quota_bytes"),
                "the key is always on the wire, even unbounded: {json}"
            );
            let back: StoreUsage = serde_json::from_str(&json).expect("decode");
            assert_eq!(back, usage);
        }
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
        // v33 delta 10's additive fields: absent means "the daemon's pre-v33 shape" — no custom
        // init, no declared placement. This assertion IS the migration note's "old clients
        // unchanged" claim; without it the claim is only prose.
        assert_eq!(req.init, None);
        assert_eq!(req.steward_placement, None);
        assert_eq!(req, CreateVmRequest::create("k", "r"));
    }

    // §18 delta 10 / Appendix A reversal 10 — the presence-attribute codec rule's NAMED test: the
    // new fields ride the same JSON the bridge and the HTTP API speak, and JSON is chosen precisely
    // because a non-self-describing codec collapses `#[serde(default)]` presence.
    //
    // The legs are populated ASYMMETRICALLY on purpose (one field `Some`, its sibling `None`, then
    // swapped): a codec or a constructor that drops presence in one direction is invisible to a
    // both-`Some` fixture, and a both-`None` fixture is the pre-delta state. The comparison is
    // field-for-field on the whole value (`PartialEq`), never a byte compare — a field dropped on
    // the first encode is dropped identically on the second, so bytes stay green while the value
    // silently changed (the trap `fuzz_targets/daemon_bridge_frame.rs` documents).
    //
    // RED on the inverse (run, observed): give either field `#[serde(default, skip_serializing)]`
    // instead of `#[serde(default)]` — the presence attribute then collapses in exactly one
    // direction and the first leg fails with `steward_placement: Some(Service { port: 5100 })` sent
    // and `None` decoded back. That is the postcard-class defect, reproduced on JSON.
    #[test]
    fn placement_fields_round_trip_over_json_with_asymmetric_presence() {
        let legs = [
            // init named, placement named: the delta's whole point.
            CreateVmRequest::create("vmlinux", "rootfs.erofs").with_service_init(
                "/vmcell-tools/mini-init",
                StewardPlacementDto::Service { port: 5100 },
            ),
            // placement `Some`, init `None` — the deliberately legal library combination.
            CreateVmRequest::create("vmlinux", "rootfs.erofs")
                .with_steward_placement(StewardPlacementDto::Service { port: 5000 }),
            // placement `Some` unit variants, init `None`.
            CreateVmRequest::create("vmlinux", "rootfs.erofs")
                .with_steward_placement(StewardPlacementDto::Pid1),
            // the refusable one still has to survive the codec to BE refused with its own name.
            CreateVmRequest::create("vmlinux", "rootfs.erofs")
                .with_steward_placement(StewardPlacementDto::None),
            // init `Some`, placement `None` — the shape the registry refuses; it must reach the
            // registry intact to be refused, so the codec has to carry it.
            CreateVmRequest {
                init: Some("/sbin/init".to_string()),
                ..CreateVmRequest::create("vmlinux", "rootfs.erofs")
            },
            // both absent: the old client.
            CreateVmRequest::create("vmlinux", "rootfs.erofs"),
        ];
        for sent in legs {
            let json = serde_json::to_string(&sent).expect("encode");
            let back: CreateVmRequest = serde_json::from_str(&json).expect("decode");
            assert_eq!(
                back, sent,
                "CreateVmRequest did not round-trip over JSON: {json}"
            );
        }

        // The wire spellings themselves, pinned: a client (or a curl) writes these by hand, so a
        // silent rename of a variant is a breaking wire change even though the Rust round-trip
        // above would stay green through it.
        let by_hand: CreateVmRequest = serde_json::from_str(
            r#"{"kernel":"k","rootfs":"r","init":"/vmcell-tools/mini-init",
                "steward_placement":{"service":{"port":5100}}}"#,
        )
        .expect("parse a hand-written service placement");
        assert_eq!(by_hand.init.as_deref(), Some("/vmcell-tools/mini-init"));
        assert_eq!(
            by_hand.steward_placement,
            Some(StewardPlacementDto::Service { port: 5100 })
        );
        for (text, want) in [
            (r#""pid1""#, StewardPlacementDto::Pid1),
            (r#""none""#, StewardPlacementDto::None),
        ] {
            let p: StewardPlacementDto = serde_json::from_str(text).expect("parse unit variant");
            assert_eq!(p, want, "wire spelling {text}");
            assert_eq!(serde_json::to_string(&want).expect("encode"), text);
        }
    }

    // The daemon's REST placement law, stated once (`control_plane_retained`) and driven over every
    // variant. Its parity with C8's `steward_port()` is pinned in `launcher.rs` (only that module
    // links `vmcell`); this half pins the rule itself, KVM-free and feature-free.
    //
    // RED on the inverse: make `control_plane_retained` return `true` for `None`.
    #[test]
    fn only_a_stewardless_placement_loses_the_control_plane() {
        assert!(StewardPlacementDto::Pid1.control_plane_retained());
        assert!(StewardPlacementDto::Service { port: 5000 }.control_plane_retained());
        assert!(StewardPlacementDto::Service { port: 5100 }.control_plane_retained());
        assert!(
            !StewardPlacementDto::None.control_plane_retained(),
            "`none` is the one placement the daemon cannot own a VM through"
        );
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
