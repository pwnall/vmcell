//! crosvm VMM backend for `vmcell`.
//!
//! Provides the [`Crosvm`] implementation of the [`vmcell::vmm::Vmm`] trait and its running-instance
//! type [`CrosvmInstance`]. crosvm is the ChromeOS Rust VMM; like Firecracker and QEMU it is a
//! secondary backend living outside the `vmcell` core (which carries only the primary Cloud
//! Hypervisor). This crate depends on `vmcell` for the shared `Vmm`/`VmInstance` traits, the
//! jail/seccomp predicates (crosvm routes its sandbox posture through `vmm_seccomp_args`), and the
//! spawn/reap/console/snapshot-eligibility helpers — every "one law, one predicate" invariant stays
//! single-sourced in `vmcell`.
//!
//! **Structure.** crosvm is driven like QEMU (a device model built on the launch command line),
//! not like Firecracker (a post-spawn REST sequence). Two differences from QEMU: (1) its control
//! plane is a side socket driven **out-of-band by re-invoking the crosvm binary as a client**
//! (`crosvm resume|suspend|powerbtn|stop <socket>`) — the socket protocol is unstable binary and is
//! never hand-rolled, so this crate needs no serde/JSON; (2) its vsock is the in-kernel vhost-vsock
//! device exposed on the host AF_VSOCK namespace (like a snapshot-eligible QEMU), so
//! [`CrosvmInstance::vsock_endpoint`] returns the [`VsockEndpoint::Vsock`] `steward_endpoint`
//! composed at spawn and there is no external vsock daemon to own.
//!
//! **Scope (validated live on a KVM host).** Boot, tap networking, block devices, in-kernel vsock,
//! sessions, and **snapshot/restore** are the shipped, matrix-validated data path. snapshot/restore
//! follows the **Firecracker** pattern, not QEMU's: crosvm bakes the vsock CID into the snapshot and
//! rejects a rotated `--vsock cid=` on restore, so `restore()` reuses the baked CID (carried in a
//! sidecar) and `restore_rotates_host_paths` is **false** — sequential lineage works, concurrent
//! fan-out from one snapshot does not. virtio-fs shares and unprivileged vhost-user-net stay
//! honest-**false** (unvalidated); each self-skips its matrix leg via `require_cap!`. See
//! `docs/implementation-notes.md` (crosvm reconciliation) for the remaining open items.

#![deny(missing_docs)]
#![deny(unreachable_pub)] // pub-in-private-module API-surface honesty
#![deny(
    clippy::undocumented_unsafe_blocks,
    clippy::missing_safety_doc,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::multiple_unsafe_ops_per_block, // one obligation per SAFETY comment
    unsafe_op_in_unsafe_fn,
    rustdoc::broken_intra_doc_links
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
use std::process::Stdio;
use std::time::Duration;
use vmcell::config::{ConsoleMode, VmConfig};
use vmcell::error::{Error, Result};
// The v33 feature vocabulary (design §7.4, invariant F6). A refusal's feature string is
// `Feature::name()` BY CONSTRUCTION here, and `VHOST_USER_BLOCKS_SNAPSHOT` is the ONE spelling of
// the S1 refusal across all four backends — the four had drifted into four different prose strings,
// which is what bred `feature.contains("vhost-user")` in three test suites.
use vmcell::feature::{Feature, VHOST_USER_BLOCKS_SNAPSHOT};
use vmcell::vmm::{PerVmResources, VmInstance, Vmm, VmmCapabilities, VsockEndpoint};

use tokio::process::Child;

/// The wall-clock budget bounding **every** crosvm control-client invocation — the one named
/// lifecycle bound this backend has (M5).
///
/// crosvm's control plane is a short-lived client process per operation (`crosvm resume|suspend|
/// powerbtn|stop <socket>`, `crosvm snapshot take …`), and a wedged VMM leaves that client blocked
/// on the socket forever: `run_control` and `snapshot_take` used to be a bare `status().await`, so
/// `boot()`, `request_shutdown()`, `pause()`, `resume()` and `snapshot()` were unbounded. The
/// damage is not just a hung call — `shutdown()` awaits `request_shutdown()` **before** the ORCH-7
/// grace poll and before the guaranteed `kill()` fallback, so one wedged `powerbtn` blocked the
/// force-kill that is supposed to be unconditional and the VM's netns/tap/cgroup/scratch/vmid were
/// never reclaimed. Every sibling backend bounds this class (CH/FC's 5 s `REQUEST_TIMEOUT`, QEMU's
/// 2 s control timeout + `MIGRATION_BUDGET`); this is crosvm's.
///
/// **Sizing.** Deliberately larger than CH/FC's generic 5 s ceiling because two crosvm control ops
/// do guest-RAM work: `snapshot take` writes the suspend image (≈268 MB for a 256 MiB guest, design
/// §16), and the first `resume --full` after `--restore` waits for that image to load. 10 s clears
/// both with margin on any real disk while keeping teardown prompt — `kill()`'s graceful `stop` is
/// bounded by this same budget (it carries no second literal of its own), so a wedged VM's forced
/// teardown is bounded by it too. The budget exists to convert an infinite wedge into a typed
/// [`Error::Timeout`], not to enforce a latency SLA; a guest-RAM-proportional snapshot budget is
/// the (cross-backend) M6-class follow-up.
///
/// Read once by [`Crosvm::new`] into [`Crosvm`]'s `control_budget`, which every instance inherits at
/// spawn — a field rather than a bare const read at the call sites so the KVM-free wedged-client
/// gate can shrink it and prove the bound end-to-end through the real `create()` path (the shape
/// `vmcell-qemu`'s migration-budget gate uses).
const CROSVM_CONTROL_BUDGET: Duration = Duration::from_secs(10);

/// The crosvm VMM backend.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Crosvm {
    /// Path to the `crosvm` executable (used both to launch the VM and, re-invoked as a client,
    /// to drive the control socket).
    pub binary_path: PathBuf,
    // The budget every control-client invocation of this backend's instances is bounded by,
    // seeded from `CROSVM_CONTROL_BUDGET` (the one named value — never a second literal at a call
    // site). Private: it is backend policy, not caller configuration; it is a field only so the
    // KVM-free gate can shrink it.
    control_budget: Duration,
}

impl Crosvm {
    /// Creates a new `Crosvm` using the specified executable path.
    #[must_use]
    pub fn new(binary_path: impl Into<PathBuf>) -> Self {
        Self {
            binary_path: binary_path.into(),
            control_budget: CROSVM_CONTROL_BUDGET,
        }
    }
}

/// A running instance of a crosvm VM.
#[derive(Debug)]
#[non_exhaustive]
pub struct CrosvmInstance {
    process: Child,
    /// The `crosvm` binary, re-invoked as a client for every control operation.
    binary_path: PathBuf,
    // The wall-clock bound on every control-client invocation this instance makes, inherited from
    // the backend at spawn (`CROSVM_CONTROL_BUDGET`). One value for `run_control` AND
    // `snapshot_take`, so no control op is unbounded and none carries its own literal (M5).
    control_budget: Duration,
    // The wall-clock bound on the guest-RAM-proportional `crosvm snapshot take` (M6): the larger
    // of `control_budget` and the ONE shared `vmcell::vmm::snapshot_request_timeout(mem_mib)`,
    // computed once at spawn. Ordinary control ops deliberately keep `control_budget` — a wedged
    // `powerbtn` must stay promptly bounded, since `shutdown()` awaits it BEFORE the guaranteed
    // `kill()`. A field, like `control_budget`, only so the KVM-free gates can shrink it.
    snapshot_budget: Duration,
    control_socket: PathBuf,
    /// Vestigial AF_UNIX path returned by [`VmInstance::vsock_path`] for API parity; crosvm's vsock
    /// is in-kernel AF_VSOCK, so [`CrosvmInstance::vsock_endpoint`] is what the host actually dials.
    vsock_path: PathBuf,
    serial_path: PathBuf,
    cid: u32,
    // The VMM leader's process group AND the one-shot "already reaped" flag, owned together by the
    // one shared helper (`vmcell::vmm::VmmProcessGroup`, L1): `kill`, `has_exited` and `Drop` all
    // route through it, so no copy can forget the M-VMM-1 guard and SIGKILL a pgid the kernel has
    // since recycled.
    group: vmcell::vmm::VmmProcessGroup,
    // `true` on an instance returned by `restore()`: the VM was launched `--suspended --restore`, so
    // the FIRST `resume()` must be `--full` (wake devices + vCPUs) to complete the restore. Consumed
    // (set false) only after that resume succeeds, so a transient failure stays retryable.
    restored: bool,
    // `config_has_vhost_user_device(cfg, res)` recorded at spawn — the S1 snapshot-eligibility guard
    // `snapshot()` reads. Always false for a crosvm VM (create() rejects shares/unpriv-net), but kept
    // as defense-in-depth so a future config path can't slip an ineligible VM past `snapshot()`.
    has_vhost_user_device: bool,
    // Whether the backend advertises snapshot/restore, captured from `capabilities()` at spawn so
    // `snapshot()` can self-guard without a handle to the backend (M-RESTORE-3, the CH shape).
    snapshot_restore_capable: bool,
    // How the host reaches this VM's steward, composed ONCE at spawn by `steward_endpoint` from the
    // config's own placement — so the port an instance reports is the DECLARED one and no reader has
    // to re-derive it. A field, like `cid`, because `vsock_endpoint()` is handed no config.
    endpoint: VsockEndpoint,
}

/// How the host reaches this VM's steward: the **transport** (crosvm's vsock is the in-kernel
/// vhost-vsock device on every path, so the guest is always addressed by CID on the host AF_VSOCK
/// namespace — never the AF_UNIX hybrid the trait defaults to) and — law C8's FIRST question — the
/// **port**, which is [`StewardPlacement::steward_port`](vmcell::config::StewardPlacement::steward_port).
///
/// The port used to be the hardcoded protocol default here. That is not a live defect on this
/// backend — `MicroVm::steward`/`connect_sessions` re-key the port per call (`with_port`), and
/// `verify_control_plane` is the trait-default no-op for crosvm because its vsock terminates inside
/// the VMM process — but it is M1's shape sitting in wait: it was exactly this spelling that, on the
/// one backend which *does* probe the endpoint verbatim (QEMU on the external-daemon transport),
/// dialed 5000 at a `Service { port: 5100 }` guest and re-spawned a healthy cell to exhaustion. An
/// instance that reports a port its cell never declared is a wrong answer whether or not today's
/// callers happen to overwrite it, so it is composed from the declaration.
///
/// [`StewardPlacement::None`](vmcell::config::StewardPlacement::None) has no steward and never
/// reaches a dial (the orchestrator keys every control-plane path on `steward_port().is_some()`), so
/// the protocol default stands in as an unused placeholder there — not as a silent fallback for a
/// declared port, of which there is none.
fn steward_endpoint(cid: u32, placement: vmcell::config::StewardPlacement) -> VsockEndpoint {
    VsockEndpoint::Vsock {
        cid,
        port: placement
            .steward_port()
            .unwrap_or(vmcell::vmm::STEWARD_VSOCK_PORT),
    }
}

/// Pre-flight self-checks for the [`CrosvmInstance::snapshot`] path.
///
/// `snapshot()` runs on the instance, which has no handle to the backend, so the `snapshot_restore`
/// capability is captured at spawn and re-checked here (M-RESTORE-3) alongside the
/// snapshot-eligibility law: a VM carrying a vhost-user device cannot be snapshotted. Factored as a
/// free function — the same shape Cloud Hypervisor ships (`snapshot_precheck`), not a second idiom —
/// so a KVM-free test can drive the false branch a live matrix can never reach (crosvm's descriptor
/// is `snapshot_restore: true`).
///
/// # Errors
/// Returns [`Error::Unsupported`] if the backend does not advertise `snapshot_restore`, or if the VM
/// has a vhost-user device attached.
fn snapshot_precheck(snapshot_restore_capable: bool, has_vhost_user: bool) -> Result<()> {
    if !snapshot_restore_capable {
        // The backend itself is the remover: the bare capability refusal, no provenance to carry,
        // rendering byte-identical to the pre-v33 literal.
        return Err(Error::unsupported("crosvm", Feature::SnapshotRestore));
    }
    if has_vhost_user {
        // The CONFIG is the remover here, so the "why" travels in the shared `Removal` instead of
        // decorating the feature string — a decorated string is a string a test then matches a
        // fragment of (F6). `restore()` returns this very same const.
        return Err(Error::from_removal("crosvm", &VHOST_USER_BLOCKS_SNAPSHOT));
    }
    Ok(())
}

/// Refuses a per-disk `io_limit`: crosvm's `--block` has no bandwidth/iops key (capability
/// `disk_io_throttle` is honest-false), so a throttled disk would otherwise be attached
/// **unthrottled** — an accepted input silently dropped.
///
/// One predicate shared by `create()` **and** `restore()`. M4: `restore()` used to accept exactly
/// what `create()` rejects (the restore run args are built by the same `build_crosvm_run_args`,
/// which has nowhere to put the limit), so a snapshot lineage could be restored with the throttle
/// quietly gone. The feature string matches the `VmmCapabilities` field name (N-VMM-1) — by
/// construction now, since [`Error::unsupported`] composes it from [`Feature::name`] and the
/// vocabulary is parity-gated against the descriptor's fields in both directions (F6).
///
/// # Errors
/// Returns [`Error::Unsupported`] if any extra disk carries an `io_limit`.
fn reject_disk_io_throttle(cfg: &VmConfig) -> Result<()> {
    if cfg.extra_disks.iter().any(|d| d.io_limit.is_some()) {
        return Err(Error::unsupported("crosvm", Feature::DiskIoThrottle));
    }
    Ok(())
}

/// Refuses the two config levers crosvm advertises as **false** and would otherwise accept and
/// silently degrade (d7).
///
/// §2.1's contract is that every backend self-checks its own descriptor instead of assuming the
/// caller consulted it, and three sibling fields (`virtio_console`, `disk_io_throttle`,
/// `usb_host_passthrough`) already do. These two did not:
///
/// - `nested_virt` — crosvm documents no working guest `/dev/kvm`, yet the SHARED
///   [`vmcell::config::build_kernel_cmdline`] emits `kvm-intel.nested=1` for **every** backend on
///   `cfg.nested_virt`, so an accepted request boots a guest whose L1 `/dev/kvm` never appears: the
///   lever reads as applied and is not.
/// - `lazy_restore` — no userfaultfd/demand-paged restore backend is wired (`restore()` loads the
///   snapshot eagerly via `crosvm run --restore`), so
///   [`RestoreMode::Lazy`](vmcell::config::RestoreMode::Lazy) would fault eagerly under a config
///   that asked for demand paging.
///
/// Both branches live in the **one** shared predicate
/// [`vmcell::vmm::reject_unadvertised_capabilities`], which keys off the
/// [`crosvm_capabilities`] value handed in — never a hardcoded `false` at the refusal site — so
/// flipping a flag flips its refusal with it, and each feature string IS the
/// [`VmmCapabilities`] field name (N-VMM-1). This wrapper exists only to bind the `"crosvm"`
/// name once; it landed as three byte-identical per-backend copies and was hoisted.
///
/// Called from `create()` **and** `restore()`, exactly like [`reject_disk_io_throttle`] (M4): a
/// `restore()` that accepted what `create()` rejects is the same defect one path over, and
/// `restore_mode` is precisely the field a restore consumes.
///
/// # Errors
/// [`Error::Unsupported`] `{ vmm: "crosvm", feature }` naming the unadvertised capability.
fn reject_unadvertised_capabilities(caps: &VmmCapabilities, cfg: &VmConfig) -> Result<()> {
    vmcell::vmm::reject_unadvertised_capabilities("crosvm", caps, cfg)
}

/// The [`JailConfig`](vmcell::config::JailConfig) actually handed to
/// [`apply_jail`](vmcell::vmm::jail::apply_jail) for a crosvm launch — the pure, total mapping from
/// the requested `(cfg.jail, cfg.vmm_seccomp)` pair to the Layer-2 posture that ships.
///
/// Sandbox posture (§12.2, validated live): crosvm ALWAYS runs `--disable-sandbox` (from
/// `vmm_seccomp_args`) because its own multiprocess minijail (`pivot_root` into `/var/empty` +
/// per-device child forking) is incompatible with the single-process supervision model. The Layer-2
/// jailer deny-list is therefore crosvm's **only** seccomp confinement, so `Enforcing` turns it ON
/// no matter what `cfg.jail` asked for (the backend is NEVER unconfined by default — the seccomp.rs
/// invariant), and `Disabled` — the loud opt-out — leaves `cfg.jail.seccomp_deny_list` exactly as
/// configured (it never forces the deny-list *off*, so an operator who asked for Layer 2 keeps it).
/// `Log` never reaches here: `vmm_seccomp_args` typed-refuses it for crosvm first.
///
/// Pure (a `Copy` in, a `Copy` out) so a KVM-free test can pin BOTH directions. M10: this flip lived
/// inline in `spawn` and deleting it left every KVM-free gate *and* the whole live `test-crosvm`
/// matrix green while crosvm ran with no seccomp filter at all. M11: its one caller is now
/// [`crosvm_launch_plan`], so *which* posture `spawn` ships is a returned value under gate too — a
/// test on this function alone was never a gate on the call.
fn effective_jail_config(cfg: &VmConfig) -> vmcell::config::JailConfig {
    let mut jail = cfg.jail; // JailConfig is Copy
    if matches!(cfg.vmm_seccomp, vmcell::config::VmmSeccomp::Enforcing) {
        jail.seccomp_deny_list = true;
    }
    jail
}

/// The crosvm snapshot artifact inside the caller's snapshot dir (`crosvm snapshot take <path>`).
/// A distinct basename so it never collides with the sidecars a caller writes into the same dir.
const SNAPSHOT_FILE: &str = "crosvm-snapshot";

/// Sidecar recording the guest vsock CID baked into the snapshot. crosvm bakes the CID into the
/// vsock device state and rejects a mismatched `--vsock cid=` on restore ("Virtio vsock incorrect
/// cid for restore"), so `restore()` must reprogram the EXACT baked CID — this file carries it across
/// the snapshot/restore boundary (the crosvm analogue of Firecracker's `HOST_PATHS_SIDECAR`, but
/// AF_VSOCK needs only the CID, not a host UDS path). Decimal text; no serde (this crate carries none).
const HOST_CID_SIDECAR: &str = "crosvm-host-cid.txt";

/// Writes the baked-CID sidecar for a snapshot in `dir`.
///
/// The **write** half of the sidecar's format contract; [`read_baked_cid`] is the read half, and the
/// two live beside each other so the format is spelled once — a writer emitting anything the reader
/// does not parse produces snapshots that only fail at restore, on a live boot.
///
/// # Errors
/// [`Error::Io`] if the sidecar cannot be written. Never logged-and-swallowed: restore reprograms
/// this exact CID, so a snapshot without it is unrestorable (M-RESTORE-2).
async fn write_baked_cid(dir: &Path, cid: u32) -> Result<()> {
    tokio::fs::write(dir.join(HOST_CID_SIDECAR), cid.to_string())
        .await
        .map_err(Error::Io)
}

/// Reads the baked guest CID back out of a snapshot dir's sidecar.
///
/// crosvm requires the restored `--vsock cid=` to match the snapshot's baked CID exactly, so this is
/// what `restore()` reprograms — never `res.guest_cid`. Both failure arms are fail-loud typed
/// [`Error::Vmm`]s naming the sidecar, on purpose: they run BEFORE any spawn, so a foreign or
/// corrupt snapshot dir surfaces here instead of as an opaque `crosvm run --restore` exit.
///
/// Extracted from `restore()` so the format contract and both error arms are drivable without KVM —
/// while it rode inline, nothing anywhere exercised either (docs/90 `vmcell-crosvm:833`).
///
/// # Errors
/// [`Error::Vmm`] if the sidecar is missing/unreadable, or if its contents are not a CID.
async fn read_baked_cid(snapshot_dir: &Path) -> Result<u32> {
    let path = snapshot_dir.join(HOST_CID_SIDECAR);
    tokio::fs::read_to_string(&path)
        .await
        .map_err(|e| {
            Error::Vmm(format!(
                "crosvm snapshot CID sidecar {} is missing/unreadable: {e}",
                path.display()
            ))
        })?
        // A trailing newline is not corruption: the sidecar is decimal TEXT, and a human or an
        // external tool that rewrites it will terminate the line.
        .trim()
        .parse()
        .map_err(|e| {
            Error::Vmm(format!(
                "crosvm snapshot CID sidecar is not a valid CID: {e}"
            ))
        })
}

/// The crosvm capability descriptor, exposed as a free function so [`Crosvm::capabilities`], the
/// `restore()` self-guard (which reads it through `capabilities()`), and the instance-level
/// `snapshot()` self-guard (which reads the `snapshot_restore` bool captured from it at spawn) all
/// consult the **same** source of truth.
///
/// Each field is the **empirically validated** value (matrix + arg-builder tests). Flipping any of the
/// remaining `false`s to `true` re-validates against a pinned crosvm build (AGENTS.md rule 5) and
/// updates its capability-honesty test.
fn crosvm_capabilities() -> VmmCapabilities {
    VmmCapabilities {
        // crosvm `snapshot take` + `run --restore` over the virtio block/net/vsock/serial device set
        // (USB dropped via --no-usb — the one non-Suspendable device). Validated live: snapshot →
        // restore reusing the BAKED vsock CID (crosvm rejects a rotated one) → steward-exec, MAC/IP/
        // clock/RNG resync all pass the snapshot_restore matrix leg. A deliberate re-gate must flip
        // this AND its capability-honesty test together (docs/45).
        snapshot_restore: true,
        // No userfaultfd/demand-paged restore backend wired.
        lazy_restore: false,
        // crosvm has `--shared-dir type=fs` (in-process virtiofs), but it is unvalidated here and
        // its snapshot-eligibility framing (in-process, not an external vhost-user virtiofsd)
        // differs from the `config_has_vhost_user_device` law — honest-false until validated;
        // create() rejects a share fail-loud meanwhile.
        virtio_fs_shares: false,
        // Whether crosvm supports the unprivileged smoltcp/vhost-user-net datapath is unconfirmed.
        unprivileged_vhost_user_net: false,
        // crosvm documents no working guest `/dev/kvm` (no nested KVM) — a hard, documented false.
        nested_virt: false,
        // crosvm has `--serial hardware=virtio-console` (hvc0); a VirtioConsole config is accepted.
        virtio_console: true,
        // FALSE — the Firecracker pattern, NOT QEMU's. crosvm bakes the vsock CID into the snapshot
        // and REQUIRES the same CID on restore: a rotated `--vsock cid=` fails "Virtio vsock incorrect
        // cid for restore: Expected: N, Actual: M" (validated live). So `restore()` reuses the baked
        // CID (carried in a sidecar), the restored VM does not get a fresh host-side vsock identity,
        // and — like FC — restore-while-alive and concurrent restores from one lineage are unsupported
        // (the §17 single-snapshot-CoW gap). Flip this AND its capability-honesty test together only if
        // a future crosvm allows CID rotation on restore.
        restore_rotates_host_paths: false,
        // crosvm's `--block` has NO bandwidth/iops key (verified against `crosvm run --help`), so it
        // cannot rate-limit disk I/O like CH/FC/QEMU — `create()` rejects a throttled disk fail-loud.
        disk_io_throttle: false,
        // crosvm's default xhci USB controller is NOT `Suspendable` (validated live: `resume` panics
        // "Suspendable::wake not implemented for XhciController"), so vmcell always launches with
        // `--no-usb` (§2.5) — there is no controller to attach a host device to. Honest-false;
        // `create()` rejects a USB device fail-loud via the shared `reject_usb_host_devices`
        // predicate. Flipping this would require dropping `--no-usb`, which re-breaks snapshot.
        usb_host_passthrough: false,
    }
}

/// Builds the crosvm `--serial` device spec for `mode`, writing the guest console to `serial_path`.
///
/// The `hardware=` token moves in lockstep with the cmdline `console=` token
/// (`build_kernel_cmdline`): `Uart` → the 8250 `ttyS0` (`hardware=serial`), `VirtioConsole` →
/// `hvc0` (`hardware=virtio-console`). A desync would sink the guest console nowhere and leave
/// `serial.log` silent, so both are driven by the one `cfg.console_mode`.
fn serial_arg(mode: ConsoleMode, serial_path: &Path) -> String {
    let hardware = match mode {
        ConsoleMode::Uart => "serial",
        ConsoleMode::VirtioConsole => "virtio-console",
    };
    format!(
        "type=file,path={},hardware={hardware},num=1,console=true,stdin=false",
        serial_path.display()
    )
}

/// Builds the argument vector for `crosvm run` — everything **after** the `run` subcommand and the
/// seccomp/sandbox flags (which come from [`vmm_seccomp_args`](vmcell::vmm::seccomp::vmm_seccomp_args)).
///
/// The kernel image is the trailing positional argument, and the rootfs `--block` is emitted first
/// so it enumerates as `/dev/vda` — the device the shared cmdline (`root=/dev/vda`,
/// `build_kernel_cmdline`) boots from. crosvm's own `root=` auto-append is deliberately not used;
/// the cmdline owns the `root=` token, exactly as on Firecracker/QEMU. Pure and unit-testable (no
/// I/O, no spawn) so a KVM-free test can assert the freeze flag and device ordering.
///
/// # Errors
/// Returns an error if the guest MAC cannot be derived from `res.vmid`
/// ([`mac_math`](vmcell::net::mac_math)).
fn build_crosvm_run_args(
    cfg: &VmConfig,
    res: &PerVmResources,
    control_socket: &Path,
    serial_path: &Path,
    guest_cid: u32,
    cmdline: &str,
    restore_from: Option<&Path>,
) -> Result<Vec<String>> {
    let mut args: Vec<String> = Vec::new();

    // Control socket: the host drives lifecycle (resume/suspend/powerbtn/stop) over this side
    // socket by re-invoking the crosvm binary as a client. crosvm binds it at startup, so
    // `register_and_await_ready` waits on it as the readiness gate.
    args.push("-s".to_string());
    args.push(control_socket.display().to_string());

    // Create-then-boot split (mirrors QEMU `-S` / FC's deferred InstanceStart): `--suspended`
    // freezes the vCPUs AND devices at launch so the guest does not run until `boot()`/`resume()`
    // issues `crosvm resume --full`. On the RESTORE path it also holds the loaded snapshot paused so
    // `restore()` can return a paused instance for the orchestrator to resume (the trait contract).
    args.push("--suspended".to_string());

    // Restore path: load the snapshot's device + guest-RAM state on startup. The device topology is
    // reconstructed from the run args below (kernel/disks/net) against a FRESH `res` — but NOT the
    // vsock CID: crosvm bakes it into the snapshot and rejects a rotated `--vsock cid=` ("Virtio
    // vsock incorrect cid for restore", validated live), so the caller passes the sidecar-carried
    // BAKED `guest_cid` here while guest RAM is loaded verbatim (`restore_rotates_host_paths:
    // false` — the Firecracker pattern; see the capability descriptor above and `restore()` below).
    if let Some(snapshot) = restore_from {
        args.push("--restore".to_string());
        args.push(snapshot.display().to_string());
    }

    // `--suspended`/`resume` runs a device sleep/wake cycle that requires every attached device to
    // implement `Suspendable`. crosvm attaches a legacy xhci USB controller by default which does
    // NOT (validated live: `resume` panics `Suspendable::wake not implemented for XhciController`);
    // the guest needs no USB, so drop it. The remaining devices (virtio block/net/vsock/serial) are
    // the Suspendable set crosvm's suspend path supports.
    args.push("--no-usb".to_string());

    args.push("-c".to_string());
    args.push(cfg.vcpus.to_string());
    args.push("-m".to_string());
    args.push(cfg.mem_mib.to_string());

    // Console/serial, driven by the SAME `cfg.console_mode` as the cmdline `console=` token so the
    // two move in lockstep. `reject_unsupported_console` gated an unsupported mode in create().
    args.push("--serial".to_string());
    args.push(serial_arg(cfg.console_mode, serial_path));

    // In-kernel vhost-vsock on the host AF_VSOCK namespace at `(guest_cid, the declared steward
    // port)` (realized against `/dev/vhost-vsock`). No external daemon and no AF_UNIX bridge — the
    // host dials the CID directly (`vsock_endpoint` returns `steward_endpoint`'s `VsockEndpoint::
    // Vsock`). The port is not in this argv: the guest learns it from the `vmcell_steward_port=`
    // cmdline token the shared composer emits, so both sides read one declaration.
    args.push("--vsock".to_string());
    args.push(format!("cid={guest_cid}"));

    // Networking: privileged TAP only for v1. Unprivileged vhost-user-net is rejected in create()
    // (capability `unprivileged_vhost_user_net` is honest-false until validated), so at most a tap
    // is present here. The guest MAC matches the shared `mac_math(vmid)` the other backends use.
    if let Some(tap) = &res.tap_name {
        args.push("--net".to_string());
        args.push(format!(
            "tap-name={tap},mac={}",
            vmcell::net::mac_math(res.vmid)?
        ));
    }

    // Block devices, in argument order → `/dev/vda`, `/dev/vdb`, … The rootfs MUST be first so it
    // enumerates as `/dev/vda`, which the cmdline boots from. `ro=true` for every rootfs source:
    // the guest mounts the root `ro` whatever its format is, so the device is attached read-only
    // to match (§4.7 — the ext4 `Block` root buys POSIX-completeness, not writability).
    //
    // *Which* host file backs `/dev/vda` is the one law, `RootfsSource::effective_image` — the
    // same predicate the config boundary's duplicate-backing-file guard uses, so the guard can
    // never protect a file this argv does not attach. **Whether it is writable** is the other one
    // law, `RootfsSource::root_device_read_only`, which owns the exhaustive per-variant match: the
    // `Block` arm here open-coded the ABSENCE of `ro=true`, contradicting the cmdline's `ro`.
    let root_image = cfg.rootfs.effective_image().display().to_string();
    let root_ro = if cfg.rootfs.root_device_read_only() {
        ",ro=true"
    } else {
        ""
    };
    args.push("--block".to_string());
    args.push(format!("path={root_image}{root_ro}"));

    // Extra virtio-blk devices (§4.6), attached AFTER the root disk so they enumerate `/dev/vdb`,
    // `/dev/vdc`, … in order and never displace `/dev/vda`. Per-disk I/O throttling (`io_limit`)
    // has no crosvm CLI equivalent and is rejected fail-loud by `reject_disk_io_throttle` on BOTH
    // the create and the restore path (M4), so it is absent here.
    for disk in &cfg.extra_disks {
        args.push("--block".to_string());
        if disk.readonly {
            args.push(format!("path={},ro=true", disk.image.display()));
        } else {
            args.push(format!("path={}", disk.image.display()));
        }
    }

    // Kernel command line (`-p`) then the kernel image as the trailing positional argument.
    args.push("-p".to_string());
    args.push(cmdline.to_string());
    args.push(cfg.kernel.display().to_string());

    Ok(args)
}

/// Builds the argument vector for a crosvm **control** invocation
/// (`crosvm <subcmd> <VM_SOCKET> [extra…]`).
///
/// The control socket is a positional argument that comes **before** any trailing flags (crosvm's
/// help is `crosvm resume <VM_SOCKET> [--full]`). One helper so the spelling lives in exactly one
/// place (and one KVM-free test). `extra` carries per-op flags such as `--full` for the boot resume.
fn crosvm_control_args(subcmd: &str, socket: &Path, extra: &[&str]) -> Vec<String> {
    let mut args = vec![subcmd.to_string(), socket.display().to_string()];
    args.extend(extra.iter().map(|s| (*s).to_string()));
    args
}

/// Everything a crosvm launch is: the **fully composed command**, plus a record of the two
/// inputs it was composed from.
///
/// `spawn` receives this and spawns [`Self::cmd`]; it never holds a
/// [`JailConfig`](vmcell::config::JailConfig), a `JailSpec` or an argv of its own, so there is
/// no window between "decide the posture" and "apply the posture" for anything to change it.
/// That window is exactly what defeated M11's first shape: with the plan carrying a mutable
/// `jail` that `spawn` later compiled, a two-line
/// `let mut plan = …; plan.jail = cfg.jail;` shipped every crosvm VM with no seccomp filter and
/// left the whole suite green, because the source scan's predicate was satisfied by the mutated
/// binding.
///
/// [`jail`](Self::jail) and [`run_args`](Self::run_args) are **records, not inputs**: the
/// command is already built when the plan exists, so mutating either changes nothing about what
/// ships. They exist so a KVM-free test can assert on the posture and argv that WERE used —
/// and, because [`Self::build`] is the only constructor and takes each of them exactly once, the
/// record provably IS what was used.
#[derive(Debug)]
struct CrosvmLaunchPlan {
    /// The composed `crosvm run …` command, with the netns join and the jail already applied by
    /// [`build_vmm_cmd`](vmcell::vmm::build_vmm_cmd). Moved out and spawned by `spawn`.
    cmd: tokio::process::Command,
    /// A record of the effective jail posture ([`effective_jail_config`]) the command's
    /// `JailSpec` was compiled from. Inert — see the type doc.
    ///
    /// Read only by the M11 gate, which is the point: it exists so a KVM-free test can name the
    /// posture that shipped. `cfg_attr(not(test), …)` rather than a bare `#[expect]`, because in a
    /// test build the field IS read and an unconditional expectation would go unfulfilled.
    ///
    /// The expectation is load-bearing, not decoration: it says "production never touches this".
    /// Any production write — including the exact
    /// `let mut plan = crosvm_launch_plan(…)?; plan.jail = cfg.jail;` that defeated M11's first
    /// shape — makes the field no longer dead, the expectation unfulfilled, and the shipped build
    /// a hard error under `RUSTFLAGS=-D warnings` (which `just ci` sets). Verified by applying
    /// that edit and observing `error: this lint expectation is unfulfilled`. So the mutation is
    /// both INERT (the command is already composed; see
    /// `mutating_the_plans_recorded_jail_cannot_change_what_ships`) and unbuildable.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "the shipped posture, recorded for the M11 gate; the command already carries it"
        )
    )]
    jail: vmcell::config::JailConfig,
    /// A record of the `crosvm run` arguments appended after the subcommand and the
    /// seccomp/sandbox flags. Inert — see the type doc.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "the shipped argv, recorded for the M11 gate; the command already carries it"
        )
    )]
    run_args: Vec<String>,
}

impl CrosvmLaunchPlan {
    /// The **only** constructor: compiles `jail` into the `JailSpec`, builds the command with
    /// that spec, and records the very same `jail` value.
    ///
    /// One value, two uses, no window between them — so a plan whose recorded posture disagrees
    /// with its command's posture is unrepresentable. The one remaining way to ship the wrong
    /// posture is to hand the wrong `jail` in at the single call site, and that is a *behavioral*
    /// difference the M11 gate catches directly (`plan.jail == effective_jail_config(cfg)` and
    /// `plan.jail != cfg.jail`), not something a source scan has to infer.
    ///
    /// # Errors
    /// Propagates [`jail_spec_from_config`](vmcell::vmm::jail::jail_spec_from_config)'s error
    /// (an unsupported jail request).
    fn build(
        binary_path: &Path,
        netns_name: Option<&str>,
        jail: vmcell::config::JailConfig,
        seccomp_args: &[String],
        run_args: Vec<String>,
    ) -> Result<Self> {
        let spec = vmcell::vmm::jail::jail_spec_from_config(&jail)?;
        let mut cmd = vmcell::vmm::build_vmm_cmd(binary_path, netns_name, &spec);
        cmd.arg("run");
        cmd.args(seccomp_args);
        cmd.args(&run_args);
        Ok(Self {
            cmd,
            jail,
            run_args,
        })
    }
}

/// The two per-VM paths a crosvm launch names, bundled so [`crosvm_launch_plan`] stays inside
/// clippy's argument budget — the same shape `vmcell-qemu`'s `QemuSpawnPaths` uses. Both are
/// derived from `res.tmp_dir` by `spawn`, which owns the scratch directory.
struct CrosvmSpawnPaths<'a> {
    /// The `--socket` control socket crosvm binds, and the readiness gate `spawn` waits on.
    control_socket: &'a Path,
    /// The serial log file the guest console is written to.
    serial_path: &'a Path,
}

/// The pure, total mapping from a config to the pair a crosvm launch is made of (M11).
///
/// `spawn` builds through this and uses **only** what it returns, so the jail posture that ships is
/// a *returned value* a KVM-free test can assert on rather than an inline argument no gate can see.
/// That distinction is the whole point: crosvm always runs `--disable-sandbox`, so the Layer-2
/// deny-list `effective_jail_config` turns on is its ONLY seccomp confinement — and while that flip
/// lived as an inline `jail_spec_from_config(&effective_jail_config(cfg))` argument, rewriting the
/// one token to `&cfg.jail` shipped every crosvm VM unconfined with `cargo test`, `just ci` and the
/// entire live `test-crosvm` matrix green (the deny-list is default-allow/EPERM, so no functional
/// leg notices).
///
/// # Errors
/// Propagates [`build_crosvm_run_args`]'s error (the guest MAC derivation),
/// [`vmm_seccomp_args`](vmcell::vmm::seccomp::vmm_seccomp_args)'s typed refusal of
/// [`VmmSeccomp::Log`](vmcell::config::VmmSeccomp::Log), and
/// [`CrosvmLaunchPlan::build`]'s jail-compilation error.
fn crosvm_launch_plan(
    binary_path: &Path,
    cfg: &VmConfig,
    res: &PerVmResources,
    paths: &CrosvmSpawnPaths<'_>,
    guest_cid: u32,
    cmdline: &str,
    restore_from: Option<&Path>,
) -> Result<CrosvmLaunchPlan> {
    // The argv half of the sandbox posture: always `--disable-sandbox` for crosvm, and the one
    // typed refusal of `VmmSeccomp::Log`. Computed here, before any spawn, so a `Log` config is
    // refused without a process ever being created.
    let seccomp_args = vmcell::vmm::seccomp::vmm_seccomp_args("crosvm", cfg.vmm_seccomp)?;
    let run_args = build_crosvm_run_args(
        cfg,
        res,
        paths.control_socket,
        paths.serial_path,
        guest_cid,
        cmdline,
        restore_from,
    )?;
    // The confinement half: the ONE `effective_jail_config` call, handed straight to the one
    // constructor that both compiles it and records it.
    CrosvmLaunchPlan::build(
        binary_path,
        res.netns_name.as_deref(),
        effective_jail_config(cfg),
        &seccomp_args,
        run_args,
    )
}

impl Crosvm {
    async fn spawn(
        &self,
        cfg: &VmConfig,
        res: &PerVmResources,
        cgroups: &dyn vmcell::metrics::CgroupFs,
        restore_from: Option<&Path>,
        // The vsock CID to program on `--vsock cid=` and report as `guest_cid()`. `res.guest_cid` on
        // a cold create; the snapshot's BAKED CID (from the sidecar) on restore, since crosvm requires
        // it to match the snapshot (`restore_rotates_host_paths: false`).
        guest_cid: u32,
    ) -> Result<CrosvmInstance> {
        // The orchestrator owns the per-VM scratch dir; derive our socket and serial-log paths
        // inside it.
        let control_socket = res.tmp_dir.join("crosvm.sock");
        let vsock_path = res.tmp_dir.join("vsock.sock"); // vestigial (crosvm uses AF_VSOCK)
        let serial_path = res.tmp_dir.join("serial.log");

        // Re-spawn safety: `MicroVm::start`'s health-gate may recreate a VM on the SAME per-VM dir;
        // a stale bound control socket left in the dir would make crosvm fail to bind. Pre-clean
        // (a no-op, and thus harmless, on the first spawn when nothing exists yet).
        #[expect(
            clippy::let_underscore_must_use,
            reason = "re-spawn pre-clean whose expected outcome is NotFound; crosvm's own bind below reports a socket it cannot create"
        )]
        let _ = tokio::fs::remove_file(&control_socket).await;

        let cmdline = vmcell::config::build_kernel_cmdline(cfg, res, "")?;

        // Sandbox posture (§12.2, validated live): the argv half is always `--disable-sandbox`, and
        // the confinement half is the Layer-2 deny-list `effective_jail_config` turns on — crosvm is
        // the one backend whose confinement is Layer 2 rather than its own filter, and it is the
        // per-backend deny-list enablement the deny-list was designed for (validated: crosvm boots +
        // execs + does tap/netns networking under the deny-list).
        //
        // M11: the whole launch — jail spec, netns, argv — is composed inside `crosvm_launch_plan`,
        // so `spawn` holds NO `JailConfig` and NO `JailSpec` and there is no window in which the
        // posture could be swapped between deciding it and applying it. `plan.jail` is an inert
        // record the KVM-free gate asserts on; mutating it here would change nothing.
        let plan = crosvm_launch_plan(
            &self.binary_path,
            cfg,
            res,
            &CrosvmSpawnPaths {
                control_socket: &control_socket,
                serial_path: &serial_path,
            },
            guest_cid,
            &cmdline,
            restore_from,
        )?;
        let mut cmd = plan.cmd;

        // Debug level (not info): the full command line is diagnostic noise on every create.
        tracing::debug!("crosvm CMD: {cmd:?}");

        let mut process = cmd
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()?;

        // Shared spawn+register+await-ready sequence (VMM-2): capture the pgid, add the VMM to its
        // cgroup, and block on the control socket — reaping the process group on any failure. The
        // readiness error is propagated raw, identically to CH/FC/QEMU.
        let pgid = vmcell::vmm::register_and_await_ready(
            &mut process,
            cgroups,
            &res.cgroup_name,
            &control_socket,
            cfg.timeouts.api_socket_poll.as_millis() as u64,
        )
        .await?;

        Ok(CrosvmInstance {
            process,
            binary_path: self.binary_path.clone(),
            // Every control op this instance makes is bounded by the backend's budget (M5).
            control_budget: self.control_budget,
            // M6: the take writes a suspend image that tracks guest RAM ~1:1 (≈268 MB for a
            // 256 MiB guest, §16), so it rides the shared guest-RAM-proportional predicate over
            // this backend's flat control budget as a floor — never the flat budget alone, which a
            // multi-GiB guest overruns by construction.
            snapshot_budget: self
                .control_budget
                .max(vmcell::vmm::snapshot_request_timeout(cfg.mem_mib)),
            control_socket,
            vsock_path,
            serial_path,
            cid: guest_cid,
            group: vmcell::vmm::VmmProcessGroup::new(pgid),
            // A restore-spawned instance is returned paused; its first `resume()` must be `--full`.
            restored: restore_from.is_some(),
            has_vhost_user_device: vmcell::vmm::config_has_vhost_user_device(cfg, res),
            // Captured from the ONE descriptor so `snapshot()` self-guards on the same source of
            // truth `capabilities()` reports (M-RESTORE-3).
            snapshot_restore_capable: self.capabilities().snapshot_restore,
            // C8's first question, answered once here from the cell's own declaration — the `cid`
            // above is the same one the argv programs (`--vsock cid=`), baked on restore.
            endpoint: steward_endpoint(guest_cid, cfg.steward_placement),
        })
    }
}

impl Vmm for Crosvm {
    type Instance = CrosvmInstance;

    async fn create(
        &self,
        cfg: &VmConfig,
        res: &PerVmResources,
        cgroups: &dyn vmcell::metrics::CgroupFs,
    ) -> Result<Self::Instance> {
        // The cmdline `console=` token and the `--serial` device wiring are both driven by
        // `cfg.console_mode`; gate an unsupported mode up front so they can never desync into a
        // silent `serial.log`. crosvm supports virtio-console, so only a future capability flip
        // would trip this.
        vmcell::vmm::reject_unsupported_console("crosvm", &self.capabilities(), cfg.console_mode)?;

        let caps = self.capabilities();
        if let vmcell::config::NetConfig::Unprivileged { .. } = cfg.net
            && !caps.unprivileged_vhost_user_net
        {
            // N-VMM-1 by construction: `Feature::name()` IS the VmmCapabilities field name, so
            // callers see one consistent spelling across backends without a literal to keep in
            // sync (F6).
            return Err(Error::unsupported(
                "crosvm",
                Feature::UnprivilegedVhostUserNet,
            ));
        }
        if res.vhost_user_socket.is_some() {
            // Deliberately still a string: a pre-attached vhost-user socket is a per-VM RESOURCE,
            // not a `VmmCapabilities` field, so the vocabulary has no `Feature` for it and §7.4
            // clause 4 fixes that granularity up front — a speculative variant here would break
            // every declaration the day it split. Do not "fix" this to a `Feature`.
            return Err(Error::Unsupported {
                vmm: "crosvm".to_string(),
                feature: "vhost_user_socket".to_string(),
            });
        }
        if !cfg.shares.is_empty() {
            return Err(Error::unsupported("crosvm", Feature::VirtioFsShares));
        }
        // Per-disk I/O throttling has no crosvm CLI equivalent (capability `disk_io_throttle` is
        // false); reject a throttled disk fail-loud rather than silently drop the limit
        // (honor-or-reject accepted input). The one predicate `restore()` shares (M4).
        reject_disk_io_throttle(cfg)?;
        // vmcell always launches crosvm with `--no-usb` (the xhci controller is not `Suspendable`,
        // §2.5), so there is no bus to attach a host device to. Refuse through the ONE shared
        // predicate rather than silently ignoring the accepted input.
        vmcell::vmm::reject_usb_host_devices("crosvm", &caps, &cfg.usb_host_devices)?;
        // `nested_virt` and `RestoreMode::Lazy` are advertised false and have no crosvm
        // realization; refuse them here rather than boot a VM whose requested lever reads as
        // applied and is not (d7). Same predicate `restore()` uses.
        reject_unadvertised_capabilities(&caps, cfg)?;

        self.spawn(cfg, res, cgroups, None, res.guest_cid).await
    }

    async fn restore(
        &self,
        snapshot_dir: &Path,
        cfg: &VmConfig,
        res: &PerVmResources,
        cgroups: &dyn vmcell::metrics::CgroupFs,
    ) -> Result<Self::Instance> {
        // VMM-5 / M-RESTORE-3: self-check the capability descriptor instead of assuming crosvm
        // semantics — the same shape CH and FC ship. crosvm's descriptor says `snapshot_restore:
        // true` today, so this branch is only reachable via a deliberate re-gate; the KVM-free
        // `snapshot_precheck` test drives the equivalent false branch on the snapshot side.
        if !self.capabilities().snapshot_restore {
            return Err(Error::unsupported("crosvm", Feature::SnapshotRestore));
        }
        vmcell::vmm::reject_unsupported_console("crosvm", &self.capabilities(), cfg.console_mode)?;

        // The USB half of the same M4 law: crosvm always runs `--no-usb`, so a
        // `usb_host_devices` list handed to `restore()` was accepted and silently dropped
        // (`create()` refuses it). The ONE shared restore predicate returns the identical
        // `usb_host_passthrough` refusal here (§8.1, The warm-snapshot path and the eligibility law), before any spawn.
        vmcell::vmm::reject_usb_host_devices_on_restore(
            "crosvm",
            &self.capabilities(),
            &cfg.usb_host_devices,
        )?;
        // M4: `restore()` must refuse exactly what `create()` refuses — the restore run args come
        // from the same `build_crosvm_run_args`, which has nowhere to put an `io_limit`, so an
        // unguarded restore would silently attach the throttled disk unthrottled. One predicate,
        // both paths.
        reject_disk_io_throttle(cfg)?;
        // Same law for the two unadvertised levers (d7): `restore_mode` is the field a restore
        // consumes, so a `RestoreMode::Lazy` accepted here would fault eagerly under a config that
        // asked for demand paging.
        reject_unadvertised_capabilities(&self.capabilities(), cfg)?;

        // Eligibility (S1, §8.1), defense in depth alongside `config::build()`, the orchestrator
        // re-check, and `check_clone_eligible`. crosvm has no external vhost-user devices, so a share
        // or unprivileged net (both already rejected at create) is the only way this trips — reject
        // fail-loud before spawning a half-restored VM.
        if vmcell::vmm::config_has_vhost_user_device(cfg, res) {
            // The same shared const `snapshot_precheck` returns (F6): one law, one spelling, so the
            // snapshot and restore halves of the eligibility rule cannot drift into the two
            // near-miss prose strings they used to carry.
            return Err(Error::from_removal("crosvm", &VHOST_USER_BLOCKS_SNAPSHOT));
        }

        // Fail loud BEFORE spawning if the snapshot artifact or its CID sidecar is missing, so a bad
        // snapshot dir surfaces as a clear typed error instead of an opaque `crosvm run --restore`
        // failure. Both are written by `snapshot()`.
        let snapshot = snapshot_dir.join(SNAPSHOT_FILE);
        if !tokio::fs::try_exists(&snapshot).await.unwrap_or(false) {
            return Err(Error::Vmm(format!(
                "crosvm snapshot artifact {} is missing (not a valid snapshot dir)",
                snapshot.display()
            )));
        }
        // crosvm requires the restored `--vsock cid=` to match the snapshot's baked CID exactly, so
        // read it from the sidecar and reprogram it (NOT `res.guest_cid`). The guest keeps the baked
        // CID (`restore_rotates_host_paths: false`); the vmid/MAC/IP still rotate to `res.vmid` via the
        // orchestrator's post-restore resync. A missing/garbled sidecar is a fail-loud pre-spawn
        // error, from the one reader that owns the format `snapshot()` writes.
        let baked_cid = read_baked_cid(snapshot_dir).await?;

        // The instance is returned paused (`restored: true`); the orchestrator continues with
        // `resume()` — never `boot()` — which issues the completing `crosvm resume --full`.
        self.spawn(cfg, res, cgroups, Some(&snapshot), baked_cid)
            .await
    }

    fn capabilities(&self) -> VmmCapabilities {
        crosvm_capabilities()
    }

    fn id(&self) -> &str {
        "crosvm"
    }
}

impl CrosvmInstance {
    /// Runs one crosvm control subcommand against this instance's side socket and fails if crosvm
    /// exits non-zero — bounded by [`CROSVM_CONTROL_BUDGET`] (M5).
    ///
    /// Each control op re-invokes the crosvm binary as a short-lived client (`crosvm <subcmd>
    /// <socket>`) — the socket protocol is unstable binary and is never hand-rolled. Awaiting the
    /// child reaps it. Not jailed or netns-entered: it is a host-side client, not the VMM.
    ///
    /// # Errors
    /// [`Error::Timeout`] naming the subcommand if the client does not exit within the budget (the
    /// abandoned client is SIGKILLed and reaped by `kill_on_drop`, so a wedged VMM leaks no client
    /// process); [`Error::Vmm`] if it exits non-zero; [`Error::Io`] if it cannot be spawned.
    async fn run_control(&self, subcmd: &str, extra: &[&str]) -> Result<()> {
        self.invoke_control(
            subcmd,
            self.control_budget,
            crosvm_control_args(subcmd, &self.control_socket, extra)
                .into_iter()
                .map(std::ffi::OsString::from)
                .collect(),
        )
        .await
    }

    /// The **one** bounded control-client invocation: spawn `crosvm <args>`, wait at most `budget`,
    /// and fail loud if it elapses or exits non-zero.
    ///
    /// One law, one predicate — and specifically one `budget` binding. `budget` is used TWICE here,
    /// for the wall-clock bound AND for the typed elapse that reports it, from the same parameter:
    /// when those were two separate expressions (`timeout(self.snapshot_budget, …)` beside
    /// `control_timeout(…, self.snapshot_budget)`), swapping only the first silently put
    /// `snapshot take` back on the flat control budget while the error message — and therefore the
    /// gate reading it — still said otherwise. Threading one parameter makes that divergence
    /// unrepresentable, which is what lets
    /// `crosvm_control_ops_are_bounded_by_the_control_budget` tell the two budgets apart.
    ///
    /// # Errors
    /// [`Error::Timeout`] naming `subcmd` and `budget` if the client does not exit in time (the
    /// abandoned client is SIGKILLed and reaped by `kill_on_drop`, so a wedged VMM leaks no client
    /// process); [`Error::Vmm`] if it exits non-zero; [`Error::Io`] if it cannot be spawned.
    async fn invoke_control(
        &self,
        subcmd: &str,
        budget: Duration,
        // `OsString`, not `String`: the snapshot path and the control socket are host paths and
        // must reach `execve` byte-for-byte, exactly as the former `.arg(path)` passed them.
        args: Vec<std::ffi::OsString>,
    ) -> Result<()> {
        let status = tokio::time::timeout(
            budget,
            tokio::process::Command::new(&self.binary_path)
                .args(&args)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::inherit())
                // The budget only bounds the *wait*; without this the abandoned client would stay
                // blocked on the wedged VMM's socket forever.
                .kill_on_drop(true)
                .status(),
        )
        .await
        .map_err(|_| {
            Error::Timeout(format!(
                "crosvm {subcmd} control command did not complete within {budget:?}"
            ))
        })??;
        if !status.success() {
            return Err(Error::Vmm(format!(
                "crosvm {subcmd} control command failed: {status}"
            )));
        }
        Ok(())
    }

    /// Writes a snapshot of the (already-suspended) VM to `path` via `crosvm snapshot take <path>
    /// <VM_SOCKET>`, bounded by this instance's `snapshot_budget` (M6) rather than the flat
    /// [`CROSVM_CONTROL_BUDGET`] every other control op rides (M5): the take writes a suspend image
    /// that tracks guest RAM ~1:1, so a multi-GiB guest overruns a flat ceiling by construction and
    /// a spurious `Timeout` here strands the VM fully suspended with a half-written image.
    /// The snapshot subcommand's positional order is `<snapshot_path> <VM_SOCKET>` — the path comes
    /// BEFORE the socket, so it does not fit `crosvm_control_args` (socket-first) and takes its own
    /// arg vector.
    ///
    /// # Errors
    /// [`Error::Timeout`] naming `snapshot take` if the client does not exit within the budget;
    /// [`Error::Vmm`] if it exits non-zero; [`Error::Io`] if it cannot be spawned.
    async fn snapshot_take(&self, path: &Path) -> Result<()> {
        self.invoke_control(
            "snapshot take",
            // The ONE guest-RAM-proportional budget on this backend (M6) — not `control_budget`.
            self.snapshot_budget,
            vec![
                std::ffi::OsString::from("snapshot"),
                std::ffi::OsString::from("take"),
                path.as_os_str().to_os_string(),
                self.control_socket.as_os_str().to_os_string(),
            ],
        )
        .await
    }
}

impl VmInstance for CrosvmInstance {
    async fn boot(&mut self) -> Result<()> {
        // Wake the vCPUs AND devices frozen by `--suspended` at create — the real start point (H-VMM-2
        // analogue). `--suspended` is a FULL suspend (devices + vCPUs), so boot needs `resume --full`:
        // a plain `resume` wakes only vCPUs and crosvm errors "Trying to wake Vcpus while Devices are
        // asleep" (validated live). boot() is only ever called on a `create()` instance; a restored
        // instance is continued via `resume()` (which does its own completing `--full`), never boot().
        self.run_control("resume", &["--full"]).await
    }

    async fn request_shutdown(&mut self) -> Result<()> {
        // ACPI power button: the steward (PID 1) honors it and powers off gracefully.
        self.run_control("powerbtn", &[]).await
    }

    async fn kill(&mut self) -> Result<()> {
        // Best-effort graceful stop first, then SIGKILL the process group and reap. The bound is
        // `run_control`'s own `CROSVM_CONTROL_BUDGET` — kill() carries no second literal of its own
        // (M5) — and the failure is logged, never silently discarded: the SIGKILL below is the
        // guarantee, so a failed stop is diagnostic, not fatal.
        if let Err(e) = self.run_control("stop", &[]).await {
            tracing::debug!("crosvm kill: graceful stop failed, forcing SIGKILL: {e}");
        }

        // The one shared signal/wait/flag sequence (L1): SIGKILL the group unless the leader was
        // already reaped, await it, record the reap (M-VMM-1).
        self.group.kill_and_wait(&mut self.process).await;
        Ok(())
    }

    async fn has_exited(&mut self) -> bool {
        // Non-blocking reap of the crosvm leader; `Ok(Some(_))` means it exited after
        // `request_shutdown` (`powerbtn`). The shared helper records the reap so `kill()`/`Drop`
        // cannot re-`SIGKILL` a possibly-recycled pgid.
        self.group.note_exit(&mut self.process)
    }

    async fn pause(&mut self) -> Result<()> {
        // vCPU-only suspend of a running VM (devices keep running) — the conventional lightweight
        // pause/resume pair. Not `--full`: that is boot()'s job, matching the `--suspended` launch.
        self.run_control("suspend", &[]).await
    }

    async fn resume(&mut self) -> Result<()> {
        // A restored instance was launched `--suspended --restore`, so its FIRST resume must be
        // `--full` (wake devices + vCPUs, completing the restore — crosvm's `resume` after `--restore`
        // also waits for the restore to finish). A plain vCPU-only resume on that state errors "Trying
        // to wake Vcpus while Devices are asleep" (the same class as boot()). Subsequent resumes
        // (after a vCPU-only pause()) are vCPU-only. Consume `restored` only AFTER the resume succeeds,
        // so a transient failure leaves the next call able to retry the completing `--full`.
        let extra: &[&str] = if self.restored { &["--full"] } else { &[] };
        self.run_control("resume", extra).await?;
        self.restored = false;
        Ok(())
    }

    async fn snapshot(&mut self, dir: &Path) -> Result<()> {
        // M-RESTORE-3: self-check the `snapshot_restore` capability (captured from the backend
        // descriptor at spawn) before doing any work, and enforce the S1 snapshot-eligibility law —
        // refuse to snapshot a VM with a vhost-user device attached. crosvm has no external
        // vhost-user devices and rejects shares/unprivileged net at create, so the second half holds
        // by construction; both are kept as defense in depth (mirrors CH's `snapshot_precheck`).
        snapshot_precheck(self.snapshot_restore_capable, self.has_vhost_user_device)?;
        // Full-suspend (crosvm requires all devices asleep to snapshot) → `snapshot take` → persist
        // the baked-CID sidecar → resume the source. Mirrors the QEMU stop→migrate→cont / CH-FC
        // pause→snapshot→resume order; the orchestrator's `MicroVm::snapshot` invalidates the cached
        // steward client afterward, covering the suspend severing the vsock connection. The take + the
        // sidecar are BOTH required for a restorable snapshot, so either failing fails the snapshot
        // fail-loud; the source resume is best-effort (warn-only), matching QEMU/CH/FC.
        self.run_control("suspend", &["--full"]).await?;
        let result = match self.snapshot_take(&dir.join(SNAPSHOT_FILE)).await {
            // Restore reprograms this exact CID; a snapshot without its CID is unrestorable, so a
            // write failure is surfaced, never logged-and-swallowed (M-RESTORE-2). Through the one
            // writer that pairs with `read_baked_cid`.
            Ok(()) => write_baked_cid(dir, self.cid).await,
            Err(e) => Err(e),
        };
        if let Err(e) = self.run_control("resume", &["--full"]).await {
            tracing::warn!("crosvm snapshot: failed to resume source after take: {e}");
        }
        result
    }

    fn vsock_path(&self) -> &Path {
        &self.vsock_path
    }

    fn vsock_endpoint(&self) -> VsockEndpoint {
        // AF_VSOCK by CID, at the DECLARED steward port — NOT the AF_UNIX hybrid default (the
        // steward transport branches only its connect prologue on this). Composed once at spawn by
        // `steward_endpoint`, so this reader cannot pick a different port than the cell declared.
        self.endpoint.clone()
    }

    fn guest_cid(&self) -> u32 {
        // On a restore this is the snapshot's BAKED CID, not `res.guest_cid` — and the orchestrator
        // reads exactly this to decide which CID to hold out of the allocatable pool for the VM's
        // lifetime (`CidGuard::adopt_baked_cid`, design §17, Open gaps and future capabilities,
        // crosvm item 7). crosvm's vsock is in-kernel AF_VSOCK, so the CID is a host-global
        // identity: reporting the fresh allocation here would silently hand the baked one back to
        // the pool for a later VM to collide on.
        self.cid
    }

    fn serial_log(&self) -> &Path {
        &self.serial_path
    }
}

impl Drop for CrosvmInstance {
    fn drop(&mut self) {
        // Teardown order (AGENTS.md): reap the VMM process group first — before touching the
        // socket — so cleanup never races a live VMM. Same helper, same order as the graceful
        // `kill()` path (L1); the SIGKILL + blocking reap is skipped if the leader was already
        // reaped, since its pgid may have been recycled (M-VMM-1).
        self.group.reap_now(&mut self.process);
        // Unlink our own control socket; the per-VM directory itself is owned and removed once by
        // the orchestrator's `VmTempDir` guard after this instance is dropped. Mirrors CH/QEMU.
        #[expect(
            clippy::let_underscore_must_use,
            reason = "Drop cannot report, and the VmTempDir guard removes the whole per-VM dir afterwards"
        )]
        let _ = std::fs::remove_file(&self.control_socket);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vmcell::config::{RootfsSource, VmConfig};

    /// The shared [`vmcell::metrics::FakeCgroupFs`], exposed by `vmcell`'s `test-support`
    /// feature (a dev-dependency of this crate). It replaces the hand-rolled per-crate
    /// `CgroupFs` fake this crate carried while `FakeCgroupFs` was `#[cfg(test)]`-only and
    /// therefore invisible downstream — one of four such copies (docs/81 §9). Most tests below
    /// exercise `create` capability guards that return **before** any cgroup interaction; the
    /// control-budget gate does reach `register_and_await_ready`, whose `add_task` this accepts.
    ///
    /// It is still structurally blind to the filesystem (AGENTS rule 4): it models slices,
    /// tasks and delegation in memory and writes no cgroup sysfs, so nothing driven by it is
    /// evidence about real cgroup residue or enforcement. That is the live `just test-crosvm`
    /// matrix.
    use vmcell::metrics::FakeCgroupFs;

    fn test_res() -> PerVmResources {
        PerVmResources {
            cgroup_name: "vmcell-test".to_string(),
            tap_name: Some("tap0".to_string()),
            netns_name: None,
            segment: None,
            vhost_user_socket: None,
            vmid: 1,
            guest_cid: 3,
            tmp_dir: PathBuf::from("/tmp/vmcell-vm-test-1"),
        }
    }

    fn erofs_cfg() -> VmConfig {
        VmConfig::builder(
            "/boot/vmlinux",
            RootfsSource::Erofs {
                image: PathBuf::from("/img/rootfs.erofs"),
            },
        )
        .build()
        .expect("build config")
    }

    // Guards the create-then-boot split and root-disk ordering: every crosvm launch must carry
    // `--suspended` (so boot()'s `resume` is the real start point) and emit the rootfs `--block`
    // FIRST so it enumerates as `/dev/vda` (what the cmdline boots from). The kernel is the trailing
    // positional argument. Inverse: dropping `--suspended` (create() runs the guest, boot() no-ops)
    // or ordering an extra disk before the rootfs (root shifts off vda) reddens here.
    #[test]
    fn crosvm_run_args_freeze_root_and_kernel_ordering() {
        let cfg = erofs_cfg();
        let res = test_res();
        let args = build_crosvm_run_args(
            &cfg,
            &res,
            Path::new("/tmp/vmcell-vm-test-1/crosvm.sock"),
            Path::new("/tmp/vmcell-vm-test-1/serial.log"),
            3,
            "console=ttyS0 root=/dev/vda",
            None,
        )
        .expect("build run args");

        assert!(
            args.iter().any(|a| a == "--suspended"),
            "crosvm must launch with --suspended so boot()'s resume is the real start point"
        );
        // A cold create carries no `--restore`.
        assert!(
            !args.iter().any(|a| a == "--restore"),
            "a cold create must not pass --restore"
        );
        assert!(
            args.iter().any(|a| a == "-s"),
            "control socket flag missing"
        );
        // `--suspended`/resume runs a device sleep/wake cycle; crosvm's default xhci USB controller
        // is not Suspendable and panics on wake, so `--no-usb` must drop it (validated live).
        assert!(
            args.iter().any(|a| a == "--no-usb"),
            "crosvm must pass --no-usb: the default xhci controller is not Suspendable and panics on \
             the --suspended → resume wake"
        );

        // The rootfs `--block` must be the FIRST block, read-only for EROFS.
        let block_idx = args
            .iter()
            .position(|a| a == "--block")
            .expect("a rootfs --block must be present");
        let block_spec = &args[block_idx + 1];
        assert!(
            block_spec.contains("rootfs.erofs") && block_spec.contains("ro=true"),
            "first --block must be the read-only rootfs (→ /dev/vda), got {block_spec}"
        );

        // The sandbox flag comes from `vmm_seccomp_args`, never from the run-args builder.
        assert!(
            !args.iter().any(|a| a == "--disable-sandbox"),
            "run-args builder must not hard-code the sandbox posture"
        );

        // The kernel image is the trailing positional argument.
        assert_eq!(
            args.last().map(String::as_str),
            Some("/boot/vmlinux"),
            "the kernel image must be the last positional argument"
        );
    }

    // One law, one predicate (§13): the `--block` that becomes `/dev/vda` names
    // `RootfsSource::effective_image` — the SAME predicate the config boundary's
    // duplicate-backing-file guard uses. They used to be separate copies of
    // `overlay.as_ref().unwrap_or(image)`, so a divergence would have let the guard protect a file
    // this argv does not attach. Expected values are recomputed THROUGH the helper, never a
    // test-local literal, and asserted on the COMPOSED argv. Buggy impl this guards: emitting the
    // base image while an overlay is set (guest writes land in the shared base) reddens the
    // overlay leg.
    #[test]
    fn crosvm_root_block_uses_the_effective_image_law() {
        let base = PathBuf::from("/img/base.raw");
        let overlay = PathBuf::from("/img/vm-7-overlay.raw");

        let run_args = |rootfs: RootfsSource| {
            let cfg = VmConfig::builder("/boot/vmlinux", rootfs)
                .build()
                .expect("build config");
            let args = build_crosvm_run_args(
                &cfg,
                &test_res(),
                Path::new("/tmp/c.sock"),
                Path::new("/tmp/s.log"),
                3,
                "root=/dev/vda",
                None,
            )
            .expect("build run args");
            // The FIRST `--block` value is the root disk (/dev/vda).
            let idx = args
                .iter()
                .position(|a| a == "--block")
                .expect("a rootfs --block must be present");
            (cfg, args[idx + 1].clone())
        };

        // Plain image: no overlay, so the base IS the effective image.
        let (plain_cfg, plain_spec) = run_args(RootfsSource::Block {
            image: base.clone(),
            overlay: None,
        });
        // `ro=true` is part of the expected string: the device's writability must not exceed the
        // mount's, and the mount is always `ro` (§4.7; `RootfsSource::root_device_read_only`).
        // Spelled as a literal rather than recomputed through the law, which would be vacuous now
        // that the composer reads it — this is the leg that reddens on the pre-delta-8 `Block`
        // arm, which emitted no `ro=true` at all.
        assert_eq!(
            plain_spec,
            format!(
                "path={},ro=true",
                plain_cfg.rootfs.effective_image().display()
            ),
            "the root --block must name the effective image and attach it READ-ONLY"
        );

        // Overlay set: the overlay backs /dev/vda, the base is never attached.
        let (ovl_cfg, ovl_spec) = run_args(RootfsSource::Block {
            image: base.clone(),
            overlay: Some(overlay),
        });
        assert_eq!(
            ovl_spec,
            format!(
                "path={},ro=true",
                ovl_cfg.rootfs.effective_image().display()
            ),
            "with an overlay set, the overlay backs /dev/vda — and it is a per-VM private COPY, \
             not a write target, so it is attached read-only too"
        );
        // Non-vacuous: the two paths genuinely differ.
        assert_ne!(
            ovl_cfg.rootfs.effective_image(),
            base,
            "the overlay case must not resolve to the base image"
        );

        // EROFS: the image itself, read-only.
        let (erofs_cfg, erofs_spec) = run_args(RootfsSource::Erofs {
            image: PathBuf::from("/img/rootfs.erofs"),
        });
        assert_eq!(
            erofs_spec,
            format!(
                "path={},ro=true",
                erofs_cfg.rootfs.effective_image().display()
            ),
            "an EROFS root is the image itself, read-only"
        );
    }

    // The tap MAC must match the shared `mac_math(vmid)` law (so the guest's derived identity lines
    // up with the other backends), and it rides the `--net tap-name=` device. Inverse: a hand-rolled
    // MAC or a missing `--net` reddens.
    #[test]
    fn crosvm_run_args_tap_uses_mac_math() {
        let cfg = erofs_cfg();
        let res = test_res();
        let args = build_crosvm_run_args(
            &cfg,
            &res,
            Path::new("/tmp/c.sock"),
            Path::new("/tmp/s.log"),
            3,
            "root=/dev/vda",
            None,
        )
        .expect("build run args");
        let net_idx = args
            .iter()
            .position(|a| a == "--net")
            .expect("a tap --net must be present when res.tap_name is set");
        let expected_mac = vmcell::net::mac_math(res.vmid).expect("mac");
        assert!(
            args[net_idx + 1].contains("tap-name=tap0")
                && args[net_idx + 1].contains(&format!("mac={expected_mac}")),
            "tap must carry tap-name and the mac_math MAC, got {}",
            args[net_idx + 1]
        );
    }

    // The restore path threads `--restore <snapshot>` into the SAME run args, still ending with the
    // kernel positional, and programs `--vsock cid=` from the `guest_cid` PARAMETER — which
    // `restore()` fills from the snapshot's BAKED CID sidecar, never from `res.guest_cid` (crosvm
    // rejects a rotated CID: "Virtio vsock incorrect cid for restore"; `restore_rotates_host_paths`
    // is false — the Firecracker pattern). The `7` below is that baked value, deliberately different
    // from `test_res().guest_cid` (3) so the assertion pins the parameter flow rather than passing
    // vacuously off the fresh `res`. Inverse: dropping `--restore`, emitting it after the kernel, or
    // sourcing the CID from `res` instead of the parameter reddens.
    #[test]
    fn crosvm_run_args_restore_emits_restore_flag() {
        let cfg = erofs_cfg();
        let res = test_res();
        let args = build_crosvm_run_args(
            &cfg,
            &res,
            Path::new("/tmp/c.sock"),
            Path::new("/tmp/s.log"),
            7,
            "root=/dev/vda",
            Some(Path::new("/snap/crosvm-snapshot")),
        )
        .expect("build restore run args");
        let restore_idx = args
            .iter()
            .position(|a| a == "--restore")
            .expect("restore must pass --restore");
        assert_eq!(args[restore_idx + 1], "/snap/crosvm-snapshot");
        // The baked CID rides `--vsock cid=<guest_cid param>`; `res.guest_cid` (3) must NOT leak in.
        assert!(
            args.iter().any(|a| a == "cid=7"),
            "restore must program the snapshot's baked guest CID on --vsock, not res.guest_cid"
        );
        assert_eq!(
            args.last().map(String::as_str),
            Some("/boot/vmlinux"),
            "the kernel image must still be the trailing positional argument on restore"
        );
    }

    // The `--serial hardware=` token must track `cfg.console_mode` in lockstep with the cmdline
    // `console=` token. Inverse: a fixed hardware= (or swapped mapping) sinks one mode's console.
    #[test]
    fn serial_arg_selects_hardware_per_console_mode() {
        assert!(serial_arg(ConsoleMode::Uart, Path::new("/s.log")).contains("hardware=serial"));
        assert!(
            serial_arg(ConsoleMode::VirtioConsole, Path::new("/s.log"))
                .contains("hardware=virtio-console")
        );
    }

    // The control socket is a positional argument BEFORE any trailing flags (`crosvm <subcmd>
    // <socket> [flags]`), the one spelling every control op shares. The boot resume needs `--full`
    // (the `--suspended` launch is a full device+vCPU suspend, so a plain resume errors "Trying to
    // wake Vcpus while Devices are asleep" — validated live). Inverse: a `--socket <path>` form, a
    // dropped socket, or a `--full` placed before the socket reddens.
    #[test]
    fn crosvm_control_args_positional_socket_then_flags() {
        assert_eq!(
            crosvm_control_args("suspend", Path::new("/run/crosvm.sock"), &[]),
            vec!["suspend".to_string(), "/run/crosvm.sock".to_string()]
        );
        assert_eq!(
            crosvm_control_args("resume", Path::new("/run/crosvm.sock"), &["--full"]),
            vec![
                "resume".to_string(),
                "/run/crosvm.sock".to_string(),
                "--full".to_string()
            ],
            "socket must be positional BEFORE --full (crosvm resume <VM_SOCKET> [--full])"
        );
    }

    // The capability-honesty gate (mirrors CH/FC/QEMU's): every crosvm capability is the empirically
    // validated value. Any deliberate re-gate must flip the flag AND this test together (AGENTS.md
    // rule 5: a capability change re-validates empirically). KVM-free.
    #[test]
    fn capabilities_are_honest_for_crosvm() {
        let caps = Crosvm::new("crosvm").capabilities();
        assert!(
            caps.snapshot_restore,
            "crosvm snapshot/restore is KVM-validated ON (snapshot take + run --restore over the \
             virtio device set, USB dropped via --no-usb)"
        );
        assert!(!caps.lazy_restore, "no UFFD/demand-paged restore backend");
        assert!(
            !caps.virtio_fs_shares,
            "crosvm --shared-dir is unvalidated here — honest-false"
        );
        assert!(
            !caps.unprivileged_vhost_user_net,
            "crosvm unprivileged vhost-user-net is unvalidated here — honest-false"
        );
        assert!(
            !caps.nested_virt,
            "crosvm documents no nested KVM — a hard false"
        );
        assert!(
            caps.virtio_console,
            "crosvm has --serial hardware=virtio-console (hvc0)"
        );
        assert!(
            !caps.restore_rotates_host_paths,
            "crosvm bakes the vsock CID into the snapshot and requires the SAME CID on restore \
             (validated: rotating it fails 'Virtio vsock incorrect cid for restore'), so restore \
             reuses the baked CID — the Firecracker pattern, NOT QEMU's rotation (§2.5)"
        );
        assert!(
            !caps.disk_io_throttle,
            "crosvm --block has no bandwidth/iops key — honest-false"
        );
        assert!(
            !caps.usb_host_passthrough,
            "vmcell always launches crosvm with --no-usb (its xhci is not Suspendable, §2.5), so \
             there is no bus to attach a host device to — honest-false; a true would silently \
             drop the requested device"
        );
    }

    // Guards N-VMM-1: the Unsupported.feature string for unprivileged networking must match the
    // VmmCapabilities field name (`unprivileged_vhost_user_net`). KVM-free — create() rejects before
    // spawning. Inverse: a spawn-anyway or a mismatched feature string reddens.
    #[tokio::test]
    async fn create_rejects_unprivileged_net_with_capability_field_name() {
        use vmcell::config::{Egress, NetConfig};
        let crosvm = Crosvm::new("/usr/bin/crosvm");
        let cfg = VmConfig::builder(
            "/k",
            RootfsSource::Erofs {
                image: PathBuf::from("/i"),
            },
        )
        .net(NetConfig::Unprivileged {
            egress: Egress::Open,
            host_services_port: None,
        })
        .build()
        .expect("build config");
        let res = PerVmResources {
            tap_name: None,
            ..test_res()
        };
        let err = crosvm
            .create(&cfg, &res, &FakeCgroupFs::new())
            .await
            .expect_err("unprivileged net must be Unsupported on crosvm v1");
        assert!(
            matches!(&err, Error::Unsupported { vmm, feature }
                if vmm == "crosvm" && feature == "unprivileged_vhost_user_net"),
            "expected an unprivileged_vhost_user_net Unsupported, got {err:?}"
        );
    }

    // Restore fails loud BEFORE spawning when the snapshot artifact is missing — a bad snapshot dir
    // surfaces as a clear typed `Vmm` error, not an opaque `crosvm run --restore` failure. KVM-free
    // (the existence check precedes any spawn). Inverse: checking after spawning would need KVM and
    // lose this clean pre-spawn error.
    #[tokio::test]
    async fn restore_checks_snapshot_file_before_spawning() {
        let crosvm = Crosvm::new("/usr/bin/crosvm");
        let cfg = erofs_cfg();
        let err = crosvm
            .restore(
                Path::new("/nonexistent-crosvm-snapshot-dir"),
                &cfg,
                &test_res(),
                &FakeCgroupFs::new(),
            )
            .await
            .expect_err(
                "crosvm restore with a missing snapshot artifact must fail before spawning",
            );
        assert!(
            matches!(&err, Error::Vmm(msg) if msg.contains("snapshot artifact") && msg.contains("missing")),
            "expected a missing-snapshot-artifact Vmm error, got {err:?}"
        );
    }

    // The baked-CID sidecar IS the crosvm snapshot/restore contract: crosvm bakes the CID into the
    // vsock device state and rejects a mismatched `--vsock cid=` on restore, so a writer and a reader
    // that disagree produce snapshots that only fail on a live boot. Nothing drove either half — not
    // the format, not either error arm (docs/90 `vmcell-crosvm:833`). KVM-free: both halves are file
    // I/O in the pre-spawn prologue.
    // Inverse: emit anything but bare decimal from the writer (`format!("cid={cid}")`) and the
    // round-trip + on-disk-bytes asserts redden; drop the `.trim()` and the newline leg reddens;
    // downgrade either arm to `Error::Io` and its typed assert reddens.
    #[tokio::test]
    async fn the_baked_cid_sidecar_round_trips_and_both_error_arms_are_typed() {
        let dir = tempfile::tempdir().expect("create snapshot dir");

        // The format contract, both directions: bare decimal text, byte-for-byte.
        write_baked_cid(dir.path(), 42)
            .await
            .expect("write sidecar");
        assert_eq!(
            tokio::fs::read_to_string(dir.path().join(HOST_CID_SIDECAR))
                .await
                .expect("read sidecar back"),
            "42",
            "the sidecar is bare decimal text: a key=value or JSON spelling breaks every restore"
        );
        assert_eq!(
            read_baked_cid(dir.path()).await.expect("parse sidecar"),
            42,
            "restore must reprogram the CID `snapshot()` baked, not the fresh allocation"
        );

        // A line-terminated sidecar (a human or an external tool rewrote it) still parses.
        tokio::fs::write(dir.path().join(HOST_CID_SIDECAR), "7\n")
            .await
            .expect("rewrite sidecar with a trailing newline");
        assert_eq!(
            read_baked_cid(dir.path()).await.expect("parse trimmed"),
            7,
            "a trailing newline is not corruption"
        );

        // Arm 1: garbled contents — a typed, fail-loud pre-spawn refusal.
        tokio::fs::write(dir.path().join(HOST_CID_SIDECAR), "cid=3")
            .await
            .expect("corrupt the sidecar");
        let err = read_baked_cid(dir.path())
            .await
            .expect_err("a non-numeric sidecar must be refused");
        assert!(
            matches!(&err, Error::Vmm(msg) if msg.contains("not a valid CID")),
            "expected a typed not-a-CID Vmm error, got {err:?}"
        );

        // Arm 2: absent sidecar — names the path, so the operator sees WHICH dir is not a snapshot.
        let empty = tempfile::tempdir().expect("create empty dir");
        let err = read_baked_cid(empty.path())
            .await
            .expect_err("a missing sidecar must be refused");
        assert!(
            matches!(&err, Error::Vmm(msg)
                if msg.contains(HOST_CID_SIDECAR) && msg.contains("missing/unreadable")),
            "expected a typed missing-sidecar Vmm error naming the path, got {err:?}"
        );
    }

    // Guards M10 — crosvm's ONLY seccomp confinement. crosvm always runs `--disable-sandbox`, so the
    // Layer-2 deny-list is the whole filter, and the `Enforcing → seccomp_deny_list = true` flip used
    // to live inline in `spawn` where deleting it left every KVM-free gate AND the entire live
    // `test-crosvm` matrix green (a silently unconfined VMM). Pins BOTH directions of the pure
    // mapping. KVM-free. Inverse: dropping the flip reddens the Enforcing assertion; force-clearing
    // the flag on `Disabled` reddens the operator-opt-in assertion; touching any other jail field
    // reddens the totality assertion.
    #[test]
    fn effective_jail_config_turns_the_deny_list_on_only_for_enforcing() {
        use vmcell::config::{JailConfig, VmmSeccomp};

        let cfg = |seccomp: VmmSeccomp, jail: JailConfig| {
            VmConfig::builder(
                "/boot/vmlinux",
                RootfsSource::Erofs {
                    image: PathBuf::from("/img/rootfs.erofs"),
                },
            )
            .vmm_seccomp(seccomp)
            .jail(jail)
            .build()
            .expect("build config")
        };

        // Enforcing: the deny-list is turned ON even though `hardened()` ships it off — this IS
        // crosvm's seccomp filter, so `Enforcing` may never leave the VMM unconfined.
        let hardened = JailConfig::hardened();
        assert!(
            !hardened.seccomp_deny_list,
            "precondition: the hardened default ships the deny-list OFF (the other backends carry \
             their own native filter)"
        );
        let enforcing = effective_jail_config(&cfg(VmmSeccomp::Enforcing, hardened));
        assert!(
            enforcing.seccomp_deny_list,
            "crosvm Enforcing must turn the Layer-2 deny-list ON: --disable-sandbox is always \
             passed, so without it the VMM runs with NO seccomp filter at all"
        );

        // Disabled (the loud opt-out): the requested posture is passed through untouched — off stays
        // off …
        let disabled = effective_jail_config(&cfg(VmmSeccomp::Disabled, hardened));
        assert!(
            !disabled.seccomp_deny_list,
            "crosvm Disabled must not silently re-enable the deny-list — the opt-out is deliberate"
        );
        // … and an operator who explicitly asked for Layer 2 keeps it (the flip is one-way).
        let mut opted_in = JailConfig::hardened();
        opted_in.seccomp_deny_list = true;
        assert!(
            effective_jail_config(&cfg(VmmSeccomp::Disabled, opted_in)).seccomp_deny_list,
            "an explicitly requested deny-list must survive VmmSeccomp::Disabled"
        );

        // Totality: `seccomp_deny_list` is the ONLY field the mapping touches, so the rest of the
        // operator's jail posture reaches `apply_jail` verbatim.
        let mut expected = hardened;
        expected.seccomp_deny_list = true;
        assert_eq!(
            enforcing, expected,
            "effective_jail_config must change seccomp_deny_list and nothing else"
        );
    }

    // Guards the B3 capability self-guard crosvm's rustdoc claimed but never had: `snapshot()` must
    // consult the captured `snapshot_restore` capability *and* the S1 vhost-user law. KVM-free — the
    // live matrix can never reach the false branch (the descriptor ships `snapshot_restore: true`),
    // which is exactly why the guard needs a unit gate. Inverse: a `snapshot()` that ignores the
    // descriptor reddens the first assertion; one that ignores the device law reddens the second.
    #[test]
    fn snapshot_precheck_enforces_capability_and_law() {
        // Backend that does not advertise snapshot_restore, even with a clean VM. The backend is
        // the remover, so the refusal is the bare capability form: `vmm` is the plain backend id.
        let err = snapshot_precheck(false, false).expect_err("incapable backend must error");
        assert!(
            matches!(&err, Error::Unsupported { vmm, feature }
                if vmm == "crosvm" && feature == Feature::SnapshotRestore.name()),
            "expected a snapshot_restore Unsupported naming the VmmCapabilities field, got {err:?}"
        );

        // Capable backend, but the VM carries a vhost-user device. F6 retired the
        // `feature.contains("vhost-user")` matcher along with the prose it matched: this leg now
        // spells the SAME `snapshot_restore` as the one above, so the exact feature comparison is
        // paired with the shared const's identity — composed through the one composer, never
        // hand-spelled, so editing the const moves both sides together. Without that pairing the
        // two legs would be indistinguishable and this assertion would be vacuous.
        let err = snapshot_precheck(true, true).expect_err("vhost-user VM must error");
        assert!(
            matches!(&err, Error::Unsupported { feature, .. }
                if feature == Feature::SnapshotRestore.name()),
            "the feature string must be Feature::name() by construction (F6), got {err:?}"
        );
        assert_eq!(
            err.to_string(),
            Error::from_removal("crosvm", &VHOST_USER_BLOCKS_SNAPSHOT).to_string(),
            "the S1 leg must be THIS removal — the capability leg above spells the same feature, \
             so the Removal's provenance is what separates them: {err:?}"
        );

        // Capable backend, snapshot-eligible VM: allowed (the positive control — the guard refuses
        // for a reason, not always). It is load-bearing for both refusals above now that they share
        // one feature string: "refused" is only evidence against a control the guard accepts.
        assert!(snapshot_precheck(true, false).is_ok());
    }

    // Guards M4's crosvm half: an `io_limit` that `create()` refuses must also be refused by
    // `restore()`, which otherwise builds the same run args with the limit silently dropped. KVM-free
    // (the rejection precedes the snapshot-artifact check and any spawn) and non-vacuous: the
    // snapshot dir does not exist, so an unguarded restore reaches the missing-artifact `Vmm` error
    // instead — which is precisely what this asserts it does NOT get. Inverse: deleting the
    // `reject_disk_io_throttle(cfg)?` call in `restore()` reddens here.
    #[tokio::test]
    async fn restore_rejects_disk_io_throttle_like_create() {
        use vmcell::config::{BlockDevice, DiskIoLimit};

        let crosvm = Crosvm::new("/usr/bin/crosvm");
        let cfg = VmConfig::builder(
            "/boot/vmlinux",
            RootfsSource::Erofs {
                image: PathBuf::from("/img/rootfs.erofs"),
            },
        )
        .with_extra_disk(
            BlockDevice::read_only("/img/data.raw")
                .with_io_limit(DiskIoLimit::bandwidth(2_000_000)),
        )
        .build()
        .expect("build config");

        let err = crosvm
            .restore(
                Path::new("/nonexistent-crosvm-snapshot-dir"),
                &cfg,
                &test_res(),
                &FakeCgroupFs::new(),
            )
            .await
            .expect_err("a throttled disk must be refused on restore, exactly as on create");
        assert!(
            matches!(&err, Error::Unsupported { vmm, feature }
                if vmm == "crosvm" && feature == "disk_io_throttle"),
            "expected a disk_io_throttle Unsupported (the VmmCapabilities field name, N-VMM-1), got \
             {err:?}"
        );

        // Positive control: the SAME restore without the throttle gets past this guard and fails on
        // the missing snapshot artifact — so the refusal above is about the io_limit, not about
        // restore refusing everything.
        let err = crosvm
            .restore(
                Path::new("/nonexistent-crosvm-snapshot-dir"),
                &erofs_cfg(),
                &test_res(),
                &FakeCgroupFs::new(),
            )
            .await
            .expect_err("the control path still fails on the missing snapshot artifact");
        assert!(
            matches!(&err, Error::Vmm(msg) if msg.contains("snapshot artifact")),
            "expected the un-throttled control to reach the missing-artifact error, got {err:?}"
        );
    }

    // docs/90 A3 (the open half of docs/78 M4), crosvm leg — the sibling of
    // `restore_rejects_disk_io_throttle_like_create`: vmcell always launches crosvm with
    // `--no-usb`, so `create()` refuses a host-USB config through the shared predicate, while
    // `restore()` accepted the same list and dropped it silently. KVM-free: the refusal precedes
    // the snapshot-artifact check and any spawn, which is what the positive control proves.
    //
    // Red on the inverse: delete the `reject_usb_host_devices_on_restore` call from `restore()`
    // and the restore leg reaches the missing-artifact `Vmm` error instead of the typed refusal.
    #[tokio::test]
    async fn restore_refuses_a_host_usb_config_exactly_as_create_does() {
        let crosvm = Crosvm::new("/usr/bin/crosvm");
        let usb_cfg = VmConfig::builder(
            "/boot/vmlinux",
            RootfsSource::Erofs {
                image: PathBuf::from("/img/rootfs.erofs"),
            },
        )
        .with_usb_host_device(vmcell::config::UsbHostDevice::new(0xdead, 0xbeef))
        // Keeps crosvm's net guard (which runs before the USB one on create) from deciding the
        // outcome, so both legs are about USB and nothing else.
        .network_disabled()
        .build()
        .expect("a host-USB device on a non-snapshotting config must build");

        let created = crosvm
            .create(&usb_cfg, &test_res(), &FakeCgroupFs::new())
            .await
            .expect_err("crosvm advertises usb_host_passthrough: false");
        let restored = crosvm
            .restore(
                Path::new("/nonexistent-crosvm-usb-snapshot"),
                &usb_cfg,
                &test_res(),
                &FakeCgroupFs::new(),
            )
            .await
            .expect_err("restore must refuse exactly what create refuses");
        for err in [&created, &restored] {
            assert!(
                matches!(err, Error::Unsupported { vmm, feature }
                    if vmm == "crosvm" && feature == Feature::UsbHostPassthrough.name()),
                "expected a usb_host_passthrough Unsupported naming the VmmCapabilities field \
                 (N-VMM-1), got {err:?}"
            );
        }
        assert_eq!(
            created.to_string(),
            restored.to_string(),
            "an incapable backend owes the restore path the IDENTICAL refusal its create path \
             gives — the descriptor arm of the shared predicate, not a second spelling"
        );

        // Positive control: the SAME restore without the device gets past this guard and fails on
        // the missing snapshot artifact — so the refusal above is about the device, not about
        // restore refusing everything.
        let err = crosvm
            .restore(
                Path::new("/nonexistent-crosvm-usb-snapshot"),
                &erofs_cfg(),
                &test_res(),
                &FakeCgroupFs::new(),
            )
            .await
            .expect_err("the control still fails on the missing snapshot artifact");
        assert!(
            matches!(&err, Error::Vmm(msg) if msg.contains("snapshot artifact")),
            "expected the un-throttled control to reach the missing-artifact error, got {err:?}"
        );
    }

    /// Writes an executable stand-in for the `crosvm` binary into `dir` and returns its path.
    ///
    /// Launched as `run …`, it creates the control socket path the readiness gate polls for (`-s
    /// <path>`) and then **wedges** (`exec sleep`, so the wedge IS the process the pgid names and a
    /// SIGKILL to the group reclaims it — no orphan sleep). Re-invoked as a control client
    /// (`resume`/`powerbtn`/`stop`/`snapshot take`) it carries no `-s` pair and wedges immediately:
    /// exactly what a hung crosvm presents to its short-lived client, and the only shape that can
    /// prove the control budget bounds the wait. KVM-free and crosvm-binary-free.
    fn wedged_crosvm_stand_in(dir: &Path) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let script = dir.join("crosvm-stand-in.sh");
        std::fs::write(
            &script,
            "#!/bin/sh\n\
             while [ $# -gt 0 ]; do\n\
             \x20 if [ \"$1\" = \"-s\" ]; then : > \"$2\"; fi\n\
             \x20 shift\n\
             done\n\
             exec sleep 600\n",
        )
        .expect("write the crosvm stand-in");
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755))
            .expect("make the crosvm stand-in executable");
        script
    }

    // M5 GATE (KVM-free, crosvm-free): EVERY crosvm control op is bounded by the ONE named
    // `CROSVM_CONTROL_BUDGET`. `run_control` and `snapshot_take` were a bare `status().await`, so
    // `boot()`, `request_shutdown()`, `pause()`, `resume()` and `snapshot()` hung forever against a
    // wedged VMM — and because `shutdown()` awaits `request_shutdown()` BEFORE the grace poll and
    // before the guaranteed `kill()`, one wedged `powerbtn` blocked the force-kill that is supposed
    // to be unconditional, leaking the VM's netns/tap/cgroup/scratch/vmid.
    //
    // Driven through the REAL `create()` so the chain under test is the shipped one (backend budget
    // → instance → every control invocation), against a stand-in binary that wedges. RED on the
    // inverse (drop either `timeout` wrapper): the call never returns and the wall-clock GUARD — 30×
    // the budget — fires with a naming panic instead of hanging the suite.
    //
    // What the stand-in structurally cannot see: that a REAL `crosvm resume|powerbtn|snapshot take`
    // succeeds inside the budget. That is the live `just test-crosvm` matrix (boot, snapshot,
    // restore), which is where the shipped `CROSVM_CONTROL_BUDGET` value — as opposed to the bound
    // itself — is exercised.
    #[tokio::test]
    async fn crosvm_control_ops_are_bounded_by_the_control_budget() {
        const BUDGET: Duration = Duration::from_millis(300);
        // Deliberately different from BUDGET: the typed elapse renders the budget it timed out
        // against, so the two are told apart by the assertions below.
        const SNAPSHOT_BUDGET: Duration = Duration::from_millis(700);
        const GUARD: Duration = Duration::from_secs(9);

        let dir = tempfile::tempdir().expect("tempdir");
        let script = wedged_crosvm_stand_in(dir.path());

        let mut crosvm = Crosvm::new(&script);
        // The shipped default is the one named const — `new` invents no literal of its own.
        assert_eq!(
            crosvm.control_budget, CROSVM_CONTROL_BUDGET,
            "Crosvm::new must seed the control budget from CROSVM_CONTROL_BUDGET"
        );
        // Shrink it for the gate (the QEMU migration-budget gate's shape): the law under test is
        // that the budget bounds the wait, not its shipped value.
        crosvm.control_budget = BUDGET;

        let res = PerVmResources {
            tap_name: None,
            tmp_dir: dir.path().to_path_buf(),
            ..test_res()
        };
        let mut inst = crosvm
            .create(&erofs_cfg(), &res, &FakeCgroupFs::new())
            .await
            .expect("the stand-in binds its control socket, so create() reaches a live instance");
        // `snapshot take` rides the SEPARATE, guest-RAM-proportional `snapshot_budget` (M6), whose
        // shipped floor is seconds. Shrink it too — but to a DIFFERENT, distinguishable value, so
        // this gate also proves WHICH budget each op is bounded by. The typed elapse renders the
        // budget it timed out against, so a `snapshot take` that silently fell back to
        // `control_budget` names 300ms instead of 700ms and reddens. (Asserting only that the field
        // is seeded correctly would be a gate on the field, not on the call — the M6 gate does that
        // half; this is the other half.)
        inst.snapshot_budget = SNAPSHOT_BUDGET;
        assert_ne!(
            BUDGET, SNAPSHOT_BUDGET,
            "the two budgets must be distinguishable or this gate cannot tell them apart"
        );

        // Every op a caller can wedge on, with the subcommand each must name in its typed error and
        // the budget each must be bounded by. `boot()` and `resume()` are distinct call sites of
        // `run_control`; `snapshot take` is the second, separately-wrapped client invocation, and
        // the ONLY one on the snapshot budget.
        let legs: [(&str, &str, Duration); 4] = [
            ("boot", "resume", BUDGET),
            ("request_shutdown", "powerbtn", BUDGET),
            ("resume", "resume", BUDGET),
            ("snapshot_take", "snapshot take", SNAPSHOT_BUDGET),
        ];
        for (op, subcmd, budget) in legs {
            let result = match op {
                "boot" => tokio::time::timeout(GUARD, inst.boot()).await,
                "request_shutdown" => tokio::time::timeout(GUARD, inst.request_shutdown()).await,
                "resume" => tokio::time::timeout(GUARD, inst.resume()).await,
                _ => {
                    tokio::time::timeout(GUARD, inst.snapshot_take(&dir.path().join("snap"))).await
                }
            };
            let result = result.unwrap_or_else(|_| {
                panic!(
                    "M5: {op}() hung past its {budget:?} budget against a wedged crosvm client — \
                     `crosvm {subcmd}` is unbounded"
                )
            });
            let err = result.expect_err("a wedged control client must surface a typed error");
            let rendered = format!("{budget:?}");
            assert!(
                matches!(&err, Error::Timeout(msg)
                    if msg.contains(subcmd)
                        && msg.contains("control command")
                        && msg.contains(&rendered)),
                "M5/M6: expected a typed Timeout naming `{subcmd}` and its {budget:?} budget, \
                 got {err:?}"
            );
        }

        // `kill()` carries no budget literal of its own: its graceful `stop` rides the same bound,
        // so the guaranteed SIGKILL is reached — the property a wedged `powerbtn` used to block.
        tokio::time::timeout(GUARD, inst.kill())
            .await
            .expect("M5: kill() must not be blocked by a wedged graceful stop")
            .expect("kill() force-kills the group and reaps");
    }

    // Guards d7's crosvm half: the two capability fields that are advertised FALSE and were
    // nevertheless accepted. `nested_virt` is the sharper one — the SHARED `build_kernel_cmdline`
    // emits `kvm-intel.nested=1` for every backend, so the request read as applied while crosvm
    // exposes no guest `/dev/kvm` at all; `RestoreMode::Lazy` silently degraded to eager. Both now
    // refuse like the three sibling flags, with the `VmmCapabilities` field name as the feature
    // string (N-VMM-1). KVM-free: the refusal precedes any spawn. Inverse: deleting either branch
    // reddens, and the positive control keeps the assertions honest — the SAME config with the
    // levers at their advertised values gets past the guard and dies on the missing binary.
    #[tokio::test]
    async fn create_rejects_the_unadvertised_nested_virt_and_lazy_restore_levers() {
        use vmcell::config::RestoreMode;

        let crosvm = Crosvm::new("/nonexistent-crosvm-binary");
        let cfg = |nested: bool, mode: RestoreMode| {
            VmConfig::builder(
                "/boot/vmlinux",
                RootfsSource::Erofs {
                    image: PathBuf::from("/img/rootfs.erofs"),
                },
            )
            .nested_virt(nested)
            .restore_mode(mode)
            .build()
            .expect("build config")
        };

        let err = crosvm
            .create(
                &cfg(true, RestoreMode::Default),
                &test_res(),
                &FakeCgroupFs::new(),
            )
            .await
            .expect_err(
                "nested_virt is advertised false and must be refused, not silently dropped",
            );
        assert!(
            matches!(&err, Error::Unsupported { vmm, feature }
                if vmm == "crosvm" && feature == "nested_virt"),
            "expected a nested_virt Unsupported naming the VmmCapabilities field, got {err:?}"
        );

        let err = crosvm
            .create(
                &cfg(false, RestoreMode::Lazy),
                &test_res(),
                &FakeCgroupFs::new(),
            )
            .await
            .expect_err("lazy_restore is advertised false and must be refused");
        assert!(
            matches!(&err, Error::Unsupported { vmm, feature }
                if vmm == "crosvm" && feature == "lazy_restore"),
            "expected a lazy_restore Unsupported naming the VmmCapabilities field, got {err:?}"
        );

        // Positive control: the advertised values pass the guard and reach the spawn, which fails
        // on the absent binary — so the refusals above are about these two levers, not about
        // `create()` refusing everything.
        let err = crosvm
            .create(
                &cfg(false, RestoreMode::Eager),
                &test_res(),
                &FakeCgroupFs::new(),
            )
            .await
            .expect_err("the stand-in binary does not exist");
        assert!(
            matches!(&err, Error::Io(_)),
            "expected the control config to reach the spawn (an Io error), got {err:?}"
        );

        // `restore()` refuses exactly what `create()` refuses — the M4 law, applied to the field a
        // restore actually consumes. Non-vacuous: the snapshot dir does not exist, so an unguarded
        // restore would reach the missing-artifact `Vmm` error instead.
        let err = crosvm
            .restore(
                Path::new("/nonexistent-crosvm-snapshot-dir"),
                &cfg(false, RestoreMode::Lazy),
                &test_res(),
                &FakeCgroupFs::new(),
            )
            .await
            .expect_err("a lazy restore must be refused on restore(), exactly as on create()");
        assert!(
            matches!(&err, Error::Unsupported { vmm, feature }
                if vmm == "crosvm" && feature == "lazy_restore"),
            "expected a lazy_restore Unsupported from restore(), got {err:?}"
        );
    }

    // M6 GATE (KVM-free): the guest-RAM-proportional `crosvm snapshot take` must NOT ride the flat
    // control budget every other control op does — a 4 GiB guest's suspend image is ~4 GB of dense
    // writes, which a 10 s ceiling overruns by construction, and a spurious Timeout mid-take leaves
    // the VM fully suspended with a half-written image. Driven through the REAL `create()`, so what
    // is asserted is the SHIPPED seeding, not a helper's arithmetic.
    //
    // Inverses, both observed red: (a) seed `snapshot_budget` from `self.control_budget` alone and
    // the large/small strict inequality fails; (b) seed `control_budget` from
    // `snapshot_request_timeout` too — collapsing the two — and the "ordinary ops keep the short
    // budget" assert fails.
    #[tokio::test]
    async fn snapshot_budget_grows_with_guest_ram_over_the_control_budget() {
        let dir = tempfile::tempdir().expect("tempdir");
        let script = wedged_crosvm_stand_in(dir.path());
        let crosvm = Crosvm::new(&script);

        let instance_with_mem = async |mem_mib: u32, leg: &str| {
            let cfg = VmConfig::builder(
                "/boot/vmlinux",
                RootfsSource::Erofs {
                    image: PathBuf::from("/img/rootfs.erofs"),
                },
            )
            .mem_mib(mem_mib)
            .build()
            .expect("build config");
            let res = PerVmResources {
                tap_name: None,
                tmp_dir: dir.path().join(leg),
                ..test_res()
            };
            std::fs::create_dir_all(&res.tmp_dir).expect("per-VM dir");
            crosvm
                .create(&cfg, &res, &FakeCgroupFs::new())
                .await
                .expect("the stand-in binds its control socket")
        };

        let small = instance_with_mem(128, "small").await;
        let large = instance_with_mem(32 * 1024, "large").await;

        assert!(
            large.snapshot_budget > small.snapshot_budget,
            "a 32 GiB guest must get MORE snapshot budget than a 128 MiB one: {:?} vs {:?}",
            large.snapshot_budget,
            small.snapshot_budget
        );
        // The guest-RAM term is the SHARED predicate's, not a local re-derivation.
        assert_eq!(
            large.snapshot_budget,
            vmcell::vmm::snapshot_request_timeout(32 * 1024),
            "above the floor the snapshot budget IS the shared predicate"
        );
        // …and this backend's flat control budget still holds underneath it.
        assert_eq!(
            small.snapshot_budget, CROSVM_CONTROL_BUDGET,
            "below the floor the snapshot budget is the flat control budget"
        );
        // The two must NOT be collapsed: an ordinary control op keeps the short bound, because
        // `shutdown()` awaits a `powerbtn` BEFORE the guaranteed force-kill.
        assert_eq!(
            large.control_budget, CROSVM_CONTROL_BUDGET,
            "a large guest must not widen the ordinary control budget — only the snapshot one"
        );
    }

    // POSITIVE CONTROL for the gate above, and the gate on `Drop`'s OWN job: an instance whose
    // group has NOT been reaped must have its process group SIGKILLed + reaped when it is dropped
    // (L1 — `Drop` is the panic path of the one teardown order). Without this leg the
    // "must not signal a recycled pgid" assertion is satisfied by a `Drop` that reaps NOTHING —
    // which is precisely the regression the crosvm consolidation introduced and this leg caught: a
    // dropped-but-never-killed VM would leak its whole process group.
    //
    // Inverse (observed red): delete `self.group.reap_now(&mut self.process)` from `Drop` and the
    // stand-in survives, so `gone` stays false.
    #[tokio::test]
    async fn drop_reaps_an_unreaped_process_group() {
        let dir = tempfile::tempdir().expect("tempdir");
        let standin = {
            let mut c = std::process::Command::new("sleep");
            c.arg("60");
            use std::os::unix::process::CommandExt;
            c.process_group(0);
            tokio::process::Command::from(c)
                .spawn()
                .expect("spawn stand-in VMM")
        };
        let live_pid = standin.id().expect("stand-in pid") as i32;
        let inst = CrosvmInstance {
            group: vmcell::vmm::VmmProcessGroup::new(standin.id()),
            process: standin,
            binary_path: dir.path().join("absent-crosvm"),
            control_budget: Duration::from_millis(50),
            snapshot_budget: Duration::from_millis(50),
            control_socket: dir.path().join("crosvm.sock"),
            vsock_path: PathBuf::new(),
            serial_path: PathBuf::new(),
            cid: 3,
            restored: false,
            has_vhost_user_device: false,
            snapshot_restore_capable: true,
            // Through the composer, not a hand-written literal, for the reason every `naming` call
            // in a test goes through the library: a second spelling of the law is a second law.
            endpoint: steward_endpoint(3, vmcell::config::StewardPlacement::Pid1),
        };
        drop(inst);

        let mut gone = false;
        for _ in 0..100 {
            if nix::sys::signal::kill(nix::unistd::Pid::from_raw(live_pid), None).is_err() {
                gone = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        // Best-effort cleanup if the drop did NOT reap, so a red run leaves no stray process.
        let _ = nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(-live_pid),
            nix::sys::signal::Signal::SIGKILL,
        );
        assert!(
            gone,
            "Drop on an UN-reaped instance must SIGKILL and reap its VMM process group"
        );
    }

    // M-VMM-1 GATE (KVM-free) on the SHIPPED call sites, not on the extracted helper: once the
    // crosvm leader is reaped its pgid can be recycled, so neither `CrosvmInstance::kill` NOR its
    // `Drop` may SIGKILL `-pgid`. A live decoy in its own process group stands in for that recycled
    // group, and BOTH teardown paths are driven against the same already-reaped instance. crosvm had
    // no such gate before (CH and FC did) — it is one of the copies §9 found.
    //
    // Inverse (observed red): replace `self.group.kill_and_wait(&mut self.process).await` in `kill`
    // — or `self.group.reap_now(&mut self.process)` in `Drop` — with an unguarded
    // `vmcell::vmm::reap_process_group(&mut self.process, Some(decoy))`, and the decoy dies.
    #[tokio::test]
    async fn kill_and_drop_do_not_signal_pgid_when_reaped() {
        let mut decoy = {
            let mut c = std::process::Command::new("sleep");
            c.arg("60");
            use std::os::unix::process::CommandExt;
            c.process_group(0);
            tokio::process::Command::from(c)
                .spawn()
                .expect("spawn decoy")
        };
        let decoy_pid = decoy.id().expect("decoy pid") as i32;

        // A fast-exiting child as the instance's own leader so `kill()`'s `process.wait()` returns
        // promptly instead of blocking on a live process.
        let leader = tokio::process::Command::new("true")
            .spawn()
            .expect("spawn `true` leader");
        let dir = tempfile::tempdir().expect("tempdir");
        let mut inst = CrosvmInstance {
            process: leader,
            // An absent binary: `kill()`'s best-effort graceful `stop` fails fast and is logged,
            // never fatal — the reap path below is what is under test.
            binary_path: dir.path().join("absent-crosvm"),
            control_budget: Duration::from_millis(50),
            snapshot_budget: Duration::from_millis(50),
            control_socket: dir.path().join("crosvm.sock"),
            vsock_path: PathBuf::new(),
            serial_path: PathBuf::new(),
            cid: 3,
            // The recycled-pgid state, which only the `test-support` constructor can fabricate:
            // no production path can mark a group reaped over a foreign pgid.
            group: vmcell::vmm::VmmProcessGroup::already_reaped_for_test(Some(decoy_pid as u32)),
            restored: false,
            has_vhost_user_device: false,
            snapshot_restore_capable: true,
            endpoint: steward_endpoint(3, vmcell::config::StewardPlacement::Pid1),
        };
        inst.kill().await.expect("kill");
        assert!(
            inst.group.is_reaped(),
            "the group must still read as reaped after kill() — the flag is one-shot"
        );
        drop(inst);

        // A SIGKILL to the (recycled) pgid would land within a few ms; give it time.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let decoy_status = decoy.try_wait().expect("try_wait decoy");
        // Clean up the decoy regardless of the outcome — a test's own fixtures are residue too.
        let _ = nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(-decoy_pid),
            nix::sys::signal::Signal::SIGKILL,
        );
        let _ = decoy.wait().await;

        assert!(
            decoy_status.is_none(),
            "kill()/Drop on a reaped crosvm instance must not SIGKILL a (recycled) pgid"
        );
    }

    /// This file's own source, for the M11 call-site scan below.
    const SOURCE: &str = include_str!("lib.rs");

    /// The number of `jail_spec_from_config` call sites this backend ships: one, inside
    /// [`CrosvmLaunchPlan::build`].
    ///
    /// Asserted exactly, so a scan that silently matched nothing — the way every source-scanning
    /// gate fails vacuously — reddens instead of passing over an empty set, and a second (possibly
    /// unlaundered) call site reddens too.
    const EXPECTED_JAIL_CALL_SITES: usize = 1;

    /// The number of [`CrosvmLaunchPlan::build`] call sites this backend ships: one, in
    /// [`crosvm_launch_plan`]. Asserted exactly, for the same anti-vacuity reason.
    const EXPECTED_PLAN_BUILD_SITES: usize = 1;

    /// This file's production text: everything before the first `#[cfg(test)]`, comment lines
    /// dropped and whitespace collapsed. The same shape `vmcell-qemu`'s `virtiofs_pacing_gate`
    /// uses — a deliberate second reader of a law, not a second copy of one.
    fn production_code(source: &str) -> String {
        let production = source
            .split_once("#[cfg(test)]")
            .map_or(source, |(before, _)| before);
        production
            .lines()
            .map(str::trim)
            .filter(|line| !line.starts_with("//"))
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// Every `jail_spec_from_config(` call expression in `code`, each truncated at its statement's
    /// `;` and normalized to start at the function name (the path prefix is irrelevant).
    fn jail_spec_calls(code: &str) -> Vec<&str> {
        code.match_indices("jail_spec_from_config(")
            .map(|(at, _)| {
                let tail = &code[at..];
                &tail[..tail.find(';').unwrap_or(tail.len())]
            })
            .collect()
    }

    /// Every `CrosvmLaunchPlan::build(` call expression in `code`, truncated at its statement's
    /// `;` — the site that decides which posture is compiled AND recorded.
    fn plan_build_calls(code: &str) -> Vec<&str> {
        code.match_indices("CrosvmLaunchPlan::build(")
            .map(|(at, _)| {
                let tail = &code[at..];
                &tail[..tail.find(';').unwrap_or(tail.len())]
            })
            .collect()
    }

    /// The law, half one: the only `jail_spec_from_config` call compiles the `jail` **parameter**
    /// of [`CrosvmLaunchPlan::build`] — the same binding the plan records — never `cfg.jail` and
    /// never a freshly-built config. `&jail)` matches only the bare parameter: `&cfg.jail)` and
    /// `&plan.jail)` do not contain it (there is no `&` immediately before `jail`).
    fn call_compiles_the_recorded_jail(call: &str) -> bool {
        call.starts_with("jail_spec_from_config(") && call.contains("&jail)")
    }

    /// The law, half two: the one plan-build site hands in `effective_jail_config(cfg)`, so the
    /// value that gets both compiled and recorded is the EFFECTIVE posture.
    fn build_site_names_the_effective_config(call: &str) -> bool {
        call.contains("effective_jail_config(cfg)")
    }

    // M11 GATE (KVM-free). crosvm always runs `--disable-sandbox`, so the Layer-2 deny-list is its
    // ONLY seccomp confinement — and while the flip rode inline as
    // `jail_spec_from_config(&effective_jail_config(cfg))`, rewriting that one token to `&cfg.jail`
    // shipped every crosvm VM with no filter at all while `cargo test -p vmcell-crosvm`, `just ci`
    // and the entire live `test-crosvm` matrix stayed green (the deny-list is default-allow/EPERM,
    // so no functional leg notices). Both halves of that hole are closed here:
    //   (1) the pure `crosvm_launch_plan` returns the jail posture, so it is a VALUE to assert on;
    //   (2) the shipped `jail_spec_from_config` call site is scanned to prove `spawn` uses that
    //       value — the assertion (1) alone structurally cannot make.
    // RED on the inverse in both directions: rewriting the plan's `effective_jail_config(cfg)` to
    // `cfg.jail` reddens (1); rewriting `spawn`'s `&plan.jail` to `&cfg.jail` reddens (2).
    #[test]
    fn the_crosvm_jail_spec_comes_from_effective_jail_config() {
        use vmcell::config::{JailConfig, VmmSeccomp};

        let cfg = VmConfig::builder(
            "/boot/vmlinux",
            RootfsSource::Erofs {
                image: PathBuf::from("/img/rootfs.erofs"),
            },
        )
        .vmm_seccomp(VmmSeccomp::Enforcing)
        .jail(JailConfig::hardened())
        .build()
        .expect("build config");
        // Precondition: the REQUESTED posture ships the deny-list off, so "effective" and
        // "requested" genuinely differ here and the assertions below are non-vacuous.
        assert!(
            !cfg.jail.seccomp_deny_list,
            "precondition: the hardened default ships the Layer-2 deny-list OFF"
        );

        let plan = crosvm_launch_plan(
            Path::new("/usr/bin/crosvm"),
            &cfg,
            &test_res(),
            &CrosvmSpawnPaths {
                control_socket: Path::new("/tmp/c.sock"),
                serial_path: Path::new("/tmp/s.log"),
            },
            3,
            "root=/dev/vda",
            None,
        )
        .expect("build the launch plan");

        // (1) The pair's jail half IS the effective posture, not the requested one.
        assert_eq!(
            plan.jail,
            effective_jail_config(&cfg),
            "the launch plan must ship `effective_jail_config(cfg)`"
        );
        assert_ne!(
            plan.jail, cfg.jail,
            "…and that is not `cfg.jail`: with Enforcing, the deny-list must be turned ON"
        );
        assert!(
            plan.jail.seccomp_deny_list,
            "crosvm's ONLY seccomp confinement must be on in the shipped jail"
        );
        // Compiled, the difference is a filter versus no filter at all — what shipping `cfg.jail`
        // would have produced (the positive control keeps the assertion above from being a
        // tautology about two structs).
        assert!(
            vmcell::vmm::jail::jail_spec_from_config(&plan.jail)
                .expect("compile the shipped spec")
                .seccomp
                .is_some(),
            "the shipped JailSpec must carry the compiled deny-list"
        );
        assert!(
            vmcell::vmm::jail::jail_spec_from_config(&cfg.jail)
                .expect("compile the requested spec")
                .seccomp
                .is_none(),
            "control: the REQUESTED posture compiles to no filter — the unconfined VMM this guards"
        );

        // The args half of the pair is the run-args builder's output verbatim, so the plan cannot
        // quietly become a second device-model builder.
        assert_eq!(
            plan.run_args,
            build_crosvm_run_args(
                &cfg,
                &test_res(),
                Path::new("/tmp/c.sock"),
                Path::new("/tmp/s.log"),
                3,
                "root=/dev/vda",
                None,
            )
            .expect("build run args"),
            "the plan's run args must be `build_crosvm_run_args`'s output"
        );

        // (2) The BACKSTOP scan. It is no longer the only defence: `CrosvmLaunchPlan::build` is
        // the sole constructor and compiles the very `jail` it records, so a plan whose record and
        // command disagree cannot be built, and `spawn` holds no jail value to mutate. What the
        // scan still adds is a check that a SECOND compilation site has not appeared, and that the
        // one build site is handed the effective posture.
        let code = production_code(SOURCE);
        let calls = jail_spec_calls(&code);
        assert_eq!(
            calls.len(),
            EXPECTED_JAIL_CALL_SITES,
            "expected {EXPECTED_JAIL_CALL_SITES} shipped jail_spec_from_config call, inside \
             `CrosvmLaunchPlan::build`; found {}: {calls:?}. If a site was legitimately added or \
             removed, update EXPECTED_JAIL_CALL_SITES — do not delete the scan.",
            calls.len()
        );
        for call in &calls {
            assert!(
                call_compiles_the_recorded_jail(call),
                "M11: the shipped JailSpec must be compiled from the very `jail` the plan records \
                 — `{call}` must be `jail_spec_from_config(&jail)`"
            );
        }
        let builds = plan_build_calls(&code);
        assert_eq!(
            builds.len(),
            EXPECTED_PLAN_BUILD_SITES,
            "expected {EXPECTED_PLAN_BUILD_SITES} CrosvmLaunchPlan::build call; found {}: \
             {builds:?}",
            builds.len()
        );
        for call in &builds {
            assert!(
                build_site_names_the_effective_config(call),
                "M11: the one plan-build site must hand in `effective_jail_config(cfg)` — `{call}`"
            );
        }
    }

    // The M11 defeat, replayed as a gate. The verifier's two-line edit was
    // `let mut plan = crosvm_launch_plan(…)?;` + `plan.jail = cfg.jail;` before the compile — it
    // satisfied the old scan (the predicate matched the mutated binding) and shipped every crosvm
    // VM unconfined. The equivalent mutation is now INERT: the command already carries the
    // compiled spec, so writing `plan.jail` afterwards changes the record and nothing else.
    //
    // This asserts that inertness directly. Inverse: move the `jail_spec_from_config` +
    // `build_vmm_cmd` back out of `CrosvmLaunchPlan::build` into `spawn`, and the argv below stops
    // being fixed at construction — the `EXPECTED_JAIL_CALL_SITES` scan and the `&jail)` predicate
    // both redden first, because the call site can no longer name the constructor's parameter.
    #[test]
    fn mutating_the_plans_recorded_jail_cannot_change_what_ships() {
        use vmcell::config::{JailConfig, VmmSeccomp};

        let cfg = VmConfig::builder(
            "/boot/vmlinux",
            RootfsSource::Erofs {
                image: PathBuf::from("/img/rootfs.erofs"),
            },
        )
        .vmm_seccomp(VmmSeccomp::Enforcing)
        .jail(JailConfig::hardened())
        .build()
        .expect("build config");

        let build_plan = || {
            crosvm_launch_plan(
                Path::new("/usr/bin/crosvm"),
                &cfg,
                &test_res(),
                &CrosvmSpawnPaths {
                    control_socket: Path::new("/tmp/c.sock"),
                    serial_path: Path::new("/tmp/s.log"),
                },
                3,
                "root=/dev/vda",
                None,
            )
            .expect("build the launch plan")
        };

        let argv_of = |plan: &CrosvmLaunchPlan| -> Vec<String> {
            plan.cmd
                .as_std()
                .get_args()
                .map(|a| a.to_string_lossy().into_owned())
                .collect()
        };

        let untouched = build_plan();
        let baseline = argv_of(&untouched);

        // The verifier's edit, verbatim in spirit: overwrite the recorded posture with the
        // REQUESTED one after the plan exists.
        let mut mutated = build_plan();
        mutated.jail = cfg.jail;
        mutated.run_args = Vec::new();

        assert_eq!(
            argv_of(&mutated),
            baseline,
            "M11: the command is composed inside the plan's only constructor, so overwriting \
             `plan.jail`/`plan.run_args` afterwards must not change a single argument that ships"
        );
        assert!(
            !baseline.is_empty(),
            "control: the composed argv is non-empty, so the equality above is not vacuous"
        );
    }

    // The scan's own red-on-inverse: the predicate must reject the regression shape and the scanner
    // must see a wrapped call while ignoring prose, so the gate above is not a test that can only
    // ever pass (AGENTS.md rule 2).
    #[test]
    fn the_jail_call_site_scanner_rejects_the_requested_config_shape() {
        // The compile-site predicate: only the constructor's own `jail` parameter passes. Both
        // regression shapes — the requested config, and the mutated-plan shape that DEFEATED the
        // previous gate — are rejected.
        assert!(!call_compiles_the_recorded_jail(
            "jail_spec_from_config(&cfg.jail)?"
        ));
        assert!(!call_compiles_the_recorded_jail(
            "jail_spec_from_config(&JailConfig::hardened())?"
        ));
        assert!(!call_compiles_the_recorded_jail(
            "jail_spec_from_config(&plan.jail)?"
        ));
        assert!(call_compiles_the_recorded_jail(
            "jail_spec_from_config(&jail)?"
        ));

        // The build-site predicate: the effective posture passes, the requested one does not.
        assert!(build_site_names_the_effective_config(
            "CrosvmLaunchPlan::build(b, n, effective_jail_config(cfg), &s, r)"
        ));
        assert!(!build_site_names_the_effective_config(
            "CrosvmLaunchPlan::build(b, n, cfg.jail, &s, r)"
        ));

        let synthetic = "// jail_spec_from_config(&cfg.jail) in a comment is not a call site\n\
             let spec =\n    vmcell::vmm::jail::jail_spec_from_config(\n    &jail)?;\n\
             let p = CrosvmLaunchPlan::build(b, n,\n effective_jail_config(cfg), &s, r)?;\n\
             #[cfg(test)]\nmod tests { jail_spec_from_config(&cfg.jail); }";
        let code = production_code(synthetic);
        let calls = jail_spec_calls(&code);
        assert_eq!(calls.len(), 1, "got {calls:?}");
        assert!(call_compiles_the_recorded_jail(calls[0]), "got {calls:?}");
        let builds = plan_build_calls(&code);
        assert_eq!(builds.len(), 1, "got {builds:?}");
        assert!(build_site_names_the_effective_config(builds[0]));
    }

    /// Production mentions of the protocol default: one, the placement-`None` placeholder inside
    /// [`steward_endpoint`]. Asserted exactly, so the scan below cannot pass over an empty set — and
    /// so a SECOND site spelling the constant reddens even when the composer is still there.
    const EXPECTED_DEFAULT_PORT_MENTIONS: usize = 1;

    // M1's shape on this backend, the KVM-free half (its live half is the `Service{5100}` leg of the
    // placement set, which runs on the primary backend; `just test-crosvm` is opt-in because CI has
    // no crosvm binary): the endpoint an instance reports carries the DECLARED steward port, law C8's
    // first question, never the protocol default.
    //
    // crosvm's own callers survive the hardcoded form — `MicroVm::steward` re-keys the port per call
    // and `verify_control_plane` is a no-op here — which is exactly why it needs a gate rather than a
    // functional leg: nothing on this backend goes red until some future reader trusts the port it is
    // handed, the way QEMU's probe did.
    //
    // RED on the inverse: put `port: vmcell::vmm::STEWARD_VSOCK_PORT` back in `steward_endpoint`'s
    // `VsockEndpoint::Vsock` and the `Service { port: 5100 }` assertion fires.
    #[test]
    fn the_reported_endpoint_carries_the_declared_steward_port() {
        use vmcell::config::StewardPlacement;

        let port_of = |e: &VsockEndpoint| match e {
            VsockEndpoint::Unix { port, .. } | VsockEndpoint::Vsock { port, .. } => *port,
        };

        // A NON-default declared port: the whole point of `Service { port }` is that the guest binds
        // it, so an endpoint reporting anything else describes a listener that is not there.
        assert_eq!(
            port_of(&steward_endpoint(
                42,
                StewardPlacement::Service { port: 5100 }
            )),
            5100,
            "the reported endpoint must carry the declared port, not the protocol default"
        );

        // The default placement is byte-identical to every release before v33 — the
        // pay-for-what-you-use floor — so a `Pid1` cell's endpoint must be unchanged.
        assert_eq!(
            port_of(&steward_endpoint(42, StewardPlacement::Pid1)),
            vmcell::vmm::STEWARD_VSOCK_PORT,
        );
        // `None` never reaches a dial, so its port is an unused placeholder — pinned so a future
        // reader does not mistake it for a dialable answer.
        assert_eq!(
            port_of(&steward_endpoint(42, StewardPlacement::None)),
            vmcell::vmm::STEWARD_VSOCK_PORT,
        );

        // …and the transport half is unconditional on this backend (in-kernel vhost-vsock on every
        // path), carrying the CID the argv programs — which the port change must not have disturbed.
        for placement in [
            StewardPlacement::Pid1,
            StewardPlacement::Service { port: 5100 },
            StewardPlacement::None,
        ] {
            assert!(
                matches!(
                    steward_endpoint(42, placement),
                    VsockEndpoint::Vsock { cid: 42, .. }
                ),
                "crosvm's transport is AF_VSOCK by CID on every path ({placement:?})"
            );
        }
    }

    // The CALL-SITE half of the gate above (AGENTS.md: a gate binds the call sites, not just the
    // extracted predicate). The composer's unit test cannot see the defect this scan is about — a
    // second, inlined `VsockEndpoint` carrying the constant beside it, which is precisely the shape
    // the defect shipped as on QEMU, twice.
    //
    // RED on the inverse: re-inline `port: vmcell::vmm::STEWARD_VSOCK_PORT` in `vsock_endpoint` (the
    // spelling this backend shipped) and the mention count goes to 2; delete the composer and the
    // `steward_port()` assertion fires.
    #[test]
    fn the_dialed_port_is_composed_once_from_the_declared_placement() {
        let code = production_code(SOURCE);
        let mentions = code.matches("STEWARD_VSOCK_PORT").count();
        assert_eq!(
            mentions, EXPECTED_DEFAULT_PORT_MENTIONS,
            "the protocol default may be spelled only as `steward_endpoint`'s placement-`None` \
             placeholder; every other mention is a site hardcoding a port the caller may have \
             re-declared (M1). Found {mentions}."
        );
        assert!(
            code.contains("placement .steward_port()") || code.contains("placement.steward_port()"),
            "the composed port must come from `StewardPlacement::steward_port()` — C8's first \
             question — not from a constant"
        );
        // Non-vacuity: the composer is actually the spawned instance's endpoint, not dead code.
        assert!(
            code.contains("steward_endpoint(guest_cid, cfg.steward_placement)"),
            "`spawn` must compose the instance's endpoint through `steward_endpoint` from the \
             config's own placement"
        );
    }

    // The scanner's own controls: prose is not code, and the regression shape is genuinely detected
    // — so the scan above is not a test that can only ever pass (AGENTS.md rule 2).
    #[test]
    fn the_port_scanner_ignores_comments_and_sees_a_re_inlined_port() {
        let clean = "// port: vmcell::vmm::STEWARD_VSOCK_PORT in a comment is not a dial site\n\
             port: placement.steward_port().unwrap_or(vmcell::vmm::STEWARD_VSOCK_PORT),\n\
             #[cfg(test)]\nmod tests { STEWARD_VSOCK_PORT }";
        assert_eq!(
            production_code(clean).matches("STEWARD_VSOCK_PORT").count(),
            EXPECTED_DEFAULT_PORT_MENTIONS,
        );
        let regressed = "port: placement.steward_port().unwrap_or(vmcell::vmm::STEWARD_VSOCK_PORT), \
             VsockEndpoint::Vsock { cid: self.cid, port: vmcell::vmm::STEWARD_VSOCK_PORT }";
        assert!(
            production_code(regressed)
                .matches("STEWARD_VSOCK_PORT")
                .count()
                > EXPECTED_DEFAULT_PORT_MENTIONS,
            "a re-inlined default port must be visible to the scan"
        );
    }
}
