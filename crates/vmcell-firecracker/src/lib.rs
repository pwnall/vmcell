//! Firecracker VMM backend for `vmcell`.
//!
//! Provides the [`Firecracker`] implementation of the [`vmcell::vmm::Vmm`] trait and its
//! running-instance type [`FcInstance`]. Extracted from the `vmcell` crate (design §2.1, The
//! trait and the capability descriptor) so the core library carries only the primary Cloud
//! Hypervisor backend; this crate depends on `vmcell` for the shared `Vmm`/`VmInstance` traits,
//! the jail/seccomp predicates, and the spawn/reap/console/snapshot-eligibility helpers — every
//! "one law, one predicate" invariant stays single-sourced in `vmcell`.

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
        clippy::allow_attributes,               // B11: prefer #[expect] over #[allow] in prod code
        clippy::allow_attributes_without_reason  // B11: every suppression states why
    )
)]

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use vmcell::config::VmConfig;
use vmcell::error::{Error, Result};
use vmcell::vmm::{PerVmResources, VmInstance, Vmm, VmmCapabilities};

use tokio::process::Child;

/// Sidecar file (written into the snapshot directory by [`FcInstance::snapshot`])
/// recording the host-side vsock UDS path and guest CID the snapshot baked in.
///
/// Firecracker's `PUT /snapshot/load` restores the vsock device *verbatim* from
/// the snapshot — it rebinds the **original** host UDS path and offers no
/// load-time override. A restore therefore runs under a fresh, vmid-derived tmp
/// dir but must rebind (and have the steward dial) the path the snapshot recorded,
/// and report the guest's baked CID. This sidecar carries both across the
/// snapshot/restore boundary.
const HOST_PATHS_SIDECAR: &str = "vmcell_host_paths.json";

/// Host-side vsock UDS path and guest CID baked into a Firecracker snapshot,
/// persisted alongside it so a later restore can rebind the exact socket FC
/// recreates (it offers no load-time override) and report the guest's baked CID.
#[derive(Serialize, Deserialize)]
struct SnapshotHostPaths {
    /// Host vsock UDS path FC baked into the snapshot; `restore()` re-binds it verbatim.
    vsock: PathBuf,
    /// Guest CID baked into the snapshot. A restored FC VM keeps this CID (the vsock
    /// device is loaded verbatim), so `guest_cid()` must report it, not the
    /// orchestrator's fresh allocation (M-VMM-3).
    cid: u32,
}

/// The Firecracker capability descriptor, exposed as a free function so both
/// [`Firecracker::capabilities`] and [`FcInstance::snapshot`] consult the **same**
/// source of truth — the latter holds no handle to the `Firecracker` backend yet
/// must self-check `snapshot_restore` (M-RESTORE-3).
fn fc_capabilities() -> VmmCapabilities {
    VmmCapabilities {
        // E2 (empirical, KVM host, pre-v17): FC warm restore used to drop the first
        // post-restore exec ("Connection dropped during exec"). That symptom predated
        // the steward's generic re-bind-after-restore loop (REBIND_IDLE 250 ms,
        // cmdline-tunable, now event-driven poll(2)) and the native in-steward resync —
        // re-validated ON (EXP-E, docs/45-claude-perf-investigation.md): the full
        // snapshot_restore::firecracker matrix assertion set (post-restore exec,
        // native MAC rotation, reseed, fail-loud clock resync, ordered teardown)
        // passes repeatedly in isolation on a KVM host. Flip back to `false` only
        // with a reproducing failure recorded in docs/45.
        snapshot_restore: true,
        // M-VMM-1: a real UFFD page-fault backend for `RestoreMode::Lazy` is not
        // wired (restore would hardcode `backend_type: "File"`, faulting eagerly), so
        // the flag is honest-false rather than silently degrading Lazy to eager.
        lazy_restore: false,
        virtio_fs_shares: false,
        unprivileged_vhost_user_net: false,
        nested_virt: false,
        // Firecracker has no virtio-console device; a VirtioConsole config is
        // rejected up front by `reject_unsupported_console` so it can never emit
        // `console=hvc0` with no `hvc0` device.
        virtio_console: false,
        // Scoped to the host **socket/serial** identity (docs/78 M1): FC's
        // `PUT /snapshot/load` re-binds the snapshot's recorded host vsock UDS path
        // VERBATIM — no load-time override exists in v1.16 — so a restored VM never
        // gets a fresh vsock path (see `HOST_PATHS_SIDECAR` and
        // `reject_live_baked_vsock`). All restores of a lineage share the one baked
        // path: restore-while-alive is rejected and concurrent restores from one
        // lineage are unsupported. The **tap** is NOT baked: `restore()` rebinds it
        // to the fresh `res.tap_name` via `network_overrides`
        // (`build_fc_snapshot_load`), the FC analogue of CH's `net[].tap` rewrite —
        // that rotation is real and this flag does not describe it.
        restore_rotates_host_paths: false,
        // FC has a native per-drive rate limiter (`rate_limiter`), §4.6.
        disk_io_throttle: true,
        // Firecracker's minimal device model has no USB controller of any kind (§2.4, QEMU q35 — the fallback and most-proven nester),
        // so host-USB passthrough is a hard, documented false; `create()` rejects a USB
        // device fail-loud via the shared `reject_usb_host_devices` predicate.
        usb_host_passthrough: false,
    }
}

/// Refuses a [`VmConfig`] asking for `nested_virt`/`lazy_restore` that [`fc_capabilities`]
/// advertises as `false`, through the **one** shared predicate
/// [`vmcell::vmm::reject_unadvertised_capabilities`] (docs/81 d7).
///
/// FC's stake in it: it exposes no VMX/SVM to the guest, yet the SHARED
/// [`vmcell::config::build_kernel_cmdline`] emits `kvm-intel.nested=1` for **every** backend
/// on `cfg.nested_virt` — so an accepted request used to boot a guest whose L1 `/dev/kvm`
/// never appears; and no UFFD page-fault backend is wired (`restore` hardcodes
/// `backend_type: "File"`), so [`RestoreMode::Lazy`](vmcell::config::RestoreMode::Lazy) would
/// fault eagerly under a config that asked for demand paging.
///
/// This wrapper exists only to bind the `"firecracker"` name once; the law, both branches and
/// the N-VMM-1 feature strings live in the shared predicate. It landed as three byte-identical
/// per-backend copies and was hoisted.
///
/// # Errors
/// [`Error::Unsupported`] `{ vmm: "firecracker", feature }` naming the unadvertised capability.
fn reject_unadvertised_capabilities(caps: &VmmCapabilities, cfg: &VmConfig) -> Result<()> {
    vmcell::vmm::reject_unadvertised_capabilities("firecracker", caps, cfg)
}

/// Serializes and writes the host vsock UDS path and guest CID Firecracker baked into
/// a snapshot to the [`HOST_PATHS_SIDECAR`] file in `dir`. The sidecar is part of the
/// snapshot artifact and `restore()` hard-requires it, so a serialize or write
/// failure is surfaced (M-RESTORE-2) — never logged-and-swallowed, which would
/// report an unrestorable snapshot as successful.
async fn write_host_paths_sidecar(dir: &Path, vsock: &Path, cid: u32) -> Result<()> {
    let json = serde_json::to_string(&SnapshotHostPaths {
        vsock: vsock.to_path_buf(),
        cid,
    })?;
    tokio::fs::write(dir.join(HOST_PATHS_SIDECAR), json).await?;
    Ok(())
}

/// How long [`reject_live_baked_vsock`]'s liveness probe waits for a `connect` to resolve.
///
/// Generous rather than tight, and the direction matters: exceeding it now REFUSES the restore, so
/// a budget too small costs a spurious retry on a loaded box, while one too large costs only this
/// much wall clock on the (already rare) stale-path route. 100 ms was measurably too small — a
/// live-listener connect exceeded it under a full workspace test run.
const BAKED_VSOCK_PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

/// What [`reject_live_baked_vsock`]'s liveness probe learned about the baked path.
///
/// Three outcomes, not two — separating them is the whole fix. Collapsing "I could not tell" into
/// "nothing owns it" is what let a slow probe unlink a live VM's socket.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BakedVsockProbe {
    /// A listener accepted the connect: a live VMM owns the path.
    Accepted,
    /// The connect FAILED (ECONNREFUSED / ENOENT / not-a-socket): nothing owns the path. The only
    /// outcome that proves anything about absence.
    Refused,
    /// The connect neither completed nor failed inside the budget. Says nothing either way.
    Inconclusive,
}

/// The one law: only a path the probe **proved** dead may be unlinked.
///
/// Extracted as a pure predicate rather than left inline because the inconclusive arm is the one
/// that matters and the one a socket-level test cannot reliably produce — a first attempt at that
/// test saturated a listener's backlog, failed to reach the timeout, and passed with the
/// fail-open regression planted. A predicate can be driven over all three inputs directly, which
/// is what makes the gate able to fail (AGENTS.md rule 2).
const fn probe_permits_unlink(probe: BakedVsockProbe) -> bool {
    matches!(probe, BakedVsockProbe::Refused)
}

/// `connect(2)` refused the path — the only errno that proves no listener owns it.
///
/// Empirically the answer for **every** dead shape a baked path can take: a stream socket whose
/// listener is gone, a leftover regular file, and even a directory all return `ECONNREFUSED`.
const CONNECT_REFUSED: i32 = nix::errno::Errno::ECONNREFUSED as i32;

/// The path vanished between the existence check and the connect — also proof that nothing owns it.
const CONNECT_MISSING: i32 = nix::errno::Errno::ENOENT as i32;

/// Which `connect` FAILURES prove the baked path is dead (§8.2's restore guard).
///
/// The arm this closes is the sibling of the timeout arm `c5a01a1` closed, and it was left blanket:
/// the guard read *any* `Err` from `connect` as "nothing owns the path" while its own rustdoc
/// claimed the narrow set. It is not narrow — `connect` also fails with `EMFILE`/`ENFILE` under fd
/// pressure, `EACCES` on a path it may not reach, `EAGAIN` when a **live** listener's backlog is
/// full, and `EINTR`. Every one of those says nothing about liveness, and every one of them made
/// the guard unlink a live VM's steward transport and let the restore proceed. Reproduced: with
/// `RLIMIT_NOFILE` low enough that `connect` returns `EMFILE`, the live-listener test's
/// `expect_err` panicked with `a live listener on the baked path must be rejected: ()` — the guard
/// had returned `Ok` for a socket a listener was sitting on.
///
/// Same direction as every other decision in this guard: only a **proof** of absence unlinks, and
/// everything else refuses, because refusing costs a loud retryable re-run while unlinking is
/// silent and severs a live VM.
const fn connect_failure_proves_dead(raw_os_error: Option<i32>) -> BakedVsockProbe {
    match raw_os_error {
        Some(CONNECT_REFUSED | CONNECT_MISSING) => BakedVsockProbe::Refused,
        _ => BakedVsockProbe::Inconclusive,
    }
}

/// Pre-restore guard + cleanup for the snapshot's baked host vsock UDS path
/// (`restore_rotates_host_paths: false` — FC re-binds this exact path verbatim).
///
/// A leftover socket *file* at the baked path is normal (the base VM's teardown
/// unlinks best-effort, and a sequential restore reuses the path), and must be
/// removed or FC's bind fails `EADDRINUSE`. But a socket that still **accepts a
/// connection** means a live VMM — the snapshotted VM or a prior restore of the
/// same lineage — still owns it; unlinking it would silently sever that VM's
/// steward transport. So: if the path exists, probe it with a short-timeout
/// connect and fail loud with a typed `Error::Vmm` naming the path when a
/// listener answers. Only a path the probe **proved** dead (ECONNREFUSED / ENOENT /
/// not-a-socket) proceeds to `remove_file` + `create_dir_all(parent)` — the parent
/// re-creation matters because the baked path lives in the long-gone base VM's
/// scratch dir, and a missing parent fails `PUT /snapshot/load` with ENOENT.
///
/// **A probe that did not PROVE the path dead is inconclusive, and inconclusive fails closed.**
/// Two arms have had to learn this, a release apart. First the timeout (below). Then the error
/// arm, which read *any* `connect` failure as "nothing owns the path" while this very paragraph
/// claimed the narrow `ECONNREFUSED`/`ENOENT` set: `connect` also fails `EMFILE`/`ENFILE` under fd
/// pressure, `EAGAIN` when a **live** listener's backlog is full, `EACCES`, and `EINTR` — none of
/// which say anything about liveness, and all of which unlinked a running VM's socket. That arm is
/// now [`connect_failure_proves_dead`], and it is a pure predicate for the reason the other one is.
///
/// **A probe TIMEOUT is inconclusive too.** It used to be
/// grouped with the dead-path answers, on the reasoning that a live listener answers
/// a local `connect` instantly. Under load it does not: a full `cargo test
/// --workspace` made a live-listener connect exceed the 100 ms budget, and this
/// function's own unit test went red — reporting, correctly, that the guard had
/// classified a LIVE socket as stale. Had that happened on a real restore the guard
/// would have unlinked a running VM's steward transport and let the restore proceed,
/// which is precisely the failure it exists to prevent. Refusing is loud, retryable,
/// and costs at most a re-run; unlinking is silent and severs a live VM.
///
/// TOCTOU, honestly: the probe and the unlink are not atomic — a restore racing
/// this window can still lose. This is a *misuse guard* catching the realistic
/// sequential mistake (restoring while the lineage is alive), not a security
/// boundary; the single-lineage constraint (design §17, Open gaps and future capabilities) is the real contract.
async fn reject_live_baked_vsock(path: &Path) -> Result<()> {
    if tokio::fs::try_exists(path).await.unwrap_or(false) {
        // Three outcomes, not two. `Ok(Err(_))` — ECONNREFUSED / ENOENT / not-a-socket — is the
        // only one that PROVES nothing owns the path, and it is the only one that unlinks.
        let probe = tokio::time::timeout(
            BAKED_VSOCK_PROBE_TIMEOUT,
            tokio::net::UnixStream::connect(path),
        )
        .await;
        let probe = match probe {
            Ok(Ok(_stream)) => BakedVsockProbe::Accepted,
            // NOT a blanket "an error means dead": only the errnos that PROVE absence unlink.
            Ok(Err(failed)) => connect_failure_proves_dead(failed.raw_os_error()),
            Err(_elapsed) => BakedVsockProbe::Inconclusive,
        };
        if !probe_permits_unlink(probe) {
            let why = match probe {
                BakedVsockProbe::Accepted => "a live listener accepted a probe connection",
                // `Refused` cannot reach here — `probe_permits_unlink` admits it — but it is named
                // rather than swept into a `_` so a fourth outcome is a compile error here instead
                // of silently inheriting somebody else's sentence.
                BakedVsockProbe::Inconclusive | BakedVsockProbe::Refused => {
                    "the probe neither reached a listener nor proved the path dead: it either did \
                     not complete within its budget, or it failed for a reason that says nothing \
                     about liveness (a resource limit, a permission error, a full backlog)"
                }
            };
            return Err(Error::Vmm(format!(
                "snapshot's baked host vsock path {} may still be in use ({why}): the \
                 snapshotted VM or a prior restore of this snapshot lineage may still own it; \
                 Firecracker re-binds this exact path verbatim, so restore must wait for that \
                 VM's teardown. Unlinking a path this probe could not prove dead would silently \
                 sever a live VM's steward transport, so an inconclusive probe refuses.",
                path.display()
            )));
        }
    }
    let _ = tokio::fs::remove_file(path).await;
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    Ok(())
}

/// The Firecracker VMM backend.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Firecracker {
    /// Path to the `firecracker` executable.
    pub binary_path: PathBuf,
    /// Lazily-probed T2 CPU-template support, cached on this instance (shared
    /// across clones). Replaces the former process-global `OnceLock` so the probe
    /// result is no longer module-global mutable state.
    cpu_template: std::sync::Arc<std::sync::OnceLock<Option<String>>>,
}

impl Firecracker {
    /// Creates a new `Firecracker` using the specified executable path.
    #[must_use]
    pub fn new(binary_path: impl Into<PathBuf>) -> Self {
        Self {
            binary_path: binary_path.into(),
            cpu_template: std::sync::Arc::new(std::sync::OnceLock::new()),
        }
    }

    /// Probes the host once for T2 CPU-template support, caching the result on
    /// this instance instead of in a process-global, so a later `Firecracker`
    /// with a different binary/config probes independently.
    ///
    /// Takes `res` because the probe VM is launched through the same composed
    /// [`t2_probe_launch`]/[`firecracker_launch_plan`] every real boot uses, which needs this VM's
    /// netns and scratch dir (docs/90 `vmcell-firecracker:789`).
    ///
    /// # Errors
    /// Propagates the probe's launch-composition refusal (a `VmmSeccomp::Log` config, a deny-list
    /// that will not compile) — a deterministic refusal `spawn_fc` would make one step later
    /// anyway. A *transient* probe failure is not an error here: it is warned about and left
    /// uncached (VMM-4).
    async fn detect_cpu_template(
        &self,
        cfg: &VmConfig,
        res: &PerVmResources,
    ) -> Result<Option<String>> {
        if let Some(val) = self.cpu_template.get() {
            return Ok(val.clone());
        }

        let probe = probe_t2_template(self, cfg, res).await?;
        // VMM-4: only a DEFINITE outcome (T2 supported or firmly unsupported) is
        // cached. A transient probe failure is warned about and left uncached so the
        // next `create()` re-probes — a one-off host hiccup must not permanently
        // disable the T2 template (and thus the extended-FPU restore guard) for every
        // VM sharing this backend.
        if probe == T2Probe::Failed {
            tracing::warn!(
                "Firecracker T2 CPU-template probe failed (transient host error, not a \
                 firm 'unsupported'); not caching a result — will re-probe on the next \
                 VM. Booting without a CPU template this time; the `noxsave` cmdline \
                 fallback still guards extended-FPU restore."
            );
        }
        if let Some(to_cache) = cache_decision(probe) {
            let _ = self.cpu_template.set(to_cache);
        }
        Ok(self.cpu_template.get().cloned().flatten())
    }
}

/// A running instance of a Firecracker VM.
#[derive(Debug)]
#[non_exhaustive]
pub struct FcInstance {
    process: Child,
    api_socket: PathBuf,
    vsock_path: PathBuf,
    serial_path: PathBuf,
    cid: u32,
    /// The VMM leader's process group AND the one-shot "already reaped" flag, owned
    /// together by the one shared helper ([`vmcell::vmm::VmmProcessGroup`], L1): `kill`,
    /// `has_exited` and `Drop` all route through it, so no copy can forget the M-VMM-1
    /// guard and SIGKILL a pgid the kernel has since recycled.
    group: vmcell::vmm::VmmProcessGroup,
    /// True if an external vhost-user-net device is attached. Such a VM is not
    /// snapshot-eligible (§2.5, The capability matrix); `snapshot()` self-guards on it. Always `false` on
    /// FC today because `create()` rejects every vhost-user device up front, but the
    /// field keeps the snapshot guard correct by construction. Mirrors CH.
    vhost_user_net: bool,
    /// The guest's RAM size, carried from `VmConfig::mem_mib` at construction: the
    /// snapshot RPCs' budget is a function of it
    /// ([`vmcell::vmm::snapshot_request_timeout`], M6), because a suspend image tracks
    /// guest RAM ~1:1 and therefore cannot ride the flat control-plane ceiling.
    mem_mib: u32,
    /// True if this instance came from a snapshot `restore()`. A restored FC VM is
    /// returned **paused** by `POST /snapshot/load {resume_vm:false}` and resumed via
    /// `resume()`, never `boot()` — so `boot()` self-guards on this flag and refuses
    /// to `InstanceStart` a restored VM (VMM-6). Mirrors CH's `restored` field.
    restored: bool,
}

impl FcInstance {
    async fn api_request(
        &self,
        method: &str,
        path: &str,
        body: Option<&impl Serialize>,
    ) -> Result<()> {
        vmcell::vmm::unix_api_request(&self.api_socket, method, path, body).await
    }

    /// The same RPC on an explicit budget, for the snapshot create/load pair — whose
    /// duration scales with guest RAM and therefore cannot ride the flat control
    /// ceiling (M6). Sized through the shared `vmcell::vmm::snapshot_request_timeout`,
    /// never a local literal.
    async fn api_request_with(
        &self,
        method: &str,
        path: &str,
        body: Option<&impl Serialize>,
        budget: std::time::Duration,
    ) -> Result<()> {
        vmcell::vmm::unix_api_request_with(&self.api_socket, method, path, body, budget).await
    }
}

/// The pure, total mapping from a config to the complete Firecracker launch (M11).
///
/// `spawn_fc` builds through this and spawns **only** what it returns, so the jail posture that
/// ships is a *returned value* a KVM-free test can assert on
/// ([`LaunchPlan::jail`](vmcell::vmm::LaunchPlan::jail)) rather than an inline
/// `jail_spec_from_config(&…)` argument no gate can see. The confinement is applied in
/// `build_vmm_cmd`'s post-fork `pre_exec` window, which nothing KVM-free observes — so while it
/// rode inline, rewriting the one `&cfg.jail` token to a weaker config shipped every Firecracker
/// VM with a different Layer-2 posture and `cargo test`, `just ci` and the whole live matrix
/// stayed green. That is the M11 defect class, proven on crosvm and representable here.
///
/// Performs no I/O (the serial-log `File::create` and the stale-socket unlink stay in the
/// caller), so a unit test can build a `VmConfig`, call this, and assert over the composed argv.
///
/// # Errors
/// Propagates [`vmm_seccomp_args`](vmcell::vmm::seccomp::vmm_seccomp_args)'s typed refusal of
/// [`VmmSeccomp::Log`](vmcell::config::VmmSeccomp::Log) (Firecracker has no observe-only mode)
/// and [`LaunchPlan::build`](vmcell::vmm::LaunchPlan::build)'s jail-compilation error.
fn firecracker_launch_plan(
    binary_path: &Path,
    cfg: &VmConfig,
    res: &PerVmResources,
    api_socket: &Path,
) -> Result<vmcell::vmm::LaunchPlan> {
    // §12.2 (Layer 1): FC's built-in filter is on unless `--no-seccomp` (Disabled); `Log` is the
    // one typed refusal, and it fires here — before any process or log file exists.
    let seccomp_args = vmcell::vmm::seccomp::vmm_seccomp_args("firecracker", cfg.vmm_seccomp)?;
    // §12.3 (Layer 2): the ONE posture value, handed to the one constructor that both compiles it
    // into the `pre_exec` jail and records it.
    let mut plan =
        vmcell::vmm::LaunchPlan::build(binary_path, res.netns_name.as_deref(), cfg.jail)?;
    let cmd = plan.command_mut();
    cmd.args(&seccomp_args);
    cmd.arg("--api-sock").arg(api_socket);
    Ok(plan)
}

impl Firecracker {
    async fn spawn_fc(
        &self,
        cfg: &VmConfig,
        res: &PerVmResources,
        cgroups: &dyn vmcell::metrics::CgroupFs,
    ) -> Result<(
        std::path::PathBuf,
        std::path::PathBuf,
        std::path::PathBuf,
        tokio::process::Child,
        Option<u32>,
    )> {
        // The orchestrator owns the per-VM scratch dir; derive our socket and
        // serial-log paths inside it.
        let api_socket = res.tmp_dir.join("api.sock");
        let vsock_path = res.tmp_dir.join("vsock.sock");
        let serial_path = res.tmp_dir.join("serial.log");

        // Firecracker expects the socket to not exist before it creates it.
        let _ = tokio::fs::remove_file(&api_socket).await;

        // M11: the whole launch — seccomp flag, jail spec, netns, argv — is composed inside
        // `firecracker_launch_plan`, so `spawn_fc` holds NO `JailConfig` and NO `JailSpec` and
        // there is no window in which the posture could be swapped between deciding it and
        // applying it. The plan's recorded posture is private to `vmcell::vmm::launch`, so the
        // two-line defeat (`let mut plan = …; plan.jail = weaker;`) does not compile; the
        // KVM-free gate asserts on the value it returns.
        let plan = firecracker_launch_plan(&self.binary_path, cfg, res, &api_socket)?;

        let log_file = std::fs::File::create(&serial_path)?;
        let mut process = plan
            .into_command()
            .stdin(Stdio::null())
            .stdout(log_file)
            .stderr(Stdio::inherit())
            .spawn()?;

        // Shared spawn+register+await-ready sequence (VMM-2): capture the pgid, add
        // the VMM to its cgroup, and block on the API socket — reaping the process
        // group on any failure. Identical error handling across CH/FC/QEMU.
        let pgid = vmcell::vmm::register_and_await_ready(
            &mut process,
            cgroups,
            &res.cgroup_name,
            &api_socket,
            cfg.timeouts.api_socket_poll.as_millis() as u64,
        )
        .await?;

        Ok((api_socket, vsock_path, serial_path, process, pgid))
    }
}

/// Outcome of the one-shot T2 CPU-template probe (VMM-4).
///
/// The old probe returned `Option<String>`, collapsing two very different cases into
/// `None`: a host that firmly reports T2 **unsupported**, and a probe that simply
/// **failed** (spawn/socket/API error — transient). Caching a transient failure as
/// "unsupported" permanently disables the T2 template — and thus the extended-FPU
/// restore guard — for every VM sharing the backend. Distinguishing the three lets
/// `detect_cpu_template` cache a definite answer but *re-probe* after a transient
/// failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum T2Probe {
    /// The host confirmed T2 support (the probe VM booted with the template).
    Supported,
    /// The host firmly rejected the T2 template (boot returned a template error).
    Unsupported,
    /// The probe could not complete (spawn/socket/API failure). Transient — must not
    /// be cached as a definitive answer.
    Failed,
}

/// Classifies the probe VM's `InstanceStart` result into a [`T2Probe`].
///
/// A `400` whose body mentions the template is the one **firm** "T2 unsupported"
/// signal; every other error (a `500`, a timeout, a transport error) is a transient
/// probe **failure**, not evidence that the host lacks T2 (VMM-4). Pure so the
/// distinction is unit-testable without spawning Firecracker.
fn classify_t2_boot(boot_res: &Result<()>) -> T2Probe {
    match boot_res {
        Ok(()) => T2Probe::Supported,
        Err(Error::VmmApi { status: 400, body })
            if body.contains("template") || body.contains("Template") =>
        {
            T2Probe::Unsupported
        }
        Err(_) => T2Probe::Failed,
    }
}

/// Maps a probe outcome to what (if anything) `detect_cpu_template` caches.
///
/// `None` means "do not cache — re-probe next time"; `Some(v)` is the value stored in
/// the shared `OnceLock`. A [`T2Probe::Failed`] must map to `None` (VMM-4): caching a
/// transient failure as "no template" is the exact permanent-disable bug. Pure so the
/// caching policy is unit-testable.
fn cache_decision(probe: T2Probe) -> Option<Option<String>> {
    match probe {
        T2Probe::Supported => Some(Some("T2".to_string())),
        T2Probe::Unsupported => Some(None),
        T2Probe::Failed => None,
    }
}

/// The extended-FPU restore-guard cmdline fragment for Firecracker (empty or `"noxsave "`).
///
/// A T2 CPU template masks the extended-state CPUID bits so the guest `glibc` never
/// dispatches to the AVX/AVX-512 routines whose XSAVE area can mismatch on restore
/// (design §2.3, Firecracker — the density tier and the fastest restore). `noxsave` is the **fallback** for hosts where the template does not
/// fit; applying it *with* a template needlessly disables the guest AVX2 the template
/// leaves usable, so it is emitted **only when no template was applied**. Returned with a
/// trailing space so it composes cleanly into the boot-args when non-empty and vanishes
/// when empty. Pure so the gating is unit-testable (audit E6,
/// `docs/41-experimental-conclusions-audit.md`).
fn noxsave_fallback(has_cpu_template: bool) -> &'static str {
    if has_cpu_template { "" } else { "noxsave " }
}

/// The **one** Firecracker interface id vmcell programs, shared by all THREE sites that name
/// it: the create path's `PUT /network-interfaces/<id>` URL ([`fc_network_interface_path`]),
/// that request's body ([`build_fc_network_interface`]), and the restore path's
/// `network_overrides` entry ([`build_fc_snapshot_load`]).
///
/// One law, one predicate: FC's `network_overrides` matches an override to a snapshotted
/// device *by this id*, so a create/restore mismatch is a silently ignored override — the
/// restore would fall back to the snapshot's baked `host_dev_name` with no error at all
/// (docs/78 M1, `fc-restore-rebinds-baked-tap-name-dead-data-plane`). A second literal is
/// exactly the divergence this const removes — the URL was one until docs/81 d6, which is why
/// the third site now derives from here and a source-level gate keeps it that way.
const FC_IFACE_ID: &str = "eth0";

/// The `PUT /network-interfaces/<id>` API path for the interface whose body carries `iface_id`.
///
/// The third copy of the id — FC matches the API path against the body's `iface_id`, so the path
/// is **derived** from it exactly as each drive's `drive_id` IS its `/drives/<drive_id>` path.
/// The create path open-coded `"/network-interfaces/eth0"` here (docs/81 d6) while the body and
/// the restore override both composed from [`FC_IFACE_ID`], which is precisely the divergence
/// that const's own doc claims to remove. Gated by
/// `fc_iface_id_single_source_gate::every_network_interface_path_here_is_composed_from_the_one_const`,
/// which reddens on a re-baked literal — the identity asserts alone cannot see a call site.
fn fc_network_interface_path(iface_id: &str) -> String {
    format!("/network-interfaces/{iface_id}")
}

/// Firecracker's `PUT /network-interfaces/<id>` body.
#[derive(Serialize, Debug, PartialEq, Eq)]
struct NetworkInterface {
    iface_id: String,
    host_dev_name: String,
    guest_mac: String,
}

/// Firecracker's `PUT /drives/<drive_id>` body.
///
/// `rate_limiter` is a **presence attribute** (`skip_serializing_if`): an unthrottled drive omits
/// the key entirely, which is FC's default (§4.6, Extra virtio-blk devices and disk-I/O
/// throttling). FC's engine channel is JSON, and `fc_drives_put_root_first_then_extras` pins the
/// omission on that codec.
#[derive(Serialize, Debug, PartialEq, Eq)]
struct Drive {
    drive_id: String,
    path_on_host: PathBuf,
    is_root_device: bool,
    is_read_only: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    rate_limiter: Option<FcRateLimiter>,
}

/// FC's `rate_limiter` — bandwidth (bytes/s) and ops (IOPS) token buckets, the SAME shape and
/// `size=rate`/`refill_time=IO_LIMIT_REFILL_TIME_MS` conversion as Cloud Hypervisor (one law, one
/// predicate, §4.6, Extra virtio-blk devices and disk-I/O throttling).
#[derive(Serialize, Debug, PartialEq, Eq)]
struct FcRateLimiter {
    #[serde(skip_serializing_if = "Option::is_none")]
    bandwidth: Option<FcTokenBucket>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ops: Option<FcTokenBucket>,
}

/// One token bucket of an [`FcRateLimiter`].
#[derive(Serialize, Debug, PartialEq, Eq)]
struct FcTokenBucket {
    size: u64,
    refill_time: u64,
}

/// Builds one bucket from a rate, using the shared refill window.
fn fc_token_bucket(rate: u64) -> FcTokenBucket {
    FcTokenBucket {
        size: rate,
        refill_time: vmcell::config::IO_LIMIT_REFILL_TIME_MS,
    }
}

/// Builds the FC drive list in `PUT` order: the **root drive first** (`/dev/vda`), then the extra
/// virtio-blk devices in configuration order (`/dev/vdb`, `/dev/vdc`, …, §4.6, Extra virtio-blk
/// devices and disk-I/O throttling). FC enumerates by attachment order, so this ordering is the
/// load-bearing contract with the cmdline's `root=/dev/vda`; each drive carries its own
/// `drive_id`, which is also its `PUT /drives/<drive_id>` path.
///
/// *Which* host file backs the root drive is the one law,
/// [`RootfsSource::effective_image`](vmcell::config::RootfsSource::effective_image) — the same
/// predicate the config boundary's duplicate-backing-file guard uses, so the guard can never
/// protect a file this wiring does not attach. **Whether it is writable** is the other one law,
/// [`RootfsSource::root_device_read_only`](vmcell::config::RootfsSource::root_device_read_only),
/// which owns the exhaustive per-variant match: `is_root_read_only` was open-coded `false` for a
/// `Block` root here, contradicting the `ro` the cmdline mounts it with (§4.7).
///
/// Pure (mirroring Cloud Hypervisor's `build_ch_disks`) so ordering, the root path and the
/// throttle mapping are gate-able without KVM: built inline in `create()`, the whole shape was
/// observable only from the live matrix.
fn build_fc_drives(cfg: &VmConfig) -> Vec<Drive> {
    let mut drives = Vec::with_capacity(1 + cfg.extra_disks.len());
    drives.push(Drive {
        drive_id: "rootfs".to_string(),
        path_on_host: cfg.rootfs.effective_image().to_path_buf(),
        is_root_device: true,
        is_read_only: cfg.rootfs.root_device_read_only(),
        rate_limiter: None,
    });
    for (i, disk) in cfg.extra_disks.iter().enumerate() {
        drives.push(Drive {
            drive_id: format!("extra{i}"),
            path_on_host: disk.image.clone(),
            is_root_device: false,
            is_read_only: disk.readonly,
            rate_limiter: disk.io_limit.as_ref().map(|limit| FcRateLimiter {
                bandwidth: limit.bandwidth_bytes_per_sec.map(fc_token_bucket),
                ops: limit.iops.map(fc_token_bucket),
            }),
        });
    }
    drives
}

/// One entry of Firecracker 1.8+'s `network_overrides` array on `PUT /snapshot/load`: rebind
/// the snapshotted interface `iface_id` to a **fresh** host tap instead of the baked one.
#[derive(Serialize, Debug, PartialEq, Eq)]
struct NetworkOverride {
    iface_id: String,
    host_dev_name: String,
}

/// Firecracker's `mem_backend` sub-object on `PUT /snapshot/load`.
#[derive(Serialize, Debug, PartialEq, Eq)]
struct MemBackend {
    backend_path: PathBuf,
    backend_type: String,
}

/// Firecracker's `PUT /snapshot/load` body.
///
/// `network_overrides` is a **presence attribute** (`skip_serializing_if`): a VM with no tap has
/// nothing to override, and a `PUT` body that is byte-identical to the pre-override one is what
/// keeps a tapless restore working against any FC that predates the field. So the key must vanish
/// entirely rather than serialize as `[]` or `null`. AGENTS ("any presence-attribute type
/// round-trips on the codec it actually ships over") — FC's engine channel is JSON
/// (`unix_api_request` → `serde_json::to_vec`), and `fc_snapshot_load_body_shapes` pins both
/// shapes on that codec.
#[derive(Serialize, Debug, PartialEq, Eq)]
struct SnapshotLoad {
    snapshot_path: PathBuf,
    mem_backend: MemBackend,
    resume_vm: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    network_overrides: Vec<NetworkOverride>,
}

/// Builds that request, with the guest MAC from the **one** [`vmcell::net::mac_math`] law.
///
/// Pure so the identity is gate-able without KVM — the other three backends pin their MAC through
/// a composed-argv/serialized-config test, and FC built this inline, so a constant MAC here left
/// the whole KVM-free suite green. It is load-bearing for §6.5: on a per-VM `/30` a duplicate MAC
/// is invisible, but two segment members share one L2 domain, where a backend-chosen or constant
/// MAC is a silent collision.
///
/// # Errors
/// Propagates [`vmcell::net::mac_math`]'s range error for an out-of-range vmid.
fn build_fc_network_interface(tap: &str, vmid: u32) -> Result<NetworkInterface> {
    Ok(NetworkInterface {
        iface_id: FC_IFACE_ID.to_string(),
        host_dev_name: tap.to_string(),
        guest_mac: vmcell::net::mac_math(vmid)?,
    })
}

/// Builds the `PUT /snapshot/load` body, rebinding the snapshotted interface onto the
/// restore's **fresh** tap when the orchestrator allocated one.
///
/// docs/78 M1 (`fc-restore-rebinds-baked-tap-name-dead-data-plane`): without
/// `network_overrides`, FC re-opens the `host_dev_name` the snapshot BAKED
/// (`<prefix>-tap-<old vmid>`) while the orchestrator has allocated a fresh vmid and plumbed
/// `<prefix>-tap-<new vmid>` in the new netns. Under the runner's ambient `CAP_NET_ADMIN` that
/// `TUNSETIFF` *succeeds* — it creates a fresh, down, unbridged tap — so the restore reports
/// success and every post-restore packet drops into an unplumbed orphan. The override is the
/// FC 1.8+ equivalent of CH's `net[].tap` restore-config rewrite (§8.2); it does **not** make
/// FC a `restore_rotates_host_paths` backend, which is about the *host socket* identity (the
/// vsock UDS is still re-bound verbatim).
///
/// `tap` is `None` for a VM the orchestrator gave no tap; the list then stays empty and the key
/// is omitted (see [`SnapshotLoad`]). Pure so both shapes are gate-able without KVM — the
/// create-path MAC defect (`fc_network_interface_carries_the_vmid_derived_mac`) proved that an
/// inline body inside `restore()` is testable only by a 70-s live matrix.
fn build_fc_snapshot_load(snapshot_dir: &Path, tap: Option<&str>) -> SnapshotLoad {
    SnapshotLoad {
        snapshot_path: snapshot_dir.join("snapshot_file"),
        mem_backend: MemBackend {
            backend_path: snapshot_dir.join("mem_file"),
            backend_type: "File".to_string(),
        },
        resume_vm: false,
        network_overrides: tap
            .map(|host_dev_name| NetworkOverride {
                iface_id: FC_IFACE_ID.to_string(),
                host_dev_name: host_dev_name.to_string(),
            })
            .into_iter()
            .collect(),
    }
}

/// Reaps a failed T2-probe child's process group and unlinks its API socket. On the
/// `wait_for_socket`-failure branch no `FcInstance` owns the socket yet (the instance
/// is built only after a successful wait), so its `Drop` never runs — without this,
/// firecracker that created its socket then exited early orphans a
/// [`T2_PROBE_SOCKET`] in the VM's scratch dir. Reap first (VMM process group before
/// sockets), then unlink, mirroring `FcInstance::drop`.
fn reap_and_unlink_probe(process: &mut tokio::process::Child, pgid: Option<u32>, socket: &Path) {
    vmcell::vmm::reap_process_group(process, pgid);
    let _ = std::fs::remove_file(socket);
}

/// The T2-probe VM's API socket, inside the VM's own scratch dir.
///
/// A distinct basename from `spawn_fc`'s `api.sock`, so the probe and the real VM never collide;
/// inside `res.tmp_dir` rather than bare `/tmp` so the orchestrator's `VmTempDir` guard reclaims it
/// even if this process is killed between spawn and reap (AGENTS.md, "Runtime files under
/// `XDG_RUNTIME_DIR` (or the artifacts dir), never bare `/tmp`"). It replaces a
/// `vmcell-fc-probe-<pid>-<nanos>.socket` in `std::env::temp_dir()`, whose uniqueness came from a
/// clock read rather than from an owned directory.
const T2_PROBE_SOCKET: &str = "t2-probe.sock";

/// Composes the T2 probe's launch: its API socket, plus the **same** [`LaunchPlan`] every real
/// Firecracker boot gets (M11).
///
/// The probe boots a real Firecracker VM. It used to spawn it from a hand-rolled
/// `std::process::Command::new(&vmm.binary_path)` — outside `firecracker_launch_plan`, so with no
/// Layer-2 jail, no `--no-seccomp`/`--seccomp-filter` flag and no netns join, while every other
/// Firecracker process on the host carried all three. The M11 source gate could not see it either:
/// it bans a *second* `jail_spec_from_config`/`build_vmm_cmd` call, and this path made neither
/// (docs/90 `vmcell-firecracker:789`). Routing it through the one composer is the fix; the gate's
/// new `Command::new` ban is what keeps a fourth spawn route from re-opening it.
///
/// Performs no I/O, so a KVM-free test asserts both halves — the shipped posture and the socket's
/// location — without spawning anything.
///
/// # Errors
/// Propagates [`firecracker_launch_plan`]'s errors: the [`VmmSeccomp::Log`] typed refusal (the
/// probe is a Firecracker process too, so it cannot honor an observe-only mode either) and a
/// deny-list that fails to compile. Both are deterministic config refusals, never a transient probe
/// failure — which is why they propagate instead of becoming [`T2Probe::Failed`] (VMM-4).
fn t2_probe_launch(
    binary_path: &Path,
    cfg: &VmConfig,
    res: &PerVmResources,
) -> Result<(PathBuf, vmcell::vmm::LaunchPlan)> {
    let api_socket = res.tmp_dir.join(T2_PROBE_SOCKET);
    let plan = firecracker_launch_plan(binary_path, cfg, res, &api_socket)?;
    Ok((api_socket, plan))
}

async fn probe_t2_template(
    vmm: &Firecracker,
    cfg: &VmConfig,
    res: &PerVmResources,
) -> Result<T2Probe> {
    // The whole launch — jail, seccomp flag, netns, `--api-sock` — from the one composer, so the
    // probe VM is confined exactly like the VM it is probing for.
    let (api_socket, plan) = t2_probe_launch(&vmm.binary_path, cfg, res)?;

    let mut process = match plan
        .into_command()
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
    {
        Ok(p) => p,
        // A spawn failure is transient host trouble (a missing binary, a fork limit), not evidence
        // about T2 — VMM-4 keeps it uncached.
        Err(_) => return Ok(T2Probe::Failed),
    };

    // The probe child is its own process-group leader (`process_group(0)`), so its
    // pid is the group id. Capture it immediately so every failure path below reaps
    // the whole group — never own a live firecracker with `pgid: None`, which would
    // orphan the process and leak it.
    let pgid = process.id();

    // VMM-3: use the shared `wait_for_socket` (which also `try_wait`s the child and
    // fails fast on an early exit) instead of a hand-rolled `try_exists`-only loop,
    // and reap the process *group* via `reap_process_group` on failure instead of the
    // leader-only, non-blocking `process.kill()` (which orphans the group).
    if vmcell::vmm::wait_for_vmm_socket(
        &api_socket,
        Some(&mut process),
        cfg.timeouts.api_socket_poll.as_millis() as u64,
    )
    .await
    .is_err()
    {
        reap_and_unlink_probe(&mut process, pgid, &api_socket);
        return Ok(T2Probe::Failed);
    }

    let instance = FcInstance {
        process,
        api_socket: api_socket.clone(),
        vsock_path: PathBuf::new(),
        serial_path: PathBuf::new(),
        cid: 0,
        group: vmcell::vmm::VmmProcessGroup::new(pgid),
        mem_mib: cfg.mem_mib,
        vhost_user_net: false,
        restored: false,
    };

    #[derive(Serialize)]
    struct MachineConfig {
        vcpu_count: u8,
        mem_size_mib: u32,
        smt: bool,
        cpu_template: Option<String>,
    }

    let mc_res = instance
        .api_request(
            "PUT",
            "/machine-config",
            Some(&MachineConfig {
                vcpu_count: 1,
                mem_size_mib: 128,
                smt: false,
                cpu_template: Some("T2".to_string()),
            }),
        )
        .await;

    if mc_res.is_err() {
        return Ok(T2Probe::Failed);
    }

    #[derive(Serialize)]
    struct BootSource {
        kernel_image_path: PathBuf,
        boot_args: String,
    }

    let bs_res = instance
        .api_request(
            "PUT",
            "/boot-source",
            Some(&BootSource {
                kernel_image_path: cfg.kernel.clone(),
                boot_args: "console=ttyS0 panic=1".to_string(),
            }),
        )
        .await;

    if bs_res.is_err() {
        return Ok(T2Probe::Failed);
    }

    #[derive(Serialize)]
    struct Action {
        action_type: String,
    }

    let boot_res = instance
        .api_request(
            "PUT",
            "/actions",
            Some(&Action {
                action_type: "InstanceStart".to_string(),
            }),
        )
        .await;

    Ok(classify_t2_boot(&boot_res))
}

impl Vmm for Firecracker {
    type Instance = FcInstance;

    async fn create(
        &self,
        cfg: &VmConfig,
        res: &PerVmResources,
        cgroups: &dyn vmcell::metrics::CgroupFs,
    ) -> Result<Self::Instance> {
        // FC has no virtio-console device, so a VirtioConsole config must be rejected
        // BEFORE build_kernel_cmdline — otherwise the boot args would carry
        // `console=hvc0` with no `hvc0` device and `serial.log` would stay empty.
        vmcell::vmm::reject_unsupported_console(
            "firecracker",
            &self.capabilities(),
            cfg.console_mode,
        )?;

        let caps = self.capabilities();
        // The two descriptor `false`s the rest of `create()` cannot see (`nested_virt`,
        // `lazy_restore`): refuse them here rather than boot a VM whose requested lever is
        // silently void.
        reject_unadvertised_capabilities(&caps, cfg)?;
        if let vmcell::config::NetConfig::Unprivileged { .. } = cfg.net
            && !caps.unprivileged_vhost_user_net
        {
            // N-VMM-1 is a TYPE LAW now (v33 F6): the feature string is `Feature::name()` by
            // construction, which IS the `VmmCapabilities` field name, pinned in both directions.
            return Err(Error::unsupported(
                "firecracker",
                vmcell::feature::Feature::UnprivilegedVhostUserNet,
            ));
        }
        if res.vhost_user_socket.is_some() {
            return Err(Error::Unsupported {
                vmm: "firecracker".to_string(),
                feature: "vhost_user_socket".to_string(),
            });
        }
        // FC has no USB controller (§2.4, QEMU q35 — the fallback and most-proven nester); refuse a passthrough request through the
        // ONE shared predicate rather than silently ignoring the accepted input.
        vmcell::vmm::reject_usb_host_devices("firecracker", &caps, &cfg.usb_host_devices)?;

        if !cfg.shares.is_empty() {
            return Err(Error::unsupported(
                "firecracker",
                vmcell::feature::Feature::VirtioFsShares,
            ));
        }

        let template = self.detect_cpu_template(cfg, res).await?;
        // `noxsave` is the extended-FPU restore-guard *fallback*, applied only when no
        // CPU template was chosen (see `noxsave_fallback`); capture the decision now,
        // before `template` is moved into the machine-config request below.
        let fpu_guard = noxsave_fallback(template.is_some());

        let (api_socket, vsock_path, serial_path, process, pgid) =
            self.spawn_fc(cfg, res, cgroups).await?;

        let instance = FcInstance {
            process,
            api_socket,
            vsock_path: vsock_path.clone(),
            serial_path: serial_path.clone(),
            cid: res.guest_cid,
            group: vmcell::vmm::VmmProcessGroup::new(pgid),
            // Always false here: the vhost-user-socket rejection above already
            // returned `Unsupported`. Computed from `res` to mirror CH and stay
            // correct if that guard ever moves.
            mem_mib: cfg.mem_mib,
            vhost_user_net: res.vhost_user_socket.is_some(),
            // Cold boot: `boot()` issues `InstanceStart` (not a resume).
            restored: false,
        };

        #[derive(Serialize)]
        struct MachineConfig {
            vcpu_count: u8,
            mem_size_mib: u32,
            smt: bool,
            cpu_template: Option<String>,
        }
        instance
            .api_request(
                "PUT",
                "/machine-config",
                Some(&MachineConfig {
                    vcpu_count: cfg.vcpus,
                    mem_size_mib: cfg.mem_mib,
                    smt: false,
                    cpu_template: template,
                }),
            )
            .await?;

        // Configure Boot Source
        #[derive(Serialize)]
        struct BootSource {
            kernel_image_path: PathBuf,
            boot_args: String,
        }

        let cmdline = vmcell::config::build_kernel_cmdline(cfg, res, fpu_guard)?;

        instance
            .api_request(
                "PUT",
                "/boot-source",
                Some(&BootSource {
                    kernel_image_path: cfg.kernel.clone(),
                    boot_args: cmdline,
                }),
            )
            .await?;

        // Configure the drives: root first, then the extra virtio-blk devices (§4.6, Extra
        // virtio-blk devices and disk-I/O throttling), PUT in `build_fc_drives` order so they
        // enumerate `/dev/vda`, `/dev/vdb`, `/dev/vdc`, … and an extra never displaces the root.
        // Each drive's `drive_id` IS its API path. FC's MMIO region is finite, so a very large
        // list surfaces fail-loud as the backend's typed API error here, never a silent drop.
        for drive in build_fc_drives(cfg) {
            let path = format!("/drives/{}", drive.drive_id);
            instance.api_request("PUT", &path, Some(&drive)).await?;
        }

        // Configure Network. Like the drives above, the interface's `iface_id` IS its API path
        // — composed through `fc_network_interface_path` from the one `FC_IFACE_ID`, so the
        // path, the body, and the restore path's `network_overrides` entry cannot drift apart
        // (a mismatch makes FC silently ignore the override and re-open the baked device).
        if let Some(tap) = &res.tap_name {
            let iface = build_fc_network_interface(tap, res.vmid)?;
            let path = fc_network_interface_path(&iface.iface_id);
            instance.api_request("PUT", &path, Some(&iface)).await?;
        }

        // Configure the entropy device (virtio-rng -> guest /dev/hwrng). The
        // steward's post-restore CSPRNG reseed reads 32 bytes of /dev/hwrng
        // into /dev/urandom (design §8.2, Restore correctness: a restored VM is not a fresh VM); CH always carries an rng device, but
        // FC only attaches one when explicitly configured — without it the
        // restored guest replays the snapshot-frozen entropy pool and the resync
        // ack reports `reseed_applied: false`. The device is snapshot-supported
        // in FC v1.16, so it travels through snapshot/load like the other
        // virtio-mmio devices.
        #[derive(Serialize)]
        struct Entropy {}
        instance
            .api_request("PUT", "/entropy", Some(&Entropy {}))
            .await?;

        // Configure Vsock
        #[derive(Serialize)]
        struct Vsock {
            guest_cid: u32,
            uds_path: PathBuf,
        }
        instance
            .api_request(
                "PUT",
                "/vsock",
                Some(&Vsock {
                    guest_cid: res.guest_cid,
                    uds_path: vsock_path.clone(),
                }),
            )
            .await?;

        Ok(instance)
    }

    async fn restore(
        &self,
        snapshot_dir: &Path,
        cfg: &VmConfig,
        res: &PerVmResources,
        cgroups: &dyn vmcell::metrics::CgroupFs,
    ) -> Result<Self::Instance> {
        // FC has no virtio-console device; reject a VirtioConsole config before any
        // spawn/build_kernel_cmdline so it can never emit `console=hvc0` with no
        // `hvc0` device.
        vmcell::vmm::reject_unsupported_console(
            "firecracker",
            &self.capabilities(),
            cfg.console_mode,
        )?;
        // Same self-check `create()` makes, on the path that actually consumes
        // `cfg.restore_mode`: a restore must not accept what create rejects.
        reject_unadvertised_capabilities(&self.capabilities(), cfg)?;
        // VMM-5: self-check the capability descriptor rather than assuming the
        // backend supports restore.
        if !self.capabilities().snapshot_restore {
            return Err(Error::unsupported(
                "firecracker",
                vmcell::feature::Feature::SnapshotRestore,
            ));
        }
        // M-RESTORE-3 / H-VMM-3 / snapshot-eligibility law: a snapshot-eligible VM has
        // no vhost-user device. Use the SHARED predicate (which also covers a virtio-fs
        // *rootfs* — the case FC's former inline check missed) to reject any virtio-fs
        // share/rootfs, unprivileged net, or external vhost-user-net handed to us via
        // the config, before spawning a VMM. FC never attaches these, so this is
        // defense in depth.
        if vmcell::vmm::config_has_vhost_user_device(cfg, res) {
            // The ONE shared refusal for this law, so the four backends cannot spell it four
            // ways again (which is what bred `feature.contains("vhost-user")` in three suites).
            return Err(Error::from_removal(
                "firecracker",
                &vmcell::feature::VHOST_USER_BLOCKS_SNAPSHOT,
            ));
        }

        // Recover the host vsock/serial UDS paths the snapshot baked in (see
        // `snapshot()` and `HOST_PATHS_SIDECAR`). Read this *before* spawning so a
        // corrupt/foreign snapshot fails loud without leaking a VMM process.
        let sidecar_path = snapshot_dir.join(HOST_PATHS_SIDECAR);
        let sidecar = tokio::fs::read_to_string(&sidecar_path).await?;
        let host_paths: SnapshotHostPaths = serde_json::from_str(&sidecar)?;

        // Firecracker rebinds the snapshot's recorded host vsock UDS at load time,
        // VERBATIM (`restore_rotates_host_paths: false`). Guard-then-clean the
        // baked path — reject a still-live listener, remove a stale leftover
        // (else the bind fails EADDRINUSE), resurrect the missing parent dir
        // (else `PUT /snapshot/load` fails ENOENT) — see `reject_live_baked_vsock`.
        // Runs BEFORE spawning, like the sidecar read above, so a rejected restore
        // fails loud without leaking a VMM process. The restored instance adopts
        // the path and its `Drop` removes the resurrected dir.
        reject_live_baked_vsock(&host_paths.vsock).await?;

        let (api_socket, _vsock_path, serial_path, process, pgid) =
            self.spawn_fc(cfg, res, cgroups).await?;

        let instance = FcInstance {
            process,
            api_socket,
            // Adopt the snapshot's vsock path so the steward dials the exact UDS FC
            // recreates verbatim on load (no load-time override). Serial is the
            // opposite: FC writes it to the FRESH `spawn_fc` stdout redirect
            // (`res.tmp_dir/serial.log`), NOT the snapshot's baked serial path — so
            // `serial_log()`/panic detection must point at the fresh path, or it reads
            // an empty/stale file FC never writes (VMM-6).
            //
            // That baked path is a pure function of (prefix, pid, ANCESTOR vmid), so this VM lives
            // in the ancestor's scratch dir while holding a freshly allocated vmid. Reporting it
            // through `vsock_path()` is what lets the orchestrator reserve the ancestor's vmid for
            // this VM's lifetime (M9, `vmcell::vmm::adopted_scratch_vmid`) — without which a later
            // VM draws that id and deletes this VM's directory out from under it.
            vsock_path: host_paths.vsock,
            serial_path,
            // A restored guest keeps the CID baked into its snapshot (the vsock device
            // is loaded verbatim); report that, not the orchestrator's fresh allocation
            // (M-VMM-3).
            cid: host_paths.cid,
            group: vmcell::vmm::VmmProcessGroup::new(pgid),
            mem_mib: cfg.mem_mib,
            // Guarded false above; computed from `res` to mirror CH.
            vhost_user_net: res.vhost_user_socket.is_some(),
            // Restored VMs are returned paused and resumed via `resume()`; `boot()`
            // self-guards on this and refuses to `InstanceStart` (VMM-6).
            restored: true,
        };

        // Load snapshot, rebinding the snapshotted interface onto THIS restore's freshly
        // allocated tap (`network_overrides`) — without it FC re-opens the baked
        // `<prefix>-tap-<old vmid>` and post-restore egress is silently dead (docs/78 M1; see
        // `build_fc_snapshot_load`).
        // Same guest-RAM-proportional class as `/snapshot/create` (M6): the load reads
        // the mem file back, so it is sized by the same shared predicate rather than the
        // flat control ceiling.
        instance
            .api_request_with(
                "PUT",
                "/snapshot/load",
                Some(&build_fc_snapshot_load(
                    snapshot_dir,
                    res.tap_name.as_deref(),
                )),
                vmcell::vmm::snapshot_request_timeout(instance.mem_mib),
            )
            .await?;

        Ok(instance)
    }

    fn capabilities(&self) -> VmmCapabilities {
        fc_capabilities()
    }

    fn id(&self) -> &str {
        "firecracker"
    }
}

impl VmInstance for FcInstance {
    async fn boot(&mut self) -> Result<()> {
        // VMM-6: a restored FC VM is returned paused by
        // `POST /snapshot/load {resume_vm:false}` and resumed via `resume()` — never
        // booted. Issuing `InstanceStart` on it is a misuse that would (re)start a
        // snapshot-loaded VM, so self-guard and fail loud (a silent `Ok(())` no-op
        // would violate the fail-loud contract) instead of `InstanceStart`-ing it.
        if self.restored {
            // NOT a `Feature`: an API-state refusal, not a capability absence — a restored VM is
            // resumed, not booted. It keeps a single snake_case token (never prose) so a caller
            // matches it exactly, which is the half of F6 that applies here.
            return Err(Error::Unsupported {
                vmm: "firecracker".to_string(),
                feature: "boot_after_restore".to_string(),
            });
        }
        #[derive(Serialize)]
        struct Action {
            action_type: String,
        }
        self.api_request(
            "PUT",
            "/actions",
            Some(&Action {
                action_type: "InstanceStart".to_string(),
            }),
        )
        .await
    }

    async fn request_shutdown(&mut self) -> Result<()> {
        #[derive(Serialize)]
        struct Action {
            action_type: String,
        }
        self.api_request(
            "PUT",
            "/actions",
            Some(&Action {
                action_type: "SendCtrlAltDel".to_string(),
            }),
        )
        .await
    }

    async fn kill(&mut self) -> Result<()> {
        // The one shared signal/wait/flag sequence (L1): SIGKILL the group unless the
        // leader was already reaped, await it, record the reap (M-VMM-1).
        self.group.kill_and_wait(&mut self.process).await;
        Ok(())
    }

    async fn has_exited(&mut self) -> bool {
        // Non-blocking reap of the VMM leader; `Ok(Some(_))` means it exited after
        // `request_shutdown`. The shared helper records the reap so `kill()`/`Drop`
        // cannot re-`SIGKILL` a possibly-recycled pgid.
        self.group.note_exit(&mut self.process)
    }

    async fn pause(&mut self) -> Result<()> {
        #[derive(Serialize)]
        struct Action {
            state: String,
        }
        self.api_request(
            "PATCH",
            "/vm",
            Some(&Action {
                state: "Paused".to_string(),
            }),
        )
        .await
    }

    async fn resume(&mut self) -> Result<()> {
        #[derive(Serialize)]
        struct Action {
            state: String,
        }
        self.api_request(
            "PATCH",
            "/vm",
            Some(&Action {
                state: "Resumed".to_string(),
            }),
        )
        .await
    }

    async fn snapshot(&mut self, dir: &Path) -> Result<()> {
        // M-RESTORE-3: self-check the capability descriptor and the
        // snapshot-eligibility law (no vhost-user device) before doing any work,
        // mirroring CH's `snapshot()` guards. A backend never assumes the caller
        // already checked.
        if !fc_capabilities().snapshot_restore {
            return Err(Error::unsupported(
                "firecracker",
                vmcell::feature::Feature::SnapshotRestore,
            ));
        }
        if vmcell::vmm::has_vhost_user_device(false, false, self.vhost_user_net) {
            return Err(Error::from_removal(
                "firecracker",
                &vmcell::feature::VHOST_USER_BLOCKS_SNAPSHOT,
            ));
        }

        #[derive(Serialize)]
        struct SnapshotCreate {
            snapshot_type: String,
            snapshot_path: PathBuf,
            mem_file_path: PathBuf,
        }

        self.pause().await?;

        // M6: `/snapshot/create` writes a dense mem file that tracks guest RAM ~1:1, so
        // it is budgeted against `mem_mib` through the shared predicate — the flat
        // control ceiling is a guaranteed spurious timeout on a multi-GiB guest, and a
        // spurious timeout here would strand the VM paused.
        let snap_res = self
            .api_request_with(
                "PUT",
                "/snapshot/create",
                Some(&SnapshotCreate {
                    snapshot_type: "Full".to_string(),
                    snapshot_path: dir.join("snapshot_file"),
                    mem_file_path: dir.join("mem_file"),
                }),
                vmcell::vmm::snapshot_request_timeout(self.mem_mib),
            )
            .await;

        // On success, persist the host vsock/serial UDS paths FC baked into the
        // snapshot so `restore()` can rebind/connect the exact socket it recreates
        // (FC offers no load-time vsock override). The sidecar is part of the
        // artifact and `restore()` hard-requires it, so a write failure is
        // propagated (M-RESTORE-2) — reporting an unrestorable snapshot as `Ok`
        // would only surface later as a confusing `restore()` error.
        let result = match snap_res {
            Ok(()) => write_host_paths_sidecar(dir, &self.vsock_path, self.cid).await,
            Err(e) => Err(e),
        };

        // Always attempt to resume so a snapshot of a still-live VM is not stranded
        // paused; a resume failure is non-fatal and only logged.
        if let Err(e) = self.resume().await {
            tracing::warn!("Failed to resume Firecracker after snapshot: {}", e);
        }

        result
    }

    fn vsock_path(&self) -> &Path {
        &self.vsock_path
    }

    fn guest_cid(&self) -> u32 {
        self.cid
    }

    fn serial_log(&self) -> &Path {
        &self.serial_path
    }
}

impl Drop for FcInstance {
    fn drop(&mut self) {
        // Teardown order (AGENTS.md): VMM process group first — reaping it before
        // touching the sockets or the per-VM directory means cleanup never races a
        // live VMM.
        // Same helper, same order as the graceful `kill()` path (L1): the group SIGKILL +
        // blocking reap is skipped if the leader was already reaped, since its pgid may
        // have been recycled (M-VMM-1).
        self.group.reap_now(&mut self.process);
        // Unlink our own sockets. The per-VM directory itself is owned and removed
        // once by the orchestrator's `VmTempDir` guard (after this instance and the
        // smoltcp process are dropped), not here. Mirrors CH.
        let _ = std::fs::remove_file(&self.api_socket);
        let _ = std::fs::remove_file(&self.vsock_path);
        // A RESTORED instance adopts the snapshot's baked vsock path, whose parent
        // dir `restore()` resurrected (it belongs to the long-gone base VM, so no
        // `VmTempDir` guard owns it). Remove it here — `remove_dir` is
        // non-recursive, so it only succeeds once empty, and it is a no-op for a
        // cold-booted instance whose vsock lives in the guard-owned scratch dir
        // (still holding api.sock/serial.log at this point, and removed by the
        // guard anyway).
        if let Some(parent) = self.vsock_path.parent() {
            let _ = std::fs::remove_dir(parent);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shared [`vmcell::metrics::FakeCgroupFs`], exposed by `vmcell`'s `test-support`
    /// feature (a dev-dependency of this crate). It replaces the hand-rolled per-crate
    /// `CgroupFs` fake this crate carried while `FakeCgroupFs` was `#[cfg(test)]`-only and
    /// therefore invisible downstream — one of four such copies (docs/81 §9).
    ///
    /// It is still structurally blind to the filesystem (AGENTS rule 4): it models slices,
    /// tasks and delegation in memory and writes no cgroup sysfs, so nothing driven by it is
    /// evidence about real cgroup residue or enforcement. That is `just test-privileged`.
    use vmcell::metrics::FakeCgroupFs;

    // v30 §18 delta 8, review fix: FC's guest MAC comes from the ONE `mac_math(vmid)` law, and the
    // JSON firecracker actually receives carries it.
    //
    // Buggy impl guarded: replacing `mac_math(res.vmid)` with a constant (say the QEMU default
    // `52:54:00:12:34:56`) left the ENTIRE KVM-free suite green — FC built its `NetworkInterface`
    // inline inside `spawn_fc`, so nothing pure was testable and only the live segment matrix
    // caught it, 73 s in. Both assertions below redden on that mutation: the identity, and the
    // per-vmid distinctness two members of one segment depend on.
    #[test]
    fn fc_network_interface_carries_the_vmid_derived_mac() {
        let a = build_fc_network_interface("vmcell-tap-7", 7).expect("a valid vmid builds");
        assert_eq!(a.iface_id, "eth0");
        assert_eq!(a.host_dev_name, "vmcell-tap-7");
        assert_eq!(
            a.guest_mac,
            vmcell::net::mac_math(7).expect("mac_math(7)"),
            "the guest MAC must be the one mac_math law, not a backend default"
        );

        // Bridge-uniqueness, the §6.5 premise: two members' MACs differ.
        let b = build_fc_network_interface("vmcell-tap-9", 9).expect("a valid vmid builds");
        assert_ne!(
            a.guest_mac, b.guest_mac,
            "two segment members on one bridge must not share a MAC"
        );

        // …and it survives serialization: this body is what FC is actually PUT.
        let json = serde_json::to_string(&a).expect("the request serializes");
        assert!(
            json.contains(&format!("\"guest_mac\":\"{}\"", a.guest_mac)),
            "the PUT body must carry the derived MAC: {json}"
        );

        // An out-of-range vmid is a typed error, not a silently truncated MAC.
        assert!(
            build_fc_network_interface("vmcell-tap-0", 0).is_err(),
            "vmid 0 has no valid MAC and must fail loud"
        );
    }

    // The drive list FC is PUT: root first (`/dev/vda`), then the extras in order
    // (`/dev/vdb`, …), each with its own id/readonly flag, and an unthrottled drive omitting
    // `rate_limiter` on the codec FC ships over (JSON). Built inline in `create()`, none of this
    // was observable without a live FC. Buggy impls guarded: extras PUT before the root (root
    // shifts off `/dev/vda` and the guest cannot mount it), an extra's `readonly` ignored, a
    // colliding `drive_id` (the second PUT overwrites the first), or a `rate_limiter: null` FC
    // rejects.
    #[test]
    fn fc_drives_put_root_first_then_extras() {
        use vmcell::config::{BlockDevice, DiskIoLimit, RootfsSource, VmConfig};

        let cfg = VmConfig::builder(
            "/vmlinux",
            RootfsSource::Erofs {
                image: PathBuf::from("/rootfs.erofs"),
            },
        )
        .with_extra_disk(BlockDevice::read_only("/img/ro.raw"))
        .with_extra_disk(
            BlockDevice::read_write("/img/rw.raw").with_io_limit(DiskIoLimit::bandwidth(2_000_000)),
        )
        .build()
        .expect("build config");

        let drives = build_fc_drives(&cfg);
        assert_eq!(
            drives,
            vec![
                // /dev/vda — the erofs root, read-only, unthrottled.
                Drive {
                    drive_id: "rootfs".to_string(),
                    path_on_host: cfg.rootfs.effective_image().to_path_buf(),
                    is_root_device: true,
                    is_read_only: true,
                    rate_limiter: None,
                },
                // /dev/vdb — the first extra disk, read-only.
                Drive {
                    drive_id: "extra0".to_string(),
                    path_on_host: PathBuf::from("/img/ro.raw"),
                    is_root_device: false,
                    is_read_only: true,
                    rate_limiter: None,
                },
                // /dev/vdc — the second extra disk, read-write and bandwidth-throttled with the
                // same `size=rate`, `refill_time=IO_LIMIT_REFILL_TIME_MS` bucket CH builds.
                Drive {
                    drive_id: "extra1".to_string(),
                    path_on_host: PathBuf::from("/img/rw.raw"),
                    is_root_device: false,
                    is_read_only: false,
                    rate_limiter: Some(FcRateLimiter {
                        bandwidth: Some(FcTokenBucket {
                            size: 2_000_000,
                            refill_time: vmcell::config::IO_LIMIT_REFILL_TIME_MS,
                        }),
                        ops: None,
                    }),
                },
            ]
        );

        // The unthrottled root omits `rate_limiter` entirely on the wire (FC's default).
        let json = serde_json::to_string(&drives[0]).expect("the request serializes");
        assert!(
            !json.contains("rate_limiter"),
            "an unthrottled drive must omit rate_limiter: {json}"
        );
    }

    // One law, one predicate (§13): the drive that becomes `/dev/vda` names
    // `RootfsSource::effective_image` — the SAME predicate the config boundary's
    // duplicate-backing-file guard uses. They used to be separate copies of
    // `overlay.as_ref().unwrap_or(image)`, so a divergence would have let the guard protect a
    // file this wiring does not attach. Expected values are recomputed THROUGH the helper, never
    // a test-local literal. Buggy impl this guards: PUTting the base image while an overlay is
    // set (guest writes land in the shared base) reddens the overlay leg.
    #[test]
    fn fc_root_drive_uses_the_effective_image_law() {
        use vmcell::config::{RootfsSource, VmConfig};

        let base = PathBuf::from("/img/base.raw");
        let overlay = PathBuf::from("/img/vm-7-overlay.raw");

        let root = |rootfs: RootfsSource| {
            let cfg = VmConfig::builder("/vmlinux", rootfs)
                .build()
                .expect("build config");
            let drive = build_fc_drives(&cfg).remove(0);
            (cfg, drive)
        };

        // Plain image: no overlay, so the base IS the effective image.
        let (plain_cfg, plain) = root(RootfsSource::Block {
            image: base.clone(),
            overlay: None,
        });
        assert_eq!(
            plain.path_on_host,
            plain_cfg.rootfs.effective_image(),
            "the root drive must be the effective image"
        );
        // The device's writability must not exceed the mount's, and the mount is always `ro`
        // (§4.7; `RootfsSource::root_device_read_only`). Asserted as the VALUE, not as equality
        // with the law — equality would be vacuous now that the wiring reads it. Reddens on the
        // pre-delta-8 `is_root_read_only = false`.
        assert!(
            plain.is_read_only,
            "a Block root drive must be attached READ-ONLY: the cmdline mounts it `ro` and F3 \
             reserves `rw`, so a writable attachment is a write path with no reader"
        );

        // Overlay set: the overlay backs /dev/vda, the base is never attached.
        let (ovl_cfg, ovl) = root(RootfsSource::Block {
            image: base.clone(),
            overlay: Some(overlay),
        });
        assert_eq!(
            ovl.path_on_host,
            ovl_cfg.rootfs.effective_image(),
            "with an overlay set, the overlay backs /dev/vda"
        );
        // Non-vacuous: the two paths genuinely differ.
        assert_ne!(
            ovl_cfg.rootfs.effective_image(),
            base,
            "the overlay case must not resolve to the base image"
        );

        // EROFS: the image itself, read-only.
        let (erofs_cfg, erofs) = root(RootfsSource::Erofs {
            image: PathBuf::from("/img/rootfs.erofs"),
        });
        assert_eq!(erofs.path_on_host, erofs_cfg.rootfs.effective_image());
        assert!(erofs.is_read_only, "an EROFS root is read-only");
    }

    // docs/78 M1 (`fc-restore-rebinds-baked-tap-name-dead-data-plane`): the `/snapshot/load`
    // body must rebind the snapshotted interface to THIS restore's fresh tap, and
    // `network_overrides` is a presence attribute — so both shapes are pinned on the codec FC
    // actually ships over (JSON, `unix_api_request` → `serde_json::to_vec`; AGENTS' postcard-trap
    // rule). Parsed back into a `Value` rather than substring-matched so "the key is ABSENT" is a
    // real assertion and not a `!contains` that a renamed field would satisfy.
    //
    // Buggy impls guarded: dropping `network_overrides` (today's shipped body) empties the Some
    // arm's array; `skip_serializing_if` removed serializes `"network_overrides":[]` on the None
    // arm; a second `"eth0"` literal that drifts from the create path
    // reddens the `FC_IFACE_ID` identity — the live consequence of all three is a silently dead
    // post-restore data plane, which only `snapshot_restore.rs`'s egress leg can see.
    #[test]
    fn fc_snapshot_load_body_shapes() {
        let dir = Path::new("/snap/lineage-1");

        let with_tap = build_fc_snapshot_load(dir, Some("vmcell-tap-42"));
        let json: serde_json::Value =
            serde_json::from_slice(&serde_json::to_vec(&with_tap).expect("the body serializes"))
                .expect("FC receives JSON");
        assert_eq!(json["snapshot_path"], "/snap/lineage-1/snapshot_file");
        assert_eq!(
            json["mem_backend"]["backend_path"],
            "/snap/lineage-1/mem_file"
        );
        assert_eq!(json["mem_backend"]["backend_type"], "File");
        assert_eq!(json["resume_vm"], false);
        let overrides = json["network_overrides"]
            .as_array()
            .expect("a tap-bearing restore must carry network_overrides");
        assert_eq!(
            overrides.len(),
            1,
            "exactly one override, for the one interface vmcell programs: {json}"
        );
        assert_eq!(
            overrides[0]["host_dev_name"], "vmcell-tap-42",
            "the override must name THIS restore's fresh tap, not the snapshot's baked one"
        );
        // The override binds by interface id: it must equal the id the CREATE path programmed,
        // or FC silently ignores the override and re-opens the baked device.
        assert_eq!(
            overrides[0]["iface_id"],
            serde_json::Value::from(FC_IFACE_ID)
        );
        assert_eq!(
            overrides[0]["iface_id"],
            serde_json::Value::from(
                build_fc_network_interface("vmcell-tap-42", 42)
                    .expect("a valid vmid builds")
                    .iface_id
            ),
            "the restore override and the create-path interface must share one iface_id"
        );

        // No tap → the key must VANISH (the body stays byte-identical to the pre-override one),
        // not serialize as `[]` or `null`.
        let no_tap = build_fc_snapshot_load(dir, None);
        let json: serde_json::Value =
            serde_json::from_slice(&serde_json::to_vec(&no_tap).expect("the body serializes"))
                .expect("FC receives JSON");
        assert!(
            json.get("network_overrides").is_none(),
            "a tapless restore must omit the presence attribute entirely, got {json}"
        );
        assert_eq!(json["resume_vm"], false);
    }

    // Guards VMM-4: the probe must distinguish a firm "T2 unsupported" (a 400 template
    // error) from a transient probe failure (a 500, a non-template 400, a timeout, a
    // transport error). The buggy inverse — the old code collapsed every `Err(_)` to
    // "not supported" — makes the 500/timeout/non-template assertions go red.
    #[test]
    fn classify_t2_boot_distinguishes_unsupported_from_failed() {
        assert_eq!(classify_t2_boot(&Ok(())), T2Probe::Supported);
        assert_eq!(
            classify_t2_boot(&Err(Error::VmmApi {
                status: 400,
                body: "cpu template T2 not supported".to_string(),
            })),
            T2Probe::Unsupported
        );
        // A 500 is a host error, NOT a firm "unsupported".
        assert_eq!(
            classify_t2_boot(&Err(Error::VmmApi {
                status: 500,
                body: "internal error".to_string(),
            })),
            T2Probe::Failed
        );
        // A 400 that isn't about the template is also just a failure, not "unsupported".
        assert_eq!(
            classify_t2_boot(&Err(Error::VmmApi {
                status: 400,
                body: "some other validation error".to_string(),
            })),
            T2Probe::Failed
        );
        // A non-API error (timeout / transport) is a transient failure.
        assert_eq!(
            classify_t2_boot(&Err(Error::Timeout("probe".to_string()))),
            T2Probe::Failed
        );
    }

    // Guards VMM-4: a TRANSIENT probe failure must NOT be cached (so the next VM
    // re-probes); only a definite Supported/Unsupported is cached. The buggy inverse
    // (`Failed => Some(None)`) permanently disables the T2 template — and the
    // extended-FPU restore guard — for every VM after a single host hiccup; here the
    // `Failed` assertion goes red.
    #[test]
    fn cache_decision_never_caches_transient_failure() {
        assert_eq!(cache_decision(T2Probe::Failed), None);
        assert_eq!(
            cache_decision(T2Probe::Supported),
            Some(Some("T2".to_string()))
        );
        assert_eq!(cache_decision(T2Probe::Unsupported), Some(None));
    }

    /// `noxsave` is the extended-FPU guard *fallback* — emitted only when no CPU
    /// template was applied. With a template it must be absent (it would needlessly
    /// disable the guest AVX2 the template leaves usable). The inverse — the former
    /// unconditional `noxsave` (audit E6, over-applied even with T2) — makes the
    /// `true` case go red.
    #[test]
    fn noxsave_only_applied_without_cpu_template() {
        assert_eq!(noxsave_fallback(false), "noxsave ");
        assert_eq!(noxsave_fallback(true), "");
    }

    /// Spawns a long-lived stand-in process in its own process group so an
    /// `FcInstance` can own a real `Child` (whose `Drop`/`kill` reaps the group) in a
    /// test that never boots a real VM.
    fn spawn_group_standin() -> Child {
        let mut std_cmd = std::process::Command::new("sleep");
        std_cmd.arg("60");
        use std::os::unix::process::CommandExt;
        std_cmd.process_group(0);
        tokio::process::Command::from(std_cmd)
            .spawn()
            .expect("spawn sleep stand-in")
    }

    /// Spawns a stand-in Firecracker API socket on `sock`: it answers `204` to every
    /// request immediately, except on `stall_path`, where it first waits `stall`
    /// (`None` = never answers). Returns the shared log of `"<METHOD> <path>"` in
    /// arrival order — which is how the snapshot test observes that the VM was resumed.
    ///
    /// One connection per request (that is what `unix_api_request` does), so each is
    /// served on its own task and a stalled snapshot cannot block the resume behind it.
    fn spawn_fake_fc_api(
        sock: &Path,
        stall_path: &'static str,
        stall: Option<std::time::Duration>,
    ) -> std::sync::Arc<std::sync::Mutex<Vec<String>>> {
        let listener = tokio::net::UnixListener::bind(sock).expect("bind fake FC API socket");
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let log = std::sync::Arc::clone(&seen);
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let log = std::sync::Arc::clone(&log);
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let mut buf = vec![0u8; 4096];
                    let Ok(n) = stream.read(&mut buf).await else {
                        return;
                    };
                    let head = String::from_utf8_lossy(&buf[..n]).into_owned();
                    let mut words = head.split_whitespace();
                    let method = words.next().unwrap_or_default().to_string();
                    let path = words.next().unwrap_or_default().to_string();
                    log.lock()
                        .expect("fake API log")
                        .push(format!("{method} {path}"));
                    if path == stall_path {
                        match stall {
                            Some(d) => tokio::time::sleep(d).await,
                            None => std::future::pending::<()>().await,
                        }
                    }
                    // The client may already have timed out and dropped the connection;
                    // a write to that closed peer is expected, not a test failure.
                    if stream
                        .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                        .await
                        .is_err()
                    {
                        return;
                    }
                    if stream.flush().await.is_err() {
                        return;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                });
            }
        });
        seen
    }

    // Guards M6 on the Firecracker side: `/snapshot/create` writes a mem file that
    // tracks guest RAM ~1:1, so it rides `vmcell::vmm::snapshot_request_timeout(mem_mib)`,
    // NOT the flat 5 s control ceiling every other RPC uses. The fake API stalls 6 s on
    // the create — past that ceiling, well inside a 2 GiB guest's budget (37 s) — so the
    // snapshot must SUCCEED, and pause → create → resume must all reach the wire (a
    // snapshot that leaves the VM paused is a wedged VM). Real time deliberately: a
    // paused clock auto-advances past the budget while hyper's multi-hop reply is still
    // in flight.
    // Inverse (route `/snapshot/create` back through the shared-ceiling `api_request`):
    // the 6 s stall exceeds 5 s and the `expect` on Ok reddens with a typed Timeout.
    #[tokio::test]
    async fn snapshot_rpc_is_budgeted_against_guest_ram_not_the_control_ceiling() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let sock = dir.path().join("api.sock");
        let seen = spawn_fake_fc_api(
            &sock,
            "/snapshot/create",
            Some(std::time::Duration::from_secs(6)),
        );

        let child = spawn_group_standin();
        let mut inst = FcInstance {
            group: vmcell::vmm::VmmProcessGroup::new(child.id()),
            process: child,
            api_socket: sock,
            vsock_path: dir.path().join("vsock.sock"),
            serial_path: PathBuf::new(),
            cid: 3,
            mem_mib: 2048,
            vhost_user_net: false,
            restored: false,
        };

        inst.snapshot(dir.path())
            .await
            .expect("a 6 s /snapshot/create must fit a 2 GiB guest's budget");

        let calls = seen.lock().expect("fake API log").clone();
        assert_eq!(
            calls,
            vec![
                "PATCH /vm".to_string(),
                "PUT /snapshot/create".to_string(),
                "PATCH /vm".to_string(),
            ],
            "snapshot must be pause → create → resume"
        );
        inst.kill().await.expect("reap the stand-in VMM");
    }

    // The T2-probe `wait_for_socket`-failure branch must unlink its API socket: no
    // FcInstance owns it there, so `Drop` never does. Residue check: the socket exists
    // before, is gone after. RED on the inverse (reap-only, no remove_file): the file
    // survives and `assert!(!socket.exists())` reddens.
    #[tokio::test]
    async fn reap_and_unlink_probe_removes_the_probe_socket() {
        let socket = std::env::temp_dir().join(format!(
            "vmcell-fc-probe-test-{}.socket",
            std::process::id()
        ));
        std::fs::write(&socket, b"").expect("seed probe socket");
        assert!(
            socket.exists(),
            "precondition: the probe socket exists before cleanup"
        );
        let mut child = spawn_group_standin();
        let pgid = child.id();
        reap_and_unlink_probe(&mut child, pgid, &socket);
        assert!(
            !socket.exists(),
            "the failed-probe branch must unlink its API socket"
        );
    }

    fn instance_with(restored: bool) -> FcInstance {
        let child = spawn_group_standin();
        FcInstance {
            group: vmcell::vmm::VmmProcessGroup::new(child.id()),
            process: child,
            // A deliberately-absent api socket: a restored VM must refuse boot BEFORE
            // any api_request, so this path is never dialed on that branch.
            api_socket: std::env::temp_dir().join("vmcell-fc-boot-test-nonexistent.sock"),
            vsock_path: PathBuf::new(),
            serial_path: PathBuf::new(),
            cid: 3,
            mem_mib: 128,
            vhost_user_net: false,
            restored,
        }
    }

    // Guards VMM-6: a restored FC instance must REFUSE `boot()` — a restored VM is
    // returned paused and resumed via `resume()`, never `InstanceStart`ed. The guard is
    // checked before any api_request, so it returns without touching the absent api
    // socket. The buggy inverse (no `restored` flag / no guard) would `InstanceStart` a
    // restored VM; here the restored assertion goes red. The cold instance must NOT
    // report boot-after-restore (it proceeds to InstanceStart and fails on the missing
    // socket with a transport error), which proves the `restored` flag is load-bearing.
    #[tokio::test]
    async fn restored_instance_refuses_boot() {
        let mut restored = instance_with(true);
        let err = restored
            .boot()
            .await
            .expect_err("a restored VM must refuse boot()");
        assert!(
            // An exact token, not a substring: the refusal spells `boot_after_restore`
            // (single snake_case, never prose) precisely so this can be an equality (F6).
            matches!(&err, Error::Unsupported { vmm, feature }
                if vmm == "firecracker" && feature == "boot_after_restore"),
            "expected boot-after-restore Unsupported, got {err:?}"
        );
        let _ = restored.kill().await;

        let mut cold = instance_with(false);
        let err = cold
            .boot()
            .await
            .expect_err("a cold VM with no api socket hits a transport error");
        assert!(
            !matches!(&err, Error::Unsupported { feature, .. } if feature == "boot_after_restore"),
            "a cold instance must not report boot-after-restore, got {err:?}"
        );
        let _ = cold.kill().await;
    }

    // Guards VMM-4: the CPU-template cache must live on the instance, not in a
    // process-global. The buggy impl (a `static OnceLock`) would let one
    // `Firecracker`'s probe result leak into a second, independently-configured
    // instance.
    #[test]
    fn cpu_template_cache_is_per_instance() {
        let a = Firecracker::new("/usr/bin/firecracker");
        let b = Firecracker::new("/usr/bin/firecracker");

        // Seed only `a`'s cache.
        let _ = a.cpu_template.set(Some("T2".to_string()));

        assert_eq!(a.cpu_template.get(), Some(&Some("T2".to_string())));
        // `b` has an independent, still-empty cache.
        assert_eq!(b.cpu_template.get(), None);
    }

    // Guards the capability HONESTY in both directions: `snapshot_restore` is
    // advertised `true` only because the full FC restore matrix assertion set was
    // re-validated on a KVM host (EXP-E, docs/45 — the historical E2 drop predated
    // the generic re-bind + native resync); `lazy_restore` stays honest-false until
    // a real UFFD backend is wired (M-VMM-1 — Lazy would silently degrade to eager).
    // A regression that turns FC restore back into the E2 symptom must flip the
    // capability AND this test together, with the failure recorded in docs/45.
    #[test]
    fn capabilities_are_honest_about_snapshot_restore() {
        let caps = Firecracker::new("/usr/bin/firecracker").capabilities();
        assert!(
            caps.snapshot_restore,
            "FC snapshot_restore is KVM-validated ON (EXP-E); a deliberate re-gate must update docs/45"
        );
        assert!(
            !caps.lazy_restore,
            "FC lazy_restore must be false until a real UFFD backend is wired (M-VMM-1)"
        );
        // FC re-binds the snapshot's baked host vsock UDS path VERBATIM (no
        // load-time override in v1.16); advertising rotation would let callers
        // assume fresh per-restore paths FC cannot provide (and would flip the
        // snapshot_restore integration test onto the CH-only rotation asserts).
        assert!(
            !caps.restore_rotates_host_paths,
            "FC restore_rotates_host_paths must be false: /snapshot/load re-binds the \
             baked path verbatim"
        );
        // CH, by contrast, rewrites the restore config so the vsock lands in the NEW
        // VM's scratch dir (§8.2, Restore correctness: a restored VM is not a fresh VM) — the rotation semantics the integration test's
        // `assert_ne` branch encodes.
        assert!(
            vmcell::vmm::cloud_hypervisor::CloudHypervisor::new("/usr/bin/cloud-hypervisor")
                .capabilities()
                .restore_rotates_host_paths,
            "CH restore_rotates_host_paths must be true: the restore config rewrite \
             moves host socket paths into the restored VM's own scratch dir"
        );
        // The instance-facing free function and the `Vmm` trait method must agree, so
        // `FcInstance::snapshot`'s self-check sees the same gate the orchestrator does.
        // FC's device model has no USB controller at all (§2.4), so a USB config is
        // rejected at create() rather than silently dropped (v30 §18 delta 9).
        assert!(
            !caps.usb_host_passthrough,
            "FC has no USB device model; a true would silently drop the requested device"
        );
        assert_eq!(caps.snapshot_restore, fc_capabilities().snapshot_restore);
        assert_eq!(caps.lazy_restore, fc_capabilities().lazy_restore);
        assert_eq!(
            caps.usb_host_passthrough,
            fc_capabilities().usb_host_passthrough
        );
        assert_eq!(
            caps.restore_rotates_host_paths,
            fc_capabilities().restore_rotates_host_paths
        );
    }

    // Guards H-VMM-3: FC restore()'s snapshot-eligibility guard must reject a virtio-fs
    // data share (a vhost-user device) via the SHARED `config_has_vhost_user_device`
    // predicate. It returns BEFORE reading the sidecar or spawning, so no KVM/snapshot
    // artifact is needed. Inverse (an inline check that never consulted the shared
    // predicate) falls through to the sidecar read and fails with an I/O error, not
    // this typed vhost-user Unsupported — reddening the assert.
    #[tokio::test]
    async fn restore_rejects_virtio_fs_share() {
        use vmcell::config::{Access, CachePolicy, RootfsSource, Share};
        let fc = Firecracker::new("/usr/bin/firecracker");
        let cfg = VmConfig::builder(
            "/k",
            RootfsSource::Erofs {
                image: PathBuf::from("/i"),
            },
        )
        .with_share(Share::new(
            "data",
            "/tmp/data",
            Access::ReadOnly,
            CachePolicy::Auto,
        ))
        .build()
        .expect("build virtio-fs share config");
        let res = PerVmResources {
            cgroup_name: "vmcell-test".to_string(),
            tap_name: Some("tap0".to_string()),
            netns_name: None,
            segment: None,
            vhost_user_socket: None,
            vmid: 1,
            guest_cid: 3,
            tmp_dir: std::env::temp_dir().join("vmcell-fc-restore-vfs-test"),
        };
        let cgroups = FakeCgroupFs::new();
        let err = fc
            .restore(Path::new("/nonexistent-snapshot"), &cfg, &res, &cgroups)
            .await
            .expect_err("FC restore must reject a virtio-fs data share");
        assert!(
            // F6: every snapshot refusal spells `snapshot_restore`, and `vmm` carries the
            // provenance. This leg discriminates by asserting BOTH — a config-sourced removal,
            // not the backend's own — so re-keying the guard to the descriptor reddens it.
            matches!(&err, Error::Unsupported { vmm, feature }
                if vmm.starts_with("firecracker")
                    && vmm.contains("vhost-user")
                    && feature == vmcell::feature::Feature::SnapshotRestore.name()),
            "expected a snapshot_restore Unsupported naming the vhost-user config, got {err:?}"
        );
    }

    // Guards N-VMM-1: the Unsupported.feature string for unprivileged networking must
    // match the VmmCapabilities field name (`unprivileged_vhost_user_net`), not the
    // ad-hoc `unprivileged_net`. create() reaches this check before spawning, so no KVM
    // is needed. Inverse (the old "unprivileged_net" literal) reddens the assert.
    #[tokio::test]
    async fn create_rejects_unprivileged_net_with_capability_field_name() {
        use vmcell::config::{Egress, NetConfig, RootfsSource};
        let fc = Firecracker::new("/usr/bin/firecracker");
        let cfg = VmConfig::builder(
            "/k",
            RootfsSource::Erofs {
                image: PathBuf::from("/i"),
            },
        )
        .net(NetConfig::Unprivileged {
            egress: Egress::default(),
            host_services_port: None,
        })
        .build()
        .expect("build unprivileged config");
        let res = PerVmResources {
            cgroup_name: "vmcell-test".to_string(),
            tap_name: None,
            netns_name: None,
            segment: None,
            vhost_user_socket: None,
            vmid: 1,
            guest_cid: 3,
            tmp_dir: std::env::temp_dir().join("vmcell-fc-unpriv-test"),
        };
        let cgroups = FakeCgroupFs::new();
        let err = fc
            .create(&cfg, &res, &cgroups)
            .await
            .expect_err("FC has no unprivileged vhost-user-net");
        assert!(
            matches!(&err, Error::Unsupported { vmm, feature }
                if vmm == "firecracker" && feature == "unprivileged_vhost_user_net"),
            "expected the capability-field-name feature string, got {err:?}"
        );
    }

    /// Resources for the reject-before-spawn tests: `tmp_dir` deliberately names a directory
    /// that does not exist, so a config that passes every guard dies in `spawn_fc`'s
    /// `File::create(serial.log)` with an I/O error — fast, and leaving no residue to clean up.
    fn reject_test_resources(tag: &str) -> PerVmResources {
        PerVmResources {
            cgroup_name: "vmcell-test".to_string(),
            tap_name: None,
            netns_name: None,
            segment: None,
            vhost_user_socket: None,
            vmid: 1,
            guest_cid: 3,
            tmp_dir: std::env::temp_dir().join(format!("vmcell-fc-absent-{tag}")),
        }
    }

    /// A backend whose binary does not exist either, for the positive controls: an ACCEPTED
    /// config must travel past the capability guards into the spawn, where it fails with
    /// something that is not a typed capability refusal.
    fn firecracker_that_cannot_spawn() -> Firecracker {
        Firecracker::new("/nonexistent/vmcell-fc-positive-control")
    }

    fn erofs_builder() -> vmcell::config::VmConfigBuilder {
        VmConfig::builder(
            "/k",
            vmcell::config::RootfsSource::Erofs {
                image: PathBuf::from("/i"),
            },
        )
    }

    // docs/81 d7: the descriptor says `nested_virt: false`, but the SHARED
    // `build_kernel_cmdline` emits `kvm-intel.nested=1` for every backend on `cfg.nested_virt`
    // — so an accepted request used to boot a guest whose L1 `/dev/kvm` never appears. The
    // refusal must fire before any spawn, with the `VmmCapabilities` field name as the feature
    // string (N-VMM-1). Inverse (deleting the `reject_unadvertised_capabilities` call, or
    // spelling the feature `nested` / `nested-virt`) reddens the assert.
    #[tokio::test]
    async fn create_rejects_nested_virt_with_capability_field_name() {
        let fc = Firecracker::new("/usr/bin/firecracker");
        let cfg = erofs_builder()
            .nested_virt(true)
            .build()
            .expect("build nested-virt config");
        let err = fc
            .create(&cfg, &reject_test_resources("nested"), &FakeCgroupFs::new())
            .await
            .expect_err("FC advertises nested_virt: false");
        assert!(
            matches!(&err, Error::Unsupported { vmm, feature }
                if vmm == "firecracker" && feature == "nested_virt"),
            "expected a nested_virt Unsupported, got {err:?}"
        );
    }

    // docs/81 d7: `lazy_restore` is honest-false (no UFFD backend; `restore` hardcodes
    // `backend_type: "File"`), so a `RestoreMode::Lazy` config silently faulted eagerly. Both
    // entry points must refuse it — `restore()` is the one that actually consumes
    // `restore_mode`, and a restore that accepts what create rejects is the crosvm M4 defect.
    // Inverse (dropping either call site) reddens that leg's assert.
    #[tokio::test]
    async fn create_and_restore_reject_lazy_restore_with_capability_field_name() {
        let fc = Firecracker::new("/usr/bin/firecracker");
        let cfg = erofs_builder()
            .restore_mode(vmcell::config::RestoreMode::Lazy)
            .build()
            .expect("build lazy-restore config");
        for err in [
            fc.create(&cfg, &reject_test_resources("lazy"), &FakeCgroupFs::new())
                .await
                .expect_err("FC advertises lazy_restore: false"),
            fc.restore(
                Path::new("/nonexistent-snapshot"),
                &cfg,
                &reject_test_resources("lazy-restore"),
                &FakeCgroupFs::new(),
            )
            .await
            .expect_err("restore must refuse exactly what create refuses"),
        ] {
            assert!(
                matches!(&err, Error::Unsupported { vmm, feature }
                    if vmm == "firecracker" && feature == "lazy_restore"),
                "expected a lazy_restore Unsupported, got {err:?}"
            );
        }
    }

    // The positive control for both refusals above (AGENTS.md: a negative security/capability
    // result needs a positive control): the ALLOWED configs — `nested_virt: false`, and each
    // `RestoreMode` the descriptor can honor — must travel PAST the capability guards. They
    // cannot reach a booted VM without KVM, so the control asserts on where they die: in the
    // spawn, never as one of these typed refusals. Inverse (a guard that ignores `caps` and
    // refuses unconditionally) reddens this immediately.
    #[tokio::test]
    async fn create_accepts_what_the_descriptor_advertises() {
        let fc = firecracker_that_cannot_spawn();
        for mode in [
            vmcell::config::RestoreMode::Default,
            vmcell::config::RestoreMode::Eager,
        ] {
            let cfg = erofs_builder()
                .nested_virt(false)
                .restore_mode(mode)
                .build()
                .expect("build an advertised config");
            let err = fc
                .create(
                    &cfg,
                    &reject_test_resources("positive-control"),
                    &FakeCgroupFs::new(),
                )
                .await
                .expect_err("the absent binary and scratch dir end the spawn");
            assert!(
                !matches!(&err, Error::Unsupported { feature, .. }
                    if feature == "nested_virt" || feature == "lazy_restore"),
                "an advertised config must reach the spawn, not a capability refusal: {err:?}"
            );
        }
    }

    // The refusals must key off the ONE descriptor value, not a hardcoded `false` beside the
    // check — otherwise a future flag flip leaves the refusal behind (the divergence class
    // `reject_usb_host_devices` exists to prevent). Feeding a synthetic descriptor that
    // advertises both proves the branch reads `caps`: inverse (`if cfg.nested_virt {` with no
    // `&& !caps.nested_virt`) reddens the `advertised` leg.
    #[test]
    fn capability_refusals_read_the_descriptor_not_a_hardcoded_bool() {
        let cfg = erofs_builder()
            .nested_virt(true)
            .restore_mode(vmcell::config::RestoreMode::Lazy)
            .build()
            .expect("build a config asking for both");
        // The shipped descriptor: both refused, and the feature strings ARE the field names.
        let shipped = fc_capabilities();
        assert!(!shipped.nested_virt && !shipped.lazy_restore);
        let err = reject_unadvertised_capabilities(&shipped, &cfg)
            .expect_err("the shipped descriptor advertises neither");
        assert!(
            matches!(&err, Error::Unsupported { vmm, feature }
                if vmm == "firecracker" && feature == "nested_virt"),
            "expected a nested_virt Unsupported, got {err:?}"
        );
        // A descriptor that advertised them accepts the same config, at the same call site.
        let advertised = VmmCapabilities {
            nested_virt: true,
            lazy_restore: true,
            ..shipped
        };
        reject_unadvertised_capabilities(&advertised, &cfg)
            .expect("a descriptor that advertises both must accept the same config");
    }

    // docs/81 d6: FC matches a `network_overrides` entry to a snapshotted device BY ITS ID, so
    // the create-path URL, the create-path body, and the restore override must all derive from
    // the one `FC_IFACE_ID` — a drifted URL is an FC 400, a drifted override id is a silently
    // ignored override and a dead post-restore data plane. The last assert proves the path is
    // COMPOSED (a re-baked literal would ignore its argument); the call site itself is guarded
    // by `fc_iface_id_single_source_gate`, which this identity test structurally cannot see.
    #[test]
    fn iface_id_is_the_one_source_for_url_body_and_restore_override() {
        let iface = build_fc_network_interface("vmcell-tap-42", 42).expect("a valid vmid builds");
        assert_eq!(iface.iface_id, FC_IFACE_ID, "the create-path body's id");

        let url = fc_network_interface_path(&iface.iface_id);
        assert_eq!(
            url.rsplit('/').next(),
            Some(iface.iface_id.as_str()),
            "the create-path URL's last segment IS the body's iface_id, got {url}"
        );

        let load = build_fc_snapshot_load(Path::new("/snap/lineage-1"), Some("vmcell-tap-42"));
        let override_id = &load
            .network_overrides
            .first()
            .expect("a tap-bearing restore carries one override")
            .iface_id;
        assert_eq!(override_id, &iface.iface_id, "the restore override's id");

        assert_eq!(
            fc_network_interface_path("eth9"),
            "/network-interfaces/eth9",
            "the URL must be composed from the id it is given, never a baked literal"
        );
    }

    // Guards M-VMM-1: `has_exited` must RECORD the leader's reap so `kill`/`Drop` do not
    // re-`SIGKILL` a possibly-recycled pgid. The flag now lives inside the shared
    // `vmcell::vmm::VmmProcessGroup`, so this asserts it through `is_reaped()` — the only
    // reader there is; nothing outside `vmcell::vmm` can set it.
    //
    // Inverse: route `has_exited` to a bare `self.process.try_wait()` instead of
    // `self.group.note_exit(...)` and the flag stays false, reddening the assert.
    #[tokio::test]
    async fn has_exited_records_reaped() {
        let mut inst = instance_with(false);
        // Kill the stand-in leader so `has_exited` observes an exited process. By pid,
        // not `-pgid`: the group is owned by `VmmProcessGroup` and deliberately hands
        // its pgid back to nobody.
        if let Some(pid) = inst.process.id() {
            let _ = nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(pid as i32),
                nix::sys::signal::Signal::SIGKILL,
            );
        }
        let mut exited = false;
        for _ in 0..100 {
            if inst.has_exited().await {
                exited = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(exited, "has_exited must report the killed leader as exited");
        assert!(
            inst.group.is_reaped(),
            "has_exited must record `reaped` after reaping the leader (M-VMM-1)"
        );
    }

    // POSITIVE CONTROL for the gate above, and the gate on `Drop`'s OWN job: an instance whose
    // group has NOT been reaped must have its process group SIGKILLed + reaped when it is dropped
    // (L1 — `Drop` is the panic path of the one teardown order). Without this leg the
    // "must not signal a recycled pgid" assertion is satisfied by a `Drop` that reaps NOTHING —
    // which is precisely the regression the Firecracker consolidation introduced and this leg caught: a
    // dropped-but-never-killed VM would leak its whole process group.
    //
    // Inverse (observed red): delete `self.group.reap_now(&mut self.process)` from `Drop` and the
    // stand-in survives, so `gone` stays false.
    #[tokio::test]
    async fn drop_reaps_an_unreaped_process_group() {
        let inst = instance_with(false);
        let live_pid = inst.process.id().expect("stand-in pid") as i32;
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

    // Guards M-VMM-1 on the SHIPPED call sites (not on the extracted helper): once the
    // leader is reaped its pgid can be recycled, so neither `FcInstance::kill` NOR
    // `FcInstance`'s `Drop` may `SIGKILL` `-pgid`. A live decoy process in its own group
    // stands in for that recycled group, and BOTH teardown paths are driven against the
    // same already-reaped instance — a backend that routed only one of them through the
    // shared helper is exactly the divergence this consolidation removes.
    //
    // Inverses, each observed red: (a) replace `self.group.kill_and_wait(&mut
    // self.process).await` in `kill` with a raw `reap_process_group(&mut self.process,
    // Some(decoy))`-style unguarded signal, or (b) replace `self.group.reap_now(&mut
    // self.process)` in `Drop` with a raw `vmcell::vmm::reap_process_group(...)` — either
    // kills the decoy and reddens the assert below.
    #[tokio::test]
    async fn kill_and_drop_do_not_signal_pgid_when_reaped() {
        // Decoy occupying a pgid, in its own process group.
        let mut decoy = spawn_group_standin();
        let decoy_pid = decoy.id().expect("decoy pid") as i32;

        // The instance's own leader is already gone (the group is already reaped). Use a
        // fast-exiting child so `kill`'s `process.wait()` returns promptly instead of
        // blocking.
        let leader = tokio::process::Command::new("true")
            .spawn()
            .expect("spawn `true` leader");
        let mut inst = FcInstance {
            process: leader,
            api_socket: PathBuf::new(),
            vsock_path: PathBuf::new(),
            serial_path: PathBuf::new(),
            cid: 3,
            // The recycled-pgid state, which only the `test-support` constructor can
            // fabricate: no production path can mark a group reaped over a foreign pgid.
            group: vmcell::vmm::VmmProcessGroup::already_reaped_for_test(Some(decoy_pid as u32)),
            mem_mib: 128,
            vhost_user_net: false,
            restored: false,
        };
        inst.kill().await.expect("kill");
        assert!(
            inst.group.is_reaped(),
            "the group must still read as reaped after kill() — the flag is one-shot"
        );
        // The `Drop` leg: dropping the instance must not re-signal either.
        drop(inst);

        // A SIGKILL to the (recycled) pgid would land within a few ms; give it time.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let decoy_status = decoy.try_wait().expect("try_wait decoy");
        // Clean up the decoy regardless of the outcome — a test's own fixtures are
        // residue too.
        let _ = nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(-decoy_pid),
            nix::sys::signal::Signal::SIGKILL,
        );
        let _ = decoy.wait().await;

        assert!(
            decoy_status.is_none(),
            "kill()/Drop on a reaped instance must not SIGKILL a (recycled) pgid — the decoy died"
        );
    }

    // Guards M-RESTORE-2 + M-VMM-3: the restore sidecar is part of the snapshot
    // artifact, so a write failure must be SURFACED, not swallowed. The buggy impl
    // (`let _ = tokio::fs::write(...).await; Ok(())`) returns `Ok` even when the
    // write fails, making `snapshot()` report an unrestorable snapshot as success;
    // the failure-path assert below then goes red. The happy path round-trips the
    // vsock path AND the baked guest CID so `restore()` can rebind the socket and
    // report the CID — inverse (drop the `cid` field / read a fresh CID) reddens the
    // CID assertion.
    #[tokio::test]
    async fn sidecar_write_round_trips_and_surfaces_errors() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vsock = PathBuf::from("/tmp/vmcell-vsock.sock");
        let baked_cid: u32 = 7;

        // Happy path: the sidecar is written and round-trips back the exact vsock path
        // and baked CID.
        write_host_paths_sidecar(dir.path(), &vsock, baked_cid)
            .await
            .expect("sidecar write should succeed in a writable dir");
        let raw = tokio::fs::read_to_string(dir.path().join(HOST_PATHS_SIDECAR))
            .await
            .expect("sidecar file should exist after a successful write");
        let parsed: SnapshotHostPaths =
            serde_json::from_str(&raw).expect("sidecar should be valid json");
        assert_eq!(parsed.vsock, vsock);
        assert_eq!(
            parsed.cid, baked_cid,
            "the sidecar must carry the guest CID a restore reports (M-VMM-3)"
        );

        // Failure path: a non-existent target directory makes the write fail; the
        // error MUST propagate rather than be swallowed into `Ok`.
        let missing = dir.path().join("does-not-exist").join("nested");
        assert!(
            write_host_paths_sidecar(&missing, &vsock, baked_cid)
                .await
                .is_err(),
            "a failed sidecar write must surface an error, not be swallowed"
        );
    }

    /// Creates a socket file at `path` whose listener is **verifiably** gone.
    ///
    /// `bind` then `drop` is the obvious construction and it is RACY, which is the mechanism behind
    /// a flake this suite carried for two passes ("the first run after a cold build fails, warm runs
    /// pass"): a listening fd open in one libtest thread is duplicated into every `fork` another
    /// thread performs in that instant, and until that child reaches `execve` (where `CLOEXEC`
    /// finally closes it) the socket is **still bound and still accepting**. So the guard probes it,
    /// gets a genuine `Ok` from `connect`, and correctly refuses to unlink a path something is
    /// listening on — and the test, which assumed its own fixture was dead, fails.
    ///
    /// Measured rather than argued: 3000 `bind`/`drop`/`connect` cycles per process, one process,
    /// sequential — **zero** anomalies in 96 000 iterations. The same loop inside the full test
    /// binary with 24 copies running concurrently (i.e. with sibling tests spawning processes) —
    /// 1 to 4 anomalies per 3000, and a plain `std::os::unix::net::UnixStream::connect` succeeds on
    /// them too, so this is the kernel's answer and not a tokio artifact.
    ///
    /// The fix is to stop assuming: bind, drop, then **confirm** the path refuses before handing it
    /// to the test. Confirmation is stable once it holds — the duplicate can only have been made
    /// while the fd was open, and it dies at the child's `execve` — so this converges rather than
    /// merely re-rolling the dice. A path that will not go quiet is a loud failure naming the race,
    /// never a silent skip.
    async fn stale_socket_file(path: &Path) {
        for attempt in 0..64 {
            let _ = std::fs::remove_file(path);
            drop(tokio::net::UnixListener::bind(path).expect("bind then drop = stale socket file"));
            assert!(path.exists(), "precondition: the stale socket file exists");
            match tokio::net::UnixStream::connect(path).await {
                Err(e) if e.raw_os_error() == Some(CONNECT_REFUSED) => return,
                other => {
                    assert!(
                        attempt < 63,
                        "could not build a provably-dead socket file at {}: the listening fd keeps \
                         being duplicated into a concurrently forking sibling test, so the path \
                         stays live (last probe: {other:?})",
                        path.display()
                    );
                }
            }
        }
    }

    // Guards the pre-restore liveness guard (`restore_rotates_host_paths: false`):
    // a baked vsock path with a LIVE listener (the snapshotted VM or a prior
    // restore of the lineage still running) must be rejected with a typed
    // still-in-use `Error::Vmm` naming the path — and the live socket must
    // SURVIVE. The buggy inverse — a guard that skips the connect probe and
    // unlinks unconditionally (the pre-guard `remove_file` + `create_dir_all`) —
    // returns `Ok` and severs the live VM's steward transport, reddening both
    // live-listener assertions (verified red). The stale-file and missing-file
    // arms pin the cleanup contract the happy restore path depends on.
    #[tokio::test]
    async fn reject_live_baked_vsock_rejects_live_listener_and_clears_stale() {
        let dir = tempfile::tempdir().expect("tempdir");

        // Live listener: typed rejection, socket left untouched.
        let live = dir.path().join("live.sock");
        let _listener = tokio::net::UnixListener::bind(&live).expect("bind live listener");
        let err = reject_live_baked_vsock(&live)
            .await
            .expect_err("a live listener on the baked path must be rejected");
        // The message re-worded when the timeout arm stopped unlinking ("still in use" →
        // "may still be in use"), because the guard now refuses on a probe it could not RESOLVE as
        // well as on one that answered. This leg keeps the discriminating half: a live listener
        // must be named as one, so the inconclusive-timeout arm below cannot satisfy this test.
        assert!(
            matches!(&err, Error::Vmm(msg)
                if msg.contains("accepted a probe connection") && msg.contains("live.sock")),
            "expected a typed live-listener Error::Vmm naming the path, got {err:?}"
        );
        assert!(
            live.exists(),
            "the guard must NOT unlink a live VM's socket on the reject path"
        );

        // Stale leftover (a dead socket file, no listener): cleared, parent kept —
        // the sequential-restore case where the bind would otherwise EADDRINUSE.
        // Through `stale_socket_file`, which VERIFIES the fixture is dead instead of assuming a
        // dropped listener is: see that helper for the fd-duplication race this used to flake on.
        let stale = dir.path().join("gone-vm").join("stale.sock");
        std::fs::create_dir_all(stale.parent().expect("parent")).expect("mk parent");
        stale_socket_file(&stale).await;
        reject_live_baked_vsock(&stale)
            .await
            .expect("a stale socket file must be cleared, not rejected");
        assert!(!stale.exists(), "the stale socket file must be removed");

        // Missing file AND missing parent (the torn-down base VM's scratch dir):
        // Ok, with the parent resurrected so FC's verbatim re-bind can succeed.
        let missing = dir.path().join("gone-parent").join("missing.sock");
        reject_live_baked_vsock(&missing)
            .await
            .expect("a missing baked path must be accepted");
        assert!(
            missing.parent().expect("parent").is_dir(),
            "the baked path's parent dir must be (re)created for FC's verbatim re-bind"
        );
    }

    // THE INCONCLUSIVE-PROBE DIRECTION, and the defect it closes. The guard used to group a probe
    // TIMEOUT with the dead-path answer — "no live listener owns the path: a stale leftover" — on
    // the reasoning that a live listener answers a local `connect` instantly. Under load it does
    // not: a full `cargo test --workspace` made a live-listener connect exceed the old 100 ms
    // budget and the sibling test above went red, reporting correctly that the guard had
    // classified a LIVE socket as stale. On a real restore that would have unlinked a running VM's
    // steward transport and let the restore proceed — precisely what the guard exists to prevent.
    //
    // Driven over the PREDICATE rather than over a socket, and that is not a shortcut. The first
    // cut of this test tried to produce a real timeout by saturating a listener's backlog; it
    // never reached the timeout (the backlog is 1024 deep), the live-listener arm fired instead,
    // and the test PASSED with the fail-open regression planted. A test that cannot reach the arm
    // it names is theater. RED on the inverse (`Inconclusive => true`): the second assertion here
    // fails naming the arm.
    #[test]
    fn only_a_provably_dead_probe_permits_unlinking_the_baked_path() {
        assert!(
            probe_permits_unlink(BakedVsockProbe::Refused),
            "a connect that FAILED proves nothing owns the path — that is the stale leftover the \
             guard exists to clear, and refusing it would break every sequential restore"
        );
        assert!(
            !probe_permits_unlink(BakedVsockProbe::Inconclusive),
            "a probe that could not resolve proves NOTHING; unlinking on it silently severs a live \
             VM's steward transport, while refusing costs a loud, retryable re-run"
        );
        assert!(
            !probe_permits_unlink(BakedVsockProbe::Accepted),
            "a live listener owns the path"
        );
    }

    // THE ERROR-ARM DIRECTION — the sibling of the timeout arm above, and the same defect one
    // release later. `Ok(Err(_))` was read as "nothing owns the path" while the guard's own rustdoc
    // claimed the narrow ECONNREFUSED/ENOENT set. It is not narrow: `connect` also fails EMFILE /
    // ENFILE under fd pressure, EAGAIN when a LIVE listener's backlog is full, EACCES, and EINTR.
    // Every one of those unlinked a running VM's steward transport and let the restore proceed.
    //
    // REPRODUCED, not reasoned: with `ulimit -n 32` the whole test binary's live-listener leg
    // panicked `a live listener on the baked path must be rejected: ()` — the guard returned `Ok`
    // for a socket a listener was sitting on.
    //
    // Driven over the PREDICATE, for the reason the timeout one is: EMFILE is not producible from
    // a test without shrinking the process's own rlimit, which every sibling test on the same
    // threads would then trip. RED on the inverse (`_ => Refused`, i.e. the shipped-until-now
    // blanket): every row in the second table fails, naming its errno.
    #[test]
    fn only_a_proof_of_absence_errno_permits_unlinking_the_baked_path() {
        use nix::errno::Errno;
        for (errno, why) in [
            (
                Errno::ECONNREFUSED,
                "the socket file is there and nothing is listening — the stale leftover the guard \
                 exists to clear, empirically also the answer for a leftover regular file",
            ),
            (
                Errno::ENOENT,
                "the path went away between the existence check and the connect",
            ),
        ] {
            assert_eq!(
                connect_failure_proves_dead(Some(errno as i32)),
                BakedVsockProbe::Refused,
                "{errno:?} PROVES nothing owns the path ({why}); refusing it would break every \
                 sequential restore"
            );
        }
        for (errno, why) in [
            (
                Errno::EMFILE,
                "the process is out of descriptors — the probe never reached the socket at all",
            ),
            (Errno::ENFILE, "the SYSTEM is out of descriptors"),
            (
                Errno::EAGAIN,
                "a LIVE listener's backlog is full: this is evidence of liveness, not of absence",
            ),
            (
                Errno::EACCES,
                "the probe may not reach the path; the VM that owns it can",
            ),
            (Errno::EINTR, "a signal interrupted the connect"),
            (
                Errno::EPROTOTYPE,
                "something else is bound there; what it is, is not established",
            ),
        ] {
            assert_eq!(
                connect_failure_proves_dead(Some(errno as i32)),
                BakedVsockProbe::Inconclusive,
                "{errno:?} says NOTHING about liveness ({why}); unlinking on it silently severs a \
                 live VM's steward transport, while refusing costs a loud, retryable re-run"
            );
        }
        assert_eq!(
            connect_failure_proves_dead(None),
            BakedVsockProbe::Inconclusive,
            "an error with no errno at all is the least evidence of any; it must not unlink"
        );
    }

    // The two socket-level outcomes end to end, so the predicate above is wired to the real probe
    // rather than merely correct in isolation: a live listener refuses and keeps its socket, a
    // provably dead one clears.
    #[tokio::test]
    async fn the_guard_wires_the_predicate_to_a_real_probe() {
        let dir = tempfile::tempdir().expect("tempdir");

        let live = dir.path().join("wired-live.sock");
        let _listener = tokio::net::UnixListener::bind(&live).expect("bind");
        let err = reject_live_baked_vsock(&live)
            .await
            .expect_err("a live listener must be refused");
        assert!(matches!(&err, Error::Vmm(msg) if msg.contains("wired-live.sock")));
        assert!(live.exists(), "a refused path must not be unlinked");

        // Same verified fixture as the sibling test, and for the same reason: a dropped listener is
        // not reliably a dead one while other threads are forking (see `stale_socket_file`).
        let dead = dir.path().join("wired-dead.sock");
        stale_socket_file(&dead).await;
        reject_live_baked_vsock(&dead)
            .await
            .expect("a provably dead path clears");
        assert!(!dead.exists());
    }

    // M11 GATE, Firecracker leg (KVM-free). The jail posture is applied in `build_vmm_cmd`'s
    // post-fork `pre_exec` closure, which NOTHING KVM-free can observe: while `spawn_fc` wrote
    // `jail_spec_from_config(&cfg.jail)?` inline, rewriting that one token to a weakened config
    // shipped every Firecracker VM with a different Layer-2 posture and left `cargo test`,
    // `just ci` and the whole live matrix green. `firecracker_launch_plan` makes the posture a
    // RETURNED VALUE, so it is assertable — and `LaunchPlan::jail` is private to
    // `vmcell::vmm::launch`, so the two-line defeat (`let mut plan = …; plan.jail = weaker;`)
    // does not even compile here.
    //
    // Red on the inverse: rewrite the plan's `cfg.jail` to `JailConfig::disabled()` (or any other
    // value) and the first assertion reddens.
    #[test]
    fn the_firecracker_launch_plan_ships_the_configured_jail_posture() {
        use vmcell::config::{JailConfig, VmmSeccomp};

        let plan_for = |jail: JailConfig| {
            let cfg = erofs_builder()
                .vmm_seccomp(VmmSeccomp::Enforcing)
                .jail(jail)
                .build()
                .expect("build config");
            let plan = firecracker_launch_plan(
                Path::new("/usr/bin/firecracker"),
                &cfg,
                &reject_test_resources("plan"),
                Path::new("/tmp/api.sock"),
            )
            .expect("build the launch plan");
            (cfg, plan)
        };

        // The plan's jail half IS the configured posture.
        let (cfg, plan) = plan_for(JailConfig::hardened());
        assert_eq!(
            plan.jail(),
            cfg.jail,
            "the launch plan must ship `cfg.jail`, not a locally-built posture"
        );

        // Positive control, so the equality above is not a tautology about two identical
        // structs: a DIFFERENT requested posture produces a different record, and compiled, the
        // difference is real hardening versus none at all — what shipping the wrong value does.
        let (disabled_cfg, disabled_plan) = plan_for(JailConfig::disabled());
        assert_eq!(disabled_plan.jail(), disabled_cfg.jail);
        assert_ne!(
            plan.jail(),
            disabled_plan.jail(),
            "control: the two postures differ, so the plan is not returning a constant"
        );
        assert!(
            !vmcell::vmm::jail::jail_spec_from_config(&plan.jail())
                .expect("compile the shipped spec")
                .is_noop(),
            "the shipped hardened posture must compile to real hardening"
        );
        assert!(
            vmcell::vmm::jail::jail_spec_from_config(&disabled_plan.jail())
                .expect("compile the disabled spec")
                .is_noop(),
            "control: the disabled posture compiles to no hardening — what a wrong value ships"
        );
    }

    // The argv half of the same plan, asserted on the COMPOSED command rather than a fragment
    // (docs/78 M11): a perfect per-fragment helper whose result never reaches the `Command` is
    // exactly the defect a composed assertion catches. Both seccomp postures are covered because
    // Firecracker's Enforcing arm emits NO flag — the empty-splice case a `contains` assertion
    // cannot tell from a deleted splice.
    //
    // Red on the inverse: drop the `cmd.args(&seccomp_args)` splice and the `Disabled` leg
    // reddens; drop the `--api-sock` splice and both legs redden.
    #[test]
    fn the_firecracker_launch_plan_composes_the_whole_argv() {
        use vmcell::config::VmmSeccomp;

        let argv_for = |policy: VmmSeccomp| {
            let cfg = erofs_builder()
                .vmm_seccomp(policy)
                .build()
                .expect("build config");
            firecracker_launch_plan(
                Path::new("/usr/bin/firecracker"),
                &cfg,
                &reject_test_resources("argv"),
                Path::new("/tmp/api.sock"),
            )
            .expect("build the launch plan")
            .argv()
        };

        assert_eq!(
            argv_for(VmmSeccomp::Enforcing),
            ["--api-sock", "/tmp/api.sock"],
            "FC's built-in filter is already on, so Enforcing adds no flag — the whole argv is \
             the API socket"
        );
        assert_eq!(
            argv_for(VmmSeccomp::Disabled),
            ["--no-seccomp", "--api-sock", "/tmp/api.sock"],
            "Disabled splices `--no-seccomp` BEFORE the API socket"
        );

        // The typed refusal fires inside the plan, before any process or log file exists.
        let cfg = erofs_builder()
            .vmm_seccomp(VmmSeccomp::Log)
            .build()
            .expect("build config");
        let err = firecracker_launch_plan(
            Path::new("/usr/bin/firecracker"),
            &cfg,
            &reject_test_resources("log"),
            Path::new("/tmp/api.sock"),
        )
        .expect_err("Firecracker has no observe-only seccomp mode");
        assert!(
            matches!(&err, Error::Unsupported { vmm, feature }
                if vmm == "firecracker" && feature == "seccomp_log"),
            "expected a seccomp_log Unsupported, got {err:?}"
        );
    }

    // The T2 probe boots a REAL Firecracker VM, and used to do it from a hand-rolled
    // `std::process::Command` — no Layer-2 jail, no seccomp flag, no netns join, and a socket in
    // bare `/tmp` — while every other Firecracker process on the host carried all four
    // (docs/90 `vmcell-firecracker:789`). Both halves of the fix are assertable KVM-free because
    // `t2_probe_launch` performs no I/O.
    //
    // Red on the inverse: hand the plan anything but `cfg.jail` (e.g. `JailConfig::disabled()`) and
    // the posture assert reddens; go back to `std::env::temp_dir()` for the socket and the
    // scratch-dir assert reddens; drop the plan entirely for a raw `Command::new` and this stops
    // compiling — with `jail_composition_gate`'s `Command::new` ban as the source-level backstop.
    #[test]
    fn the_t2_probe_launches_through_the_same_composed_plan_as_a_real_boot() {
        use vmcell::config::{JailConfig, VmmSeccomp};

        let res = reject_test_resources("t2-probe");
        let cfg = erofs_builder()
            .vmm_seccomp(VmmSeccomp::Disabled)
            .jail(JailConfig::hardened())
            .build()
            .expect("build config");

        let (socket, plan) = t2_probe_launch(Path::new("/usr/bin/firecracker"), &cfg, &res)
            .expect("compose the probe launch");

        // The probe VM is confined by the very posture the VM it probes for will be.
        assert_eq!(
            plan.jail(),
            cfg.jail,
            "the probe must ship `cfg.jail` — an unjailed probe is a Firecracker process on the \
             host with no Layer-2 confinement at all"
        );
        // …and it is a real posture, not the empty one (the control the sibling plan gate makes
        // explicit).
        assert!(
            !vmcell::vmm::jail::jail_spec_from_config(&plan.jail())
                .expect("compile the shipped spec")
                .is_noop(),
            "the shipped hardened posture must compile to real hardening"
        );

        // The socket lives in THIS VM's scratch dir (reclaimed by the orchestrator's guard even if
        // we are killed between spawn and reap), not in bare `/tmp`, and never collides with
        // `spawn_fc`'s own `api.sock`.
        assert_eq!(socket, res.tmp_dir.join(T2_PROBE_SOCKET));
        assert_ne!(socket, res.tmp_dir.join("api.sock"));
        assert!(
            !socket.starts_with(std::env::temp_dir().join("vmcell-fc-probe")),
            "the probe socket must not be a clock-named file in the shared temp dir"
        );

        // The composed argv is the real one — the seccomp flag AND the probe's own `--api-sock`,
        // asserted whole rather than by fragment (docs/78 M11).
        assert_eq!(
            plan.argv(),
            [
                "--no-seccomp".to_string(),
                "--api-sock".to_string(),
                socket.display().to_string(),
            ],
            "the probe's argv must be the composed launch, seccomp posture included"
        );

        // The netns join is a `pre_exec` property of the same composer, so it is invisible here and
        // in every other KVM-free test — the argv of a netns member is byte-identical. That half is
        // structural: `firecracker_launch_plan` is handed `res.netns_name`, and
        // `jail_composition_gate` is what forbids a spawn route that skips it.
        let mut member = reject_test_resources("t2-probe");
        member.netns_name = Some("vmcell-net-1".to_string());
        let (netns_socket, netns_plan) =
            t2_probe_launch(Path::new("/usr/bin/firecracker"), &cfg, &member)
                .expect("compose the probe launch in a netns");
        assert_eq!(netns_socket, socket);
        assert_eq!(netns_plan.argv(), plan.argv());
    }
}

/// Source-level gate for docs/81 d6: the Firecracker interface id lives in exactly one place,
/// [`FC_IFACE_ID`], and **every** site that names it — the create-path URL, the create-path body,
/// the restore `network_overrides` entry — derives from that const.
///
/// Scans this file's own text because the defect is invisible to a behavioral test: the shipped
/// URL literal `"/network-interfaces/eth0"` was byte-identical to the composed path, so
/// `fc_snapshot_load_body_shapes`' three-way identity assert stayed green while the third copy
/// sat one edit away from drifting (an id change would have moved the body and the override and
/// left the URL behind — FC 400s the mismatch, loudly, but only on a live boot). Precedent for
/// scanning source rather than behavior: `vmcell::vmm::cloud_hypervisor::virtiofs_pacing_gate`,
/// whose module doc carries the full rationale, and `vmcell-qemu`'s copy of it.
///
/// It catches: any `/network-interfaces…` string literal in production code whose id segment is
/// baked rather than interpolated. It cannot catch: a drift outside this file, or an
/// interpolation of the wrong variable — which
/// `tests::iface_id_is_the_one_source_for_url_body_and_restore_override` covers from the other
/// side.
#[cfg(test)]
mod fc_iface_id_single_source_gate {
    use super::FC_IFACE_ID;

    const SOURCE: &str = include_str!("lib.rs");

    /// The number of `/network-interfaces` string literals this backend ships: one, the
    /// `fc_network_interface_path` composer.
    ///
    /// Asserted exactly, so a scan that silently matched nothing — the way every source-scanning
    /// gate fails vacuously — reddens instead of passing over an empty set.
    const EXPECTED_COMPOSERS: usize = 1;

    /// This file's production text: everything before the first `#[cfg(test)]`, comment lines
    /// dropped and whitespace collapsed.
    ///
    /// Dropping comments keeps a rustdoc mention of the API path (`PUT /network-interfaces/<id>`)
    /// from being scanned as code; collapsing whitespace keeps a rustfmt line break from hiding
    /// half of a literal.
    ///
    /// `pub(super)` so this file's other source-level gate ([`super::jail_composition_gate`])
    /// reads the SAME normalizer instead of carrying a second copy of it — two readers of one
    /// law, not two laws.
    pub(super) fn production_code(source: &str) -> String {
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

    /// Every `/network-interfaces…` string literal in `code`, each without its quotes.
    fn network_interface_literals(code: &str) -> Vec<&str> {
        code.match_indices("\"/network-interfaces")
            .map(|(at, _)| {
                let tail = &code[at + 1..];
                &tail[..tail.find('"').unwrap_or(tail.len())]
            })
            .collect()
    }

    /// The law: the id segment of the path is an interpolation, never a baked id.
    fn path_id_segment_is_interpolated(literal: &str) -> bool {
        literal
            .strip_prefix("/network-interfaces/")
            .is_some_and(|segment| segment.starts_with('{') && segment.ends_with('}'))
    }

    #[test]
    fn every_network_interface_path_here_is_composed_from_the_one_const() {
        let code = production_code(SOURCE);
        let literals = network_interface_literals(&code);
        assert_eq!(
            literals.len(),
            EXPECTED_COMPOSERS,
            "expected {EXPECTED_COMPOSERS} `/network-interfaces` literal (the composer in \
             `fc_network_interface_path`); found {}: {literals:?}. If a site was legitimately \
             added or removed, update EXPECTED_COMPOSERS — do not delete the scan.",
            literals.len()
        );
        for literal in &literals {
            assert!(
                path_id_segment_is_interpolated(literal),
                "`{literal}` bakes the interface id into the URL; compose it from FC_IFACE_ID \
                 via `fc_network_interface_path` so the URL, the body, and the restore override \
                 cannot drift apart (docs/81 d6)"
            );
        }
        // Named directly, and derived from the const so THIS file never carries the banned
        // literal itself: the exact text d6 found must not come back by any route.
        let banned = format!("/network-interfaces/{FC_IFACE_ID}");
        assert!(
            !code.contains(&banned),
            "production code must not name `{banned}` literally"
        );
    }
}

/// Source-level gate for M11's structural half on this backend: the launch is composed in
/// **one** place, and no second `JailSpec` compilation can reappear beside it.
///
/// [`the_firecracker_launch_plan_ships_the_configured_jail_posture`](tests::the_firecracker_launch_plan_ships_the_configured_jail_posture)
/// asserts the posture the plan *returns*; [`vmcell::vmm::LaunchPlan`]'s private field makes
/// overwriting that record a compile error. Neither can see the one remaining regression: moving
/// `jail_spec_from_config` + `build_vmm_cmd` back out of the plan into `spawn_fc`, which re-opens
/// the window between deciding the posture and applying it and leaves the plan's record
/// describing a command nobody spawns. That is a property of this file's *text*, so it is
/// scanned — the same shape as the sibling [`fc_iface_id_single_source_gate`], whose
/// `production_code` normalizer this reuses rather than copies.
///
/// It also catches the route it MISSED: the T2 CPU-template probe spawned firecracker from its own
/// `std::process::Command::new(&vmm.binary_path)`, so it made neither banned call and shipped a real
/// Firecracker VM with no jail, no seccomp flag and no netns — invisible here, and invisible to
/// every behavioral test because a probe VM has no data plane to assert on (docs/90
/// `vmcell-firecracker:789`). The ban is therefore on *building a command at all*: in production
/// text this backend constructs no `Command`, because the only VMM it may spawn is the one the plan
/// composed.
///
/// It catches: a raw `jail_spec_from_config` call in this backend, a second launch-plan
/// construction, a deleted one, and any `Command::new`/`Command::from` spawn route beside the plan.
/// It cannot catch: the wrong `JailConfig` handed to the plan — that is behavioral, and the KVM-free
/// plan gate asserts it directly.
#[cfg(test)]
mod jail_composition_gate {
    use super::fc_iface_id_single_source_gate::production_code;

    const SOURCE: &str = include_str!("lib.rs");

    /// The number of launch-plan constructions this backend ships: one, in
    /// [`super::firecracker_launch_plan`].
    ///
    /// Asserted exactly, so a scan that silently matched nothing — the way every source-scanning
    /// gate fails vacuously — reddens instead of passing over an empty set, and a second
    /// (possibly divergent) construction reddens too.
    const EXPECTED_PLAN_BUILD_SITES: usize = 1;

    /// Every call expression naming `needle` in `code`, truncated at its statement's `;`.
    fn calls<'a>(code: &'a str, needle: &str) -> Vec<&'a str> {
        code.match_indices(needle)
            .map(|(at, _)| {
                let tail = &code[at..];
                &tail[..tail.find(';').unwrap_or(tail.len())]
            })
            .collect()
    }

    #[test]
    fn the_launch_is_composed_only_in_the_plan() {
        let code = production_code(SOURCE);

        let raw = calls(&code, "jail_spec_from_config(");
        assert!(
            raw.is_empty(),
            "M11: this backend must compile no `JailSpec` of its own — the one compilation lives \
             in `vmcell::vmm::LaunchPlan::build`, which records the very value it compiles. \
             Found {raw:?}"
        );
        let raw_cmd = calls(&code, "build_vmm_cmd(");
        assert!(
            raw_cmd.is_empty(),
            "M11: this backend must not build a VMM command outside the launch plan. Found \
             {raw_cmd:?}"
        );
        // The route the two bans above could not see: a hand-rolled `Command`. The T2 probe used
        // one, so it called neither banned helper and still spawned an unjailed, netns-less
        // Firecracker VM. In production text there is no `Command` construction at all — the plan
        // owns the only one.
        for spawner in ["Command::new(", "Command::from("] {
            let hand_rolled = calls(&code, spawner);
            assert!(
                hand_rolled.is_empty(),
                "M11: this backend must spawn nothing it did not compose — `{spawner}` in \
                 production text bypasses the jail, the seccomp flag and the netns join the way \
                 the T2 probe did. Route it through `firecracker_launch_plan` (see \
                 `t2_probe_launch`). Found {hand_rolled:?}"
            );
        }

        // The anti-vacuity half: the two assertions above are satisfied by a file with no launch
        // at all, so the launch must be here, exactly once.
        let builds = calls(&code, "LaunchPlan::build(");
        assert_eq!(
            builds.len(),
            EXPECTED_PLAN_BUILD_SITES,
            "expected {EXPECTED_PLAN_BUILD_SITES} `LaunchPlan::build` call; found {}: {builds:?}. \
             If a site was legitimately added or removed, update EXPECTED_PLAN_BUILD_SITES — do \
             not delete the scan.",
            builds.len()
        );
    }

    /// The scanner's own controls: a prose mention is not a call site, a call split across two
    /// rustfmt lines is still seen whole, and the regression shape is genuinely detected — so the
    /// scan above is not a test that can only ever pass (AGENTS.md rule 2).
    #[test]
    fn the_scanner_sees_the_regression_and_ignores_comments() {
        let regressed = "// the plan calls jail_spec_from_config for us\n\
             let jail =\n    vmcell::vmm::jail::jail_spec_from_config(\n    &cfg.jail)?;\n\
             #[cfg(test)]\nmod tests { LaunchPlan::build(x); }";
        let code = production_code(regressed);
        assert_eq!(calls(&code, "jail_spec_from_config(").len(), 1);
        assert!(calls(&code, "LaunchPlan::build(").is_empty());

        let composed = "// jail_spec_from_config in prose is not a call\n\
             let mut plan =\n    vmcell::vmm::LaunchPlan::build(b, n,\n    cfg.jail)?;";
        let code = production_code(composed);
        assert!(calls(&code, "jail_spec_from_config(").is_empty());
        assert_eq!(calls(&code, "LaunchPlan::build(").len(), 1);

        // The hand-rolled-spawner leg: the exact probe shape is seen, a `#[cfg(test)]` stand-in
        // spawner is not (the tests below DO spawn `sleep`/`true` on purpose), and prose is not.
        let probe = "// spawns firecracker with Command::new for the T2 probe\n\
             let mut std_cmd =\n    std::process::Command::new(\n    &vmm.binary_path);\n\
             #[cfg(test)]\nmod tests { Command::new(\"sleep\"); }";
        let code = production_code(probe);
        assert_eq!(calls(&code, "Command::new(").len(), 1);
        assert!(calls(&code, "Command::from(").is_empty());
    }
}
