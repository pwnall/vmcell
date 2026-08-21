//! Virtual Machine Monitor (VMM) abstraction and management.
//!
//! This module provides a generic abstraction for the four shipping VMM backends — Cloud
//! Hypervisor (primary, in-tree), Firecracker, QEMU, and crosvm (the out-of-tree
//! `vmcell-firecracker`/`vmcell-qemu`/`vmcell-crosvm` crates) — as well as fake implementations
//! for testing.

use crate::config::VmConfig;
use crate::error::Result;
/// Cloud Hypervisor VMM backend implementation.
pub mod cloud_hypervisor;

pub use cloud_hypervisor::{ChInstance, CloudHypervisor};

/// Structured guest-kernel fault capture: a serial console → the typed fault it proves (§5.4, The guest-kernel contract and the bootstrap seed).
pub mod fault;

/// Jailer-equivalent pre-exec hardening of the VMM child (design §12.3, Layer 2 — the jailer-equivalent (JailSpec + apply_jail)).
pub mod jail;

/// The VMM subprocess's own seccomp-BPF confinement — one predicate, four backends (§12.2, Layer 1 — the VMM's own seccomp filter).
pub mod seccomp;

/// Host USB passthrough: claiming a host device for a guest, and giving it back (§2.4).
///
/// `usb_host_passthrough` is a capability, so the backend owns only its own argv; resolving,
/// prechecking and restoring the host driver bindings are unified and live here.
pub mod usb;

// The Firecracker and QEMU backends were extracted into the standalone `vmcell-firecracker` and
// `vmcell-qemu` crates, and crosvm shipped as `vmcell-crosvm` (they depend on `vmcell`; `vmcell`
// has no production edge back). Only Cloud Hypervisor — the primary backend — stays in-tree, so
// the roster is one in-tree plus three out-of-tree. The shared `Vmm`/`VmInstance` traits, the
// jail/seccomp predicates, and the spawn/reap/console/snapshot-eligibility helpers below remain the
// single source of truth those crates depend on.

use serde::Serialize;
use std::path::{Path, PathBuf};

/// A trait for reading a serial log.
pub trait SerialLog: Send + Sync {
    /// Checks if the log contains a kernel panic — "has the guest kernel stopped?".
    ///
    /// Kept as the primitive because that is the one question a *waiting* caller needs answered on
    /// every poll: no later poll of a stopped kernel can succeed. What the guest died *of* is
    /// [`classify_fault`](Self::classify_fault).
    fn contains_panic(&self) -> bool;

    /// Classify what the log proves about the guest kernel — panic, oops, KASAN report, lockdep
    /// splat — or `None` for a healthy, empty or unrecognized console
    /// ([`fault::classify_serial_fault`]).
    ///
    /// **Provided, not required**, and the default is the honest reading of an implementation that
    /// only knows the boolean: `contains_panic()` becomes a [`fault::GuestFault::Panic`] with no
    /// console line to quote. An implementation that *has* the console text overrides this — the
    /// classification is only as good as the evidence it was given, and a fake that was never given
    /// any must not fabricate a class it cannot see.
    fn classify_fault(&self) -> Option<fault::SerialFault> {
        self.contains_panic().then(fault::SerialFault::opaque_panic)
    }
}

/// A real serial log that reads from a file.
pub struct RealSerialLog {
    /// The path to the log file.
    pub path: PathBuf,
}

impl RealSerialLog {
    /// The console's current bytes, or `None` if there is no console evidence to read.
    ///
    /// An absent or unreadable file is `None` — **not** an empty log — because the two mean
    /// opposite things to a caller: "the guest printed nothing" is evidence about the guest, while
    /// "I could not look" is a fact about the host, and a host problem must never be reported as a
    /// guest fault ([`fault::expiry_error`]).
    fn read(&self) -> Option<String> {
        if !self.path.exists() {
            return None;
        }
        std::fs::read_to_string(&self.path).ok()
    }
}

impl SerialLog for RealSerialLog {
    fn contains_panic(&self) -> bool {
        // ONE panic-signature list, in `fault`; this used to carry its own copy of the three
        // literals, which is exactly the drift `ban-inline-kernel-fault-signature.sh` now bans.
        self.read()
            .is_some_and(|log| fault::log_reports_panic(&log))
    }

    fn classify_fault(&self) -> Option<fault::SerialFault> {
        self.read()
            .as_deref()
            .and_then(fault::classify_serial_fault)
    }
}

/// A fake serial log for testing.
pub struct FakeSerialLog {
    /// Whether a panic is simulated.
    pub panicked: bool,
}

impl SerialLog for FakeSerialLog {
    fn contains_panic(&self) -> bool {
        self.panicked
    }
}

/// The generic VMM control-plane ceiling: the budget for an RPC whose duration is
/// **flat in guest state** (`create`, `boot`, `pause`, `resume`, `shutdown`).
///
/// Deliberately *not* used for the snapshot RPC, whose duration is proportional to
/// guest RAM — that one budget comes from [`snapshot_request_timeout`].
const CONTROL_REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// The conservative floor on sustained snapshot write throughput, in MiB of guest RAM
/// per second, used to size [`snapshot_request_timeout`].
///
/// A suspend image tracks guest RAM ~1:1 (`docs/benchmark-results.md`: a 256 MiB guest
/// snapshots to 268.5 MB on CH and 268.4 MB on FC, ≈100 % memory file), so the write is
/// `mem_mib` MiB of dense data. 64 MiB/s is far below any modern host's sustained write
/// rate and is chosen as the *floor* — the budget exists to catch a wedged VMM, not to
/// second-guess a slow or contended disk.
const SNAPSHOT_MIN_WRITE_MIB_PER_SEC: u64 = 64;

/// The control-plane budget for the guest-RAM-proportional snapshot RPC
/// (CH `PUT /api/v1/vm.snapshot`, FC `PUT /snapshot/create` and `PUT /snapshot/load`).
///
/// **One law, one predicate**: every backend sizes that RPC here, never on the flat
/// `CONTROL_REQUEST_TIMEOUT`, which a multi-GiB guest overruns by construction —
/// a spurious `Error::Timeout` mid-snapshot leaves the VM paused with a half-written
/// image (M6). The budget is the flat ceiling plus the write time implied by
/// `SNAPSHOT_MIN_WRITE_MIB_PER_SEC`, rounded up, so it degrades to the flat ceiling
/// for a zero-RAM (probe) instance and grows linearly with the guest.
#[must_use]
pub fn snapshot_request_timeout(mem_mib: u32) -> std::time::Duration {
    CONTROL_REQUEST_TIMEOUT
        + std::time::Duration::from_secs(
            u64::from(mem_mib).div_ceil(SNAPSHOT_MIN_WRITE_MIB_PER_SEC),
        )
}

/// Helper to send an HTTP request over a Unix domain socket, on the generic
/// `CONTROL_REQUEST_TIMEOUT` ceiling.
///
/// Bounds the whole connect → handshake → send → collect sequence with a fixed
/// ceiling so a wedged VMM control socket can never hang a `create`/`boot`/`pause`
/// RPC forever — the failure surfaces as a typed
/// [`Error::Timeout`](crate::error::Error::Timeout) before an outer readiness timeout
/// could mask it (M-VMM-2). The QMP path already caps at 2 s; this uses a wider margin.
///
/// The snapshot RPC does **not** belong here: its duration scales with guest RAM, so it
/// goes through [`unix_api_request_with`] carrying [`snapshot_request_timeout`].
///
/// # Errors
/// Returns an error if the request cannot be sent, the server returns a non-2xx
/// status (as [`Error::VmmApi`](crate::error::Error::VmmApi) carrying the status and
/// body), or the request does not complete within the timeout ceiling
/// ([`Error::Timeout`](crate::error::Error::Timeout)).
pub async fn unix_api_request<T: Serialize>(
    api_socket: &Path,
    method: &str,
    path: &str,
    body: Option<&T>,
) -> Result<()> {
    unix_api_request_with(api_socket, method, path, body, CONTROL_REQUEST_TIMEOUT).await
}

/// [`unix_api_request`] with an explicit budget, for an RPC whose duration is a
/// function of the VM rather than a constant.
///
/// `budget` bounds the **whole** connect → handshake → send → collect sequence, not the
/// gaps between its steps. The only caller-sized budget today is
/// [`snapshot_request_timeout`]; a caller that reaches for a bare literal here is
/// re-introducing the fixed ceiling M6 removed.
///
/// # Errors
/// As [`unix_api_request`], with the elapse reported against `budget`.
pub async fn unix_api_request_with<T: Serialize>(
    api_socket: &Path,
    method: &str,
    path: &str,
    body: Option<&T>,
    budget: std::time::Duration,
) -> Result<()> {
    tokio::time::timeout(budget, async move {
        let stream = tokio::net::UnixStream::connect(api_socket).await?;

        let io = hyper_util::rt::TokioIo::new(stream);
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;

        tokio::task::spawn(async move {
            if let Err(err) = conn.await {
                tracing::warn!("HTTP connection failed: {:?}", err);
            }
        });

        let body_bytes = if let Some(b) = body {
            serde_json::to_vec(b)
                .map_err(|e| crate::error::Error::Serialize(format!("serialize: {e}")))?
        } else {
            Vec::new()
        };

        let req = hyper::Request::builder()
            .method(method)
            .uri(path)
            .header("Host", "localhost")
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .body(http_body_util::Full::new(hyper::body::Bytes::from(
                body_bytes,
            )))?;

        let res = sender.send_request(req).await?;

        if !res.status().is_success() {
            let status = res.status();
            use http_body_util::BodyExt;
            let bytes = res
                .into_body()
                .collect()
                .await
                .map(|c| c.to_bytes())
                .unwrap_or_default();
            return Err(crate::error::Error::VmmApi {
                status: status.as_u16(),
                body: String::from_utf8_lossy(&bytes).into_owned(),
            });
        }

        Ok(())
    })
    .await
    .map_err(|_| {
        crate::error::Error::Timeout(format!(
            "VMM API request {method} {path} did not complete within {budget:?}"
        ))
    })?
}

/// RAII guard owning a single per-VM scratch directory under the system temp dir
/// (`/tmp/vmcell-vm-{pid}-{vmid}/`).
///
/// The orchestrator creates exactly one of these per VM — before networking setup —
/// and threads its [`path`](VmTempDir::path) to every VMM backend through
/// [`PerVmResources::tmp_dir`]. Every per-VM temporary (the API/QMP socket, the
/// vsock socket, the serial log, the smoltcp NAT socket, virtiofsd sockets) lives
/// inside this one directory with a single owner, replacing the former
/// triplicated per-backend create/own/delete.
///
/// On [`Drop`] the directory and everything in it is removed via
/// `remove_vm_tmp_dir` (idempotent, private), so creating the guard early also reclaims
/// the directory if VM construction fails partway. `MicroVm` drops this guard
/// **after** the VMM process group, the vhost-user daemons, and the smoltcp
/// process are gone, so removal never races a process still holding a socket
/// inside it.
#[derive(Debug)]
pub struct VmTempDir {
    /// The owned per-VM directory path.
    path: PathBuf,
}

/// Builds the per-VM scratch-directory path under `base` for process `pid` and
/// VM id `vmid`.
///
/// Pure and **injective in `(pid, vmid)`**: the `-` delimiter guarantees that,
/// e.g., `(1, 23)` and `(12, 3)` never collapse to the same directory, so every
/// per-VM path derived from it (`api.sock`/`vsock.sock`/`serial.log`) is unique
/// per `(pid, vmid)`. This is the property the path-injectivity prop test pins
/// (design §13, Cross-cutting invariants — "Temp-dir collision on PID-only path"); isolating the
/// construction here is what makes `(pid, vmid)` prop-exercisable without a real
/// process id.
#[must_use]
pub(crate) fn per_vm_scratch_dir(prefix: &str, base: &Path, pid: u32, vmid: u32) -> PathBuf {
    base.join(crate::naming::scratch_dir_name(prefix, pid, vmid))
}

/// The **ancestor** vmid a restored VM's adopted host path is keyed on — the id whose scratch
/// directory that path lives in (M9). `None` when the path is inside this VM's own `own_dir`, or is
/// not a per-VM scratch path at all.
///
/// Firecracker's `PUT /snapshot/load` offers no override for the vsock UDS, so its restore re-binds
/// the host path its snapshot baked, verbatim — and that path is a pure function of
/// `(prefix, pid, ANCESTOR vmid)`. The restored VM therefore lives in
/// `<prefix>-vm-<pid>-<ANCESTOR vmid>/` while the orchestrator hands it a *freshly allocated* vmid.
/// Nothing reserved the ancestor's, so it was free for same-process reallocation — a later VM
/// drawing it mints the very directory the restored VM is living in and deletes it on teardown
/// (docs/90 M9). The orchestrator therefore reserves what this returns for the restored VM's
/// lifetime.
///
/// Keyed on the path the backend *actually adopted*, not on the capability descriptor: the hazard is
/// a live path outside the VM's own directory, whoever produced it. So CH (which rewrites the
/// snapshot's `config.json` to this VM's own paths), QEMU (which rotates) and crosvm (whose
/// non-rotating resource is the baked guest *CID*, not a host path — it spawns into its own scratch
/// dir) all return `None` without a per-backend branch.
///
/// The layout is spelled **once**, in [`crate::naming::scratch_dir_name`]: the two trailing numeric
/// tokens are read as the candidate `(pid, vmid)` and accepted only if the forward composer
/// reproduces the directory name byte-for-byte, so this inverse cannot drift from it. A foreign pid
/// still counts — vmids are claimed host-globally, and the pid in a path is no promise about which
/// process will next hold that id.
#[must_use]
pub(crate) fn adopted_scratch_vmid(prefix: &str, own_dir: &Path, adopted: &Path) -> Option<u32> {
    let dir = adopted.parent()?;
    if dir == own_dir {
        return None;
    }
    let name = dir.file_name()?.to_str()?;
    let mut tail = name.rsplitn(3, '-');
    let vmid: u32 = tail.next()?.parse().ok()?;
    let pid: u32 = tail.next()?.parse().ok()?;
    (crate::naming::scratch_dir_name(prefix, pid, vmid) == name).then_some(vmid)
}

impl VmTempDir {
    /// Creates the per-VM temporary directory `<temp>/<prefix>-vm-{pid}-{vmid}/` and returns a guard
    /// that removes it on drop. `prefix` is the VM's [`resource_prefix`](crate::config::VmConfig).
    ///
    /// # Errors
    /// Returns an error if the directory cannot be created.
    pub async fn create(prefix: &str, vmid: u32) -> Result<Self> {
        let path = per_vm_scratch_dir(prefix, &std::env::temp_dir(), std::process::id(), vmid);
        tokio::fs::create_dir_all(&path).await?;
        Ok(Self { path })
    }

    /// Returns the path to the owned per-VM directory.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for VmTempDir {
    fn drop(&mut self) {
        remove_vm_tmp_dir(&self.path);
    }
}

/// Removes a per-VM temporary directory owned by a [`VmTempDir`] guard,
/// including its serial log, lock files, and any leftover sockets.
///
/// Without this the directory (holding `serial.log`, and `api.sock.lock` for CH)
/// leaks one-per-VM and `/tmp` grows unbounded across runs (E3). Call it on the
/// owning instance's `Drop`/teardown path **after** the VMM process group has
/// been reaped, so removal never races a live VMM.
///
/// Best-effort by design: this runs on the `Drop` path where there is no
/// `Result` to surface and `Drop` must not panic; the directory may also already
/// be gone. A genuine removal failure is logged for visibility rather than
/// swallowed silently.
pub(crate) fn remove_vm_tmp_dir(dir: &Path) {
    if let Err(e) = std::fs::remove_dir_all(dir) {
        // A missing directory is the normal idempotent-teardown case, not a leak.
        if e.kind() != std::io::ErrorKind::NotFound {
            tracing::warn!("failed to remove per-VM temp dir {}: {}", dir.display(), e);
        }
    }
}

/// The NUL-terminated netns path [`build_vmm_cmd`]'s `pre_exec` hands to `open(2)`, composed
/// **pre-fork**.
///
/// A different *shape* of the netns-layout law, not a second copy of it: the post-fork window may not
/// allocate, so `open` needs a C string, and `crate::net::tap::netns_path` yields a `PathBuf`. This
/// converts one into the other on the parent side, where allocating is free, so the directory a VMM
/// is exec'd into is by construction the one the datapath binds its taps in.
///
/// Named (rather than inlined in the closure's capture) so the composition has something to be
/// gate-able from: `netns_open_path_composes_from_the_layout_law` recomputes it through the law, so a
/// `format!` that re-spells the layout inline reddens even where it produces the same bytes today.
fn netns_open_path(netns_name: &str) -> String {
    // `display()` is lossless here: the layout is ASCII and the name comes from `crate::naming`.
    format!("{}\0", crate::net::tap::netns_path(netns_name).display())
}

/// Builds a Tokio command for the VMM, handling network namespaces, the jailer-equivalent
/// pre-exec hardening (design §12.3, Layer 2 — the jailer-equivalent (JailSpec + apply_jail)), and process groups.
///
/// The single `pre_exec` closure resets SIGINT/SIGTERM to `SIG_DFL`, enters the netns (when
/// `netns_name` is `Some`) and then applies `jail` to the VMM child — the order is load-bearing:
/// `setns` needs the caps the child still holds pre-exec, and the jail (`no_new_privs` + rlimits +
/// seccomp) is applied after. All three are async-signal-safe (`signal` on a constant, `open`/
/// `setns`/`close` on a pre-allocated string, and [`jail::apply_jail`]'s raw
/// `prctl`/`setrlimit`/`seccomp` on already-allocated inputs). The closure is **always** installed:
/// the signal reset applies even with no netns and a no-op jail (M9).
pub fn build_vmm_cmd(
    binary_path: &Path,
    netns_name: Option<&str>,
    jail: &crate::vmm::jail::JailSpec,
) -> tokio::process::Command {
    let mut std_cmd = std::process::Command::new(binary_path);
    use std::os::unix::process::CommandExt;
    std_cmd.process_group(0);

    // Pre-allocate the NUL-terminated netns path (or nothing) BEFORE the closure, so nothing
    // allocates in the post-fork window. Both of `netns_open_path`'s allocations — the `PathBuf` the
    // layout law composes and this `String` — happen on this side of the fork.
    let netns_path: Option<String> = netns_name.map(netns_open_path);
    let jail = jail.clone();

    let pre_exec = move || -> std::io::Result<()> {
        // M9 (`broker-child-dies-to-terminal-signals-orphaning-vms`): a supervisor may ignore
        // SIGINT/SIGTERM so a terminal Ctrl-C cannot kill it before its ordered teardown runs
        // (`vmcelld`'s broker child does) — and an IGNORED disposition SURVIVES `execve`, unlike
        // a caught one. Reset both here so the VMM we exec keeps normal signal behavior (an
        // operator's `kill` on a VMM, and the teardown's own signals, must still work). First:
        // it needs no caps and must hold even if a later step fails the spawn.
        // SAFETY: `signal(2)` with `SIG_DFL` on a valid signal number — async-signal-safe,
        // touches no memory of ours, and allocates nothing in the post-fork window.
        unsafe { libc::signal(libc::SIGINT, libc::SIG_DFL) };
        // SAFETY: as above, for SIGTERM.
        unsafe { libc::signal(libc::SIGTERM, libc::SIG_DFL) };
        if let Some(path) = &netns_path {
            // SAFETY: `open(2)` on the pre-allocated NUL-terminated `path`; async-signal-safe.
            let fd = unsafe {
                libc::open(
                    path.as_ptr() as *const libc::c_char,
                    libc::O_RDONLY | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                return Err(std::io::Error::last_os_error());
            }
            // SAFETY: `setns(2)` on the fd opened just above; async-signal-safe.
            if unsafe { libc::setns(fd, libc::CLONE_NEWNET) } != 0 {
                let err = std::io::Error::last_os_error();
                // SAFETY: close the fd opened above on the error path; async-signal-safe.
                unsafe { libc::close(fd) };
                return Err(err);
            }
            // SAFETY: close the fd opened above on the success path; async-signal-safe.
            unsafe { libc::close(fd) };
        }
        // Jailer-equivalent hardening AFTER the netns join (setns still needs the caps).
        crate::vmm::jail::apply_jail(&jail)
    };
    // SAFETY: `pre_exec` runs `pre_exec` post-fork/pre-exec; it is async-signal-safe (above).
    unsafe {
        std_cmd.pre_exec(pre_exec);
    }
    tokio::process::Command::from(std_cmd)
}

/// The one compile-and-record constructor for a jailed VMM launch (M11).
///
/// Its own module, not a bare item in [`crate::vmm`], for one load-bearing reason: a private
/// field is readable by the defining module **and its descendants**, and every backend in this
/// crate (`vmm::cloud_hypervisor`) is a descendant of `vmm`. Making `launch` a *sibling* of the
/// backend modules puts [`LaunchPlan::jail`] out of reach of all four backends alike — the
/// in-tree primary included — so the mutation that defeated M11's first shape is a **compile
/// error** everywhere rather than merely inert in three crates out of four.
pub mod launch {
    use crate::error::Result;
    use std::path::Path;

    /// A composed VMM launch: the `Command` to spawn, plus a **record** of the
    /// [`JailConfig`](crate::config::JailConfig) its `JailSpec` was compiled from.
    ///
    /// # Why this type exists (M11)
    ///
    /// The jail posture a VMM ships with is applied in
    /// [`build_vmm_cmd`](super::build_vmm_cmd)'s post-fork `pre_exec` closure, which no
    /// KVM-free test can observe. While each backend wrote
    /// `jail_spec_from_config(&…)?` inline in its spawn function, the argument was an
    /// **inline expression no gate could see**: rewriting that one token shipped a different —
    /// on crosvm, an absent — confinement with `cargo test`, `just ci` and the entire live
    /// matrix green, because the deny-list is default-allow/`EPERM` and no functional leg
    /// notices.
    ///
    /// Routing every backend through this constructor turns the posture into a **returned
    /// value**: [`Self::jail`] is what a unit test asserts on, and because [`Self::build`] is
    /// the only constructor and consumes its `jail` argument exactly twice — once to compile,
    /// once to record — a plan whose record disagrees with its command is unrepresentable.
    ///
    /// The field is private with no setter, so the two-line defeat
    /// (`let mut plan = …; plan.jail = cfg.jail;`) does not compile in any backend. The one
    /// remaining way to ship the wrong posture is to hand the wrong value to [`Self::build`],
    /// and that is a *behavioral* difference each backend's gate asserts on directly rather
    /// than a source property a scan has to infer.
    #[derive(Debug)]
    pub struct LaunchPlan {
        /// The composed command, with the netns join and the compiled jail already installed.
        cmd: tokio::process::Command,
        /// The posture `cmd`'s `JailSpec` was compiled from. A record, not an input.
        jail: crate::config::JailConfig,
    }

    impl LaunchPlan {
        /// Compiles `jail` into a `JailSpec`, builds the VMM command with that spec, and
        /// records the very same `jail` value.
        ///
        /// One value, two uses, no window between them. This is the **only**
        /// [`jail_spec_from_config`](super::jail::jail_spec_from_config) call in any shipping
        /// launch path; each backend gates the absence of a second one over its own source.
        ///
        /// # Errors
        /// Propagates [`jail_spec_from_config`](super::jail::jail_spec_from_config)'s error
        /// (a seccomp deny-list that fails to compile).
        pub fn build(
            binary_path: &Path,
            netns_name: Option<&str>,
            jail: crate::config::JailConfig,
        ) -> Result<Self> {
            let spec = super::jail::jail_spec_from_config(&jail)?;
            let cmd = super::build_vmm_cmd(binary_path, netns_name, &spec);
            Ok(Self { cmd, jail })
        }

        /// The jail posture this plan's command was compiled from.
        ///
        /// `JailConfig` is `Copy`, so this hands out a value, not a handle: a caller still
        /// cannot reach the record.
        #[must_use]
        pub fn jail(&self) -> crate::config::JailConfig {
            self.jail
        }

        /// The composed command, for appending backend arguments.
        pub fn command_mut(&mut self) -> &mut tokio::process::Command {
            &mut self.cmd
        }

        /// The composed command, for inspection (the argv gates read it through here).
        #[must_use]
        pub fn command(&self) -> &tokio::process::Command {
            &self.cmd
        }

        /// Consumes the plan, yielding the command to spawn.
        #[must_use]
        pub fn into_command(self) -> tokio::process::Command {
            self.cmd
        }

        /// The composed argv (arguments only, not `argv[0]`), lossily decoded.
        ///
        /// The one accessor every backend's composed-argv gate reads, so "assert on the whole
        /// command, never a fragment" needs no per-crate helper (docs/78 M11).
        #[must_use]
        pub fn argv(&self) -> Vec<String> {
            self.cmd
                .as_std()
                .get_args()
                .map(|a| a.to_string_lossy().into_owned())
                .collect()
        }
    }
}

pub use launch::LaunchPlan;

/// Waits until the given socket path appears, or times out.
///
/// Polls for the socket's existence on an absolute deadline. If the spawned process
/// exits before the socket appears, fails fast with the real exit status instead of
/// falling through to a later, less-informative timeout.
///
/// # Errors
/// - Returns [`Error::Vmm`](crate::error::Error::Vmm) if the process exits before the
///   socket appears.
/// - Returns [`Error::Timeout`](crate::error::Error::Timeout) if the socket does not
///   appear within `timeout_ms`.
pub async fn wait_for_socket(
    socket_path: &Path,
    mut process: Option<&mut tokio::process::Child>,
    timeout_ms: u64,
    interval_ms: u64,
) -> Result<()> {
    // The interval is caller-supplied via the pub `VmConfig.timeouts` field, so clamp
    // it to >= 1 ms (a 0 interval would busy-spin). Drive off an absolute deadline so
    // (a) the socket is checked at least once even when `interval_ms > timeout_ms`
    // (the old `timeout_ms / interval_ms == 0` computed zero iterations and returned
    // Timeout without a single check), and (b) a socket appearing in the final
    // sub-interval is not missed (L-VMM-1).
    let interval = std::time::Duration::from_millis(interval_ms.max(1));
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(timeout_ms);

    loop {
        if tokio::fs::try_exists(socket_path).await.unwrap_or(false) {
            return Ok(());
        }
        // Fail fast on an early VMM exit so the real cause surfaces instead of a
        // later, less-informative Timeout (M-VMM-8). `None` when the socket's producer
        // is an in-process thread (the smoltcp NAT) with no child to watch — then only
        // the socket-existence + deadline checks apply.
        if let Some(p) = process.as_deref_mut()
            && let Some(status) = p.try_wait().unwrap_or(None)
        {
            return Err(crate::error::Error::Vmm(format!(
                "process exited early: {status}"
            )));
        }

        let now = std::time::Instant::now();
        if now >= deadline {
            break;
        }
        let sleep_dur = interval.min(deadline - now);
        tokio::time::sleep(sleep_dur).await;
    }

    Err(crate::error::Error::Timeout(
        "socket failed to appear in time".into(),
    ))
}

/// The **one** wall-clock ceiling, in milliseconds, for a VMM control socket to appear
/// after the VMM (or one of its helper daemons) is exec'd.
///
/// Every backend used to spell this `1000` inline at its own
/// `register_and_await_ready`/`wait_for_socket` call site — six bare literals across CH,
/// Firecracker, QEMU and crosvm, with nothing tying them together (docs/81 §8). The
/// ceiling is now named here and **cannot** be passed from a call site: neither
/// [`register_and_await_ready`] nor [`wait_for_vmm_socket`] takes a timeout argument, so
/// re-introducing a literal is a compile error rather than a silent per-backend drift.
///
/// Sizing: the VMM binds its control socket as one of its first acts, well inside 1 s on
/// any host; the ceiling exists to convert a never-starting VMM into a typed
/// [`Error::Timeout`](crate::error::Error::Timeout) promptly, so the caller's bounded
/// retry gets a fresh VM instead of the suite hanging. It is deliberately NOT the budget
/// for anything guest-RAM-proportional — that is [`snapshot_request_timeout`] — nor for
/// virtiofsd, whose readiness wait is paced from the `VmConfig` timeout profile
/// (`crate::fs`).
pub const VMM_SOCKET_READY_TIMEOUT_MS: u64 = 1000;

/// [`wait_for_socket`] on the one shared [`VMM_SOCKET_READY_TIMEOUT_MS`] ceiling, for a
/// VMM (or VMM helper daemon) control socket.
///
/// The ceiling is not a parameter, so no backend can spell it as a literal again (§8);
/// `interval_ms` stays caller-supplied because it is genuine per-VM configuration
/// (`VmConfig::timeouts.api_socket_poll`, §9.4 — one profile paces every readiness wait
/// of a VM).
///
/// # Errors
/// As [`wait_for_socket`], with the elapse reported against
/// [`VMM_SOCKET_READY_TIMEOUT_MS`].
pub async fn wait_for_vmm_socket(
    socket_path: &Path,
    process: Option<&mut tokio::process::Child>,
    interval_ms: u64,
) -> Result<()> {
    wait_for_socket(
        socket_path,
        process,
        VMM_SOCKET_READY_TIMEOUT_MS,
        interval_ms,
    )
    .await
}

/// `SIGKILL` to `-pgid`, best-effort.
///
/// The **one** place this crate spells the negated-pgid signal, so every caller —
/// [`reap_process_group`] and [`VmmProcessGroup`] — shares one `SAFETY`-equivalent
/// rationale and one suppression of the send error. Best-effort by design: it runs on
/// teardown paths where the group may already be gone (`ESRCH`) and there is no `Result`
/// to surface.
fn sigkill_process_group(pgid: u32) {
    // A failure here is `ESRCH` (the group is already gone) or `EPERM`; neither is
    // actionable on a teardown path, and every caller's next step (waitpid / Child::wait)
    // establishes the real outcome. This is the ONE site in the crate that discards a
    // `kill(-pgid)` result, which is why it is a named function rather than an idiom.
    #[expect(
        clippy::let_underscore_must_use,
        reason = "the ONE site in this crate that discards kill(-pgid): ESRCH means the group is already gone, and every caller's next step establishes the real outcome"
    )]
    let _ = nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(-(pgid as i32)),
        nix::sys::signal::Signal::SIGKILL,
    );
}

/// Force-kills a just-spawned VMM process *group* (`SIGKILL` to `-pgid`) and reaps
/// the leader. Use on the error paths between spawning a VMM and constructing the
/// owning instance (whose `Drop` would otherwise do this): a failure there — e.g. a
/// cgroup `add_task` or a readiness timeout — must not leak a running VMM, because
/// `tokio::process::Child` does not kill on drop. No-op when `pgid` is `None`.
pub fn reap_process_group(process: &mut tokio::process::Child, pgid: Option<u32>) {
    let Some(pgid) = pgid else {
        return;
    };
    sigkill_process_group(pgid);
    if let Some(pid) = process.id() {
        #[expect(
            clippy::let_underscore_must_use,
            reason = "reaping a leader that is already gone (ECHILD) is the wanted outcome on an error path that is about to report something else"
        )]
        let _ = nix::sys::wait::waitpid(nix::unistd::Pid::from_raw(pid as i32), None);
    }
}

/// A VMM leader's process group **and** the one-shot "the leader has been reaped" flag
/// that guards signalling it (M-VMM-1) — owned together, so the flag cannot be set by one
/// site and ignored by another.
///
/// **Why this is a type and not two fields.** Every backend instance carried
/// `pgid: Option<u32>` beside `reaped: bool` and re-implemented the same three-step dance
/// in `kill()`, `has_exited()` and `Drop` — twelve copies across CH, Firecracker, QEMU and
/// crosvm (docs/81 §9). The sequence is safety-critical: once the leader is reaped the
/// kernel is free to recycle its pgid, so a `SIGKILL` to `-pgid` after that point can land
/// on an **unrelated process group**. A single copy that forgot the `!reaped` guard, or
/// forgot to set the flag, is a signal to someone else's processes.
///
/// The pgid is **private and never handed back out**: there is no accessor, so no code
/// outside this module can construct `-pgid` for a VMM leader's group at all. That makes
/// "re-signal after the flag is set" unrepresentable rather than merely scanned for — the
/// only ways to signal the group are [`Self::kill_and_wait`] and [`Self::reap_now`], both
/// of which consult and then set the flag.
#[derive(Debug)]
pub struct VmmProcessGroup {
    /// The VMM leader's process-group id, captured at spawn (`Child::id()` of a leader
    /// spawned with `process_group(0)`). `None` when the leader was already reaped before
    /// the id could be captured, in which case there is nothing to signal.
    pgid: Option<u32>,
    /// `true` once the leader has been reaped (by `has_exited`, `kill`, or `Drop`). After
    /// that the kernel may recycle the pgid, so the group must never be signalled again.
    reaped: bool,
}

impl VmmProcessGroup {
    /// Adopts a freshly-spawned VMM leader's process group. The group has not been reaped
    /// yet, so the first teardown call is the one that signals it.
    #[must_use]
    pub fn new(pgid: Option<u32>) -> Self {
        Self {
            pgid,
            reaped: false,
        }
    }

    /// `true` once the leader has been reaped and the group must not be signalled again.
    ///
    /// Read-only: there is no setter, so a call site cannot clear the flag and re-arm a
    /// signal to a possibly-recycled pgid.
    #[must_use]
    pub fn is_reaped(&self) -> bool {
        self.reaped
    }

    /// The graceful teardown path (`VmInstance::kill`): `SIGKILL` the group unless the
    /// leader was already reaped, then await the leader and record the reap.
    ///
    /// `process` must be the group's leader. Backend-specific steps that bracket this —
    /// QEMU's QMP `quit` and USB re-bind, crosvm's `stop` — stay at the call site; only
    /// the signal/wait/flag ordering lives here.
    pub async fn kill_and_wait(&mut self, process: &mut tokio::process::Child) {
        // Skip the group SIGKILL if the leader was already reaped: its pgid may have been
        // recycled onto an unrelated group (M-VMM-1).
        if !self.reaped
            && let Some(pgid) = self.pgid
        {
            sigkill_process_group(pgid);
        }
        // Await the leader unconditionally: on the already-reaped path this returns the
        // cached status immediately, and on the signalled path it is what actually reaps.
        // Awaited unconditionally: on the already-reaped path this returns the cached status
        // immediately, and on the signalled path it is what actually reaps. The exit STATUS is not
        // the question — `reaped` below is — and a SIGKILLed VMM's status is never informative.
        #[expect(
            clippy::let_underscore_must_use,
            reason = "this await exists to reap, not to read a status: a SIGKILLed VMM's exit status carries nothing the caller can act on"
        )]
        let _ = process.wait().await;
        // The leader is reaped now; `Drop` must not re-signal a possibly-recycled pgid.
        self.reaped = true;
    }

    /// The `Drop` teardown path: `SIGKILL` the group and blocking-`waitpid` the leader,
    /// unless it was already reaped.
    ///
    /// Same ordering and same guard as [`Self::kill_and_wait`], in the synchronous form
    /// `Drop` needs (L1: `Drop` is the panic path, `kill` the graceful one, one helper for
    /// both). Idempotent: a second call after the flag is set is a no-op.
    pub fn reap_now(&mut self, process: &mut tokio::process::Child) {
        if !self.reaped {
            reap_process_group(process, self.pgid);
            self.reaped = true;
        }
    }

    /// The `VmInstance::has_exited` path: non-blocking `try_wait` on the leader, recording
    /// the reap when it reports an exit.
    ///
    /// Returns `true` when the leader has exited (the guest powered off after
    /// `request_shutdown`). Recording the reap here is what stops a later `kill()`/`Drop`
    /// from signalling a pgid the kernel may since have recycled (M-VMM-1).
    pub fn note_exit(&mut self, process: &mut tokio::process::Child) -> bool {
        if matches!(process.try_wait(), Ok(Some(_))) {
            self.reaped = true;
            true
        } else {
            false
        }
    }

    /// Builds an **already-reaped** group over `pgid`, for tests that need the
    /// recycled-pgid state without actually reaping a leader.
    ///
    /// Test-only: gated behind the `test-support` feature so production code cannot
    /// fabricate the state. The per-backend M-VMM-1 gates use it to point a reaped group
    /// at a live decoy process and assert the decoy survives teardown.
    #[cfg(any(test, feature = "test-support"))]
    #[must_use]
    pub fn already_reaped_for_test(pgid: Option<u32>) -> Self {
        Self { pgid, reaped: true }
    }
}

/// Registers a freshly-spawned VMM process with its cgroup and blocks until its
/// control socket appears, reaping the process **group** on any failure.
///
/// This is the one shared "capture pgid → `add_task` (reap-on-err) → `wait_for_socket`
/// (reap-on-err)" sequence for **every** backend — CH, Firecracker, QEMU, and crosvm (VMM-2). It
/// was copy-pasted into `spawn_ch`/`spawn_fc`/`spawn_qemu` and had already diverged (QEMU
/// wrapped the readiness error in `Error::Vmm` while CH/FC propagated the raw error); routing
/// every backend through this helper makes the error handling **identical** — the
/// place per-backend divergence bugs hide (AGENTS.md "don't triplicate; extract").
///
/// `tokio::process::Child` does not kill on drop, so a cgroup `add_task` failure or a
/// readiness timeout here MUST reap the spawned VMM group or it leaks — the owning
/// instance (whose `Drop` reaps) is not constructed until the caller returns. Returns
/// the captured pgid on success.
///
/// The readiness ceiling is **not** a parameter: it is the one shared
/// [`VMM_SOCKET_READY_TIMEOUT_MS`], so a backend cannot spell it as a literal again (§8).
///
/// # Errors
/// Returns — after reaping the process group — the raw underlying error: the cgroup
/// `add_task` failure, or the readiness [`Error::Timeout`](crate::error::Error::Timeout)/process-exited-early
/// `Error` from [`wait_for_socket`]. The error is returned verbatim and identically
/// across backends, so no backend can silently diverge on how it wraps it.
pub async fn register_and_await_ready(
    process: &mut tokio::process::Child,
    cgroups: &dyn crate::metrics::CgroupFs,
    cgroup_name: &str,
    socket_path: &Path,
    interval_ms: u64,
) -> Result<Option<u32>> {
    register_and_await_ready_within(
        process,
        cgroups,
        cgroup_name,
        socket_path,
        VMM_SOCKET_READY_TIMEOUT_MS,
        interval_ms,
    )
    .await
}

/// The one body of the register+await-ready sequence, with the readiness ceiling still a
/// parameter.
///
/// **Private**, and that is the point: it is the seam this module's own reap-on-failure
/// gate uses to pass a ceiling short enough to keep the KVM-free suite fast, and it is
/// unreachable from every backend crate, so no shipped call site can reach for a ceiling
/// of its own (§8). The public entry point is [`register_and_await_ready`], which has no
/// ceiling argument at all.
async fn register_and_await_ready_within(
    process: &mut tokio::process::Child,
    cgroups: &dyn crate::metrics::CgroupFs,
    cgroup_name: &str,
    socket_path: &Path,
    timeout_ms: u64,
    interval_ms: u64,
) -> Result<Option<u32>> {
    // Capture the process-group id immediately: from here on any error must reap the
    // spawned VMM group, or it leaks.
    let pgid = process.id();

    if let Some(pid) = process.id()
        && let Err(e) = cgroups.add_task(cgroup_name, pid)
    {
        reap_process_group(process, pgid);
        return Err(e);
    }

    if let Err(e) = wait_for_socket(socket_path, Some(&mut *process), timeout_ms, interval_ms).await
    {
        reap_process_group(process, pgid);
        return Err(e);
    }

    Ok(pgid)
}

/// Self-guard that rejects [`ConsoleMode::VirtioConsole`](crate::config::ConsoleMode::VirtioConsole)
/// on a backend whose capability descriptor does not advertise `virtio_console`
/// (Firecracker).
///
/// The kernel-cmdline `console=` token (`build_kernel_cmdline`) and the per-backend
/// console device wiring must move in lockstep: a backend that emitted `console=hvc0`
/// with no virtio-console device would send the guest's console output nowhere and
/// leave `serial.log` silent. Every backend's `create()`/`restore()` self-guards with
/// this instead of assuming the caller checked, returning a typed
/// [`Error::Unsupported`](crate::error::Error::Unsupported) that mirrors the other
/// capability rejects. A [`ConsoleMode::Uart`](crate::config::ConsoleMode::Uart)
/// config is always accepted.
///
/// # Errors
/// Returns [`Error::Unsupported`](crate::error::Error::Unsupported)
/// `{ vmm, feature: "virtio_console" }` when `mode` is `VirtioConsole` and
/// `caps.virtio_console` is `false`; `Ok(())` otherwise.
pub fn reject_unsupported_console(
    vmm: &str,
    caps: &VmmCapabilities,
    mode: crate::config::ConsoleMode,
) -> Result<()> {
    if matches!(mode, crate::config::ConsoleMode::VirtioConsole) && !caps.virtio_console {
        return Err(crate::error::Error::unsupported(
            vmm,
            crate::feature::Feature::VirtioConsole,
        ));
    }
    Ok(())
}

/// Refuses a [`crate::config::VmConfig`] that asks for a capability the backend's
/// **own** descriptor advertises as `false`, for the two config fields no other guard
/// covers: `nested_virt` and `lazy_restore` (docs/81 d7).
///
/// §2.1's contract is that every backend self-checks its own descriptor instead of assuming
/// the caller consulted it, and three sibling fields (`virtio_console`, `disk_io_throttle`,
/// `usb_host_passthrough`) already route through one shared predicate each. These two
/// silently degraded instead:
///
/// - `nested_virt` — the SHARED [`crate::config::build_kernel_cmdline`] emits
///   `kvm-intel.nested=1` for **every** backend on `cfg.nested_virt`, so a backend that
///   exposes no VMX/SVM to the guest (Firecracker, crosvm) accepted the request and booted
///   a guest whose L1 `/dev/kvm` never appears. The lever reads as applied and is not.
/// - `lazy_restore` — a backend with no userfaultfd/demand-paged restore backend wired
///   (Firecracker hardcodes `backend_type: "File"`; QEMU and crosvm load eagerly) faulted
///   eagerly under a [`RestoreMode::Lazy`](crate::config::RestoreMode::Lazy) config that had
///   asked for demand paging — an accepted input silently downgraded.
///
/// **One law, one predicate.** This landed as three byte-identical per-backend copies
/// differing only in the `vmm` string; the copies are now one function every backend calls
/// (docs/81 d7 follow-up). Both branches key off the **one** [`VmmCapabilities`] value handed
/// in — never a hardcoded `false` at the refusal site — so flipping a flag flips its refusal
/// with it, and each feature string IS the `VmmCapabilities` field name (N-VMM-1). A backend
/// whose flag is `true` today (QEMU's `nested_virt`) keeps a dormant branch rather than a
/// deleted one, exactly like [`reject_usb_host_devices`]: a deliberate re-gate turns every
/// such config into the typed refusal here, with no second site to update.
///
/// Called from `create()` **and** `restore()`, before any spawn: a `restore()` that accepted
/// exactly what `create()` rejects is the crosvm M4 defect one path over, and `restore_mode`
/// is precisely the field a restore consumes.
///
/// # Errors
/// Returns [`Error::Unsupported`](crate::error::Error::Unsupported) `{ vmm, feature }` naming
/// the unadvertised capability: `"nested_virt"` when `cfg.nested_virt` is set and
/// `caps.nested_virt` is `false`, `"lazy_restore"` when `cfg.restore_mode` is
/// [`RestoreMode::Lazy`](crate::config::RestoreMode::Lazy) and `caps.lazy_restore` is
/// `false`; `Ok(())` otherwise.
pub fn reject_unadvertised_capabilities(
    vmm: &str,
    caps: &VmmCapabilities,
    cfg: &crate::config::VmConfig,
) -> Result<()> {
    if cfg.nested_virt && !caps.nested_virt {
        // N-VMM-1 is a TYPE LAW now (F6): `Feature::name()` IS the descriptor's field name,
        // pinned in both directions by `feature_roster_matches_vmm_capabilities_fields`.
        return Err(crate::error::Error::unsupported(
            vmm,
            crate::feature::Feature::NestedVirt,
        ));
    }
    if matches!(cfg.restore_mode, crate::config::RestoreMode::Lazy) && !caps.lazy_restore {
        return Err(crate::error::Error::unsupported(
            vmm,
            crate::feature::Feature::LazyRestore,
        ));
    }
    Ok(())
}

/// Rejects [`VmConfig::usb_host_devices`](crate::config::VmConfig::usb_host_devices) on a
/// backend that cannot attach a host USB device (§2.4, QEMU q35 — the fallback and most-proven nester), so the request is never
/// silently dropped.
///
/// The **one** predicate every backend's `create()` calls (AGENTS.md "one law, one
/// predicate"): QEMU passes it (its `usb_host_passthrough` is `true`), CH / Firecracker /
/// crosvm refuse. Routing all four through here means a future capability flip — in
/// either direction — changes the refusal at exactly one site, and the feature string can
/// never drift from the [`VmmCapabilities`] field name (N-VMM-1).
///
/// # Errors
/// Returns [`Error::Unsupported`](crate::error::Error::Unsupported)
/// `{ vmm, feature: "usb_host_passthrough" }` when `devices` is non-empty and
/// `caps.usb_host_passthrough` is `false`; `Ok(())` otherwise.
pub fn reject_usb_host_devices(
    vmm: &str,
    caps: &VmmCapabilities,
    devices: &[crate::config::UsbHostDevice],
) -> Result<()> {
    if !devices.is_empty() && !caps.usb_host_passthrough {
        return Err(crate::error::Error::unsupported(
            vmm,
            crate::feature::Feature::UsbHostPassthrough,
        ));
    }
    Ok(())
}

/// **The one refusal every backend's `restore()` returns for a host-USB config** — the *same*
/// [`Removal`](crate::feature::Removal) value the orchestrator's clone-eligibility arm returns
/// (`INELIGIBLE_USB_PASSTHROUGH`), aliased here because that arm is `pub(crate)` and three of the
/// four backends live in their own crates (§8.1, The warm-snapshot path and the eligibility law).
///
/// A `const` initialized *from* the orchestrator's arm rather than a second literal: the two
/// boundaries cannot drift into two near-miss prose strings the way the four vhost-user refusals
/// did before [`crate::feature::VHOST_USER_BLOCKS_SNAPSHOT`] collapsed them, and a backend test can
/// assert arm IDENTITY instead of matching a fragment.
pub const USB_PASSTHROUGH_BLOCKS_RESTORE: crate::feature::Removal =
    crate::orchestrator::INELIGIBLE_USB_PASSTHROUGH;

/// Rejects [`VmConfig::usb_host_devices`](crate::config::VmConfig::usb_host_devices) on the
/// **restore** path, on every backend — the half of the honor-or-reject law `create()` already
/// held (§8.1, The warm-snapshot path and the eligibility law).
///
/// A passed-through host USB device is host state living **outside** guest RAM: the migration
/// stream carries the guest's view of the xhci controller, never the device behind it. So no
/// backend can honor such a config on restore, and until this predicate existed none refused it
/// either — CH / Firecracker / crosvm dropped the accepted list silently, and QEMU (whose
/// `usb_host_passthrough` is `true`, so [`reject_usb_host_devices`] passes it) spliced
/// `-device usb-host,…` into the restored VM's argv **without** the
/// [`usb::claim_usb_host_devices`] precheck `create()` runs — an unresolved, unproven,
/// never-put-back claim on a host device (§2.4, QEMU q35 — the fallback and most-proven nester).
///
/// **One law, one predicate, two arms:**
///
/// 1. the create-side arm, delegated to [`reject_usb_host_devices`] and therefore keyed off the
///    [`VmmCapabilities`] handed in — never a hardcoded `false` here — so a backend that cannot
///    attach a host USB device at all refuses a restore with the *identical* typed error its
///    `create()` returns (`usb_host_passthrough`): a restore must not accept what create rejects,
///    and a re-gate of the flag moves both paths at one site;
/// 2. the restore-only arm, reached only when arm 1 passed — i.e. on a backend whose descriptor
///    says it *can* attach one — which refuses with [`USB_PASSTHROUGH_BLOCKS_RESTORE`]
///    (`snapshot_restore`, config provenance). This arm is deliberately capability-INDEPENDENT:
///    the migration stream carries no host device on any backend, present or future, so there is
///    no descriptor field for it to read. Copying arm 1 alone into `restore()` would have been a
///    no-op on QEMU — the one backend that actually splices `usb-host` into its argv.
///
/// The orchestrator covers every in-tree production path, but [`Vmm`] is public: a downstream
/// consumer calling `vmm.restore()` directly bypassed it entirely, which is why the refusal
/// belongs here too.
///
/// # Errors
/// Returns [`Error::Unsupported`](crate::error::Error::Unsupported) when `devices` is non-empty:
/// `{ vmm, feature: "usb_host_passthrough" }` when `caps.usb_host_passthrough` is `false`,
/// otherwise the [`USB_PASSTHROUGH_BLOCKS_RESTORE`] refusal (`feature: "snapshot_restore"`).
/// `Ok(())` for an empty list.
pub fn reject_usb_host_devices_on_restore(
    vmm: &str,
    caps: &VmmCapabilities,
    devices: &[crate::config::UsbHostDevice],
) -> Result<()> {
    // Arm 1: whatever `create()` would say, `restore()` says too — keyed off the descriptor, never
    // a hardcoded `false` here.
    reject_usb_host_devices(vmm, caps, devices)?;
    // Arm 2: the backend CAN attach one cold, and still cannot re-attach one to a restored VM.
    if !devices.is_empty() {
        return Err(crate::error::Error::from_removal(
            vmm,
            &USB_PASSTHROUGH_BLOCKS_RESTORE,
        ));
    }
    Ok(())
}

/// Returns `true` when a VM carrying any of these is **not** snapshot-eligible,
/// because it has a vhost-user device attached (a virtio-fs data share served by
/// virtiofsd, the unprivileged `vhost-user-net` NAT, or an external `vhost-user-net`
/// socket). The snapshot-eligibility law (§8.1, The warm-snapshot path and the eligibility law) requires every backend to self-guard
/// `snapshot()`/`restore()` against such a VM rather than assume the caller checked.
///
/// This is the ONE shared predicate for all backends (M-VMM-5): the former per-backend
/// copies had already diverged — the Firecracker copy never grew the virtio-fs *rootfs*
/// term the CH copy carried, so a virtio-fs-rootfs restore slipped its guard (H-VMM-3).
/// Centralizing it makes that class of divergence impossible. (Design §18 delta 5, Delta register: changes from the validated v27 build
/// later removed the virtio-fs-rootfs variant entirely, making that boundary case
/// unrepresentable rather than a runtime check.)
pub fn has_vhost_user_device(
    virtio_fs_share: bool,
    unprivileged_net: bool,
    vhost_user_net: bool,
) -> bool {
    virtio_fs_share || unprivileged_net || vhost_user_net
}

/// Returns `true` when `cfg`/`res` describe a VM that carries any vhost-user device and
/// is therefore **not** snapshot-eligible (§8.1, The warm-snapshot path and the eligibility law). Covers the boundary cases at
/// `restore()`/`snapshot()`: a virtio-fs data share (backed by virtiofsd), the
/// unprivileged `vhost-user-net` NAT, and an external `vhost-user-net` socket.
pub fn config_has_vhost_user_device(cfg: &VmConfig, res: &PerVmResources) -> bool {
    let virtio_fs = !cfg.shares.is_empty();
    has_vhost_user_device(
        virtio_fs,
        matches!(cfg.net, crate::config::NetConfig::Unprivileged { .. }),
        res.vhost_user_socket.is_some(),
    )
}

/// The lowest guest vsock context ID. The AF_VSOCK ABI reserves 0, 1 and 2
/// (`VMADDR_CID_HYPERVISOR`, `VMADDR_CID_LOCAL`, `VMADDR_CID_HOST`), so guests start at 3.
pub const MIN_GUEST_CID: u32 = 3;

/// The highest guest vsock context ID this host hands out — **derived** from
/// [`crate::net::MAX_VMID`], never spelled as its own number.
///
/// `MicroVm::start` allocates a guest CID unconditionally, so a CID space narrower than the vmid
/// space is the *binding* ceiling on concurrent VMs per host. It was: the range was a literal
/// `3..=254`, which is 252 CIDs — below the address map's own 254 — so widening the `/16` map alone
/// would have raised the concurrent-VM count by exactly zero (design §17, Networking). Sizing this
/// off `MAX_VMID` makes the two move together by construction, and home 4 of
/// `the_vmid_ceiling_is_one_law_with_five_other_homes` drains a real allocator to prove the
/// derivation reaches the allocator and not just the constant.
///
/// A vsock CID is a `u32` with only 0/1/2 and `u32::MAX` (`VMADDR_CID_ANY`) reserved, so the old
/// 254 was policy rather than an ABI limit and there is headroom far beyond this.
pub const MAX_GUEST_CID: u32 = MIN_GUEST_CID + crate::net::MAX_VMID - 1;

/// The guest CID range's own ABI precondition, as a compile error: it must start above the three
/// reserved low CIDs and stop below `VMADDR_CID_ANY`. Not implied by the derivation above — a
/// `MIN_GUEST_CID` lowered to 2 would hand a guest the host's own CID, and a `MAX_VMID` near
/// `u32::MAX` would hand one `VMADDR_CID_ANY`.
const _: () = assert!(
    MIN_GUEST_CID > 2 && MAX_GUEST_CID < u32::MAX,
    "the guest CID range escaped the AF_VSOCK reserved values (0/1/2 and u32::MAX)"
);

/// The live guest CIDs plus the search hint that keeps [`CidAllocator::allocate`] linear.
#[derive(Debug)]
struct CidPool {
    /// Every CID currently handed out or reserved.
    active: std::collections::BTreeSet<u32>,
    /// Invariant: every CID in `MIN_GUEST_CID..next_free` is in [`Self::active`], so a search may
    /// start here instead of at [`MIN_GUEST_CID`].
    ///
    /// This exists because the space is now ~10⁴ wide rather than 252: rescanning from
    /// `MIN_GUEST_CID` on every call made filling the pool quadratic, and filling the pool is
    /// precisely what the exhaustion gates do.
    next_free: u32,
}

/// Allocates unique Context IDs (CIDs) for vsock connections.
/// CIDs in [`MIN_GUEST_CID`]`..=`[`MAX_GUEST_CID`] are available for guests.
#[derive(Debug)]
pub struct CidAllocator {
    active: std::sync::Mutex<CidPool>,
}

impl CidAllocator {
    /// Creates a new CID allocator.
    #[must_use]
    pub fn new() -> Self {
        Self {
            active: std::sync::Mutex::new(CidPool {
                active: std::collections::BTreeSet::new(),
                next_free: MIN_GUEST_CID,
            }),
        }
    }
}

impl Default for CidAllocator {
    fn default() -> Self {
        Self::new()
    }
}

impl CidAllocator {
    /// Allocates and returns a unique Context ID (CID) for VSOCK communication.
    ///
    /// Hands out the lowest free CID, so a released CID is reused before an untouched one.
    ///
    /// # Errors
    /// Returns an error if every CID in [`MIN_GUEST_CID`]`..=`[`MAX_GUEST_CID`] is in use.
    pub fn allocate(&self) -> Result<u32> {
        // Recover from a poisoned lock instead of panicking: the guarded value is
        // a live-CID set plus a hint derived from it, with no invariant a panic
        // mid-mutation can leave broken — `next_free` is only ever lowered by
        // `release`, so adopting the inner value is sound.
        let mut pool = self.active.lock().unwrap_or_else(|e| e.into_inner());
        // Walk the contiguous live run starting at the hint. By `CidPool::next_free`'s invariant
        // everything below the hint is live, so this finds the same lowest free CID a scan from
        // `MIN_GUEST_CID` would, in time proportional to the run rather than to the whole space.
        let mut cid = pool.next_free;
        for &live in pool.active.range(cid..) {
            if live > cid {
                break;
            }
            cid = live + 1;
        }
        if cid > MAX_GUEST_CID {
            return Err(crate::error::Error::Vmm(
                "CID allocator exhausted".to_string(),
            ));
        }
        pool.active.insert(cid);
        pool.next_free = cid + 1;
        Ok(cid)
    }

    /// Reserves a specific guest CID ([`MIN_GUEST_CID`]`..=`[`MAX_GUEST_CID`]), so a test — or a
    /// caller that must pin a CID — can force a later [`allocate`](CidAllocator::allocate) to hand
    /// a *different* one. Mirrors
    /// [`VmidAllocator::reserve`](crate::orchestrator::VmidAllocator::reserve);
    /// CIDs are in-process only (no cross-process FS claim, unlike VMIDs).
    ///
    /// # Errors
    /// Returns [`Error::Vmm`](crate::error::Error::Vmm) if `cid` is out of the guest
    /// range, or [`Error::Exhaustion`](crate::error::Error::Exhaustion) if it
    /// is already reserved.
    pub fn reserve(&self, cid: u32) -> Result<u32> {
        if !(MIN_GUEST_CID..=MAX_GUEST_CID).contains(&cid) {
            return Err(crate::error::Error::Vmm(format!(
                "cid {cid} out of range (must be {MIN_GUEST_CID}..={MAX_GUEST_CID})"
            )));
        }
        // Recover from a poisoned lock instead of panicking, for the reason `allocate` gives.
        let mut pool = self.active.lock().unwrap_or_else(|e| e.into_inner());
        if pool.active.contains(&cid) {
            return Err(crate::error::Error::Exhaustion(format!(
                "CID {cid} already reserved"
            )));
        }
        // No `next_free` adjustment: a `cid` below the hint is live by the hint's own invariant and
        // was refused above, so anything reaching here is at or above it.
        pool.active.insert(cid);
        Ok(cid)
    }

    /// Releases a previously allocated CID.
    pub fn release(&self, cid: u32) {
        // Recover from a poisoned lock instead of panicking, for the reason `allocate` gives.
        let mut pool = self.active.lock().unwrap_or_else(|e| e.into_inner());
        pool.active.remove(&cid);
        // Restore `CidPool::next_free`'s invariant: this CID is no longer live, so the hint may not
        // claim everything below it is. Skipping this leaks the freed CID until the pool empties.
        if cid >= MIN_GUEST_CID && cid < pool.next_free {
            pool.next_free = cid;
        }
    }
}

/// Per-VM resources allocated by the orchestrator before VM creation.
///
/// Constructed by the orchestrator and, in their tests, by the out-of-tree backend crates
/// (`vmcell-firecracker`/`vmcell-qemu`/`vmcell-crosvm`). It is deliberately **not**
/// `#[non_exhaustive]`: every backend must be handed a fully-specified resource set, so a new
/// field should be a compile error in each backend crate (fail-loud) rather than a
/// silently-defaulted one. (`vmcell` is `publish = false`; there is no external consumer relying
/// on non-exhaustiveness.)
#[derive(Debug, Clone)]
pub struct PerVmResources {
    /// Name of the cgroup v2 slice for the VM.
    pub cgroup_name: String,
    /// Optional TAP interface name for privileged networking.
    pub tap_name: Option<String>,
    /// Optional network namespace name for privileged networking. On a **segment** member this is
    /// the *segment's* namespace (`<prefix>-seg-<segid>`), not a per-VM one — the VMM enters it
    /// through the same `build_vmm_cmd` pre-exec `setns`, so no backend needs new spawn logic.
    pub netns_name: Option<String>,
    /// This VM's place in a VM-to-VM segment, when it is a member (§6.5, VM-to-VM segments;
    /// v30 §18 delta 8). `None` for every non-segment VM.
    ///
    /// This is the exhaustive-struct channel §6.2 names: a backend cannot compile without
    /// acknowledging segments, and [`crate::config::build_kernel_cmdline`] reads the member's
    /// address from here. The **device** wiring still keys on `tap_name` (a member's tap is an
    /// ordinary tap — it simply lives in the segment's namespace), so no backend re-derives the
    /// mode from `cfg.net`.
    pub segment: Option<crate::net::SegmentMembership>,
    /// Optional vhost-user socket path for unprivileged networking.
    pub vhost_user_socket: Option<PathBuf>,
    /// Unique internal VM ID.
    pub vmid: u32,
    /// Context ID for vsock communication.
    pub guest_cid: u32,
    /// Per-VM scratch directory (owned by the orchestrator via [`VmTempDir`]).
    /// Backends derive all of their socket and serial-log paths inside this
    /// directory; it is created once before networking setup and removed once on
    /// teardown.
    pub tmp_dir: PathBuf,
}

/// Virtual Machine Monitor (VMM) capabilities.
///
/// Every backend — including the out-of-tree `vmcell-firecracker`/`vmcell-qemu`/`vmcell-crosvm`
/// crates and the `FakeVmm` — constructs its own descriptor by naming all fields. It is
/// deliberately **not** `#[non_exhaustive]`: a new capability must force every backend to declare
/// its stance on it (a compile error until it does), not default silently to `false`. (`vmcell`
/// is `publish = false`; there is no external consumer relying on non-exhaustiveness.)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmmCapabilities {
    /// True if the VMM supports snapshot and restore.
    pub snapshot_restore: bool,
    /// True if the VMM supports lazy userfaultfd-based demand-paged restore.
    pub lazy_restore: bool,
    /// True if the VMM supports virtio-fs shared directories.
    pub virtio_fs_shares: bool,
    /// True if the VMM supports vhost-user-net for unprivileged networking.
    pub unprivileged_vhost_user_net: bool,
    /// True if the VMM supports nested virtualization (exposing KVM to guest).
    pub nested_virt: bool,
    /// True if the VMM can attach a virtio-console (`hvc0`) device (Cloud
    /// Hypervisor, QEMU, and crosvm — the latter via `--serial
    /// hardware=virtio-console`). Firecracker has no virtio-console, so a
    /// [`ConsoleMode::VirtioConsole`](crate::config::ConsoleMode::VirtioConsole)
    /// config is rejected there (`console=hvc0` with no device silences the log).
    pub virtio_console: bool,
    /// True if `restore()` gives the restored VM **fresh host-side socket paths**
    /// inside its own scratch dir. Cloud Hypervisor does: its restore config
    /// rewrite moves the vsock/serial paths into the new VM's tmp dir before
    /// launch (§8.2, Restore correctness: a restored VM is not a fresh VM), and so does QEMU (its
    /// restore programs a fresh guest CID). Firecracker does not: `PUT /snapshot/load` re-binds the
    /// snapshot's recorded host vsock UDS path **verbatim** — no load-time
    /// override exists in FC v1.16. Neither does crosvm: it bakes the vsock CID
    /// into the snapshot and rejects a rotated `--vsock cid=` on restore, so
    /// `restore()` reuses the baked CID — the Firecracker pattern (§2.5, crosvm — the fourth backend (v29, boot-first)).
    /// Consequences when `false`: every restore of a snapshot lineage shares the
    /// ONE baked host vsock path, so (a) restoring
    /// while the snapshotted VM (or a prior restore of it) is still alive is
    /// rejected by the backend's pre-restore liveness guard, and (b) concurrent
    /// restores from one snapshot lineage are unsupported (the design §17, Open gaps and future capabilities
    /// single-snapshot-CoW gap covers every non-rotating backend anyway).
    pub restore_rotates_host_paths: bool,
    /// True if the VMM can rate-limit an extra virtio-blk device's I/O
    /// ([`DiskIoLimit`](crate::config::DiskIoLimit), §4.6). Cloud Hypervisor
    /// (`rate_limiter_config`), Firecracker (`rate_limiter`), and QEMU
    /// (`throttling.*`) all have a native per-drive limiter; **crosvm has none**
    /// (its `--block` exposes no bandwidth/iops key), so it advertises `false`
    /// and rejects a throttled disk fail-loud at `create()`. A backend that
    /// reports `false` self-skips the `extra_block_io_throttle` data-plane test
    /// via `require_cap!` rather than failing it.
    pub disk_io_throttle: bool,
    /// True if the VMM can attach a **host USB device** to the guest
    /// ([`VmConfig::usb_host_devices`](crate::config::VmConfig::usb_host_devices), §2.4, QEMU q35 — the fallback and most-proven nester).
    /// QEMU is the only backend whose upstream binary does (`qemu-xhci` + `usb-host`);
    /// Cloud Hypervisor has no upstream USB, Firecracker has none, and crosvm's default
    /// xhci controller is not `Suspendable` (vmcell always passes `--no-usb`, §2.5, crosvm — the fourth backend (v29, boot-first)), so
    /// all three are honest-`false` and reject a USB device fail-loud at `create()` via
    /// [`reject_usb_host_devices`].
    ///
    /// Deliberately **narrow** (USB, not a generic `host_device` flag): the flag claims
    /// exactly what is live-validated; the flag + config + typed-refusal *pattern* is the
    /// part that generalizes to other device classes (§7.1, the `mem_limit_enforced`
    /// naming lesson — narrow names for narrow claims).
    pub usb_host_passthrough: bool,
}

/// Abstract Virtual Machine Monitor (VMM) trait.
///
/// A backend abstracts the differences between Cloud Hypervisor, Firecracker, QEMU, and
/// crosvm. Every implementation **self-checks** unsupported operations against
/// its [`capabilities`](Vmm::capabilities) and returns
/// [`Error::Unsupported`](crate::error::Error::Unsupported) with a typed feature name
/// rather than assuming the caller validated first (design §2.1, The trait and the capability descriptor).
pub trait Vmm: Send + Sync {
    /// The associated instance type representing a running VM.
    type Instance: VmInstance;

    /// Creates a new VM from configuration.
    ///
    /// Spawns the VMM process, registers it with its cgroup, and waits for the control
    /// socket to appear. The returned instance is **ready to
    /// [`boot`](VmInstance::boot)** — the guest is configured but not yet running.
    ///
    /// # Errors
    /// Returns an error if the VMM process fails to spawn or become ready, or if the
    /// configuration is invalid for this backend — e.g.
    /// [`Error::Unsupported`](crate::error::Error::Unsupported) for a virtio-fs rootfs,
    /// an unsupported console mode, or unprivileged networking on a backend that lacks
    /// vhost-user-net.
    async fn create(
        &self,
        cfg: &VmConfig,
        res: &PerVmResources,
        cgroups: &dyn crate::metrics::CgroupFs,
    ) -> Result<Self::Instance>;

    /// Restores a VM from a snapshot directory.
    ///
    /// The returned instance is **paused**: the caller continues with
    /// [`resume`](VmInstance::resume), **never** [`boot`](VmInstance::boot) — the guest
    /// is already running inside the snapshot and is resumed from its paused point, not
    /// cold-booted (design §2.1, The trait and the capability descriptor). Device topology is reconstructed from the snapshot;
    /// `cfg` is consulted only for timeouts, console-mode validation, and capability
    /// self-checks.
    ///
    /// # Errors
    /// - [`Error::Unsupported`](crate::error::Error::Unsupported) when this backend does
    ///   not advertise `capabilities().snapshot_restore`.
    /// - [`Error::Unsupported`](crate::error::Error::Unsupported) when `cfg`/`res` carry
    ///   any vhost-user device (a virtio-fs share or rootfs, unprivileged networking, or
    ///   an external vhost-user-net socket) — the snapshot-eligibility law (§8.1, The warm-snapshot path and the eligibility law)
    ///   rejects such a VM before restore.
    /// - Snapshot I/O, parse, or VMM-start errors.
    async fn restore(
        &self,
        snapshot_dir: &Path,
        cfg: &VmConfig,
        res: &PerVmResources,
        cgroups: &dyn crate::metrics::CgroupFs,
    ) -> Result<Self::Instance>;

    /// Returns the capabilities of this VMM backend.
    ///
    /// Callers **must** consult this before invoking optional operations (snapshot,
    /// restore, nested virt, virtio-fs, …); a `false` capability means the operation
    /// returns [`Error::Unsupported`](crate::error::Error::Unsupported).
    fn capabilities(&self) -> VmmCapabilities;

    /// Returns the string identifier of this VMM backend.
    fn id(&self) -> &str;
}

/// The vsock port the steward listens on and the host dials.
///
/// **Re-exported, not defined** (v33 delta 4): the one definition is
/// [`vmcell_protocol::STEWARD_VSOCK_PORT`], in the crate the host and the guest already share.
/// It used to be defined here with the steward's private `VSOCK_PORT` as "its mirror on the other
/// side of the boundary" — two mirrors of one number across a process boundary, which can only
/// ever fail at run time as an opaque connect timeout.
///
/// It is a `const` **bound to** the protocol crate's value rather than a `pub use` of it, for one
/// mechanical reason: `cargo semver-checks` reads a const replaced by a re-export as
/// `pub_module_level_const_missing` — a removal — even though `vmcell::vmm::STEWARD_VSOCK_PORT`
/// still resolves for every consumer. Taking the re-export would have meant ledgering a breaking
/// change that breaks nobody, which is worse than this line: there is still exactly ONE literal
/// `5000` in the workspace, and it is in `vmcell-protocol`.
pub const STEWARD_VSOCK_PORT: u32 = vmcell_protocol::STEWARD_VSOCK_PORT;

/// How the host reaches a VM's steward vsock control plane.
///
/// Cloud Hypervisor, Firecracker, and QEMU's default external `vhost-device-vsock`
/// daemon all bridge the guest's vsock onto a host **AF_UNIX** socket spoken with
/// the Firecracker-style hybrid `CONNECT <port>`/`OK` prologue —
/// [`VsockEndpoint::Unix`]. A snapshot-eligible QEMU instead attaches the in-kernel
/// `vhost-vsock-pci` device (§2.4, QEMU q35 — the fallback and most-proven nester), which exposes the guest directly on the host's
/// **AF_VSOCK** namespace at `(guest_cid, port)` — no AF_UNIX path and no hybrid
/// handshake — [`VsockEndpoint::Vsock`]. crosvm is the one backend that is **always**
/// on that AF_VSOCK arm: its vsock is the in-kernel device on every path, and its
/// AF_UNIX `vsock_path` is vestigial API parity (§2.5, crosvm — the fourth backend (v29, boot-first)).
/// The steward transport ([`crate::steward`]) branches only its connect *prologue* on this; the framed protocol after the
/// guest's first `Ready` frame is byte-identical on both.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VsockEndpoint {
    /// A host AF_UNIX socket path plus the hybrid-vsock port to `CONNECT` to.
    Unix {
        /// Host-side AF_UNIX socket the VMM (or its vsock daemon) listens on.
        path: PathBuf,
        /// The vsock port carried in the `CONNECT <port>` handshake line.
        port: u32,
    },
    /// A host AF_VSOCK address — a direct in-kernel vhost-vsock connection with no
    /// hybrid handshake.
    Vsock {
        /// The guest's vsock Context ID the host dials.
        cid: u32,
        /// The vsock port the steward listens on.
        port: u32,
    },
}

impl VsockEndpoint {
    /// The same transport, dialing `port` instead.
    ///
    /// [`VmInstance::vsock_endpoint`] reports the backend's **transport** (an AF_UNIX path or a
    /// guest CID) and fills in the default port, because an instance has no idea what placement its
    /// cell declared. The control plane substitutes the port
    /// [`StewardPlacement::steward_port`](crate::config::StewardPlacement::steward_port) names —
    /// C8's first question — so a `Service { port }` cell is dialed where its steward actually
    /// listens. Without this the port would be an accepted input that is silently ignored: the
    /// cmdline token would carry 5100 to the guest while the host kept dialing 5000, and the
    /// mismatch would surface only as an opaque connect timeout.
    #[must_use]
    pub fn with_port(self, port: u32) -> Self {
        match self {
            VsockEndpoint::Unix { path, .. } => VsockEndpoint::Unix { path, port },
            VsockEndpoint::Vsock { cid, .. } => VsockEndpoint::Vsock { cid, port },
        }
    }
}

/// Represents a running or created VM instance.
pub trait VmInstance: Send {
    /// Boots the VM from a created state.
    ///
    /// Valid only on instances returned by [`Vmm::create`], never on a restored
    /// instance — a restored VM is already running inside its snapshot and must be
    /// [`resume`](VmInstance::resume)d, not booted. Backends whose restored instance
    /// cannot boot self-guard and return
    /// [`Error::Unsupported`](crate::error::Error::Unsupported).
    ///
    /// # Errors
    /// Returns an error if the boot process fails, or
    /// [`Error::Unsupported`](crate::error::Error::Unsupported) if called on a restored
    /// instance.
    async fn boot(&mut self) -> Result<()>;
    /// Requests a graceful shutdown of the VM.
    ///
    /// # Errors
    /// Returns an error if the request cannot be sent.
    async fn request_shutdown(&mut self) -> Result<()>;
    /// Forcefully kills the VM instance.
    ///
    /// # Errors
    /// Returns an error if the VMM process cannot be killed.
    async fn kill(&mut self) -> Result<()>;
    /// Reports, without blocking, whether the underlying VMM process has already
    /// exited. The graceful [`MicroVm::shutdown`](crate::orchestrator::MicroVm::shutdown)
    /// polls this after `request_shutdown` so it can return as soon as the guest
    /// has actually powered off, instead of always sleeping the full grace window
    /// (the `try_wait` early-return ORCH-7 deferred). Defaults to `false`
    /// (conservative — "not known to have exited," so `shutdown` waits its bounded
    /// grace) for backends/fakes without a reapable process handle.
    async fn has_exited(&mut self) -> bool {
        false
    }
    /// Pauses the VM, preparing it for a snapshot.
    ///
    /// # Errors
    /// Returns an error if pausing fails.
    async fn pause(&mut self) -> Result<()>;
    /// Resumes the VM after it was paused or snapshot-restored.
    ///
    /// This is the continuation point for a restored instance (see
    /// [`Vmm::restore`]), which is returned paused rather than booted.
    ///
    /// # Errors
    /// Returns an error if resuming fails.
    async fn resume(&mut self) -> Result<()>;
    /// Snapshots the VM state to the specified directory.
    ///
    /// # Errors
    /// Returns an error if the snapshot operation fails.
    async fn snapshot(&mut self, dir: &Path) -> Result<()>;
    /// Returns the path to this instance's vsock control socket.
    fn vsock_path(&self) -> &Path;
    /// Returns the endpoint the host uses to reach this instance's steward
    /// vsock control plane.
    ///
    /// Defaults to [`VsockEndpoint::Unix`] over [`vsock_path`](VmInstance::vsock_path)
    /// with the shared internal steward vsock port — the AF_UNIX hybrid-vsock transport Cloud
    /// Hypervisor, Firecracker, and an external-daemon QEMU use. A backend whose control plane
    /// rides an AF_VSOCK transport overrides this to return [`VsockEndpoint::Vsock`] carrying its
    /// [`guest_cid`](VmInstance::guest_cid): a snapshot-eligible QEMU on the in-kernel
    /// `vhost-vsock-pci` device (§2.4, QEMU q35 — the fallback and most-proven nester), and crosvm
    /// on **every** path (its vsock is in-kernel unconditionally, §2.5, crosvm — the fourth backend (v29, boot-first)).
    ///
    /// **The default's port is [`STEWARD_VSOCK_PORT`], which is not necessarily the cell's declared
    /// one** ([`steward_port`](crate::config::StewardPlacement::steward_port), law C8's first
    /// question). It stands here as a placeholder because the *instance* has no view of the config:
    /// `MicroVm::steward` and `MicroVm::connect_sessions` re-key the port per call
    /// (`.with_port(..)`), so on a `Service { port: 5100 }` cell every dial that goes through them is
    /// correct however this default reads.
    ///
    /// The one consumer that does **not** re-key is
    /// [`verify_control_plane`](VmInstance::verify_control_plane), which probes the endpoint it finds
    /// verbatim. An implementor overriding that probe must therefore return the **declared** port
    /// here — carry the placement into the instance, the way `vmcell-qemu`'s `steward_endpoint` does
    /// — or its health gate dials 5000 at a cell listening on 5100, spends the whole probe budget
    /// against a bridge that never answers a dead port, and re-spawns a healthy VM to exhaustion
    /// (docs/90 M1, the shipped defect). Leaving the default in place is safe only while the probe
    /// stays the no-op default. The workspace-wide baked-port scan in `crate::config`'s C8 gate pins
    /// this as one of the three sites that may bake the constant at all.
    fn vsock_endpoint(&self) -> VsockEndpoint {
        VsockEndpoint::Unix {
            path: self.vsock_path().to_path_buf(),
            port: STEWARD_VSOCK_PORT,
        }
    }
    /// Returns the unique vsock Context ID (CID) assigned to this VM.
    fn guest_cid(&self) -> u32;
    /// Returns the path to the VM's serial log file.
    fn serial_log(&self) -> &Path;

    /// Bounded post-boot check that the guest control-plane (vsock) transport is
    /// actually carrying traffic, so [`MicroVm::start`](crate::MicroVm::start) can
    /// re-spawn a VM whose transport came up half-wired instead of returning it.
    ///
    /// Default: `Ok(())`. Cloud Hypervisor, Firecracker, and crosvm terminate vsock *inside*
    /// the VMM process (crosvm on the in-kernel vhost-vsock device), so the device cannot
    /// half-initialize — there is nothing to probe. QEMU overrides this: its vsock rides an **external**
    /// `vhost-device-vsock` daemon over a `vhost-user-vsock` virtqueue whose
    /// bring-up races. On the measured host ~11% of QEMU boots leave that data path
    /// wedged for the VM's entire life — the daemon accepts the host `CONNECT` but
    /// never reaches the guest listener — surfacing only ~10 s later as a steward
    /// connection timeout. Returning `Err` here lets the orchestrator recreate the
    /// VM instead. See `docs/benchmark-results.md` ("QEMU steward-timeout flake") and
    /// `tests/qemu_vsock_flake_repro.rs`.
    ///
    /// `budget` bounds the probe; a healthy transport answers well before it, so a
    /// healthy boot pays only its real connect latency, not the whole budget.
    ///
    /// **This probe is handed no port, so an implementor dials
    /// [`vsock_endpoint`](VmInstance::vsock_endpoint) verbatim — and that endpoint's port is
    /// whatever the instance put there, which for the trait default is [`STEWARD_VSOCK_PORT`] and
    /// not the cell's declared
    /// [`steward_port`](crate::config::StewardPlacement::steward_port).** Unlike `MicroVm::steward`
    /// and `MicroVm::connect_sessions`, which re-key the port per call (`.with_port(..)`), there is
    /// nowhere for the declared port to enter here. So an override must probe an endpoint whose port
    /// is already the declared one: `vmcell-qemu` builds its instance endpoint from the placement for
    /// exactly this reason, after the baked 5000 killed and re-spawned healthy `Service { port: 5100 }`
    /// cells to exhaustion (docs/90 M1). Threading the resolved endpoint in as a parameter would make
    /// the trap unrepresentable, and is a breaking change to this trait — recorded as the structural
    /// option rather than done silently.
    ///
    /// # Errors
    /// Returns an error if the control plane is not confirmed live within `budget`.
    async fn verify_control_plane(
        &self,
        _budget: std::time::Duration,
        _timeouts: &crate::config::Timeouts,
    ) -> Result<()> {
        Ok(())
    }
}

/// A scriptable fault menu for [`FakeVmm`] (design §18 delta 9, Delta register: changes from the validated v27 build, §9.8, Testability seams) — drives the orchestrator's
/// failure / retry / timeout paths at the `Vmm`/`VmInstance` seam itself, not only through the
/// surrounding seams. Every field defaults to "no fault", so `FakeVmm::default()` is a healthy
/// backend.
#[derive(Debug, Clone, Default)]
pub struct FaultMenu {
    /// [`Vmm::create`] returns `Err` (models a VMM that fails to spawn).
    pub fail_create: bool,
    /// [`VmInstance::boot`] returns `Err` (models a guest that fails to boot).
    pub fail_boot: bool,
    /// [`Vmm::restore`] returns `Err` (models a snapshot restore that fails).
    pub fail_restore: bool,
    /// [`VmInstance::resume`] returns `Err` (models a paused guest that will not resume).
    pub fail_resume: bool,
    /// [`VmInstance::verify_control_plane`] returns `Err` for the **first N** calls, then `Ok` —
    /// modelling QEMU's occasionally-wedged vhost-user-vsock bring-up that `MicroVm::start`'s
    /// respawn loop recovers from. The counter lives on the [`FakeVmm`] (shared with every instance
    /// it creates), so it spans the respawns that each build a fresh instance. `0` = never wedged.
    pub wedge_control_plane_for: usize,
    /// An artificial delay applied inside `boot`/`verify_control_plane`, modelling slow readiness.
    /// `None` (default) = no delay.
    pub readiness_delay: Option<std::time::Duration>,
}

/// A fake VMM for testing without booting a real VM.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct FakeVmm {
    /// Records calls made to the fake VMM.
    pub calls: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    /// The scriptable fault menu (design §18 delta 9, Delta register: changes from the validated v27 build); default = a healthy backend.
    pub faults: FaultMenu,
    /// Control-plane probe counter shared with every instance this fake creates, so
    /// [`FaultMenu::wedge_control_plane_for`] spans the respawns that each build a fresh instance.
    pub control_plane_probes: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    /// The host vsock path a **restored** instance reports, modelling a backend that re-binds the
    /// path its snapshot baked instead of rotating to a fresh one — the Firecracker shape (M9).
    /// `None` (default) = the fake's own path, i.e. a backend whose restore names this VM's own
    /// paths, like the CH it otherwise stands in for.
    ///
    /// Only `restore` honors it; `create` always reports the fake's own path, because a cold boot
    /// adopts nothing.
    pub restored_vsock_path: Option<PathBuf>,
}

impl FakeVmm {
    /// A fake backend scripted with `faults` (design §18 delta 9, Delta register: changes from the validated v27 build).
    #[must_use]
    pub fn with_faults(faults: FaultMenu) -> Self {
        Self {
            faults,
            ..Self::default()
        }
    }

    /// A fake backend whose `restore` adopts `path` as its host vsock path instead of naming this
    /// VM's own — Firecracker's verbatim baked-path rebind (M9).
    #[must_use]
    pub fn adopting_baked_vsock(path: impl Into<PathBuf>) -> Self {
        Self {
            restored_vsock_path: Some(path.into()),
            ..Self::default()
        }
    }

    /// Builds an instance carrying this fake's fault menu and its shared probe counter, so
    /// `boot`/`resume`/`verify_control_plane` on the instance observe the same script — including
    /// across the respawns `MicroVm::start` mints from the same `FakeVmm`.
    fn instance(&self) -> FakeVmInstance {
        FakeVmInstance {
            vsock_path: PathBuf::from("/tmp/fake-vsock"),
            serial: PathBuf::from("/tmp/fake-serial"),
            calls: self.calls.clone(),
            faults: self.faults.clone(),
            control_plane_probes: self.control_plane_probes.clone(),
        }
    }

    /// The instance a `restore` yields: [`Self::instance`], with the baked host vsock path adopted
    /// when this fake was built to model a non-rotating backend.
    fn restored_instance(&self) -> FakeVmInstance {
        let mut instance = self.instance();
        if let Some(baked) = &self.restored_vsock_path {
            instance.vsock_path = baked.clone();
        }
        instance
    }
}

/// A fake VM instance for testing.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct FakeVmInstance {
    /// Simulates a vsock path.
    pub vsock_path: PathBuf,
    /// Simulates a serial path.
    pub serial: PathBuf,
    /// Records calls made to the fake instance.
    pub calls: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    /// The fault menu inherited from the creating [`FakeVmm`] (design §18 delta 9, Delta register: changes from the validated v27 build).
    pub faults: FaultMenu,
    /// Shared with the creating [`FakeVmm`] so the control-plane wedge counter spans respawns.
    pub control_plane_probes: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl Vmm for FakeVmm {
    type Instance = FakeVmInstance;

    async fn create(
        &self,
        _cfg: &VmConfig,
        _res: &PerVmResources,
        _cgroups: &dyn crate::metrics::CgroupFs,
    ) -> Result<Self::Instance> {
        if let Ok(mut lock) = self.calls.lock() {
            lock.push("create".to_string());
        }
        if self.faults.fail_create {
            return Err(crate::error::Error::Vmm(
                "scripted create failure (FakeVmm fault menu)".into(),
            ));
        }
        Ok(self.instance())
    }

    async fn restore(
        &self,
        _snapshot_dir: &Path,
        _cfg: &VmConfig,
        _res: &PerVmResources,
        _cgroups: &dyn crate::metrics::CgroupFs,
    ) -> Result<Self::Instance> {
        if let Ok(mut lock) = self.calls.lock() {
            lock.push("restore".to_string());
        }
        if self.faults.fail_restore {
            return Err(crate::error::Error::Vmm(
                "scripted restore failure (FakeVmm fault menu)".into(),
            ));
        }
        Ok(self.restored_instance())
    }

    fn capabilities(&self) -> VmmCapabilities {
        VmmCapabilities {
            snapshot_restore: true,
            lazy_restore: false,
            virtio_fs_shares: true,
            unprivileged_vhost_user_net: true,
            nested_virt: true,
            virtio_console: true,
            // Mirrors CH (the primary backend the fake stands in for). No fake-
            // backed test asserts on restore paths today; a test exercising the
            // FC-style verbatim-rebind semantics should build its own fake with
            // this set `false`.
            restore_rotates_host_paths: true,
            disk_io_throttle: true,
            // Mirrors CH (the primary backend the fake stands in for): no USB
            // passthrough. A fake-driven test of the QEMU-only USB path must build its
            // own fake with this set `true` — and note the fakes are argv- and
            // device-node-blind either way (the live leg is the only evidence there).
            usb_host_passthrough: false,
        }
    }

    fn id(&self) -> &str {
        "fake"
    }
}

impl VmInstance for FakeVmInstance {
    async fn boot(&mut self) -> Result<()> {
        if let Ok(mut lock) = self.calls.lock() {
            lock.push("boot".to_string());
        }
        if let Some(d) = self.faults.readiness_delay {
            tokio::time::sleep(d).await;
        }
        if self.faults.fail_boot {
            return Err(crate::error::Error::Vmm(
                "scripted boot failure (FakeVmm fault menu)".into(),
            ));
        }
        Ok(())
    }
    async fn request_shutdown(&mut self) -> Result<()> {
        if let Ok(mut lock) = self.calls.lock() {
            lock.push("request_shutdown".to_string());
        }
        Ok(())
    }
    async fn kill(&mut self) -> Result<()> {
        if let Ok(mut lock) = self.calls.lock() {
            lock.push("kill".to_string());
        }
        Ok(())
    }
    async fn has_exited(&mut self) -> bool {
        // The fake has no real VMM process to reap, so it is trivially "exited":
        // `shutdown()`'s grace poll returns immediately instead of waiting the full
        // ceiling, keeping the teardown-order unit test fast (it asserts order, not
        // timing).
        true
    }
    async fn pause(&mut self) -> Result<()> {
        if let Ok(mut lock) = self.calls.lock() {
            lock.push("pause".to_string());
        }
        Ok(())
    }
    async fn resume(&mut self) -> Result<()> {
        if let Ok(mut lock) = self.calls.lock() {
            lock.push("resume".to_string());
        }
        if self.faults.fail_resume {
            return Err(crate::error::Error::Vmm(
                "scripted resume failure (FakeVmm fault menu)".into(),
            ));
        }
        Ok(())
    }
    async fn snapshot(&mut self, _dir: &Path) -> Result<()> {
        if let Ok(mut lock) = self.calls.lock() {
            lock.push("snapshot".to_string());
        }
        Ok(())
    }
    fn vsock_path(&self) -> &Path {
        &self.vsock_path
    }
    fn guest_cid(&self) -> u32 {
        3
    }
    fn serial_log(&self) -> &Path {
        &self.serial
    }

    async fn verify_control_plane(
        &self,
        _budget: std::time::Duration,
        _timeouts: &crate::config::Timeouts,
    ) -> Result<()> {
        if let Some(d) = self.faults.readiness_delay {
            tokio::time::sleep(d).await;
        }
        // Wedge the control plane for the first N probes (delta 9), then report healthy — models
        // QEMU's occasionally-stuck vhost-user-vsock bring-up that `MicroVm::start`'s respawn loop
        // recovers from. The counter is shared with the creating `FakeVmm`, so it spans respawns.
        let n = self
            .control_plane_probes
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if n < self.faults.wedge_control_plane_for {
            return Err(crate::error::Error::Vmm(format!(
                "scripted wedged control plane (FakeVmm), probe {n} < {}",
                self.faults.wedge_control_plane_for
            )));
        }
        Ok(())
    }
}

impl Drop for FakeVmInstance {
    fn drop(&mut self) {
        if let Ok(mut lock) = self.calls.lock() {
            lock.push("drop".to_string());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    // The netns-layout law's fourth shape (docs/90 `net/tap.rs:27`): `build_vmm_cmd` used to spell
    // `/var/run/netns/{n}\0` itself, so the directory a VMM was exec'd into and the one the datapath
    // bound its taps in were two independent facts. The judge is `net::tap::netns_path` — the law —
    // recomputed here, so re-inlining the literal reddens this even while it still happens to
    // produce the same bytes; `net::tap::netns_layout_gate` is the other half, scanning for the
    // literal's return.
    #[test]
    fn netns_open_path_composes_from_the_layout_law() {
        let composed = netns_open_path("vmcell-net-7");
        assert_eq!(
            composed.strip_suffix('\0'),
            Some(
                crate::net::tap::netns_path("vmcell-net-7")
                    .to_str()
                    .expect("the layout and a `naming`-composed netns name are both UTF-8")
            ),
            "the pre-fork C string must be the law's path plus a terminator, nothing else"
        );
        // Exactly one NUL, at the end: `open(2)` reads to the first one, so a stray earlier
        // terminator would silently open a PREFIX of the namespace path.
        assert_eq!(composed.matches('\0').count(), 1);
        assert!(composed.ends_with('\0'));
        // A segment namespace is the same composition — the sweep and the members share one layout.
        assert_eq!(
            netns_open_path("vmcell-seg-3").strip_suffix('\0'),
            crate::net::tap::netns_path("vmcell-seg-3").to_str()
        );
    }

    // M9, the law's half: which vmid a restored VM's ADOPTED host path is keyed on. A non-rotating
    // backend re-binds the vsock UDS its snapshot baked, so the restored VM lives in the ancestor
    // vmid's scratch dir while holding a fresh vmid of its own — and the ancestor's was free for
    // reallocation. The inverse of each arm below is a real defect: returning `Some` for the VM's
    // own directory reserves a second id per restore forever, and returning `None` for a foreign
    // directory is the finding itself.
    #[test]
    fn adopted_scratch_vmid_names_the_ancestor_and_only_a_real_scratch_path() {
        let base = std::path::Path::new("/tmp");
        let own = per_vm_scratch_dir("vmcell", base, 4242, 9);

        // The FC shape: the snapshot's baked path, in the ANCESTOR's directory.
        let baked = per_vm_scratch_dir("vmcell", base, 4242, 5).join("vsock.sock");
        assert_eq!(adopted_scratch_vmid("vmcell", &own, &baked), Some(5));

        // A foreign pid still counts: vmids are claimed host-globally, and the pid in a path is no
        // promise about which process will next hold that id.
        let other_pid = per_vm_scratch_dir("vmcell", base, 777, 5).join("vsock.sock");
        assert_eq!(adopted_scratch_vmid("vmcell", &own, &other_pid), Some(5));

        // This VM's OWN path (CH rewrites the snapshot config to it; QEMU rotates to it) reserves
        // nothing — it is already covered by the VM's own vmid guard.
        assert_eq!(
            adopted_scratch_vmid("vmcell", &own, &own.join("vsock.sock")),
            None
        );

        // Not a per-VM scratch path at all: a different prefix's tree, a non-numeric tail, and a
        // bare file in the temp dir. Reserving an id off any of these would be arbitrary.
        assert_eq!(
            adopted_scratch_vmid(
                "vmcell",
                &own,
                &per_vm_scratch_dir("other", base, 4242, 5).join("vsock.sock")
            ),
            None
        );
        assert_eq!(
            adopted_scratch_vmid(
                "vmcell",
                &own,
                std::path::Path::new("/tmp/vmcell-vm-a-b/v.sock")
            ),
            None
        );
        assert_eq!(
            adopted_scratch_vmid("vmcell", &own, std::path::Path::new("/tmp/fake-vsock")),
            None
        );

        // The inverse is the forward composer, so a prefix that itself contains the `-vm-<n>-<n>`
        // shape cannot be mis-parsed into somebody else's id.
        let tricky_own = per_vm_scratch_dir("my-vm-9", base, 4242, 9);
        let tricky = per_vm_scratch_dir("my-vm-9", base, 4242, 5).join("vsock.sock");
        assert_eq!(
            adopted_scratch_vmid("my-vm-9", &tricky_own, &tricky),
            Some(5)
        );
        assert_eq!(adopted_scratch_vmid("vmcell", &tricky_own, &tricky), None);
    }

    // M9, the CALL-SITE half — the one that actually reddens on the shipped defect (AGENTS.md: "a
    // gate binds the call sites, not just the extracted predicate"). A restore whose backend adopted
    // the ancestor's baked path must hold that ancestor's vmid for the restored VM's whole lifetime,
    // or a later VM draws it, `VmTempDir::create`s the very directory the restored VM is living in,
    // and removes it on teardown. KVM-free: the fake models the verbatim rebind, and `FakeVmm` is
    // filesystem-blind, so this asserts on the ALLOCATOR — which is exactly where the identity lives.
    //
    // Red on the inverse: drop the `adopt_lineage` call from `restore_inner` (or hand it
    // `res.vmid`) and the "cannot be reallocated" assert fails; drop the release from
    // `VmidGuard::drop` and the post-drop assert fails.
    #[tokio::test]
    async fn a_restore_holds_the_ancestor_vmid_its_adopted_paths_are_keyed_on() {
        const OWN: u32 = 9;
        const ANCESTOR: u32 = 5;

        let baked = per_vm_scratch_dir(
            "vmcell",
            &std::env::temp_dir(),
            std::process::id(),
            ANCESTOR,
        )
        .join("vsock.sock");
        let vmm = FakeVmm::adopting_baked_vsock(&baked);
        let env = crate::env::HostEnv::for_unit_tests();
        let cfg = crate::config::VmConfig::builder(
            PathBuf::from("/vmlinux"),
            crate::config::RootfsSource::Erofs {
                image: PathBuf::from("/rootfs.erofs"),
            },
        )
        // Pinned so the fresh vmid is never the ancestor's by luck — that would make every
        // assertion below vacuously true.
        .vmid(OWN)
        .network_disabled()
        .build()
        .expect("valid config");

        // Precondition: the ancestor's id is free, so the refusal below is about this restore.
        env.vmids
            .reserve(ANCESTOR)
            .expect("precondition: the ancestor vmid is free");
        env.vmids.release(ANCESTOR);

        let vm = crate::MicroVm::restore(&vmm, std::path::Path::new("/tmp/fake-snap"), cfg, &env)
            .await
            .expect("the fake restore must succeed");

        assert!(
            env.vmids.reserve(ANCESTOR).is_err(),
            "the ancestor vmid {ANCESTOR} must not be reallocatable while a restore is living in \
             its scratch directory"
        );
        // Non-vacuity: the restored VM's own id is a DIFFERENT one, so the refusal above is the
        // lineage reservation and not just the VM's own guard.
        assert!(
            env.vmids.reserve(OWN).is_err(),
            "the restored VM's own vmid is held too"
        );
        assert_ne!(OWN, ANCESTOR);

        // …and the reservation is a lease, not a leak: teardown returns BOTH ids.
        drop(vm);
        assert_eq!(
            env.vmids.reserve(ANCESTOR).expect("ancestor released"),
            ANCESTOR
        );
        assert_eq!(env.vmids.reserve(OWN).expect("own vmid released"), OWN);
    }

    // The boundary case between the two legs above: a snapshot taken by ANOTHER process whose VM
    // held the very id this restore drew. The adopted directory is a different one (`<prefix>-vm-<other
    // pid>-<id>`), so the law names an ancestor — but this guard already holds that id, and
    // `reserve` reports our own claim as a conflict. Left unhandled, one restore in 254 fails with a
    // spurious "vmid in use".
    // Red on the inverse: make `adopt_lineage`'s conflict arm a refusal — the shape this fix
    // deliberately did NOT take, because an already-claimed id already satisfies the invariant — and
    // the restore below fails with `Exhaustion`.
    #[tokio::test]
    async fn a_restore_whose_ancestor_id_is_its_own_is_not_refused() {
        const OWN: u32 = 13;

        // Same vmid, a foreign pid — the shape a cross-process snapshot restore hits.
        let baked =
            per_vm_scratch_dir("vmcell", &std::env::temp_dir(), 424_242, OWN).join("vsock.sock");
        let vmm = FakeVmm::adopting_baked_vsock(&baked);
        let env = crate::env::HostEnv::for_unit_tests();
        let cfg = crate::config::VmConfig::builder(
            PathBuf::from("/vmlinux"),
            crate::config::RootfsSource::Erofs {
                image: PathBuf::from("/rootfs.erofs"),
            },
        )
        .vmid(OWN)
        .network_disabled()
        .build()
        .expect("valid config");

        let vm = crate::MicroVm::restore(&vmm, std::path::Path::new("/tmp/fake-snap"), cfg, &env)
            .await
            .expect("a restore whose ancestor id is the id it drew must not be refused");

        // Precondition of the whole test: the law DID name an ancestor here, so this is not passing
        // because nothing was adopted.
        let own_dir = per_vm_scratch_dir("vmcell", &std::env::temp_dir(), std::process::id(), OWN);
        assert_eq!(adopted_scratch_vmid("vmcell", &own_dir, &baked), Some(OWN));

        // And the id is held exactly once, so the single `release` on drop returns it.
        drop(vm);
        assert_eq!(env.vmids.reserve(OWN).expect("own vmid released"), OWN);
    }

    // The shape the LIVE restore suites actually run: the caller holds the source VM's vmid across
    // the restore on purpose, to force the restored VM onto a different one
    // (`snapshot_restore.rs`/`extra_block.rs` both do). The ancestor's id is therefore already out of
    // the pool — which is the whole property M9's reservation buys — so the restore must proceed, and
    // must NOT take ownership of a claim it did not make.
    // Red on the inverse, both ways: make the conflict arm a refusal and the restore fails; set
    // `self.lineage = Some(ancestor)` on it and the post-drop assert fails, because teardown hands
    // somebody else's identity back to the pool — a worse defect than the one being fixed.
    #[tokio::test]
    async fn a_restore_does_not_release_an_ancestor_claim_it_never_took() {
        const OWN: u32 = 21;
        const ANCESTOR: u32 = 22;

        let baked = per_vm_scratch_dir(
            "vmcell",
            &std::env::temp_dir(),
            std::process::id(),
            ANCESTOR,
        )
        .join("vsock.sock");
        let vmm = FakeVmm::adopting_baked_vsock(&baked);
        let env = crate::env::HostEnv::for_unit_tests();
        let cfg = crate::config::VmConfig::builder(
            PathBuf::from("/vmlinux"),
            crate::config::RootfsSource::Erofs {
                image: PathBuf::from("/rootfs.erofs"),
            },
        )
        .vmid(OWN)
        .network_disabled()
        .build()
        .expect("valid config");

        // The caller's own hold on the ancestor's id, taken BEFORE the restore.
        env.vmids
            .reserve(ANCESTOR)
            .expect("the caller reserves the source vmid to force rotation");

        let vm = crate::MicroVm::restore(&vmm, std::path::Path::new("/tmp/fake-snap"), cfg, &env)
            .await
            .expect("a restore whose ancestor id is already claimed must not be refused");

        // The teardown releases only what this VM took: the caller's claim survives it.
        drop(vm);
        assert!(
            env.vmids.reserve(ANCESTOR).is_err(),
            "the caller's claim on vmid {ANCESTOR} must survive the restored VM's teardown"
        );
        assert_eq!(env.vmids.reserve(OWN).expect("own vmid released"), OWN);
    }

    // The other half of the same law at the same call site: a ROTATING backend (the default fake,
    // standing in for CH, whose restore rewrites the snapshot config to this VM's own paths) must
    // reserve NOTHING extra. Without this, "reserve the ancestor" could be implemented as "reserve
    // something on every restore", quietly halving the id space.
    #[tokio::test]
    async fn a_rotating_backend_restore_holds_only_its_own_vmid() {
        const OWN: u32 = 11;

        let vmm = FakeVmm::default();
        let env = crate::env::HostEnv::for_unit_tests();
        let cfg = crate::config::VmConfig::builder(
            PathBuf::from("/vmlinux"),
            crate::config::RootfsSource::Erofs {
                image: PathBuf::from("/rootfs.erofs"),
            },
        )
        .vmid(OWN)
        .network_disabled()
        .build()
        .expect("valid config");

        let vm = crate::MicroVm::restore(&vmm, std::path::Path::new("/tmp/fake-snap"), cfg, &env)
            .await
            .expect("the fake restore must succeed");

        // Every id except this VM's own is still available: the whole space, one held.
        let held: Vec<u32> = (1..=crate::net::MAX_VMID)
            .filter(|id| env.vmids.reserve(*id).is_err())
            .collect();
        assert_eq!(
            held,
            vec![OWN],
            "a rotating backend's restore must hold exactly its own vmid"
        );
        drop(vm);
    }

    // Guards E3: the per-VM temp dir (serial.log + lock + stale sockets) must be
    // removed on teardown, not just the vsock socket. The inverse — a teardown
    // that removes only the sockets and leaves the directory — is exactly the
    // leak this finding reports, and goes red here because the dir still exists.
    #[test]
    fn test_remove_vm_tmp_dir_removes_whole_dir() {
        let parent = tempfile::tempdir().expect("create parent tempdir");
        let vm_dir = parent.path().join("vmcell-vm-1-2");
        std::fs::create_dir_all(&vm_dir).expect("create per-VM dir");
        std::fs::write(vm_dir.join("serial.log"), b"boot log").expect("write serial.log");
        std::fs::write(vm_dir.join("api.sock.lock"), b"").expect("write lock");
        assert!(vm_dir.exists(), "precondition: per-VM dir exists");

        remove_vm_tmp_dir(&vm_dir);

        assert!(
            !vm_dir.exists(),
            "per-VM temp dir (with serial.log) leaked after teardown"
        );

        // Idempotent: removing an already-gone dir is a no-op, not a panic/error.
        remove_vm_tmp_dir(&vm_dir);
    }

    // Pins the trait default: every backend that does NOT override `vsock_endpoint`
    // keeps the AF_UNIX hybrid-vsock transport, derived from `vsock_path()` + the
    // shared `STEWARD_VSOCK_PORT`. A backend on the AF_VSOCK transport (an in-kernel-vsock QEMU,
    // and crosvm always) must override this method; the buggy inverse (a QEMU or crosvm
    // that forgets to override, so the host dials a vestigial AF_UNIX path) is
    // exactly what an endpoint-mismatch would surface.
    #[test]
    fn fake_instance_vsock_endpoint_defaults_to_unix_path() {
        // FRU (`..Default::default()`) can't move out of a `Drop` type, so set the
        // one field we care about after constructing the default.
        let mut inst = FakeVmInstance::default();
        inst.vsock_path = PathBuf::from("/tmp/probe-vsock.sock");
        assert_eq!(
            inst.vsock_endpoint(),
            VsockEndpoint::Unix {
                path: PathBuf::from("/tmp/probe-vsock.sock"),
                port: STEWARD_VSOCK_PORT,
            },
        );
    }

    /// Spawns a long-lived stand-in process in its own process group, returning the
    /// live tokio `Child`. Drives the reap tests without a real VMM binary.
    fn spawn_group_standin() -> tokio::process::Child {
        let mut std_cmd = std::process::Command::new("sleep");
        std_cmd.arg("60");
        use std::os::unix::process::CommandExt;
        std_cmd.process_group(0);
        tokio::process::Command::from(std_cmd)
            .spawn()
            .expect("spawn sleep stand-in")
    }

    // Guards VMM-2: the shared spawn+register+await-ready helper MUST reap the process
    // group when the control socket never appears (readiness failure). The buggy
    // inverse — a backend that diverged and dropped the bare `Child` (no kill-on-drop)
    // on the readiness path — would leave the process running; this asserts the helper
    // both surfaces a `Timeout` and kills the group.
    #[tokio::test]
    async fn register_and_await_ready_reaps_group_on_readiness_failure() {
        let mut process = spawn_group_standin();
        let pid = process.id().expect("stand-in pid") as i32;
        let cgroups = crate::metrics::FakeCgroupFs::new(); // add_task succeeds
        // A socket that never appears + a short timeout forces the readiness failure.
        let never = std::env::temp_dir().join("vmcell-nonexistent-readiness.sock");
        let _ = std::fs::remove_file(&never);

        // The private `_within` seam, so this gate keeps its short ceiling: the public
        // `register_and_await_ready` takes no ceiling argument at all (§8).
        let result =
            register_and_await_ready_within(&mut process, &cgroups, "vmcell-test", &never, 100, 20)
                .await;
        assert!(
            matches!(result, Err(crate::error::Error::Timeout(_))),
            "readiness failure must surface a Timeout, got {result:?}"
        );

        // The process group must have been reaped. Poll to stay robust against the
        // host reaper winning the waitpid race.
        let mut gone = false;
        for _ in 0..50 {
            if nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), None).is_err() {
                gone = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(
            gone,
            "register_and_await_ready must reap the process group on a readiness failure"
        );
    }

    // Guards §8: the readiness ceiling has exactly ONE home. `register_and_await_ready`
    // and `wait_for_vmm_socket` must take no ceiling argument (a backend that could pass
    // one would re-create the six bare `1000`s docs/81 §8 found), and the value they use
    // must be the named const. Inverse: change either wrapper to forward a literal of its
    // own instead of `VMM_SOCKET_READY_TIMEOUT_MS` and the elapsed-time assert reddens;
    // re-adding a ceiling parameter to either signature reddens at COMPILE time, since
    // these calls pass none.
    #[tokio::test]
    async fn vmm_socket_readiness_rides_the_one_named_ceiling() {
        let never = std::env::temp_dir().join("vmcell-nonexistent-vmm-ready-ceiling.sock");
        let _ = std::fs::remove_file(&never);

        let started = std::time::Instant::now();
        let result = wait_for_vmm_socket(&never, None, 20).await;
        let elapsed = started.elapsed();

        assert!(
            matches!(result, Err(crate::error::Error::Timeout(_))),
            "an absent socket must time out, got {result:?}"
        );
        // The wrapper passes VMM_SOCKET_READY_TIMEOUT_MS and nothing else, so the elapse
        // brackets it. The upper bound is generous (a loaded CI box) but far below any
        // plausible second literal a backend would reach for.
        let ceiling = std::time::Duration::from_millis(VMM_SOCKET_READY_TIMEOUT_MS);
        assert!(
            elapsed >= ceiling,
            "wait_for_vmm_socket returned after {elapsed:?}, before its {ceiling:?} ceiling"
        );
        assert!(
            elapsed < ceiling * 4,
            "wait_for_vmm_socket took {elapsed:?}, far past the {ceiling:?} ceiling it must ride"
        );
    }

    // Guards M-VMM-1 / L1 for the shared owner of the reaped flag. Once the leader is
    // reaped the kernel may recycle its pgid, so NEITHER teardown path may signal the
    // group again. A live decoy in its own process group stands in for that recycled
    // group; both `kill_and_wait` (the graceful path) and `reap_now` (the `Drop` path)
    // are driven against the SAME already-reaped group, because a helper that guards one
    // and not the other is exactly the divergence this type exists to prevent.
    //
    // Inverse: drop the `!self.reaped` guard in either method and the decoy is SIGKILLed,
    // so `try_wait` reports it exited — reddening the assert for that leg.
    #[tokio::test]
    async fn reaped_process_group_never_signals_a_recycled_pgid() {
        let mut decoy = spawn_group_standin();
        let decoy_pgid = decoy.id().expect("decoy pid");

        let mut group = VmmProcessGroup::already_reaped_for_test(Some(decoy_pgid));
        assert!(group.is_reaped(), "the fixture must start already-reaped");

        // A fast-exiting stand-in leader so `kill_and_wait`'s `process.wait()` returns
        // promptly instead of blocking on a live process.
        let mut leader = tokio::process::Command::new("true")
            .spawn()
            .expect("spawn `true` leader");
        group.kill_and_wait(&mut leader).await;
        group.reap_now(&mut leader);

        // A SIGKILL to the (recycled) pgid would land within a few ms; give it time.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let decoy_status = decoy.try_wait().expect("try_wait decoy");
        // Clean up the decoy regardless of the outcome — a test's own fixtures are
        // residue too.
        sigkill_process_group(decoy_pgid);
        let _ = decoy.wait().await;

        assert!(
            decoy_status.is_none(),
            "a reaped VmmProcessGroup must not SIGKILL its (recycled) pgid — the decoy died"
        );
    }

    // The POSITIVE control for the test above: a group that has NOT been reaped is
    // signalled, so the negative result there is about the flag and not about a helper
    // that never signals anything. Inverse: make `kill_and_wait` skip the signal
    // unconditionally and the group survives, reddening `gone`.
    #[tokio::test]
    async fn unreaped_process_group_is_signalled_and_flagged() {
        let mut leader = spawn_group_standin();
        let pid = leader.id().expect("stand-in pid") as i32;

        let mut group = VmmProcessGroup::new(Some(pid as u32));
        assert!(!group.is_reaped(), "a fresh group is not reaped");
        group.kill_and_wait(&mut leader).await;
        assert!(
            group.is_reaped(),
            "kill_and_wait must record the reap so Drop cannot re-signal (M-VMM-1)"
        );

        let mut gone = false;
        for _ in 0..50 {
            if nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), None).is_err() {
                gone = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(
            gone,
            "kill_and_wait must SIGKILL an un-reaped process group"
        );
    }

    // Guards M-VMM-1's other half: `note_exit` must RECORD the reap, or a later
    // `kill()`/`Drop` re-signals a pgid the kernel may already have recycled. Inverse:
    // return the bool without setting the flag and `is_reaped()` stays false.
    #[tokio::test]
    async fn note_exit_records_the_reap() {
        let mut leader = spawn_group_standin();
        let pgid = leader.id().expect("stand-in pid");
        sigkill_process_group(pgid);

        let mut group = VmmProcessGroup::new(Some(pgid));
        let mut exited = false;
        for _ in 0..100 {
            if group.note_exit(&mut leader) {
                exited = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(exited, "note_exit must report the killed leader as exited");
        assert!(
            group.is_reaped(),
            "note_exit must record `reaped` after reaping the leader (M-VMM-1)"
        );
    }

    // Guards d7's law in its ONE home: each branch keys off the descriptor value handed
    // in (never a hardcoded bool), the feature string EQUALS the `VmmCapabilities` field
    // name (N-VMM-1), and the `vmm` string is the caller's. Inverse: hardcode either
    // refusal (so an advertised capability is still refused) and the advertised legs
    // redden; misspell a feature string and its assert reddens.
    #[test]
    fn reject_unadvertised_capabilities_keys_off_the_descriptor_it_is_handed() {
        let caps = |nested: bool, lazy: bool| VmmCapabilities {
            snapshot_restore: true,
            lazy_restore: lazy,
            virtio_fs_shares: true,
            unprivileged_vhost_user_net: true,
            nested_virt: nested,
            virtio_console: true,
            restore_rotates_host_paths: true,
            disk_io_throttle: true,
            usb_host_passthrough: false,
        };
        let cfg = |nested: bool, mode: crate::config::RestoreMode| {
            crate::config::VmConfig::builder(
                "/k",
                crate::config::RootfsSource::Erofs {
                    image: PathBuf::from("/i"),
                },
            )
            .nested_virt(nested)
            .restore_mode(mode)
            .build()
            .expect("a minimal erofs config builds")
        };

        // Advertised: both pass.
        reject_unadvertised_capabilities(
            "probe",
            &caps(true, true),
            &cfg(true, crate::config::RestoreMode::Lazy),
        )
        .expect("an advertised capability must be accepted");

        // Unadvertised nested_virt.
        let err = reject_unadvertised_capabilities(
            "probe",
            &caps(false, true),
            &cfg(true, crate::config::RestoreMode::Default),
        )
        .expect_err("nested_virt on an incapable descriptor must be refused");
        assert!(
            matches!(&err, crate::error::Error::Unsupported { vmm, feature }
                if vmm == "probe" && feature == "nested_virt"),
            "expected Unsupported{{vmm: probe, feature: nested_virt}}, got {err:?}"
        );

        // Unadvertised lazy_restore.
        let err = reject_unadvertised_capabilities(
            "probe",
            &caps(true, false),
            &cfg(false, crate::config::RestoreMode::Lazy),
        )
        .expect_err("RestoreMode::Lazy on an incapable descriptor must be refused");
        assert!(
            matches!(&err, crate::error::Error::Unsupported { vmm, feature }
                if vmm == "probe" && feature == "lazy_restore"),
            "expected Unsupported{{vmm: probe, feature: lazy_restore}}, got {err:?}"
        );

        // Eager restore is never the lazy_restore case, whatever the flag says.
        reject_unadvertised_capabilities(
            "probe",
            &caps(true, false),
            &cfg(false, crate::config::RestoreMode::Eager),
        )
        .expect("Eager restore must not trip the lazy_restore guard");
    }

    // Guards the interval clamp in `wait_for_socket`: the interval is caller-supplied
    // via the pub `VmConfig.timeouts` field, so an unclamped implementation (the buggy
    // inverse) computes `timeout_ms / 0` and panics before any readiness check runs.
    // With the clamp, a 0-interval call degrades to a 1 ms poll and still finds the
    // already-present socket path.
    #[tokio::test]
    async fn wait_for_socket_zero_interval_does_not_divide_by_zero() {
        // `kill_on_drop` (not `spawn_group_standin`) so the single-process stand-in
        // is reclaimed even when the call panics — the buggy-inverse path this test
        // guards never reaches the explicit reap below.
        let mut process = tokio::process::Command::new("sleep")
            .arg("60")
            .kill_on_drop(true)
            .spawn()
            .expect("spawn sleep stand-in");
        let dir = tempfile::tempdir().expect("create tempdir");
        let sock = dir.path().join("present.sock");
        std::fs::write(&sock, b"").expect("create stand-in socket path");

        let result = wait_for_socket(&sock, Some(&mut process), 100, 0).await;

        // Best-effort prompt reap on the success path (kill_on_drop covers panic);
        // the discarded results cannot affect the verdict, which is `result` below.
        let _ = process.start_kill();
        let _ = process.wait().await;
        result.expect("a present socket with a 0 interval must succeed, not panic");
    }

    // Guards M-VMM-8: the readiness wait must surface an early VMM exit as the real
    // cause, not fall through to a Timeout a full window later. Inverse: delete the
    // `try_wait` guard and this returns a Timeout (after the whole deadline) instead of
    // a fast `Vmm("process exited early")`, reddening both assertions.
    #[tokio::test]
    async fn wait_for_socket_fails_fast_on_early_process_exit() {
        let mut process = tokio::process::Command::new("sh")
            .arg("-c")
            .arg("exit 7")
            .spawn()
            .expect("spawn sh");

        let dir = tempfile::tempdir().expect("create tempdir");
        let never = dir.path().join("vmcell-never-appears.sock");

        let start = std::time::Instant::now();
        // A generous 5 s ceiling: the fail-fast path must return in well under it.
        let result = wait_for_socket(&never, Some(&mut process), 5000, 50).await;
        let elapsed = start.elapsed();

        assert!(
            matches!(&result, Err(crate::error::Error::Vmm(msg)) if msg.contains("exited early")),
            "an early process exit must return a Vmm error naming it, got {result:?}"
        );
        assert!(
            elapsed.as_millis() < 2000,
            "early exit must fail fast (well under the 5 s ceiling), took {elapsed:?}"
        );
    }

    // Guards L-VMM-1: with interval > timeout the old `timeout_ms / interval_ms == 0`
    // loop ran zero checks and returned Timeout without ever looking; the deadline loop
    // must still check at least once and find an already-present socket. Inverse:
    // restore the iteration-count loop and this returns Timeout immediately.
    #[tokio::test]
    async fn wait_for_socket_interval_greater_than_timeout_still_checks_once() {
        let mut process = tokio::process::Command::new("sleep")
            .arg("60")
            .kill_on_drop(true)
            .spawn()
            .expect("spawn sleep stand-in");
        let dir = tempfile::tempdir().expect("create tempdir");
        let sock = dir.path().join("present.sock");
        std::fs::write(&sock, b"").expect("create stand-in socket path");

        let result = wait_for_socket(&sock, Some(&mut process), 100, 2000).await;
        let _ = process.start_kill();
        let _ = process.wait().await;
        result.expect("interval > timeout must still check the present socket once");
    }

    // Guards the process-less (`None`) readiness path used for the smoltcp vhost-user-net
    // socket (an in-process thread, no `Child` to watch): a present socket returns Ok and
    // an absent one Times Out, with no `try_wait` on a non-existent process. Inverse:
    // make the `process` param non-optional again and the smoltcp caller (qemu.rs) fails
    // to compile, or an `unwrap` on the `None` process panics here.
    #[tokio::test]
    async fn wait_for_socket_process_less_present_ok_absent_times_out() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let present = dir.path().join("present.sock");
        std::fs::write(&present, b"").expect("create stand-in socket path");
        wait_for_socket(&present, None, 100, 5)
            .await
            .expect("a present socket must succeed with no process to watch");

        let absent = dir.path().join("never.sock");
        let result = wait_for_socket(&absent, None, 60, 5).await;
        assert!(
            matches!(result, Err(crate::error::Error::Timeout(_))),
            "an absent socket with no process must Time Out, got {result:?}"
        );
    }

    // Guards M6: the snapshot RPC's budget is a function of guest RAM, not the flat
    // control ceiling. Pure math against known values, so a regression to a constant is
    // caught KVM-free. Inverse (`snapshot_request_timeout` returning
    // `CONTROL_REQUEST_TIMEOUT`) reddens every assert but the zero-RAM one.
    #[test]
    fn snapshot_request_timeout_scales_with_guest_ram() {
        use std::time::Duration;

        // A zero-RAM instance (the FC CPU-template probe) degrades to the flat ceiling.
        assert_eq!(snapshot_request_timeout(0), CONTROL_REQUEST_TIMEOUT);
        // 64 MiB/s floor, rounded UP: 256 MiB ⇒ 4 s of write on top of the ceiling.
        assert_eq!(snapshot_request_timeout(256), Duration::from_secs(5 + 4));
        // A partial second still costs a whole one (`div_ceil`), never zero.
        assert_eq!(snapshot_request_timeout(1), Duration::from_secs(5 + 1));
        assert_eq!(snapshot_request_timeout(2048), Duration::from_secs(5 + 32));
        // The 4 GiB guest the flat 5 s ceiling could not have finished under any
        // plausible disk: strictly more than a minute of budget.
        assert!(snapshot_request_timeout(4096) > Duration::from_secs(60));
        // Monotone non-decreasing across the range.
        let mut prev = snapshot_request_timeout(0);
        for mib in (0..=8192).step_by(97) {
            let now = snapshot_request_timeout(mib);
            assert!(
                now >= prev,
                "budget must not shrink as guest RAM grows ({mib} MiB)"
            );
            prev = now;
        }
    }

    // Guards M-VMM-2: a control socket that accepts a connection but never speaks must
    // not hang a control RPC forever — it surfaces a typed Timeout. Paused time
    // auto-advances to the request ceiling once every task is parked on the silent
    // socket. Inverse: remove the `tokio::time::timeout` wrap and this never returns.
    #[tokio::test(start_paused = true)]
    async fn unix_api_request_times_out_on_wedged_socket() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let sock = dir.path().join("wedged.sock");
        let listener = tokio::net::UnixListener::bind(&sock).expect("bind wedged listener");
        tokio::spawn(async move {
            if let Ok((_stream, _)) = listener.accept().await {
                // Hold the accepted connection open but never respond.
                std::future::pending::<()>().await;
            }
        });

        let result = unix_api_request(&sock, "GET", "/health", None::<&()>).await;
        assert!(
            matches!(result, Err(crate::error::Error::Timeout(_))),
            "a wedged control socket must surface a Timeout, got {result:?}"
        );
    }

    // Guards M-VMM-9: a non-2xx reply must map to Error::VmmApi carrying the status AND
    // the response body (firecracker's T2 probe pattern-matches status 400 + body
    // "template"). Inverse: drop the body-collection loop and `body` is empty,
    // reddening `contains("template")`; drop the status mapping and it is not VmmApi.
    #[tokio::test]
    async fn unix_api_request_maps_non_2xx_status_and_body() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let sock = dir.path().join("api.sock");
        let listener = tokio::net::UnixListener::bind(&sock).expect("bind api listener");

        let server = tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                // Drain the request so the client's write completes.
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf).await;
                let resp = "HTTP/1.1 400 Bad Request\r\nContent-Length: 14\r\n\r\ntemplate error";
                let _ = stream.write_all(resp.as_bytes()).await;
                let _ = stream.flush().await;
                // Hold the connection briefly so the client reads the full body.
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        });

        let result = unix_api_request(&sock, "POST", "/test", None::<&serde_json::Value>).await;
        let _ = server.await;
        assert!(
            matches!(&result, Err(crate::error::Error::VmmApi { status: 400, body })
                if body.contains("template")),
            "a non-2xx reply must map to VmmApi with status + body, got {result:?}"
        );
    }

    fn res_with(vhost_user_socket: Option<PathBuf>) -> PerVmResources {
        PerVmResources {
            cgroup_name: "vmcell-test".to_string(),
            tap_name: Some("tap0".to_string()),
            netns_name: Some("ns0".to_string()),
            segment: None,
            vhost_user_socket,
            vmid: 1,
            guest_cid: 3,
            tmp_dir: PathBuf::from("/tmp/vmcell-vm-test-1"),
        }
    }

    // Guards M-VMM-5 / H-VMM-3: the ONE shared snapshot-eligibility predicate. The
    // pure truth table plus the config boundaries — including a virtio-fs data
    // share. Inverse: drop the `!cfg.shares.is_empty()` term from
    // `config_has_vhost_user_device` and the virtio-fs-share assertion reddens.
    #[test]
    fn config_has_vhost_user_device_covers_all_boundaries() {
        use crate::config::{Access, CachePolicy, Egress, NetConfig, RootfsSource, Share};

        assert!(has_vhost_user_device(true, false, false));
        assert!(has_vhost_user_device(false, true, false));
        assert!(has_vhost_user_device(false, false, true));
        assert!(!has_vhost_user_device(false, false, false));

        let virtio_fs_share = VmConfig::builder(
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
        assert!(
            config_has_vhost_user_device(&virtio_fs_share, &res_with(None)),
            "a virtio-fs data share must be treated as a vhost-user device"
        );

        let unprivileged = VmConfig::builder(
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
        assert!(config_has_vhost_user_device(&unprivileged, &res_with(None)));

        let plain = VmConfig::builder(
            "/k",
            RootfsSource::Erofs {
                image: PathBuf::from("/i"),
            },
        )
        .build()
        .expect("build plain config");
        assert!(config_has_vhost_user_device(
            &plain,
            &res_with(Some(PathBuf::from("/run/vhost.sock")))
        ));

        let eligible = VmConfig::builder(
            "/k",
            RootfsSource::Erofs {
                image: PathBuf::from("/i"),
            },
        )
        .net(NetConfig::Privileged {
            egress: Egress::default(),
        })
        .build()
        .expect("build eligible config");
        assert!(!config_has_vhost_user_device(&eligible, &res_with(None)));

        // §4.6 (Extra virtio-blk devices and disk-I/O throttling): an extra PLAIN virtio-blk device is NOT a vhost-user device, so it
        // must stay snapshot-eligible ("plain virtio-blk composes with snapshot",
        // §17, Open gaps and future capabilities / §8.1, The warm-snapshot path and the eligibility law). A false positive here would wrongly disqualify snapshot.
        // Inverse: add an `extra_disks` term to `config_has_vhost_user_device` and
        // this reddens.
        let with_extra_disk = VmConfig::builder(
            "/k",
            RootfsSource::Erofs {
                image: PathBuf::from("/i"),
            },
        )
        .with_extra_disk(crate::config::BlockDevice::read_write("/img/data.raw"))
        .build()
        .expect("build config with an extra disk");
        assert!(
            !config_has_vhost_user_device(&with_extra_disk, &res_with(None)),
            "a plain extra virtio-blk device must not disqualify snapshot eligibility"
        );
    }

    // Guards the shared console self-guard: VirtioConsole on a backend that does not
    // advertise `virtio_console` (Firecracker) must return a typed
    // `Unsupported { feature: "virtio_console" }`; a capable backend (CH/QEMU/crosvm) must
    // accept it; and Uart is always accepted regardless of the capability. The buggy
    // inverse (no guard, or gating the wrong mode) lets a VirtioConsole config reach a
    // backend with no hvc0 device — `console=hvc0` then sinks nowhere and serial.log
    // goes silent — and reddens one of the assertions below.
    #[test]
    fn reject_unsupported_console_gates_only_virtio_on_incapable_backends() {
        use crate::config::ConsoleMode;

        let caps = |virtio_console: bool| VmmCapabilities {
            snapshot_restore: true,
            lazy_restore: false,
            virtio_fs_shares: true,
            unprivileged_vhost_user_net: true,
            nested_virt: true,
            virtio_console,
            restore_rotates_host_paths: true,
            disk_io_throttle: true,
            usb_host_passthrough: false,
        };

        // FC-like (virtio_console:false) + VirtioConsole => Unsupported.
        let err =
            reject_unsupported_console("firecracker", &caps(false), ConsoleMode::VirtioConsole)
                .expect_err("an incapable backend must reject VirtioConsole");
        assert!(
            matches!(&err, crate::error::Error::Unsupported { vmm, feature }
                if vmm == "firecracker" && feature == "virtio_console"),
            "expected virtio_console Unsupported, got {err:?}"
        );

        // CH/QEMU/crosvm-like (virtio_console:true) + VirtioConsole => Ok. crosvm advertises
        // `virtio_console: true` too (`--serial hardware=virtio-console`), so it belongs on this
        // side of the guard.
        for vmm in ["cloud-hypervisor", "qemu", "crosvm"] {
            reject_unsupported_console(vmm, &caps(true), ConsoleMode::VirtioConsole)
                .expect("a capable backend must accept VirtioConsole");
        }

        // Uart is always accepted, on capable and incapable backends alike (the
        // over-rejection inverse — gating Uart too — reddens here).
        reject_unsupported_console("firecracker", &caps(false), ConsoleMode::Uart)
            .expect("Uart must always be accepted");
        reject_unsupported_console("cloud-hypervisor", &caps(true), ConsoleMode::Uart)
            .expect("Uart must always be accepted");
    }

    // v30 §18 delta 9: the ONE host-USB refusal predicate. Guards three things at once —
    // (a) an incapable backend refuses a non-empty list, (b) the typed feature string IS
    // the `VmmCapabilities` field name (N-VMM-1; a caller matching feature strings sees
    // one spelling across CH/FC/crosvm), and (c) an EMPTY list is accepted everywhere, so
    // adding the predicate to four `create()` paths cannot reject the 99% config.
    // Red on the inverse: a refusal keyed on `caps.usb_host_passthrough` alone (ignoring
    // emptiness) fails the empty-list legs; a hand-spelled "usb-host"/"usb_passthrough"
    // feature string fails the equality assert.
    #[test]
    fn reject_usb_host_devices_refuses_only_incapable_backends_with_devices() {
        use crate::config::UsbHostDevice;

        let caps = |usb_host_passthrough: bool| VmmCapabilities {
            snapshot_restore: true,
            lazy_restore: false,
            virtio_fs_shares: true,
            unprivileged_vhost_user_net: true,
            nested_virt: true,
            virtio_console: true,
            restore_rotates_host_paths: true,
            disk_io_throttle: true,
            usb_host_passthrough,
        };
        let devices = [UsbHostDevice::new(0x1d6b, 0x0002)];

        // Incapable backend + a device => typed Unsupported naming the field.
        for vmm in ["cloud-hypervisor", "firecracker", "crosvm"] {
            let err = reject_usb_host_devices(vmm, &caps(false), &devices)
                .expect_err("an incapable backend must reject a host USB device");
            assert!(
                matches!(&err, crate::error::Error::Unsupported { vmm: got, feature }
                    if got == vmm && feature == "usb_host_passthrough"),
                "expected usb_host_passthrough Unsupported from {vmm}, got {err:?}"
            );
        }

        // QEMU-like (capable) + a device => Ok.
        reject_usb_host_devices("qemu", &caps(true), &devices)
            .expect("a capable backend must accept a host USB device");

        // The empty list is accepted on BOTH sides — the over-rejection inverse.
        reject_usb_host_devices("cloud-hypervisor", &caps(false), &[])
            .expect("no USB device requested must never be refused");
        reject_usb_host_devices("qemu", &caps(true), &[])
            .expect("no USB device requested must never be refused");
    }

    // docs/90 A3: the restore half of the same law, whose two arms answer two different
    // questions and must not collapse into one. (a) An incapable backend owes `restore()` the
    // IDENTICAL refusal its `create()` gives — same `vmm`, same `usb_host_passthrough` feature
    // string — because a restore that accepts what create rejects is the M4 defect; (b) a
    // CAPABLE backend (QEMU alone) still cannot re-attach a host device to a restored VM, so it
    // gets the `snapshot_restore` removal instead, with the config provenance naming the input
    // to drop; (c) the empty list is accepted on both sides, so wiring this into four
    // `restore()` paths cannot reject the 99% config.
    //
    // Red on the inverse: an arm-2-only predicate (dropping the delegation to
    // `reject_usb_host_devices`) reddens the incapable legs' identity assert; an arm-1-only
    // predicate — the trap of "just copy create's precheck", which is a NO-OP on the one backend
    // that actually splices USB into its argv — reddens the QEMU leg, which would return `Ok`.
    #[test]
    fn reject_usb_host_devices_on_restore_answers_incapable_and_capable_backends_differently() {
        use crate::config::UsbHostDevice;

        let caps = |usb_host_passthrough: bool| VmmCapabilities {
            snapshot_restore: true,
            lazy_restore: false,
            virtio_fs_shares: true,
            unprivileged_vhost_user_net: true,
            nested_virt: true,
            virtio_console: true,
            restore_rotates_host_paths: true,
            disk_io_throttle: true,
            usb_host_passthrough,
        };
        let devices = [UsbHostDevice::new(0x1d6b, 0x0002)];

        // (a) Incapable backend: byte-identical to what `create()` refuses with.
        for vmm in ["cloud-hypervisor", "firecracker", "crosvm"] {
            let on_create = reject_usb_host_devices(vmm, &caps(false), &devices)
                .expect_err("create refuses a host USB device on an incapable backend");
            let on_restore = reject_usb_host_devices_on_restore(vmm, &caps(false), &devices)
                .expect_err("restore must refuse exactly what create refuses");
            assert!(
                matches!(&on_restore, crate::error::Error::Unsupported { vmm: got, feature }
                    if got == vmm
                        && feature == crate::feature::Feature::UsbHostPassthrough.name()),
                "expected the create-side usb_host_passthrough Unsupported from {vmm}, got \
                 {on_restore:?}"
            );
            assert_eq!(on_create.to_string(), on_restore.to_string());
        }

        // (b) Capable backend: create accepts (asserted, so the leg is not vacuous), restore
        //     refuses with the restore-only arm — the SAME `Removal` the orchestrator's
        //     clone-eligibility boundary returns for this config, asserted by identity.
        reject_usb_host_devices("qemu", &caps(true), &devices)
            .expect("a capable backend accepts a host USB device on the COLD path");
        let err = reject_usb_host_devices_on_restore("qemu", &caps(true), &devices)
            .expect_err("no backend can re-attach a host USB device to a restored VM");
        assert!(
            matches!(&err, crate::error::Error::Unsupported { feature, .. }
                if feature == crate::feature::Feature::SnapshotRestore.name()),
            "the feature string must be Feature::name() by construction (F6), got {err:?}"
        );
        assert_eq!(
            err.to_string(),
            crate::error::Error::from_removal("qemu", &USB_PASSTHROUGH_BLOCKS_RESTORE).to_string(),
            "the capable-backend arm must be THIS removal — the one the orchestrator boundary \
             already returns for the same config: {err:?}"
        );

        // (c) The empty list is accepted on both sides — the over-rejection inverse.
        reject_usb_host_devices_on_restore("cloud-hypervisor", &caps(false), &[])
            .expect("no USB device requested must never be refused");
        reject_usb_host_devices_on_restore("qemu", &caps(true), &[])
            .expect("no USB device requested must never be refused");
    }

    /// The rustdoc block immediately above `anchor` (skipping any attributes between them), with
    /// the `///` markers stripped and whitespace normalized so a name split across a line break
    /// still matches. Panics if the anchor is missing or carries no doc — an extraction that
    /// silently returned nothing would make every roster assert below vacuous.
    fn doc_block_before(source: &str, anchor: &str) -> String {
        let before = source
            .split_once(anchor)
            .unwrap_or_else(|| panic!("`{anchor}` must exist in this file"))
            .0;
        let mut doc: Vec<&str> = Vec::new();
        for line in before.lines().rev() {
            let trimmed = line.trim_start();
            if let Some(rest) = trimmed.strip_prefix("///") {
                doc.push(rest);
                continue;
            }
            // Attributes and blank lines sit between the doc and its item; anything else ends the
            // block.
            if doc.is_empty() && (trimmed.is_empty() || trimmed.starts_with("#[")) {
                continue;
            }
            break;
        }
        assert!(!doc.is_empty(), "`{anchor}` must carry a rustdoc block");
        doc.reverse();
        crate::vmm::seccomp::roster::normalize_ws(&doc.join("\n"))
    }

    // GATE (docs/78 §9.4 `vmm-rustdoc-stale-backend-rosters`) — five rustdoc rosters in this module
    // had gone stale on crosvm (the `Vmm` trait, `PerVmResources`, `VmmCapabilities`,
    // `virtio_console`, and the two vsock-endpoint docs), each still describing three backends
    // while four ship. A roster is checkable, so it gets a gate: every doc block below must name
    // every backend `vmm_seccomp_args` dispatches — the authoritative roster, since a backend
    // cannot ship without an arm there (`crate::vmm::seccomp::roster`, which both doc gates share
    // rather than keeping a second copy). Two of the blocks enumerate the out-of-tree backend
    // *crates* instead of prose names, so they are checked against `vmcell-<id>` for every
    // non-primary backend.
    //
    // Red-on-inverse: delete `crosvm` from any one block (e.g. revert the `Vmm` trait doc to
    // "QEMU, Cloud Hypervisor, and Firecracker") and this reddens naming that block; add a fifth
    // `vmm_seccomp_args` arm and every block reddens until it is documented.
    #[test]
    fn backend_rosters_in_this_modules_rustdoc_name_every_shipping_backend() {
        use crate::vmm::seccomp::roster;

        const SOURCE: &str = include_str!("mod.rs");

        let ids = roster::dispatched_backend_ids();
        // The scan is self-checking: a silently-empty roster would make everything below vacuous.
        assert_eq!(
            ids.len(),
            roster::BACKEND_DISPLAY_NAMES.len(),
            "the seccomp dispatch scan found {ids:?} against roster {:?}",
            roster::BACKEND_DISPLAY_NAMES
        );

        // Rosters written as prose backend names.
        // The `//!` markers come off before normalizing, or a name the comment wrapped would read
        // as "Cloud //! Hypervisor" and never match.
        let module_doc = roster::normalize_ws(
            &SOURCE
                .lines()
                .map_while(|l| l.strip_prefix("//!"))
                .collect::<Vec<_>>()
                .join("\n"),
        );
        let prose_blocks: [(&str, String); 9] = [
            ("the module doc", module_doc),
            (
                "the `Vmm` trait",
                doc_block_before(SOURCE, "pub trait Vmm: Send + Sync {"),
            ),
            (
                "`VmmCapabilities::virtio_console`",
                doc_block_before(SOURCE, "    pub virtio_console: bool,"),
            ),
            (
                "`VmmCapabilities::restore_rotates_host_paths`",
                doc_block_before(SOURCE, "    pub restore_rotates_host_paths: bool,"),
            ),
            (
                "`VmmCapabilities::disk_io_throttle`",
                doc_block_before(SOURCE, "    pub disk_io_throttle: bool,"),
            ),
            (
                "`VmmCapabilities::usb_host_passthrough`",
                doc_block_before(SOURCE, "    pub usb_host_passthrough: bool,"),
            ),
            (
                "the `VsockEndpoint` enum",
                doc_block_before(SOURCE, "pub enum VsockEndpoint {"),
            ),
            (
                "`VmInstance::vsock_endpoint`",
                doc_block_before(SOURCE, "    fn vsock_endpoint(&self) -> VsockEndpoint {"),
            ),
            (
                "`VmInstance::verify_control_plane`",
                doc_block_before(SOURCE, "    async fn verify_control_plane("),
            ),
        ];
        for (what, doc) in &prose_blocks {
            for id in &ids {
                let display = roster::display_name(id);
                assert!(
                    doc.contains(display),
                    "{what} enumerates backends but never names {display} — a stale roster is how \
                     a reader learns the wrong shipping set"
                );
            }
        }

        // Rosters written as the out-of-tree backend crate names. Cloud Hypervisor is the primary,
        // in-tree backend and has no such crate, so it is derived out of this list rather than
        // hand-maintained.
        let crate_blocks: [(&str, String); 2] = [
            (
                "`PerVmResources`",
                doc_block_before(SOURCE, "pub struct PerVmResources {"),
            ),
            (
                "`VmmCapabilities`",
                doc_block_before(SOURCE, "pub struct VmmCapabilities {"),
            ),
        ];
        for (what, doc) in &crate_blocks {
            for id in ids.iter().filter(|id| *id != "cloud-hypervisor") {
                let krate = format!("vmcell-{id}");
                assert!(
                    doc.contains(&krate),
                    "{what} lists the out-of-tree backend crates but omits `{krate}`"
                );
            }
        }

        // The manifest's composition-root comment is a roster too (docs/78 §9.4
        // `cargo-toml-three-backends-comment`: it claimed bench-vm "drives all three backends"
        // while `VMM_BIN_RESOLVERS` wires four). No other test can reach a `Cargo.toml` comment, so
        // it rides here. Red-on-inverse: put "three" back and this reddens.
        const MANIFEST: &str = include_str!("../../Cargo.toml");
        let count_word = roster::COUNT_WORDS
            .get(ids.len())
            .expect("the backend roster is small enough to spell out");
        assert!(
            MANIFEST.contains(&format!("bench-vm drives all {count_word} backends")),
            "crates/vmcell/Cargo.toml must say bench-vm drives all {count_word} backends \
             ({} dispatch arms: {ids:?})",
            ids.len()
        );
        // …and names the crates it wires. Scoped to that comment's own lines — the manifest's
        // dev-dependencies name every backend crate anyway, so a whole-file `contains` would pass
        // vacuously.
        let comment: String = roster::normalize_ws(
            &MANIFEST
                .lines()
                .skip_while(|l| !l.contains("bench-vm drives all"))
                .take(3)
                .map(|l| l.trim_start_matches('#'))
                .collect::<Vec<_>>()
                .join("\n"),
        );
        for id in ids.iter().filter(|id| *id != "cloud-hypervisor") {
            let krate = format!("vmcell-{id}");
            assert!(
                comment.contains(&krate),
                "the manifest's composition-root comment omits `{krate}`: {comment}"
            );
        }
    }

    // GATE (docs/90 `m1`, the trap half) — the seam that produced M1 is a *pair* of items: the
    // `vsock_endpoint` trait default bakes `STEWARD_VSOCK_PORT`, and `verify_control_plane` is handed
    // no port and so dials that endpoint verbatim. Every re-keying consumer (`MicroVm::steward`,
    // `connect_sessions`) hid the mismatch, so the next backend to override the probe walks into it
    // again unless both docs *say* the baked port is not the declared one. `config`'s
    // `no_crate_bakes_the_steward_port_outside_the_justified_sites` pins the code side across the
    // workspace; this pins the warning that makes the pinned site legible.
    //
    // Needles are real identifiers, not prose, so a rename of the law reddens this rather than
    // quietly leaving a doc that names something gone. Red-on-inverse: drop any one needle from
    // either block (e.g. the `steward_port` mention from `vsock_endpoint`'s doc) and this fails
    // naming that block and that needle.
    #[test]
    fn both_halves_of_the_baked_port_seam_document_that_it_is_not_the_declared_port() {
        const SOURCE: &str = include_str!("mod.rs");

        // The port the default bakes, the declared-port law it is not, and — per item — the other
        // half of the seam, so neither doc can describe the hazard without pointing at its partner.
        let blocks: [(&str, String, [&str; 3]); 2] = [
            (
                "`VmInstance::vsock_endpoint`",
                doc_block_before(SOURCE, "    fn vsock_endpoint(&self) -> VsockEndpoint {"),
                ["STEWARD_VSOCK_PORT", "steward_port", "verify_control_plane"],
            ),
            (
                "`VmInstance::verify_control_plane`",
                doc_block_before(SOURCE, "    async fn verify_control_plane("),
                ["STEWARD_VSOCK_PORT", "steward_port", "vsock_endpoint"],
            ),
        ];
        for (what, doc, needles) in &blocks {
            for needle in needles {
                assert!(
                    doc.contains(needle),
                    "{what}'s rustdoc must name `{needle}`: the baked default port and the declared \
                     one are different facts, and a probe that dials the endpoint verbatim is how \
                     M1 destroyed and re-spawned healthy `Service` cells"
                );
            }
        }

        // Non-vacuity of the needles themselves: `steward_port` is a substring of nothing else here,
        // but `vsock_endpoint` would also match the *anchor* text if `doc_block_before` ever returned
        // the item line. It does not — assert the extraction is doc only.
        for (what, doc, _) in &blocks {
            assert!(
                !doc.contains("fn vsock_endpoint(&self)") && !doc.contains("async fn"),
                "{what}'s extracted block leaked its item signature, so the needles above could \
                 match code instead of prose"
            );
        }
    }

    #[test]
    fn test_cid_allocator() {
        let alloc = CidAllocator::new();
        let cid1 = alloc.allocate().unwrap();
        let cid2 = alloc.allocate().unwrap();
        assert!(cid1 >= 3);
        assert!(cid2 > cid1);
        alloc.release(cid1);
        let cid3 = alloc.allocate().unwrap();
        assert_eq!(cid1, cid3);
    }

    // `CidAllocator::reserve` pins a specific CID so a later `allocate` skips it
    // (used by the restore/zygote tests to force CID rotation to a distinct value).
    // RED on the inverse: a `reserve` that did not insert would let `allocate` hand
    // back the reserved CID, failing the `assert_ne`; a missing range check would
    // accept the out-of-range CID 2.
    #[test]
    fn test_cid_allocator_reserve() {
        let alloc = CidAllocator::new();
        assert_eq!(alloc.reserve(7).expect("reserve 7"), 7);
        // Re-reserving a held CID is an exhaustion error, not a silent success.
        assert!(matches!(
            alloc.reserve(7),
            Err(crate::error::Error::Exhaustion(_))
        ));
        // A subsequent allocate must NOT hand back the reserved CID.
        for _ in 0..5 {
            assert_ne!(
                alloc.allocate().expect("allocate"),
                7,
                "reserved CID leaked"
            );
        }
        // Releasing the reservation frees it for reuse.
        alloc.release(7);
        assert_eq!(alloc.reserve(7).expect("reserve after release"), 7);
        // Out-of-range CIDs (the ABI-reserved `0..=2` and anything past `MAX_GUEST_CID`) are
        // rejected. Both boundaries are read off the consts, so the range moving with
        // `net::MAX_VMID` cannot leave this leg asserting a stale refusal.
        assert!(matches!(
            alloc.reserve(MIN_GUEST_CID - 1),
            Err(crate::error::Error::Vmm(_))
        ));
        assert!(matches!(
            alloc.reserve(MAX_GUEST_CID + 1),
            Err(crate::error::Error::Vmm(_))
        ));
        // …and the boundaries themselves are ACCEPTED, so an over-strict range (one that shrank
        // the space by a notch at either end) reddens here rather than passing the negatives.
        // On a fresh allocator: `alloc` has already handed out the low CIDs above.
        let fresh = CidAllocator::new();
        assert_eq!(
            fresh.reserve(MIN_GUEST_CID).expect("the lowest guest CID"),
            MIN_GUEST_CID
        );
        assert_eq!(
            fresh.reserve(MAX_GUEST_CID).expect("the highest guest CID"),
            MAX_GUEST_CID
        );
    }

    // Guards VMM-7: a poisoned mutex must be recovered, not panicked on. The buggy
    // impl (`.lock().expect("mutex poisoned")`) aborts the test here.
    #[test]
    fn test_cid_allocator_recovers_from_poison() {
        let alloc = std::sync::Arc::new(CidAllocator::new());
        let poisoner = alloc.clone();
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = poisoner.active.lock().expect("fresh lock");
            panic!("poison the mutex while holding the guard");
        }));
        // The lock is now poisoned; both operations must still work.
        let cid = alloc.allocate().expect("allocate after poison");
        assert!(cid >= MIN_GUEST_CID);
        alloc.release(cid);
    }

    proptest! {
        // Guards VMM-6: the previous version allocated and discarded, asserting
        // nothing. This asserts the allocator's contract so a broken allocator
        // (handing out reserved/duplicate/out-of-range CIDs, or failing the
        // release round-trip) goes red.
        #[test]
        fn test_cid_allocator_prop(n in 0usize..260) {
            let alloc = CidAllocator::new();
            let mut allocated: Vec<u32> = Vec::new();
            for _ in 0..n {
                match alloc.allocate() {
                    Ok(cid) => {
                        // The ABI-reserved 0/1/2 are never handed out, and nothing above the
                        // derived ceiling is either.
                        prop_assert!(cid >= MIN_GUEST_CID, "cid {} is in the reserved range", cid);
                        prop_assert!(cid <= MAX_GUEST_CID, "cid {} exceeds the ceiling", cid);
                        // Uniqueness: a live CID is never handed out twice.
                        prop_assert!(!allocated.contains(&cid), "duplicate cid {}", cid);
                        allocated.push(cid);
                    }
                    Err(e) => {
                        // `n` is far below the space's width, so refusing here is never
                        // exhaustion — it is an allocator that gave up early. Exhaustion itself is
                        // proved by the two tests that actually fill the pool
                        // (`cid_allocator_reuses_freed_and_wraps_without_colliding_with_live` in
                        // tests/proptests.rs, and home 4 of net's ceiling roster); driving it from
                        // here would cost ~10^4 allocations per proptest case.
                        prop_assert!(
                            false,
                            "the allocator refused CID #{} of a {}-wide space with {} live: {:?}",
                            allocated.len() + 1,
                            MAX_GUEST_CID - MIN_GUEST_CID + 1,
                            allocated.len(),
                            e
                        );
                    }
                }
            }
            // release + re-allocate round-trips: a freed CID is handed back.
            if let Some(&first) = allocated.first() {
                alloc.release(first);
                let reused = alloc.allocate().expect("re-allocate after release");
                prop_assert_eq!(reused, first);
            }
        }
    }

    // Design §13 (Cross-cutting invariants): the per-VM scratch dir — and every per-VM socket/serial
    // path derived from it — must be INJECTIVE in (pid, vmid). These are the
    // DETERMINISTIC regression cases for the two documented buggy inverses, which a
    // random proptest almost never stumbles on (concatenation collisions are sparse
    // over the full input space — a coincidental-pass trap). Both go red reliably:
    //   * PID-only path (drops vmid): (5,1) and (5,2) would collapse to one dir.
    //   * delimiter-drop `vmcell-vm-{pid}-{vmid}`: (1,23) and (12,3) both -> "…-123".
    #[test]
    fn test_per_vm_path_delimiter_and_vmid_are_load_bearing() {
        let base = Path::new("/tmp");
        for leaf in ["api.sock", "vsock.sock", "serial.log"] {
            // vmid must participate (guards a PID-only regression).
            assert_ne!(
                per_vm_scratch_dir("vmcell", base, 5, 1).join(leaf),
                per_vm_scratch_dir("vmcell", base, 5, 2).join(leaf),
                "{leaf}: distinct vmids under one pid must not collide"
            );
            // The delimiter must participate (guards a `{pid}{vmid}` regression).
            assert_ne!(
                per_vm_scratch_dir("vmcell", base, 1, 23).join(leaf),
                per_vm_scratch_dir("vmcell", base, 12, 3).join(leaf),
                "{leaf}: (1,23) and (12,3) must not collide"
            );
        }
    }

    proptest! {
        // The general property: any two distinct (pid, vmid) pairs yield distinct
        // api.sock/vsock.sock/serial.log paths.
        #[test]
        fn test_per_vm_paths_injective_in_pid_vmid(
            pid1 in 0u32..100_000, vmid1 in 0u32..=crate::net::MAX_VMID,
            pid2 in 0u32..100_000, vmid2 in 0u32..=crate::net::MAX_VMID,
        ) {
            prop_assume!((pid1, vmid1) != (pid2, vmid2));
            let base = Path::new("/tmp");
            let d1 = per_vm_scratch_dir("vmcell", base, pid1, vmid1);
            let d2 = per_vm_scratch_dir("vmcell", base, pid2, vmid2);
            for leaf in ["api.sock", "vsock.sock", "serial.log"] {
                prop_assert_ne!(
                    d1.join(leaf),
                    d2.join(leaf),
                    "path {} collided for ({},{}) vs ({},{})",
                    leaf, pid1, vmid1, pid2, vmid2
                );
            }
        }
    }
}
