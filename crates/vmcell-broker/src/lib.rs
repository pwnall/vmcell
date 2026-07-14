//! vmcell setup broker — the privilege boundary for the daemon/API mode (design §12.4, Layer 3 —
//! the setup broker (network surface never holds caps); invariant §13, Cross-cutting
//! invariants).
//!
//! `setns(CLONE_NEWNET)` needs `CAP_SYS_ADMIN` in the netns's owning user namespace, so an
//! unprivileged process can **never** join a broker-created netns. This forces the **spawner
//! model**: a minimal, no-network privileged **broker** child holds the three caps
//! (`CAP_NET_ADMIN`+`CAP_SYS_ADMIN`+`CAP_DAC_OVERRIDE`), performs netns/tap/nft/cgroup setup +
//! the jailed VMM spawn, and answers a fixed, audited request menu over a framed Unix-socket
//! pair; the **parent** ([`vmcell_privilege::apply_broker_parent_drop`]) drops **all** caps and
//! serves the HTTP API — so a bug in the request parser can no longer reach the caps.
//!
//! The broker reuses `vmcell`'s audited netns/nft/cgroup/sweep code through the injected seams
//! ([`BrokerBackend`]), so its dispatch logic is unit-tested against recording fakes with **no
//! root** (the same discipline the orchestrator uses). It links `vmcell` (net/metrics subset)
//! but NOT `vmcell-daemon` / any web stack — the caps and the network surface stay in separate
//! processes.
//!
//! **Ships now (gated in `just ci`):** the framed protocol + codec (round-trip + over-cap
//! reject), the setup/teardown/cgroup/sweep dispatch (fake-tested), the parent cap-drop plan
//! ([`vmcell_privilege::plan_broker_parent_drop`]), and the fork transport ([`spawn_broker`]).
//! **Forward work (KVM-host-validated, §17, Open gaps and future capabilities):**
//! [`BrokerRequest::SpawnVmm`]'s live
//! fork→`setns`→jail→`execve`→pidfd path, and the `vmcelld` cutover from the retain-caps model
//! (§13, Cross-cutting invariants) to fork-broker-then-drop.

#![deny(missing_docs, unsafe_op_in_unsafe_fn, rustdoc::broken_intra_doc_links)]
#![deny(unreachable_pub)]
#![deny(
    clippy::undocumented_unsafe_blocks,
    clippy::missing_safety_doc,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::multiple_unsafe_ops_per_block
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
        clippy::allow_attributes,
        clippy::allow_attributes_without_reason
    )
)]

use serde::{Serialize, de::DeserializeOwned};
use std::collections::{BTreeSet, HashMap};
use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use vmcell::config::{IoMax, ResourceLimits};
use vmcell::metrics::{CgroupFs, DefaultCgroupFs};
use vmcell::net::tap::{DefaultNftApplier, NetNamespace, Netlink, NftApplier, RtNetlink};
use vmcell::orchestrator::{HostOrphanScanner, OrphanScanner, sweep_orphans};

pub use vmcell_privilege::{
    BrokerParentDropPlan, apply_broker_parent_drop, plan_broker_parent_drop,
};

/// The maximum size of a single framed broker message. Broker messages are tiny; this generous
/// cap is the [`MAX_FRAME_BYTES`](vmcell)-style boundary the receiver enforces **before**
/// allocating, so a corrupt or hostile length prefix cannot drive an unbounded allocation.
pub const MAX_BROKER_FRAME_BYTES: usize = 1 << 20; // 1 MiB

// ---------------------------------------------------------------------------------------------
// Wire protocol
// ---------------------------------------------------------------------------------------------

/// Serializable mirror of [`ResourceLimits`] (which is not itself `serde`), so cgroup limits can
/// cross the broker IPC. Converted at the boundary via [`BrokerLimits::into_resource_limits`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, serde::Deserialize, Default)]
pub struct BrokerLimits {
    /// `memory.max`, in MiB.
    pub mem_max_mib: Option<u32>,
    /// `cpu.max` percentage.
    pub cpu_max_pct: Option<u32>,
    /// `pids.max`.
    pub pids_max: Option<u32>,
    /// `io.max` (device + per-direction bandwidth/IOPS caps).
    pub io_max: Option<BrokerIoMax>,
}

/// Serializable mirror of [`IoMax`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, serde::Deserialize)]
pub struct BrokerIoMax {
    /// Device node string, e.g. `"8:0"`.
    pub device: String,
    /// Read bandwidth max, bytes/sec.
    pub rbps: Option<u64>,
    /// Write bandwidth max, bytes/sec.
    pub wbps: Option<u64>,
    /// Read IOPS max.
    pub riops: Option<u64>,
    /// Write IOPS max.
    pub wiops: Option<u64>,
}

impl BrokerLimits {
    /// Converts the wire form into a `vmcell` [`ResourceLimits`].
    ///
    /// Built via `Default` + field assignment because `ResourceLimits`/`IoMax` are
    /// `#[non_exhaustive]` (a struct literal is not constructible from outside `vmcell`).
    #[must_use]
    pub fn into_resource_limits(self) -> ResourceLimits {
        let mut rl = ResourceLimits::default();
        rl.mem_max_mib = self.mem_max_mib;
        rl.cpu_max_pct = self.cpu_max_pct;
        rl.pids_max = self.pids_max;
        rl.io_max = self.io_max.map(|io| {
            let mut m = IoMax::default();
            m.device = io.device;
            m.rbps = io.rbps;
            m.wbps = io.wbps;
            m.riops = io.riops;
            m.wiops = io.wiops;
            m
        });
        rl
    }

    /// Builds the wire form from a `vmcell` [`ResourceLimits`].
    #[must_use]
    pub fn from_resource_limits(rl: &ResourceLimits) -> Self {
        Self {
            mem_max_mib: rl.mem_max_mib,
            cpu_max_pct: rl.cpu_max_pct,
            pids_max: rl.pids_max,
            io_max: rl.io_max.as_ref().map(|io| BrokerIoMax {
                device: io.device.clone(),
                rbps: io.rbps,
                wbps: io.wbps,
                riops: io.riops,
                wiops: io.wiops,
            }),
        }
    }
}

/// The fixed, audited menu of privileged operations the broker performs. Every variant's fields
/// are validated at the boundary before any side effect — that validation is the broker's whole
/// security value (§13, Cross-cutting invariants).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, serde::Deserialize)]
pub enum BrokerRequest {
    /// Liveness check — no side effect, no caps needed.
    Health,
    /// Create the per-VM netns + tap (and, when `proxy_port` is set, the nft TPROXY ruleset).
    SetupNetwork {
        /// The VM's internal id (drives the `/30` + names).
        vmid: u32,
        /// The resource prefix for the netns/tap names.
        prefix: String,
        /// When set, emit the egress-proxy nft ruleset pointing at this host proxy port.
        proxy_port: Option<u16>,
    },
    /// Create the per-VM cgroup v2 slice with the given limits.
    CreateCgroup {
        /// The VM's internal id.
        vmid: u32,
        /// The resource prefix for the slice name.
        prefix: String,
        /// The limits to write.
        limits: BrokerLimits,
    },
    /// Spawn the jailed VMM into `netns`/`cgroup` (fork→setns→jail→execve→pidfd). The live path
    /// is the KVM-host-validated forward step (§17, Open gaps and future capabilities); today
    /// the handler refuses fail-loud.
    SpawnVmm {
        /// The VM's internal id.
        vmid: u32,
        /// The VMM argv (the parent computes it; the broker only performs the privileged spawn).
        argv: Vec<String>,
        /// The netns name to `setns` into.
        netns: String,
        /// The cgroup slice name to place the child in.
        cgroup: String,
    },
    /// Tear down the per-VM netns + cgroup (reverse of setup), asserting residue-gone.
    Teardown {
        /// The VM's internal id.
        vmid: u32,
        /// The resource prefix.
        prefix: String,
    },
    /// Reclaim leaked netns/cgroup/scratch for `prefix`, sparing every id in `live_vmids` (the
    /// start-up orphan sweep, §11.4, The VM registry and the start-up sweep).
    Sweep {
        /// The resource prefix whose leaks to reclaim.
        prefix: String,
        /// The live ids to spare (never swept).
        live_vmids: Vec<u32>,
    },
    /// Graceful shutdown of the broker serve loop.
    Shutdown,
}

/// The broker's reply to a [`BrokerRequest`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, serde::Deserialize)]
pub enum BrokerReply {
    /// Success with no payload (`Health`, `Teardown`, `Shutdown`).
    Done,
    /// A netns was set up.
    NetworkReady {
        /// The tap interface name.
        tap: String,
        /// The netns name.
        netns: String,
        /// The host-side gateway IP (`10.200.<n>.1`).
        host_ip: String,
    },
    /// A cgroup slice was created.
    CgroupReady {
        /// The slice name.
        name: String,
    },
    /// A sweep completed; the reclaimed resource names/paths.
    SweepDone {
        /// Reclaimed netns names.
        netns: Vec<String>,
        /// Reclaimed cgroup slice names.
        cgroup_slices: Vec<String>,
        /// Reclaimed scratch-dir paths (as strings).
        scratch_dirs: Vec<String>,
    },
    /// A typed error string; the parent maps it to a daemon error.
    Error(String),
}

// ---------------------------------------------------------------------------------------------
// Framed codec — length-prefixed postcard, over-cap rejected before allocation
// ---------------------------------------------------------------------------------------------

/// Writes a length-prefixed frame (`u32` big-endian length + payload), rejecting an over-cap
/// payload before writing.
///
/// # Errors
/// [`io::ErrorKind::InvalidData`] if `payload` exceeds [`MAX_BROKER_FRAME_BYTES`]; the underlying
/// I/O error on a failed write.
pub fn write_frame(w: &mut impl Write, payload: &[u8]) -> io::Result<()> {
    let len = u32::try_from(payload.len())
        .ok()
        .filter(|_| payload.len() <= MAX_BROKER_FRAME_BYTES);
    let Some(len) = len else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "broker frame {} exceeds cap {MAX_BROKER_FRAME_BYTES}",
                payload.len()
            ),
        ));
    };
    w.write_all(&len.to_be_bytes())?;
    w.write_all(payload)?;
    w.flush()
}

/// Reads a length-prefixed frame, rejecting an over-cap length **before** allocating the buffer.
///
/// # Errors
/// [`io::ErrorKind::InvalidData`] if the length prefix exceeds [`MAX_BROKER_FRAME_BYTES`]; the
/// underlying I/O error (including [`io::ErrorKind::UnexpectedEof`] on a closed peer).
pub fn read_frame(r: &mut impl Read) -> io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_BROKER_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "broker frame length {len} exceeds cap {MAX_BROKER_FRAME_BYTES} (rejected before allocation)"
            ),
        ));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

/// Serializes `msg` with postcard and writes it as one frame.
///
/// # Errors
/// [`io::ErrorKind::InvalidData`] on a serialization failure; the underlying write error.
pub fn send_msg<T: Serialize>(w: &mut impl Write, msg: &T) -> io::Result<()> {
    let bytes =
        postcard::to_allocvec(msg).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    write_frame(w, &bytes)
}

/// Reads one frame and deserializes it with postcard.
///
/// # Errors
/// The read error, or [`io::ErrorKind::InvalidData`] on a deserialization failure.
pub fn recv_msg<T: DeserializeOwned>(r: &mut impl Read) -> io::Result<T> {
    let bytes = read_frame(r)?;
    postcard::from_bytes(&bytes).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

// ---------------------------------------------------------------------------------------------
// Backend seam — the audited `vmcell` primitives, injectable for root-free tests
// ---------------------------------------------------------------------------------------------

/// The privileged primitives the broker performs, injected so the dispatch logic is unit-testable
/// against recording fakes with no root (the orchestrator's "injectable side-effect trait with a
/// real impl and a recording fake" discipline, design §9.8, Testability seams).
pub trait BrokerBackend: Send {
    /// A fresh netlink handle for a netns create/sweep (each `NetNamespace` owns its own).
    fn new_netlink(&self) -> Box<dyn Netlink>;
    /// The nft applier for the egress-proxy ruleset.
    fn nft(&self) -> &dyn NftApplier;
    /// The cgroup backend.
    fn cgroups(&self) -> &dyn CgroupFs;
    /// A host orphan scanner for `prefix`.
    fn new_scanner(&self, prefix: &str) -> Box<dyn OrphanScanner>;
}

/// The real backend: `RtNetlink` + `DefaultNftApplier` + `DefaultCgroupFs` + `HostOrphanScanner`.
pub struct RealBrokerBackend {
    nft: DefaultNftApplier,
    cgroups: DefaultCgroupFs,
}

impl Default for RealBrokerBackend {
    fn default() -> Self {
        Self {
            nft: DefaultNftApplier,
            cgroups: DefaultCgroupFs,
        }
    }
}

impl BrokerBackend for RealBrokerBackend {
    fn new_netlink(&self) -> Box<dyn Netlink> {
        Box::new(RtNetlink)
    }
    fn nft(&self) -> &dyn NftApplier {
        &self.nft
    }
    fn cgroups(&self) -> &dyn CgroupFs {
        &self.cgroups
    }
    fn new_scanner(&self, prefix: &str) -> Box<dyn OrphanScanner> {
        Box::new(HostOrphanScanner::new(prefix))
    }
}

// ---------------------------------------------------------------------------------------------
// Server + dispatch
// ---------------------------------------------------------------------------------------------

/// The broker's request handler. Holds the injected [`BrokerBackend`] and owns the per-VM netns
/// handles it created (so `Teardown` can `delete()` them).
pub struct BrokerServer<B: BrokerBackend> {
    backend: B,
    netns_by_vmid: HashMap<u32, NetNamespace>,
}

impl<B: BrokerBackend> BrokerServer<B> {
    /// Builds a server over `backend`.
    pub fn new(backend: B) -> Self {
        Self {
            backend,
            netns_by_vmid: HashMap::new(),
        }
    }

    /// Handles one request, performing its privileged side effect and returning the reply. Never
    /// panics on a backend error — it maps to [`BrokerReply::Error`] (the parent surfaces it).
    pub fn dispatch(&mut self, req: BrokerRequest) -> BrokerReply {
        match req {
            BrokerRequest::Health | BrokerRequest::Shutdown => BrokerReply::Done,
            BrokerRequest::SetupNetwork {
                vmid,
                prefix,
                proxy_port,
            } => match NetNamespace::create(&prefix, vmid, self.backend.new_netlink()) {
                Ok(ns) => {
                    // Fail loud: an out-of-range vmid makes host_ip() (via ip_math) error; do not
                    // mask it into an empty gateway. `ns` is dropped on this return, so its Drop
                    // reclaims the just-created netns (no residue).
                    let host_ip = match ns.host_ip() {
                        Ok(ip) => ip,
                        Err(e) => return BrokerReply::Error(format!("host ip: {e}")),
                    };
                    if let Some(port) = proxy_port
                        && let Err(e) = ns.emit_proxy_rules(port, self.backend.nft())
                    {
                        return BrokerReply::Error(format!("emit nft ruleset: {e}"));
                    }
                    let reply = BrokerReply::NetworkReady {
                        tap: ns.tap_name.clone(),
                        netns: ns.name.clone(),
                        host_ip,
                    };
                    self.netns_by_vmid.insert(vmid, ns);
                    reply
                }
                Err(e) => BrokerReply::Error(format!("setup netns: {e}")),
            },
            BrokerRequest::CreateCgroup {
                vmid,
                prefix,
                limits,
            } => {
                let name = vmcell::naming::cgroup_slice_name(&prefix, vmid);
                match self
                    .backend
                    .cgroups()
                    .create_slice(&name, &limits.into_resource_limits())
                {
                    Ok(()) => BrokerReply::CgroupReady { name },
                    Err(e) => BrokerReply::Error(format!("create cgroup slice: {e}")),
                }
            }
            BrokerRequest::SpawnVmm { .. } => BrokerReply::Error(
                "the jailed-VMM spawner (fork→setns→jail→execve→pidfd) is the KVM-host-validated \
                 forward step — design §17 (Open gaps and future capabilities)"
                    .to_string(),
            ),
            BrokerRequest::Teardown { vmid, prefix } => {
                let mut errs = Vec::new();
                if let Some(mut ns) = self.netns_by_vmid.remove(&vmid)
                    && let Err(e) = ns.delete()
                {
                    errs.push(format!("delete netns: {e}"));
                }
                let name = vmcell::naming::cgroup_slice_name(&prefix, vmid);
                if let Err(e) = self.backend.cgroups().delete_slice(&name) {
                    errs.push(format!("delete cgroup slice: {e}"));
                }
                if errs.is_empty() {
                    BrokerReply::Done
                } else {
                    BrokerReply::Error(errs.join("; "))
                }
            }
            BrokerRequest::Sweep { prefix, live_vmids } => {
                let scanner = self.backend.new_scanner(&prefix);
                let netlink = self.backend.new_netlink();
                let live: BTreeSet<u32> = live_vmids.into_iter().collect();
                let report = sweep_orphans(
                    scanner.as_ref(),
                    netlink.as_ref(),
                    self.backend.cgroups(),
                    &live,
                );
                BrokerReply::SweepDone {
                    netns: report.netns,
                    cgroup_slices: report.cgroup_slices,
                    scratch_dirs: report
                        .scratch_dirs
                        .iter()
                        .map(|p| p.display().to_string())
                        .collect(),
                }
            }
        }
    }
}

/// Serves the broker protocol on `sock` until a [`BrokerRequest::Shutdown`] (replying `Done`) or
/// the peer closes the connection (EOF).
///
/// # Errors
/// A framing / I/O error other than a clean peer EOF (which returns `Ok(())`).
pub fn serve<B: BrokerBackend>(
    server: &mut BrokerServer<B>,
    mut sock: UnixStream,
) -> io::Result<()> {
    loop {
        let req: BrokerRequest = match recv_msg(&mut sock) {
            Ok(r) => r,
            // A closed peer is a clean end of service, not an error.
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e),
        };
        let shutdown = matches!(req, BrokerRequest::Shutdown);
        let reply = server.dispatch(req);
        send_msg(&mut sock, &reply)?;
        if shutdown {
            return Ok(());
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Client + fork transport
// ---------------------------------------------------------------------------------------------

/// The parent-side handle to a running broker: a framed request/reply channel over the socket
/// pair. Blocking (the parent calls it from a `spawn_blocking` context when wired, §17, Open
/// gaps and future capabilities).
#[derive(Debug)]
pub struct BrokerClient {
    sock: UnixStream,
}

impl BrokerClient {
    /// Wraps an already-connected socket end (e.g. one half of [`UnixStream::pair`]).
    #[must_use]
    pub fn new(sock: UnixStream) -> Self {
        Self { sock }
    }

    /// Sends `req` and reads the reply.
    ///
    /// # Errors
    /// A framing / I/O error on either leg.
    pub fn request(&mut self, req: &BrokerRequest) -> io::Result<BrokerReply> {
        send_msg(&mut self.sock, req)?;
        recv_msg(&mut self.sock)
    }

    /// Asks the broker to shut down gracefully.
    ///
    /// # Errors
    /// A framing / I/O error.
    pub fn shutdown(&mut self) -> io::Result<BrokerReply> {
        self.request(&BrokerRequest::Shutdown)
    }
}

/// A handle to the forked broker child. On drop it force-kills and reaps the child, so a dropped
/// handle never leaks the privileged broker (teardown-is-ownership).
#[derive(Debug)]
pub struct BrokerChild {
    pid: libc::pid_t,
    reaped: bool,
}

impl BrokerChild {
    /// The broker child's pid.
    #[must_use]
    pub fn pid(&self) -> libc::pid_t {
        self.pid
    }

    /// Waits for the broker child to exit (call after [`BrokerClient::shutdown`]), returning its
    /// exit code if it exited normally (`None` if killed by a signal or already reaped). Retries on
    /// `EINTR` so a signal-interrupted wait never latches a still-live child as reaped (zombie).
    pub fn reap(&mut self) -> Option<i32> {
        if self.reaped {
            return None;
        }
        loop {
            let mut status: libc::c_int = 0;
            // SAFETY: waitpid on our own child pid with a valid status out-pointer.
            let rc = unsafe { libc::waitpid(self.pid, &mut status, 0) };
            if rc > 0 {
                self.reaped = true;
                // `WIFEXITED`/`WEXITSTATUS` are safe const accessors over the status
                // word `waitpid` just wrote; no `unsafe` needed.
                let exited = libc::WIFEXITED(status);
                let code = libc::WEXITSTATUS(status);
                return if exited { Some(code) } else { None };
            }
            // Retry only a signal-interrupted wait; any other error (ECHILD/EINVAL) is terminal.
            if io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
                self.reaped = true;
                return None;
            }
        }
    }
}

impl Drop for BrokerChild {
    fn drop(&mut self) {
        if self.reaped {
            return;
        }
        // SAFETY: SIGKILL to our own child pid; harmless if it already exited.
        unsafe { libc::kill(self.pid, libc::SIGKILL) };
        self.reap();
    }
}

/// Which side of a [`fork_privileged_child`] the caller is now running on.
#[derive(Debug)]
pub enum ForkSide {
    /// The original (parent) process: keep serving, holding the child handle for reap-on-drop.
    Parent {
        /// The parent's end of the control socket.
        sock: UnixStream,
        /// The forked child, reaped on drop.
        child: BrokerChild,
    },
    /// The forked (child) process: it has `PR_SET_PDEATHSIG=SIGKILL` set and holds the child's end
    /// of the control socket. The child must do its work and terminate with `_exit` (never return
    /// through the parent's stack).
    Child {
        /// The child's end of the control socket.
        sock: UnixStream,
    },
}

/// The generic privilege-separation fork: makes a `socketpair`, `fork`s, and returns which
/// [`ForkSide`] the caller is on. The child gets `PR_SET_PDEATHSIG=SIGKILL` (dies with the parent).
/// The caller decides what each side does — the thin [`spawn_broker_with`] serves a [`BrokerServer`]
/// in the child; the daemon (`vmcell-daemon`) runs its own async registry-serve in the child and
/// drops caps + serves HTTP in the parent (the §12.4, Layer 3 — the setup broker (network
/// surface never holds caps) / §13, Cross-cutting invariants cutover).
///
/// MUST be called **before** the caller spawns any thread / async runtime (fork-with-threads is
/// unsafe): after the fork, the child inherits only the calling thread, so any code that could block
/// on a lock held by another thread would deadlock (§12.4, Layer 3 — the setup broker (network
/// surface never holds caps)). This is a **caller obligation** the signature cannot enforce; the
/// broker's fork tests run under a multi-threaded harness but stay safe only because the child
/// touches solely its own fake state and `_exit`s without ever acquiring a parent-held lock — do
/// not extend the child's work with anything that could contend an inherited lock.
///
/// The caller drops its own capabilities on the [`ForkSide::Parent`] branch
/// ([`apply_broker_parent_drop`]); this function does not, so a test can fork without mutating the
/// test process's caps.
///
/// # Errors
/// The `socketpair`/`fork` I/O error.
pub fn fork_privileged_child() -> io::Result<ForkSide> {
    let (parent_sock, child_sock) = UnixStream::pair()?;
    // SAFETY: `fork(2)`; both branches below are the standard post-fork split — the child closes the
    // parent's socket end and sets pdeathsig, the parent closes the child's end. Called before any
    // thread/runtime exists (§12.4, Layer 3 — the setup broker (network surface never holds
    // caps)), so no inherited-lock hazard.
    match unsafe { libc::fork() } {
        -1 => Err(io::Error::last_os_error()),
        0 => {
            drop(parent_sock);
            // SAFETY: `prctl(PR_SET_PDEATHSIG, SIGKILL)` — no pointer args; the broker dies if the
            // parent does (AGENTS.md helper-daemon rule).
            unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) };
            Ok(ForkSide::Child { sock: child_sock })
        }
        pid => {
            drop(child_sock);
            Ok(ForkSide::Parent {
                sock: parent_sock,
                child: BrokerChild { pid, reaped: false },
            })
        }
    }
}

/// Forks a broker child serving [`RealBrokerBackend`], returning the parent's [`BrokerClient`] and
/// the child handle. **The caller must then drop its capabilities** ([`apply_broker_parent_drop`]).
///
/// # Errors
/// The `socketpair`/`fork` I/O error.
pub fn spawn_broker() -> io::Result<(BrokerClient, BrokerChild)> {
    spawn_broker_with(RealBrokerBackend::default())
}

/// Like [`spawn_broker`] but with an injected backend — the seam the fork-transport test uses to
/// serve a recording fake with no root.
///
/// # Errors
/// The `socketpair`/`fork` I/O error.
pub fn spawn_broker_with<B: BrokerBackend + 'static>(
    backend: B,
) -> io::Result<(BrokerClient, BrokerChild)> {
    match fork_privileged_child()? {
        ForkSide::Child { sock } => {
            let mut server = BrokerServer::new(backend);
            // Fail loud: a framing/dispatch fault in the serve loop must not exit 0 (which the
            // parent would read as a clean shutdown). Surface it as a non-zero exit — the only
            // fail-loud channel a forked child has (no stderr/tracing here).
            let code = if serve(&mut server, sock).is_ok() {
                0
            } else {
                1
            };
            // SAFETY: `_exit` is async-signal-safe and skips at-exit handlers — correct for a forked
            // child that must not run the parent's teardown.
            unsafe { libc::_exit(code) };
        }
        ForkSide::Parent { sock, child } => Ok((BrokerClient::new(sock), child)),
    }
}

#[cfg(test)]
mod tests;
