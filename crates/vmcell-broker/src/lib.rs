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
    /// Reclaim leaked netns/segment-netns/cgroup/scratch for `prefix`, sparing every id in
    /// `live_vmids` / `live_segids` (the start-up orphan sweep, §11.4, The VM registry and the
    /// start-up sweep).
    Sweep {
        /// The resource prefix whose leaks to reclaim.
        prefix: String,
        /// The live **vmids** to spare (never swept): the `-net-`/`-vm-` classes.
        live_vmids: Vec<u32>,
        /// The live **segids** to spare (never swept): the `-seg-` class (§6.5). Its own id
        /// space — checking it against `live_vmids` fails open. A plain `Vec<u32>` with no serde
        /// presence attribute, so the postcard channel round-trips it faithfully (Appendix A
        /// reversal 10 does not apply); parent and broker child still ship together.
        live_segids: Vec<u32>,
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
        /// Reclaimed per-VM netns names.
        netns: Vec<String>,
        /// Reclaimed segment netns names (§6.5).
        segment_netns: Vec<String>,
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
                // `vm_slice_name`, NOT the bare `cgroup_slice_name` leaf: the name every
                // `CgroupFs` verb takes is relative to the cgroup-v2 mount root
                // (`create_slice_at` joins `/sys/fs/cgroup/{name}`; the orphan sweep's scanner
                // likewise reports root-relative paths), so the leaf alone names a slice at the
                // ROOT of the hierarchy while the orchestrator places the VM at
                // `{§13 sibling base}/{leaf}` — a different directory on every systemd host, and
                // therefore a slice created here that no VMM is ever added to plus an orchestrator
                // slice this teardown never deletes. It is the same law on both sides because the
                // base is read from `/proc/self/cgroup` and this process is a plain `fork(2)` of
                // the supervisor (`fork_privileged_child`) that never moves between cgroups, so it
                // reads the supervisor's own line. One law, one predicate — pinned by
                // `cgroup_placement_gate` below.
                let name = vmcell::naming::vm_slice_name(&prefix, vmid);
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
                // The same placement law `CreateCgroup` used above (see its comment): a teardown
                // naming the bare leaf would delete a slice at the hierarchy root and leak the
                // one the create actually made.
                let name = vmcell::naming::vm_slice_name(&prefix, vmid);
                if let Err(e) = self.backend.cgroups().delete_slice(&name) {
                    errs.push(format!("delete cgroup slice: {e}"));
                }
                if errs.is_empty() {
                    BrokerReply::Done
                } else {
                    BrokerReply::Error(errs.join("; "))
                }
            }
            BrokerRequest::Sweep {
                prefix,
                live_vmids,
                live_segids,
            } => {
                let scanner = self.backend.new_scanner(&prefix);
                let netlink = self.backend.new_netlink();
                let live: BTreeSet<u32> = live_vmids.into_iter().collect();
                let live_segs: BTreeSet<u32> = live_segids.into_iter().collect();
                let report = sweep_orphans(
                    scanner.as_ref(),
                    netlink.as_ref(),
                    self.backend.cgroups(),
                    &live,
                    &live_segs,
                );
                BrokerReply::SweepDone {
                    netns: report.netns,
                    segment_netns: report.segment_netns,
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

/// Call-site gate for the cgroup **placement** law (§13 sibling placement).
///
/// The claim is about the two `dispatch` arms above, not about a helper, so — like
/// `vmcell-qemu`'s `virtiofs_pacing_gate` — it reads this file's own production text and pins
/// what those call sites name. A behavioral assertion over a recording `CgroupFs` sees the
/// *name the broker chose*; it cannot see a future third site that reaches for the leaf again,
/// which is exactly how the two copies diverged in the first place.
#[cfg(test)]
mod cgroup_placement_gate {
    const SOURCE: &str = include_str!("lib.rs");

    /// The cgroup-slice names this broker composes: one in `CreateCgroup`, one in `Teardown`.
    ///
    /// Asserted exactly, so a scan that silently matched nothing — how every source-scanning
    /// gate fails vacuously — reddens instead of passing over an empty set.
    const EXPECTED_CALL_SITES: usize = 2;

    /// This file's production text: everything before the first `#[cfg(test)]`, comment lines
    /// dropped and whitespace collapsed (so a call split across rustfmt lines is still seen
    /// whole, and prose naming the rejected spelling is not a call site).
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

    /// Every cgroup-slice-name composition in `code`, truncated at its statement's `;`.
    fn slice_name_calls(code: &str) -> Vec<&str> {
        code.match_indices("slice_name(")
            .map(|(at, _)| {
                let start = code[..at]
                    .rfind(|c: char| !(c.is_alphanumeric() || c == '_' || c == ':'))
                    .map_or(0, |i| i + 1);
                let tail = &code[start..];
                &tail[..tail.find(';').unwrap_or(tail.len())]
            })
            .collect()
    }

    /// The law: the broker names the slice the ORCHESTRATOR places the VM in — leaf **plus**
    /// §13 sibling base — never the bare leaf, which names a slice at the cgroup-hierarchy root.
    fn call_uses_the_placement_law(call: &str) -> bool {
        call.starts_with("vmcell::naming::vm_slice_name(")
    }

    #[test]
    fn every_broker_cgroup_name_is_the_orchestrators_placement() {
        let code = production_code(SOURCE);
        let calls = slice_name_calls(&code);
        assert_eq!(
            calls.len(),
            EXPECTED_CALL_SITES,
            "expected {EXPECTED_CALL_SITES} cgroup-slice names (CreateCgroup, Teardown); found \
             {}: {calls:?}. If a site was legitimately added or removed, update \
             EXPECTED_CALL_SITES — do not delete the scan.",
            calls.len()
        );
        for call in &calls {
            assert!(
                call_uses_the_placement_law(call),
                "§13 sibling placement: `{call}` names a cgroup slice the orchestrator does not \
                 use — `vmcell::naming::cgroup_slice_name` is the bare leaf, which resolves to \
                 /sys/fs/cgroup/<leaf> while the VM lives at <base>/<leaf>. Use \
                 `vmcell::naming::vm_slice_name`."
            );
        }
    }

    /// The gate's own red-on-inverse: the predicate must reject the spelling that shipped, so
    /// the scan above is not a test that can only ever pass (AGENTS.md rule 2).
    #[test]
    fn the_placement_predicate_rejects_the_bare_leaf() {
        assert!(!call_uses_the_placement_law(
            "vmcell::naming::cgroup_slice_name(&prefix, vmid)"
        ));
        assert!(call_uses_the_placement_law(
            "vmcell::naming::vm_slice_name(&prefix, vmid)"
        ));
    }

    /// The two laws are genuinely different — the evidence behind the fix, and what keeps the
    /// scan above from guarding a distinction without a difference. On a host whose
    /// `/proc/self/cgroup` carries a unified entry the placed name is strictly longer than the
    /// leaf and ends with it; with no entry the two coincide and the broker's old spelling was
    /// accidentally right, which is why the defect was invisible in a container-less unit test.
    #[test]
    fn the_placed_name_extends_the_leaf_with_the_sibling_base() {
        let leaf = vmcell::naming::cgroup_slice_name("vmcell", 7);
        let placed = vmcell::naming::vm_slice_name("vmcell", 7);
        assert!(
            placed.ends_with(&leaf),
            "the placed slice name must end in the leaf: {placed:?} vs {leaf:?}"
        );
        let base = std::fs::read_to_string("/proc/self/cgroup")
            .ok()
            .and_then(|c| vmcell::metrics::cgroup_base_from_proc(&c));
        match base {
            Some(base) => assert_eq!(
                placed,
                format!("{base}/{leaf}"),
                "with a unified cgroup entry the broker must name the sibling-placed slice"
            ),
            None => assert_eq!(
                placed, leaf,
                "with no unified cgroup entry there is no base to place under"
            ),
        }
    }
}
