use crate::agent::AgentClient;
use crate::config::VmConfig;
use crate::error::Result;
use crate::metrics::ResourceUsage;
use crate::net::NetNamespace;
#[cfg(feature = "net-unprivileged")]
use crate::net::SmoltcpProcess;
use crate::proxy::{EgressProxy, ProxyConfig};
use crate::vmm::{PerVmResources, VmInstance, Vmm};
use std::sync::{Arc, Mutex};
use tracing::info;

/// Bounded grace window `shutdown()` waits after `request_shutdown()` before the
/// SIGKILL fallback, so the guest gets time to flush and power off cleanly
/// (ORCH-7). The `Drop` path does not wait — it force-kills immediately — so
/// this only applies to the explicit graceful `shutdown()`.
const SHUTDOWN_GRACE: std::time::Duration = std::time::Duration::from_millis(500);

/// A trait for providing time.
pub trait Clock: Send + Sync {
    /// Returns the current time.
    fn now(&self) -> std::time::SystemTime;
}

/// A real clock that uses the system time.
pub struct RealClock;
impl Clock for RealClock {
    fn now(&self) -> std::time::SystemTime {
        std::time::SystemTime::now()
    }
}

/// A fake clock for testing.
pub struct FakeClock {
    /// The simulated current time.
    pub time: std::time::SystemTime,
}
impl Clock for FakeClock {
    fn now(&self) -> std::time::SystemTime {
        self.time
    }
}

/// A guard that releases the CID when dropped.
#[derive(Debug)]
pub struct CidGuard {
    /// The unique guest CID.
    pub cid: u32,
    allocator: std::sync::Arc<crate::vmm::CidAllocator>,
}

impl Drop for CidGuard {
    fn drop(&mut self) {
        self.allocator.release(self.cid);
    }
}

/// Allocates unique VM IDs for the orchestrator.
///
/// `new()` is hermetic: it tracks reservations only in-process, so two
/// independent allocators in the same process never interfere (this is what
/// unit tests rely on). The design injects a single shared `Arc<VmidAllocator>`
/// per process, so in-process uniqueness is sufficient there. Use
/// [`VmidAllocator::shared`] for cross-process uniqueness on a real host, where
/// several runner processes may share host-global resources keyed by VMID
/// (netns, tap, cgroup, socket paths, CID, MAC, IP).
#[derive(Clone)]
pub struct VmidAllocator {
    active: Arc<Mutex<std::collections::BTreeSet<u32>>>,
    /// When set, cross-process reservations are recorded as lock files in this
    /// directory. `None` (the default) means in-process-only (hermetic).
    lock_dir: Option<std::path::PathBuf>,
    /// Injected clock used **only** to seed the search start (a hermetic,
    /// non-critical randomization that spreads the first-tried vmid across
    /// processes). Injected rather than reading `SystemTime::now()` directly so
    /// this seam is consistent with the rest of the file (ORCH-8) and the seed
    /// is deterministic under a `FakeClock` in tests.
    ///
    /// The `+ RefUnwindSafe` bound keeps `VmidAllocator` (and any public type that
    /// embeds it, e.g. `artifact::SnapshotStage`) `UnwindSafe`/`RefUnwindSafe`: a
    /// bare `dyn Clock` trait object is not unwind-safe, so storing one silently
    /// drops those auto-traits from the public surface. Both `Clock` impls
    /// (`RealClock`, `FakeClock`) satisfy it, so the bound is free here.
    clock: Arc<dyn Clock + std::panic::RefUnwindSafe>,
}

impl std::fmt::Debug for VmidAllocator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The injected `Clock` is not `Debug`; omit it (it is a non-critical seed
        // source, never part of the allocator's identity).
        f.debug_struct("VmidAllocator")
            .field("active", &self.active)
            .field("lock_dir", &self.lock_dir)
            .finish_non_exhaustive()
    }
}

impl Default for VmidAllocator {
    fn default() -> Self {
        Self::new()
    }
}

impl VmidAllocator {
    /// Creates a new, hermetic VMID allocator (in-process reservations only).
    #[must_use]
    pub fn new() -> Self {
        Self::with_clock(Arc::new(RealClock))
    }

    /// Creates a hermetic allocator seeded from an injected [`Clock`] (ORCH-8).
    /// Used by the unit tests to make the search-start seed deterministic; the
    /// public constructors seed from [`RealClock`].
    fn with_clock(clock: Arc<dyn Clock + std::panic::RefUnwindSafe>) -> Self {
        Self {
            active: Arc::new(Mutex::new(std::collections::BTreeSet::new())),
            lock_dir: None,
            clock,
        }
    }

    /// Creates a VMID allocator that additionally enforces cross-process
    /// uniqueness via lock files under `/tmp/vmcell-vmid`. Crashed-owner
    /// reservations are reclaimed by an owner-liveness check (`/proc/<pid>`), so
    /// a crash does not erode capacity permanently.
    #[must_use]
    pub fn shared() -> Self {
        Self {
            active: Arc::new(Mutex::new(std::collections::BTreeSet::new())),
            lock_dir: Some(std::path::PathBuf::from("/tmp/vmcell-vmid")),
            clock: Arc::new(RealClock),
        }
    }

    /// Attempts to claim `vmid` in the cross-process lock directory.
    ///
    /// Returns `true` when there is no cross-process locking configured
    /// (hermetic mode) or the claim succeeded; `false` when another live
    /// process already holds it.
    fn try_claim_fs(&self, vmid: u32) -> bool {
        let Some(dir) = &self.lock_dir else {
            return true;
        };
        let _ = std::fs::create_dir_all(dir);
        let lock_path = dir.join(format!("{}.lock", vmid));
        if std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&lock_path)
            .is_ok()
        {
            let _ = std::fs::write(&lock_path, std::process::id().to_string());
            return true;
        }
        // Owner-liveness reclaim: if the recorded owner is gone, take it over.
        if let Ok(contents) = std::fs::read_to_string(&lock_path) {
            if let Ok(pid) = contents.trim().parse::<u32>() {
                if !std::path::Path::new(&format!("/proc/{}", pid)).exists()
                    && std::fs::remove_file(&lock_path).is_ok()
                    && std::fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .open(&lock_path)
                        .is_ok()
                {
                    let _ = std::fs::write(&lock_path, std::process::id().to_string());
                    return true;
                }
            }
        }
        false
    }

    /// Releases the cross-process lock for `vmid`, if any.
    fn release_fs(&self, vmid: u32) {
        if let Some(dir) = &self.lock_dir {
            let lock_path = dir.join(format!("{}.lock", vmid));
            let _ = std::fs::remove_file(&lock_path);
        }
    }

    /// Allocates and returns the next available unique VMID.
    ///
    /// # Errors
    /// Returns an error if all 254 VMIDs are currently in use.
    pub fn allocate(&self) -> Result<u32> {
        let mut active = self.active.lock().unwrap_or_else(|e| e.into_inner());
        // ORCH-8: seed from the injected clock (consistent with the rest of the
        // file), not `SystemTime::now()` directly. Non-critical: `allocate()`
        // scans all 254 vmids and returns the first free one regardless of seed.
        let seed = self
            .clock
            .now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos();
        let start = (seed % 254) + 1;
        for i in 0..254 {
            let vmid = (start + i - 1) % 254 + 1;
            if !active.contains(&vmid) && self.try_claim_fs(vmid) {
                active.insert(vmid);
                return Ok(vmid);
            }
        }
        Err(crate::error::Error::Exhaustion(
            "No available VMIDs (limit 254)".to_string(),
        ))
    }

    /// Reserves a specific VMID, honoring a caller-supplied `cfg.vmid`.
    ///
    /// # Errors
    /// Returns [`crate::error::Error::Config`] if `vmid` is out of the `1..=254`
    /// range, or [`crate::error::Error::Exhaustion`] if it is already reserved
    /// (in-process or by another live process).
    pub fn reserve(&self, vmid: u32) -> Result<u32> {
        if !(1..=254).contains(&vmid) {
            return Err(crate::error::Error::Config(format!(
                "vmid {} out of range (must be 1..=254)",
                vmid
            )));
        }
        let mut active = self.active.lock().unwrap_or_else(|e| e.into_inner());
        if active.contains(&vmid) {
            return Err(crate::error::Error::Exhaustion(format!(
                "VMID {} already reserved",
                vmid
            )));
        }
        if !self.try_claim_fs(vmid) {
            return Err(crate::error::Error::Exhaustion(format!(
                "VMID {} already in use by another process",
                vmid
            )));
        }
        active.insert(vmid);
        Ok(vmid)
    }

    /// Releases a previously allocated VMID.
    pub fn release(&self, vmid: u32) {
        let mut active = self.active.lock().unwrap_or_else(|e| e.into_inner());
        active.remove(&vmid);
        self.release_fs(vmid);
    }
}

/// A guard that releases the VMID when dropped.
#[derive(Debug)]
pub struct VmidGuard {
    /// The unique virtual machine ID.
    pub vmid: u32,
    allocator: VmidAllocator,
}

impl Drop for VmidGuard {
    fn drop(&mut self) {
        self.allocator.release(self.vmid);
    }
}

/// Represents a fully managed test VM, including its associated resources and VMM instance.
#[derive(Debug)]
#[non_exhaustive]
pub struct MicroVm<V: Vmm> {
    /// The internal unique ID assigned to this VM.
    vmid: Option<VmidGuard>,
    /// The underlying VMM instance running the VM.
    instance: Option<V::Instance>,
    /// The network namespace associated with this VM, if any.
    netns: Option<NetNamespace>,
    #[cfg(feature = "net-unprivileged")]
    /// The smoltcp userspace networking process associated with this VM, if any.
    smoltcp: Option<SmoltcpProcess>,
    /// The egress proxy associated with this VM, if any.
    proxy: Option<EgressProxy>,
    /// The name of the cgroup for this VM.
    cgroup_name: Option<String>,
    /// The cgroup file system implementation.
    cgroup_fs: Option<Arc<dyn crate::metrics::CgroupFs>>,
    /// The cached agent client connection, if any.
    agent_client: Option<AgentClient>,
    /// Whether the VM was restored from a snapshot.
    restored: bool,
    /// Whether the one-shot post-restore CSPRNG reseed actually applied (exit 0)
    /// on the first post-restore [`MicroVm::agent`] call. `None` until that resync
    /// runs; `Some(false)` when the best-effort reseed could not be applied (e.g.
    /// `/dev/hwrng` missing). Lets a restore test assert the reseed was applied
    /// rather than inferring it from two `/dev/urandom` reads differing.
    restore_reseed_applied: Option<bool>,
    /// The CID guard.
    cid: Option<CidGuard>,
    /// The per-VM scratch-directory guard. Created early in `start()`/`restore()`
    /// (before networking) so a partway construction failure still reclaims it,
    /// and dropped LAST on teardown — after the instance, smoltcp, and daemons
    /// whose sockets live inside it are gone.
    tmp_dir: Option<crate::vmm::VmTempDir>,
}

/// A guard that deletes the cgroup slice on drop unless disarmed.
///
/// Created in `setup_env` immediately after the slice is created so that any
/// later failure during VM construction (CID allocation, `create`, `boot`,
/// `restore`, `resume`) releases the slice — mirroring `CidGuard`/`VmidGuard`.
/// On success it is disarmed and `MicroVm::Drop` takes over deletion (preserving
/// the documented teardown order).
#[derive(Debug)]
struct CgroupGuard {
    name: String,
    fs: Arc<dyn crate::metrics::CgroupFs>,
    armed: bool,
}

impl CgroupGuard {
    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for CgroupGuard {
    fn drop(&mut self) {
        if self.armed {
            if let Err(e) = self.fs.delete_slice(&self.name) {
                tracing::warn!("failed to delete leaked cgroup slice {}: {}", self.name, e);
            }
        }
    }
}

struct EnvSetup {
    res: PerVmResources,
    cid_guard: CidGuard,
    cgroup_guard: CgroupGuard,
    netns: Option<NetNamespace>,
    #[cfg(feature = "net-unprivileged")]
    smoltcp: Option<SmoltcpProcess>,
    proxy: Option<EgressProxy>,
}

/// Minimal guest-exec seam the one-shot post-restore resync needs.
///
/// Implemented for the real [`AgentClient`] and for a recording fake in the unit
/// tests, so the resync's ordering and its "clear `restored` only after the
/// mandatory step succeeds" contract (M-RESTORE-1) can be exercised without a
/// live guest.
trait GuestExec {
    /// Runs `argv` in the guest and returns its outcome.
    async fn exec_argv(&mut self, argv: Vec<String>) -> Result<crate::agent::ExecOutcome>;
}

impl GuestExec for AgentClient {
    async fn exec_argv(&mut self, argv: Vec<String>) -> Result<crate::agent::ExecOutcome> {
        self.exec(crate::agent::ExecRequest::new(argv)).await
    }
}

/// Runs the one-shot post-restore guest resync when `*restored` is set, clearing
/// the flag **only after** the mandatory clock resync succeeds.
///
/// M-RESTORE-1: a snapshot resumes at the frozen instant, so the guest clock,
/// CSPRNG state, and network identity must be refreshed on **every** restore
/// (§9.2). The mandatory clock resync is the *first* post-restore exec, which is
/// exactly where the freshly-rebound guest vsock listener is flakiest. The flag
/// is therefore propagated (`?`) and left **set** on a transient failure so the
/// next `agent()` call retries the whole resync, instead of being cleared up
/// front (the bug, which permanently skipped clock/RNG/MAC resync after one
/// transient first-exec error). `*reseed_applied` records whether the
/// best-effort CSPRNG reseed actually applied, so a caller can assert the reseed
/// ran rather than inferring it from two `/dev/urandom` reads differing.
async fn maybe_resync_after_restore<E: GuestExec>(
    restored: &mut bool,
    reseed_applied: &mut Option<bool>,
    exec: &mut E,
    clock: &dyn Clock,
    vmid: u32,
) -> Result<()> {
    if !*restored {
        return Ok(());
    }

    // Mandatory, host-driven clock resync: the guest cannot fix a frozen RTC from
    // inside (§9.2). Propagated with `?` so a transient first-exec failure leaves
    // `*restored` set and the next agent() call retries.
    let host_time = clock
        .now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    tracing::info!(
        "Automatically resyncing guest clock to host time: {}",
        host_time
    );
    let outcome = exec
        .exec_argv(vec![
            "date".to_string(),
            "-s".to_string(),
            format!("@{}", host_time),
        ])
        .await?;
    if outcome.code != 0 {
        // ORCH-3: the clock resync is mandatory (§9.2) — a non-zero exit is a
        // *surfaced, typed* failure, not a warning. We return here **before**
        // clearing `*restored`, so the flag stays set and the next `agent()`
        // call retries the whole resync. The previous code merely `warn!`d and
        // then cleared `restored` unconditionally, permanently masking a
        // persistently-failing clock set and leaving time-sensitive tests to see
        // a frozen wall clock (silent-Ok-on-failure, the exact §7.1 defect).
        return Err(crate::error::Error::Agent(format!(
            "mandatory post-restore clock resync failed (exit {}): {}",
            outcome.code,
            String::from_utf8_lossy(&outcome.stderr)
        )));
    }

    // Best-effort re-seed of the guest CSPRNG from the virtio-rng device after
    // restore (the snapshot may have captured RNG state). The reseed itself is
    // best-effort — a missing/unreadable `/dev/hwrng` must not fail the resync —
    // but whether it applied is recorded so a restore test can assert it ran.
    let reseed = match exec
        .exec_argv(vec![
            "sh".into(),
            "-c".into(),
            "head -c 32 /dev/hwrng > /dev/urandom".into(),
        ])
        .await
    {
        Ok(outcome) => {
            if outcome.code != 0 {
                tracing::warn!(
                    "restore RNG reseed failed (exit {}): {}",
                    outcome.code,
                    String::from_utf8_lossy(&outcome.stderr)
                );
            }
            outcome.code == 0
        }
        Err(e) => {
            tracing::warn!("restore RNG reseed could not be executed: {}", e);
            false
        }
    };
    *reseed_applied = Some(reseed);

    let mac = crate::net::mac_math(vmid)
        .map_err(|e| crate::error::Error::Agent(format!("mac math: {}", e)))?;
    // ORCH-1 / §9.2: MAC rotation is the ONLY in-guest identity change the
    // restore path performs, via a single `ip link set eth0 address <mac>` — a
    // device-layer write (the guest-tools helper's `SIOCSIFHWADDR` ioctl, §5.3),
    // consistent with the zero-netlink-in-PID-1 contract (§4.3). The IP address
    // is deliberately NOT rotated: the old `ip addr flush && ip addr add && ip
    // route add` chain was wrong — `ip addr flush` drops the IP-PNP default route
    // (breaking post-restore egress to non-local hosts) and re-introduces exactly
    // the in-guest netlink the design forbids. The guest keeps the address the
    // kernel `ip=` cmdline set. Sent as a direct argv (no `sh -c` &&-chain is
    // needed now that it is a single command). Best-effort: never keeps
    // `restored` set.
    match exec
        .exec_argv(vec![
            "ip".into(),
            "link".into(),
            "set".into(),
            "eth0".into(),
            "address".into(),
            mac,
        ])
        .await
    {
        Ok(outcome) if outcome.code != 0 => {
            tracing::warn!(
                "restore MAC rotation failed (exit {}): {}",
                outcome.code,
                String::from_utf8_lossy(&outcome.stderr)
            );
        }
        Err(e) => {
            tracing::warn!("restore MAC rotation could not be executed: {}", e);
        }
        _ => {}
    }

    // Clear `restored` ONLY now — after the mandatory clock resync above
    // succeeded (M-RESTORE-1). The RNG/network steps are best-effort and never
    // keep the flag set.
    *restored = false;
    Ok(())
}

impl<V: Vmm> MicroVm<V> {
    /// Gets the internal unique ID assigned to this VM.
    ///
    /// # Panics
    /// Panics if the VMID is missing.
    pub fn vmid(&self) -> u32 {
        self.vmid.as_ref().expect("vmid missing").vmid
    }

    /// Gets a reference to the underlying VMM instance.
    ///
    /// # Panics
    /// Panics if the instance is missing.
    pub fn instance(&self) -> &V::Instance {
        self.instance.as_ref().expect("instance missing")
    }

    /// Gets a mutable reference to the underlying VMM instance.
    ///
    /// # Panics
    /// Panics if the instance is missing.
    pub fn instance_mut(&mut self) -> &mut V::Instance {
        self.instance.as_mut().expect("instance missing")
    }

    /// Gets the network namespace associated with this VM, if any.
    pub fn netns(&self) -> Option<&NetNamespace> {
        self.netns.as_ref()
    }

    #[cfg(feature = "net-unprivileged")]
    /// Gets the smoltcp userspace networking process associated with this VM, if any.
    pub fn smoltcp(&self) -> Option<&SmoltcpProcess> {
        self.smoltcp.as_ref()
    }

    /// Gets the egress proxy associated with this VM, if any.
    pub fn proxy(&self) -> Option<&EgressProxy> {
        self.proxy.as_ref()
    }

    async fn setup_env(
        vmid: u32,
        tmp_dir: &std::path::Path,
        cfg: &VmConfig,
        cid_alloc: std::sync::Arc<crate::vmm::CidAllocator>,
        cgroup_fs: Arc<dyn crate::metrics::CgroupFs>,
    ) -> Result<EnvSetup> {
        let mut netns = None;
        #[cfg(feature = "net-unprivileged")]
        let mut smoltcp = None;
        let mut proxy = None;
        let mut tap_name = None;
        let mut netns_name = None;
        #[allow(unused_mut)]
        let mut vhost_user_socket = None;

        match &cfg.net {
            crate::config::NetConfig::Privileged {
                egress,
                host_services_port,
            } => {
                let _ = egress;
                let _ = host_services_port;
                let ns = NetNamespace::create(vmid, Box::new(crate::net::tap::RtNetlink))?;
                tap_name = Some(ns.tap_name.clone());
                netns_name = Some(ns.name.clone());

                if let crate::config::Egress::Filtered(proxy_cfg) = egress {
                    #[cfg(feature = "proxy")]
                    {
                        // Privileged egress front-end: the nft TPROXY ruleset
                        // (`tproxy to :<port>`, emitted below) redirects the guest's
                        // tcp/80,443 into this listener, so it MUST be an
                        // `IP_TRANSPARENT` socket for the kernel to deliver the
                        // redirected connections and preserve the original
                        // destination (H-PROXY-1). `start_transparent` fails loud if
                        // `IP_TRANSPARENT` cannot be set (e.g. missing CAP_NET_ADMIN)
                        // rather than silently degrading to a non-transparent bind
                        // that TPROXY cannot deliver to. NOTE: hudsucker is an
                        // explicit-proxy MITM (expects CONNECT/absolute-form), so a
                        // fully transparent HTTP MITM additionally needs absolute-form
                        // reconstruction from the recovered destination; that is
                        // tracked as follow-up — see implementation-notes.md.
                        let px = EgressProxy::start_transparent(crate::proxy::ProxyConfig {
                            port: 0,
                            netns: Some(format!("vmcell-net-{}", vmid)),
                            doubles: proxy_cfg.doubles.clone(),
                            blocked_domains: proxy_cfg.blocked_domains.clone(),
                        })
                        .await?;
                        ns.emit_proxy_rules(px.port, &crate::net::tap::DefaultNftApplier)?;
                        proxy = Some(px);
                    }
                }

                netns = Some(ns);
            }
            crate::config::NetConfig::Unprivileged {
                egress,
                host_services_port,
            } => {
                let _ = host_services_port;
                let mut _proxy_port = 0;

                if let crate::config::Egress::Filtered(proxy_cfg) = egress {
                    #[cfg(feature = "proxy")]
                    {
                        let px = EgressProxy::start(ProxyConfig {
                            port: 0,
                            netns: None,
                            doubles: proxy_cfg.doubles.clone(),
                            blocked_domains: proxy_cfg.blocked_domains.clone(),
                        })
                        .await?;
                        _proxy_port = px.port;
                        proxy = Some(px);
                    }
                }
                #[cfg(feature = "net-unprivileged")]
                {
                    // Consolidated into the per-VM scratch dir so the NAT socket is
                    // owned and reclaimed with everything else. The same path is
                    // handed to BOTH the smoltcp helper (which binds/unlinks it) and
                    // the VMM (via `vhost_user_socket`) so both sides agree.
                    let socket_path = tmp_dir.join("smoltcp.sock");
                    let mut ports = vec![];
                    let proxy_port_opt = if _proxy_port > 0 {
                        Some(_proxy_port)
                    } else {
                        None
                    };
                    if let Some(p) = host_services_port {
                        ports.push(*p);
                    }
                    // Register the egress proxy's port as a permanent forward-port so a guest
                    // configured with `http_proxy=<gateway>:<proxy_port>` reaches it: permanent
                    // listeners are pre-armed and re-armed (unlike the dynamic SYN-intercept
                    // path), which the explicit-proxy egress tests rely on.
                    if let Some(p) = proxy_port_opt {
                        ports.push(p);
                    }
                    let p = SmoltcpProcess::start(vmid, ports, proxy_port_opt, socket_path.clone());
                    vhost_user_socket = Some(socket_path);
                    smoltcp = Some(p);
                }
            }
            crate::config::NetConfig::None => {}
        }

        let mut cgroup_name = format!("vmcell-vm-{}", vmid);
        if let Ok(cgroup_str) = std::fs::read_to_string("/proc/self/cgroup") {
            if let Some(path) = cgroup_str.trim().split("0::").nth(1) {
                let mut base = path.trim_start_matches('/');
                if base.ends_with("/supervisor") {
                    base = base.trim_end_matches("/supervisor");
                }
                if !base.is_empty() {
                    cgroup_name = format!("{}/vmcell-vm-{}", base, vmid);
                }
            }
        }

        cgroup_fs.create_slice(&cgroup_name, &cfg.limits)?;
        // Armed immediately: any failure below (CID allocation, create/boot/
        // restore/resume in the caller) now releases the slice instead of
        // leaking it.
        let cgroup_guard = CgroupGuard {
            name: cgroup_name.clone(),
            fs: cgroup_fs.clone(),
            armed: true,
        };

        let guest_cid = cid_alloc.allocate()?;
        let cid_guard = CidGuard {
            cid: guest_cid,
            allocator: cid_alloc,
        };

        let res = PerVmResources {
            cgroup_name,
            tap_name,
            netns_name,
            vhost_user_socket,
            vmid,
            guest_cid,
            tmp_dir: tmp_dir.to_path_buf(),
        };

        Ok(EnvSetup {
            res,
            cid_guard,
            cgroup_guard,
            netns,
            #[cfg(feature = "net-unprivileged")]
            smoltcp,
            proxy,
        })
    }

    /// Starts a new VM with the given configuration.
    ///
    /// # Errors
    /// Returns an error if network setup, proxy start, or VM boot fails.
    ///
    /// # Examples
    /// ```rust
    /// # use std::sync::Arc;
    /// # use std::path::PathBuf;
    /// # use vmcell::orchestrator::{MicroVm, VmidAllocator};
    /// # use vmcell::config::{VmConfig, RootfsSource};
    /// # use vmcell::vmm::CidAllocator;
    /// # use vmcell::vmm::cloud_hypervisor::CloudHypervisor;
    /// # async fn run() {
    /// let vmm = CloudHypervisor::new("cloud-hypervisor");
    /// let cfg = VmConfig::builder(PathBuf::from("/vmlinux"), RootfsSource::VirtioFs { dir: PathBuf::from("/rootfs") }).build().unwrap();
    /// let cid_alloc = std::sync::Arc::new(CidAllocator::new());
    /// let vmid_alloc = VmidAllocator::new();
    /// let vm = MicroVm::start(&vmm, cfg, cid_alloc.clone(), vmid_alloc, Box::new(vmcell::metrics::DefaultCgroupFs::default())).await.unwrap();
    /// # }
    /// ```
    pub async fn start(
        vmm: &V,
        cfg: VmConfig,
        cid_alloc: std::sync::Arc<crate::vmm::CidAllocator>,
        vmid_alloc: VmidAllocator,
        cgroup_fs: Box<dyn crate::metrics::CgroupFs>,
    ) -> Result<Self> {
        let cgroup_fs: Arc<dyn crate::metrics::CgroupFs> = Arc::from(cgroup_fs);
        // Honor an explicitly-configured VMID by reserving it through the
        // allocator; otherwise allocate the next free one.
        let vmid_value = match cfg.vmid {
            Some(v) => vmid_alloc.reserve(v)?,
            None => vmid_alloc.allocate()?,
        };
        let vmid = VmidGuard {
            vmid: vmid_value,
            allocator: vmid_alloc,
        };
        // Create the single owned per-VM scratch dir EARLY — before networking —
        // so its guard reclaims it even if setup or create/boot fails partway, and
        // so the smoltcp NAT socket can live inside it.
        let tmp_dir = crate::vmm::VmTempDir::create(vmid.vmid).await?;
        let mut env = Self::setup_env(
            vmid.vmid,
            tmp_dir.path(),
            &cfg,
            cid_alloc.clone(),
            cgroup_fs.clone(),
        )
        .await?;

        let mut instance = vmm.create(&cfg, &env.res, &*cgroup_fs).await?;
        info!("Booting instance...");
        instance.boot().await?;
        info!("Instance booted.");
        // Success: ownership of the slice transfers to the returned MicroVm,
        // whose Drop deletes it in the documented teardown order.
        env.cgroup_guard.disarm();
        Ok(Self {
            vmid: Some(vmid),
            instance: Some(instance),
            netns: env.netns,
            #[cfg(feature = "net-unprivileged")]
            smoltcp: env.smoltcp,
            proxy: env.proxy,
            cgroup_name: Some(env.res.cgroup_name.clone()),
            cgroup_fs: Some(cgroup_fs),
            agent_client: None,
            restored: false,
            restore_reseed_applied: None,
            cid: Some(env.cid_guard),
            tmp_dir: Some(tmp_dir),
        })
    }

    /// Restores a VM from a snapshot directory with the given configuration.
    ///
    /// # Errors
    /// Returns an error if network setup, proxy start, or VM restore fails.
    ///
    /// # Examples
    /// ```rust
    /// # use std::sync::Arc;
    /// # use std::path::PathBuf;
    /// # use vmcell::orchestrator::{MicroVm, VmidAllocator};
    /// # use vmcell::config::{VmConfig, RootfsSource};
    /// # use vmcell::vmm::CidAllocator;
    /// # use vmcell::vmm::cloud_hypervisor::CloudHypervisor;
    /// # async fn run() {
    /// let vmm = CloudHypervisor::new("cloud-hypervisor");
    /// let cfg = VmConfig::builder(PathBuf::from("/vmlinux"), RootfsSource::Erofs { image: PathBuf::from("/rootfs.erofs") }).build().unwrap();
    /// let cid_alloc = std::sync::Arc::new(CidAllocator::new());
    /// let vmid_alloc = VmidAllocator::new();
    /// let snap_dir = PathBuf::from("/tmp/snap");
    /// let vm = MicroVm::restore(&vmm, &snap_dir, cfg, cid_alloc.clone(), vmid_alloc, Box::new(vmcell::metrics::DefaultCgroupFs::default())).await.unwrap();
    /// # }
    /// ```
    pub async fn restore(
        vmm: &V,
        snapshot_dir: &std::path::Path,
        cfg: VmConfig,
        cid_alloc: std::sync::Arc<crate::vmm::CidAllocator>,
        vmid_alloc: VmidAllocator,
        cgroup_fs: Box<dyn crate::metrics::CgroupFs>,
    ) -> Result<Self> {
        // §3.3 boundary 2 (ORCH-4): the restore-path re-check of the
        // snapshot-eligibility law returns `Error::Unsupported { vmm, feature }`
        // (a capability rejection a caller can match on), NOT the generic
        // `Error::Config` — a config a snapshot-eligible VMM cannot honor is an
        // unsupported capability, not a malformed config.
        if matches!(cfg.rootfs, crate::config::RootfsSource::VirtioFs { .. }) {
            return Err(crate::error::Error::Unsupported {
                vmm: vmm.id().to_string(),
                feature: "snapshot restore with a virtio-fs rootfs (vhost-user device)".into(),
            });
        }

        if matches!(cfg.net, crate::config::NetConfig::Unprivileged { .. }) {
            return Err(crate::error::Error::Unsupported {
                vmm: vmm.id().to_string(),
                feature: "snapshot restore with unprivileged (vhost-user-net) networking".into(),
            });
        }

        // Snapshot-eligibility law: a virtio-fs data share is served by
        // virtiofsd (a vhost-user device), which a snapshot-eligible VM must
        // not attach. Reject it here (enforced in code, not just docs).
        if !cfg.shares.is_empty() {
            return Err(crate::error::Error::Unsupported {
                vmm: vmm.id().to_string(),
                feature: "snapshot restore with a virtio-fs data share (vhost-user device)".into(),
            });
        }

        let cgroup_fs: Arc<dyn crate::metrics::CgroupFs> = Arc::from(cgroup_fs);
        let vmid_value = match cfg.vmid {
            Some(v) => vmid_alloc.reserve(v)?,
            None => vmid_alloc.allocate()?,
        };
        let vmid = VmidGuard {
            vmid: vmid_value,
            allocator: vmid_alloc,
        };
        // Create the single owned per-VM scratch dir EARLY (see `start()`).
        let tmp_dir = crate::vmm::VmTempDir::create(vmid.vmid).await?;
        let mut env = Self::setup_env(
            vmid.vmid,
            tmp_dir.path(),
            &cfg,
            cid_alloc.clone(),
            cgroup_fs.clone(),
        )
        .await?;

        info!("Restoring instance...");
        let mut instance = vmm
            .restore(snapshot_dir, &cfg, &env.res, &*cgroup_fs)
            .await?;
        info!("Resuming instance...");
        instance.resume().await?;
        info!("Instance resumed.");
        env.cgroup_guard.disarm();
        Ok(Self {
            vmid: Some(vmid),
            instance: Some(instance),
            netns: env.netns,
            #[cfg(feature = "net-unprivileged")]
            smoltcp: env.smoltcp,
            proxy: env.proxy,
            cgroup_name: Some(env.res.cgroup_name.clone()),
            cgroup_fs: Some(cgroup_fs),
            agent_client: None,
            restored: true,
            restore_reseed_applied: None,
            cid: Some(env.cid_guard),
            tmp_dir: Some(tmp_dir),
        })
    }

    /// Gets the agent client, connecting (and waiting for the connection) on
    /// first use.
    ///
    /// On the **first** call after a snapshot restore this also performs the
    /// one-shot guest resync — clock, CSPRNG reseed, and network identity (§9.2);
    /// see [`maybe_resync_after_restore`]. The `restored` flag is cleared only
    /// after the mandatory clock resync succeeds, so a transient first-exec
    /// failure retries on the next call rather than permanently skipping the
    /// resync (M-RESTORE-1).
    ///
    /// # Panics
    /// Panics if the VM instance is missing.
    ///
    /// # Errors
    /// Returns an error if the agent connection or handshake fails or times out,
    /// or if the mandatory post-restore clock resync exec fails.
    pub async fn agent(
        &mut self,
        timeout: Option<std::time::Duration>,
        clock: &dyn Clock,
    ) -> Result<&mut AgentClient> {
        if self.agent_client.is_none() {
            let client = AgentClient::connect(
                self.instance
                    .as_ref()
                    .expect("instance missing")
                    .vsock_path(),
                5000,
                timeout.unwrap_or(std::time::Duration::from_secs(10)),
                &crate::vmm::RealSerialLog {
                    path: self
                        .instance
                        .as_ref()
                        .expect("instance missing")
                        .serial_log()
                        .to_path_buf(),
                },
            )
            .await?;
            self.agent_client = Some(client);
        }

        let agent_ref = self
            .agent_client
            .as_mut()
            .ok_or_else(|| crate::error::Error::Agent("Failed to connect to agent".into()))?;

        if self.restored {
            // No explicit reconnect here: this `agent()` is the first call after
            // restore (agent_client started `None`), so the `connect()` above
            // already IS the post-restore connection. CH re-creates the vhost-vsock
            // device on `--restore`, so the guest's pre-snapshot listener goes deaf;
            // the guest agent re-binds its listener on idle (see `serve_vsock` in
            // vmcell-guest-agent), and `AgentClient::connect` retries with backoff
            // until that fresh listener accepts. A second, overlapping connect would
            // be redundant.
            let vmid = self.vmid.as_ref().expect("vmid missing").vmid;
            // M-RESTORE-1: clears `self.restored` only after the mandatory clock
            // resync succeeds, so a transient first-exec failure retries the full
            // resync on the next call instead of being silently dropped.
            maybe_resync_after_restore(
                &mut self.restored,
                &mut self.restore_reseed_applied,
                agent_ref,
                clock,
                vmid,
            )
            .await?;
        }

        Ok(agent_ref)
    }

    /// Whether the one-shot post-restore CSPRNG reseed actually applied (exit 0)
    /// on the first post-restore [`MicroVm::agent`] call.
    ///
    /// `None` before that resync has run; `Some(true)` when the reseed
    /// (`head -c 32 /dev/hwrng > /dev/urandom`) succeeded; `Some(false)` when the
    /// best-effort reseed could not be applied. A restore test asserts
    /// `Some(true)` instead of inferring the reseed from two `/dev/urandom` reads
    /// differing (which can pass coincidentally even when the reseed silently
    /// failed).
    #[must_use]
    pub fn restore_reseed_applied(&self) -> Option<bool> {
        self.restore_reseed_applied
    }

    /// Retrieves resource usage metrics for the VM.
    ///
    /// # Errors
    /// Returns an error if metrics collection fails.
    pub async fn usage(&self) -> Result<ResourceUsage> {
        if let (Some(cg_name), Some(fs)) = (&self.cgroup_name, &self.cgroup_fs) {
            fs.read_stats(cg_name)
        } else {
            // No cgroup is attached, so no requested limit is being enforced —
            // surface that honestly (`limits_enforced: false`) rather than handing
            // back an all-zero usage that implies a measured, enforced state
            // (§7.1 rule 3 / H-FAILLOUD-1). `ResourceUsage::default()` already has
            // the flag `false`; spell it out so the intent cannot silently drift.
            Ok(ResourceUsage {
                limits_enforced: false,
                ..ResourceUsage::default()
            })
        }
    }

    /// Pauses the running VM.
    ///
    /// Promoted to a first-class `MicroVm` method in v15 (§10.2) — previously
    /// reachable only via [`MicroVm::instance_mut`] — so the library, CLI, and a
    /// future daemon share one lifecycle-verb surface. Required before
    /// [`MicroVm::snapshot`] when driving the pause→snapshot→resume cycle by hand.
    ///
    /// # Errors
    /// Returns an error if the backend fails to pause the VM.
    pub async fn pause(&mut self) -> Result<()> {
        self.instance_mut().pause().await
    }

    /// Resumes a paused VM (after [`MicroVm::pause`] or a snapshot restore).
    ///
    /// Promoted to a first-class `MicroVm` method in v15 (§10.2).
    ///
    /// # Errors
    /// Returns an error if the backend fails to resume the VM.
    pub async fn resume(&mut self) -> Result<()> {
        self.instance_mut().resume().await
    }

    /// Writes a snapshot of the VM into `dir` (the backend pauses internally, writes
    /// the snapshot, then resumes).
    ///
    /// Promoted to a first-class `MicroVm` method in v15 (§10.2). Snapshot-eligible
    /// VMs only: a vhost-user device (virtio-fs rootfs/share or unprivileged net) is
    /// rejected at `VmConfig::build()` (the §3.3 law), and a backend that does not
    /// advertise `snapshot_restore` returns [`crate::error::Error::Unsupported`].
    ///
    /// # Errors
    /// Returns an error if the backend fails to snapshot, or
    /// [`crate::error::Error::Unsupported`] on a backend without snapshot support.
    pub async fn snapshot(&mut self, dir: &std::path::Path) -> Result<()> {
        self.instance_mut().snapshot(dir).await
    }

    /// Releases every per-VM resource that must be torn down **after** the VMM
    /// instance, in the one canonical order:
    /// smoltcp NAT → egress proxy → netns → cgroup → CID → VMID → scratch dir.
    ///
    /// Both [`shutdown`](Self::shutdown) (after the graceful async
    /// `request_shutdown` + `kill`) and [`Drop`] route through this single
    /// helper so the two teardown paths **cannot diverge** (ORCH-2): the old
    /// `shutdown()` deleted the netns *before* dropping the egress proxy, which
    /// on the privileged path runs *inside* that netns — removing a netns while
    /// a process still holds interfaces/sockets in it hangs or leaks (the
    /// AGENTS.md teardown-order invariant). Every field is `take()`n, so a
    /// second call (e.g. `Drop` running after `shutdown()` already ran) is a
    /// no-op.
    fn teardown_post_instance(&mut self) {
        // The egress proxy (privileged transparent/explicit front-end) and the
        // smoltcp NAT (unprivileged path) hold sockets/threads INSIDE the netns,
        // so they MUST be released before the netns is deleted.
        #[cfg(feature = "net-unprivileged")]
        drop(self.smoltcp.take());
        drop(self.proxy.take());
        // Netns after proxy/smoltcp, before cgroup (the documented order).
        // `NetNamespace::delete()` is idempotent and `NetNamespace::Drop`
        // performs the single teardown, surfacing a *genuine* failure via the
        // NET-8 warning; dropping the taken value tears it down exactly once.
        drop(self.netns.take());
        if let (Some(cg_name), Some(fs)) = (self.cgroup_name.take(), self.cgroup_fs.take()) {
            let _ = fs.delete_slice(&cg_name);
        }
        drop(self.cid.take());
        drop(self.vmid.take());
        // The per-VM scratch dir goes LAST: the instance (VMM process group +
        // virtiofsd/vhost-vsock daemons) and the smoltcp process — all dropped
        // above — own sockets that live inside it, so removing it any earlier
        // would race a live process still holding a socket there.
        drop(self.tmp_dir.take());
    }

    /// Shuts down the VM and cleans up associated resources.
    ///
    /// # Errors
    /// Returns an error if shutting down the VM or proxy fails.
    pub async fn shutdown(mut self) -> Result<()> {
        if let Some(mut inst) = self.instance.take() {
            let _ = inst.request_shutdown().await;

            // ORCH-7: give the guest a bounded grace window to flush and power
            // off after the shutdown request, before the SIGKILL fallback — an
            // immediate `kill()` grants ~0 flush time. (A poll that returns early
            // once the guest actually exits would need a `try_wait` on the
            // `VmInstance` trait, which is out of this change's file scope; the
            // fixed window is the correct-by-construction minimal fix.)
            tokio::time::sleep(SHUTDOWN_GRACE).await;

            // Force-kill + reap the process group so no zombie/EBUSY blocks the
            // netns teardown below.
            let _ = inst.kill().await;
            // Instance fully torn down here (end of scope) BEFORE the shared
            // post-instance teardown deletes the netns it held interfaces in.
        }

        // ORCH-2: everything after the instance goes through the ONE shared
        // ordered helper, so `shutdown()` and `Drop` cannot diverge — in
        // particular the proxy/smoltcp NAT are released before the netns.
        self.teardown_post_instance();
        Ok(())
    }
}

impl<V: Vmm> Drop for MicroVm<V> {
    fn drop(&mut self) {
        // Teardown order: VMM instance (process group + virtiofsd/vhost-vsock
        // daemons) FIRST, then the shared post-instance teardown
        // (proxy/smoltcp → netns → cgroup → cid → vmid → scratch dir). Routing
        // through the same helper as `shutdown()` keeps the two paths identical
        // (ORCH-2).
        drop(self.instance.take());
        self.teardown_post_instance();
    }
}

/// Parses the trailing vmid from a per-VM resource identifier — the last
/// `-`-separated numeric token. Works for every vmcell resource name:
/// `vmcell-net-<vmid>`, a `vmcell-vm-<vmid>` cgroup slice (even nested under a
/// `<base>/…` prefix), and a `vmcell-vm-<pid>-<vmid>` scratch dir. Returns
/// `None` when the tail is not a `u32`, so a foreign entry is never swept.
fn trailing_vmid(name: &str) -> Option<u32> {
    name.rsplit('-').next()?.parse().ok()
}

/// Read-only enumeration seam for the orphan sweeper ([`sweep_orphans`]).
///
/// A hard crash (SIGKILL/OOM) bypasses [`MicroVm`]'s `Drop`, leaking
/// host-global resources keyed by vmid — network namespaces, per-VM cgroup
/// slices, and per-VM scratch directories — that a later vmid then collides
/// with (ORCH-6, a standing B1 gap: teardown was previously RAII-only). The
/// sweeper lists candidates through this trait so it can be exercised with a
/// recording fake (no privileged host state); removal then goes through the
/// injected [`Netlink`](crate::net::tap::Netlink)/[`CgroupFs`](crate::metrics::CgroupFs)
/// seams so only non-live ids are reclaimed, in the canonical teardown order.
pub trait OrphanScanner: Send + Sync {
    /// Names of every network namespace matching the `vmcell-net-*` prefix.
    fn scan_netns(&self) -> Vec<String>;
    /// Names (paths relative to the cgroup-v2 root, as [`CgroupFs`](crate::metrics::CgroupFs)
    /// expects) of every per-VM cgroup slice matching `vmcell-vm-*`.
    fn scan_cgroup_slices(&self) -> Vec<String>;
    /// Per-VM scratch directories whose basename matches `vmcell-vm-*`.
    fn scan_scratch_dirs(&self) -> Vec<std::path::PathBuf>;
}

/// The production [`OrphanScanner`]: enumerates `/var/run/netns`, the cgroup-v2
/// mount at `/sys/fs/cgroup`, and the per-VM scratch base
/// ([`std::env::temp_dir`]).
///
/// Host-facing (privileged) — this real path reads privileged host state and is
/// **correct-by-construction, not KVM/privilege-validated here**; the unit tests
/// drive [`sweep_orphans`] through a recording fake instead. Deeply-nested
/// delegated cgroup slices are found by a bounded recursive walk.
#[derive(Debug, Default, Clone)]
pub struct HostOrphanScanner;

impl HostOrphanScanner {
    /// Bounded recursive walk of the cgroup-v2 tree under `root`, collecting the
    /// paths (relative to `/sys/fs/cgroup`) of directories named `vmcell-vm-*`.
    fn walk_cgroup_slices(root: &std::path::Path, rel: &str, depth: u8, out: &mut Vec<String>) {
        if depth == 0 {
            return;
        }
        let Ok(entries) = std::fs::read_dir(root) else {
            return;
        };
        for entry in entries.flatten() {
            if !entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                continue;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            let child_rel = if rel.is_empty() {
                name.clone()
            } else {
                format!("{}/{}", rel, name)
            };
            if name.starts_with("vmcell-vm-") {
                out.push(child_rel);
                // A per-VM slice has no vmcell children; no need to descend.
                continue;
            }
            Self::walk_cgroup_slices(&entry.path(), &child_rel, depth - 1, out);
        }
    }
}

impl OrphanScanner for HostOrphanScanner {
    fn scan_netns(&self) -> Vec<String> {
        let Ok(dir) = std::fs::read_dir("/var/run/netns") else {
            return Vec::new();
        };
        dir.flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with("vmcell-net-"))
            .collect()
    }

    fn scan_cgroup_slices(&self) -> Vec<String> {
        let mut out = Vec::new();
        Self::walk_cgroup_slices(std::path::Path::new("/sys/fs/cgroup"), "", 4, &mut out);
        out
    }

    fn scan_scratch_dirs(&self) -> Vec<std::path::PathBuf> {
        let base = std::env::temp_dir();
        let Ok(dir) = std::fs::read_dir(&base) else {
            return Vec::new();
        };
        dir.flatten()
            .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
            .map(|e| e.path())
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with("vmcell-vm-"))
            })
            .collect()
    }
}

/// What a [`sweep_orphans`] pass reclaimed, returned for logging and tests.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SweepReport {
    /// Network namespaces removed (in sweep order).
    pub netns: Vec<String>,
    /// Cgroup slices removed (in sweep order).
    pub cgroup_slices: Vec<String>,
    /// Per-VM scratch directories removed (in sweep order).
    pub scratch_dirs: Vec<std::path::PathBuf>,
}

/// Reclaims orphaned per-VM host resources left by a crashed run (ORCH-6).
///
/// Enumerates candidates through the injected [`OrphanScanner`] and removes each
/// one whose trailing vmid is **not** in `live_vmids` — so a resource still owned
/// by a running VM is never swept — through the injected
/// [`Netlink`](crate::net::tap::Netlink) (netns) and
/// [`CgroupFs`](crate::metrics::CgroupFs) (cgroup slice) seams, plus a direct
/// scratch-dir `remove_dir_all`. Removal follows the canonical teardown order —
/// **netns → cgroup → scratch dir** (an orphan has no live instance or proxy, so
/// that is the relevant tail of the AGENTS.md order). Returns a [`SweepReport`]
/// of what was reclaimed. Intended to run once at process/suite start (a leaked
/// netns collides with a later vmid: `netns add … Operation not permitted`).
///
/// The real host paths (netns delete, cgroup rmdir) are privileged and are
/// **not** KVM/privilege-validated here; the unit tests exercise the ordering,
/// live-skip, and per-seam delegation through recording fakes.
pub fn sweep_orphans(
    scanner: &dyn OrphanScanner,
    netlink: &dyn crate::net::tap::Netlink,
    cgroup_fs: &dyn crate::metrics::CgroupFs,
    live_vmids: &std::collections::BTreeSet<u32>,
) -> SweepReport {
    let mut report = SweepReport::default();

    for name in scanner.scan_netns() {
        let Some(vmid) = trailing_vmid(&name) else {
            continue;
        };
        if live_vmids.contains(&vmid) {
            continue; // still owned by a live VM — never sweep it
        }
        match netlink.delete_netns(&name) {
            Ok(()) => report.netns.push(name),
            Err(e) => tracing::warn!("sweep_orphans: failed to delete netns {}: {}", name, e),
        }
    }

    for name in scanner.scan_cgroup_slices() {
        let Some(vmid) = trailing_vmid(&name) else {
            continue;
        };
        if live_vmids.contains(&vmid) {
            continue;
        }
        match cgroup_fs.delete_slice(&name) {
            Ok(()) => report.cgroup_slices.push(name),
            Err(e) => {
                tracing::warn!(
                    "sweep_orphans: failed to delete cgroup slice {}: {}",
                    name,
                    e
                );
            }
        }
    }

    for dir in scanner.scan_scratch_dirs() {
        let Some(vmid) = dir
            .file_name()
            .and_then(|n| n.to_str())
            .and_then(trailing_vmid)
        else {
            continue;
        };
        if live_vmids.contains(&vmid) {
            continue;
        }
        match std::fs::remove_dir_all(&dir) {
            Ok(()) => report.scratch_dirs.push(dir),
            // Already gone (a racing Drop reclaimed it) is success, not a leak.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => report.scratch_dirs.push(dir),
            Err(e) => tracing::warn!(
                "sweep_orphans: failed to remove scratch dir {}: {}",
                dir.display(),
                e
            ),
        }
    }

    report
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_allocate_vmid() {
        let alloc = VmidAllocator::new();
        let vmid1 = alloc.allocate().unwrap();
        let vmid2 = alloc.allocate().unwrap();
        assert_ne!(vmid1, vmid2);
        assert!((1..=254).contains(&vmid1));
        alloc.release(vmid1);
        alloc.release(vmid2);
    }

    #[test]
    fn test_allocate_vmid_exhaustion() {
        let alloc = VmidAllocator::new();
        let mut vmids = Vec::new();
        while let Ok(id) = alloc.allocate() {
            vmids.push(id);
        }
        assert!(alloc.allocate().is_err());
        for id in vmids {
            alloc.release(id);
        }
    }

    // CONFIG-ERROR-ORCH-6. Buggy impl: a process-global `/tmp/vmcell-vmid-*.lock`
    // namespace couples two in-process allocators, so exhausting one (or a
    // leaked lock from a crashed run) would make the other fail to allocate.
    #[test]
    fn test_vmid_allocators_are_independent() {
        let a = VmidAllocator::new();
        let b = VmidAllocator::new();
        // Exhaust `a` entirely.
        while a.allocate().is_ok() {}
        assert!(a.allocate().is_err());
        // `b` must be completely unaffected.
        let mut from_b = Vec::new();
        for _ in 0..254 {
            from_b.push(
                b.allocate()
                    .expect("independent allocator must not be coupled"),
            );
        }
        assert_eq!(from_b.len(), 254);
    }

    // CONFIG-ERROR-ORCH-5 / DESIGN-DIVERGENCE-4. Buggy impl: reserve() does not
    // exist / does not honor a specific VMID, or fails to reject conflicts and
    // out-of-range values.
    #[test]
    fn test_reserve_specific_vmid_and_conflicts() {
        let alloc = VmidAllocator::new();
        assert_eq!(alloc.reserve(42).unwrap(), 42);
        // Second reservation of the same id conflicts.
        assert!(matches!(
            alloc.reserve(42),
            Err(crate::error::Error::Exhaustion(_))
        ));
        // A plain allocate must skip the reserved id.
        for _ in 0..253 {
            assert_ne!(alloc.allocate().unwrap(), 42);
        }
        // Out-of-range reservations are Config errors.
        assert!(matches!(
            alloc.reserve(0),
            Err(crate::error::Error::Config(_))
        ));
        assert!(matches!(
            alloc.reserve(255),
            Err(crate::error::Error::Config(_))
        ));
    }

    // ORCH-8. The search-start seed comes from the INJECTED clock, not
    // `SystemTime::now()` directly. On an empty allocator `allocate()` returns
    // exactly the seeded start `(subsec_nanos % 254) + 1`, so a fixed `FakeClock`
    // makes the first allocation deterministic. Buggy impl (seeding from
    // `SystemTime::now()`) ignores the injected clock and returns a wall-clock
    // value instead — reddening these exact-value assertions.
    #[test]
    fn test_vmid_allocate_seed_uses_injected_clock() {
        let at = |ns: u32| -> Arc<dyn Clock + std::panic::RefUnwindSafe> {
            Arc::new(FakeClock {
                time: std::time::UNIX_EPOCH + std::time::Duration::new(0, ns),
            })
        };
        let a = VmidAllocator::with_clock(at(1000));
        assert_eq!(a.allocate().unwrap(), (1000 % 254) + 1);
        // A different fixed time yields a different starting vmid → the seed is
        // genuinely clock-derived, not a constant.
        let b = VmidAllocator::with_clock(at(2000));
        assert_eq!(b.allocate().unwrap(), (2000 % 254) + 1);
    }

    // ---- Full teardown-order assertion (design §12.4 / §12.3) ----
    //
    // The design mandates asserting the FULL `MicroVm::Drop` order — VMM instance
    // (which owns the VMM process group AND its virtiofsd/vhost-vsock daemons) ->
    // netns -> cgroup — via recording fakes, on both normal drop and panic. The
    // integration-level `assert_instance_before_cgroup` in tests/lifecycle.rs can
    // only observe `instance -> cgroup` (its FakeVmm runs `network_disabled`, and an
    // integration test cannot inject a recording netns). These in-crate unit tests
    // construct `MicroVm` directly so a recording netns participates, pinning the
    // load-bearing `instance -> netns` edge: a netns torn down BEFORE the VMM stops
    // holding interfaces in it hangs/leaks (AGENTS.md teardown order). virtiofsd and
    // the tmpfs overlay are internal to the VMM instance's own `Drop`, so they are
    // not separately observable at this seam layer — see the alignment-pass note in
    // implementation-notes.md.
    #[cfg(feature = "net-privileged")]
    struct TimelineNetlink {
        log: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    }
    #[cfg(feature = "net-privileged")]
    impl crate::net::tap::Netlink for TimelineNetlink {
        fn add_netns(&self, _name: &str) -> Result<()> {
            Ok(())
        }
        fn setup_tap(
            &self,
            _netns: &str,
            _tap: &str,
            _vmid: u32,
        ) -> Result<Option<tun_tap::Iface>> {
            Ok(None)
        }
        fn delete_netns(&self, _name: &str) -> Result<()> {
            self.log
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push("netns_delete".to_string());
            Ok(())
        }
        fn setup_tproxy_routing(&self, _netns: &str) -> Result<()> {
            Ok(())
        }
    }

    #[cfg(feature = "net-privileged")]
    #[derive(Clone)]
    struct TimelineCgroupFs {
        log: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    }
    #[cfg(feature = "net-privileged")]
    impl std::fmt::Debug for TimelineCgroupFs {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("TimelineCgroupFs")
        }
    }
    #[cfg(feature = "net-privileged")]
    impl crate::metrics::CgroupFs for TimelineCgroupFs {
        fn create_slice(&self, _name: &str, _limits: &crate::config::ResourceLimits) -> Result<()> {
            Ok(())
        }
        fn delete_slice(&self, _name: &str) -> Result<()> {
            self.log
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push("cgroup_delete".to_string());
            Ok(())
        }
        fn read_stats(&self, _name: &str) -> Result<ResourceUsage> {
            Ok(ResourceUsage::default())
        }
        fn add_task(&self, _name: &str, _pid: u32) -> Result<()> {
            Ok(())
        }
    }

    // Builds a `MicroVm` whose instance-drop, netns-teardown, and cgroup-delete all
    // record into one shared timeline, so their relative order is observable.
    #[cfg(feature = "net-privileged")]
    fn micro_vm_for_order_test(
        log: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    ) -> MicroVm<crate::vmm::FakeVmm> {
        let instance = crate::vmm::FakeVmInstance {
            vsock_path: std::path::PathBuf::from("/tmp/vmcell-order-vsock.sock"),
            serial: std::path::PathBuf::from("/tmp/vmcell-order-serial.log"),
            calls: log.clone(),
        };
        let netns = NetNamespace::create(7, Box::new(TimelineNetlink { log: log.clone() }))
            .expect("fake netns create must succeed with a recording netlink");
        MicroVm::<crate::vmm::FakeVmm> {
            vmid: None,
            instance: Some(instance),
            netns: Some(netns),
            #[cfg(feature = "net-unprivileged")]
            smoltcp: None,
            proxy: None,
            cgroup_name: Some("vmcell-vm-7".to_string()),
            cgroup_fs: Some(std::sync::Arc::new(TimelineCgroupFs { log })),
            agent_client: None,
            restored: false,
            restore_reseed_applied: None,
            cid: None,
            tmp_dir: None,
        }
    }

    // Asserts the full teardown order: instance drop -> netns delete -> cgroup
    // delete. Goes red on the inverse — e.g. `MicroVm::Drop` deleting the cgroup or
    // the netns before dropping the instance (the documented hang/leak).
    #[cfg(feature = "net-privileged")]
    fn assert_full_teardown_order(log: &[String]) {
        let idx = |needle: &str| {
            log.iter()
                .position(|c| c == needle)
                .unwrap_or_else(|| panic!("{needle} not recorded; timeline: {log:?}"))
        };
        let instance = idx("drop");
        let netns = idx("netns_delete");
        let cgroup = idx("cgroup_delete");
        assert!(
            instance < netns && netns < cgroup,
            "teardown must be instance -> netns -> cgroup; got timeline: {log:?}"
        );
    }

    #[cfg(feature = "net-privileged")]
    #[test]
    fn test_drop_order_full_chain_normal() {
        let log = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        {
            let _vm = micro_vm_for_order_test(log.clone());
        }
        let calls = log.lock().unwrap_or_else(|e| e.into_inner());
        assert_full_teardown_order(&calls);
    }

    #[cfg(feature = "net-privileged")]
    #[test]
    fn test_drop_order_full_chain_on_panic() {
        let log = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let log_in = log.clone();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _vm = micro_vm_for_order_test(log_in);
            panic!("simulate panic inside scope");
        }));
        assert!(result.is_err(), "the closure must have panicked");
        let calls = log.lock().unwrap_or_else(|e| e.into_inner());
        assert_full_teardown_order(&calls);
    }

    /// A CgroupFs fake that records create/delete calls, used to prove the
    /// slice is released on a construction failure.
    #[derive(Debug, Default, Clone)]
    struct RecordingCgroupFs {
        created: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
        deleted: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    }

    impl crate::metrics::CgroupFs for RecordingCgroupFs {
        fn create_slice(&self, name: &str, _limits: &crate::config::ResourceLimits) -> Result<()> {
            self.created
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(name.to_string());
            Ok(())
        }
        fn delete_slice(&self, name: &str) -> Result<()> {
            self.deleted
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(name.to_string());
            Ok(())
        }
        fn read_stats(&self, _name: &str) -> Result<ResourceUsage> {
            Ok(ResourceUsage::default())
        }
        fn add_task(&self, _name: &str, _pid: u32) -> Result<()> {
            Ok(())
        }
    }

    /// A VMM whose `create`/`restore` always fail, to exercise the error path
    /// after the cgroup slice has been created.
    #[derive(Debug)]
    struct CreateFailVmm;

    impl Vmm for CreateFailVmm {
        type Instance = crate::vmm::FakeVmInstance;

        async fn create(
            &self,
            _cfg: &VmConfig,
            _res: &PerVmResources,
            _cgroups: &dyn crate::metrics::CgroupFs,
        ) -> Result<Self::Instance> {
            Err(crate::error::Error::Vmm("create failed".into()))
        }

        async fn restore(
            &self,
            _snapshot_dir: &std::path::Path,
            _cfg: &VmConfig,
            _res: &PerVmResources,
            _cgroups: &dyn crate::metrics::CgroupFs,
        ) -> Result<Self::Instance> {
            Err(crate::error::Error::Vmm("restore failed".into()))
        }

        fn capabilities(&self) -> crate::vmm::VmmCapabilities {
            crate::vmm::VmmCapabilities {
                snapshot_restore: true,
                lazy_restore: false,
                virtio_fs_shares: true,
                unprivileged_vhost_user_net: true,
                nested_virt: true,
            }
        }

        fn id(&self) -> &str {
            "createfail"
        }
    }

    fn erofs_cfg() -> VmConfig {
        VmConfig::builder(
            std::path::PathBuf::from("/vmlinux"),
            crate::config::RootfsSource::Erofs {
                image: std::path::PathBuf::from("/rootfs.erofs"),
            },
        )
        .network_disabled()
        .build()
        .expect("valid config")
    }

    // CONFIG-ERROR-ORCH-2. Buggy impl: setup_env returns the slice as a bare
    // String with no RAII guard, so a create/boot failure leaks it (the slice
    // is created but never deleted).
    #[tokio::test]
    async fn test_cgroup_slice_deleted_on_create_failure() {
        let vmm = CreateFailVmm;
        let cfg = erofs_cfg();
        let cid_alloc = std::sync::Arc::new(crate::vmm::CidAllocator::new());
        let vmid_alloc = VmidAllocator::new();
        let recorder = RecordingCgroupFs::default();
        let res = MicroVm::<CreateFailVmm>::start(
            &vmm,
            cfg,
            cid_alloc,
            vmid_alloc,
            Box::new(recorder.clone()),
        )
        .await;
        assert!(res.is_err(), "create failure must propagate");
        let created = recorder.created.lock().unwrap_or_else(|e| e.into_inner());
        let deleted = recorder.deleted.lock().unwrap_or_else(|e| e.into_inner());
        assert!(
            !created.is_empty(),
            "a slice should have been created in setup_env"
        );
        assert_eq!(
            *created, *deleted,
            "every created slice must be deleted on the failure path"
        );
    }

    // CONFIG-ERROR-ORCH-5. Buggy impl: start() ignores cfg.vmid and always
    // allocates a fresh VMID.
    #[tokio::test]
    async fn test_start_honors_cfg_vmid() {
        let vmm = crate::vmm::FakeVmm::default();
        let mut cfg = erofs_cfg();
        cfg.vmid = Some(7);
        let cid_alloc = std::sync::Arc::new(crate::vmm::CidAllocator::new());
        let vmid_alloc = VmidAllocator::new();
        let vm = MicroVm::start(
            &vmm,
            cfg,
            cid_alloc,
            vmid_alloc,
            Box::new(crate::metrics::FakeCgroupFs::new()),
        )
        .await
        .expect("start should succeed with fakes");
        assert_eq!(vm.vmid(), 7);
    }

    // CONFIG-ERROR-ORCH-5. Buggy impl: start() does not reserve cfg.vmid through
    // the allocator, so a conflicting explicit VMID is not detected.
    #[tokio::test]
    async fn test_start_rejects_vmid_conflict() {
        let vmm = crate::vmm::FakeVmm::default();
        let mut cfg = erofs_cfg();
        cfg.vmid = Some(7);
        let cid_alloc = std::sync::Arc::new(crate::vmm::CidAllocator::new());
        let vmid_alloc = VmidAllocator::new();
        // Someone already holds VMID 7 on this shared allocator.
        vmid_alloc.reserve(7).expect("pre-reservation");
        let res = MicroVm::start(
            &vmm,
            cfg,
            cid_alloc,
            vmid_alloc.clone(),
            Box::new(crate::metrics::FakeCgroupFs::new()),
        )
        .await;
        assert!(
            matches!(res, Err(crate::error::Error::Exhaustion(_))),
            "a conflicting explicit VMID must be rejected"
        );
    }

    // C1 / CONFIG-ERROR-ORCH-1. Buggy impl: restore() only guards a virtio-fs
    // rootfs and unprivileged net, letting a virtio-fs data Share (a vhost-user
    // device) through onto the snapshot path.
    #[tokio::test]
    async fn test_restore_rejects_data_shares() {
        let vmm = crate::vmm::FakeVmm::default();
        // A non-snapshotting config with a data share builds fine.
        let cfg = VmConfig::builder(
            std::path::PathBuf::from("/vmlinux"),
            crate::config::RootfsSource::Erofs {
                image: std::path::PathBuf::from("/rootfs.erofs"),
            },
        )
        .network_disabled()
        .with_share(crate::config::Share::new(
            "data",
            "/tmp/data",
            crate::config::Access::ReadOnly,
            crate::config::CachePolicy::Auto,
        ))
        .build()
        .expect("valid config");
        let cid_alloc = std::sync::Arc::new(crate::vmm::CidAllocator::new());
        let vmid_alloc = VmidAllocator::new();
        let res = MicroVm::restore(
            &vmm,
            std::path::Path::new("/fake/snap"),
            cfg,
            cid_alloc,
            vmid_alloc,
            Box::new(crate::metrics::FakeCgroupFs::new()),
        )
        .await;
        // ORCH-4 / §3.3 boundary 2: a vhost-user device on the restore path is an
        // `Unsupported` capability rejection, not a generic `Config` error.
        assert!(matches!(res, Err(crate::error::Error::Unsupported { .. })));
    }

    /// A recording guest-exec fake for the post-restore resync tests. Fails the
    /// first `fail_first_n` calls (modelling a just-rebound, still-flaky vsock),
    /// then records and succeeds; the CSPRNG reseed command's exit code is
    /// configurable to drive the "reseed not applied" path.
    #[derive(Default)]
    struct FakeExec {
        recorded: Vec<Vec<String>>,
        calls: usize,
        fail_first_n: usize,
        rng_exit_code: i32,
        /// Exit code returned for the mandatory `date -s` clock resync (ORCH-3);
        /// default 0. Non-zero drives the fail-loud clock-resync path.
        clock_exit_code: i32,
    }

    impl GuestExec for FakeExec {
        async fn exec_argv(&mut self, argv: Vec<String>) -> Result<crate::agent::ExecOutcome> {
            self.calls += 1;
            if self.calls <= self.fail_first_n {
                return Err(crate::error::Error::Agent(
                    "transient post-restore drop".into(),
                ));
            }
            let code = if argv.iter().any(|a| a.contains("/dev/hwrng")) {
                self.rng_exit_code
            } else if argv.first().map(String::as_str) == Some("date") {
                self.clock_exit_code
            } else {
                0
            };
            self.recorded.push(argv);
            Ok(crate::agent::ExecOutcome::new(code, vec![], vec![]))
        }
    }

    fn fixed_clock() -> FakeClock {
        FakeClock {
            time: std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000),
        }
    }

    // M-RESTORE-1. A transient failure of the FIRST post-restore exec (the
    // mandatory clock resync) must NOT clear `restored`; the next call must retry
    // the full resync. Buggy impl (clearing `restored` up front, then a hard `?`
    // on the first exec) leaves `restored == false` after the failure, so the
    // resync — clock, RNG reseed, MAC/network — never runs again. This goes red on
    // that inverse: it asserts the flag stays set after the failed pass and that
    // the full three-command resync runs on the retry.
    #[tokio::test]
    async fn test_resync_retries_after_transient_first_exec_failure() {
        let clock = fixed_clock();
        let mut restored = true;
        let mut reseed = None;
        let mut exec = FakeExec {
            fail_first_n: 1,
            ..FakeExec::default()
        };

        let first =
            maybe_resync_after_restore(&mut restored, &mut reseed, &mut exec, &clock, 5).await;
        assert!(
            first.is_err(),
            "transient clock-resync failure must propagate"
        );
        assert!(
            restored,
            "restored must stay set after a transient first-exec failure so the resync retries"
        );
        assert!(
            reseed.is_none(),
            "no reseed result recorded on the failed pass"
        );
        assert!(
            exec.recorded.is_empty(),
            "the failed first exec must not have recorded any resync command"
        );

        // Retry: the guest is reachable now; the full resync runs and only then is
        // the flag cleared.
        let second =
            maybe_resync_after_restore(&mut restored, &mut reseed, &mut exec, &clock, 5).await;
        assert!(second.is_ok(), "the retried resync must succeed");
        assert!(
            !restored,
            "restored is cleared only AFTER the mandatory clock resync succeeds"
        );
        assert_eq!(
            reseed,
            Some(true),
            "the reseed applied on the successful pass"
        );
        // The three resync commands ran, in order: clock, RNG reseed, MAC.
        assert_eq!(exec.recorded.len(), 3, "full resync must run on retry");
        assert_eq!(exec.recorded[0][0], "date");
        assert!(exec.recorded[1].iter().any(|a| a.contains("/dev/hwrng")));
        // ORCH-1 / §9.2: MAC rotation is a single direct `ip link set eth0
        // address <mac>` argv — NOT an `sh -c` chain with `ip addr flush/add` +
        // `ip route add` (which drops the IP-PNP route and re-adds in-guest
        // netlink). Reddens if the old flush/add/route chain is restored.
        assert_eq!(
            &exec.recorded[2][..5],
            &["ip", "link", "set", "eth0", "address"]
        );
        assert_eq!(
            exec.recorded[2].len(),
            6,
            "argv is `ip link set eth0 address <mac>`"
        );
        assert!(
            !exec.recorded[2]
                .iter()
                .any(|a| a == "flush" || a == "add" || a == "route" || a.contains("sh")),
            "the wrong addr-flush/add + route-add chain must be gone: {:?}",
            exec.recorded[2]
        );
    }

    // Test-discipline (c): the typed "reseed applied" result must report
    // Some(false) when the best-effort reseed command exits non-zero (e.g.
    // /dev/hwrng missing), so a restore test can assert the reseed actually
    // applied instead of inferring it from two /dev/urandom reads differing.
    // Buggy impl (always recording Some(true), or never recording) goes red.
    #[tokio::test]
    async fn test_resync_records_reseed_not_applied_on_nonzero_exit() {
        let clock = fixed_clock();
        let mut restored = true;
        let mut reseed = None;
        let mut exec = FakeExec {
            rng_exit_code: 1,
            ..FakeExec::default()
        };
        maybe_resync_after_restore(&mut restored, &mut reseed, &mut exec, &clock, 5)
            .await
            .expect("clock resync succeeds; the reseed is best-effort");
        assert_eq!(
            reseed,
            Some(false),
            "a non-zero reseed exit must be surfaced as not-applied"
        );
        assert!(
            !restored,
            "a best-effort reseed failure must NOT keep restored set (the clock resync succeeded)"
        );
    }

    // The resync is a no-op when the VM was not restored: no exec is issued and no
    // reseed result is recorded. Guards against running the resync on a cold boot.
    #[tokio::test]
    async fn test_resync_is_noop_when_not_restored() {
        let clock = fixed_clock();
        let mut restored = false;
        let mut reseed = None;
        let mut exec = FakeExec::default();
        maybe_resync_after_restore(&mut restored, &mut reseed, &mut exec, &clock, 5)
            .await
            .unwrap();
        assert!(exec.recorded.is_empty(), "no resync when not restored");
        assert_eq!(reseed, None);
    }

    // ORCH-3. A NON-ZERO exit of the mandatory clock resync (`date -s`) must be
    // surfaced as a typed failure — NOT swallowed with a `warn!` while `restored`
    // is cleared as if it succeeded. Buggy impl (warn + fall through +
    // `*restored = false`) returns `Ok(())`, clears `restored`, and never retries,
    // so a time-sensitive restored test silently sees a frozen wall clock. This
    // reddens on that inverse: it asserts the Err is returned, `restored` stays
    // set (so the next agent() call retries), and the best-effort RNG/MAC steps
    // did NOT run past the failed mandatory step.
    #[tokio::test]
    async fn test_resync_clock_nonzero_exit_is_surfaced() {
        let clock = fixed_clock();
        let mut restored = true;
        let mut reseed = None;
        let mut exec = FakeExec {
            clock_exit_code: 1,
            ..FakeExec::default()
        };
        let res =
            maybe_resync_after_restore(&mut restored, &mut reseed, &mut exec, &clock, 5).await;
        assert!(
            matches!(res, Err(crate::error::Error::Agent(_))),
            "a non-zero clock-resync exit must be a surfaced, typed failure, not Ok"
        );
        assert!(
            restored,
            "restored must STAY set after a failed mandatory clock resync so it retries"
        );
        assert_eq!(
            reseed, None,
            "the best-effort RNG reseed must not run once the mandatory clock resync failed"
        );
        // Only the failed `date` command was attempted; no RNG/MAC follow-on.
        assert_eq!(
            exec.recorded.len(),
            1,
            "resync stops at the failed mandatory step"
        );
        assert_eq!(exec.recorded[0][0], "date");
    }

    /// A `CgroupFs` whose `read_stats` reports a configurable `limits_enforced`,
    /// so `usage()` can be shown to surface the real enforcement state rather than
    /// a rosy constant.
    #[derive(Debug, Clone)]
    struct EnforcementCgroupFs {
        enforced: bool,
    }

    impl crate::metrics::CgroupFs for EnforcementCgroupFs {
        fn create_slice(&self, _name: &str, _limits: &crate::config::ResourceLimits) -> Result<()> {
            Ok(())
        }
        fn delete_slice(&self, _name: &str) -> Result<()> {
            Ok(())
        }
        fn read_stats(&self, _name: &str) -> Result<ResourceUsage> {
            Ok(ResourceUsage {
                limits_enforced: self.enforced,
                ..ResourceUsage::default()
            })
        }
        fn add_task(&self, _name: &str, _pid: u32) -> Result<()> {
            Ok(())
        }
    }

    async fn start_with_cgroup(fs: EnforcementCgroupFs) -> MicroVm<crate::vmm::FakeVmm> {
        let vmm = crate::vmm::FakeVmm::default();
        MicroVm::start(
            &vmm,
            erofs_cfg(),
            std::sync::Arc::new(crate::vmm::CidAllocator::new()),
            VmidAllocator::new(),
            Box::new(fs),
        )
        .await
        .expect("start should succeed with fakes")
    }

    // H-FAILLOUD-1 (surfacing). When the cgroup reports limits NOT enforced (an
    // undelegated controller — the VM is effectively running unbounded), usage()
    // must surface limits_enforced=false. Buggy impl that returns
    // ResourceUsage::default() unconditionally (ignoring read_stats) or hardcodes
    // true goes red here, while the inverse (enforced) test below stays green —
    // proving usage() reflects the real flag, not a constant.
    #[tokio::test]
    async fn test_usage_surfaces_unenforced_limits_honestly() {
        let vm = start_with_cgroup(EnforcementCgroupFs { enforced: false }).await;
        let usage = vm.usage().await.unwrap();
        assert!(
            !usage.limits_enforced,
            "usage() must honestly surface that the requested limits are NOT enforced"
        );
    }

    #[tokio::test]
    async fn test_usage_surfaces_enforced_limits() {
        let vm = start_with_cgroup(EnforcementCgroupFs { enforced: true }).await;
        let usage = vm.usage().await.unwrap();
        assert!(
            usage.limits_enforced,
            "usage() must surface enforced limits as true (control for the false case)"
        );
    }

    // H-FAILLOUD-1 (surfacing). The no-cgroup-attached branch (orchestrator
    // usage() else arm) must report limits_enforced=false, not imply an all-zero,
    // measured-and-enforced usage. Buggy impl returning a usage with the flag
    // forced true (or omitting the field's honest default) goes red.
    #[tokio::test]
    async fn test_usage_without_cgroup_reports_unenforced() {
        let vm: MicroVm<crate::vmm::FakeVmm> = MicroVm {
            vmid: None,
            instance: None,
            netns: None,
            #[cfg(feature = "net-unprivileged")]
            smoltcp: None,
            proxy: None,
            cgroup_name: None,
            cgroup_fs: None,
            agent_client: None,
            restored: false,
            restore_reseed_applied: None,
            cid: None,
            tmp_dir: None,
        };
        let usage = vm.usage().await.unwrap();
        assert!(
            !usage.limits_enforced,
            "with no cgroup attached, usage() must report limits as unenforced"
        );
    }

    // v15 §10.2: pause/resume/snapshot are promoted to first-class MicroVm methods.
    // Each must FORWARD to the underlying VmInstance. The FakeVmInstance records every
    // call it receives, so the inverse — a no-op MicroVm method that silently does not
    // delegate — leaves the corresponding instance call unrecorded and goes red here.
    #[tokio::test]
    async fn test_microvm_lifecycle_verbs_delegate_to_instance() {
        let mut vm = start_with_cgroup(EnforcementCgroupFs { enforced: true }).await;
        vm.pause().await.expect("pause");
        vm.snapshot(std::path::Path::new("/tmp/vmcell-snap-test"))
            .await
            .expect("snapshot");
        vm.resume().await.expect("resume");
        let calls = vm.instance().calls.lock().expect("calls lock").clone();
        assert!(
            calls.contains(&"pause".to_string()),
            "MicroVm::pause must delegate to the instance: {calls:?}"
        );
        assert!(
            calls.contains(&"snapshot".to_string()),
            "MicroVm::snapshot must delegate to the instance: {calls:?}"
        );
        assert!(
            calls.contains(&"resume".to_string()),
            "MicroVm::resume must delegate to the instance: {calls:?}"
        );
    }

    // ORCH-5 (B1/B6). Dropping a `MicroVm` that holds a REAL `Some(cid)` /
    // `Some(vmid)` guard must return BOTH ids to their allocators. The existing
    // drop-order builder sets `cid: None, vmid: None`, so its guard-Drop release
    // paths are no-ops; `test_allocate_vmid` exercises `release()` directly, not
    // guard-Drop. This builds the guards, captures the ids, drops the VM, and
    // asserts the SAME ids are handed back out. The no-op-release inverse (a
    // `Drop`/guard that does not call `release()`) reddens: the CID re-allocation
    // would skip `cid` and the VMID re-reservation would fail `Exhaustion`.
    #[test]
    fn test_drop_returns_cid_and_vmid_to_allocators() {
        let cid_alloc = std::sync::Arc::new(crate::vmm::CidAllocator::new());
        let vmid_alloc = VmidAllocator::new();
        let cid = cid_alloc.allocate().expect("cid"); // lowest free = 3
        let vmid = vmid_alloc.reserve(9).expect("vmid");

        let vm: MicroVm<crate::vmm::FakeVmm> = MicroVm {
            vmid: Some(VmidGuard {
                vmid,
                allocator: vmid_alloc.clone(),
            }),
            instance: None,
            netns: None,
            #[cfg(feature = "net-unprivileged")]
            smoltcp: None,
            proxy: None,
            cgroup_name: None,
            cgroup_fs: None,
            agent_client: None,
            restored: false,
            restore_reseed_applied: None,
            cid: Some(CidGuard {
                cid,
                allocator: cid_alloc.clone(),
            }),
            tmp_dir: None,
        };
        drop(vm);

        assert_eq!(
            cid_alloc.allocate().expect("cid re-alloc"),
            cid,
            "the CID must be returned to the allocator on guard-Drop"
        );
        assert!(
            vmid_alloc.reserve(vmid).is_ok(),
            "the VMID must be returned to the allocator on guard-Drop"
        );
    }

    // ---- ORCH-6: orphan sweeper (recording fakes) ----

    struct FakeOrphanScanner {
        netns: Vec<String>,
        cgroups: Vec<String>,
        scratch: Vec<std::path::PathBuf>,
    }
    impl OrphanScanner for FakeOrphanScanner {
        fn scan_netns(&self) -> Vec<String> {
            self.netns.clone()
        }
        fn scan_cgroup_slices(&self) -> Vec<String> {
            self.cgroups.clone()
        }
        fn scan_scratch_dirs(&self) -> Vec<std::path::PathBuf> {
            self.scratch.clone()
        }
    }

    #[cfg(feature = "net-privileged")]
    struct RecordingSweepNetlink {
        log: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    }
    #[cfg(feature = "net-privileged")]
    impl crate::net::tap::Netlink for RecordingSweepNetlink {
        fn add_netns(&self, _name: &str) -> Result<()> {
            Ok(())
        }
        fn setup_tap(
            &self,
            _netns: &str,
            _tap: &str,
            _vmid: u32,
        ) -> Result<Option<tun_tap::Iface>> {
            Ok(None)
        }
        fn delete_netns(&self, name: &str) -> Result<()> {
            self.log
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(format!("netns:{name}"));
            Ok(())
        }
        fn setup_tproxy_routing(&self, _netns: &str) -> Result<()> {
            Ok(())
        }
    }

    #[derive(Clone)]
    struct RecordingSweepCgroupFs {
        log: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    }
    impl std::fmt::Debug for RecordingSweepCgroupFs {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("RecordingSweepCgroupFs")
        }
    }
    impl crate::metrics::CgroupFs for RecordingSweepCgroupFs {
        fn create_slice(&self, _name: &str, _limits: &crate::config::ResourceLimits) -> Result<()> {
            Ok(())
        }
        fn delete_slice(&self, name: &str) -> Result<()> {
            self.log
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(format!("cgroup:{name}"));
            Ok(())
        }
        fn read_stats(&self, _name: &str) -> Result<ResourceUsage> {
            Ok(ResourceUsage::default())
        }
        fn add_task(&self, _name: &str, _pid: u32) -> Result<()> {
            Ok(())
        }
    }

    // ORCH-6. `sweep_orphans` must reclaim ONLY resources whose trailing vmid is
    // not live, in the canonical teardown order (netns -> cgroup -> scratch dir),
    // through the injected Netlink/CgroupFs seams. Seeds the scanner with an
    // orphan (vmid 3) and a live (vmid 7) entry of each kind. Reddens on: sweeping
    // a live id (no-skip), skipping an orphan, or reordering netns-vs-cgroup.
    #[cfg(feature = "net-privileged")]
    #[test]
    fn test_sweep_orphans_reclaims_only_dead_ids_in_order() {
        let log = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let nl = RecordingSweepNetlink { log: log.clone() };
        let cg = RecordingSweepCgroupFs { log: log.clone() };
        let live: std::collections::BTreeSet<u32> = [7].into_iter().collect();

        // Real scratch dirs so removal is observable on disk (unique per process).
        let base = std::env::temp_dir();
        let pid = std::process::id();
        let orphan_dir = base.join(format!("vmcell-vm-{pid}-3"));
        let live_dir = base.join(format!("vmcell-vm-{pid}-7"));
        std::fs::create_dir_all(&orphan_dir).expect("orphan dir");
        std::fs::create_dir_all(&live_dir).expect("live dir");

        let scanner = FakeOrphanScanner {
            netns: vec!["vmcell-net-3".into(), "vmcell-net-7".into()],
            cgroups: vec!["base/vmcell-vm-3".into(), "base/vmcell-vm-7".into()],
            scratch: vec![orphan_dir.clone(), live_dir.clone()],
        };

        let report = sweep_orphans(&scanner, &nl, &cg, &live);

        // Only the dead (vmid 3) resources were swept; the live (vmid 7) kept.
        assert_eq!(report.netns, vec!["vmcell-net-3".to_string()]);
        assert_eq!(report.cgroup_slices, vec!["base/vmcell-vm-3".to_string()]);
        assert_eq!(report.scratch_dirs, vec![orphan_dir.clone()]);
        assert!(
            !orphan_dir.exists(),
            "the orphan scratch dir must be removed"
        );
        assert!(live_dir.exists(), "the live scratch dir must be kept");

        // Every netns delete precedes every cgroup delete, and only orphans were
        // deleted through the injected seams.
        let calls = log.lock().unwrap_or_else(|e| e.into_inner()).clone();
        assert_eq!(
            calls,
            vec![
                "netns:vmcell-net-3".to_string(),
                "cgroup:base/vmcell-vm-3".to_string(),
            ],
            "sweep must delete only the orphan, netns before cgroup: {calls:?}"
        );

        let _ = std::fs::remove_dir_all(&live_dir);
    }

    // ---- ORCH-2: shutdown() tears down the proxy BEFORE the netns ----
    //
    // The old `shutdown()` deleted the netns before dropping the egress proxy that
    // runs inside it. Route both `shutdown()` and `Drop` through one shared
    // ordered helper so they cannot diverge. This drives the REAL `shutdown()`
    // path with a real loopback `EgressProxy`, a recording netns, and a recording
    // cgroup. The recording netns, at delete time, probes whether the proxy's port
    // is already free: `EgressProxy::Drop` synchronously joins its thread (freeing
    // the port), so in the correct order the port is free ("proxy_gone") by the
    // time the netns is deleted. The inverse (netns removed while the proxy still
    // listens) makes the probe find the port bound ("proxy_present") -> red.
    #[cfg(all(feature = "net-privileged", feature = "proxy"))]
    struct ShutdownOrderNetlink {
        log: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
        proxy_port: u16,
    }
    #[cfg(all(feature = "net-privileged", feature = "proxy"))]
    impl crate::net::tap::Netlink for ShutdownOrderNetlink {
        fn add_netns(&self, _name: &str) -> Result<()> {
            Ok(())
        }
        fn setup_tap(
            &self,
            _netns: &str,
            _tap: &str,
            _vmid: u32,
        ) -> Result<Option<tun_tap::Iface>> {
            Ok(None)
        }
        fn delete_netns(&self, name: &str) -> Result<()> {
            let mut log = self.log.lock().unwrap_or_else(|e| e.into_inner());
            log.push(format!("netns_delete:{name}"));
            // If the proxy's port is bindable now, the proxy was torn down BEFORE
            // this netns delete (correct order); if still bound, the netns is being
            // removed while the proxy runs inside it (the ORCH-2 bug).
            let probe = std::net::TcpListener::bind(("127.0.0.1", self.proxy_port));
            log.push(if probe.is_ok() {
                "proxy_gone".to_string()
            } else {
                "proxy_present".to_string()
            });
            Ok(())
        }
        fn setup_tproxy_routing(&self, _netns: &str) -> Result<()> {
            Ok(())
        }
    }

    #[cfg(all(feature = "net-privileged", feature = "proxy"))]
    #[tokio::test]
    async fn test_shutdown_tears_down_proxy_before_netns() {
        let proxy = EgressProxy::start(ProxyConfig::default())
            .await
            .expect("real loopback proxy must start");
        let port = proxy.port;
        let log = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));

        let netns = NetNamespace::create(
            11,
            Box::new(ShutdownOrderNetlink {
                log: log.clone(),
                proxy_port: port,
            }),
        )
        .expect("fake netns create");

        let instance = crate::vmm::FakeVmInstance {
            vsock_path: std::path::PathBuf::from("/tmp/vmcell-shutdown-vsock.sock"),
            serial: std::path::PathBuf::from("/tmp/vmcell-shutdown-serial.log"),
            calls: log.clone(),
        };

        let vm = MicroVm::<crate::vmm::FakeVmm> {
            vmid: None,
            instance: Some(instance),
            netns: Some(netns),
            #[cfg(feature = "net-unprivileged")]
            smoltcp: None,
            proxy: Some(proxy),
            cgroup_name: Some("vmcell-vm-11".to_string()),
            cgroup_fs: Some(std::sync::Arc::new(TimelineCgroupFs { log: log.clone() })),
            agent_client: None,
            restored: false,
            restore_reseed_applied: None,
            cid: None,
            tmp_dir: None,
        };

        vm.shutdown().await.expect("shutdown ok");

        let calls = log.lock().unwrap_or_else(|e| e.into_inner()).clone();
        assert!(
            calls.iter().any(|c| c == "proxy_gone"),
            "the proxy must be torn down BEFORE the netns is deleted: {calls:?}"
        );
        assert!(
            !calls.iter().any(|c| c == "proxy_present"),
            "the netns must NOT be deleted while the proxy still runs inside it: {calls:?}"
        );
        let idx = |needle: &str| calls.iter().position(|c| c == needle);
        let drop_i = idx("drop").expect("instance drop recorded");
        let netns_i = idx("netns_delete:vmcell-net-11").expect("netns delete recorded");
        let cg_i = idx("cgroup_delete").expect("cgroup delete recorded");
        assert!(
            drop_i < netns_i && netns_i < cg_i,
            "shutdown() teardown must be instance -> netns -> cgroup: {calls:?}"
        );
        // ORCH-7: request_shutdown precedes the SIGKILL fallback (the grace sits
        // between them).
        let rs_i = idx("request_shutdown").expect("request_shutdown recorded");
        let kill_i = idx("kill").expect("kill recorded");
        assert!(
            rs_i < kill_i,
            "request_shutdown must precede the SIGKILL fallback: {calls:?}"
        );
    }
}
