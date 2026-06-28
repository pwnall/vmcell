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
#[derive(Debug, Clone, Default)]
pub struct VmidAllocator {
    active: Arc<Mutex<std::collections::BTreeSet<u32>>>,
    /// When set, cross-process reservations are recorded as lock files in this
    /// directory. `None` (the default) means in-process-only (hermetic).
    lock_dir: Option<std::path::PathBuf>,
}

impl VmidAllocator {
    /// Creates a new, hermetic VMID allocator (in-process reservations only).
    #[must_use]
    pub fn new() -> Self {
        Self {
            active: Arc::new(Mutex::new(std::collections::BTreeSet::new())),
            lock_dir: None,
        }
    }

    /// Creates a VMID allocator that additionally enforces cross-process
    /// uniqueness via lock files under `/tmp/imp-vmid`. Crashed-owner
    /// reservations are reclaimed by an owner-liveness check (`/proc/<pid>`), so
    /// a crash does not erode capacity permanently.
    #[must_use]
    pub fn shared() -> Self {
        Self {
            active: Arc::new(Mutex::new(std::collections::BTreeSet::new())),
            lock_dir: Some(std::path::PathBuf::from("/tmp/imp-vmid")),
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
        let seed = std::time::SystemTime::now()
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
pub struct TestVm<V: Vmm> {
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
    /// The CID guard.
    cid: Option<CidGuard>,
}

/// A guard that deletes the cgroup slice on drop unless disarmed.
///
/// Created in `setup_env` immediately after the slice is created so that any
/// later failure during VM construction (CID allocation, `create`, `boot`,
/// `restore`, `resume`) releases the slice — mirroring `CidGuard`/`VmidGuard`.
/// On success it is disarmed and `TestVm::Drop` takes over deletion (preserving
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

impl<V: Vmm> TestVm<V> {
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
                        let px = EgressProxy::start(crate::proxy::ProxyConfig {
                            port: 0,
                            netns: Some(format!("imp-net-{}", vmid)),
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
            crate::config::NetConfig::Rootless {
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
                    let socket_path =
                        std::path::PathBuf::from(format!("/tmp/imp-smoltcp-{}.sock", vmid));
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

        let mut cgroup_name = format!("imp-vm-{}", vmid);
        if let Ok(cgroup_str) = std::fs::read_to_string("/proc/self/cgroup") {
            if let Some(path) = cgroup_str.trim().split("0::").nth(1) {
                let mut base = path.trim_start_matches('/');
                if base.ends_with("/supervisor") {
                    base = base.trim_end_matches("/supervisor");
                }
                if !base.is_empty() {
                    cgroup_name = format!("{}/imp-vm-{}", base, vmid);
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
    /// # use imp_testing::orchestrator::{TestVm, VmidAllocator};
    /// # use imp_testing::config::{VmConfig, RootfsSource};
    /// # use imp_testing::vmm::CidAllocator;
    /// # use imp_testing::vmm::cloud_hypervisor::CloudHypervisor;
    /// # async fn run() {
    /// let vmm = CloudHypervisor::new("cloud-hypervisor");
    /// let cfg = VmConfig::builder(PathBuf::from("/vmlinux"), RootfsSource::VirtioFs { dir: PathBuf::from("/rootfs") }).build().unwrap();
    /// let cid_alloc = std::sync::Arc::new(CidAllocator::new());
    /// let vmid_alloc = VmidAllocator::new();
    /// let vm = TestVm::start(&vmm, cfg, cid_alloc.clone(), vmid_alloc, Box::new(imp_testing::metrics::DefaultCgroupFs::default())).await.unwrap();
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
        let mut env =
            Self::setup_env(vmid.vmid, &cfg, cid_alloc.clone(), cgroup_fs.clone()).await?;

        let mut instance = vmm.create(&cfg, &env.res, &*cgroup_fs).await?;
        info!("Booting instance...");
        instance.boot().await?;
        info!("Instance booted.");
        // Success: ownership of the slice transfers to the returned TestVm,
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
            cid: Some(env.cid_guard),
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
    /// # use imp_testing::orchestrator::{TestVm, VmidAllocator};
    /// # use imp_testing::config::{VmConfig, RootfsSource};
    /// # use imp_testing::vmm::CidAllocator;
    /// # use imp_testing::vmm::cloud_hypervisor::CloudHypervisor;
    /// # async fn run() {
    /// let vmm = CloudHypervisor::new("cloud-hypervisor");
    /// let cfg = VmConfig::builder(PathBuf::from("/vmlinux"), RootfsSource::Erofs { image: PathBuf::from("/rootfs.erofs") }).build().unwrap();
    /// let cid_alloc = std::sync::Arc::new(CidAllocator::new());
    /// let vmid_alloc = VmidAllocator::new();
    /// let snap_dir = PathBuf::from("/tmp/snap");
    /// let vm = TestVm::restore(&vmm, &snap_dir, cfg, cid_alloc.clone(), vmid_alloc, Box::new(imp_testing::metrics::DefaultCgroupFs::default())).await.unwrap();
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
        if matches!(cfg.rootfs, crate::config::RootfsSource::VirtioFs { .. }) {
            return Err(crate::error::Error::Config(
                "virtio-fs rootfs cannot be used with snapshot restore".into(),
            ));
        }

        if matches!(cfg.net, crate::config::NetConfig::Rootless { .. }) {
            return Err(crate::error::Error::Config(
                "rootless networking cannot be used with snapshot restore".into(),
            ));
        }

        // Snapshot-eligibility law: a virtio-fs data share is served by
        // virtiofsd (a vhost-user device), which a snapshot-eligible VM must
        // not attach. Reject it here (enforced in code, not just docs).
        if !cfg.shares.is_empty() {
            return Err(crate::error::Error::Config(
                "virtio-fs data shares cannot be used with snapshot restore".into(),
            ));
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
        let mut env =
            Self::setup_env(vmid.vmid, &cfg, cid_alloc.clone(), cgroup_fs.clone()).await?;

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
            cid: Some(env.cid_guard),
        })
    }

    /// Connects to the VM agent, returning a mutable reference to the client.
    ///
    /// # Errors
    /// Returns an error if the agent connection or handshake fails.
    /// Gets the agent client, waiting for the connection if necessary.
    ///
    /// # Panics
    /// Panics if the VM instance is missing.
    ///
    /// # Errors
    /// Returns an error if the connection fails or times out.
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
            self.restored = false;

            // No explicit reconnect here: this `agent()` is the first call after
            // restore (agent_client started `None`), so the `connect()` above
            // already IS the post-restore connection. CH re-creates the vhost-vsock
            // device on `--restore`, so the guest's pre-snapshot listener goes deaf;
            // the guest agent re-binds its listener on idle (see `serve_vsock` in
            // imp-guest-agent), and `AgentClient::connect` retries with backoff
            // until that fresh listener accepts. A second, overlapping connect would
            // be redundant.

            // Automatically resync guest clock forward
            let host_time = clock
                .now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            tracing::info!(
                "Automatically resyncing guest clock to host time: {}",
                host_time
            );
            let outcome = agent_ref
                .exec(crate::agent::ExecRequest::new(vec![
                    "date".to_string(),
                    "-s".to_string(),
                    format!("@{}", host_time),
                ]))
                .await?;
            if outcome.code != 0 {
                tracing::warn!(
                    "Failed to automatically resync guest clock: {}",
                    String::from_utf8_lossy(&outcome.stderr)
                );
            }

            // Best-effort re-seed of the guest CSPRNG from the virtio-rng
            // device after restore (the snapshot may have captured RNG state).
            // Surface failures rather than silently discarding the Result.
            match agent_ref
                .exec(crate::agent::ExecRequest::new(vec![
                    "sh".into(),
                    "-c".into(),
                    "head -c 32 /dev/hwrng > /dev/urandom".into(),
                ]))
                .await
            {
                Ok(outcome) if outcome.code != 0 => {
                    tracing::warn!(
                        "restore RNG reseed failed (exit {}): {}",
                        outcome.code,
                        String::from_utf8_lossy(&outcome.stderr)
                    );
                }
                Err(e) => {
                    tracing::warn!("restore RNG reseed could not be executed: {}", e);
                }
                _ => {}
            }

            let mac = crate::net::mac_math(self.vmid.as_ref().expect("vmid missing").vmid)
                .map_err(|e| crate::error::Error::Agent(format!("mac math: {}", e)))?;
            let (gateway, _guest_ip, ip) =
                crate::net::ip_math(self.vmid.as_ref().expect("vmid missing").vmid)
                    .map_err(|e| crate::error::Error::Agent(format!("ip math: {}", e)))?;
            // NOTE: re-running `ip` inside the guest on restore diverges from the
            // zero-netlink-in-PID-1 invariant; it is a documented last-resort
            // fallback for rotating the guest network identity after a snapshot
            // restore until device-layer rotation lands (see
            // implementation-notes.md). `ip addr flush` drops the IP-PNP default
            // route, so it MUST be re-added via the /30 gateway, otherwise
            // post-restore egress to non-local destinations breaks. The Result
            // is surfaced rather than discarded.
            match agent_ref
                .exec(crate::agent::ExecRequest::new(vec![
                    "sh".into(),
                    "-c".into(),
                    format!(
                        "ip link set eth0 address {mac} && ip addr flush dev eth0 && ip addr add {ip} dev eth0 && ip route add default via {gateway} dev eth0"
                    ),
                ]))
                .await
            {
                Ok(outcome) if outcome.code != 0 => {
                    tracing::warn!(
                        "restore network bring-up failed (exit {}): {}",
                        outcome.code,
                        String::from_utf8_lossy(&outcome.stderr)
                    );
                }
                Err(e) => {
                    tracing::warn!("restore network bring-up could not be executed: {}", e);
                }
                _ => {}
            }
        }

        Ok(agent_ref)
    }

    /// Retrieves resource usage metrics for the VM.
    ///
    /// # Errors
    /// Returns an error if metrics collection fails.
    pub async fn usage(&self) -> Result<ResourceUsage> {
        if let (Some(cg_name), Some(fs)) = (&self.cgroup_name, &self.cgroup_fs) {
            fs.read_stats(cg_name)
        } else {
            Ok(ResourceUsage::default())
        }
    }

    /// Shuts down the VM and cleans up associated resources.
    ///
    /// # Errors
    /// Returns an error if shutting down the VM or proxy fails.
    pub async fn shutdown(mut self) -> Result<()> {
        if let Some(mut inst) = self.instance.take() {
            let _ = inst.request_shutdown().await;

            // Actually wait for it to stop to prevent zombie and ebusy
            let _ = inst.kill().await;
        }

        if let Some(mut ns) = self.netns.take() {
            let _ = ns.delete();
        }
        if let (Some(cg_name), Some(fs)) = (self.cgroup_name.take(), self.cgroup_fs.take()) {
            let _ = fs.delete_slice(&cg_name);
        }
        #[cfg(feature = "net-unprivileged")]
        let _ = self.smoltcp.take();
        let _ = self.proxy.take();
        Ok(())
    }
}

impl<V: Vmm> Drop for TestVm<V> {
    fn drop(&mut self) {
        // Enforce teardown order: VMM instance -> virtiofsd -> netns/cgroup/overlay/sockets
        drop(self.instance.take());

        #[cfg(feature = "net-unprivileged")]
        drop(self.smoltcp.take());
        drop(self.proxy.take());
        if let Some(mut ns) = self.netns.take() {
            let _ = ns.delete();
        }
        if let (Some(cg_name), Some(fs)) = (self.cgroup_name.take(), self.cgroup_fs.take()) {
            let _ = fs.delete_slice(&cg_name);
        }
        drop(self.cid.take());
        drop(self.vmid.take());
    }
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

    // CONFIG-ERROR-ORCH-6. Buggy impl: a process-global `/tmp/imp-vmid-*.lock`
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
        let res = TestVm::<CreateFailVmm>::start(
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
        let vm = TestVm::start(
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
        let res = TestVm::start(
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
    // rootfs and rootless net, letting a virtio-fs data Share (a vhost-user
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
        let res = TestVm::restore(
            &vmm,
            std::path::Path::new("/fake/snap"),
            cfg,
            cid_alloc,
            vmid_alloc,
            Box::new(crate::metrics::FakeCgroupFs::new()),
        )
        .await;
        assert!(matches!(res, Err(crate::error::Error::Config(_))));
    }
}
