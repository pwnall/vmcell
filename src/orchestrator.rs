use crate::agent::AgentClient;
use crate::config::VmConfig;
use crate::error::Result;
use crate::metrics::ResourceUsage;
use crate::net::NetNamespace;
#[cfg(feature = "net-unprivileged")]
use crate::net::SmoltcpProcess;
use crate::proxy::{EgressProxy, ProxyConfig};
use crate::vmm::{PerVmResources, VmInstance, Vmm};
#[cfg(feature = "metrics")]
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
#[derive(Debug, Clone, Default)]
pub struct VmidAllocator {
    active: Arc<Mutex<std::collections::BTreeSet<u32>>>,
}

impl VmidAllocator {
    /// Creates a new VMID allocator.
    #[must_use]
    pub fn new() -> Self {
        Self {
            active: Arc::new(Mutex::new(std::collections::BTreeSet::new())),
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
            if !active.contains(&vmid) {
                let lock_path = format!("/tmp/imp-vmid-{}.lock", vmid);
                if std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&lock_path)
                    .is_ok()
                {
                    active.insert(vmid);
                    return Ok(vmid);
                }
            }
        }
        Err(crate::error::Error::Exhaustion(
            "No available VMIDs (limit 254)".to_string(),
        ))
    }

    /// Releases a previously allocated VMID.
    pub fn release(&self, vmid: u32) {
        let mut active = self.active.lock().unwrap_or_else(|e| e.into_inner());
        active.remove(&vmid);
        let lock_path = format!("/tmp/imp-vmid-{}.lock", vmid);
        let _ = std::fs::remove_file(&lock_path);
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
    cgroup_fs: Option<Box<dyn crate::metrics::CgroupFs>>,
    /// The cached agent client connection, if any.
    agent_client: Option<AgentClient>,
    /// Whether the VM was restored from a snapshot.
    restored: bool,
    /// The CID guard.
    cid: Option<CidGuard>,
}

struct EnvSetup {
    res: PerVmResources,
    cid_guard: CidGuard,
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
        cgroup_fs: &dyn crate::metrics::CgroupFs,
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
        let vmid = VmidGuard {
            vmid: vmid_alloc.allocate()?,
            allocator: vmid_alloc,
        };
        let env = Self::setup_env(vmid.vmid, &cfg, cid_alloc.clone(), &*cgroup_fs).await?;

        let mut instance = vmm.create(&cfg, &env.res, &*cgroup_fs).await?;
        info!("Booting instance...");
        instance.boot().await?;
        info!("Instance booted.");
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

        let vmid = VmidGuard {
            vmid: vmid_alloc.allocate()?,
            allocator: vmid_alloc,
        };
        let env = Self::setup_env(vmid.vmid, &cfg, cid_alloc.clone(), &*cgroup_fs).await?;

        info!("Restoring instance...");
        let mut instance = vmm
            .restore(snapshot_dir, &cfg, &env.res, &*cgroup_fs)
            .await?;
        info!("Resuming instance...");
        instance.resume().await?;
        info!("Instance resumed.");
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

            agent_ref
                .reconnect(
                    self.instance
                        .as_ref()
                        .expect("instance missing")
                        .vsock_path(),
                    5000,
                    &crate::vmm::RealSerialLog {
                        path: self
                            .instance
                            .as_ref()
                            .expect("instance missing")
                            .serial_log()
                            .to_path_buf(),
                    },
                    timeout.unwrap_or(std::time::Duration::from_secs(10)),
                )
                .await?;

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

            let _ = agent_ref
                .exec(crate::agent::ExecRequest::new(vec![
                    "sh".into(),
                    "-c".into(),
                    "head -c 32 /dev/hwrng > /dev/urandom".into(),
                ]))
                .await;

            let mac = crate::net::mac_math(self.vmid.as_ref().expect("vmid missing").vmid)
                .map_err(|e| crate::error::Error::Agent(format!("mac math: {}", e)))?;
            let (_, _, ip) = crate::net::ip_math(self.vmid.as_ref().expect("vmid missing").vmid)
                .map_err(|e| crate::error::Error::Agent(format!("ip math: {}", e)))?;
            let _ = agent_ref.exec(crate::agent::ExecRequest::new(vec![
                "sh".into(), "-c".into(), format!("ip link set eth0 address {} && ip addr flush dev eth0 && ip addr add {} dev eth0", mac, ip)
            ])).await;
        }

        Ok(agent_ref)
    }

    /// Retrieves resource usage metrics for the VM.
    ///
    /// # Panics
    /// Panics if the VM instance is missing.
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
}
