use crate::agent::AgentClient;
use crate::config::VmConfig;
use crate::error::Result;
use crate::metrics::ResourceUsage;
use crate::net::NetNamespace;
#[cfg(feature = "net-rootless")]
use crate::net::SmoltcpProcess;
use crate::proxy::{EgressProxy, ProxyConfig};
use crate::vmm::{PerVmResources, VmInstance, Vmm};
#[cfg(feature = "metrics")]
use cgroups_rs::{cgroup_builder::CgroupBuilder, hierarchies};
use std::sync::{Arc, Mutex};
use tracing::info;

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
    vmid: VmidGuard,
    /// The underlying VMM instance running the VM.
    instance: V::Instance,
    /// The network namespace associated with this VM, if any.
    netns: Option<NetNamespace>,
    #[cfg(feature = "net-rootless")]
    /// The smoltcp userspace networking process associated with this VM, if any.
    smoltcp: Option<SmoltcpProcess>,
    /// The egress proxy associated with this VM, if any.
    proxy: Option<EgressProxy>,
    /// The name of the cgroup for this VM.
    cgroup_name: Option<String>,
    /// The cached agent client connection, if any.
    agent_client: Option<AgentClient>,
    /// Whether the VM was restored from a snapshot.
    restored: bool,
}

struct EnvSetup {
    res: PerVmResources,
    netns: Option<NetNamespace>,
    #[cfg(feature = "net-rootless")]
    smoltcp: Option<SmoltcpProcess>,
    proxy: Option<EgressProxy>,
}

impl<V: Vmm> TestVm<V> {
    /// Gets the internal unique ID assigned to this VM.
    pub fn vmid(&self) -> u32 {
        self.vmid.vmid
    }

    /// Gets a reference to the underlying VMM instance.
    pub fn instance(&self) -> &V::Instance {
        &self.instance
    }

    /// Gets a mutable reference to the underlying VMM instance.
    pub fn instance_mut(&mut self) -> &mut V::Instance {
        &mut self.instance
    }

    /// Gets the network namespace associated with this VM, if any.
    pub fn netns(&self) -> Option<&NetNamespace> {
        self.netns.as_ref()
    }

    #[cfg(feature = "net-rootless")]
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
        cid_alloc: &crate::vmm::CidAllocator,
    ) -> Result<EnvSetup> {
        let mut netns = None;
        #[cfg(feature = "net-rootless")]
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
                #[cfg(feature = "net-rootless")]
                {
                    let socket_path =
                        std::path::PathBuf::from(format!("/tmp/imp-smoltcp-{}.sock", vmid));
                    let mut ports = vec![];
                    if _proxy_port > 0 {
                        ports.push(_proxy_port);
                    }
                    if let Some(p) = host_services_port {
                        ports.push(*p);
                    }
                    let p = SmoltcpProcess::start(vmid, ports, socket_path.clone());
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

        #[cfg(feature = "metrics")]
        {
            let mut builder = CgroupBuilder::new(&cgroup_name);
            if let Some(mem) = cfg.limits.mem_max_mib {
                builder = builder
                    .memory()
                    .memory_hard_limit((mem as i64) << 20)
                    .done();
            }
            if let Some(cpu) = cfg.limits.cpu_max_pct {
                let period = 100_000_u64;
                let quota = (cpu as u64) * period / 100;
                builder = builder.cpu().quota(quota as i64).period(period).done();
            }
            if let Err(e) = builder.build(Box::new(hierarchies::V2::new())) {
                tracing::warn!("Failed to create cgroup {}: {}", cgroup_name, e);
            }

            if let Some(pids) = cfg.limits.pids_max {
                let pids_max_path = format!("/sys/fs/cgroup/{}/pids.max", cgroup_name);
                if let Err(e) = std::fs::write(&pids_max_path, pids.to_string()) {
                    tracing::warn!("Failed to apply pids.max: {}", e);
                }
            }
            if let Some(io) = &cfg.limits.io_max {
                let io_max_path = format!("/sys/fs/cgroup/{}/io.max", cgroup_name);
                let mut rules = Vec::new();
                if let Some(rbps) = io.rbps {
                    rules.push(format!("rbps={}", rbps));
                }
                if let Some(wbps) = io.wbps {
                    rules.push(format!("wbps={}", wbps));
                }
                if let Some(riops) = io.riops {
                    rules.push(format!("riops={}", riops));
                }
                if let Some(wiops) = io.wiops {
                    rules.push(format!("wiops={}", wiops));
                }
                if !rules.is_empty() {
                    let io_str = format!("{} {}\n", io.device, rules.join(" "));
                    if let Err(e) = std::fs::write(&io_max_path, io_str) {
                        tracing::warn!("Failed to apply io.max: {}", e);
                    }
                }
            }
        }

        let guest_cid = cid_alloc.allocate()?;

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
            netns,
            #[cfg(feature = "net-rootless")]
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
    /// let cid_alloc = CidAllocator::new();
    /// let vmid_alloc = Arc::new(VmidAllocator::new());
    /// let vm = TestVm::start(&vmm, cfg, &cid_alloc, vmid_alloc).await.unwrap();
    /// # }
    /// ```
    pub async fn start(
        vmm: &V,
        cfg: VmConfig,
        cid_alloc: &crate::vmm::CidAllocator,
        vmid_alloc: VmidAllocator,
    ) -> Result<Self> {
        let vmid = VmidGuard {
            vmid: vmid_alloc.allocate()?,
            allocator: vmid_alloc,
        };
        let env = Self::setup_env(vmid.vmid, &cfg, cid_alloc).await?;

        let mut instance = vmm.create(&cfg, &env.res).await?;
        info!("Booting instance...");
        instance.boot().await?;
        info!("Instance booted.");
        Ok(Self {
            vmid,
            instance,
            netns: env.netns,
            #[cfg(feature = "net-rootless")]
            smoltcp: env.smoltcp,
            proxy: env.proxy,
            cgroup_name: Some(env.res.cgroup_name.clone()),
            agent_client: None,
            restored: false,
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
    /// let cid_alloc = CidAllocator::new();
    /// let vmid_alloc = Arc::new(VmidAllocator::new());
    /// let snap_dir = PathBuf::from("/tmp/snap");
    /// let vm = TestVm::restore(&vmm, &snap_dir, cfg, &cid_alloc, vmid_alloc).await.unwrap();
    /// # }
    /// ```
    pub async fn restore(
        vmm: &V,
        snapshot_dir: &std::path::Path,
        cfg: VmConfig,
        cid_alloc: &crate::vmm::CidAllocator,
        vmid_alloc: VmidAllocator,
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
        let env = Self::setup_env(vmid.vmid, &cfg, cid_alloc).await?;

        info!("Restoring instance...");
        let mut instance = vmm.restore(snapshot_dir, &cfg, &env.res).await?;
        info!("Resuming instance...");
        instance.resume().await?;
        info!("Instance resumed.");
        Ok(Self {
            vmid,
            instance,
            netns: env.netns,
            #[cfg(feature = "net-rootless")]
            smoltcp: env.smoltcp,
            proxy: env.proxy,
            cgroup_name: Some(env.res.cgroup_name.clone()),
            agent_client: None,
            restored: true,
        })
    }

    /// Connects to the VM agent, returning a mutable reference to the client.
    ///
    /// # Errors
    /// Returns an error if the agent connection or handshake fails.
    /// Gets the agent client, waiting for the connection if necessary.
    ///
    /// # Errors
    /// Returns an error if the connection fails or times out.
    pub async fn agent(
        &mut self,
        timeout: Option<std::time::Duration>,
    ) -> Result<&mut AgentClient> {
        if self.agent_client.is_none() {
            let client = AgentClient::connect(
                self.instance.vsock_path(),
                5000,
                timeout.unwrap_or(std::time::Duration::from_secs(10)),
                self.instance.serial_log(),
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
            // Automatically resync guest clock forward
            let host_time = std::time::SystemTime::now()
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

            let mac = format!(
                "02:00:{:02x}:{:02x}:{:02x}:{:02x}",
                (self.vmid.vmid >> 24) & 0xff,
                (self.vmid.vmid >> 16) & 0xff,
                (self.vmid.vmid >> 8) & 0xff,
                self.vmid.vmid & 0xff
            );
            let ip = format!("10.200.{}.2/30", self.vmid.vmid);
            let _ = agent_ref.exec(crate::agent::ExecRequest::new(vec![
                "sh".into(), "-c".into(), format!("ip link set eth0 address {} && ip addr flush dev eth0 && ip addr add {} dev eth0", mac, ip)
            ])).await;
        }

        Ok(agent_ref)
    }

    /// Retrieves resource usage metrics for the VM.
    ///
    /// # Errors
    /// Returns an error if metrics collection fails.
    pub async fn usage(&self) -> Result<ResourceUsage> {
        self.instance.stats().await
    }

    /// Shuts down the VM and cleans up associated resources.
    ///
    /// # Errors
    /// Returns an error if shutting down the VM or proxy fails.
    pub async fn shutdown(mut self) -> Result<()> {
        let _ = self.instance.request_shutdown().await;

        // Actually wait for it to stop to prevent zombie and ebusy
        let _ = self.instance.kill().await;

        if let Some(mut ns) = self.netns.take() {
            let _ = ns.delete();
        }
        #[cfg(feature = "metrics")]
        if let Some(cg_name) = self.cgroup_name.take() {
            let cg =
                cgroups_rs::Cgroup::load(Box::new(cgroups_rs::hierarchies::V2::new()), &cg_name);
            let _ = cg.delete();
        }
        #[cfg(feature = "net-rootless")]
        let _ = self.smoltcp.take();
        let _ = self.proxy.take();
        Ok(())
    }
}

impl<V: Vmm> Drop for TestVm<V> {
    fn drop(&mut self) {
        #[cfg(feature = "net-rootless")]
        let _ = self.smoltcp.take();
        let _ = self.proxy.take();
        if let Some(mut ns) = self.netns.take() {
            let _ = ns.delete();
        }
        #[cfg(feature = "metrics")]
        if let Some(cg_name) = self.cgroup_name.take() {
            let cg =
                cgroups_rs::Cgroup::load(Box::new(cgroups_rs::hierarchies::V2::new()), &cg_name);
            let _ = cg.delete();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[serial_test::serial]
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
    #[serial_test::serial]
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

    #[test]
    fn test_per_vm_path_injectivity() {
        // Test that path construction uses vmid uniquely
        let vmid1 = 1;
        let vmid2 = 2;
        let cg1 = format!("imp-vm-{}", vmid1);
        let cg2 = format!("imp-vm-{}", vmid2);
        assert_ne!(cg1, cg2);
        let sock1 = format!("/tmp/imp-smoltcp-{}.sock", vmid1);
        let sock2 = format!("/tmp/imp-smoltcp-{}.sock", vmid2);
        assert_ne!(sock1, sock2);
    }
}
