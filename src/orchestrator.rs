use crate::agent::AgentClient;
use crate::config::VmConfig;
use crate::error::Result;
use crate::metrics::ResourceUsage;
use crate::net::NetNamespace;
#[cfg(feature = "experiment-smoltcp")]
use crate::net::SmoltcpProcess;
use crate::proxy::{EgressProxy, ProxyConfig};
use crate::vmm::{PerVmResources, VmInstance, Vmm};
use cgroups_rs::{cgroup_builder::CgroupBuilder, hierarchies};
use std::sync::atomic::{AtomicU32, Ordering};

static VMID_COUNTER: AtomicU32 = AtomicU32::new(1);

/// Represents a fully managed test VM, including its associated resources and VMM instance.
pub struct TestVm<V: Vmm> {
    /// The internal unique ID assigned to this VM.
    pub vmid: u32,
    /// The underlying VMM instance running the VM.
    pub instance: V::Instance,
    /// The network namespace associated with this VM, if any.
    pub netns: Option<NetNamespace>,
    #[cfg(feature = "experiment-smoltcp")]
    /// The smoltcp userspace networking process associated with this VM, if any.
    pub smoltcp: Option<SmoltcpProcess>,
    /// The egress proxy associated with this VM, if any.
    pub proxy: Option<EgressProxy>,
}

impl<V: Vmm> TestVm<V> {
    /// Starts a new test VM using the provided VMM and configuration.
    ///
    /// # Errors
    /// Returns an error if the VM cannot be started or resources cannot be allocated.
    pub async fn start(vmm: &V, cfg: VmConfig) -> Result<Self> {
        let pid = std::process::id() % 25;
        let c = VMID_COUNTER.fetch_add(1, Ordering::SeqCst);
        let vmid = pid * 10 + c;

        let mut netns = None;
        #[cfg(feature = "experiment-smoltcp")]
        let mut smoltcp = None;
        let mut proxy = None;
        let mut tap_name = None;
        let mut netns_name = None;
        #[allow(unused_mut)]
        let mut vhost_user_socket = None;

        match &cfg.net {
            crate::config::NetConfig::Privileged {
                egress,
                host_services,
            } => {
                let _ = egress;
                let _ = host_services;
                let ns = NetNamespace::create(vmid)?;
                tap_name = Some(ns.tap_name.clone());
                netns_name = Some(ns.name.clone());

                let px = EgressProxy::start(ProxyConfig {
                    port: 0,
                    netns: Some(ns.name.clone()),
                })
                .await?;
                ns.emit_proxy_rules(px.port)?;

                proxy = Some(px);
                netns = Some(ns);
            }
            crate::config::NetConfig::Rootless {
                egress,
                host_services,
            } => {
                let _ = egress;
                let _ = host_services;
                let px = EgressProxy::start(ProxyConfig {
                    port: 0,
                    netns: None,
                })
                .await?;
                
                #[cfg(feature = "experiment-smoltcp")]
                {
                    let socket_path = std::path::PathBuf::from(format!("/tmp/imp-smoltcp-{}.sock", vmid));
                    let mut ports = vec![px.port];
                    if *host_services {
                        ports.push(8080);
                    }
                    let p = SmoltcpProcess::start(vmid, ports, socket_path.clone());
                    vhost_user_socket = Some(socket_path);
                    smoltcp = Some(p);
                }
                proxy = Some(px);
            }
            crate::config::NetConfig::None => {}
        }

        let mut cgroup_name = format!("imp-vm-{}", vmid);
        // Try to nest inside our current cgroup slice if possible
        if let Ok(cgroup_str) = std::fs::read_to_string("/proc/self/cgroup") {
            if let Some(path) = cgroup_str.trim().split("0::").nth(1) {
                let mut base = path.trim_start_matches('/');
                // If running under a "supervisor" cgroup to satisfy the "no internal processes" rule,
                // create the VM cgroup as a sibling rather than a child.
                if base.ends_with("/supervisor") {
                    base = base.trim_end_matches("/supervisor");
                }
                if !base.is_empty() {
                    cgroup_name = format!("{}/imp-vm-{}", base, vmid);
                }
            }
        }

        let mut builder = CgroupBuilder::new(&cgroup_name);
        if let Some(mem) = cfg.limits.mem_max_mib {
            builder = builder
                .memory()
                .memory_hard_limit((mem as i64) << 20)
                .done();
        }
        let _cg = builder.build(Box::new(hierarchies::V2::new()));

        let res = PerVmResources {
            cgroup_name: cgroup_name.clone(),
            tap_name,
            netns_name,
            vhost_user_socket,
            vmid,
        };
        println!("Creating instance...");
        let mut instance = vmm.create(&cfg, &res).await?;
        println!("Booting instance...");
        instance.boot().await?;
        println!("Instance booted.");
        Ok(Self {
            vmid,
            instance,
            netns,
            #[cfg(feature = "experiment-smoltcp")]
            smoltcp,
            proxy,
        })
    }

    /// Connects to the guest agent running inside the VM and returns an API client.
    ///
    /// # Errors
    /// Returns an error if the connection cannot be established.
    pub async fn agent(&mut self) -> Result<AgentClient> {
        // Retry connecting since the VM might take a second to boot and bind vsock
        for _ in 0..50 {
            if let Ok(client) = AgentClient::connect(self.instance.vsock_path(), 5000).await {
                return Ok(client);
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        }
        AgentClient::connect(self.instance.vsock_path(), 5000).await
    }

    /// Retrieves resource usage statistics for the VM.
    ///
    /// # Errors
    /// Returns an error if the stats cannot be collected.
    pub async fn usage(&self) -> Result<ResourceUsage> {
        self.instance.stats().await
    }

    /// Gracefully shuts down the VM, cleaning up all associated resources.
    ///
    /// # Errors
    /// Returns an error if the shutdown times out or fails.
    pub async fn shutdown(mut self) -> Result<()> {
        self.instance.request_shutdown().await?;
        if let Some(ns) = &self.netns {
            let _ = ns.delete();
        }
        // Actually wait for it to stop then delete cgroup
        let _ = self.instance.kill().await;
        Ok(())
    }
}
