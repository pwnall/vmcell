use crate::agent::AgentClient;
use crate::config::VmConfig;
use crate::error::Result;
use crate::metrics::ResourceUsage;
use crate::net::{NetNamespace, PasstProcess};
use crate::proxy::{EgressProxy, ProxyConfig};
use crate::vmm::{PerVmResources, VmInstance, Vmm};
use cgroups_rs::{cgroup_builder::CgroupBuilder, hierarchies};
use std::sync::atomic::{AtomicU32, Ordering};

static VMID_COUNTER: AtomicU32 = AtomicU32::new(1);

pub struct TestVm<V: Vmm> {
    pub vmid: u32,
    pub instance: V::Instance,
    pub netns: Option<NetNamespace>,
    pub passt: Option<PasstProcess>,
    pub proxy: Option<EgressProxy>,
}

impl<V: Vmm> TestVm<V> {
    pub async fn start(vmm: &V, cfg: VmConfig) -> Result<Self> {
        let pid = std::process::id() % 25;
        let c = VMID_COUNTER.fetch_add(1, Ordering::SeqCst);
        let vmid = pid * 10 + c;

        let mut netns = None;
        let mut passt = None;
        let mut proxy = None;
        let mut tap_name = None;
        let mut netns_name = None;
        let mut passt_socket = None;

        match &cfg.net {
            crate::config::NetConfig::Privileged { egress, host_services } => {
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
            crate::config::NetConfig::Rootless { egress, host_services } => {
                let _ = egress;
                let _ = host_services;
                let px = EgressProxy::start(ProxyConfig {
                    port: 0,
                    netns: None,
                }).await?;
                let p = PasstProcess::start(vmid)?;
                passt_socket = Some(p.socket_path.clone());
                passt = Some(p);
                proxy = Some(px);
            }
            crate::config::NetConfig::None => {}
        }

        let cgroup_name = format!("imp-vm-{}", vmid);
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
            passt_socket,
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
            passt,
            proxy,
        })
    }

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

    pub async fn usage(&self) -> Result<ResourceUsage> {
        self.instance.stats().await
    }

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
