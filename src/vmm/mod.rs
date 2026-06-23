use crate::config::VmConfig;
use crate::error::Result;
use crate::metrics::ResourceUsage;
pub mod cloud_hypervisor;

use async_trait::async_trait;
use std::path::{Path, PathBuf};

pub struct PerVmResources {
    pub cgroup_name: String,
    pub tap_name: Option<String>,
    pub netns_name: Option<String>,
    pub passt_socket: Option<PathBuf>,
    pub vmid: u32,
}

#[async_trait]
pub trait Vmm: Send + Sync {
    type Instance: VmInstance;

    async fn create(&self, cfg: &VmConfig, res: &PerVmResources) -> Result<Self::Instance>;
}

#[async_trait]
pub trait VmInstance: Send {
    async fn boot(&mut self) -> Result<()>;
    async fn request_shutdown(&mut self) -> Result<()>;
    async fn kill(&mut self) -> Result<()>;
    async fn snapshot(&mut self, dir: &Path) -> Result<()>;
    async fn stats(&self) -> Result<ResourceUsage>;
    fn vsock_path(&self) -> &Path;
    fn serial_log(&self) -> &Path;
}

#[derive(Default)]
pub struct FakeVmm {}

pub struct FakeVmInstance {
    vsock: PathBuf,
    serial: PathBuf,
}

#[async_trait]
impl Vmm for FakeVmm {
    type Instance = FakeVmInstance;

    async fn create(&self, _cfg: &VmConfig, _res: &PerVmResources) -> Result<Self::Instance> {
        Ok(FakeVmInstance {
            vsock: PathBuf::from("/tmp/fake-vsock"),
            serial: PathBuf::from("/tmp/fake-serial"),
        })
    }
}

#[async_trait]
impl VmInstance for FakeVmInstance {
    async fn boot(&mut self) -> Result<()> {
        Ok(())
    }
    async fn request_shutdown(&mut self) -> Result<()> {
        Ok(())
    }
    async fn kill(&mut self) -> Result<()> {
        Ok(())
    }
    async fn snapshot(&mut self, _dir: &Path) -> Result<()> {
        Ok(())
    }
    async fn stats(&self) -> Result<ResourceUsage> {
        Ok(ResourceUsage {
            mem_peak_mib: 0,
            mem_current_mib: 0,
            cpu_usec: 0,
            io_read_bytes: 0,
            io_write_bytes: 0,
            net_rx_bytes: 0,
            net_tx_bytes: 0,
        })
    }
    fn vsock_path(&self) -> &Path {
        &self.vsock
    }
    fn serial_log(&self) -> &Path {
        &self.serial
    }
}
