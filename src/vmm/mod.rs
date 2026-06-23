use crate::config::VmConfig;
use crate::error::Result;
use crate::metrics::ResourceUsage;
/// Cloud Hypervisor VMM backend implementation.
pub mod cloud_hypervisor;

use async_trait::async_trait;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

static NEXT_CID: AtomicU32 = AtomicU32::new(3);

/// Allocates unique Context IDs (CIDs) for vsock connections.
/// CIDs >= 3 are available for guests.
pub struct CidAllocator;

impl CidAllocator {
    /// Allocates and returns the next available unique CID.
    pub fn allocate() -> u32 {
        NEXT_CID.fetch_add(1, Ordering::SeqCst)
    }
}

/// Per-VM resources allocated by the orchestrator before VM creation.
pub struct PerVmResources {
    /// Name of the cgroup v2 slice for the VM.
    pub cgroup_name: String,
    /// Optional TAP interface name for privileged networking.
    pub tap_name: Option<String>,
    /// Optional network namespace name for privileged networking.
    pub netns_name: Option<String>,
    /// Optional vhost-user socket path for rootless networking.
    pub vhost_user_socket: Option<PathBuf>,
    /// Unique internal VM ID.
    pub vmid: u32,
}

/// Abstract Virtual Machine Monitor (VMM) trait.
#[async_trait]
pub trait Vmm: Send + Sync {
    /// The associated instance type representing a running VM.
    type Instance: VmInstance;

    /// Creates a new VM instance with the given configuration and resources.
    ///
    /// # Errors
    /// Returns an error if the VMM process fails to start or configuration is invalid.
    async fn create(&self, cfg: &VmConfig, res: &PerVmResources) -> Result<Self::Instance>;
}

/// Represents a running or created VM instance.
#[async_trait]
pub trait VmInstance: Send {
    /// Boots the VM from a created state.
    ///
    /// # Errors
    /// Returns an error if the boot process fails.
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
    /// Pauses the VM, preparing it for a snapshot.
    ///
    /// # Errors
    /// Returns an error if pausing fails.
    async fn pause(&mut self) -> Result<()>;
    /// Resumes the VM after it was paused or snapshotted.
    ///
    /// # Errors
    /// Returns an error if resuming fails.
    async fn resume(&mut self) -> Result<()>;
    /// Snapshots the VM state to the specified directory.
    ///
    /// # Errors
    /// Returns an error if the snapshot operation fails.
    async fn snapshot(&mut self, dir: &Path) -> Result<()>;
    /// Retrieves live statistics and resource usage for the VM.
    ///
    /// # Errors
    /// Returns an error if stats cannot be collected.
    async fn stats(&self) -> Result<ResourceUsage>;
    /// Returns the path to the AF_UNIX socket for vsock communication.
    fn vsock_path(&self) -> &Path;
    /// Returns the unique vsock Context ID (CID) assigned to this VM.
    fn guest_cid(&self) -> u32;
    /// Returns the path to the VM's serial log file.
    fn serial_log(&self) -> &Path;
}

/// A fake VMM for testing without booting a real VM.
#[derive(Default)]
pub struct FakeVmm {}

/// A fake VM instance for testing.
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
    async fn pause(&mut self) -> Result<()> {
        Ok(())
    }
    async fn resume(&mut self) -> Result<()> {
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
    fn guest_cid(&self) -> u32 {
        3
    }
    fn serial_log(&self) -> &Path {
        &self.serial
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cid_allocator() {
        let cid1 = CidAllocator::allocate();
        let cid2 = CidAllocator::allocate();
        assert!(cid1 >= 3);
        assert!(cid2 > cid1);
    }
}
