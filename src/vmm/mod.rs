//! Virtual Machine Monitor (VMM) abstraction and management.
//!
//! This module provides a generic abstraction for different VMM backends
//! (like Cloud Hypervisor), as well as fake implementations for testing.

use crate::config::VmConfig;
use crate::error::Result;
use crate::metrics::ResourceUsage;
/// Cloud Hypervisor VMM backend implementation.
pub mod cloud_hypervisor;

pub use cloud_hypervisor::CloudHypervisor;

#[cfg(feature = "firecracker")]
/// Firecracker VMM backend implementation.
pub mod firecracker;

#[cfg(feature = "firecracker")]
pub use firecracker::Firecracker;

#[cfg(feature = "qemu")]
/// QEMU VMM backend implementation.
pub mod qemu;

#[cfg(feature = "qemu")]
pub use qemu::{Qemu, QemuInstance};

use serde::Serialize;
use std::path::{Path, PathBuf};

/// Helper to send an HTTP request over a Unix domain socket.
pub async fn unix_api_request<T: Serialize>(
    api_socket: &Path,
    method: &str,
    path: &str,
    body: Option<&T>,
) -> Result<()> {
    let stream = tokio::net::UnixStream::connect(api_socket)
        .await
        .map_err(|e| crate::error::Error::Vmm(format!("socket connect: {}", e)))?;

    let io = hyper_util::rt::TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
        .await
        .map_err(|e| crate::error::Error::Vmm(format!("handshake error: {}", e)))?;

    tokio::task::spawn(async move {
        if let Err(err) = conn.await {
            tracing::warn!("HTTP connection failed: {:?}", err);
        }
    });

    let body_bytes = if let Some(b) = body {
        serde_json::to_vec(b)
            .map_err(|e| crate::error::Error::Serialize(format!("serialize: {}", e)))?
    } else {
        Vec::new()
    };

    let req = hyper::Request::builder()
        .method(method)
        .uri(path)
        .header("Host", "localhost")
        .header("Content-Type", "application/json")
        .header("Accept", "application/json")
        .body(http_body_util::Full::new(hyper::body::Bytes::from(
            body_bytes,
        )))
        .map_err(|e| crate::error::Error::Vmm(format!("request builder error: {}", e)))?;

    let res = sender
        .send_request(req)
        .await
        .map_err(|e| crate::error::Error::Vmm(format!("send_request error: {}", e)))?;

    if !res.status().is_success() {
        let status = res.status();
        use http_body_util::BodyExt;
        let bytes = res
            .into_body()
            .collect()
            .await
            .map(|c| c.to_bytes())
            .unwrap_or_default();
        return Err(crate::error::Error::VmmApi {
            status: status.as_u16(),
            body: String::from_utf8_lossy(&bytes).into_owned(),
        });
    }

    Ok(())
}

/// Creates a temporary directory for a specific VM ID.
pub async fn create_vm_tmp_dir(vmid: u32) -> Result<PathBuf> {
    let tmp = std::env::temp_dir().join(format!("imp-vm-{}-{}", std::process::id(), vmid));
    tokio::fs::create_dir_all(&tmp).await?;
    Ok(tmp)
}

/// Builds a Tokio command for the VMM, handling network namespaces and process groups.
pub fn build_vmm_cmd(binary_path: &Path, netns_name: Option<&str>) -> tokio::process::Command {
    let mut std_cmd = if let Some(netns) = netns_name {
        let mut c = std::process::Command::new("ip");
        c.arg("netns").arg("exec").arg(netns).arg(binary_path);
        c
    } else {
        std::process::Command::new(binary_path)
    };
    use std::os::unix::process::CommandExt;
    std_cmd.process_group(0);
    tokio::process::Command::from(std_cmd)
}

/// Writes a PID to a cgroup's `cgroup.procs` file.
pub async fn write_cgroup_procs(cgroup_name: &str, pid: u32) {
    if !cgroup_name.is_empty() {
        let procs_path = format!("/sys/fs/cgroup/{}/cgroup.procs", cgroup_name);
        if let Err(e) = tokio::fs::write(&procs_path, pid.to_string()).await {
            tracing::error!(
                "WARNING: failed to write process {} to {}: {:?}",
                pid,
                procs_path,
                e
            );
        } else {
            tracing::info!("Added process {} to cgroup {}", pid, cgroup_name);
        }
    }
}

/// Waits until the given socket path appears, or times out. Returns true if it exists.
pub async fn wait_for_socket(socket_path: &Path, timeout_ms: u64, interval_ms: u64) -> bool {
    let iterations = timeout_ms / interval_ms;
    for _ in 0..iterations {
        if tokio::fs::try_exists(socket_path).await.unwrap_or(false) {
            return true;
        }
        tokio::time::sleep(std::time::Duration::from_millis(interval_ms)).await;
    }
    false
}

static GLOBAL_CIDS: std::sync::OnceLock<std::sync::Mutex<std::collections::BTreeSet<u32>>> =
    std::sync::OnceLock::new();

fn get_cids() -> &'static std::sync::Mutex<std::collections::BTreeSet<u32>> {
    GLOBAL_CIDS.get_or_init(|| std::sync::Mutex::new(std::collections::BTreeSet::new()))
}

/// Allocates unique Context IDs (CIDs) for vsock connections.
/// CIDs >= 3 are available for guests.
pub struct CidAllocator {}

impl CidAllocator {
    /// Creates a new CID allocator.
    #[must_use]
    pub fn new() -> Self {
        // Initialize the global CIDs if it hasn't been already.
        let _ = get_cids();
        Self {}
    }
}

impl Default for CidAllocator {
    fn default() -> Self {
        Self::new()
    }
}

impl CidAllocator {
    /// Allocates and returns a unique Context ID (CID) for VSOCK communication.
    ///
    /// # Errors
    /// Returns an error if all 252 guest CIDs are in use.
    ///
    /// # Panics
    /// Panics if the global CID allocator lock is poisoned.
    pub fn allocate(&self) -> Result<u32> {
        let mut active = get_cids().lock().expect("mutex poisoned");
        for i in 3..=254 {
            if !active.contains(&i) {
                active.insert(i);
                return Ok(i);
            }
        }
        Err(crate::error::Error::Vmm(
            "CID allocator exhausted".to_string(),
        ))
    }

    /// Releases a previously allocated CID.
    ///
    /// # Panics
    /// Panics if the global CID allocator lock is poisoned.
    pub fn release(&self, cid: u32) {
        let mut active = get_cids().lock().expect("mutex poisoned");
        active.remove(&cid);
    }
}

/// Per-VM resources allocated by the orchestrator before VM creation.
#[derive(Debug, Clone)]
#[non_exhaustive]
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
    /// Context ID for vsock communication.
    pub guest_cid: u32,
}

/// Virtual Machine Monitor (VMM) capabilities.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct VmmCapabilities {
    /// True if the VMM supports snapshot and restore.
    pub snapshot_restore: bool,
    /// True if the VMM supports lazy userfaultfd-based demand-paged restore.
    pub lazy_restore: bool,
    /// True if the VMM supports virtio-fs shared directories.
    pub virtio_fs_shares: bool,
    /// True if the VMM supports vhost-user-net for rootless networking.
    pub rootless_vhost_user_net: bool,
    /// True if the VMM supports nested virtualization (exposing KVM to guest).
    pub nested_virt: bool,
}

/// Abstract Virtual Machine Monitor (VMM) trait.
pub trait Vmm: Send + Sync {
    /// The associated instance type representing a running VM.
    type Instance: VmInstance;

    /// Creates a new VM instance with the given configuration and resources.
    ///
    /// # Errors
    /// Returns an error if the VMM process fails to start or configuration is invalid.
    async fn create(&self, cfg: &VmConfig, res: &PerVmResources) -> Result<Self::Instance>;

    /// Restores a VM instance from a snapshot directory with the given resources.
    ///
    /// # Errors
    /// Returns an error if the VMM process fails to start from the snapshot.
    async fn restore(
        &self,
        snapshot_dir: &Path,
        cfg: &VmConfig,
        res: &PerVmResources,
    ) -> Result<Self::Instance>;

    /// Returns the capabilities of this VMM backend.
    fn capabilities(&self) -> VmmCapabilities;
}

/// Represents a running or created VM instance.
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
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct FakeVmm {
    /// Records calls made to the fake VMM.
    pub calls: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
}

/// A fake VM instance for testing.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct FakeVmInstance {
    /// Simulates a vsock path.
    pub vsock_path: PathBuf,
    /// Simulates a serial path.
    pub serial: PathBuf,
    /// Records calls made to the fake instance.
    pub calls: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
}

impl Vmm for FakeVmm {
    type Instance = FakeVmInstance;

    async fn create(&self, _cfg: &VmConfig, _res: &PerVmResources) -> Result<Self::Instance> {
        if let Ok(mut lock) = self.calls.lock() {
            lock.push("create".to_string());
        }
        Ok(FakeVmInstance {
            vsock_path: PathBuf::from("/tmp/fake-vsock"),
            serial: PathBuf::from("/tmp/fake-serial"),
            calls: self.calls.clone(),
        })
    }

    async fn restore(
        &self,
        _snapshot_dir: &Path,
        _cfg: &VmConfig,
        _res: &PerVmResources,
    ) -> Result<Self::Instance> {
        if let Ok(mut lock) = self.calls.lock() {
            lock.push("restore".to_string());
        }
        Ok(FakeVmInstance {
            vsock_path: PathBuf::from("/tmp/fake-vsock"),
            serial: PathBuf::from("/tmp/fake-serial"),
            calls: self.calls.clone(),
        })
    }

    fn capabilities(&self) -> VmmCapabilities {
        VmmCapabilities {
            snapshot_restore: true,
            lazy_restore: false,
            virtio_fs_shares: true,
            rootless_vhost_user_net: true,
            nested_virt: true,
        }
    }
}

impl VmInstance for FakeVmInstance {
    async fn boot(&mut self) -> Result<()> {
        if let Ok(mut lock) = self.calls.lock() {
            lock.push("boot".to_string());
        }
        Ok(())
    }
    async fn request_shutdown(&mut self) -> Result<()> {
        if let Ok(mut lock) = self.calls.lock() {
            lock.push("request_shutdown".to_string());
        }
        Ok(())
    }
    async fn kill(&mut self) -> Result<()> {
        if let Ok(mut lock) = self.calls.lock() {
            lock.push("kill".to_string());
        }
        Ok(())
    }
    async fn pause(&mut self) -> Result<()> {
        if let Ok(mut lock) = self.calls.lock() {
            lock.push("pause".to_string());
        }
        Ok(())
    }
    async fn resume(&mut self) -> Result<()> {
        if let Ok(mut lock) = self.calls.lock() {
            lock.push("resume".to_string());
        }
        Ok(())
    }
    async fn snapshot(&mut self, _dir: &Path) -> Result<()> {
        if let Ok(mut lock) = self.calls.lock() {
            lock.push("snapshot".to_string());
        }
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
        &self.vsock_path
    }
    fn guest_cid(&self) -> u32 {
        3
    }
    fn serial_log(&self) -> &Path {
        &self.serial
    }
}

impl Drop for FakeVmInstance {
    fn drop(&mut self) {
        if let Ok(mut lock) = self.calls.lock() {
            lock.push("drop".to_string());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn test_cid_allocator() {
        let alloc = CidAllocator::new();
        let cid1 = alloc.allocate().unwrap();
        let cid2 = alloc.allocate().unwrap();
        assert!(cid1 >= 3);
        assert!(cid2 > cid1);
        alloc.release(cid1);
        let cid3 = alloc.allocate().unwrap();
        assert_eq!(cid1, cid3);
    }

    proptest! {
        #[test]
        fn test_cid_allocator_prop(cid_sequence in proptest::collection::vec(3u32..255u32, 0..100)) {
            let alloc = CidAllocator::new();
            for _ in &cid_sequence {
                let _ = alloc.allocate();
            }
        }
    }
}
