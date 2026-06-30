//! Virtual Machine Monitor (VMM) abstraction and management.
//!
//! This module provides a generic abstraction for different VMM backends
//! (like Cloud Hypervisor), as well as fake implementations for testing.

use crate::config::VmConfig;
use crate::error::Result;
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

/// A trait for reading a serial log.
pub trait SerialLog: Send + Sync {
    /// Checks if the log contains a kernel panic.
    fn contains_panic(&self) -> bool;
}

/// A real serial log that reads from a file.
pub struct RealSerialLog {
    /// The path to the log file.
    pub path: PathBuf,
}

impl SerialLog for RealSerialLog {
    fn contains_panic(&self) -> bool {
        if self.path.exists() {
            if let Ok(log_content) = std::fs::read_to_string(&self.path) {
                return log_content.contains("Kernel panic")
                    || log_content.contains("panicked at")
                    || log_content.contains("panic - not syncing");
            }
        }
        false
    }
}

/// A fake serial log for testing.
pub struct FakeSerialLog {
    /// Whether a panic is simulated.
    pub panicked: bool,
}

impl SerialLog for FakeSerialLog {
    fn contains_panic(&self) -> bool {
        self.panicked
    }
}

/// Helper to send an HTTP request over a Unix domain socket.
///
/// # Errors
/// Returns an error if the request cannot be sent or the server returns an error status.
pub async fn unix_api_request<T: Serialize>(
    api_socket: &Path,
    method: &str,
    path: &str,
    body: Option<&T>,
) -> Result<()> {
    let stream = tokio::net::UnixStream::connect(api_socket).await?;

    let io = hyper_util::rt::TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;

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
        )))?;

    let res = sender.send_request(req).await?;

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

/// RAII guard owning a single per-VM scratch directory under the system temp dir
/// (`/tmp/vmcell-vm-{pid}-{vmid}/`).
///
/// The orchestrator creates exactly one of these per VM — before networking setup —
/// and threads its [`path`](VmTempDir::path) to every VMM backend through
/// [`PerVmResources::tmp_dir`]. Every per-VM temporary (the API/QMP socket, the
/// vsock socket, the serial log, the smoltcp NAT socket, virtiofsd sockets) lives
/// inside this one directory with a single owner, replacing the former
/// triplicated per-backend create/own/delete.
///
/// On [`Drop`] the directory and everything in it is removed via
/// [`remove_vm_tmp_dir`] (idempotent), so creating the guard early also reclaims
/// the directory if VM construction fails partway. `MicroVm` drops this guard
/// **after** the VMM process group, the vhost-user daemons, and the smoltcp
/// process are gone, so removal never races a process still holding a socket
/// inside it.
#[derive(Debug)]
pub struct VmTempDir {
    /// The owned per-VM directory path.
    path: PathBuf,
}

impl VmTempDir {
    /// Creates the per-VM temporary directory `/tmp/vmcell-vm-{pid}-{vmid}/` and
    /// returns a guard that removes it on drop.
    ///
    /// # Errors
    /// Returns an error if the directory cannot be created.
    pub async fn create(vmid: u32) -> Result<Self> {
        let path = std::env::temp_dir().join(format!("vmcell-vm-{}-{}", std::process::id(), vmid));
        tokio::fs::create_dir_all(&path).await?;
        Ok(Self { path })
    }

    /// Returns the path to the owned per-VM directory.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for VmTempDir {
    fn drop(&mut self) {
        remove_vm_tmp_dir(&self.path);
    }
}

/// Removes a per-VM temporary directory owned by a [`VmTempDir`] guard,
/// including its serial log, lock files, and any leftover sockets.
///
/// Without this the directory (holding `serial.log`, and `api.sock.lock` for CH)
/// leaks one-per-VM and `/tmp` grows unbounded across runs (E3). Call it on the
/// owning instance's `Drop`/teardown path **after** the VMM process group has
/// been reaped, so removal never races a live VMM.
///
/// Best-effort by design: this runs on the `Drop` path where there is no
/// `Result` to surface and `Drop` must not panic; the directory may also already
/// be gone. A genuine removal failure is logged for visibility rather than
/// swallowed silently.
pub(crate) fn remove_vm_tmp_dir(dir: &Path) {
    if let Err(e) = std::fs::remove_dir_all(dir) {
        // A missing directory is the normal idempotent-teardown case, not a leak.
        if e.kind() != std::io::ErrorKind::NotFound {
            tracing::warn!("failed to remove per-VM temp dir {}: {}", dir.display(), e);
        }
    }
}

/// Builds a Tokio command for the VMM, handling network namespaces and process groups.
pub fn build_vmm_cmd(binary_path: &Path, netns_name: Option<&str>) -> tokio::process::Command {
    let mut std_cmd = std::process::Command::new(binary_path);
    use std::os::unix::process::CommandExt;
    std_cmd.process_group(0);
    if let Some(netns) = netns_name {
        let netns_path = format!("/var/run/netns/{}\0", netns);
        // SAFETY: kill is safe to call and only sends a signal to a process.
        unsafe {
            std_cmd.pre_exec(move || {
                let fd = libc::open(
                    netns_path.as_ptr() as *const libc::c_char,
                    libc::O_RDONLY | libc::O_CLOEXEC,
                );
                if fd < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::setns(fd, libc::CLONE_NEWNET) != 0 {
                    let err = std::io::Error::last_os_error();
                    libc::close(fd);
                    return Err(err);
                }
                libc::close(fd);
                Ok(())
            });
        }
    }
    tokio::process::Command::from(std_cmd)
}

/// Waits until the given socket path appears, or times out.
///
/// Returns true if the socket is found. Returns false if the timeout is reached
/// or if the provided process exits early.
///
/// # Errors
/// Returns an error if the process exits before the socket appears,
/// or if the timeout is reached.
pub async fn wait_for_socket(
    socket_path: &Path,
    process: &mut tokio::process::Child,
    timeout_ms: u64,
    interval_ms: u64,
) -> Result<()> {
    let iterations = timeout_ms / interval_ms;
    for _ in 0..iterations {
        if tokio::fs::try_exists(socket_path).await.unwrap_or(false) {
            return Ok(());
        }
        if let Some(status) = process.try_wait().unwrap_or(None) {
            return Err(crate::error::Error::Vmm(format!(
                "process exited early: {}",
                status
            )));
        }
        tokio::time::sleep(std::time::Duration::from_millis(interval_ms)).await;
    }
    Err(crate::error::Error::Timeout(
        "socket failed to appear in time".into(),
    ))
}

/// Force-kills a just-spawned VMM process *group* (`SIGKILL` to `-pgid`) and reaps
/// the leader. Use on the error paths between spawning a VMM and constructing the
/// owning instance (whose `Drop` would otherwise do this): a failure there — e.g. a
/// cgroup `add_task` or a readiness timeout — must not leak a running VMM, because
/// `tokio::process::Child` does not kill on drop. No-op when `pgid` is `None`.
pub(crate) fn reap_process_group(process: &mut tokio::process::Child, pgid: Option<u32>) {
    let Some(pgid) = pgid else {
        return;
    };
    let _ = nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(-(pgid as i32)),
        nix::sys::signal::Signal::SIGKILL,
    );
    if let Some(pid) = process.id() {
        let _ = nix::sys::wait::waitpid(nix::unistd::Pid::from_raw(pid as i32), None);
    }
}

/// Allocates unique Context IDs (CIDs) for vsock connections.
/// CIDs >= 3 are available for guests.
#[derive(Debug)]
pub struct CidAllocator {
    active: std::sync::Mutex<std::collections::BTreeSet<u32>>,
}

impl CidAllocator {
    /// Creates a new CID allocator.
    #[must_use]
    pub fn new() -> Self {
        Self {
            active: std::sync::Mutex::new(std::collections::BTreeSet::new()),
        }
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
    pub fn allocate(&self) -> Result<u32> {
        // Recover from a poisoned lock instead of panicking: the guarded value is
        // a plain `BTreeSet` of live CIDs with no cross-field invariant, so a
        // panic mid-mutation cannot leave it in an unusable state — adopting the
        // inner set is sound.
        let mut active = self.active.lock().unwrap_or_else(|e| e.into_inner());
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
    pub fn release(&self, cid: u32) {
        // Recover from a poisoned lock instead of panicking: the guarded `BTreeSet`
        // of live CIDs has no cross-field invariant, so adopting the inner set is
        // sound.
        let mut active = self.active.lock().unwrap_or_else(|e| e.into_inner());
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
    /// Optional vhost-user socket path for unprivileged networking.
    pub vhost_user_socket: Option<PathBuf>,
    /// Unique internal VM ID.
    pub vmid: u32,
    /// Context ID for vsock communication.
    pub guest_cid: u32,
    /// Per-VM scratch directory (owned by the orchestrator via [`VmTempDir`]).
    /// Backends derive all of their socket and serial-log paths inside this
    /// directory; it is created once before networking setup and removed once on
    /// teardown.
    pub tmp_dir: PathBuf,
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
    /// True if the VMM supports vhost-user-net for unprivileged networking.
    pub unprivileged_vhost_user_net: bool,
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
    async fn create(
        &self,
        cfg: &VmConfig,
        res: &PerVmResources,
        cgroups: &dyn crate::metrics::CgroupFs,
    ) -> Result<Self::Instance>;

    /// Restores a VM instance from a snapshot directory with the given resources.
    ///
    /// # Errors
    /// Returns an error if the VMM process fails to start from the snapshot.
    async fn restore(
        &self,
        snapshot_dir: &Path,
        cfg: &VmConfig,
        res: &PerVmResources,
        cgroups: &dyn crate::metrics::CgroupFs,
    ) -> Result<Self::Instance>;

    /// Returns the capabilities of this VMM backend.
    fn capabilities(&self) -> VmmCapabilities;

    /// Returns the string identifier of this VMM backend.
    fn id(&self) -> &str;
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
    /// Returns the path to this instance's vsock control socket.
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

    async fn create(
        &self,
        _cfg: &VmConfig,
        _res: &PerVmResources,
        _cgroups: &dyn crate::metrics::CgroupFs,
    ) -> Result<Self::Instance> {
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
        _cgroups: &dyn crate::metrics::CgroupFs,
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
            unprivileged_vhost_user_net: true,
            nested_virt: true,
        }
    }

    fn id(&self) -> &str {
        "fake"
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

    // Guards E3: the per-VM temp dir (serial.log + lock + stale sockets) must be
    // removed on teardown, not just the vsock socket. The inverse — a teardown
    // that removes only the sockets and leaves the directory — is exactly the
    // leak this finding reports, and goes red here because the dir still exists.
    #[test]
    fn test_remove_vm_tmp_dir_removes_whole_dir() {
        let parent = tempfile::tempdir().expect("create parent tempdir");
        let vm_dir = parent.path().join("vmcell-vm-1-2");
        std::fs::create_dir_all(&vm_dir).expect("create per-VM dir");
        std::fs::write(vm_dir.join("serial.log"), b"boot log").expect("write serial.log");
        std::fs::write(vm_dir.join("api.sock.lock"), b"").expect("write lock");
        assert!(vm_dir.exists(), "precondition: per-VM dir exists");

        remove_vm_tmp_dir(&vm_dir);

        assert!(
            !vm_dir.exists(),
            "per-VM temp dir (with serial.log) leaked after teardown"
        );

        // Idempotent: removing an already-gone dir is a no-op, not a panic/error.
        remove_vm_tmp_dir(&vm_dir);
    }

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

    // Guards VMM-7: a poisoned mutex must be recovered, not panicked on. The buggy
    // impl (`.lock().expect("mutex poisoned")`) aborts the test here.
    #[test]
    fn test_cid_allocator_recovers_from_poison() {
        let alloc = std::sync::Arc::new(CidAllocator::new());
        let poisoner = alloc.clone();
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = poisoner.active.lock().expect("fresh lock");
            panic!("poison the mutex while holding the guard");
        }));
        // The lock is now poisoned; both operations must still work.
        let cid = alloc.allocate().expect("allocate after poison");
        assert!(cid >= 3);
        alloc.release(cid);
    }

    proptest! {
        // Guards VMM-6: the previous version allocated and discarded, asserting
        // nothing. This asserts the allocator's contract so a broken allocator
        // (handing out reserved/duplicate/out-of-range CIDs, or failing the
        // release round-trip) goes red.
        #[test]
        fn test_cid_allocator_prop(n in 0usize..260) {
            let alloc = CidAllocator::new();
            let mut allocated: Vec<u32> = Vec::new();
            for _ in 0..n {
                match alloc.allocate() {
                    Ok(cid) => {
                        // Reserved CIDs 0/1/2 are never handed out, and the
                        // ceiling is 254.
                        prop_assert!(cid >= 3, "cid {} is in the reserved range", cid);
                        prop_assert!(cid <= 254, "cid {} exceeds the ceiling", cid);
                        // Uniqueness: a live CID is never handed out twice.
                        prop_assert!(!allocated.contains(&cid), "duplicate cid {}", cid);
                        allocated.push(cid);
                    }
                    Err(_) => {
                        // Exhaustion only after all 252 guest CIDs (3..=254) are live.
                        prop_assert_eq!(allocated.len(), 252);
                    }
                }
            }
            // release + re-allocate round-trips: a freed CID is handed back.
            if let Some(&first) = allocated.first() {
                alloc.release(first);
                let reused = alloc.allocate().expect("re-allocate after release");
                prop_assert_eq!(reused, first);
            }
        }
    }
}
