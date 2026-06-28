//! Resource usage tracking and metrics collection.

#![forbid(unsafe_code)]

use crate::error::Result;

/// Resource usage statistics for a VM instance.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct ResourceUsage {
    /// Peak memory usage in MiB.
    pub mem_peak_mib: u64,
    /// Current memory usage in MiB.
    pub mem_current_mib: u64,
    /// CPU usage in microseconds.
    pub cpu_usec: u64,
    /// Bytes read from disk/block devices.
    pub io_read_bytes: u64,
    /// Bytes written to disk/block devices.
    pub io_write_bytes: u64,
    /// Bytes received over network.
    ///
    /// Not yet wired: cgroup v2 has no network byte accounting, and `read_stats`
    /// only receives the cgroup name, not the VM's netns/interface handle, so this
    /// stays `0` until a per-netns interface stats source is threaded through.
    pub net_rx_bytes: u64,
    /// Bytes transmitted over network.
    ///
    /// Not yet wired: see [`ResourceUsage::net_rx_bytes`] for why this stays `0`.
    pub net_tx_bytes: u64,
}

/// Interface for managing cgroups.
pub trait CgroupFs: Send + Sync + std::fmt::Debug {
    /// Creates a cgroup slice with the given limits.
    ///
    /// # Errors
    /// Returns an error if the slice cannot be created or limits applied.
    fn create_slice(&self, name: &str, limits: &crate::config::ResourceLimits) -> Result<()>;
    /// Deletes a cgroup slice.
    ///
    /// # Errors
    /// Returns an error if the slice cannot be deleted.
    fn delete_slice(&self, name: &str) -> Result<()>;
    /// Reads resource usage statistics from a given cgroup.
    ///
    /// # Errors
    /// Returns an error if reading the stats fails.
    fn read_stats(&self, name: &str) -> Result<ResourceUsage>;
    /// Adds a task (process ID) to the cgroup.
    ///
    /// # Errors
    /// Returns an error if adding the task fails.
    fn add_task(&self, name: &str, pid: u32) -> Result<()>;
}

/// Computes the cgroup-v2 `cpu.max` `(quota, period)` pair for a CPU cap expressed
/// as a percentage of one core. The period is fixed at 100000us and the quota is the
/// matching slice of that period (e.g. 50% -> `(50000, 100000)`, 200% -> `(200000, 100000)`).
#[cfg(feature = "metrics")]
fn cpu_quota_period(cpu_max_pct: u32) -> (i64, u64) {
    let period = 100_000_u64;
    let quota = u64::from(cpu_max_pct) * period / 100;
    (quota as i64, period)
}

/// Converts a memory cap in MiB to the byte value written to `memory.max`
/// (`memory_hard_limit`). MiB is `<< 20`, not the SI `1_000_000`.
#[cfg(feature = "metrics")]
fn mem_hard_limit_bytes(mem_max_mib: u32) -> i64 {
    i64::from(mem_max_mib) << 20
}

/// Renders the exact `io.max` control-file contents for the given limits, or `None`
/// when no rate rule is set (so the caller skips the write). Format:
/// `<device> rbps=.. wbps=.. riops=.. wiops=..\n`, emitting only the present fields
/// in that fixed order.
#[cfg(feature = "metrics")]
fn render_io_max(io: &crate::config::IoMax) -> Option<String> {
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
    if rules.is_empty() {
        None
    } else {
        Some(format!("{} {}\n", io.device, rules.join(" ")))
    }
}

/// Renders the exact `pids.max` control-file contents (a bare decimal count).
#[cfg(feature = "metrics")]
fn render_pids_max(pids_max: u32) -> String {
    pids_max.to_string()
}

/// Best-effort application of a single cgroup limit: enable `controller` on the
/// parent's `subtree_control` so the matching control file exists on `name`, then
/// write `value`. A constrained or non-delegated cgroup layout may not allow
/// enabling the controller; we then `warn!` and skip the limit so VM creation still
/// succeeds (limit-dependent tests gate on controller availability themselves).
#[cfg(feature = "metrics")]
fn try_apply_limit(name: &str, controller: &str, file: &str, value: &str) {
    if let Some(parent) = std::path::Path::new(name).parent() {
        let parent = parent.to_string_lossy();
        if !parent.is_empty() {
            let _ = std::fs::write(
                format!("/sys/fs/cgroup/{}/cgroup.subtree_control", parent),
                format!("+{}", controller),
            );
        }
    }
    if let Err(e) = std::fs::write(format!("/sys/fs/cgroup/{}/{}", name, file), value) {
        tracing::warn!(
            "cgroup {}: could not apply {} (controller '{}' unavailable in this layout): {}",
            name,
            file,
            controller,
            e
        );
    }
}

/// Sums the `rbytes`/`wbytes` counters across every device line of a cgroup-v2
/// `io.stat` file, returning `(read_bytes, write_bytes)`. A device with no counters
/// (or an empty file) contributes nothing.
fn parse_io_stat_bytes(contents: &str) -> (u64, u64) {
    let mut read_bytes = 0u64;
    let mut write_bytes = 0u64;
    for line in contents.lines() {
        for field in line.split_whitespace() {
            if let Some(v) = field
                .strip_prefix("rbytes=")
                .and_then(|s| s.parse::<u64>().ok())
            {
                read_bytes = read_bytes.saturating_add(v);
            } else if let Some(v) = field
                .strip_prefix("wbytes=")
                .and_then(|s| s.parse::<u64>().ok())
            {
                write_bytes = write_bytes.saturating_add(v);
            }
        }
    }
    (read_bytes, write_bytes)
}

/// Extracts the `usage_usec` value from a cgroup-v2 `cpu.stat` file, if present.
fn parse_cpu_usage_usec(contents: &str) -> Option<u64> {
    contents.lines().find_map(|line| {
        line.strip_prefix("usage_usec ")
            .and_then(|s| s.trim().parse::<u64>().ok())
    })
}

/// The default CgroupFs implementation.
#[derive(Debug, Default, Clone)]
pub struct DefaultCgroupFs;

impl CgroupFs for DefaultCgroupFs {
    fn create_slice(&self, name: &str, limits: &crate::config::ResourceLimits) -> Result<()> {
        // Create the per-VM cgroup directly with `mkdir`. The previous
        // implementation used `cgroups-rs` `CgroupBuilder`, whose V2 path
        // manipulates the parent's `subtree_control` and leaves the new cgroup in a
        // state that rejects `cgroup.procs` writes (EOPNOTSUPP) under common systemd
        // cgroup layouts; a plain directory + direct limit writes is robust across
        // layouts. (The cgroup must still live in a non-threaded `domain` subtree —
        // a threaded scope rejects `cgroup.procs` regardless; see implementation-notes.)
        std::fs::create_dir_all(format!("/sys/fs/cgroup/{}", name))
            .map_err(|e| crate::error::Error::Cgroup(format!("create cgroup {}: {}", name, e)))?;

        #[cfg(feature = "metrics")]
        {
            if let Some(mem) = limits.mem_max_mib {
                try_apply_limit(
                    name,
                    "memory",
                    "memory.max",
                    &mem_hard_limit_bytes(mem).to_string(),
                );
            }
            if let Some(cpu) = limits.cpu_max_pct {
                let (quota, period) = cpu_quota_period(cpu);
                try_apply_limit(name, "cpu", "cpu.max", &format!("{} {}", quota, period));
            }
            if let Some(pids) = limits.pids_max {
                try_apply_limit(name, "pids", "pids.max", &render_pids_max(pids));
            }
            if let Some(io) = &limits.io_max {
                if let Some(io_str) = render_io_max(io) {
                    try_apply_limit(name, "io", "io.max", io_str.trim_end());
                }
            }
        }
        #[cfg(not(feature = "metrics"))]
        let _ = limits;
        Ok(())
    }

    fn delete_slice(&self, name: &str) -> Result<()> {
        if !name.is_empty() {
            // Best-effort rmdir of the (now-empty) per-VM cgroup. The owning VMM
            // process group is reaped before this runs, so the cgroup has no
            // remaining members.
            let _ = std::fs::remove_dir(format!("/sys/fs/cgroup/{}", name));
        }
        Ok(())
    }

    fn read_stats(&self, name: &str) -> Result<ResourceUsage> {
        let mut usage = ResourceUsage::default();
        let base_path = format!("/sys/fs/cgroup/{}", name);

        // Memory: read directly from sysfs and unconditionally (METRICS-FS-3). The
        // previous implementation gated this on cgroups-rs reporting a Mem subsystem,
        // which silently returned 0 in the very constrained/delegated case it claimed
        // to handle. Only a genuinely absent control file now falls through to 0.
        if let Ok(s) = std::fs::read_to_string(format!("{}/memory.current", base_path)) {
            if let Ok(val) = s.trim().parse::<u64>() {
                usage.mem_current_mib = val / 1024 / 1024;
            }
        }
        if let Ok(s) = std::fs::read_to_string(format!("{}/memory.peak", base_path)) {
            if let Ok(val) = s.trim().parse::<u64>() {
                usage.mem_peak_mib = val / 1024 / 1024;
            }
        }

        // I/O byte counters: sum rbytes/wbytes over every device line of io.stat
        // (METRICS-FS-1). These fields were previously never populated.
        if let Ok(s) = std::fs::read_to_string(format!("{}/io.stat", base_path)) {
            let (read_bytes, write_bytes) = parse_io_stat_bytes(&s);
            usage.io_read_bytes = read_bytes;
            usage.io_write_bytes = write_bytes;
        }

        // CPU usage in microseconds: the `usage_usec` line of cpu.stat.
        if let Ok(s) = std::fs::read_to_string(format!("{}/cpu.stat", base_path)) {
            if let Some(val) = parse_cpu_usage_usec(&s) {
                usage.cpu_usec = val;
            }
        }

        // net_rx_bytes/net_tx_bytes are intentionally left at 0: cgroup v2 has no
        // network byte accounting and this method has no handle to the VM's netns.
        // See the field docs on `ResourceUsage`.
        Ok(usage)
    }

    fn add_task(&self, name: &str, pid: u32) -> Result<()> {
        if !name.is_empty() {
            let procs_path = format!("/sys/fs/cgroup/{}/cgroup.procs", name);
            // Write PID directly to bypass `Cgroup::add_task` limitations for nested unprivileged cgroups
            std::fs::write(&procs_path, pid.to_string()).map_err(|e| {
                crate::error::Error::Cgroup(format!(
                    "Failed to add process {} to cgroup {}: {}",
                    pid, name, e
                ))
            })?;
            tracing::info!("Added process {} to cgroup {}", pid, name);
        }
        Ok(())
    }
}

/// A fake CgroupFs implementation for unit testing.
//
// METRICS-FS-4 note: this is a test-only fake. Its `.lock().unwrap()` calls keep
// `unwrap` deliberately — the mutex is exercised single-threaded within a test, so a
// poisoned guard would itself be a test bug we want to surface loudly. Production
// mutex callers (e.g. `fs::in_process`) recover from poison via `into_inner()`.
#[cfg(test)]
#[derive(Debug, Clone)]
pub struct FakeCgroupFs {
    state: std::sync::Arc<std::sync::Mutex<FakeCgroupState>>,
}

#[cfg(test)]
#[derive(Debug, Default)]
struct FakeCgroupState {
    pub slices: std::collections::HashMap<String, crate::config::ResourceLimits>,
    pub tasks: std::collections::HashMap<String, Vec<u32>>,
}

#[cfg(test)]
impl Default for FakeCgroupFs {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
impl FakeCgroupFs {
    /// Creates a new fake cgroup filesystem.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: std::sync::Arc::new(std::sync::Mutex::new(FakeCgroupState::default())),
        }
    }

    /// Checks if a slice exists.
    /// # Panics
    /// Panics if the internal mutex is poisoned.
    pub fn has_slice(&self, name: &str) -> bool {
        self.state.lock().unwrap().slices.contains_key(name)
    }

    /// Gets limits for a slice.
    /// # Panics
    /// Panics if the internal mutex is poisoned.
    pub fn get_limits(&self, name: &str) -> Option<crate::config::ResourceLimits> {
        self.state.lock().unwrap().slices.get(name).cloned()
    }

    /// Checks if a task is added.
    /// # Panics
    /// Panics if the internal mutex is poisoned.
    pub fn has_task(&self, name: &str, pid: u32) -> bool {
        self.state
            .lock()
            .unwrap()
            .tasks
            .get(name)
            .map(|t| t.contains(&pid))
            .unwrap_or(false)
    }
}

#[cfg(test)]
impl CgroupFs for FakeCgroupFs {
    fn create_slice(&self, name: &str, limits: &crate::config::ResourceLimits) -> Result<()> {
        let mut state = self.state.lock().unwrap();
        state.slices.insert(name.to_string(), limits.clone());
        Ok(())
    }

    fn delete_slice(&self, name: &str) -> Result<()> {
        let mut state = self.state.lock().unwrap();
        state.slices.remove(name);
        state.tasks.remove(name);
        Ok(())
    }

    fn read_stats(&self, _name: &str) -> Result<ResourceUsage> {
        Ok(ResourceUsage {
            mem_peak_mib: 42,
            mem_current_mib: 21,
            cpu_usec: 1000,
            io_read_bytes: 0,
            io_write_bytes: 0,
            net_rx_bytes: 0,
            net_tx_bytes: 0,
        })
    }

    fn add_task(&self, name: &str, pid: u32) -> Result<()> {
        let mut state = self.state.lock().unwrap();
        state.tasks.entry(name.to_string()).or_default().push(pid);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ResourceLimits;

    #[test]
    fn test_fake_cgroup_fs() {
        let fs = FakeCgroupFs::new();
        let name = "imp-vm-1";
        let limits = ResourceLimits {
            mem_max_mib: Some(128),
            cpu_max_pct: Some(50),
            pids_max: None,
            io_max: None,
        };

        fs.create_slice(name, &limits).unwrap();
        assert!(fs.has_slice(name));

        let stored_limits = fs.get_limits(name).unwrap();
        assert_eq!(stored_limits.mem_max_mib, Some(128));
        assert_eq!(stored_limits.cpu_max_pct, Some(50));

        fs.add_task(name, 1234).unwrap();
        assert!(fs.has_task(name, 1234));

        fs.delete_slice(name).unwrap();
        assert!(!fs.has_slice(name));
        assert!(!fs.has_task(name, 1234));
    }

    // METRICS-FS-1: guards against the regression where io.stat is never read (fields
    // permanently 0) and against summing only the first device or swapping read/write.
    #[test]
    fn test_parse_io_stat_sums_all_devices() {
        let sample = "8:0 rbytes=100 wbytes=200 rios=1 wios=2 dbytes=0 dios=0\n\
                      259:0 rbytes=50 wbytes=25 rios=3 wios=4 dbytes=0 dios=0\n";
        let (read_bytes, write_bytes) = parse_io_stat_bytes(sample);
        // An impl that read only the first line would yield (100, 200); a read/write
        // swap would yield (225, 150). Both are red against these exact totals.
        assert_eq!(read_bytes, 150);
        assert_eq!(write_bytes, 225);
    }

    #[test]
    fn test_parse_io_stat_empty_is_zero() {
        assert_eq!(parse_io_stat_bytes(""), (0, 0));
        assert_eq!(parse_io_stat_bytes("8:0 rios=1 wios=2\n"), (0, 0));
    }

    // Guards against parsing the wrong key (e.g. `user_usec`) for cpu_usec.
    #[test]
    fn test_parse_cpu_usage_usec_picks_usage_line() {
        let sample = "usage_usec 123456\nuser_usec 100000\nsystem_usec 23456\n";
        assert_eq!(parse_cpu_usage_usec(sample), Some(123_456));
        assert_eq!(parse_cpu_usage_usec("user_usec 5\n"), None);
        assert_eq!(parse_cpu_usage_usec(""), None);
    }

    // METRICS-FS-2: exact control-file rendering. Each assertion goes red on an
    // inverted formula or a mis-rendered rule string.
    #[cfg(feature = "metrics")]
    #[test]
    fn test_cpu_quota_period_exact() {
        // Inverting the ratio (period * 100 / pct) would give (200_000, 100_000) for 50%.
        assert_eq!(cpu_quota_period(50), (50_000, 100_000));
        assert_eq!(cpu_quota_period(100), (100_000, 100_000));
        assert_eq!(cpu_quota_period(200), (200_000, 100_000));
    }

    #[cfg(feature = "metrics")]
    #[test]
    fn test_mem_hard_limit_bytes_exact() {
        // Using SI MB (1_000_000) or the wrong shift would fail these.
        assert_eq!(mem_hard_limit_bytes(128), 128 * 1024 * 1024);
        assert_eq!(mem_hard_limit_bytes(1), 1_048_576);
    }

    #[cfg(feature = "metrics")]
    #[test]
    fn test_render_io_max_exact() {
        let io = crate::config::IoMax {
            device: "8:0".to_string(),
            rbps: Some(1000),
            wbps: Some(2000),
            riops: None,
            wiops: Some(50),
        };
        // Exact bytes the kernel sees, in fixed order, omitting the unset riops field,
        // with a trailing newline.
        assert_eq!(
            render_io_max(&io).as_deref(),
            Some("8:0 rbps=1000 wbps=2000 wiops=50\n")
        );

        let empty = crate::config::IoMax {
            device: "8:0".to_string(),
            rbps: None,
            wbps: None,
            riops: None,
            wiops: None,
        };
        // No rules => no write at all (None), not an empty/malformed line.
        assert_eq!(render_io_max(&empty), None);
    }

    #[cfg(feature = "metrics")]
    #[test]
    fn test_render_pids_max_exact() {
        assert_eq!(render_pids_max(64), "64");
    }
}
