//! Resource usage tracking and metrics collection.

#![forbid(unsafe_code)]

use crate::error::Result;
#[cfg(feature = "metrics")]
use cgroups_rs::{cgroup_builder::CgroupBuilder, hierarchies};

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
    pub net_rx_bytes: u64,
    /// Bytes transmitted over network.
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

/// The default CgroupFs implementation.
#[derive(Debug, Default, Clone)]
pub struct DefaultCgroupFs;

impl CgroupFs for DefaultCgroupFs {
    fn create_slice(&self, name: &str, limits: &crate::config::ResourceLimits) -> Result<()> {
        #[cfg(feature = "metrics")]
        {
            let mut builder = CgroupBuilder::new(name);
            if let Some(mem) = limits.mem_max_mib {
                builder = builder
                    .memory()
                    .memory_hard_limit((mem as i64) << 20)
                    .done();
            }
            if let Some(cpu) = limits.cpu_max_pct {
                let period = 100_000_u64;
                let quota = (cpu as u64) * period / 100;
                builder = builder.cpu().quota(quota as i64).period(period).done();
            }
            if let Err(e) = builder.build(Box::new(hierarchies::V2::new())) {
                tracing::warn!("Failed to create cgroup {}: {}", name, e);
                return Err(crate::error::Error::Cgroup(e.to_string()));
            }

            if let Some(pids) = limits.pids_max {
                let pids_max_path = format!("/sys/fs/cgroup/{}/pids.max", name);
                std::fs::write(&pids_max_path, pids.to_string()).map_err(|e| {
                    crate::error::Error::Cgroup(format!("Failed to apply pids.max: {}", e))
                })?;
            }
            if let Some(io) = &limits.io_max {
                let io_max_path = format!("/sys/fs/cgroup/{}/io.max", name);
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
                    std::fs::write(&io_max_path, io_str).map_err(|e| {
                        crate::error::Error::Cgroup(format!("Failed to apply io.max: {}", e))
                    })?;
                }
            }
        }
        // Silence unused parameter warnings when metrics feature is off
        #[cfg(not(feature = "metrics"))]
        {
            let _ = name;
            let _ = limits;
        }
        Ok(())
    }

    fn delete_slice(&self, name: &str) -> Result<()> {
        #[cfg(feature = "metrics")]
        {
            let cg = cgroups_rs::Cgroup::load(Box::new(hierarchies::V2::new()), name);
            let _ = cg.delete();
        }
        #[cfg(not(feature = "metrics"))]
        let _ = name;
        Ok(())
    }

    fn read_stats(&self, name: &str) -> Result<ResourceUsage> {
        let mut usage = ResourceUsage::default();
        #[cfg(feature = "metrics")]
        {
            let cg = cgroups_rs::Cgroup::load(Box::new(hierarchies::V2::new()), name);
            for sub in cg.subsystems() {
                match sub {
                    cgroups_rs::Subsystem::Mem(_) => {
                        let base_path = format!("/sys/fs/cgroup/{}", name);
                        if let Ok(s) =
                            std::fs::read_to_string(format!("{}/memory.current", base_path))
                        {
                            if let Ok(val) = s.trim().parse::<u64>() {
                                usage.mem_current_mib = val / 1024 / 1024;
                            }
                        }
                        if let Ok(s) = std::fs::read_to_string(format!("{}/memory.peak", base_path))
                        {
                            if let Ok(val) = s.trim().parse::<u64>() {
                                usage.mem_peak_mib = val / 1024 / 1024;
                            }
                        }
                    }
                    cgroups_rs::Subsystem::Cpu(c) => {
                        let stat = c.cpu().stat;
                        for line in stat.lines() {
                            if let Some(val) = line
                                .strip_prefix("usage_usec ")
                                .and_then(|s| s.parse::<u64>().ok())
                            {
                                usage.cpu_usec = val;
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        #[cfg(not(feature = "metrics"))]
        let _ = name;

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
}
