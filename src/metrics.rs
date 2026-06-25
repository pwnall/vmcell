//! Resource usage tracking and metrics collection.

#![forbid(unsafe_code)]

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

/// Reads resource usage statistics from a given cgroup.
#[must_use]
pub fn read_cgroup_stats(cgroup_name: Option<&str>) -> ResourceUsage {
    let mut usage = ResourceUsage::default();
    #[cfg(feature = "metrics")]
    {
        if let Some(cg_name) = cgroup_name {
            let cg =
                cgroups_rs::Cgroup::load(Box::new(cgroups_rs::hierarchies::V2::new()), cg_name);
            for sub in cg.subsystems() {
                match sub {
                    cgroups_rs::Subsystem::Mem(_) => {
                        let base_path = format!("/sys/fs/cgroup/{}", cg_name);
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
    }
    usage
}
