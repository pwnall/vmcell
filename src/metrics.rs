#[derive(Clone, Debug, Default)]
/// Resource usage statistics for a VM instance.
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
