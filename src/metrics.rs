#[derive(Clone, Debug, Default)]
pub struct ResourceUsage {
    pub mem_peak_mib: u64,
    pub mem_current_mib: u64,
    pub cpu_usec: u64,
    pub io_read_bytes: u64,
    pub io_write_bytes: u64,
    pub net_rx_bytes: u64,
    pub net_tx_bytes: u64,
}
