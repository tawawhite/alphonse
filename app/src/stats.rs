/// Capture statistic information
#[derive(Debug, Default)]
pub struct CaptureStat {
    /// Total received packets
    pub rx_pkts: u64,
    /// Total received bytes
    pub rx_bytes: u64,
    /// Total dropped packets
    pub dropped: u64,
    /// Total dropped packets by network interface
    pub if_dropped: u64,
}
