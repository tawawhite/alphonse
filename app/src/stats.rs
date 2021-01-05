/// Capture statistic information
#[derive(Debug, Default)]
pub struct CaptureStat {
    /// Total received packets
    pub received: u64,
    /// Total dropped packets
    pub dropped: u64,
    /// Total dropped packets by network interface
    pub if_dropped: u64,
}
