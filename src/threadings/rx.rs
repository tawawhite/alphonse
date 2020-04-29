extern crate pcap;

use super::capture::{Capture, Libpcap};

/// 收包线程
pub struct RxThread<C: Capture> {
    /// 线程ID
    id: u8,
    /// 收包总数
    pub rx_count: u64,
    /// 采集后端
    capture: Option<C>,
}

impl RxThread<Libpcap> {
    pub fn new(id: u8) -> RxThread<Libpcap> {
        RxThread {
            id,
            rx_count: 0,
            capture: None,
        }
    }
}
