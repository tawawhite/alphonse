extern crate pcap;

use super::error::Error;
use super::packet::Packet;
use super::{config, error, packet};

mod libpcap;

pub use libpcap::Libpcap;

pub trait Capture {
    fn next(&mut self) -> Result<Packet, Error>;
}

// 开始采集
pub fn start_capture(_config: &config::Config) -> impl Capture {
    #[cfg(all(target_os = "linux", feature = "dpdk"))]
    {
        if _config.backend.as_str().eq_ignore_ascii_case("dpdk") {}
    }

    Libpcap::new()
}
