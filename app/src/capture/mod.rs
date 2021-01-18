use anyhow::Result;

use alphonse_api::packet::Packet;

use crate::config::Config;
use crate::stats::CaptureStat;

#[cfg(all(target_os = "linux", feature = "dpdk"))]
pub mod dpdk;
pub mod libpcap;

pub use libpcap::{NetworkInterface, Offline};

pub trait Capture {
    fn configure(&mut self, _: &Config) -> Result<()> {
        Ok(())
    }

    fn next(&mut self) -> Result<Box<dyn Packet>>;
    fn stats(&mut self) -> Result<CaptureStat>;
}

pub struct CaptureUtility {
    pub init: fn(cfg: &mut Config) -> Result<()>,
    pub cleanup: fn(cfg: &Config) -> Result<()>,
}
