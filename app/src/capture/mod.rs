use anyhow::Result;

use alphonse_api::packet::Packet;

use crate::config::Config;
use crate::stats::CaptureStat;

#[cfg(all(target_os = "linux", feature = "dpdk"))]
pub mod dpdk;
mod libpcap;

pub use libpcap::{NetworkInterface, Offline};

pub trait Capture {
    fn init(_: &Config) -> Result<()> {
        Ok(())
    }

    fn cleanup() -> Result<()> {
        Ok(())
    }

    fn configure(&mut self, _: &Config) -> Result<()> {
        Ok(())
    }

    fn next(&mut self) -> Result<Box<dyn Packet>>;
    fn stats(&mut self) -> Result<CaptureStat>;
}
