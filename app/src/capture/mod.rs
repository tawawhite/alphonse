use anyhow::Result;

use alphonse_api::packet::Packet;

use crate::stats::CaptureStat;

mod libpcap;

pub use libpcap::{NetworkInterface, Offline};

pub trait Capture {
    fn next(&mut self) -> Result<Box<dyn Packet>>;
    fn stats(&mut self) -> Result<CaptureStat>;
}
