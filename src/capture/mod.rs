extern crate pcap;

use anyhow::Result;

use super::packet;
use super::packet::Packet;

mod libpcap;

pub use libpcap::{NetworkInterface, Offline};

pub trait Capture {
    fn next(&mut self) -> Result<Box<Packet>>;
}
