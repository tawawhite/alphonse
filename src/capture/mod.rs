extern crate pcap;

use super::error::Error;
use super::packet::Packet;
use super::{config, error, packet};

mod libpcap;

pub use libpcap::{NetworkInterface, Offline};

pub trait Capture {
    fn next(&mut self) -> Result<Packet, Error>;
}
