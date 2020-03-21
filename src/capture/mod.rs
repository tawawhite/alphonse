extern crate pcap;

use super::{error, packet};

mod libpcap;

pub use libpcap::Libpcap;

pub trait Backend {}

pub struct Capture<B: Backend> {
    backend: B,
}
