//! We do not perform serious protocol parsing in this module.
//! All we do here is figuring out layer's length and protocol type, that's it.
//! More serious protocol parsing jobs are done by the protocol parsers in another module.
//!
//!

use std::hash::{Hash, Hasher};

use super::error;

extern crate libc;
extern crate pcap;

pub mod link;
pub mod network;
pub mod parser;
pub mod transport;

pub const PACKET_MAX_LAYERS: usize = 4;

pub const DIRECTION_LEFT: bool = false;
pub const DIRECTION_RIGHT: bool = true;

#[derive(Default, Clone, Copy, Debug)]
#[repr(packed)]
/// Packet protocol layer, 3 bytes
pub struct Layer {
    pub protocol: Protocol,
    /// protocol start offset
    pub offset: u16,
}

impl Hash for Layer {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.protocol.hash(state);
    }
}

pub struct Packet {
    /// timestamp
    pub ts: libc::timeval,
    /// capture length
    pub caplen: u32,
    /// actual length
    pub data: Vec<u8>,
    /// All layer's basic info
    pub layers: [Layer; PACKET_MAX_LAYERS],
    /// How much layers does the packet contain
    pub last_layer_index: u8,
    /// Direction
    pub direction: bool,
}

impl Packet {
    #[inline]
    pub fn len(&self) -> u16 {
        self.data.len() as u16
    }

    #[inline]
    /// return the length of the specific layer
    pub fn len_of_layer(&self, depth: usize) -> u16 {
        match depth {
            0 => self.len(),
            _ => self.len() - self.layers[depth].offset,
        }
    }

    pub fn from(raw_pkt: pcap::Packet) -> Packet {
        Packet {
            ts: raw_pkt.header.ts,
            caplen: raw_pkt.header.caplen,
            data: Vec::from(raw_pkt.data),
            last_layer_index: 0,
            layers: [Layer {
                protocol: Protocol::default(),
                offset: 0,
            }; PACKET_MAX_LAYERS],
            direction: DIRECTION_LEFT,
        }
    }
}

impl Hash for Packet {
    #[inline]
    fn hash<H: Hasher>(&self, state: &mut H) {
        match self.layers[2].protocol {
            Protocol::TCP | Protocol::UDP => {
                self.layers[2].hash(state);
                let src_port_pos = (self.layers[2].offset) as usize;
                let dst_port_pos = (self.layers[2].offset + 2) as usize;
                self.data.as_slice()[src_port_pos..src_port_pos + 4].hash(state);
                self.data.as_slice()[dst_port_pos..dst_port_pos + 4].hash(state);
            }
            _ => {}
        };

        match self.layers[1].protocol {
            Protocol::IPV4 => {
                let src_ip_pos = (self.layers[1].offset + 12) as usize;
                let dst_ip_pos = (self.layers[1].offset + 16) as usize;
                self.data.as_slice()[src_ip_pos..src_ip_pos + 4].hash(state);
                self.data.as_slice()[dst_ip_pos..dst_ip_pos + 4].hash(state);
            }
            Protocol::IPV6 => {
                let src_ip_pos = (self.layers[1].offset + 8) as usize;
                let dst_ip_pos = (self.layers[1].offset + 16) as usize;
                self.data.as_slice()[src_ip_pos..src_ip_pos + 4].hash(state);
                self.data.as_slice()[dst_ip_pos..dst_ip_pos + 16].hash(state);
            }
            _ => {
                0_u8.hash(state);
            }
        };
    }
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, Hash)]
/// Protocol collection, 1 byte
pub enum Protocol {
    // Data link layer protocols
    NULL,
    ETHERNET,
    RAW,
    PPP,
    MPLS,
    PPPOE,

    // Tunnel protocols
    GRE,

    // Network layer protocols
    IPV4,
    IPV6,
    ICMP,
    CLNS,
    DDP,
    EGP,
    EIGRP,
    IGMP,
    IPX,
    ESP,
    OSPF,
    PIM,
    RIP,
    VLAN,
    WIREGUARD,

    // Transport layer protocols
    TCP,
    UDP,
    SCTP,

    // Application layer protocols
    HTTP,

    // Unknown protocol
    UNKNOWN,

    APPLICATION,
}

impl Default for Protocol {
    #[inline]
    fn default() -> Self {
        Protocol::UNKNOWN
    }
}

pub type Parser = parser::Parser;
