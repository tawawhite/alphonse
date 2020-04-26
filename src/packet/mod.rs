//! We do not perform serious protocol parsing in this module.
//! All we do here is figuring out layer's length and protocol type, that's it.
//! More serious protocol parsing jobs are done by the protocol parsers in another module.
//!
//!

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

#[repr(u8)]
#[derive(Clone, Copy, Debug)]
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
}

impl Default for Protocol {
    #[inline]
    fn default() -> Self {
        Protocol::UNKNOWN
    }
}

pub type Parser = parser::Parser;
