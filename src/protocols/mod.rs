//! We do not perform serious protocol parsing in this module.
//! All we do here is figuring out layer's length and protocol type, that's it.
//! More serious protocol parsing jobs are done by the protocol parsers in another module.
//!
//!

use super::error;
use super::packet;
use super::packet::Layer;

pub mod link;
pub mod network;
pub mod parser;
pub mod transport;

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
