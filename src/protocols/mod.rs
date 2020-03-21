//! We do not perform serious protocol parsing in this module.
//! All we do here is figuring out layer's length and protocol type, that's it.
//! More serious protocol parsing jobs are done by the protocol parsers in another module.
//!
//!

use super::packet;

pub mod link;
pub mod network;
mod parser;
pub mod transport;

#[derive(Clone, Copy, Debug)]
pub enum Error {
    /// Parsing this kind of Protocol is not supported by alphonse
    UnsupportProtocol,
    /// The packet is a corrupt packet, either too short or just broken
    CorruptPacket,
    /// Alphonse has no idea about this kind of protocol
    UnknownProtocol,
}

#[derive(Clone, Copy, Debug)]
pub enum DataLinkProto {
    Null,
    Ethernet,
    Raw,
    IPv4,
    PPP,
    Mpls,
    PPPoE,
}

#[derive(Clone, Copy, Debug)]
pub enum NetworkProto {
    IPv4,
    IPv6,
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
    WIREGUARD,
}

#[derive(Clone, Copy, Debug)]
pub enum TunnelProto {
    GRE,
}

#[derive(Clone, Copy, Debug)]
pub enum TransProto {
    TCP,
    UDP,
    SCTP,
}

#[derive(Clone, Copy, Debug)]
pub enum ApplicationProto {
    HTTP,
}

#[derive(Clone, Copy, Debug)]
pub enum LayerProto {
    DataLink(DataLinkProto),
    Network(NetworkProto),
    Tunnel(TunnelProto),
    Transport(TransProto),
    Application(ApplicationProto),
}

#[derive(Default, Clone, Copy)]
pub struct Layer {
    pub start_pos: u16,
}

pub type Parser = parser::Parser;
