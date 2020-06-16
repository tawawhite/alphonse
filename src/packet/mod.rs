//! We do not perform serious protocol parsing in this module.
//! All we do here is figuring out layer's length and protocol type, that's it.
//! More serious protocol parsing jobs are done by the protocol parsers in another module.
//!
//!

use std::hash::{Hash, Hasher};

extern crate libc;
extern crate pcap;

pub mod link;
pub mod network;
pub mod parser;
pub mod transport;

pub const DIRECTION_LEFT: bool = false;
pub const DIRECTION_RIGHT: bool = true;

#[derive(Default)]
#[repr(packed)]
/// Packet protocol layer, 3 bytes
pub struct Layer {
    pub protocol: Protocol,
    /// protocol start offset
    pub offset: u16,
}

impl Hash for Layer {
    #[inline]
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.protocol.hash(state);
    }
}

pub struct Packet {
    /// timestamp
    pub ts: libc::timeval,
    /// capture length
    pub caplen: u32,
    /// raw packet data
    pub data: Box<Vec<u8>>,
    /// data link layer
    pub data_link_layer: Layer,
    /// network layer
    pub network_layer: Layer,
    /// transport layer
    pub trans_layer: Layer,
    /// application layer
    pub app_layer: Layer,
    /// Direction
    pub direction: bool,
    /// Packet hash, improve hash performance
    pub hash: u64,
}

impl Packet {
    #[inline]
    pub fn len(&self) -> u16 {
        self.data.len() as u16
    }

    #[inline]
    pub fn from(raw_pkt: &pcap::Packet) -> Packet {
        Packet {
            ts: raw_pkt.header.ts,
            caplen: raw_pkt.header.caplen,
            data: Box::new(Vec::from(raw_pkt.data)),
            data_link_layer: Layer::default(),
            network_layer: Layer::default(),
            trans_layer: Layer::default(),
            app_layer: Layer::default(),
            direction: DIRECTION_LEFT,
            hash: 0,
        }
    }

    /// Get src port
    ///
    /// It's the caller's duty to guarantee transport layer is TCP/UDP
    #[inline]
    pub fn get_src_port(&self) -> u16 {
        let src_port_pos = (self.trans_layer.offset) as usize;
        unsafe { *(&self.data[src_port_pos] as *const u8 as *const u16) }
    }

    /// Get dst port
    ///
    /// It's the caller's duty to guarantee transport layer is TCP/UDP
    #[inline]
    pub fn get_dst_port(&self) -> u16 {
        let dst_port_pos = (self.trans_layer.offset + 2) as usize;
        unsafe { *(&self.data[dst_port_pos] as *const u8 as *const u16) }
    }

    /// Get src ipv4 address
    ///
    /// It's the caller's duty to guarantee network layer is IPV4
    #[inline]
    pub fn get_src_ipv4(&self) -> u32 {
        let src_ip_pos = (self.network_layer.offset + 12) as usize;
        unsafe { *(&self.data[src_ip_pos] as *const u8 as *const u32) }
    }

    /// Get dst ipv4 address
    ///
    /// It's the caller's duty to guarantee network layer is IPV4
    #[inline]
    pub fn get_dst_ipv4(&self) -> u32 {
        let dst_ip_pos = (self.network_layer.offset + 16) as usize;
        unsafe { *(&self.data[dst_ip_pos] as *const u8 as *const u32) }
    }

    /// Get src ipv6 address
    ///
    /// It's the caller's duty to guarantee network layer is IPV6
    #[inline]
    pub fn get_src_ipv6(&self) -> &u128 {
        let src_ip_pos = (self.network_layer.offset + 8) as usize;
        unsafe { &*(&self.data[src_ip_pos] as *const u8 as *const u128) }
    }

    /// Get dst ipv6 address
    ///
    /// It's the caller's duty to guarantee network layer is IPV6
    #[inline]
    pub fn get_dst_ipv6(&self) -> &u128 {
        let dst_ip_pos = (self.network_layer.offset + 8 + 16) as usize;
        unsafe { &*(&self.data[dst_ip_pos] as *const u8 as *const u128) }
    }
}

impl Hash for Packet {
    #[inline]
    fn hash<H: Hasher>(&self, state: &mut H) {
        if self.hash != 0 {
            return self.hash.hash(state);
        }

        match self.trans_layer.protocol {
            Protocol::TCP | Protocol::UDP => {
                self.get_src_port().hash(state);
                self.get_dst_port().hash(state);
            }
            _ => {}
        };

        match self.network_layer.protocol {
            Protocol::IPV4 => {
                self.get_src_ipv4().hash(state);
                self.get_dst_ipv4().hash(state);
            }
            Protocol::IPV6 => {
                (*self.get_src_ipv6()).hash(state);
                (*self.get_dst_ipv6()).hash(state);
            }
            _ => {}
        };
    }
}

impl PartialEq for Packet {
    #[inline]
    fn eq(&self, other: &Packet) -> bool {
        if self.trans_layer.protocol != other.trans_layer.protocol {
            return false;
        }

        if self.network_layer.protocol != other.network_layer.protocol {
            return false;
        }

        match self.trans_layer.protocol {
            Protocol::TCP | Protocol::UDP => {
                let self_src_port = self.get_src_port();
                let self_dst_port = self.get_dst_port();
                let other_src_port = self.get_src_port();
                let other_dst_port = self.get_dst_port();

                let self_cmp = self_src_port > self_dst_port;
                let other_cmp = other_src_port > other_dst_port;

                if self_cmp == other_cmp {
                    if (self_src_port != other_src_port) || (self_dst_port == other_dst_port) {
                        return false;
                    }
                } else {
                    if (self_src_port != other_dst_port) || (self_dst_port == other_src_port) {
                        return false;
                    }
                }
            }
            _ => {}
        };

        match self.network_layer.protocol {
            Protocol::IPV4 => {
                let self_src_ip = self.get_src_ipv4();
                let self_dst_ip = self.get_dst_ipv4();
                let other_src_ip = other.get_src_ipv4();
                let other_dst_ip = other.get_dst_ipv4();

                let self_cmp = self_src_ip > self_dst_ip;
                let other_cmp = other_src_ip > other_dst_ip;
                if self_cmp == other_cmp {
                    if (self_src_ip != other_src_ip) || (self_dst_ip == other_dst_ip) {
                        return false;
                    }
                } else {
                    if (self_src_ip != other_dst_ip) || (self_dst_ip == other_src_ip) {
                        return false;
                    }
                }
            }
            Protocol::IPV6 => {
                let self_src_ip = self.get_src_ipv6();
                let self_dst_ip = self.get_dst_ipv6();
                let other_src_ip = other.get_src_ipv6();
                let other_dst_ip = other.get_dst_ipv6();

                let self_cmp = self_src_ip > self_dst_ip;
                let other_cmp = other_src_ip > other_dst_ip;
                if self_cmp == other_cmp {
                    if (self_src_ip != other_src_ip) || (self_dst_ip == other_dst_ip) {
                        return false;
                    }
                } else {
                    if (self_src_ip != other_dst_ip) || (self_dst_ip == other_src_ip) {
                        return false;
                    }
                }
            }
            _ => {}
        };

        true
    }
}

impl Eq for Packet {}

#[repr(u8)]
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
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
