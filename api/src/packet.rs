//! We do not perform serious protocol parsing in this module.
//! All we do here is figuring out layer's length and protocol type, that's it.
//! More serious protocol parsing jobs are done by the protocol parsers in another module.
//!
//!

use std::convert::TryFrom;
use std::hash::{Hash, Hasher};

extern crate libc;

use super::classifiers::matched::Rule;

#[repr(u8)]
pub enum Direction {
    LEFT = 0,
    RIGHT = 1,
}

impl Default for Direction {
    fn default() -> Self {
        Direction::LEFT
    }
}

#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
/// Packet protocol layer, 3 bytes
pub struct Layer {
    /// protocol start offset
    pub offset: u16,
    pub protocol: Protocol,
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
    /// Packet hash, improve hash performance
    pub hash: u64,
    pub rules: Box<Vec<Rule>>,
}

impl Packet {
    #[inline]
    pub fn from(ts: &libc::timeval, caplen: u32, data: &[u8]) -> Self {
        Packet {
            ts: *ts,
            caplen,
            data: Box::new(Vec::from(data)),
            data_link_layer: Layer::default(),
            network_layer: Layer::default(),
            trans_layer: Layer::default(),
            app_layer: Layer::default(),
            hash: 0,
            rules: Box::new(Vec::new()),
        }
    }

    #[inline]
    pub fn len(&self) -> u16 {
        self.data.len() as u16
    }

    #[inline]
    pub fn bytes(&self) -> u16 {
        self.data.len() as u16
    }

    #[inline]
    pub fn data_bytes(&self) -> u16 {
        match self.trans_layer.protocol {
            Protocol::TCP | Protocol::UDP | Protocol::SCTP => self.bytes() - self.app_layer.offset,
            _ => self.bytes() - self.trans_layer.offset,
        }
    }

    #[inline]
    pub fn direction(&self) -> Direction {
        match self.trans_layer.protocol {
            Protocol::TCP | Protocol::UDP | Protocol::SCTP => {
                if self.src_port() > self.dst_port() {
                    return Direction::LEFT;
                } else {
                    return Direction::RIGHT;
                }
            }
            _ => {}
        };

        match self.network_layer.protocol {
            Protocol::IPV4 => {
                if self.src_ipv4() > self.src_ipv4() {
                    return Direction::LEFT;
                } else {
                    return Direction::RIGHT;
                }
            }
            Protocol::IPV6 => {
                if *self.src_ipv6() > *self.src_ipv6() {
                    return Direction::LEFT;
                } else {
                    return Direction::RIGHT;
                }
            }
            _ => {}
        }

        Direction::LEFT
    }

    /// Get src port
    ///
    /// It's the caller's duty to guarantee transport layer is TCP/UDP
    #[inline]
    pub fn src_port(&self) -> u16 {
        let src_port_pos = (self.trans_layer.offset) as usize;
        unsafe { (*(self.data.as_ptr().add(src_port_pos) as *const u16)).to_be() }
    }

    /// Get dst port
    ///
    /// It's the caller's duty to guarantee transport layer is TCP/UDP
    #[inline]
    pub fn dst_port(&self) -> u16 {
        let dst_port_pos = (self.trans_layer.offset + 2) as usize;
        unsafe { (*(self.data.as_ptr().add(dst_port_pos) as *const u16)).to_be() }
    }

    /// Get src ipv4 address
    ///
    /// It's the caller's duty to guarantee network layer is IPV4
    #[inline]
    pub fn src_ipv4(&self) -> u32 {
        let src_ip_pos = (self.network_layer.offset + 12) as usize;
        unsafe { (*(self.data.as_ptr().add(src_ip_pos) as *const u32)).to_be() }
    }

    /// Get dst ipv4 address
    ///
    /// It's the caller's duty to guarantee network layer is IPV4
    #[inline]
    pub fn dst_ipv4(&self) -> u32 {
        let dst_ip_pos = (self.network_layer.offset + 16) as usize;
        unsafe { (*(self.data.as_ptr().add(dst_ip_pos) as *const u32)).to_be() }
    }

    /// Get src ipv6 address
    ///
    /// It's the caller's duty to guarantee network layer is IPV6
    #[inline]
    pub fn src_ipv6(&self) -> &u128 {
        let src_ip_pos = (self.network_layer.offset + 8) as usize;
        unsafe { &*(self.data.as_ptr().add(src_ip_pos) as *const u128) }
    }

    /// Get dst ipv6 address
    ///
    /// It's the caller's duty to guarantee network layer is IPV6
    #[inline]
    pub fn dst_ipv6(&self) -> &u128 {
        let dst_ip_pos = (self.network_layer.offset + 8 + 16) as usize;
        unsafe { &*(self.data.as_ptr().add(dst_ip_pos) as *const u128) }
    }

    /// Get src mac address
    ///
    /// It's the caller's duty to guarantee datalink layer is Ethernet
    #[inline]
    pub fn src_mac(&self) -> &[u8; 6] {
        <&[u8; 6]>::try_from(&self.data.as_slice()[6..12]).unwrap()
    }

    /// Get dst mac address
    ///
    /// It's the caller's duty to guarantee datalink layer is Ethernet
    #[inline]
    pub fn dst_mac(&self) -> &[u8; 6] {
        <&[u8; 6]>::try_from(&self.data.as_slice()[0..6]).unwrap()
    }

    #[inline]
    /// Get packet's application layer payload
    pub fn payload(&self) -> &[u8] {
        &self.data.as_slice()[self.app_layer.offset as usize..]
    }
}

impl Default for Packet {
    fn default() -> Self {
        Packet {
            ts: libc::timeval {
                tv_sec: 0,
                tv_usec: 0,
            },
            caplen: 0,
            data: Box::new(Vec::new()),
            data_link_layer: Layer::default(),
            network_layer: Layer::default(),
            trans_layer: Layer::default(),
            app_layer: Layer::default(),
            hash: 0,
            rules: Box::new(Vec::new()),
        }
    }
}

impl std::fmt::Debug for Packet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let stime = std::time::UNIX_EPOCH
            + std::time::Duration::from_nanos(
                self.ts.tv_sec as u64 * 1000000000 + self.ts.tv_usec as u64 * 1000,
            );
        let datetime = chrono::DateTime::<chrono::Utc>::from(stime);
        let timestamp_str = datetime.format("%Y-%m-%d %H:%M:%S.%f").to_string();
        f.debug_struct("Packet")
            .field("ts", &timestamp_str)
            .field("caplen", &self.caplen)
            .field("data_link_layer", &self.data_link_layer)
            .field("network_layer", &self.network_layer)
            .field("trans_layer", &self.trans_layer)
            .field("app_layer", &self.app_layer)
            .finish()
    }
}

impl Hash for Packet {
    #[inline]
    fn hash<H: Hasher>(&self, state: &mut H) {
        if self.hash != 0 {
            return self.hash.hash(state);
        }

        match self.trans_layer.protocol {
            Protocol::TCP | Protocol::UDP | Protocol::SCTP => {
                let src_port = self.src_port();
                let dst_port = self.dst_port();
                if src_port > dst_port {
                    src_port.hash(state);
                    dst_port.hash(state);
                } else {
                    dst_port.hash(state);
                    src_port.hash(state);
                }
            }
            _ => {}
        };

        match self.network_layer.protocol {
            Protocol::IPV4 => {
                let src_ip = self.src_ipv4();
                let dst_ip = self.dst_ipv4();
                if src_ip > dst_ip {
                    src_ip.hash(state);
                    dst_ip.hash(state);
                } else {
                    dst_ip.hash(state);
                    src_ip.hash(state);
                }
            }
            Protocol::IPV6 => {
                let src_ip = *self.src_ipv6();
                let dst_ip = *self.dst_ipv6();
                if src_ip > dst_ip {
                    src_ip.hash(state);
                    dst_ip.hash(state);
                } else {
                    dst_ip.hash(state);
                    src_ip.hash(state);
                }
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
            Protocol::TCP | Protocol::UDP | Protocol::SCTP => {
                let self_src_port = self.src_port();
                let self_dst_port = self.dst_port();
                let other_src_port = self.src_port();
                let other_dst_port = self.dst_port();

                let self_cmp = self_src_port > self_dst_port;
                let other_cmp = other_src_port > other_dst_port;

                if self_cmp == other_cmp {
                    if (self_src_port != other_src_port) || (self_dst_port != other_dst_port) {
                        return false;
                    }
                } else {
                    if (self_src_port != other_dst_port) || (self_dst_port != other_src_port) {
                        return false;
                    }
                }
            }
            _ => {}
        };

        match self.network_layer.protocol {
            Protocol::IPV4 => {
                let self_src_ip = self.src_ipv4();
                let self_dst_ip = self.dst_ipv4();
                let other_src_ip = other.src_ipv4();
                let other_dst_ip = other.dst_ipv4();

                let self_cmp = self_src_ip > self_dst_ip;
                let other_cmp = other_src_ip > other_dst_ip;
                if self_cmp == other_cmp {
                    if (self_src_ip != other_src_ip) || (self_dst_ip != other_dst_ip) {
                        return false;
                    }
                } else {
                    if (self_src_ip != other_dst_ip) || (self_dst_ip != other_src_ip) {
                        return false;
                    }
                }
            }
            Protocol::IPV6 => {
                let self_src_ip = self.src_ipv6();
                let self_dst_ip = self.dst_ipv6();
                let other_src_ip = other.src_ipv6();
                let other_dst_ip = other.dst_ipv6();

                let self_cmp = self_src_ip > self_dst_ip;
                let other_cmp = other_src_ip > other_dst_ip;
                if self_cmp == other_cmp {
                    if (self_src_ip != other_src_ip) || (self_dst_ip != other_dst_ip) {
                        return false;
                    }
                } else {
                    if (self_src_ip != other_dst_ip) || (self_dst_ip != other_src_ip) {
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

impl Clone for Packet {
    fn clone(&self) -> Self {
        Packet {
            ts: self.ts,
            caplen: self.caplen,
            data: self.data.clone(),
            data_link_layer: self.data_link_layer,
            network_layer: self.network_layer,
            trans_layer: self.trans_layer,
            app_layer: self.app_layer,
            hash: self.hash,
            rules: self.rules.clone(),
        }
    }
}

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

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_data_bytes() {}

    #[test]
    fn test_src_port() {
        let mut pkt = Packet::default();
        pkt.data = Box::new(vec![0x14, 0xe9]);
        pkt.trans_layer.offset = 0;
        assert_eq!(pkt.src_port(), 5353);
    }

    #[test]
    fn test_dst_port() {
        let mut pkt = Packet::default();
        pkt.data = Box::new(vec![0, 0, 0x14, 0xe9]);
        pkt.trans_layer.offset = 0;
        assert_eq!(pkt.dst_port(), 5353);
    }

    #[test]
    fn test_src_ipv4() {
        let mut pkt = Packet::default();
        pkt.data = Box::new(vec![
            0x45, 0x00, 0x02, 0x2d, 0x00, 0x00, 0x40, 0x00, 0x40, 0x06, 0x79, 0x1d, 0xc0, 0xa8,
            0x02, 0xde, 0xda, 0x62, 0x21, 0xc5, 0xe2, 0xb2, 0x01, 0xbb, 0x2b, 0xd5, 0x16, 0xf7,
            0x66, 0x96, 0xcf, 0xb8, 0x50, 0x18, 0x10, 0x00, 0x8a, 0xcf, 0x00, 0x00,
        ]);
        pkt.network_layer.offset = 0;
        assert_eq!(pkt.src_ipv4(), 0xc0a802de);
    }

    #[test]
    fn test_dst_ipv4() {
        let mut pkt = Packet::default();
        pkt.data = Box::new(vec![
            0x45, 0x00, 0x02, 0x2d, 0x00, 0x00, 0x40, 0x00, 0x40, 0x06, 0x79, 0x1d, 0xc0, 0xa8,
            0x02, 0xde, 0xda, 0x62, 0x21, 0xc5, 0xe2, 0xb2, 0x01, 0xbb, 0x2b, 0xd5, 0x16, 0xf7,
            0x66, 0x96, 0xcf, 0xb8, 0x50, 0x18, 0x10, 0x00, 0x8a, 0xcf, 0x00, 0x00,
        ]);
        pkt.network_layer.offset = 0;
        assert_eq!(pkt.dst_ipv4(), 0xda6221c5);
    }

    #[test]
    fn test_src_ipv6() {
        let mut pkt = Packet::default();
        pkt.data = Box::new(vec![
            0x60, 0x0c, 0x6b, 0x7b, 0x00, 0xb8, 0x11, 0xff, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x10, 0x08, 0xfa, 0x70, 0x46, 0xe8, 0x42, 0x04, 0xff, 0x02, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfb,
        ]);
        pkt.network_layer.offset = 0;
        assert_eq!(pkt.src_ipv6().to_be(), 0xfe800000000000001008fa7046e84204);
    }

    #[test]
    fn test_dst_ipv6() {
        let mut pkt = Packet::default();
        pkt.data = Box::new(vec![
            0x60, 0x0c, 0x6b, 0x7b, 0x00, 0xb8, 0x11, 0xff, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x10, 0x08, 0xfa, 0x70, 0x46, 0xe8, 0x42, 0x04, 0xff, 0x02, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfb,
        ]);
        pkt.network_layer.offset = 0;
        assert_eq!(pkt.dst_ipv6().to_be(), 0xff0200000000000000000000000000fb);
    }
}
