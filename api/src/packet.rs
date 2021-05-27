//! We do not perform serious protocol parsing in this module.
//! All we do here is figuring out layer's length and protocol type, that's it.
//! More serious protocol parsing jobs are done by the packet processors in another module.
//!
//!

use std::convert::TryFrom;
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use tinyvec::TinyVec;

use serde::ser::SerializeSeq;
use serde::{Serialize, Serializer};

use super::classifiers::matched::Rule;

#[repr(u8)]
#[derive(Clone, Copy, Debug, Hash, PartialEq)]
pub enum Direction {
    Right = 0,
    Left = 1,
}

impl Default for Direction {
    fn default() -> Self {
        Direction::Right
    }
}

#[derive(Clone, Copy, Debug, Default)]
/// Packet protocol layer
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

impl Layer {
    /// Get this layer's raw packet data
    pub fn data<'a>(&self, pkt: &'a dyn Packet) -> &'a [u8] {
        let payload = pkt.payload();
        let data = &payload[self.offset as usize..0];
        data
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Layers {
    pub data_link: Layer,
    pub network: Layer,
    pub trans: Layer,
    pub app: Layer,
}

#[repr(u8)]
#[derive(Debug, PartialEq, Eq)]
pub enum PacketHashMethod {
    /// Normal 5 tuple hash
    FiveTuple,
    /// Hash use only mac address
    #[cfg(feature = "pkt-hash-mac")]
    MacOnly,
}

#[derive(Debug, Eq)]
pub struct PacketHashKey {
    pub hash_method: PacketHashMethod,
    pub network_proto: Protocol,
    pub trans_proto: Protocol,
    pub src_port: u16,
    pub dst_port: u16,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    #[cfg(feature = "pkt-hash-mac")]
    pub src_mac: [u8; 6],
    #[cfg(feature = "pkt-hash-mac")]
    pub dst_mac: [u8; 6],
}

impl Default for PacketHashKey {
    fn default() -> PacketHashKey {
        PacketHashKey {
            hash_method: PacketHashMethod::FiveTuple,
            network_proto: Protocol::default(),
            trans_proto: Protocol::default(),
            src_port: 0,
            dst_port: 0,
            src_ip: IpAddr::V4(Ipv4Addr::from(0)),
            dst_ip: IpAddr::V4(Ipv4Addr::from(0)),
            #[cfg(feature = "pkt-hash-mac")]
            src_mac: [0; 6],
            #[cfg(feature = "pkt-hash-mac")]
            dst_mac: [0; 6],
        }
    }
}

impl From<&dyn Packet> for PacketHashKey {
    fn from(pkt: &dyn Packet) -> Self {
        let mut key = Self::default();
        key.network_proto = pkt.layers().network.protocol;
        key.trans_proto = pkt.layers().trans.protocol;

        unsafe {
            match key.trans_proto {
                Protocol::TCP | Protocol::UDP | Protocol::SCTP => {
                    if pkt.src_port() > pkt.dst_port() {
                        key.src_port = pkt.src_port();
                        key.dst_port = pkt.dst_port();
                    } else {
                        key.src_port = pkt.dst_port();
                        key.dst_port = pkt.src_port();
                    }
                }
                _ => {}
            };
        }

        match key.network_proto {
            Protocol::IPV4 => {
                let src_ip = unsafe { pkt.src_ipv4() };
                let dst_ip = unsafe { pkt.dst_ipv4() };
                if src_ip > dst_ip {
                    key.src_ip = IpAddr::V4(Ipv4Addr::from(src_ip));
                    key.dst_ip = IpAddr::V4(Ipv4Addr::from(dst_ip));
                } else {
                    key.src_ip = IpAddr::V4(Ipv4Addr::from(dst_ip));
                    key.dst_ip = IpAddr::V4(Ipv4Addr::from(src_ip));
                }
            }
            Protocol::IPV6 => {
                let src_ip = unsafe { *pkt.src_ipv6() };
                let dst_ip = unsafe { *pkt.dst_ipv6() };
                if src_ip > dst_ip {
                    key.src_ip = IpAddr::V6(Ipv6Addr::from(src_ip));
                    key.dst_ip = IpAddr::V6(Ipv6Addr::from(dst_ip));
                } else {
                    key.src_ip = IpAddr::V6(Ipv6Addr::from(dst_ip));
                    key.dst_ip = IpAddr::V6(Ipv6Addr::from(src_ip));
                }
            }
            _ => {}
        };

        #[cfg(feature = "pkt-hash-mac")]
        {
            match key.hash_method {
                PacketHashMethod::MacOnly => {
                    let src_mac = unsafe { pkt.src_mac() };
                    let dst_mac = unsafe { pkt.dst_mac() };
                    if src_mac > dst_mac {
                        key.src_mac.copy_from_slice(src_mac);
                        key.dst_mac.copy_from_slice(dst_mac);
                    } else {
                        key.src_mac.copy_from_slice(dst_mac);
                        key.dst_mac.copy_from_slice(src_mac);
                    }
                }
                _ => {}
            }
        }

        key
    }
}

impl Hash for PacketHashKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        match self.hash_method {
            PacketHashMethod::FiveTuple => {
                self.trans_proto.hash(state);
                self.src_port.hash(state);
                self.dst_port.hash(state);
                self.src_ip.hash(state);
                self.dst_ip.hash(state);
            }
            #[cfg(feature = "pkt-hash-mac")]
            PacketHashMethod::MacOnly => {
                self.src_mac.hash(state);
                self.dst_mac.hash(state);
            }
        }
    }
}

impl PartialEq for PacketHashKey {
    fn eq(&self, other: &PacketHashKey) -> bool {
        if self.trans_proto != other.trans_proto {
            return false;
        }

        match self.trans_proto {
            Protocol::TCP | Protocol::UDP | Protocol::SCTP => {
                let self_src_port = self.src_port;
                let self_dst_port = self.dst_port;
                let other_src_port = self.src_port;
                let other_dst_port = self.dst_port;

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

        match self.network_proto {
            Protocol::IPV4 | Protocol::IPV6 => {
                let self_src_ip = self.src_ip;
                let self_dst_ip = self.dst_ip;
                let other_src_ip = other.src_ip;
                let other_dst_ip = other.dst_ip;

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

/// By default, we consider one packet couldn't match more than 8 rules.
/// However, if matched rules exceed 8, use heap instead
/// In this way, we could guarantee all rules could be added, also
/// reduce heap allocation using a Vec
pub const DEFAULT_MAX_MATCHED_RULES: usize = 8;

/// Type alia for matched rule vector
pub type Rules = TinyVec<[Rule; DEFAULT_MAX_MATCHED_RULES]>;

pub trait Packet: Send {
    /// Get raw packet data
    fn raw(&self) -> &[u8];

    /// Get packet capture time
    fn ts(&self) -> &libc::timeval;

    /// Get packet capture length
    fn caplen(&self) -> u32;

    fn layers(&self) -> &Layers;
    fn layers_mut(&mut self) -> &mut Layers;

    fn rules(&self) -> &[Rule];
    fn rules_mut(&mut self) -> &mut Rules;

    fn tunnel(&self) -> Tunnel;
    fn tunnel_mut(&mut self) -> &mut Tunnel;

    fn clone_box(&self) -> Box<dyn Packet + '_>;

    #[inline]
    fn data_len(&self) -> u16 {
        match self.layers().trans.protocol {
            Protocol::TCP | Protocol::UDP | Protocol::SCTP => {
                self.caplen() as u16 - self.layers().app.offset
            }
            _ => self.caplen() as u16 - self.layers().trans.offset,
        }
    }

    /// Get src port
    ///
    /// It's the caller's duty to guarantee transport layer is TCP/UDP
    #[inline]
    unsafe fn src_port(&self) -> u16 {
        let src_port_pos = (self.layers().trans.offset) as usize;
        (*(self.raw().as_ptr().add(src_port_pos) as *const u16)).to_be()
    }

    /// Get dst port
    ///
    /// It's the caller's duty to guarantee transport layer is TCP/UDP
    #[inline]
    unsafe fn dst_port(&self) -> u16 {
        let dst_port_pos = (self.layers().trans.offset + 2) as usize;
        (*(self.raw().as_ptr().add(dst_port_pos) as *const u16)).to_be()
    }

    /// Get src ipv4 address
    ///
    /// It's the caller's duty to guarantee network layer is IPV4
    #[inline]
    unsafe fn src_ipv4(&self) -> u32 {
        let src_ip_pos = (self.layers().network.offset + 12) as usize;
        (*(self.raw().as_ptr().add(src_ip_pos) as *const u32)).to_be()
    }

    /// Get dst ipv4 address
    ///
    /// It's the caller's duty to guarantee network layer is IPV4
    #[inline]
    unsafe fn dst_ipv4(&self) -> u32 {
        let dst_ip_pos = (self.layers().network.offset + 16) as usize;
        (*(self.raw().as_ptr().add(dst_ip_pos) as *const u32)).to_be()
    }

    /// Get src ipv6 address
    ///
    /// It's the caller's duty to guarantee network layer is IPV6
    #[inline]
    unsafe fn src_ipv6(&self) -> &u128 {
        let src_ip_pos = (self.layers().network.offset + 8) as usize;
        &*(self.raw().as_ptr().add(src_ip_pos) as *const u128)
    }

    /// Get dst ipv6 address
    ///
    /// It's the caller's duty to guarantee network layer is IPV6
    #[inline]
    unsafe fn dst_ipv6(&self) -> &u128 {
        let dst_ip_pos = (self.layers().network.offset + 8 + 16) as usize;
        &*(self.raw().as_ptr().add(dst_ip_pos) as *const u128)
    }

    /// Get src mac address
    ///
    /// It's the caller's duty to guarantee datalink layer is Ethernet
    #[inline]
    unsafe fn src_mac(&self) -> &[u8; 6] {
        <&[u8; 6]>::try_from(&self.raw()[6..12]).unwrap()
    }

    /// Get dst mac address
    ///
    /// It's the caller's duty to guarantee datalink layer is Ethernet
    #[inline]
    unsafe fn dst_mac(&self) -> &[u8; 6] {
        <&[u8; 6]>::try_from(&self.raw()[0..6]).unwrap()
    }

    #[inline]
    /// Get packet's application layer payload
    fn payload(&self) -> &[u8] {
        &self.raw()[self.layers().app.offset as usize..]
    }

    #[inline]
    fn direction(&self) -> Direction {
        match self.layers().trans.protocol {
            Protocol::TCP | Protocol::UDP | Protocol::SCTP => {
                if unsafe { self.src_port() > self.dst_port() } {
                    return Direction::Right;
                } else {
                    return Direction::Left;
                }
            }
            _ => {}
        };

        match self.layers().network.protocol {
            Protocol::IPV4 => {
                if unsafe { self.src_ipv4() > self.dst_ipv4() } {
                    return Direction::Right;
                } else {
                    return Direction::Left;
                }
            }
            Protocol::IPV6 => {
                if unsafe { *self.src_ipv6() > *self.dst_ipv6() } {
                    return Direction::Right;
                } else {
                    return Direction::Left;
                }
            }
            _ => {}
        }

        Direction::Right
    }
}

impl std::fmt::Debug for dyn Packet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let stime = std::time::UNIX_EPOCH
            + std::time::Duration::from_nanos(
                self.ts().tv_sec as u64 * 1000000000 + self.ts().tv_usec as u64 * 1000,
            );
        let datetime = chrono::DateTime::<chrono::Utc>::from(stime);
        let timestamp_str = datetime.format("%Y-%m-%d %H:%M:%S.%f").to_string();
        f.debug_struct("Packet")
            .field("ts", &timestamp_str)
            .field("caplen", &self.caplen())
            .field("data link layer", &self.layers().data_link)
            .field("network layer", &self.layers().network)
            .field("trans layer", &self.layers().trans)
            .field("app layer", &self.layers().app)
            .finish()
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
    L2TP,

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

bitflags! {
    pub struct Tunnel: u8 {
        const NONE = 0;
        const GRE = 0b00000001;
        const PPPOE = 0b00000010;
        const MPLS = 0b00000100;
        const PPP = 0b00001000;
        const GTP = 0b00010000;
        const VXLAN = 0b00100000;
        const L2TP = 0b01000000;
    }
}

impl Default for Tunnel {
    fn default() -> Self {
        Tunnel::NONE
    }
}

impl Serialize for Tunnel {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut s = serializer.serialize_seq(None)?;
        if self.contains(Tunnel::GRE) {
            s.serialize_element("gre")?;
        }
        if self.contains(Tunnel::GTP) {
            s.serialize_element("gtp")?;
        }
        if self.contains(Tunnel::L2TP) {
            s.serialize_element("l2tp")?;
        }
        if self.contains(Tunnel::MPLS) {
            s.serialize_element("mpls")?;
        }
        if self.contains(Tunnel::PPP) {
            s.serialize_element("ppp")?;
        }
        if self.contains(Tunnel::PPPOE) {
            s.serialize_element("pppoe")?;
        }
        if self.contains(Tunnel::VXLAN) {
            s.serialize_element("vxlan")?;
        }
        s.end()
    }
}

#[cfg(test)]
pub mod test {
    use super::Packet as PacketTrait;
    use super::*;
    use crate::utils::packet::Packet;

    #[test]
    fn test_data_bytes() {}

    #[test]
    fn test_src_port() {
        let mut pkt = Packet::default();
        pkt.raw = Box::new(vec![0x14, 0xe9]);
        pkt.layers_mut().trans.offset = 0;
        unsafe { assert_eq!(pkt.src_port(), 5353) };
    }

    #[test]
    fn test_dst_port() {
        let mut pkt = Packet::default();
        pkt.raw = Box::new(vec![0, 0, 0x14, 0xe9]);
        pkt.layers_mut().trans.offset = 0;
        unsafe { assert_eq!(pkt.dst_port(), 5353) };
    }

    #[test]
    fn test_src_ipv4() {
        let mut pkt = Packet::default();
        pkt.raw = Box::new(vec![
            0x45, 0x00, 0x02, 0x2d, 0x00, 0x00, 0x40, 0x00, 0x40, 0x06, 0x79, 0x1d, 0xc0, 0xa8,
            0x02, 0xde, 0xda, 0x62, 0x21, 0xc5, 0xe2, 0xb2, 0x01, 0xbb, 0x2b, 0xd5, 0x16, 0xf7,
            0x66, 0x96, 0xcf, 0xb8, 0x50, 0x18, 0x10, 0x00, 0x8a, 0xcf, 0x00, 0x00,
        ]);
        pkt.layers_mut().network.offset = 0;
        unsafe { assert_eq!(pkt.src_ipv4(), 0xc0a802de) };
    }

    #[test]
    fn test_dst_ipv4() {
        let mut pkt = Packet::default();
        pkt.raw = Box::new(vec![
            0x45, 0x00, 0x02, 0x2d, 0x00, 0x00, 0x40, 0x00, 0x40, 0x06, 0x79, 0x1d, 0xc0, 0xa8,
            0x02, 0xde, 0xda, 0x62, 0x21, 0xc5, 0xe2, 0xb2, 0x01, 0xbb, 0x2b, 0xd5, 0x16, 0xf7,
            0x66, 0x96, 0xcf, 0xb8, 0x50, 0x18, 0x10, 0x00, 0x8a, 0xcf, 0x00, 0x00,
        ]);
        pkt.layers_mut().network.offset = 0;
        unsafe { assert_eq!(pkt.dst_ipv4(), 0xda6221c5) };
    }

    #[test]
    fn test_src_ipv6() {
        let mut pkt = Packet::default();
        pkt.raw = Box::new(vec![
            0x60, 0x0c, 0x6b, 0x7b, 0x00, 0xb8, 0x11, 0xff, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x10, 0x08, 0xfa, 0x70, 0x46, 0xe8, 0x42, 0x04, 0xff, 0x02, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfb,
        ]);
        pkt.layers_mut().network.offset = 0;
        unsafe { assert_eq!(pkt.src_ipv6().to_be(), 0xfe800000000000001008fa7046e84204) };
    }

    #[test]
    fn test_dst_ipv6() {
        let mut pkt = Packet::default();
        pkt.raw = Box::new(vec![
            0x60, 0x0c, 0x6b, 0x7b, 0x00, 0xb8, 0x11, 0xff, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x10, 0x08, 0xfa, 0x70, 0x46, 0xe8, 0x42, 0x04, 0xff, 0x02, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfb,
        ]);
        pkt.layers_mut().network.offset = 0;
        unsafe { assert_eq!(pkt.dst_ipv6().to_be(), 0xff0200000000000000000000000000fb) };
    }

    #[test]
    fn serialize_tunnel() {
        let tunnel = Tunnel::GRE;
        assert_eq!("[\"gre\"]", serde_json::to_string(&tunnel).unwrap());

        let tunnel = Tunnel::GRE | Tunnel::L2TP;
        assert_eq!(
            "[\"gre\",\"l2tp\"]",
            serde_json::to_string(&tunnel).unwrap()
        );
    }
}
