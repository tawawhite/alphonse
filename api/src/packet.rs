use std::convert::TryFrom;
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ops::Range;

use tinyvec::TinyVec;

use serde::ser::SerializeSeq;
use serde::{Serialize, Serializer};

use crate::classifiers::matched::Rule;

/// This direction does not mean anything, like from src to dst nor from client to server.
/// It is merely a mark to indicate packet direction by for example 5 tuple.
/// Enum item name may change in the future, don't count on it.
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

impl Direction {
    /// Getting the opposite direction of this direction
    pub fn reverse(&self) -> Direction {
        match self {
            Direction::Left => Direction::Right,
            Direction::Right => Direction::Left,
        }
    }
}

#[repr(C)]
#[derive(Clone, Debug, Default)]
/// Packet protocol layer
pub struct Layer {
    /// protocol start offset to the start of packet
    ///
    /// Generally a packet is no longer than MTU, normally 1500 bytes.
    /// However, considering loopback interface may generate packets way
    /// bigger than u16's max value, we may change this offset's type to
    /// usize in the future.
    pub range: Range<usize>,
    pub protocol: Protocol,
}

impl Hash for Layer {
    #[inline]
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.protocol.hash(state);
    }
}

const MAX_LAYERS: usize = 8;

#[derive(Clone, Debug, Default)]
pub struct Layers {
    pub datalink: Option<u8>,
    pub network: Option<u8>,
    pub transport: Option<u8>,
    pub application: Option<u8>,
    layers: TinyVec<[Layer; MAX_LAYERS]>,
}

impl Layers {
    pub fn new_with_default_max_layers() -> Self {
        let mut layers = tinyvec::tiny_vec!([Layer; MAX_LAYERS]);
        for _ in 0..MAX_LAYERS {
            layers.push(Layer::default());
        }
        Self {
            datalink: None,
            network: None,
            transport: None,
            application: None,
            layers,
        }
    }
}

impl Layers {
    pub fn datalink(&self) -> Option<&Layer> {
        self.datalink.map_or(None, |i| self.layers.get(i as usize))
    }

    pub(crate) fn datalink_mut(&mut self) -> Option<&mut Layer> {
        self.datalink
            .map_or(None, move |i| self.layers.get_mut(i as usize))
    }

    pub fn network(&self) -> Option<&Layer> {
        self.network.map_or(None, |i| self.layers.get(i as usize))
    }

    pub(crate) fn network_mut(&mut self) -> Option<&mut Layer> {
        self.network
            .map_or(None, move |i| self.layers.get_mut(i as usize))
    }

    pub fn transport(&self) -> Option<&Layer> {
        self.transport.map_or(None, |i| self.layers.get(i as usize))
    }

    pub(crate) fn transport_mut(&mut self) -> Option<&mut Layer> {
        self.transport
            .map_or(None, move |i| self.layers.get_mut(i as usize))
    }

    pub fn application(&self) -> Option<&Layer> {
        self.application
            .map_or(None, |i| self.layers.get(i as usize))
    }

    pub(crate) fn application_mut(&mut self) -> Option<&mut Layer> {
        self.application
            .map_or(None, move |i| self.layers.get_mut(i as usize))
    }

    pub fn len(&self) -> usize {
        self.layers.len()
    }
}

impl AsRef<TinyVec<[Layer; MAX_LAYERS]>> for Layers {
    fn as_ref(&self) -> &TinyVec<[Layer; MAX_LAYERS]> {
        &self.layers
    }
}
impl AsMut<TinyVec<[Layer; MAX_LAYERS]>> for Layers {
    fn as_mut(&mut self) -> &mut TinyVec<[Layer; MAX_LAYERS]> {
        &mut self.layers
    }
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

impl Default for PacketHashMethod {
    fn default() -> Self {
        PacketHashMethod::FiveTuple
    }
}

#[repr(C)]
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
        key.network_proto = pkt
            .layers()
            .network()
            .map_or(Protocol::UNKNOWN, |l| l.protocol);
        key.trans_proto = pkt
            .layers()
            .transport()
            .map_or(Protocol::UNKNOWN, |l| l.protocol);

        if pkt.src_port() > pkt.dst_port() {
            key.src_port = pkt.src_port().unwrap_or(0);
            key.dst_port = pkt.dst_port().unwrap_or(0);
        } else {
            key.src_port = pkt.dst_port().unwrap_or(0);
            key.dst_port = pkt.src_port().unwrap_or(0);
        }

        match key.network_proto {
            Protocol::IPV4 => {
                let src_ip = pkt.src_ipv4().unwrap_or(0);
                let dst_ip = pkt.dst_ipv4().unwrap_or(0);
                if src_ip > dst_ip {
                    key.src_ip = IpAddr::V4(Ipv4Addr::from(src_ip));
                    key.dst_ip = IpAddr::V4(Ipv4Addr::from(dst_ip));
                } else {
                    key.src_ip = IpAddr::V4(Ipv4Addr::from(dst_ip));
                    key.dst_ip = IpAddr::V4(Ipv4Addr::from(src_ip));
                }
            }
            Protocol::IPV6 => {
                let src_ip = *pkt.src_ipv6().unwrap_or(&[0; 16]);
                let dst_ip = *pkt.dst_ipv6().unwrap_or(&[0; 16]);
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

#[repr(C)]
#[derive(Clone, Debug, Default)]
pub struct Rules(TinyVec<[Rule; DEFAULT_MAX_MATCHED_RULES]>);

impl AsRef<TinyVec<[Rule; DEFAULT_MAX_MATCHED_RULES]>> for Rules {
    fn as_ref(&self) -> &TinyVec<[Rule; DEFAULT_MAX_MATCHED_RULES]> {
        &self.0
    }
}

impl AsMut<TinyVec<[Rule; DEFAULT_MAX_MATCHED_RULES]>> for Rules {
    fn as_mut(&mut self) -> &mut TinyVec<[Rule; DEFAULT_MAX_MATCHED_RULES]> {
        &mut self.0
    }
}

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

    fn clone_box<'a, 'b>(&'a self) -> Box<dyn Packet + 'b>;

    /// Get src port if this layer is TCP|UDP|SCTP
    fn src_port(&self) -> Option<u16> {
        match self.layers().transport() {
            None => None,
            Some(l) => match l.protocol {
                Protocol::TCP | Protocol::UDP | Protocol::SCTP => {
                    let data = &self.raw()[l.range.clone()];
                    Some(((data[0] as u16) << 8) + data[1] as u16)
                }
                _ => None,
            },
        }
    }

    /// Get dst port if this layer is TCP|UDP|SCTP
    fn dst_port(&self) -> Option<u16> {
        match self.layers().transport() {
            None => None,
            Some(l) => match l.protocol {
                Protocol::TCP | Protocol::UDP | Protocol::SCTP => {
                    let data = &self.raw()[l.range.clone()];
                    Some(((data[2] as u16) << 8) + data[3] as u16)
                }
                _ => None,
            },
        }
    }

    fn src_ipv4(&self) -> Option<u32> {
        match self.layers().network() {
            None => None,
            Some(l) => {
                match l.protocol {
                    Protocol::IPV4 => {}
                    _ => return None,
                };
                let mut ip = 0;
                for i in &self.raw()[l.range.clone()][12..16] {
                    ip = (ip << 8) + *i as u32;
                }
                Some(ip)
            }
        }
    }

    fn dst_ipv4(&self) -> Option<u32> {
        match self.layers().network() {
            None => None,
            Some(l) => {
                match l.protocol {
                    Protocol::IPV4 => {}
                    _ => return None,
                };
                let mut ip = 0;
                for i in &self.raw()[l.range.clone()][16..20] {
                    ip = (ip << 8) + *i as u32;
                }
                Some(ip)
            }
        }
    }

    fn src_ipv6(&self) -> Option<&[u8; 16]> {
        match self.layers().network() {
            None => None,
            Some(l) => {
                match l.protocol {
                    Protocol::IPV6 => {}
                    _ => return None,
                };
                <&[u8; 16]>::try_from(&self.raw()[l.range.clone()][8..24])
                    .map_or_else(|_| None, |ip| Some(ip))
            }
        }
    }

    fn dst_ipv6(&self) -> Option<&[u8; 16]> {
        match self.layers().network() {
            None => None,
            Some(l) => {
                match l.protocol {
                    Protocol::IPV6 => {}
                    _ => return None,
                };
                <&[u8; 16]>::try_from(&self.raw()[l.range.clone()][24..40])
                    .map_or_else(|_| None, |ip| Some(ip))
            }
        }
    }

    fn src_mac(&self) -> Option<&[u8; 6]> {
        match self.layers().datalink() {
            None => None,
            Some(l) => {
                match l.protocol {
                    Protocol::ETHERNET => {}
                    _ => return None,
                };
                <&[u8; 6]>::try_from(&self.raw()[l.range.clone()][6..12])
                    .map_or_else(|_| None, |mac| Some(mac))
            }
        }
    }

    fn dst_mac(&self) -> Option<&[u8; 6]> {
        match self.layers().datalink() {
            None => None,
            Some(l) => {
                match l.protocol {
                    Protocol::ETHERNET => {}
                    _ => return None,
                };
                <&[u8; 6]>::try_from(&self.raw()[l.range.clone()][0..6])
                    .map_or_else(|_| None, |mac| Some(mac))
            }
        }
    }

    #[inline]
    /// Get packet's application layer payload
    fn payload(&self) -> &[u8] {
        match self.layers().application() {
            None => &[],
            Some(l) => match l.protocol {
                Protocol::APPLICATION => &self.raw()[l.range.clone()],
                _ => &[],
            },
        }
    }

    #[inline]
    fn direction(&self) -> Direction {
        match self.src_port().cmp(&self.dst_port()) {
            std::cmp::Ordering::Greater => return Direction::Right,
            std::cmp::Ordering::Less => return Direction::Left,
            _ => {}
        }

        if let (Some(src), Some(dst)) = (self.src_ipv4(), self.dst_ipv4()) {
            match src.cmp(&dst) {
                std::cmp::Ordering::Greater => return Direction::Right,
                std::cmp::Ordering::Less => return Direction::Left,
                _ => {}
            }
        }

        if let (Some(src), Some(dst)) = (self.src_ipv6(), self.dst_ipv6()) {
            match src.cmp(&dst) {
                std::cmp::Ordering::Greater => return Direction::Right,
                std::cmp::Ordering::Less => return Direction::Left,
                _ => {}
            }
        }

        Direction::Right
    }
}

impl Clone for Box<dyn Packet> {
    fn clone(&self) -> Self {
        self.clone_box()
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
            .field("datalink layer", &self.layers().datalink().clone())
            .field("network layer", &self.layers().network())
            .field("trans layer", &self.layers().transport())
            .field("app layer", &self.layers().application())
            .finish()
    }
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, AsRefStr)]
/// Protocol collection, 1 byte
pub enum Protocol {
    // Data link layer protocols
    #[strum(serialize = "null")]
    NULL,
    #[strum(serialize = "ethernet")]
    ETHERNET,
    #[strum(serialize = "raw")]
    RAW,
    #[strum(serialize = "frame_relay")]
    FRAME_RELAY,
    #[strum(serialize = "ppp")]
    PPP,
    #[strum(serialize = "mpls")]
    MPLS,
    #[strum(serialize = "pppoe")]
    PPPOE,
    #[strum(serialize = "arp")]
    ARP,

    // Tunnel protocols
    #[strum(serialize = "gre")]
    GRE,
    #[strum(serialize = "l2tp")]
    L2TP,
    #[strum(serialize = "erspan")]
    ERSPAN,

    // Network layer protocols
    #[strum(serialize = "ipv4")]
    IPV4,
    #[strum(serialize = "ipv6")]
    IPV6,
    #[strum(serialize = "icmp")]
    ICMP,
    #[strum(serialize = "clns")]
    CLNS,
    #[strum(serialize = "ddp")]
    DDP,
    #[strum(serialize = "egp")]
    EGP,
    #[strum(serialize = "eigrp")]
    EIGRP,
    #[strum(serialize = "igmp")]
    IGMP,
    #[strum(serialize = "ipx")]
    IPX,
    #[strum(serialize = "esp")]
    ESP,
    #[strum(serialize = "ospf")]
    OSPF,
    #[strum(serialize = "pim")]
    PIM,
    #[strum(serialize = "rip")]
    RIP,
    #[strum(serialize = "vlan")]
    VLAN,
    #[strum(serialize = "wireguard")]
    WIREGUARD,

    // Transport layer protocols
    #[strum(serialize = "tcp")]
    TCP,
    #[strum(serialize = "udp")]
    UDP,
    #[strum(serialize = "sctp")]
    SCTP,

    // Application layer protocols
    #[strum(serialize = "http")]
    HTTP,

    // Unknown protocol
    #[strum(serialize = "unknown")]
    UNKNOWN,

    #[strum(serialize = "application")]
    APPLICATION,
}

impl Default for Protocol {
    #[inline]
    fn default() -> Self {
        Protocol::UNKNOWN
    }
}

bitflags! {
    #[repr(transparent)]
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

pub mod test {
    use super::{Layers, Protocol, Rule, Rules, Tunnel};
    use crate::packet::Packet as PacketTrait;
    use std::ops::Range;

    // Packet structure only for test use
    #[derive(Clone)]
    #[repr(C)]
    pub struct Packet {
        /// timestamp
        pub ts: libc::timeval,
        /// capture length
        pub caplen: u32,
        /// raw packet data
        pub raw: Box<Vec<u8>>,
        /// protocol layers
        pub layers: Layers,
        /// Packet hash, improve hash performance
        pub hash: u64,
        pub rules: Rules,
        pub tunnel: Tunnel,
    }

    impl Default for Packet {
        fn default() -> Self {
            Packet {
                ts: libc::timeval {
                    tv_sec: 0,
                    tv_usec: 0,
                },
                caplen: 0,
                raw: Box::new(Vec::new()),
                layers: Layers::default(),
                hash: 0,
                rules: Rules::default(),
                tunnel: Tunnel::default(),
            }
        }
    }

    impl PacketTrait for Packet {
        fn raw(&self) -> &[u8] {
            self.raw.as_slice()
        }

        fn ts(&self) -> &libc::timeval {
            &self.ts
        }

        fn caplen(&self) -> u32 {
            self.caplen
        }

        fn layers(&self) -> &Layers {
            &self.layers
        }

        fn layers_mut(&mut self) -> &mut Layers {
            &mut self.layers
        }

        fn rules(&self) -> &[Rule] {
            self.rules.as_ref().as_slice()
        }

        fn rules_mut(&mut self) -> &mut Rules {
            &mut self.rules
        }

        fn tunnel(&self) -> Tunnel {
            self.tunnel
        }

        fn tunnel_mut(&mut self) -> &mut Tunnel {
            &mut self.tunnel
        }

        fn clone_box<'a, 'b>(&'a self) -> Box<dyn PacketTrait + 'b> {
            Box::new(self.clone())
        }
    }

    #[test]
    fn test_data_bytes() {}

    #[test]
    fn test_src_port() {
        let mut pkt = Packet::default();
        pkt.raw = Box::new(vec![0x14, 0xe9]);
        println!("len: {}", pkt.layers().layers.len());
        pkt.layers = Layers::new_with_default_max_layers();
        pkt.layers.transport = Some(0);
        let trans_layer = pkt.layers.transport_mut().unwrap();

        trans_layer.range = Range { start: 0, end: 2 };
        trans_layer.protocol = Protocol::TCP;
        assert_eq!(pkt.src_port(), Some(5353));

        let trans_layer = pkt.layers.transport_mut().unwrap();
        trans_layer.range = Range { start: 0, end: 2 };
        trans_layer.protocol = Protocol::UDP;
        assert_eq!(pkt.src_port(), Some(5353));

        let trans_layer = pkt.layers.transport_mut().unwrap();
        trans_layer.range = Range { start: 0, end: 2 };
        trans_layer.protocol = Protocol::SCTP;
        assert_eq!(pkt.src_port(), Some(5353));
    }

    #[test]
    fn test_dst_port() {
        let mut pkt = Packet::default();
        pkt.raw = Box::new(vec![0, 0, 0x14, 0xe9]);
        pkt.layers = Layers::new_with_default_max_layers();
        pkt.layers.transport = Some(0);
        let trans_layer = pkt.layers_mut().transport_mut().unwrap();

        trans_layer.range = Range { start: 0, end: 4 };
        trans_layer.protocol = Protocol::TCP;
        assert_eq!(pkt.dst_port(), Some(5353));

        let trans_layer = pkt.layers_mut().transport_mut().unwrap();
        trans_layer.range = Range { start: 0, end: 4 };
        trans_layer.protocol = Protocol::UDP;
        assert_eq!(pkt.dst_port(), Some(5353));

        let trans_layer = pkt.layers_mut().transport_mut().unwrap();
        trans_layer.range = Range { start: 0, end: 4 };
        trans_layer.protocol = Protocol::SCTP;
        assert_eq!(pkt.dst_port(), Some(5353));
    }

    #[test]
    fn test_src_ipv4() {
        let mut pkt = Packet::default();
        pkt.raw = Box::new(vec![
            0x45, 0x00, 0x02, 0x2d, 0x00, 0x00, 0x40, 0x00, 0x40, 0x06, 0x79, 0x1d, 0xc0, 0xa8,
            0x02, 0xde, 0xda, 0x62, 0x21, 0xc5, 0xe2, 0xb2, 0x01, 0xbb, 0x2b, 0xd5, 0x16, 0xf7,
            0x66, 0x96, 0xcf, 0xb8, 0x50, 0x18, 0x10, 0x00, 0x8a, 0xcf, 0x00, 0x00,
        ]);
        pkt.layers = Layers::new_with_default_max_layers();
        pkt.layers.network = Some(0);
        let end = pkt.raw().len() as usize;
        let network = pkt.layers_mut().network_mut().unwrap();

        network.range.start = 0;
        network.range.end = end;
        network.protocol = Protocol::IPV4;
        assert_eq!(pkt.src_ipv4(), Some(0xc0a802de));
    }

    #[test]
    fn test_dst_ipv4() {
        let mut pkt = Packet::default();
        pkt.raw = Box::new(vec![
            0x45, 0x00, 0x02, 0x2d, 0x00, 0x00, 0x40, 0x00, 0x40, 0x06, 0x79, 0x1d, 0xc0, 0xa8,
            0x02, 0xde, 0xda, 0x62, 0x21, 0xc5, 0xe2, 0xb2, 0x01, 0xbb, 0x2b, 0xd5, 0x16, 0xf7,
            0x66, 0x96, 0xcf, 0xb8, 0x50, 0x18, 0x10, 0x00, 0x8a, 0xcf, 0x00, 0x00,
        ]);
        pkt.layers = Layers::new_with_default_max_layers();
        pkt.layers.network = Some(0);
        let end = pkt.raw().len() as usize;
        let network = pkt.layers_mut().network_mut().unwrap();

        network.range.start = 0;
        network.range.end = end;
        network.protocol = Protocol::IPV4;
        assert_eq!(pkt.dst_ipv4(), Some(0xda6221c5));
    }

    #[test]
    fn test_src_ipv6() {
        let mut pkt = Packet::default();
        pkt.raw = Box::new(vec![
            0x60, 0x0c, 0x6b, 0x7b, 0x00, 0xb8, 0x11, 0xff, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x10, 0x08, 0xfa, 0x70, 0x46, 0xe8, 0x42, 0x04, 0xff, 0x02, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfb,
        ]);
        pkt.layers = Layers::new_with_default_max_layers();
        pkt.layers.network = Some(0);
        let end = pkt.raw().len();
        let network = pkt.layers_mut().network_mut().unwrap();

        network.range.start = 0;
        network.range.end = end;
        network.protocol = Protocol::IPV6;

        assert_eq!(
            pkt.src_ipv6(),
            Some(&[
                0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x08, 0xfa, 0x70, 0x46, 0xe8,
                0x42, 0x04
            ])
        );
    }

    #[test]
    fn test_dst_ipv6() {
        let mut pkt = Packet::default();
        pkt.raw = Box::new(vec![
            0x60, 0x0c, 0x6b, 0x7b, 0x00, 0xb8, 0x11, 0xff, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x10, 0x08, 0xfa, 0x70, 0x46, 0xe8, 0x42, 0x04, 0xff, 0x02, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfb,
        ]);
        pkt.layers = Layers::new_with_default_max_layers();
        pkt.layers.network = Some(0);
        let end = pkt.raw().len();
        let network = pkt.layers_mut().network_mut().unwrap();

        network.range.start = 0;
        network.range.end = end;
        network.protocol = Protocol::IPV6;
        assert_eq!(
            pkt.dst_ipv6(),
            Some(&[
                0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0xfb
            ])
        );
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
