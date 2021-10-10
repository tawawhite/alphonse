use std::fmt::{Display, Formatter};

use anyhow::Result;
use nom::error::{ErrorKind, ParseError};
use nom::IResult;

use alphonse_api as api;
use api::packet::{Layer, Layers, Packet, Protocol};

mod etype;
pub mod link;
pub mod network;
pub mod transport;
pub mod tunnel;

pub use etype::EtherType;
use link::LinkType;

/// Parse current layer's protocol, return next layer's protocol and remaining data
///
/// # Arguments
///
/// * `data` - Data of this layer and its payload
pub type Callback = fn(data: &[u8]) -> IResult<Option<Protocol>, &[u8], Error<&[u8]>>;

#[derive(Debug)]
pub enum Error<I> {
    UnsupportProtocol(&'static str),
    UnsupportIPProtocol(u8),
    CorruptPacket(&'static str),
    UnknownProtocol,
    UnknownEtype(u16),
    Nom(I, ErrorKind),
}

impl<I> Display for Error<I> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::UnknownProtocol => write!(f, "Unknown Protocol"),
            Error::UnknownEtype(etype) => write!(f, "Unknown etype({})", etype),
            Error::UnsupportProtocol(s) | Error::CorruptPacket(s) => write!(f, "{}", s),
            Error::UnsupportIPProtocol(ip_proto) => {
                write!(f, "Unsupport IP Protocol({})", ip_proto)
            }
            Error::Nom(e, ek) => write!(f, "",),
        }
    }
}

impl<I> ParseError<I> for Error<I> {
    fn from_error_kind(input: I, kind: ErrorKind) -> Self {
        Error::Nom(input, kind)
    }

    fn append(_: I, _: ErrorKind, other: Self) -> Self {
        other
    }
}

impl<I: std::fmt::Debug> std::error::Error for Error<I> {}

pub struct ProtocolDessector {
    /// SnapLen, Snap Length, or snapshot length is the amount of data for each frame
    /// that is actually captured by the network capturing tool and stored into the CaptureFile.
    /// https://wiki.wireshark.org/SnapLen
    _snap_len: u32,
    link_type: LinkType,
    callbacks: Vec<Option<Callback>>,
}

impl ProtocolDessector {
    /// create a new protocol parser
    pub fn new(link_type: LinkType) -> Self {
        let mut callbacks = vec![];
        for _ in 0..u8::MAX as usize {
            callbacks.push(None);
        }
        let mut parser = Self {
            _snap_len: 65535,
            link_type,
            callbacks,
        };
        // register protocol callbacks
        // link layer protocol parsers
        parser.callbacks[Protocol::ETHERNET as u8 as usize] = Some(link::ethernet::dissect);
        parser.callbacks[Protocol::NULL as u8 as usize] = Some(link::null::dissect);
        parser.callbacks[Protocol::FRAME_RELAY as u8 as usize] = Some(link::frame_relay::dissect);
        parser.callbacks[Protocol::ARP as u8 as usize] = Some(link::arp::dissect);

        // tunnel protocol parsers
        parser.callbacks[Protocol::MPLS as u8 as usize] = Some(tunnel::mpls::dissect);
        parser.callbacks[Protocol::L2TP as u8 as usize] = Some(tunnel::l2tp::dissect);
        parser.callbacks[Protocol::PPP as u8 as usize] = Some(tunnel::ppp::dissect);
        parser.callbacks[Protocol::PPPOE as u8 as usize] = Some(tunnel::pppoe::dissect);
        parser.callbacks[Protocol::GRE as u8 as usize] = Some(tunnel::gre::dissect);

        // network layer protocl parsers
        parser.callbacks[Protocol::IPV4 as u8 as usize] = Some(network::ipv4::dissect);
        parser.callbacks[Protocol::IPV6 as u8 as usize] = Some(network::ipv6::dissect);
        parser.callbacks[Protocol::VLAN as u8 as usize] = Some(network::vlan::dissect);
        parser.callbacks[Protocol::ICMP as u8 as usize] = Some(network::icmp::dissect);
        parser.callbacks[Protocol::ERSPAN as u8 as usize] = Some(network::erspan::dissect);
        // parser.callbacks[Protocol::ESP as u8 as usize] = Some(Box::new(network::esp::dissect));
        // parser.callbacks[Protocol::IGMP as u8 as usize] = Some(Box::new(network::igmp::dissect));

        // transport layer protocl parsers
        parser.callbacks[Protocol::TCP as u8 as usize] = Some(transport::tcp::dissect);
        parser.callbacks[Protocol::UDP as u8 as usize] = Some(transport::udp::dissect);
        parser.callbacks[Protocol::SCTP as u8 as usize] = Some(transport::sctp::dissect);

        parser
    }

    /// parse a single packet
    #[inline]
    pub fn parse_pkt(&self, pkt: &mut dyn Packet) -> Result<(), Error<&[u8]>> {
        let mut layers = Layers::default();
        // 根据 link type 解析数据链路层协议, 获取下一层协议的协议类型和起始位置
        let mut result = match self.link_type {
            LinkType::NULL => {
                pkt.layers_mut().data_link.protocol = Protocol::NULL;
                let index = pkt.layers_mut().data_link.protocol as u8 as usize;
                self.callbacks[index].unwrap()(pkt.raw())
            }
            LinkType::ETHERNET => {
                pkt.layers_mut().data_link.protocol = Protocol::ETHERNET;
                let index = pkt.layers_mut().data_link.protocol as u8 as usize;
                self.callbacks[index].unwrap()(pkt.raw())
            }
            LinkType::FRAME_RELAY => {
                pkt.layers_mut().data_link.protocol = Protocol::FRAME_RELAY;
                let index = pkt.layers_mut().data_link.protocol as u8 as usize;
                self.callbacks[index].unwrap()(pkt.raw())
            }
            LinkType::RAW | LinkType::IPV4 => Ok((Some(Protocol::IPV4), pkt.raw())),
            LinkType::IPV6 => Ok((Some(Protocol::IPV6), pkt.raw())),
        };

        loop {
            let (protocol, data) = match result {
                Ok((p, data)) => match p {
                    Some(p) => (p, data),
                    None => return Ok(()),
                },
                Err(e) => todo!("properly handle parse error"),
            };

            let offset = (pkt.raw().len() - data.len()) as u16;
            result = match &self.callbacks[protocol as usize] {
                Some(dissect) => {
                    let layer = Layer { offset, protocol };
                    match protocol {
                        Protocol::ETHERNET => layers.data_link = layer,
                        Protocol::IPV4 | Protocol::IPV6 => layers.network = layer,
                        Protocol::TCP | Protocol::UDP | Protocol::SCTP => layers.trans = layer,
                        _ => {}
                    };
                    dissect(data)
                }
                None => {
                    let layer = Layer { offset, protocol };
                    match protocol {
                        Protocol::APPLICATION => {
                            layers.app = layer;
                            return Ok(());
                        }
                        _ => {
                            return Err(Error::UnsupportProtocol(""));
                        }
                    };
                }
            };
        }
    }
}
