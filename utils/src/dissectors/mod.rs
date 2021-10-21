use std::fmt::{Display, Formatter};
use std::ops::Range;

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

/// Parse current layer's protocol, return current layer's length, next layer's protocol and remaining data
///
/// # Arguments
///
/// * `data` - Data of this layer and its payload
pub type Callback = fn(data: &[u8]) -> IResult<(usize, Option<Protocol>), &[u8], Error>;

#[derive(Debug)]
pub enum Error {
    UnsupportProtocol(&'static str),
    UnsupportIPProtocol(u8),
    CorruptPacket(&'static str),
    UnknownProtocol,
    UnknownEtype(u16),
    Nom(ErrorKind),
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::UnknownProtocol => write!(f, "Unknown Protocol"),
            Error::UnknownEtype(etype) => write!(f, "Unknown etype({})", etype),
            Error::UnsupportProtocol(s) | Error::CorruptPacket(s) => write!(f, "{}", s),
            Error::UnsupportIPProtocol(ip_proto) => {
                write!(f, "Unsupport IP Protocol({})", ip_proto)
            }
            Error::Nom(_) => write!(f, "Nom parse error",),
        }
    }
}

impl<I> ParseError<I> for Error {
    fn from_error_kind(_: I, kind: ErrorKind) -> Self {
        Error::Nom(kind)
    }

    fn append(_: I, _: ErrorKind, other: Self) -> Self {
        other
    }
}

impl std::error::Error for Error {}

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
    pub fn parse_pkt(&self, pkt: &mut dyn Packet) -> Result<(), Error> {
        let mut consumed = 0;
        let mut layers = Layers::default();
        let mut cur_proto = None;

        let mut result = match self.link_type {
            LinkType::NULL => Ok(((0, Some(Protocol::NULL)), pkt.raw())),
            LinkType::ETHERNET => Ok(((0, Some(Protocol::ETHERNET)), pkt.raw())),
            LinkType::FRAME_RELAY => Ok(((0, Some(Protocol::FRAME_RELAY)), pkt.raw())),
            LinkType::RAW | LinkType::IPV4 => Ok(((0, Some(Protocol::IPV4)), pkt.raw())),
            LinkType::IPV6 => Ok(((0, Some(Protocol::IPV6)), pkt.raw())),
        };

        loop {
            let ((len, nxt_proto), data) = match result {
                Ok(r) => r,
                Err(e) => {
                    match e {
                        nom::Err::Error(e) => return Err(e),
                        nom::Err::Incomplete(_) => {
                            return Err(Error::Nom(nom::error::ErrorKind::Eof))
                        }
                        nom::Err::Failure(e) => return Err(e),
                    };
                }
            };

            match cur_proto {
                Some(protocol) => {
                    let layer = Layer {
                        protocol,
                        range: Range {
                            start: consumed,
                            end: consumed + len,
                        },
                    };
                    consumed += len;
                    layers.as_mut().push(layer);
                    match protocol {
                        Protocol::ETHERNET => layers.datalink = Some(layers.len() as u8 - 1),
                        Protocol::IPV4 | Protocol::IPV6 => {
                            layers.network = Some(layers.len() as u8 - 1)
                        }
                        Protocol::TCP | Protocol::UDP | Protocol::SCTP => {
                            layers.transport = Some(layers.len() as u8 - 1)
                        }
                        _ => {}
                    };
                }
                None => {}
            };

            let nxt_proto = match nxt_proto {
                Some(p) => match p {
                    Protocol::APPLICATION => {
                        let layer = Layer {
                            protocol: p,
                            range: Range {
                                start: consumed,
                                end: consumed + data.len(),
                            },
                        };
                        layers.as_mut().push(layer);
                        layers.application = Some(layers.len() as u8 - 1);
                        *pkt.layers_mut() = layers;
                        return Ok(());
                    }
                    _ => p,
                },
                None => {
                    *pkt.layers_mut() = layers;
                    return Ok(());
                }
            };
            cur_proto = Some(nxt_proto);

            result = match &self.callbacks[nxt_proto as usize] {
                Some(dissect) => dissect(data),
                None => {
                    return Err(Error::UnsupportProtocol(""));
                }
            };
        }
    }
}
