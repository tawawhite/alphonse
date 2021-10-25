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

/// Dissector parse result. Means this layer's format and content is ok,
/// but next layer's protocol maybe unsupported or unkown
#[derive(Debug, PartialEq)]
pub enum DissectResult {
    /// Next layer's protocol
    Ok(Protocol),
    /// No next layer
    None,
    /// Next layer's protocol is unkown as unsupported
    UnsupportProtocol(&'static str),
    /// Next layer's IP protocol is unkown as unsupported
    UnsupportIPProtocol(u8),
    /// Next layer's protocol is unkown
    UnknownProtocol,
    /// Next layer's etype is unkown
    UnknownEtype(u16),
}

#[derive(Debug)]
pub struct Error(&'static str);

impl<I> ParseError<I> for Error {
    fn from_error_kind(_: I, _: ErrorKind) -> Self {
        Self("nom parse error")
    }

    fn append(_: I, _: ErrorKind, other: Self) -> Self {
        other
    }
}

/// Parse current layer's protocol, return current layer's length, next layer's protocol and remaining data
///
/// # Arguments
///
/// * `data` - Data of this layer and its payload
pub type Callback = fn(data: &[u8]) -> IResult<&[u8], (usize, DissectResult), Error>;

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

        let mut protocol = match self.link_type {
            LinkType::NULL => Protocol::NULL,
            LinkType::ETHERNET => Protocol::ETHERNET,
            LinkType::FRAME_RELAY => Protocol::FRAME_RELAY,
            LinkType::RAW | LinkType::IPV4 => Protocol::IPV4,
            LinkType::IPV6 => Protocol::IPV6,
        };

        let mut result = match &self.callbacks[protocol as usize] {
            Some(dissect) => dissect(pkt.raw()),
            None => return Err(Error("Unsupport protocol")),
        };

        loop {
            let (data, (len, nxt_proto)) = match result {
                Ok(r) => r,
                Err(e) => {
                    match e {
                        nom::Err::Error(e) => return Err(e),
                        nom::Err::Incomplete(_) => return Err(Error("Packet too short")),
                        nom::Err::Failure(e) => return Err(e),
                    };
                }
            };

            // Push current layer into packet's protocol stack
            let layer = Layer::new(protocol, consumed, consumed + len);
            consumed += len;
            layers.as_mut().push(layer);
            match protocol {
                Protocol::ETHERNET => layers.datalink = Some(layers.len() as u8 - 1),
                Protocol::IPV4 | Protocol::IPV6 => layers.network = Some(layers.len() as u8 - 1),
                Protocol::TCP | Protocol::UDP | Protocol::SCTP => {
                    layers.transport = Some(layers.len() as u8 - 1)
                }
                _ => {}
            };

            protocol = match nxt_proto {
                DissectResult::Ok(p) => match p {
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
                _ => {
                    *pkt.layers_mut() = layers;
                    return Ok(());
                }
            };

            result = match &self.callbacks[protocol as usize] {
                Some(dissect) => dissect(data),
                None => {
                    *pkt.layers_mut() = layers;
                    return Err(Error("Unsupport protocol"));
                }
            };
        }
    }
}
