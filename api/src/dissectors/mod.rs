use std::fmt::{Display, Formatter};

use anyhow::Result;

use crate::packet::{Layer, Packet, Protocol};

pub mod link;
pub mod network;
pub mod transport;
pub mod tunnel;

use link::LinkType;

/// A dissector only validate protocol format and returns layer start offset
pub trait Dissector {
    /// Parse current layer's protocol, return next layer's protocol and offset
    ///
    /// # Arguments
    ///
    /// * `buf` - Buffer of this layer and its payload
    ///
    /// * `offset` - Position to the start of the packet
    fn dissect(&self, buf: &[u8], offset: u16) -> Result<Option<Layer>, Error>;
}

pub type Callback = fn(buf: &[u8], offset: u16) -> Result<Option<Layer>, Error>;

#[derive(Debug)]
pub enum Error {
    UnsupportProtocol(String),
    CorruptPacket(String),
    UnknownProtocol,
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match &self {
            Error::UnknownProtocol => write!(f, "Unknown Protocol"),
            Error::UnsupportProtocol(s) | Error::CorruptPacket(s) => write!(f, "{}", s),
        }
    }
}

impl std::error::Error for Error {}

pub struct ProtocolDessector {
    /// SnapLen, Snap Length, or snapshot length is the amount of data for each frame
    /// that is actually captured by the network capturing tool and stored into the CaptureFile.
    /// https://wiki.wireshark.org/SnapLen
    _snap_len: u32,
    link_type: LinkType,
    callbacks: Vec<Option<Box<dyn Dissector>>>,
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
        parser.callbacks[Protocol::ETHERNET as u8 as usize] =
            Some(Box::new(link::ethernet::Dissector::default()));
        parser.callbacks[Protocol::NULL as u8 as usize] =
            Some(Box::new(link::null::Dissector::default()));
        parser.callbacks[Protocol::FRAME_RELAY as u8 as usize] =
            Some(Box::new(link::frame_relay::Dissector::default()));

        // tunnel protocol parsers
        parser.callbacks[Protocol::MPLS as u8 as usize] =
            Some(Box::new(tunnel::mpls::Dissector::default()));
        parser.callbacks[Protocol::L2TP as u8 as usize] =
            Some(Box::new(tunnel::l2tp::Dissector::default()));
        parser.callbacks[Protocol::PPP as u8 as usize] =
            Some(Box::new(tunnel::ppp::Dissector::default()));
        parser.callbacks[Protocol::PPPOE as u8 as usize] =
            Some(Box::new(tunnel::pppoe::Dissector::default()));
        parser.callbacks[Protocol::GRE as u8 as usize] =
            Some(Box::new(tunnel::gre::Dissector::default()));

        // network layer protocl parsers
        parser.callbacks[Protocol::IPV4 as u8 as usize] =
            Some(Box::new(network::ipv4::Dissector::default()));
        parser.callbacks[Protocol::IPV6 as u8 as usize] =
            Some(Box::new(network::ipv6::Dissector::default()));
        parser.callbacks[Protocol::VLAN as u8 as usize] =
            Some(Box::new(network::vlan::Dissector::default()));
        parser.callbacks[Protocol::ICMP as u8 as usize] =
            Some(Box::new(network::icmp::Dissector::default()));

        // transport layer protocl parsers
        parser.callbacks[Protocol::TCP as u8 as usize] =
            Some(Box::new(transport::tcp::Dissector::default()));
        parser.callbacks[Protocol::UDP as u8 as usize] =
            Some(Box::new(transport::udp::Dissector::default()));
        parser.callbacks[Protocol::SCTP as u8 as usize] =
            Some(Box::new(transport::sctp::Dissector::default()));

        parser
    }

    /// parse a single packet
    #[inline]
    pub fn parse_pkt(&self, pkt: &mut dyn Packet) -> Result<(), Error> {
        // 根据 link type 解析数据链路层协议, 获取下一层协议的协议类型和起始位置
        let mut result = match self.link_type {
            LinkType::NULL => {
                pkt.layers_mut().data_link.protocol = Protocol::NULL;
                let index = pkt.layers_mut().data_link.protocol as u8 as usize;
                self.callbacks[index]
                    .as_ref()
                    .unwrap()
                    .dissect(pkt.raw(), 0)
            }
            LinkType::ETHERNET => {
                pkt.layers_mut().data_link.protocol = Protocol::ETHERNET;
                let index = pkt.layers_mut().data_link.protocol as u8 as usize;
                self.callbacks[index]
                    .as_ref()
                    .unwrap()
                    .dissect(pkt.raw(), 0)
            }
            LinkType::FRAME_RELAY => {
                pkt.layers_mut().data_link.protocol = Protocol::FRAME_RELAY;
                let index = pkt.layers_mut().data_link.protocol as u8 as usize;
                self.callbacks[index]
                    .as_ref()
                    .unwrap()
                    .dissect(pkt.raw(), 0)
            }
            LinkType::RAW | LinkType::IPV4 => {
                let layer = Layer {
                    protocol: Protocol::IPV4,
                    offset: 0,
                };
                Ok(Some(layer))
            }
            LinkType::IPV6 => {
                let layer = Layer {
                    protocol: Protocol::IPV6,
                    offset: 0,
                };
                Ok(Some(layer))
            }
        };

        let mut layer = match result {
            Ok(l) => match l {
                Some(l) => l,
                None => return Ok(()),
            },
            Err(e) => return Err(e),
        };

        loop {
            let index = layer.protocol as u8 as usize;
            result = match &self.callbacks[index] {
                Some(p) => {
                    match &layer.protocol {
                        Protocol::ETHERNET => pkt.layers_mut().data_link = layer,
                        Protocol::IPV4 | Protocol::IPV6 => pkt.layers_mut().network = layer,
                        Protocol::TCP | Protocol::UDP | Protocol::SCTP => {
                            pkt.layers_mut().trans = layer
                        }
                        _ => {}
                    };
                    let buf = &pkt.raw()[layer.offset as usize..];
                    let offset = layer.offset;
                    p.dissect(buf, offset)
                }
                None => {
                    match layer.protocol {
                        Protocol::APPLICATION => {
                            pkt.layers_mut().app = layer;
                            return Ok(());
                        }
                        _ => {
                            return Err(Error::UnsupportProtocol(format!(
                                "Unsupport protocol {:?}",
                                layer.protocol
                            )))
                        }
                    };
                }
            };

            match result {
                Ok(l) => {
                    layer = match l {
                        None => return Ok(()),
                        Some(l) => l,
                    };
                    // layer = l;
                }
                Err(e) => return Err(e),
            };
        }
    }
}
