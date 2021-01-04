use std::fmt::{Display, Formatter};

use anyhow::Result;

use super::{link, network, transport, tunnel, Layer, Packet, Protocol};

/// 仅解析协议在数据包中的开始位置和协议长度的 parser
pub trait SimpleProtocolParser {
    /// 解析当层数据包，并设置下一层的开始位置
    ///
    /// # Arguments
    ///
    /// * `buf` - Buffer of this layer and its payload
    ///
    /// * `offset` - Position to the start of the packet
    fn parse(buf: &[u8], offset: u16) -> Result<Option<Layer>, Error>;
}

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

pub struct Parser {
    /// SnapLen, Snap Length, or snapshot length is the amount of data for each frame
    /// that is actually captured by the network capturing tool and stored into the CaptureFile.
    /// https://wiki.wireshark.org/SnapLen
    _snap_len: u32,
    link_type: u16,
}

impl Parser {
    /// create a new protocol parser
    pub fn new(link_type: u16) -> Parser {
        Parser {
            _snap_len: 65535,
            link_type,
        }
    }
}

impl Parser {
    /// 解析单个数据包
    #[inline]
    pub fn parse_pkt(&self, pkt: &mut dyn Packet) -> Result<(), Error> {
        // 根据 link type 解析数据链路层协议, 获取下一层协议的协议类型和起始位置
        let mut result = match self.link_type {
            link::NULL => {
                pkt.data_link_layer().protocol = Protocol::NULL;
                link::null::Parser::parse(pkt.raw(), 0)
            }
            link::ETHERNET => {
                pkt.data_link_layer().protocol = Protocol::ETHERNET;
                link::ethernet::Parser::parse(pkt.raw(), 0)
            }
            link::RAW | link::IPV4 => {
                let layer = Layer {
                    protocol: Protocol::IPV4,
                    offset: 0,
                };
                Ok(Some(layer))
            }
            link::IPV6 => {
                let layer = Layer {
                    protocol: Protocol::IPV6,
                    offset: 0,
                };
                Ok(Some(layer))
            }
            _ => {
                return Err(Error::UnsupportProtocol(format!(
                    "Unsupport data link layer protocol, link type: {}",
                    self.link_type
                )))
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
            let offset = layer.offset;
            result = match &layer.protocol {
                Protocol::ETHERNET => {
                    if pkt.data_link_layer().protocol == Protocol::UNKNOWN {
                        *pkt.data_link_layer_mut() = layer;
                    }
                    let buf = &pkt.raw()[layer.offset as usize..];
                    link::ethernet::Parser::parse(buf, offset)
                }
                Protocol::NULL => {
                    if pkt.data_link_layer().protocol == Protocol::UNKNOWN {
                        *pkt.data_link_layer_mut() = layer;
                    }
                    let buf = &pkt.raw()[layer.offset as usize..];
                    link::null::Parser::parse(buf, offset)
                }
                Protocol::MPLS => {
                    let buf = &pkt.raw()[layer.offset as usize..];
                    tunnel::mpls::Parser::parse(buf, offset)
                }
                Protocol::RAW | Protocol::IPV4 => {
                    if pkt.network_layer().protocol == Protocol::UNKNOWN {
                        *pkt.network_layer_mut() = layer;
                    }
                    let buf = &pkt.raw()[layer.offset as usize..];
                    network::ipv4::Parser::parse(buf, offset)
                }
                Protocol::IPV6 => {
                    if pkt.network_layer().protocol == Protocol::UNKNOWN {
                        *pkt.network_layer_mut() = layer;
                    }
                    let buf = &pkt.raw()[layer.offset as usize..];
                    network::ipv6::Parser::parse(buf, offset)
                }
                Protocol::VLAN => {
                    if pkt.network_layer().protocol == Protocol::UNKNOWN {
                        *pkt.network_layer_mut() = layer;
                    }
                    let buf = &pkt.raw()[layer.offset as usize..];
                    network::vlan::Parser::parse(buf, offset)
                }
                Protocol::ICMP => {
                    if pkt.network_layer().protocol == Protocol::UNKNOWN {
                        *pkt.network_layer_mut() = layer;
                    }
                    let buf = &pkt.raw()[layer.offset as usize..];
                    network::icmp::Parser::parse(buf, offset)
                }
                Protocol::TCP => {
                    if pkt.trans_layer_mut().protocol == Protocol::UNKNOWN {
                        *pkt.trans_layer_mut() = layer;
                    }
                    let buf = &pkt.raw()[layer.offset as usize..];
                    transport::tcp::Parser::parse(buf, offset)
                }
                Protocol::UDP => {
                    if pkt.trans_layer_mut().protocol == Protocol::UNKNOWN {
                        *pkt.trans_layer_mut() = layer;
                    }
                    let buf = &pkt.raw()[layer.offset as usize..];
                    transport::udp::Parser::parse(buf, offset)
                }
                Protocol::SCTP => {
                    if pkt.trans_layer_mut().protocol == Protocol::UNKNOWN {
                        *pkt.trans_layer_mut() = layer;
                    }
                    let buf = &pkt.raw()[layer.offset as usize..];
                    transport::sctp::Parser::parse(buf, offset)
                }
                Protocol::APPLICATION => {
                    *pkt.app_layer_mut() = layer;
                    return Ok(());
                }
                Protocol::UNKNOWN => {
                    return Err(Error::UnknownProtocol);
                }
                p => {
                    return Err(Error::UnsupportProtocol(format!(
                        "Unsupport protocol {:?}",
                        p
                    )));
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
