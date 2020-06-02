use super::error::ParserError;
use super::{link, network, transport, Layer, Packet, Protocol};

/// 仅解析协议在数据包中的开始位置和协议长度的 parser
pub trait SimpleProtocolParser {
    /// 解析当层数据包，并设置下一层的开始位置
    ///
    /// # Arguments
    ///
    /// * `buf` - 该层协议的内容，包含协议头
    ///
    /// * `offset` - 本层协议距离数据包头部的距离
    ///
    /// * `pkt` - 数据包
    fn parse(buf: &[u8], offset: u16) -> Result<Layer, ParserError>;
}

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
    pub fn parse_pkt(&self, pkt: &mut Packet) -> Result<(), ParserError> {
        let mut layer;
        // 根据 link type 解析数据链路层协议, 获取下一层协议的协议类型和起始位置
        let mut result = match self.link_type {
            link::NULL => {
                pkt.data_link_layer.protocol = Protocol::NULL;
                link::null::Parser::parse(pkt.data.as_ref(), 0)
            }
            link::ETHERNET => {
                pkt.data_link_layer.protocol = Protocol::ETHERNET;
                link::ethernet::Parser::parse(pkt.data.as_ref(), 0)
            }
            link::RAW | link::IPV4 => {
                let layer = Layer {
                    protocol: Protocol::IPV4,
                    offset: 0,
                };
                Ok(layer)
            }
            link::IPV6 => {
                let layer = Layer {
                    protocol: Protocol::IPV6,
                    offset: 0,
                };
                Ok(layer)
            }
            _ => {
                return Err(ParserError::UnsupportProtocol(format!(
                    "Unsupport data link layer protocol, link type: {}",
                    self.link_type
                )))
            }
        };

        layer = match result {
            Ok(l) => l,
            Err(e) => return Err(e),
        };

        loop {
            let offset = layer.offset;
            let buf = &pkt.data.as_slice()[layer.offset as usize..];
            result = match &layer.protocol {
                Protocol::ETHERNET => {
                    if pkt.data_link_layer.protocol == Protocol::UNKNOWN {
                        pkt.data_link_layer = layer;
                    }
                    link::ethernet::Parser::parse(buf, offset)
                }
                Protocol::NULL => {
                    if pkt.data_link_layer.protocol == Protocol::UNKNOWN {
                        pkt.data_link_layer = layer;
                    }
                    link::null::Parser::parse(buf, offset)
                }
                Protocol::RAW | Protocol::IPV4 => {
                    if pkt.network_layer.protocol == Protocol::UNKNOWN {
                        pkt.network_layer = layer;
                    }
                    network::ipv4::Parser::parse(buf, offset)
                }
                Protocol::IPV6 => {
                    if pkt.network_layer.protocol == Protocol::UNKNOWN {
                        pkt.network_layer = layer;
                    }
                    network::ipv6::Parser::parse(buf, offset)
                }
                Protocol::VLAN => {
                    if pkt.network_layer.protocol == Protocol::UNKNOWN {
                        pkt.network_layer = layer;
                    }
                    network::vlan::Parser::parse(buf, offset)
                }
                Protocol::ICMP => {
                    if pkt.network_layer.protocol == Protocol::UNKNOWN {
                        pkt.network_layer = layer;
                    }
                    network::icmp::Parser::parse(buf, offset)
                }
                Protocol::TCP => {
                    if pkt.trans_layer.protocol == Protocol::UNKNOWN {
                        pkt.trans_layer = layer;
                    }
                    transport::tcp::Parser::parse(buf, offset)
                }
                Protocol::UDP => {
                    if pkt.trans_layer.protocol == Protocol::UNKNOWN {
                        pkt.trans_layer = layer;
                    }
                    transport::udp::Parser::parse(buf, offset)
                }
                Protocol::APPLICATION => return Ok(()),
                Protocol::UNKNOWN => {
                    return Err(ParserError::UnknownProtocol);
                }
                p => {
                    return Err(ParserError::UnsupportProtocol(format!(
                        "Unsupport protocol {:?}",
                        p
                    )));
                }
            };

            match result {
                Ok(l) => {
                    layer = l;
                }
                Err(e) => return Err(e),
            };
        }
    }
}
