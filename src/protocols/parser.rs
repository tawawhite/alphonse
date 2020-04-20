use super::error::ParserError;
use super::{link, network, packet, Layer, Protocol};

/// 仅解析协议在数据包中的开始位置和协议长度的 parser
pub trait SimpleProtocolParser {
    /// 解析当层数据包，并设置下一层的开始位置
    ///
    /// # Arguments
    ///
    /// * `clayer` - 当前层协议对应的层级
    ///
    /// * `nlayer` - 下一层协议的对应的层级
    ///
    /// * `pkt` - 数据包
    fn parse(buf: &[u8]) -> Result<(Layer, u16), ParserError>;
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
    pub fn parse_pkt(&self, pkt: &mut packet::Packet) -> Result<(), ParserError> {
        // 根据 link type 解析数据链路层协议
        let mut result = match self.link_type {
            link::NULL => {
                pkt.layers[0].protocol = Protocol::NULL;
                pkt.last_layer_index += 1;
                link::null::Parser::parse(pkt.data.as_ref())
            }
            link::ETHERNET => {
                pkt.layers[0].protocol = Protocol::ETHERNET;
                pkt.last_layer_index += 1;
                link::ethernet::Parser::parse(pkt.data.as_ref())
            }
            link::RAW | link::IPV4 => {
                pkt.layers[0].protocol = Protocol::IPV4;
                let layer = Layer {
                    protocol: Protocol::IPV4,
                    offset: 0,
                };
                Ok((layer, 0))
            }
            link::IPV6 => {
                pkt.layers[0].protocol = Protocol::IPV6;
                let layer = Layer {
                    protocol: Protocol::IPV6,
                    offset: 0,
                };
                Ok((layer, 0))
            }
            _ => {
                return Err(ParserError::UnsupportProtocol(format!(
                    "Unsupport data link layer protocol, link type: {}",
                    self.link_type
                )))
            }
        };

        let mut layer;
        let mut offset;
        match result {
            Ok((l, o)) => {
                layer = l;
                offset = o as usize;
            }
            Err(e) => return Err(e),
        };

        loop {
            let buf = &pkt.data.as_slice()[offset..];
            result = match layer.protocol {
                Protocol::UNKNOWN => {
                    break;
                }
                Protocol::ETHERNET => link::ethernet::Parser::parse(buf),
                Protocol::NULL => link::null::Parser::parse(buf),
                Protocol::RAW | Protocol::IPV4 => network::ipv4::Parser::parse(buf),
                Protocol::IPV6 => network::ipv6::Parser::parse(buf),
                Protocol::VLAN => network::vlan::Parser::parse(buf),
                Protocol::ICMP => network::icmp::Parser::parse(buf),
                p => {
                    return Err(ParserError::UnsupportProtocol(format!(
                        "Unsupport protocol {:?}",
                        p
                    )))
                }
            };

            match result {
                Ok((l, o)) => {
                    layer = l;
                    offset = o as usize;
                }
                Err(e) => return Err(e),
            };
        }

        Ok(())
    }
}
