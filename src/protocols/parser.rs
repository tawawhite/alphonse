use super::error::ParserError;
use super::{link, network, packet, Protocol};

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
    fn parse(
        &self,
        clayer: u8,
        nlayer: u8,
        pkt: &mut packet::Packet,
    ) -> Result<Protocol, ParserError>;
}

pub struct Parser {
    /// SnapLen, Snap Length, or snapshot length is the amount of data for each frame
    /// that is actually captured by the network capturing tool and stored into the CaptureFile.
    /// https://wiki.wireshark.org/SnapLen
    snap_len: u32,
    link_type: u16,
}

impl Parser {
    /// create a new protocol parser
    pub fn new(link_type: u16) -> Parser {
        Parser {
            snap_len: 65535,
            link_type,
        }
    }
}

impl Parser {
    /// 解析单个数据包
    pub fn parse_pkt(&mut self, pkt: &mut packet::Packet) -> Result<(), ParserError> {
        let mut protocol;

        // 根据 link type 解析数据链路层协议
        let mut result = match self.link_type {
            link::NULL => link::null::parse(pkt),
            link::ETHERNET => link::ethernet::parse(pkt),
            link::RAW | link::IPV4 => Ok(Protocol::IPV4),
            link::IPV6 => Ok(Protocol::IPV6),
            _ => Err(ParserError::UnsupportProtocol(format!(
                "Unsupport data link layer protocol, link type: {}",
                self.link_type
            ))),
        };

        match result {
            Ok(p) => protocol = p,
            Err(e) => return Err(e),
        };

        loop {
            result = match protocol {
                Protocol::UNKNOWN => {
                    break;
                }
                Protocol::ETHERNET => link::ethernet::parse(pkt),
                Protocol::NULL => link::null::parse(pkt),
                Protocol::RAW | Protocol::IPV4 => network::ipv4::parse(pkt),
                Protocol::IPV6 => network::ipv6::parse(pkt),
                Protocol::VLAN => network::vlan::parse(pkt),
                Protocol::ICMP => network::icmp::parse(pkt),
                _ => {
                    return Err(ParserError::UnsupportProtocol(String::from(
                        "Unsupport protocol",
                    )))
                }
            };

            match result {
                Ok(p) => protocol = p,
                Err(_) => {}
            };
        }

        Ok(())
    }
}
