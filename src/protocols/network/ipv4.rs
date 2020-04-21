use super::ParserError;
use super::{Layer, Protocol, SimpleProtocolParser};

// const IP: u8 = 0;
const ICMP: u8 = 1;
// const IGMP: u8 = 2;
// const GGP: u8 = 3;
const IPV4: u8 = 4;
const TCP: u8 = 6;
// const ST: u8 = 7;
// const EGP: u8 = 8;
// const PIGP: u8 = 9;
// const RCCMON: u8 = 10;
// const NVPII: u8 = 11;
// const PUP: u8 = 12;
// const ARGUS: u8 = 13;
const UDP: u8 = 17;
const IPV6: u8 = 41;
const GRE: u8 = 47;
const ESP: u8 = 50;
const SCTP: u8 = 132;

pub struct Parser {}
impl SimpleProtocolParser for Parser {
    #[inline]
    fn parse(buf: &[u8]) -> Result<Layer, ParserError> {
        if buf.len() < 4 * 5 {
            // 如果报文内容长度小于IP报文最短长度(IP协议头长度)
            // 数据包有错误
            return Err(ParserError::CorruptPacket(format!(
                "Corrupted IPV4 packet, packet too short ({} bytes)",
                buf.len()
            )));
        }

        let ip_vhl = buf[0];
        let ip_version = ip_vhl >> 4;

        if ip_version != 4 {
            // 如果报文中实际的 IP 版本号不是 IPv4，数据包有错误
            return Err(ParserError::CorruptPacket(format!(
                "Corrupted IPV4 packet, expecting ip vesrion is 4, actual version is: {}",
                ip_version
            )));
        }

        let ip_hdr_len = ((ip_vhl & 0b00001111) * 4) as u16;

        if ip_hdr_len < 4 * 5 || buf.len() < ip_hdr_len as usize {
            // 如果报文中的IP头长度小于20字节或报文长度小于报文中声明的IP头长度, 数据包有错误
            return Err(ParserError::CorruptPacket(format!("The packet is a corrupt packet, ip header too short nor payload length is less then claimed length")));
        }

        let ip_len = (buf[(2) as usize] as u16) << 8 | (buf[(3) as usize] as u16);

        if buf.len() < ip_len as usize {
            // 如果报文的长度小于 IP 报文中声明的数据报长度，数据包有错误
            return Err(ParserError::CorruptPacket(format!(
                "The packet is a corrupt packet, payload length is less then claimed length"
            )));
        }

        let mut layer = Layer {
            protocol: Protocol::default(),
            offset: ip_hdr_len,
        };
        let ip_proto = buf[(9) as usize];

        match ip_proto {
            ICMP => layer.protocol = Protocol::ICMP,
            IPV4 => layer.protocol = Protocol::IPV4,
            TCP => layer.protocol = Protocol::TCP,
            UDP => layer.protocol = Protocol::UDP,
            ESP => layer.protocol = Protocol::ESP,
            IPV6 => layer.protocol = Protocol::IPV6,
            GRE => layer.protocol = Protocol::GRE,
            SCTP => layer.protocol = Protocol::SCTP,
            _ => {
                return Err(ParserError::UnsupportProtocol(format!(
                    "Unsupport ipv4 protocol, ipv4 protocol: {}",
                    ip_proto
                )))
            }
        };

        Ok(layer)
    }
}
