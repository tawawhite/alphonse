use super::{ip_proto, Layer, ParserError, Protocol, SimpleProtocolParser};

pub struct Parser {}

impl SimpleProtocolParser for Parser {
    #[inline]
    fn parse(buf: &[u8], offset: u16) -> Result<Layer, ParserError> {
        if buf.len() < 40 {
            return Err(ParserError::CorruptPacket(format!(
                "Corrupted IPV6 packet, packet too short ({} bytes)",
                buf.len()
            )));
        }

        let ip_vhl = buf[0];
        let ip_version = ip_vhl >> 4;

        if ip_version != 6 {
            return Err(ParserError::CorruptPacket(format!(
                "Corrupted IPV6 packet, expecting ip vesrion is 6, actual version is: {}",
                ip_version
            )));
        }

        let ip_len = (buf[4] as u16) << 8 | (buf[5] as u16);
        if buf.len() < ip_len as usize {
            // 如果报文的长度小于 IP 报文中声明的数据报长度，数据包有错误
            return Err(ParserError::CorruptPacket(format!(
                "The packet is a corrupt packet, payload length is less then claimed length"
            )));
        }

        let mut layer = Layer {
            protocol: Protocol::default(),
            offset: offset + 40,
        };
        let ip_proto = buf[(6) as usize];

        match ip_proto {
            ip_proto::ICMP => layer.protocol = Protocol::ICMP,
            ip_proto::IPV4 => layer.protocol = Protocol::IPV4,
            ip_proto::TCP => layer.protocol = Protocol::TCP,
            ip_proto::UDP => layer.protocol = Protocol::UDP,
            ip_proto::ESP => layer.protocol = Protocol::ESP,
            ip_proto::IPV6 => layer.protocol = Protocol::IPV6,
            ip_proto::GRE => layer.protocol = Protocol::GRE,
            ip_proto::SCTP => layer.protocol = Protocol::SCTP,
            _ => {
                return Err(ParserError::UnsupportProtocol(format!(
                    "Unsupport ipv6 protocol, ipv6 protocol: {}",
                    ip_proto
                )));
            }
        };
        Ok(layer)
    }
}
