use super::{ip_proto, Error, Layer, Protocol, SimpleProtocolParser};

pub struct Parser {}
impl SimpleProtocolParser for Parser {
    #[inline]
    fn parse(buf: &[u8], offset: u16) -> Result<Layer, Error> {
        if buf.len() < 4 * 5 {
            // 如果报文内容长度小于IP报文最短长度(IP协议头长度)
            // 数据包有错误
            return Err(Error::CorruptPacket(format!(
                "Corrupted IPV4 packet, packet too short ({} bytes)",
                buf.len()
            )));
        }

        let ip_vhl = buf[0 + offset as usize];
        let ip_version = ip_vhl >> 4;

        if ip_version != 4 {
            // 如果报文中实际的 IP 版本号不是 IPv4，数据包有错误
            return Err(Error::CorruptPacket(format!(
                "Corrupted IPV4 packet, expecting ip vesrion is 4, actual version is: {}",
                ip_version
            )));
        }

        let ip_hdr_len = ((ip_vhl & 0x0f) * 4) as u16;

        if ip_hdr_len < 4 * 5 || buf.len() < ip_hdr_len as usize {
            // 如果报文中的IP头长度小于20字节或报文长度小于报文中声明的IP头长度, 数据包有错误
            return Err(Error::CorruptPacket(format!("The packet is a corrupt packet, ip header too short nor payload length is less then claimed length")));
        }

        let ip_len = (buf[2 + offset as usize] as u16) << 8 | (buf[3 + offset as usize] as u16);

        if buf.len() < ip_len as usize {
            // 如果报文的长度小于 IP 报文中声明的数据报长度，数据包有错误
            return Err(Error::CorruptPacket(format!(
                "The packet is a corrupt packet, payload length is less then claimed length"
            )));
        }

        let mut layer = Layer {
            protocol: Protocol::default(),
            offset: offset + ip_hdr_len,
        };
        let ip_proto = buf[9 + offset as usize];

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
                return Err(Error::UnsupportProtocol(format!(
                    "Unsupport ipv4 protocol, ipv4 protocol: {}",
                    ip_proto
                )))
            }
        };

        Ok(layer)
    }
}
