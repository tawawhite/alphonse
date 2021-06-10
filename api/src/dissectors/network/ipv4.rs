use super::{ip_proto, Error, Layer, Protocol};

#[derive(Default)]
pub struct Dissector {}

impl super::Dissector for Dissector {
    #[inline]
    fn dissect(&self, buf: &[u8], offset: u16) -> Result<Option<Layer>, Error> {
        if buf.len() < 4 * 5 {
            // 如果报文内容长度小于IP报文最短长度(IP协议头长度)
            // 数据包有错误
            return Err(Error::CorruptPacket(format!(
                "Corrupted IPV4 packet, packet too short ({} bytes)",
                buf.len()
            )));
        }

        let ip_vhl = buf[0];
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

        let ip_len = (buf[2] as u16) << 8 | (buf[3] as u16);

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
        let ip_proto = buf[9];

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

        Ok(Some(layer))
    }
}

#[cfg(test)]
mod tests {
    use crate::dissectors::Dissector as D;

    use super::*;

    #[test]
    fn test_ok() {
        let buf = [
            0x45, 0x00, 0x00, 0x64, 0x00, 0x0a, 0x00, 0x00, 0xff, 0x01, 0xa5, 0x6a, 0x0a, 0x01,
            0x02, 0x01, 0x0a, 0x22, 0x00, 0x01, // ipv4
            0x08, 0x00, 0x3a, 0x77, 0x0a, 0x39, 0x06, 0x2b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1f,
            0x33, 0x50, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
            0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
            0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
            0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
            0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, //icmp
        ];
        let dissector = Dissector::default();
        let result = dissector.dissect(&buf, 0);
        assert!(matches!(result, Ok(_)));
    }

    #[test]
    fn test_err_pkt_too_short() {
        let buf = [0x45];
        let dissector = Dissector::default();
        let result = dissector.dissect(&buf, 0);
        assert!(matches!(result.unwrap_err(), Error::CorruptPacket(_)));
    }

    #[test]
    fn test_err_not_ipv4() {
        let buf = [
            0x65, 0x00, 0x00, 0x64, 0x00, 0x0a, 0x00, 0x00, 0xff, 0x01, 0xa5, 0x6a, 0x0a, 0x01,
            0x02, 0x01, 0x0a, 0x22, 0x00, 0x01,
        ];
        let dissector = Dissector::default();
        let result = dissector.dissect(&buf, 0);
        assert!(matches!(result.unwrap_err(), Error::CorruptPacket(_)));
    }

    #[test]
    fn test_err_ip_hdr_len_too_short() {
        let buf = [
            0x44, 0x00, 0x00, 0x64, 0x00, 0x0a, 0x00, 0x00, 0xff, 0x01, 0xa5, 0x6a, 0x0a, 0x01,
            0x02, 0x01, 0x0a, 0x22, 0x00, 0x01,
        ];
        let dissector = Dissector::default();
        let result = dissector.dissect(&buf, 0);
        assert!(matches!(result.unwrap_err(), Error::CorruptPacket(_)));
    }

    #[test]
    fn test_err_buf_len_shorter_than_ip_hdr_len() {
        let buf = [
            0x46, 0x00, 0x00, 0x64, 0x00, 0x0a, 0x00, 0x00, 0xff, 0x01, 0xa5, 0x6a, 0x0a, 0x01,
            0x02, 0x01, 0x0a, 0x22, 0x00, 0x01,
        ];
        let dissector = Dissector::default();
        let result = dissector.dissect(&buf, 0);
        assert!(matches!(result.unwrap_err(), Error::CorruptPacket(_)));
    }

    #[test]
    fn test_err_payload_too_short() {
        let buf = [
            0x45, 0x00, 0x00, 0x64, 0x00, 0x0a, 0x00, 0x00, 0xff, 0x01, 0xa5, 0x6a, 0x0a, 0x01,
            0x02, 0x01, 0x0a, 0x22, 0x00, 0x01,
        ];
        let dissector = Dissector::default();
        let result = dissector.dissect(&buf, 0);
        assert!(matches!(result, Err(_)));
        assert!(matches!(result.unwrap_err(), Error::CorruptPacket(_)));
    }

    #[test]
    fn test_err_unsupport_protocol() {
        let buf = [
            0x45, 0x00, 0x00, 0x64, 0x00, 0x0a, 0x00, 0x00, 0xff, 0xff, 0xa5, 0x6a, 0x0a, 0x01,
            0x02, 0x01, 0x0a, 0x22, 0x00, 0x01, //ipv4
            0x08, 0x00, 0x3a, 0x77, 0x0a, 0x39, 0x06, 0x2b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1f,
            0x33, 0x50, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
            0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
            0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
            0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
            0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, // icmp
        ];
        let dissector = Dissector::default();
        let result = dissector.dissect(&buf, 0);
        assert!(matches!(result, Err(_)));
        assert!(matches!(result.unwrap_err(), Error::UnsupportProtocol(_)));
    }
}
