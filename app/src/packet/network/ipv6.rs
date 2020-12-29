use super::{ip_proto, Error, Layer, Protocol, SimpleProtocolParser};

pub struct Parser {}

impl SimpleProtocolParser for Parser {
    #[inline]
    fn parse(buf: &[u8], offset: u16) -> Result<Option<Layer>, Error> {
        if buf.len() < 40 {
            return Err(Error::CorruptPacket(format!(
                "Corrupted IPV6 packet, packet too short ({} bytes)",
                buf.len()
            )));
        }

        let ip_vhl = buf[0];
        let ip_version = ip_vhl >> 4;

        if ip_version != 6 {
            return Err(Error::CorruptPacket(format!(
                "Corrupted IPV6 packet, expecting ip vesrion is 6, actual version is: {}",
                ip_version
            )));
        }

        let ip_len = (buf[4] as u16) << 8 | (buf[5] as u16);
        if buf.len() < ip_len as usize {
            // 如果报文的长度小于 IP 报文中声明的数据报长度，数据包有错误
            return Err(Error::CorruptPacket(format!(
                "The packet is a corrupt packet, payload length is less then claimed length"
            )));
        }

        let mut layer = Layer {
            protocol: Protocol::default(),
            offset: offset + 40,
        };
        let ip_proto = buf[6];

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
                    "Unsupport ipv6 protocol, ipv6 protocol: {}",
                    ip_proto
                )));
            }
        };
        Ok(Some(layer))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ok() {
        let buf = [
            0x60, 0x02, 0xd9, 0x95, 0x01, 0x54, 0x11, 0xf2, 0x11, 0x11, 0x22, 0x22, 0x33, 0x33,
            0x44, 0x44, 0x55, 0x55, 0x77, 0x77, 0x00, 0x00, 0x00, 0x00, 0x11, 0x11, 0x22, 0x22,
            0x33, 0x33, 0x44, 0x44, 0x55, 0x55, 0x88, 0x88, 0xa8, 0xac, 0x7b, 0xc0, // ipv6
            0x00, 0x35, 0xde, 0xc6, 0x01, 0x54, 0xe8, 0x6a, //udp
            0x9d, 0x46, 0x81, 0x80, 0x00, 0x01, 0x00, 0x11, 0x00, 0x00, 0x00, 0x00, 0x07, 0x78,
            0x78, 0x78, 0x78, 0x78, 0x78, 0x35, 0x08, 0x78, 0x78, 0x78, 0x78, 0x78, 0x78, 0x78,
            0x36, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x05,
            0x00, 0x01, 0x00, 0x00, 0x00, 0x07, 0x00, 0x13, 0x06, 0x78, 0x78, 0x78, 0x78, 0x78,
            0x37, 0x01, 0x78, 0x07, 0x78, 0x78, 0x78, 0x78, 0x78, 0x78, 0x38, 0xc0, 0x1d, 0xc0,
            0x32, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x0b, 0x2f, 0x00, 0x0b, 0x08, 0x78, 0x78,
            0x78, 0x78, 0x78, 0x78, 0x78, 0x39, 0xc0, 0x3b, 0xc0, 0x51, 0x00, 0x01, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x25, 0x00, 0x04, 0x0a, 0x01, 0x09, 0xb6, 0xc0, 0x51, 0x00, 0x01,
            0x00, 0x01, 0x00, 0x00, 0x00, 0x25, 0x00, 0x04, 0x0a, 0x01, 0x09, 0x86, 0xc0, 0x51,
            0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x25, 0x00, 0x04, 0x0a, 0x01, 0x0a, 0xb6,
            0xc0, 0x51, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x25, 0x00, 0x04, 0x0a, 0x01,
            0xe0, 0x46, 0xc0, 0x51, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x25, 0x00, 0x04,
            0x0a, 0x01, 0x0a, 0x96, 0xc0, 0x51, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x25,
            0x00, 0x04, 0x0a, 0x01, 0xe0, 0x66, 0xc0, 0x51, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
            0x00, 0x25, 0x00, 0x04, 0x0a, 0x01, 0xe9, 0xb6, 0xc0, 0x51, 0x00, 0x01, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x25, 0x00, 0x04, 0x0a, 0x01, 0xe9, 0x96, 0xc0, 0x51, 0x00, 0x01,
            0x00, 0x01, 0x00, 0x00, 0x00, 0x25, 0x00, 0x04, 0x0a, 0x01, 0xe0, 0x76, 0xc0, 0x51,
            0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x25, 0x00, 0x04, 0x0a, 0x01, 0xe9, 0x86,
            0xc0, 0x51, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x25, 0x00, 0x04, 0x0a, 0x01,
            0x0a, 0xa6, 0xc0, 0x51, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x25, 0x00, 0x04,
            0x0a, 0x01, 0x09, 0xa6, 0xc0, 0x51, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x25,
            0x00, 0x04, 0x0a, 0x01, 0x0a, 0x86, 0xc0, 0x51, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
            0x00, 0x25, 0x00, 0x04, 0x0a, 0x01, 0xe0, 0x56, 0xc0, 0x51, 0x00, 0x01, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x25, 0x00, 0x04, 0x0a, 0x01, 0x09, 0x96, //dns
        ];
        let result = Parser::parse(&buf, 0);
        assert!(matches!(result, Ok(_)));
    }

    #[test]
    fn test_err_pkt_too_short() {
        let buf = [0x60];
        let result = Parser::parse(&buf, 0);
        assert!(matches!(result.unwrap_err(), Error::CorruptPacket(_)));
    }

    #[test]
    fn test_err_not_ipv6() {
        let buf = [
            0x45, 0x00, 0x00, 0x64, 0x00, 0x0a, 0x00, 0x00, 0xff, 0x01, 0xa5, 0x6a, 0x0a, 0x01,
            0x02, 0x01, 0x0a, 0x22, 0x00, 0x01,
        ];
        let result = Parser::parse(&buf, 0);
        assert!(matches!(result.unwrap_err(), Error::CorruptPacket(_)));
    }

    #[test]
    fn test_err_buf_len_shorter_than_ip_hdr_len() {
        let buf = [
            0x60, 0x00, 0x00, 0x00, 0x00, 0x3c, 0x3a, 0x40, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00,
            0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x20, 0x01, 0x0d, 0xb8,
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
        ];
        let result = Parser::parse(&buf, 0);
        assert!(matches!(result.unwrap_err(), Error::CorruptPacket(_)));
    }

    #[test]
    fn test_err_unsupport_protocol() {
        let buf = [
            0x60, 0x00, 0x00, 0x00, 0x00, 0x3c, 0xff, 0x40, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00,
            0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x20, 0x01, 0x0d, 0xb8,
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, //ipv4
            0x08, 0x00, 0x3a, 0x77, 0x0a, 0x39, 0x06, 0x2b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1f,
            0x33, 0x50, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
            0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
            0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
            0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
            0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, // icmpv6
        ];
        let result = Parser::parse(&buf, 0);
        assert!(matches!(result, Err(_)));
        assert!(matches!(result.unwrap_err(), Error::UnsupportProtocol(_)));
    }
}