use super::{Error, Layer, Protocol, SimpleProtocolParser};

pub struct Parser {}

impl SimpleProtocolParser for Parser {
    #[inline]
    fn parse(buf: &[u8], _offset: u16) -> Result<Option<Layer>, Error> {
        if buf.len() < 4 {
            return Err(Error::CorruptPacket(format!(
                "The packet is corrupted, packet too short ({} bytes)",
                buf.len()
            )));
        }

        let mut layer = Layer {
            protocol: Protocol::default(),
            offset: 0,
        };
        layer.offset = 4;
        let link_type = buf[0];

        // from https://www.tcpdump.org/linktypes.html
        match link_type {
            2 => layer.protocol = Protocol::IPV4,
            // OSI packets
            7 => {
                return Err(Error::UnsupportProtocol(format!(
                    "Does not support OSI packet"
                )))
            }
            // IPX packets
            23 => {
                return Err(Error::UnsupportProtocol(format!(
                    "Does not support IPX packet"
                )))
            }
            24 | 28 | 30 => layer.protocol = Protocol::IPV6,
            _ => {
                return Err(Error::UnsupportProtocol(format!(
                    "Unknown protocol {}",
                    buf[0],
                )))
            }
        }

        Ok(Some(layer))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ok_ipv4() {
        let buf = [
            0x02, 0x80, 0xc2, 0x00, 0x00, 0x00, 0xcc, 0x04, 0x0d, 0x5c, 0xf0, 0x00, 0x08, 0x00,
        ];
        let result = Parser::parse(&buf, 0);
        assert!(matches!(result, Ok(_)));

        let l = result.unwrap();
        assert!(matches!(l, Some(_)));
        assert!(matches!(l.unwrap().protocol, Protocol::IPV4));
    }

    #[test]
    fn test_ok_ipv6() {
        let buf = [
            24, 0x80, 0xc2, 0x00, 0x00, 0x00, 0xcc, 0x04, 0x0d, 0x5c, 0xf0, 0x00, 0x08, 0x00,
        ];
        let result = Parser::parse(&buf, 0);
        assert!(matches!(result, Ok(_)));

        let l = result.unwrap();
        assert!(matches!(l, Some(_)));
        assert!(matches!(l.unwrap().protocol, Protocol::IPV6));

        let buf = [
            28, 0x80, 0xc2, 0x00, 0x00, 0x00, 0xcc, 0x04, 0x0d, 0x5c, 0xf0, 0x00, 0x08, 0x00,
        ];
        let result = Parser::parse(&buf, 0);
        assert!(matches!(result, Ok(_)));

        let l = result.unwrap();
        assert!(matches!(l, Some(_)));
        assert!(matches!(l.unwrap().protocol, Protocol::IPV6));

        let buf = [
            28, 0x80, 0xc2, 0x00, 0x00, 0x00, 0xcc, 0x04, 0x0d, 0x5c, 0xf0, 0x00, 0x08, 0x00,
        ];
        let result = Parser::parse(&buf, 0);
        assert!(matches!(result, Ok(_)));

        let l = result.unwrap();
        assert!(matches!(l, Some(_)));
        assert!(matches!(l.unwrap().protocol, Protocol::IPV6));
    }

    #[test]
    fn test_err_pkt_too_short() {
        let buf = [0x01];
        let result = Parser::parse(&buf, 0);
        assert!(matches!(result, Err(_)));
        assert!(matches!(result.unwrap_err(), Error::CorruptPacket(_)));
    }

    #[test]
    fn test_err_unsupport_protocol() {
        let buf = [
            0x07, 0x80, 0xc2, 0x00, 0x00, 0x00, 0xcc, 0x04, 0x0d, 0x5c, 0xf0, 0x00, 0x06, 0x00,
        ];
        let result = Parser::parse(&buf, 0);
        assert!(matches!(result, Err(_)));
        assert!(matches!(result.unwrap_err(), Error::UnsupportProtocol(_)));

        let buf = [
            23, 0x80, 0xc2, 0x00, 0x00, 0x00, 0xcc, 0x04, 0x0d, 0x5c, 0xf0, 0x00, 0x06, 0x00,
        ];
        let result = Parser::parse(&buf, 0);
        assert!(matches!(result, Err(_)));
        assert!(matches!(result.unwrap_err(), Error::UnsupportProtocol(_)));
    }
}
