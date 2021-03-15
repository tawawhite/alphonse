use super::{Error, Layer, Protocol, SimpleProtocolParser};

#[derive(Default)]
pub struct Parser {}

impl SimpleProtocolParser for Parser {
    #[inline]
    fn parse(&self, buf: &[u8], offset: u16) -> Result<Option<Layer>, Error> {
        if buf.len() < 20 {
            // 如果报文内容长度小于IP报文最短长度(IP协议头长度)
            // 数据包有错误
            return Err(Error::CorruptPacket(format!(
                "Corrupted TCP packet, packet too short ({} bytes)",
                buf.len()
            )));
        }

        let tcp_hdr_len = (buf[12] >> 4) * 4;
        if tcp_hdr_len as usize > buf.len() {
            return Err(Error::CorruptPacket(format!(
                "Corrupted TCP packet, packet too short ({} bytes)",
                buf.len()
            )));
        }

        let layer = Layer {
            protocol: Protocol::APPLICATION,
            offset: offset + tcp_hdr_len as u16,
        };

        Ok(Some(layer))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const PARSER: Parser = Parser {};

    #[test]
    fn test_ok() {
        let buf = [
            0x04, 0x3f, 0x08, 0x22, 0x04, 0x61, 0x1b, 0xea, 0x00, 0x00, 0x00, 0x00, 0xb0, 0x02,
            0xff, 0xff, 0x7c, 0x77, 0x00, 0x00, 0x02, 0x04, 0x05, 0x34, 0x01, 0x03, 0x03, 0x03,
            0x01, 0x01, 0x08, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01,
            0x04, 0x02,
        ];
        assert!(matches!(PARSER.parse(&buf, 0), Ok(_)));
    }

    #[test]
    fn test_err_packet_too_short() {
        let buf = [0x04];
        let result = PARSER.parse(&buf, 0);
        assert!(matches!(result, Err(_)));
        let err = result.unwrap_err();
        assert!(matches!(err, Error::CorruptPacket(_)));
    }

    #[test]
    fn test_err_payload_shorter_then_tcp_hdr_len() {
        let buf = [
            0x04, 0x3f, 0x08, 0x22, 0x04, 0x61, 0x1b, 0xea, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x02,
            0xff, 0xff, 0x7c, 0x77, 0x00, 0x00, 0x02, 0x04, 0x05, 0x34, 0x01, 0x03, 0x03, 0x03,
            0x01, 0x01, 0x08, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01,
            0x04, 0x02,
        ];
        let result = PARSER.parse(&buf, 0);
        assert!(matches!(result, Err(_)));
        let err = result.unwrap_err();
        assert!(matches!(err, Error::CorruptPacket(_)));
    }
}
