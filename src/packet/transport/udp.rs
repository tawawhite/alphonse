use super::{Error, Layer, Protocol, SimpleProtocolParser};

pub struct Parser {}
impl SimpleProtocolParser for Parser {
    #[inline]
    fn parse(buf: &[u8], offset: u16) -> Result<Layer, Error> {
        if buf.len() < 8 {
            // 如果报文内容长度小于IP报文最短长度(IP协议头长度)
            // 数据包有错误
            return Err(Error::CorruptPacket(format!(
                "Corrupted UDP packet, packet too short ({} bytes)",
                buf.len()
            )));
        }

        let layer = Layer {
            protocol: Protocol::APPLICATION,
            offset: offset + 8,
        };

        Ok(layer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ok() {
        let buf = [
            0xf4, 0x63, 0x00, 0x35, 0x00, 0x28, 0x93, 0xab, 0xe0, 0x39, 0x01, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x77, 0x77, 0x77, 0x06, 0x67, 0x69, 0x74,
            0x68, 0x75, 0x62, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01,
        ];
        let result = Parser::parse(&buf, 0);
        assert!(matches!(result, Ok(_)));

        let layer = result.unwrap();
        assert!(matches!(layer.protocol, Protocol::APPLICATION));
        assert_eq!(layer.offset, 8);
    }

    #[test]
    fn test_pkt_too_short() {
        let buf = [0xf4];
        let result = Parser::parse(&buf, 0);
        assert!(matches!(result, Err(_)));

        let err = result.unwrap_err();
        assert!(matches!(err, Error::CorruptPacket(_)));
    }
}
