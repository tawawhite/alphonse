use super::{Layer, ParserError, Protocol, SimpleProtocolParser};

pub struct Parser {}
impl SimpleProtocolParser for Parser {
    #[inline]
    fn parse(buf: &[u8], offset: u16) -> Result<Layer, ParserError> {
        if buf.len() < 8 {
            // 如果报文内容长度小于IP报文最短长度(IP协议头长度)
            // 数据包有错误
            return Err(ParserError::CorruptPacket(format!(
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
