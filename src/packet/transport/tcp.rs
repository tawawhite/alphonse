use super::{Error, Layer, Protocol, SimpleProtocolParser};

pub struct Parser {}
impl SimpleProtocolParser for Parser {
    #[inline]
    fn parse(buf: &[u8], offset: u16) -> Result<Layer, Error> {
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

        Ok(layer)
    }
}
