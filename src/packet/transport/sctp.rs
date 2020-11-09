use super::{Error, Layer, Protocol, SimpleProtocolParser};

pub struct Parser {}
impl SimpleProtocolParser for Parser {
    #[inline]
    fn parse(buf: &[u8], offset: u16) -> Result<Option<Layer>, Error> {
        if buf.len() < 12 {
            return Err(Error::CorruptPacket(format!(
                "Corrupted SCTP packet, packet too short ({} bytes)",
                buf.len()
            )));
        }

        // here we asume sctp must has at least one data chunk
        // need checking rfc document to make sure
        let layer = Layer {
            protocol: Protocol::APPLICATION,
            offset: offset + 16 as u16,
        };

        Ok(Some(layer))
    }
}
