use super::{Error, Layer, Protocol, SimpleProtocolParser};

#[derive(Default)]
pub struct Parser;

impl SimpleProtocolParser for Parser {
    #[inline]
    fn parse(&self, buf: &[u8], offset: u16) -> Result<Option<Layer>, Error> {
        if buf.len() < 4 || buf[2] != 0x00 {
            return Err(Error::CorruptPacket(format!("Corrupted PPPOE packet")));
        }

        let layer = match buf[3] {
            0x21 => Layer {
                protocol: Protocol::IPV4,
                offset: offset + 4,
            },
            0x57 => Layer {
                protocol: Protocol::IPV6,
                offset: offset + 4,
            },
            _ => Layer {
                protocol: Protocol::UNKNOWN,
                offset: offset + 4,
            },
        };

        Ok(Some(layer))
    }
}
