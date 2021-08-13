use super::{Error, Layer, Protocol};

#[derive(Default)]
pub struct Dissector {}

impl super::Dissector for Dissector {
    #[inline]
    fn dissect(&self, buf: &[u8], offset: u16) -> Result<Option<Layer>, Error> {
        if buf.len() < 8 {
            return Err(Error::CorruptPacket(format!(
                "Corrupt ERSPAN packet, packet too short: {}",
                buf.len(),
            )));
        }

        if buf[0] >> 4 != 1 {
            return Ok(Some(Layer {
                protocol: Protocol::UNKNOWN,
                offset: offset + 8,
            }));
        }

        return Ok(Some(Layer {
            protocol: Protocol::ETHERNET,
            offset: offset + 8,
        }));
    }
}
