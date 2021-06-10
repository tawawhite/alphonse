use super::{Error, Layer, Protocol};

#[derive(Default)]
pub struct Dissector {}

impl super::Dissector for Dissector {
    #[inline]
    fn dissect(&self, buf: &[u8], offset: u16) -> Result<Option<Layer>, Error> {
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
