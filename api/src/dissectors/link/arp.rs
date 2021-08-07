use super::Error;
use super::Layer;

#[derive(Default)]
pub struct Dissector {}

impl super::Dissector for Dissector {
    #[inline]
    fn dissect(&self, buf: &[u8], _offset: u16) -> Result<Option<Layer>, Error> {
        if buf.len() < 28 {
            return Err(Error::CorruptPacket(format!(
                "The arp packet is corrupted, packet too short ({} bytes)",
                buf.len()
            )));
        }

        if buf[7] > 2 {
            // Neither a request nor a response
            return Err(Error::CorruptPacket(format!(
                "The arp packet is corrupted, Neither a request nor a response"
            )));
        }

        Ok(None)
    }
}
