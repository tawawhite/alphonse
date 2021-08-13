use super::{Error, Layer, Protocol};

#[derive(Default)]
pub struct Dissector;

impl super::Dissector for Dissector {
    #[inline]
    fn dissect(&self, buf: &[u8], offset: u16) -> Result<Option<Layer>, Error> {
        if buf.len() < 8 || buf[0] != 0x11 || buf[1] != 0 {
            return Err(Error::CorruptPacket(format!("Corrupted PPPOE packet")));
        }

        let plen = (((buf[4] as u16) << 8) | buf[5] as u16) as usize;
        if plen != buf.len() - 6 {
            return Err(Error::CorruptPacket(format!("Corrupted PPPOE packet")));
        }

        let protocol = ((buf[6] as u16) << 8) | buf[7] as u16;
        let layer = match protocol {
            0x21 => Layer {
                protocol: Protocol::IPV4,
                offset: offset + 8,
            },
            0x57 => Layer {
                protocol: Protocol::IPV6,
                offset: offset + 8,
            },
            _ => Layer {
                protocol: Protocol::UNKNOWN,
                offset: offset + 8,
            },
        };

        Ok(Some(layer))
    }
}
