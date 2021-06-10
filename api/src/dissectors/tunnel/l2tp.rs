use super::{Error, Layer, Protocol};

const DATAMESSAGE: u16 = 0b0000000000000000;
const CONTROLMESSAGE: u16 = 0b1000000000000000;
const LENGTH: u16 = 0b0100000000000000;
const SEQUENCE: u16 = 0b0000100000000000;
const OFFSET: u16 = 0b0000001000000000;
const PRIORITY: u16 = 0b0000000100000000;

#[repr(u8)]
#[derive(Debug)]
enum Type {
    Data = 0,
    Control = 1,
}

#[derive(Debug)]
struct PacketType {
    _type: Type,
    length: bool,
    sequence: bool,
    offset: bool,
    priority: bool,
}

impl PacketType {
    pub fn new() -> Self {
        Self {
            _type: Type::Control,
            length: false,
            sequence: false,
            offset: false,
            priority: false,
        }
    }
}

#[derive(Default)]
pub struct Dissector {}

impl Dissector {
    #[inline]
    /// Get L2TP protocol version number
    fn l2tp_version(control: u16) -> u16 {
        control & 0x000f
    }
}

impl super::Dissector for Dissector {
    #[inline]
    fn dissect(&self, buf: &[u8], offset: u16) -> Result<Option<Layer>, Error> {
        if buf.len() < 2 {
            return Err(Error::CorruptPacket(format!(
                "Corrupted L2TP packet, packet too short ({} bytes)",
                buf.len()
            )));
        }

        let control = unsafe { (*(buf.as_ptr() as *const u16)).to_be() };
        match Dissector::l2tp_version(control) {
            2 | 3 => {}
            ver => {
                return Err(Error::CorruptPacket(format!(
                    "Unsupported or invalid L2TP version: {})",
                    ver
                )))
            }
        };

        let length = if control & LENGTH == LENGTH {
            unsafe { (*(buf.as_ptr().add(2) as *const u16)).to_be() }
        } else {
            let mut length = 2;
            if control & SEQUENCE == SEQUENCE {
                length += 4;
            }
            if control & OFFSET == OFFSET {
                length += 2;
            }
            if control & PRIORITY == PRIORITY {
                length += 2;
            }
            length += 4; // Tunnel ID & Session ID
            length
        };

        let layer = Layer {
            protocol: Protocol::PPP,
            offset: offset + length,
        };

        Ok(Some(layer))
    }
}

#[cfg(test)]
mod test {
    use crate::dissectors::Dissector as D;

    use super::*;

    #[test]
    fn test_offset_bit_present() {
        let buf = [
            0x02, 0x02, 0x4a, 0x32, 0xd3, 0x5e, 0x00, 0x00, 0xff, 0x03, 0x00, 0x57,
        ];
        let dissector = Dissector::default();
        let result = dissector.dissect(&buf, 0);
        assert!(matches!(result, Ok(_)));

        let layer = result.unwrap();
        assert!(matches!(layer.unwrap().protocol, Protocol::PPP));
        assert_eq!(layer.unwrap().offset, 8);
    }

    #[test]
    fn test_length_bit_present() {
        let buf = [
            0xc8, 0x02, 0x00, 0x14, 0x05, 0xf7, 0x00, 0x00, 0x00, 0x0f, 0x00, 0x02, 0x80, 0x08,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x06,
        ];
        let dissector = Dissector::default();
        let result = dissector.dissect(&buf, 0);
        assert!(matches!(result, Ok(_)));

        let layer = result.unwrap();
        assert!(matches!(layer.unwrap().protocol, Protocol::PPP));
        assert_eq!(layer.unwrap().offset, 20);
    }

    #[test]
    fn test_sequence_bit_present() {
        let buf = [0x08, 0x02, 0x05, 0xf7, 0x00, 0x00, 0x00, 0x0f, 0x00, 0x02];
        let dissector = Dissector::default();
        let result = dissector.dissect(&buf, 0);
        assert!(matches!(result, Ok(_)));

        let layer = result.unwrap();
        assert!(matches!(layer.unwrap().protocol, Protocol::PPP));
        assert_eq!(layer.unwrap().offset, 10);
    }
}
