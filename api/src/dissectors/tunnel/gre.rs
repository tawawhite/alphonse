use super::super::link::ethernet::EtherType;
use super::{Error, Layer, Protocol};

use nom::bytes::streaming::take;
use nom::number::streaming::{be_u16, be_u8};
use nom::IResult;
use num_traits::FromPrimitive;

#[derive(Default)]
pub struct Dissector;

impl super::Dissector for Dissector {
    #[inline]
    fn dissect(&self, buf: &[u8], offset: u16) -> Result<Option<Layer>, Error> {
        if buf.len() < 4 {
            return Err(Error::CorruptPacket(format!("Corrupted GRE packet")));
        }

        let (remain, proto) = dissect(buf).or(Err(Error::CorruptPacket(String::from(
            "Corrupt GRE packet",
        ))))?;
        let offset = offset + (buf.len() - remain.len()) as u16;
        let protocol = match EtherType::from_u16(proto) {
            None => Protocol::UNKNOWN,
            Some(etype) => etype.into(),
        };

        Ok(Some(Layer { protocol, offset }))
    }
}

fn dissect(mut buf: &[u8]) -> IResult<&[u8], u16> {
    let (b, flags_version) = be_u16(buf)?;
    let (b, proto_type) = be_u16(b)?;
    buf = b;

    if flags_version & (0x8000 | 0x4000) != 0 {
        let (b, _) = take(4usize)(buf)?;
        buf = b
    };

    if (flags_version & 0x2000) != 0 {
        let (b, _) = take(4usize)(buf)?;
        buf = b;
    };

    if (flags_version & 0x1000) != 0 {
        let (b, _) = take(4usize)(buf)?;
        buf = b;
    };

    if (flags_version & 0x4000) != 0 {
        while buf.len() > 0 {
            let (b, _) = take(3usize)(buf)?;
            let (b, tlen) = be_u8(b)?;
            if tlen == 0 {
                break;
            }
            let (b, _) = take(tlen as usize)(b)?;
            buf = b;
        }
    };

    if (flags_version & 0x0080) != 0 {
        let (b, _) = take(4usize)(buf)?;
        buf = b;
    };

    Ok((buf, proto_type))
}

#[cfg(test)]
mod test {
    use anyhow::Result;

    use super::super::Dissector as Trait;
    use super::*;

    #[test]
    fn too_short() {
        let buf = [0x00];
        let dissector = Dissector::default();
        assert!(matches!(dissector.dissect(&buf, 0), Err(_)));

        let buf = [0x00, 0x01, 0x02];
        let dissector = Dissector::default();
        assert!(matches!(dissector.dissect(&buf, 0), Err(_)));
    }

    #[test]
    fn checksum_bit_in_complete() {
        let buf = [0x80, 0x00, 0x00, 0x00];
        assert!(matches!(dissect(&buf), Err(_)));
    }

    #[test]
    fn routing_bit_in_complete() {
        let buf = [0x40, 0x00, 0x00, 0x00];
        assert!(matches!(dissect(&buf), Err(_)));

        // take(3) fail
        let buf = [0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert!(matches!(dissect(&buf), Err(_)));

        // be_u8 fail
        let buf = [
            0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        assert!(matches!(dissect(&buf), Err(_)));

        // tlen non zero and take(tlen) fail
        let buf = [
            0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        ];
        assert!(matches!(dissect(&buf), Err(_)));
    }

    #[test]
    fn key_bit_in_complete() {
        let buf = [0x20, 0x00, 0x00, 0x00];
        assert!(matches!(dissect(&buf), Err(_)));
    }

    #[test]
    fn reserve_flags_in_complete() {
        let buf = [0x00, 0x80, 0x00, 0x00];
        assert!(matches!(dissect(&buf), Err(_)));
    }

    #[test]
    fn ok() -> Result<()> {
        let buf = [0x10, 0x00, 0x88, 0xbe, 0x00, 0x00, 0x07, 0x07];
        let dissector = Dissector::default();
        let result = dissector.dissect(&buf, 0);
        assert!(result.is_ok());
        assert!(matches!(&result?, Some(l) if l.protocol == Protocol::ERSPAN && l.offset == 8));

        Ok(())
    }
}
