use nom::bytes::complete::take;
use nom::number::complete::{be_u16, be_u8};
use nom::IResult;
use num_traits::FromPrimitive;

use crate::dissectors::{Error, EtherType, Protocol};

pub fn dissect(data: &[u8]) -> IResult<Option<Protocol>, &[u8], Error<&[u8]>> {
    let (data, _) = take(4usize)(data)?;

    let (data, flags_version) = be_u16(data)?;
    let (mut data, proto_type) = be_u16(data)?;

    if flags_version & (0x8000 | 0x4000) != 0 {
        let (remain, _) = take(4usize)(data)?;
        data = remain
    };

    if (flags_version & 0x2000) != 0 {
        let (remain, _) = take(4usize)(data)?;
        data = remain;
    };

    if (flags_version & 0x1000) != 0 {
        let (remain, _) = take(4usize)(data)?;
        data = remain;
    };

    if (flags_version & 0x4000) != 0 {
        while data.len() > 0 {
            let (remain, _) = take(3usize)(data)?;
            let (remain, tlen) = be_u8(remain)?;
            if tlen == 0 {
                break;
            }
            let (remain, _) = take(tlen as usize)(remain)?;
            data = remain;
        }
    };

    if (flags_version & 0x0080) != 0 {
        let (remain, _) = take(4usize)(data)?;
        data = remain;
    };

    let protocol = match EtherType::from_u16(proto_type) {
        None => return Ok((Some(Protocol::UNKNOWN), data)),
        Some(etype) => etype.into(),
    };

    return Ok((Some(protocol), data));
}

#[cfg(test)]
mod test {
    use anyhow::Result;

    use super::*;

    #[test]
    fn too_short() {
        let buf = [0x00];
        assert!(matches!(dissect(&buf), Err(nom::Err::Incomplete(_))));

        let buf = [0x00, 0x01, 0x02];
        assert!(matches!(dissect(&buf), Err(nom::Err::Incomplete(_))));
    }

    #[test]
    fn checksum_bit_incomplete() {
        let buf = [0x80, 0x00, 0x00, 0x00];
        assert!(matches!(dissect(&buf), Err(nom::Err::Incomplete(_))));
    }

    #[test]
    fn routing_bit_incomplete() {
        let buf = [0x40, 0x00, 0x00, 0x00];
        assert!(matches!(dissect(&buf), Err(nom::Err::Incomplete(_))));

        // take(3) fail
        let buf = [0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert!(matches!(dissect(&buf), Err(nom::Err::Incomplete(_))));

        // be_u8 fail
        let buf = [
            0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        assert!(matches!(dissect(&buf), Err(nom::Err::Incomplete(_))));

        // tlen non zero and take(tlen) fail
        let buf = [
            0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        ];
        assert!(matches!(dissect(&buf), Err(nom::Err::Incomplete(_))));
    }

    #[test]
    fn key_bit_incomplete() {
        let buf = [0x20, 0x00, 0x00, 0x00];
        assert!(matches!(dissect(&buf), Err(nom::Err::Incomplete(_))));
    }

    #[test]
    fn reserve_flags_incomplete() {
        let buf = [0x00, 0x80, 0x00, 0x00];
        assert!(matches!(dissect(&buf), Err(nom::Err::Incomplete(_))));
    }

    #[test]
    fn ok() -> Result<()> {
        let buf = [0x10, 0x00, 0x88, 0xbe, 0x00, 0x00, 0x07, 0x07];
        let (protocol, data) = dissect(&buf).unwrap();
        assert_eq!(protocol, Some(Protocol::ERSPAN));
        assert_eq!(data.len(), 0);

        Ok(())
    }
}
