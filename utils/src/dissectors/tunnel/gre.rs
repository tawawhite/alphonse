use nom::bytes::complete::take;
use nom::number::complete::{be_u16, be_u8};
use nom::IResult;
use num_traits::FromPrimitive;

use crate::dissectors::{Error, EtherType, Protocol};

pub fn dissect(data: &[u8]) -> IResult<(usize, Option<Protocol>), &[u8], Error<&[u8]>> {
    let org_len = data.len();
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

    let len = org_len - data.len();
    let protocol = match EtherType::from_u16(proto_type) {
        None => return Ok(((len, Some(Protocol::UNKNOWN)), data)),
        Some(etype) => etype.into(),
    };

    return Ok(((len, Some(protocol)), data));
}

#[cfg(test)]
mod test {
    use anyhow::Result;

    use super::*;

    #[test]
    fn too_short() {
        let buf = [0x00];
        let result = dissect(&buf);
        assert!(matches!(result, Err(nom::Err::Error(Error::Nom(_, _)))));

        let buf = [0x00, 0x01, 0x02];
        let result = dissect(&buf);
        assert!(matches!(result, Err(nom::Err::Error(Error::Nom(_, _)))));
    }

    #[test]
    fn checksum_bit_incomplete() {
        let buf = [0x80, 0x00, 0x00, 0x00];
        let result = dissect(&buf);
        assert!(matches!(result, Err(nom::Err::Error(Error::Nom(_, _)))));
    }

    #[test]
    fn routing_bit_incomplete() {
        let buf = [0x40, 0x00, 0x00, 0x00];
        let result = dissect(&buf);
        assert!(matches!(result, Err(nom::Err::Error(Error::Nom(_, _)))));

        // take(3) fail
        let buf = [0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let result = dissect(&buf);
        println!("result: {:?}", result);
        assert!(matches!(result, Err(nom::Err::Error(Error::Nom(_, _)))));

        // be_u8 fail
        let buf = [
            0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let result = dissect(&buf);
        assert!(matches!(result, Err(nom::Err::Error(Error::Nom(_, _)))));

        // tlen non zero and take(tlen) fail
        let buf = [
            0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        ];
        let result = dissect(&buf);
        assert!(matches!(result, Err(nom::Err::Error(Error::Nom(_, _)))));
    }

    #[test]
    fn key_bit_incomplete() {
        let buf = [0x20, 0x00, 0x00, 0x00];
        let result = dissect(&buf);
        assert!(matches!(result, Err(nom::Err::Error(Error::Nom(_, _)))));
    }

    #[test]
    fn reserve_flags_incomplete() {
        let buf = [0x00, 0x80, 0x00, 0x00];
        let result = dissect(&buf);
        assert!(matches!(result, Err(nom::Err::Error(Error::Nom(_, _)))));
    }

    #[test]
    fn ok() -> Result<()> {
        let buf = [0x10, 0x00, 0x88, 0xbe, 0x00, 0x00, 0x07, 0x07];
        let ((len, protocol), data) = dissect(&buf).unwrap();
        assert_eq!(len, 8);
        assert_eq!(protocol, Some(Protocol::ERSPAN));
        assert_eq!(data.len(), 0);

        Ok(())
    }
}
