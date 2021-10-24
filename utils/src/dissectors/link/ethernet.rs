use nom::bytes::complete::take;
use nom::number::complete::be_u16;
use nom::IResult;
use num_traits::FromPrimitive;

use crate::dissectors::{DissectResult, Error, EtherType};

pub fn dissect(data: &[u8]) -> IResult<&[u8], (usize, DissectResult), Error> {
    let (remain, data) = take(14usize)(data)?;
    let (_, etype) = be_u16(&data[12..])?;
    match EtherType::from_u16(etype) {
        None => Ok((remain, (14, DissectResult::UnknownEtype(etype)))),
        Some(etype) => Ok((remain, (14, DissectResult::Ok(etype.into())))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ok() {
        let buf = [
            0x01, 0x80, 0xc2, 0x00, 0x00, 0x00, 0xcc, 0x04, 0x0d, 0x5c, 0xf0, 0x00, 0x08, 0x00,
        ];
        assert!(matches!(dissect(&buf), Ok(_)));
    }

    #[test]
    fn pkt_too_short() {
        let buf = [
            0x01, 0x80, 0xc2, 0x00, 0x00, 0x00, 0xcc, 0x04, 0x0d, 0x5c, 0xf0, 0x00,
        ];
        let result = dissect(&buf);
        assert!(matches!(result, Err(nom::Err::Error(_))));
    }

    #[test]
    fn unkown_etype() {
        let buf = [
            0x01, 0x80, 0xc2, 0x00, 0x00, 0x00, 0xcc, 0x04, 0x0d, 0x5c, 0xf0, 0x00, 0x06, 0x00,
        ];
        let result = dissect(&buf);
        assert!(matches!(
            result,
            Ok((_, (_, DissectResult::UnknownEtype(_))))
        ));
    }
}
