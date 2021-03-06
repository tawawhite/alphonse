use nom::bytes::complete::take;
use nom::number::complete::be_u16;
use nom::IResult;

use crate::dissectors::{DissectResult, Error, Protocol};

pub fn dissect(data: &[u8]) -> IResult<&[u8], (usize, DissectResult), Error> {
    let (remain, data) = take(8usize)(data)?;

    let (data, src_port) = be_u16(data)?;
    let (data, dst_port) = be_u16(data)?;
    if src_port == 1701 && dst_port == 1701 {
        return Ok((remain, (8, DissectResult::Ok(Protocol::L2TP))));
    }

    return Ok((remain, (8, DissectResult::Ok(Protocol::APPLICATION))));
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_ok() {
        let buf = [
            0xf4, 0x63, 0x00, 0x35, 0x00, 0x28, 0x93, 0xab, 0xe0, 0x39, 0x01, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x77, 0x77, 0x77, 0x06, 0x67, 0x69, 0x74,
            0x68, 0x75, 0x62, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01,
        ];
        let result = dissect(&buf);
        assert!(matches!(result, Ok(_)));

        let (remain, (_, protocol)) = result.unwrap();
        assert!(matches!(protocol, DissectResult::Ok(Protocol::APPLICATION)));
        assert_eq!(remain.len(), 32);
    }

    #[test]
    fn test_pkt_too_short() {
        let buf = [0xf4];
        let result = dissect(&buf);
        assert!(matches!(result, Err(nom::Err::Error(_))));
    }

    #[test]
    fn l2tp() {
        let buf = [0x06, 0xa5, 0x06, 0xa5, 0x00, 0x54, 0x00, 0x00];
        let result = dissect(&buf);
        assert!(matches!(result, Ok(_)));

        let (remain, (_, protocol)) = result.unwrap();
        assert!(matches!(protocol, DissectResult::Ok(Protocol::L2TP)));
        assert_eq!(remain.len(), 0);
    }
}
