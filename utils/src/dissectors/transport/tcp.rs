use nom::bytes::complete::take;
use nom::combinator::peek;
use nom::IResult;

use crate::dissectors::{DissectResult, Error, Protocol};

pub fn dissect(data: &[u8]) -> IResult<&[u8], (usize, DissectResult), Error> {
    let (remain, data) = peek(take(13usize))(data)?;
    let tcp_hdr_len = ((data[12] >> 4) * 4) as usize;
    if tcp_hdr_len < 20 {
        return Err(nom::Err::Error(Error(
            "Corrupted TCP packet, tcp header len too short",
        )));
    }

    let (remain, _) = take(tcp_hdr_len)(remain)?;
    return Ok((
        remain,
        (tcp_hdr_len, DissectResult::Ok(Protocol::APPLICATION)),
    ));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ok() {
        let buf = [
            0x04, 0x3f, 0x08, 0x22, 0x04, 0x61, 0x1b, 0xea, 0x00, 0x00, 0x00, 0x00, 0xb0, 0x02,
            0xff, 0xff, 0x7c, 0x77, 0x00, 0x00, 0x02, 0x04, 0x05, 0x34, 0x01, 0x03, 0x03, 0x03,
            0x01, 0x01, 0x08, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01,
            0x04, 0x02,
        ];
        assert!(matches!(dissect(&buf), Ok(_)));
    }

    #[test]
    fn test_err_packet_too_short() {
        let buf = [0x04];
        let result = dissect(&buf);
        assert!(matches!(result, Err(_)));
        assert!(matches!(result, Err(nom::Err::Error(_))));
    }

    #[test]
    fn test_err_payload_shorter_then_tcp_hdr_len() {
        let buf = [
            0x04, 0x3f, 0x08, 0x22, 0x04, 0x61, 0x1b, 0xea, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x02,
            0xff, 0xff, 0x7c, 0x77, 0x00, 0x00, 0x02, 0x04, 0x05, 0x34, 0x01, 0x03, 0x03, 0x03,
            0x01, 0x01, 0x08, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01,
            0x04, 0x02,
        ];
        let result = dissect(&buf);
        assert!(matches!(result, Err(nom::Err::Error(_))));
    }
}
