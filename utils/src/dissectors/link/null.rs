use nom::bytes::complete::take;
use nom::IResult;

use crate::dissectors::{DissectResult, Error, Protocol};

pub fn dissect(data: &[u8]) -> IResult<&[u8], (usize, DissectResult), Error> {
    let (remain, data) = take(4usize)(data)?;

    let result = match data[0] {
        2 => DissectResult::Ok(Protocol::IPV4),
        // OSI packets
        7 => DissectResult::UnsupportProtocol("OSI"),
        // IPX packets
        23 => DissectResult::UnsupportProtocol("IPX"),
        24 | 28 | 30 => DissectResult::Ok(Protocol::IPV6),
        _ => DissectResult::UnknownProtocol,
    };

    Ok((remain, (4, result)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ok_ipv4() {
        let buf = [
            0x02, 0x80, 0xc2, 0x00, 0x00, 0x00, 0xcc, 0x04, 0x0d, 0x5c, 0xf0, 0x00, 0x08, 0x00,
        ];
        let result = dissect(&buf);
        assert!(matches!(result, Ok(_)));

        let (_, (_, protocol)) = result.unwrap();
        assert!(matches!(protocol, DissectResult::Ok(Protocol::IPV4)));
    }

    #[test]
    fn test_ok_ipv6() {
        let buf = [
            24, 0x80, 0xc2, 0x00, 0x00, 0x00, 0xcc, 0x04, 0x0d, 0x5c, 0xf0, 0x00, 0x08, 0x00,
        ];
        let result = dissect(&buf);
        assert!(matches!(result, Ok(_)));

        let (_, (_, protocol)) = result.unwrap();
        assert!(matches!(protocol, DissectResult::Ok(Protocol::IPV6)));
    }

    #[test]
    fn test_err_pkt_too_short() {
        let buf = [0x01];
        let result = dissect(&buf);
        assert!(matches!(result, Err(nom::Err::Error(_))));
    }

    #[test]
    fn test_err_unsupport_protocol() {
        let buf = [
            0x07, 0x80, 0xc2, 0x00, 0x00, 0x00, 0xcc, 0x04, 0x0d, 0x5c, 0xf0, 0x00, 0x06, 0x00,
        ];
        let result = dissect(&buf);
        assert!(matches!(
            result.unwrap(),
            (_, (_, DissectResult::UnsupportProtocol(_)))
        ));

        let buf = [
            23, 0x80, 0xc2, 0x00, 0x00, 0x00, 0xcc, 0x04, 0x0d, 0x5c, 0xf0, 0x00, 0x06, 0x00,
        ];
        let result = dissect(&buf);
        assert!(matches!(
            result.unwrap(),
            (_, (_, DissectResult::UnsupportProtocol(_)))
        ));
    }
}
