use nom::bytes::complete::take;
use nom::IResult;

use crate::dissectors::{Error, Protocol};

pub fn dissect(data: &[u8]) -> IResult<(usize, Option<Protocol>), &[u8], Error> {
    let (remain, data) = take(4usize)(data)?;

    let protocol = match data[0] {
        2 => Protocol::IPV4,
        // OSI packets
        7 => {
            return Err(nom::Err::Error(Error::UnsupportProtocol(
                "Does not support OSI packet",
            )))
        }
        // IPX packets
        23 => {
            return Err(nom::Err::Error(Error::UnsupportProtocol(
                "Does not support IPX packet",
            )))
        }
        24 | 28 | 30 => Protocol::IPV6,
        _ => return Err(nom::Err::Error(Error::UnknownProtocol)),
    };

    Ok(((4, Some(protocol)), remain))
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

        let ((_, protocol), _) = result.unwrap();
        assert!(matches!(protocol, Some(Protocol::IPV4)));
    }

    #[test]
    fn test_ok_ipv6() {
        let buf = [
            24, 0x80, 0xc2, 0x00, 0x00, 0x00, 0xcc, 0x04, 0x0d, 0x5c, 0xf0, 0x00, 0x08, 0x00,
        ];
        let result = dissect(&buf);
        assert!(matches!(result, Ok(_)));

        let ((_, protocol), _) = result.unwrap();
        assert!(matches!(protocol, Some(Protocol::IPV6)));
    }

    #[test]
    fn test_err_pkt_too_short() {
        let buf = [0x01];
        let result = dissect(&buf);
        assert!(matches!(result, Err(nom::Err::Error(Error::Nom(_)))));
    }

    #[test]
    fn test_err_unsupport_protocol() {
        let buf = [
            0x07, 0x80, 0xc2, 0x00, 0x00, 0x00, 0xcc, 0x04, 0x0d, 0x5c, 0xf0, 0x00, 0x06, 0x00,
        ];
        let result = dissect(&buf);
        assert!(matches!(result, Err(_)));
        assert!(matches!(
            result.unwrap_err(),
            nom::Err::Error(Error::UnsupportProtocol(_))
        ));

        let buf = [
            23, 0x80, 0xc2, 0x00, 0x00, 0x00, 0xcc, 0x04, 0x0d, 0x5c, 0xf0, 0x00, 0x06, 0x00,
        ];
        let result = dissect(&buf);
        assert!(matches!(result, Err(_)));
        assert!(matches!(
            result.unwrap_err(),
            nom::Err::Error(Error::UnsupportProtocol(_))
        ));
    }
}
