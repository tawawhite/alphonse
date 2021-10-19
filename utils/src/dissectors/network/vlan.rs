use nom::bytes::complete::take;
use nom::number::complete::be_u16;
use nom::IResult;
use num_traits::FromPrimitive;

use super::{Error, Protocol};
use crate::dissectors::EtherType;

pub fn dissect(data: &[u8]) -> IResult<(usize, Option<Protocol>), &[u8], Error> {
    let (remain, _) = take(2usize)(data)?;
    let (remain, etype) = be_u16(remain)?;
    let protocol = match EtherType::from_u16(etype) {
        None => return Err(nom::Err::Error(Error::UnknownEtype(etype))),
        Some(proto) => proto.into(),
    };

    Ok(((4, Some(protocol)), remain))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ok() {
        let buf = [0xc2, 0x00, 0x08, 0x00];
        let result = dissect(&buf);
        assert!(matches!(result.unwrap(), ((4, Some(protocol)), _) if protocol == Protocol::IPV4));
    }

    #[test]
    fn test_err_unsupport_protocol() {
        let buf = [0xc2, 0x00, 0x08, 0x01];
        let result = dissect(&buf);
        assert!(matches!(
            result.unwrap_err(),
            nom::Err::Error(Error::UnknownEtype(_))
        ));
    }
}
