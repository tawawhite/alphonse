use nom::bytes::complete::take;
use nom::number::complete::be_u16;
use nom::IResult;
use num_traits::FromPrimitive;

use crate::dissectors::{DissectResult, Error, EtherType};

pub fn dissect(data: &[u8]) -> IResult<&[u8], (usize, DissectResult), Error> {
    let (remain, _) = take(2usize)(data)?;
    let (remain, etype) = be_u16(remain)?;
    let protocol = match EtherType::from_u16(etype) {
        None => return Ok((remain, (4, DissectResult::UnknownEtype(etype)))),
        Some(proto) => proto.into(),
    };

    Ok((remain, (4, DissectResult::Ok(protocol))))
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::dissectors::Protocol;

    #[test]
    fn test_ok() {
        let buf = [0xc2, 0x00, 0x08, 0x00];
        let result = dissect(&buf);
        assert!(
            matches!(result.unwrap(), ( _,(4, DissectResult::Ok(protocol))) if protocol == Protocol::IPV4)
        );
    }

    #[test]
    fn test_err_unknown_etype() {
        let buf = [0xc2, 0x00, 0x08, 0x01];
        let result = dissect(&buf);
        assert!(matches!(
            result,
            Ok((_, (_, DissectResult::UnknownEtype(_))))
        ));
    }
}
