use nom::bytes::complete::take;
use nom::IResult;

use crate::dissectors::{DissectResult, Error, Protocol};

pub fn dissect(data: &[u8]) -> IResult<&[u8], (usize, DissectResult), Error> {
    let (remain, data) = take(4usize)(data)?;
    if data[2] != 0x00 {
        return Err(nom::Err::Error(Error("Corrupted PPPOE packet")));
    }

    let protocol = match data[3] {
        0x21 => Protocol::IPV4,
        0x57 => Protocol::IPV6,
        _ => return Ok((remain, (4, DissectResult::UnknownProtocol))),
    };

    Ok((remain, (4, DissectResult::Ok(protocol))))
}
