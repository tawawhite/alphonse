use nom::bytes::complete::take;
use nom::IResult;

use crate::dissectors::{DissectResult, Error, Protocol};

pub fn dissect(data: &[u8]) -> IResult<&[u8], (usize, DissectResult), Error> {
    let (remain, data) = take(8usize)(data)?;

    if data[0] >> 4 != 1 {
        return Ok((&[], (8, DissectResult::UnknownProtocol)));
    }

    return Ok((remain, (8, DissectResult::Ok(Protocol::ETHERNET))));
}
