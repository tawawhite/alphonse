use nom::bytes::complete::take;
use nom::IResult;

use crate::dissectors::{DissectResult, Error, Protocol};

pub fn dissect(data: &[u8]) -> IResult<&[u8], (usize, DissectResult), Error> {
    let (remain, _) = take(12usize)(data)?;
    return Ok((remain, (12, DissectResult::Ok(Protocol::APPLICATION))));
}
