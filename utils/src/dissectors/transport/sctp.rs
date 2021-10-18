use nom::bytes::complete::take;
use nom::IResult;

use super::{Error, Protocol};

pub fn dissect(data: &[u8]) -> IResult<(usize, Option<Protocol>), &[u8], Error<&[u8]>> {
    let (remain, _) = take(12usize)(data)?;
    return Ok(((12, Some(Protocol::APPLICATION)), remain));
}
