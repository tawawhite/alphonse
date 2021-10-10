use nom::bytes::complete::take;
use nom::IResult;

use super::{Error, Protocol};

pub fn dissect(data: &[u8]) -> IResult<Option<Protocol>, &[u8], Error<&[u8]>> {
    let (remain, _) = take(12usize)(data)?;
    return Ok((Some(Protocol::APPLICATION), remain));
}
