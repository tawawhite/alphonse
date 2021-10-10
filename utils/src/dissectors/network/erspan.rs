use nom::bytes::complete::take;
use nom::IResult;

use super::{Error, Protocol};

pub fn dissect(data: &[u8]) -> IResult<Option<Protocol>, &[u8], Error<&[u8]>> {
    let (remain, data) = take(8usize)(data)?;

    if data[0] >> 4 != 1 {
        return Ok((Some(Protocol::UNKNOWN), &[]));
    }

    return Ok((Some(Protocol::ETHERNET), remain));
}
