use nom::bytes::complete::take;
use nom::IResult;

use super::{Error, Protocol};

pub fn dissect(data: &[u8]) -> IResult<(usize, Option<Protocol>), &[u8], Error<&[u8]>> {
    let (remain, data) = take(8usize)(data)?;

    if data[0] >> 4 != 1 {
        return Ok(((8, Some(Protocol::UNKNOWN)), &[]));
    }

    return Ok(((8, Some(Protocol::ETHERNET)), remain));
}
