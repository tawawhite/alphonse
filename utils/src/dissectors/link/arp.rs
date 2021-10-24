use nom::bytes::complete::take;
use nom::IResult;

use crate::dissectors::{DissectResult, Error};

pub fn dissect(data: &[u8]) -> IResult<&[u8], (usize, DissectResult), Error> {
    take(28usize)(data)?;
    Ok((&[], (28, DissectResult::None)))
}
