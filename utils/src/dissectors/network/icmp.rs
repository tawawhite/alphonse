use nom::number::complete::{be_u16, be_u8};
use nom::IResult;

use crate::dissectors::{DissectResult, Error};

#[repr(u8)]
enum Type {
    EchoReplay = 0,
    DesUnreachable = 3,
}

pub fn dissect(data: &[u8]) -> IResult<&[u8], (usize, DissectResult), Error> {
    let (data, icmp_type) = be_u8(data)?;
    let (data, code) = be_u8(data)?;
    let (data, checksum) = be_u16(data)?;
    Ok((data, (4, DissectResult::None)))
}
