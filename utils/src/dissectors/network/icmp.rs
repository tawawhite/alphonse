use crate::dissectors::{Error, Protocol};

use nom::number::complete::{be_u16, be_u8};
use nom::IResult;

// struct Type(u8);
// impl Type {
//     pub const EchoReplay: u8 = 0;
//     pub const DesUnreachable: u8 = 3;
// }

#[repr(u8)]
enum Type {
    EchoReplay = 0,
    DesUnreachable = 3,
}

pub fn dissect(data: &[u8]) -> IResult<(usize, Option<Protocol>), &[u8], Error<&[u8]>> {
    let (data, icmp_type) = be_u8(data)?;
    let (data, code) = be_u8(data)?;
    let (data, checksum) = be_u16(data)?;
    Ok(((4, None), &[]))
}
