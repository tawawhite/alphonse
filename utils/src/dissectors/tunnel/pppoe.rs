use nom::bytes::complete::take;
use nom::combinator::peek;
use nom::number::complete::be_u16;
use nom::IResult;

use super::{Error, Protocol};

pub fn dissect(data: &[u8]) -> IResult<Option<Protocol>, &[u8], Error<&[u8]>> {
    let (remain, data) = take(8usize)(data)?;
    if data[0] != 0x11 || data[1] != 0 {
        return Err(nom::Err::Error(Error::CorruptPacket(
            "Corrupted PPPOE packet",
        )));
    }

    let (_, plen) = be_u16(&data[4..])?;
    let (_, _) = peek(take(plen as usize))(remain)?;

    let (_, protocol) = be_u16(&data[6..])?;
    let protocol = match protocol {
        0x21 => Protocol::IPV4,
        0x57 => Protocol::IPV6,
        _ => Protocol::UNKNOWN,
    };

    Ok((Some(protocol), remain))
}
