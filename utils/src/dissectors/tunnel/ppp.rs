use nom::bytes::complete::take;
use nom::IResult;

use super::{Error, Protocol};

pub fn dissect(data: &[u8]) -> IResult<Option<Protocol>, &[u8], Error<&[u8]>> {
    let (remain, data) = take(4usize)(data)?;
    if data[2] != 0x00 {
        return Err(nom::Err::Error(Error::CorruptPacket(
            "Corrupted PPPOE packet",
        )));
    }

    let protocol = match data[3] {
        0x21 => Protocol::IPV4,
        0x57 => Protocol::IPV6,
        _ => Protocol::UNKNOWN,
    };

    Ok((Some(protocol), remain))
}
