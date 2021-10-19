use nom::bytes::complete::take;
use nom::IResult;

use crate::dissectors::{Error, Protocol};

pub fn dissect(data: &[u8]) -> IResult<(usize, Option<Protocol>), &[u8], Error> {
    let (_, data) = take(28usize)(data)?;
    if data[7] > 2 {
        // Neither a request nor a response
        return Err(nom::Err::Error(Error::CorruptPacket(
            "The arp packet is corrupted, Neither a request nor a response",
        )));
    }

    Ok(((28, None), &[]))
}
