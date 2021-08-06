use super::{Error, Layer};

use nom::number::streaming::{be_u16, be_u32, be_u8};
use nom::IResult;

#[derive(Default)]
pub struct Dissector {}

impl super::Dissector for Dissector {
    #[inline]
    fn dissect(&self, buf: &[u8], _offset: u16) -> Result<Option<Layer>, Error> {
        dissect(buf).or(Err(Error::CorruptPacket(String::from(
            "Corrupt ICMP packet",
        ))))?;

        return Ok(None);
    }
}

fn dissect(buf: &[u8]) -> IResult<&[u8], ()> {
    let (buf, _) = be_u8(buf)?;
    let (buf, _) = be_u16(buf)?;
    let (buf, _) = be_u32(buf)?;
    Ok((buf, ()))
}
