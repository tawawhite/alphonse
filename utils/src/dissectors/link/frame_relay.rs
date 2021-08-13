//! From what I understand, Frame Relay protocol is derived from the HDLC protocol
//! The relatinship is like this:
//! IBM's SDLC --> HDLC ----> X.25 LAPB
//!                     |\
//!                     | --> V.42 LAPM
//!                     |\
//!                     | --> Frame Relay LAPF
//!                      \
//!                       --> ISDN LAPD
//! HDLC protocol has two (maybe more) versions: ISO standard and Cisco's standard
//! Within ISO's standard there is no protocol type in the protocol, but Cisco's does contain this field
//! So what we actually doing here is parsing Cisco's HDLC protocol and its deriving protocols
//! And in this specific case is Frame Relay protocol

use super::ethernet::EtherType;
use super::{Error, Layer, Protocol};

use nom::bytes::complete::take;
use nom::number::streaming::be_u16;
use nom::IResult;
use num_traits::FromPrimitive;

#[derive(Default)]
pub struct Dissector {}

impl super::Dissector for Dissector {
    #[inline]
    fn dissect(&self, buf: &[u8], offset: u16) -> Result<Option<Layer>, Error> {
        if buf.len() < 4 {
            return Err(Error::CorruptPacket(String::from(
                "Corrupt FrameRelay packet",
            )));
        }

        let (remain, protocol) = dissect(buf).or(Err(Error::CorruptPacket(String::from(
            "Corrupt FrameRelay packet",
        ))))?;
        let offset = offset + (buf.len() - remain.len()) as u16;
        Ok(Some(Layer { protocol, offset }))
    }
}

fn dissect(buf: &[u8]) -> IResult<&[u8], Protocol> {
    let (buf, _) = take(2usize)(buf)?;
    let (buf, proto) = be_u16(buf)?;
    let proto = match EtherType::from_u16(proto) {
        None => Protocol::UNKNOWN,
        Some(proto) => proto.into(),
    };
    Ok((buf, proto))
}
