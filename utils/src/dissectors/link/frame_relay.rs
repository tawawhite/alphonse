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

use nom::bytes::complete::take;
use nom::number::streaming::be_u16;
use nom::IResult;
use num_traits::FromPrimitive;

use crate::dissectors::{DissectResult, Error, EtherType};

pub fn dissect(data: &[u8]) -> IResult<&[u8], (usize, DissectResult), Error> {
    let (data, _) = take(2usize)(data)?;
    let (data, proto) = be_u16(data)?;
    let result = match EtherType::from_u16(proto) {
        None => DissectResult::UnknownProtocol,
        Some(proto) => DissectResult::Ok(proto.into()),
    };

    Ok((data, (4, result)))
}
