use super::Protocol;
use super::{packet, Error};

#[inline]
pub fn parse(_pkt: &mut packet::Packet) -> Result<Protocol, Error> {
    return Err(Error::ParserError(format!("Unsupport protocol: ICMP")));
}
