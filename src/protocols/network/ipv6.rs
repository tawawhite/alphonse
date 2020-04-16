use super::Protocol;
use super::{packet, ParserError};

#[inline]
pub fn parse(_pkt: &mut packet::Packet) -> Result<Protocol, ParserError> {
    return Err(ParserError::UnsupportProtocol(format!(
        "Unsupport protocol: IPV6"
    )));
}
