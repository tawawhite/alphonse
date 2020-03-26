use super::super::LayerProto;
use super::{packet, Error};

#[inline]
pub fn parse(_pkt: &mut packet::Packet) -> Result<LayerProto, Error> {
    return Err(Error::ParserError(format!("Unsupport protocol: ICMP")));
}
