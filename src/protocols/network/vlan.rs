use super::super::link;
use super::Protocol;
use super::{packet, ParserError};

pub fn parse(pkt: &mut packet::Packet) -> Result<Protocol, ParserError> {
    let clayer = pkt.last_layer_index as usize;
    let cspos = pkt.layers[clayer].start_pos; // current layer start position
    let etype = (pkt.data[cspos as usize] as u16) << 8 | pkt.data[(cspos + 1) as usize] as u16;
    pkt.layers[clayer].start_pos = cspos + 4;

    match etype {
        link::ethernet::IPV4 => Ok(Protocol::IPV4),
        link::ethernet::IPV6 => Ok(Protocol::IPV6),
        link::ethernet::PPP => Ok(Protocol::PPP),
        link::ethernet::MPLSUC => Ok(Protocol::MPLS),
        link::ethernet::PPPOES => Ok(Protocol::PPPOE),
        link::ethernet::VLAN => Ok(Protocol::VLAN),
        _ => Err(ParserError::UnsupportProtocol(format!(
            "Unsupport protocol, ether type: {}",
            etype
        ))),
    }
}
