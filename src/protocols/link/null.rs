use super::super::Protocol;
use super::{packet, Error};

#[inline]
pub fn parse(pkt: &mut packet::Packet) -> Result<Protocol, Error> {
    let clayer = pkt.last_layer_index as usize;
    let cspos = pkt.layers[clayer].start_pos; // current layer start position
    let proto_len = pkt.len() - cspos;

    if proto_len < 4 {
        return Err(Error::ParserError(format!(
            "The packet is a corrupt packet, packet too short"
        )));
    }

    // 计算下一层协议的开始位置, 并暂存在当前 layer 的信息中
    pkt.layers[clayer].start_pos = cspos + 4;

    // from https://www.tcpdump.org/linktypes.html
    match pkt.data[cspos as usize] {
        2 => Ok(Protocol::IPV4),
        // OSI packets
        7 => Err(Error::ParserError(format!("Does not support OSI packet"))),
        // IPX packets
        23 => Err(Error::ParserError(format!("Does not support IPX packet"))),
        24 | 28 | 30 => Ok(Protocol::IPV6),
        _ => Err(Error::ParserError(format!(
            "Unknown protocol {}",
            pkt.data[cspos as usize],
        ))),
    }
}
