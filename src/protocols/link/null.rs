use super::super::{LayerProto, NetworkProto};
use super::{packet, Error};

#[inline]
pub fn parse(pkt: &mut packet::Packet) -> Result<LayerProto, Error> {
    let clayer = pkt.last_layer_index as usize;
    let cspos = pkt.layers[clayer].start_pos; // current layer start position
    let proto_len = pkt.len() - cspos;

    if proto_len < 4 {
        return Err(Error::CorruptPacket);
    }

    // 计算下一层协议的开始位置, 并暂存在当前 layer 的信息中
    pkt.layers[clayer].start_pos = cspos + 4;

    // from https://www.tcpdump.org/linktypes.html
    match pkt.data()[cspos as usize] {
        2 => Ok(LayerProto::Network(NetworkProto::IPv4)),
        // OSI packets
        7 => Err(Error::UnsupportProtocol),
        // IPX packets
        23 => Err(Error::UnsupportProtocol),
        24 | 28 | 30 => Ok(LayerProto::Network(NetworkProto::IPv6)),
        _ => Err(Error::UnknownProtocol),
    }
}
