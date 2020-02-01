use super::super::{LayerProto, NetworkProto, TransProto, TunnelProto};
use super::{packet, Error};

const IP: u8 = 0;
const ICMP: u8 = 1;
const IGMP: u8 = 2;
const GGP: u8 = 3;
const IPV4: u8 = 4;
const TCP: u8 = 6;
const ST: u8 = 7;
const EGP: u8 = 8;
const PIGP: u8 = 9;
const RCCMON: u8 = 10;
const NVPII: u8 = 11;
const PUP: u8 = 12;
const ARGUS: u8 = 13;
const UDP: u8 = 17;
const IPV6: u8 = 41;
const GRE: u8 = 47;
const ESP: u8 = 50;
const SCTP: u8 = 132;

#[inline]
pub fn parse(pkt: &mut packet::Packet) -> Result<LayerProto, Error> {
    let clayer = pkt.last_layer_index as usize;
    let cspos = pkt.layers[clayer].start_pos;
    let proto_len = pkt.len() - cspos;

    if proto_len < 4 * 5 {
        // 如果报文内容长度小于IP报文最短长度(IP协议头长度)
        // 数据包有错误
        return Err(Error::CorruptPacket);
    }

    let ip_vhl = pkt.data()[cspos as usize];
    let ip_version = ip_vhl >> 4;

    if ip_version != 4 {
        // 如果报文中实际的 IP 版本号不是 IPv4，数据包有错误
        return Err(Error::CorruptPacket);
    }

    let ip_hdr_len = ((ip_vhl & 0b00001111) * 4) as u16;

    if ip_hdr_len < 4 * 5 || proto_len < ip_hdr_len {
        // 如果报文中的IP头长度小于20字节或报文长度小于报文中声明的IP头长度, 数据包有错误
        return Err(Error::CorruptPacket);
    }

    let ip_len =
        (pkt.data()[(cspos + 2) as usize] as u16) << 8 | (pkt.data()[(cspos + 3) as usize] as u16);

    if proto_len < ip_len {
        // 如果报文的长度小于 IP 报文中声明的数据报长度，数据包有错误
        return Err(Error::CorruptPacket);
    }

    // 计算下一层协议的开始位置
    pkt.layers[clayer].start_pos = cspos + ip_len;

    let ip_proto = pkt.data()[(cspos + 9) as usize];

    match ip_proto {
        ICMP => Ok(LayerProto::Network(NetworkProto::ICMP)),
        IPV4 => Ok(LayerProto::Network(NetworkProto::IPv4)),
        TCP => Ok(LayerProto::Transport(TransProto::TCP)),
        UDP => Ok(LayerProto::Transport(TransProto::UDP)),
        ESP => Ok(LayerProto::Network(NetworkProto::ESP)),
        IPV6 => Ok(LayerProto::Network(NetworkProto::IPv6)),
        GRE => Ok(LayerProto::Tunnel(TunnelProto::GRE)),
        SCTP => Ok(LayerProto::Transport(TransProto::SCTP)),
        _ => Err(Error::UnsupportProtocol),
    }
}
