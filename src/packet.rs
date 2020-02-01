extern crate pcap;

/// 最大协议层数
/// 目前按照TCP/IP协议栈的层数定义为4层，即：
/// 链路层、网络层、传输层、应用层
///
/// 这样虽然会丢失一些中间协议的开始位置和信息，
/// 但是减少了数据包基础结构的大小，
/// 而且其实有可能某些情况下对于中间层的隧道协议不关心的情况下，
/// 没有必要去知晓这些内容
pub const PACKET_MAX_LAYERS: usize = 4;

#[derive(Default, Clone, Copy)]
pub struct Layer {
    pub start_pos: u16,
}

pub struct Packet<'a> {
    /// Raw packet data using libpcap's definition
    raw: pcap::Packet<'a>,

    /// All layer's basic info
    pub layers: [Layer; PACKET_MAX_LAYERS],

    /// How much layers does the packet contain
    pub last_layer_index: u8,
}

impl<'a> Packet<'a> {
    #[inline]
    pub fn len(&self) -> u16 {
        self.raw.len() as u16
    }

    #[inline]
    /// return the length of the specific layer
    pub fn len_of_layer(&self, depth: usize) -> u16 {
        match depth {
            0 => self.len(),
            _ => self.len() - self.layers[depth].start_pos,
        }
    }

    #[inline]
    pub fn data(&self) -> &'a [u8] {
        self.raw.data
    }

    pub fn new(raw_pkt: pcap::Packet<'a>) -> Packet<'a> {
        Packet {
            raw: raw_pkt,
            last_layer_index: 0,
            layers: [Layer { start_pos: 0 }; PACKET_MAX_LAYERS],
        }
    }
}
