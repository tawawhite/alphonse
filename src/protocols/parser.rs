use std::marker::PhantomData;
use std::path::Path;

use super::super::error;
use super::{capture, link, network, packet, Error, LayerProto};

/// 仅解析协议在数据包中的开始位置和协议长度的 parser
pub trait SimpleProtocolParser {
    /// 解析当层数据包，并设置下一层的开始位置
    ///
    /// # Arguments
    ///
    /// * `clayer` - 当前层协议对应的层级
    ///
    /// * `nlayer` - 下一层协议的对应的层级
    ///
    /// * `pkt` - 数据包
    fn parse(
        &self,
        clayer: u8,
        nlayer: u8,
        pkt: &mut packet::Packet,
    ) -> Result<Option<LayerProto>, Error>;
}

pub struct Parser<B: capture::Backend> {
    /// SnapLen, Snap Length, or snapshot length is the amount of data for each frame
    /// that is actually captured by the network capturing tool and stored into the CaptureFile.
    /// https://wiki.wireshark.org/SnapLen
    snap_len: u32,
    pub link_parser: link::Parser,
    pub network_parser: network::Parser,
    _marker: PhantomData<B>,
}

impl Parser<capture::Offline> {
    pub fn from_pcap_file<P: AsRef<Path>>(
        path: &P,
    ) -> Result<Parser<capture::Offline>, error::Error> {
        if !path.as_ref().exists() {
            // check pcap file's existence
            return Err(error::Error::ParserError(String::from(format!(
                "{} does not exists!",
                path.as_ref().display()
            ))));
        }

        let result = pcap::Capture::from_file(path);
        let pcap_file;
        match result {
            Err(e) => {
                eprintln!("{}", e);
                std::process::exit(-1);
            }
            Ok(v) => pcap_file = v,
        }

        Ok(Parser::<capture::Offline> {
            link_parser: link::Parser::from_pcap_file(&pcap_file),
            network_parser: network::Parser::new(),
            snap_len: 65535,
            _marker: PhantomData,
        })
    }
}

impl<B: capture::Backend> Parser<B> {
    /// 解析单个数据包
    pub fn parse_pkt(&mut self, pkt: &mut packet::Packet) -> Result<(), Error> {
        // 解析数据链路层数据包
        let result = self.link_parser.parse(pkt);
        let nwproto;
        match result {
            Ok(p) => {
                nwproto = p;
            }
            Err(e) => return Err(e),
        };

        // 解析网络层数据包
        let transproto;
        self.network_parser.net_type(nwproto);
        match self.network_parser.parse(pkt) {
            Err(e) => Err(e),
            Ok(p) => {
                transproto = p;
                Ok(())
            }
        };
        Ok(())
    }
}
