use std::path::Path;

use super::error::Error;
use super::packet::Packet;
use super::pcap;
use super::Capture;

pub struct Libpcap {
    pcap_file: Option<pcap::Capture<pcap::Offline>>,
}

impl Capture for Libpcap {
    #[inline]
    /// 获取下一个数据包
    fn next(&mut self) -> Result<Packet, Error> {
        match self.pcap_file.as_mut().unwrap().next() {
            Ok(raw_pkt) => Ok(Packet::from(&raw_pkt)),
            Err(e) => Err(Error::CaptureError(e)),
        }
    }
}

impl Libpcap {
    #[inline]
    /// Get pcap file's link type
    pub fn link_type(&self) -> u16 {
        self.pcap_file.as_ref().unwrap().get_datalink().0 as u16
    }

    pub fn new() -> Libpcap {
        Libpcap { pcap_file: None }
    }

    #[inline]
    /// 从 pcap 文件初始化 Capture
    pub fn from_file<P: AsRef<Path>>(path: &P) -> Result<Libpcap, Error> {
        if !path.as_ref().exists() {
            // check pcap file's existence
            return Err(Error::IoError(std::io::Error::from(
                std::io::ErrorKind::NotFound,
            )));
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

        Ok(Libpcap {
            pcap_file: Some(pcap_file),
        })
    }
}
