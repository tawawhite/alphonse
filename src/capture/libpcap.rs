use std::path::Path;

use super::error::Error;
use super::packet::Packet;
use super::pcap;
use super::{Backend, Capture};

pub struct Libpcap {
    pcap_file: pcap::Capture<pcap::Offline>,
}

impl Backend for Libpcap {}

impl Capture<Libpcap> {
    #[inline]
    /// Get pcap file's link type
    pub fn link_type(&self) -> u16 {
        self.backend.pcap_file.get_datalink().0 as u16
    }

    #[inline]
    /// 从 pcap 文件初始化 Capture
    pub fn from_pcap_file<P: AsRef<Path>>(path: &P) -> Result<Capture<Libpcap>, Error> {
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

        Ok(Capture {
            backend: Libpcap { pcap_file },
        })
    }

    #[inline]
    /// 获取下一个数据包
    pub fn next(&mut self) -> Result<Packet, Error> {
        match self.backend.pcap_file.next() {
            Ok(raw_pkt) => Ok(Packet::new(raw_pkt)),
            Err(e) => Err(Error::CaptureError(e)),
        }
    }
}
