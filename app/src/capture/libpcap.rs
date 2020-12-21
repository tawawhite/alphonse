use std::path::Path;

use anyhow::{anyhow, Result};

use alphonse_api::packet::Packet;

use super::Capture;

pub struct Offline {
    cap: Box<pcap::Capture<pcap::Offline>>,
}

impl Offline {
    #[inline]
    /// Get pcap file's link type
    pub fn link_type(&self) -> u16 {
        self.cap.get_datalink().0 as u16
    }
}

impl Offline {
    pub fn try_from_path<P: AsRef<Path>>(path: P) -> Result<Offline> {
        if !path.as_ref().exists() {
            return Err(anyhow!("File does not exist"));
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

        Ok(Offline {
            cap: Box::new(pcap_file),
        })
    }
}

impl Capture for Offline {
    #[inline]
    /// 获取下一个数据包
    fn next(&mut self) -> Result<Box<Packet>> {
        let raw_pkt = self.cap.as_mut().next()?;
        let mut pkt: Box<Packet> = Box::default();
        pkt.ts = raw_pkt.header.ts;
        pkt.caplen = raw_pkt.header.caplen;
        pkt.data = Box::new(Vec::from(raw_pkt.data));
        Ok(pkt)
    }
}

pub struct NetworkInterface {
    cap: Box<pcap::Capture<pcap::Active>>,
}

impl Capture for NetworkInterface {
    #[inline]
    /// 获取下一个数据包
    fn next(&mut self) -> Result<Box<Packet>> {
        let raw_pkt = self.cap.as_mut().next()?;
        let mut pkt: Box<Packet> = Box::default();
        pkt.ts = raw_pkt.header.ts;
        pkt.caplen = raw_pkt.header.caplen;
        pkt.data = Box::new(Vec::from(raw_pkt.data));
        Ok(pkt)
    }
}

impl NetworkInterface {
    /// Initialize a Libpcap instance from a network interface
    pub fn try_from_str<S: AsRef<str>>(interface: S) -> Result<NetworkInterface> {
        let inter_string = String::from(interface.as_ref());
        match pcap::Device::list() {
            Ok(devices) => {
                let _ = match devices.iter().position(|x| inter_string.eq(&x.name)) {
                    Some(p) => p,
                    None => todo!(),
                };

                let cap = pcap::Capture::from_device(interface.as_ref())
                    .unwrap()
                    .promisc(true)
                    .timeout(1000)
                    .open()
                    .unwrap();
                Ok(NetworkInterface { cap: Box::new(cap) })
            }
            Err(_) => todo!(),
        }
    }
}
