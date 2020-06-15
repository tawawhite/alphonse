use std::convert::TryFrom;
use std::path::Path;

use super::error::Error;
use super::packet::Packet;
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
    pub fn try_from_path<P: AsRef<Path>>(path: P) -> Result<Offline, Error> {
        if !path.as_ref().exists() {
            // check pcap file's existence
            return Err(Error::CommonError(format!("File does not exist")));
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
    fn next(&mut self) -> Result<Packet, Error> {
        match self.cap.as_mut().next() {
            Ok(raw_pkt) => Ok(Packet::from(&raw_pkt)),
            Err(e) => Err(Error::CaptureError(e)),
        }
    }
}

pub struct NetworkInterface {
    cap: Box<pcap::Capture<pcap::Active>>,
}

impl Capture for NetworkInterface {
    #[inline]
    /// 获取下一个数据包
    fn next(&mut self) -> Result<Packet, Error> {
        match self.cap.next() {
            Ok(raw_pkt) => Ok(Packet::from(&raw_pkt)),
            Err(e) => Err(Error::CaptureError(e)),
        }
    }
}

impl NetworkInterface {
    /// Initialize a Libpcap instance from a network interface
    pub fn try_from_str<S: AsRef<str>>(interface: S) -> Result<NetworkInterface, Error> {
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
                    .open()
                    .unwrap();
                Ok(NetworkInterface { cap: Box::new(cap) })
            }
            Err(_) => todo!(),
        }
    }
}
