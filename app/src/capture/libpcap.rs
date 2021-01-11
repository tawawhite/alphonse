use std::path::Path;

use anyhow::{anyhow, Result};

use alphonse_api::classifiers::matched::Rule;
use alphonse_api::packet::Layers;
use alphonse_api::packet::Packet as PacketTrait;

use crate::stats::CaptureStat;

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
    fn next(&mut self) -> Result<Box<dyn PacketTrait>> {
        let raw = self.cap.as_mut().next()?;
        let pkt = unsafe {
            Box::new(Packet {
                raw: pcap::Packet {
                    header: &*(raw.header as *const pcap::PacketHeader),
                    data: std::slice::from_raw_parts(raw.data.as_ptr(), raw.data.len()),
                },
                layers: Layers::default(),
                hash: 0,
                rules: Box::new(Vec::new()),
                drop: false,
            })
        };
        Ok(pkt)
    }

    fn stats(&mut self) -> Result<CaptureStat> {
        let mut stats = CaptureStat::default();
        let cap_stats = self.cap.as_mut().stats()?;
        stats.rx_pkts = cap_stats.received as u64;
        stats.dropped = cap_stats.dropped as u64;
        stats.if_dropped = cap_stats.if_dropped as u64;
        Ok(stats)
    }
}

pub struct NetworkInterface {
    cap: Box<pcap::Capture<pcap::Active>>,
}

impl Capture for NetworkInterface {
    #[inline]
    /// 获取下一个数据包
    fn next(&mut self) -> Result<Box<dyn PacketTrait>> {
        let raw = self.cap.as_mut().next()?;
        let pkt: Box<Packet> = unsafe {
            Box::new(Packet {
                raw: pcap::Packet {
                    header: &*(raw.header as *const pcap::PacketHeader),
                    data: std::slice::from_raw_parts(raw.data.as_ptr(), raw.data.len()),
                },
                layers: Layers::default(),
                hash: 0,
                rules: Box::new(Vec::new()),
                drop: false,
            })
        };
        Ok(pkt)
    }

    fn stats(&mut self) -> Result<CaptureStat> {
        let mut stats = CaptureStat::default();
        let cap_stats = self.cap.as_mut().stats()?;
        stats.rx_pkts = cap_stats.received as u64;
        stats.dropped = cap_stats.dropped as u64;
        stats.if_dropped = cap_stats.if_dropped as u64;
        Ok(stats)
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

#[derive(Clone)]
pub struct Packet<'a> {
    raw: pcap::Packet<'a>,
    layers: Layers,
    hash: u64,
    rules: Box<Vec<Rule>>,
    drop: bool,
}

impl<'a> PacketTrait for Packet<'a> {
    fn raw(&self) -> &[u8] {
        self.raw.data
    }

    fn ts(&self) -> &libc::timeval {
        &self.raw.header.ts
    }

    fn caplen(&self) -> u32 {
        self.raw.header.caplen
    }

    fn layers(&self) -> &Layers {
        &self.layers
    }

    fn layers_mut(&mut self) -> &mut Layers {
        &mut self.layers
    }

    fn hash(&self) -> u64 {
        self.hash
    }

    fn hash_mut(&mut self) -> &mut u64 {
        &mut self.hash
    }

    fn rules(&self) -> &[Rule] {
        self.rules.as_slice()
    }

    fn rules_mut(&mut self) -> &mut Vec<Rule> {
        &mut self.rules
    }

    fn clone_box(&self) -> Box<dyn PacketTrait + '_> {
        Box::new(self.clone())
    }

    fn clone_box_deep(&self) -> Box<dyn PacketTrait> {
        // copy header info
        let hdr = Box::new(self.raw.header.clone());
        let hdr = Box::into_raw(hdr);

        // copy pcaket raw buffer
        let mut raw_buf = Box::new(vec![0; self.raw.len()]);
        raw_buf.copy_from_slice(self.raw.data);
        let len = raw_buf.len();
        let ptr = Box::into_raw(raw_buf.into_boxed_slice());

        unsafe {
            Box::new(Packet {
                raw: pcap::Packet {
                    header: &*hdr,
                    data: std::slice::from_raw_parts((*ptr).as_ptr(), len),
                },
                layers: self.layers,
                hash: self.hash,
                rules: self.rules.clone(),
                drop: true,
            })
        }
    }
}

impl<'a> Drop for Packet<'a> {
    fn drop(&mut self) {
        if self.drop == true {
            let ptr = self.raw.header as *const pcap::PacketHeader as *mut pcap::PacketHeader;
            let a = unsafe { Box::from_raw(ptr) };
            drop(a);
            let a = unsafe { Box::from_raw(self.raw.data.as_ptr() as *mut u8) };
            drop(a);
        }
    }
}
