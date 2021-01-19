use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::Result;
use crossbeam_channel::Sender;

use alphonse_api as api;
use api::classifiers::matched::Rule;
use api::packet::Layers;
use api::packet::Packet as PacketTrait;

use crate::capture::Capture;
use crate::config::Config;
use crate::rx::RxUtility;
use crate::stats::CaptureStat;

pub const UTILITY: RxUtility = RxUtility {
    init: |_| Ok(()),
    start,
    cleanup: |_| Ok(()),
};

pub fn start(
    cfg: Arc<Config>,
    sender: Sender<Box<dyn PacketTrait>>,
    exit: Arc<AtomicBool>,
) -> Result<()> {
    let mut handles = vec![];
    for (id, interface) in cfg.interfaces.iter().enumerate() {
        let cfg = cfg.clone();
        let mut thread = RxThread {
            id: id as u8,
            exit: exit.clone(),
            sender: sender.clone(),
            interface: interface.clone(),
        };
        let builder = std::thread::Builder::new().name(thread.name());
        let handle = builder.spawn(move || thread.spawn(cfg))?;
        handles.push(handle);
    }

    for handle in handles {
        match handle.join() {
            Ok(_) => {}
            Err(e) => eprintln!("{:?}", e),
        };
    }

    Ok(())
}

struct RxThread {
    id: u8,
    exit: Arc<AtomicBool>,
    sender: Sender<Box<dyn PacketTrait>>,
    interface: String,
}

impl RxThread {
    pub fn spawn(&mut self, _cfg: Arc<Config>) -> Result<()> {
        let mut cap = NetworkInterface::try_from_str(self.interface.as_str())?;

        while !self.exit.load(Ordering::Relaxed) {
            let pkt = match cap.next() {
                Ok(pkt) => pkt,
                Err(err) => {
                    return Err(err);
                }
            };

            match self.sender.send(pkt) {
                Ok(_) => {}
                Err(err) => {
                    eprintln!("{} sender error: {}", self.name(), err)
                }
            };
        }
        Ok(())
    }

    pub fn name(&self) -> String {
        format!("alphonse-{}", self.interface)
    }
}

struct NetworkInterface {
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
                    .buffer_size(i32::MAX)
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
