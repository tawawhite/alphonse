use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;

use anyhow::Result;
use crossbeam_channel::Sender;

use alphonse_api as api;
use api::classifiers::matched::Rule;
use api::packet::Layers;
use api::packet::Packet as PacketTrait;

use crate::config::Config;
use crate::rx::RxUtility;
use crate::stats::CaptureStat;

pub const UTILITY: RxUtility = RxUtility {
    init: |_| Ok(()),
    start,
    cleanup: |_| Ok(()),
};

pub fn start(
    exit: Arc<AtomicBool>,
    cfg: Arc<Config>,
    sender: Sender<Box<dyn PacketTrait>>,
) -> Result<Option<Vec<JoinHandle<Result<()>>>>> {
    let mut handles = vec![];
    for interface in cfg.interfaces.iter() {
        let cfg = cfg.clone();
        let mut thread = RxThread {
            exit: exit.clone(),
            sender: sender.clone(),
            interface: interface.clone(),
        };
        let builder = std::thread::Builder::new().name(thread.name());
        let handle = builder.spawn(move || thread.spawn(cfg))?;
        handles.push(handle);
    }

    Ok(Some(handles))
}

struct RxThread {
    exit: Arc<AtomicBool>,
    sender: Sender<Box<dyn PacketTrait>>,
    interface: String,
}

impl RxThread {
    pub fn spawn(&mut self, _cfg: Arc<Config>) -> Result<()> {
        let mut cap = NetworkInterface::try_from_str(self.interface.as_str())?;

        println!("{} started", self.name());

        while !self.exit.load(Ordering::Relaxed) {
            let pkt = cap.next()?;
            match self.sender.send(pkt) {
                Ok(_) => {}
                Err(err) => {
                    eprintln!("{} sender error: {}", self.name(), err)
                }
            };
        }

        println!("{} exit", self.name());
        Ok(())
    }

    pub fn name(&self) -> String {
        format!("alphonse-{}", self.interface)
    }
}

struct NetworkInterface {
    cap: Box<pcap::Capture<pcap::Active>>,
}

impl NetworkInterface {
    #[inline]
    fn next(&mut self) -> Result<Box<dyn PacketTrait>> {
        let raw = self.cap.as_mut().next()?;
        let pkt: Box<Packet> = Box::new(Packet::from(&raw));
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
pub struct Packet {
    raw: Vec<u8>,
    ts: libc::timeval,
    caplen: u32,
    layers: Layers,
    rules: Box<Vec<Rule>>,
}

impl PacketTrait for Packet {
    fn raw(&self) -> &[u8] {
        self.raw.as_slice()
    }

    fn ts(&self) -> &libc::timeval {
        &self.ts
    }

    fn caplen(&self) -> u32 {
        self.caplen
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
}

impl From<&pcap::Packet<'_>> for Packet {
    fn from(pkt: &pcap::Packet) -> Self {
        Packet {
            raw: Vec::from(pkt.data),
            ts: pkt.header.ts,
            caplen: pkt.header.caplen,
            layers: Layers::default(),
            rules: Box::new(Vec::new()),
        }
    }
}
