use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use anyhow::{anyhow, Result};
use crossbeam_channel::Sender;
use fnv::FnvHasher;
use pcap::{Active, Capture};
use tokio::task::JoinHandle;

use alphonse_api as api;
use alphonse_utils as utils;
use api::classifiers::matched::Rule;
use api::config::Config;
use api::packet::Packet as PacketTrait;
use api::packet::{Layers, PacketHashKey, Rules, Tunnel};
use api::plugins::rx::{RxDriver, RxStat};
use api::plugins::{Plugin, PluginType};
use utils::dissectors::{link::LinkType, ProtocolDessector};

#[cfg(feature = "arkime")]
mod arkime;

#[derive(Default)]
struct Driver {
    rt: Option<tokio::runtime::Runtime>,
    /// Thread handles
    handles: Vec<JoinHandle<Result<()>>>,
    caps: Vec<Arc<NetworkInterface>>,
}

impl Plugin for Driver {
    fn plugin_type(&self) -> PluginType {
        PluginType::RxDriver
    }

    fn name(&self) -> &str {
        "rx-libpcap"
    }

    fn cleanup(&mut self) -> Result<()> {
        let mut handles = vec![];
        while let Some(hdl) = self.handles.pop() {
            handles.push(hdl);
        }

        match &self.rt {
            None => unreachable!("this should never happen"),
            Some(rt) => rt.block_on(async {
                futures::future::join_all(handles).await;
            }),
        }

        Ok(())
    }
}

impl RxDriver for Driver {
    fn start(&mut self, cfg: Arc<Config>, senders: &[Sender<Box<dyn PacketTrait>>]) -> Result<()> {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .thread_name("alphonse-libpcap")
            .enable_all()
            .build()?;

        let interfaces = cfg.get_str_arr(&"rx.libpcap.interfaces");
        if interfaces.is_empty() {
            return Err(anyhow!(
                "Could not lauch {} driver without specifying any network interface",
                self.name()
            ));
        }

        for interface in &interfaces {
            let cfg = cfg.clone();
            let cap = Arc::new(NetworkInterface::try_from_str(interface.as_str())?);
            let mut thread = RxThread {
                exit: cfg.exit.clone(),
                senders: senders.iter().map(|s| s.clone()).collect(),
                interface: interface.clone(),
                cap: cap.clone(),
            };
            let hdl = rt.spawn_blocking(move || thread.spawn(cfg));
            self.handles.push(hdl);
            self.caps.push(cap);
        }

        #[cfg(feature = "arkime")]
        {
            let caps = self.caps.clone();
            let hdl = rt.spawn_blocking(move || arkime::main_loop(cfg, caps));
            self.handles.push(hdl);
        }

        self.rt = Some(rt);

        Ok(())
    }

    fn stats(&self) -> Result<RxStat> {
        gather_stats(&self.caps)
    }
}

#[inline]
fn gather_stats(caps: &[Arc<NetworkInterface>]) -> Result<RxStat> {
    let mut stat = RxStat::default();
    for cap in caps {
        match cap.stats() {
            Ok(stats) => stat += stats,
            Err(e) => eprintln!("{}", e),
        }
    }
    Ok(stat)
}

struct RxThread {
    exit: Arc<AtomicBool>,
    senders: Vec<Sender<Box<dyn PacketTrait>>>,
    interface: String,
    cap: Arc<NetworkInterface>,
}

impl RxThread {
    pub fn spawn(&mut self, cfg: Arc<Config>) -> Result<()> {
        let mut hasher = FnvHasher::default();
        let parser = ProtocolDessector::new(LinkType::ETHERNET);
        let mut rx_cnt: u64 = 0;

        println!("{} started", self.name());

        while !self.exit.load(Ordering::Relaxed) {
            let mut pkt: Box<dyn PacketTrait> = match self.cap.next() {
                Ok(p) => p,
                Err(e) => {
                    match e {
                        pcap::Error::TimeoutExpired => {
                            std::thread::sleep(std::time::Duration::from_millis(100));
                            continue;
                        }
                        _ => return Err(anyhow!("{}", e)),
                    };
                }
            };

            self.cap
                .rx_bytes
                .fetch_add(pkt.raw().len() as u64, Ordering::Relaxed);

            match parser.parse_pkt(pkt.as_mut()) {
                Ok(_) => {}
                Err(e) => match e {
                    utils::dissectors::Error::UnsupportProtocol(_) => {}
                    _ => todo!(),
                },
            };

            rx_cnt += 1;
            if rx_cnt % cfg.rx_stat_log_interval == 0 {
                match self.cap.stats() {
                    Ok(stats) => {
                        println!(
                            "{} {} {}({:.3}) {}",
                            rx_cnt,
                            stats.rx_pkts,
                            stats.dropped,
                            stats.dropped as f64 / stats.rx_pkts as f64,
                            stats.if_dropped,
                        );
                    }
                    Err(_) => {}
                };
            }

            PacketHashKey::from(pkt.as_ref()).hash(&mut hasher);
            let i = hasher.finish() as usize % self.senders.len();
            hasher = FnvHasher::default();
            let sender = &self.senders[i];

            match sender.try_send(pkt) {
                Ok(_) => {}
                Err(err) => match err {
                    crossbeam_channel::TrySendError::Full(_) => {
                        self.cap.overload_pkts.fetch_add(1, Ordering::Relaxed);
                        let overload = self.cap.overload_pkts.load(Ordering::Relaxed);
                        if overload % 10000 == 0 {
                            println!("{} overloading, total overload {}", self.name(), overload);
                        }
                    }
                    crossbeam_channel::TrySendError::Disconnected(_) => {
                        println!("{} channel is closed, exit", self.name());
                        break;
                    }
                },
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
    cap: Capture<Active>,
    rx_bytes: AtomicU64,
    overload_pkts: AtomicU64,
}

impl NetworkInterface {
    #[inline]
    fn next(&self) -> Result<Box<Packet>, pcap::Error> {
        let c = unsafe { &mut (*(&self.cap as *const _ as *mut Capture<Active>)) };
        let raw = c.next()?;
        let pkt: Box<Packet> = Box::new(Packet::from(&raw));
        Ok(pkt)
    }

    #[inline]
    fn stats(&self) -> Result<RxStat> {
        let mut stats = RxStat::default();
        let c = unsafe { &mut (*(&self.cap as *const _ as *mut Capture<Active>)) };
        let cap_stats = c.stats()?;
        stats.rx_pkts = cap_stats.received as u64;
        stats.dropped = cap_stats.dropped as u64;
        stats.if_dropped = cap_stats.if_dropped as u64;
        stats.overload_dropped = self.overload_pkts.load(Ordering::Relaxed);
        stats.rx_bytes = self.rx_bytes.load(Ordering::Relaxed);
        Ok(stats)
    }
}

impl NetworkInterface {
    /// Initialize a Libpcap instance from a network interface
    pub fn try_from_str<S: AsRef<str>>(interface: S) -> Result<NetworkInterface> {
        let interface = String::from(interface.as_ref());
        match pcap::Device::list() {
            Ok(devices) => {
                let _ = match devices.iter().position(|x| interface == x.name) {
                    Some(p) => p,
                    None => {
                        return Err(anyhow!(
                            "target network interface {} does not exits",
                            interface
                        ))
                    }
                };

                let cap = pcap::Capture::from_device(interface.as_ref())?
                    .promisc(true)
                    .timeout(1000)
                    .buffer_size(i32::MAX)
                    .open()?;
                Ok(NetworkInterface {
                    cap,
                    rx_bytes: AtomicU64::new(0),
                    overload_pkts: AtomicU64::new(0),
                })
            }
            Err(e) => return Err(anyhow!("{}", e)),
        }
    }
}

#[derive(Clone)]
pub struct Packet {
    raw: Vec<u8>,
    ts: libc::timeval,
    caplen: u32,
    layers: Layers,
    rules: Rules,
    tunnel: Tunnel,
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
        self.rules.as_ref().as_slice()
    }

    fn rules_mut(&mut self) -> &mut Rules {
        &mut self.rules
    }

    fn tunnel(&self) -> Tunnel {
        self.tunnel
    }

    fn tunnel_mut(&mut self) -> &mut Tunnel {
        &mut self.tunnel
    }

    fn clone_box<'a, 'b>(&'a self) -> Box<dyn PacketTrait + 'b> {
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
            rules: Rules::default(),
            tunnel: Tunnel::default(),
        }
    }
}

#[no_mangle]
pub extern "C" fn al_new_rx_driver() -> Box<Box<dyn RxDriver>> {
    Box::new(Box::new(Driver::default()))
}

#[no_mangle]
pub extern "C" fn al_plugin_type() -> PluginType {
    PluginType::RxDriver
}
