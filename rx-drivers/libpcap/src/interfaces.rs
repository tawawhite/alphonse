use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use anyhow::{anyhow, Result};
use crossbeam_channel::Sender;
use fnv::FnvHasher;
use pcap::{Active, Capture};

use alphonse_api as api;
use alphonse_utils as utils;
use api::config::Config;
use api::packet::Packet as PacketTrait;
use api::packet::PacketHashKey;
use api::plugins::rx::RxStat;
use api::plugins::Plugin;
use utils::dissectors::link::LinkType;
use utils::dissectors::ProtocolDessector;

#[cfg(feature = "arkime")]
use crate::arkime;
use crate::{CaptureUnit, Driver, Packet};

impl Driver {
    pub(crate) fn start_interfaces(
        &mut self,
        cfg: Arc<Config>,
        senders: &[Sender<Box<dyn PacketTrait>>],
    ) -> Result<()> {
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
            let cap = cap as Arc<dyn CaptureUnit>;
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

    #[inline]
    pub fn gather_interfaces_stats(&self) -> Result<RxStat> {
        let mut stat = RxStat::default();
        for cap in &self.caps {
            match cap.stats() {
                Ok(stats) => stat += stats,
                Err(e) => eprintln!("{}", e),
            }
        }
        Ok(stat)
    }
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
                Err(_) => {}
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

impl CaptureUnit for NetworkInterface {
    #[inline]
    fn next(&self) -> Result<Box<dyn PacketTrait>, pcap::Error> {
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
