use std::cell::RefCell;
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::thread::JoinHandle;

use anyhow::{anyhow, Result};
use crossbeam_channel::Sender;
use fnv::FnvHasher;

use alphonse_api as api;
use api::classifiers::matched::Rule;
use api::config::Config;
use api::dissectors::{link::LinkType, ProtocolDessector};
use api::packet::Packet as PacketTrait;
use api::packet::{Layers, PacketHashKey, Rules, Tunnel};
use api::plugins::rx::{RxDriver, RxStat};
use api::plugins::{Plugin, PluginType};

#[derive(Clone, Default)]
struct Driver {
    /// Thread handle
    handle: Arc<RwLock<Option<JoinHandle<Result<()>>>>>,
    /// Thread context
    thread_ctx: Arc<RwLock<Vec<Arc<RxThread>>>>,
}

impl Plugin for Driver {
    fn plugin_type(&self) -> PluginType {
        PluginType::RxDriver
    }

    fn name(&self) -> &str {
        "rx-libpcap"
    }

    fn cleanup(&self) -> Result<()> {
        let mut handle = match self.handle.write() {
            Ok(h) => h,
            Err(e) => return Err(anyhow!("{}", e)),
        };

        match handle.take() {
            None => {}
            Some(handle) => {
                match handle.join() {
                    Ok(_) => {}
                    Err(e) => eprintln!("{:?}", e),
                };
            }
        }

        Ok(())
    }
}

impl RxDriver for Driver {
    fn start(&self, cfg: Arc<Config>, senders: &[Sender<Box<dyn PacketTrait>>]) -> Result<()> {
        let interfaces = cfg.get_str_arr(&"rx.libpcap.interfaces");
        if interfaces.is_empty() {
            return Err(anyhow!(
                "Could lauch {} driver without specifying any network interfaces",
                self.name()
            ));
        }

        let mut ctx = match self.thread_ctx.write() {
            Ok(ctx) => ctx,
            Err(e) => return Err(anyhow!("{}", e)),
        };
        for (id, interface) in interfaces.iter().enumerate() {
            let cfg = cfg.clone();
            let thread = RxThread {
                id: id as u8,
                exit: cfg.exit.clone(),
                senders: senders.iter().map(|s| s.clone()).collect(),
                interface: interface.clone(),
                cap: Some(RefCell::new(NetworkInterface::try_from_str(
                    interface.as_str(),
                )?)),
            };
            ctx.push(Arc::new(thread));
        }

        // create a new native thread to use tokio runtime
        let threads = ctx.iter().map(|t| t.clone()).collect();
        let builder = std::thread::Builder::new().name(self.name().to_string());
        let handle = builder.spawn(move || main_loop(cfg, threads))?;

        match self.handle.write() {
            Ok(mut h) => {
                *h = Some(handle);
            }
            Err(e) => return Err(anyhow!("{}", e)),
        };

        Ok(())
    }

    fn stats(&self) -> Result<RxStat> {
        let mut stat = RxStat::default();
        let threads = self.thread_ctx.read().or_else(|e| Err(anyhow!("{}", e)))?;
        for thread in threads.iter() {
            stat += thread.stats();
        }
        Ok(stat)
    }
}

fn main_loop(cfg: Arc<Config>, threads: Vec<Arc<RxThread>>) -> Result<()> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .thread_name("alphonse-libpcap")
        .enable_all()
        .build()?;
    rt.block_on(async {
        let mut handles = vec![];
        let mut stats = vec![];

        for thread in threads {
            let cfg = cfg.clone();
            let handle = tokio::task::spawn_blocking(move || thread.spawn(cfg));
            handles.push(handle);
            stats.push(RxStat::default());
        }

        for hdl in handles {
            match hdl.await {
                Err(e) => eprintln!("{}", e),
                Ok(r) => match r {
                    Err(e) => eprintln!("{}", e),
                    Ok(_) => {}
                },
            };
        }
    });

    Ok(())
}

struct RxThread {
    id: u8,
    exit: Arc<AtomicBool>,
    senders: Vec<Sender<Box<dyn PacketTrait>>>,
    interface: String,
    cap: Option<RefCell<NetworkInterface>>,
}

// Since RxThread is
unsafe impl Send for RxThread {}
unsafe impl Sync for RxThread {}

impl RxThread {
    pub fn spawn(&self, cfg: Arc<Config>) -> Result<()> {
        let mut hasher = FnvHasher::default();
        let parser = ProtocolDessector::new(LinkType::ETHERNET);
        let mut cap = match &self.cap {
            None => return Err(anyhow!("")),
            Some(c) => c.borrow_mut(),
        };
        let mut overflow_cnt: u64 = 0;
        let mut rx_cnt: u64 = 0;

        println!("{} started", self.name());

        while !self.exit.load(Ordering::Relaxed) {
            let mut pkt = match cap.next() {
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

            match parser.parse_pkt(pkt.as_mut()) {
                Ok(_) => {}
                Err(e) => match e {
                    api::dissectors::Error::UnsupportProtocol(_) => {}
                    _ => todo!(),
                },
            };

            rx_cnt += 1;
            if rx_cnt % cfg.rx_stat_log_interval == 0 {
                match cap.stats() {
                    Ok(stats) => {
                        println!(
                            "{} {}({:.3}) {}",
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
                        overflow_cnt += 1;
                        if overflow_cnt % 10000 == 0 {
                            println!(
                                "{} overflowing, total overflow {}",
                                self.name(),
                                overflow_cnt
                            );
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

    pub fn stats(&self) -> RxStat {
        RxStat::default()
    }
}

struct NetworkInterface {
    cap: Box<pcap::Capture<pcap::Active>>,
}

impl NetworkInterface {
    #[inline]
    fn next(&mut self) -> Result<Box<dyn PacketTrait>, pcap::Error> {
        let raw = self.cap.as_mut().next()?;
        let pkt: Box<Packet> = Box::new(Packet::from(&raw));
        Ok(pkt)
    }

    fn stats(&mut self) -> Result<RxStat> {
        let mut stats = RxStat::default();
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
