use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::thread::JoinHandle;

use anyhow::{anyhow, Result};
use crossbeam_channel::Sender;

use alphonse_api as api;
use api::classifiers::matched::Rule;
use api::config::Config;
use api::packet::Packet as PacketTrait;
use api::packet::{Layers, Rules, Tunnel};
use api::plugins::rx::{RxDriver, RxStat};
use api::plugins::{Plugin, PluginType};

#[derive(Clone, Default)]
struct Driver {
    handles: Arc<RwLock<Vec<JoinHandle<Result<()>>>>>,
    stats: RxStat,
}

impl Plugin for Driver {
    fn plugin_type(&self) -> PluginType {
        PluginType::RxDriver
    }

    fn name(&self) -> &str {
        "rx-libpcap"
    }

    fn cleanup(&self) -> Result<()> {
        let mut handles = match self.handles.write() {
            Ok(h) => h,
            Err(e) => return Err(anyhow!("{}", e)),
        };

        while handles.len() > 0 {
            let hdl = handles.pop();
            match hdl {
                None => continue,
                Some(hdl) => match hdl.join() {
                    Ok(_) => {}
                    Err(e) => eprintln!("{:?}", e),
                },
            }
        }

        Ok(())
    }
}

impl RxDriver for Driver {
    fn start(&self, cfg: Arc<Config>, sender: Sender<Box<dyn PacketTrait>>) -> Result<()> {
        let mut handles = vec![];
        let interfaces = cfg.get_str_arr(&"rx.libpcap.interfaces");
        if interfaces.is_empty() {
            return Err(anyhow!(
                "{} launches without specifying any network interfaces",
                self.name()
            ));
        }

        for interface in interfaces.iter() {
            let cfg = cfg.clone();
            let mut thread = RxThread {
                exit: cfg.exit.clone(),
                sender: sender.clone(),
                interface: interface.clone(),
            };
            let builder = std::thread::Builder::new().name(thread.name());
            let handle = builder.spawn(move || thread.spawn(cfg))?;
            handles.push(handle);
        }

        match self.handles.write() {
            Ok(mut h) => {
                *h.as_mut() = handles;
            }
            Err(e) => return Err(anyhow!("{}", e)),
        };
        Ok(())
    }

    fn stats(&self) -> RxStat {
        self.stats
    }
}

struct RxThread {
    exit: Arc<AtomicBool>,
    sender: Sender<Box<dyn PacketTrait>>,
    interface: String,
}

impl RxThread {
    pub fn spawn(&mut self, cfg: Arc<Config>) -> Result<()> {
        let mut cap = NetworkInterface::try_from_str(self.interface.as_str())?;
        let mut overflow_cnt: u64 = 0;
        let mut rx_cnt: u64 = 0;

        println!("{} started", self.name());

        while !self.exit.load(Ordering::Relaxed) {
            let pkt = match cap.next() {
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

            match self.sender.try_send(pkt) {
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
        self.rules.as_slice()
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
