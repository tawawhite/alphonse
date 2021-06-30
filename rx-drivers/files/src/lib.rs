use std::ffi::OsString;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::thread::JoinHandle;

use anyhow::{anyhow, Result};
use crossbeam_channel::Sender;
use fnv::FnvHasher;
use num_traits::cast::FromPrimitive;
use path_absolutize::Absolutize;

use alphonse_api as api;
use api::classifiers::matched::Rule;
use api::config::Config;
use api::packet::Packet as PacketTrait;
use api::packet::{Layers, PacketHashKey, Rules, Tunnel};
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
        "rx-files"
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
    fn start(&self, cfg: Arc<Config>, senders: &[Sender<Box<dyn PacketTrait>>]) -> Result<()> {
        let mut handles = vec![];
        let mut thread = RxThread {
            exit: cfg.exit.clone(),
            files: get_pcap_files(cfg.as_ref()),
            senders: senders.iter().map(|s| s.clone()).collect(),
            hasher: FnvHasher::default(),
        };
        if thread.files.is_empty() {
            return Err(anyhow!(
                "{} launches without specifying any pcap file",
                self.name()
            ));
        }

        let builder = std::thread::Builder::new().name(thread.name());
        let handle = builder.spawn(move || thread.spawn(cfg))?;
        handles.push(handle);
        Ok(())
    }

    fn stats(&self) -> Result<RxStat> {
        Ok(self.stats)
    }
}

/// get pcap files according to command line arguments/configuration file
fn get_pcap_files(cfg: &Config) -> Vec<PathBuf> {
    let mut files = Vec::new();
    if !cfg.pcap_file.is_empty() {
        files.push(PathBuf::from(&cfg.pcap_file));
    } else if !cfg.pcap_dir.is_empty() {
        let path_buf = PathBuf::from(&cfg.pcap_dir);
        let pcap_dir = path_buf.absolutize().unwrap();
        for entry in pcap_dir.read_dir().expect("read_dir call failed") {
            if let Ok(entry) = entry {
                let buf = entry.path();
                if buf.is_dir() {
                    continue;
                }

                match buf.extension() {
                    None => continue,
                    Some(s) => {
                        let ext = std::ffi::OsString::from(s);
                        let pcap_ext = OsString::from("pcap");
                        let pcapng_ext = OsString::from("pcapng");
                        match ext {
                            _ if ext == pcap_ext => files.push(entry.path()),
                            _ if ext == pcapng_ext => files.push(entry.path()),
                            _ => {} // if file is not pcap or pcapng, skip
                        };
                    }
                };
            }
        }
    }

    return files;
}

struct RxThread {
    exit: Arc<AtomicBool>,
    senders: Vec<Sender<Box<dyn PacketTrait>>>,
    files: Vec<PathBuf>,
    hasher: FnvHasher,
}

impl RxThread {
    pub fn spawn(&mut self, _cfg: Arc<Config>) -> Result<()> {
        if self.files.is_empty() {
            return Ok(());
        }

        println!("{} started", self.name());

        for file in &self.files {
            if !file.exists() {
                return Err(anyhow!("File does not exist"));
            }

            let mut cap = Offline::try_from_path(file)?;
            let link_type =
                api::dissectors::link::LinkType::from_u16(cap.cap.get_datalink().0 as u16)
                    .ok_or_else(|| anyhow!("Unrecognized link type"))?;
            let parser = api::dissectors::ProtocolDessector::new(link_type);
            let mut overflow_cnt = 0;

            while !self.exit.load(Ordering::Relaxed) {
                let mut pkt = match cap.next() {
                    Ok(pkt) => pkt,
                    Err(err) => {
                        if err.to_string().as_str() == "no more packets to read from the file" {
                        } else {
                            eprintln!("{}", err);
                        }
                        break;
                    }
                };

                match parser.parse_pkt(pkt.as_mut()) {
                    Ok(_) => {}
                    Err(e) => match e {
                        api::dissectors::Error::UnsupportProtocol(_) => {}
                        _ => todo!(),
                    },
                };

                PacketHashKey::from(pkt.as_ref()).hash(&mut self.hasher);
                let i = self.hasher.finish() as usize % self.senders.len();
                self.hasher = FnvHasher::default();
                let sender = &mut self.senders[i];

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
        }

        // terminate alphonse after all packets are send to packet processing thread
        while self.senders.iter().any(|s| s.len() != 0) {}
        self.exit.swap(true, Ordering::Relaxed);

        println!("{} exit", self.name());

        Ok(())
    }

    pub fn name(&self) -> String {
        "alphonse-replay".to_string()
    }
}

struct Offline {
    cap: Box<pcap::Capture<pcap::Offline>>,
}

impl Offline {
    #[inline]
    fn next(&mut self) -> Result<Box<dyn PacketTrait>> {
        let raw = self.cap.as_mut().next()?;
        let pkt = Box::new(Packet::from(&raw));
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
