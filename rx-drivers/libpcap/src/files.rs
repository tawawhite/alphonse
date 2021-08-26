use std::ffi::OsString;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::{anyhow, Result};
use crossbeam_channel::Sender;
use fnv::FnvHasher;
use num_traits::cast::FromPrimitive;
use path_absolutize::Absolutize;

use alphonse_api as api;
use alphonse_utils as utils;
use api::config::Config;
use api::packet::Packet as PacketTrait;
use api::packet::PacketHashKey;
use api::plugins::rx::RxStat;
use api::plugins::Plugin;
use utils::dissectors::link::LinkType;

use crate::{CaptureUnit, Driver, Packet};

impl Driver {
    pub(crate) fn start_files(
        &mut self,
        cfg: Arc<Config>,
        senders: &[Sender<Box<dyn PacketTrait>>],
    ) -> Result<()> {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .thread_name("alphonse-libpcap")
            .enable_all()
            .build()?;

        let mut thread = RxThread {
            exit: cfg.exit.clone(),
            files: get_pcap_files(cfg.as_ref()),
            senders: senders.iter().map(|s| s.clone()).collect(),
        };
        if thread.files.is_empty() {
            return Err(anyhow!(
                "{} launches without specifying any pcap file",
                self.name()
            ));
        }

        let hdl = rt.spawn_blocking(move || thread.spawn(cfg));
        self.handles.push(hdl);

        self.rt = Some(rt);

        Ok(())
    }

    #[inline]
    pub fn gather_files_stats(&self) -> Result<RxStat> {
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

/// get pcap files according to command line arguments/configuration file
pub fn get_pcap_files(cfg: &Config) -> Vec<PathBuf> {
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
}

impl RxThread {
    pub fn spawn(&mut self, cfg: Arc<Config>) -> Result<()> {
        if self.files.is_empty() {
            return Ok(());
        }

        let mut hasher = FnvHasher::default();
        let mut rx_byte: u64 = 0;
        let mut rx_cnt: u64 = 0;

        println!("{} started", self.name());

        for file in &self.files {
            if !file.exists() {
                return Err(anyhow!("File does not exist"));
            }

            let cap = Offline::try_from_path(file)?;
            let link_type = LinkType::from_u16(cap.cap.get_datalink().0 as u16)
                .ok_or_else(|| anyhow!("Unrecognized link type"))?;
            let parser = utils::dissectors::ProtocolDessector::new(link_type);

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
                        utils::dissectors::Error::UnsupportProtocol(_) => {}
                        _ => todo!(),
                    },
                };

                rx_cnt += 1;
                rx_byte += pkt.raw().len() as u64;
                if rx_cnt % cfg.rx_stat_log_interval == 0 {
                    println!("{} {}", rx_cnt, rx_byte,);
                }

                PacketHashKey::from(pkt.as_ref()).hash(&mut hasher);
                let i = hasher.finish() as usize % self.senders.len();
                hasher = FnvHasher::default();
                let sender = &mut self.senders[i];

                match sender.try_send(pkt) {
                    Ok(_) => {}
                    Err(err) => {
                        match err {
                            crossbeam_channel::TrySendError::Full(_) => {
                                // wait until sender is not full
                                while sender.is_full() {}
                            }
                            crossbeam_channel::TrySendError::Disconnected(_) => {
                                println!("{} channel is closed, exit", self.name());
                                break;
                            }
                        };
                    }
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
    cap: pcap::Capture<pcap::Offline>,
}

impl CaptureUnit for Offline {
    #[inline]
    fn next(&self) -> Result<Box<dyn PacketTrait>, pcap::Error> {
        let c = unsafe { &mut (*(&self.cap as *const _ as *mut pcap::Capture<pcap::Offline>)) };
        let raw = c.next()?;
        let pkt = Box::new(Packet::from(&raw));
        Ok(pkt)
    }

    fn stats(&self) -> Result<RxStat> {
        let mut stats = RxStat::default();
        let c = unsafe { &mut (*(&self.cap as *const _ as *mut pcap::Capture<pcap::Offline>)) };
        let cap_stats = c.stats()?;
        stats.rx_pkts = cap_stats.received as u64;
        stats.dropped = cap_stats.dropped as u64;
        stats.if_dropped = cap_stats.if_dropped as u64;
        Ok(stats)
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

        Ok(Offline { cap: pcap_file })
    }
}
