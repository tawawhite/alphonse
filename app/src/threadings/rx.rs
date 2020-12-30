use std::any::TypeId;
use std::ffi::OsString;
use std::hash::{Hash, Hasher};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::{anyhow, Result};
use crossbeam_channel::{Sender, TrySendError};
use path_absolutize::Absolutize;

use alphonse_api::packet::Packet;

use super::capture::{Capture, NetworkInterface, Offline};
use super::config;
use super::packet::{parser, Parser};

/// RX Thread
pub struct RxThread {
    /// Thread ID
    id: u8,
    /// Exit flag
    exit: Arc<AtomicBool>,
    /// Total received packet count
    pub rx_count: u64,
    /// Basic protocol parser
    parser: Parser,
    /// Packet channel sender
    senders: Vec<Sender<Box<Packet>>>,
}

impl RxThread {
    /// Create a new rx thread
    pub fn new(
        id: u8,
        link_type: u16,
        senders: Vec<Sender<Box<Packet>>>,
        exit: Arc<AtomicBool>,
    ) -> RxThread {
        RxThread {
            id,
            exit,
            rx_count: 0,
            parser: Parser::new(link_type),
            senders,
        }
    }

    pub fn id(&self) -> u8 {
        self.id
    }

    /// get pcap files according to command line arguments/configuration file
    fn get_pcap_files(cfg: &config::Config) -> Vec<PathBuf> {
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

    #[inline]
    fn rx<C: 'static + Capture>(&mut self, cap: &mut C) -> Result<()> {
        while !self.exit.load(Ordering::Relaxed) {
            let mut pkt = match cap.next() {
                Ok(pkt) => pkt,
                Err(err) => {
                    if TypeId::of::<C>() == TypeId::of::<super::capture::Offline>() {
                        return Ok(());
                    }
                    return Err(err);
                }
            };

            self.rx_count += 1;

            match self.parser.parse_pkt(&mut pkt) {
                Ok(_) => {}
                Err(e) => match e {
                    parser::Error::UnsupportProtocol(_) => {}
                    _ => todo!(),
                },
            };

            // TODO: inline with_seed function
            let mut hasher = twox_hash::Xxh3Hash64::with_seed(0);
            pkt.hash(&mut hasher);
            pkt.hash = hasher.finish();

            let thread = (pkt.hash % self.senders.len() as u64) as usize;
            match self.senders[thread].try_send(pkt) {
                Ok(_) => {}
                Err(e) => {
                    match e {
                        TrySendError::Full(_) => {
                            eprintln!("pkt channel {} is full, overflowing", self.id);
                        }
                        TrySendError::Disconnected(_) => {
                            eprintln!("rx thread {} {}, thread exit", self.id, e);
                            return Err(anyhow!("Channel diconnected"));
                        }
                    };
                }
            };
        }
        Ok(())
    }

    fn process_files(&mut self, files: &Vec<PathBuf>) -> Result<()> {
        for file in files {
            let mut cap = Offline::try_from_path(file)?;
            self.rx(&mut cap)?;
        }
        Ok(())
    }

    fn listen_network_interface(&mut self, cfg: &Arc<config::Config>) -> Result<()> {
        let interface = match cfg.interfaces.get(self.id as usize) {
            Some(i) => i,
            None => todo!(),
        };

        let mut cap = NetworkInterface::try_from_str(interface)?;
        self.rx(&mut cap)?;

        Ok(())
    }

    pub fn spawn(&mut self, cfg: Arc<config::Config>) -> Result<()> {
        println!("rx thread {} started", self.id);

        let files = RxThread::get_pcap_files(cfg.as_ref());
        if !files.is_empty() {
            self.process_files(&files)?;
        } else {
            self.listen_network_interface(&cfg)?;
        };

        println!("rx thread {} exit", self.id);

        Ok(())
    }
}
