use std::any::TypeId;
use std::collections::HashMap;
use std::ffi::OsString;
use std::hash::{Hash, Hasher};
use std::os::raw::c_long;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::SystemTime;

use anyhow::Result;
use crossbeam_channel::Sender;
use fnv::FnvHashMap;
use path_absolutize::Absolutize;

use alphonse_api as api;
use api::classifiers::ClassifierManager;
use api::packet::{Packet, Protocol};
use api::parsers::{ParserID, ProtocolParserTrait};
use api::session::Session;
use api::utils::timeval::TimeVal;

use super::capture::{Capture, NetworkInterface, Offline};
use super::config;
use super::packet::{parser, Parser};

/// Data structure to store session info and session's protocol parsers
struct SessionData {
    info: Arc<Session>,
    parsers: Box<FnvHashMap<ParserID, Box<dyn ProtocolParserTrait>>>,
}

impl SessionData {
    fn new() -> Self {
        SessionData {
            info: Arc::new(Session::new()),
            parsers: Box::new(FnvHashMap::default()),
        }
    }
}

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
    sender: Sender<Arc<Session>>,
    /// Packet Classifier
    classifier: Arc<ClassifierManager>,
}

impl RxThread {
    /// Create a new rx thread
    pub fn new(
        id: u8,
        link_type: u16,
        sender: Sender<Arc<Session>>,
        classifier: Arc<ClassifierManager>,
        exit: Arc<AtomicBool>,
    ) -> RxThread {
        RxThread {
            id,
            exit,
            rx_count: 0,
            parser: Parser::new(link_type),
            classifier,
            sender,
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
    fn parse_pkt(
        &self,
        scratch: &mut api::classifiers::ClassifyScratch,
        protocol_parsers: &mut Box<Vec<Box<dyn ProtocolParserTrait>>>,
        pkt: &mut Box<dyn Packet>,
        ses: &mut Session,
        ses_parsers: &mut FnvHashMap<ParserID, Box<dyn ProtocolParserTrait>>,
    ) -> Result<()> {
        self.classifier.classify(pkt, scratch)?;

        for rule in pkt.rules().iter() {
            for parser_id in rule.parsers.iter() {
                match ses_parsers.get_mut(parser_id) {
                    Some(parser) => {
                        parser.parse_pkt(pkt, rule, ses)?;
                    }
                    None => {
                        let mut parser = protocol_parsers
                            .get_mut(*parser_id as usize)
                            .unwrap()
                            .box_clone();
                        parser.parse_pkt(pkt, rule, ses)?;
                        ses_parsers.insert(parser.id(), parser);
                    }
                };
            }
        }

        Ok(())
    }

    /// Check whether a session is timeout
    #[inline]
    fn timeout(
        ts: u64,
        session_table: &mut HashMap<Box<dyn Packet>, Box<SessionData>>,
        sender: &mut Sender<Arc<Session>>,
        cfg: &Arc<config::Config>,
    ) -> Result<()> {
        &mut session_table.retain(|pkt, ses| {
            let timeout = match pkt.trans_layer().protocol {
                Protocol::TCP => ses.info.timeout(cfg.tcp_timeout as c_long, ts as c_long),
                Protocol::UDP => ses.info.timeout(cfg.udp_timeout as c_long, ts as c_long),
                Protocol::SCTP => ses.info.timeout(cfg.sctp_timeout as c_long, ts as c_long),
                _ => ses
                    .info
                    .timeout(cfg.default_timeout as c_long, ts as c_long),
            };

            if timeout {
                println!("timeouted");
                match sender.send(ses.info.clone()) {
                    Ok(_) => {}
                    Err(err) => {
                        eprintln!("sender error: {}", err);
                        return false;
                    }
                }
            }

            !timeout
        });

        Ok(())
    }

    #[inline]
    fn rx<C: 'static + Capture>(
        &mut self,
        cap: &mut C,
        cfg: &Arc<config::Config>,
        protocol_parsers: &mut Box<Vec<Box<dyn ProtocolParserTrait>>>,
    ) -> Result<()> {
        let mut last_packet_time: u64 = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut last_timeout_check_time: u64 = last_packet_time + cfg.timeout_interval;
        let mut session_table: HashMap<Box<dyn Packet>, Box<SessionData>> = Default::default();
        let mut classify_scratch = match self.classifier.alloc_scratch() {
            Ok(scratch) => scratch,
            Err(_) => todo!(),
        };

        while !self.exit.load(Ordering::Relaxed) {
            let mut pkt = match cap.next() {
                Ok(pkt) => pkt,
                Err(err) => {
                    if TypeId::of::<C>() == TypeId::of::<super::capture::Offline>() {
                        break;
                    }
                    return Err(err);
                }
            };

            last_packet_time = pkt.ts().tv_sec as u64;
            self.rx_count += 1;

            match self.parser.parse_pkt(pkt.as_mut()) {
                Ok(_) => {}
                Err(e) => match e {
                    parser::Error::UnsupportProtocol(_) => {}
                    _ => todo!(),
                },
            };

            // TODO: inline with_seed function
            let mut hasher = twox_hash::Xxh3Hash64::with_seed(0);
            pkt.hash(&mut hasher);
            *pkt.hash_mut() = hasher.finish();

            match session_table.get_mut(&pkt) {
                Some(ses) => {
                    let info = Arc::get_mut(&mut ses.info).unwrap();
                    info.update(&pkt);
                    self.parse_pkt(
                        &mut classify_scratch,
                        protocol_parsers,
                        &mut pkt,
                        info,
                        ses.parsers.as_mut(),
                    )
                    .unwrap();
                }
                None => {
                    let key = pkt.clone_box_deep();
                    let mut ses = Box::new(SessionData::new());
                    let info = Arc::get_mut(&mut ses.info).unwrap();
                    info.start_time = TimeVal::new(*pkt.ts());
                    info.update(&pkt);
                    self.parse_pkt(
                        &mut classify_scratch,
                        protocol_parsers,
                        &mut pkt,
                        Arc::get_mut(&mut ses.info).unwrap(),
                        ses.parsers.as_mut(),
                    )
                    .unwrap();

                    &mut session_table.insert(key, ses);
                }
            }

            if last_packet_time > last_timeout_check_time {
                Self::timeout(last_packet_time, &mut session_table, &mut self.sender, &cfg)?;
                last_timeout_check_time = last_packet_time;
            }
        }

        for (_, ses) in session_table.iter() {
            self.sender.send(ses.info.clone())?;
        }
        Ok(())
    }

    fn process_files(
        &mut self,
        cfg: &Arc<config::Config>,
        files: &Vec<PathBuf>,
        protocol_parsers: &mut Box<Vec<Box<dyn ProtocolParserTrait>>>,
    ) -> Result<()> {
        for file in files {
            let mut cap = Offline::try_from_path(file)?;
            self.rx(&mut cap, cfg, protocol_parsers)?;
        }
        Ok(())
    }

    fn listen_network_interface(
        &mut self,
        cfg: &Arc<config::Config>,
        protocol_parsers: &mut Box<Vec<Box<dyn ProtocolParserTrait>>>,
    ) -> Result<()> {
        let interface = match cfg.interfaces.get(self.id as usize) {
            Some(i) => i,
            None => todo!(),
        };

        let mut cap = NetworkInterface::try_from_str(interface)?;
        self.rx(&mut cap, cfg, protocol_parsers)?;

        Ok(())
    }

    pub fn spawn(
        &mut self,
        cfg: Arc<config::Config>,
        mut protocol_parsers: Box<Vec<Box<dyn ProtocolParserTrait>>>,
    ) -> Result<()> {
        println!("rx thread {} started", self.id);

        let files = RxThread::get_pcap_files(cfg.as_ref());
        if !files.is_empty() {
            self.process_files(&cfg, &files, &mut protocol_parsers)?;
        } else {
            self.listen_network_interface(&cfg, &mut protocol_parsers)?;
        };

        println!("rx thread {} exit", self.id);

        Ok(())
    }
}
