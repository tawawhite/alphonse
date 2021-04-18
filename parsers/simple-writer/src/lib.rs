use std::hash::Hasher;
use std::hash::{BuildHasher, Hash};
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::thread::JoinHandle;

use anyhow::{anyhow, Result};
use once_cell::sync::OnceCell;
use serde::Deserialize;
use yaml_rust::YamlEmitter;

use alphonse_api as api;
use api::classifiers::{matched::Rule, ClassifierManager};
use api::packet::{Packet, PacketHashKey};
use api::parsers::{ParserID, ProtocolParserTrait};
use api::session::Session;
use api::utils::yaml::Yaml;

mod scheuler;
mod threadings;

use scheuler::Scheduler;

const PKG_NAME: &'static str = env!("CARGO_PKG_NAME");
static mut HANDLES: OnceCell<Vec<JoinHandle<Result<()>>>> = OnceCell::new();
static mut SCHEDULERS: OnceCell<Vec<Scheduler>> = OnceCell::new();

#[derive(Clone, Debug, Default, Deserialize)]
struct Config {
    /// Output pcap directory
    #[serde(rename = "pcap.dirs")]
    pub pcap_dirs: Vec<String>,

    /// Output pcap directory
    #[serde(rename = "max.file.size")]
    pub max_file_size: usize,

    /// Whether alphonse run in offline replay mode
    #[serde(skip_deserializing)]
    pub offline: bool,

    /// Current alphonse node name
    #[serde(skip_deserializing)]
    pub node: String,

    /// Original yaml config
    #[serde(skip_deserializing)]
    pub doc: Yaml,
}

#[derive(Debug)]
enum WriteError {
    /// Disk is overloading
    Overload,
    /// Could not open file on disk
    FileOpenError,
    /// Could write packet to disk
    FileWriteError,
}

/// Writing pcap file encryption mode
#[derive(Clone, Copy, Debug)]
pub enum Mode {
    Normal,
    XOR2048,
    AES256CTR,
}

/// Writing pcap file format
#[derive(Clone, Copy, Debug)]
pub enum Format {
    Pcap,
    Pcapng,
}

/// Pcap directory selecting algorithm
#[derive(Clone, Copy, Debug)]
pub enum PcapDirAlgorithm {
    MaxFreePercent,
    MaxFreeBytes,
    RoundRobin,
}

#[derive(Debug, Default)]
pub struct PacketInfo {
    /// Packet thread id
    thread: u8,
    /// Indicate whether a PacketWriter should close current pcap file after this pkt
    closing: bool,
    /// Formatted pcap/pcapng packet buffer
    buf: Vec<u8>,
    /// Current writing file name
    fname: Arc<RwLock<PathBuf>>,
}

/// Pcap writer, write pacp to disk or remote filesystem or whatever
#[derive(Debug)]
pub struct SimpleWriter {
    /// Current opened pcap file handle
    file: Option<std::fs::File>,
}

impl Default for SimpleWriter {
    fn default() -> Self {
        Self { file: None }
    }
}

impl Clone for SimpleWriter {
    fn clone(&self) -> Self {
        todo!("implement clone method for SimpleWriter")
    }
}

impl SimpleWriter {
    /// Wirte packet to disk
    fn write(&mut self, pkt: &[u8], info: &PacketInfo) -> Result<()> {
        let file = match &mut self.file {
            Some(f) => f,
            // None => todo!("handle file is None"),
            None => return Err(anyhow!("{:?}", WriteError::FileOpenError)),
        };

        match file.write(pkt) {
            Ok(_) => {}
            // Err(_) => {
            //     todo!("handle file write error")
            // }
            Err(e) => return Err(anyhow!("{}", e)),
        };

        if info.closing {
            // Open new pcap file for writing
            while let Ok(fname) = info.fname.read() {
                let file = std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(fname.as_path())?;
                self.file = Some(file);
            }
        }

        Ok(())
    }
}

#[derive(Default)]
struct Processor {
    /// Processor ID
    id: ParserID,
    /// Whether current packet is registered with this processer
    classified: bool,
    /// Actual packet disk position
    packet_pos: Vec<isize>,
    /// Hasher to decide which scheduler to use
    hasher: fnv::FnvHasher,
}

impl Clone for Processor {
    fn clone(&self) -> Self {
        Self {
            id: self.id,
            classified: self.classified,
            packet_pos: self.packet_pos.clone(),
            hasher: fnv::FnvBuildHasher::default().build_hasher(),
        }
    }
}

impl ProtocolParserTrait for Processor {
    fn box_clone(&self) -> Box<dyn ProtocolParserTrait> {
        println!("shit");
        let info = Box::new(PacketInfo::default());
        let schedulers = unsafe {
            SCHEDULERS
                .get()
                .ok_or(anyhow!("{}: SCHEDULERS is not initialized", self.name()))
                .unwrap()
        };
        schedulers[0].send(info);
        Box::new(self.clone())
    }

    fn id(&self) -> ParserID {
        self.id
    }

    fn set_id(&mut self, id: ParserID) {
        self.id = id
    }

    fn name(&self) -> &str {
        PKG_NAME
    }

    fn init(&mut self, alcfg: &api::config::Config) -> Result<()> {
        let root = "simple-writer";
        let yaml = match alcfg.doc.as_ref()[root] {
            yaml_rust::Yaml::Hash(_) => {
                let mut out = String::new();
                let mut emitter = YamlEmitter::new(&mut out);
                emitter.dump(&alcfg.doc.as_ref()[root])?;
                out
            }
            yaml_rust::Yaml::BadValue => {
                println!(
                    "Option {} not found or bad hash value, {} initialization failed",
                    root,
                    self.name()
                );
                return Err(anyhow!(""));
            }
            _ => {
                println!(
                    "Wrong value type for {}, expecting string, {} initialization failed",
                    root,
                    self.name()
                );
                return Err(anyhow!(""));
            }
        };

        let mut cfg: Config = serde_yaml::from_str(&yaml)?;
        cfg.doc = alcfg.doc.clone();

        // Prepare global packet write info writer
        let (sender, receiver) = crossbeam_channel::bounded(100000);
        let mut schedulers = vec![];
        for i in 0..alcfg.pkt_threads {
            let mut scheduler = Scheduler::new(i, sender.clone());
            scheduler.pcap_dirs = cfg
                .pcap_dirs
                .iter()
                .map(|path| PathBuf::from(path))
                .collect();
            // scheduler.max_file_size = cfg.max_file_size;
            schedulers.push(scheduler);
        }
        unsafe {
            // unlikely to failed
            SCHEDULERS
                .set(schedulers)
                .ok()
                .ok_or(anyhow!("{} SCHEDULERS are already set", self.name()))?
        };

        // Prepare packet info writer and spawn a writer thread
        let mut thread = threadings::Thread {
            writer: SimpleWriter::default(),
            receiver,
        };
        let builder = std::thread::Builder::new().name(self.name().to_string());
        let handle = builder.spawn(move || thread.spawn()).unwrap();
        let handles = vec![handle];

        unsafe {
            HANDLES
                .set(handles)
                .expect("Writer thread handles are already setted");
        }

        Ok(())
    }

    fn exit(&mut self) -> Result<()> {
        // At this moment, all packet process threads are finished, nothing would use SCHEDULERS any more,
        // so cleanup all existing schedulers. Once all the schedulers were dropped, PacketInfo channel
        // would be closed, so the packet writing thread would be closed too.
        let mut schedulers = unsafe { SCHEDULERS.take().ok_or(anyhow!(""))? };
        schedulers.clear();

        let handles = unsafe { HANDLES.take().ok_or(anyhow!(""))? };
        for hdl in handles {
            match hdl.join() {
                Ok(_) => {}
                Err(e) => {
                    eprintln!("{:?}", e);
                }
            };
        }
        Ok(())
    }

    fn register_classify_rules(&mut self, manager: &mut ClassifierManager) -> Result<()> {
        let mut rule = api::classifiers::Rule::new(self.id);
        rule.rule_type = api::classifiers::RuleType::All;
        rule.priority = 0;
        manager.add_rule(&mut rule)?;

        Ok(())
    }

    fn parse_pkt(
        &mut self,
        pkt: &dyn Packet,
        _rule: Option<&Rule>,
        _ses: &mut Session,
    ) -> Result<()> {
        PacketHashKey::from(pkt).hash(&mut self.hasher);
        let schedulers = unsafe {
            SCHEDULERS
                .get()
                .ok_or(anyhow!("{}: SCHEDULERS is not initialized", self.name()))?
        };
        let hash = self.hasher.finish() as usize % schedulers.len();
        let info = schedulers[hash].gen(pkt);
        schedulers[hash].send(info)?;
        Ok(())
    }

    fn is_classified(&self) -> bool {
        self.classified
    }

    fn classified_as_this_protocol(&mut self) -> Result<()> {
        self.classified = true;
        Ok(())
    }

    /// Add packet positions into session after session is about to timeout or closed
    fn finish(&mut self, ses: &mut Session) {
        let value = serde_json::Value::Array(
            self.packet_pos
                .iter()
                .map(|pos| serde_json::json!(pos))
                .collect(),
        );
        ses.add_field(&"packetPos", &value);
    }
}

#[no_mangle]
pub extern "C" fn al_new_protocol_parser() -> Box<Box<dyn api::parsers::ProtocolParserTrait>> {
    Box::new(Box::new(Processor::default()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_pkt() -> Result<()> {
        let cfg = api::config::Config::default();
        let mut processor = Processor::default();
        processor.init(&cfg)?;
        let pkt = api::utils::packet::Packet::default();
        let mut ses = Session::default();
        processor.parse_pkt(&pkt, None, &mut ses)?;
        Ok(())
    }

    #[test]
    fn finish() {
        let mut processor = Processor::default();
        processor.packet_pos = vec![-1, 1, 2, 3, 4, 5];

        let mut ses = Session::new();
        processor.finish(&mut ses);

        let packet_pos = ses.fields["packetPos"].clone();
        assert!(packet_pos.is_array());
        let packet_pos = packet_pos.as_array().unwrap();
        assert_eq!(packet_pos.len(), 6);
        assert_eq!(packet_pos[0], -1);
        assert_eq!(packet_pos[1], 1);
    }
}
