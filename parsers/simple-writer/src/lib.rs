use std::hash::Hasher;
use std::hash::{BuildHasher, Hash};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;

use anyhow::{anyhow, Result};
use crossbeam_channel::{Receiver, Sender};
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
mod writer;

use scheuler::Scheduler;
use writer::SimpleWriter;

const PKG_NAME: &'static str = env!("CARGO_PKG_NAME");
static FILE_ID: AtomicU32 = AtomicU32::new(0);
static mut HANDLES: OnceCell<Vec<JoinHandle<Result<()>>>> = OnceCell::new();
static mut SCHEDULERS: OnceCell<Vec<Scheduler>> = OnceCell::new();
static mut CHANNEL: OnceCell<(Sender<Box<PacketInfo>>, Receiver<Box<PacketInfo>>)> =
    OnceCell::new();

#[derive(Clone, Debug, Default, Deserialize)]
pub struct Config {
    /// Whether save packets to disk or not
    #[serde(skip_deserializing)]
    pub dryrun: bool,

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

    /// Alphonse exit flag
    #[serde(skip_deserializing)]
    pub exit: Arc<AtomicBool>,

    /// Arkime Elasticsearch host name
    #[serde(skip_deserializing)]
    #[cfg(feature = "arkime")]
    pub es_host: String,
}

/// Writing pcap file encryption mode
#[derive(Clone, Copy, Debug)]
pub enum Mode {
    Normal,
    XOR2048,
    AES256CTR,
}

/// Pcap directory selecting algorithm
#[derive(Clone, Copy, Debug)]
pub enum PcapDirAlgorithm {
    MaxFreePercent,
    MaxFreeBytes,
    RoundRobin,
}

/// The structure contains the file information
#[derive(Clone, Debug)]
enum File {
    ID(u32),
    Name(PathBuf),
}

impl Default for File {
    fn default() -> Self {
        File::ID(0)
    }
}

#[derive(Debug, Default)]
pub struct PacketInfo {
    /// Packet thread id, which is also the scheduler thread ID
    thread: u8,
    /// Indicate whether a PacketWriter should close current pcap file after this pkt
    closing: bool,
    /// Formatted pcap/pcapng packet buffer
    buf: Vec<u8>,
    /// Current writing file name
    file_info: File,
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
    /// Current file ID
    fid: u32,
}

impl Clone for Processor {
    fn clone(&self) -> Self {
        Self {
            id: self.id,
            classified: self.classified,
            packet_pos: self.packet_pos.clone(),
            hasher: fnv::FnvBuildHasher::default().build_hasher(),
            fid: self.fid,
        }
    }
}

impl ProtocolParserTrait for Processor {
    fn box_clone(&self) -> Box<dyn ProtocolParserTrait> {
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
        cfg.exit = alcfg.exit.clone();
        #[cfg(feature = "arkime")]
        {
            cfg.es_host = alcfg.get_str("elasticsearch", "http://localhost:9200");
        }

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
            scheduler.max_file_size = cfg.max_file_size;
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
            receiver: receiver.clone(),
        };
        let builder = std::thread::Builder::new().name(self.name().to_string());
        let handle = builder.spawn(move || thread.spawn(cfg.clone()))?;
        let handles = vec![handle];

        unsafe {
            HANDLES
                .set(handles)
                .expect("Writer thread handles are already setted");
            CHANNEL
                .set((sender, receiver))
                .expect("Packet info channel is already setted");
        }

        Ok(())
    }

    fn exit(&mut self) -> Result<()> {
        // At this moment, all packet process threads are finished, nothing would use SCHEDULERS any more,
        // so cleanup all existing schedulers. Once all the schedulers were dropped, PacketInfo channel
        // would be closed, so the packet writing thread would be closed too.
        let mut schedulers = unsafe { SCHEDULERS.take().ok_or(anyhow!(""))? };
        schedulers.clear();

        let (sender, receiver) = unsafe { CHANNEL.take().ok_or(anyhow!(""))? };
        drop(sender);
        drop(receiver);

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
        let info = schedulers[hash].gen(pkt, FILE_ID.load(Ordering::Relaxed));
        if schedulers[hash].current_fid() != self.fid {
            self.fid = schedulers[hash].current_fid();
            self.packet_pos
                .push(-(schedulers[hash].current_fid() as isize));
        }
        self.packet_pos
            .push(schedulers[hash].current_pos() as isize);

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
