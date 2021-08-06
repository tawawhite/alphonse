use std::collections::HashSet;
use std::hash::Hasher;
use std::hash::{BuildHasher, Hash};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;

use anyhow::{anyhow, Result};
use crossbeam_channel::{Receiver, Sender};
use elasticsearch::http::transport::Transport;
use elasticsearch::Elasticsearch;
use fnv::FnvHasher;
use once_cell::sync::OnceCell;
use serde::{Deserialize, Serialize, Serializer};
use serde_json::json;
use tokio::task::JoinHandle;
use yaml_rust::YamlEmitter;

use alphonse_api as api;
use api::classifiers::{matched::Rule, ClassifierManager};
use api::config::Yaml;
use api::packet::{Packet, PacketHashKey};
use api::plugins::processor::{Processor, ProcessorID};
use api::plugins::{Plugin, PluginType};
use api::session::Session;

#[cfg(feature = "arkime")]
mod arkime;
mod scheuler;
mod threadings;
mod writer;

use scheuler::Scheduler;
use threadings::main_loop;
use writer::SimpleWriter;

const PKG_NAME: &'static str = env!("CARGO_PKG_NAME");
static FILE_ID: AtomicU32 = AtomicU32::new(0);
static mut HANDLES: OnceCell<Vec<JoinHandle<Result<()>>>> = OnceCell::new();
static mut SCHEDULERS: OnceCell<Vec<Scheduler>> = OnceCell::new();
static mut CHANNEL: OnceCell<(Sender<Box<PacketInfo>>, Receiver<Box<PacketInfo>>)> =
    OnceCell::new();
static RT: OnceCell<tokio::runtime::Runtime> = OnceCell::new();

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

    /// Current alphonse node name
    #[serde(skip_deserializing)]
    pub prefix: String,

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

#[allow(dead_code)]
fn bool_serialize<S>(locked: &bool, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let locked = if *locked { 1 } else { 0 };
    s.serialize_u8(locked)
}

/// Arkime files Index document data structure
#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
struct PcapFileInfo {
    filesize: usize,
    first: u64,
    last: u64,
    #[cfg_attr(feature = "arkime", serde(serialize_with = "bool_serialize"))]
    locked: bool,
    name: PathBuf,
    node: String,
    /// Pcap file ID number
    num: u32,
    packet_pos_encoding: String,
}

#[derive(Debug)]
pub struct PacketInfo {
    /// Packet thread id, which is also the scheduler thread ID
    thread: u8,
    /// Indicate whether a PacketWriter should close current pcap file after this pkt
    closing: bool,
    /// Formatted pcap/pcapng packet buffer
    buf: Vec<u8>,
    /// Current writing file name
    file_info: Option<(PcapFileInfo, usize)>,
}

#[derive(Default)]
struct SimpleWriterProcessor {
    /// Processor ID
    id: ProcessorID,
    /// Actual packet disk position
    packet_pos: Box<Vec<isize>>,
    /// File sequence ID
    file_id: Box<HashSet<u32>>,
    /// Hasher to decide which scheduler to use
    hasher: fnv::FnvHasher,
    /// Current file ID
    fid: u32,
}

impl Clone for SimpleWriterProcessor {
    fn clone(&self) -> Self {
        Self {
            id: self.id,
            packet_pos: Default::default(),
            file_id: Default::default(),
            hasher: fnv::FnvBuildHasher::default().build_hasher(),
            fid: 0,
        }
    }
}

impl Plugin for SimpleWriterProcessor {
    fn plugin_type(&self) -> PluginType {
        PluginType::PacketProcessor
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
        cfg.node = alcfg.node.clone();
        #[cfg(feature = "arkime")]
        {
            cfg.es_host = alcfg.get_str("elasticsearch", "http://localhost:9200");
            cfg.prefix = alcfg.get_str("prefix", "");
        }

        // Prepare global packet write info writer
        let (sender, receiver) = crossbeam_channel::bounded(100000);
        let mut schedulers = vec![];
        for i in 0..alcfg.pkt_threads {
            let mut scheduler = Scheduler::new(i, cfg.node.clone(), sender.clone());
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

        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .thread_name("alphonse-libpcap")
            .enable_all()
            .build()?;
        RT.set(rt)
            .or(Err(anyhow!("simple writer tokio runtime is already set")))?;
        let rt = RT
            .get()
            .ok_or(anyhow!("simple writer tokio runtime is None"))?;

        let cfg = Arc::new(cfg);
        // Initialize pcap file sequence ID number
        #[cfg(feature = "arkime")]
        {
            let cfg = cfg.clone();
            let ts = Transport::single_node(cfg.es_host.as_str())?;
            let es = Arc::new(Elasticsearch::new(ts));
            let id = rt.block_on(async { arkime::get_sequence_number(&es, &cfg).await })?;
            FILE_ID.store(id as u32, Ordering::SeqCst);
        }
        #[cfg(not(feature = "arkime"))]
        {
            let id = get_sequence_number(&es, &cfg)?;
            FILE_ID.store(id as u32, Ordering::SeqCst);
        }

        // Prepare packet info writer and spawn a writer thread
        let recv = receiver.clone();
        let hdl = rt.spawn_blocking(move || main_loop(cfg, recv));
        let handles = vec![hdl];

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

    fn cleanup(&mut self) -> Result<()> {
        // At this moment, all packet process threads are finished, nothing would use SCHEDULERS any more,
        // so cleanup all existing schedulers. Once all the schedulers were dropped, PacketInfo channel
        // would be closed, so the packet writing thread would be closed too.
        let mut schedulers = unsafe { SCHEDULERS.take().ok_or(anyhow!(""))? };
        // TODO: update file info in Elasticsearch
        schedulers.clear();

        let (sender, receiver) = unsafe { CHANNEL.take().ok_or(anyhow!(""))? };
        drop(sender);
        drop(receiver);

        let rt = RT
            .get()
            .ok_or(anyhow!("simple writer tokio runtime is None"))?;
        let handles = unsafe { HANDLES.take().ok_or(anyhow!(""))? };

        rt.block_on(async {
            futures::future::join_all(handles).await;
        });

        Ok(())
    }
}

impl Processor for SimpleWriterProcessor {
    fn clone_processor(&self) -> Box<dyn Processor> {
        Box::new(self.clone())
    }

    fn id(&self) -> ProcessorID {
        self.id
    }

    fn set_id(&mut self, id: ProcessorID) {
        self.id = id
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
        self.hasher = FnvHasher::default();
        let info = schedulers[hash].gen(pkt);
        if schedulers[hash].current_fid() != self.fid {
            self.fid = schedulers[hash].current_fid();
            self.file_id.insert(schedulers[hash].current_fid());
            self.packet_pos
                .push(-(schedulers[hash].current_fid() as isize));
        }
        self.packet_pos
            .push(schedulers[hash].current_pos() as isize);

        schedulers[hash].send(info)?;
        Ok(())
    }

    fn mid_save(&mut self, ses: &mut Session) {
        self.save(ses);
    }

    /// Add packet positions into session after session is about to timeout or closed
    fn save(&mut self, ses: &mut Session) {
        let packet_pos = std::mem::take(&mut self.packet_pos);
        ses.add_field(&"packetPos", json!(packet_pos));

        let file_id = std::mem::take(&mut self.file_id);
        ses.add_field(&"fileId", json!(file_id));
    }
}

#[no_mangle]
pub extern "C" fn al_new_pkt_processor() -> Box<Box<dyn Processor>> {
    Box::new(Box::new(SimpleWriterProcessor::default()))
}

#[no_mangle]
pub extern "C" fn al_plugin_type() -> PluginType {
    PluginType::PacketProcessor
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finish() {
        let mut processor = SimpleWriterProcessor::default();
        processor.packet_pos = Box::new(vec![-1, 1, 2, 3, 4, 5]);

        let mut ses = Session::new();
        processor.save(&mut ses);

        let packet_pos = ses.fields["packetPos"].clone();
        assert!(packet_pos.is_array());
        let packet_pos = packet_pos.as_array().unwrap();
        assert_eq!(packet_pos.len(), 6);
        assert_eq!(packet_pos[0], -1);
        assert_eq!(packet_pos[1], 1);
    }
}
