use std::num::NonZeroUsize;
use std::os::raw::c_long;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::Result;
use crossbeam_channel::{Receiver, Sender};
use fnv::{FnvBuildHasher, FnvHashMap};
use serde_json::json;

use alphonse_api as api;
use api::classifiers::ClassifierManager;
use api::config::Config;
use api::packet::Protocol;
use api::packet::{Packet, PacketHashKey};
use api::plugins::processor::{Builder, Processor, ProcessorID};
use api::session::Session;
use api::session::TimeVal;

pub struct SessionData {
    pub info: Box<Session>,
    pub processors: Box<FnvHashMap<ProcessorID, Box<dyn Processor>>>,
}

impl Default for SessionData {
    fn default() -> SessionData {
        SessionData {
            // Here we use Session::new(), since default() doesn't generate the struct we need
            info: Box::new(Session::new()),
            processors: Box::new(FnvHashMap::default()),
        }
    }
}

/// All the possible session timeout reasons
#[derive(Debug)]
enum ExpireReason {
    Timeout,
    TooMuchPackets,
    SessionIdleTooLong,
}

/// Thread local session table, only used by one single pkt process thread
struct SessionTable {
    raw: FnvHashMap<PacketHashKey, Box<SessionData>>,
    lru: clru::CLruCache<PacketHashKey, (), FnvBuildHasher>,
}

impl SessionTable {
    fn with_capacity(capacity: NonZeroUsize) -> Self {
        Self {
            raw: FnvHashMap::with_capacity_and_hasher(capacity.get(), FnvBuildHasher::default()),
            lru: clru::CLruCache::with_hasher(capacity, FnvBuildHasher::default()),
        }
    }

    fn get_mut(&mut self, key: &PacketHashKey) -> Option<&mut Box<SessionData>> {
        match self.lru.get(&key) {
            None => None,
            Some(_) => self.raw.get_mut(key),
        }
    }

    fn insert(&mut self, key: PacketHashKey, ses: Box<SessionData>) {
        self.lru.put(key.clone(), ());
        self.raw.insert(key, ses);
    }

    fn expire(&mut self, cfg: &Config, now: u64) -> Option<(ExpireReason, Box<SessionData>)> {
        // get least updated session's mut ref
        let key = match self.lru.back() {
            None => return None,
            Some((key, _)) => key,
        };
        let ses = match self.raw.get_mut(key) {
            None => unreachable!("Key founded in lru but not in hashmap, should never happens"),
            Some(ses) => ses,
        };

        let reason = if ses.info.idle_too_long(now) {
            Some(ExpireReason::SessionIdleTooLong)
        } else if ses.info.too_much_packets(cfg.ses_max_packets as u32) {
            Some(ExpireReason::TooMuchPackets)
        } else {
            let timeout = match key.trans_proto {
                Protocol::TCP => ses.info.timeout(cfg.tcp_timeout as c_long, now as c_long),
                Protocol::UDP => ses.info.timeout(cfg.udp_timeout as c_long, now as c_long),
                Protocol::SCTP => ses.info.timeout(cfg.sctp_timeout as c_long, now as c_long),
                _ => ses
                    .info
                    .timeout(cfg.default_timeout as c_long, now as c_long),
            };
            if timeout {
                Some(ExpireReason::Timeout)
            } else {
                None
            }
        };

        match reason {
            None => None,
            Some(r) => {
                let key = match self.lru.pop_back() {
                    None => unreachable!("Here lru always pops out a value"),
                    Some((key, _)) => key,
                };
                let ses = match self.raw.remove(&key) {
                    None => unreachable!("Here hashmap always return Some"),
                    Some(ses) => ses,
                };
                Some((r, ses))
            }
        }
    }
}

pub struct PktThread {
    pub id: u8,
    exit: Arc<AtomicBool>,
    classifier: Arc<ClassifierManager>,
    receiver: Receiver<Box<dyn Packet>>,
    senders: Vec<Sender<Arc<Box<Session>>>>,
    session_table: SessionTable,
}

impl PktThread {
    pub fn new(
        id: u8,
        exit: Arc<AtomicBool>,
        classifier: Arc<ClassifierManager>,
        receiver: Receiver<Box<dyn Packet>>,
        senders: Vec<Sender<Arc<Box<Session>>>>,
        session_table_size: NonZeroUsize,
    ) -> Self {
        Self {
            id,
            exit,
            classifier,
            receiver,
            senders,
            session_table: SessionTable::with_capacity(session_table_size),
        }
    }

    pub fn name(&self) -> String {
        format!("alphonse-pkt{}", self.id)
    }

    pub fn spawn(&mut self, cfg: Arc<Config>, builders: Vec<Arc<dyn Builder>>) -> Result<()> {
        let builders = builders.iter().map(|b| b.as_ref()).collect::<Vec<_>>();
        let mut classify_scratch = match self.classifier.alloc_scratch() {
            Ok(scratch) => scratch,
            Err(_) => todo!(),
        };
        println!("{} started", self.name());

        while !self.exit.load(Ordering::Relaxed) {
            let mut pkt = match self.receiver.recv() {
                Err(_) => {
                    self.exit.store(true, Ordering::SeqCst);
                    break;
                }
                Ok(s) => s,
            };
            let now = pkt.ts().tv_sec as u64;

            self.classifier
                .classify(pkt.as_mut(), &mut classify_scratch)?;

            let key = PacketHashKey::from(pkt.as_ref());

            match self.session_table.expire(&cfg, now) {
                None => {}
                Some((reason, mut ses)) => match reason {
                    ExpireReason::SessionIdleTooLong | ExpireReason::TooMuchPackets => {
                        for (_, processor) in ses.processors.iter_mut() {
                            processor.mid_save(ses.info.as_mut());
                        }
                        let mut info_new = Box::new(Session::new());
                        info_new.src_direction = ses.info.src_direction;
                        info_new.start_time = ses.info.start_time.clone();
                        info_new.save_time = ses.info.save_time + cfg.ses_save_timeout as u64;
                        let info = Arc::new(std::mem::replace(&mut ses.info, info_new));
                        for sender in &self.senders {
                            sender.try_send(info.clone()).unwrap();
                        }
                        ses.info.mid_save_reset(now + cfg.ses_save_timeout as u64);
                        self.session_table.insert(key.clone(), ses);
                    }
                    ExpireReason::Timeout => {
                        for (_, processor) in ses.processors.iter_mut() {
                            processor.save(ses.info.as_mut());
                        }
                        let info =
                            Arc::new(std::mem::replace(&mut ses.info, Box::new(Session::new())));
                        for sender in &self.senders {
                            sender.try_send(info.clone()).unwrap();
                        }
                    }
                },
            };

            match self.session_table.get_mut(&key) {
                Some(ses) => {
                    ses.info.update(pkt.as_ref());
                    parse_pkt(&cfg, &builders, pkt.as_mut(), ses.as_mut())?;

                    continue;
                }
                None => {}
            };

            let mut ses = Box::new(SessionData::default());
            ses.info.start_time = TimeVal::new(*pkt.ts());
            ses.info.timestamp = TimeVal::new(*pkt.ts());
            ses.info.save_time = pkt.ts().tv_sec as u64 + cfg.ses_save_timeout as u64;
            ses.info.src_direction = pkt.direction();
            ses.info.add_field(&"node", json!(cfg.node));
            ses.info.update(pkt.as_ref());
            parse_pkt(&cfg, &builders, pkt.as_mut(), ses.as_mut())?;

            self.session_table.insert(key, ses);
        }

        println!("{} exit", self.name());

        Ok(())
    }
}

#[inline]
fn parse_pkt(
    cfg: &Config,
    builders: &[&dyn Builder],
    pkt: &mut dyn Packet,
    ses_data: &mut SessionData,
) -> Result<()> {
    for rule in pkt.rules().iter() {
        for id in rule.processors.iter() {
            match ses_data.processors.get_mut(id) {
                Some(_) => {}
                None => {
                    let builder = &builders[*id as usize];
                    let processor = builders[*id as usize].build(&cfg);
                    ses_data.processors.insert(builder.id(), processor);
                }
            };
        }
    }

    for (_, processor) in ses_data.processors.iter_mut() {
        let mut matched = false;
        for rule in pkt.rules().iter() {
            // If processor has bind a rule this packet matches, parse with this rule
            // otherwise this pkt just belongs to the same session, parse without rule information
            for id in rule.processors.iter() {
                if *id == processor.id() {
                    match processor.parse_pkt(pkt, Some(rule), ses_data.info.as_mut()) {
                        Ok(_) => {}
                        Err(e) => {
                            eprintln!("{}: {}", processor.name(), e);
                            return Err(e);
                        }
                    };
                    matched = true;
                }
            }
        }

        if !matched {
            processor.parse_pkt(pkt, None, ses_data.info.as_mut())?;
        }
    }

    Ok(())
}
