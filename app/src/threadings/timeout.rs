use std::os::raw::c_long;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::SystemTime;

use anyhow::Result;
use crossbeam_channel::Sender;
use dashmap::DashMap;
use fnv::{FnvBuildHasher, FnvHashMap};
use rayon::iter::{ParallelBridge, ParallelIterator};

use alphonse_api as api;
use api::config::Config;
use api::packet::{PacketHashKey, Protocol};
use api::plugins::processor::{Processor, ProcessorID};
use api::session::Session;

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

pub type SessionTable = DashMap<PacketHashKey, Box<SessionData>, FnvBuildHasher>;

/// Session table timeout thread
pub struct TimeoutThread {
    id: u8,
    exit: Arc<AtomicBool>,
    senders: Vec<Sender<Box<Session>>>,
    session_table: Arc<SessionTable>,
}

impl TimeoutThread {
    pub fn new(
        id: u8,
        exit: Arc<AtomicBool>,
        senders: Vec<Sender<Box<Session>>>,
        session_table: Arc<SessionTable>,
    ) -> Self {
        Self {
            id,
            exit,
            senders,
            session_table,
        }
    }

    pub fn name(&self) -> String {
        format!("alphonse-timeout{}", self.id)
    }

    pub fn spawn(&self, cfg: Arc<Config>) -> Result<()> {
        let now: u64 = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut next_timeout_check_time: u64 = now + cfg.timeout_interval;
        println!("{} started", self.name());

        while !self.exit.load(Ordering::Relaxed) {
            let now: u64 = SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            if now <= next_timeout_check_time {
                continue;
            }

            next_timeout_check_time = now + cfg.timeout_interval;
            self.session_table
                .shards()
                .iter()
                .par_bridge()
                .for_each(|shard| {
                    shard.write().retain(|key, ses| {
                        let ses = ses.get_mut();
                        let timeout = match key.trans_proto {
                            Protocol::TCP => {
                                ses.info.timeout(cfg.tcp_timeout as c_long, now as c_long)
                            }
                            Protocol::UDP => {
                                ses.info.timeout(cfg.udp_timeout as c_long, now as c_long)
                            }
                            Protocol::SCTP => {
                                ses.info.timeout(cfg.sctp_timeout as c_long, now as c_long)
                            }
                            _ => ses
                                .info
                                .timeout(cfg.default_timeout as c_long, now as c_long),
                        };

                        if ses.info.need_mid_save(cfg.ses_max_packets as u32, now) {
                            for (_, processor) in ses.processors.iter_mut() {
                                processor.mid_save(ses.info.as_mut());
                            }
                            for sender in &self.senders {
                                sender.try_send(ses.info.clone()).unwrap();
                            }
                            ses.info.mid_save_reset(now + cfg.ses_save_timeout as u64);
                        } else if timeout {
                            for (_, processor) in ses.processors.iter_mut() {
                                processor.save(ses.info.as_mut());
                            }
                            for sender in &self.senders {
                                sender.try_send(ses.info.clone()).unwrap();
                            }
                        }
                        !timeout
                    })
                });
        }

        self.session_table
            .shards()
            .iter()
            .par_bridge()
            .for_each(|shard| {
                shard.write().retain(|_, ses| {
                    let ses = ses.get_mut();
                    for (_, processor) in ses.processors.iter_mut() {
                        processor.save(ses.info.as_mut());
                    }
                    for sender in &self.senders {
                        sender.try_send(ses.info.clone()).unwrap();
                    }
                    false
                })
            });

        println!("{} exit", self.name());

        Ok(())
    }
}
