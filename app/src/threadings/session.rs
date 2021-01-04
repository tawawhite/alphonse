use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::Result;
use crossbeam_channel::Receiver;
use fnv::FnvHashMap;

use alphonse_api as api;
use api::classifiers::ClassifierManager;
use api::packet::Packet;
use api::parsers::{ParserID, ProtocolParserTrait};

use super::config;
use super::sessions::Session;

/// Data structure to store session info and session's protocol parsers
struct SessionData {
    info: Box<Session>,
    parsers: Box<FnvHashMap<ParserID, Box<dyn ProtocolParserTrait>>>,
}

impl SessionData {
    fn new() -> Self {
        SessionData {
            info: Box::new(Session::new()),
            parsers: Box::new(FnvHashMap::default()),
        }
    }
}

/// 数据包处理线程
pub struct SessionThread {
    /// 线程ID
    id: u8,
    exit: Arc<AtomicBool>,
    receiver: Receiver<Box<dyn Packet>>,
}

impl SessionThread {
    pub fn new(
        id: u8,
        exit: Arc<AtomicBool>,
        receiver: Receiver<Box<dyn Packet>>,
    ) -> SessionThread {
        SessionThread { id, exit, receiver }
    }

    pub fn id(&self) -> u8 {
        self.id
    }

    pub fn spawn(&mut self, cfg: Arc<config::Config>) -> Result<()> {
        println!("session thread {} started", self.id);

        while !self.exit.load(Ordering::Relaxed) {
            let mut pkt = match self.receiver.recv() {
                Err(_) => break,
                Ok(p) => p,
            };
        }

        println!("session thread {} exit", self.id);
        Ok(())
    }
}
