use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::Result;
use crossbeam_channel::Receiver;

use super::config;
use super::sessions::Session;

/// 数据包处理线程
pub struct SessionThread {
    /// 线程ID
    id: u8,
    exit: Arc<AtomicBool>,
    receiver: Receiver<Arc<Session>>,
}

impl SessionThread {
    pub fn new(id: u8, exit: Arc<AtomicBool>, receiver: Receiver<Arc<Session>>) -> SessionThread {
        SessionThread { id, exit, receiver }
    }

    pub fn id(&self) -> u8 {
        self.id
    }

    pub fn spawn(&mut self, _cfg: Arc<config::Config>) -> Result<()> {
        println!("session thread {} started", self.id);

        while !self.exit.load(Ordering::Relaxed) {
            let ses = match self.receiver.recv() {
                Err(_) => break,
                Ok(s) => s,
            };
            println!("{}", serde_json::to_string(ses.as_ref()).unwrap());
        }

        println!("session thread {} exit", self.id);
        Ok(())
    }
}
