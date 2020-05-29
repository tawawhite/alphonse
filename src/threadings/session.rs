use std::collections::hash_map::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

extern crate crossbeam_channel;

use crossbeam_channel::Receiver;

use super::packet::Packet;
use super::sessions::Session;

/// 数据包处理线程
pub struct SessionThread {
    /// 线程ID
    id: u8,
    exit: Arc<AtomicBool>,
    receiver: Receiver<Box<Packet>>,
    session_table: HashMap<Packet, Session>,
}

impl SessionThread {
    pub fn new(id: u8, exit: Arc<AtomicBool>, receiver: Receiver<Box<Packet>>) -> SessionThread {
        SessionThread {
            id,
            exit,
            receiver,
            session_table: HashMap::new(),
        }
    }

    pub fn spawn(&mut self) {
        while !self.exit.load(Ordering::Relaxed) {
            match self.receiver.recv() {
                Ok(p) => match self.session_table.contains_key(&p) {
                    true => match self.session_table.get_mut(&p) {
                        Some(ses) => {
                            ses.pkts.push(p);
                        }
                        None => {}
                    },
                    false => {
                        let mut ses = Session::new();
                        ses.start_time = p.ts;
                        &mut self.session_table.insert(*p, ses);
                    }
                },
                Err(_) => break,
            };
        }
    }
}
