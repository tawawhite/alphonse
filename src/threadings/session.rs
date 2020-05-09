extern crate crossbeam_channel;

use std::hash::{Hash, Hasher};

use crossbeam_channel::Receiver;

use super::packet::Packet;

/// 数据包处理线程
pub struct SessionThread {
    /// 线程ID
    id: u8,
    receiver: Box<Receiver<Packet>>,
    hasher: std::collections::hash_map::DefaultHasher,
}

impl SessionThread {
    pub fn new(id: u8, receiver: Box<Receiver<Packet>>) -> SessionThread {
        SessionThread {
            id,
            receiver,
            hasher: std::collections::hash_map::DefaultHasher::new(),
        }
    }

    pub fn spawn(&mut self) {
        loop {
            match self.receiver.recv() {
                Ok(p) => {
                    p.hash(&mut self.hasher);
                    println!("pkt hash: {}", self.hasher.finish());
                }
                Err(_) => {}
            };
        }
    }
}
