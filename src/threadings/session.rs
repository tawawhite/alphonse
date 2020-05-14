extern crate crossbeam_channel;

use std::collections::hash_map::{DefaultHasher, HashMap};
use std::hash::{Hash, Hasher};

use crossbeam_channel::Receiver;

use super::packet::Packet;
use super::sessions::Session;

/// 数据包处理线程
pub struct SessionThread {
    /// 线程ID
    id: u8,
    receiver: Box<Receiver<Box<Packet>>>,
    session_table: HashMap<Packet, Session>,
}

impl SessionThread {
    pub fn new(id: u8, receiver: Box<Receiver<Box<Packet>>>) -> SessionThread {
        SessionThread {
            id,
            receiver,
            session_table: HashMap::new(),
        }
    }

    pub fn spawn(&mut self) {
        loop {
            match self.receiver.recv() {
                Ok(p) => match self.session_table.contains_key(&p) {
                    true => {
                        let ses = &mut self.session_table.get_mut(&p);
                        match ses {
                            Some(s) => {
                                s.pkts.push(Box::from(p));
                            }
                            None => {}
                        }
                    }
                    false => {
                        let ses = Session::new();
                        &mut self.session_table.insert(*p, ses);
                    }
                },
                Err(_) => {}
            };
        }
    }
}
