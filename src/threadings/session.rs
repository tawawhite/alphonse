use std::collections::hash_map::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::Result;
use crossbeam_channel::Receiver;

use super::packet::{Direction, Packet};
use super::protocol::Classifier;
use super::sessions::Session;

/// 数据包处理线程
pub struct SessionThread {
    /// 线程ID
    id: u8,
    exit: Arc<AtomicBool>,
    receiver: Receiver<Box<Packet>>,
    session_table: HashMap<Packet, Session>,
    classifier: Arc<Classifier>,
}

impl SessionThread {
    pub fn new(
        id: u8,
        exit: Arc<AtomicBool>,
        receiver: Receiver<Box<Packet>>,
        classifier: Arc<Classifier>,
    ) -> SessionThread {
        SessionThread {
            id,
            exit,
            receiver,
            session_table: Default::default(),
            classifier,
        }
    }

    pub fn spawn(&mut self) -> Result<()> {
        println!("session thread {} started", self.id);
        let classify_scratch = match self.classifier.alloc_scratch() {
            Ok(scratch) => scratch,
            Err(_) => todo!(),
        };

        while !self.exit.load(Ordering::Relaxed) {
            match self.receiver.recv() {
                Ok(p) => {
                    let mut protocols = Vec::new();
                    self.classifier
                        .classify(&p, &mut protocols, &classify_scratch)?;

                    match self.session_table.get_mut(&p) {
                        Some(ses) => {
                            ses.pkts.push(p);
                        }
                        None => {
                            let mut ses = Session::new();
                            ses.start_time = p.ts;
                            match p.direction() {
                                Direction::LEFT => {
                                    ses.bytes[0] += p.bytes() as u64;
                                    ses.data_bytes[0] += p.data_bytes() as u64;
                                }
                                Direction::RIGHT => {
                                    ses.bytes[1] += p.bytes() as u64;
                                    ses.data_bytes[1] += p.data_bytes() as u64;
                                }
                            }
                            &mut self.session_table.insert(*p, ses);
                        }
                    }
                }
                Err(_) => break,
            };
        }

        println!("session thread {} exit", self.id);
        Ok(())
    }
}
