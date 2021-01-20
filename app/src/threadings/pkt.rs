use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::Result;
use crossbeam_channel::{Receiver, Sender};
use fnv::FnvHasher;

use alphonse_api as api;
use api::packet::{Packet, PacketHashKey};

pub struct PktThread {
    id: u8,
    exit: Arc<AtomicBool>,
    receiver: Receiver<Box<dyn Packet>>,
    senders: Vec<Sender<Box<dyn Packet>>>,
}

impl PktThread {
    pub fn new(
        id: u8,
        exit: Arc<AtomicBool>,
        receiver: Receiver<Box<dyn Packet>>,
        senders: &Vec<Sender<Box<dyn Packet>>>,
    ) -> Self {
        Self {
            id,
            exit,
            receiver,
            senders: senders.iter().map(|s| s.clone()).collect(),
        }
    }

    pub fn name(&self) -> String {
        format!("alphonse-pkt{}", self.id)
    }

    pub fn spawn(&self) -> Result<()> {
        let parser = crate::packet::Parser::new(crate::packet::link::ETHERNET);
        let sender_cnt = self.senders.len() as u64;

        println!("{} started", self.name());

        while !self.exit.load(Ordering::Relaxed) {
            let mut pkt = match self.receiver.recv() {
                Err(_) => break,
                Ok(s) => s,
            };

            match parser.parse_pkt(pkt.as_mut()) {
                Ok(_) => {}
                Err(e) => match e {
                    crate::packet::parser::Error::UnsupportProtocol(_) => {}
                    _ => todo!(),
                },
            };

            let key = PacketHashKey::from(pkt.as_ref());
            let mut hasher = FnvHasher::default();
            key.hash(&mut hasher);
            let thread = (hasher.finish() % sender_cnt) as usize;

            match self.senders[thread].try_send(pkt) {
                Ok(_) => {}
                Err(err) => match err {
                    crossbeam_channel::TrySendError::Full(_) => {}
                    crossbeam_channel::TrySendError::Disconnected(_) => {}
                },
            };
        }

        println!("{} exit", self.name());

        Ok(())
    }
}
