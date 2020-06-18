use std::iter::FromIterator;

use anyhow::Result;
use hyperscan::{BlockDatabase, Builder};

use super::packet;
use super::Protocol;

/// Protocol Classifier
pub struct Classifier {
    protocol_table: Box<Vec<Protocol>>,

    all_pkt_protocols: Box<Vec<u8>>,

    tcp_port_protocols: Box<Vec<Vec<u8>>>,
    udp_port_protocols: Box<Vec<Vec<u8>>>,
    sctp_port_protocols: Box<Vec<Vec<u8>>>,

    dpi_rules: Box<Vec<hyperscan::Pattern>>,

    hs_db: Option<BlockDatabase>,
}

/// Protocol classifier scratch
///
/// Must not be shared across threads
pub struct ClassifyScratch {
    hs_scratch: Option<hyperscan::Scratch>,
}

impl Classifier {
    pub fn new() -> Classifier {
        fn initialize_vec_of_vec(size: usize) -> Vec<Vec<u8>> {
            let mut v: Vec<Vec<u8>> = Vec::with_capacity(size);
            for _ in 0..size {
                v.push(Vec::new());
            }
            v
        }

        Classifier {
            protocol_table: Box::new(Vec::with_capacity(256)),
            all_pkt_protocols: Box::new(Vec::new()),
            tcp_port_protocols: Box::new(initialize_vec_of_vec(65536)),
            udp_port_protocols: Box::new(initialize_vec_of_vec(65536)),
            sctp_port_protocols: Box::new(initialize_vec_of_vec(65536)),
            dpi_rules: Box::new(Vec::new()),
            hs_db: None,
        }
    }

    /// Allocate a protocol classifier scratch
    pub fn alloc_scratch(&self) -> Result<ClassifyScratch> {
        let scratch;
        match &self.hs_db {
            Some(db) => scratch = Some(db.alloc_scratch()?),
            None => scratch = None,
        };
        Ok(ClassifyScratch {
            hs_scratch: scratch,
        })
    }

    pub fn add_all_pkt_rule(&mut self, protocol_id: u8) {
        self.all_pkt_protocols.push(protocol_id);
    }

    /// Add port classify rule for a protocol
    pub fn add_port_rule(&mut self, protocol_id: u8, src_port: u16, trans_proto: packet::Protocol) {
        match trans_proto {
            packet::Protocol::TCP => match (*self.tcp_port_protocols).get_mut(src_port as usize) {
                Some(vec) => vec.push(protocol_id),
                None => unimplemented!(),
            },
            packet::Protocol::UDP => match (*self.udp_port_protocols).get_mut(src_port as usize) {
                Some(vec) => vec.push(protocol_id),
                None => unimplemented!(),
            },
            packet::Protocol::SCTP => {
                match (*self.sctp_port_protocols).get_mut(src_port as usize) {
                    Some(vec) => vec.push(protocol_id),
                    None => unimplemented!(),
                }
            }
            _ => unimplemented!(),
        };
    }

    pub fn add_dpi_rule(&mut self, rule: hyperscan::Pattern) {
        self.dpi_rules.push(rule);
    }

    pub fn prepare(&mut self) {
        if self.dpi_rules.len() == 0 {
            self.hs_db = None
        } else {
            let patterns = hyperscan::Patterns::from_iter(self.dpi_rules.clone().into_iter());
            self.hs_db = Some(patterns.build().unwrap());
        }
    }

    /// Classify protocol
    #[inline]
    pub fn classify(
        &self,
        pkt: &packet::Packet,
        protocols: &mut Vec<u8>,
        scratch: &ClassifyScratch,
    ) -> Result<()> {
        match (&self.hs_db, &scratch.hs_scratch) {
            (Some(db), Some(s)) => Ok(db.scan(
                &pkt.data.as_slice()[pkt.app_layer.offset as usize..],
                s,
                |id, from, to, _flags| {
                    println!("found pattern #{} @ [{}, {})", id, from, to);
                    protocols.push(id as u8);
                    hyperscan::Matching::Continue
                },
            )?),
            _ => Ok(()),
        }
    }
}
