use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::Result;
use crossbeam_channel::Receiver;

use alphonse_api as api;
use api::classifiers::ClassifierManager;
use api::config::Config;
use api::packet::{Packet, PacketHashKey};
use api::plugins::parsers::Processor;
use api::utils::timeval::TimeVal;

use crate::rx::{SessionData, SessionTable};

pub struct PktThread {
    id: u8,
    exit: Arc<AtomicBool>,
    classifier: Arc<ClassifierManager>,
    receiver: Receiver<Box<dyn Packet>>,
}

impl PktThread {
    pub fn new(
        id: u8,
        exit: Arc<AtomicBool>,
        classifier: Arc<ClassifierManager>,
        receiver: Receiver<Box<dyn Packet>>,
    ) -> Self {
        Self {
            id,
            exit,
            classifier,
            receiver,
        }
    }

    pub fn name(&self) -> String {
        format!("alphonse-pkt{}", self.id)
    }

    #[inline]
    fn parse_pkt(
        &self,
        scratch: &mut api::classifiers::ClassifyScratch,
        processors: &mut Box<Vec<Box<dyn Processor>>>,
        pkt: &mut dyn Packet,
        ses_data: &mut SessionData,
    ) -> Result<()> {
        self.classifier.classify(pkt, scratch)?;

        for rule in pkt.rules().iter() {
            for id in rule.processors.iter() {
                match ses_data.processors.get_mut(id) {
                    Some(_) => {}
                    None => {
                        let processor = processors.get_mut(*id as usize).unwrap().box_clone();
                        ses_data.processors.insert(processor.id(), processor);
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
                        processor.parse_pkt(pkt, Some(rule), ses_data.info.as_mut())?;
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

    pub fn spawn(
        &self,
        cfg: Arc<Config>,
        session_table: Arc<SessionTable>,
        mut processors: Box<Vec<Box<dyn Processor>>>,
    ) -> Result<()> {
        let parser = crate::packet::Parser::new(crate::packet::link::ETHERNET);
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

            match parser.parse_pkt(pkt.as_mut()) {
                Ok(_) => {}
                Err(e) => match e {
                    crate::packet::parser::Error::UnsupportProtocol(_) => {}
                    _ => todo!(),
                },
            };

            let key = PacketHashKey::from(pkt.as_ref());
            match session_table.get_mut(&key) {
                Some(mut ses) => {
                    ses.info.update(pkt.as_ref());
                    self.parse_pkt(
                        &mut classify_scratch,
                        &mut processors,
                        pkt.as_mut(),
                        ses.as_mut(),
                    )
                    .unwrap();
                }
                None => {
                    let mut ses = Box::new(SessionData::default());
                    ses.info.start_time = TimeVal::new(*pkt.ts());
                    ses.info.save_time = pkt.ts().tv_sec as u64 + cfg.ses_save_timeout as u64;
                    ses.info.src_direction = pkt.direction();
                    ses.info.update(pkt.as_ref());
                    self.parse_pkt(
                        &mut classify_scratch,
                        &mut processors,
                        pkt.as_mut(),
                        ses.as_mut(),
                    )
                    .unwrap();

                    &mut session_table.insert(key, ses);
                }
            };
        }

        println!("{} exit", self.name());

        Ok(())
    }
}
