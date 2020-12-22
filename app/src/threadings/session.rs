use std::collections::hash_map::HashMap;
use std::os::raw::c_long;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::SystemTime;

use anyhow::Result;
use crossbeam_channel::Receiver;

use alphonse_api as api;
use api::packet::{Packet, Protocol};
use api::{classifiers::ClassifierManager, parsers::ProtocolParserTrait, utils::timeval::TimeVal};

use super::config;
use super::sessions::Session;

/// 数据包处理线程
pub struct SessionThread {
    /// 线程ID
    id: u8,
    exit: Arc<AtomicBool>,
    receiver: Receiver<Box<Packet>>,
    classifier: Arc<ClassifierManager>,
}

impl SessionThread {
    pub fn new(
        id: u8,
        exit: Arc<AtomicBool>,
        receiver: Receiver<Box<Packet>>,
        classifier: Arc<ClassifierManager>,
    ) -> SessionThread {
        SessionThread {
            id,
            exit,
            receiver,
            classifier,
        }
    }

    #[inline]
    fn parse_pkt(
        &self,
        scratch: &mut api::classifiers::ClassifyScratch,
        protocol_parsers: &mut Box<Vec<Box<dyn ProtocolParserTrait>>>,
        pkt: &mut Packet,
        ses: &mut Session,
    ) -> Result<()> {
        self.classifier.classify(pkt, scratch)?;

        for parser_id in pkt.parsers().iter() {
            let parser = &mut protocol_parsers[*parser_id as usize];
            ses.parsers.push(parser.box_clone());
            parser.parse_pkt(pkt, ses)?;
        }

        Ok(())
    }

    /// Check whether a session is timeout
    #[inline]
    pub fn timeout(
        ts: u64,
        session_table: &mut HashMap<Box<Packet>, Rc<Session>>,
        timeout_epoch: &mut u16,
        cfg: &Arc<config::Config>,
    ) {
        if *timeout_epoch == cfg.timeout_pkt_epoch {
            &mut session_table.retain(|pkt, ses| match pkt.trans_layer.protocol {
                Protocol::TCP => !ses.timeout(cfg.tcp_timeout as c_long, ts as c_long),
                Protocol::UDP => !ses.timeout(cfg.udp_timeout as c_long, ts as c_long),
                Protocol::SCTP => !ses.timeout(cfg.sctp_timeout as c_long, ts as c_long),
                _ => !ses.timeout(cfg.default_timeout as c_long, ts as c_long),
            });
            *timeout_epoch = 0;
        } else {
            *timeout_epoch += 1;
        }
    }

    pub fn spawn(
        &mut self,
        cfg: Arc<config::Config>,
        mut protocol_parsers: Box<Vec<Box<dyn ProtocolParserTrait>>>,
    ) -> Result<()> {
        let mut lastPacketTime: u64 = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut session_table: HashMap<Box<Packet>, Rc<Session>> = Default::default();
        println!("session thread {} started", self.id);
        let mut classify_scratch = match self.classifier.alloc_scratch() {
            Ok(scratch) => scratch,
            Err(_) => todo!(),
        };

        let mut timeout_epoch = 0;
        while !self.exit.load(Ordering::Relaxed) {
            match self.receiver.recv() {
                Ok(mut p) => {
                    lastPacketTime = p.ts.tv_sec as u64;
                    match session_table.get_mut(&p) {
                        Some(mut ses) => {
                            match Rc::get_mut(&mut ses) {
                                Some(ses_rc) => {
                                    self.parse_pkt(
                                        &mut classify_scratch,
                                        &mut protocol_parsers,
                                        &mut p,
                                        ses_rc,
                                    )
                                    .unwrap();
                                    ses_rc.update(&p);
                                }
                                None => todo!("handle session rc get_mut None"),
                            };
                        }
                        None => {
                            let key = p.clone();
                            let mut ses = Rc::new(Session::new());
                            let ses_rc = Rc::get_mut(&mut ses).unwrap();
                            ses_rc.start_time = TimeVal::new(p.ts);
                            ses_rc.update(&p);
                            self.parse_pkt(
                                &mut classify_scratch,
                                &mut protocol_parsers,
                                &mut p,
                                ses_rc,
                            )
                            .unwrap();
                            &mut session_table.insert(key, ses);
                        }
                    }

                    SessionThread::timeout(
                        lastPacketTime,
                        &mut session_table,
                        &mut timeout_epoch,
                        &cfg,
                    );
                }
                Err(_) => break,
            };
        }

        println!("session thread {} exit", self.id);
        Ok(())
    }
}
