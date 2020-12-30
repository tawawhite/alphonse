use std::collections::hash_map::HashMap;
use std::os::raw::c_long;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::SystemTime;

use anyhow::Result;
use crossbeam_channel::Receiver;
use fnv::FnvHashMap;

use alphonse_api as api;
use api::classifiers::ClassifierManager;
use api::packet::{Packet, Protocol};
use api::parsers::{ParserID, ProtocolParserTrait};
use api::utils::timeval::TimeVal;

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
        ses_parsers: &mut FnvHashMap<ParserID, Box<dyn ProtocolParserTrait>>,
    ) -> Result<()> {
        self.classifier.classify(pkt, scratch)?;

        for rule in pkt.rules.iter() {
            for parser_id in rule.parsers.iter() {
                match ses_parsers.get_mut(parser_id) {
                    Some(parser) => {
                        parser.parse_pkt(pkt, rule, ses)?;
                    }
                    None => {
                        let mut parser = protocol_parsers
                            .get_mut(*parser_id as usize)
                            .unwrap()
                            .box_clone();
                        parser.parse_pkt(pkt, rule, ses)?;
                        ses_parsers.insert(parser.id(), parser);
                    }
                };
            }
        }

        Ok(())
    }

    /// Check whether a session is timeout
    #[inline]
    fn timeout(
        ts: u64,
        session_table: &mut HashMap<Box<Packet>, Rc<SessionData>>,
        cfg: &Arc<config::Config>,
    ) {
        &mut session_table.retain(|pkt, ses| match pkt.trans_layer.protocol {
            Protocol::TCP => !ses.info.timeout(cfg.tcp_timeout as c_long, ts as c_long),
            Protocol::UDP => !ses.info.timeout(cfg.udp_timeout as c_long, ts as c_long),
            Protocol::SCTP => !ses.info.timeout(cfg.sctp_timeout as c_long, ts as c_long),
            _ => !ses
                .info
                .timeout(cfg.default_timeout as c_long, ts as c_long),
        });
    }

    pub fn spawn(
        &mut self,
        cfg: Arc<config::Config>,
        mut protocol_parsers: Box<Vec<Box<dyn ProtocolParserTrait>>>,
    ) -> Result<()> {
        let mut last_packet_time: u64 = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut last_timeout_check_time: u64 = last_packet_time + cfg.timeout_interval;
        let mut session_table: HashMap<Box<Packet>, Rc<SessionData>> = Default::default();

        println!("session thread {} started", self.id);

        let mut classify_scratch = match self.classifier.alloc_scratch() {
            Ok(scratch) => scratch,
            Err(_) => todo!(),
        };

        while !self.exit.load(Ordering::Relaxed) {
            let mut pkt = match self.receiver.recv() {
                Err(_) => break,
                Ok(p) => p,
            };

            last_packet_time = pkt.ts.tv_sec as u64;

            match session_table.get_mut(&pkt) {
                Some(mut ses) => {
                    match Rc::get_mut(&mut ses) {
                        Some(data) => {
                            data.info.update(&pkt);
                            self.parse_pkt(
                                &mut classify_scratch,
                                &mut protocol_parsers,
                                &mut pkt,
                                data.info.as_mut(),
                                data.parsers.as_mut(),
                            )
                            .unwrap();
                        }
                        None => todo!("handle session rc get_mut None"),
                    };
                }
                None => {
                    let key = pkt.clone();
                    let mut ses_rc = Rc::new(SessionData::new());
                    let data = Rc::get_mut(&mut ses_rc).unwrap();
                    data.info.start_time = TimeVal::new(pkt.ts);
                    data.info.update(&pkt);
                    self.parse_pkt(
                        &mut classify_scratch,
                        &mut protocol_parsers,
                        &mut pkt,
                        data.info.as_mut(),
                        data.parsers.as_mut(),
                    )
                    .unwrap();

                    &mut session_table.insert(key, ses_rc);
                }
            }

            if last_packet_time >= last_timeout_check_time {
                SessionThread::timeout(last_packet_time, &mut session_table, &cfg);
                last_timeout_check_time = last_packet_time;
            }
        }

        println!("session thread {} exit", self.id);
        Ok(())
    }
}
