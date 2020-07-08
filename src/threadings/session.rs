use std::collections::hash_map::HashMap;
use std::os::raw::c_long;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::SystemTime;

use anyhow::Result;
use crossbeam_channel::Receiver;

use super::classifier::ClassifierManager;
use super::config;
use super::packet::{Packet, Protocol};
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

    pub fn spawn(&mut self, cfg: Arc<config::Config>) -> Result<()> {
        let mut session_table: HashMap<Packet, Rc<Session>> = Default::default();
        println!("session thread {} started", self.id);
        let classify_scratch = match self.classifier.alloc_scratch() {
            Ok(scratch) => scratch,
            Err(_) => todo!(),
        };

        let mut timeout_epoch = 0;
        while !self.exit.load(Ordering::Relaxed) {
            match self.receiver.recv() {
                Ok(p) => {
                    let mut protocols = Vec::new();
                    self.classifier
                        .classify(&p, &mut protocols, &classify_scratch)?;

                    match session_table.get_mut(&p) {
                        Some(mut ses) => {
                            match Rc::get_mut(&mut ses) {
                                Some(ses_rc) => {
                                    ses_rc.update(&p);
                                }
                                None => todo!("handle session rc get_mut None"),
                            };
                        }
                        None => {
                            let key = Packet {
                                ts: p.ts,
                                caplen: p.caplen,
                                data: Box::new(p.data.as_ref().clone()),
                                data_link_layer: p.data_link_layer,
                                network_layer: p.network_layer,
                                trans_layer: p.trans_layer,
                                app_layer: p.app_layer,
                                hash: p.hash,
                            };
                            let mut ses = Rc::new(Session::new());
                            let ses_rc = Rc::get_mut(&mut ses).unwrap();
                            ses_rc.start_time = p.ts;
                            ses_rc.update(&p);
                            &mut session_table.insert(key, ses);
                        }
                    }

                    if timeout_epoch == cfg.timeout_pkt_epoch {
                        let timestamp = SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_secs();
                        &mut session_table.retain(|pkt, ses| match pkt.trans_layer.protocol {
                            Protocol::TCP => {
                                ses.timeout(cfg.tcp_timeout as c_long, timestamp as c_long)
                            }
                            Protocol::UDP => {
                                ses.timeout(cfg.udp_timeout as c_long, timestamp as c_long)
                            }
                            Protocol::SCTP => {
                                ses.timeout(cfg.sctp_timeout as c_long, timestamp as c_long)
                            }
                            _ => ses.timeout(cfg.default_timeout as c_long, timestamp as c_long),
                        });
                        timeout_epoch = 0;
                    } else {
                        timeout_epoch += 1;
                    }
                }
                Err(_) => break,
            };
        }

        println!("session thread {} exit", self.id);
        Ok(())
    }
}
