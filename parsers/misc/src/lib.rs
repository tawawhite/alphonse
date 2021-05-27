use anyhow::Result;
use fnv::FnvHashMap;

use alphonse_api as api;
use api::classifiers::{ClassifierManager, RuleID};
use api::packet::Packet;
use api::plugins::processor::{Processor, ProcessorID};
use api::plugins::{Plugin, PluginType};
use api::session::Session;

mod areospike;
mod aruba_papi;
mod bgp;
mod bitcoin;
mod bittorrent;
mod bjnp;
mod cassandra;
mod dcerpc;
mod dropbox;
mod elasticsearch;
mod flap;
mod flash_policy;
mod gh0st;
mod hadoop;
mod hbase;
mod hdfs;
mod honeywell;
mod hsrp;
mod imap;
mod isakmp;
mod jabber;
mod kafka;
mod macros;
mod memcached;
mod mongo;
mod mqtt;
mod netflow;
mod nsclient;
mod ntp;
mod nzsql;
mod other220;
mod pjl;
mod pop3;
mod rdp;
mod redis;
mod rip;
mod rmi;
mod safet;
mod sip;
mod skinny;
mod splunk;
mod ssdp;
mod steam;
mod stun;
mod syslog;
mod tacacs;
mod telnet;
mod thrift;
mod user;
mod vnc;
mod whois;
mod wudo;
mod x11;
mod zabbix;
mod zookeeper;

#[derive(Clone, Default)]
pub struct Misc {
    id: ProcessorID,
    name: String,
    classified: bool,
    match_cbs: FnvHashMap<RuleID, MatchCallBack>,
}

// fn classify_func(ses: &mut Session, payload: &[u8]) {}
type ClassifyFunc = fn(ses: &mut Session, pkt: &dyn Packet);

#[derive(Clone)]
pub enum MatchCallBack {
    Func(ClassifyFunc),
    ProtocolName(String),
    None,
}

impl Plugin for Misc {
    fn plugin_type(&self) -> PluginType {
        PluginType::PacketProcessor
    }

    fn name(&self) -> &str {
        &self.name.as_str()
    }
}

impl Processor for Misc {
    fn clone_processor(&self) -> Box<dyn Processor> {
        Box::new(self.clone())
    }

    /// Get parser id
    fn id(&self) -> ProcessorID {
        self.id
    }

    /// Get parser id
    fn set_id(&mut self, id: ProcessorID) {
        self.id = id
    }

    fn register_classify_rules(&mut self, manager: &mut ClassifierManager) -> Result<()> {
        areospike::register_classify_rules(self, manager)?;
        aruba_papi::register_classify_rules(self, manager)?;
        bgp::register_classify_rules(self, manager)?;
        bittorrent::register_classify_rules(self, manager)?;
        bitcoin::register_classify_rules(self, manager)?;
        bjnp::register_classify_rules(self, manager)?;
        cassandra::register_classify_rules(self, manager)?;
        dcerpc::register_classify_rules(self, manager)?;
        dropbox::register_classify_rules(self, manager)?;
        elasticsearch::register_classify_rules(self, manager)?;
        flash_policy::register_classify_rules(self, manager)?;
        flap::register_classify_rules(self, manager)?;
        gh0st::register_classify_rules(self, manager)?;
        hadoop::register_classify_rules(self, manager)?;
        hbase::register_classify_rules(self, manager)?;
        hdfs::register_classify_rules(self, manager)?;
        honeywell::register_classify_rules(self, manager)?;
        hsrp::register_classify_rules(self, manager)?;
        imap::register_classify_rules(self, manager)?;
        isakmp::register_classify_rules(self, manager)?;
        jabber::register_classify_rules(self, manager)?;
        kafka::register_classify_rules(self, manager)?;
        memcached::register_classify_rules(self, manager)?;
        mongo::register_classify_rules(self, manager)?;
        mqtt::register_classify_rules(self, manager)?;
        netflow::register_classify_rules(self, manager)?;
        nsclient::register_classify_rules(self, manager)?;
        ntp::register_classify_rules(self, manager)?;
        nzsql::register_classify_rules(self, manager)?;
        other220::register_classify_rules(self, manager)?;
        pjl::register_classify_rules(self, manager)?;
        pop3::register_classify_rules(self, manager)?;
        rdp::register_classify_rules(self, manager)?;
        redis::register_classify_rules(self, manager)?;
        rip::register_classify_rules(self, manager)?;
        rmi::register_classify_rules(self, manager)?;
        safet::register_classify_rules(self, manager)?;
        skinny::register_classify_rules(self, manager)?;
        sip::register_classify_rules(self, manager)?;
        splunk::register_classify_rules(self, manager)?;
        ssdp::register_classify_rules(self, manager)?;
        steam::register_classify_rules(self, manager)?;
        stun::register_classify_rules(self, manager)?;
        syslog::register_classify_rules(self, manager)?;
        tacacs::register_classify_rules(self, manager)?;
        telnet::register_classify_rules(self, manager)?;
        thrift::register_classify_rules(self, manager)?;
        user::register_classify_rules(self, manager)?;
        vnc::register_classify_rules(self, manager)?;
        whois::register_classify_rules(self, manager)?;
        wudo::register_classify_rules(self, manager)?;
        x11::register_classify_rules(self, manager)?;
        zabbix::register_classify_rules(self, manager)?;
        zookeeper::register_classify_rules(self, manager)?;

        Ok(())
    }

    fn is_classified(&self) -> bool {
        self.classified
    }

    fn classified_as_this_protocol(&mut self) -> Result<()> {
        self.classified = true;
        Ok(())
    }

    fn parse_pkt(
        &mut self,
        pkt: &dyn api::packet::Packet,
        rule: Option<&api::classifiers::matched::Rule>,
        ses: &mut api::session::Session,
    ) -> Result<()> {
        let rule = match rule {
            None => {
                return Ok(());
            }
            Some(r) => r,
        };
        match self.match_cbs.get(&rule.id()) {
            Some(cb) => match cb {
                MatchCallBack::ProtocolName(protocol) => {
                    ses.add_protocol(protocol);
                }
                MatchCallBack::Func(func) => func(ses, pkt),
                MatchCallBack::None => {}
            },
            None => {
                todo!("handle rule matched, but no callback found")
            }
        };
        Ok(())
    }
}

#[no_mangle]
pub extern "C" fn al_new_pkt_processor() -> Box<Box<dyn Processor>> {
    Box::new(Box::new(Misc::default()))
}

#[no_mangle]
pub extern "C" fn al_plugin_type() -> PluginType {
    PluginType::PacketProcessor
}
