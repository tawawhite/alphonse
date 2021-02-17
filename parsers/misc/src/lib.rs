use anyhow::Result;
use fnv::FnvHashMap;

use alphonse_api as api;
use api::classifiers::{ClassifierManager, RuleID};
use api::packet::Packet;
use api::parsers::ParserID;
use api::parsers::ProtocolParserTrait;
use api::session::Session;

mod areospike;
mod bitcoin;
mod bittorrent;
mod bjnp;
mod cassandra;
mod flap;
mod gh0st;
mod imap;
mod jabber;
mod macros;
mod mongo;
mod ntp;
mod other220;
mod pop3;
mod rdp;
mod redis;
mod sip;
mod stun;
mod syslog;
mod thrift;
mod user;
mod vnc;

#[derive(Clone, Default)]
pub struct ProtocolParser {
    id: ParserID,
    name: String,
    classified: bool,
    match_cbs: FnvHashMap<RuleID, MatchCallBack>,
}

// fn classify_func(ses: &mut Session, payload: &[u8]) {}
type ClassifyFunc = fn(ses: &mut Session, pkt: &Box<dyn Packet>);

#[derive(Clone)]
pub enum MatchCallBack {
    Func(ClassifyFunc),
    ProtocolName(String),
    None,
}

impl ProtocolParserTrait for ProtocolParser {
    fn box_clone(&self) -> Box<dyn api::parsers::ProtocolParserTrait> {
        Box::new(self.clone())
    }

    /// Get parser id
    fn id(&self) -> ParserID {
        self.id
    }

    /// Get parser id
    fn set_id(&mut self, id: ParserID) {
        self.id = id
    }

    /// Get parser name
    fn name(&self) -> &str {
        &self.name.as_str()
    }

    fn register_classify_rules(&mut self, manager: &mut ClassifierManager) -> Result<()> {
        areospike::register_classify_rules(self, manager)?;
        bittorrent::register_classify_rules(self, manager)?;
        bitcoin::register_classify_rules(self, manager)?;
        bjnp::register_classify_rules(self, manager)?;
        cassandra::register_classify_rules(self, manager)?;
        flap::register_classify_rules(self, manager)?;
        gh0st::register_classify_rules(self, manager)?;
        imap::register_classify_rules(self, manager)?;
        jabber::register_classify_rules(self, manager)?;
        mongo::register_classify_rules(self, manager)?;
        ntp::register_classify_rules(self, manager)?;
        other220::register_classify_rules(self, manager)?;
        pop3::register_classify_rules(self, manager)?;
        rdp::register_classify_rules(self, manager)?;
        redis::register_classify_rules(self, manager)?;
        sip::register_classify_rules(self, manager)?;
        stun::register_classify_rules(self, manager)?;
        syslog::register_classify_rules(self, manager)?;
        thrift::register_classify_rules(self, manager)?;
        user::register_classify_rules(self, manager)?;
        vnc::register_classify_rules(self, manager)?;

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
        pkt: &Box<dyn api::packet::Packet>,
        rule: &api::classifiers::matched::Rule,
        ses: &mut api::session::Session,
    ) -> Result<()> {
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
pub extern "C" fn al_new_protocol_parser() -> Box<Box<dyn api::parsers::ProtocolParserTrait>> {
    Box::new(Box::new(ProtocolParser::default()))
}
