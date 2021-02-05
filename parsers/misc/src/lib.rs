use anyhow::Result;
use fnv::FnvHashMap;

use alphonse_api as api;
use api::classifiers::{ClassifierManager, RuleID};
use api::packet::Packet;
use api::parsers::ParserID;
use api::parsers::ProtocolParserTrait;
use api::session::Session;

mod bitcoin;
mod bittorrent;
mod gh0st;
mod imap;
mod jabber;
mod mongo;
mod other220;
mod pop3;
mod rdp;
mod redis;
mod sip;
mod vnc;

#[derive(Clone, Default)]
struct ProtocolParser {
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
        bittorrent::register_classify_rules(self.id, manager, &mut self.match_cbs)?;
        bitcoin::register_classify_rules(self.id, manager, &mut self.match_cbs)?;
        gh0st::register_classify_rules(self.id, manager, &mut self.match_cbs)?;
        imap::register_classify_rules(self.id, manager, &mut self.match_cbs)?;
        jabber::register_classify_rules(self.id, manager, &mut self.match_cbs)?;
        mongo::register_classify_rules(self.id, manager, &mut self.match_cbs)?;
        other220::register_classify_rules(self.id, manager, &mut self.match_cbs)?;
        pop3::register_classify_rules(self.id, manager, &mut self.match_cbs)?;
        rdp::register_classify_rules(self.id, manager, &mut self.match_cbs)?;
        redis::register_classify_rules(self.id, manager, &mut self.match_cbs)?;
        sip::register_classify_rules(self.id, manager, &mut self.match_cbs)?;
        vnc::register_classify_rules(self.id, manager, &mut self.match_cbs)?;

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
            },
            None => {
                todo!("handle rule matched, but no callback found")
            }
        };
        Ok(())
    }
}
