use anyhow::Result;
use fnv::FnvHashMap;
use hyperscan::pattern;

use alphonse_api as api;
use api::classifiers::{dpi, ClassifierManager, Rule, RuleID, RuleType};
use api::packet::Packet;
use api::parsers::ParserID;
use api::session::Session;

use super::MatchCallBack;

pub fn register_classify_rules(
    id: ParserID,
    manager: &mut ClassifierManager,
    match_cbs: &mut FnvHashMap<RuleID, MatchCallBack>,
) -> Result<()> {
    let mut dpi_rule = dpi::Rule::new(pattern! {r"^\*\sOK\s"});
    dpi_rule.protocol = dpi::Protocol::TCP;
    let mut rule = Rule::new(id);
    rule.rule_type = RuleType::DPI(dpi_rule);
    let rule_id = manager.add_rule(&mut rule)?;
    match_cbs.insert(rule_id, MatchCallBack::Func(classify));

    Ok(())
}

fn classify(ses: &mut Session, pkt: &Box<dyn Packet>) {
    match &pkt.payload()[5..].windows(4).position(|win| win == b"IMAP") {
        Some(_) => ses.add_protocol("imap"),
        None => {}
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use api::packet::Protocol;
    use api::session::Session;
    use api::{parsers::ProtocolParserTrait, utils::packet::Packet as TestPacket};

    use crate::ProtocolParser;

    #[test]
    fn imap() {
        let mut manager = ClassifierManager::new();
        let mut parser = ProtocolParser::default();
        parser.register_classify_rules(&mut manager).unwrap();
        manager.prepare().unwrap();
        let mut scratch = manager.alloc_scratch().unwrap();

        let mut pkt: Box<TestPacket> = Box::new(TestPacket::default());
        pkt.raw = Box::new(b"* OK \r\n IMAP".to_vec());
        pkt.layers.trans.protocol = Protocol::TCP;
        let mut pkt: Box<dyn api::packet::Packet> = pkt;
        manager.classify(&mut pkt, &mut scratch).unwrap();
        assert_eq!(pkt.rules().len(), 1);

        let mut ses = Session::new();
        parser.parse_pkt(&pkt, &pkt.rules()[0], &mut ses).unwrap();
        assert!(ses.has_protocol("imap"));
    }
}
