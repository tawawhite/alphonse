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
    // TODO: test whether using this huge bounded repeat is bad for performance
    let mut dpi_rule = dpi::Rule::new(pattern! {r"^[\x13\x19\x1a\x1b\x1cx21\x23\x24\xd9\xdb\xe3]"});
    dpi_rule.protocol = dpi::Protocol::UDP;
    let mut rule = Rule::new(id);
    rule.rule_type = RuleType::DPI(dpi_rule);
    let rule_id = manager.add_rule(&mut rule)?;
    match_cbs.insert(rule_id, MatchCallBack::Func(classify));

    Ok(())
}

fn classify(ses: &mut Session, pkt: &Box<dyn Packet>) {
    unsafe {
        println!("{} {}", pkt.src_port(), pkt.dst_port());
        if pkt.src_port() != 123 && pkt.dst_port() != 123 {
            return;
        }
    }

    if pkt.payload().len() < 48 || pkt.payload()[1] > 16 {
        return;
    }

    ses.add_protocol("ntp");
}

#[cfg(test)]
mod test {
    use super::*;
    use api::packet::Protocol;
    use api::session::Session;
    use api::{parsers::ProtocolParserTrait, utils::packet::Packet as TestPacket};

    use crate::ProtocolParser;

    #[test]
    fn areospike() {
        let mut manager = ClassifierManager::new();
        let mut parser = ProtocolParser::default();
        parser.register_classify_rules(&mut manager).unwrap();
        manager.prepare().unwrap();
        let mut scratch = manager.alloc_scratch().unwrap();

        // pattern 1
        let mut pkt: Box<TestPacket> = Box::new(TestPacket::default());
        pkt.raw = Box::new(vec![
            0x00, 0x7b, 0x00, 0x7b, 0x00, 0x38, 0xf8, 0xd2, 0xd9, 0x00, 0x0a, 0xfa, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x01, 0x02, 0x90, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc5, 0x02, 0x04, 0xec, 0xec, 0x42, 0xee, 0x92,
        ]);
        pkt.layers.trans.protocol = Protocol::UDP;
        pkt.layers.app.offset = 8;
        let mut pkt: Box<dyn api::packet::Packet> = pkt;
        manager.classify(&mut pkt, &mut scratch).unwrap();
        assert_eq!(pkt.rules().len(), 1);

        let mut ses = Session::new();
        for rule in pkt.rules() {
            parser.parse_pkt(&pkt, rule, &mut ses).unwrap();
        }
        assert!(ses.has_protocol("ntp"));
    }
}
