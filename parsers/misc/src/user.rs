use anyhow::Result;
use fnv::FnvHashMap;

use alphonse_api as api;
use api::classifiers::{dpi, ClassifierManager, Rule, RuleID, RuleType};
use api::packet::Packet;
use api::parsers::ParserID;
use api::session::Session;
use hyperscan::pattern;

use super::MatchCallBack;

pub fn register_classify_rules(
    id: ParserID,
    manager: &mut ClassifierManager,
    match_cbs: &mut FnvHashMap<RuleID, MatchCallBack>,
) -> Result<()> {
    let mut dpi_rule = dpi::Rule::new(pattern! {r"^USER\s"});
    dpi_rule.protocol = dpi::Protocol::TCP;
    let mut rule = Rule::new(id);
    rule.rule_type = RuleType::DPI(dpi_rule);
    let rule_id = manager.add_rule(&mut rule)?;
    match_cbs.insert(rule_id, MatchCallBack::None);
    let user_pattern_id = match &manager.get_rule(rule_id).unwrap().rule_type {
        RuleType::DPI(rule) => rule.hs_pattern.id.unwrap(),
        _ => unreachable!(),
    };

    let mut dpi_rule = dpi::Rule::new(pattern! {r"((\sNICK)|(\+iw))"});
    dpi_rule.protocol = dpi::Protocol::TCP;
    let mut rule = Rule::new(id);
    rule.rule_type = RuleType::DPI(dpi_rule);
    let rule_id = manager.add_rule(&mut rule)?;
    match_cbs.insert(rule_id, MatchCallBack::None);
    let irc_pattern_id = match &manager.get_rule(rule_id).unwrap().rule_type {
        RuleType::DPI(rule) => rule.hs_pattern.id.unwrap(),
        _ => unreachable!(),
    };

    let com_pattern = hyperscan::Pattern {
        expression: format!("{}&!{}", user_pattern_id, irc_pattern_id),
        flags: hyperscan::PatternFlags::COMBINATION,
        id: None,
        ext: hyperscan::ExprExt::default(),
        som: None,
    };
    let mut dpi_rule = dpi::Rule::new(com_pattern);
    dpi_rule.protocol = dpi::Protocol::TCP;
    let mut rule = Rule::new(id);
    rule.rule_type = RuleType::DPI(dpi_rule);
    let rule_id = manager.add_rule(&mut rule)?;
    match_cbs.insert(rule_id, MatchCallBack::Func(classify));

    Ok(())
}

fn classify(ses: &mut Session, pkt: &Box<dyn Packet>) {
    let payload = pkt.payload();
    if payload.len() <= 5 {
        return;
    }

    let user =
        match pkt.payload()[5..]
            .iter()
            .position(|i| match unsafe { libc::isspace(*i as i32) } {
                0 => false,
                _ => true,
            }) {
            Some(i) => {
                let user = pkt.payload()[i..].to_ascii_lowercase();
                String::from_utf8_lossy(&user).to_string()
            }
            None => {
                let user = pkt.payload()[5..].to_ascii_lowercase();
                String::from_utf8_lossy(&user).to_string()
            }
        };
    ses.add_field(&"user", &serde_json::json!(user));
}

#[cfg(test)]
mod test {
    use super::*;
    use api::packet::Protocol;
    use api::session::Session;
    use api::{parsers::ProtocolParserTrait, utils::packet::Packet as TestPacket};

    use crate::ProtocolParser;

    #[test]
    fn user() {
        let mut manager = ClassifierManager::new();
        let mut parser = ProtocolParser::default();
        parser.register_classify_rules(&mut manager).unwrap();
        manager.prepare().unwrap();
        let mut scratch = manager.alloc_scratch().unwrap();

        // Windows branch 1
        let mut pkt: Box<TestPacket> = Box::new(TestPacket::default());
        pkt.raw = Box::new(b"USER test_user".to_vec());
        pkt.layers.trans.protocol = Protocol::TCP;
        let mut pkt: Box<dyn api::packet::Packet> = pkt;
        manager.classify(&mut pkt, &mut scratch).unwrap();
        assert_eq!(pkt.rules().len(), 2);

        let mut ses = Session::new();
        for i in 0..pkt.rules().len() {
            parser.parse_pkt(&pkt, &pkt.rules()[i], &mut ses).unwrap();
        }
        assert_eq!("\"test_user\"", ses.fields["user"].to_string());
    }
}
