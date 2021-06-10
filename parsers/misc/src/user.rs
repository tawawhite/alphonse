use anyhow::Result;

use alphonse_api as api;
use api::classifiers::{dpi, ClassifierManager, Rule, RuleType};
use api::packet::Packet;
use api::session::Session;

use crate::{
    add_dpi_rule_with_func, add_dpi_tcp_rule_with_func, add_none_dpi_rule, add_none_dpi_tcp_rule,
    MatchCallBack, Misc,
};

pub fn register_classify_rules(parser: &mut Misc, manager: &mut ClassifierManager) -> Result<()> {
    let user_pattern_id = add_none_dpi_tcp_rule!(r"^USER\s", parser, manager);
    let irc_pattern_id = add_none_dpi_tcp_rule!(r"((\sNICK)|(\+iw))", parser, manager);
    let com_pattern = hyperscan::Pattern {
        expression: format!("{}&!{}", user_pattern_id, irc_pattern_id),
        flags: hyperscan::PatternFlags::COMBINATION,
        id: None,
        ext: hyperscan::ExprExt::default(),
        som: None,
    };
    add_dpi_tcp_rule_with_func!(com_pattern, classify, parser, manager);

    Ok(())
}

fn classify(ses: &mut Session, pkt: &dyn Packet) -> Result<()> {
    let payload = pkt.payload();
    if payload.len() <= 5 {
        return Ok(());
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
    ses.add_field(&"user", serde_json::json!(user));
    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    use api::packet::Protocol;
    use api::plugins::processor::Processor;
    use api::session::Session;
    use api::utils::packet::Packet as TestPacket;

    use crate::Misc;

    #[test]
    fn user() {
        let mut manager = ClassifierManager::new();
        let mut parser = Misc::default();
        parser.register_classify_rules(&mut manager).unwrap();
        manager.prepare().unwrap();
        let mut scratch = manager.alloc_scratch().unwrap();

        // Windows branch 1
        let mut pkt: Box<TestPacket> = Box::new(TestPacket::default());
        pkt.raw = Box::new(b"USER test_user".to_vec());
        pkt.layers.trans.protocol = Protocol::TCP;
        let mut pkt: Box<dyn api::packet::Packet> = pkt;
        manager.classify(pkt.as_mut(), &mut scratch).unwrap();
        assert_eq!(pkt.rules().len(), 2);

        let mut ses = Session::new();
        for rule in pkt.rules() {
            parser
                .parse_pkt(pkt.as_ref(), Some(rule), &mut ses)
                .unwrap();
        }
        assert_eq!("\"test_user\"", ses.fields["user"].to_string());
    }
}
