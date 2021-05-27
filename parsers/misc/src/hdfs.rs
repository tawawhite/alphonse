use anyhow::Result;

use alphonse_api as api;
use api::classifiers::{dpi, ClassifierManager};
use api::packet::Packet;
use api::session::Session;

use super::{add_dpi_rule_with_func, add_dpi_tcp_rule_with_func, MatchCallBack, Misc};

pub fn register_classify_rules(parser: &mut Misc, manager: &mut ClassifierManager) -> Result<()> {
    add_dpi_tcp_rule_with_func!(r"^\x00\x1c[\x50\x51\x55]", classify, parser, manager);
    Ok(())
}

fn classify(ses: &mut Session, pkt: &dyn Packet) {
    if pkt.payload().len() < 10 || pkt.payload()[5] != 0xa {
        return;
    }

    ses.add_protocol(&"hdfs");
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
    fn netflow() {
        let mut manager = ClassifierManager::new();
        let mut parser = Misc::default();
        parser.register_classify_rules(&mut manager).unwrap();
        manager.prepare().unwrap();
        let mut scratch = manager.alloc_scratch().unwrap();

        let mut pkt: Box<TestPacket> = Box::new(TestPacket::default());
        pkt.raw = Box::new(b"\x00\x1c\x50\x00\x00\x0a\x00\x00\x00\x00".to_vec());
        pkt.layers.trans.protocol = Protocol::TCP;
        let mut pkt: Box<dyn api::packet::Packet> = pkt;
        manager.classify(pkt.as_mut(), &mut scratch).unwrap();
        assert!(pkt.rules().len() > 0);

        let mut ses = Session::new();
        for rule in pkt.rules() {
            parser
                .parse_pkt(pkt.as_ref(), Some(rule), &mut ses)
                .unwrap();
        }
        assert!(ses.has_protocol(&"hdfs"));
    }
}
