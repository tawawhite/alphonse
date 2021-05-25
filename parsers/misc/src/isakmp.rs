use anyhow::Result;

use alphonse_api as api;
use api::classifiers::ClassifierManager;
use api::packet::{Packet, Protocol};
use api::session::Session;

use crate::{add_port_rule_with_func, MatchCallBack, Misc};

pub fn register_classify_rules(parser: &mut Misc, manager: &mut ClassifierManager) -> Result<()> {
    add_port_rule_with_func!(500, classify, Protocol::UDP, parser, manager);
    add_port_rule_with_func!(4500, classify, Protocol::UDP, parser, manager);

    Ok(())
}

fn classify(ses: &mut Session, pkt: &dyn Packet) {
    if pkt.data_len() < 18 {
        return;
    }
    if pkt.payload()[16] != 1
        && pkt.payload()[16] != 8
        && pkt.payload()[16] != 33
        && pkt.payload()[16] != 46
    {
        return;
    }

    if pkt.payload()[17] != 0x10 && pkt.payload()[17] != 0x20 && pkt.payload()[17] != 0x02 {
        return;
    }

    ses.add_protocol(&"isakmp");
}

#[cfg(test)]
mod test {
    use super::*;
    use api::packet::Protocol;
    use api::plugins::parsers::Processor;
    use api::session::Session;
    use api::utils::packet::Packet as TestPacket;

    use crate::Misc;

    #[test]
    fn isakmp() {
        let mut manager = ClassifierManager::new();
        let mut parser = Misc::default();
        parser.register_classify_rules(&mut manager).unwrap();
        manager.prepare().unwrap();
        let mut scratch = manager.alloc_scratch().unwrap();

        // UDP 500
        let mut pkt: Box<TestPacket> = Box::new(TestPacket::default());
        pkt.raw = Box::new(vec![
            0x01, 0xf4, 0x01, 0xf4, 0xe4, 0x7a, 0x59, 0x1f, 0xd0, 0x57, 0x58, 0x7f, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x10, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]);
        pkt.layers.trans.protocol = Protocol::UDP;
        pkt.layers.app.offset = 4;
        pkt.caplen = pkt.raw.len() as u32;
        let mut pkt: Box<dyn api::packet::Packet> = pkt;
        manager.classify(pkt.as_mut(), &mut scratch).unwrap();
        assert!(pkt.rules().len() > 0);

        let mut ses = Session::new();
        for rule in pkt.rules() {
            println!("{:?}", rule);
            parser
                .parse_pkt(pkt.as_ref(), Some(rule), &mut ses)
                .unwrap();
        }
        assert!(ses.has_protocol(&"isakmp"));

        // UDP 4500
        let mut pkt: Box<TestPacket> = Box::new(TestPacket::default());
        pkt.raw = Box::new(vec![
            0x11, 0x94, 0x11, 0x94, 0xe4, 0x7a, 0x59, 0x1f, 0xd0, 0x57, 0x58, 0x7f, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x10, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]);
        pkt.layers.trans.protocol = Protocol::UDP;
        pkt.layers.app.offset = 4;
        pkt.caplen = pkt.raw.len() as u32;
        let mut pkt: Box<dyn api::packet::Packet> = pkt;
        manager.classify(pkt.as_mut(), &mut scratch).unwrap();
        assert!(pkt.rules().len() > 0);

        let mut ses = Session::new();
        for rule in pkt.rules() {
            parser
                .parse_pkt(pkt.as_ref(), Some(rule), &mut ses)
                .unwrap();
        }
        assert!(ses.has_protocol(&"isakmp"));
    }
}
