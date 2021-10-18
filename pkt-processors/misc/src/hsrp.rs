use anyhow::Result;

use alphonse_api as api;
use api::classifiers::ClassifierManager;
use api::packet::Packet;
use api::session::Session;

use crate::{add_protocol, ClassifyFunc, Misc};

pub fn register_classify_rules(parser: &mut Misc, manager: &mut ClassifierManager) -> Result<()> {
    let c = Box::new(classify as ClassifyFunc);
    parser.add_udp_port_rule_with_func(1985, c.as_ref(), manager)?;
    parser.add_udp_port_rule_with_func(2029, c.as_ref(), manager)
}

fn classify(ses: &mut Session, pkt: &dyn Packet) -> Result<()> {
    if pkt.src_port() != pkt.dst_port() || pkt.payload().len() < 3 {
        return Ok(());
    }
    if pkt.payload()[..2] == [0, 3] {
        add_protocol(ses, "hsrp");
    } else if pkt.payload()[..3] == [1, 40, 2] {
        add_protocol(ses, "hsrpv2");
    }
    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    use api::packet::Protocol;
    use api::plugins::processor::Processor;
    use api::session::Session;

    use crate::test::{assert_has_protocol, Packet};

    #[test]
    fn skinny() {
        let mut manager = ClassifierManager::new();
        let mut parser = Misc::default();
        parser.register_classify_rules(&mut manager).unwrap();
        manager.prepare().unwrap();
        let mut scratch = manager.alloc_scratch().unwrap();

        // hsrp on port 1985
        let mut pkt: Box<Packet> = Box::new(Packet::default());
        pkt.raw = Box::new(vec![0x07, 0xc1, 0x07, 0xc1, 0x00, 0x03, 0x00]);
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
        assert_has_protocol(&ses, "hsrp");

        // hsrp on port 2029
        let mut pkt: Box<Packet> = Box::new(Packet::default());
        pkt.raw = Box::new(vec![0x07, 0xed, 0x07, 0xed, 0x01, 40, 0x02]);
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
        assert_has_protocol(&ses, "hsrpv2");
    }
}
