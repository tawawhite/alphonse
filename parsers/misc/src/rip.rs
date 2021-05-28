use anyhow::Result;

use alphonse_api as api;
use api::classifiers::{dpi, ClassifierManager};
use api::packet::Packet;
use api::session::{ProtocolLayer, Session};

use crate::{
    add_dpi_rule_with_func, add_dpi_udp_rule_with_func, add_protocol, MatchCallBack, Misc,
};

pub fn register_classify_rules(parser: &mut Misc, manager: &mut ClassifierManager) -> Result<()> {
    add_dpi_udp_rule_with_func!(r"^[\x01\x02]{2}\x00\x00", classify, parser, manager);

    Ok(())
}

fn classify(ses: &mut Session, pkt: &dyn Packet) -> Result<()> {
    unsafe {
        if pkt.src_port() == 520 || pkt.dst_port() == 520 {
            add_protocol!(ses, "rip");
        }
    }

    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    use api::packet::Protocol;
    use api::plugins::processor::Processor;
    use api::utils::packet::Packet as TestPacket;

    use crate::assert_has_protocol;

    #[test]
    fn rip() {
        let mut manager = ClassifierManager::new();
        let mut parser = Misc::default();
        parser.register_classify_rules(&mut manager).unwrap();
        manager.prepare().unwrap();
        let mut scratch = manager.alloc_scratch().unwrap();

        // \x01\x01\x00\x00
        let mut pkt: Box<TestPacket> = Box::new(TestPacket::default());
        pkt.raw = Box::new(b"\x00\x00\x02\x08\x01\x01\x00\x00".to_vec());
        pkt.layers.trans.protocol = Protocol::UDP;
        pkt.layers.app.offset = 4;
        let mut pkt: Box<dyn api::packet::Packet> = pkt;
        manager.classify(pkt.as_mut(), &mut scratch).unwrap();
        assert!(pkt.rules().len() > 1);

        let mut ses = Session::new();
        for rule in pkt.rules() {
            parser
                .parse_pkt(pkt.as_ref(), Some(rule), &mut ses)
                .unwrap();
        }
        assert_has_protocol!(ses, "rip");

        // \x01\x02\x00\x00
        let mut pkt: Box<TestPacket> = Box::new(TestPacket::default());
        pkt.raw = Box::new(b"\x00\x00\x02\x08\x01\x01\x00\x00".to_vec());
        pkt.layers.trans.protocol = Protocol::UDP;
        pkt.layers.app.offset = 4;
        let mut pkt: Box<dyn api::packet::Packet> = pkt;
        manager.classify(pkt.as_mut(), &mut scratch).unwrap();
        assert!(pkt.rules().len() > 1);

        let mut ses = Session::new();
        for rule in pkt.rules() {
            parser
                .parse_pkt(pkt.as_ref(), Some(rule), &mut ses)
                .unwrap();
        }
        assert_has_protocol!(ses, "rip");

        // \x02\x01\x00\x00
        let mut pkt: Box<TestPacket> = Box::new(TestPacket::default());
        pkt.raw = Box::new(b"\x00\x00\x02\x08\x01\x01\x00\x00".to_vec());
        pkt.layers.trans.protocol = Protocol::UDP;
        pkt.layers.app.offset = 4;
        let mut pkt: Box<dyn api::packet::Packet> = pkt;
        manager.classify(pkt.as_mut(), &mut scratch).unwrap();
        assert!(pkt.rules().len() > 1);

        let mut ses = Session::new();
        for rule in pkt.rules() {
            parser
                .parse_pkt(pkt.as_ref(), Some(rule), &mut ses)
                .unwrap();
        }
        assert_has_protocol!(ses, "rip");

        // \x02\x02\x00\x00
        let mut pkt: Box<TestPacket> = Box::new(TestPacket::default());
        pkt.raw = Box::new(b"\x00\x00\x02\x08\x01\x01\x00\x00".to_vec());
        pkt.layers.trans.protocol = Protocol::UDP;
        pkt.layers.app.offset = 4;
        let mut pkt: Box<dyn api::packet::Packet> = pkt;
        manager.classify(pkt.as_mut(), &mut scratch).unwrap();
        assert!(pkt.rules().len() > 1);

        let mut ses = Session::new();
        for rule in pkt.rules() {
            parser
                .parse_pkt(pkt.as_ref(), Some(rule), &mut ses)
                .unwrap();
        }
        assert_has_protocol!(ses, "rip");
    }
}
