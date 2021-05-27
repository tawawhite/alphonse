use anyhow::Result;

use alphonse_api as api;
use api::classifiers::{dpi, ClassifierManager};

use crate::{
    add_simple_dpi_rule, add_simple_dpi_tcp_udp_rule, add_simple_dpi_udp_rule, MatchCallBack, Misc,
};

pub fn register_classify_rules(parser: &mut Misc, manager: &mut ClassifierManager) -> Result<()> {
    add_simple_dpi_tcp_udp_rule!(r"^RSP/...STUN", "stun", parser, manager);

    add_simple_dpi_udp_rule!(
        r"^((\x00\x01)|(\x0\x03)|(\x01\x01))\x00",
        "stun",
        parser,
        manager
    );

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
    fn stun() {
        let mut manager = ClassifierManager::new();
        let mut parser = Misc::default();
        parser.register_classify_rules(&mut manager).unwrap();
        manager.prepare().unwrap();
        let mut scratch = manager.alloc_scratch().unwrap();

        // rule 1
        let mut pkt: Box<TestPacket> = Box::new(TestPacket::default());
        pkt.raw = Box::new(b"RSP/   STUN".to_vec());
        pkt.layers.trans.protocol = Protocol::TCP;
        let mut pkt: Box<dyn api::packet::Packet> = pkt;
        manager.classify(pkt.as_mut(), &mut scratch).unwrap();
        assert_eq!(pkt.rules().len(), 1);

        let mut ses = Session::new();
        parser
            .parse_pkt(pkt.as_ref(), Some(&pkt.rules()[0]), &mut ses)
            .unwrap();
        assert!(ses.has_protocol(&"stun"));

        // rule 2 pattern 1
        let mut pkt: Box<TestPacket> = Box::new(TestPacket::default());
        pkt.raw = Box::new(b"\x00\x01\x00".to_vec());
        pkt.layers.trans.protocol = Protocol::UDP;
        let mut pkt: Box<dyn api::packet::Packet> = pkt;
        manager.classify(pkt.as_mut(), &mut scratch).unwrap();
        assert_eq!(pkt.rules().len(), 1);

        let mut ses = Session::new();
        parser
            .parse_pkt(pkt.as_ref(), Some(&pkt.rules()[0]), &mut ses)
            .unwrap();
        assert!(ses.has_protocol(&"stun"));

        // rule 2 pattern 2
        let mut pkt: Box<TestPacket> = Box::new(TestPacket::default());
        pkt.raw = Box::new(b"\x00\x03\x00".to_vec());
        pkt.layers.trans.protocol = Protocol::UDP;
        let mut pkt: Box<dyn api::packet::Packet> = pkt;
        manager.classify(pkt.as_mut(), &mut scratch).unwrap();
        assert_eq!(pkt.rules().len(), 1);

        let mut ses = Session::new();
        parser
            .parse_pkt(pkt.as_ref(), Some(&pkt.rules()[0]), &mut ses)
            .unwrap();
        assert!(ses.has_protocol(&"stun"));

        // rule 2 pattern 3
        let mut pkt: Box<TestPacket> = Box::new(TestPacket::default());
        pkt.raw = Box::new(b"\x01\x01\x00".to_vec());
        pkt.layers.trans.protocol = Protocol::UDP;
        let mut pkt: Box<dyn api::packet::Packet> = pkt;
        manager.classify(pkt.as_mut(), &mut scratch).unwrap();
        assert_eq!(pkt.rules().len(), 1);

        let mut ses = Session::new();
        parser
            .parse_pkt(pkt.as_ref(), Some(&pkt.rules()[0]), &mut ses)
            .unwrap();
        assert!(ses.has_protocol(&"stun"));
    }
}
