use anyhow::Result;

use alphonse_api as api;
use api::classifiers::ClassifierManager;

use crate::Misc;

pub fn register_classify_rules(parser: &mut Misc, manager: &mut ClassifierManager) -> Result<()> {
    parser.add_simple_tcp_dpi_rule(r"^\x1b\x25\x2d\x31\x32\x33\x34\x35", "pjl", manager)?;
    parser.add_simple_tcp_dpi_rule(r"^\x40\x50\x4a\x4c\x20", "pjl", manager)
}

#[cfg(test)]
mod test {
    use super::*;
    use api::packet::Protocol;
    use api::plugins::processor::Processor;
    use api::session::Session;

    use crate::test::{assert_has_protocol, Packet};

    #[test]
    fn pjl() {
        let mut manager = ClassifierManager::new();
        let mut parser = Misc::default();
        parser.register_classify_rules(&mut manager).unwrap();
        manager.prepare().unwrap();
        let mut scratch = manager.alloc_scratch().unwrap();

        // pattern 1
        let mut pkt: Box<Packet> = Box::new(Packet::default());
        pkt.raw = Box::new(b"\x1b\x25\x2d\x31\x32\x33\x34\x35".to_vec());
        pkt.layers.trans.protocol = Protocol::TCP;
        let mut pkt: Box<dyn api::packet::Packet> = pkt;
        manager.classify(pkt.as_mut(), &mut scratch).unwrap();
        assert_eq!(pkt.rules().len(), 1);

        let mut ses = Session::new();
        parser
            .parse_pkt(pkt.as_ref(), Some(&pkt.rules()[0]), &mut ses)
            .unwrap();
        assert_has_protocol(&ses, "pjl");

        // pattern 2
        let mut pkt: Box<Packet> = Box::new(Packet::default());
        pkt.raw = Box::new(b"\x40\x50\x4a\x4c\x20".to_vec());
        pkt.layers.trans.protocol = Protocol::TCP;
        let mut pkt: Box<dyn api::packet::Packet> = pkt;
        manager.classify(pkt.as_mut(), &mut scratch).unwrap();
        assert_eq!(pkt.rules().len(), 1);

        let mut ses = Session::new();
        parser
            .parse_pkt(pkt.as_ref(), Some(&pkt.rules()[0]), &mut ses)
            .unwrap();
        assert_has_protocol(&ses, "pjl");
    }
}
