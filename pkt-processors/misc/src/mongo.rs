use anyhow::Result;

use alphonse_api as api;
use api::classifiers::ClassifierManager;

use crate::Misc;

pub fn register_classify_rules(parser: &mut Misc, manager: &mut ClassifierManager) -> Result<()> {
    parser.add_simple_tcp_dpi_rule(r"^.{8}[\x00\xff]{4}\xd4\x07\x00\x00", "mongo", manager)
}

#[cfg(test)]
mod test {
    use super::*;
    use api::packet::Protocol;
    use api::plugins::processor::Processor;
    use api::session::Session;

    use crate::test::{assert_has_protocol, Packet};

    #[test]
    fn mongo() {
        let mut manager = ClassifierManager::new();
        let mut parser = Misc::default();
        parser.register_classify_rules(&mut manager).unwrap();
        manager.prepare().unwrap();
        let mut scratch = manager.alloc_scratch().unwrap();

        // \x00{4}
        let mut pkt: Box<Packet> = Box::new(Packet::default());
        pkt.raw = Box::new(b"12345678\x00\x00\x00\x00\xd4\x07\x00\x00".to_vec());
        pkt.layers.trans.protocol = Protocol::TCP;
        let mut pkt: Box<dyn api::packet::Packet> = pkt;
        manager.classify(pkt.as_mut(), &mut scratch).unwrap();
        assert_eq!(pkt.rules().len(), 1);

        let mut ses = Session::new();
        parser
            .parse_pkt(pkt.as_ref(), Some(&pkt.rules()[0]), &mut ses)
            .unwrap();
        assert_has_protocol(&ses, "mongo");

        // \xff{4}
        let mut pkt: Box<Packet> = Box::new(Packet::default());
        pkt.raw = Box::new(b"12345678\xff\xff\xff\xff\xd4\x07\x00\x00".to_vec());
        pkt.layers.trans.protocol = Protocol::TCP;
        let mut pkt: Box<dyn api::packet::Packet> = pkt;
        manager.classify(pkt.as_mut(), &mut scratch).unwrap();
        assert_eq!(pkt.rules().len(), 1);

        let mut ses = Session::new();
        parser
            .parse_pkt(pkt.as_ref(), Some(&pkt.rules()[0]), &mut ses)
            .unwrap();
        assert_has_protocol(&ses, "mongo");
    }
}
