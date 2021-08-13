use anyhow::Result;

use alphonse_api as api;
use api::classifiers::ClassifierManager;

use crate::Misc;

pub fn register_classify_rules(parser: &mut Misc, manager: &mut ClassifierManager) -> Result<()> {
    parser.add_simple_tcp_dpi_rule(r"^\x00\x00\x00\x08\x00\x01\x00\x03", "nzsql", manager)
}

#[cfg(test)]
mod test {
    use super::*;
    use api::packet::Protocol;
    use api::plugins::processor::Processor;
    use api::session::Session;

    use crate::test::{assert_has_protocol, Packet};

    #[test]
    fn nzsql() {
        let mut manager = ClassifierManager::new();
        let mut parser = Misc::default();
        parser.register_classify_rules(&mut manager).unwrap();
        manager.prepare().unwrap();
        let mut scratch = manager.alloc_scratch().unwrap();

        // \x00\x00\x00\x08\x00\x01\x00\x03
        let mut pkt: Box<Packet> = Box::new(Packet::default());
        pkt.raw = Box::new(b"\x00\x00\x00\x08\x00\x01\x00\x03".to_vec());
        pkt.layers.trans.protocol = Protocol::TCP;
        let mut pkt: Box<dyn api::packet::Packet> = pkt;
        manager.classify(pkt.as_mut(), &mut scratch).unwrap();
        assert!(pkt.rules().len() > 1);

        let mut ses = Session::new();
        for rule in pkt.rules() {
            parser
                .parse_pkt(pkt.as_ref(), Some(rule), &mut ses)
                .unwrap();
        }
        assert_has_protocol(&ses, "nzsql");
    }
}
