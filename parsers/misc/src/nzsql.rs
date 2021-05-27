use anyhow::Result;

use alphonse_api as api;
use api::classifiers::{dpi, ClassifierManager};

use crate::{add_simple_dpi_rule, add_simple_dpi_tcp_rule, MatchCallBack, Misc};

pub fn register_classify_rules(parser: &mut Misc, manager: &mut ClassifierManager) -> Result<()> {
    add_simple_dpi_tcp_rule!(
        r"^\x00\x00\x00\x08\x00\x01\x00\x03",
        "nzsql",
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
    fn nzsql() {
        let mut manager = ClassifierManager::new();
        let mut parser = Misc::default();
        parser.register_classify_rules(&mut manager).unwrap();
        manager.prepare().unwrap();
        let mut scratch = manager.alloc_scratch().unwrap();

        // \x00\x00\x00\x08\x00\x01\x00\x03
        let mut pkt: Box<TestPacket> = Box::new(TestPacket::default());
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
        assert!(ses.has_protocol(&"nzsql"));
    }
}
