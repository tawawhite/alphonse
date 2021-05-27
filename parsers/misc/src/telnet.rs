use anyhow::Result;

use alphonse_api as api;
use api::classifiers::ClassifierManager;
use api::packet::{Packet, Protocol};
use api::session::Session;

use crate::{add_port_rule_with_func, add_tcp_port_rule_with_func, MatchCallBack, Misc};

pub fn register_classify_rules(parser: &mut Misc, manager: &mut ClassifierManager) -> Result<()> {
    add_tcp_port_rule_with_func!(23, classify, parser, manager);
    Ok(())
}

fn classify(ses: &mut Session, pkt: &dyn Packet) {
    if pkt.payload().len() < 3 || pkt.payload()[0] != 0xff || pkt.payload()[1] < 0xfa {
        return;
    }

    ses.add_protocol(&"telnet");
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
    fn telnet() {
        let mut manager = ClassifierManager::new();
        let mut parser = Misc::default();
        parser.register_classify_rules(&mut manager).unwrap();
        manager.prepare().unwrap();
        let mut scratch = manager.alloc_scratch().unwrap();

        let mut pkt: Box<TestPacket> = Box::new(TestPacket::default());
        pkt.raw = Box::new(vec![0x00, 0x17, 0, 0, 0xff, 0xff, 0]);
        pkt.layers.trans.protocol = Protocol::TCP;
        pkt.layers.app.offset = 4;
        pkt.caplen = pkt.raw.len() as u32;
        let mut pkt: Box<dyn api::packet::Packet> = pkt;
        manager.classify(pkt.as_mut(), &mut scratch).unwrap();
        assert!(pkt.rules().len() > 0);

        let mut ses = Session::new();
        parser
            .parse_pkt(pkt.as_ref(), Some(&pkt.rules()[0]), &mut ses)
            .unwrap();
        assert!(ses.has_protocol(&"telnet"));
    }
}
