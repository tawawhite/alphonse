use anyhow::Result;

use alphonse_api as api;
use api::classifiers::{dpi, ClassifierManager};
use api::packet::Packet;
use api::session::{ProtocolLayer, Session};

use super::{
    add_dpi_rule_with_func, add_dpi_tcp_udp_rule_with_func, add_protocol, MatchCallBack, Misc,
};

pub fn register_classify_rules(parser: &mut Misc, manager: &mut ClassifierManager) -> Result<()> {
    add_dpi_tcp_udp_rule_with_func!(
        r"^(\xc0\x01[\x01\x02])|(\xc0\x02\x01)|(\xc0\x03[\x01\x02])|(\xc1\x01[\x01\x02])",
        classify,
        parser,
        manager
    );

    Ok(())
}

fn classify(ses: &mut Session, pkt: &dyn Packet) -> Result<()> {
    unsafe {
        if pkt.src_port() == 49 || pkt.dst_port() == 49 {
            add_protocol!(ses, "tacacs");
        }
    }

    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    use api::packet::Protocol;
    use api::plugins::processor::Processor;
    use api::session::Session;
    use api::utils::packet::Packet as TestPacket;

    use crate::assert_has_protocol;

    #[test]
    fn tacacs() {
        let mut manager = ClassifierManager::new();
        let mut parser = Misc::default();
        parser.register_classify_rules(&mut manager).unwrap();
        manager.prepare().unwrap();
        let mut scratch = manager.alloc_scratch().unwrap();

        let mut pkt: Box<TestPacket> = Box::new(TestPacket::default());
        pkt.raw = Box::new(vec![
            0xe6, 0xcf, 0x00, 0x31, 0x39, 0x83, 0x1f, 0x05, 0x6d, 0x2e, 0xaf, 0x30, 0x50, 0x10,
            0x10, 0x20, 0x49, 0x93, 0x00, 0x00, 0xc0, 0x01, 0x01,
        ]);
        pkt.layers.trans.protocol = Protocol::TCP;
        pkt.layers.app.offset = 20;
        let mut pkt: Box<dyn api::packet::Packet> = pkt;
        manager.classify(pkt.as_mut(), &mut scratch).unwrap();
        assert_eq!(pkt.rules().len(), 1);

        let mut ses = Session::new();
        parser
            .parse_pkt(pkt.as_ref(), Some(&pkt.rules()[0]), &mut ses)
            .unwrap();
        assert_has_protocol!(ses, "tacacs");
    }
}
