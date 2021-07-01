//! Skinny Client Control Protocol, in arkime it is called sccp.
//! However there is another protocol named 'Signalling Connection Control Part',
//! which is a network layer protocol could also be called 'sccp'.
//! So to distinguish between these two protocols, we call this skinny.

use anyhow::Result;

use alphonse_api as api;
use api::classifiers::ClassifierManager;
use api::packet::{Packet, Protocol};
use api::session::{ProtocolLayer, Session};

use crate::{add_port_rule_with_func, add_protocol, MatchCallBack, Misc};

pub fn register_classify_rules(parser: &mut Misc, manager: &mut ClassifierManager) -> Result<()> {
    add_port_rule_with_func!(2000, classify, Protocol::TCP, parser, manager);

    Ok(())
}

fn classify(ses: &mut Session, pkt: &dyn Packet) -> Result<()> {
    let len = (pkt.payload()[0] as u32)
        | (pkt.payload()[1] as u32) << 8
        | (pkt.payload()[2] as u32) << 16
        | (pkt.payload()[3] as u32) << 24;
    if pkt.payload().len() < len as usize || pkt.payload().len() < 9 {
        return Ok(());
    }

    if pkt.payload()[4..8] != [0; 4] {
        return Ok(());
    }

    add_protocol!(ses, "skinny");
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
    fn skinny() {
        let mut manager = ClassifierManager::new();
        let mut parser = Misc::default();
        parser.register_classify_rules(&mut manager).unwrap();
        manager.prepare().unwrap();
        let mut scratch = manager.alloc_scratch().unwrap();

        // UDP 500
        let mut pkt: Box<TestPacket> = Box::new(TestPacket::default());
        pkt.raw = Box::new(vec![
            0x07, 0xd0, 0xc5, 0x28, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x01,
            0x00, 0x00, 0x0d, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x58, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ]);
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
        assert_has_protocol!(ses, "skinny");
    }
}
