use anyhow::Result;

use alphonse_api as api;
use api::classifiers::ClassifierManager;
use api::packet::Packet;
use api::session::Session;

use crate::{add_protocol, ClassifyFunc, Misc};

pub fn register_classify_rules(parser: &mut Misc, manager: &mut ClassifierManager) -> Result<()> {
    let c = Box::new(classify as ClassifyFunc);
    parser.add_udp_port_rule_with_func(500, c.as_ref(), manager)?;
    parser.add_udp_port_rule_with_func(4500, c.as_ref(), manager)
}

fn classify(ses: &mut Session, pkt: &dyn Packet) -> Result<()> {
    if pkt.data_len() < 18 {
        return Ok(());
    }

    if pkt.payload()[16] != 1
        && pkt.payload()[16] != 8
        && pkt.payload()[16] != 33
        && pkt.payload()[16] != 46
    {
        return Ok(());
    }

    if pkt.payload()[17] != 0x10 && pkt.payload()[17] != 0x20 && pkt.payload()[17] != 0x02 {
        return Ok(());
    }

    add_protocol(ses, "isakmp");

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
    fn isakmp() {
        let mut manager = ClassifierManager::new();
        let mut parser = Misc::default();
        parser.register_classify_rules(&mut manager).unwrap();
        manager.prepare().unwrap();
        let mut scratch = manager.alloc_scratch().unwrap();

        // UDP 500
        let mut pkt: Box<Packet> = Box::new(Packet::default());
        pkt.raw = Box::new(vec![
            0x01, 0xf4, 0x01, 0xf4, 0xe4, 0x7a, 0x59, 0x1f, 0xd0, 0x57, 0x58, 0x7f, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x10, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]);
        pkt.layers.trans.protocol = Protocol::UDP;
        pkt.layers.app.offset = 4;
        pkt.caplen = pkt.raw.len() as u32;
        let mut pkt: Box<dyn api::packet::Packet> = pkt;
        manager.classify(pkt.as_mut(), &mut scratch).unwrap();
        assert!(pkt.rules().len() > 0);

        let mut ses = Session::new();
        for rule in pkt.rules() {
            println!("{:?}", rule);
            parser
                .parse_pkt(pkt.as_ref(), Some(rule), &mut ses)
                .unwrap();
        }
        assert_has_protocol(&ses, "isakmp");

        // UDP 4500
        let mut pkt: Box<Packet> = Box::new(Packet::default());
        pkt.raw = Box::new(vec![
            0x11, 0x94, 0x11, 0x94, 0xe4, 0x7a, 0x59, 0x1f, 0xd0, 0x57, 0x58, 0x7f, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x10, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]);
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
        assert_has_protocol(&ses, "isakmp");
    }
}
