use anyhow::Result;

use alphonse_api as api;
use api::classifiers::ClassifierManager;
use api::packet::Packet;
use api::session::Session;

use super::{add_protocol, Builder, ClassifyFunc};

pub fn register_classify_rules(
    builder: &mut Builder,
    manager: &mut ClassifierManager,
) -> Result<()> {
    let c = Box::new(classify as ClassifyFunc);
    builder.add_udp_dpi_rule_with_func(
        r"^[\x13\x19\x1a\x1b\x1cx21\x23\x24\xd9\xdb\xe3]",
        c.as_ref(),
        manager,
    )
}

fn classify(ses: &mut Session, pkt: &dyn Packet) -> Result<()> {
    if pkt.src_port() != Some(123) && pkt.dst_port() != Some(123) {
        return Ok(());
    }

    if pkt.payload().len() < 48 || pkt.payload()[1] > 16 {
        return Ok(());
    }

    add_protocol(ses, "ntp");
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
    fn ntp() {
        let mut manager = ClassifierManager::new();
        let mut parser = Misc::default();
        parser.register_classify_rules(&mut manager).unwrap();
        manager.prepare().unwrap();
        let mut scratch = manager.alloc_scratch().unwrap();

        // pattern 1
        let mut pkt: Box<Packet> = Box::new(Packet::default());
        pkt.raw = Box::new(vec![
            0x00, 0x7b, 0x00, 0x7b, 0x00, 0x38, 0xf8, 0xd2, 0xd9, 0x00, 0x0a, 0xfa, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x01, 0x02, 0x90, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc5, 0x02, 0x04, 0xec, 0xec, 0x42, 0xee, 0x92,
        ]);
        pkt.layers.trans.protocol = Protocol::UDP;
        pkt.layers.app.offset = 8;
        let mut pkt: Box<dyn api::packet::Packet> = pkt;
        manager.classify(pkt.as_mut(), &mut scratch).unwrap();
        assert_eq!(pkt.rules().len(), 1);

        let mut ses = Session::new();
        for rule in pkt.rules() {
            parser
                .parse_pkt(pkt.as_ref(), Some(rule), &mut ses)
                .unwrap();
        }
        assert_has_protocol(&ses, "ntp");
    }
}
