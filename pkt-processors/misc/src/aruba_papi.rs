use anyhow::Result;

use alphonse_api as api;
use api::classifiers::ClassifierManager;
use api::packet::Packet;
use api::session::Session;

use crate::{add_protocol, Builder, ClassifyFunc};

pub fn register_classify_rules(
    builder: &mut Builder,
    manager: &mut ClassifierManager,
) -> Result<()> {
    let c = Box::new(classify as ClassifyFunc);
    builder.add_udp_port_rule_with_func(8211, c.as_ref(), manager)
}

fn classify(ses: &mut Session, pkt: &dyn Packet) -> Result<()> {
    if pkt.payload().len() < 20 {
        return Ok(());
    }
    if pkt.payload()[0] != 0x49 || pkt.payload()[1] != 0x72 {
        return Ok(());
    }

    add_protocol(ses, "aruba-papi");
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
    fn aruba_papi() {
        let mut manager = ClassifierManager::new();
        let mut parser = Misc::default();
        parser.register_classify_rules(&mut manager).unwrap();
        manager.prepare().unwrap();
        let mut scratch = manager.alloc_scratch().unwrap();

        // UDP 500
        let mut pkt: Box<Packet> = Box::new(Packet::default());
        pkt.raw = Box::new(vec![
            0x20, 0x13, 0x20, 0x13, 0x49, 0x72, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]);
        pkt.layers.trans.protocol = Protocol::UDP;
        pkt.layers.app.offset = 4;
        pkt.caplen = pkt.raw.len() as u32;
        let mut pkt: Box<dyn api::packet::Packet> = pkt;
        manager.classify(pkt.as_mut(), &mut scratch).unwrap();
        assert!(pkt.rules().len() > 0);

        let mut ses = Session::new();
        parser
            .parse_pkt(pkt.as_ref(), Some(&pkt.rules()[0]), &mut ses)
            .unwrap();
        assert_has_protocol(&ses, "aruba-papi");
    }
}
