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
    builder.add_udp_dpi_rule_with_func(r"^.host_int", c.as_ref(), manager)
}

fn classify(ses: &mut Session, pkt: &dyn Packet) -> Result<()> {
    if pkt.src_port() == Some(17500) || pkt.dst_port() == Some(17500) {
        add_protocol(ses, "dropbox-lan-sync");
    }
    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    use api::packet::Protocol;
    use api::plugins::processor::Processor;

    use crate::test::{assert_has_protocol, Packet};

    #[test]
    fn test() {
        let mut manager = ClassifierManager::new();
        let mut parser = Misc::default();
        parser.register_classify_rules(&mut manager).unwrap();
        manager.prepare().unwrap();
        let mut scratch = manager.alloc_scratch().unwrap();

        let mut pkt: Box<Packet> = Box::new(Packet::default());
        pkt.raw = Box::new(vec![
            0x44, 0x5c, 0x00, 0x31, 0x39, 0x83, 0x1f, 0x05, 0x6d, 0x2e, 0xaf, 0x30, 0x50, 0x10,
            0x10, 0x20, 0x49, 0x93, 0x00, 0x00, 0x20, 0x68, 0x6f, 0x73, 0x74, 0x5f, 0x69, 0x6e,
            0x74,
        ]);
        pkt.layers.trans.protocol = Protocol::UDP;
        pkt.layers.app.offset = 20;
        let mut pkt: Box<dyn api::packet::Packet> = pkt;
        manager.classify(pkt.as_mut(), &mut scratch).unwrap();
        assert_eq!(pkt.rules().len(), 1);

        let mut ses = Session::new();
        parser
            .parse_pkt(pkt.as_ref(), Some(&pkt.rules()[0]), &mut ses)
            .unwrap();
        assert_has_protocol(&ses, "dropbox-lan-sync");
    }
}
