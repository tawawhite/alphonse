use anyhow::Result;

use alphonse_api as api;
use api::classifiers::ClassifierManager;
use api::packet::Packet;
use api::session::Session;

use crate::{add_protocol, Misc};

pub fn register_classify_rules(parser: &mut Misc, manager: &mut ClassifierManager) -> Result<()> {
    parser.add_tcp_dpi_rule_with_func(r"^\x00\x00", classify, manager)
}

fn classify(ses: &mut Session, pkt: &dyn Packet) -> Result<()> {
    let payload = pkt.payload();
    if payload.len() < 10 || payload[4] != 0 || payload[5] > 6 || payload[7] != 0 {
        return Ok(());
    }

    let flen = 4 + ((payload[2] as u16) << 8 | payload[3] as u16) as usize;
    if payload.len() != flen {
        return Ok(());
    }

    add_protocol(ses, "kafka");

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
    fn test() {
        let mut manager = ClassifierManager::new();
        let mut parser = Misc::default();
        parser.register_classify_rules(&mut manager).unwrap();
        manager.prepare().unwrap();
        let mut scratch = manager.alloc_scratch().unwrap();

        let mut pkt: Box<Packet> = Box::new(Packet::default());
        pkt.raw = Box::new(vec![
            0x00, 0x00, 0x00, 0x4b, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x23, 0x69, 0x6e, 0x74, 0x65,
            0x67, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x74, 0x65, 0x73, 0x74, 0x2e, 0x74,
            0x6f, 0x70, 0x69, 0x63, 0x31, 0x34, 0x37, 0x35, 0x30, 0x30, 0x37, 0x30, 0x36, 0x39,
            0x33, 0x35, 0x32, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01,
        ]);
        pkt.layers.trans.protocol = Protocol::TCP;
        let mut pkt: Box<dyn api::packet::Packet> = pkt;
        manager.classify(pkt.as_mut(), &mut scratch).unwrap();
        assert_eq!(pkt.rules().len(), 1);

        let mut ses = Session::new();
        parser
            .parse_pkt(pkt.as_ref(), Some(&pkt.rules()[0]), &mut ses)
            .unwrap();
        assert_has_protocol(&ses, "kafka");
    }
}
