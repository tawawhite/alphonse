use anyhow::Result;

use alphonse_api as api;
use api::classifiers::ClassifierManager;
use api::packet::Packet;
use api::session::Session;

use super::{add_protocol, ClassifyFunc, Misc};

pub fn register_classify_rules(parser: &mut Misc, manager: &mut ClassifierManager) -> Result<()> {
    let c = Box::new(classify as ClassifyFunc);
    parser.add_tcp_dpi_rule_with_func(r"^\x2a\x01", c.as_ref(), manager)
}

fn classify(ses: &mut Session, pkt: &dyn Packet) -> Result<()> {
    let payload = pkt.payload();
    if payload.len() < 6 {
        return Ok(());
    }

    let flen = ((payload[4] as u16) << 8 | payload[5] as u16) as usize;
    if payload.len() < flen {
        return Ok(());
    }

    if payload.len() == flen || payload[flen] as char == '*' {
        add_protocol(ses, "flap");
    }

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

        // condition 1
        let mut pkt: Box<Packet> = Box::new(Packet::default());
        pkt.raw = Box::new(b"\x2a\x01\x02\x03\x00\x06".to_vec());
        pkt.layers.trans.protocol = Protocol::TCP;
        let mut pkt: Box<dyn api::packet::Packet> = pkt;
        manager.classify(pkt.as_mut(), &mut scratch).unwrap();
        assert_eq!(pkt.rules().len(), 1);

        let mut ses = Session::new();
        parser
            .parse_pkt(pkt.as_ref(), Some(&pkt.rules()[0]), &mut ses)
            .unwrap();
        assert_has_protocol(&ses, "flap");

        // condition 2
        let mut pkt: Box<Packet> = Box::new(Packet::default());
        pkt.raw = Box::new(b"\x2a\x01\x02\x03\x00\x07\x06*\x08".to_vec());
        pkt.layers.trans.protocol = Protocol::TCP;
        let mut pkt: Box<dyn api::packet::Packet> = pkt;
        manager.classify(pkt.as_mut(), &mut scratch).unwrap();
        assert_eq!(pkt.rules().len(), 1);

        let mut ses = Session::new();
        parser
            .parse_pkt(pkt.as_ref(), Some(&pkt.rules()[0]), &mut ses)
            .unwrap();
        assert_has_protocol(&ses, "flap");
    }
}
