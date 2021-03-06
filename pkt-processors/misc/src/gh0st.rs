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
    let c = Box::new(classify_windows as ClassifyFunc);
    builder.add_tcp_dpi_rule_with_func(
        r"^[a-zA-z0-9:]{5}..\x00\x00....\x78\x9c",
        c.as_ref(),
        manager,
    )?;
    let c = Box::new(classify_mac as ClassifyFunc);
    builder.add_tcp_dpi_rule_with_func(r"^[a-zA-z0-9:]{5}\x00\x00.{6}\x78\x9c", c.as_ref(), manager)
}

fn classify_windows(ses: &mut Session, pkt: &dyn Packet) -> Result<()> {
    let payload = pkt.payload();
    if payload.len() < 15 {
        return Ok(());
    }

    if ((payload[6] as u16 & 0xff) << 8 | (payload[5] as u16 & 0xff)) == payload.len() as u16 {
        add_protocol(ses, "gh0st");
    } else if payload[11] == 0 && payload[12] == 0 {
        add_protocol(ses, "gh0st");
    }

    Ok(())
}

fn classify_mac(ses: &mut Session, pkt: &dyn Packet) -> Result<()> {
    let payload = pkt.payload();
    if payload.len() < 15 {
        return Ok(());
    }

    if ((payload[7] as u16 & 0xff) << 8 | (payload[8] as u16 & 0xff)) == payload.len() as u16 {
        add_protocol(ses, "gh0st");
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
    fn gh0st() {
        let mut manager = ClassifierManager::new();
        let mut parser = Misc::default();
        parser.register_classify_rules(&mut manager).unwrap();
        manager.prepare().unwrap();
        let mut scratch = manager.alloc_scratch().unwrap();

        // Windows branch 1
        let mut pkt: Box<Packet> = Box::new(Packet::default());
        pkt.raw = Box::new(b"Gh0st\x0f\x00\x00\x00\x09\x10\x11\x12\x78\x9c".to_vec());
        pkt.layers.trans.protocol = Protocol::TCP;
        let mut pkt: Box<dyn api::packet::Packet> = pkt;
        manager.classify(pkt.as_mut(), &mut scratch).unwrap();
        assert_eq!(pkt.rules().len(), 1);

        let mut ses = Session::new();
        parser
            .parse_pkt(pkt.as_ref(), Some(&pkt.rules()[0]), &mut ses)
            .unwrap();
        assert_has_protocol(&ses, "gh0st");

        // Windows branch 2
        let mut pkt: Box<Packet> = Box::new(Packet::default());
        pkt.raw = Box::new(b"Gh0st\x05\x06\x00\x00\x09\x10\x00\x00\x78\x9c".to_vec());
        pkt.layers.trans.protocol = Protocol::TCP;
        let mut pkt: Box<dyn api::packet::Packet> = pkt;
        manager.classify(pkt.as_mut(), &mut scratch).unwrap();
        assert_eq!(pkt.rules().len(), 1);

        let mut ses = Session::new();
        parser
            .parse_pkt(pkt.as_ref(), Some(&pkt.rules()[0]), &mut ses)
            .unwrap();
        assert_has_protocol(&ses, "gh0st");

        // mac
        let mut pkt: Box<Packet> = Box::new(Packet::default());
        pkt.raw = Box::new(b"Gh0st\x00\x00\x00\x0f\x09\x10\x11\x12\x78\x9c".to_vec());
        pkt.layers.trans.protocol = Protocol::TCP;
        let mut pkt: Box<dyn api::packet::Packet> = pkt;
        manager.classify(pkt.as_mut(), &mut scratch).unwrap();
        assert_eq!(pkt.rules().len(), 1);

        let mut ses = Session::new();
        parser
            .parse_pkt(pkt.as_ref(), Some(&pkt.rules()[0]), &mut ses)
            .unwrap();
        assert_has_protocol(&ses, "gh0st");
    }
}
