//! Skinny Client Control Protocol, in arkime it is called sccp.
//! However there is another protocol named 'Signalling Connection Control Part',
//! which is a network layer protocol could also be called 'sccp'.
//! So to distinguish between these two protocols, we call this skinny.

use anyhow::Result;
use nom::number::streaming::le_u32;

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
    builder.add_tcp_port_rule_with_func(2000, c.as_ref(), manager)
}

fn classify(ses: &mut Session, pkt: &dyn Packet) -> Result<()> {
    let _ = _classify(ses, pkt);
    Ok(())
}

fn _classify<'a>(ses: &mut Session, pkt: &'a dyn Packet) -> nom::IResult<&'a [u8], ()> {
    let (data, len) = le_u32(pkt.payload())?;
    if data.len() < len as usize || data.len() < 9 {
        return Ok((&[], ()));
    }

    if data[..4] != [0; 4] {
        return Ok((&[], ()));
    }

    add_protocol(ses, "skinny");
    Ok((&[], ()))
}

#[cfg(test)]
mod test {
    use super::*;
    use api::packet::Protocol;
    use api::plugins::processor::Processor;
    use api::session::Session;

    use crate::test::{assert_has_protocol, Packet};

    #[test]
    fn skinny() {
        let mut manager = ClassifierManager::new();
        let mut parser = Misc::default();
        parser.register_classify_rules(&mut manager).unwrap();
        manager.prepare().unwrap();
        let mut scratch = manager.alloc_scratch().unwrap();

        // UDP 500
        let mut pkt: Box<Packet> = Box::new(Packet::default());
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
        assert_has_protocol(&ses, "skinny");
    }
}
