use anyhow::Result;
use serde_json::json;

use alphonse_api as api;
use api::classifiers::ClassifierManager;
use api::packet::Packet;
use api::session::Session;

use crate::{add_protocol, Misc};

const MARKER: [u8; 16] = [0xff; 16];
const TYPE: &[&str] = &[
    "Reserved",
    "OPEN",
    "UPDATE",
    "NOTIFICATION",
    "KEEPALIVE",
    "ROUTE-REFRESH",
];

pub fn register_classify_rules(parser: &mut Misc, manager: &mut ClassifierManager) -> Result<()> {
    parser.add_tcp_port_rule_with_func(179, classify, manager)
}

fn classify(ses: &mut Session, pkt: &dyn Packet) -> Result<()> {
    if pkt.data_len() < 19 || pkt.payload()[0..16] != MARKER {
        return Ok(());
    }

    add_protocol(ses, "bgp");

    let msg_type = pkt.payload()[18] as usize;
    if msg_type < TYPE.len() {
        ses.add_field(&"bgp.type", json!(TYPE[msg_type]));
    } else {
        ses.add_field(&"bgp.type", json!("Unassigned"));
    }

    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    use api::packet::Protocol;
    use api::plugins::processor::Processor;
    use api::session::ProtocolLayer;

    use crate::test::{assert_has_protocol, Packet};

    #[test]
    fn bgp() {
        let mut manager = ClassifierManager::new();
        let mut parser = Misc::default();
        parser.register_classify_rules(&mut manager).unwrap();
        manager.prepare().unwrap();
        let mut scratch = manager.alloc_scratch().unwrap();

        // port does not match
        let mut pkt: Box<Packet> = Box::new(Packet::default());
        pkt.raw = Box::new(vec![
            0x64, 0xdc, 0x00, 0xb4, 0x9f, 0x49, 0x77, 0x8b, 0x08, 0x7c, 0xd2, 0x26, 0xa0, 0x18,
            0x40, 0x00, 0xf3, 0x65, 0x00, 0x00, 0x13, 0x12, 0x9a, 0xb9, 0x9d, 0x4a, 0x6d, 0x94,
            0x11, 0x8b, 0xf7, 0x56, 0x2d, 0xf7, 0xfb, 0xe5, 0x75, 0xa3, 0x00, 0x00,
        ]);
        pkt.layers.trans.protocol = Protocol::TCP;
        let mut pkt: Box<dyn api::packet::Packet> = pkt;
        manager.classify(pkt.as_mut(), &mut scratch).unwrap();
        assert_eq!(pkt.rules().len(), 0);

        // does not start with marker
        let mut pkt: Box<Packet> = Box::new(Packet::default());
        pkt.raw = Box::new(vec![
            0x64, 0xdc, 0x00, 0xb3, 0x9f, 0x49, 0x77, 0x8b, 0x08, 0x7c, 0xd2, 0x26, 0xa0, 0x18,
            0x40, 0x00, 0xf3, 0x65, 0x00, 0x00, 0x13, 0x12, 0x9a, 0xb9, 0x9d, 0x4a, 0x6d, 0x94,
            0x11, 0x8b, 0xf7, 0x56, 0x2d, 0xf7, 0xfb, 0xe5, 0x75, 0xa3, 0x00, 0x00, 0x00, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0x00, 0x2d, 0x01, 0x04, 0xfe, 0x4c, 0x00, 0xb4, 0x0a, 0x00, 0x00, 0x01, 0x10, 0x02,
            0x06, 0x01, 0x04, 0x00, 0x01, 0x00, 0x01, 0x02, 0x02, 0x80, 0x00, 0x02, 0x02, 0x02,
            0x00,
        ]);
        pkt.layers.trans.protocol = Protocol::TCP;
        pkt.layers.app.offset = 40;
        pkt.caplen = 85;
        let mut pkt: Box<dyn api::packet::Packet> = pkt;
        manager.classify(pkt.as_mut(), &mut scratch).unwrap();
        assert!(pkt.rules().len() > 0);

        let mut ses = Session::new();
        for rule in pkt.rules() {
            parser
                .parse_pkt(pkt.as_ref(), Some(rule), &mut ses)
                .unwrap();
        }
        assert!(!ses.has_protocol(&"bgp", ProtocolLayer::Application));

        // OPEN message type
        let mut pkt: Box<Packet> = Box::new(Packet::default());
        pkt.raw = Box::new(vec![
            0x64, 0xdc, 0x00, 0xb3, 0x9f, 0x49, 0x77, 0x8b, 0x08, 0x7c, 0xd2, 0x26, 0xa0, 0x18,
            0x40, 0x00, 0xf3, 0x65, 0x00, 0x00, 0x13, 0x12, 0x9a, 0xb9, 0x9d, 0x4a, 0x6d, 0x94,
            0x11, 0x8b, 0xf7, 0x56, 0x2d, 0xf7, 0xfb, 0xe5, 0x75, 0xa3, 0x00, 0x00, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0x00, 0x2d, 0x01, 0x04, 0xfe, 0x4c, 0x00, 0xb4, 0x0a, 0x00, 0x00, 0x01, 0x10, 0x02,
            0x06, 0x01, 0x04, 0x00, 0x01, 0x00, 0x01, 0x02, 0x02, 0x80, 0x00, 0x02, 0x02, 0x02,
            0x00,
        ]);
        pkt.layers.trans.protocol = Protocol::TCP;
        pkt.layers.app.offset = 40;
        pkt.caplen = 85;
        let mut pkt: Box<dyn api::packet::Packet> = pkt;
        manager.classify(pkt.as_mut(), &mut scratch).unwrap();
        assert_eq!(pkt.rules().len(), 1);

        let mut ses = Session::new();
        parser
            .parse_pkt(pkt.as_ref(), Some(&pkt.rules()[0]), &mut ses)
            .unwrap();
        assert_has_protocol(&ses, "bgp");
        let a = &ses.fields.as_object().unwrap()["bgp.type"];
        assert_eq!(a.as_str().unwrap(), "OPEN");
    }
}
