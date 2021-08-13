use anyhow::Result;

use alphonse_api as api;
use api::classifiers::ClassifierManager;
use api::packet::Packet;
use api::session::Session;

use super::{add_protocol, Misc};

pub fn register_classify_rules(parser: &mut Misc, manager: &mut ClassifierManager) -> Result<()> {
    parser.add_tcp_dpi_rule_with_func(r"^220\s", classify, manager)
}

fn classify(ses: &mut Session, pkt: &dyn Packet) -> Result<()> {
    let payload = pkt.payload();
    match payload[4..].windows(4).position(|win| win == b"LMTP") {
        Some(_) => {
            add_protocol(ses, "lmtp");
            return Ok(());
        }
        None => {}
    }

    match (
        payload[4..].windows(4).position(|win| win == b"SMTP"),
        payload[4..].windows(4).position(|win| win == b"TLS"),
    ) {
        (None, None) => {
            add_protocol(ses, "ftp");
        }
        _ => {}
    };

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
    fn other220() {
        let mut manager = ClassifierManager::new();
        let mut parser = Misc::default();
        parser.register_classify_rules(&mut manager).unwrap();
        manager.prepare().unwrap();
        let mut scratch = manager.alloc_scratch().unwrap();

        // LMTP
        let mut pkt: Box<Packet> = Box::new(Packet::default());
        pkt.raw = Box::new(b"220 LMTP".to_vec());
        pkt.layers.trans.protocol = Protocol::TCP;
        let mut pkt: Box<dyn api::packet::Packet> = pkt;
        manager.classify(pkt.as_mut(), &mut scratch).unwrap();
        assert_eq!(pkt.rules().len(), 1);

        let mut ses = Session::new();
        parser
            .parse_pkt(pkt.as_ref(), Some(&pkt.rules()[0]), &mut ses)
            .unwrap();
        assert_has_protocol(&ses, "lmtp");

        // ftp
        let mut pkt: Box<Packet> = Box::new(Packet::default());
        pkt.raw = Box::new(b"220 FTP".to_vec());
        pkt.layers.trans.protocol = Protocol::TCP;
        let mut pkt: Box<dyn api::packet::Packet> = pkt;
        manager.classify(pkt.as_mut(), &mut scratch).unwrap();
        assert_eq!(pkt.rules().len(), 1);

        let mut ses = Session::new();
        parser
            .parse_pkt(pkt.as_ref(), Some(&pkt.rules()[0]), &mut ses)
            .unwrap();
        assert_has_protocol(&ses, "ftp");
    }
}
