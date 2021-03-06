use anyhow::Result;
use nom::bytes::streaming::take;
use nom::number::streaming::{be_u16, be_u8};
use nom::IResult;
use serde_json::json;

use alphonse_api as api;
use api::classifiers::ClassifierManager;
use api::packet::Packet;
use api::session::Session;

use super::{add_protocol, Builder, ClassifyFunc};

pub fn register_classify_rules(
    builder: &mut Builder,
    manager: &mut ClassifierManager,
) -> Result<()> {
    let c = Box::new(classify_wrapper as ClassifyFunc);
    builder.add_tcp_dpi_rule_with_func(r"^\x10.{3}MQ", c.as_ref(), manager)
}

#[inline]
fn classify_wrapper(ses: &mut Session, pkt: &dyn Packet) -> Result<()> {
    add_protocol(ses, "mqtt");

    match classify(ses, pkt) {
        Ok(_) => {}
        Err(_) => {}
    };
    Ok(())
}

fn classify<'a>(ses: &'a mut Session, pkt: &'a dyn Packet) -> IResult<&'a [u8], ()> {
    let payload = pkt.payload();
    let (payload, _msg_len) = be_u8(payload)?;
    let (payload, name_len) = be_u16(payload)?;
    let (payload, _) = take(name_len)(payload)?;
    let (payload, _version) = be_u8(payload)?;
    let (payload, flags) = be_u8(payload)?;
    let (payload, _keep_alive) = be_u16(payload)?;
    let (payload, _id_len) = be_u16(payload)?;

    let payload = if flags & 0x04 > 0 {
        let (payload, skip_len) = be_u16(payload)?;
        let (payload, _) = take(skip_len)(payload)?;
        let (payload, skip_len) = be_u16(payload)?;
        let (payload, _) = take(skip_len)(payload)?;
        payload
    } else {
        payload
    };

    if flags & 0x80 > 0 {
        let (payload, user_len) = be_u16(payload)?;
        let (payload, _) = take(user_len)(payload)?;
        match std::str::from_utf8(payload.to_ascii_lowercase().as_slice()) {
            Ok(name) => ses.add_field(&"user", json!(name)),
            Err(_) => {}
        };
    }

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
    fn mqtt() {
        let mut manager = ClassifierManager::new();
        let mut parser = Misc::default();
        parser.register_classify_rules(&mut manager).unwrap();
        manager.prepare().unwrap();
        let mut scratch = manager.alloc_scratch().unwrap();

        let mut pkt: Box<Packet> = Box::new(Packet::default());
        pkt.raw = Box::new(vec![
            0x10, 0x25, 0x00, 0x06, 0x4d, 0x51, 0x49, 0x73, 0x64, 0x70, 0x03, 0x02, 0x00, 0x05,
            0x00, 0x17, 0x70, 0x61, 0x68, 0x6f, 0x2f, 0x33, 0x34, 0x41, 0x41, 0x45, 0x35, 0x34,
            0x41, 0x37, 0x35, 0x44, 0x38, 0x33, 0x39, 0x35, 0x36, 0x36, 0x45,
        ]);
        pkt.layers.trans.protocol = Protocol::TCP;
        let mut pkt: Box<dyn api::packet::Packet> = pkt;
        manager.classify(pkt.as_mut(), &mut scratch).unwrap();
        assert!(pkt.rules().len() > 0);

        let mut ses = Session::new();
        for rule in pkt.rules() {
            parser
                .parse_pkt(pkt.as_ref(), Some(rule), &mut ses)
                .unwrap();
        }
        assert_has_protocol(&ses, "mqtt");
    }
}
