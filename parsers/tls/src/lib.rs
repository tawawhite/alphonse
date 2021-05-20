use std::collections::HashSet;

use anyhow::Result;
use serde::Serialize;
use serde_json::json;
use tls_parser::TlsServerHelloContents;

use alphonse_api as api;
use api::classifiers;
use api::classifiers::{matched, RuleID};
use api::packet::{Direction, Packet, Protocol};
use api::parsers::ParserID;
use api::plugins::{Plugin, PluginType};
use api::session::Session;

mod cert;
mod ja3;
mod tcp;
mod udp;

use cert::Cert;

#[repr(u8)]
#[derive(Clone, Copy, Debug, Hash, PartialEq)]
enum Side {
    Client = 0,
    Server = 1,
}

impl Default for Side {
    fn default() -> Self {
        Side::Client
    }
}

#[derive(Clone, Default, Serialize)]
struct SideInfo {
    #[serde(skip_serializing)]
    side: Side,
    /// Session ID
    session_ids: HashSet<String>,
    /// ja3
    #[serde(skip_serializing)]
    ja3s: HashSet<ja3::Ja3>,
    /// Last time unprocessed payload
    #[serde(skip_serializing)]
    remained: Vec<u8>,
}

#[derive(Clone, Default)]
struct Processor {
    id: ParserID,
    name: String,
    classified: bool,

    tcp_rule_id: RuleID,
    udp_rule_id: RuleID,

    side_data: [SideInfo; 2],
    certs: Vec<Cert>,
    hostnames: HashSet<String>,
}

impl Processor {
    fn new() -> Self {
        let mut p = Self::default();
        p.name = String::from("tls");
        p
    }
}

impl Plugin for Processor {
    fn plugin_type(&self) -> PluginType {
        PluginType::PacketProcessor
    }

    fn name(&self) -> &str {
        &self.name.as_str()
    }
}

impl api::parsers::ProtocolParserTrait for Processor {
    fn box_clone(&self) -> Box<dyn api::parsers::ProtocolParserTrait> {
        Box::new(self.clone())
    }

    /// Get parser id
    fn id(&self) -> ParserID {
        self.id
    }

    /// Get parser id
    fn set_id(&mut self, id: ParserID) {
        self.id = id
    }

    fn register_classify_rules(
        &mut self,
        manager: &mut classifiers::ClassifierManager,
    ) -> Result<()> {
        self.tcp_rule_id = manager.add_tcp_dpi_rule(self.id, r"^\x16\x03")?;

        self.udp_rule_id =
            manager.add_udp_dpi_rule(self.id, r"^\x16(\x01\x00|\xfe[\xff\xfe\xfd])")?;

        Ok(())
    }

    fn is_classified(&self) -> bool {
        self.classified
    }

    fn classified_as_this_protocol(&mut self) -> Result<()> {
        self.classified = true;
        return Ok(());
    }

    fn parse_pkt(
        &mut self,
        pkt: &dyn Packet,
        _rule: Option<&matched::Rule>,
        ses: &mut Session,
    ) -> Result<()> {
        match pkt.layers().trans.protocol {
            Protocol::TCP => self.parse_tcp_pkt(pkt, ses),
            Protocol::UDP => self.parse_udp_pkt(pkt, ses),
            _ => unreachable!(),
        }
    }

    fn finish(&mut self, ses: &mut Session) {
        ses.add_field(&"cert", &json!(self.certs));
        for side in &self.side_data {
            match side.side {
                Side::Client => {}
                Side::Server => {}
            };
        }
        println!("{}", serde_json::to_string_pretty(ses).unwrap());
    }
}

impl Processor {
    fn handle_server_hello(&mut self, dir: Direction, hello: &TlsServerHelloContents) {
        let dir = dir as u8 as usize;
        self.side_data[dir].side = Side::Server;
        match hello.session_id {
            Some(id) => {
                self.side_data[dir].session_ids.insert(hex::encode(id));
            }
            None => {}
        };
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use api::classifiers::ClassifierManager;
    use api::packet::Protocol;
    use api::parsers::ProtocolParserTrait;
    use api::utils::packet::Packet as TestPacket;

    #[test]
    fn classify() {
        let mut manager = ClassifierManager::new();
        let mut parser = Processor::new();
        parser.register_classify_rules(&mut manager).unwrap();
        manager.prepare().unwrap();
        let mut scratch = manager.alloc_scratch().unwrap();

        // \x16\x01\x00
        let mut pkt: Box<TestPacket> = Box::new(TestPacket::default());
        pkt.raw = Box::new(b"\x16\x01\x00".to_vec());
        pkt.layers.trans.protocol = Protocol::UDP;
        let mut pkt: Box<dyn api::packet::Packet> = pkt;
        manager.classify(pkt.as_mut(), &mut scratch).unwrap();
        assert_eq!(pkt.rules().len(), 1);

        // \x16\xfe\xff
        let mut pkt: Box<TestPacket> = Box::new(TestPacket::default());
        pkt.raw = Box::new(b"\x16\xfe\xff".to_vec());
        pkt.layers.trans.protocol = Protocol::UDP;
        let mut pkt: Box<dyn api::packet::Packet> = pkt;
        manager.classify(pkt.as_mut(), &mut scratch).unwrap();
        assert_eq!(pkt.rules().len(), 1);

        // \x16\xfe\xfe
        let mut pkt: Box<TestPacket> = Box::new(TestPacket::default());
        pkt.raw = Box::new(b"\x16\xfe\xfe".to_vec());
        pkt.layers.trans.protocol = Protocol::UDP;
        let mut pkt: Box<dyn api::packet::Packet> = pkt;
        manager.classify(pkt.as_mut(), &mut scratch).unwrap();
        assert_eq!(pkt.rules().len(), 1);

        // \x16\xfe\xfd
        let mut pkt: Box<TestPacket> = Box::new(TestPacket::default());
        pkt.raw = Box::new(b"\x16\xfe\xfd".to_vec());
        pkt.layers.trans.protocol = Protocol::UDP;
        let mut pkt: Box<dyn api::packet::Packet> = pkt;
        manager.classify(pkt.as_mut(), &mut scratch).unwrap();
        assert_eq!(pkt.rules().len(), 1);

        // \x16\x03
        let mut pkt: Box<TestPacket> = Box::new(TestPacket::default());
        pkt.raw = Box::new(b"\x16\x03".to_vec());
        pkt.layers.trans.protocol = Protocol::TCP;
        let mut pkt: Box<dyn api::packet::Packet> = pkt;
        manager.classify(pkt.as_mut(), &mut scratch).unwrap();
        assert_eq!(pkt.rules().len(), 1);
    }
}

#[no_mangle]
pub extern "C" fn al_new_protocol_parser() -> Box<Box<dyn api::parsers::ProtocolParserTrait>> {
    Box::new(Box::new(Processor::new()))
}
