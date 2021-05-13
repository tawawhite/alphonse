use std::collections::HashSet;

use anyhow::Result;
use hyperscan::pattern;
use tls_parser::{TlsPlaintext, TlsServerHelloContents};

use alphonse_api as api;
use api::classifiers;
use api::classifiers::{dpi, matched, Rule, RuleID, RuleType};
use api::packet::{Packet, Protocol};
use api::parsers::ParserID;
use api::session::Session;
use api::{add_simple_dpi_rule, add_simple_dpi_tcp_rule, add_simple_dpi_udp_rule};

mod cert;
mod ja3;
mod tcp;
mod udp;

#[derive(Debug, Default, Clone)]
struct CertInfo {
    common_name: Vec<String>,
    org_name: Vec<String>,
}

#[derive(Debug, Default, Clone)]
struct Cert {
    pub hash: u32,
    pub not_before: u64,
    pub not_after: u64,
    pub issuer: CertInfo,
    pub subject: CertInfo,
    pub alt: Vec<String>,
    pub serial_number: String,
    pub bucket: usize,
    pub hash_str: String,
    pub is_ca: bool,
    pub algorithm: String,
    pub curv: String,
}

#[derive(Clone, Default)]
struct Processor<'a> {
    id: ParserID,
    name: String,
    classified: bool,
    certs: Vec<Cert>,
    tcp_rule_id: RuleID,
    udp_rule_id: RuleID,
    client_data: Option<TlsPlaintext<'a>>,
    server_data: Option<TlsPlaintext<'a>>,
    client_session_ids: HashSet<String>,
    server_session_ids: HashSet<String>,
    client_ja3: ja3::Ja3,
    server_ja3: ja3::Ja3,
    hostnames: HashSet<String>,
    supported_groups: HashSet<u16>,
    ec_point_formats: HashSet<u8>,
}

impl<'a> Processor<'a> {
    fn new() -> Self {
        let mut p = Self::default();
        p.name = String::from("dtls");
        p
    }
}

impl<'a> api::parsers::ProtocolParserTrait for Processor<'static> {
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

    /// Get parser name
    fn name(&self) -> &str {
        &self.name.as_str()
    }

    fn register_classify_rules(
        &mut self,
        manager: &mut classifiers::ClassifierManager,
    ) -> Result<()> {
        self.tcp_rule_id = add_simple_dpi_tcp_rule!(r"^\x16\x03", self.id, manager);

        self.udp_rule_id =
            add_simple_dpi_udp_rule!(r"^\x16(\x01\x00|\xfe[\xff\xfe\xfd])", self.id, manager);

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

    fn finish(&mut self, _: &mut Session) {
        for cert in &self.certs {
            println!("{:?}", cert);
        }
    }
}

impl<'a> Processor<'static> {
    fn handle_server_hello(&mut self, hello: &TlsServerHelloContents) {
        match hello.session_id {
            Some(id) => {
                self.server_session_ids.insert(hex::encode(id));
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
