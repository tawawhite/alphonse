use anyhow::Result;
use hyperscan::pattern;
use x509_parser::prelude::{parse_x509_certificate, GeneralName, ParsedExtension};

use alphonse_api as api;
use api::classifiers;
use api::classifiers::{dpi, matched, Rule, RuleType};
use api::packet::Packet;
use api::parsers::ParserID;
use api::session::Session;
use api::{add_simple_dpi_rule, add_simple_dpi_udp_rule};

#[derive(Debug, Default, Clone)]
struct CertInfo {
    comman_name: Vec<String>,
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

#[derive(Clone)]
struct Processor {
    id: ParserID,
    name: String,
    classified: bool,
    certs: Vec<Cert>,
}

impl Processor {
    fn new() -> Self {
        Self {
            id: 0,
            name: String::from("dtls"),
            classified: false,
            certs: vec![],
        }
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

    /// Get parser name
    fn name(&self) -> &str {
        &self.name.as_str()
    }

    fn register_classify_rules(
        &mut self,
        manager: &mut classifiers::ClassifierManager,
    ) -> Result<()> {
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
        if !self.is_classified() {
            if pkt.data_len() < 100 || pkt.data_len() < 13 || pkt.payload()[13] != 1 {
                return Ok(());
            }
            // If this session is already classified as this protocol, skip
            self.classified_as_this_protocol()?;
            ses.add_protocol(&self.name());
        }

        if pkt.payload()[0] != 22 {
            // 0x22 is handshake packet
            return Ok(());
        }

        let mut remained: usize = pkt.data_len() as usize;
        while remained >= 13 {
            remained -= 13;
            let len = ((pkt.payload()[10] as u16) << 8) | (pkt.payload()[11] as u16);
            if len as usize > remained {
                // remained unprocessed payload is not long enough
                return Ok(());
            }

            let offset = pkt.data_len() as usize - remained;
            let consumed = self.parse_handshake(&pkt.payload()[offset..], ses);
            remained -= consumed;
        }

        Ok(())
    }

    fn finish(&mut self, _: &mut Session) {
        for cert in &self.certs {
            println!("{:?}", cert);
        }
    }
}

impl Processor {
    /// Parse dtls handshake packet buffer
    ///
    /// # Arguments
    ///
    /// `payload` - dtls packet payload
    ///
    /// `ses` - dtls session
    ///
    /// # Returns
    ///
    fn parse_handshake(&mut self, payload: &[u8], ses: &mut Session) -> usize {
        let handshake_type = payload[0];
        let handshake_len =
            ((payload[1] as u32) << 16) | ((payload[2] as u32) << 8) | (payload[3] as u32);
        let frame_offset =
            ((payload[6] as u32) << 16) | ((payload[7] as u32) << 8) | (payload[8] as u32);

        if handshake_len as usize > payload.len() || frame_offset != 0 {
            // if payload is not enough, return
            // and also alphonse don't handle fragmented packets yet
            return 9;
        }

        match handshake_type {
            11 => 9 + self.parse_server_certificate(&payload[15..], ses),
            _ => handshake_len as usize + 12,
        }
    }

    fn parse_server_certificate(&mut self, payload: &[u8], _ses: &mut Session) -> usize {
        let mut remained = payload.len();
        while remained > 3 {
            let mut cert = Cert::default();
            let offset = payload.len() - remained + 3;
            match parse_x509_certificate(&payload[offset..]) {
                Err(_) => return payload.len(),
                Ok((remain, cer)) => {
                    // get cert serial number
                    cert.serial_number = format!("{:x}", cer.tbs_certificate.serial);

                    // get issuer information
                    for cn in cer.issuer().iter_common_name() {
                        match cn.as_str() {
                            Ok(cn) => cert.issuer.comman_name.push(cn.to_string()),
                            Err(_) => continue,
                        }
                    }

                    for org in cer.issuer().iter_organization() {
                        match org.as_str() {
                            Ok(org) => cert.issuer.comman_name.push(org.to_string()),
                            Err(_) => continue,
                        }
                    }

                    // get validity information
                    cert.not_before = cer.validity().not_before.timestamp() as u64;
                    cert.not_after = cer.validity().not_after.timestamp() as u64;

                    // get subject information
                    for cn in cer.subject().iter_common_name() {
                        match cn.as_str() {
                            Ok(cn) => cert.issuer.comman_name.push(cn.to_string()),
                            Err(_) => continue,
                        }
                    }

                    for org in cer.subject().iter_organization() {
                        match org.as_str() {
                            Ok(org) => cert.issuer.comman_name.push(org.to_string()),
                            Err(_) => continue,
                        }
                    }

                    // get extension infomation
                    for ext in cer.extensions().values() {
                        match ext.parsed_extension() {
                            ParsedExtension::KeyUsage(usage) => {}
                            ParsedExtension::SubjectAlternativeName(an) => {
                                for gn in &an.general_names {
                                    match gn {
                                        GeneralName::DNSName(n) => cert.alt.push(n.to_string()),
                                        _ => continue,
                                    }
                                }
                            }
                            _ => continue,
                        };
                    }

                    remained = remain.len();
                }
            };

            self.certs.push(cert);
        }
        0
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
    }
}

#[no_mangle]
pub extern "C" fn al_new_protocol_parser() -> Box<Box<dyn api::parsers::ProtocolParserTrait>> {
    Box::new(Box::new(Processor::new()))
}
