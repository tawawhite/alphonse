use std::collections::HashSet;

use anyhow::Result;
use serde::Serialize;
use serde_json::json;
use tls_parser::{
    parse_tls_extensions, ClientHello, TlsCipherSuite, TlsExtension, TlsServerHelloContents,
    TlsVersion,
};

use alphonse_api as api;
use api::classifiers;
use api::classifiers::{matched, RuleID};
use api::packet::{Direction, Packet, Protocol};
use api::plugins::processor::{Processor, ProcessorID};
use api::plugins::{Plugin, PluginType};
use api::session::Session;

mod cert;
mod ja3;
mod tcp;
mod udp;

use cert::Cert;
use ja3::{Ja3, Ja3s};

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
    /// Last time unprocessed payload
    #[serde(skip_serializing)]
    remained: Vec<u8>,
}

#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
struct TLS {
    #[serde(skip_serializing_if = "HashSet::is_empty")]
    version: HashSet<String>,
    #[serde(skip_serializing_if = "HashSet::is_empty")]
    cipher: HashSet<String>,
    #[serde(skip_serializing_if = "HashSet::is_empty")]
    ja3: HashSet<String>,
    #[serde(skip_serializing_if = "HashSet::is_empty")]
    ja3s: HashSet<String>,
    #[serde(skip_serializing_if = "HashSet::is_empty")]
    server_session_id: HashSet<String>,
    #[serde(skip_serializing_if = "HashSet::is_empty")]
    client_session_id: HashSet<String>,
    #[serde(skip_serializing_if = "HashSet::is_empty")]
    ja3string: HashSet<String>,
    #[serde(skip_serializing_if = "HashSet::is_empty")]
    ja3sstring: HashSet<String>,
}

#[derive(Clone, Default)]
struct TlsProcessor {
    id: ProcessorID,
    classified: bool,
    client_direction: Direction,

    tcp_rule_id: RuleID,
    udp_rule_id: RuleID,

    side_data: [SideInfo; 2],
    certs: Vec<Cert>,
    tls: TLS,
    hostnames: HashSet<String>,
}

impl Plugin for TlsProcessor {
    fn plugin_type(&self) -> PluginType {
        PluginType::PacketProcessor
    }

    fn name(&self) -> &str {
        "tls"
    }
}

impl Processor for TlsProcessor {
    fn clone_processor(&self) -> Box<dyn Processor> {
        Box::new(self.clone())
    }

    /// Get parser id
    fn id(&self) -> ProcessorID {
        self.id
    }

    /// Get parser id
    fn set_id(&mut self, id: ProcessorID) {
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

    fn save(&mut self, ses: &mut Session) {
        for cert in &self.certs {
            if cert.ca {
                ses.add_tag(&"self-signed");
            }
        }
        if !self.certs.is_empty() {
            ses.add_field(&"cert", json!(self.certs));
        }
        ses.add_field(&"tls", json!(self.tls));
        // TODO: this would lead to error when http connect request followed by tls session
        ses.add_field(&"host.http", json!(self.hostnames));
    }

    fn mid_save(&mut self, ses: &mut api::session::Session) {
        self.save(ses);
        self.certs.clear();
        self.tls = TLS::default();
        self.hostnames.clear();
    }
}

impl TlsProcessor {
    fn handle_client_hello<'a, H: ClientHello<'a>>(&mut self, dir: Direction, hello: &H) {
        self.client_direction = dir;
        match hello.session_id() {
            Some(id) => {
                self.tls.client_session_id.insert(hex::encode(id));
            }
            None => {}
        };

        let mut ja3 = Ja3::default();
        ja3.set_tls_version(u16::from(hello.version()));
        ja3.set_ciphers(hello.ciphers());

        let buf = hello.ext().unwrap_or_default();
        let (_, exts) = parse_tls_extensions(buf).unwrap_or_default();
        for ext in &exts {
            ja3.set_extension_type(ext);
            match ext {
                TlsExtension::SNI(names) => {
                    for (_, name) in names {
                        match std::str::from_utf8(name) {
                            Err(_) => {}
                            Ok(name) => {
                                self.hostnames.insert(name.to_string());
                            }
                        }
                    }
                }
                TlsExtension::EllipticCurves(groups) => {
                    ja3.set_supported_groups(groups);
                }
                TlsExtension::EcPointFormats(formats) => {
                    ja3.set_ec_points(formats);
                }
                _ => {}
            }
        }
        let mut md5 = md5::Context::new();
        let ja3 = ja3.to_string();
        md5.consume(ja3.as_bytes());
        self.tls.ja3.insert(format!("{:x}", md5.compute()));
        self.tls.ja3string.insert(ja3);
    }

    fn handle_server_hello(&mut self, dir: Direction, hello: &TlsServerHelloContents) {
        self.client_direction = dir.reverse();
        match hello.session_id {
            Some(id) => {
                self.tls.server_session_id.insert(hex::encode(id));
            }
            None => {}
        };

        match hello.version {
            TlsVersion::DTls10 => self.tls.version.insert("DTLSv1.0".to_string()),
            TlsVersion::DTls11 => self.tls.version.insert("DTLSv1.1".to_string()),
            TlsVersion::DTls12 => self.tls.version.insert("DTLSv1.2".to_string()),
            TlsVersion::Ssl30 => self.tls.version.insert("SSLv3".to_string()),
            TlsVersion::Tls10 => self.tls.version.insert("TLSv1.0".to_string()),
            TlsVersion::Tls11 => self.tls.version.insert("TLSv1.1".to_string()),
            TlsVersion::Tls12 => self.tls.version.insert("TLSv1.2".to_string()),
            TlsVersion::Tls13 => self.tls.version.insert("TLSv1.3".to_string()),
            TlsVersion::Tls13Draft18 => self.tls.version.insert("TLSv1.3-draft-18".to_string()),
            TlsVersion::Tls13Draft19 => self.tls.version.insert("TLSv1.3-draft-19".to_string()),
            TlsVersion::Tls13Draft20 => self.tls.version.insert("TLSv1.3-draft-20".to_string()),
            TlsVersion::Tls13Draft21 => self.tls.version.insert("TLSv1.3-draft-21".to_string()),
            TlsVersion::Tls13Draft22 => self.tls.version.insert("TLSv1.3-draft-22".to_string()),
            TlsVersion::Tls13Draft23 => self.tls.version.insert("TLSv1.3-draft-23".to_string()),
            v => self.tls.version.insert(v.to_string()),
        };

        match TlsCipherSuite::from_id(hello.cipher.0) {
            Some(cipher) => {
                self.tls.cipher.insert(cipher.name.to_string());
            }
            None => {}
        };

        let mut ja3s = Ja3s::default();
        ja3s.set_tls_version(u16::from(hello.version));
        ja3s.set_cipher(hello.cipher);
        let buf = hello.ext.unwrap_or_default();
        let (_, exts) = parse_tls_extensions(buf).unwrap_or_default();
        for ext in exts {
            ja3s.set_extension_type(&ext);
        }

        let mut md5 = md5::Context::new();
        let ja3s = ja3s.to_string();
        md5.consume(ja3s.as_bytes());
        self.tls.ja3s.insert(format!("{:x}", md5.compute()));
        self.tls.ja3sstring.insert(ja3s);
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use api::classifiers::ClassifierManager;
    use api::packet::test::Packet;
    use api::packet::Protocol;
    use api::plugins::processor::Processor;

    #[test]
    fn classify() {
        let mut manager = ClassifierManager::new();
        let mut parser = TlsProcessor::default();
        parser.register_classify_rules(&mut manager).unwrap();
        manager.prepare().unwrap();
        let mut scratch = manager.alloc_scratch().unwrap();

        // \x16\x01\x00
        let mut pkt: Box<Packet> = Box::new(Packet::default());
        pkt.raw = Box::new(b"\x16\x01\x00".to_vec());
        pkt.layers.trans.protocol = Protocol::UDP;
        let mut pkt: Box<dyn api::packet::Packet> = pkt;
        manager.classify(pkt.as_mut(), &mut scratch).unwrap();
        assert_eq!(pkt.rules().len(), 1);

        // \x16\xfe\xff
        let mut pkt: Box<Packet> = Box::new(Packet::default());
        pkt.raw = Box::new(b"\x16\xfe\xff".to_vec());
        pkt.layers.trans.protocol = Protocol::UDP;
        let mut pkt: Box<dyn api::packet::Packet> = pkt;
        manager.classify(pkt.as_mut(), &mut scratch).unwrap();
        assert_eq!(pkt.rules().len(), 1);

        // \x16\xfe\xfe
        let mut pkt: Box<Packet> = Box::new(Packet::default());
        pkt.raw = Box::new(b"\x16\xfe\xfe".to_vec());
        pkt.layers.trans.protocol = Protocol::UDP;
        let mut pkt: Box<dyn api::packet::Packet> = pkt;
        manager.classify(pkt.as_mut(), &mut scratch).unwrap();
        assert_eq!(pkt.rules().len(), 1);

        // \x16\xfe\xfd
        let mut pkt: Box<Packet> = Box::new(Packet::default());
        pkt.raw = Box::new(b"\x16\xfe\xfd".to_vec());
        pkt.layers.trans.protocol = Protocol::UDP;
        let mut pkt: Box<dyn api::packet::Packet> = pkt;
        manager.classify(pkt.as_mut(), &mut scratch).unwrap();
        assert_eq!(pkt.rules().len(), 1);

        // \x16\x03
        let mut pkt: Box<Packet> = Box::new(Packet::default());
        pkt.raw = Box::new(b"\x16\x03".to_vec());
        pkt.layers.trans.protocol = Protocol::TCP;
        let mut pkt: Box<dyn api::packet::Packet> = pkt;
        manager.classify(pkt.as_mut(), &mut scratch).unwrap();
        assert_eq!(pkt.rules().len(), 1);
    }
}

#[no_mangle]
pub extern "C" fn al_new_pkt_processor() -> Box<Box<dyn Processor>> {
    Box::new(Box::new(TlsProcessor::default()))
}

#[no_mangle]
pub extern "C" fn al_plugin_type() -> PluginType {
    PluginType::PacketProcessor
}
