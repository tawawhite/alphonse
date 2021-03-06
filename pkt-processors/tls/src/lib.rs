use std::collections::HashSet;

use anyhow::Result;
use serde::Serialize;
use serde_json::json;
use tls_parser::{
    parse_tls_extensions, ClientHello, TlsCipherSuite, TlsExtension, TlsServerHelloContents,
    TlsVersion,
};

use alphonse_api as api;
use alphonse_utils as utils;
use api::classifiers;
use api::classifiers::{matched, RuleID};
use api::packet::{Direction, Packet, Protocol};
use api::plugins::processor::{Builder as ProcessorBuilder, Processor, ProcessorID};
use api::plugins::{Plugin, PluginType};
use api::session::Session;
use utils::tcp_reassembly::TcpReorder;

mod cert;
mod ja3;
mod tcp;
mod udp;

use cert::Cert;
use ja3::{Ja3, Ja3s};

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

#[derive(Debug, Default)]
struct Builder {
    id: ProcessorID,
    tcp_rule_id: RuleID,
    udp_rule_id: RuleID,
}

impl Plugin for Builder {
    fn plugin_type(&self) -> PluginType {
        PluginType::PacketProcessor
    }

    fn name(&self) -> &str {
        "tls"
    }
}

impl ProcessorBuilder for Builder {
    fn build(&self, _: &api::config::Config) -> Box<dyn Processor> {
        let mut pcr = Box::new(TlsProcessor::default());
        pcr.id = self.id();
        pcr.tcp_rule_id = self.tcp_rule_id;
        pcr.udp_rule_id = self.udp_rule_id;
        pcr.tcp_reorder[0] = TcpReorder::with_capacity(8);
        pcr.tcp_reorder[1] = TcpReorder::with_capacity(8);
        pcr
    }

    fn id(&self) -> ProcessorID {
        self.id
    }

    fn set_id(&mut self, id: ProcessorID) {
        self.id = id
    }

    fn register_classify_rules(
        &mut self,
        manager: &mut classifiers::ClassifierManager,
    ) -> Result<()> {
        self.tcp_rule_id = manager.add_tcp_dpi_rule(self.id, r"^\x16\x03")?;
        self.udp_rule_id =
            manager.add_tcp_dpi_rule(self.id, r"^\x16(\x01\x00|\xfe[\xff\xfe\xfd])")?;

        Ok(())
    }
}

#[derive(Clone, Default)]
struct TlsProcessor {
    id: ProcessorID,
    classified: bool,
    client_direction: Direction,
    has_change_cipher_spec: bool,

    tcp_rule_id: RuleID,
    udp_rule_id: RuleID,

    buffer: [Vec<u8>; 2],
    tcp_reorder: [TcpReorder; 2],
    certs: Vec<Cert>,
    tls: TLS,
    hostnames: HashSet<String>,
}

unsafe impl Send for TlsProcessor {}
unsafe impl Sync for TlsProcessor {}

impl Processor for TlsProcessor {
    /// Get parser id
    fn id(&self) -> ProcessorID {
        self.id
    }

    fn name(&self) -> &'static str {
        &"tls"
    }

    fn parse_pkt(
        &mut self,
        pkt: &dyn Packet,
        _rule: Option<&matched::Rule>,
        ses: &mut Session,
    ) -> Result<()> {
        if self.has_change_cipher_spec || pkt.payload().len() == 0 {
            return Ok(());
        }

        match pkt.layers().transport() {
            None => unreachable!("this should never happends"),
            Some(l) => match l.protocol {
                Protocol::TCP => self.parse_tcp_pkt(pkt, ses),
                Protocol::UDP => self.parse_udp_pkt(pkt, ses),
                _ => unreachable!(),
            },
        }
    }

    fn save(&mut self, ses: &mut Session) {
        let pkts = self.tcp_reorder[0].get_all_pkts();
        self.reassemble_and_parse(pkts, Direction::Right);

        let pkts = self.tcp_reorder[1].get_all_pkts();
        self.reassemble_and_parse(pkts, Direction::Left);

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

#[no_mangle]
pub extern "C" fn al_new_pkt_processor_builder() -> Box<Box<dyn ProcessorBuilder>> {
    Box::new(Box::new(Builder::default()))
}

#[no_mangle]
pub extern "C" fn al_plugin_type() -> PluginType {
    PluginType::PacketProcessor
}
