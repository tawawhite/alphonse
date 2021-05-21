use anyhow::Result;
use tls_parser::{
    parse_tls_extensions, parse_tls_plaintext, Err as TlsErr, TlsCipherSuiteID,
    TlsClientHelloContents, TlsExtension, TlsMessage, TlsMessageHandshake, TlsPlaintext,
};

use alphonse_api as api;
use api::packet::{Direction, Packet};
use api::plugins::parsers::Processor;
use api::plugins::Plugin;
use api::session::Session;

use crate::ja3::Ja3;
use crate::{Side, TlsProcessor};

impl TlsProcessor {
    pub fn parse_tcp_pkt(&mut self, pkt: &dyn Packet, ses: &mut Session) -> Result<()> {
        if !self.is_classified() {
            // If this session is already classified as this protocol, skip
            self.classified_as_this_protocol()?;
            ses.add_protocol(&self.name());
        }

        let dir = pkt.direction() as u8 as usize;
        let mut _buf = vec![];
        let mut buf = if self.side_data[dir].remained.len() > 0 {
            _buf = self.side_data[dir].remained.clone();
            _buf.extend_from_slice(pkt.payload());
            _buf.as_slice()
        } else {
            pkt.payload()
        };

        while !buf.is_empty() {
            let (b, result) = match parse_tls_plaintext(buf) {
                Ok(r) => r,
                Err(e) => {
                    match e {
                        TlsErr::Incomplete(_) => {
                            self.side_data[dir].remained = buf.iter().map(|x| *x).collect();
                        }
                        _ => {}
                    };
                    break;
                }
            };

            self.handle_tls_parse_result(pkt.direction(), result);
            buf = b;

            let side = &mut self.side_data[dir];
            if buf.len() > 0 && side.remained.len() > buf.len() {
                let offset = side.remained.len() - buf.len();
                side.remained = side.remained[offset..].iter().map(|x| *x).collect();
            }
        }

        Ok(())
    }

    fn handle_tls_parse_result(&mut self, dir: Direction, result: TlsPlaintext) {
        for msg in &result.msg {
            match msg {
                TlsMessage::Handshake(handshake) => {
                    match handshake {
                        TlsMessageHandshake::ClientHello(hello) => {
                            self.handle_tls_client_hello(dir, hello)
                        }
                        TlsMessageHandshake::Certificate(cert) => {
                            self.handle_certificate(cert);
                        }
                        TlsMessageHandshake::ServerHello(hello) => {
                            self.handle_server_hello(dir, hello);
                        }
                        _ => {}
                    };
                }
                _ => {}
            };
        }
    }

    fn handle_tls_client_hello(&mut self, dir: Direction, hello: &TlsClientHelloContents) {
        let dir = dir as u8 as usize;

        self.side_data[dir].side = Side::Client;

        let mut ja3 = Ja3::default();
        match hello.session_id {
            Some(id) => {
                self.side_data[dir].session_ids.insert(hex::encode(id));
            }
            None => {}
        };

        ja3.set_tls_version(u16::from(hello.get_version()));

        let ciphers: Vec<TlsCipherSuiteID> = hello
            .get_ciphers()
            .iter()
            .filter(|opt| opt.is_some())
            .map(|opt| TlsCipherSuiteID(opt.unwrap().id))
            .collect();
        ja3.set_ciphers(ciphers.as_slice());

        let buf = hello.ext.unwrap_or_default();
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
        self.side_data[dir].ja3s.insert(ja3);
    }
}
