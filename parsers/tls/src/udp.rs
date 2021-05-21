use anyhow::Result;
use tls_parser::{
    parse_dtls_plaintext_records, parse_tls_extensions, DTLSClientHello, DTLSMessage,
    DTLSMessageHandshakeBody, DTLSPlaintext, TlsExtension,
};

use alphonse_api as api;
use api::packet::{Direction, Packet};
use api::plugins::parsers::ProtocolParserTrait;
use api::plugins::Plugin;
use api::session::Session;

use crate::ja3::Ja3;
use crate::Processor;

impl Processor {
    pub fn parse_udp_pkt(&mut self, pkt: &dyn Packet, ses: &mut Session) -> Result<()> {
        if !self.is_classified() {
            // If this session is already classified as this protocol, skip
            self.classified_as_this_protocol()?;
            ses.add_protocol(&self.name());
        }

        let (_, results) = match parse_dtls_plaintext_records(pkt.payload()) {
            Ok(r) => r,
            Err(_) => return Ok(()),
        };

        self.handle_dtls_parse_result(pkt.direction(), &results);

        Ok(())
    }

    fn handle_dtls_parse_result(&mut self, dir: Direction, result: &Vec<DTLSPlaintext>) {
        for plaintext in result {
            for msg in &plaintext.messages {
                match msg {
                    DTLSMessage::Handshake(handshake) => match &handshake.body {
                        DTLSMessageHandshakeBody::ClientHello(hello) => {
                            self.handle_dtls_client_hello(dir, hello)
                        }
                        DTLSMessageHandshakeBody::Certificate(cert) => {
                            self.handle_certificate(cert)
                        }
                        DTLSMessageHandshakeBody::ServerHello(hello) => {
                            self.handle_server_hello(dir, hello)
                        }
                        _ => {}
                    },
                    _ => {}
                };
            }
        }
    }

    fn handle_dtls_client_hello(&mut self, dir: Direction, hello: &DTLSClientHello) {
        let dir = dir as u8 as usize;
        let mut ja3 = Ja3::default();
        match hello.session_id {
            Some(id) => {
                self.side_data[dir].session_ids.insert(hex::encode(id));
            }
            None => {}
        };

        ja3.set_tls_version(u16::from(hello.version));

        ja3.set_ciphers(&hello.ciphers);

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
