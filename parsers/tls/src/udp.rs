use anyhow::Result;
use tls_parser::{
    parse_dtls_plaintext_records, parse_tls_extensions, DTLSClientHello, DTLSMessage,
    DTLSMessageHandshakeBody, DTLSPlaintext, TlsExtension,
};

use alphonse_api as api;
use api::packet::Packet;
use api::parsers::ProtocolParserTrait;
use api::session::Session;

use crate::ja3::Ja3;
use crate::Processor;

impl<'a> Processor<'static> {
    pub fn parse_udp_pkt(&mut self, pkt: &dyn Packet, ses: &mut Session) -> Result<()> {
        if !self.is_classified() {
            let (buf, results) = match parse_dtls_plaintext_records(pkt.payload()) {
                Ok(r) => r,
                Err(_) => return Ok(()),
            };

            // If this session is already classified as this protocol, skip
            self.classified_as_this_protocol()?;
            ses.add_protocol(&self.name());

            self.handle_dtls_parse_result(buf, &results);
            return Ok(());
        }

        let (buf, results) = match parse_dtls_plaintext_records(pkt.payload()) {
            Ok(r) => r,
            Err(_) => return Ok(()),
        };

        self.handle_dtls_parse_result(buf, &results);

        Ok(())
    }

    fn handle_dtls_parse_result(&mut self, buf: &[u8], result: &Vec<DTLSPlaintext>) {
        let mut cnt = 0;
        for plaintext in result {
            cnt += 1;
            println!("cnt: {}", cnt);
            for msg in &plaintext.messages {
                match msg {
                    DTLSMessage::Handshake(handshake) => match &handshake.body {
                        DTLSMessageHandshakeBody::ClientHello(hello) => {
                            self.handle_dtls_client_hello(hello)
                        }
                        DTLSMessageHandshakeBody::Certificate(cert) => {
                            self.handle_certificate(cert)
                        }
                        DTLSMessageHandshakeBody::ServerHello(hello) => {
                            self.handle_server_hello(hello)
                        }
                        _ => {}
                    },
                    _ => {}
                };
            }
        }
    }

    fn handle_dtls_client_hello(&mut self, hello: &DTLSClientHello) {
        let mut ja3 = Ja3::default();
        match hello.session_id {
            Some(id) => {
                self.client_session_ids.insert(hex::encode(id));
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
        self.client_ja3s.insert(ja3);
    }
}
