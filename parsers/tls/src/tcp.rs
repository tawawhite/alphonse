use anyhow::Result;
use tls_parser::{
    parse_tls_extensions, parse_tls_plaintext, TlsClientHelloContents, TlsExtension, TlsMessage,
    TlsMessageHandshake, TlsPlaintext,
};

use alphonse_api as api;
use api::packet::Packet;
use api::parsers::ProtocolParserTrait;
use api::session::Session;

use crate::Processor;

impl<'a> Processor<'static> {
    pub fn parse_tcp_pkt(&mut self, pkt: &dyn Packet, ses: &mut Session) -> Result<()> {
        if !self.is_classified() {
            let (buf, result) = match parse_tls_plaintext(pkt.payload()) {
                Ok(r) => r,
                Err(_) => return Ok(()),
            };

            // If this session is already classified as this protocol, skip
            self.classified_as_this_protocol()?;
            ses.add_protocol(&self.name());

            self.handle_tls_parse_result(buf, result);
        }

        let (buf, result) = match parse_tls_plaintext(pkt.payload()) {
            Ok(r) => r,
            Err(_) => return Ok(()),
        };

        self.handle_tls_parse_result(buf, result);

        Ok(())
    }

    fn handle_tls_parse_result(&mut self, buf: &[u8], result: TlsPlaintext) {
        for msg in &result.msg {
            match msg {
                TlsMessage::Handshake(handshake) => match handshake {
                    TlsMessageHandshake::ClientHello(hello) => self.handle_tls_client_hello(hello),
                    TlsMessageHandshake::Certificate(cert) => self.handle_certificate(cert),
                    TlsMessageHandshake::ServerHello(hello) => self.handle_server_hello(hello),
                    _ => {}
                },
                _ => {}
            };
        }
    }

    fn handle_tls_client_hello(&mut self, hello: &TlsClientHelloContents) {
        match hello.session_id {
            Some(id) => {
                self.client_session_ids.insert(hex::encode(id));
            }
            None => {}
        };

        let version = hello.get_version();
        let buf = hello.ext.unwrap_or_default();
        let (_, exts) = parse_tls_extensions(buf).unwrap_or_default();
        for ext in &exts {
            match ext {
                TlsExtension::SNI(names) => {
                    for (_, name) in names {
                        match std::str::from_utf8(name) {
                            Ok(name) => {
                                println!("{}", name);
                                self.hostnames.insert(name.to_string());
                            }
                            Err(_) => {}
                        }
                    }
                }
                TlsExtension::EllipticCurves(groups) => {}
                TlsExtension::EcPointFormats(formates) => {}
                _ => {}
            }
        }
    }
}
