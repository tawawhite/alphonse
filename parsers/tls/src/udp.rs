use anyhow::Result;
use tls_parser::{
    parse_dtls_plaintext_records, DTLSClientHello, DTLSMessage, DTLSMessageHandshakeBody,
    DTLSPlaintext, TlsServerHelloContents,
};

use alphonse_api as api;
use api::packet::Packet;
use api::parsers::ProtocolParserTrait;
use api::session::Session;

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
        }

        let (buf, results) = match parse_dtls_plaintext_records(pkt.payload()) {
            Ok(r) => r,
            Err(_) => return Ok(()),
        };

        self.handle_dtls_parse_result(buf, &results);

        Ok(())
    }

    fn handle_dtls_parse_result(&mut self, buf: &[u8], result: &Vec<DTLSPlaintext>) {
        for plaintext in result {
            for msg in &plaintext.messages {
                match msg {
                    DTLSMessage::Handshake(handshake) => match &handshake.body {
                        DTLSMessageHandshakeBody::ClientHello(hello) => {
                            self.handle_dtls_client_hello(hello)
                        }
                        DTLSMessageHandshakeBody::Certificate(cert) => {}
                        DTLSMessageHandshakeBody::ServerHello(hello) => {
                            self.handle_dtls_server_hello(hello)
                        }
                        _ => {}
                    },
                    _ => {}
                };
            }
        }
    }

    fn handle_dtls_client_hello(&mut self, hello: &DTLSClientHello) {}

    fn handle_dtls_server_hello(&mut self, hello: &TlsServerHelloContents) {}
}
