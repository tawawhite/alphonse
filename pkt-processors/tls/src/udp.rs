use anyhow::Result;
use tls_parser::{
    parse_dtls_plaintext_records, DTLSMessage, DTLSMessageHandshakeBody, DTLSPlaintext,
};

use alphonse_api as api;
use api::packet::{Direction, Packet};
use api::plugins::Plugin;
use api::session::{ProtocolLayer, Session};

use crate::TlsProcessor;

impl TlsProcessor {
    pub fn parse_udp_pkt(&mut self, pkt: &dyn Packet, ses: &mut Session) -> Result<()> {
        if !self.classified {
            // If this session is already classified as this protocol, skip
            self.classified = true;
            ses.add_protocol(&self.name(), ProtocolLayer::Application);
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
                            self.handle_client_hello(dir, hello)
                        }
                        DTLSMessageHandshakeBody::Certificate(cert) => {
                            self.handle_certificate(cert)
                        }
                        DTLSMessageHandshakeBody::ServerHello(hello) => {
                            self.handle_server_hello(dir, hello)
                        }
                        _ => {}
                    },
                    DTLSMessage::ChangeCipherSpec => self.has_change_cipher_spec = true,
                    _ => {}
                };
            }
        }
    }
}
