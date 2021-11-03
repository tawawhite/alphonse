use anyhow::Result;
use tls_parser::{
    parse_tls_plaintext, Err as TlsErr, TlsMessage, TlsMessageHandshake, TlsPlaintext,
};

use alphonse_api as api;
use api::packet::{Direction, Packet};
use api::session::{ProtocolLayer, Session};

use crate::TlsProcessor;

impl TlsProcessor {
    pub fn parse_tcp_pkt(&mut self, pkt: &dyn Packet, ses: &mut Session) -> Result<()> {
        if !self.classified {
            // If this session is already classified as this protocol, skip
            self.classified = true;
            ses.add_protocol(&"tls", ProtocolLayer::Application);
        }

        let dir = pkt.direction() as u8 as usize;
        if self.tcp_reorder[dir].full() {
            let pkts = self.tcp_reorder[dir].get_interval_pkts();
            self.reassemble_and_parse(pkts, pkt.direction());
        }

        self.tcp_reorder[dir].insert_and_reorder(pkt.clone_box());

        Ok(())
    }

    pub fn reassemble_and_parse(&mut self, pkts: Vec<Box<dyn Packet>>, dir: Direction) {
        let payloads = pkts
            .iter()
            .map(|p| p.payload())
            .collect::<Vec<_>>()
            .join(&[] as &[u8]);

        let mut payloads: &[u8] = &payloads;
        while !payloads.is_empty() {
            let (b, result) = match parse_tls_plaintext(&payloads) {
                Ok(r) => r,
                Err(TlsErr::Incomplete(_)) => {
                    let dir = dir as usize;
                    self.buffer[dir].extend_from_slice(&payloads);
                    return;
                }
                _ => return,
            };

            self.handle_tls_parse_result(dir, result);
            payloads = b;
        }

        let dir = dir as usize;
        self.buffer[dir] = payloads.to_vec();
    }

    fn handle_tls_parse_result(&mut self, dir: Direction, result: TlsPlaintext) {
        for msg in &result.msg {
            match msg {
                TlsMessage::Handshake(handshake) => {
                    match handshake {
                        TlsMessageHandshake::ClientHello(hello) => {
                            self.handle_client_hello(dir, hello)
                        }
                        TlsMessageHandshake::Certificate(cert) => {
                            self.handle_certificate(cert);
                        }
                        TlsMessageHandshake::ServerHello(hello) => {
                            self.handle_server_hello(dir, hello);
                        }
                        TlsMessageHandshake::ServerKeyExchange(_) => {}
                        TlsMessageHandshake::ServerHelloV13Draft18(_) => {
                            todo!("process tls 1.3 server hello(draft 18)");
                        }
                        TlsMessageHandshake::HelloRetryRequest(_) => {
                            todo!("process tls 1.3 server hello retry request");
                        }
                        _ => {}
                    };
                }
                TlsMessage::ChangeCipherSpec => self.has_change_cipher_spec = true,
                _ => {}
            };
        }
    }
}
