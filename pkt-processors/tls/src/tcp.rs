use anyhow::Result;
use tls_parser::{
    parse_tls_plaintext, Err as TlsErr, TlsMessage, TlsMessageHandshake, TlsPlaintext,
};

use alphonse_api as api;
use api::packet::{Direction, Packet};
use api::plugins::Plugin;
use api::session::{ProtocolLayer, Session};

use crate::TlsProcessor;

impl TlsProcessor {
    pub fn parse_tcp_pkt(&mut self, pkt: &dyn Packet, ses: &mut Session) -> Result<()> {
        if !self.classified {
            // If this session is already classified as this protocol, skip
            self.classified = true;
            ses.add_protocol(&self.name(), ProtocolLayer::Application);
        }

        let dir = pkt.direction() as u8 as usize;
        if self.tcp_reorder[dir].full() {
            let pkts = self.tcp_reorder[dir].get_interval_pkts();
            self.reassemble_and_parse(pkts);
        }

        self.tcp_reorder[dir].insert_and_reorder(pkt.clone_box());

        Ok(())
    }

    pub fn reassemble_and_parse(&mut self, pkts: Vec<Box<dyn Packet>>) {
        for pkt in pkts {
            let dir = pkt.direction() as u8 as usize;
            let mut _buf = vec![];
            let mut buf = if self.buffer[dir].len() > 0 {
                if self.buffer[dir].len() + pkt.payload().len() > 16_777_216 {
                    // Tls record overflow
                    return;
                }

                // If there are bytes left from last packet, prepend them to current packet's payloads
                _buf = self.buffer[dir].split_off(0);
                _buf.extend_from_slice(pkt.payload());
                _buf.as_slice()
            } else {
                pkt.payload()
            };

            while !buf.is_empty() {
                let (b, result) = match parse_tls_plaintext(buf) {
                    Ok(r) => r,
                    Err(TlsErr::Incomplete(_)) => {
                        self.buffer[dir].extend_from_slice(buf);
                        break;
                    }
                    _ => break,
                };

                self.handle_tls_parse_result(pkt.direction(), result);
                buf = b;
            }
        }
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
