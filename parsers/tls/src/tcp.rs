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
        let mut _buf = vec![];
        let mut buf = if self.side_data[dir].remained.len() > 0 {
            // If there are bytes left from last packet, prepend them to current packet's payloads
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
                _ => {}
            };
        }
    }
}
