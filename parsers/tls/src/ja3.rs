//! This module is directly copied from ja3-rs crate (https://github.com/jabedude/ja3-rs)
//! The reason why we don't use the crate directly are listed below:
//!
//! The ja3-rs crate doesn't provide a public api to parse a existing TlsClientHelloContents or
//! TlsServerHelloContents struct. Alphonse already decodes a tls packet and its client/server
//! hello. ja3-rs's current api have to dissect the packet again and parse the tls packet again
//! this is redundant calculation cost.

use tls_parser::{
    parse_tls_extensions, parse_tls_plaintext, TlsExtension, TlsExtensionType, TlsMessage,
    TlsMessageHandshake, TlsRecordType,
};

const GREASE: [u16; 16] = [
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
    0xcaca, 0xdada, 0xeaea, 0xfafa,
];

#[derive(Clone, Debug, Default)]
pub struct Ja3 {
    string: String,
}

impl Ja3 {
    pub fn set_tls_version(&mut self, ver: u16) {
        self.string.push_str(&format!("{},", ver));
    }

    pub fn set_ciphers(&mut self, ciphers: &Vec<u16>) {
        for cipher in ciphers {
            self.string.push_str(&format!("{}-", cipher));
        }
        self.string.pop();
        self.string.push(',');
    }
}

fn process_extensions(extensions: &[u8]) -> Option<String> {
    let mut ja3_exts = String::new();
    let mut supported_groups = String::new();
    let mut ec_points = String::new();
    let (_, exts) = parse_tls_extensions(extensions).unwrap();
    for extension in exts {
        let ext_val = u16::from(TlsExtensionType::from(&extension));
        if GREASE.contains(&ext_val) {
            continue;
        }
        ja3_exts.push_str(&format!("{}-", ext_val));
        match extension {
            TlsExtension::EllipticCurves(curves) => {
                for curve in curves {
                    if !GREASE.contains(&curve.0) {
                        supported_groups.push_str(&format!("{}-", curve.0));
                    }
                }
            }
            TlsExtension::EcPointFormats(points) => {
                for point in points {
                    ec_points.push_str(&format!("{}-", point));
                }
            }
            _ => {}
        }
    }
    ja3_exts.pop();
    supported_groups.pop();
    ec_points.pop();
    let ret = format!("{},{},{}", ja3_exts, supported_groups, ec_points);
    Some(ret)
}

fn ja3_string_client_hello(packet: &[u8]) -> Option<String> {
    let mut ja3_string = String::new();
    let res = parse_tls_plaintext(packet);
    match res {
        Ok((rem, record)) => {
            if record.hdr.record_type != TlsRecordType::Handshake {
                return None;
            }
            for rec in record.msg {
                if let TlsMessage::Handshake(handshake) = rec {
                    if let TlsMessageHandshake::ClientHello(contents) = handshake {
                        ja3_string.push_str(&format!("{},", u16::from(contents.version)));
                        for cipher in contents.ciphers {
                            if !GREASE.contains(&cipher) {
                                ja3_string.push_str(&format!("{}-", u16::from(cipher)));
                            }
                        }
                        ja3_string.pop();
                        ja3_string.push(',');
                        if let Some(extensions) = contents.ext {
                            let ext = process_extensions(extensions).unwrap();
                            ja3_string.push_str(&ext);
                        }
                    }
                }
            }
        }
        _ => {
            return None;
        }
    }

    println!("ja3_string: {}", ja3_string);
    Some(ja3_string)
}
