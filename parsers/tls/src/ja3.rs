//! This module is directly copied from ja3-rs crate (https://github.com/jabedude/ja3-rs)
//! The reason why we don't use the crate directly are listed below:
//!
//! The ja3-rs crate doesn't provide a public api to parse a existing TlsClientHelloContents or
//! TlsServerHelloContents struct. Alphonse already decodes a tls packet and its client/server
//! hello. ja3-rs's current api have to dissect the packet again and parse the tls packet again
//! this is redundant calculation cost.

use tls_parser::{NamedGroup, TlsCipherSuiteID, TlsExtension, TlsExtensionType};

const GREASE: [u16; 16] = [
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
    0xcaca, 0xdada, 0xeaea, 0xfafa,
];

#[derive(Clone, Debug, Default, Hash, PartialEq, Eq)]
pub struct Ja3 {
    ver: u16,
    ciphers: Vec<u16>,
    exts: Vec<u16>,
    supported_groups: Vec<u16>,
    ec_points: Vec<u8>,
}

impl Ja3 {
    pub fn set_tls_version(&mut self, ver: u16) {
        self.ver = ver;
    }

    pub fn set_ciphers(&mut self, ciphers: &[TlsCipherSuiteID]) {
        self.ciphers = ciphers.iter().map(|x| u16::from(*x)).collect();
    }

    pub fn set_extension_type(&mut self, ext: &TlsExtension) {
        let ext_val = u16::from(TlsExtensionType::from(ext));
        if GREASE.contains(&ext_val) {
            return;
        }

        self.exts.push(ext_val);
    }

    pub fn set_supported_groups(&mut self, curves: &[NamedGroup]) {
        for curve in curves {
            if !GREASE.contains(&curve.0) {
                self.supported_groups.push(curve.0)
            }
        }
    }

    pub fn set_ec_points(&mut self, points: &[u8]) {
        for point in points {
            self.ec_points.push(*point);
        }
    }

    pub fn string(&mut self) -> String {
        let mut str = String::new();

        str.push_str(&format!("{},", self.ver));

        for cipher in &self.ciphers {
            str.push_str(&format!("{}-", cipher));
        }
        str.pop();
        str.push(',');

        for ext in &self.exts {
            str.push_str(&format!("{}-", ext));
        }
        str.pop();
        str.push(',');

        for group in &self.supported_groups {
            str.push_str(&format!("{}-", group));
        }
        str.pop();
        str.push(',');

        for point in &self.ec_points {
            str.push_str(&format!("{}-", point));
        }
        str.pop();

        str
    }
}
