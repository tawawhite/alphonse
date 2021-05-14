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
    string: String,
    exts: String,
    supported_groups: String,
    ec_points: String,
}

impl Ja3 {
    pub fn set_tls_version(&mut self, ver: u16) {
        self.string.push_str(&format!("{},", ver));
    }

    pub fn set_ciphers(&mut self, ciphers: &[TlsCipherSuiteID]) {
        for cipher in ciphers {
            self.string.push_str(&format!("{}-", cipher));
        }
        self.string.pop();
        self.string.push(',');
    }

    pub fn set_extension_type(&mut self, ext: &TlsExtension) {
        let ext_val = u16::from(TlsExtensionType::from(ext));
        if GREASE.contains(&ext_val) {
            return;
        }

        self.exts.push_str(&format!("{}-", ext_val));
    }

    pub fn set_supported_groups(&mut self, curves: &[NamedGroup]) {
        for curve in curves {
            if !GREASE.contains(&curve.0) {
                self.supported_groups.push_str(&format!("{}-", curve.0));
            }
        }
    }

    pub fn set_ec_points(&mut self, points: &[u8]) {
        for point in points {
            self.ec_points.push_str(&format!("{}-", point));
        }
    }

    pub fn hash(&mut self) -> Option<md5::Digest> {
        self.exts.pop();
        self.supported_groups.pop();
        self.ec_points.pop();
        self.string = format!(
            "{}{},{},{}",
            self.string, self.exts, self.supported_groups, self.ec_points
        );
        if self.string.is_empty() {
            None
        } else {
            Some(md5::compute(self.string.as_bytes()))
        }
    }
}
