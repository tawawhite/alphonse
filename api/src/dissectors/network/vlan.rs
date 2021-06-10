use super::{Error, Layer};

use super::super::link;
use super::Protocol;

#[derive(Default)]
pub struct Dissector {}

impl super::Dissector for Dissector {
    fn dissect(&self, buf: &[u8], offset: u16) -> Result<Option<Layer>, Error> {
        let mut layer = Layer {
            protocol: Protocol::default(),
            offset: offset + 4 + 2,
        };

        let etype = (buf[0] as u16) << 8 | buf[1] as u16;
        match etype {
            link::ethernet::IPV4 => layer.protocol = Protocol::IPV4,
            link::ethernet::IPV6 => layer.protocol = Protocol::IPV6,
            link::ethernet::PPP => layer.protocol = Protocol::PPP,
            link::ethernet::MPLSUC => layer.protocol = Protocol::MPLS,
            link::ethernet::PPPOES => layer.protocol = Protocol::PPPOE,
            link::ethernet::VLAN => layer.protocol = Protocol::VLAN,
            _ => {
                return Err(Error::UnsupportProtocol(format!(
                    "Unsupport protocol, ether type: {}",
                    etype
                )))
            }
        };

        Ok(Some(layer))
    }
}

#[cfg(test)]
mod tests {
    use crate::dissectors::Dissector as D;

    use super::*;

    #[test]
    fn test_ok() {
        let buf = [0x08, 0x00, 0xc2, 0x00, 0x00, 0x00];
        let dissector = Dissector::default();
        assert!(matches!(dissector.dissect(&buf, 0), Ok(_)));
    }

    #[test]
    fn test_err_unsupport_protocol() {
        let buf = [0x08, 0x01, 0xc2, 0x00, 0x00, 0x00];
        let dissector = Dissector::default();
        let result = dissector.dissect(&buf, 0);
        let err = result.unwrap_err();
        assert!(matches!(err, Error::UnsupportProtocol(_)));
    }
}
