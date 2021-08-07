use num_traits::FromPrimitive;

use super::super::link;
use super::{Error, Layer, Protocol};

#[derive(Default)]
pub struct Dissector {}

impl super::Dissector for Dissector {
    fn dissect(&self, buf: &[u8], offset: u16) -> Result<Option<Layer>, Error> {
        let mut layer = Layer {
            protocol: Protocol::default(),
            offset: offset + 4,
        };

        let etype = (buf[2] as u16) << 8 | buf[3] as u16;
        layer.protocol = match link::ethernet::EtherType::from_u16(etype) {
            None => Protocol::UNKNOWN,
            Some(proto) => proto.into(),
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
        let buf = [0xc2, 0x00, 0x08, 0x00];
        let dissector = Dissector::default();
        assert!(
            matches!(dissector.dissect(&buf, 0), Ok(Some(layer)) if layer.protocol == Protocol::IPV4 && layer.offset == 4)
        );
    }

    #[test]
    fn test_err_unsupport_protocol() {
        let buf = [0xc2, 0x00, 0x08, 0x01];
        let dissector = Dissector::default();
        let result = dissector.dissect(&buf, 0);
        let err = result.unwrap_err();
        assert!(matches!(err, Error::UnsupportProtocol(_)));
    }
}
