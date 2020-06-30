use super::{Error, Layer, SimpleProtocolParser};

use super::super::link;
use super::Protocol;

pub struct Parser {}
impl SimpleProtocolParser for Parser {
    fn parse(buf: &[u8], offset: u16) -> Result<Layer, Error> {
        let mut layer = Layer {
            protocol: Protocol::default(),
            offset: offset + 4 + 2,
        };

        let etype = (buf[0] as u16) << 8 | buf[0] as u16;
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

        Ok(layer)
    }
}
