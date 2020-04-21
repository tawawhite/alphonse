use super::ParserError;
use super::{Layer, SimpleProtocolParser};

use super::super::link;
use super::Protocol;

pub struct Parser {}
impl SimpleProtocolParser for Parser {
    fn parse(buf: &[u8]) -> Result<Layer, ParserError> {
        let mut layer = Layer {
            protocol: Protocol::default(),
            offset: 4 + 2,
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
                return Err(ParserError::UnsupportProtocol(format!(
                    "Unsupport protocol, ether type: {}",
                    etype
                )))
            }
        };

        Ok(layer)
    }
}
