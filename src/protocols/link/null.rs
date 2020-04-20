use super::error::ParserError;
use super::{Layer, Protocol, SimpleProtocolParser};

pub struct Parser {}

impl SimpleProtocolParser for Parser {
    #[inline]
    fn parse(buf: &[u8]) -> Result<(Layer, u16), ParserError> {
        if buf.len() < 4 {
            return Err(ParserError::CorruptPacket(format!(
                "The packet is corrupted, packet too short ({} bytes)",
                buf.len()
            )));
        }

        let mut layer = Layer {
            protocol: Protocol::default(),
            offset: 0,
        };
        let next_proto_offset = 4;
        let link_type = buf[0];

        // from https://www.tcpdump.org/linktypes.html
        match link_type {
            2 => layer.protocol = Protocol::IPV4,
            // OSI packets
            7 => {
                return Err(ParserError::UnsupportProtocol(format!(
                    "Does not support OSI packet"
                )))
            }
            // IPX packets
            23 => {
                return Err(ParserError::UnsupportProtocol(format!(
                    "Does not support IPX packet"
                )))
            }
            24 | 28 | 30 => layer.protocol = Protocol::IPV6,
            _ => {
                return Err(ParserError::UnsupportProtocol(format!(
                    "Unknown protocol {}",
                    buf[0],
                )))
            }
        }

        Ok((layer, next_proto_offset))
    }
}
