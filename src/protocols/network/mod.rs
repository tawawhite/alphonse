use super::super::packet;
use super::error::Error;
use super::{LayerProto, NetworkProto, TransProto};

mod icmp;
mod ipv4;
mod ipv6;

pub struct Parser {
    net_type: NetworkProto,
}

impl Parser {
    pub fn new() -> Parser {
        Parser {
            net_type: NetworkProto::IPv4,
        }
    }

    pub fn net_type(&mut self, t: NetworkProto) {
        self.net_type = t;
    }

    pub fn parse(&self, pkt: &mut packet::Packet) -> Result<TransProto, Error> {
        let result = match self.net_type {
            NetworkProto::IPv4 => ipv4::parse(pkt),
            NetworkProto::IPv6 => ipv6::parse(pkt),
            NetworkProto::ICMP => icmp::parse(pkt),
            _ => Err(Error::ParserError(format!(
                "Unsupport network layer protocol, link type: {:?}",
                self.net_type
            ))),
        };

        match result {
            Ok(lp) => match lp {
                LayerProto::Transport(tp) => Ok(tp),
                _ => Err(Error::ParserError(format!(
                    "Unsupport network layer protocol, link type: {:?}",
                    lp
                ))),
            },
            Err(e) => Err(e),
        }
    }
}
