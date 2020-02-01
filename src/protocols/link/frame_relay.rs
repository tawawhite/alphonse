//! From what I understand, Frame Relay protocol is derived from the HDLC protocol
//! The relatinship is like this:
//! IBM's SDLC --> HDLC ----> X.25 LAPB
//!                     |\
//!                     | --> V.42 LAPM
//!                     |\
//!                     | --> Frame Relay LAPF
//!                      \
//!                       --> ISDN LAPD
//! HDLC protocol has two (maybe more) versions: ISO standard and Cisco's standard
//! Within ISO's standard there is no protocol type in the protocol, but Cisco's does contain this field
//! So what we actually doing here is parsing Cisco's HDLC protocol and its deriving protocols
//! And in this specific case is Frame Relay protocol

use super::super::network;
use super::{packet, Error};

#[inline]
pub fn parse(pkt: &mut packet::Packet, depth: usize) -> Result<packet::LayerType, Error> {
    if pkt.len_of_layer(depth) < 4 {
        return Err(Error::CorruptPacket);
    }

    // calculate next layers start byte position
    pkt.layers[depth + 1].start_pos = pkt.layers[depth].start_pos + 4;

    let pos = pkt.layers[depth].start_pos;
    let protocol_type = (pkt.data()[pos + 2] as u16) << 8 | pkt.data()[pos + 3] as u16;
    if protocol_type == 0x03cc {
        return Ok(packet::LayerType::Network(network::NetworkType::IPV4));
    }

    Ok(())
}
