use super::{packet, Error};

pub fn parse(pkt: &packet::Packet) -> Result<(), Error> {
    if pkt.len() < 4 {
        return Err(Error::CorruptPacket);
    }

    match pkt.data()[0] {
        2 => {}
        7 => {}
        23 => {}
        24 | 28 | 30 => {}
        _ => {}
    }
    Ok(())
}
