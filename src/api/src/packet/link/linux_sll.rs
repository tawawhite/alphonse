use super::{packet, Error};

#[inline]
pub fn parse(pkt: &mut packet::Packet, mut depth: usize) -> Result<(), Error> {
    // calculate next layers start byte position
    pkt.layers[depth + 1].start_pos = pkt.layers[depth].start_pos + 2;

    let pos = pkt.layers[depth + 1].start_pos;

    if pkt.data()[pos + 0] == 0 && pkt.data()[pos + 1] <= 4 {
        depth = depth + 1;
        return parse(pkt, depth);
    }

    Ok(())
}
