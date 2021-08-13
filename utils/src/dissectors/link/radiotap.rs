use super::{packet, Error};

pub fn parse(pkt: &mut packet::Packet, mut depth: usize) -> Result<(), Error> {
    let pos = pkt.layers[depth].start_pos;
    if pkt.data()[pos] != 0 || pkt.len_of_layer(depth) < 36 {
        return Err(Error::UnknownProtocol);
    }

    let mut header_length =
        ((pkt.data()[pos + 2] as u16) << 8 | pkt.data()[pos + 3] as u16) as usize;
    if header_length + 24 + 8 >= pkt.len_of_layer(depth) {
        return Err(Error::UnknownProtocol);
    }

    if pkt.data()[pos + header_length] != 8 {
        return Err(Error::UnknownProtocol);
    }

    header_length = header_length + 24 + 3;
    if pkt.data()[pos + header_length] != 0
        || pkt.data()[pos + header_length + 1] != 0
        || pkt.data()[pos + header_length + 2] != 0
    {
        return Err(Error::UnknownProtocol);
    }

    header_length = header_length + 3;
    let proto_type = ((pkt.data()[pos + header_length] as u16) << 8
        | pkt.data()[pos + header_length + 1] as u16) as usize;
    header_length = header_length + 2;

    Ok(())
}
