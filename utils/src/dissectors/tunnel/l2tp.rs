use nom::bytes::complete::take;
use nom::number::complete::be_u16;
use nom::IResult;

use crate::dissectors::{DissectResult, Error, Protocol};

const DATAMESSAGE: u16 = 0b0000000000000000;
const CONTROLMESSAGE: u16 = 0b1000000000000000;
const LENGTH: u16 = 0b0100000000000000;
const SEQUENCE: u16 = 0b0000100000000000;
const OFFSET: u16 = 0b0000001000000000;
const PRIORITY: u16 = 0b0000000100000000;

#[repr(u8)]
#[derive(Debug)]
enum Type {
    Data = 0,
    Control = 1,
}

#[derive(Debug)]
struct PacketType {
    _type: Type,
    length: bool,
    sequence: bool,
    offset: bool,
    priority: bool,
}

impl PacketType {
    pub fn new() -> Self {
        Self {
            _type: Type::Control,
            length: false,
            sequence: false,
            offset: false,
            priority: false,
        }
    }
}

fn l2tp_version(control: u16) -> u16 {
    control & 0x000f
}

pub fn dissect(data: &[u8]) -> IResult<&[u8], (usize, DissectResult), Error> {
    let org_len = data.len();
    let (data, control) = be_u16(data)?;

    match l2tp_version(control) {
        2 | 3 => {}
        _ => {
            return Err(nom::Err::Error(Error(
                "Unsupported or invalid L2TP version",
            )))
        }
    };

    let data = if control & LENGTH == LENGTH {
        let (data, _) = be_u16(data)?;
        data
    } else {
        let (mut data, _) = take(2usize)(data)?;
        if control & SEQUENCE == SEQUENCE {
            let (remain, _) = take(4usize)(data)?;
            data = remain
        }
        if control & OFFSET == OFFSET {
            let (remain, _) = take(2usize)(data)?;
            data = remain
        }
        if control & PRIORITY == PRIORITY {
            let (remain, _) = take(2usize)(data)?;
            data = remain
        }
        data
    };
    let (data, _) = take(4usize)(data)?;

    return Ok((
        data,
        (org_len - data.len(), DissectResult::Ok(Protocol::PPP)),
    ));
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_offset_bit_present() {
        let buf = [
            0x02, 0x02, 0x4a, 0x32, 0xd3, 0x5e, 0x00, 0x00, 0xff, 0x03, 0x00, 0x57,
        ];
        let result = dissect(&buf);
        assert!(matches!(result, Ok(_)));

        let (data, (len, protocol)) = result.unwrap();
        assert!(matches!(protocol, DissectResult::Ok(Protocol::PPP)));
        assert_eq!(data.len(), 8);
    }

    #[test]
    fn test_length_bit_present() {
        let buf = [
            0xc8, 0x02, 0x00, 0x14, 0x05, 0xf7, 0x00, 0x00, 0x00, 0x0f, 0x00, 0x02, 0x80, 0x08,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x06,
        ];
        let result = dissect(&buf);
        assert!(matches!(result, Ok(_)));

        let (data, (len, protocol)) = result.unwrap();
        assert!(matches!(protocol, DissectResult::Ok(Protocol::PPP)));
        assert_eq!(data.len(), 12);
    }

    #[test]
    fn test_sequence_bit_present() {
        let buf = [0x08, 0x02, 0x05, 0xf7, 0x00, 0x00, 0x00, 0x0f, 0x00, 0x02];
        let result = dissect(&buf);
        assert!(matches!(result, Ok(_)));

        let (data, (len, protocol)) = result.unwrap();
        assert!(matches!(protocol, DissectResult::Ok(Protocol::PPP)));
        assert_eq!(data.len(), 0);
    }
}
