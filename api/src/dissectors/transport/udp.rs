use super::{Error, Layer, Protocol};

#[derive(Default)]
pub struct Dissector;

impl super::Dissector for Dissector {
    #[inline]
    fn dissect(&self, buf: &[u8], offset: u16) -> Result<Option<Layer>, Error> {
        if buf.len() < 8 {
            // 如果报文内容长度小于IP报文最短长度(IP协议头长度)
            // 数据包有错误
            return Err(Error::CorruptPacket(format!(
                "Corrupted UDP packet, packet too short ({} bytes)",
                buf.len()
            )));
        }

        let src_port = ((buf[0] as u16) << 8) + buf[1] as u16;
        let dst_port = ((buf[2] as u16) << 8) + buf[3] as u16;
        if src_port == 1701 && dst_port == 1701 {
            let layer = Layer {
                protocol: Protocol::L2TP,
                offset: offset + 8,
            };
            return Ok(Some(layer));
        }

        let layer = Layer {
            protocol: Protocol::APPLICATION,
            offset: offset + 8,
        };

        Ok(Some(layer))
    }
}

#[cfg(test)]
mod test {
    use crate::dissectors::Dissector as D;

    use super::*;

    #[test]
    fn test_ok() {
        let buf = [
            0xf4, 0x63, 0x00, 0x35, 0x00, 0x28, 0x93, 0xab, 0xe0, 0x39, 0x01, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x77, 0x77, 0x77, 0x06, 0x67, 0x69, 0x74,
            0x68, 0x75, 0x62, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01,
        ];
        let dissector = Dissector::default();
        let result = dissector.dissect(&buf, 0);
        assert!(matches!(result, Ok(_)));

        let layer = result.unwrap();
        assert!(matches!(layer, Some(_)));
        assert!(matches!(layer.unwrap().protocol, Protocol::APPLICATION));
        assert_eq!(layer.unwrap().offset, 8);
    }

    #[test]
    fn test_pkt_too_short() {
        let buf = [0xf4];
        let dissector = Dissector::default();
        let result = dissector.dissect(&buf, 0);
        assert!(matches!(result, Err(_)));

        let err = result.unwrap_err();
        assert!(matches!(err, Error::CorruptPacket(_)));
    }

    #[test]
    fn l2tp() {
        let buf = [0x06, 0xa5, 0x06, 0xa5, 0x00, 0x54, 0x00, 0x00];
        let dissector = Dissector::default();
        let result = dissector.dissect(&buf, 0);
        assert!(matches!(result, Ok(_)));

        let layer = result.unwrap();
        assert!(matches!(layer, Some(_)));
        assert!(matches!(layer.unwrap().protocol, Protocol::L2TP));
        assert_eq!(layer.unwrap().offset, 8);
    }
}
