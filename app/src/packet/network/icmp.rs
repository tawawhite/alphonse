use super::{Error, Layer, SimpleProtocolParser};

#[derive(Default)]
pub struct Parser {}

impl SimpleProtocolParser for Parser {
    #[inline]
    fn parse(&self, _buf: &[u8], _offset: u16) -> Result<Option<Layer>, Error> {
        return Err(Error::UnsupportProtocol(format!(
            "Unsupport protocol: ICMP"
        )));
    }
}
