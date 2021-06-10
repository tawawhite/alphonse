use super::{Error, Layer};

#[derive(Default)]
pub struct Dissector {}

impl super::Dissector for Dissector {
    #[inline]
    fn dissect(&self, _buf: &[u8], _offset: u16) -> Result<Option<Layer>, Error> {
        return Err(Error::UnsupportProtocol(format!(
            "Unsupport protocol: ICMP"
        )));
    }
}
