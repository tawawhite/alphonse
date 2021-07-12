use anyhow::Result;
use serde::Serialize;
use std::io::{self, Write};

#[derive(Clone, Copy, Debug, Default)]
struct ByteCount(usize);

impl Write for ByteCount {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0 += buf.len();
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Get serialized json size(bytes) without producing a heap allocated json string
///
/// https://github.com/serde-rs/json/issues/784
#[inline]
pub fn get_ser_json_size<T: Serialize>(value: &T) -> Result<usize> {
    let mut ser = serde_json::Serializer::new(ByteCount(0));
    value.serialize(&mut ser)?;
    Ok(ser.into_inner().0)
}
