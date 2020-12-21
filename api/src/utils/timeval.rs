use std::any::TypeId;
use std::marker::PhantomData;
use std::ops::{Deref, DerefMut};

use libc::timeval;
use serde::{Serialize, Serializer};

pub mod precision {
    /// TimeVal serialize precision
    pub trait Precision {}
    pub struct Second {}
    impl Precision for Second {}
    pub struct Millisecond {}
    impl Precision for Millisecond {}
}

/// Wrapper type for libc::timeval
pub struct TimeVal<P: 'static + precision::Precision> {
    tv: timeval,
    percision: PhantomData<&'static P>,
}

impl<P: precision::Precision> TimeVal<P> {
    pub fn new(tv: timeval) -> Self {
        TimeVal {
            tv,
            percision: PhantomData,
        }
    }
}

impl<P: precision::Precision> Serialize for TimeVal<P> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if TypeId::of::<P>() == TypeId::of::<precision::Millisecond>() {
            serializer.serialize_u64(self.tv_sec as u64 * 1000 + self.tv_usec as u64 / 1000)
        } else {
            serializer.serialize_u64(self.tv_sec as u64 + self.tv_usec as u64 / 1000000)
        }
    }
}

impl<P: precision::Precision> Deref for TimeVal<P> {
    type Target = libc::timeval;

    fn deref(&self) -> &Self::Target {
        &self.tv
    }
}

impl<P: precision::Precision> DerefMut for TimeVal<P> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.tv
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use serde_json;

    #[test]
    fn serialize() {
        let tv = TimeVal::<precision::Second>::new(timeval {
            tv_sec: 0,
            tv_usec: 0,
        });
        let s = serde_json::to_string_pretty(&tv).unwrap();
        assert_eq!(s, "0");

        let tv = TimeVal::<precision::Millisecond>::new(timeval {
            tv_sec: 1608011935,
            tv_usec: 807924,
        });
        let s = serde_json::to_string_pretty(&tv).unwrap();
        assert_eq!(s, "1608011935807");

        let tv = TimeVal::<precision::Second>::new(timeval {
            tv_sec: 1608011935,
            tv_usec: 807924,
        });
        let s = serde_json::to_string_pretty(&tv).unwrap();
        assert_eq!(s, "1608011935");
    }
}
