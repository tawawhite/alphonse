#![feature(test)]

extern crate test;

extern crate twox_hash;

use std::hash::Hash;

use test::Bencher;

use alphonse_api as api;
use api::packet::PacketHashKey;

#[bench]
fn xxh3_hash(b: &mut Bencher) {
    let key = PacketHashKey::default();
    b.iter(|| {
        let mut hasher = twox_hash::Xxh3Hash64::with_seed(0);
        key.hash(&mut hasher);
    });
}

#[bench]
fn fnv_hash(b: &mut Bencher) {
    let key = PacketHashKey::default();
    b.iter(|| {
        let mut hasher = fnv::FnvHasher::with_key(0);
        key.hash(&mut hasher);
    });
}

#[bench]
fn sip_hash(b: &mut Bencher) {
    let key = PacketHashKey::default();
    b.iter(|| {
        let mut hasher = std::collections::hash_map::DefaultHasher::default();
        key.hash(&mut hasher);
    });
}
