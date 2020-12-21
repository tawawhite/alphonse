#[macro_use]
extern crate enum_primitive_derive;
extern crate num_traits;
extern crate serde;

pub static API_VERSION: &str = env!("CARGO_PKG_VERSION");
pub static RUSTC_VERSION: &str = env!("RUSTC_VERSION");

pub mod classifiers;
pub mod packet;
pub mod parsers;
pub mod session;
pub mod utils;
