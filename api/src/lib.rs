#[macro_use]
extern crate bitflags;
#[macro_use]
extern crate enum_primitive_derive;

pub static API_VERSION: &str = env!("CARGO_PKG_VERSION");
pub static RUSTC_VERSION: &str = env!("RUSTC_VERSION");

pub mod classifiers;
pub mod packet;
pub mod parsers;
pub mod session;
pub mod utils;
