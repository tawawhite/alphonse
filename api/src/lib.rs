#[macro_use]
extern crate bitflags;
#[macro_use]
extern crate enum_primitive_derive;
#[macro_use]
extern crate strum;

#[cfg(feature = "use-tcmalloc")]
use tcmalloc::TCMalloc;

#[cfg(feature = "use-tcmalloc")]
#[global_allocator]
static GLOBAL: TCMalloc = TCMalloc;

pub static API_VERSION: &str = env!("CARGO_PKG_VERSION");
pub static RUSTC_VERSION: &str = env!("RUSTC_VERSION");

pub use hyperscan;

pub mod classifiers;
pub mod config;
pub mod packet;
pub mod plugins;
pub mod session;
