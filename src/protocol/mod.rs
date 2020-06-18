use super::packet;

mod classifier;

pub use classifier::{Classifier, ClassifyScratch};

/// Network Protocol
#[derive(Clone, Default)]
pub struct Protocol {
    name: String,
    id: u8,
}
