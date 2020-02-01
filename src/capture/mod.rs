pub mod offline;

pub trait Backend {}

pub struct Offline {}

impl Backend for Offline {}
