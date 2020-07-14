use anyhow::Result;

use super::classifier::ClassifierManager;
use super::{packet, session};

pub type ParserID = u8;

/// register a protocol parser into alphonse
pub type RegisterProtocolParserFunc = fn(&mut Vec<Box<dyn ProtocolParser>>) -> Result<()>;

// Initialize parser required global resources
pub type ParserInitFunc = fn() -> Result<()>;

// Release parser required global resources
pub type ParserExitFunc = fn() -> Result<()>;

pub trait ProtocolParser {
    /// Get parser id
    fn id(&self) -> ParserID;

    /// Set parser id
    fn set_id(&mut self, id: ParserID);

    /// Get parser name
    fn name(&self) -> String;

    /// Initialize parser required global resources
    fn init(&mut self) -> Result<()>;

    // Release parser required global resources
    fn exit(&mut self) -> Result<()>;

    /// Register a protocol classifier
    fn register_classifier(&self, manager: &mut ClassifierManager) -> Result<()>;

    /// Parse a single packet and maybe update session information
    fn parse_pkt(&self, pkt: &packet::Packet, ses: &mut session::Session);
}
