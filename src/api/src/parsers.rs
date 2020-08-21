use anyhow::Result;

use super::classifier::ClassifierManager;
use super::{packet, session};

pub type ParserID = u8;

/// Create a Box of the protocol parser
pub type NewProtocolParserBoxFunc = fn() -> Result<Box<dyn ProtocolParser>>;
/// Create a Vector of Box of the protocol parser
pub type NewProtocolParserBoxesFunc = fn() -> Result<Vec<Box<dyn ProtocolParser>>>;

// Initialize parser required global resources
pub type ParserInitFunc = fn() -> Result<()>;

// Release parser required global resources
pub type ParserExitFunc = fn() -> Result<()>;

pub trait ProtocolParser: Send + Sync {
    /// Clone a Protocol Parser
    fn box_clone(&self) -> Box<dyn ProtocolParser>;

    /// Get parser id
    fn id(&self) -> ParserID;

    /// Set parser id
    fn set_id(&mut self, id: ParserID);

    /// Get parser name
    fn name(&self) -> String;

    /// Initialize parser required global resources
    fn init(&mut self) -> Result<()> {
        Ok(())
    }

    // Release parser required global resources
    fn exit(&mut self) -> Result<()> {
        Ok(())
    }

    /// Register a protocol classifier
    fn register_classifier(&mut self, manager: &mut ClassifierManager) -> Result<()>;

    /// Parse a single packet and maybe update session information
    fn parse_pkt(&mut self, _pkt: &packet::Packet, ses: &mut session::Session) {
        if !self.is_classified() {
            // If this session is already classified as Bittorrent protocol, skip
            self.classified_as_this_protocol();
            ses.add_protocol(self.name());
        }
    }

    /// Check whether the session is classfied as this protocol
    fn is_classified(&self) -> bool {
        false
    }

    fn classified_as_this_protocol(&mut self);
}
