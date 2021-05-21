use anyhow::Result;

use crate::classifiers::matched;
use crate::classifiers::ClassifierManager;
use crate::plugins::Plugin;
use crate::{packet, session};

pub type ParserID = u8;

/// Create a Box of the protocol parser
pub type NewProtocolParserFunc = extern "C" fn() -> Box<Box<dyn Processor>>;
/// Create a Vector of Box of the protocol parser
pub type NewProtocolParserBoxesFunc = extern "C" fn() -> Box<Vec<Box<dyn Processor>>>;

// Initialize parser required global resources
pub type ParserInitFunc = fn() -> Result<()>;

// Release parser required global resources
pub type ParserExitFunc = fn() -> Result<()>;

pub trait Processor: Send + Sync + Plugin {
    /// Clone a Protocol Parser
    fn box_clone(&self) -> Box<dyn Processor>;

    /// Get parser id
    fn id(&self) -> ParserID;

    /// Set parser id
    fn set_id(&mut self, id: ParserID);

    /// Register protocol classify rules
    fn register_classify_rules(&mut self, manager: &mut ClassifierManager) -> Result<()>;

    /// Parse a single packet and maybe update session information
    fn parse_pkt(
        &mut self,
        _pkt: &dyn packet::Packet,
        _rule: Option<&matched::Rule>,
        ses: &mut session::Session,
    ) -> Result<()> {
        if !self.is_classified() {
            // If this session is already classified as this protocol, skip
            self.classified_as_this_protocol()?;
            ses.add_protocol(&self.name());
        }

        Ok(())
    }

    /// Check whether the session is classfied as this protocol
    fn is_classified(&self) -> bool;

    /// Change this protocol parser's internal state to indicate this session is classfied as this protocol
    fn classified_as_this_protocol(&mut self) -> Result<()>;

    /// Cleanup operations
    fn finish(&mut self, _: &mut session::Session) {}
}
