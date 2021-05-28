use anyhow::Result;

use crate::classifiers::matched;
use crate::classifiers::ClassifierManager;
use crate::plugins::Plugin;
use crate::{packet, session};

pub type ProcessorID = u8;

/// Create a Box of the packet processor
pub type NewProcessorFunc = extern "C" fn() -> Box<Box<dyn Processor>>;
pub const NEW_PKT_PROCESSOR_FUNC_NAME: &str = "al_new_pkt_processor";

pub trait Processor: Send + Sync + Plugin {
    /// Clone a Protocol Processor
    fn clone_processor(&self) -> Box<dyn Processor>;

    /// Get processor id
    fn id(&self) -> ProcessorID;

    /// Set processor id
    fn set_id(&mut self, id: ProcessorID);

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
            ses.add_protocol(&self.name(), session::ProtocolLayer::All)?;
        }

        Ok(())
    }

    /// Check whether the session is classfied as this protocol
    fn is_classified(&self) -> bool;

    /// Change this protocol processor's internal state to indicate this session is classfied as this protocol
    fn classified_as_this_protocol(&mut self) -> Result<()>;

    /// Cleanup operations
    fn finish(&mut self, _: &mut session::Session) {}
}