use anyhow::Result;

use crate::classifiers::matched;
use crate::classifiers::ClassifierManager;
use crate::config::Config;
use crate::packet::Packet;
use crate::plugins::Plugin;
use crate::session::Session;

pub type ProcessorID = u8;

/// Create a Box of the packet processor
pub type NewProcessorBuilderFunc = extern "C" fn() -> Box<Box<dyn Builder>>;
pub const NEW_PKT_PROCESSOR_BUILDER_FUNC_NAME: &str = "al_new_pkt_processor_builder";

pub trait Builder: Send + Sync + Plugin {
    fn build(&self, cfg: &Config) -> Box<dyn Processor>;

    /// Get processor id
    fn id(&self) -> ProcessorID;

    /// Set processor id
    fn set_id(&mut self, id: ProcessorID);

    /// Register protocol classify rules
    fn register_classify_rules(&mut self, manager: &mut ClassifierManager) -> Result<()>;
}

pub trait Processor: Send + Sync {
    /// Get processor id
    fn id(&self) -> ProcessorID;

    fn name(&self) -> &'static str;

    /// Parse a single packet and maybe update session information
    fn parse_pkt(
        &mut self,
        _pkt: &dyn Packet,
        _rule: Option<&matched::Rule>,
        _ses: &mut Session,
    ) -> Result<()> {
        Ok(())
    }

    #[inline]
    /// Called when this session needs to mid save, by default call finish method
    fn mid_save(&mut self, ses: &mut Session) {
        self.save(ses)
    }

    /// Called when this session is timeout, add fields to this sessions
    fn save(&mut self, ses: &mut Session);
}
