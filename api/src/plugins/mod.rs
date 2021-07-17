use anyhow::Result;

use crate::config::Config;

pub mod output;
pub mod processor;
pub mod rx;

#[repr(C)]
pub enum PluginType {
    /// A rx driver
    RxDriver = 0,

    /// A packet processor
    PacketProcessor = 1,

    /// An output plugin (Elasticsearch, Kafka, Disk, etc.)
    OutputPlugin = 2,
}

/// General Plugin trait
pub trait Plugin {
    /// Plugin name
    fn name(&self) -> &str;

    /// Get the plugin type
    fn plugin_type(&self) -> PluginType;

    /// Initialize plugin required global resources
    fn init(&self, _cfg: &Config) -> Result<()> {
        Ok(())
    }

    /// Initialize the plugin
    fn cleanup(&mut self) -> Result<()> {
        Ok(())
    }
}

/// Create a Box of the packet processor
pub type PluginTypeFunc = extern "C" fn() -> PluginType;
/// Get the plugin type of this plugin
pub const PLUGIN_TYPE_FUNC_NAME: &str = "al_plugin_type";
