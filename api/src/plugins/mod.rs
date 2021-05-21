use anyhow::Result;

use crate::config::Config;

pub mod parsers;

#[repr(C)]
pub enum PluginType {
    /// A rx driver
    RxDriver = 0,

    /// A packet processor
    PacketProcessor = 1,

    /// An output plugin (Elasticsearch, Kafka, Disk, etc.)
    Output = 2,
}

/// General Plugin trait
pub trait Plugin {
    fn clone_plugin(&self) -> Box<dyn Plugin>;

    /// Plugin name
    fn name(&self) -> &str;

    /// Get the plugin type
    fn plugin_type(&self) -> PluginType;

    /// Initialize plugin required global resources
    fn init(&self, _cfg: &Config) -> Result<()> {
        Ok(())
    }

    /// Initialize the plugin
    fn cleanup(&self) -> Result<()> {
        Ok(())
    }
}

/// Create a Box of plugin
pub type NewPluginFunc = extern "C" fn() -> Box<Box<dyn Plugin>>;

pub const NEW_PLUGIN_FUNC_NAME: &str = "al_new_plugin";
