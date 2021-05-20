use anyhow::Result;

use crate::config::Config;

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
    /// Get the plugin type
    fn plugin_type(&self) -> PluginType;

    /// Plugin name
    fn name(&self) -> &str;

    /// Initialize plugin required global resources
    ///
    /// # Arguments
    ///
    /// `_cfg` - alphonse configuration
    fn init(&self, _cfg: &Config) -> Result<()> {
        Ok(())
    }

    /// Initialize the plugin
    fn cleanup(&self) -> Result<()> {
        Ok(())
    }
}
