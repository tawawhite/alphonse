use std::sync::Arc;

use anyhow::Result;
use crossbeam_channel::Receiver;

use crate::config::Config;
use crate::plugins::Plugin;
use crate::session::Session;

/// Create a Box of rx driver
pub type NewOutputPluginFunc = extern "C" fn() -> Box<Box<dyn OutputPlugin>>;
pub const NEW_OUTPUT_PLUGIN_FUNC_NAME: &str = "al_new_output_plugin";

pub trait OutputPlugin: Plugin {
    fn clone_output_plugin(&self) -> Box<dyn OutputPlugin>;
    fn start(&self, cfg: Arc<Config>, receiver: &Receiver<Box<Session>>) -> Result<()>;
}
