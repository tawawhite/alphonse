use std::sync::Arc;

use anyhow::Result;
use crossbeam_channel::Sender;
use serde::Serialize;

use crate::config::Config;
use crate::packet::Packet;
use crate::plugins::Plugin;

/// Create a Box of rx driver
pub type NewRxDriverFunc = extern "C" fn() -> Box<Box<dyn RxDriver>>;
pub const NEW_RX_DRIVER_FUNC_NAME: &str = "al_new_rx_driver";

/// RX statistic information
#[derive(Clone, Copy, Debug, Default, Serialize)]
pub struct RxStat {
    /// Total received packets
    pub rx_pkts: u64,
    /// Total received bytes
    pub rx_bytes: u64,
    /// Total dropped packets
    pub dropped: u64,
    /// Total dropped packets by network interface
    pub if_dropped: u64,
}

pub trait RxDriver: Plugin {
    fn start(&self, cfg: Arc<Config>, senders: &[Sender<Box<dyn Packet>>]) -> Result<()>;
    fn stats(&self) -> RxStat;
}
