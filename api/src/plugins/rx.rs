use std::ops::{Add, AddAssign};
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
#[repr(C)]
pub struct RxStat {
    /// Total received packets
    pub rx_pkts: u64,
    /// Total received bytes
    pub rx_bytes: u64,
    /// Total overload dropped packets
    pub overload_dropped: u64,
    /// Total dropped packets
    pub dropped: u64,
    /// Total dropped packets by network interface
    pub if_dropped: u64,
}

impl Add for RxStat {
    type Output = Self;
    fn add(self, rhs: Self) -> Self::Output {
        Self {
            rx_pkts: self.rx_pkts + rhs.rx_pkts,
            rx_bytes: self.rx_bytes + rhs.rx_bytes,
            dropped: self.dropped + rhs.dropped,
            if_dropped: self.if_dropped + rhs.if_dropped,
            overload_dropped: self.overload_dropped + rhs.overload_dropped,
        }
    }
}

impl AddAssign for RxStat {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs
    }
}

pub trait RxDriver: Plugin {
    /// Start a rx driver
    ///
    /// Generally a rx driver needs to create a new thread to receive and process pkts at the same time.
    /// In old api, this is a sync function, which means an rx driver could only use
    fn start(&mut self, cfg: Arc<Config>, senders: &[Sender<Box<dyn Packet>>]) -> Result<()>;
    fn stats(&self) -> Result<RxStat>;
    /// Whether this driver support offline pcap processing
    fn support_offline(&self) -> bool {
        false
    }
}
