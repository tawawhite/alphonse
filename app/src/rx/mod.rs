use std::sync::{atomic::AtomicBool, Arc};
use std::thread::JoinHandle;

use alphonse_api as api;
use anyhow::Result;
use api::packet::Packet;
use crossbeam_channel::Sender;

use crate::config::Config;

#[cfg(all(target_os = "linux", feature = "dpdk"))]
pub mod dpdk;
pub mod files;
pub mod libpcap;

pub struct RxUtility {
    pub init: fn(cfg: &mut Config) -> Result<()>,
    pub start: fn(
        exit: Arc<AtomicBool>,
        cfg: Arc<Config>,
        sender: Sender<Box<dyn Packet>>,
    ) -> Result<Option<Vec<JoinHandle<Result<()>>>>>,
    pub cleanup: fn(cfg: &Config) -> Result<()>,
}
