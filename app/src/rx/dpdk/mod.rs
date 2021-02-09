use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::thread::JoinHandle;

use anyhow::{anyhow, Result};
use crossbeam_channel::Sender;

use alphonse_api as api;
use api::packet::{Layers, Packet as PacketTrait, Tunnel};
use rte::mbuf::MBufPool;

use crate::config::Config;
use crate::rx::RxUtility;

mod device;
mod mempool;

pub const UTILITY: RxUtility = RxUtility {
    init,
    start,
    cleanup,
};

fn init(cfg: &mut Config) -> Result<()> {
    rte::eal::init(cfg.dpdk_eal_args.as_slice())?;
    Ok(())
}

fn start(
    exit: Arc<AtomicBool>,
    cfg: Arc<Config>,
    sender: Sender<Box<dyn PacketTrait>>,
) -> Result<Option<Vec<JoinHandle<Result<()>>>>> {
    let mempool = mempool::create_pktmbuf_pool(&cfg)?;

    {
        let ptr = mempool.as_ref() as *const _ as *mut rte::mempool::MemoryPool;
        let mb_pool = unsafe { &mut (*ptr) };
        device::init_ports(&cfg, mb_pool)?;
    }

    Ok(None)
}

fn cleanup(_: &Config) -> Result<()> {
    rte::eal::cleanup()
}
