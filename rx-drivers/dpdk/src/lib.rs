use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::thread::JoinHandle;

use anyhow::{anyhow, Result};
use crossbeam_channel::Sender;
use rte::ethdev::EthDevice;

use alphonse_api as api;
use api::config::Config;
use api::packet::Packet as PacketTrait;
use api::plugins::rx::{RxDriver, RxStat};
use api::plugins::{Plugin, PluginType};

mod device;
mod mempool;

use device::Device;

#[derive(Clone, Default)]
struct Driver {
    handles: Arc<RwLock<Vec<JoinHandle<Result<()>>>>>,
    stats: RxStat,
}

impl Plugin for Driver {
    fn plugin_type(&self) -> PluginType {
        PluginType::RxDriver
    }

    fn name(&self) -> &str {
        "rx-libpcap"
    }

    fn init(&mut self, cfg: &Config) -> Result<()> {
        rte::eal::init(cfg.dpdk_eal_args.as_slice())?;
        Ok(())
    }

    fn cleanup(&mut self) -> Result<()> {
        let mut handles = match self.handles.write() {
            Ok(h) => h,
            Err(e) => return Err(anyhow!("{}", e)),
        };

        while handles.len() > 0 {
            let hdl = handles.pop();
            match hdl {
                None => continue,
                Some(hdl) => match hdl.join() {
                    Ok(_) => {}
                    Err(e) => eprintln!("{:?}", e),
                },
            }
        }

        Ok(())
    }
}

impl RxDriver for Driver {
    fn start(&mut self, cfg: Arc<Config>, senders: &[Sender<Box<dyn PacketTrait>>]) -> Result<()> {
        let mempool = mempool::create_pktmbuf_pool(&cfg)?;

        {
            let ptr = mempool.as_ref() as *const _ as *mut rte::mempool::MemoryPool;
            let mb_pool = unsafe { &mut (*ptr) };
            device::init_ports(&cfg, mb_pool)?;
        }

        let mut handles = vec![];
        for (_, device) in device::devices(&cfg)? {
            let cfg = cfg.clone();
            let mut thread = RxThread {
                exit: cfg.exit.clone(),
                senders: senders.to_vec(),
                device: device.clone(),
            };
            let builder = std::thread::Builder::new().name(thread.name());
            let handle = builder.spawn(move || thread.spawn(cfg))?;
            handles.push(handle);
        }
        match self.handles.write() {
            Ok(mut h) => {
                *h.as_mut() = handles;
            }
            Err(e) => return Err(anyhow!("{}", e)),
        };

        Ok(())
    }

    fn stats(&self) -> Result<RxStat> {
        Ok(self.stats)
    }
}

struct RxThread {
    exit: Arc<AtomicBool>,
    device: Device,
    senders: Vec<Sender<Box<dyn PacketTrait>>>,
}

impl RxThread {
    pub fn spawn(&mut self, _cfg: Arc<Config>) -> Result<()> {
        let mut mbufs = vec![None; 8];
        let mut rx_count: u64 = 0;
        println!("{} started", self.name());

        while !self.exit.load(Ordering::Relaxed) {
            for queue in &self.device.rx_queues {
                let cnt = self.device.port.rx_burst(*queue, &mut mbufs);
                rx_count += cnt as u64;
                for mbuf in mbufs[0..cnt].iter() {
                    match mbuf {
                        Some(_) => {}
                        None => break,
                    }
                }
            }
        }

        println!("{} exit", self.name());
        Ok(())
    }

    pub fn name(&self) -> String {
        format!("alphonse-{}-{:?}", self.device.port, self.device.rx_queues)
    }
}
