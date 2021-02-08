use std::collections::HashMap;
use std::ffi::CStr;
use std::ops::Deref;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::thread::JoinHandle;

use anyhow::{anyhow, Result};
use crossbeam_channel::Sender;
use rte::ethdev::EthDevice;
use yaml_rust::Yaml;

use alphonse_api as api;
use api::classifiers::matched::Rule;
use api::packet::{Layers, Packet as PacketTrait, Tunnel};
use api::utils::timeval::{precision, TimeVal};

use crate::config::Config;
use crate::rx::RxUtility;
use crate::stats::CaptureStat;

pub const UTILITY: RxUtility = RxUtility {
    init,
    start,
    cleanup,
};

fn init(cfg: &mut Config) -> Result<()> {
    init_eal(cfg)?;

    Ok(())
}

fn start(
    exit: Arc<AtomicBool>,
    cfg: Arc<Config>,
    sender: Sender<Box<dyn PacketTrait>>,
) -> Result<Option<Vec<JoinHandle<Result<()>>>>> {
    init_ports(&cfg)?;

    let pool_size = cfg.get_integer(
        &"dpdk.pkt.pool.size",
        2i64.pow(22) - 1,
        2i64.pow(21) - 1,
        2i64.pow(24) - 1,
    ) as u32;

    if !is_power_of_two(pool_size + 1) {
        eprintln!(
            "dpdk.pkt.pool.size {} is not optimal, consider make it a power of two minus one",
            pool_size
        );
    }

    let cache_size = cfg.get_integer(&"dpdk.pkt.pool.cache.size", 512, 32, 2048) as u32;
    if !is_cache_size_valid(cache_size, pool_size) {
        anyhow!("Invalid dpdk.pkt.pool.cache.size: {}", cache_size);
    }

    let mempool = rte::mbuf::pool_create(
        &"alphonse-pkt-pool",
        pool_size,
        cache_size,
        0,
        2048,
        rte::socket_id() as i32,
    )?;

    Ok(None)
}

fn cleanup(_: &Config) -> Result<()> {
    rte::eal::cleanup()
}

fn is_power_of_two<T: Into<u64>>(x: T) -> bool {
    let x: u64 = x.into();
    x != 0 && ((x & (x - 1)) == 0)
}

fn is_cache_size_valid<T: Into<u64>>(cache_size: T, pool_size: u32) -> bool {
    let x: u64 = cache_size.into();
    if x == 0 {
        return true;
    }

    if x > rte::ffi::RTE_MEMPOOL_CACHE_MAX_SIZE as u64 {
        return false;
    }

    if x as f64 > pool_size as f64 / 1.5 {
        return false;
    }

    if (pool_size + 1) as u64 % x != 0 {
        eprintln!(
            "dpdk.pkt.pool.cache.size {} is not optimal,\
                 it is advised to choose cache_size to have: pool_size modulo cache_size == 0",
            x
        );
    }

    true
}

/// Minimium DPDK rx unit
#[derive(Clone, Debug)]
pub struct Device {
    /// DPDK port ID
    pub port: rte::PortId,
    /// Rx queues
    pub rx_queues: Vec<rte::QueueId>,
}

impl Device {
    pub fn new(port: rte::PortId, rx_queues: &Vec<rte::QueueId>) -> Self {
        Self {
            port,
            rx_queues: rx_queues.clone(),
        }
    }
}

fn configure(port: rte::PortId, nb_rx_queue: u16) -> Result<()> {
    let rss_key = [
        0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D,
        0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
        0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
    ];

    let rss_conf = rte::ethdev::EthRssConf {
        key: Some(rss_key),
        hash: rte::ethdev::RssHashFunc::ETH_RSS_PROTO_MASK,
    };
    let mut rx_adv_conf = rte::ethdev::RxAdvConf::default();
    rx_adv_conf.rss_conf = Some(rss_conf);

    let mut rx_mode = rte::ethdev::EthRxMode::default();
    rx_mode.mq_mode = rte::ffi::rte_eth_rx_mq_mode::ETH_MQ_RX_RSS;

    let mut conf = rte::ethdev::EthConf::default();
    conf.rx_adv_conf = Some(rx_adv_conf);
    conf.rxmode = Some(rx_mode);

    port.configure(nb_rx_queue, 0, &conf)?;

    Ok(())
}

fn rx_queue_setup(
    port: rte::PortId,
    nb_rx_queue: u16,
    mb_pool: &mut rte::mempool::MemoryPool,
) -> Result<()> {
    for i in 0..nb_rx_queue {
        let mut rx_conf = rte::ffi::rte_eth_rxconf::default();
        rx_conf.rx_thresh.pthresh = 8;
        rx_conf.rx_thresh.hthresh = 0;
        rx_conf.rx_thresh.wthresh = 4;
        rx_conf.rx_free_thresh = 0;
        rx_conf.rx_drop_en = 0;
        rx_conf.rx_deferred_start = 0;
        port.rx_queue_setup(i, 4096, Some(rx_conf), mb_pool)?;
    }
    Ok(())
}

fn init_eal(cfg: &Config) -> Result<()> {
    rte::eal::init(cfg.dpdk_eal_args.as_slice())?;
    Ok(())
}

/// Get all avaliable DPDK devices
pub fn devices(cfg: &Config) -> Result<Vec<(rte::lcore::Id, Device)>> {
    if rte::ethdev::count() == 0 {
        return Err(anyhow!("no avaiable port found"));
    }

    let mut devices = vec![];
    let ports: HashMap<String, rte::PortId> = rte::ethdev::devices()
        .map(|port| {
            let info = port.info();
            let name = unsafe { CStr::from_ptr((*info.device).name).to_str().unwrap() };
            (name.to_string(), port)
        })
        .collect();

    let doc = &cfg.docs[0];
    let rx_ports = doc["dpdk.rx.ports"]
        .as_hash()
        .ok_or(anyhow!("dpdk.rx.ports is not hash"))?;
    for (k, v) in rx_ports.iter() {
        let pci = k.as_str().ok_or(anyhow!("key is not a string"))?;
        let port = match ports.get(pci) {
            Some(port) => *port,
            None => {
                eprintln!("specific port {} doesn't exist or is not available", pci);
                eprintln!("available ports: {:?}", ports.keys());
                continue;
            }
        };

        let cores = v.as_vec().ok_or(anyhow!("cores is not an array"))?;
        let mut nb_rx_queue = 0;
        for core in cores {
            let core = core.as_hash().ok_or(anyhow!("core is not a hash"))?;
            let queues = core
                .get(&Yaml::String("queue".to_string()))
                .ok_or(anyhow!("no queue found"))?
                .as_i64()
                .ok_or(anyhow!("queue is not i64"))?;
            let lcore = core
                .get(&Yaml::String("core".to_string()))
                .ok_or(anyhow!("no core found"))?
                .as_i64()
                .ok_or(anyhow!("core is not i64"))? as u32;
            devices.push((
                rte::lcore::Id::from(lcore),
                Device::new(
                    port,
                    &(nb_rx_queue as u16..(nb_rx_queue + queues) as u16).collect(),
                ),
            ));
            nb_rx_queue += queues;
        }
    }

    Ok(devices)
}

/// Initialize all ports
fn init_ports(cfg: &Config) -> Result<()> {
    if rte::ethdev::count() == 0 {
        return Err(anyhow!("no avaiable port found"));
    }

    println!("available port count: {}", rte::ethdev::count());

    let devices = devices(cfg)?;

    let mut ports: HashMap<rte::PortId, u16> = HashMap::new();
    for dev in &devices {
        let dev = &dev.1;
        let port = dev.port;
        let nb_rx_queues = dev.rx_queues.len() as u16;
        match ports.get_mut(&port) {
            Some(nb) => *nb += nb_rx_queues,
            None => {
                ports.insert(port, nb_rx_queues);
            }
        };
    }

    for (port, nb_rx_queue) in ports.iter() {
        let name = unsafe { CStr::from_ptr((*port.info().device).name).to_str().unwrap() };
        println!("configuring port {}", name);
        configure(*port, *nb_rx_queue)?;
        // Self::rx_queue_setup(port, nb_rx_queue, mb_pool);

        // TODO: set mtu by alphonse config
        port.set_mtu(1514)?;
        // port.start()?;
    }

    Ok(())
}

impl Device {
    fn configure(&mut self, _: &Config) -> Result<()> {
        Ok(())
    }

    fn next(&mut self) -> Result<Box<dyn PacketTrait>> {
        unimplemented!("dpdk::Device::next not implemented")
    }

    fn stats(&mut self) -> Result<CaptureStat> {
        Ok(CaptureStat::default())
    }
}

pub struct Packet {
    mbuf: Box<rte::mbuf::MBuf>,
    ts: TimeVal<precision::Millisecond>,
    layers: Layers,
    rules: Box<Vec<Rule>>,
    tunnel: Tunnel,
    drop: bool,
}

impl Packet {
    fn set(&mut self, mbuf: Box<rte::mbuf::MBuf>, ts: TimeVal<precision::Millisecond>) {
        if self.drop {
            self.mbuf.free();
        }

        self.mbuf = mbuf;
        self.ts = ts;
    }
}

unsafe impl Send for Packet {}

impl Clone for Packet {
    fn clone(&self) -> Self {
        Self {
            mbuf: self.mbuf.clone(),
            ts: self.ts.clone(),
            layers: self.layers.clone(),
            rules: self.rules.clone(),
            tunnel: self.tunnel,
            drop: self.drop,
        }
    }
}

impl PacketTrait for Packet {
    fn raw(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.mbuf.mtod().as_ptr(), self.mbuf.pkt_len()) }
    }

    fn caplen(&self) -> u32 {
        self.mbuf.pkt_len() as u32
    }

    fn ts(&self) -> &libc::timeval {
        self.ts.deref()
    }

    fn layers(&self) -> &Layers {
        &self.layers
    }

    fn layers_mut(&mut self) -> &mut Layers {
        &mut self.layers
    }

    fn rules(&self) -> &[Rule] {
        self.rules.as_slice()
    }

    fn rules_mut(&mut self) -> &mut Vec<Rule> {
        &mut self.rules
    }

    fn tunnel(&self) -> Tunnel {
        self.tunnel
    }

    fn tunnel_mut(&mut self) -> &mut Tunnel {
        &mut self.tunnel
    }

    fn clone_box(&self) -> Box<dyn PacketTrait + '_> {
        Box::new(self.clone())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_is_power_of_two() {
        assert!(!is_power_of_two(0u32));
        assert!(is_power_of_two(2u32));
        assert!(is_power_of_two(4194304u32));
    }
}
