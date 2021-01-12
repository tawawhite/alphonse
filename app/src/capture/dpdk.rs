use std::ops::Deref;

use anyhow::Result;
use rte::ethdev::EthDevice;

use alphonse_api as api;
use api::classifiers::matched::Rule;
use api::packet::{Layers, Packet as PacketTrait};
use api::utils::timeval::{precision, TimeVal};

use crate::config::Config;
use crate::stats::CaptureStat;
#[allow(non_camel_case_types)]

pub struct Device {
    port: rte::PortId,
    pub thread: u8,
}

impl Device {
    pub fn new(port: rte::PortId, thread: u8) -> Self {
        Self { port, thread }
    }
}

impl super::Capture for Device {
    fn init(cfg: &Config) -> Result<()> {
        rte::eal::init(cfg.dpdk_eal_args.as_slice()).expect("fail to initial EAL");

        println!("available port count: {}", rte::ethdev::count());

        for port in rte::ethdev::devices() {
            let info = port.info();
            println!("found port: {:?}", info);
        }

        Ok(())
    }

    fn configure(&mut self, _: &Config) -> Result<()> {
        Ok(())
    }

    fn cleanup() -> Result<()> {
        rte::eal::cleanup()
    }

    fn next(&mut self) -> Result<Box<dyn PacketTrait>> {
        unimplemented!("dpdk::Device::next not implemented")
    }

    fn stats(&mut self) -> Result<CaptureStat> {
        Ok(CaptureStat::default())
    }
}

impl Device {
    pub fn port_id(&self) -> rte::PortId {
        self.port
    }
}

pub struct Packet {
    mbuf: Box<rte::mbuf::MBuf>,
    ts: TimeVal<precision::Millisecond>,
    layers: Layers,
    rules: Box<Vec<Rule>>,
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

    fn clone_box(&self) -> Box<dyn PacketTrait + '_> {
        Box::new(self.clone())
    }

    fn clone_box_deep(&self) -> Box<dyn PacketTrait> {
        Box::new(self.clone())
    }
}
