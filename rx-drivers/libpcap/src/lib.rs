use std::sync::Arc;

use anyhow::Result;
use crossbeam_channel::Sender;
use tokio::task::JoinHandle;

use alphonse_api as api;
use api::classifiers::matched::Rule;
use api::config::Config;
use api::packet::Packet as PacketTrait;
use api::packet::{Layers, Rules, Tunnel};
use api::plugins::rx::{RxDriver, RxStat};
use api::plugins::{Plugin, PluginType};

#[cfg(feature = "arkime")]
mod arkime;
mod files;
mod interfaces;

trait CaptureUnit: Send + Sync {
    fn next(&self) -> Result<Box<dyn PacketTrait>, pcap::Error>;
    fn stats(&self) -> Result<RxStat>;
}

fn gather_stats(caps: &[&dyn CaptureUnit]) -> Result<RxStat> {
    let mut stat = RxStat::default();
    for cap in caps {
        match cap.stats() {
            Ok(stats) => stat += stats,
            Err(e) => eprintln!("{}", e),
        }
    }
    Ok(stat)
}

#[derive(Default)]
struct Driver {
    rt: Option<tokio::runtime::Runtime>,
    /// Thread handles
    handles: Vec<JoinHandle<Result<()>>>,
    caps: Vec<Arc<dyn CaptureUnit>>,
    cfg: Arc<Config>,
}

impl Plugin for Driver {
    fn plugin_type(&self) -> PluginType {
        PluginType::RxDriver
    }

    fn name(&self) -> &str {
        "rx-libpcap"
    }

    fn cleanup(&mut self) -> Result<()> {
        let mut handles = vec![];
        while let Some(hdl) = self.handles.pop() {
            handles.push(hdl);
        }

        match &self.rt {
            None => unreachable!("this should never happen"),
            Some(rt) => rt.block_on(async {
                futures::future::join_all(handles).await;
            }),
        }

        Ok(())
    }
}

impl RxDriver for Driver {
    fn start(&mut self, cfg: Arc<Config>, senders: &[Sender<Box<dyn PacketTrait>>]) -> Result<()> {
        self.cfg = cfg;
        if self.cfg.pcap_file.is_empty() && self.cfg.pcap_dir.is_empty() {
            self.start_interfaces(self.cfg.clone(), senders)
        } else {
            self.start_files(self.cfg.clone(), senders)
        }
    }

    fn stats(&self) -> Result<RxStat> {
        if self.cfg.pcap_file.is_empty() && self.cfg.pcap_dir.is_empty() {
            self.gather_interfaces_stats()
        } else {
            self.gather_files_stats()
        }
    }

    fn support_offline(&self) -> bool {
        true
    }
}

#[derive(Clone)]
pub struct Packet {
    raw: Vec<u8>,
    ts: libc::timeval,
    caplen: u32,
    layers: Layers,
    rules: Rules,
    tunnel: Tunnel,
}

impl PacketTrait for Packet {
    fn raw(&self) -> &[u8] {
        self.raw.as_slice()
    }

    fn ts(&self) -> &libc::timeval {
        &self.ts
    }

    fn caplen(&self) -> u32 {
        self.caplen
    }

    fn layers(&self) -> &Layers {
        &self.layers
    }

    fn layers_mut(&mut self) -> &mut Layers {
        &mut self.layers
    }

    fn rules(&self) -> &[Rule] {
        self.rules.as_ref().as_slice()
    }

    fn rules_mut(&mut self) -> &mut Rules {
        &mut self.rules
    }

    fn tunnel(&self) -> Tunnel {
        self.tunnel
    }

    fn tunnel_mut(&mut self) -> &mut Tunnel {
        &mut self.tunnel
    }

    fn clone_box<'a, 'b>(&'a self) -> Box<dyn PacketTrait + 'b> {
        Box::new(self.clone())
    }
}

impl From<&pcap::Packet<'_>> for Packet {
    fn from(pkt: &pcap::Packet) -> Self {
        Packet {
            raw: Vec::from(pkt.data),
            ts: pkt.header.ts,
            caplen: pkt.header.caplen,
            layers: Layers::default(),
            rules: Rules::default(),
            tunnel: Tunnel::default(),
        }
    }
}

#[no_mangle]
pub extern "C" fn al_new_rx_driver() -> Box<Box<dyn RxDriver>> {
    Box::new(Box::new(Driver::default()))
}

#[no_mangle]
pub extern "C" fn al_plugin_type() -> PluginType {
    PluginType::RxDriver
}
