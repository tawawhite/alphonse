use std::hash::Hash;
use std::path::PathBuf;

use anyhow::Result;
use fnv::FnvHashSet;
use mac_address::MacAddress;
use serde::Serialize;
use serde_json::json;

use alphonse_api as api;
use api::classifiers;
use api::packet::{Direction, Protocol};
use api::plugins::processor::{
    Builder as ProcessorBuilder, Processor as PktProcessor, ProcessorID,
};
use api::plugins::{Plugin, PluginType};
use api::session::{ProtocolLayer, Session};

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize)]
struct MacInfo {
    addr: MacAddress,
}

impl Default for MacInfo {
    fn default() -> Self {
        Self {
            addr: MacAddress::new([0; 6]),
        }
    }
}

#[derive(Clone, Debug, Default)]
struct Builder {
    id: ProcessorID,
}

impl ProcessorBuilder for Builder {
    fn build(&self, _: &api::config::Config) -> Box<dyn PktProcessor> {
        let mut p = Box::new(Processor::default());
        p.id = self.id;
        p
    }

    fn id(&self) -> ProcessorID {
        self.id
    }

    fn set_id(&mut self, id: ProcessorID) {
        self.id = id
    }

    fn register_classify_rules(
        &mut self,
        manager: &mut classifiers::ClassifierManager,
    ) -> Result<()> {
        manager.add_protocol_rule(self.id(), Protocol::ETHERNET)?;
        Ok(())
    }
}

impl Plugin for Builder {
    fn plugin_type(&self) -> PluginType {
        PluginType::PacketProcessor
    }

    /// Get parser name
    fn name(&self) -> &str {
        "ethernet"
    }

    fn init(&mut self, alcfg: &api::config::Config) -> Result<()> {
        let _db_dir = PathBuf::from(alcfg.get_str(&"ethernet.oui.directory", "etc"));
        Ok(())
    }
}

#[derive(Clone, Default)]
struct Processor {
    id: ProcessorID,
    classified: bool,
    src_direction: Direction,
    src_macs: FnvHashSet<MacInfo>,
    dst_macs: FnvHashSet<MacInfo>,
}

impl PktProcessor for Processor {
    fn id(&self) -> ProcessorID {
        self.id
    }

    fn name(&self) -> &'static str {
        &"ethernet"
    }

    fn parse_pkt(
        &mut self,
        pkt: &dyn api::packet::Packet,
        _rule: Option<&api::classifiers::matched::Rule>,
        ses: &mut Session,
    ) -> Result<()> {
        if !self.classified {
            self.classified = true;
            self.src_direction = pkt.direction();

            let protocol = match pkt.layers().datalink() {
                None => unreachable!("ethernet received a pkt with no datalink layer"),
                Some(layer) => layer.protocol,
            };
            match protocol {
                Protocol::ETHERNET => {
                    ses.add_protocol(&"ethernet", ProtocolLayer::Datalink);
                }
                _ => unreachable!(),
            }
        }
        let src_mac = match pkt.src_mac() {
            None => unreachable!("ethernet received a pkt with no datalink layer"),
            Some(mac) => MacAddress::new(mac.clone()),
        };
        let dst_mac = match pkt.src_mac() {
            None => unreachable!("ethernet received a pkt with no datalink layer"),
            Some(mac) => MacAddress::new(mac.clone()),
        };

        let (src_mac, dst_mac) = if self.src_direction == pkt.direction() {
            (src_mac, dst_mac)
        } else {
            (dst_mac, src_mac)
        };

        let info = MacInfo { addr: src_mac };
        self.src_macs.insert(info);

        let info = MacInfo { addr: dst_mac };
        self.dst_macs.insert(info);

        Ok(())
    }

    fn save(&mut self, ses: &mut Session) {
        ses.add_field(
            &"srcMac",
            json!(self
                .src_macs
                .iter()
                .map(|i| i.addr.clone())
                .collect::<Vec<_>>()),
        );
        ses.add_field(
            &"dstMac",
            json!(self
                .dst_macs
                .iter()
                .map(|i| i.addr.clone())
                .collect::<Vec<_>>()),
        );
    }
}

#[no_mangle]
pub extern "C" fn al_new_pkt_processor_builder() -> Box<Box<dyn ProcessorBuilder>> {
    Box::new(Box::new(Builder::default()))
}

#[no_mangle]
pub extern "C" fn al_plugin_type() -> PluginType {
    PluginType::PacketProcessor
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn serde() -> Result<()> {
        let addr = MacAddress::new([0; 6]);
        assert_eq!(
            serde_json::to_string(&json!(addr))?,
            "\"00:00:00:00:00:00\""
        );

        Ok(())
    }
}
