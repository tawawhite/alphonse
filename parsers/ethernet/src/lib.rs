use std::hash::Hash;
use std::path::PathBuf;

use anyhow::Result;
use fnv::FnvHashSet;
use serde::Serialize;
use serde_json::json;

use alphonse_api as api;
use api::classifiers;
use api::packet::{Direction, Protocol};
use api::plugins::processor::{Processor, ProcessorID};
use api::plugins::{Plugin, PluginType};
use api::session::{ProtocolLayer, Session};

#[derive(Clone, Debug, PartialEq, Serialize)]
struct MacAddress(mac_address::MacAddress);

impl Eq for MacAddress {}
impl Hash for MacAddress {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.bytes().hash(state)
    }
}

impl MacAddress {
    pub fn new(bytes: [u8; 6]) -> Self {
        Self(mac_address::MacAddress::new(bytes))
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize)]
struct MacInfo {
    addr: MacAddress,
}

impl Default for MacInfo {
    fn default() -> Self {
        Self {
            addr: MacAddress(mac_address::MacAddress::new([0; 6])),
        }
    }
}

#[derive(Clone, Default)]
struct EthernetProcessor {
    id: ProcessorID,
    classified: bool,
    src_direction: Direction,
    src_macs: FnvHashSet<MacInfo>,
    dst_macs: FnvHashSet<MacInfo>,
}

impl Plugin for EthernetProcessor {
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

impl Processor for EthernetProcessor {
    fn clone_processor(&self) -> Box<dyn Processor> {
        Box::new(self.clone())
    }

    /// Get parser id
    fn id(&self) -> ProcessorID {
        self.id
    }

    /// Get parser id
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

    fn parse_pkt(
        &mut self,
        pkt: &dyn api::packet::Packet,
        _rule: Option<&api::classifiers::matched::Rule>,
        ses: &mut Session,
    ) -> Result<()> {
        if !self.classified {
            self.classified = true;
            self.src_direction = pkt.direction();
            match pkt.layers().data_link.protocol {
                Protocol::ETHERNET => {
                    ses.add_protocol(&"ethernet", ProtocolLayer::Datalink);
                }
                _ => unreachable!(),
            }
        }

        let (src_mac, dst_mac) = if self.src_direction == pkt.direction() {
            let src_mac = unsafe { MacAddress::new(pkt.src_mac().clone()) };
            let dst_mac = unsafe { MacAddress::new(pkt.dst_mac().clone()) };
            (src_mac, dst_mac)
        } else {
            let src_mac = unsafe { MacAddress::new(pkt.dst_mac().clone()) };
            let dst_mac = unsafe { MacAddress::new(pkt.src_mac().clone()) };
            (src_mac, dst_mac)
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
pub extern "C" fn al_new_pkt_processor() -> Box<Box<dyn Processor>> {
    Box::new(Box::new(EthernetProcessor::default()))
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
