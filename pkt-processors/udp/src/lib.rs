use anyhow::Result;
use serde_json::json;

use alphonse_api as api;
use api::classifiers::{matched, ClassifierManager};
use api::config::Config;
use api::packet::{Packet, Protocol};
use api::plugins::processor::{
    Builder as ProcessorBuilder, Processor as PktProcessor, ProcessorID,
};
use api::plugins::{Plugin, PluginType};
use api::session::{ProtocolLayer, Session};

#[derive(Clone, Debug, Default)]
struct Builder {
    id: ProcessorID,
    name: String,
}

impl ProcessorBuilder for Builder {
    fn build(&self, _: &Config) -> Box<dyn PktProcessor> {
        let mut p = Box::new(Processor::default());
        p.id = p.id();
        p
    }

    fn id(&self) -> ProcessorID {
        self.id
    }

    fn set_id(&mut self, id: ProcessorID) {
        self.id = id
    }

    fn register_classify_rules(&mut self, manager: &mut ClassifierManager) -> Result<()> {
        manager.add_protocol_rule(self.id(), Protocol::UDP)?;
        Ok(())
    }
}

impl Plugin for Builder {
    fn plugin_type(&self) -> PluginType {
        PluginType::PacketProcessor
    }

    fn name(&self) -> &str {
        "udp"
    }
}

#[derive(Clone, Debug, Default)]
struct Processor {
    id: ProcessorID,
    classified: bool,
}

impl PktProcessor for Processor {
    fn id(&self) -> ProcessorID {
        self.id
    }

    fn name(&self) -> &'static str {
        &"udp"
    }

    fn parse_pkt(
        &mut self,
        pkt: &dyn Packet,
        _rule: Option<&matched::Rule>,
        ses: &mut Session,
    ) -> Result<()> {
        if !self.classified {
            self.classified = true;
            ses.add_protocol(&"dns", ProtocolLayer::Transport);
            match pkt.src_port() {
                Some(port) => ses.add_field(&"srcPort", json!(port)),
                None => unreachable!("udp processor get a pkt without src port"),
            }
            match pkt.dst_port() {
                Some(port) => ses.add_field(&"dstPort", json!(port)),
                None => unreachable!("udp processor get a pkt without dst port"),
            }
        }

        Ok(())
    }

    fn save(&mut self, _: &mut Session) {
        self.classified = false;
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
