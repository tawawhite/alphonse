use anyhow::Result;
use serde_json::json;

use alphonse_api as api;
use api::classifiers::{matched, ClassifierManager, Rule, RuleType};
use api::packet::{Packet, Protocol};
use api::plugins::processor::{Processor, ProcessorID};
use api::plugins::{Plugin, PluginType};
use api::session::{ProtocolLayer, Session};

#[derive(Clone, Debug, Default)]
struct ProtocolParser {
    id: ProcessorID,
    name: String,
    classified: bool,
}

impl Plugin for ProtocolParser {
    fn plugin_type(&self) -> PluginType {
        PluginType::PacketProcessor
    }

    fn name(&self) -> &str {
        "udp"
    }
}

impl ProtocolParser {
    fn new() -> ProtocolParser {
        let mut parser = ProtocolParser::default();
        parser.name = String::from("tcp");
        parser
    }
}

impl Processor for ProtocolParser {
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

    fn register_classify_rules(&mut self, manager: &mut ClassifierManager) -> Result<()> {
        let mut rule = Rule::new(self.id);
        rule.rule_type = RuleType::Protocol(api::classifiers::protocol::Rule(Protocol::UDP));
        manager.add_rule(&mut rule)?;
        Ok(())
    }

    fn parse_pkt(
        &mut self,
        pkt: &dyn Packet,
        _rule: Option<&matched::Rule>,
        ses: &mut Session,
    ) -> Result<()> {
        if !self.classified {
            self.classified = true;
            ses.add_protocol(&self.name(), ProtocolLayer::Transport);
            unsafe {
                ses.add_field(&"srcPort", json!(pkt.src_port()));
                ses.add_field(&"dstPort", json!(pkt.dst_port()));
            }
        }

        Ok(())
    }

    fn save(&mut self, _: &mut Session) {
        self.classified = false;
    }
}

#[no_mangle]
pub extern "C" fn al_new_pkt_processor() -> Box<Box<dyn Processor>> {
    Box::new(Box::new(ProtocolParser::new()))
}

#[no_mangle]
pub extern "C" fn al_plugin_type() -> PluginType {
    PluginType::PacketProcessor
}
