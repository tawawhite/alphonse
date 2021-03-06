use anyhow::Result;
use serde::Serialize;
use serde_json::json;

use alphonse_api as api;
use api::classifiers::{matched, ClassifierManager};
use api::packet::{Direction, Packet, Protocol};
use api::plugins::processor::{Builder as ProcessorBuilder, Processor as Prcr, ProcessorID};
use api::plugins::{Plugin, PluginType};
use api::session::Session;

pub fn shannon_entropy<T: AsRef<[u8]>>(data: T, base: f32) -> f32 {
    let bytes = data.as_ref();
    let mut entropy = 0.0;
    let mut counts = [0; 256];

    for &b in bytes {
        counts[b as usize] += 1;
    }

    for &count in &counts {
        if count == 0 {
            continue;
        }

        let p: f32 = (count as f32) / (bytes.len() as f32);
        entropy -= p * p.log(base);
    }

    entropy
}

#[derive(Clone, Copy, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
struct EntropyFields {
    dst_avg_entropy: f32,
    dst_entropy_cnt: usize,
    src_avg_entropy: f32,
    src_entropy_cnt: usize,
}

#[derive(Clone, Debug, Default)]
struct Builder {
    id: ProcessorID,
    entropy_base: f32,
    entropy_threshold: f32,
}

impl Plugin for Builder {
    fn plugin_type(&self) -> PluginType {
        PluginType::PacketProcessor
    }

    fn name(&self) -> &str {
        "entropy"
    }

    fn init(&mut self, _cfg: &api::config::Config) -> Result<()> {
        self.entropy_threshold = _cfg.get_float(&"entropy.threshold", 0.4, 0.0, f64::MAX) as f32;
        self.entropy_base = _cfg.get_float(&"entropy.base", 10.0, 0.0, 10.0) as f32;
        Ok(())
    }
}

impl ProcessorBuilder for Builder {
    fn build(&self, _: &api::config::Config) -> Box<dyn Prcr> {
        let mut p = Box::new(Processor::default());
        p.id = self.id;
        p.entropy_base = self.entropy_base;
        p.entropy_threshold = self.entropy_threshold;
        p
    }

    fn id(&self) -> ProcessorID {
        self.id
    }

    fn set_id(&mut self, id: ProcessorID) {
        self.id = id
    }

    fn register_classify_rules(&mut self, manager: &mut ClassifierManager) -> Result<()> {
        manager.add_protocol_rule(self.id, Protocol::TCP)?;
        manager.add_protocol_rule(self.id, Protocol::UDP)?;
        manager.add_protocol_rule(self.id, Protocol::SCTP)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Default)]
struct Processor {
    id: ProcessorID,
    entropy_base: f32,
    entropy_threshold: f32,
    src_direction: Direction,
    dst_entropy: Vec<f32>,
    dst_payloads: Vec<Vec<u8>>,
    src_entropy: Vec<f32>,
    src_payloads: Vec<Vec<u8>>,
}

impl Prcr for Processor {
    /// Get parser id
    fn id(&self) -> ProcessorID {
        self.id
    }

    fn name(&self) -> &'static str {
        &"entropy"
    }

    fn parse_pkt(
        &mut self,
        pkt: &dyn Packet,
        _rule: Option<&matched::Rule>,
        ses: &mut Session,
    ) -> Result<()> {
        if pkt.payload().len() == 0 || ses.has_app_protocol() {
            return Ok(());
        }

        if !ses.pkt_count[0] == 0 && ses.pkt_count[1] == 0 {
            self.src_direction = pkt.direction();
        }

        if (ses.pkt_count[0] + ses.pkt_count[1]) < 20 {
            // start calculate entropy after have received 20 valid packets
            // and still not recognized as any application layer protocol
            if pkt.direction() == self.src_direction {
                self.src_payloads.push(pkt.payload().to_vec());
            } else {
                self.dst_payloads.push(pkt.payload().to_vec());
            }
            return Ok(());
        }

        if !self.src_payloads.is_empty() {
            for payload in &self.src_payloads {
                self.src_entropy
                    .push(shannon_entropy(payload, self.entropy_base));
            }
            self.src_payloads.clear();
        }

        if !self.dst_payloads.is_empty() {
            for payload in &self.dst_payloads {
                self.dst_entropy
                    .push(shannon_entropy(payload, self.entropy_base));
            }
            self.dst_payloads.clear();
        }

        if pkt.direction() == self.src_direction {
            self.src_entropy
                .push(shannon_entropy(pkt.payload(), self.entropy_base));
        } else {
            self.dst_entropy
                .push(shannon_entropy(pkt.payload(), self.entropy_base));
        }

        Ok(())
    }

    fn save(&mut self, ses: &mut Session) {
        if ses.has_app_protocol() {
            return;
        }

        if !self.src_payloads.is_empty() {
            for payload in &self.src_payloads {
                self.src_entropy
                    .push(shannon_entropy(payload, self.entropy_base));
            }
            self.src_payloads.clear();
        }

        if !self.dst_payloads.is_empty() {
            for payload in &self.dst_payloads {
                self.dst_entropy
                    .push(shannon_entropy(payload, self.entropy_base));
            }
            self.dst_payloads.clear();
        }

        let mut entropy = EntropyFields::default();
        entropy.dst_avg_entropy = self.dst_entropy.iter().sum();
        entropy.src_avg_entropy = self.src_entropy.iter().sum();
        entropy.dst_entropy_cnt = self
            .dst_entropy
            .iter()
            .filter(|e| **e <= self.entropy_threshold)
            .count();
        entropy.src_entropy_cnt = self
            .src_entropy
            .iter()
            .filter(|e| **e <= self.entropy_threshold)
            .count();

        ses.add_field(&"entropy", json!(entropy));

        self.dst_entropy.clear();
        self.src_entropy.clear();
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
