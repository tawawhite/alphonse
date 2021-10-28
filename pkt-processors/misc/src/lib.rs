use std::collections::HashSet;
use std::str::FromStr;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use fnv::FnvHashMap;
use serde::Deserialize;

use alphonse_api as api;
use api::classifiers::{dpi, ClassifierManager, RuleID};
use api::hyperscan;
use api::packet::Packet;
use api::plugins::processor::{
    Builder as ProcessorBuilder, Processor as PktProcessor, ProcessorID,
};
use api::plugins::{Plugin, PluginType};
use api::session::{ProtocolLayer, Session};

mod aruba_papi;
mod bgp;
mod dropbox;
mod flap;
mod general;
mod gh0st;
mod hdfs;
mod hsrp;
mod imap;
mod isakmp;
mod kafka;
mod mqtt;
mod netflow;
mod ntp;
mod other220;
mod rdp;
mod rip;
mod safet;
mod skinny;
mod tacacs;
mod telnet;
mod user;
mod wudo;

use general::MiscRule;

trait MiscProcessUnit: Send + Sync {
    fn process(&mut self, ses: &mut Session, pkt: &dyn Packet) -> Result<()>;
    fn box_clone(&self) -> Box<dyn MiscProcessUnit>;
}

impl Clone for Box<dyn MiscProcessUnit> {
    fn clone(&self) -> Self {
        self.box_clone()
    }
}

#[derive(Clone, Deserialize)]
enum MatchCallBack {
    #[serde(skip_deserializing)]
    Func(Box<dyn MiscProcessUnit>),
    ProtocolName(String),
    Tag(String),
}

#[derive(Default)]
pub struct Builder {
    id: ProcessorID,
    match_cbs: FnvHashMap<RuleID, Vec<MatchCallBack>>,
    rules: Arc<HashSet<MiscRule>>,
}

impl ProcessorBuilder for Builder {
    fn build(&self, _: &api::config::Config) -> Box<dyn PktProcessor> {
        let mut p = Box::new(Misc::default());
        p.id = self.id;
        p
    }

    fn id(&self) -> ProcessorID {
        self.id
    }

    fn set_id(&mut self, id: ProcessorID) {
        self.id = id
    }

    fn register_classify_rules(&mut self, manager: &mut ClassifierManager) -> Result<()> {
        let rules = self.rules.as_ref().clone();
        for rule in &rules {
            match rule {
                MiscRule::Port(r) => self.add_simple_port_rule(r, manager)?,
                MiscRule::Regex(r) => self.add_dpi_rule(r, manager)?,
            }
        }

        aruba_papi::register_classify_rules(self, manager)?;
        bgp::register_classify_rules(self, manager)?;
        dropbox::register_classify_rules(self, manager)?;
        flap::register_classify_rules(self, manager)?;
        gh0st::register_classify_rules(self, manager)?;
        hdfs::register_classify_rules(self, manager)?;
        hsrp::register_classify_rules(self, manager)?;
        imap::register_classify_rules(self, manager)?;
        isakmp::register_classify_rules(self, manager)?;
        kafka::register_classify_rules(self, manager)?;
        mqtt::register_classify_rules(self, manager)?;
        netflow::register_classify_rules(self, manager)?;
        ntp::register_classify_rules(self, manager)?;
        other220::register_classify_rules(self, manager)?;
        rdp::register_classify_rules(self, manager)?;
        rip::register_classify_rules(self, manager)?;
        safet::register_classify_rules(self, manager)?;
        skinny::register_classify_rules(self, manager)?;
        tacacs::register_classify_rules(self, manager)?;
        telnet::register_classify_rules(self, manager)?;
        user::register_classify_rules(self, manager)?;
        wudo::register_classify_rules(self, manager)?;

        Ok(())
    }
}

impl Plugin for Builder {
    fn plugin_type(&self) -> PluginType {
        PluginType::PacketProcessor
    }

    fn init(&mut self, cfg: &api::config::Config) -> Result<()> {
        let rules = cfg.get_object("misc.rules");
        match rules {
            yaml_rust::Yaml::Array(a) => {
                let mut rules = std::collections::HashSet::new();
                for rule in a {
                    let mut out_str = String::new();
                    let mut emitter = yaml_rust::YamlEmitter::new(&mut out_str);
                    emitter.dump(rule)?;
                    let rule: MiscRule = serde_yaml::from_str(&out_str)?;
                    rules.insert(rule);
                }
                self.rules = Arc::new(rules);
            }
            yaml_rust::Yaml::Null => println!("misc pkt-processor has no rule to load"),
            _ => {
                eprintln!("Couldn't load misc.rules, invalid value type or bad array value");
                return Err(anyhow!("Failed to load misc.rules"));
            }
        }

        Ok(())
    }

    fn name(&self) -> &str {
        "misc"
    }
}

impl Builder {
    fn insert_cb(&mut self, id: RuleID, cb: MatchCallBack) {
        match self.match_cbs.get_mut(&id) {
            None => {
                self.match_cbs.insert(id, vec![cb]);
            }
            Some(cbs) => cbs.push(cb),
        }
    }

    fn add_dpi_rule(
        &mut self,
        rule: &general::Regex,
        manager: &mut ClassifierManager,
    ) -> Result<()> {
        let flags = match &rule.regex_flags {
            Some(flags) => api::hyperscan::CompileFlags::from_str(flags)?,
            None => api::hyperscan::CompileFlags::default(),
        };

        let mut pattern = hyperscan::Pattern::new(&rule.regex)?;
        pattern.flags = flags;
        let rule_id =
            manager.add_dpi_rule(self.id, &pattern, rule.basic.transport_protocol.into())?;

        if let Some(protocol) = &rule.basic.protocol {
            self.insert_cb(rule_id, MatchCallBack::ProtocolName(protocol.clone()));
        }
        if let Some(tag) = &rule.basic.tag {
            self.insert_cb(rule_id, MatchCallBack::Tag(tag.clone()));
        }
        Ok(())
    }

    fn add_dpi_rule_with_func<S: AsRef<str>>(
        &mut self,
        pattern: S,
        trans_protocol: dpi::Protocol,
        func: &dyn MiscProcessUnit,
        manager: &mut ClassifierManager,
    ) -> Result<()> {
        let rule_id = manager.add_simple_dpi_rule(self.id, pattern, trans_protocol)?;
        self.insert_cb(rule_id, MatchCallBack::Func(func.box_clone()));
        Ok(())
    }

    fn add_tcp_dpi_rule_with_func<S: AsRef<str>>(
        &mut self,
        pattern: S,
        func: &dyn MiscProcessUnit,
        manager: &mut ClassifierManager,
    ) -> Result<()> {
        self.add_dpi_rule_with_func(pattern, dpi::Protocol::TCP, func, manager)
    }

    fn add_udp_dpi_rule_with_func<S: AsRef<str>>(
        &mut self,
        pattern: S,
        func: &dyn MiscProcessUnit,
        manager: &mut ClassifierManager,
    ) -> Result<()> {
        self.add_dpi_rule_with_func(pattern, dpi::Protocol::UDP, func, manager)
    }

    fn add_tcp_udp_dpi_rule_with_func<S: AsRef<str>>(
        &mut self,
        pattern: S,
        func: &dyn MiscProcessUnit,
        manager: &mut ClassifierManager,
    ) -> Result<()> {
        self.add_dpi_rule_with_func(
            pattern,
            dpi::Protocol::TCP | dpi::Protocol::UDP,
            func,
            manager,
        )
    }

    fn add_simple_port_rule(
        &mut self,
        rule: &general::Port,
        manager: &mut ClassifierManager,
    ) -> Result<()> {
        let rule_id =
            manager.add_port_rule(self.id, rule.port, rule.basic.transport_protocol.into())?;
        if let Some(protocol) = &rule.basic.protocol {
            self.insert_cb(rule_id, MatchCallBack::ProtocolName(protocol.clone()));
        }
        if let Some(tag) = &rule.basic.tag {
            self.insert_cb(rule_id, MatchCallBack::Tag(tag.clone()));
        }

        Ok(())
    }

    fn add_port_rule_with_func(
        &mut self,
        port: u16,
        protocol: api::packet::Protocol,
        func: &dyn MiscProcessUnit,
        manager: &mut ClassifierManager,
    ) -> Result<()> {
        let rule_id = manager.add_port_rule(self.id, port, protocol)?;
        self.insert_cb(rule_id, MatchCallBack::Func(func.box_clone()));
        Ok(())
    }

    fn add_tcp_port_rule_with_func(
        &mut self,
        port: u16,
        func: &dyn MiscProcessUnit,
        manager: &mut ClassifierManager,
    ) -> Result<()> {
        self.add_port_rule_with_func(port, api::packet::Protocol::TCP, func, manager)
    }

    fn add_udp_port_rule_with_func(
        &mut self,
        port: u16,
        func: &dyn MiscProcessUnit,
        manager: &mut ClassifierManager,
    ) -> Result<()> {
        self.add_port_rule_with_func(port, api::packet::Protocol::UDP, func, manager)
    }
}

#[derive(Clone, Default)]
pub struct Misc {
    id: ProcessorID,
    classified: bool,
    match_cbs: FnvHashMap<RuleID, Vec<MatchCallBack>>,
    rules: Arc<HashSet<MiscRule>>,
}

type ClassifyFunc = fn(ses: &mut Session, pkt: &dyn Packet) -> Result<()>;

impl MiscProcessUnit for ClassifyFunc {
    fn process(&mut self, ses: &mut Session, pkt: &dyn Packet) -> Result<()> {
        self(ses, pkt)
    }

    fn box_clone(&self) -> Box<dyn MiscProcessUnit> {
        Box::new(self.clone())
    }
}

impl PktProcessor for Misc {
    fn id(&self) -> ProcessorID {
        self.id
    }

    fn name(&self) -> &'static str {
        &"misc"
    }

    fn parse_pkt(
        &mut self,
        pkt: &dyn api::packet::Packet,
        rule: Option<&api::classifiers::matched::Rule>,
        ses: &mut api::session::Session,
    ) -> Result<()> {
        let rule = match rule {
            None => {
                return Ok(());
            }
            Some(r) => r,
        };
        match self.match_cbs.get_mut(&rule.id()) {
            Some(cbs) => {
                for cb in cbs {
                    match cb {
                        MatchCallBack::ProtocolName(protocol) => {
                            ses.add_protocol(protocol, ProtocolLayer::Application);
                        }
                        MatchCallBack::Tag(tag) => {
                            ses.add_tag(tag);
                        }
                        MatchCallBack::Func(func) => {
                            func.process(ses, pkt)?;
                        }
                    };
                }
            }
            None => {
                todo!("handle rule matched, but no callback found")
            }
        };
        Ok(())
    }

    fn save(&mut self, _: &mut Session) {}
}

fn add_protocol<S: AsRef<str>>(ses: &mut Session, protocol: S) {
    ses.add_protocol(&protocol, ProtocolLayer::Application)
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
    use std::fs::File;
    use std::io::Read;
    use std::path::Path;

    use yaml_rust::YamlLoader;

    use api::config::Config;
    pub use api::packet::test::Packet;
    use api::packet::Protocol;

    pub fn assert_has_protocol<S: AsRef<str>>(ses: &Session, protocol: S) {
        assert!(ses.has_protocol(&protocol, ProtocolLayer::Application))
    }

    #[test]
    pub fn sample_rules() -> Result<()> {
        let mut config = Config::default();
        let cfg_path = Path::new("../../alphonse.example.yml");
        let mut s = String::new();
        File::open(cfg_path)?.read_to_string(&mut s)?;
        let docs = YamlLoader::load_from_str(&s)?;
        let doc = &docs[0];
        config.doc = api::config::Yaml(doc.clone());

        let mut misc = Misc::default();
        misc.init(&config).unwrap();

        let mut manager = ClassifierManager::new();

        misc.register_classify_rules(&mut manager).unwrap();
        manager.prepare().unwrap();
        let mut scratch = manager.alloc_scratch().unwrap();

        // areospike
        let mut pkt: Box<Packet> = Box::new(Packet::default());
        pkt.raw = Box::new(b"\x02\x01\x00\x00\x00\x00\x00\x4e\x6e\x6f\x64\x65".to_vec());
        pkt.layers.trans.protocol = Protocol::TCP;
        pkt.layers.app.protocol = Protocol::APPLICATION;
        pkt.caplen = pkt.raw.len() as u32;
        let mut pkt: Box<dyn api::packet::Packet> = pkt;
        manager.classify(pkt.as_mut(), &mut scratch).unwrap();

        assert!(pkt.rules().len() > 0);
        let mut ses = Session::new();
        misc.parse_pkt(pkt.as_ref(), Some(&pkt.rules()[0]), &mut ses)
            .unwrap();
        assert_has_protocol(&ses, "areospike");

        // bitcoin
        let mut pkt: Box<Packet> = Box::new(Packet::default());
        pkt.raw = Box::new(b"\xf9\xbe\xb4\xd9".to_vec());
        pkt.layers.trans.protocol = Protocol::TCP;
        pkt.layers.app.protocol = Protocol::APPLICATION;
        let mut pkt: Box<dyn api::packet::Packet> = pkt;
        manager.classify(pkt.as_mut(), &mut scratch).unwrap();
        assert!(pkt.rules().len() > 0);

        let mut ses = Session::new();
        misc.parse_pkt(pkt.as_ref(), Some(&pkt.rules()[0]), &mut ses)
            .unwrap();
        assert_has_protocol(&ses, "bitcoin");

        Ok(())
    }
}
