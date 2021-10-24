use std::hash::Hash;

use anyhow::{anyhow, Result};

use crate::packet::{Packet, Protocol};

use super::matched;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Rule(pub Protocol);

pub struct Classifier {
    /// Port rules
    rules: Vec<matched::Rule>,
}

impl Default for Classifier {
    fn default() -> Self {
        Classifier {
            rules: vec![matched::Rule::new(matched::RuleType::Protocol); u8::MAX as usize],
        }
    }
}

impl super::Classifier for Classifier {
    fn add_rule(&mut self, rule: &super::Rule) -> Result<super::Rule> {
        let proto_rule = match &rule.rule_type {
            super::RuleType::Protocol(r) => r,
            r => {
                return Err(anyhow!(
                    "Mismatched rule type, expecting Protocol Rule, get {:?}",
                    r
                ))
            }
        };

        let i = proto_rule.0 as u8 as usize;
        self.rules[i].id = rule.id;
        self.rules[i].processors.push(rule.processors[0]);
        Ok(super::Rule {
            id: self.rules[i].id(),
            priority: self.rules[i].priority,
            rule_type: rule.rule_type.clone(),
            processors: self.rules[i].processors.clone(),
        })
    }
}

impl Classifier {
    pub fn classify(&self, pkt: &mut dyn Packet) {
        let mut protocols = vec![];
        for layer in pkt.layers().as_ref() {
            let protocol = layer.protocol as usize;
            if self.rules[protocol].processors.len() > 0 {
                protocols.push(protocol);
            }
        }
        for protocol in protocols {
            pkt.rules_mut().as_mut().push(self.rules[protocol].clone());
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::classifiers::Classifier as ClassifierTrait;
    use crate::packet::test::Packet;
    use crate::packet::Layers;
    use crate::packet::Packet as PacketTrait;

    #[test]
    fn add_same_protocol_rule() {
        let mut classifier = Box::new(Classifier::default());
        let proto_rule = Rule(Protocol::TCP);
        let mut rule = crate::classifiers::Rule::new(1);
        rule.rule_type = crate::classifiers::RuleType::Protocol(proto_rule);
        assert!(matches!(classifier.add_rule(&mut rule), Ok(_)));

        let rule = &classifier.rules[proto_rule.0 as usize];
        assert_eq!(rule.processors.len(), 1);
        assert_eq!(rule.processors[0], 1);

        // Add a same rule only ID is different, we expected the same
        let proto_rule = Rule(Protocol::TCP);
        let mut rule = crate::classifiers::Rule::new(2);
        rule.rule_type = crate::classifiers::RuleType::Protocol(proto_rule);
        assert!(matches!(classifier.add_rule(&mut rule), Ok(rule) if rule.id == 0));

        let rule = &classifier.rules[proto_rule.0 as usize];
        assert_eq!(rule.processors.len(), 2);
        assert_eq!(rule.processors[1], 2);
    }

    #[test]
    fn add_invalid_rule_type_rule() {
        let mut classifier = Classifier::default();
        let mut rule = super::super::Rule::new(0);
        rule.rule_type = super::super::RuleType::All;
        assert!(matches!(classifier.add_rule(&mut rule), Err(_)));
    }

    /// Classify a normal TCP/IP stack packet
    #[test]
    fn classify() {
        let mut classifier = Box::new(Classifier::default());
        let proto_rule = Rule(Protocol::TCP);
        let mut rule = crate::classifiers::Rule::new(1);
        rule.rule_type = crate::classifiers::RuleType::Protocol(proto_rule);
        classifier.add_rule(&mut rule).unwrap();

        let mut pkt = Box::new(Packet::default());
        *pkt.layers_mut() = Layers::new_with_default_max_layers();
        pkt.layers_mut().datalink = Some(0);
        pkt.layers_mut().datalink_mut().unwrap().protocol = Protocol::ETHERNET;
        pkt.layers_mut().network = Some(0);
        pkt.layers_mut().network_mut().unwrap().protocol = Protocol::IPV4;
        pkt.layers_mut().transport = Some(0);
        pkt.layers_mut().transport_mut().unwrap().protocol = Protocol::TCP;
        let mut pkt: Box<dyn PacketTrait> = pkt;
        classifier.classify(pkt.as_mut());
        assert_eq!(pkt.rules().len(), 1);
        assert_eq!(pkt.rules()[0].rule_type, matched::RuleType::Protocol);
        assert_eq!(pkt.rules()[0].processors[0], 1);
        assert_eq!(pkt.rules()[0].processors.len(), 1);

        // classify a packet with no layers at all
        let mut classifier = Box::new(Classifier::default());
        let proto_rule = Rule(Protocol::ETHERNET);
        let mut rule = crate::classifiers::Rule::new(1);
        rule.rule_type = crate::classifiers::RuleType::Protocol(proto_rule);
        classifier.add_rule(&mut rule).unwrap();

        let pkt = Box::new(Packet::default());
        let mut pkt: Box<dyn PacketTrait> = pkt;
        classifier.classify(pkt.as_mut());
        assert_eq!(pkt.rules().len(), 0);
    }
}
