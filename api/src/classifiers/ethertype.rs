use anyhow::{anyhow, Result};

use crate::classifiers::matched;
use crate::packet::{Packet, Protocol};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Rule {
    pub ethertype: u16,
}

#[derive(Clone, Debug)]
pub struct Classifier {
    /// Port rules
    rules: Vec<matched::Rule>,
}

impl Default for Classifier {
    fn default() -> Self {
        Classifier {
            rules: vec![matched::Rule::new(matched::RuleType::EtherType); std::u16::MAX as usize],
        }
    }
}

impl super::Classifier for Classifier {
    fn add_rule(&mut self, rule: &super::Rule) -> Result<super::Rule> {
        let proto_rule = match &rule.rule_type {
            super::RuleType::EtherType(r) => r,
            r => {
                return Err(anyhow!(
                    "Mismatched rule type, expecting EtherType Rule, get {:?}",
                    r
                ))
            }
        };

        let etype = proto_rule.ethertype as usize;
        self.rules[etype].id = rule.id;
        self.rules[etype].processors.push(rule.processors[0]);
        Ok(super::Rule {
            id: self.rules[etype].id(),
            priority: self.rules[etype].priority,
            rule_type: rule.rule_type.clone(),
            processors: self.rules[etype].processors.clone(),
        })
    }
}

impl Classifier {
    pub fn classify(&self, pkt: &mut dyn Packet) {
        match pkt.layers().data_link.protocol {
            Protocol::ETHERNET => {
                let offset = pkt.layers().data_link.offset as usize;
                let etype = (pkt.raw()[offset + 12] as u16) << 8 | (pkt.raw()[offset + 13] as u16);
                let etype = etype as usize;
                if self.rules[etype].processors.len() > 0 {
                    pkt.rules_mut().as_mut().push(self.rules[etype].clone());
                }
            }
            _ => return,
        };
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::classifiers::{self, Classifier as ClassifierTrait};
    use crate::packet::test::Packet;
    use crate::packet::{self, Packet as PacketTrait};

    #[test]
    fn add_same_etype_rule() {
        let mut classifier = Box::new(Classifier::default());
        let etype_rule = Rule { ethertype: 0 };
        let mut rule = classifiers::Rule::new(1);
        rule.rule_type = classifiers::RuleType::EtherType(etype_rule);
        assert!(matches!(classifier.add_rule(&mut rule), Ok(_)));

        let rule = &classifier.rules[etype_rule.ethertype as usize];
        assert_eq!(rule.processors.len(), 1);
        assert_eq!(rule.processors[0], 1);

        // Add a same rule only ID is different, we expected the same
        let etype_rule = Rule { ethertype: 0 };
        let mut rule = classifiers::Rule::new(2);
        rule.rule_type = classifiers::RuleType::EtherType(etype_rule);
        assert!(matches!(classifier.add_rule(&mut rule), Ok(rule) if rule.id == 0));

        let rule = &classifier.rules[etype_rule.ethertype as usize];
        assert_eq!(rule.processors.len(), 2);
        assert_eq!(rule.processors[1], 2);
    }

    #[test]
    fn add_invalid_rule_type_rule() {
        let mut classifier = Classifier::default();
        let mut rule = classifiers::Rule::new(0);
        rule.rule_type = classifiers::RuleType::All;
        assert!(matches!(classifier.add_rule(&mut rule), Err(_)));
    }

    /// Classify a normal TCP/IP stack packet
    #[test]
    fn classify() {
        let mut classifier = Box::new(Classifier::default());
        let etype_rule = Rule { ethertype: 0x0800 };
        let mut rule = crate::classifiers::Rule::new(1);
        rule.rule_type = crate::classifiers::RuleType::EtherType(etype_rule);
        classifier.add_rule(&mut rule).unwrap();

        let mut pkt = Box::new(Packet::default());
        pkt.layers_mut().data_link = packet::Layer {
            offset: 0,
            protocol: packet::Protocol::ETHERNET,
        };
        pkt.raw = Box::new(vec![
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00,
        ]);

        let mut pkt: Box<dyn PacketTrait> = pkt;
        classifier.classify(pkt.as_mut());
        assert_eq!(pkt.rules().len(), 1);
        assert_eq!(pkt.rules()[0].rule_type, matched::RuleType::EtherType);
        assert_eq!(pkt.rules()[0].processors[0], 1);
        assert_eq!(pkt.rules()[0].processors.len(), 1);
    }
}
