use anyhow::{anyhow, Result};

use crate::packet;

use super::matched;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Rule {
    /// Port number
    pub port: u16,
    /// Transport layer protocol
    pub protocol: packet::Protocol,
}

pub struct Classifier {
    /// Port rules
    rules: Vec<matched::Rule>,
}

impl Default for Classifier {
    fn default() -> Self {
        Classifier {
            rules: vec![matched::Rule::new(matched::RuleType::Port); std::u16::MAX as usize * 3],
        }
    }
}

impl super::Classifier for Classifier {
    fn add_rule(&mut self, rule: &super::Rule) -> Result<super::Rule> {
        let port_rule = match &rule.rule_type {
            super::RuleType::Port(r) => r,
            r => {
                return Err(anyhow!(
                    "Mismatched rule type, expecting Port Rule, get {:?}",
                    r
                ))
            }
        };

        let base_index = match port_rule.protocol {
            packet::Protocol::TCP => std::u16::MAX as usize * 0,
            packet::Protocol::UDP => std::u16::MAX as usize * 1,
            packet::Protocol::SCTP => std::u16::MAX as usize * 2,
            _ => {
                return Err(anyhow!(
                    "Invalid protocol for a port rule, expecting TCP/UDP/SCTP, get {:?}",
                    port_rule.protocol
                ))
            }
        };
        let index = base_index + port_rule.port as usize;
        self.rules[index].id = rule.id;
        self.rules[index].processors.push(rule.processors[0]);

        Ok(super::Rule {
            id: self.rules[index].id(),
            priority: self.rules[index].priority,
            rule_type: rule.rule_type.clone(),
            processors: self.rules[index].processors.clone(),
        })
    }
}

impl Classifier {
    /// Classify packet by transport protocol and port
    pub fn classify(&self, pkt: &mut dyn packet::Packet) {
        let base_index = match pkt.layers().transport() {
            None => return,
            Some(l) => match l.protocol {
                packet::Protocol::TCP => std::u16::MAX as usize * 0,
                packet::Protocol::UDP => std::u16::MAX as usize * 1,
                packet::Protocol::SCTP => std::u16::MAX as usize * 2,
                _ => return,
            },
        };

        let src_port = match pkt.src_port() {
            None => unreachable!("this should never happens"),
            Some(port) => port,
        };
        let src_index = src_port as usize + base_index;
        if self.rules[src_index].processors.len() > 0 {
            pkt.rules_mut().as_mut().push(self.rules[src_index].clone());
        }

        let dst_port = match pkt.dst_port() {
            None => unreachable!("this should never happens"),
            Some(port) => port,
        };
        let dst_index = dst_port as usize + base_index;
        if self.rules[dst_index].processors.len() > 0 {
            pkt.rules_mut().as_mut().push(self.rules[dst_index].clone());
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
    fn add_same_port_rule() {
        let mut classifier = Box::new(Classifier::default());
        let port_rule = Rule {
            port: 80,
            protocol: packet::Protocol::TCP,
        };
        let mut rule = super::super::Rule::new(1);
        rule.rule_type = super::super::RuleType::Port(port_rule);
        assert!(matches!(classifier.add_rule(&mut rule), Ok(_)));

        let rule = &classifier.rules[(port_rule.port) as usize];
        assert_eq!(rule.processors.len(), 1);
        assert_eq!(rule.processors[0], 1);

        let port_rule = Rule {
            port: 80,
            protocol: packet::Protocol::TCP,
        };
        let mut rule = super::super::Rule::new(12);
        rule.rule_type = super::super::RuleType::Port(port_rule);
        assert!(matches!(classifier.add_rule(&mut rule), Ok(rule) if rule.id == 0));

        let rule = &classifier.rules[(port_rule.port) as usize];
        assert_eq!(rule.processors.len(), 2);
        assert_eq!(rule.processors[1], 12);
    }

    #[test]
    fn add_invalid_rule_type_rule() {
        let mut classifier = Classifier::default();
        let mut rule = super::super::Rule::new(0);
        rule.rule_type = super::super::RuleType::All;
        assert!(matches!(classifier.add_rule(&mut rule), Err(_)));
    }

    #[test]
    fn add_invalid_transport_protocol_rule() {
        let mut classifier = Classifier::default();
        let mut rule = super::super::Rule::new(0);
        rule.rule_type = super::super::RuleType::Port(Rule {
            port: 0,
            protocol: packet::Protocol::ETHERNET,
        });
        assert!(matches!(classifier.add_rule(&mut rule), Err(_)));
    }

    #[test]
    fn classify() {
        let mut classifier = Classifier::default();
        let port_rule = Rule {
            port: 80,
            protocol: packet::Protocol::TCP,
        };
        let mut rule = super::super::Rule::new(1);
        rule.rule_type = super::super::RuleType::Port(port_rule);

        classifier.add_rule(&mut rule).unwrap();

        let mut pkt = Box::new(Packet::default());
        pkt.raw = Box::new(vec![
            0x8c, 0xab, 0x8e, 0xfc, 0x30, 0xc1, 0x8c, 0x85, 0x90, 0x1b, 0x17, 0x95, 0x08, 0x00,
            0x45, 0x00, 0x01, 0x5e, 0x00, 0x00, 0x40, 0x00, 0x40, 0x06, 0x1c, 0x4e, 0xc0, 0xa8,
            0x02, 0xde, 0x11, 0xfd, 0x47, 0xc9, 0xe3, 0x0a, 0x00, 0x50, 0x73, 0xd0, 0x6a, 0x40,
            0xcd, 0xed, 0xce, 0xde, 0x80, 0x18, 0x08, 0x0a, 0x2b, 0xcd, 0x00, 0x00, 0x01, 0x01,
            0x08, 0x0a, 0x40, 0x16, 0x4f, 0xf8, 0x84, 0x8b, 0x3e, 0x21, 0x47, 0x45, 0x54, 0x20,
            0x2f, 0x6f, 0x63, 0x73, 0x70, 0x2d, 0x64, 0x65, 0x76, 0x69, 0x64, 0x30, 0x31, 0x2f,
            0x4d, 0x45, 0x34, 0x77, 0x54, 0x4b, 0x41, 0x44, 0x41, 0x67, 0x45, 0x41, 0x4d, 0x45,
            0x55, 0x77, 0x51, 0x7a, 0x42, 0x42, 0x4d, 0x41, 0x6b, 0x47, 0x42, 0x53, 0x73, 0x4f,
            0x41, 0x77, 0x49, 0x61, 0x42, 0x51, 0x41, 0x45, 0x46, 0x44, 0x4f, 0x42, 0x30, 0x65,
            0x25, 0x32, 0x46, 0x62, 0x61, 0x4c, 0x43, 0x46, 0x49, 0x55, 0x30, 0x75, 0x37, 0x36,
            0x25, 0x32, 0x42, 0x4d, 0x53, 0x6d, 0x6c, 0x6b, 0x50, 0x43, 0x70, 0x73, 0x42, 0x42,
            0x52, 0x58, 0x46, 0x25, 0x32, 0x42, 0x32, 0x69, 0x7a, 0x39, 0x78, 0x38, 0x6d, 0x4b,
            0x45, 0x51, 0x34, 0x50, 0x79, 0x25, 0x32, 0x42, 0x68, 0x79, 0x30, 0x73, 0x38, 0x75,
            0x4d, 0x58, 0x56, 0x41, 0x49, 0x49, 0x54, 0x61, 0x46, 0x74, 0x6d, 0x55, 0x59, 0x67,
            0x4c, 0x61, 0x59, 0x25, 0x33, 0x44, 0x20, 0x48, 0x54, 0x54, 0x50, 0x2f, 0x31, 0x2e,
            0x31, 0x0d, 0x0a, 0x48, 0x6f, 0x73, 0x74, 0x3a, 0x20, 0x6f, 0x63, 0x73, 0x70, 0x2e,
            0x61, 0x70, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x0d, 0x0a, 0x41, 0x63, 0x63,
            0x65, 0x70, 0x74, 0x3a, 0x20, 0x2a, 0x2f, 0x2a, 0x0d, 0x0a, 0x41, 0x63, 0x63, 0x65,
            0x70, 0x74, 0x2d, 0x4c, 0x61, 0x6e, 0x67, 0x75, 0x61, 0x67, 0x65, 0x3a, 0x20, 0x7a,
            0x68, 0x2d, 0x63, 0x6e, 0x0d, 0x0a, 0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69,
            0x6f, 0x6e, 0x3a, 0x20, 0x6b, 0x65, 0x65, 0x70, 0x2d, 0x61, 0x6c, 0x69, 0x76, 0x65,
            0x0d, 0x0a, 0x41, 0x63, 0x63, 0x65, 0x70, 0x74, 0x2d, 0x45, 0x6e, 0x63, 0x6f, 0x64,
            0x69, 0x6e, 0x67, 0x3a, 0x20, 0x67, 0x7a, 0x69, 0x70, 0x2c, 0x20, 0x64, 0x65, 0x66,
            0x6c, 0x61, 0x74, 0x65, 0x0d, 0x0a, 0x55, 0x73, 0x65, 0x72, 0x2d, 0x41, 0x67, 0x65,
            0x6e, 0x74, 0x3a, 0x20, 0x63, 0x6f, 0x6d, 0x2e, 0x61, 0x70, 0x70, 0x6c, 0x65, 0x2e,
            0x74, 0x72, 0x75, 0x73, 0x74, 0x64, 0x2f, 0x32, 0x2e, 0x30, 0x0d, 0x0a, 0x0d, 0x0a,
        ]);
        pkt.layers = Layers::new_with_default_max_layers();
        pkt.layers.transport = Some(0);
        let end = pkt.raw().len();
        let transport = pkt.layers_mut().transport_mut().unwrap();

        transport.protocol = packet::Protocol::TCP;
        transport.range.start = 34;
        transport.range.end = end;
        let mut pkt: Box<dyn PacketTrait> = pkt;
        classifier.classify(pkt.as_mut());
        assert_eq!(pkt.rules().len(), 1);
        assert_eq!(pkt.rules()[0].rule_type, matched::RuleType::Port);
        assert_eq!(pkt.rules()[0].processors[0], 1);
        assert_eq!(pkt.rules()[0].processors.len(), 1);

        let port_rule = Rule {
            port: 53,
            protocol: packet::Protocol::UDP,
        };
        let mut rule = super::super::Rule::new(2);
        rule.rule_type = super::super::RuleType::Port(port_rule);

        classifier.add_rule(&mut rule).unwrap();

        let mut pkt = Box::new(Packet::default());
        pkt.raw = Box::new(vec![
            0x8c, 0xab, 0x8e, 0xfc, 0x30, 0xc1, 0x8c, 0x85, 0x90, 0x1b, 0x17, 0x95, 0x08, 0x00,
            0x45, 0x00, 0x00, 0x49, 0x94, 0x8f, 0x00, 0x00, 0xff, 0x11, 0xa0, 0xe4, 0xc0, 0xa8,
            0x02, 0xde, 0xc0, 0xa8, 0x02, 0x01, 0xd2, 0x28, 0x00, 0x35, 0x00, 0x35, 0xf8, 0x70,
            0x9c, 0xfc, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x73,
            0x61, 0x66, 0x65, 0x62, 0x72, 0x6f, 0x77, 0x73, 0x69, 0x6e, 0x67, 0x0a, 0x67, 0x6f,
            0x6f, 0x67, 0x6c, 0x65, 0x61, 0x70, 0x69, 0x73, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00,
            0x01, 0x00, 0x01,
        ]);
        *pkt.layers_mut() = Layers::new_with_default_max_layers();
        pkt.layers.transport = Some(0);
        let end = pkt.raw().len();
        let transport = pkt.layers_mut().transport_mut().unwrap();

        transport.protocol = packet::Protocol::UDP;
        transport.range.start = 34;
        transport.range.end = end;
        let mut pkt: Box<dyn PacketTrait> = pkt;
        classifier.classify(pkt.as_mut());
        assert_eq!(pkt.rules().len(), 1);
        assert_eq!(pkt.rules()[0].rule_type, matched::RuleType::Port);
        assert_eq!(pkt.rules()[0].processors[0], 2);
        assert_eq!(pkt.rules()[0].processors.len(), 1);

        let port_rule = Rule {
            port: 32836,
            protocol: packet::Protocol::SCTP,
        };
        let mut rule = super::super::Rule::new(3);
        rule.rule_type = super::super::RuleType::Port(port_rule);

        classifier.add_rule(&mut rule).unwrap();

        let mut pkt = Box::new(Packet::default());
        pkt.raw = Box::new(vec![
            0x00, 0x04, 0x96, 0x08, 0xe0, 0x40, 0x00, 0x0e, 0x2e, 0x24, 0x37, 0x5f, 0x08, 0x00,
            0x45, 0x02, 0x01, 0xc4, 0x00, 0x01, 0x40, 0x00, 0x40, 0x84, 0xbb, 0x6f, 0x9b, 0xe6,
            0x18, 0x9b, 0xcb, 0xff, 0xfc, 0xc2, 0x80, 0x44, 0x00, 0x50, 0xd2, 0x6a, 0xc1, 0xe5,
            0x70, 0xe5, 0x5b, 0x4c, 0x00, 0x03, 0x01, 0xa3, 0x2b, 0x2d, 0x7e, 0xb2, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x47, 0x45, 0x54, 0x20, 0x2f, 0x20, 0x48, 0x54,
            0x54, 0x50, 0x2f, 0x31, 0x2e, 0x31, 0x0d, 0x0a, 0x48, 0x6f, 0x73, 0x74, 0x3a, 0x20,
            0x32, 0x30, 0x33, 0x2e, 0x32, 0x35, 0x35, 0x2e, 0x32, 0x35, 0x32, 0x2e, 0x31, 0x39,
            0x34, 0x0d, 0x0a, 0x55, 0x73, 0x65, 0x72, 0x2d, 0x41, 0x67, 0x65, 0x6e, 0x74, 0x3a,
            0x20, 0x4d, 0x6f, 0x7a, 0x69, 0x6c, 0x6c, 0x61, 0x2f, 0x35, 0x2e, 0x30, 0x20, 0x28,
            0x58, 0x31, 0x31, 0x3b, 0x20, 0x55, 0x3b, 0x20, 0x4c, 0x69, 0x6e, 0x75, 0x78, 0x20,
            0x69, 0x36, 0x38, 0x36, 0x3b, 0x20, 0x6b, 0x6f, 0x2d, 0x4b, 0x52, 0x3b, 0x20, 0x72,
            0x76, 0x3a, 0x31, 0x2e, 0x37, 0x2e, 0x31, 0x32, 0x29, 0x20, 0x47, 0x65, 0x63, 0x6b,
            0x6f, 0x2f, 0x32, 0x30, 0x30, 0x35, 0x31, 0x30, 0x30, 0x37, 0x20, 0x44, 0x65, 0x62,
            0x69, 0x61, 0x6e, 0x2f, 0x31, 0x2e, 0x37, 0x2e, 0x31, 0x32, 0x2d, 0x31, 0x0d, 0x0a,
            0x41, 0x63, 0x63, 0x65, 0x70, 0x74, 0x3a, 0x20, 0x74, 0x65, 0x78, 0x74, 0x2f, 0x78,
            0x6d, 0x6c, 0x2c, 0x61, 0x70, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e,
            0x2f, 0x78, 0x6d, 0x6c, 0x2c, 0x61, 0x70, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x69,
            0x6f, 0x6e, 0x2f, 0x78, 0x68, 0x74, 0x6d, 0x6c, 0x2b, 0x78, 0x6d, 0x6c, 0x2c, 0x74,
            0x65, 0x78, 0x74, 0x2f, 0x68, 0x74, 0x6d, 0x6c, 0x3b, 0x71, 0x3d, 0x30, 0x2e, 0x39,
            0x2c, 0x74, 0x65, 0x78, 0x74, 0x2f, 0x70, 0x6c, 0x61, 0x69, 0x6e, 0x3b, 0x71, 0x3d,
            0x30, 0x2e, 0x38, 0x2c, 0x69, 0x6d, 0x61, 0x67, 0x65, 0x2f, 0x70, 0x6e, 0x67, 0x2c,
            0x2a, 0x2f, 0x2a, 0x3b, 0x71, 0x3d, 0x30, 0x2e, 0x35, 0x0d, 0x0a, 0x41, 0x63, 0x63,
            0x65, 0x70, 0x74, 0x2d, 0x4c, 0x61, 0x6e, 0x67, 0x75, 0x61, 0x67, 0x65, 0x3a, 0x20,
            0x6b, 0x6f, 0x2c, 0x65, 0x6e, 0x2d, 0x75, 0x73, 0x3b, 0x71, 0x3d, 0x30, 0x2e, 0x37,
            0x2c, 0x65, 0x6e, 0x3b, 0x71, 0x3d, 0x30, 0x2e, 0x33, 0x0d, 0x0a, 0x41, 0x63, 0x63,
            0x65, 0x70, 0x74, 0x2d, 0x45, 0x6e, 0x63, 0x6f, 0x64, 0x69, 0x6e, 0x67, 0x3a, 0x20,
            0x67, 0x7a, 0x69, 0x70, 0x2c, 0x64, 0x65, 0x66, 0x6c, 0x61, 0x74, 0x65, 0x0d, 0x0a,
            0x41, 0x63, 0x63, 0x65, 0x70, 0x74, 0x2d, 0x43, 0x68, 0x61, 0x72, 0x73, 0x65, 0x74,
            0x3a, 0x20, 0x45, 0x55, 0x43, 0x2d, 0x4b, 0x52, 0x2c, 0x75, 0x74, 0x66, 0x2d, 0x38,
            0x3b, 0x71, 0x3d, 0x30, 0x2e, 0x37, 0x2c, 0x2a, 0x3b, 0x71, 0x3d, 0x30, 0x2e, 0x37,
            0x0d, 0x0a, 0x4b, 0x65, 0x65, 0x70, 0x2d, 0x41, 0x6c, 0x69, 0x76, 0x65, 0x3a, 0x20,
            0x33, 0x30, 0x30, 0x0d, 0x0a, 0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f,
            0x6e, 0x3a, 0x20, 0x6b, 0x65, 0x65, 0x70, 0x2d, 0x61, 0x6c, 0x69, 0x76, 0x65, 0x0d,
            0x0a, 0x0d, 0x0a, 0x00,
        ]);
        *pkt.layers_mut() = Layers::new_with_default_max_layers();
        pkt.layers.transport = Some(0);
        let end = pkt.raw().len();
        let transport = pkt.layers_mut().transport_mut().unwrap();

        transport.protocol = packet::Protocol::SCTP;
        transport.range.start = 34;
        transport.range.end = end;
        let mut pkt: Box<dyn PacketTrait> = pkt;
        classifier.classify(pkt.as_mut());
        assert_eq!(pkt.rules().len(), 1);
        assert_eq!(pkt.rules()[0].rule_type, matched::RuleType::Port);
        assert_eq!(pkt.rules()[0].processors[0], 3);
        assert_eq!(pkt.rules()[0].processors.len(), 1);
    }
}
