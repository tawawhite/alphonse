use std::iter::FromIterator;

use anyhow::Result;
use hyperscan::{BlockDatabase, Builder};

use super::packet;
use super::parsers::ParserID;

#[derive(Clone)]
struct DpiRule {
    hs_pattern: hyperscan::Pattern,
    protocols: Vec<ParserID>,
}

/// Protocol Classifier
pub struct ClassifierManager {
    all_pkt_protocols: Box<Vec<ParserID>>,

    tcp_port_protocols: Box<Vec<Vec<ParserID>>>,
    udp_port_protocols: Box<Vec<Vec<ParserID>>>,
    sctp_port_protocols: Box<Vec<Vec<ParserID>>>,

    dpi_rules: Box<Vec<DpiRule>>,

    hs_db: Option<BlockDatabase>,
}

/// Protocol classifier scratch
///
/// Must not be shared across threads
pub struct ClassifyScratch {
    hs_scratch: Option<hyperscan::Scratch>,
}

impl ClassifierManager {
    pub fn new() -> ClassifierManager {
        fn initialize_vec_of_vec(size: usize) -> Vec<Vec<ParserID>> {
            let mut v: Vec<Vec<ParserID>> = Vec::with_capacity(size);
            for _ in 0..size {
                v.push(Vec::new());
            }
            v
        }

        ClassifierManager {
            all_pkt_protocols: Box::new(Vec::new()),
            tcp_port_protocols: Box::new(initialize_vec_of_vec(65536)),
            udp_port_protocols: Box::new(initialize_vec_of_vec(65536)),
            sctp_port_protocols: Box::new(initialize_vec_of_vec(65536)),
            dpi_rules: Box::new(Vec::new()),
            hs_db: None,
        }
    }

    /// Allocate a protocol classifier scratch
    pub fn alloc_scratch(&self) -> Result<ClassifyScratch> {
        let scratch = match &self.hs_db {
            Some(db) => Some(db.alloc_scratch()?),
            None => None,
        };
        Ok(ClassifyScratch {
            hs_scratch: scratch,
        })
    }

    pub fn add_all_pkt_rule(&mut self, parser_id: ParserID) {
        self.all_pkt_protocols.push(parser_id);
    }

    /// Add port classify rule for a protocol
    pub fn add_port_rule(
        &mut self,
        parser_id: ParserID,
        src_port: u16,
        trans_proto: packet::Protocol,
    ) {
        match trans_proto {
            packet::Protocol::TCP => match (*self.tcp_port_protocols).get_mut(src_port as usize) {
                Some(vec) => vec.push(parser_id),
                None => unimplemented!(),
            },
            packet::Protocol::UDP => match (*self.udp_port_protocols).get_mut(src_port as usize) {
                Some(vec) => vec.push(parser_id),
                None => unimplemented!(),
            },
            packet::Protocol::SCTP => {
                match (*self.sctp_port_protocols).get_mut(src_port as usize) {
                    Some(vec) => vec.push(parser_id),
                    None => unimplemented!(),
                }
            }
            _ => unimplemented!(),
        };
    }

    pub fn add_dpi_rule(&mut self, pattern: hyperscan::Pattern, parser_id: ParserID) {
        let mut same_pattern_index: i32 = -1;
        for (i, dpi_rule) in (&*self.dpi_rules).iter().enumerate() {
            if dpi_rule.hs_pattern.expression == pattern.expression {
                same_pattern_index = i as i32;
                break;
            }
        }

        if same_pattern_index < 0 {
            let dpi_rule = DpiRule {
                hs_pattern: pattern,
                protocols: vec![parser_id],
            };
            self.dpi_rules.push(dpi_rule);
        } else {
            let dpi_rule = self.dpi_rules.get_mut(same_pattern_index as usize).unwrap();
            let mut id_conflict = false;
            for p_id in &dpi_rule.protocols {
                if *p_id == parser_id {
                    id_conflict = true;
                    break;
                }
            }
            if !id_conflict {
                dpi_rule.protocols.push(parser_id);
            } else {
                panic!("DpiRule protocol id conflict!");
            }
        }
    }

    pub fn prepare(&mut self) {
        if self.dpi_rules.len() == 0 {
            self.hs_db = None
        } else {
            let patterns = hyperscan::Patterns::from_iter(
                (*self.dpi_rules.clone())
                    .into_iter()
                    .map(|r| r.hs_pattern)
                    .into_iter(),
            );
            self.hs_db = Some(patterns.build().unwrap());
        }
    }

    /// Classify protocol
    #[inline]
    pub fn classify(
        &self,
        pkt: &packet::Packet,
        protocols: &mut Vec<ParserID>,
        scratch: &ClassifyScratch,
    ) -> Result<()> {
        match (&self.hs_db, &scratch.hs_scratch) {
            (Some(db), Some(s)) => {
                db.scan(
                    &pkt.data.as_slice()[pkt.app_layer.offset as usize..],
                    s,
                    |id, _from, _to, _flags| {
                        // !!! use direct access for performance, very dangerous, may panic !!!
                        let dpi_rule = &self.dpi_rules[id as usize];
                        protocols.extend(&dpi_rule.protocols);
                        hyperscan::Matching::Continue
                    },
                )?;
                Ok(())
            }
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn classifier_add_all_pkt_rule() {
        let mut classifier = ClassifierManager::new();
        classifier.add_all_pkt_rule(0);
        assert_eq!(classifier.all_pkt_protocols.len(), 1);
        assert_eq!(classifier.all_pkt_protocols[0], 0);
    }

    #[test]
    fn classifier_add_port_rule() {
        let mut classifier = ClassifierManager::new();
        classifier.add_port_rule(0, 443, packet::Protocol::TCP);
        assert_eq!(classifier.tcp_port_protocols[443][0], 0);

        classifier.add_port_rule(100, 80, packet::Protocol::UDP);
        classifier.add_port_rule(200, 80, packet::Protocol::UDP);
        assert_eq!(classifier.udp_port_protocols[80][0], 100);
        assert_eq!(classifier.udp_port_protocols[80][1], 200);

        classifier.add_port_rule(4, 400, packet::Protocol::SCTP);
        assert_eq!(classifier.sctp_port_protocols[400][0], 4);
    }

    #[test]
    fn classifier_add_dpi_rule() {
        let mut classifier = ClassifierManager::new();
        let expression = String::from("regex");
        let pattern = hyperscan::Pattern::new(expression.clone()).unwrap();
        classifier.add_dpi_rule(pattern, 100);
        assert_eq!(classifier.dpi_rules[0].hs_pattern.expression, expression);
        assert_eq!(classifier.dpi_rules[0].protocols[0], 100);

        classifier.prepare();
        let scratch = classifier.alloc_scratch().unwrap();
        let mut protocols = Vec::new();
        let mut pkt = packet::Packet::default();

        classifier.classify(&pkt, &mut protocols, &scratch).unwrap();
        assert_eq!(protocols.len(), 0);

        pkt.data = Box::new(Vec::from(String::from("regex").as_bytes()));
        classifier.classify(&pkt, &mut protocols, &scratch).unwrap();
        assert_eq!(protocols.len(), 1);
        println!("result: {:?}", protocols);
        assert_eq!(protocols[0], 100);
    }

    #[test]
    fn classifier_add_dpi_rule_with_existing_expression() {
        let mut classifier = ClassifierManager::new();
        let expression = String::from("regex");
        let pattern = hyperscan::Pattern::new(expression.clone()).unwrap();
        classifier.add_dpi_rule(pattern, 100);
        assert_eq!(classifier.dpi_rules[0].hs_pattern.expression, expression);
        assert_eq!(classifier.dpi_rules[0].protocols[0], 100);

        let expression = String::from("regex");
        let pattern = hyperscan::Pattern::new(expression.clone()).unwrap();
        classifier.add_dpi_rule(pattern, 8);
        assert_eq!(classifier.dpi_rules[0].hs_pattern.expression, expression);
        assert_eq!(classifier.dpi_rules[0].protocols[1], 8);
    }
}
