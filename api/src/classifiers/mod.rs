use anyhow::Result;
// use hyperscan::{BlockDatabase, Builder};

use super::packet;
use super::parsers::ParserID;

pub mod all;
pub mod dpi;
pub mod port;

const MAX_PARSER_NUM: usize = 8;

type RuleID = u32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleType {
    // Get packets by dpi rule
    DPI(dpi::Rule),
    // Get packets by transport layer port
    Port(port::Rule),
    // Get packets by protocol
    Protocol,
    // Get all packets
    All,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Rule {
    /// Rule ID
    id: RuleID,
    /// Rule priority, 255 is the highest, 0 is the lowest
    pub priority: u8,
    /// Rule type, see details in RuleType
    pub rule_type: RuleType,
    /// Matched protocol parsers
    parsers: [ParserID; MAX_PARSER_NUM],
    /// Actual matched protocol parsers count
    parsers_count: u8,
}

impl Rule {
    /// Get rule's id
    pub fn id(&self) -> RuleID {
        self.id
    }

    /// Create a new classify rule
    pub fn new(parser_id: ParserID) -> Self {
        let mut rule = Rule {
            id: 0,
            priority: 0,
            rule_type: RuleType::All,
            parsers: [0; MAX_PARSER_NUM],
            parsers_count: 1,
        };
        rule.parsers[0] = parser_id;
        rule
    }
}

pub mod matched {
    use super::{ParserID, RuleID, MAX_PARSER_NUM};
    #[repr(u8)]
    #[derive(Debug, Clone, Copy, PartialEq, Primitive)]
    pub enum RuleType {
        // Get all packets
        All = 0,
        // Get packets by dpi rule
        DPI = 1,
        // Get packets by transport layer port
        Port = 2,
        // Get packets by protocol
        Protocol = 3,
    }

    impl From<&super::RuleType> for RuleType {
        fn from(rule_type: &super::RuleType) -> Self {
            match rule_type {
                super::RuleType::All => RuleType::All,
                super::RuleType::Port(_) => RuleType::Port,
                super::RuleType::DPI(_) => RuleType::DPI,
                super::RuleType::Protocol => RuleType::Protocol,
            }
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq)]
    pub struct Rule {
        pub id: RuleID,
        pub priority: u8,
        pub rule_type: RuleType,
        pub parsers: [ParserID; MAX_PARSER_NUM],
        pub parsers_count: u8,
    }

    impl Default for Rule {
        fn default() -> Self {
            Rule {
                id: 0,
                priority: 255,
                rule_type: RuleType::All,
                parsers: [0; MAX_PARSER_NUM],
                parsers_count: 0,
            }
        }
    }

    impl From<&super::Rule> for Rule {
        fn from(rule: &super::Rule) -> Self {
            Rule {
                id: rule.id,
                priority: rule.priority,
                rule_type: RuleType::from(&rule.rule_type),
                parsers: rule.parsers,
                parsers_count: rule.parsers_count,
            }
        }
    }

    impl Rule {
        /// Get rule's id
        pub fn id(&self) -> RuleID {
            self.id
        }
    }
}

pub trait Classifier {
    /// Add a classify rule for this classifier
    ///
    /// # Arguments
    ///
    /// * `rule` - Rule information
    ///
    /// # Returns
    ///
    /// * `Result<&matched::Rule>` - Rule
    fn add_rule(&mut self, rule: &Rule) -> Result<&matched::Rule>;
}

/// Protocol Classifier
pub struct ClassifierManager {
    /// Store rule detail information
    rules: Vec<Box<Rule>>,
    /// Receive all pkts rules
    all_pkt_classifier: all::Classifier,
    /// Port classifier
    port_classifier: port::Classifier,
    /// DPI classifier
    dpi_classifier: dpi::Classifier,
}

pub type ClassifyScratch = dpi::ClassifyScratch;

impl ClassifierManager {
    pub fn new() -> ClassifierManager {
        ClassifierManager {
            rules: vec![Box::new(Rule {
                id: 0,
                priority: 255,
                rule_type: RuleType::All,
                parsers: [0; MAX_PARSER_NUM],
                parsers_count: 0,
            })], // first rule is always the receive all pkt rule
            all_pkt_classifier: all::Classifier::default(),
            port_classifier: port::Classifier::default(),
            dpi_classifier: dpi::Classifier::default(),
        }
    }

    /// Find whether there specific rule is already registerd
    ///
    /// # Arguments
    ///
    /// * `rule` - Rule information
    ///
    /// # Returns
    ///
    /// * 'Option<&Rule>` - Find result
    fn find(&self, rule: &Rule) -> Option<&Rule> {
        fn eq(a: &Rule, b: &Rule) -> bool {
            match (&a.rule_type, &b.rule_type) {
                (RuleType::All, RuleType::All) => true,
                (RuleType::All, _) => false,
                (_, RuleType::All) => false,
                _ => (a.priority == b.priority) && (a.rule_type == b.rule_type),
            }
        }

        for r in &self.rules {
            if eq(r.as_ref(), rule) {
                return Some(r.as_ref());
            }
        }
        None
    }

    pub fn add_rule(&mut self, rule: &mut Rule) -> Result<RuleID> {
        match self.find(rule) {
            None => {
                rule.id = self.rules.len() as RuleID;
                self.rules.push(Box::new(rule.clone()));
            }
            Some(r) => rule.id = r.id(),
        };

        let rule = match rule.rule_type {
            RuleType::All => self.all_pkt_classifier.add_rule(rule)?,
            RuleType::DPI(_) => self.dpi_classifier.add_rule(rule)?,
            RuleType::Port(_) => self.port_classifier.add_rule(rule)?,
            RuleType::Protocol => {
                unimplemented!()
            }
        };

        self.rules[rule.id() as usize].parsers = rule.parsers;
        self.rules[rule.id() as usize].parsers_count = rule.parsers_count;

        Ok(rule.id())
    }

    /// Allocate a protocol classifier scratch
    ///
    /// # Returns
    ///
    /// * `Result<ClassifyScratch>` - classifier scratch
    pub fn alloc_scratch(&self) -> Result<ClassifyScratch> {
        self.dpi_classifier.alloc_scratch()
    }

    pub fn prepare(&mut self) -> Result<()> {
        self.dpi_classifier.prepare()
    }

    /// Classify protocol
    #[inline]
    pub fn classify(
        &self,
        pkt: &mut packet::Packet,
        scratch: &mut dpi::ClassifyScratch,
    ) -> Result<()> {
        self.all_pkt_classifier.classify(pkt);

        self.port_classifier.classify(pkt);

        self.dpi_classifier.classify(pkt, scratch)?;

        Ok(())
    }

    /// Get rule by ID
    #[inline]
    pub fn get_rule(&self, id: RuleID) -> Option<&Box<Rule>> {
        self.rules.get(id as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_all_pkt_rule() {
        let mut classifier = ClassifierManager::new();
        // add a regular receive all pkt rule
        let mut rule: Rule = Rule {
            id: 0,
            priority: 255,
            parsers: [0; MAX_PARSER_NUM],
            parsers_count: 1,
            rule_type: RuleType::All,
        };
        rule.parsers[0] = 1;

        classifier.add_rule(&mut rule).unwrap();
        assert_eq!(classifier.rules.len(), 1);
        assert_eq!(classifier.rules[0].id(), 0);
        assert_eq!(classifier.rules[0].priority, 255);
        assert_eq!(classifier.rules[0].parsers_count, 1);
        assert_eq!(classifier.rules[0].parsers[0], 1);
        assert!(matches!(classifier.rules[0].rule_type, RuleType::All));

        // add a rule that has different id and priority
        let mut rule: Rule = Rule {
            id: 1,
            priority: 0,
            parsers: [0; MAX_PARSER_NUM],
            parsers_count: 1,
            rule_type: RuleType::All,
        };
        rule.parsers[0] = 2;
        classifier.add_rule(&mut rule).unwrap();
        assert_eq!(classifier.rules.len(), 1);
        assert_eq!(classifier.rules[0].id(), 0);
        assert_eq!(classifier.rules[0].priority, 255);
        assert_eq!(classifier.rules[0].parsers_count, 2);
        assert_eq!(classifier.rules[0].parsers[0], 1);
        assert_eq!(classifier.rules[0].parsers[1], 2);
    }

    #[test]
    fn add_port_rule() {
        let mut classifier = ClassifierManager::new();
        // add a regular port rule
        let mut rule: Rule = Rule {
            id: 0,
            priority: 255,
            parsers: [0; MAX_PARSER_NUM],
            parsers_count: 1,
            rule_type: RuleType::Port(port::Rule {
                port: 80,
                protocol: packet::Protocol::TCP,
            }),
        };
        rule.parsers[0] = 1;
        classifier.add_rule(&mut rule).unwrap();
        assert_eq!(classifier.rules.len(), 2);
        assert_eq!(classifier.rules[1].id(), 1);
        assert_eq!(classifier.rules[1].priority, 255);
        assert_eq!(classifier.rules[1].parsers_count, 1);
        assert_eq!(classifier.rules[1].parsers[0], 1);
        assert!(matches!(classifier.rules[1].rule_type, RuleType::Port(r) if r.port == 80));
        match classifier.rules[1].rule_type {
            RuleType::Port(r) => {
                assert!(matches!(r.protocol, packet::Protocol::TCP));
            }
            _ => unreachable!(),
        };
    }

    #[test]
    fn classifier_add_dpi_rule() {
        // let mut classifier = ClassifierManager::new();
        // let expression = String::from("regex");
        // let pattern = hyperscan::Pattern::new(expression.clone()).unwrap();
        // classifier.add_dpi_rule(pattern, 100);
        // assert_eq!(classifier.dpi_rules[0].hs_pattern.expression, expression);
        // assert_eq!(classifier.dpi_rules[0].protocols[0], 100);

        // classifier.prepare();
        // let scratch = classifier.alloc_scratch().unwrap();
        // let mut protocols = Vec::new();
        // let mut pkt = packet::Packet::default();

        // classifier.classify(&pkt, &mut protocols, &scratch).unwrap();
        // assert_eq!(protocols.len(), 0);

        // pkt.data = Box::new(Vec::from(String::from("regex").as_bytes()));
        // classifier.classify(&pkt, &mut protocols, &scratch).unwrap();
        // assert_eq!(protocols.len(), 1);
        // println!("result: {:?}", protocols);
        // assert_eq!(protocols[0], 100);
    }

    #[test]
    fn classifier_add_dpi_rule_with_existing_expression() {
        // let mut classifier = ClassifierManager::new();
        // let expression = String::from("regex");
        // let pattern = hyperscan::Pattern::new(expression.clone()).unwrap();
        // classifier.add_dpi_rule(pattern, 100);
        // assert_eq!(classifier.dpi_rules[0].hs_pattern.expression, expression);
        // assert_eq!(classifier.dpi_rules[0].protocols[0], 100);

        // let expression = String::from("regex");
        // let pattern = hyperscan::Pattern::new(expression.clone()).unwrap();
        // classifier.add_dpi_rule(pattern, 8);
        // assert_eq!(classifier.dpi_rules[0].hs_pattern.expression, expression);
        // assert_eq!(classifier.dpi_rules[0].protocols[1], 8);
    }

    #[test]
    fn rule_type_size() {
        // assert_eq!(std::mem::size_of::<RuleType>(), 1);
        // assert_eq!(std::mem::size_of::<Rule>(), 1);
        // assert_eq!(std::mem::size_of::<hyperscan::Pattern>(), 1);
        // assert_eq!(std::mem::size_of::<Result<()>>(), 1);
    }
}