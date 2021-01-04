use anyhow::{anyhow, Result};

use super::{matched, packet};

pub struct Classifier {
    // The receive all pkt rule
    rule: matched::Rule,
}

impl Default for Classifier {
    fn default() -> Self {
        Classifier {
            rule: matched::Rule::default(),
        }
    }
}

impl super::Classifier for Classifier {
    fn add_rule(&mut self, rule: &super::Rule) -> Result<&matched::Rule> {
        let parser_id = match rule.rule_type {
            super::RuleType::All => rule.parsers[0],
            _ => {
                return Err(anyhow!(
                    "Mismatched rule type, expecting Port Rule, get {:?}",
                    rule.rule_type
                ))
            }
        };

        // Prevent add same parser again, unlikely happen
        if self.rule.parsers.len() > 0 {
            match self.rule.parsers.iter().find(|id| **id == parser_id) {
                Some(_) => return Ok(&self.rule),
                None => {}
            };
        }

        self.rule.parsers.push(parser_id);
        Ok(&self.rule)
    }
}

impl Classifier {
    #[inline]
    pub fn classify(&self, pkt: &mut Box<dyn packet::Packet>) {
        if self.rule.parsers.len() > 0 {
            pkt.rules_mut().push(self.rule.clone())
        }
    }
}

#[cfg(test)]
mod test {
    use super::super::RuleID;
    use super::*;
    use crate::classifiers::Classifier as ClassifierTrait;

    #[test]
    fn add_rule_with_same_parser_id() {
        let mut classifier = Classifier::default();
        let rule = super::super::Rule::new(1);

        assert!(matches!(classifier.add_rule(&rule), Ok(_)));

        let rule = super::super::Rule::new(1);
        assert!(matches!(classifier.add_rule(&rule), Ok(_)));
        assert_eq!(classifier.rule.parsers.len(), 1);
    }

    #[test]
    fn add_invalid_rule_type_rule() {
        let mut classifier = Classifier::default();
        let mut rule = super::super::Rule::new(0);
        rule.rule_type = super::super::RuleType::Protocol;
        assert!(matches!(classifier.add_rule(&rule), Err(_)));
    }

    #[test]
    fn rule_exceed_max_parser_num() {
        let mut classifier = Box::new(Classifier::default());
        for i in 0..8 {
            let mut rule = super::super::Rule::new(i as super::super::ParserID);
            rule.id = i as RuleID;
            assert!(matches!(classifier.add_rule(&rule), Ok(_)));
        }
        assert_eq!(classifier.rule.parsers.len(), 8);
    }

    #[test]
    fn classify() {
        let mut classifier = Classifier::default();
        let rule = super::super::Rule::new(1);

        assert!(matches!(classifier.add_rule(&rule), Ok(_)));

        let mut pkt = packet::Packet::default();
        classifier.classify(&mut pkt);
        assert_eq!(pkt.rules.len(), 1);
    }

    #[test]
    fn classify_without_any_parser() {
        let classifier = Classifier::default();
        let mut pkt = packet::Packet::default();
        classifier.classify(&mut pkt);
        assert_eq!(pkt.rules.len(), 0);
    }
}
