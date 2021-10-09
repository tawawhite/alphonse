use serde::Deserialize;

use alphonse_api as api;
use api::classifiers::dpi;
use api::packet;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Deserialize)]
pub enum TransportProtocol {
    TCP,
    UDP,
    SCTP,
}

impl Into<dpi::Protocol> for TransportProtocol {
    fn into(self) -> dpi::Protocol {
        match self {
            TransportProtocol::SCTP => dpi::Protocol::SCTP,
            TransportProtocol::TCP => dpi::Protocol::TCP,
            TransportProtocol::UDP => dpi::Protocol::UDP,
        }
    }
}

impl Into<packet::Protocol> for TransportProtocol {
    fn into(self) -> packet::Protocol {
        match self {
            TransportProtocol::SCTP => packet::Protocol::SCTP,
            TransportProtocol::TCP => packet::Protocol::TCP,
            TransportProtocol::UDP => packet::Protocol::UDP,
        }
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Deserialize)]
pub struct Regex {
    pub regex: String,
    pub regex_flags: Option<String>,
    pub save_matched: Option<bool>,
    #[serde(flatten)]
    pub basic: BasicRule,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Deserialize)]
pub struct Port {
    pub port: u16,
    #[serde(flatten)]
    pub basic: BasicRule,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Deserialize)]
pub struct BasicRule {
    pub transport_protocol: TransportProtocol,
    pub protocol: Option<String>,
    pub tag: Option<String>,
    pub desc: Option<String>,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Deserialize)]
#[serde(untagged)]
pub enum MiscRule {
    Regex(Regex),
    Port(Port),
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn deserialize_regex() {
        let rule = r###"
regex: "regex"
transport_protocol: TCP
protocol: regex
tag: regex
desc: regex
"###;

        let r: MiscRule = serde_yaml::from_str(rule).unwrap();
        match r {
            MiscRule::Port(_) => panic!("Expecting regex misc rule, get port misc rule"),
            MiscRule::Regex(rule) => {
                assert_eq!(rule.regex, "regex");
                assert_eq!(rule.regex_flags, None);
                assert_eq!(rule.basic.transport_protocol, TransportProtocol::TCP);
                assert!(matches!(rule.basic.protocol, Some(r) if r == "regex"));
                assert!(matches!(rule.basic.tag, Some(r) if r == "regex"));
                assert!(matches!(rule.basic.desc, Some(r) if r == "regex"));
            }
        }

        let rule = r###"
regex: "regex"
transport_protocol: UDP
tag: regex
"###;

        let r: MiscRule = serde_yaml::from_str(rule).unwrap();
        match r {
            MiscRule::Port(_) => panic!("Expecting regex misc rule, get port misc rule"),
            MiscRule::Regex(rule) => {
                assert_eq!(rule.regex, "regex");
                assert_eq!(rule.basic.transport_protocol, TransportProtocol::UDP);
                assert!(matches!(rule.basic.protocol, None));
                assert!(matches!(rule.basic.tag, Some(r) if r == "regex"));
                assert!(matches!(rule.basic.desc, None));
            }
        }
    }

    #[test]
    fn deserialize_port() {
        let rule = r###"
port: 8080
transport_protocol: TCP
protocol: port
tag: port
desc: port
"###;

        let r: MiscRule = serde_yaml::from_str(rule).unwrap();
        match r {
            MiscRule::Regex(_) => panic!("Expecting port misc rule, get regex misc rule"),
            MiscRule::Port(rule) => {
                assert_eq!(rule.port, 8080);
                assert_eq!(rule.basic.transport_protocol, TransportProtocol::TCP);
                assert!(matches!(rule.basic.protocol, Some(p) if p == "port"));
                assert!(matches!(rule.basic.tag, Some(t) if t == "port"));
                assert!(matches!(rule.basic.desc, Some(d) if d == "port"));
            }
        }
    }
}
