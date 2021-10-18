use std::collections::HashSet;

use anyhow::{anyhow, Result};
use dhcp_parser2::{parse_dhcp_message, DHCPMessageType};
use fnv::FnvHashSet;
use mac_address::MacAddress;
use serde::{ser::SerializeSeq, Serialize, Serializer};
use serde_json::json;

use alphonse_api as api;
use api::classifiers::{ClassifierManager, RuleID};
use api::packet::{Packet, Protocol};
use api::plugins::processor::{Processor, ProcessorID};
use api::plugins::{Plugin, PluginType};
use api::session::{ProtocolLayer, Session};

fn msg_type_to_string(msg_type: DHCPMessageType) -> String {
    match msg_type {
        DHCPMessageType::DHCPACK => "ACK".to_string(),
        DHCPMessageType::DHCPDECLINE => "DECLINE".to_string(),
        DHCPMessageType::DHCPDISCOVER => "DISCOVER".to_string(),
        DHCPMessageType::DHCPNAK => "NAK".to_string(),
        DHCPMessageType::DHCPOFFER => "OFFER".to_string(),
        DHCPMessageType::DHCPRELEASE => "RELEASE".to_string(),
        DHCPMessageType::DHCPREQUEST => "REQUEST".to_string(),
        msg_type => msg_type.0.to_string(),
    }
}

fn serialize_transaction_id<S>(xids: &FnvHashSet<u32>, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let mut s = s.serialize_seq(Some(xids.len()))?;
    for xid in xids {
        s.serialize_element(&format!("{:x}", xid))?;
    }
    s.end()
}

#[derive(Clone, Debug, Default, Serialize)]
#[cfg_attr(feature = "arkime", serde(rename_all = "camelCase"))]
struct DHCP {
    #[serde(
        skip_serializing_if = "HashSet::is_empty",
        serialize_with = "serialize_transaction_id"
    )]
    id: FnvHashSet<u32>,
    #[serde(skip_serializing_if = "HashSet::is_empty")]
    mac: FnvHashSet<MacAddress>,
    #[serde(skip_serializing_if = "HashSet::is_empty", rename = "type")]
    msg_type: HashSet<String>,
}

#[derive(Clone, Debug, Default)]
struct DHCPProcessor {
    id: ProcessorID,
    classified: bool,
    v4_rule_id: RuleID,
    v6_rule_id: RuleID,
    fields: Option<Box<DHCP>>,
}

impl Plugin for DHCPProcessor {
    /// Get parser name
    fn name(&self) -> &str {
        "dhcp"
    }

    fn plugin_type(&self) -> PluginType {
        PluginType::PacketProcessor
    }
}

impl Processor for DHCPProcessor {
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
        // dns
        self.v4_rule_id = manager.add_udp_port_rule(self.id(), 67)?;
        self.v6_rule_id = manager.add_udp_port_rule(self.id(), 547)?;

        Ok(())
    }

    fn parse_pkt(
        &mut self,
        pkt: &dyn Packet,
        rule: Option<&api::classifiers::matched::Rule>,
        ses: &mut Session,
    ) -> Result<()> {
        let rule = match rule {
            None => return Ok(()),
            Some(rule) => rule,
        };

        if self.fields.is_none() {
            self.fields = Some(Box::new(DHCP::default()));
        }

        let dhcp = match &mut self.fields {
            Some(dhcp) => dhcp,
            None => unreachable!("this should never happen"),
        };

        if rule.id == self.v4_rule_id {
            parse_dhcp(ses, pkt, dhcp)
        } else if rule.id == self.v6_rule_id {
            parse_dhcpv6(ses, pkt)
        } else {
            return Ok(());
        };

        self.fields = Some(Box::new(DHCP::default()));

        Ok(())
    }

    fn save(&mut self, ses: &mut Session) {
        let fields = self.fields.take();
        let fields = match fields {
            None => return,
            Some(fields) => fields,
        };
        ses.add_field(&"dhcp", json!(fields));
    }

    fn mid_save(&mut self, ses: &mut Session) {
        self.save(ses);
        self.fields = None;
    }
}

fn parse_dhcp(ses: &mut Session, pkt: &dyn Packet, dhcp: &mut DHCP) {
    let payload = pkt.payload();
    let protocol = match pkt.layers().network() {
        None => unreachable!("dhcp processor received a pkt with no network layer"),
        Some(layer) => layer.protocol,
    };
    if payload.len() < 256 || (payload[0] != 1 && payload[0] != 2) && protocol == Protocol::IPV4 {
        if payload.len() < 240 || &payload[236..240] != b"\x63\x82\x53\x63" {
            return;
        }
    }
    match parse_dhcp_message(pkt.payload()) {
        Ok((_, msg)) => {
            dhcp.id.insert(msg.xid);
            let mac = MacAddress::new([
                msg.chaddr[0],
                msg.chaddr[1],
                msg.chaddr[2],
                msg.chaddr[3],
                msg.chaddr[4],
                msg.chaddr[5],
            ]);
            dhcp.mac.insert(mac);
            match msg.message_type() {
                None => {}
                Some(msg_type) => {
                    dhcp.msg_type.insert(msg_type_to_string(msg_type));
                }
            };
            println!("dhcp: {:?}", dhcp);
        }
        Err(e) => eprintln!("{}", e),
    };
    ses.add_protocol(&"dhcp", ProtocolLayer::Application);
}

fn parse_dhcpv6(ses: &mut Session, pkt: &dyn Packet) {
    let protocol = match pkt.layers().network() {
        None => unreachable!("dhcp processor received a pkt with no network layer"),
        Some(layer) => layer.protocol,
    };
    if pkt.payload()[0] != 1 && pkt.payload()[0] != 11 && protocol == Protocol::IPV6 {
        return;
    }

    ses.add_protocol(&"dhcpv6", ProtocolLayer::Application);
}

impl DHCPProcessor {}

#[no_mangle]
pub extern "C" fn al_new_pkt_processor() -> Box<Box<dyn Processor>> {
    Box::new(Box::new(DHCPProcessor::default()))
}

#[no_mangle]
pub extern "C" fn al_plugin_type() -> PluginType {
    PluginType::PacketProcessor
}
