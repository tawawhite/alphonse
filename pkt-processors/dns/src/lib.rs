#[macro_use]
extern crate bitflags;
#[macro_use]
extern crate enum_primitive_derive;

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::{anyhow, Result};
use num_traits::FromPrimitive;
use serde::Serialize;
use serde_json::json;

use alphonse_api as api;
use api::classifiers::{ClassifierManager, RuleID};
use api::packet::Protocol;
use api::plugins::processor::{
    Builder as ProcessorBuilder, Processor as PktProcessor, ProcessorID,
};
use api::plugins::{Plugin, PluginType};
use api::session::{ProtocolLayer, Session};

mod consts;
mod parser;

use parser::{
    parse_dns_packet, parse_dns_query, parse_dns_resource_records, parse_tcp_dns_packet, Class,
    DnsMessage, DnsMessageType, OpCode, RCode, ResourceRecord, ResourceRecordType,
};

#[derive(Clone, Debug, Default, Serialize)]
#[cfg_attr(feature = "arkime", serde(rename_all = "camelCase"))]
struct DNS {
    #[serde(skip_serializing_if = "HashSet::is_empty")]
    host: HashSet<String>,
    #[serde(skip_serializing_if = "HashSet::is_empty")]
    ip: HashSet<IpAddr>,
    #[serde(skip_serializing_if = "HashSet::is_empty")]
    mailserver_host: HashSet<String>,
    #[serde(skip_serializing_if = "HashSet::is_empty")]
    mailserver_ip: HashSet<IpAddr>,
    #[serde(skip_serializing_if = "HashSet::is_empty")]
    nameserver_host: HashSet<String>,
    #[serde(skip_serializing_if = "HashSet::is_empty")]
    nameserver_ip: HashSet<IpAddr>,
    #[serde(skip_serializing_if = "HashSet::is_empty")]
    opcode: HashSet<OpCode>,
    #[serde(skip_serializing_if = "HashSet::is_empty")]
    puny: HashSet<String>,
    #[serde(skip_serializing_if = "HashSet::is_empty")]
    qc: HashSet<Class>,
    #[serde(skip_serializing_if = "HashSet::is_empty")]
    qt: HashSet<ResourceRecordType>,
    #[serde(skip_serializing_if = "HashSet::is_empty")]
    status: HashSet<RCode>,
}

#[derive(Clone, Debug, Default)]
struct Builder {
    id: ProcessorID,
    tcp_rule_id: RuleID,
    udp_rule_id: RuleID,
    llmnr_rule_id: RuleID,
    mdns_rule_id: RuleID,
}

impl ProcessorBuilder for Builder {
    fn build(&self, _: &api::config::Config) -> Box<dyn PktProcessor> {
        let mut p = Box::new(DNSProcessor::default());
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
        // dns
        self.tcp_rule_id = manager.add_tcp_port_rule(self.id(), 53)?;
        self.udp_rule_id = manager.add_udp_port_rule(self.id(), 53)?;

        // mdns
        self.mdns_rule_id = manager.add_udp_port_rule(self.id(), 5353)?;

        // llmnr
        self.llmnr_rule_id = manager.add_udp_port_rule(self.id(), 5355)?;

        Ok(())
    }
}

impl Plugin for Builder {
    /// Get parser name
    fn name(&self) -> &str {
        "dns"
    }

    fn plugin_type(&self) -> PluginType {
        PluginType::PacketProcessor
    }
}

#[derive(Clone, Debug, Default)]
struct DNSProcessor {
    id: ProcessorID,
    classified: bool,
    tcp_rule_id: RuleID,
    udp_rule_id: RuleID,
    llmnr_rule_id: RuleID,
    mdns_rule_id: RuleID,
    fields: Option<Box<DNS>>,
}

impl PktProcessor for DNSProcessor {
    fn id(&self) -> ProcessorID {
        self.id
    }

    fn name(&self) -> &'static str {
        &"dns"
    }

    fn parse_pkt(
        &mut self,
        pkt: &dyn api::packet::Packet,
        rule: Option<&api::classifiers::matched::Rule>,
        ses: &mut Session,
    ) -> Result<()> {
        if !self.classified {
            self.classified = true;
            match rule {
                None => {
                    ses.add_protocol(&"dns", ProtocolLayer::Application);
                }
                Some(rule) => {
                    if rule.id == self.mdns_rule_id {
                        ses.add_protocol(&"mdns", ProtocolLayer::Application);
                    } else if rule.id == self.llmnr_rule_id {
                        ses.add_protocol(&"llmnr", ProtocolLayer::Application);
                    } else {
                        ses.add_protocol(&"dns", ProtocolLayer::Application);
                    }
                }
            };
            self.fields = Some(Box::new(DNS::default()));
        }

        let dns = match &mut self.fields {
            Some(dns) => dns,
            None => return Ok(()),
        };

        let protocol = match pkt.layers().transport() {
            None => unreachable!("dns get a pkt with no transport layer"),
            Some(layer) => layer.protocol,
        };

        let msg = match protocol {
            Protocol::TCP => match parse_tcp_dns_packet(pkt.payload()) {
                Err(e) => match e {
                    nom::Err::Incomplete(_) => {
                        todo!("handle imcomplete tcp dns packet, very unlikelyt to happen")
                    }
                    _ => return Ok(()),
                },

                Ok((_, msg)) => msg,
            },
            Protocol::UDP => match parse_dns_packet(pkt.payload()) {
                Err(e) => return Err(anyhow!("{}", e)),
                Ok((_, msg)) => msg,
            },
            _ => unreachable!("dns parser only binds tcp and udp rule"),
        };

        match OpCode::from_u8(msg.flags.op_code()) {
            None => eprintln!("unassigned OpCode({})", msg.flags.op_code()),
            Some(opcode) => {
                dns.opcode.insert(opcode);
            }
        };

        match RCode::from_u16(msg.flags.reply_code() as u16) {
            None => eprintln!("unassigned RCode({})", msg.flags.reply_code()),
            Some(rcode) => {
                dns.status.insert(rcode);
            }
        }

        let mut remain = msg.queries;
        for _ in 0..msg.qry_num as usize {
            let (tmp, query) = match parse_dns_query(remain) {
                Err(_) => return Ok(()),
                Ok(r) => r,
            };

            let name = match query.name() {
                Err(_) => return Ok(()),
                Ok((_, name)) => name,
            };

            let tmp = match msg.msg_type {
                DnsMessageType::Query => tmp,
                DnsMessageType::Response => {
                    match Self::on_resource_records(dns, &msg, &name, tmp) {
                        Err(_) => return Ok(()),
                        Ok(tmp) => tmp,
                    }
                }
            };

            Self::add_host(dns, &name);
            remain = tmp
        }

        Ok(())
    }

    fn save(&mut self, ses: &mut Session) {
        let fields = self.fields.take();
        let fields = match fields {
            None => return,
            Some(fields) => fields,
        };
        ses.add_field(&"dns", json!(fields));
    }
}

impl DNSProcessor {
    fn add_host(dns: &mut DNS, host: &String) {
        if host.contains("xn--") {
            dns.puny.insert(host.to_ascii_lowercase());
        }
        dns.host.insert(host.clone());
    }

    fn on_resource_records<'a>(
        dns: &mut DNS,
        msg: &DnsMessage,
        host: &String,
        answers: &'a [u8],
    ) -> Result<&'a [u8]> {
        let remain = match parse_dns_resource_records(answers) {
            Err(_) => &[],
            Ok((remain, records)) => {
                for record in records {
                    let class = match Class::from_u16(record.class) {
                        None => continue,
                        Some(class) => class,
                    };

                    dns.qc.insert(class);

                    match class {
                        Class::IN => {}
                        _ => continue,
                    };

                    let rr_type = match ResourceRecordType::from_u16(record.rr_type) {
                        None => continue,
                        Some(rr_type) => rr_type,
                    };
                    dns.qt.insert(rr_type);

                    match rr_type {
                        ResourceRecordType::A => Self::on_a(dns, msg, host, &record),
                        ResourceRecordType::AAAA => Self::on_aaaa(dns, msg, host, &record),
                        ResourceRecordType::NS => Self::on_ns(dns, msg, host, &record),
                        ResourceRecordType::CNAME => Self::on_cname(dns, msg, host, &record),
                        ResourceRecordType::MX => Self::on_mx(dns, msg, host, &record),
                        _ => continue,
                    }
                    .unwrap();
                }
                remain
            }
        };

        Ok(remain)
    }

    /// Called on a host address record
    fn on_a<'a>(
        dns: &mut DNS,
        msg: &DnsMessage,
        host: &String,
        record: &ResourceRecord,
    ) -> Result<()> {
        match OpCode::from_u8(msg.flags.op_code()) {
            None => eprintln!("unassigned OpCode({})", msg.flags.op_code()),
            Some(opcode) => {
                let ip = record.data;
                let ip = IpAddr::V4(Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]));
                match opcode {
                    OpCode::Update => {
                        dns.ip.insert(ip);
                    }
                    _ => {
                        if dns.host.contains(host) {
                            dns.ip.insert(ip);
                        }
                        if dns.mailserver_host.contains(host) {
                            dns.mailserver_ip.insert(ip);
                        }
                        if dns.nameserver_host.contains(host) {
                            dns.nameserver_ip.insert(ip);
                        }
                    }
                };
            }
        };
        Ok(())
    }

    /// Called on an IPV6 address record
    fn on_aaaa<'a>(
        dns: &mut DNS,
        msg: &DnsMessage,
        host: &String,
        record: &ResourceRecord,
    ) -> Result<()> {
        match OpCode::from_u8(msg.flags.op_code()) {
            None => eprintln!("unassigned OpCode({})", msg.flags.op_code()),
            Some(opcode) => {
                let ip = unsafe { *(record.data.as_ptr() as *const u128) };
                let ip = IpAddr::V6(Ipv6Addr::from(ip));
                match opcode {
                    OpCode::Update => {
                        dns.ip.insert(ip);
                    }
                    _ => {
                        if dns.host.contains(host) {
                            dns.ip.insert(ip);
                        }
                        if dns.mailserver_host.contains(host) {
                            dns.mailserver_ip.insert(ip);
                        }
                        if dns.nameserver_host.contains(host) {
                            dns.nameserver_ip.insert(ip);
                        }
                    }
                };
            }
        };
        Ok(())
    }

    /// Called on an authoritative name server record
    fn on_ns<'a>(dns: &mut DNS, _: &DnsMessage, host: &String, _: &ResourceRecord) -> Result<()> {
        dns.nameserver_host.insert(host.clone());
        Ok(())
    }

    /// Called on canonical name for an alias record
    fn on_cname<'a>(
        dns: &mut DNS,
        _: &DnsMessage,
        host: &String,
        _: &ResourceRecord,
    ) -> Result<()> {
        Self::add_host(dns, host);
        Ok(())
    }

    /// Called on mail exchange record
    fn on_mx<'a>(dns: &mut DNS, _: &DnsMessage, host: &String, _: &ResourceRecord) -> Result<()> {
        dns.mailserver_host.insert(host.clone());
        Self::add_host(dns, host);
        Ok(())
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
