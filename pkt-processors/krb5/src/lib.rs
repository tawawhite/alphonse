use std::collections::HashSet;

use anyhow::Result;
use der_parser::ber::BerTag;
use kerberos_parser::krb5::PAType;
use kerberos_parser::krb5_parser::{
    parse_ap_req, parse_as_rep, parse_as_req, parse_krb_error, parse_tgs_rep, parse_tgs_req,
};
use nom::bytes::streaming::take_until1;
use serde::Serialize;
use serde_json::json;

use alphonse_api as api;
use api::classifiers::{ClassifierManager, RuleID};
use api::packet::{Direction, Protocol};
use api::plugins::processor::{Builder as ProcessorBuilder, Processor as Pcr, ProcessorID};
use api::plugins::{Plugin, PluginType};
use api::session::{ProtocolLayer, Session};

#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
struct Kerberos {
    #[serde(skip_serializing_if = "HashSet::is_empty")]
    realm: HashSet<String>,
    #[serde(skip_serializing_if = "HashSet::is_empty")]
    cname: HashSet<String>,
    #[serde(skip_serializing_if = "HashSet::is_empty")]
    sname: HashSet<String>,
    #[serde(skip_serializing_if = "HashSet::is_empty")]
    crealm: HashSet<String>,
    #[serde(skip_serializing_if = "HashSet::is_empty")]
    ticket_sname: HashSet<String>,
    #[serde(skip_serializing_if = "HashSet::is_empty")]
    ticket_realm: HashSet<String>,
}

#[derive(Clone, Debug, Default)]
struct Builder {
    id: ProcessorID,
}

impl ProcessorBuilder for Builder {
    fn build(&self, _: &api::config::Config) -> Box<dyn Pcr> {
        let mut p = Box::new(Processor::default());
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
        manager.add_tcp_udp_dpi_rule(self.id(), r"^.*\x03\x02\x01\x05")?;

        Ok(())
    }
}

impl Plugin for Builder {
    /// Get parser name
    fn name(&self) -> &str {
        "krb5"
    }

    fn plugin_type(&self) -> PluginType {
        PluginType::PacketProcessor
    }
}

#[derive(Clone, Debug, Default)]
struct Processor {
    id: ProcessorID,
    classified: bool,
    client_direction: Direction,
    tcp_rule_id: RuleID,
    udp_rule_id: RuleID,
    fields: Option<Box<Kerberos>>,
}

impl Pcr for Processor {
    fn id(&self) -> ProcessorID {
        self.id
    }

    fn name(&self) -> &'static str {
        &"krb5"
    }

    fn parse_pkt(
        &mut self,
        pkt: &dyn api::packet::Packet,
        _: Option<&api::classifiers::matched::Rule>,
        ses: &mut Session,
    ) -> Result<()> {
        if !self.classified {
            self.classified = true;
            ses.add_protocol(&"krb5", ProtocolLayer::Application);
            self.fields = Some(Box::new(Kerberos::default()));
        }

        let layer = match pkt.layers().transport() {
            None => unreachable!("this should never happens"),
            Some(l) => l,
        };

        match layer.protocol {
            Protocol::TCP => {
                let tag: &[u8] = b"\x03\x02\x01\x05";
                let r = take_until1::<&[u8], &[u8], nom::error::Error<&[u8]>>(tag)(pkt.payload());
                let data = if let Ok((_, data)) = r {
                    &pkt.payload()[data.len() - 9..]
                } else {
                    return Ok(());
                };
                let _ = self.parse_udp_pkt(data);
            }
            Protocol::UDP => {
                let _ = self.parse_udp_pkt(pkt.payload());
            }
            _ => {}
        };

        Ok(())
    }

    fn save(&mut self, ses: &mut Session) {
        let fields = self.fields.take();
        let fields = match fields {
            None => return,
            Some(fields) => fields,
        };
        ses.add_field(&"krb5", json!(fields));
    }
}

impl Processor {
    fn parse_udp_pkt(&mut self, data: &[u8]) -> Result<()> {
        let krb = match &mut self.fields {
            Some(krb) => krb,
            None => return Ok(()),
        };

        let (_, hdr) = der_parser::der::der_read_element_header(data).unwrap();
        if !hdr.is_application() {
            return Ok(());
        }

        match hdr.tag {
            BerTag::Sequence | BerTag::Enumerated => {
                let res = parse_as_req(data);
                if let Ok((_, kdc_req)) = res {
                    if let Some(cnames) = kdc_req.req_body.cname {
                        for cname in cnames.name_string {
                            krb.cname.insert(cname);
                        }
                    }

                    krb.realm.insert(kdc_req.req_body.realm.0);

                    if let Some(snames) = kdc_req.req_body.sname {
                        for sname in snames.name_string {
                            krb.sname.insert(sname);
                        }
                    }
                };
            }
            BerTag::Set | BerTag::EmbeddedPdv => {
                let res = parse_as_rep(data);
                if let Ok((_, kdc_rep)) = res {
                    for cname in kdc_rep.cname.name_string {
                        krb.cname.insert(cname);
                    }

                    krb.crealm.insert(kdc_rep.crealm.0);

                    for sname in kdc_rep.ticket.sname.name_string {
                        krb.ticket_sname.insert(sname);
                    }
                    krb.ticket_realm.insert(kdc_rep.ticket.realm.0);
                }
            }
            BerTag::NumericString | BerTag::Utf8String => {
                let res = parse_tgs_req(data);
                if let Ok((_, kdc_req)) = res {
                    if let Some(cnames) = kdc_req.req_body.cname {
                        for cname in cnames.name_string {
                            krb.cname.insert(cname);
                        }
                    }

                    krb.realm.insert(kdc_req.req_body.realm.0);

                    if let Some(snames) = kdc_req.req_body.sname {
                        for sname in snames.name_string {
                            krb.sname.insert(sname);
                        }
                    }

                    for padata in &kdc_req.padata {
                        if padata.padata_type == PAType::PA_TGS_REQ {
                            match parse_ap_req(padata.padata_value) {
                                Ok((_, ap_req)) => {
                                    for sname in ap_req.ticket.sname.name_string {
                                        krb.ticket_sname.insert(sname);
                                    }
                                    krb.ticket_realm.insert(ap_req.ticket.realm.0);
                                }
                                _ => {}
                            }
                        }
                    }
                }
            }
            BerTag::PrintableString | BerTag::RelativeOid => {
                let res = parse_tgs_rep(data);
                if let Ok((_, kdc_rep)) = res {
                    for cname in kdc_rep.cname.name_string {
                        krb.cname.insert(cname);
                    }
                    krb.crealm.insert(kdc_rep.crealm.0);
                    for sname in kdc_rep.ticket.sname.name_string {
                        krb.ticket_sname.insert(sname);
                    }
                    krb.ticket_realm.insert(kdc_rep.ticket.realm.0);
                }
            }
            BerTag::T61String => {
                let res = parse_ap_req(data);
                if let Ok((_, ap_req)) = res {
                    for sname in ap_req.ticket.sname.name_string {
                        krb.ticket_sname.insert(sname);
                    }
                    krb.ticket_realm.insert(ap_req.ticket.realm.0);
                }
            }
            BerTag::BmpString => {
                let res = parse_krb_error(data);
                if let Ok((_, error)) = res {
                    if let Some(cnames) = error.cname {
                        for cname in cnames.name_string {
                            krb.cname.insert(cname);
                        }
                    }

                    krb.realm.insert(error.realm.0);

                    for sname in error.sname.name_string {
                        krb.sname.insert(sname);
                    }
                }
            }
            _ => {}
        };
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
