use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;

use anyhow::{anyhow, Result};
use maxminddb::{geoip2, Reader as GeoLiteReader};
use memmap::Mmap;
use once_cell::sync::OnceCell;
use serde::Serialize;
use serde_json::json;

use alphonse_api as api;
use api::classifiers;
use api::packet::Protocol;
use api::plugins::parsers::{Processor, ProcessorID};
use api::plugins::{Plugin, PluginType};
use api::session::Session;

static ASN_DB: OnceCell<GeoLiteReader<Mmap>> = OnceCell::new();
static COUNTRY_DB: OnceCell<GeoLiteReader<Mmap>> = OnceCell::new();
static CITY_DB: OnceCell<GeoLiteReader<Mmap>> = OnceCell::new();

#[derive(Clone, Debug, Serialize)]
struct IpInfo {
    addr: IpAddr,
    asn: String,
    country: String,
    city: String,
}

impl Default for IpInfo {
    fn default() -> Self {
        Self {
            addr: IpAddr::V4(Ipv4Addr::from(0)),
            asn: String::default(),
            country: String::default(),
            city: String::default(),
        }
    }
}

#[derive(Default)]
struct IPProcessor {
    id: ProcessorID,
    name: String,
    classified: bool,
    processed: bool,
    src_ip: IpInfo,
    dst_ip: IpInfo,
}

impl Clone for IPProcessor {
    fn clone(&self) -> Self {
        Self {
            id: self.id,
            name: self.name.clone(),
            classified: self.classified,
            processed: self.processed,
            src_ip: self.src_ip.clone(),
            dst_ip: self.dst_ip.clone(),
        }
    }
}

impl Plugin for IPProcessor {
    fn plugin_type(&self) -> PluginType {
        PluginType::PacketProcessor
    }

    /// Get parser name
    fn name(&self) -> &str {
        &self.name.as_str()
    }

    fn init(&self, alcfg: &api::config::Config) -> Result<()> {
        let db_dir = PathBuf::from(alcfg.get_str(&"ip.db.directory", "etc"));
        let db_path = db_dir.join("GeoLite2-ASN.mmdb");
        ASN_DB
            .set(GeoLiteReader::open_mmap(db_path)?)
            .ok()
            .ok_or(anyhow!("{} ASN_DBS are already set", self.name()))?;

        let db_path = db_dir.join("GeoLite2-Country.mmdb");
        COUNTRY_DB
            .set(GeoLiteReader::open_mmap(db_path)?)
            .ok()
            .ok_or(anyhow!("{} COUNTRY_DBS are already set", self.name()))?;

        let db_path = db_dir.join("GeoLite2-City.mmdb");
        CITY_DB
            .set(GeoLiteReader::open_mmap(db_path)?)
            .ok()
            .ok_or(anyhow!("{} CITY_DBS are already set", self.name()))?;

        Ok(())
    }
}

impl Processor for IPProcessor {
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

    fn register_classify_rules(
        &mut self,
        manager: &mut classifiers::ClassifierManager,
    ) -> Result<()> {
        manager.add_etype_rule(self.id(), 0x0800)?;
        manager.add_etype_rule(self.id(), 0x86dd)?;
        Ok(())
    }

    fn is_classified(&self) -> bool {
        self.classified
    }

    fn classified_as_this_protocol(&mut self) -> Result<()> {
        self.classified = true;
        Ok(())
    }

    fn parse_pkt(
        &mut self,
        pkt: &dyn api::packet::Packet,
        _rule: Option<&api::classifiers::matched::Rule>,
        ses: &mut Session,
    ) -> Result<()> {
        if self.processed {
            return Ok(());
        };

        if !self.is_classified() {
            self.classified_as_this_protocol()?;
            match pkt.layers().network.protocol {
                Protocol::IPV4 => ses.add_protocol(&"ipv4"),
                Protocol::IPV6 => ses.add_protocol(&"ipv6"),
                _ => unreachable!(),
            }
        }

        self.src_ip.addr = unsafe {
            match pkt.layers().network.protocol {
                Protocol::IPV4 => IpAddr::V4(Ipv4Addr::from(pkt.src_ipv4())),
                Protocol::IPV6 => IpAddr::V6(Ipv6Addr::from(*pkt.src_ipv6())),
                _ => unreachable!(),
            }
        };

        self.dst_ip.addr = unsafe {
            match pkt.layers().network.protocol {
                Protocol::IPV4 => IpAddr::V4(Ipv4Addr::from(pkt.dst_ipv4())),
                Protocol::IPV6 => IpAddr::V6(Ipv6Addr::from(*pkt.dst_ipv6())),
                _ => {
                    unreachable!()
                }
            }
        };

        let db = ASN_DB
            .get()
            .ok_or(anyhow!("{}: ASN_DBS is not initialized", self.name()))?;

        let asn: Option<geoip2::Asn> = db.lookup(self.src_ip.addr).ok();
        self.src_ip.asn = asn_to_string(&asn);
        let asn: Option<geoip2::Asn> = db.lookup(self.dst_ip.addr).ok();
        self.dst_ip.asn = asn_to_string(&asn);

        let db = COUNTRY_DB
            .get()
            .ok_or(anyhow!("{}: ASN_DBS is not initialized", self.name()))?;
        let country: Option<geoip2::Country> = db.lookup(self.src_ip.addr).ok();
        self.src_ip.country = country_to_string(&country);
        let country: Option<geoip2::Country> = db.lookup(self.dst_ip.addr).ok();
        self.dst_ip.country = country_to_string(&country);

        let db = CITY_DB
            .get()
            .ok_or(anyhow!("{}: ASN_DBS is not initialized", self.name()))?;
        let src_city: Option<geoip2::City> = db.lookup(self.src_ip.addr).ok();
        self.src_ip.city = city_to_string(&src_city);
        let dst_city: Option<geoip2::City> = db.lookup(self.dst_ip.addr).ok();
        self.dst_ip.city = city_to_string(&dst_city);

        self.processed = true;

        Ok(())
    }

    fn finish(&mut self, ses: &mut Session) {
        ses.add_field(&"srcIp", &json!(self.src_ip.addr));
        if !self.src_ip.asn.is_empty() {
            ses.add_field(&"src.ASN", &json!(self.src_ip.asn));
        }
        if !self.src_ip.country.is_empty() {
            ses.add_field(&"src.GEO", &json!(self.src_ip.country));
        }
        if !self.src_ip.city.is_empty() {
            ses.add_field(&"src.GEOCity", &json!(self.src_ip.city));
        }

        ses.add_field(&"dstIp", &json!(self.dst_ip.addr));
        if !self.src_ip.asn.is_empty() {
            ses.add_field(&"dst.ASN", &json!(self.src_ip.asn));
        }
        if !self.src_ip.country.is_empty() {
            ses.add_field(&"dst.GEO", &json!(self.src_ip.country));
        }
        if !self.src_ip.city.is_empty() {
            ses.add_field(&"dst.GEOCity", &json!(self.src_ip.city));
        }
    }
}

fn asn_to_string(asn: &Option<geoip2::Asn>) -> String {
    match asn {
        None => String::new(),
        Some(asn) => {
            match (
                asn.autonomous_system_number,
                asn.autonomous_system_organization,
            ) {
                (Some(num), Some(org)) => format!("{} {}", num, org),
                (Some(num), None) => format!("{}", num),
                (None, Some(org)) => format!("{}", org),
                (None, None) => String::new(),
            }
        }
    }
}

fn country_to_string(country: &Option<geoip2::Country>) -> String {
    match country {
        None => String::new(),
        Some(country) => match &country.country {
            None => String::new(),
            Some(country) => country.iso_code.unwrap_or_default().to_string(),
        },
    }
}

fn city_to_string(city: &Option<geoip2::City>) -> String {
    match city {
        None => String::new(),
        Some(city) => match &city.city {
            None => String::new(),
            Some(c) => match &c.names {
                None => String::new(),
                Some(names) => match names.get("en") {
                    None => String::new(),
                    Some(name) => name.to_string(),
                },
            },
        },
    }
}

#[no_mangle]
pub extern "C" fn al_new_protocol_parser() -> Box<Box<dyn Processor>> {
    Box::new(Box::new(IPProcessor::default()))
}
