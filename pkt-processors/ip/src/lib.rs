use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;

use anyhow::{anyhow, Result};
use maxminddb::{geoip2, Reader as GeoLiteReader};
use memmap2::Mmap;
use once_cell::sync::OnceCell;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::json;

use alphonse_api as api;
use api::classifiers;
use api::packet::Protocol;
use api::plugins::processor::{
    Builder as ProcessorBuilder, Processor as PktProcessor, ProcessorID,
};
use api::plugins::{Plugin, PluginType};
use api::session::{ProtocolLayer, Session};

static ASN_DB: OnceCell<GeoLiteReader<Mmap>> = OnceCell::new();
static COUNTRY_DB: OnceCell<GeoLiteReader<Mmap>> = OnceCell::new();
static CITY_DB: OnceCell<GeoLiteReader<Mmap>> = OnceCell::new();
static RIR: OnceCell<Vec<String>> = OnceCell::new();

fn deserialize_prefix<'de, D>(deserializer: D) -> Result<u8, D::Error>
where
    D: Deserializer<'de>,
{
    // i have no idea how i transform data: String to ActualData
    let prefix = String::deserialize(deserializer)?;
    let prefix = &prefix[0..3];
    let prefix = prefix.parse::<u8>().map_err(serde::de::Error::custom)?;
    Ok(prefix)
}

fn deserialize_rir<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    // i have no idea how i transform data: String to ActualData
    let prefix = String::deserialize(deserializer)?;
    for (i, part) in prefix.split('.').enumerate() {
        if i == 0 {
            continue;
        }
        return Ok(part.to_ascii_uppercase());
    }

    Ok(String::default())
}

/// IP's regional Internet registry
#[derive(Debug, Deserialize)]
struct IpRir {
    #[serde(rename = "Prefix")]
    #[serde(deserialize_with = "deserialize_prefix")]
    prefix: u8,
    #[serde(rename = "WHOIS")]
    #[serde(deserialize_with = "deserialize_rir")]
    rir: String,
}

#[derive(Clone, Debug, Serialize)]
struct IpInfo {
    addr: IpAddr,
    asn: String,
    country: String,
    city: String,
    rir: String,
}

impl Default for IpInfo {
    fn default() -> Self {
        Self {
            addr: IpAddr::V4(Ipv4Addr::from(0)),
            asn: String::default(),
            country: String::default(),
            city: String::default(),
            rir: String::default(),
        }
    }
}

/// Converts this address to an [`IPv4` address] if it's an "IPv4-mapped IPv6 address
/// defined in [IETF RFC 4291 section 2.5.5.2], otherwise returns [`None`].
///
/// Since Ipv6Addr::to_ipv4_mapped is not stablized in std library, make a copy
fn ipv6_to_ipv4_mapped(addr: &Ipv6Addr) -> Option<Ipv4Addr> {
    match addr.octets() {
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, a, b, c, d] => Some(Ipv4Addr::new(a, b, c, d)),
        _ => None,
    }
}

/// Get RIR info of an ipv4 address
fn ipv4_get_rir(addr: &Ipv4Addr, rir: &mut String) {
    match RIR.get() {
        None => {}
        Some(rirs) => *rir = rirs[addr.octets()[0] as usize].clone(),
    };
}

fn ip_get_rir(addr: &IpAddr, rir: &mut String) {
    match addr {
        IpAddr::V4(addr) => ipv4_get_rir(&addr, rir),
        IpAddr::V6(addr) => match ipv6_to_ipv4_mapped(addr) {
            None => {}
            Some(addr) => ipv4_get_rir(&addr, rir),
        },
    }
}

#[derive(Clone, Debug, Default)]
struct Builder {
    id: ProcessorID,
}

impl ProcessorBuilder for Builder {
    fn build(&self, _: &api::config::Config) -> Box<dyn PktProcessor> {
        let mut p = Box::new(IPProcessor::default());
        p.id = self.id;
        p
    }

    fn id(&self) -> ProcessorID {
        self.id
    }

    fn set_id(&mut self, id: ProcessorID) {
        self.id = id
    }

    fn register_classify_rules(
        &mut self,
        manager: &mut classifiers::ClassifierManager,
    ) -> Result<()> {
        manager.add_protocol_rule(self.id(), Protocol::IPV4)?;
        manager.add_protocol_rule(self.id(), Protocol::IPV6)?;
        Ok(())
    }
}

impl Plugin for Builder {
    fn plugin_type(&self) -> PluginType {
        PluginType::PacketProcessor
    }

    /// Get parser name
    fn name(&self) -> &str {
        "ip"
    }

    fn init(&mut self, alcfg: &api::config::Config) -> Result<()> {
        let db_dir = PathBuf::from(alcfg.get_str(&"ip.db.directory", "etc"));
        let db_path = db_dir.join("GeoLite2-ASN.mmdb");
        if !db_path.exists() {
            return Err(anyhow!("{} does not exist", db_path.to_string_lossy()));
        }

        ASN_DB
            .set(GeoLiteReader::open_mmap(db_path)?)
            .ok()
            .ok_or(anyhow!("{} ASN_DBS are already set", self.name()))?;

        let db_path = db_dir.join("GeoLite2-Country.mmdb");
        if !db_path.exists() {
            return Err(anyhow!("{} does not exist", db_path.to_string_lossy()));
        }
        COUNTRY_DB
            .set(GeoLiteReader::open_mmap(db_path)?)
            .ok()
            .ok_or(anyhow!("{} COUNTRY_DBS are already set", self.name()))?;

        let db_path = db_dir.join("GeoLite2-City.mmdb");
        if !db_path.exists() {
            return Err(anyhow!("{} does not exist", db_path.to_string_lossy()));
        }
        CITY_DB
            .set(GeoLiteReader::open_mmap(db_path)?)
            .ok()
            .ok_or(anyhow!("{} CITY_DBS are already set", self.name()))?;

        let mut rirs = vec![String::default(); u8::MAX as usize + 1];
        let headers = csv::StringRecord::from(vec![
            "Prefix",
            "Designation",
            "Date",
            "WHOIS",
            "RDAP",
            "Status [1]",
            "Note",
        ]);
        let rir_path = db_dir.join("ipv4-address-space.csv");
        if !rir_path.exists() {
            return Err(anyhow!("{} does not exist", rir_path.to_string_lossy()));
        }
        let mut reader = csv::Reader::from_path(rir_path)?;
        reader.set_headers(headers.clone());
        for (i, row) in reader.records().enumerate() {
            if i == 0 {
                continue;
            }
            let record = row?;
            let rir: IpRir = record.deserialize(Some(&headers))?;
            rirs[rir.prefix as usize] = rir.rir;
        }
        RIR.set(rirs)
            .ok()
            .ok_or(anyhow!("{} RIR is already set", self.name()))?;

        Ok(())
    }
}

#[derive(Clone, Default)]
struct IPProcessor {
    id: ProcessorID,
    classified: bool,
    processed: bool,
    ip_protocol: u8,
    src_ip: IpInfo,
    dst_ip: IpInfo,
}

impl PktProcessor for IPProcessor {
    fn id(&self) -> ProcessorID {
        self.id
    }

    fn name(&self) -> &'static str {
        &"ip"
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

        let layer = match pkt.layers().network() {
            None => unreachable!("ip processor received a pkt with no network layer"),
            Some(layer) => layer,
        };

        match layer.protocol {
            Protocol::IPV4 => {
                self.ip_protocol = pkt.raw()[layer.range.clone()][9];
                ses.add_protocol(&"ipv4", ProtocolLayer::Network);
                self.src_ip.addr = match pkt.src_ipv4() {
                    None => unreachable!("ip processor received a pkt with non ipv4 network layer"),
                    Some(ipv4) => IpAddr::V4(Ipv4Addr::from(ipv4)),
                };
                self.dst_ip.addr = match pkt.dst_ipv4() {
                    None => unreachable!("ip processor received a pkt with non ipv4 network layer"),
                    Some(ipv4) => IpAddr::V4(Ipv4Addr::from(ipv4)),
                }
            }
            Protocol::IPV6 => {
                self.ip_protocol = pkt.raw()[layer.range.clone()][6];
                ses.add_protocol(&"ipv6", ProtocolLayer::Network);
                self.src_ip.addr = match pkt.src_ipv6() {
                    None => unreachable!("ip processor received a pkt with non ipv6 network layer"),
                    Some(ipv6) => IpAddr::V6(Ipv6Addr::from(ipv6.clone())),
                };
                self.dst_ip.addr = match pkt.dst_ipv6() {
                    None => unreachable!("ip processor received a pkt with non ipv6 network layer"),
                    Some(ipv6) => IpAddr::V6(Ipv6Addr::from(ipv6.clone())),
                }
            }
            _ => unreachable!("ip processor received a pkt with non ipv4/ipv6 network layer"),
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

        ip_get_rir(&self.src_ip.addr, &mut self.src_ip.rir);
        ip_get_rir(&self.dst_ip.addr, &mut self.dst_ip.rir);

        self.processed = true;

        Ok(())
    }

    fn save(&mut self, ses: &mut Session) {
        ses.add_field(&"ipProtocol", json!(self.ip_protocol));
        ses.add_field(&"srcIp", json!(self.src_ip.addr));
        if !self.src_ip.asn.is_empty() {
            ses.add_field(&"srcASN", json!(self.src_ip.asn));
        }
        if !self.src_ip.country.is_empty() {
            ses.add_field(&"srcGEO", json!(self.src_ip.country));
        }
        if !self.src_ip.city.is_empty() {
            ses.add_field(&"srcGEOCity", json!(self.src_ip.city));
        }
        if !self.src_ip.rir.is_empty() {
            ses.add_field(&"srcRIR", json!(self.src_ip.rir));
        }

        ses.add_field(&"dstIp", json!(self.dst_ip.addr));
        if !self.dst_ip.asn.is_empty() {
            ses.add_field(&"dstASN", json!(self.dst_ip.asn));
        }
        if !self.dst_ip.country.is_empty() {
            ses.add_field(&"dstGEO", json!(self.dst_ip.country));
        }
        if !self.dst_ip.city.is_empty() {
            ses.add_field(&"dstGEOCity", json!(self.dst_ip.city));
        }
        if !self.dst_ip.rir.is_empty() {
            ses.add_field(&"dstRIR", json!(self.dst_ip.rir));
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
pub extern "C" fn al_new_pkt_processor_builder() -> Box<Box<dyn ProcessorBuilder>> {
    Box::new(Box::new(Builder::default()))
}

#[no_mangle]
pub extern "C" fn al_plugin_type() -> PluginType {
    PluginType::PacketProcessor
}
