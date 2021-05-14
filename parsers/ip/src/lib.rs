use std::hash::{BuildHasher, Hash, Hasher};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::{anyhow, Result};
use maxminddb::{geoip2, Reader as GeoLiteReader};
use memmap::Mmap;
use once_cell::sync::OnceCell;

use alphonse_api as api;
use api::add_protocol_rule;
use api::classifiers::{self, protocol, Rule, RuleType};
use api::packet::{PacketHashKey, Protocol};
use api::parsers::ParserID;
use api::session::Session;

static ASN_DBS: OnceCell<Vec<GeoLiteReader<Mmap>>> = OnceCell::new();
static COUNTRY_DBS: OnceCell<Vec<GeoLiteReader<Mmap>>> = OnceCell::new();
static CITY_DBS: OnceCell<Vec<GeoLiteReader<Mmap>>> = OnceCell::new();

#[derive(Default)]
struct Processor {
    id: ParserID,
    name: String,
    classified: bool,
    processed: bool,
    /// Hasher to decide which thread this processor belongs to
    hasher: fnv::FnvHasher,
}

impl Clone for Processor {
    fn clone(&self) -> Self {
        Self {
            id: self.id,
            name: self.name.clone(),
            classified: self.classified,
            processed: self.processed,
            hasher: fnv::FnvBuildHasher::default().build_hasher(),
        }
    }
}

impl api::parsers::ProtocolParserTrait for Processor {
    fn box_clone(&self) -> Box<dyn api::parsers::ProtocolParserTrait> {
        Box::new(self.clone())
    }

    /// Get parser id
    fn id(&self) -> ParserID {
        self.id
    }

    /// Get parser id
    fn set_id(&mut self, id: ParserID) {
        self.id = id
    }

    /// Get parser name
    fn name(&self) -> &str {
        &self.name.as_str()
    }

    fn init(&mut self, alcfg: &api::config::Config) -> Result<()> {
        let mut dbs = vec![];
        for _ in 0..alcfg.pkt_threads {
            let db = GeoLiteReader::open_mmap("./etc/GeoLite2-ASN.mmdb")?;
            dbs.push(db);
        }
        ASN_DBS
            .set(dbs)
            .ok()
            .ok_or(anyhow!("{} ASN_DBS are already set", self.name()))?;

        let mut dbs = vec![];
        for _ in 0..alcfg.pkt_threads {
            let db = GeoLiteReader::open_mmap("./etc/GeoLite2-Country.mmdb")?;
            dbs.push(db);
        }
        COUNTRY_DBS
            .set(dbs)
            .ok()
            .ok_or(anyhow!("{} COUNTRY_DBS are already set", self.name()))?;

        let mut dbs = vec![];
        for _ in 0..alcfg.pkt_threads {
            let db = GeoLiteReader::open_mmap("./etc/GeoLite2-City.mmdb")?;
            dbs.push(db);
        }
        CITY_DBS
            .set(dbs)
            .ok()
            .ok_or(anyhow!("{} CITY_DBS are already set", self.name()))?;

        Ok(())
    }

    fn register_classify_rules(
        &mut self,
        manager: &mut classifiers::ClassifierManager,
    ) -> Result<()> {
        add_protocol_rule!(Protocol::IPV4, self.id(), manager);
        add_protocol_rule!(Protocol::IPV6, self.id(), manager);
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

        let src_ip = unsafe {
            match pkt.layers().network.protocol {
                Protocol::IPV4 => IpAddr::V4(Ipv4Addr::from(pkt.src_ipv4())),
                Protocol::IPV6 => IpAddr::V6(Ipv6Addr::from(*pkt.src_ipv6())),
                _ => {
                    unreachable!()
                }
            }
        };

        let dst_ip = unsafe {
            match pkt.layers().network.protocol {
                Protocol::IPV4 => IpAddr::V4(Ipv4Addr::from(pkt.dst_ipv4())),
                Protocol::IPV6 => IpAddr::V6(Ipv6Addr::from(*pkt.dst_ipv6())),
                _ => {
                    unreachable!()
                }
            }
        };

        PacketHashKey::from(pkt).hash(&mut self.hasher);
        let dbs = unsafe {
            ASN_DBS
                .get()
                .ok_or(anyhow!("{}: ASN_DBS is not initialized", self.name()))?
        };
        let hash = self.hasher.finish() as usize % dbs.len();

        let src_asn: Option<geoip2::Asn> = dbs[hash].lookup(src_ip).ok();
        let dst_asn: Option<geoip2::Asn> = dbs[hash].lookup(dst_ip).ok();

        let src_country: Option<geoip2::Country> = dbs[hash].lookup(src_ip).ok();
        let dst_country: Option<geoip2::Country> = dbs[hash].lookup(dst_ip).ok();

        let src_city: Option<geoip2::City> = dbs[hash].lookup(src_ip).ok();
        let dst_city: Option<geoip2::City> = dbs[hash].lookup(dst_ip).ok();

        println!("{:?} {:?} {:?}", src_asn, src_country, src_city);
        println!("{:?} {:?} {:?}", dst_asn, dst_country, dst_city);
        self.processed = true;
        Ok(())
    }

    fn finish(&mut self, ses: &mut Session) {}
}

#[no_mangle]
pub extern "C" fn al_new_protocol_parser() -> Box<Box<dyn api::parsers::ProtocolParserTrait>> {
    Box::new(Box::new(Processor::default()))
}
