use std::convert::TryFrom;
use std::fmt;
use std::fs::File;
use std::hash::Hash;
use std::io::Read;
use std::path::Path;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use elasticsearch::Elasticsearch;
use elasticsearch::{IndexParts, SearchParts, UpdateParts};
use serde::de::{self, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use yaml_rust::Yaml;

use alphonse_utils as utils;

use crate::Config;

#[derive(Clone, Debug, Deserialize, Eq, Hash, Serialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum FieldType {
    Integer,
    TermField,
    LoTermField,
    UpTermField,
    IP,
    Seconds,
    Viewand,
    Fileand,
    TextField,
    LoTextField,
    UpTextField,
    Date,
}

impl Default for FieldType {
    fn default() -> Self {
        FieldType::TermField
    }
}

bitflags! {
    pub struct FieldFlags: u16 {
        const FAKE = 0b1000;
        const DISABLED = 0b10000;
        const CNT = 0b100000;
        /// Don't suggest using this flag, since Arkime itself says don't use it
        const IP = 0b1000000;
    }
}

impl Default for FieldFlags {
    fn default() -> Self {
        FieldFlags::empty()
    }
}

struct FlagsVisitor;
const FLAGS_STRING: &[&str] = &["linked-sessions", "nodb", "fake", "disabled", "cnt", "ip"];

impl<'de> Visitor<'de> for FlagsVisitor {
    type Value = FieldFlags;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("an string sequence")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut flags = FieldFlags::empty();

        while let Ok(flag) = seq.next_element() {
            let flag: Option<String> = flag;
            match flag {
                Some(f) => match f.as_str() {
                    "fake" => flags = flags | FieldFlags::FAKE,
                    "disabled" => flags = flags | FieldFlags::DISABLED,
                    "cnt" => flags = flags | FieldFlags::CNT,
                    "ip" => flags = flags | FieldFlags::IP,
                    _ => return Err(de::Error::unknown_variant(f.as_str(), FLAGS_STRING)),
                },
                None => return Ok(flags),
            }
        }

        Ok(flags)
    }
}

impl<'de> Deserialize<'de> for FieldFlags {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_struct("FieldFlags", &["bits"], FlagsVisitor)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Serialize, PartialEq)]
#[serde(untagged)]
pub enum Category {
    Single(String),
    Multiple(Vec<String>),
}

// Currently I haven't find a good way to dynamically convert an arbitray yaml hashmap
// into a json object, so Field struct needs to have all the possible fields have been
// defined in Arkime

#[derive(Clone, Debug, Default, Deserialize, Eq, Hash, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Field {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aliases: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<Category>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub db_field: Option<String>,
    pub db_field2: String,
    #[serde(skip_serializing)]
    #[serde(default)]
    pub expression: String,
    #[serde(skip_serializing)]
    pub flags: Option<FieldFlags>,
    pub friendly_name: String,
    pub group: String,
    pub help: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub no_facet: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port_field: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port_field2: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_field: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub regex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required_right: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transform: Option<String>,
    pub r#type: FieldType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type2: Option<String>,
}

impl TryFrom<&Yaml> for Field {
    type Error = anyhow::Error;
    fn try_from(value: &Yaml) -> Result<Self, Self::Error> {
        match value {
            Yaml::Hash(_) => {}
            Yaml::BadValue => return Err(anyhow!("Invalid hash value for a field")),
            _ => return Err(anyhow!("Wrong value type for a field, expecting hash type")),
        };

        let mut tmp = String::new();
        let mut emitter = yaml_rust::YamlEmitter::new(&mut tmp);
        emitter.dump(value)?;

        let field: Field = serde_yaml::from_str(tmp.as_mut_str())?;

        Ok(field)
    }
}

/// Get fields from a yaml field
///
/// Of course one can choose to define fields in pkt processor impl. However, it would be more
/// clear and more flexible to be able to define a field in a yaml file
pub fn get_fields_from_yaml<P: AsRef<Path>>(fpath: &P) -> Result<Vec<Field>> {
    let mut s = String::new();
    File::open(fpath)?.read_to_string(&mut s)?;
    let docs = yaml_rust::YamlLoader::load_from_str(&s)?;
    let doc = docs
        .get(0)
        .ok_or(anyhow!("No document founded in {:?}", fpath.as_ref()))?;

    match &doc {
        Yaml::Array(arr) => {
            let mut fields = vec![];
            for elm in arr {
                let field = Field::try_from(elm)?;
                if field.expression.is_empty() {
                    return Err(anyhow!(
                        "Get field without expression field, field: {}",
                        serde_json::to_string_pretty(&field)?
                    ));
                }
                // println!("{}", serde_json::to_string_pretty(&field).unwrap());
                fields.push(field)
            }
            Ok(fields)
        }
        Yaml::BadValue => Err(anyhow!("Invalid array value for a field")),
        _ => Err(anyhow!(
            "Wrong value type for a field, expecting array type"
        )),
    }
}

async fn load_fields(es: Arc<Elasticsearch>, cfg: &Config) -> Result<Vec<Field>> {
    let index = format!("{}fields", cfg.prefix);
    let resp = es
        .search(SearchParts::Index(&[&index]))
        .size(3000)
        .timeout(&"3s")
        .send()
        .await?;
    match resp.status_code().as_u16() {
        code if code >= 200 && code < 300 => {
            let json: serde_json::Value = resp.json().await?;
            let hits = json
                .get("hits")
                .ok_or(anyhow!("No 'hits' found in ES's search response"))?
                .get("hits")
                .ok_or(anyhow!("No 'hits' found in ES's search response"))?
                .as_array()
                .ok_or(anyhow!("'hits' is not array type in ES's search response"))?;

            let mut fields = vec![];
            for hit in hits {
                let expression = hit
                    .get("_id")
                    .ok_or(anyhow!("No \"_id\" found in hit"))?
                    .as_str()
                    .ok_or(anyhow!("Could not parse \"_id\" as string"))?;
                let source = hit
                    .get("_source")
                    .ok_or(anyhow!("No \"_source\" found in hit"))?;
                let mut field: Field = serde_json::from_value(source.clone())?;
                field.expression = expression.to_string();
                fields.push(field);
            }
            Ok(fields)
        }
        c => Err(anyhow!("{} {}", c, resp.text().await?)),
    }
}

/// Add local fields into Elasticsearch
pub async fn add_fields(es: Arc<Elasticsearch>, cfg: &Config, fields: Vec<Field>) -> Result<()> {
    let mut existing_fields = load_fields(es.clone(), cfg).await?;

    for field in fields {
        let exists = existing_fields
            .iter()
            .find(|f| f.db_field2 == field.db_field2);
        let flags = field.flags.unwrap_or_default();

        match exists {
            None => {
                existing_fields.push(field.clone());
                add_field(&es, cfg, &field).await?;
            }
            Some(f) => {
                if f.r#type != field.r#type {
                    eprintln!(
                        "Field kind in db {:?} does match field kind {:?} in capture for field {}",
                        f.r#type, field.r#type, field.expression
                    );
                }

                if f.category != field.category {
                    eprintln!(
                        "Field category in db {:?} does match field category {:?} in capture for field {}",
                        f.category, field.category, field.expression
                    );
                    update_field(&es, cfg, &field).await?;
                }

                if f.transform != field.transform {
                    eprintln!(
                        "Field transform in db {:?} does match field transform {:?} in capture for field {}",
                        f.transform, field.transform, field.expression
                    );
                    update_field(&es, cfg, &field).await?;
                }

                if !flags.contains(FieldFlags::FAKE) {
                    // TODO: arkime stuff
                }

                if flags.contains(FieldFlags::CNT) {
                    let mut new = field.clone();
                    new.db_field2 = format!("{}Cnt", new.db_field2);
                    let exist = existing_fields.iter().any(|f| f.db_field2 == new.db_field2);
                    if !exist {
                        new.expression = format!("{}.cnt", new.expression);
                        new.friendly_name = format!("{} Cnt", new.friendly_name);
                        new.help = format!("Unique number of {}", new.help);
                        new.r#type = FieldType::Integer;
                        add_field(&es, cfg, &new).await?;
                    }
                }

                if flags.contains(FieldFlags::FAKE) {
                    // TODO: remove fake field
                }

                if flags.contains(FieldFlags::IP) || field.r#type == FieldType::IP {
                    let mut geo = field.clone();
                    geo.db_field2 = format!("{}GEO", geo.db_field2);
                    let exist = existing_fields.iter().any(|f| f.db_field2 == geo.db_field2);
                    if !exist {
                        geo.expression = if flags.contains(FieldFlags::IP) {
                            format!("country.{}", geo.expression)
                        } else {
                            format!("{}.country", geo.expression)
                        };
                        geo.friendly_name = format!("{} GEO", geo.friendly_name);
                        geo.help = format!("GeoIP country string calculated from the {}", geo.help);
                        geo.r#type = FieldType::UpTermField;
                        add_field(&es, cfg, &geo).await?;
                    }

                    let mut asn = field.clone();
                    asn.db_field2 = format!("{}ASN", asn.db_field2);
                    let exist = existing_fields.iter().any(|f| f.db_field2 == asn.db_field2);
                    if !exist {
                        asn.expression = if flags.contains(FieldFlags::IP) {
                            format!("asn.{}", asn.expression)
                        } else {
                            format!("{}.asn", asn.expression)
                        };
                        asn.friendly_name = format!("{} ASN", asn.friendly_name);
                        asn.help = format!("GeoIP ASN string calculated from the {}", asn.help);
                        asn.r#type = FieldType::TermField;
                        add_field(&es, cfg, &asn).await?;
                    }

                    let mut rir = field.clone();
                    rir.db_field2 = format!("{}RIR", rir.db_field2);
                    let exist = existing_fields.iter().any(|f| f.db_field2 == rir.db_field2);
                    if !exist {
                        rir.expression = if flags.contains(FieldFlags::IP) {
                            format!("rir.{}", rir.expression)
                        } else {
                            format!("{}.rir", rir.expression)
                        };
                        rir.expression = format!("{}.rir", rir.expression);
                        rir.friendly_name = format!("{} RIR", rir.friendly_name);
                        rir.help = format!(
                            "Regional Internet Registry string calculated from {}",
                            rir.help
                        );
                        rir.r#type = FieldType::UpTermField;
                        add_field(&es, cfg, &rir).await?;
                    }
                }

                match field.r#type {
                    FieldType::IP => {}
                    _ => {}
                };

                add_field(&es, cfg, &field).await?;
            }
        }
    }

    Ok(())
}

/// Add an field into Elasticsearch
async fn add_field(es: &Arc<Elasticsearch>, cfg: &Config, field: &Field) -> Result<()> {
    let index = format!("{}fields", cfg.prefix);
    let resp = es
        .index(IndexParts::IndexId(&index, &field.expression))
        .body(field)
        .send()
        .await?;
    utils::elasticsearch::handle_resp(resp).await?;
    Ok(())
}

async fn update_field(es: &Arc<Elasticsearch>, cfg: &Config, field: &Field) -> Result<()> {
    let index = format!("{}fields", cfg.prefix);
    let resp = es
        .update(UpdateParts::IndexId(&index, &field.expression))
        .body(field)
        .send()
        .await?;
    utils::elasticsearch::handle_resp(resp).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use serde_json::json;

    #[test]
    fn load() {
        get_fields_from_yaml(&"../etc/fields.yml").unwrap();
    }

    #[test]
    fn field_type_serialize() {
        use serde_json::to_string;
        let field_type = FieldType::Date;
        assert_eq!(to_string(&json!(field_type)).unwrap(), "\"date\"");

        let field_type = FieldType::Fileand;
        assert_eq!(to_string(&json!(field_type)).unwrap(), "\"fileand\"");

        let field_type = FieldType::IP;
        assert_eq!(to_string(&json!(field_type)).unwrap(), "\"ip\"");

        let field_type = FieldType::Integer;
        assert_eq!(to_string(&json!(field_type)).unwrap(), "\"integer\"");

        let field_type = FieldType::LoTermField;
        assert_eq!(to_string(&json!(field_type)).unwrap(), "\"lotermfield\"");

        let field_type = FieldType::LoTextField;
        assert_eq!(to_string(&json!(field_type)).unwrap(), "\"lotextfield\"");

        let field_type = FieldType::Seconds;
        assert_eq!(to_string(&json!(field_type)).unwrap(), "\"seconds\"");

        let field_type = FieldType::TermField;
        assert_eq!(to_string(&json!(field_type)).unwrap(), "\"termfield\"");

        let field_type = FieldType::UpTermField;
        assert_eq!(to_string(&json!(field_type)).unwrap(), "\"uptermfield\"");

        let field_type = FieldType::Viewand;
        assert_eq!(to_string(&json!(field_type)).unwrap(), "\"viewand\"");
    }

    #[test]
    fn field_type_deserialize() {
        use serde_yaml::from_str;

        let field_type: FieldType = from_str("date").unwrap();
        assert_eq!(field_type, FieldType::Date);

        let field_type: FieldType = from_str("fileand").unwrap();
        assert_eq!(field_type, FieldType::Fileand);

        let field_type: FieldType = from_str("ip").unwrap();
        assert_eq!(field_type, FieldType::IP);

        let field_type: FieldType = from_str("integer").unwrap();
        assert_eq!(field_type, FieldType::Integer);

        let field_type: FieldType = from_str("lotermfield").unwrap();
        assert_eq!(field_type, FieldType::LoTermField);

        let field_type: FieldType = from_str("lotextfield").unwrap();
        assert_eq!(field_type, FieldType::LoTextField);

        let field_type: FieldType = from_str("seconds").unwrap();
        assert_eq!(field_type, FieldType::Seconds);

        let field_type: FieldType = from_str("termfield").unwrap();
        assert_eq!(field_type, FieldType::TermField);

        let field_type: FieldType = from_str("uptermfield").unwrap();
        assert_eq!(field_type, FieldType::UpTermField);

        let field_type: FieldType = from_str("viewand").unwrap();
        assert_eq!(field_type, FieldType::Viewand);
    }

    #[test]
    fn field_flags_deserialize() {
        let flags: FieldFlags = serde_yaml::from_str("[cnt]").unwrap();
        assert_eq!(flags, FieldFlags::CNT);

        let flags: FieldFlags = serde_yaml::from_str("[linked-sessions]").unwrap();
        assert_eq!(flags, FieldFlags::LINKED_SESSIONS);

        let flags: FieldFlags = serde_yaml::from_str("[nodb]").unwrap();
        assert_eq!(flags, FieldFlags::NODB);

        let flags: FieldFlags = serde_yaml::from_str("[disabled]").unwrap();
        assert_eq!(flags, FieldFlags::DISABLED);

        let flags: FieldFlags = serde_yaml::from_str("[fake]").unwrap();
        assert_eq!(flags, FieldFlags::FAKE);

        let flags: FieldFlags = serde_yaml::from_str("[fake, cnt]").unwrap();
        assert_eq!(flags, FieldFlags::FAKE | FieldFlags::CNT);

        let flags: FieldFlags = serde_yaml::from_str("[]").unwrap();
        assert_eq!(flags, FieldFlags::empty());

        let result: Result<FieldFlags, serde_yaml::Error> = serde_yaml::from_str("[invalid]");
        assert!(matches!(result, Err(_)));
    }

    #[test]
    fn category_deserialize() {
        let category: Category = serde_json::from_str("[\"ip\"]").unwrap();
        assert!(matches!(category, Category::Multiple(_)));

        let category: Category = serde_json::from_str("\"ip\"").unwrap();
        assert!(matches!(category, Category::Single(_)));
    }
}
