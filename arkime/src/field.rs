use std::convert::TryFrom;
use std::fmt;
use std::fs::File;
use std::hash::Hash;
use std::io::Read;
use std::path::Path;

use anyhow::{anyhow, Result};
use serde::de::{self, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use yaml_rust::Yaml;

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
        const LINKED_SESSIONS = 0b1;
        const FORCE_UTF8 = 0b10;
        /// In the future, this flag maybe removed, since it doesn't make any sense in alphonse
        const NODB = 0b100;
        const FAKE = 0b1000;
        const DISABLED = 0b10000;
        const CNT = 0b100000;
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
                    "linked-sessions" => flags = flags | FieldFlags::LINKED_SESSIONS,
                    "nodb" => flags = flags | FieldFlags::NODB,
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

// Currently I haven't find a good way to dynamically convert an arbitray yaml hashmap
// into a json object, so Field struct needs to have all the possible fields have been
// defined in Arkime

#[derive(Clone, Debug, Default, Deserialize, Eq, Hash, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Field {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aliases: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub db_field: Option<String>,
    pub db_field2: String,
    #[serde(rename(serialize = "_id"))]
    pub expression: String,
    #[serde(skip_serializing)]
    pub flags: Option<FieldFlags>,
    pub friendly_name: String,
    pub group: String,
    pub help: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub no_facet: Option<bool>,
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

#[cfg(test)]
mod tests {
    use super::*;

    use serde_json::json;

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
}
