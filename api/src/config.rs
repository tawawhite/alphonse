use std::sync::{atomic::AtomicBool, Arc};

use anyhow::{anyhow, Result};

#[derive(Default, Clone)]
pub struct Config {
    pub exit: Arc<AtomicBool>,
    /// Configure file dist location
    pub fpath: String,
    pub rx_driver: String,
    pub verbose_mode: bool,
    pub pkt_channel_size: u32,
    pub default_timeout: u16,
    pub delete: bool,
    pub dpdk_eal_args: Vec<String>,
    pub dry_run: bool,
    pub node: String,
    pub hostname: String,
    pub processors: Vec<String>,
    pub pcap_file: String,
    pub pcap_dir: String,
    pub pkt_threads: u8,
    pub quiet: bool,
    pub recursive: bool,
    pub rx_stat_log_interval: u64,
    /// Max single session packets
    pub ses_max_packets: u16,
    /// Max session connection duration
    pub ses_save_timeout: u16,
    pub sctp_timeout: u16,
    pub tags: Vec<String>,
    pub tcp_timeout: u16,
    pub timeout_interval: u64,
    pub udp_timeout: u16,
    pub doc: Yaml,
}

impl Config {
    pub fn get_integer(&self, key: &str, default: i64, min: i64, max: i64) -> i64 {
        get_integer(&self.doc.as_ref(), key, default, min, max)
    }

    pub fn get_float(&self, key: &str, default: f64, min: f64, max: f64) -> f64 {
        get_float(&self.doc.as_ref(), key, default, min, max)
    }

    pub fn get_str(&self, key: &str, default: &str) -> String {
        get_str(&self.doc.as_ref(), key, default)
    }

    pub fn get_str_arr(&self, key: &str) -> Vec<String> {
        get_str_arr(&self.doc.as_ref(), key)
    }

    pub fn get_boolean(&self, key: &str, default: bool) -> bool {
        get_boolean(&self.doc.as_ref(), key, default)
    }

    pub fn get_object(&self, key: &str) -> &yaml_rust::Yaml {
        get_object(&self.doc.as_ref(), key)
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
/// Simple wrapper struct to implement Default trait for toml::Value
pub struct Yaml(pub yaml_rust::Yaml);

impl Default for Yaml {
    fn default() -> Self {
        Self(yaml_rust::Yaml::Null)
    }
}

impl AsRef<yaml_rust::Yaml> for Yaml {
    fn as_ref(&self) -> &yaml_rust::Yaml {
        &self.0
    }
}

impl AsMut<yaml_rust::Yaml> for Yaml {
    fn as_mut(&mut self) -> &mut yaml_rust::Yaml {
        &mut self.0
    }
}

fn get_str(doc: &yaml_rust::Yaml, key: &str, default: &str) -> String {
    match &doc[key] {
        yaml_rust::Yaml::String(s) => s.clone(),
        yaml_rust::Yaml::BadValue => {
            println!(
                "Option {} not found or bad string value, set {} to {}",
                key, key, default
            );
            default.to_string()
        }
        _ => {
            println!(
                "Wrong value type for {}, expecting string, set {} to {}",
                key, key, default
            );
            default.to_string()
        }
    }
}

fn get_str_without_default(doc: &yaml_rust::Yaml, key: &str) -> Result<String> {
    match &doc[key] {
        yaml_rust::Yaml::String(s) => Ok(s.clone()),
        yaml_rust::Yaml::BadValue => Err(anyhow!("Option {} not found or bad string value", key,)),
        _ => Err(anyhow!("Wrong value type for {}, expecting string", key,)),
    }
}

fn get_boolean(doc: &yaml_rust::Yaml, key: &str, default: bool) -> bool {
    match doc[key] {
        yaml_rust::Yaml::Boolean(b) => b,
        yaml_rust::Yaml::BadValue => {
            println!(
                "Option {} not found or bad boolean value, set {} to {}",
                key, key, default
            );
            default
        }
        _ => {
            println!(
                "Wrong value type for {}, expecting boolean, set {} to {}",
                key, key, default
            );
            default
        }
    }
}

fn get_boolean_without_default(doc: &yaml_rust::Yaml, key: &str) -> Result<bool> {
    match &doc[key] {
        yaml_rust::Yaml::Boolean(b) => Ok(b.clone()),
        yaml_rust::Yaml::BadValue => Err(anyhow!("Option {} not found or bad boolean value", key,)),
        _ => Err(anyhow!("Wrong value type for {}, expecting boolean", key,)),
    }
}

fn get_integer(doc: &yaml_rust::Yaml, key: &str, default: i64, min: i64, max: i64) -> i64 {
    match doc[key] {
        yaml_rust::Yaml::Integer(i) => {
            if i < min || i > max {
                println!(
                    "Option {} is less/greater than min/max value {}/{}, set {} to {}",
                    key, min, max, key, default
                );
                default
            } else {
                i
            }
        }
        yaml_rust::Yaml::BadValue => {
            println!(
                "Option {} not found or bad integer value, set {} to {}",
                key, key, default
            );
            default
        }
        _ => {
            println!(
                "Wrong value type for {}, expecting string, set {} to {}",
                key, key, default
            );
            default
        }
    }
}

fn get_str_arr(doc: &yaml_rust::Yaml, key: &str) -> Vec<String> {
    let mut result = vec![];
    match &doc[key] {
        yaml_rust::Yaml::Array(a) => {
            for element in a {
                match element {
                    yaml_rust::Yaml::String(s) => result.push(String::from(s)),
                    yaml_rust::Yaml::BadValue => println!("Bad string value for {}'s element", key),
                    _ => println!("Wrong value type for {}' element, expecting string", key),
                }
            }
        }
        yaml_rust::Yaml::BadValue => println!(
            "Option {} not found or bad array value, set {} to empty array",
            key, key
        ),
        _ => println!(
            "Wrong value type for {}, expecting array, set {} to empty array",
            key, key
        ),
    }
    result
}

fn get_float(doc: &yaml_rust::Yaml, key: &str, default: f64, min: f64, max: f64) -> f64 {
    match &doc[key] {
        yaml_rust::Yaml::Real(f) => {
            let f = match &f.parse::<f64>() {
                Ok(f) => *f,
                Err(e) => {
                    eprintln!("{}", e);
                    0.0
                }
            };
            if f < min || f > max {
                println!(
                    "Option {} is less/greater than min/max value {}/{}, set {} to {}",
                    key, min, max, key, default
                );
                default
            } else {
                f
            }
        }
        yaml_rust::Yaml::BadValue => {
            println!(
                "Option {} not found or bad integer value, set {} to {}",
                key, key, default
            );
            default
        }
        _ => {
            println!(
                "Wrong value type for {}, expecting string, set {} to {}",
                key, key, default
            );
            default
        }
    }
}

fn get_object<'a>(doc: &'a yaml_rust::Yaml, key: &str) -> &'a yaml_rust::Yaml {
    match &doc[key] {
        yaml_rust::Yaml::BadValue => {
            eprintln!("{} not found, set {} to Null", key, key);
            &yaml_rust::Yaml::Null
        }
        obj => obj as &yaml_rust::Yaml,
    }
}
