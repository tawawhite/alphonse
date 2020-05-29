use std::fs::File;
use std::io::Read;
use std::path::Path;

extern crate clap;
extern crate yaml_rust;

use yaml_rust::{Yaml, YamlLoader};

use super::commands::CliArg;
use super::error::Error;

#[derive(Default, Clone)]
pub struct Config {
    pub backend: String,
    pub verbose_mode: bool,
    pub delete: bool,
    pub dpdk_eal_args: Vec<String>,
    pub dry_run: bool,
    pub pcap_file: String,
    pub pcap_dir: String,
    pub rx_threads: u8,
    pub ses_threads: u8,
    pub quiet: bool,
    pub recursive: bool,
    pub tags: Vec<String>,
}

/// Parse command line arguments and set configuration
pub fn parse_args(root_cmd: clap::App) -> Result<Config, Error> {
    let mut config: Config = Default::default();
    let matches = root_cmd.get_matches();

    if let Some(config_file) = matches.value_of("config") {
        parse_config_file(config_file, &mut config)?;
    }

    set_config_by_cli_args(&mut config, &matches);

    Ok(config)
}

fn parse_config_file(config_file: &str, config: &mut Config) -> Result<(), Error> {
    let cfg_path = Path::new(config_file);
    if !cfg_path.exists() {
        eprintln!(
            "\"{}\" does not exist! Use default configuration file instead",
            config_file
        );
    }

    let mut s = String::new();
    File::open(cfg_path)?.read_to_string(&mut s)?;

    let docs = YamlLoader::load_from_str(&s)?;
    let doc = &docs[0];

    match &doc["threads.rx"] {
        Yaml::Integer(i) => config.rx_threads = *i as u8,
        Yaml::BadValue => {
            return Err(Error::CommonError(String::from(
                "Option threads.rx not found or bad integer value",
            )))
        }
        _ => {
            return Err(Error::CommonError(String::from(
                "Wrong value type for threads.rx, expecting integer",
            )))
        }
    };

    match &doc["threads.session"] {
        Yaml::Integer(i) => config.ses_threads = *i as u8,
        Yaml::BadValue => {
            return Err(Error::CommonError(String::from(
                "Option threads.ses not found or bad integer value",
            )))
        }
        _ => {
            return Err(Error::CommonError(String::from(
                "Wrong value type for threads.rx, expecting integer",
            )))
        }
    };

    match &doc["backend"] {
        Yaml::String(s) => match s.as_str() {
            "dpdk" | "libpcap" => {
                config.backend = String::from(s);
            }
            _ => return Err(Error::CommonError(format!("Invalid backend option: {}", s))),
        },
        Yaml::BadValue => {
            return Err(Error::CommonError(String::from(
                "Option backend not found or bad string value",
            )))
        }
        _ => {
            return Err(Error::CommonError(String::from(
                "Wrong value type for backend, expecting string",
            )))
        }
    };

    #[cfg(all(target_os = "linux", feature = "dpdk"))]
    {
        // 处理 DPDK EAL 启动参数
        match *&doc["dpdk"] {
            Yaml::Array(ref array) => {
                for v in array {
                    let s = v.as_str().ok_or(Error::CommonError(format!(
                        "Failed to convert Yaml into &str"
                    )))?;
                    config.dpdk_eal_args.push(String::from(s));
                }
                Ok(())
            }
            _ => {
                return Err(Error::CommonError(format!(
                    "Invalid/Empty dpdk args in {}",
                    config_file
                )))
            }
        };
    }
    Ok(())
}

/// Use command arguments overrides config file settings
fn set_config_by_cli_args(config: &mut Config, matches: &clap::ArgMatches) {
    config.delete = matches.is_present(CliArg::Delete.as_str());
    config.dry_run = matches.is_present(CliArg::DryRun.as_str());
    config.quiet = matches.is_present(CliArg::Quiet.as_str());
    config.recursive = matches.is_present(CliArg::Recursive.as_str());
    config.verbose_mode = matches.is_present(CliArg::Verbose.as_str());

    if let Some(pcap_file) = matches.value_of(CliArg::PcapFile.as_str()) {
        config.pcap_file = String::from(pcap_file);
    }

    if let Some(pcap_dir) = matches.value_of(CliArg::PcapDir.as_str()) {
        config.pcap_dir = String::from(pcap_dir);
    }

    if let Some(tags) = matches.values_of(CliArg::Tags.as_str()) {
        config.tags = tags.map(|x| String::from(x)).collect::<Vec<_>>();
    }
}
