use std::fs::File;
use std::io::Read;
use std::path::Path;

use anyhow::{anyhow, Result};
use yaml_rust::{Yaml, YamlLoader};

use super::commands::CliArg;

#[derive(Default, Clone)]
pub struct Config {
    pub backend: String,
    pub verbose_mode: bool,
    pub default_timeout: u16,
    pub delete: bool,
    pub dpdk_eal_args: Vec<String>,
    pub dry_run: bool,
    pub interfaces: Vec<String>,
    pub pcap_file: String,
    pub pcap_dir: String,
    pub quiet: bool,
    pub recursive: bool,
    pub rx_threads: u8,
    pub ses_threads: u8,
    pub sctp_timeout: u16,
    pub tags: Vec<String>,
    pub tcp_timeout: u16,
    pub timeout_pkt_epoch: u16,
    pub udp_timeout: u16,
}

/// Parse command line arguments and set configuration
pub fn parse_args(root_cmd: clap::App) -> Result<Config> {
    let mut config: Config = Default::default();
    let matches = root_cmd.get_matches();

    if let Some(config_file) = matches.value_of("config") {
        parse_config_file(config_file, &mut config)?;
    }

    set_config_by_cli_args(&mut config, &matches);

    if (config.pcap_dir.is_empty() || config.pcap_file.is_empty()) && config.interfaces.is_empty() {
        return Err(anyhow!(
            "Launched without specify network interface nor pcap file/dir"
        ));
    }

    Ok(config)
}

fn set_integer<T: std::cmp::PartialOrd + std::fmt::Display + Copy>(
    dst: &mut T,
    src: T,
    default: T,
    max: T,
    min: T,
    name: &str,
) {
    if src > max || src < min {
        *dst = default;
        println!(
            "{} is out of range: [{}, {}], set to default value: {}",
            name, min, max, default
        );
    }
    *dst = src;
}

fn parse_config_file(config_file: &str, config: &mut Config) -> Result<()> {
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

    match &doc["timeout.pkt-epoch"] {
        Yaml::Integer(i) => set_integer(
            &mut config.timeout_pkt_epoch,
            *i as u16,
            8,
            0xffff,
            1,
            "timeout.pkt-epoch",
        ),
        Yaml::BadValue => {
            println!("Option timeout.pkt-epoch not found or bad integer value, set timeout.pkt-epoch to 60 secs");
            config.timeout_pkt_epoch = 8;
        }
        _ => {
            return Err(anyhow!(
                "Wrong value type for timeout.pkt-epoch, expecting integer",
            ))
        }
    };

    match &doc["timeout.default"] {
        Yaml::Integer(i) => set_integer(
            &mut config.default_timeout,
            *i as u16,
            60,
            0xffff,
            10,
            "timeout.default",
        ),
        Yaml::BadValue => {
            println!("Option timeout.default not found or bad integer value, set timeout.default to 60 secs");
            config.default_timeout = 60;
        }
        _ => {
            return Err(anyhow!(
                "Wrong value type for timeout.default, expecting integer",
            ))
        }
    };

    match &doc["timeout.tcp"] {
        Yaml::Integer(i) => set_integer(
            &mut config.tcp_timeout,
            *i as u16,
            60,
            0xffff,
            10,
            "timeout.tcp",
        ),
        Yaml::BadValue => {
            println!(
                "Option timeout.tcp not found or bad integer value, set timeout.tcp to 60 secs"
            );
            config.tcp_timeout = 480;
        }
        _ => {
            return Err(anyhow!(
                "Wrong value type for timeout.tcp, expecting integer",
            ))
        }
    };

    match &doc["timeout.udp"] {
        Yaml::Integer(i) => set_integer(
            &mut config.udp_timeout,
            *i as u16,
            60,
            0xffff,
            10,
            "timeout.udp",
        ),
        Yaml::BadValue => {
            println!(
                "Option timeout.udp not found or bad integer value, set timeout.udp to 60 secs"
            );
            config.udp_timeout = 480;
        }
        _ => {
            return Err(anyhow!(
                "Wrong value type for timeout.udp, expecting integer",
            ))
        }
    };

    match &doc["timeout.sctp"] {
        Yaml::Integer(i) => set_integer(
            &mut config.sctp_timeout,
            *i as u16,
            60,
            0xffff,
            10,
            "timeout.sctp",
        ),
        Yaml::BadValue => {
            println!(
                "Option timeout.sctp not found or bad integer value, set timeout.udp to 60 secs"
            );
            config.udp_timeout = 480;
        }
        _ => {
            return Err(anyhow!(
                "Wrong value type for timeout.sctp, expecting integer",
            ))
        }
    };

    match &doc["threads.rx"] {
        Yaml::Integer(i) => config.rx_threads = *i as u8,
        Yaml::BadValue => return Err(anyhow!("Option threads.rx not found or bad integer value",)),
        _ => {
            return Err(anyhow!(
                "Wrong value type for threads.rx, expecting integer",
            ))
        }
    };

    match &doc["threads.session"] {
        Yaml::Integer(i) => config.ses_threads = *i as u8,
        Yaml::BadValue => {
            return Err(anyhow!("Option threads.ses not found or bad integer value",))
        }
        _ => {
            return Err(anyhow!(
                "Wrong value type for threads.rx, expecting integer",
            ))
        }
    };

    match &doc["backend"] {
        Yaml::String(s) => match s.as_str() {
            "dpdk" | "libpcap" => {
                config.backend = String::from(s);
            }
            _ => return Err(anyhow!("Invalid backend option: {}", s)),
        },
        Yaml::BadValue => return Err(anyhow!("Option backend not found or bad string value",)),
        _ => return Err(anyhow!("Wrong value type for backend, expecting string",)),
    };

    match &doc["interfaces"] {
        Yaml::Array(a) => {
            for element in a {
                match element {
                    Yaml::String(s) => config.interfaces.push(s.clone()),
                    Yaml::BadValue => {
                        return Err(anyhow!("Bad string value for an interface value",))
                    }
                    _ => {
                        return Err(anyhow!(
                            "Wrong value type for interfaces' element, expecting string",
                        ))
                    }
                }
            }
        }
        Yaml::BadValue => return Err(anyhow!("Option interfaces not found or bad array value",)),
        _ => return Err(anyhow!("Wrong value type for interfaces, expecting array",)),
    }

    #[cfg(all(target_os = "linux", feature = "dpdk"))]
    {
        // 处理 DPDK EAL 启动参数
        match *&doc["dpdk"] {
            Yaml::Array(ref array) => {
                for v in array {
                    let s = v
                        .as_str()
                        .ok_or(anyhow!("Failed to convert Yaml into &str"))?;
                    config.dpdk_eal_args.push(String::from(s));
                }
                Ok(())
            }
            _ => return Err(anyhow!("Invalid/Empty dpdk args in {}", config_file)),
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
