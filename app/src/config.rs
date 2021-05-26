use std::fs::File;
use std::io::Read;
use std::path::Path;

use anyhow::{anyhow, Result};
use yaml_rust::YamlLoader;

use alphonse_api as api;
use api::config::Config;
use api::utils::yaml::{get_integer, get_str, get_str_arr};

use super::commands::CliArg;

/// Parse command line arguments and set configuration
pub fn parse_args(root_cmd: clap::App) -> Result<Config> {
    let mut config: Config = Default::default();
    let matches = root_cmd.get_matches();

    if let Some(config_file) = matches.value_of("config") {
        config.fpath = config_file.to_string();
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
    config.doc = api::utils::yaml::Yaml(doc.clone());

    config.pkt_channel_size =
        get_integer(doc, "channel.pkt.size", 1000000, 100000, 10000000) as u32;
    config.timeout_interval = get_integer(doc, "timeout.interval", 1, 1, 10) as u64;
    config.default_timeout = get_integer(doc, "timeout.default", 60, 10, 180) as u16;
    config.tcp_timeout = get_integer(doc, "timeout.tcp", 60, 10, 180) as u16;
    config.udp_timeout = get_integer(doc, "timeout.udp", 60, 10, 180) as u16;
    config.sctp_timeout = get_integer(doc, "timeout.sctp", 60, 10, 180) as u16;
    config.ses_save_timeout = get_integer(doc, "timeout.ses.save", 180, 60, 360) as u16;

    config.ses_max_packets =
        get_integer(doc, "ses.max.packets", 10000, 1000, u16::MAX as i64) as u16;

    config.pkt_threads = get_integer(doc, "threads.pkt", 1, 1, 24) as u8;
    config.rx_threads = get_integer(doc, "threads.rx", 1, 1, 24) as u8;
    config.ses_threads = get_integer(doc, "threads.session", 1, 1, 24) as u8;
    config.output_threads = get_integer(doc, "threads.output", 1, 1, 24) as u8;

    let backend = get_str(doc, "rx.backend", "libpcap");
    match backend.as_str() {
        "dpdk" | "libpcap" => {
            config.rx_backend = backend;
        }
        _ => {
            println!(
                "Invalid rx.backend option: {}, set rx.backend to {}",
                s, "libpcap"
            );
        }
    };

    config.processors = get_str_arr(doc, "processors");
    config.interfaces = get_str_arr(doc, "interfaces");

    config.rx_stat_log_interval =
        get_integer(doc, "rx.stats.log.interval", 10000, 10000, i64::MAX) as u64;

    #[cfg(all(target_os = "linux", feature = "dpdk"))]
    {
        // parse DPDK EAL intialize arguments
        let args = doc["dpdk.eal.args"]
            .as_vec()
            .ok_or(anyhow!("Invalid type/bad value for dpdk.eal.args"))?;
        for arg in args {
            let arg = arg
                .as_str()
                .ok_or(anyhow!("Failed to convert Yaml into &str"))?
                .to_string();
            config.dpdk_eal_args.push(arg);
        }
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
