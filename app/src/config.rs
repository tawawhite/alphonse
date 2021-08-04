use std::fs::File;
use std::io::Read;
use std::path::Path;

use anyhow::{anyhow, Result};
use yaml_rust::YamlLoader;

use alphonse_api as api;
use api::config::Config;

use super::commands::CliArg;

/// Parse command line arguments and set configuration
pub fn parse_args(root_cmd: clap::App) -> Result<Config> {
    let mut config: Config = Default::default();
    let hn = hostname::get()?;
    let hn = hn
        .to_str()
        .ok_or(anyhow!("Hostname {:?} is not a valid UTF-8 string", hn))?;
    config.hostname = hn.to_string();

    let matches = root_cmd.get_matches();

    if let Some(config_file) = matches.value_of("config") {
        config.fpath = config_file.to_string();
        parse_config_file(config_file, &mut config)?;
    }

    set_config_by_cli_args(&mut config, &matches);

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
    config.doc = api::config::Yaml(doc.clone());

    config.pkt_channel_size =
        config.get_integer("channel.pkt.size", 1000000, 100000, 10000000) as u32;
    config.timeout_interval = config.get_integer("timeout.interval", 1, 1, 10) as u64;
    config.default_timeout = config.get_integer("timeout.default", 60, 10, 180) as u16;
    config.tcp_timeout = config.get_integer("timeout.tcp", 60, 10, 180) as u16;
    config.udp_timeout = config.get_integer("timeout.udp", 60, 10, 180) as u16;
    config.sctp_timeout = config.get_integer("timeout.sctp", 60, 10, 180) as u16;
    config.ses_save_timeout = config.get_integer("timeout.ses.save", 180, 60, 360) as u16;

    config.ses_max_packets =
        config.get_integer("ses.max.packets", 10000, 1000, u16::MAX as i64) as u16;

    config.pkt_threads = config.get_integer("threads.pkt", 1, 1, 24) as u8;

    config.rx_driver = config.get_str("plugins.rx-driver", "rxlibpcap");
    config.processors = config.get_str_arr("plugins.processors");

    // If there is a node in configuration file, use that, other wise use current machine's hostname
    config.node = config.get_str("node", config.hostname.as_str());

    config.rx_stat_log_interval =
        config.get_integer("rx.stats.log.interval", 10000, 10000, i64::MAX) as u64;

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
    config.delete = matches.is_present(CliArg::Delete.as_ref());
    config.dry_run = matches.is_present(CliArg::DryRun.as_ref());
    config.quiet = matches.is_present(CliArg::Quiet.as_ref());
    config.recursive = matches.is_present(CliArg::Recursive.as_ref());
    config.verbose_mode = matches.is_present(CliArg::Verbose.as_ref());

    if let Some(pcap_file) = matches.value_of(CliArg::PcapFile.as_ref()) {
        config.pcap_file = String::from(pcap_file);
    }

    if let Some(pcap_dir) = matches.value_of(CliArg::PcapDir.as_ref()) {
        config.pcap_dir = String::from(pcap_dir);
    }

    if let Some(tags) = matches.values_of(CliArg::Tags.as_ref()) {
        config.tags = tags.map(|x| String::from(x)).collect::<Vec<_>>();
    }

    if let Some(hostname) = matches.value_of(CliArg::Host.as_ref()) {
        config.hostname = String::from(hostname);
        config.node = config.hostname.clone();
    }

    if let Some(node) = matches.value_of(CliArg::Node.as_ref()) {
        config.node = String::from(node);
    }
}
