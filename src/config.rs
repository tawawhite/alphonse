extern crate clap;
extern crate yaml_rust;

use crate::commands;

use std::fs::File;
use std::io::Read;
use std::path::Path;

use yaml_rust::YamlLoader;

use commands::CliArg;

#[derive(Default)]
pub struct Config {
    pub debug_mode: bool,
    pub delete: bool,
    pub dry_run: bool,
    pub pcap_file: String,
    pub pcap_dir: String,
    pub quiet: bool,
    pub recursive: bool,
    pub tags: Vec<String>,
}

/// Parse command line arguments and set configuration
pub fn parse_args(root_cmd: clap::App) -> Config {
    let mut config: Config = Default::default();
    let matches = root_cmd.get_matches();

    if let Some(config_file) = matches.value_of("config") {
        parse_config_file(config_file, &mut config);
    }

    set_config_by_cli_args(&mut config, &matches);

    config
}

fn parse_config_file(config_file: &str, _config: &mut Config) {
    let cfg_path = Path::new(config_file);
    if !cfg_path.exists() {
        eprintln!(
            "\"{}\" does not exist! Use default configuration file instead",
            config_file
        );
    }

    let mut f = File::open(cfg_path).unwrap();
    let mut s = String::new();
    f.read_to_string(&mut s).unwrap();

    let docs = YamlLoader::load_from_str(&s).unwrap();
    let doc = &docs[0];

    doc["some-key"].as_str().unwrap_or("value");
}

/// Use command arguments overrides config file settings
fn set_config_by_cli_args(config: &mut Config, matches: &clap::ArgMatches) {
    config.debug_mode = matches.is_present(CliArg::Debug.as_str());
    config.delete = matches.is_present(CliArg::Delete.as_str());
    config.dry_run = matches.is_present(CliArg::DryRun.as_str());
    config.quiet = matches.is_present(CliArg::Quiet.as_str());
    config.recursive = matches.is_present(CliArg::Recursive.as_str());

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
