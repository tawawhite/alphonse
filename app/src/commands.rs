use std::convert::AsRef;

use clap::{App, Arg};

/// Avaliable command line arguments
#[derive(Debug, AsRefStr)]
pub enum CliArg {
    #[strum(serialize = "config")]
    Config,
    #[strum(serialize = "delete")]
    Delete,
    #[strum(serialize = "dryrun")]
    DryRun,
    #[strum(serialize = "host")]
    Host,
    #[strum(serialize = "node")]
    Node,
    #[strum(serialize = "pcap-dir")]
    PcapDir,
    #[strum(serialize = "pcap-file")]
    PcapFile,
    #[strum(serialize = "quiet")]
    Quiet,
    #[strum(serialize = "recursive")]
    Recursive,
    #[strum(serialize = "tags")]
    Tags,
    #[strum(serialize = "verbose")]
    Verbose,
}

/// Construct a new clap root command
pub fn new_root_command<'a>() -> clap::App<'a, 'static> {
    let root_cmd = App::new(crate_name!())
        .version(crate_version!())
        .author(crate_authors!())
        .args(&[
            Arg::with_name(CliArg::Config.as_ref())
                .short("c")
                .value_name("FILE")
                .help("Use a specific config file")
                .takes_value(true),
            Arg::with_name(CliArg::Delete.as_ref())
                .long("delete")
                .help("In offline mode delete files once processed"),
            Arg::with_name(CliArg::DryRun.as_ref())
                .long("dryrun")
                .help("In dry run mode, nothing would be written to databases or filesystem"),
            Arg::with_name(CliArg::Host.as_ref())
                .long("host")
                .value_name("HOST")
                .help("Override hostname")
                .takes_value(true),
            Arg::with_name(CliArg::Node.as_ref())
                .short("n")
                .long("node")
                .value_name("NODE")
                .help(
                    "alphonse node name, defaults to hostname. Multiple nodes can run on same host",
                )
                .takes_value(true),
            Arg::with_name(CliArg::PcapDir.as_ref())
                .short("R")
                .value_name("PCAP-DIR")
                .help("Offline pcap directory, all *.pcap files will be processed")
                .takes_value(true)
                .conflicts_with(CliArg::PcapFile.as_ref()),
            Arg::with_name(CliArg::PcapFile.as_ref())
                .short("r")
                .value_name("PCAP-FILE")
                .help("Offline pcap file")
                .takes_value(true)
                .conflicts_with(CliArg::PcapDir.as_ref()),
            Arg::with_name(CliArg::Quiet.as_ref())
                .short("q")
                .long("quiet")
                .help("Turn off info level logging"),
            Arg::with_name(CliArg::Recursive.as_ref())
                .long("recursive")
                .help("In offline pcap directory mode, recurse sub directories"),
            Arg::with_name(CliArg::Tags.as_ref())
                .short("t")
                .long("tags")
                .help("Extra tags to add to all packets")
                .takes_value(true)
                .multiple(true),
            Arg::with_name(CliArg::Verbose.as_ref())
                .short("v")
                .long("verbose")
                .help("Turn on all debugging"),
        ]);

    return root_cmd;
}
