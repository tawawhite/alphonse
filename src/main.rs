#[macro_use]
extern crate clap;

mod capture;
mod commands;
mod config;
#[cfg(all(target_os = "linux", feature = "dpdk"))]
mod dpdk;
mod error;
mod packet;
mod protocols;

#[cfg(all(target_os = "linux", feature = "dpdk"))]
fn main() -> Result<(), error::Error> {
    let root_cmd = commands::new_root_command();

    let mut config = config::parse_args(root_cmd)?;

    match dpdk::eal_init(&mut config.dpdk_eal_args) {
        Err(e) => {
            dpdk::eal_cleanup();
            return Err(e);
        }
        Ok(_) => {}
    };

    let parser_result = protocols::Parser::from_pcap_file(&config.pcap_file);
    let mut parser;
    match parser_result {
        Err(e) => {
            dpdk::eal_cleanup();
            return Err(e);
        }
        Ok(p) => parser = p,
    }

    let cap_result = capture::Capture::from_pcap_file(&config.pcap_file);
    let mut cap;
    match cap_result {
        Err(e) => {
            dpdk::eal_cleanup();
            return Err(e);
        }
        Ok(c) => cap = c,
    }

    while let Ok(mut pkt) = cap.next() {
        let result = parser.parse_pkt(&mut pkt);
        match result {
            Ok(_) => {}
            Err(e) => println!("{:?}", e),
        }
    }

    dpdk::eal_cleanup();

    Ok(())
}

#[cfg(not(feature = "dpdk"))]
fn main() -> Result<(), error::Error> {
    let root_cmd = commands::new_root_command();
    let config = config::parse_args(root_cmd)?;

    let parser_result = protocols::Parser::from_pcap_file(&config.pcap_file);
    let mut parser;
    match parser_result {
        Err(e) => {
            return Err(e);
        }
        Ok(p) => parser = p,
    }

    let cap_result = capture::Capture::from_pcap_file(&config.pcap_file);
    let mut cap;
    match cap_result {
        Err(e) => {
            return Err(e);
        }
        Ok(c) => cap = c,
    }

    while let Ok(mut pkt) = cap.next() {
        let result = parser.parse_pkt(&mut pkt);
        match result {
            Ok(_) => {}
            Err(e) => println!("{:?}", e),
        }
    }

    Ok(())
}
