#[macro_use]
extern crate clap;

mod capture;
mod commands;
mod config;
mod dpdk;
mod error;
mod packet;
mod protocols;

fn main() {
    let root_cmd = commands::new_root_command();

    let config = config::parse_args(root_cmd);

    let parser_result = protocols::Parser::from_pcap_file(&config.pcap_file);
    let mut parser;
    match parser_result {
        Err(e) => {
            println!("{:?}", e);
            return;
        }
        Ok(p) => parser = p,
    }

    let cap_result = capture::Capture::from_pcap_file(&config.pcap_file);
    let mut cap;
    match cap_result {
        Err(e) => {
            println!("{:?}", e);
            return;
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

    println!("Hello, world!");
}
