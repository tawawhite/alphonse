extern crate pcap;

use std::path::Path;

use super::super::packet;
use super::super::protocols;

pub fn process_pcap_file<P: AsRef<Path>>(path: &P) {
    if !path.as_ref().exists() {
        // check pcap file's existence
        eprintln!("{} does not exists!", path.as_ref().display());
        std::process::exit(-1);
    }

    let result = pcap::Capture::from_file(path);
    let mut pcap_file;
    match result {
        Err(e) => {
            eprintln!("{}", e);
            std::process::exit(-1);
        }
        Ok(v) => pcap_file = v,
    }

    let mut parser = protocols::Parser::from_pcap_file(&pcap_file);

    while let Ok(raw_packet) = pcap_file.next() {
        let mut pkt = packet::Packet::new(raw_packet);
        let result = parser.parse_pkt(&mut pkt);
        match result {
            Ok(_) => {}
            Err(e) => println!("{:?}", e),
        }
    }
}
