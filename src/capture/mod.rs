use std::path::Path;

extern crate pcap;

use super::{error, packet};

pub trait Backend {}

pub struct Offline {
    pcap_file: pcap::Capture<pcap::Offline>,
}

impl Backend for Offline {}

pub struct Capture<B: Backend> {
    backend: B,
}

impl Capture<Offline> {
    pub fn from_pcap_file<P: AsRef<Path>>(path: &P) -> Result<Capture<Offline>, error::Error> {
        if !path.as_ref().exists() {
            // check pcap file's existence
            return Err(error::Error::IoError(std::io::Error::from(
                std::io::ErrorKind::NotFound,
            )));
        }

        let result = pcap::Capture::from_file(path);
        let pcap_file;
        match result {
            Err(e) => {
                eprintln!("{}", e);
                std::process::exit(-1);
            }
            Ok(v) => pcap_file = v,
        }

        Ok(Capture {
            backend: Offline { pcap_file },
        })
    }

    #[inline]
    pub fn next(&mut self) -> Result<packet::Packet, error::Error> {
        let result;
        match self.backend.pcap_file.next() {
            Ok(raw_pkt) => result = Ok(packet::Packet::new(raw_pkt)),
            Err(e) => result = Err(error::Error::CaptureError(e)),
        }
        result
    }
}
