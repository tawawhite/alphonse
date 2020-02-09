use std::error::Error;
use std::marker::PhantomData;
use std::path::Path;

extern crate pcap;

use super::{error, packet};

pub trait Backend {}

pub struct Offline {}

impl Backend for Offline {}

pub struct Capture<B: Backend> {
    backend: PhantomData<B>,
    pcap_file: pcap::Capture<pcap::Offline>,
}

impl Capture<Offline> {
    pub fn from_pcap_file<P: AsRef<Path>>(path: &P) -> Result<Capture<Offline>, error::Error> {
        if !path.as_ref().exists() {
            // check pcap file's existence
            return Err(error::Error::CaptureError(String::from(format!(
                "{} does not exists!",
                path.as_ref().display()
            ))));
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
            backend: PhantomData,
            pcap_file,
        })
    }

    #[inline]
    pub fn next(&mut self) -> Result<packet::Packet, error::Error> {
        let result;
        match self.pcap_file.next() {
            Ok(raw_pkt) => result = Ok(packet::Packet::new(raw_pkt)),
            Err(e) => result = Err(error::Error::CaptureError(String::from(e.description()))),
        }
        result
    }
}
