use std::fmt::{Display, Formatter};

extern crate pcap;
extern crate yaml_rust;

#[derive(Debug)]
pub enum ParserError {
    UnsupportProtocol(String),
    CorruptPacket(String),
    UnknownProtocol,
}

#[derive(Debug)]
pub enum Error {
    CaptureError(pcap::Error),
    CommonError(String),
    ConfigParseError(yaml_rust::ScanError),
    DpdkError(String),
    IoError(std::io::Error),
    ParserError(ParserError),
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match &self {
            Error::CommonError(ref e) => e.fmt(f),
            _ => self.fmt(f),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self {
            _ => None,
        }
    }
}

impl From<yaml_rust::ScanError> for Error {
    fn from(e: yaml_rust::ScanError) -> Self {
        Error::ConfigParseError(e)
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::IoError(e)
    }
}

impl From<ParserError> for Error {
    fn from(e: ParserError) -> Self {
        Error::ParserError(e)
    }
}
