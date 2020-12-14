use std::os::raw::c_long;

use super::packet;
use super::parsers;

/// network session
pub struct Session {
    pub id: String,
    /// Some session only contains one direction's packets
    /// Some protocols may work in that way
    /// but network problems could cause single direction
    pub single_direction: bool,
    /// session total packets
    pub pkt_count: [u32; 2],
    /// session total bytes
    pub bytes: [u64; 2],
    /// session total data bytes
    pub data_bytes: [u64; 2],
    /// session start time
    pub start_time: libc::timeval,
    /// session end time
    pub end_time: libc::timeval,
    /// indicate nothing to parse here
    pub parse_finished: bool,
    /// custom fields
    pub fields: serde_json::Value,
    /// protocol parsers, registered dynamically
    pub parsers: Vec<Box<dyn parsers::ProtocolParser>>,
}

impl Session {
    /// Create a new session
    pub fn new() -> Session {
        Session {
            id: String::new(),
            single_direction: false,
            pkt_count: [0; 2],
            bytes: [0; 2],
            data_bytes: [0; 2],
            start_time: libc::timeval {
                tv_sec: 0,
                tv_usec: 0,
            },
            end_time: libc::timeval {
                tv_sec: 0,
                tv_usec: 0,
            },
            parse_finished: false,
            fields: serde_json::Value::default(),
            parsers: Vec::with_capacity(1),
        }
    }

    #[inline]
    /// update session information
    pub fn update(&mut self, pkt: &Box<packet::Packet>) {
        match pkt.direction() {
            packet::Direction::LEFT => {
                self.pkt_count[0] += 1;
                self.bytes[0] += pkt.bytes() as u64;
                self.data_bytes[0] += pkt.data_bytes() as u64;
            }
            packet::Direction::RIGHT => {
                self.pkt_count[1] += 1;
                self.bytes[1] += pkt.bytes() as u64;
                self.data_bytes[1] += pkt.data_bytes() as u64;
            }
        }
        self.end_time = pkt.ts;
    }

    #[inline]
    /// whether this session is too long
    pub fn timeout(&self, timeout: c_long, timestamp: c_long) -> bool {
        if self.end_time.tv_sec + timeout < timestamp {
            true
        } else {
            false
        }
    }

    /// Add session protocol information
    pub fn add_protocol(&mut self, protocol: String) {
        match self.fields.get_mut("protocols") {
            Some(protocols) => match protocols.as_array_mut() {
                Some(ps) => ps.push(serde_json::value::Value::String(protocol)),
                None => todo!("decide how to handle non array type protocols field"),
            },
            None => {
                let protocols = vec![serde_json::value::Value::String(protocol)];
                self.fields["protocols"] = serde_json::Value::Array(protocols);
            }
        }
    }
}
