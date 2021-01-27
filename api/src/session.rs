use std::collections::HashSet;
use std::os::raw::c_long;

use serde::Serialize;

use super::packet;
use super::utils::timeval::{precision, TimeVal};

/// Network session
#[derive(Serialize)]
#[cfg_attr(feature = "arkime", serde(rename_all = "camelCase"))]
pub struct Session {
    #[serde(skip_serializing_if = "String::is_empty")]
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
    #[cfg_attr(feature = "arkime", serde(rename = "firstPacket"))]
    pub start_time: TimeVal<precision::Millisecond>,
    /// session end time
    #[cfg_attr(feature = "arkime", serde(rename = "lastPacket"))]
    pub end_time: TimeVal<precision::Millisecond>,
    /// indicate nothing to parse here
    #[serde(skip_serializing)]
    pub parse_finished: bool,
    /// custom fields
    #[serde(flatten)]
    pub fields: serde_json::Value,
    /// Tags
    tags: HashSet<Box<String>>,
    /// Protocols
    protocols: HashSet<Box<String>>,
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
            start_time: TimeVal::new(libc::timeval {
                tv_sec: 0,
                tv_usec: 0,
            }),
            end_time: TimeVal::new(libc::timeval {
                tv_sec: 0,
                tv_usec: 0,
            }),
            parse_finished: false,
            fields: serde_json::Value::default(),
            tags: HashSet::new(),
            protocols: HashSet::new(),
        }
    }

    #[inline]
    /// update session information
    pub fn update(&mut self, pkt: &Box<dyn packet::Packet>) {
        match pkt.direction() {
            packet::Direction::LEFT => {
                self.pkt_count[0] += 1;
                self.bytes[0] += pkt.caplen() as u64;
                self.data_bytes[0] += pkt.data_len() as u64;
            }
            packet::Direction::RIGHT => {
                self.pkt_count[1] += 1;
                self.bytes[1] += pkt.caplen() as u64;
                self.data_bytes[1] += pkt.data_len() as u64;
            }
        }
        self.end_time = TimeVal::new(*pkt.ts());
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
    #[inline]
    pub fn add_protocol(&mut self, protocol: Box<String>) {
        self.protocols.insert(protocol.clone());
    }

    /// Add tag
    #[inline]
    pub fn add_tag(&mut self, tag: Box<String>) {
        self.tags.insert(tag.clone());
    }
}
