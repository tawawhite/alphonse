use std::collections::HashSet;
use std::os::raw::c_long;

use serde::ser::SerializeStruct;
use serde::{Serialize, Serializer};

use super::packet;
use super::utils::timeval::{precision, TimeVal};

fn packets_serialize<S>(packets: &[u32; 2], s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let mut state = s.serialize_struct("", 2)?;
    state.serialize_field("srcPackets", &packets[0])?;
    state.serialize_field("dstPackets", &packets[0])?;
    state.end()
}

fn bytes_serialize<S>(bytes: &[u64; 2], s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let mut state = s.serialize_struct("", 2)?;
    state.serialize_field("srcBytes", &bytes[0])?;
    state.serialize_field("dstBytes", &bytes[0])?;
    state.end()
}

fn data_bytes_serialize<S>(data_bytes: &[u64; 2], s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let mut state = s.serialize_struct("", 2)?;
    state.serialize_field("srcDataBytes", &data_bytes[0])?;
    state.serialize_field("dstDataBytes", &data_bytes[0])?;
    state.end()
}

/// Network session
#[derive(Clone, Default, Serialize)]
#[cfg_attr(feature = "arkime", serde(rename_all = "camelCase"))]
pub struct Session {
    #[serde(skip_serializing_if = "String::is_empty")]
    pub id: Box<String>,
    /// Some session only contains one direction's packets
    /// Some protocols may work in that way
    /// but network problems could cause single direction
    pub single_direction: bool,
    /// session total packets
    #[cfg_attr(feature = "arkime", serde(flatten))]
    #[cfg_attr(feature = "arkime", serde(serialize_with = "packets_serialize"))]
    pub pkt_count: [u32; 2],
    /// session total bytes
    #[cfg_attr(feature = "arkime", serde(flatten))]
    #[cfg_attr(feature = "arkime", serde(serialize_with = "bytes_serialize"))]
    pub bytes: [u64; 2],
    /// session total data bytes
    #[cfg_attr(feature = "arkime", serde(flatten))]
    #[cfg_attr(feature = "arkime", serde(serialize_with = "data_bytes_serialize"))]
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
    pub fields: Box<serde_json::Value>,
    /// Tags
    tags: Box<HashSet<String>>,
    /// Protocols
    protocols: Box<HashSet<String>>,
    /// Tunnel Protocols
    tunnels: packet::Tunnel,
}

impl Session {
    /// Create a new session
    pub fn new() -> Session {
        Session {
            id: Box::new(String::new()),
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
            fields: Box::new(serde_json::Value::default()),
            tags: Box::new(HashSet::new()),
            protocols: Box::new(HashSet::new()),
            tunnels: packet::Tunnel::default(),
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
    pub fn add_protocol(&mut self, protocol: &String) {
        self.protocols.insert(protocol.clone());
    }

    /// Add tag
    #[inline]
    pub fn add_tag(&mut self, tag: &String) {
        self.tags.insert(tag.clone());
    }
}
