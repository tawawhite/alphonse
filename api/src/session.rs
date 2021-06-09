use std::collections::HashSet;
use std::os::raw::c_long;

use anyhow::{anyhow, Result};
use serde::ser::SerializeStruct;
use serde::{Serialize, Serializer};
use serde_json::json;

use crate::packet;
use crate::utils::timeval::{precision, TimeVal};

#[allow(dead_code)]
fn packets_serialize<S>(packets: &[u32; 2], s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let mut state = s.serialize_struct("", 2)?;
    state.serialize_field("srcPackets", &packets[0])?;
    state.serialize_field("dstPackets", &packets[1])?;
    state.end()
}

#[allow(dead_code)]
fn bytes_serialize<S>(bytes: &[u64; 2], s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let mut state = s.serialize_struct("", 2)?;
    state.serialize_field("srcBytes", &bytes[0])?;
    state.serialize_field("dstBytes", &bytes[1])?;
    state.end()
}

#[allow(dead_code)]
fn data_bytes_serialize<S>(data_bytes: &[u64; 2], s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let mut state = s.serialize_struct("", 2)?;
    state.serialize_field("srcDataBytes", &data_bytes[0])?;
    state.serialize_field("dstDataBytes", &data_bytes[1])?;
    state.end()
}

#[derive(Clone, Copy, Debug)]
pub enum ProtocolLayer {
    All,
    Datalink,
    Network,
    Transport,
    Application,
    Tunnel,
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

    /// Store which direction is src to dst
    #[serde(skip_serializing)]
    pub src_direction: packet::Direction,

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

    /// Session next save time, used for long connection with few packets
    #[serde(skip_serializing)]
    pub save_time: u64,

    /// indicate nothing to parse here
    #[serde(skip_serializing)]
    pub parse_finished: bool,
    /// custom fields
    #[serde(flatten)]
    pub fields: Box<serde_json::Value>,

    /// Tags
    #[serde(skip_serializing_if = "HashSet::is_empty")]
    tags: Box<HashSet<String>>,

    /// Tunnel Protocols
    #[serde(skip_serializing_if = "packet::Tunnel::is_empty")]
    tunnels: packet::Tunnel,
}

impl Session {
    pub fn new() -> Session {
        let mut ses = Session::default();
        ses.fields = Box::new(json!({}));
        ses
    }

    #[inline]
    /// update session information
    pub fn update(&mut self, pkt: &dyn packet::Packet) {
        if pkt.direction() == self.src_direction {
            self.pkt_count[0] += 1;
            self.bytes[0] += pkt.caplen() as u64;
            self.data_bytes[0] += pkt.data_len() as u64;
        } else {
            self.pkt_count[1] += 1;
            self.bytes[1] += pkt.caplen() as u64;
            self.data_bytes[1] += pkt.data_len() as u64;
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

    /// Add tag
    #[inline]
    pub fn add_tag<S: AsRef<str>>(&mut self, tag: &S) {
        self.tags.insert(tag.as_ref().to_string());
    }

    /// Add field
    #[inline]
    pub fn add_field<S: AsRef<str>>(&mut self, key: &S, value: &serde_json::Value) {
        match self.fields.as_mut() {
            serde_json::Value::Object(obj) => match obj.get(key.as_ref()) {
                None => obj.insert(key.as_ref().to_string(), value.clone()),
                Some(_) => todo!(),
            },
            _ => todo!("need to guarantee fields is an object in Session initialization"),
        };
    }

    pub fn add_protocol<S: AsRef<str>>(
        &mut self,
        protocol: &S,
        layer: ProtocolLayer,
    ) -> Result<()> {
        let layer = match layer {
            ProtocolLayer::All => "protocol",
            ProtocolLayer::Datalink => "protocols.datalink",
            ProtocolLayer::Network => "protocols.network",
            ProtocolLayer::Transport => "protocols.transport",
            ProtocolLayer::Application => "protocols.app",
            ProtocolLayer::Tunnel => "protocols.tunnel",
        };
        match self.fields.as_mut() {
            serde_json::Value::Object(obj) => match obj.get_mut(layer) {
                Some(protocols) => {
                    let protocols = protocols
                        .as_array_mut()
                        .ok_or(anyhow!("{} is not an json array", layer))?;
                    match protocols.iter().find(|p| match p.as_str() {
                        Some(p) => p == protocol.as_ref(),
                        None => false,
                    }) {
                        Some(_) => {}
                        None => protocols.push(json!(protocol.as_ref())),
                    };
                }
                None => {
                    obj.insert(layer.to_string(), json!(vec![json!(protocol.as_ref())]));
                }
            },
            _ => todo!("need to guarantee fields is an object in Session initialization"),
        };
        Ok(())
    }

    pub fn has_protocol<S: AsRef<str>>(
        &mut self,
        protocol: &S,
        layer: ProtocolLayer,
    ) -> Result<bool> {
        let layer = match layer {
            ProtocolLayer::All => "protocol",
            ProtocolLayer::Datalink => "protocols.datalink",
            ProtocolLayer::Network => "protocols.network",
            ProtocolLayer::Transport => "protocols.transport",
            ProtocolLayer::Application => "protocols.app",
            ProtocolLayer::Tunnel => "protocols.tunnel",
        };
        match self.fields.as_mut() {
            serde_json::Value::Object(obj) => match obj.get_mut(layer) {
                Some(protocols) => {
                    let protocols = protocols
                        .as_array_mut()
                        .ok_or(anyhow!("{} is not an json array", layer))?;
                    match protocols.iter().find(|p| match p.as_str() {
                        Some(p) => p == protocol.as_ref(),
                        None => false,
                    }) {
                        Some(_) => Ok(true),
                        None => Ok(false),
                    }
                }
                None => Ok(false),
            },
            _ => todo!("need to guarantee fields is an object in Session initialization"),
        }
    }

    /// Whether this session needs to do a middle save operation
    #[inline]
    pub fn need_mid_save(&self, max_packets: u32, tv_sec: u64) -> bool {
        if self.truncate(max_packets as u32) {
            return true;
        }

        if self.save_time < tv_sec {
            // If session connection active too long, need to save a middle result
            return true;
        }

        false
    }

    /// Whether should truncate this session into a smaller session
    #[inline]
    pub fn truncate(&self, max_packets: u32) -> bool {
        if self.pkt_count[0] + self.pkt_count[1] >= max_packets {
            true
        } else {
            false
        }
    }

    /// Reset mid saved session
    #[inline]
    pub fn mid_save_reset(&mut self, save_time: u64) {
        self.pkt_count = [0, 0];
        self.bytes = [0, 0];
        self.data_bytes = [0, 0];
        self.save_time = save_time;
        self.fields = Box::new(json!({}));
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn add_protocol() -> Result<()> {
        let mut ses = Session::new();
        ses.add_protocol(&"protocol", ProtocolLayer::All)?;
        assert_eq!(
            ses.has_protocol(&"protocol", ProtocolLayer::All).unwrap(),
            true
        );

        Ok(())
    }
}
