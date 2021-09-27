#![allow(non_camel_case_types)]

use anyhow::Result;
use serde::Serialize;
use serde_json::json;

use alphonse_api as api;
use alphonse_utils as utils;
use api::classifiers::{matched, ClassifierManager, Rule, RuleType};
use api::packet::{Direction, Packet, Protocol};
use api::plugins::processor::{Processor, ProcessorID};
use api::plugins::{Plugin, PluginType};
use api::session::{ProtocolLayer, Session};
use utils::tcp_reassembly::{TcpFlags, TcpHdr};

fn is_zero(x: &usize) -> bool {
    *x == 0
}

#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
struct TcpFlagsCnt {
    #[serde(skip_serializing_if = "is_zero")]
    ack: usize,
    #[serde(skip_serializing_if = "is_zero")]
    dst_zero: usize,
    #[serde(skip_serializing_if = "is_zero")]
    fin: usize,
    #[serde(skip_serializing_if = "is_zero")]
    psh: usize,
    #[serde(skip_serializing_if = "is_zero")]
    rst: usize,
    #[serde(skip_serializing_if = "is_zero")]
    src_zero: usize,
    #[serde(skip_serializing_if = "is_zero")]
    syn: usize,
    #[serde(rename = "syn-ack")]
    #[serde(skip_serializing_if = "is_zero")]
    syn_ack: usize,
    #[serde(skip_serializing_if = "is_zero")]
    urg: usize,
}

#[derive(Clone, Debug, Default)]
struct ProtocolParser {
    id: ProcessorID,
    name: String,
    classified: bool,
    src_dir: Direction,
    flags_cnt: TcpFlagsCnt,
    syn_time: u64,
    ack_time: u64,
    seq: [u32; 2],
}

impl Plugin for ProtocolParser {
    fn plugin_type(&self) -> PluginType {
        PluginType::PacketProcessor
    }

    fn name(&self) -> &str {
        &self.name.as_str()
    }
}

impl ProtocolParser {
    fn new() -> ProtocolParser {
        let mut parser = ProtocolParser::default();
        parser.name = String::from("tcp");
        parser
    }
}

impl Processor for ProtocolParser {
    fn clone_processor(&self) -> Box<dyn Processor> {
        Box::new(self.clone())
    }

    /// Get parser id
    fn id(&self) -> ProcessorID {
        self.id
    }

    /// Get parser id
    fn set_id(&mut self, id: ProcessorID) {
        self.id = id
    }

    fn register_classify_rules(&mut self, manager: &mut ClassifierManager) -> Result<()> {
        let mut rule = Rule::new(self.id);
        rule.rule_type = RuleType::Protocol(api::classifiers::protocol::Rule(Protocol::TCP));
        manager.add_rule(&mut rule)?;
        Ok(())
    }

    fn parse_pkt(
        &mut self,
        pkt: &dyn Packet,
        _rule: Option<&matched::Rule>,
        ses: &mut Session,
    ) -> Result<()> {
        if !self.classified {
            self.src_dir = pkt.direction();
            // If this session is already classified as this protocol, skip
            self.classified = true;
            ses.add_protocol(&self.name(), ProtocolLayer::Transport);
            unsafe {
                ses.add_field(&"srcPort", json!(pkt.src_port()));
                ses.add_field(&"dstPort", json!(pkt.dst_port()));
            }
            // println!("{}", serde_json::to_string(ses).unwrap());
        }

        let dir = pkt.direction() as usize;

        let hdr = TcpHdr::from_pkt(pkt);
        let flags = hdr.flags();

        if hdr.win == 0 && flags.contains(TcpFlags::RST) {
            self.flags_cnt.src_zero += 1;
        }

        // let len = (pkt.data_len() - pkt.layers().trans.offset) - 4 * (hdr.off_resv_ns >> 4) as u16;
        // if len < 0 {
        //     return Ok(());
        // }

        if flags.contains(TcpFlags::URG) {
            self.flags_cnt.urg += 1;
        }

        if flags.contains(TcpFlags::SYN) {
            if flags.contains(TcpFlags::ACK) {
                self.flags_cnt.syn_ack += 1;
            } else {
                self.flags_cnt.syn += 1;
                if self.syn_time == 0 {
                    self.syn_time = (pkt.ts().tv_sec - ses.start_time.tv_sec) as u64 * 1000000
                        + (pkt.ts().tv_usec - ses.start_time.tv_usec) as u64
                        + 1;
                }
                self.ack_time = 0;
            }
            return Ok(());
        }

        if flags.contains(TcpFlags::RST) {
            self.flags_cnt.rst += 1;
            let diff = seq_diff(hdr.seq, self.seq[dir]);
            if diff <= 0 {
                if diff == 0 {
                    // TODO: inform alphonse this session should be closed
                    return Ok(());
                }
            }
            // TODO: update tcp state
        }

        if flags.contains(TcpFlags::FIN) {
            self.flags_cnt.fin += 1;
        }

        if (flags & (TcpFlags::FIN | TcpFlags::RST | TcpFlags::PSH | TcpFlags::SYN | TcpFlags::ACK))
            .contains(TcpFlags::ACK)
        {
            self.flags_cnt.ack += 1;
            if self.ack_time == 0 {
                // self.ack_time = (pkt.ts().tv_sec - ses.start_time.tv_sec) as u64 * 1000000
                //     + (pkt.ts().tv_usec - ses.start_time.tv_usec) as u64
                //     + 1;
            }
        }

        if flags.contains(TcpFlags::PSH) {
            self.flags_cnt.psh += 1;
        }

        if self.flags_cnt.syn_ack == 0 && self.seq[dir] == 0 {
            ses.add_tag(&"no-syn-ack");
            self.seq[dir] = hdr.seq;
        }

        if flags.contains(TcpFlags::ACK) || flags.contains(TcpFlags::RST) {}

        Ok(())
    }

    fn mid_save(&mut self, ses: &mut Session) {
        self.classified = false;
        self.save(ses)
    }

    fn save(&mut self, ses: &mut Session) {
        ses.add_field(&"tcpflags", json!(self.flags_cnt));
        // println!("{}", serde_json::to_string_pretty(ses).unwrap());
    }
}

fn seq_diff(a: u32, b: u32) -> u32 {
    // if a > 0xc0000000 && b < 0x40000000 {
    //     return a.wrapping_add(0x100000000) - b;
    // }

    // if b > 0xc0000000 && a < 0x40000000 {
    //     return a - b.wrapping_sub(0x100000000);
    // }

    return b - a;
}

#[no_mangle]
pub extern "C" fn al_new_pkt_processor() -> Box<Box<dyn Processor>> {
    Box::new(Box::new(ProtocolParser::new()))
}

#[no_mangle]
pub extern "C" fn al_plugin_type() -> PluginType {
    PluginType::PacketProcessor
}
