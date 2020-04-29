extern crate crossbeam_channel;
extern crate pcap;

use std::path::PathBuf;

use crossbeam_channel::{unbounded, Receiver, Sender};

use super::capture::{Capture, Libpcap};
use super::config;
use super::error::Error;
use super::packet::{Packet, Parser};

/// 数据包处理线程
pub struct PktThread {
    /// 线程ID
    id: u8,
    /// 收包总数
    pub rx_count: u64,
    // 基本协议解析器
    parser: Parser,
    sender: Box<Sender<Packet>>,
    receiver: Box<Receiver<Packet>>,
}

impl PktThread {
    /// 创建一个新的收包线程结构体
    pub fn new(
        id: u8,
        link_type: u16,
        sender: Box<Sender<Packet>>,
        receiver: Box<Receiver<Packet>>,
    ) -> PktThread {
        PktThread {
            id,
            rx_count: 0,
            parser: Parser::new(link_type),
            sender,
            receiver,
        }
    }
}

impl PktThread {
    pub fn spawn(&mut self, cfg: Box<config::Config>) -> Result<(), Error> {
        let mut files = Vec::new();
        if !cfg.pcap_file.is_empty() {
            println!("pcap file: {}", cfg.pcap_file);
            files.push(cfg.pcap_file.clone());
        } else if !cfg.pcap_dir.is_empty() {
            println!("pcap dir: {}", cfg.pcap_dir);
        }

        for file in files {
            let result = Libpcap::from_file(&file);
            let mut cap;
            match result {
                Err(e) => {
                    return Err(e);
                }
                Ok(c) => cap = c,
            }

            while let Ok(mut pkt) = cap.next() {
                match self.parser.parse_pkt(&mut pkt) {
                    Ok(_) => {}
                    Err(e) => {
                        println!("{:?}", e);
                    }
                };
                let result = self.sender.send(pkt);
                match result {
                    Ok(_) => {}
                    Err(_) => {} // TODO: handle error
                }
            }
        }
        Ok(())
    }
}
