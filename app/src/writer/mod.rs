use std::io::Write;
use std::path::PathBuf;

use anyhow::Result;
use chrono::{Datelike, TimeZone};
use pcap::PacketHeader;

use alphonse_api as api;
use api::arkime::writer::{Config, PacketWriteInfo, PacketWriter};
use api::packet::Packet;
use api::session::Session;

pub enum Mode {
    Normal,
    XOR2048,
    AES256CTR,
}

pub enum PcapDirAlgorithm {
    MaxFreePercent,
    MaxFreeBytes,
    RoundRobin,
}

/// A simple writer write packet into host machine's hard disk
pub struct SimpleWriter {
    /// Thread specific packet write information
    info: PacketWriteInfo,
    file: std::fs::File,
    mode: Mode,
    cfg: Config,
}

impl PacketWriter for SimpleWriter {
    fn gen_write_info(&mut self, pkt: Box<dyn Packet>, ses: &mut Session) -> Result<()> {
        Ok(())
    }

    fn write(&mut self, info: &PacketWriteInfo) -> Result<()> {
        let pkt = info.pkt.as_ref();
        let name = match self.mode {
            Mode::Normal => gen_fname(&self.cfg, pkt.ts().tv_sec as u64, 0),
            Mode::XOR2048 => unimplemented!(),
            Mode::AES256CTR => unimplemented!(),
        };

        self.file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(name)?;

        // write packet header
        let hdr = PacketHeader {
            ts: pkt.ts().clone(),
            caplen: pkt.caplen(),
            len: pkt.data_len() as u32,
        };

        let hdr = &hdr as *const PacketHeader as *const u8;
        let hdr = unsafe { std::slice::from_raw_parts(hdr, std::mem::size_of::<PacketHeader>()) };
        match self.info.file.write(hdr) {
            Ok(n) => {
                self.info.fpos += n;
                self.info.buf_pos += n;
            }
            Err(_) => {
                todo!("handle file write error")
            }
        };

        // write packet content
        match self.info.file.write(pkt.raw()) {
            Ok(n) => {
                self.info.fpos += n;
                self.info.buf_pos += n;
            }
            Err(_) => {
                todo!("handle file write error")
            }
        };

        Ok(())
    }
}

/// Generate pcap file name
fn gen_fname(cfg: &Config, ts: u64, id: u64) -> PathBuf {
    let datetime = chrono::Local.timestamp(ts as i64, 0);
    let fpath = PathBuf::from(&cfg.pcap_dir[0]);
    let fname = format!(
        "{}-{:2}{:0>2}{:0>2}-{}.pcap",
        cfg.node,
        datetime.year() % 100,
        datetime.month(),
        datetime.day(),
        id
    );
    fpath.join(fname.as_str())
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use super::*;

    #[test]
    fn gen_fname() {
        let mut cfg = Config::default();
        cfg.pcap_dir = vec!["/test-dir".to_string()];
        cfg.node = "node".to_string();
        let fname = super::gen_fname(&cfg, 0, 1);
        assert_eq!(
            fname,
            PathBuf::from_str("/test-dir/node-700101-1.pcap").unwrap()
        );

        cfg.pcap_dir = vec!["/abc".to_string()];
        cfg.node = "node1".to_string();
        let fname = super::gen_fname(&cfg, 1615295648, 2);
        assert_eq!(
            fname,
            PathBuf::from_str("/abc/node1-210309-2.pcap").unwrap()
        );
    }
}
