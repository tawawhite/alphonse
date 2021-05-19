use std::cell::{Cell, RefCell};
use std::path::PathBuf;

use anyhow::Result;
use chrono::{Datelike, TimeZone};
use crossbeam_channel::Sender;

use alphonse_api as api;
use api::packet::Packet;

use crate::{writer::PacketHeader, File, Mode, PacketInfo, PcapDirAlgorithm};

#[derive(Clone, Debug)]
/// Packet writing schedular
pub struct Scheduler {
    id: u8,
    /// Current opened pcap file name
    fname: RefCell<PathBuf>,
    /// Current pcap file id
    fid: Cell<u32>,
    /// Pcap file size
    fsize: Cell<usize>,
    /// Writing mode
    mode: Mode,
    /// Write info sender
    sender: Sender<Box<PacketInfo>>,
    /// Packet wirte buffer size
    write_size: usize,
    /// Maxium single pcap file size
    pub max_file_size: usize,
    /// All avaliable pcap write directoreis
    pub pcap_dirs: Vec<PathBuf>,
    /// Current using pcap file directory
    pcap_dir: RefCell<PathBuf>,
    /// Pcap directory selecting algorithm
    dir_algorithm: PcapDirAlgorithm,
    /// Alphonse node name
    node: String,
}

unsafe impl Send for Scheduler {}
unsafe impl Sync for Scheduler {}

impl Scheduler {
    pub fn new(id: u8, sender: Sender<Box<PacketInfo>>) -> Self {
        Self {
            id,
            fname: RefCell::new(PathBuf::from("")),
            fid: Cell::new(0),
            fsize: Cell::new(0),
            mode: Mode::Normal,
            sender,
            write_size: 0,
            max_file_size: 1,
            pcap_dirs: vec![],
            pcap_dir: RefCell::new(PathBuf::from("")),
            dir_algorithm: PcapDirAlgorithm::RoundRobin,
            node: "node".to_string(),
        }
    }

    /// Generate packet write information of a packet
    pub fn gen(&self, pkt: &dyn Packet, fid: u32) -> Box<PacketInfo> {
        let mut fsize = self.fsize.get();
        fsize += std::mem::size_of::<PacketHeader>() + pkt.raw().len() as usize;
        self.fsize.set(fsize);

        let closing = self.fsize.get() >= self.max_file_size;
        let file_info;
        if closing || self.fname.borrow().to_string_lossy().is_empty() {
            // if current pcap file is gonna close, send a new name to the pcap writer
            self.fid.set(fid);
            let name = match self.mode {
                Mode::Normal => self.gen_fname(pkt.ts().tv_sec as u64, self.fid.get() as u64),
                Mode::XOR2048 => unimplemented!(),
                Mode::AES256CTR => unimplemented!(),
            };
            self.fname.replace(name.clone());
            file_info = File::Name(self.fname.borrow().clone());
            self.fsize.set(0);
        } else {
            file_info = File::ID(self.fid.get());
        };

        // construct a pcap packet from a raw packet
        // TODO: in the future we may need to support pcapng format
        let hdr_len = std::mem::size_of::<PacketHeader>();
        let buf_len = hdr_len + pkt.raw().len();
        let mut buf = vec![0; buf_len];

        let hdr = PacketHeader::from(pkt);
        let hdr = &hdr as *const PacketHeader as *const u8;
        let hdr = unsafe { std::slice::from_raw_parts(hdr, hdr_len) };
        buf[0..hdr_len].copy_from_slice(hdr);

        buf[hdr_len..].copy_from_slice(pkt.raw());

        Box::new(PacketInfo {
            thread: self.id,
            closing,
            buf,
            file_info,
        })
    }

    /// Send packet info to info channel
    pub fn send(&self, info: Box<PacketInfo>) -> Result<()> {
        Ok(self.sender.try_send(info)?)
    }

    /// Generate file name to write packets
    fn gen_fname(&self, ts: u64, id: u64) -> PathBuf {
        match self.dir_algorithm {
            PcapDirAlgorithm::MaxFreeBytes => {
                let mut max_free_space_bytes = 0;
                for dir in &self.pcap_dirs {
                    // TODO: We may need a windows platform implementation in the future
                    let stat = nix::sys::statvfs::statvfs(dir.as_path()).unwrap();
                    if (stat.blocks_available() * stat.blocks_free()) >= max_free_space_bytes {
                        max_free_space_bytes = stat.blocks_available() * stat.blocks_free();
                        self.pcap_dir.replace(dir.clone());
                    }
                }
            }
            PcapDirAlgorithm::MaxFreePercent => {
                let mut max_free_space_percent = 0.0;
                for dir in &self.pcap_dirs {
                    // TODO: We may need a windows platform implementation in the future
                    let stat = nix::sys::statvfs::statvfs(dir.as_path()).unwrap();
                    if (stat.blocks_available() / stat.blocks()) as f64 >= max_free_space_percent {
                        max_free_space_percent = (stat.blocks_available() / stat.blocks()) as f64;
                        self.pcap_dir.replace(dir.clone());
                    }
                }
            }
            PcapDirAlgorithm::RoundRobin => {
                for (i, dir) in self.pcap_dirs.iter().enumerate() {
                    let cmp = match self.pcap_dir.borrow().cmp(dir) {
                        std::cmp::Ordering::Equal => true,
                        _ => false,
                    };
                    if cmp {
                        match self.pcap_dirs.get(i + 1) {
                            Some(dir) => self.pcap_dir.replace(dir.clone()),
                            None => self.pcap_dir.replace(self.pcap_dirs[0].clone()),
                        };
                        break;
                    }
                }
                // ! Panic if pcap_dirs is empty, in real application this is very unlikely to happen
                self.pcap_dir.replace(self.pcap_dirs[0].clone());
            }
        };

        let datetime = chrono::Local.timestamp(ts as i64, 0);
        let fname = format!(
            "{}-{:2}{:0>2}{:0>2}-{:0>8}.pcap",
            self.node,
            datetime.year() % 100,
            datetime.month(),
            datetime.day(),
            id
        );
        self.pcap_dir.borrow().join(fname.as_str())
    }

    pub fn current_pos(&self) -> usize {
        self.fsize.get()
    }

    pub fn current_fid(&self) -> u32 {
        self.fid.get()
    }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use super::*;

    #[test]
    fn gen_fname() {
        let (sender, _) = crossbeam_channel::bounded(1);
        let mut scheduler = Scheduler::new(0, sender);

        scheduler.pcap_dirs = vec![PathBuf::from_str("/test-dir").unwrap()];
        scheduler.pcap_dir = RefCell::new(PathBuf::from_str("/test-dir").unwrap());
        scheduler.node = "node".to_string();
        let fname = scheduler.gen_fname(0, 1);
        assert_eq!(
            fname,
            PathBuf::from_str("/test-dir/node-700101-00000001.pcap").unwrap()
        );

        scheduler.pcap_dirs = vec![PathBuf::from_str("/abc").unwrap()];
        scheduler.pcap_dir = RefCell::new(PathBuf::from_str("/abc").unwrap());
        scheduler.node = "node1".to_string();
        let fname = scheduler.gen_fname(1615295648, 2);
        assert_eq!(
            fname,
            PathBuf::from_str("/abc/node1-210309-00000002.pcap").unwrap()
        );
    }
}
