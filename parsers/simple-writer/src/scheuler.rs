use std::cell::RefCell;
use std::path::PathBuf;
use std::sync::atomic::Ordering;

use anyhow::Result;
use chrono::{Datelike, TimeZone};
use crossbeam_channel::Sender;
use path_absolutize::Absolutize;

use alphonse_api as api;
use api::packet::Packet;

use crate::writer::PcapFileHeader;
use crate::{Mode, PacketInfo, PcapDirAlgorithm, PcapFileInfo, FILE_ID};

pub struct Timeval {
    _tv_sec: u32,
    _tv_usec: u32,
}

pub struct PacketHeader {
    _ts: Timeval,
    _cap_len: u32,
    _org_len: u32,
}

impl From<&dyn Packet> for PacketHeader {
    fn from(pkt: &dyn Packet) -> Self {
        Self {
            _ts: Timeval {
                _tv_sec: pkt.ts().tv_sec as u32,
                _tv_usec: pkt.ts().tv_usec as u32,
            },
            _cap_len: pkt.caplen(),
            _org_len: pkt.raw().len() as u32,
        }
    }
}

#[derive(Clone, Debug)]
/// Packet writing schedular
pub struct Scheduler {
    /// Scheduler ID
    id: u8,
    /// Writing mode
    mode: Mode,
    /// Write info sender
    sender: Sender<Box<PacketInfo>>,
    /// Packet write buffer size
    write_size: usize,
    /// Maxium single pcap file size
    pub max_file_size: usize,
    /// All avaliable pcap write directoreis
    pub pcap_dirs: Vec<PathBuf>,
    /// Current using pcap file directory
    pcap_dir: RefCell<PathBuf>,
    /// Pcap directory selecting algorithm
    dir_algorithm: PcapDirAlgorithm,
    /// Current pcap file information
    file_info: RefCell<PcapFileInfo>,
}

unsafe impl Send for Scheduler {}
unsafe impl Sync for Scheduler {}

impl Scheduler {
    pub fn new(id: u8, node: String, sender: Sender<Box<PacketInfo>>) -> Self {
        let mut file_info = PcapFileInfo::default();
        file_info.node = node;
        let file_info = RefCell::new(file_info);
        Self {
            id,
            mode: Mode::Normal,
            sender,
            write_size: 0,
            max_file_size: 1,
            pcap_dirs: vec![],
            pcap_dir: RefCell::new(PathBuf::from("")),
            dir_algorithm: PcapDirAlgorithm::RoundRobin,
            file_info,
        }
    }

    /// Generate packet write information of a packet
    pub fn gen(&self, pkt: &dyn Packet) -> Box<PacketInfo> {
        let mut file_info = self.file_info.borrow_mut();
        file_info.filesize += std::mem::size_of::<PacketHeader>();
        file_info.filesize += pkt.raw().len();

        let filesize = file_info.filesize;
        let closing = file_info.filesize >= self.max_file_size;
        let file_info = if closing || file_info.name.as_os_str().is_empty() {
            // if current pcap file is gonna close, send a new name to the pcap writer
            let mut fid = FILE_ID.load(Ordering::Relaxed);
            if !file_info.name.as_os_str().is_empty() {
                // Since the ES query is executed on another thread, it's a 'lazy' operation
                // and is merely a mechanism to inform the elasticsearch to update the
                // file sequence, so add scheduler's file id to prevent overwrite the first
                // pcap file
                fid += 1;
            }

            file_info.num = fid;
            file_info.name = match self.mode {
                Mode::Normal => {
                    let fpath = self.gen_fname(
                        pkt.ts().tv_sec as u64,
                        &file_info.node,
                        file_info.num as u64,
                    );
                    // absolutize always return OK(_)
                    let fpath = fpath.absolutize().unwrap();
                    PathBuf::from(fpath.as_ref())
                }
                Mode::XOR2048 => unimplemented!(),
                Mode::AES256CTR => unimplemented!(),
            };
            file_info.first = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            file_info.filesize = std::mem::size_of::<PcapFileHeader>();
            file_info.locked = true;
            Some((file_info.clone(), filesize))
        } else {
            None
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
    fn gen_fname(&self, ts: u64, node: &str, id: u64) -> PathBuf {
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
            node,
            datetime.year() % 100,
            datetime.month(),
            datetime.day(),
            id
        );
        self.pcap_dir.borrow().join(fname.as_str())
    }

    pub fn current_pos(&self) -> usize {
        self.file_info.borrow().filesize
    }

    pub fn current_fid(&self) -> u32 {
        self.file_info.borrow().num
    }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use super::*;

    #[test]
    fn gen_fname() {
        let (sender, _) = crossbeam_channel::bounded(1);
        let mut scheduler = Scheduler::new(0, "node".to_string(), sender);

        scheduler.pcap_dirs = vec![PathBuf::from_str("/test-dir").unwrap()];
        scheduler.pcap_dir = RefCell::new(PathBuf::from_str("/test-dir").unwrap());
        let fname = scheduler.gen_fname(0, "node", 1);
        assert_eq!(
            fname,
            PathBuf::from_str("/test-dir/node-700101-00000001.pcap").unwrap()
        );

        scheduler.pcap_dirs = vec![PathBuf::from_str("/abc").unwrap()];
        scheduler.pcap_dir = RefCell::new(PathBuf::from_str("/abc").unwrap());
        scheduler.file_info.borrow_mut().node = "node1".to_string();
        let fname = scheduler.gen_fname(1615295648, "node1", 2);
        assert_eq!(
            fname,
            PathBuf::from_str("/abc/node1-210309-00000002.pcap").unwrap()
        );
    }
}
