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
    /// Maxium single pcap file size
    pub max_file_size: usize,
    /// All avaliable pcap write directoreis
    pub pcap_dirs: Vec<PathBuf>,
    /// Current using pcap file directory
    pcap_dir: PathBuf,
    /// Pcap directory selecting algorithm
    dir_algorithm: PcapDirAlgorithm,
    /// Current pcap file information
    file_info: PcapFileInfo,
}

unsafe impl Send for Scheduler {}
unsafe impl Sync for Scheduler {}

impl Scheduler {
    pub fn new(id: u8, node: String, sender: Sender<Box<PacketInfo>>) -> Self {
        let mut file_info = PcapFileInfo::default();
        file_info.node = node;
        Self {
            id,
            mode: Mode::Normal,
            sender,
            max_file_size: 1,
            pcap_dirs: vec![],
            pcap_dir: PathBuf::from(""),
            dir_algorithm: PcapDirAlgorithm::RoundRobin,
            file_info,
        }
    }

    /// Generate packet write information of a packet
    pub fn gen(&mut self, pkt: &dyn Packet) -> (Box<PacketInfo>, (u32, usize)) {
        let closing = self.file_info.filesize >= self.max_file_size;
        let info = if closing || self.file_info.name.as_os_str().is_empty() {
            // if current pcap file is gonna close, send a new name to the pcap writer
            let mut fid = FILE_ID.load(Ordering::Relaxed);
            let last_file_size = if !self.file_info.name.as_os_str().is_empty() {
                // Since the ES query is executed on another thread, it's a 'lazy' operation
                // and is merely a mechanism to inform the elasticsearch to update the
                // file sequence, so add scheduler's file id to prevent overwrite the first
                // pcap file
                fid += 1;
                self.file_info.filesize
            } else {
                std::mem::size_of::<PcapFileHeader>()
            };

            self.file_info.num = fid;
            self.file_info.name = match self.mode {
                Mode::Normal => {
                    let fpath = self.gen_fname(pkt.ts().tv_sec as u64);
                    // absolutize always return OK(_)
                    let fpath = fpath.absolutize().unwrap();
                    PathBuf::from(fpath.as_ref())
                }
                Mode::XOR2048 => unimplemented!(),
                Mode::AES256CTR => unimplemented!(),
            };
            self.file_info.first = pkt.ts().tv_sec as u64;
            self.file_info.last = pkt.ts().tv_sec as u64;
            self.file_info.filesize = std::mem::size_of::<PcapFileHeader>();
            self.file_info.locked = true;
            Some((self.file_info.clone(), last_file_size))
        } else {
            None
        };
        let fid = self.file_info.num;
        let pos = self.file_info.filesize;

        self.file_info.filesize += std::mem::size_of::<PacketHeader>();
        self.file_info.filesize += pkt.raw().len();
        self.file_info.last = pkt.ts().tv_sec as u64;

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

        (
            Box::new(PacketInfo {
                thread: self.id,
                closing,
                buf,
                file_info: info,
            }),
            (fid, pos),
        )
    }

    /// Send packet info to info channel
    pub fn send(&self, info: Box<PacketInfo>) -> Result<()> {
        Ok(self.sender.try_send(info)?)
    }

    /// Generate file name to write packets
    fn gen_fname(&mut self, ts: u64) -> PathBuf {
        match self.dir_algorithm {
            PcapDirAlgorithm::MaxFreeBytes => {
                let mut max_free_space_bytes = 0;
                for dir in &self.pcap_dirs {
                    // TODO: We may need a windows platform implementation in the future
                    let stat = nix::sys::statvfs::statvfs(dir.as_path()).unwrap();
                    if (stat.blocks_available() * stat.blocks_free()) >= max_free_space_bytes {
                        max_free_space_bytes = stat.blocks_available() * stat.blocks_free();
                        self.pcap_dir = dir.clone();
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
                        self.pcap_dir = dir.clone();
                    }
                }
            }
            PcapDirAlgorithm::RoundRobin => {
                for (i, dir) in self.pcap_dirs.iter().enumerate() {
                    if &self.pcap_dir == dir {
                        match self.pcap_dirs.get(i + 1) {
                            Some(dir) => self.pcap_dir = dir.clone(),
                            None => self.pcap_dir = self.pcap_dirs[0].clone(),
                        };
                        break;
                    }
                }
                // ! Panic if pcap_dirs is empty, in real application this is very unlikely to happen
                self.pcap_dir = self.pcap_dirs[0].clone();
            }
        };

        let datetime = chrono::Local.timestamp(ts as i64, 0);
        let fname = format!(
            "{}-{:2}{:0>2}{:0>2}-{:0>8}.pcap",
            self.file_info.node,
            datetime.year() % 100,
            datetime.month(),
            datetime.day(),
            self.file_info.num
        );
        self.pcap_dir.join(fname.as_str())
    }
}

#[cfg(test)]
mod test {
    use std::mem::size_of;

    use alphonse_api::packet::Packet as Pkt;
    use api::packet::test::Packet;

    use super::*;

    #[test]
    fn gen_fname() {
        let (sender, _) = crossbeam_channel::bounded(1);
        let mut scheduler = Scheduler::new(0, "node".to_string(), sender);
        scheduler.pcap_dirs = vec![PathBuf::from("/test-dir")];
        scheduler.pcap_dir = PathBuf::from("/test-dir");
        scheduler.file_info.num = 1;
        scheduler.file_info.node = "node".to_string();

        let fname = scheduler.gen_fname(0);
        assert_eq!(fname, PathBuf::from("/test-dir/node-700101-00000001.pcap"));

        scheduler.pcap_dirs = vec![PathBuf::from("/abc")];
        scheduler.pcap_dir = PathBuf::from("/abc");
        scheduler.file_info.node = "node1".to_string();
        scheduler.file_info.num = 2;
        let fname = scheduler.gen_fname(1615295648);
        assert_eq!(fname, PathBuf::from("/abc/node1-210309-00000002.pcap"));
    }

    #[test]
    fn gen_pkt_info() -> Result<()> {
        let (sender, _) = crossbeam_channel::bounded(1);
        let mut scheduler = Scheduler::new(0, "node".to_string(), sender);
        scheduler.max_file_size = 60;
        scheduler.pcap_dirs = vec![PathBuf::from("/test-dir")];

        // scheduler received first packet
        let mut pkt1 = Packet::default();
        pkt1.raw = Box::new(vec![0, 1, 2, 3, 4, 5]);
        pkt1.ts.tv_sec = 12345;
        let (fileinfo, (fid, pos)) = scheduler.gen(&pkt1);

        let info = &scheduler.file_info;
        assert_eq!(scheduler.file_info.num, 0);
        assert_eq!(
            scheduler.file_info.filesize,
            size_of::<PcapFileHeader>() + size_of::<PacketHeader>() + pkt1.raw().len()
        );
        assert_eq!(info.first, pkt1.ts.tv_sec as u64);
        assert_eq!(info.last, pkt1.ts.tv_sec as u64);
        assert_eq!(info.locked, true);
        assert_eq!(info.node, "node");
        drop(info);

        assert_eq!(fileinfo.closing, false);
        assert_eq!(fileinfo.file_info.is_some(), true);
        let (info, size) = fileinfo.file_info.unwrap();
        assert_eq!(size, size_of::<PcapFileHeader>());
        assert_eq!(info.num, 0);
        assert_eq!(info.filesize, size_of::<PcapFileHeader>());
        assert_eq!(info.first, pkt1.ts.tv_sec as u64);
        assert_eq!(info.last, pkt1.ts.tv_sec as u64);
        assert_eq!(info.locked, true);
        assert_eq!(info.node, "node");

        assert_eq!(fid, 0);
        assert_eq!(pos, size_of::<PcapFileHeader>());

        // scheduler received second packet
        let mut pkt2 = Packet::default();
        pkt2.raw = Box::new(vec![6, 7, 8, 9, 0]);
        pkt2.ts.tv_sec = 12346;
        let (fileinfo, (fid, pos)) = scheduler.gen(&pkt2);

        let info = &scheduler.file_info;
        assert_eq!(scheduler.file_info.num, 0);
        assert_eq!(
            scheduler.file_info.filesize,
            size_of::<PcapFileHeader>()
                + size_of::<PacketHeader>() * 2
                + pkt1.raw.len()
                + pkt2.raw().len()
        );
        assert_eq!(info.first, pkt1.ts.tv_sec as u64);
        assert_eq!(info.last, pkt2.ts.tv_sec as u64);
        assert_eq!(info.locked, true);
        assert_eq!(info.node, "node");
        drop(info);

        assert_eq!(fileinfo.closing, false);
        assert_eq!(fileinfo.file_info.is_none(), true);

        assert_eq!(fid, 0);
        assert_eq!(
            pos,
            size_of::<PcapFileHeader>() + size_of::<PacketHeader>() + pkt1.raw().len()
        );

        // scheduler received third packet, this time should be writing pkt into a new file
        let mut pkt3 = Packet::default();
        pkt3.raw = Box::new(vec![6, 7, 8, 9, 0]);
        pkt3.ts.tv_sec = 12347;
        let (fileinfo, (fid, pos)) = scheduler.gen(&pkt3);

        let info = &scheduler.file_info;
        assert_eq!(scheduler.file_info.num, 1);
        assert_eq!(
            scheduler.file_info.filesize,
            size_of::<PcapFileHeader>() + size_of::<PacketHeader>() + pkt3.raw().len()
        );
        assert_eq!(info.first, pkt3.ts.tv_sec as u64);
        assert_eq!(info.last, pkt3.ts.tv_sec as u64);
        assert_eq!(info.locked, true);
        assert_eq!(info.node, "node");
        drop(info);

        assert_eq!(fileinfo.closing, true);
        assert_eq!(fileinfo.file_info.is_some(), true);
        let (info, size) = fileinfo.file_info.unwrap();
        assert_eq!(
            size,
            size_of::<PcapFileHeader>()
                + size_of::<PacketHeader>() * 2
                + pkt1.raw().len()
                + pkt2.raw().len()
        );
        assert_eq!(info.num, 1);
        assert_eq!(info.filesize, size_of::<PcapFileHeader>());
        assert_eq!(info.first, pkt3.ts.tv_sec as u64);
        assert_eq!(info.last, pkt3.ts.tv_sec as u64);
        assert_eq!(info.locked, true);
        assert_eq!(info.node, "node");

        assert_eq!(fid, 1);
        assert_eq!(pos, size_of::<PcapFileHeader>());

        Ok(())
    }
}
