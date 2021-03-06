use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use elasticsearch::Elasticsearch;
use tokio::runtime::Handle;

use crate::arkime::index_file_info;
use crate::PacketInfo;

#[repr(C)]
#[derive(Debug)]
pub struct PcapFileHeader {
    magic: u32,
    version_major: u16,
    version_minor: u16,
    /// gmt to local correction
    thiszone: i32,
    /// accuracy of timestamps
    sigfigs: u32,
    /// max length saved portion of each pkt
    snaplen: u32,
    /// data link type (LINKTYPE_*)
    linktype: u32,
}

impl Default for PcapFileHeader {
    fn default() -> Self {
        Self {
            magic: 0xa1b2c3d4,
            version_major: 2,
            version_minor: 4,
            thiszone: 0,
            sigfigs: 0,
            snaplen: 0,
            linktype: 1,
        }
    }
}

/// Writing pcap file format
#[derive(Clone, Copy, Debug)]
pub enum Format {
    Pcap,
    Pcapng,
}

impl Default for Format {
    fn default() -> Self {
        Format::Pcap
    }
}

#[derive(Debug)]
enum WriteError {
    /// Disk is overloading
    Overload,
    /// Could not open file on disk
    FileOpenError,
    /// Could write packet to disk
    FileWriteError,
}

/// Pcap writer, write pacp to disk or remote filesystem or whatever
#[derive(Debug)]
pub struct SimpleWriter {
    enable_arkime: bool,
    es: Arc<Elasticsearch>,
    fname: PathBuf,
    /// Current opened pcap file handle
    file: Option<std::fs::File>,
    format: Format,
    pcap_file_header: PcapFileHeader,
}

impl Clone for SimpleWriter {
    fn clone(&self) -> Self {
        todo!("implement clone method for SimpleWriter")
    }
}

impl SimpleWriter {
    pub fn new(enable_arkime: bool, es: Arc<Elasticsearch>) -> Self {
        Self {
            enable_arkime,
            es,
            fname: PathBuf::default(),
            file: None,
            format: Format::default(),
            pcap_file_header: PcapFileHeader::default(),
        }
    }

    /// Wirte packet to disk
    pub fn write(&mut self, info: Box<PacketInfo>) -> Result<()> {
        let pkt = info.buf.as_slice();
        if info.closing || self.file.is_none() {
            // Open new pcap file for writing
            let info = match &info.file_info {
                Some((info, _)) => info,
                None => {
                    unreachable!("If a pcap file is about to close or no file is opened for writing, file info must not be a ID")
                }
            };
            let mut file = std::fs::File::create(&info.name)?;

            // Update file information in Elasticsearch
            if self.enable_arkime {
                let es = self.es.clone();
                let info = Box::new(info.clone());
                Handle::current().spawn(async {
                    match index_file_info(es, info).await {
                        Ok(_) => {}
                        Err(e) => {
                            eprintln!("{}", e);
                        }
                    }
                });
            }

            match self.format {
                Format::Pcap => {}
                Format::Pcapng => {
                    unimplemented!("pcapng format is not implemented yet")
                }
            };

            let hdr_len = std::mem::size_of::<PcapFileHeader>();
            let hdr = unsafe {
                let hdr = (&self.pcap_file_header) as *const PcapFileHeader as *const u8;
                std::slice::from_raw_parts(hdr, hdr_len)
            };
            file.write(hdr)?;

            self.fname = info.name.clone();
            self.file = Some(file);
        }

        let file = match &mut self.file {
            Some(f) => f,
            None => return Err(anyhow!("{:?}", WriteError::FileOpenError)),
        };

        match file.write(pkt) {
            Ok(_) => {}
            Err(e) => return Err(anyhow!("{}", e)),
        };

        Ok(())
    }
}
