use anyhow::{anyhow, Result};

use tokio::io::AsyncWriteExt;

use crate::{File, PacketInfo};

#[repr(C)]
#[derive(Debug)]
struct PcapFileHeader {
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
    /// Current opened pcap file handle
    file: Option<tokio::fs::File>,
    format: Format,
    pcap_file_header: PcapFileHeader,
}

impl Default for SimpleWriter {
    fn default() -> Self {
        Self {
            file: None,
            format: Format::default(),
            pcap_file_header: PcapFileHeader::default(),
        }
    }
}

impl Clone for SimpleWriter {
    fn clone(&self) -> Self {
        todo!("implement clone method for SimpleWriter")
    }
}

impl SimpleWriter {
    /// Wirte packet to disk
    pub async fn write(&mut self, pkt: &[u8], info: &PacketInfo) -> Result<()> {
        if info.closing || self.file.is_none() {
            // Open new pcap file for writing
            let fname = match &info.file_info {
                File::Name(name) => name,
                File::ID(_) => {
                    unreachable!("If a pcap file is about to close or no file is opened for writing, file info must not be a ID")
                }
            };
            let mut file = tokio::fs::File::create(fname).await?;

            match self.format {
                Format::Pcap => {}
                Format::Pcapng => {
                    unimplemented!("pcapng format is not implemented yet")
                }
            };

            let hdr_len = std::mem::size_of::<PcapFileHeader>();
            let hdr = (&self.pcap_file_header) as *const PcapFileHeader as *const u8;
            let hdr = unsafe { std::slice::from_raw_parts(hdr, hdr_len) };
            file.write(hdr).await?;
            self.file = Some(file);
        }

        let file = match &mut self.file {
            Some(f) => f,
            None => return Err(anyhow!("{:?}", WriteError::FileOpenError)),
        };

        match file.write(pkt).await {
            Ok(_) => {}
            Err(e) => return Err(anyhow!("{}", e)),
        };

        Ok(())
    }
}
