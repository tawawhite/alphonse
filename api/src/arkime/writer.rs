use std::io::Write;

use anyhow::Result;
use yaml_rust::Yaml;

use crate::packet::Packet;
use crate::session::Session;

#[derive(Debug, Default)]
pub struct Config {
    // Output pcap directory
    pub pcap_dir: Vec<String>,
    // Whether alphonse run in offline replay mode
    pub offline: bool,
    // Current alphonse node name
    pub node: String,
    // Original yaml config
    pub docs: Vec<Yaml>,
}

pub enum Error {
    /// Disk is overloading
    Overload,
}

pub trait File: Send + Write {
    fn id(&self) -> isize;
    fn id_mut(&mut self) -> &mut isize;
}

pub struct PacketWriteInfo {
    /// The actual packet to write to file
    pub pkt: Box<dyn Packet>,
    /// Actual File handle
    pub file: Box<dyn File>,
    /// File position
    pub fpos: usize,
    /// Buffer position
    pub buf_pos: usize,
    /// Whether current file is closing
    pub closing: bool,
}

pub trait PacketWriter: Send {
    /// Generate packet write information
    ///
    /// This function just generate packet write infomation, which is pretty cheap and fast,
    /// so it wouldn't effect packet thread's performance.
    fn gen_write_info(&mut self, pkt: Box<dyn Packet>, ses: &mut Session) -> Result<()>;

    /// Wirte packet to actual disk
    fn write(&mut self, _info: &PacketWriteInfo) -> Result<()> {
        Ok(())
    }
}
