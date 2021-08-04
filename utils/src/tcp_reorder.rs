use std::{cmp::Ordering, collections::VecDeque};

use alphonse_api as api;
use api::packet::{Packet, Protocol};

#[repr(C)]
struct TcpHdr {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub hdr_len_flags: u16,
    pub win: u16,
    pub sum: u16,
    pub urp: u16,
}

bitflags! {
    struct TcpFlags: u8 {
        const FIN = 0b00000001;
        const SYN = 0b00000010;
        const RST = 0b00000100;
        const PSH = 0b00001000;
        const ACK = 0b00010000;
        const URG = 0b00100000;
    }
}

impl TcpHdr {
    /// TCP header length
    pub fn hdr_len(&self) -> u8 {
        (self.hdr_len_flags >> 12) as u8
    }

    /// TCP flags
    pub fn flags(&self) -> TcpFlags {
        TcpFlags::from_bits_truncate(self.hdr_len_flags as u8)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct TcpReorder {
    /// Whether skip inserting TCP retransmission packets
    skip_retransmission: bool,
    /// Whether skip TCP packets only have ACK flag
    skip_ack_pkt: bool,
}

pub trait Container: Extend<Box<dyn Packet>> {}

impl TcpReorder {
    /// Insert given packet into packet buffer
    pub fn reorder_and_insert<T: Container>(&self, pkt: Box<dyn Packet>, pkts: &T) {
        let _a = Vec::<u8>::new();
        let mut _b = VecDeque::<u8>::new();
        _b.make_contiguous();
    }
}

/// Reorder packet by tcp sequence
///
/// # Arguments
///
/// * `pkts` - packets to be sorted
pub fn reorder_tcp_pkts(pkts: &mut [&dyn Packet]) {
    for pkt in pkts {
        match pkt.layers().trans.protocol {
            // If packets is not tcp protocol, don't order it
            Protocol::TCP => {}
            _ => return,
        }

        let tcp_data = pkt.layers().trans.data(*pkt);
        let tcp_hdr = unsafe { &*(tcp_data.as_ptr() as *const TcpHdr) };
        if tcp_hdr.flags() == TcpFlags::SYN {
            continue;
        }
    }
}

fn timeval_cmp(tv1: &libc::timeval, tv2: &libc::timeval) -> Ordering {
    if tv1.tv_sec != tv2.tv_sec {
        tv1.tv_usec.cmp(&tv2.tv_usec)
    } else {
        Ordering::Equal
    }
}

/// Compare two tcp packets
pub fn tcp_pkt_cmp(pkt1: &dyn Packet, pkt2: &dyn Packet) -> Ordering {
    let tcp_data = pkt1.layers().trans.data(pkt1);
    let tcp_hdr1 = unsafe { &*(tcp_data.as_ptr() as *const TcpHdr) };
    let tcp_data = pkt2.layers().trans.data(pkt2);
    let tcp_hdr2 = unsafe { &*(tcp_data.as_ptr() as *const TcpHdr) };

    if tcp_hdr1.flags() == TcpFlags::SYN || tcp_hdr2.flags() != TcpFlags::SYN {
        return Ordering::Greater;
    } else if tcp_hdr1.flags() != TcpFlags::SYN || tcp_hdr2.flags() == TcpFlags::SYN {
        return Ordering::Less;
    }

    timeval_cmp(pkt1.ts(), pkt2.ts())
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn tcp_hdr_size() {
        assert_eq!(std::mem::size_of::<TcpHdr>(), 20);
    }
}
