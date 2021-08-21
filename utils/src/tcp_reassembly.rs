use std::cmp::{max, min};
use std::collections::VecDeque;

use alphonse_api as api;
use api::packet::Packet;

#[repr(C)]
#[derive(Debug, Default)]
pub struct TcpHdr {
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
    pub struct TcpFlags: u8 {
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

    /// TCP options
    pub fn options(&self) -> &[u8] {
        if self.hdr_len() > 20 {
            let opts = self as *const _ as *const u8;
            let opts = unsafe { opts.add(20) };
            let opts = unsafe { std::slice::from_raw_parts(opts, self.hdr_len() as usize - 20) };
            opts
        } else {
            &[]
        }
    }

    pub fn from_pkt(pkt: &dyn Packet) -> &Self {
        let layer = pkt.layers().trans;
        let hdr = &pkt.raw()[layer.offset as usize..];
        unsafe { &(*(hdr.as_ptr() as *const TcpHdr)) }
    }

    pub fn next_seq(&self, payload_len: u32) -> u32 {
        let flags = self.flags();
        let flag_len = if flags.contains(TcpFlags::SYN) || flags.contains(TcpFlags::FIN) {
            1
        } else {
            0
        };
        self.seq + flag_len + payload_len
    }
}

pub fn parse_options(opts: &[u8]) {}

#[derive(Clone, Copy, Debug, Default, Eq)]
struct SeqInterval((u32, u32));

impl PartialEq for SeqInterval {
    fn eq(&self, other: &Self) -> bool {
        self.0 .0 == other.0 .0 && self.0 .1 == other.0 .1
    }
}

impl SeqInterval {
    /// Get a tcp packet's sequence interval, **it's the caller's responsibility to guarantee
    /// pkt is a TCP packet**
    fn from_pkt(pkt: &dyn Packet) -> Self {
        let hdr = TcpHdr::from_pkt(pkt);
        Self((hdr.seq, hdr.seq + pkt.payload().len() as u32))
    }

    /// Whether this interval overlaps another interval
    fn overlaps(&self, other: Self) -> bool {
        if self.eq(&other) {
            return true;
        }

        if self.0 .0 >= other.0 .0 && self.0 .0 <= other.0 .1 {
            return true;
        }

        if self.0 .1 >= other.0 .0 && self.0 .1 <= other.0 .1 {
            return true;
        }

        return false;
    }

    /// Whether this inverval overlays another interval
    fn overlays(&self, other: Self) -> bool {
        self.0 .0 <= other.0 .0 && self.0 .1 >= other.0 .1
    }

    /// Combine two intervals into a huger interval, **it is the caller's duty to guarantee
    /// tow intervals overlaps with each other**
    fn union(&self, other: Self) -> Self {
        Self((min(self.0 .0, other.0 .0), max(self.0 .1, other.0 .1)))
    }

    /// Combine two intervals into a huger interval, if two intervals does not overlaps with
    /// each other, returns None
    #[allow(dead_code)]
    fn union_strict(&self, other: Self) -> Option<Self> {
        if self.overlaps(other) {
            Some(Self((
                min(self.0 .0, other.0 .0),
                max(self.0 .1, other.0 .1),
            )))
        } else {
            None
        }
    }
}

/// Data struct to store each direction's packets and TCP seq info
#[derive(Clone, Debug, Default)]
pub struct TcpReorder {
    /// The lowest seq number of current TCP flow
    seq_min: u32,
    /// Highest seq number current TCP flow has delivered,
    /// pkt lower than this seq would be dropped directly
    seq_delivered: u32,
    /// Actual pkt buffer
    pkts: VecDeque<Box<dyn Packet>>,
    /// Continuative seq intervals
    seq_intervals: VecDeque<(SeqInterval, (usize, usize))>,
    /// Flow already get FIN or RST
    fin_or_rst: bool,
    /// Max pkts could hold
    capacity: usize,
}

impl TcpReorder {
    pub fn with_capacity(capacity: usize) -> Self {
        let mut buf = Self::default();
        buf.capacity = capacity;
        buf.seq_intervals = VecDeque::with_capacity(capacity);
        buf.seq_intervals.reserve_exact(capacity);
        buf
    }

    /// Get current seq number
    pub fn seq(&self) -> Option<u32> {
        if self.pkts.len() == 0 {
            None
        } else {
            Some(TcpHdr::from_pkt(self.pkts[self.pkts.len() - 1].as_ref()).seq)
        }
    }

    /// Whether this pkt buffer is full. If so, should call get_interval_pkts
    pub fn full(&self) -> bool {
        self.pkts.len() < self.capacity
    }

    /// Get pkts in the oldest interval
    pub fn get_interval_pkts(&mut self) -> Vec<Box<dyn Packet>> {
        let pkts = match self.seq_intervals.pop_front() {
            None => vec![],
            Some((_, indices)) => {
                let num = indices.1 - indices.0;
                let mut pkts = vec![];
                for _ in 0..num - 1 {
                    pkts.push(self.pkts.pop_front().unwrap())
                }
                pkts
            }
        };

        for (_, indices) in &mut self.seq_intervals {
            indices.0 = indices.0 - pkts.len();
            indices.1 = indices.1 - pkts.len();
        }

        pkts
    }

    /// Pop all pkts out of buffers
    pub fn get_all_pkts(&mut self) -> Vec<Box<dyn Packet>> {
        self.seq_intervals.clear();
        let pkts = VecDeque::with_capacity(self.capacity);
        let pkts = std::mem::replace(&mut self.pkts, pkts);
        pkts.into_iter().collect()
    }

    /// Insert given tcp packet into packet buffer. It is the caller's responsibility to guarantee
    /// `pkt` is a TCP packet
    pub fn insert_and_reorder(&mut self, pkt: Box<dyn Packet>) {
        let hdr = TcpHdr::from_pkt(pkt.as_ref());
        let flags = hdr.flags();
        let fin_rst_syn = flags.intersects(TcpFlags::FIN | TcpFlags::RST | TcpFlags::SYN);
        if pkt.payload().len() == 0 && !fin_rst_syn {
            // ignore ACK pkts or TCP pkts without payloads
            // If sender side is over don't do anything and return
            if flags.contains(TcpFlags::ACK) {
                return;
            }
        }

        if flags.contains(TcpFlags::SYN) {
            self.seq_min = hdr.seq;
            return;
        }

        self._insert_and_reorder(pkt);
    }

    fn _insert_and_reorder(&mut self, pkt: Box<dyn Packet>) {
        if pkt.payload().len() == 0 {
            return;
        }

        // TODO: support seq num wrap around
        let intv = SeqInterval::from_pkt(pkt.as_ref());
        if self.seq_intervals.is_empty() {
            // empty is a speical case, handle it separtely
            self.pkts.push_back(pkt);
            self.seq_intervals.push_back((intv, (0, 1)));
            return;
        }

        let len = self.seq_intervals.len();
        for i in 0..len {
            let i = len - i - 1;
            let (intv_i, indices_i) = &self.seq_intervals[i];
            if intv_i.eq(&intv) {
                // retransmission, skip this pkt
                return;
            }

            if intv_i.overlaps(intv) {
                let intv_new = intv_i.union(intv);
                if intv_i.overlays(intv) {
                    // if existing seq interval overlays incoming pkt, do nothing
                    return;
                }

                let mut indices_new = (0, 0);
                let mut need_merge = false;
                let mut indice_change_num: isize = 0;

                if intv.overlays(*intv_i) {
                    // incoming pkt overlays existing interval,
                    // replace whole interval and its pkts with the new pkt
                    let num = indices_i.1 - indices_i.0;
                    for _ in 0..num {
                        self.pkts.remove(indices_i.0);
                    }
                    self.pkts.insert(indices_i.0, pkt);
                    indices_new = (indices_i.0, indices_i.0 + 1);
                    need_merge = true;
                    indice_change_num = -(num as isize);
                } else if intv.0 .0 == intv_new.0 .0 {
                    // incoming pkt is older than exising interval, insert in front of it
                    self.pkts.insert(indices_i.0, pkt);
                    indices_new = (indices_i.0, indices_i.1 + 1);
                    need_merge = true;
                    indice_change_num = 1;
                } else if intv.0 .1 == intv_new.0 .1 {
                    // incoming pkt is newer than exising interval, insert behind of it
                    self.pkts.insert(indices_i.1, pkt);
                    indices_new = (indices_i.0, indices_i.1 + 1);
                    indice_change_num = 1;
                }

                self.seq_intervals[i] = (intv_new, indices_new);
                self.seq_intervals.make_contiguous();
                let indices = &mut self.seq_intervals.as_mut_slices().0[i + 1..]
                    .iter_mut()
                    .map(|(_, indices)| indices);

                for pair in indices {
                    if indice_change_num > 0 {
                        let num = indice_change_num as usize;
                        *pair = (pair.0 + num, pair.1 + num);
                    } else if indice_change_num < 0 {
                        let num = indice_change_num.abs() as usize;
                        *pair = (pair.0 - num, pair.1 - num);
                    }
                }

                if need_merge {
                    self.merge_intervals();
                }

                return;
            }

            if intv_i.0 .1 <= intv.0 .0 {
                // incoming pkt has the newest seq, push to pkts
                self.pkts.push_back(pkt);
                let indices = (self.pkts.len() - 1, self.pkts.len());
                self.seq_intervals.push_back((intv, indices));
                return;
            }

            // incoming pkt is an out of order pkt or a retransmit pkt, need to find proper insert position
            return;
        }
    }

    /// Internal function to merge existing intervals
    fn merge_intervals(&mut self) {
        self.seq_intervals.make_contiguous();

        let len = self.seq_intervals.len();
        let mut i = 0;
        while i < len {
            let (intv1, indices1) = &self.seq_intervals[i];
            let (intv2, indices2) = &self.seq_intervals[i + 1];
            if !intv1.overlaps(*intv2) {
                i = i + 1;
                continue;
            }

            let intv_new = intv1.union(*intv2);
            let indices_new = (indices1.0, indices2.1);

            self.seq_intervals.pop_front();

            self.seq_intervals[0].0 = intv_new;
            self.seq_intervals[0].1 = indices_new;

            break;
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use alphonse_api::packet::{Packet as Pkt, Protocol};
    use api::packet::test::Packet;

    // test only mutable reference
    impl TcpHdr {
        pub fn flags_mut(&mut self) -> &mut TcpFlags {
            unsafe { &mut (*(&mut self.hdr_len_flags as *mut _ as *mut TcpFlags)) }
        }

        pub fn from_pkt_mut(pkt: &mut dyn Pkt) -> &mut Self {
            unsafe { &mut (*(Self::from_pkt(pkt) as *const _ as *mut TcpHdr)) }
        }
    }

    #[test]
    fn tcp_hdr_size() {
        assert_eq!(std::mem::size_of::<TcpHdr>(), 20);
    }

    #[test]
    fn flags_mut() {
        let mut hdr = TcpHdr::default();
        hdr.hdr_len_flags = 0b00000010u16;
        assert!(hdr.flags_mut().contains(TcpFlags::SYN));

        hdr.flags_mut().insert(TcpFlags::PSH);
        assert!(hdr.flags_mut().contains(TcpFlags::PSH));
        assert!(hdr.flags().contains(TcpFlags::PSH));
    }

    #[test]
    fn insert_into_empty() {
        let mut tr = TcpReorder::default();

        let mut pkt = Box::new(Packet::default());
        pkt.raw = Box::new(vec![0; 24]);
        pkt.layers_mut().trans.protocol = Protocol::TCP;
        pkt.layers_mut().app.offset = 20;
        let intv1 = SeqInterval::from_pkt(pkt.as_ref());

        tr.insert_and_reorder(pkt);

        assert_eq!(tr.seq_intervals.len(), 1);
        assert_eq!(tr.seq_intervals[0].0, intv1);
        assert_eq!(tr.seq_intervals[0].1, (0, 1));
        assert_eq!(tr.pkts.len(), 1);
    }

    #[test]
    fn insert_retransmission_pkt() {
        let mut tr = TcpReorder::default();

        let mut pkt1 = Box::new(Packet::default());
        pkt1.raw = Box::new(vec![0; 24]);
        pkt1.layers_mut().trans.protocol = Protocol::TCP;
        pkt1.layers_mut().app.offset = 20;
        let intv1 = SeqInterval::from_pkt(pkt1.as_ref());

        let pkt2 = pkt1.clone();

        tr.insert_and_reorder(pkt1);
        tr.insert_and_reorder(pkt2);

        assert_eq!(tr.seq_intervals.len(), 1);
        assert_eq!(tr.seq_intervals[0].0, intv1);
        assert_eq!(tr.seq_intervals[0].1, (0, 1));
        assert_eq!(tr.pkts.len(), 1);
    }

    #[test]
    fn insert_continuative_seq_pkt() {
        let mut pktbuf = TcpReorder::default();

        let mut pkt1 = Box::new(Packet::default());
        pkt1.raw = Box::new(vec![0; 24]);
        pkt1.layers_mut().trans.protocol = Protocol::TCP;
        pkt1.layers_mut().app.offset = 20;
        let intv1 = SeqInterval::from_pkt(pkt1.as_ref());

        pktbuf.insert_and_reorder(pkt1);

        let mut pkt2 = Box::new(Packet::default());
        pkt2.raw = Box::new(vec![0; 24]);
        pkt2.layers_mut().trans.protocol = Protocol::TCP;
        pkt2.layers_mut().app.offset = 20;
        let hdr = TcpHdr::from_pkt_mut(pkt2.as_mut());
        hdr.seq = 4;
        let intv2 = SeqInterval::from_pkt(pkt2.as_ref());

        assert!(intv1.overlaps(intv2));

        pktbuf.insert_and_reorder(pkt2);

        assert_eq!(pktbuf.seq_intervals.len(), 1);
        assert_eq!(pktbuf.seq_intervals[0].0, intv1.union(intv2));
        assert_eq!(pktbuf.seq_intervals[0].1, (0, 2));
        assert_eq!(pktbuf.pkts.len(), 2);
    }

    #[test]
    fn insert_non_overlap_new_seq_pkt() {
        let mut tr = TcpReorder::default();

        let mut pkt1 = Box::new(Packet::default());
        pkt1.raw = Box::new(vec![0; 24]);
        pkt1.layers_mut().trans.protocol = Protocol::TCP;
        pkt1.layers_mut().app.offset = 20;
        let intv1 = SeqInterval::from_pkt(pkt1.as_ref());

        tr.insert_and_reorder(pkt1);

        let mut pkt2 = Box::new(Packet::default());
        pkt2.raw = Box::new(vec![0; 24]);
        pkt2.layers_mut().trans.protocol = Protocol::TCP;
        pkt2.layers_mut().app.offset = 20;
        let hdr = TcpHdr::from_pkt_mut(pkt2.as_mut());
        hdr.seq = 5;
        let intv2 = SeqInterval::from_pkt(pkt2.as_ref());

        assert!(!intv1.overlaps(intv2));

        tr.insert_and_reorder(pkt2);

        assert_eq!(tr.seq_intervals.len(), 2);
        assert_eq!(tr.seq_intervals[0].0, intv1);
        assert_eq!(tr.seq_intervals[0].1, (0, 1));
        assert_eq!(tr.seq_intervals[1].0, intv2);
        assert_eq!(tr.seq_intervals[1].1, (1, 2));
        assert_eq!(tr.pkts.len(), 2);
    }

    #[test]
    fn insert_overlap_retransmission_old_seq_pkt() {
        let mut tr = TcpReorder::default();

        let mut pkt = Box::new(Packet::default());
        pkt.raw = Box::new(vec![0; 24]);
        pkt.layers_mut().trans.protocol = Protocol::TCP;
        pkt.layers_mut().app.offset = 20;
        // (0, 4)
        let intv1 = SeqInterval::from_pkt(pkt.as_ref());

        tr.insert_and_reorder(pkt);

        let mut pkt = Box::new(Packet::default());
        pkt.raw = Box::new(vec![0; 24]);
        pkt.layers_mut().trans.protocol = Protocol::TCP;
        pkt.layers_mut().app.offset = 20;
        let hdr = TcpHdr::from_pkt_mut(pkt.as_mut());
        hdr.seq = 5;
        // (5, 9)
        let intv2 = SeqInterval::from_pkt(pkt.as_ref());

        tr.insert_and_reorder(pkt);

        let mut pkt = Box::new(Packet::default());
        pkt.raw = Box::new(vec![0; 24]);
        pkt.layers_mut().trans.protocol = Protocol::TCP;
        pkt.layers_mut().app.offset = 20;
        let hdr = TcpHdr::from_pkt_mut(pkt.as_mut());
        hdr.seq = 4;
        // (4, 8)
        let intv3 = SeqInterval::from_pkt(pkt.as_ref());

        tr.insert_and_reorder(pkt);

        assert_eq!(tr.seq_intervals.len(), 1);
        // (0, 9)
        assert_eq!(
            tr.seq_intervals[0].0,
            intv1
                .union_strict(intv3)
                .unwrap()
                .union_strict(intv2)
                .unwrap()
        );
        assert_eq!(tr.seq_intervals[0].1, (0, 3));
        assert_eq!(tr.pkts.len(), 3);

        let hdr1 = TcpHdr::from_pkt(tr.pkts[0].as_ref());
        let hdr2 = TcpHdr::from_pkt(tr.pkts[1].as_ref());
        let hdr3 = TcpHdr::from_pkt(tr.pkts[2].as_ref());
        assert!(hdr1.seq < hdr2.seq);
        assert!(hdr2.seq < hdr3.seq);
    }

    #[test]
    fn insert_overlap_retransmission_new_seq_pkt() {
        let mut tr = TcpReorder::default();

        let mut pkt = Box::new(Packet::default());
        pkt.raw = Box::new(vec![0; 24]);
        pkt.layers_mut().trans.protocol = Protocol::TCP;
        pkt.layers_mut().app.offset = 20;
        // (0, 4)
        let intv1 = SeqInterval::from_pkt(pkt.as_ref());

        tr.insert_and_reorder(pkt);

        let mut pkt = Box::new(Packet::default());
        pkt.raw = Box::new(vec![0; 24]);
        pkt.layers_mut().trans.protocol = Protocol::TCP;
        pkt.layers_mut().app.offset = 20;
        let hdr = TcpHdr::from_pkt_mut(pkt.as_mut());
        hdr.seq = 5;
        // (5, 9)
        let intv2 = SeqInterval::from_pkt(pkt.as_ref());

        tr.insert_and_reorder(pkt);

        let mut pkt = Box::new(Packet::default());
        pkt.raw = Box::new(vec![0; 24]);
        pkt.layers_mut().trans.protocol = Protocol::TCP;
        pkt.layers_mut().app.offset = 20;
        let hdr = TcpHdr::from_pkt_mut(pkt.as_mut());
        hdr.seq = 7;
        // (7, 11)
        let intv3 = SeqInterval::from_pkt(pkt.as_ref());

        tr.insert_and_reorder(pkt);

        assert_eq!(tr.seq_intervals.len(), 2);
        // (0, 4)
        assert_eq!(tr.seq_intervals[0].0, intv1);
        assert_eq!(tr.seq_intervals[0].1, (0, 1));

        // (5, 11)
        assert_eq!(tr.seq_intervals[1].0, intv2.union(intv3));
        assert_eq!(tr.seq_intervals[1].1, (1, 3));
        assert_eq!(tr.pkts.len(), 3);

        let hdr1 = TcpHdr::from_pkt(tr.pkts[0].as_ref());
        let hdr2 = TcpHdr::from_pkt(tr.pkts[1].as_ref());
        let hdr3 = TcpHdr::from_pkt(tr.pkts[2].as_ref());
        assert!(hdr1.seq < hdr2.seq);
        assert!(hdr2.seq < hdr3.seq);
    }

    #[test]
    fn insert_overlay_retransmission_pkt() {
        let mut tr = TcpReorder::default();

        let mut pkt = Box::new(Packet::default());
        pkt.raw = Box::new(vec![0; 24]);
        pkt.layers_mut().trans.protocol = Protocol::TCP;
        pkt.layers_mut().app.offset = 20;
        // (0, 4)
        let intv1 = SeqInterval::from_pkt(pkt.as_ref());

        tr.insert_and_reorder(pkt);

        let mut pkt = Box::new(Packet::default());
        pkt.raw = Box::new(vec![0; 24]);
        pkt.layers_mut().trans.protocol = Protocol::TCP;
        pkt.layers_mut().app.offset = 20;
        let hdr = TcpHdr::from_pkt_mut(pkt.as_mut());
        hdr.seq = 5;
        // (5, 9)
        let intv2 = SeqInterval::from_pkt(pkt.as_ref());

        tr.insert_and_reorder(pkt);

        let mut pkt = Box::new(Packet::default());
        pkt.raw = Box::new(vec![0; 28]);
        pkt.layers_mut().trans.protocol = Protocol::TCP;
        pkt.layers_mut().app.offset = 20;
        let hdr = TcpHdr::from_pkt_mut(pkt.as_mut());
        hdr.seq = 3;
        // (3, 11)
        let intv3 = SeqInterval::from_pkt(pkt.as_ref());

        tr.insert_and_reorder(pkt);

        assert_eq!(tr.seq_intervals.len(), 1);
        assert_eq!(tr.seq_intervals[0].0, intv3.union(intv2).union(intv1));
        assert_eq!(tr.seq_intervals[0].1, (0, 2));

        assert_eq!(tr.pkts.len(), 2);

        let hdr1 = TcpHdr::from_pkt(tr.pkts[0].as_ref());
        let hdr2 = TcpHdr::from_pkt(tr.pkts[1].as_ref());
        assert!(hdr1.seq < hdr2.seq);
    }

    #[test]
    fn insert_and_reorder_syn() {
        let mut tcp_order = TcpReorder::default();

        let mut pkt = Box::new(Packet::default());
        pkt.raw = Box::new(vec![0; 24]);
        pkt.layers_mut().trans.protocol = Protocol::TCP;
        let hdr = TcpHdr::from_pkt_mut(pkt.as_mut());
        hdr.flags_mut().insert(TcpFlags::SYN);
        hdr.flags_mut().insert(TcpFlags::ACK);
        assert!(hdr.flags().contains(TcpFlags::SYN));
        assert!(hdr.flags().contains(TcpFlags::ACK));
        let dir = pkt.direction();

        tcp_order.insert_and_reorder(pkt);
    }

    #[test]
    fn insert_and_reorder_skip_ack() {
        let mut tcp_order = TcpReorder::default();

        let mut pkt = Box::new(Packet::default());
        pkt.raw = Box::new(vec![0; 24]);
        pkt.layers_mut().trans.protocol = Protocol::TCP;
        let hdr = TcpHdr::from_pkt_mut(pkt.as_mut());
        hdr.flags_mut().insert(TcpFlags::SYN);
        assert!(hdr.flags().contains(TcpFlags::SYN));

        tcp_order.insert_and_reorder(pkt);

        let mut pkt = Box::new(Packet::default());
        pkt.raw = Box::new(vec![0; 24]);
        pkt.layers_mut().trans.protocol = Protocol::TCP;
        let hdr = TcpHdr::from_pkt_mut(pkt.as_mut());
        hdr.flags_mut().insert(TcpFlags::ACK);
        assert!(hdr.flags().contains(TcpFlags::ACK));

        tcp_order.insert_and_reorder(pkt);

        assert_eq!(tcp_order.pkts.len(), 1);
    }
}
