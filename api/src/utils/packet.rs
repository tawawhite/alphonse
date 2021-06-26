use crate::classifiers::matched::Rule;
use crate::packet::{Layers, Packet as PacketTrait, Rules, Tunnel};

// Packet structure only for test use
#[derive(Clone)]
#[repr(C)]
pub struct Packet {
    /// timestamp
    pub ts: libc::timeval,
    /// capture length
    pub caplen: u32,
    /// raw packet data
    pub raw: Box<Vec<u8>>,
    /// protocol layers
    pub layers: Layers,
    /// Packet hash, improve hash performance
    pub hash: u64,
    pub rules: Rules,
    pub tunnel: Tunnel,
}

impl Default for Packet {
    fn default() -> Self {
        Packet {
            ts: libc::timeval {
                tv_sec: 0,
                tv_usec: 0,
            },
            caplen: 0,
            raw: Box::new(Vec::new()),
            layers: Layers::default(),
            hash: 0,
            rules: Rules::default(),
            tunnel: Tunnel::default(),
        }
    }
}

impl PacketTrait for Packet {
    fn raw(&self) -> &[u8] {
        self.raw.as_slice()
    }

    fn ts(&self) -> &libc::timeval {
        &self.ts
    }

    fn caplen(&self) -> u32 {
        self.caplen
    }

    fn layers(&self) -> &Layers {
        &self.layers
    }

    fn layers_mut(&mut self) -> &mut Layers {
        &mut self.layers
    }

    fn rules(&self) -> &[Rule] {
        self.rules.as_ref().as_slice()
    }

    fn rules_mut(&mut self) -> &mut Rules {
        &mut self.rules
    }

    fn tunnel(&self) -> Tunnel {
        self.tunnel
    }

    fn tunnel_mut(&mut self) -> &mut Tunnel {
        &mut self.tunnel
    }

    fn clone_box(&self) -> Box<dyn PacketTrait + '_> {
        Box::new(self.clone())
    }
}
