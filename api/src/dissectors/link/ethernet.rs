use super::Error;
use super::{Layer, Protocol};

/// ETHER TYPES
///
/// From Wireshark's etypes.h
/// https://github.com/wireshark/wireshark/blob/master/epan/etypes.h

// const XNS_IDP: u16 = 0x0600;
pub const IPV4: u16 = 0x0800;
// const X25L3: u16 = 0x0805;
// const ARP: u16 = 0x0806;
// const WoL: u16 = 0x0842;
// const WMX_M2M: u16 = 0x08F0;
// const BPQ: u16 = 0x08FF;
// const VINES_IP: u16 = 0x0BAD;
// const VINES_ECHO: u16 = 0x0BAF;
// const TRAIN: u16 = 0x1984;
// const CGMP: u16 = 0x2001;
// const GIGAMON: u16 = 0x22E5;
// const MSRP: u16 = 0x22EA;
/// Audio Video Transport Protocol
// const AVTP: u16 = 0x22F0;
/// ROHC (Robust Header Compression) is an IP header compression protocol specified in
/// IETF RFC 3095 "RObust Header Compression (ROHC): Framework and four profiles: RTP;
/// UDP; ESP; and uncompressed". The specification is available at http://www.ietf.org/rfc/rfc3095.txt.
// const ROHC: u16 = 0x22F1;
// const TRILL: u16 = 0x22F3;
// const L2ISIS: u16 = 0x22F4;
// const CENTRINO_PROMISC: u16 = 0x2452;
// const EPL_V1: u16 = 0x3E3F;
// const DEC: u16 = 0x6000;
// const DNA_DL: u16 = 0x6001;
// const DNA_RC: u16 = 0x6002;
// const DNA_RT: u16 = 0x6003;
// const LAT: u16 = 0x6004;
// const DEC_DIAG: u16 = 0x6005;
// const DEC_CUST: u16 = 0x6006;
// const DEC_SCA: u16 = 0x6007;
// const ETHBRIDGE: u16 = 0x6558;
// const RAW_FR: u16 = 0x6559;
// const REVARP: u16 = 0x8035;
// const DEC_LB: u16 = 0x8038;
// const DEC_LAST: u16 = 0x8041;
// const AppleTalk: u16 = 0x809B;
// const SNA: u16 = 0x80D5;
// const DLR: u16 = 0x80E1;
// const AARP: u16 = 0x80F3;
pub const VLAN: u16 = 0x8100;
// const NSRP: u16 = 0x8133;
// const IPX: u16 = 0x8137;
// const SNMP: u16 = 0x814C;
// const WCP: u16 = 0x80FF;
// const STP: u16 = 0x8181;
// const ISMP: u16 = 0x81FD;
// const ISMP_TBFLOOD: u16 = 0x81FF;
// const QNX_QNET6: u16 = 0x8204;
pub const IPV6: u16 = 0x86DD;
// const WLCCP: u16 = 0x872D;
/// Flow Control Protocol
// const MAC_CONTROL: u16 = 0x8808;
/// Ethernet Slow Protocols[11] such as the Link Aggregation Control Protocol
// const SLOW_PROTOCOLS: u16 = 0x8809;
/// Point-to-Point Protocol (PPP)
pub const PPP: u16 = 0x880B;
// const CobraNet: u16 = 0x8819;
pub const MPLSUC: u16 = 0x8847;
// const MPLSmc: u16 = 0x8848;
/// Some Foundry proprietary protocol
// const FOUNDRY: u16 = 0x885A;
// const PPPoEd: u16 = 0x8863;
pub const PPPOES: u16 = 0x8864;
/// Intel Advanced Networking Services
// const INTEL_ANS: u16 = 0x886D;
/// MS Network Load Balancing heartbeat http://www.microsoft.com/technet/treeview/default.asp?url:u16=/TechNet/prodtechnol/windows2000serv/deploy/confeat/nlbovw.asp
// const MS_NLB_HEARTBEAT: u16 = 0x886F;
/// 802.2 jumbo frames http://tools.ietf.org/html/draft-ietf-isis-ext-eth
// const JUMBO_LLC: u16 = 0x8870;
// const HOMEPLUG: u16 = 0x887B;
/// the byte stream protocol that is used for IP based micro-mobility bearer interfaces (A10)
/// in CDMA2000(R)-based wireless networks
// const CDMA2000_A10_UBS: u16 = 0x8881;
// const ATMOE: u16 = 0x8884;
/// 802.1x Authentication
// const EAPOL: u16 = 0x888E;
// const PROFINET: u16 = 0x8892;
// const HYPERSCSI: u16 = 0x889A;
/// Mindspeed Technologies www.mindspeed.com
// const CSM_ENCAPS: u16 = 0x889B;
/// Telkonet powerline ethernet
// const TELKONET: u16 = 0x88A1;
// const AoE: u16 = 0x88A2;
/// Ethernet type for EtherCAT frames
// const ECATF: u16 = 0x88A4;
/// IEEE 802.1ad Provider Bridge; Q-in-Q
// const IEEE_802_1AD: u16 = 0x88A8;
/// Ethernet Powerlink
///
/// communication profile for Real-Time Ethernet
// const EPL_V2: u16 = 0x88AB;
/// XiMeta Technology Americas Inc. proprietary communication protocol
// const XIMETA: u16 = 0x88AD;
// const BRDWALK: u16 = 0x88AE;
/// Instant Wireless Network Communications; Co. Ltd.
///
/// WAI is a new authentication protocol that
/// will be used to access authentication in
/// IP based networks. This protocol establishes
/// a logic channel between a station and access
/// equipment by using an EtherType Field to
/// accomplish authentication
// const WAI: u16 = 0x88B4;
/// IEEE 802a OUI Extended Ethertype
// const IEEE802_OUI_EXTENDED: u16 = 0x88B7;
/// Generic Object Oriented Substation event
// const IEC61850_GOOSE: u16 = 0x88B8;
/// GSE (Generic Substation Events) Management Services
// const IEC61850_GSE: u16 = 0x88B9;
// const IEC61850_SV: u16 = 0x88BA;
/// Transparent Inter Process Communication
// const TIPC: u16 = 0x88CA;
// const RSN_PREAUTH: u16 = 0x88C7;
/// Link Layer Discovery Protocol
// const LLDP: u16 = 0x88CC;
/// SERCOS interface real-time protocol for motion control
// const SERCOS: u16 = 0x88CD;
pub const _3GPP2: u16 = 0x88D2;
// const CESOETH: u16 = 0x88D8;
/// Link Layer Topology Discovery
// const LLTD: u16 = 0x88D9;
/// Wireless Access in a Vehicle Environment
/// (WAVE) Short Message Protocol (WSM) as defined in IEEE P1609.3
// const WSMP: u16 = 0x88DC;
/// VMware LabManager (used to be Akimbi Systems)
// const VMLAB: u16 = 0x88DE;
/// HomePlug AV MME
// const HOMEPLUG_AV: u16 = 0x88E1;
/// IEC 61158-6-10 Media Redundancy Protocol (MRP)
// const MRP: u16 = 0x88E3;
/// IEEE 802.1ae Media access control security (MACSEC)
// const MACSEC: u16 = 0x88E5;
/// IEEE 802.1ah Provider Backbone Bridge Mac-in-Mac
// const IEEE_802_1AH: u16 = 0x88E7;
/// Ethernet Local Management Interface (E-LMI) (MEF16)
// const ELMI: u16 = 0x88EE;
/// IEEE 802.1ak Multiple VLAN Registration Protocol
// const MVRP: u16 = 0x88F5;
/// IEEE 802.1ak Multiple MAC Registration Protocol
// const MMRP: u16 = 0x88F6;
/// Precision Time Protocol (PTP) over Ethernet (IEEE 1588)
// const PTPoE: u16 = 0x88F7;
/// DMTF NC-SI: Network Controller Sideband Interface
// const NCSI: u16 = 0x88F8;
/// Parallel Redundancy Protocol (IEC62439 Part 3)
// const PRP: u16 = 0x88FB;
/// Nokia Siemens Networks Flow Layer Internal Protocol
// const FLIP: u16 = 0x8901;
/// IEEE 802.1ag Connectivity Fault Management (CFM) Protocol / ITU-T Recommendation Y.1731 (OAM)
// const CFM: u16 = 0x8902;
/// Cisco Systems Inc DCE
// const DCE: u16 = 0x8903;
/// Fibre Channel over Ethernet
// const FCoE: u16 = 0x8906;
/// Cisco Systems Inc - Cisco MetaData
// const CMD: u16 = 0x8909;
/// IEEE 802.11 data encapsulation
// const IEEE80211_DATA_ENCAP: u16 = 0x890d;
/// ENEA LINX IPC protocol over Ethernet
// const LINX: u16 = 0x8911;
/// FCoE Initialization Protocol
// const FCoEIP: u16 = 0x8914;
/// Media Independent Handover Protocol
// const MIH: u16 = 0x8917;
/// TTEthernet Protocol Control Frame
// const TTE_PCF: u16 = 0x891D;
/// Ethernet Configuration Testing Protocol
// const ECTP: u16 = 0x9000;
/// RTnet: Real-Time Media Access Control
// const RTMAC: u16 = 0x9021;
/// RTnet: Real-Time Configuration Protocol
// const RTCFG: u16 = 0x9022;
/// Veritas Technologies Low Latency Transport (LLT)
// const LLT: u16 = 0xCAFE;
/// Digium TDMoE packets (not officially registered)
// const TDMOE: u16 = 0xD00D;
/// used to transport FC frames+MDS hdr internal to Cisco's MDS switch
// const FCFT: u16 = 0xFCFC;
/// Infiniband RDMA over Converged Ethernet
// const ROCE: u16 = 0x8915;

#[derive(Primitive)]
#[repr(u16)]
pub enum EtherType {
    IPV4 = 0x0800,
    VLAN = 0x8100,
    IPV6 = 0x86DD,
    PPP = 0x880B,
    MPLSUC = 0x8847,
    PPPOES = 0x8864,
    ERSPAN = 0x88Be,
    _3GPP2 = 0x88D2,
}

impl Into<Protocol> for EtherType {
    fn into(self) -> Protocol {
        match self {
            Self::IPV4 => Protocol::IPV4,
            Self::VLAN => Protocol::VLAN,
            Self::IPV6 => Protocol::IPV6,
            Self::PPP => Protocol::PPP,
            Self::MPLSUC => Protocol::MPLS,
            Self::PPPOES => Protocol::PPPOE,
            Self::ERSPAN => Protocol::ERSPAN,
            _ => Protocol::UNKNOWN,
        }
    }
}

#[derive(Default)]
pub struct Dissector {}

impl super::Dissector for Dissector {
    #[inline]
    fn dissect(&self, buf: &[u8], offset: u16) -> Result<Option<Layer>, Error> {
        if buf.len() < 14 {
            return Err(Error::CorruptPacket(format!(
                "The ethernet packet is corrupted, packet too short ({} bytes)",
                buf.len()
            )));
        }

        let mut layer = Layer {
            protocol: Protocol::default(),
            offset,
        };

        let etype = (buf[12] as u16) << 8 | buf[12 + 1] as u16;
        layer.offset = layer.offset + 6 + 6 + 2;
        match etype {
            IPV4 => layer.protocol = Protocol::IPV4,
            IPV6 => layer.protocol = Protocol::IPV6,
            PPP => layer.protocol = Protocol::PPP,
            MPLSUC => layer.protocol = Protocol::MPLS,
            PPPOES => layer.protocol = Protocol::PPPOE,
            VLAN => {
                layer.protocol = Protocol::VLAN;
                layer.offset = layer.offset + 6 + 6;
            }
            _ => {
                return Err(Error::UnsupportProtocol(format!(
                    "Unsupport protocol, ether type: {:x}",
                    etype
                )));
            }
        };

        Ok(Some(layer))
    }
}

#[cfg(test)]
mod tests {
    use crate::dissectors::Dissector as D;

    use super::*;

    #[test]
    fn ok() {
        let buf = [
            0x01, 0x80, 0xc2, 0x00, 0x00, 0x00, 0xcc, 0x04, 0x0d, 0x5c, 0xf0, 0x00, 0x08, 0x00,
        ];
        let dissector = Dissector::default();
        assert!(matches!(dissector.dissect(&buf, 0), Ok(_)));
    }

    #[test]
    fn pkt_too_short() {
        let buf = [
            0x01, 0x80, 0xc2, 0x00, 0x00, 0x00, 0xcc, 0x04, 0x0d, 0x5c, 0xf0, 0x00,
        ];
        let dissector = Dissector::default();
        let result = dissector.dissect(&buf, 0);
        assert!(matches!(result, Err(_)));
        assert!(matches!(result.unwrap_err(), Error::CorruptPacket(_)));
    }

    #[test]
    fn unsupport_protocol() {
        let buf = [
            0x01, 0x80, 0xc2, 0x00, 0x00, 0x00, 0xcc, 0x04, 0x0d, 0x5c, 0xf0, 0x00, 0x06, 0x00,
        ];
        let dissector = Dissector::default();
        let result = dissector.dissect(&buf, 0);
        assert!(matches!(result, Err(_)));
        assert!(matches!(result.unwrap_err(), Error::UnsupportProtocol(_)));
    }
}
