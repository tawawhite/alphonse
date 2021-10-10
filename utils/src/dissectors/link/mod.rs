#![allow(non_camel_case_types)]

pub mod arp;
pub mod ethernet;
pub mod frame_relay;
pub mod null;

#[repr(u16)]
#[derive(Debug, Primitive)]
pub enum LinkType {
    NULL = 0,
    ETHERNET = 1,
    RAW = 101,
    FRAME_RELAY = 107,
    IPV4 = 228,
    IPV6 = 229,
}

impl Default for LinkType {
    fn default() -> Self {
        Self::ETHERNET
    }
}

/// From https://www.tcpdump.org/linktypes.html
pub const NULL: u16 = 0;
pub const ETHERNET: u16 = 1;
// pub const AX25: u16 = 3;
// pub const IEEE802_5: u16 = 6;
// pub const ARCNET_BSD: u16 = 7;
// pub const SLIP: u16 = 8;
// pub const PPP: u16 = 9;
// pub const FDDI: u16 = 10;
// pub const PPP_HDLC: u16 = 50;
// pub const PPP_ETHER: u16 = 51;
// pub const ATM_RFC1483: u16 = 100;
pub const RAW: u16 = 101;
// pub const C_HDLC: u16 = 104;
// pub const IEEE802_11: u16 = 105;
// pub const FRELAY: u16 = 107;
// pub const LOOP: u16 = 108;
// pub const LINUX_SLL: u16 = 113;
// pub const LTALK: u16 = 114;
// pub const PFLOG: u16 = 117;
// pub const IEEE802_11_PRISM: u16 = 119;
// pub const IP_OVER_FC: u16 = 122;
// pub const SUNATM: u16 = 123;
// pub const IEEE802_11_RADIOTAP: u16 = 127;
// pub const ARCNET_LINUX: u16 = 129;
// pub const APPLE_IP_OVER_IEEE1394: u16 = 138;
// pub const MTP2_WITH_PHDR: u16 = 139;
// pub const MTP2: u16 = 140;
// pub const MTP3: u16 = 141;
// pub const SCCP: u16 = 142;
// pub const DOCSIS: u16 = 143;
// pub const LINUX_IRDA: u16 = 144;
// pub const USER0: u16 = 147;
// pub const USER1: u16 = 148;
// pub const USER2: u16 = 149;
// pub const USER3: u16 = 150;
// pub const USER4: u16 = 151;
// pub const USER5: u16 = 152;
// pub const USER6: u16 = 153;
// pub const USER7: u16 = 154;
// pub const USER8: u16 = 155;
// pub const USER9: u16 = 156;
// pub const USER10: u16 = 157;
// pub const USER11: u16 = 158;
// pub const USER12: u16 = 159;
// pub const USER13: u16 = 160;
// pub const USER14: u16 = 161;
// pub const USER15: u16 = 162;
// pub const IEEE802_11_AVS: u16 = 163;
// pub const BACNET_MS_TP: u16 = 165;
// pub const PPP_PPPD: u16 = 166;
// pub const GPRS_LLC: u16 = 169;
// pub const GPF_T: u16 = 170;
// pub const GPF_F: u16 = 171;
// pub const LINUX_LAPD: u16 = 177;
// pub const MFR: u16 = 182;
// pub const BLUETOOTH_HCI_H4: u16 = 187;
// pub const USB_LINUX: u16 = 189;
// pub const PPI: u16 = 192;
// pub const IEEE802_15_4_WITHFCS: u16 = 195;
// pub const SITA: u16 = 196;
// pub const ERF: u16 = 197;
// pub const BLUETOOTH_HCI_H4_WITH_PHDR: u16 = 201;
// pub const AX25_KISS: u16 = 202;
// pub const LAPD: u16 = 203;
// pub const PPP_WITH_DIR: u16 = 204;
// pub const C_HDLC_WITH_DIR: u16 = 205;
// pub const FRELAY_WITH_DIR: u16 = 206;
// pub const LAPB_WITH_DIR: u16 = 207;
// pub const IPMB_LINUX: u16 = 209;
// pub const IEEE802_15_4_NONASK_PHY: u16 = 215;
// pub const USB_LINUX_MMAPPED: u16 = 220;
// pub const FC_2: u16 = 224;
// pub const FC_2_WITH_FRAME_DELIMS: u16 = 225;
// pub const IPNET: u16 = 226;
// pub const CAN_SOCKETCAN: u16 = 227;
pub const IPV4: u16 = 228;
pub const IPV6: u16 = 229;
// pub const IEEE802_15_4_NOFCS: u16 = 230;
// pub const DBUS: u16 = 231;
// pub const DVB_CI: u16 = 235;
// pub const MUX27010: u16 = 236;
// pub const STANAG_5066_D_PDU: u16 = 237;
// pub const NFLOG: u16 = 239;
// pub const NETANALYZER: u16 = 240;
// pub const NETANALYZER_TRANSPARENT: u16 = 241;
// pub const IPOIB: u16 = 242;
// pub const MPEG_2_TS: u16 = 243;
// pub const NG40: u16 = 244;
// pub const NFC_LLCP: u16 = 245;
// pub const INFINIBAND: u16 = 247;
// pub const SCTP: u16 = 248;
// pub const USBPCAP: u16 = 249;
// pub const RTAC_SERIAL: u16 = 250;
// pub const BLUETOOTH_LE_LL: u16 = 251;
// pub const NETLINK: u16 = 253;
// pub const BLUETOOTH_LINUX_MONITOR: u16 = 254;
// pub const BLUETOOTH_BREDR_BB: u16 = 255;
// pub const BLUETOOTH_LE_LL_WITH_PHDR: u16 = 256;
// pub const PROFIBUS_DL: u16 = 257;
// pub const PKTAP: u16 = 258;
// pub const EPON: u16 = 259;
// pub const IPMI_HPM_2: u16 = 260;
// pub const ZWAVE_R1_R2: u16 = 261;
// pub const ZWAVE_R3: u16 = 262;
// pub const WATTSTOPPER_DLM: u16 = 263;
// pub const ISO_14443: u16 = 264;
// pub const RDS: u16 = 265;
// pub const USB_DARWIN: u16 = 266;
// pub const SDLC: u16 = 268;
// pub const LORATAP: u16 = 270;
// pub const VSOCK: u16 = 271;
// pub const NORDIC_BLE: u16 = 272;
// pub const DOCSIS31_XRA31: u16 = 273;
// pub const ETHERNET_MPACKET: u16 = 274;
// pub const DISPLAYPORT_AUX: u16 = 275;
// pub const LINUX_SLL2: u16 = 276;
// pub const OPENVIZSLA: u16 = 278;
// pub const EBHSCR: u16 = 279;
// pub const VPP_DISPATCH: u16 = 280;
// pub const DSA_TAG_BRCM: u16 = 281;
// pub const DSA_TAG_BRCM_PREPEND: u16 = 282;
// pub const IEEE802_15_4_TAP: u16 = 283;
// pub const DSA_TAG_DSA: u16 = 284;
// pub const DSA_TAG_EDSA: u16 = 285;
// pub const ELEE: u16 = 286;
// pub const Z_WAVE_SERIAL: u16 = 287;
// pub const USB_2_0: u16 = 288;
