#![allow(non_camel_case_types)]

use super::super::packet;
use super::{network, Error, LayerProto, NetworkProto};

mod ethernet;
mod null;

/// From https://www.tcpdump.org/linktypes.html
const NULL: u16 = 0;
const ETHERNET: u16 = 1;
const AX25: u16 = 3;
const IEEE802_5: u16 = 6;
const ARCNET_BSD: u16 = 7;
const SLIP: u16 = 8;
const PPP: u16 = 9;
const FDDI: u16 = 10;
const PPP_HDLC: u16 = 50;
const PPP_ETHER: u16 = 51;
const ATM_RFC1483: u16 = 100;
const RAW: u16 = 101;
const C_HDLC: u16 = 104;
const IEEE802_11: u16 = 105;
const FRELAY: u16 = 107;
const LOOP: u16 = 108;
const LINUX_SLL: u16 = 113;
const LTALK: u16 = 114;
const PFLOG: u16 = 117;
const IEEE802_11_PRISM: u16 = 119;
const IP_OVER_FC: u16 = 122;
const SUNATM: u16 = 123;
const IEEE802_11_RADIOTAP: u16 = 127;
const ARCNET_LINUX: u16 = 129;
const APPLE_IP_OVER_IEEE1394: u16 = 138;
const MTP2_WITH_PHDR: u16 = 139;
const MTP2: u16 = 140;
const MTP3: u16 = 141;
const SCCP: u16 = 142;
const DOCSIS: u16 = 143;
const LINUX_IRDA: u16 = 144;
const USER0: u16 = 147;
const USER1: u16 = 148;
const USER2: u16 = 149;
const USER3: u16 = 150;
const USER4: u16 = 151;
const USER5: u16 = 152;
const USER6: u16 = 153;
const USER7: u16 = 154;
const USER8: u16 = 155;
const USER9: u16 = 156;
const USER10: u16 = 157;
const USER11: u16 = 158;
const USER12: u16 = 159;
const USER13: u16 = 160;
const USER14: u16 = 161;
const USER15: u16 = 162;
const IEEE802_11_AVS: u16 = 163;
const BACNET_MS_TP: u16 = 165;
const PPP_PPPD: u16 = 166;
const GPRS_LLC: u16 = 169;
const GPF_T: u16 = 170;
const GPF_F: u16 = 171;
const LINUX_LAPD: u16 = 177;
const MFR: u16 = 182;
const BLUETOOTH_HCI_H4: u16 = 187;
const USB_LINUX: u16 = 189;
const PPI: u16 = 192;
const IEEE802_15_4_WITHFCS: u16 = 195;
const SITA: u16 = 196;
const ERF: u16 = 197;
const BLUETOOTH_HCI_H4_WITH_PHDR: u16 = 201;
const AX25_KISS: u16 = 202;
const LAPD: u16 = 203;
const PPP_WITH_DIR: u16 = 204;
const C_HDLC_WITH_DIR: u16 = 205;
const FRELAY_WITH_DIR: u16 = 206;
const LAPB_WITH_DIR: u16 = 207;
const IPMB_LINUX: u16 = 209;
const IEEE802_15_4_NONASK_PHY: u16 = 215;
const USB_LINUX_MMAPPED: u16 = 220;
const FC_2: u16 = 224;
const FC_2_WITH_FRAME_DELIMS: u16 = 225;
const IPNET: u16 = 226;
const CAN_SOCKETCAN: u16 = 227;
const IPV4: u16 = 228;
const IPV6: u16 = 229;
const IEEE802_15_4_NOFCS: u16 = 230;
const DBUS: u16 = 231;
const DVB_CI: u16 = 235;
const MUX27010: u16 = 236;
const STANAG_5066_D_PDU: u16 = 237;
const NFLOG: u16 = 239;
const NETANALYZER: u16 = 240;
const NETANALYZER_TRANSPARENT: u16 = 241;
const IPOIB: u16 = 242;
const MPEG_2_TS: u16 = 243;
const NG40: u16 = 244;
const NFC_LLCP: u16 = 245;
const INFINIBAND: u16 = 247;
const SCTP: u16 = 248;
const USBPCAP: u16 = 249;
const RTAC_SERIAL: u16 = 250;
const BLUETOOTH_LE_LL: u16 = 251;
const NETLINK: u16 = 253;
const BLUETOOTH_LINUX_MONITOR: u16 = 254;
const BLUETOOTH_BREDR_BB: u16 = 255;
const BLUETOOTH_LE_LL_WITH_PHDR: u16 = 256;
const PROFIBUS_DL: u16 = 257;
const PKTAP: u16 = 258;
const EPON: u16 = 259;
const IPMI_HPM_2: u16 = 260;
const ZWAVE_R1_R2: u16 = 261;
const ZWAVE_R3: u16 = 262;
const WATTSTOPPER_DLM: u16 = 263;
const ISO_14443: u16 = 264;
const RDS: u16 = 265;
const USB_DARWIN: u16 = 266;
const SDLC: u16 = 268;
const LORATAP: u16 = 270;
const VSOCK: u16 = 271;
const NORDIC_BLE: u16 = 272;
const DOCSIS31_XRA31: u16 = 273;
const ETHERNET_MPACKET: u16 = 274;
const DISPLAYPORT_AUX: u16 = 275;
const LINUX_SLL2: u16 = 276;
const OPENVIZSLA: u16 = 278;
const EBHSCR: u16 = 279;
const VPP_DISPATCH: u16 = 280;
const DSA_TAG_BRCM: u16 = 281;
const DSA_TAG_BRCM_PREPEND: u16 = 282;
const IEEE802_15_4_TAP: u16 = 283;
const DSA_TAG_DSA: u16 = 284;
const DSA_TAG_EDSA: u16 = 285;
const ELEE: u16 = 286;
const Z_WAVE_SERIAL: u16 = 287;
const USB_2_0: u16 = 288;

pub struct Parser {
    link_type: u16,
}

impl Parser {
    /// Initialize a data-link layer parser for offline pcap file
    pub fn from_pcap_file(cap: &pcap::Capture<pcap::Offline>) -> Parser {
        Parser {
            link_type: cap.get_datalink().0 as u16,
        }
    }

    /// Initialize a data-link layer parser
    pub fn new(t: u16) -> Parser {
        Parser { link_type: t }
    }

    pub fn parse(&self, pkt: &mut packet::Packet) -> Result<NetworkProto, Error> {
        let clayer = pkt.last_layer_index;
        // save the original start position of current layer
        let org_layer_start_pos = pkt.layers[clayer as usize].start_pos;

        // 解析当前数据链路层的协议
        let result = match self.link_type {
            NULL => null::parse(pkt),
            ETHERNET => ethernet::parse(pkt),
            RAW | IPV4 => return Ok(NetworkProto::IPv4),
            _ => return Err(Error::UnsupportProtocol),
        };

        // 如果解析出下层为数据链路层协议，继续解析
        // 如果解析出下层为网络层协议, 返回协议类型
        // 如果解析过程出错，返回错误
        match result {
            Ok(t) => match t {
                LayerProto::DataLink(_) => self.parse(pkt),
                LayerProto::Network(nw) => {
                    // 设置网络层的开始位置
                    pkt.layers[(clayer + 1) as usize].start_pos =
                        pkt.layers[clayer as usize].start_pos;
                    // 将本层协议的开始位置恢复到初始位置
                    pkt.layers[clayer as usize].start_pos = org_layer_start_pos;
                    // 增加协议层数
                    pkt.last_layer_index = pkt.last_layer_index + 1;
                    Ok(nw)
                }
                _ => Err(Error::CorruptPacket),
            },
            Err(e) => Err(e),
        }
    }
}
