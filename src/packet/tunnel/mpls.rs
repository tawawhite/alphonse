#[cfg(feature = "heuristic-mpls")]
use super::{link, network};
use super::{Error, Layer, Protocol, SimpleProtocolParser};

pub struct Parser;

impl SimpleProtocolParser for Parser {
    #[inline]
    fn parse(buf: &[u8], offset: u16) -> Result<Layer, Error> {
        if buf.len() < 4 {
            // 如果报文内容长度小于IP报文最短长度(IP协议头长度)
            // 数据包有错误
            return Err(Error::CorruptPacket(format!(
                "Corrupted MPLS packet, packet too short ({} bytes)",
                buf.len()
            )));
        }

        let mut pos: usize = 0;

        let mut mpls_stack_bottom = buf[2] & 0x1;
        while mpls_stack_bottom == 1 {
            pos += 4;
            if pos > buf.len() {
                break;
            }

            mpls_stack_bottom = buf[pos + 2] & 0x1;

            #[cfg(feature = "heuristic-mpls")]
            {
                // Try to decode it as an Ethernet protocol first
                // If failed, then try to decode it other ways
                match link::ethernet::Parser::parse(buf, offset + pos as u16) {
                    Ok(l) => {
                        match l.protocol {
                            Protocol::IPV4 => {
                                match network::ipv4::Parser::parse(
                                    buf,
                                    offset + l.offset + pos as u16,
                                ) {
                                    Ok(_) => {
                                        let layer = Layer {
                                            protocol: Protocol::ETHERNET,
                                            offset: offset + pos as u16,
                                        };
                                        return Ok(layer);
                                    }
                                    Err(_) => {}
                                }
                            }
                            Protocol::IPV6 => {
                                match network::ipv6::Parser::parse(
                                    buf,
                                    offset + l.offset + pos as u16,
                                ) {
                                    Ok(_) => {
                                        let layer = Layer {
                                            protocol: Protocol::ETHERNET,
                                            offset: offset + pos as u16,
                                        };
                                        return Ok(layer);
                                    }
                                    Err(_) => {}
                                }
                            }
                            Protocol::PPP => {
                                todo! {"too much tunnel layers to handle"}
                            }
                            Protocol::MPLS => {
                                todo! {"too much tunnel layers to handle"}
                            }
                            Protocol::PPPOE => {
                                todo! {"too much tunnel layers to handle"}
                            }
                            Protocol::VLAN => {
                                todo! {"too much tunnel layers to handle"}
                            }
                            _ => {} // do nothing, unsupported protocol
                        };
                    }
                    Err(_) => {} // If can't detect next layer
                };
            }

            match buf[offset as usize + pos] >> 4 {
                0b0000 => {
                    // PW Ethernet Control Word
                    let layer = Layer {
                        protocol: Protocol::ETHERNET,
                        offset: offset + 4 + pos as u16,
                    };
                    return Ok(layer);
                }
                0b0100 => {
                    let layer = Layer {
                        protocol: Protocol::IPV4,
                        offset: offset + pos as u16,
                    };
                    return Ok(layer);
                }
                0b0110 => {
                    let layer = Layer {
                        protocol: Protocol::IPV6,
                        offset: offset + pos as u16,
                    };
                    return Ok(layer);
                }
                _ => {}
            };
        }

        return Err(Error::CorruptPacket(format!(
            "Corrupted MPLS packet, at mpls stack bottom but no valid network layer found",
        )));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_layer_mpls_with_ipv4() {
        let buffer = [
            0x00, 0x01, 0xd1, 0xff, // mpls
            0x45, 0x00, 0x00, 0x64, 0x00, 0x0a, 0x00, 0x00, 0xff, 0x01, 0xa5, 0x6a, 0x0a, 0x01,
            0x02, 0x01, 0x0a, 0x22, 0x00, 0x01, // ipv4
            0x08, 0x00, 0x3a, 0x77, 0x0a, 0x39, 0x06, 0x2b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1f,
            0x33, 0x50, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
            0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
            0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
            0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
            0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, // icmp
        ];
        let offset = 0;

        match Parser::parse(&buffer, offset) {
            Ok(l) => {
                assert_eq!(l.protocol, Protocol::IPV4);
                assert_eq!(l.offset, 4);
            }
            Err(_) => {}
        }
    }

    #[test]
    fn test_single_layer_mpls_with_ipv6() {
        let buffer = [
            0x00, 0x01, 0xd1, 0xff, // mpls
            0x60, 0x0c, 0x6b, 0x7b, 0x00, 0xb8, 0x11, 0xff, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x10, 0x08, 0xfa, 0x70, 0x46, 0xe8, 0x42, 0x04, 0xff, 0x02, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfb, // ipv6
            0x14, 0xe9, 0x14, 0xe9, 0x00, 0xb8, 0x5a, 0x88, //udp
            0xa6, 0xea, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x73,
            0x77, 0x2d, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x05, 0x6f, 0x62, 0x64, 0x65, 0x76,
            0x02, 0x61, 0x74, 0x00, 0x00, 0x01, 0x00, 0x01, // dns,
        ];
        let offset = 0;

        match Parser::parse(&buffer, offset) {
            Ok(l) => {
                assert_eq!(l.protocol, Protocol::IPV6);
                assert_eq!(l.offset, 4);
            }
            Err(_) => {}
        }
    }

    #[test]
    fn test_double_layer_mpls_with_ethernet() {
        let buffer = [
            0x00, 0x01, 0x20, 0xfe, // mpls
            0x00, 0x01, 0x01, 0xff, // mpls
            0x00, 0x00, 0x00, 0x00, // PW Ethernet Control Word
            0x01, 0x80, 0xc2, 0x00, 0x00, 0x00, 0xcc, 0x04, 0x0d, 0x5c, 0xf0, 0x00, 0x00,
            0x26, // Ethernet
            0x42, 0x42, 0x03, // Logical-Link Control
            0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0xcc, 0x04, 0x0d, 0x5c, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x80, 0x00, 0xcc, 0x04, 0x0d, 0x5c, 0x00, 0x00, 0x80, 0x01, 0x00,
            0x00, 0x14, 0x00, 0x02, 0x00, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, // Spanning Tree Protocol
        ];
        let offset = 0;

        match Parser::parse(&buffer, offset) {
            Ok(l) => {
                assert_eq!(l.protocol, Protocol::ETHERNET);
                assert_eq!(l.offset, 8);
            }
            Err(_) => {}
        }
    }

    #[test]
    fn test_ethernet_over_mpls_with_pw_control_word() {
        let buffer = [
            0x00, 0x01, 0x20, 0xfe, // mpls
            0x00, 0x01, 0x01, 0xff, // mpls
            0x00, 0x00, 0x00, 0x00, // PW Ethernet Control Word
            0x01, 0x80, 0xc2, 0x00, 0x00, 0x00, 0xcc, 0x04, 0x0d, 0x5c, 0xf0, 0x00, 0x00,
            0x26, // Ethernet
            0x42, 0x42, 0x03, // Logical-Link Control
            0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0xcc, 0x04, 0x0d, 0x5c, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x80, 0x00, 0xcc, 0x04, 0x0d, 0x5c, 0x00, 0x00, 0x80, 0x01, 0x00,
            0x00, 0x14, 0x00, 0x02, 0x00, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, // Spanning Tree Protocol
        ];
        let offset = 0;

        match Parser::parse(&buffer, offset) {
            Ok(l) => {
                assert_eq!(l.protocol, Protocol::ETHERNET);
                assert_eq!(l.offset, 8);
            }
            Err(_) => {}
        }
    }

    #[test]
    #[cfg(feature = "heuristic-mpls")]
    fn test_ethernet_over_mpls_without_pw_contrtol_word() {
        let buffer = [
            0x00, 0x01, 0x01, 0xff, // mpls
            0x01, 0x80, 0xc2, 0x00, 0x00, 0x00, 0xcc, 0x04, 0x0d, 0x5c, 0xf0, 0x00, 0x08,
            0x00, // Ethernet
            0x45, 0x00, 0x00, 0x64, 0x00, 0x0a, 0x00, 0x00, 0xff, 0x01, 0xa5, 0x6a, 0x0a, 0x01,
            0x02, 0x01, 0x0a, 0x22, 0x00, 0x01, // ipv4
            0x08, 0x00, 0x3a, 0x77, 0x0a, 0x39, 0x06, 0x2b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1f,
            0x33, 0x50, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
            0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
            0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
            0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
            0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, // icmp
        ];
        let offset = 0;

        match Parser::parse(&buffer, offset) {
            Ok(l) => {
                assert_eq!(l.protocol, Protocol::ETHERNET);
                assert_eq!(l.offset, 4);
            }
            Err(_) => {}
        }
    }
}
