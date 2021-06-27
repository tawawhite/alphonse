#![allow(non_camel_case_types)]

use std::hash::Hash;

use serde::Serialize;

#[repr(u16)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Primitive, Serialize)]
pub enum Class {
    IN = 1,
    CH = 3,
    HS = 4,
    NONE = 254,
    ANY = 255,
}

bitflags! {
    pub struct Flags: u16 {
        const RESPONSE = 0b1000000000000000;
        const AUTHORITATIVE_ANSWER = 0b0000010000000000;
        const TRUNCATED = 0b0000001000000000;
        const RECURSION_DESIRED = 0b0000000100000000;
        const RECURSION_AVALIABLE = 0b0000000010000000;
        const Z = 0b0000000001000000;
        const ANSWER_AUTHENCATED = 0b0000000000100000;
        const NO_AUTH_ACCEPTABLE = 0b0000000000010000;
    }
}

impl Default for Flags {
    fn default() -> Self {
        Flags::from_bits_truncate(0)
    }
}

impl Flags {
    #[inline]
    /// Get Op Code
    pub fn op_code(&self) -> u8 {
        ((self.bits() & 0b0111100000000000) >> 8) as u8
    }

    #[inline]
    /// Get Reply Code
    pub fn reply_code(&self) -> u8 {
        ((self.bits() & 0b0000000000001111) >> 8) as u8
    }
}
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Primitive, Serialize)]
pub enum OpCode {
    Query = 0,
    IQuery = 1,
    Status = 2,
    Notify = 4,
    Update = 5,
    DSO = 6,
}

#[repr(u16)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Primitive, Serialize)]
pub enum RCode {
    NoError = 0,
    FormErr = 1,
    ServFail = 2,
    NXDomain = 3,
    NotImp = 4,
    Refused = 5,
    YXDomain = 6,
    YXRRSet = 7,
    NXRRSet = 8,
    NotAuth = 9,
    NotZone = 10,
    DSOTYPENI = 11,
    BADVERS_OR_BADKEY = 16,
    BADKEY = 17,
    BADTIME = 18,
    BADMODE = 19,
    BADNAME = 20,
    BADALG = 21,
    BADTRUNC = 22,
    BADCOOKIE = 23,
}

#[repr(u16)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Primitive, Serialize)]
pub enum ResourceRecordType {
    A = 1,
    NS = 2,
    MD = 3,
    MF = 4,
    CNAME = 5,
    SOA = 6,
    MB = 7,
    MG = 8,
    MR = 9,
    NULL = 10,
    WKS = 11,
    PTR = 12,
    HINFO = 13,
    MINFO = 14,
    MX = 15,
    TXT = 16,
    RP = 17,
    AFSDB = 18,
    X25 = 19,
    ISDN = 20,
    RT = 21,
    NSAP = 22,
    NSAP_PTR = 23,
    SIG = 24,
    KEY = 25,
    PX = 26,
    GPOS = 27,
    AAAA = 28,
    LOC = 29,
    NXT = 30,
    EID = 31,
    NIMLOC = 32,
    SRV = 33,
    ATMA = 34,
    NAPTR = 35,
    KX = 36,
    CERT = 37,
    A6 = 38,
    DNAME = 39,
    SINK = 40,
    OPT = 41,
    APL = 42,
    DS = 43,
    SSHFP = 44,
    IPSECKEY = 45,
    RRSIG = 46,
    NSEC = 47,
    DNSKEY = 48,
    DHCID = 49,
    NSEC3 = 50,
    NSEC3PARAM = 51,
    TLSA = 52,
    SMIMA = 53,
    HIP = 55,
    NINFO = 56,
    RKEY = 57,
    TALINK = 58,
    CDS = 59,
    CDNSKEY = 60,
    OPENPGPKEY = 61,
    CSYNC = 62,
    ZONEMD = 63,
    SVCB = 64,
    HTTPS = 65,
    SPF = 99,
    UINFO = 100,
    UID = 101,
    GID = 102,
    UNSPEC = 103,
    NID = 104,
    L32 = 105,
    L64 = 106,
    LP = 107,
    EUI48 = 108,
    EUI64 = 109,
    TKEY = 249,
    TSIG = 250,
    IXFR = 251,
    AXFR = 252,
    MAILB = 253,
    MAILA = 254,
    ALL = 255,
    URI = 256,
    CAA = 257,
    AVC = 258,
    DOA = 259,
    AMTRELAY = 260,
    TA = 32768,
    DLV = 32769,
}
