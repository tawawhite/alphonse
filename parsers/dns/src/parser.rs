use nom::bytes::streaming::take;
use nom::combinator::complete;
use nom::number::streaming::{be_u16, be_u32, be_u8};
use nom::IResult;

pub use crate::consts::*;

#[derive(Debug, Default)]
pub struct Query<'a> {
    name: &'a [u8],
    qtype: u16,
    class: u16,
}

impl<'a> Query<'a> {
    pub fn name(&self) -> IResult<&[u8], String> {
        let mut name = String::new();
        let mut s = self.name;

        loop {
            let (tmp, len) = be_u8(s)?;
            if (len == 0) | (len == 0xc0) {
                s = tmp;
                break;
            }
            let (tmp, part) = take(len)(tmp)?;
            s = tmp;
            let part = unsafe { std::str::from_utf8_unchecked(part) };
            name.push_str(part);
            name.push('.');
        }
        name.pop();

        Ok((s, name))
    }
}

#[derive(Debug)]
#[repr(u8)]
pub enum DnsMessageType {
    Query,
    Response,
}

impl Default for DnsMessageType {
    fn default() -> Self {
        DnsMessageType::Query
    }
}

#[derive(Debug, Default)]
pub struct DnsMessage<'a> {
    pub msg_type: DnsMessageType,
    pub transaction_id: u16,
    pub flags: Flags,
    pub qry_num: u16,
    pub answer_num: u16,
    pub authority_rec_num: u16,
    pub additional_rec_num: u16,
    pub queries: &'a [u8],
}

#[derive(Debug, Default)]
/// A DNS answer
pub struct ResourceRecord<'a> {
    pub name: u16,
    /// Resource record type
    pub rr_type: u16,
    pub class: u16,
    pub time_to_live: u32,
    pub data_len: u16,
    pub data: &'a [u8],
}

#[derive(Debug, Default)]
pub struct DnsResponse<'a> {
    transaction_id: u16,
    flags: Flags,
    qry_num: u16,
    answer_num: u16,
    authority_rec_num: u16,
    additional_rec_num: u16,
    queries: &'a [u8],
    pub answers: &'a [u8],
    pub nameservers: &'a [u8],
    pub additional_records: &'a [u8],
}

#[inline]
/// Get transaction ID
fn parse_trans_id(s: &[u8]) -> IResult<&[u8], u16> {
    Ok(be_u16(s)?)
}

#[inline]
fn parse_flags(s: &[u8]) -> IResult<&[u8], Flags> {
    let (s, flags) = be_u16(s)?;
    let flags = Flags::from_bits_truncate(flags);
    Ok((s, flags))
}

pub fn parse_tcp_dns_packet(s: &[u8]) -> IResult<&[u8], DnsMessage> {
    let (s, total_len) = be_u16(s)?;
    let mut parser = complete(take(total_len));
    let (_, s) = parser(s)?;
    parse_dns_packet(s)
}

pub fn parse_dns_packet(s: &[u8]) -> IResult<&[u8], DnsMessage> {
    let (s, id) = parse_trans_id(s)?;
    let (s, flags) = parse_flags(s)?;
    let (s, qry_num) = be_u16(s)?;
    let (s, answer_num) = be_u16(s)?;
    let (s, authority_rec_num) = be_u16(s)?;
    let (s, additional_rec_num) = be_u16(s)?;

    if (flags & Flags::RESPONSE) == Flags::RESPONSE {
        let mut resp = DnsMessage::default();
        resp.msg_type = DnsMessageType::Response;
        resp.transaction_id = id;
        resp.flags = flags;
        resp.qry_num = qry_num;
        resp.answer_num = answer_num;
        resp.authority_rec_num = authority_rec_num;
        resp.additional_rec_num = additional_rec_num;
        resp.queries = s;
        Ok((s, resp))
    } else {
        let mut query = DnsMessage::default();
        query.msg_type = DnsMessageType::Query;
        query.transaction_id = id;
        query.flags = flags;
        query.qry_num = qry_num;
        query.answer_num = answer_num;
        query.authority_rec_num = authority_rec_num;
        query.additional_rec_num = additional_rec_num;
        query.queries = s;
        Ok((s, query))
    }
}

/// Parse DNS query
///
/// General DNS query packet only contains one query, however, it is allowed for
/// a single DNS query packet to have multiple queries. To reduce heap allocation,
/// use tiny vec: if there is only one query, the result is stored on stack,
/// otherwise realloc memory on heap to store all the quries
pub fn parse_dns_query(mut s: &[u8]) -> IResult<&[u8], Query> {
    let mut query = Query::default();
    query.name = s;
    let mut end = 0;
    loop {
        let (tmp, len) = be_u8(s)?;
        end += 1;
        match len {
            0 => {
                s = tmp;
                break;
            }
            0xc0 => {
                let (tmp, _) = take(1usize)(tmp)?;
                s = tmp;
                break;
            }
            _ => {
                let (tmp, _) = take(len)(tmp)?;
                s = tmp;
                end += len;
            }
        }
    }

    query.name = &query.name[..end as usize];

    let (tmp, qry_type) = be_u16(s)?;
    let (tmp, qry_class) = be_u16(tmp)?;
    query.qtype = qry_type;
    query.class = qry_class;
    s = tmp;

    Ok((s, query))
}

pub fn parse_dns_resource_records(mut s: &[u8]) -> IResult<&[u8], Vec<ResourceRecord>> {
    let mut answers = vec![];
    loop {
        if s.len() <= 0 {
            break;
        }

        loop {
            if s.len() <= 0 {
                break;
            }
            let mut answer = ResourceRecord::default();
            let (tmp, name) = be_u16(s)?;
            let (tmp, rr_type) = be_u16(tmp)?;
            let (tmp, class) = be_u16(tmp)?;
            let (tmp, time_to_live) = be_u32(tmp)?;
            let (tmp, data_len) = be_u16(tmp)?;
            let (tmp, data) = take(data_len)(tmp)?;

            answer.name = name;
            answer.rr_type = rr_type;
            answer.class = class;
            answer.time_to_live = time_to_live;
            answer.data_len = data_len;
            answer.data = data;
            s = tmp;
            answers.push(answer);
        }
    }

    Ok((&[], answers))
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use num_traits::FromPrimitive;

    use super::*;

    const SINGLE_QUERY: &[u8] = &[
        0x03, 0x77, 0x77, 0x77, 0x06, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x03, 0x63, 0x6f, 0x6d,
        0x00, 0x00, 0x01, 0x00, 0x01,
    ];
    const QUERY_PKT: &[u8] = &[
        0xe0, 0x39, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x77, 0x77,
        0x77, 0x06, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x03,
    ];
    const RESPONSE_PKT: &[u8] = &[
        0xe0, 0x39, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x04, 0x00, 0x04, 0x03, 0x77, 0x77,
        0x77, 0x06, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01,
        0x00, 0x01, 0xc0, 0x0c, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x07, 0xbc, 0x00, 0x02, 0xc0,
        0x10, 0xc0, 0x10, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x04, 0x00, 0x04, 0xc0, 0x1e,
        0xfc, 0x80, 0xc0, 0x10, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x01, 0x48, 0x00, 0x14, 0x03,
        0x6e, 0x73, 0x33, 0x03, 0x70, 0x31, 0x36, 0x06, 0x64, 0x79, 0x6e, 0x65, 0x63, 0x74, 0x03,
        0x6e, 0x65, 0x74, 0x00, 0xc0, 0x10, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x01, 0x48, 0x00,
        0x06, 0x03, 0x6e, 0x73, 0x32, 0xc0, 0x4e, 0xc0, 0x10, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00,
        0x01, 0x48, 0x00, 0x06, 0x03, 0x6e, 0x73, 0x34, 0xc0, 0x4e, 0xc0, 0x10, 0x00, 0x02, 0x00,
        0x01, 0x00, 0x00, 0x01, 0x48, 0x00, 0x06, 0x03, 0x6e, 0x73, 0x31, 0xc0, 0x4e, 0xc0, 0x6a,
        0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x0e, 0x10, 0x00, 0x04, 0x0a, 0x02, 0x5f, 0x0c, 0xc0,
        0x4a, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x0e, 0x10, 0x00, 0x04, 0x0a, 0x02, 0x5f, 0x0c,
        0xc0, 0x8e, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x0e, 0x10, 0x00, 0x04, 0x0a, 0x02, 0x5f,
        0x0c, 0xc0, 0x7c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x0e, 0x10, 0x00, 0x04, 0x0a, 0x02,
        0x5f, 0x0c,
    ];

    #[test]
    fn parse_query() -> Result<()> {
        let (s, query) = parse_dns_query(&SINGLE_QUERY)?;
        assert_eq!(s.len(), 0);
        assert_eq!(query.qtype, 0x0001);
        assert_eq!(query.class, 0x0001);
        match query.name() {
            Ok(r) => {
                assert_eq!(r.1, "www.github.com");
            }
            Err(_) => {}
        };

        Ok(())
    }

    #[test]
    fn parse_query_pkt() -> Result<()> {
        let (_, msg) = parse_dns_packet(QUERY_PKT)?;
        assert!(matches!(msg.msg_type, DnsMessageType::Query));
        assert_eq!(msg.transaction_id, 0xe039);
        assert_eq!(msg.flags, Flags::RECURSION_DESIRED);
        assert_eq!(msg.qry_num, 1);
        assert_eq!(msg.answer_num, 0);
        assert_eq!(msg.authority_rec_num, 0);
        assert_eq!(msg.additional_rec_num, 0);
        Ok(())
    }

    #[test]
    fn parse_response_pkt() -> Result<()> {
        let (_, msg) = parse_dns_packet(RESPONSE_PKT)?;
        assert!(matches!(msg.msg_type, DnsMessageType::Response));
        assert_eq!(msg.transaction_id, 0xe039);
        assert_eq!(
            msg.flags & Flags::RECURSION_DESIRED,
            Flags::RECURSION_DESIRED
        );
        assert_eq!(
            msg.flags & Flags::RECURSION_AVALIABLE,
            Flags::RECURSION_AVALIABLE
        );
        assert_eq!(msg.qry_num, 1);
        assert_eq!(msg.answer_num, 2);
        assert_eq!(msg.authority_rec_num, 4);
        assert_eq!(msg.additional_rec_num, 4);
        Ok(())
    }

    #[test]
    fn parse_answers() -> Result<()> {
        let (_, answers) = parse_dns_resource_records(&RESPONSE_PKT[32..])?;

        // 1st record
        let rr_type = ResourceRecordType::from_u16(answers[0].rr_type);
        assert!(matches!(rr_type, Some(ResourceRecordType::CNAME)));

        let class = Class::from_u16(answers[0].class);
        assert!(matches!(class, Some(Class::IN)));

        assert_eq!(answers[0].time_to_live, 1980);
        assert_eq!(answers[0].data_len, 2);

        // 2nd record
        let rr_type = ResourceRecordType::from_u16(answers[1].rr_type);
        assert!(matches!(rr_type, Some(ResourceRecordType::A)));

        let class = Class::from_u16(answers[1].class);
        assert!(matches!(class, Some(Class::IN)));
        assert_eq!(answers[1].time_to_live, 4);
        assert_eq!(answers[1].data_len, 4);

        // 3rd record
        let rr_type = ResourceRecordType::from_u16(answers[2].rr_type);
        assert!(matches!(rr_type, Some(ResourceRecordType::NS)));

        let class = Class::from_u16(answers[2].class);
        assert!(matches!(class, Some(Class::IN)));
        assert_eq!(answers[2].time_to_live, 328);
        assert_eq!(answers[2].data_len, 20);

        // 7th record
        let rr_type = ResourceRecordType::from_u16(answers[6].rr_type);
        assert!(matches!(rr_type, Some(ResourceRecordType::A)));

        let class = Class::from_u16(answers[6].class);
        assert!(matches!(class, Some(Class::IN)));
        assert_eq!(answers[6].time_to_live, 3600);
        assert_eq!(answers[6].data_len, 4);

        Ok(())
    }
}
