//! Minimal DNS message handling (RFC 1035): read the question and the
//! A/AAAA/CNAME answers of a message, and build the sinkhole replies the DNS
//! filter sends for blocked names. Everything else is passed through as raw
//! bytes, so unknown record types and extensions keep working.

use super::rules::Answer;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const TYPE_A: u16 = 1;
pub const TYPE_CNAME: u16 = 5;
pub const TYPE_AAAA: u16 = 28;
const CLASS_IN: u16 = 1;
const HEADER_LEN: usize = 12;
/// Compression pointers followed per name before giving up (loop guard).
const MAX_POINTERS: usize = 32;

#[derive(Debug, Clone, PartialEq)]
pub struct Question {
    /// Lowercase name without the trailing dot.
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
    /// Byte range of the whole question section entry in the message.
    pub end: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Message {
    pub id: u16,
    pub flags: u16,
    pub question: Option<Question>,
    pub answers: Vec<Answer>,
}

impl Message {
    pub fn is_response(&self) -> bool {
        self.flags & 0x8000 != 0
    }
    pub fn rcode(&self) -> u8 {
        (self.flags & 0x000F) as u8
    }
}

fn u16_at(buf: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*buf.get(at)?, *buf.get(at + 1)?]))
}

/// Reads a possibly compressed name starting at `at`. Returns the name and
/// the offset just past it in the original (uncompressed) position.
pub fn read_name(buf: &[u8], mut at: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut end = None;
    let mut jumps = 0;
    let mut total = 0;
    loop {
        let len = *buf.get(at)? as usize;
        match len & 0xC0 {
            0x00 if len == 0 => {
                end.get_or_insert(at + 1);
                break;
            }
            0x00 => {
                let label = buf.get(at + 1..at + 1 + len)?;
                total += len + 1;
                if total > 255 {
                    return None;
                }
                labels.push(String::from_utf8_lossy(label).to_ascii_lowercase());
                at += 1 + len;
            }
            0xC0 => {
                let pointer = (u16_at(buf, at)? & 0x3FFF) as usize;
                end.get_or_insert(at + 2);
                jumps += 1;
                if jumps > MAX_POINTERS || pointer >= buf.len() {
                    return None;
                }
                at = pointer;
            }
            _ => return None, // reserved label types
        }
    }
    Some((labels.join("."), end?))
}

/// Parses the header, first question and A/AAAA/CNAME answers. Returns
/// `None` for anything malformed.
pub fn parse(buf: &[u8]) -> Option<Message> {
    if buf.len() < HEADER_LEN {
        return None;
    }
    let id = u16_at(buf, 0)?;
    let flags = u16_at(buf, 2)?;
    let qdcount = u16_at(buf, 4)?;
    let ancount = u16_at(buf, 6)?;
    let mut at = HEADER_LEN;
    let mut question = None;
    for i in 0..qdcount {
        let (name, next) = read_name(buf, at)?;
        let qtype = u16_at(buf, next)?;
        let qclass = u16_at(buf, next + 2)?;
        at = next + 4;
        if i == 0 {
            question = Some(Question { name, qtype, qclass, end: at });
        }
    }
    let mut answers = Vec::new();
    for _ in 0..ancount {
        let (_, next) = read_name(buf, at)?;
        let rtype = u16_at(buf, next)?;
        let rdlen = u16_at(buf, next + 8)? as usize;
        let rdata_at = next + 10;
        let rdata = buf.get(rdata_at..rdata_at + rdlen)?;
        match rtype {
            TYPE_A if rdlen == 4 => answers.push(Answer::Address(IpAddr::V4(Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3])))),
            TYPE_AAAA if rdlen == 16 => {
                let octets: [u8; 16] = rdata.try_into().ok()?;
                answers.push(Answer::Address(IpAddr::V6(Ipv6Addr::from(octets))));
            }
            TYPE_CNAME => answers.push(Answer::Cname(read_name(buf, rdata_at)?.0)),
            _ => {}
        }
        at = rdata_at + rdlen;
    }
    Some(Message { id, flags, question, answers })
}

/// Builds the reply for a blocked lookup from the original `query` bytes:
/// an A question gets `sinkhole` (so the browser connects to the block-page
/// server), any other type gets an empty, successful answer. The question is
/// copied verbatim; additional records (EDNS) are dropped.
pub fn sinkhole_reply(query: &[u8], sinkhole: Ipv4Addr, ttl: u32) -> Option<Vec<u8>> {
    let message = parse(query)?;
    let question = message.question?;
    let mut out = Vec::with_capacity(question.end + 16);
    out.extend_from_slice(&message.id.to_be_bytes());
    // QR=1, keep opcode and RD, set RA; rcode 0.
    let flags = 0x8000 | (message.flags & 0x7900) | 0x0080;
    out.extend_from_slice(&flags.to_be_bytes());
    let answer = question.qtype == TYPE_A && question.qclass == CLASS_IN;
    out.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    out.extend_from_slice(&(answer as u16).to_be_bytes()); // ancount
    out.extend_from_slice(&[0, 0, 0, 0]); // nscount, arcount
    out.extend_from_slice(query.get(HEADER_LEN..question.end)?);
    if answer {
        out.extend_from_slice(&[0xC0, 0x0C]); // pointer to the question name
        out.extend_from_slice(&TYPE_A.to_be_bytes());
        out.extend_from_slice(&CLASS_IN.to_be_bytes());
        out.extend_from_slice(&ttl.to_be_bytes());
        out.extend_from_slice(&4u16.to_be_bytes());
        out.extend_from_slice(&sinkhole.octets());
    }
    Some(out)
}

/// A SERVFAIL reply for `query`, used when the upstream resolver is down.
pub fn servfail_reply(query: &[u8]) -> Option<Vec<u8>> {
    let message = parse(query)?;
    let end = message.question.as_ref().map_or(HEADER_LEN, |q| q.end);
    let mut out = query.get(..end)?.to_vec();
    let flags = 0x8000 | (message.flags & 0x7900) | 0x0080 | 2;
    out[2..4].copy_from_slice(&flags.to_be_bytes());
    out[4..6].copy_from_slice(&(message.question.is_some() as u16).to_be_bytes());
    out[6..12].fill(0);
    Some(out)
}

/// Builds a query (used by tests and the self-check).
pub fn build_query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&0x0100u16.to_be_bytes()); // RD
    out.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]);
    for label in name.trim_end_matches('.').split('.').filter(|l| !l.is_empty()) {
        out.push(label.len().min(63) as u8);
        out.extend_from_slice(&label.as_bytes()[..label.len().min(63)]);
    }
    out.push(0);
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&CLASS_IN.to_be_bytes());
    out
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A response to `query` with the given answers, using compression the
    /// way real resolvers do.
    pub(crate) fn response(query: &[u8], answers: &[(u16, Vec<u8>)]) -> Vec<u8> {
        let q = parse(query).unwrap().question.unwrap();
        let mut out = query[..q.end].to_vec();
        out[2] |= 0x80;
        out[3] |= 0x80;
        out[6..8].copy_from_slice(&(answers.len() as u16).to_be_bytes());
        for (rtype, rdata) in answers {
            out.extend_from_slice(&[0xC0, 0x0C]);
            out.extend_from_slice(&rtype.to_be_bytes());
            out.extend_from_slice(&CLASS_IN.to_be_bytes());
            out.extend_from_slice(&300u32.to_be_bytes());
            out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
            out.extend_from_slice(rdata);
        }
        out
    }

    #[test]
    fn parses_questions_and_compressed_answers() {
        let query = build_query(0x1234, "WWW.Example.COM.", TYPE_A);
        let m = parse(&query).unwrap();
        assert_eq!((m.id, m.is_response()), (0x1234, false));
        assert_eq!(m.question.as_ref().unwrap().name, "www.example.com");

        // CNAME "cdn" + pointer to "example.com" at offset 16, then an A record.
        let cname_rdata = vec![3, b'c', b'd', b'n', 0xC0, 16];
        let reply = response(&query, &[(TYPE_CNAME, cname_rdata), (TYPE_A, vec![192, 0, 2, 7]), (TYPE_AAAA, vec![0; 16])]);
        let m = parse(&reply).unwrap();
        assert!(m.is_response());
        assert_eq!(
            m.answers,
            [
                Answer::Cname("cdn.example.com".into()),
                Answer::Address("192.0.2.7".parse().unwrap()),
                Answer::Address("::".parse().unwrap()),
            ]
        );
    }

    #[test]
    fn rejects_pointer_loops_and_truncation() {
        let mut query = build_query(1, "a.example", TYPE_A);
        assert!(parse(&query[..query.len() - 2]).is_none());
        // Replace the name with a pointer to itself.
        query.truncate(12);
        query.extend_from_slice(&[0xC0, 12, 0, 1, 0, 1]);
        assert!(parse(&query).is_none());
    }

    #[test]
    fn sinkhole_answers_a_and_empties_other_types() {
        let sinkhole: Ipv4Addr = "127.66.0.1".parse().unwrap();
        let a = sinkhole_reply(&build_query(7, "bad.example", TYPE_A), sinkhole, 60).unwrap();
        let m = parse(&a).unwrap();
        assert_eq!((m.id, m.is_response(), m.rcode()), (7, true, 0));
        assert_eq!(m.answers, [Answer::Address(IpAddr::V4(sinkhole))]);

        let aaaa = sinkhole_reply(&build_query(8, "bad.example", TYPE_AAAA), sinkhole, 60).unwrap();
        let m = parse(&aaaa).unwrap();
        assert!(m.answers.is_empty());
        assert_eq!(m.question.unwrap().name, "bad.example");

        let fail = servfail_reply(&build_query(9, "x.example", TYPE_A)).unwrap();
        assert_eq!(parse(&fail).unwrap().rcode(), 2);
    }
}
