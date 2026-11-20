//! The guest's resolver, answered in the runtime: the DNS queries the program's libc sends to the
//! nameserver `/etc/resolv.conf` names reach the host as datagrams (`tsi`'s `net_sendto`), and
//! the answer is built here from the `on_resolve` hook's addresses. Only what a stub resolver
//! asks: one question, class IN; `A` answered with the hook's IPv4 addresses; any other type
//! (`AAAA` among them) with no data (NOERROR, no answers), without asking the hook (`tsi`). No
//! recursion, no EDNS (an OPT record in the query is ignored, and none is sent back).

use alloc::string::String;
use alloc::vec::Vec;
use core::net::Ipv4Addr;

/// A DNS response code (RFC 1035 4.1.1, RFC 2136). What getaddrinfo makes of each: NXDOMAIN is
/// EAI_NONAME; SERVFAIL EAI_AGAIN (a temporary failure). glibc takes REFUSED and NOTIMP for a
/// server's trouble too (it tries the next server, then EAI_AGAIN), so a refusal that must stay
/// one (a denied name) is NOTAUTH: musl answers it EAI_FAIL, glibc (which folds a non-recoverable
/// answer into "not found") EAI_NONAME; neither retries it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Rcode {
    NoError = 0,
    FormErr = 1,
    ServFail = 2,
    NxDomain = 3,
    NotImp = 4,
    Refused = 5,
    NotAuth = 9,
}

pub const TYPE_A: u16 = 1;
pub const TYPE_AAAA: u16 = 28;
const CLASS_IN: u16 = 1;
const TTL: u32 = 60;

/// One question, parsed.
#[derive(Debug, PartialEq, Eq)]
pub struct Query<'a> {
    pub id: u16,
    /// The query's flags (its RD bit is echoed).
    pub flags: u16,
    /// The name, lowercased, without a trailing dot.
    pub name: String,
    pub qtype: u16,
    /// The question section as sent, echoed in the answer.
    pub question: &'a [u8],
}

fn u16_at(b: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(i)?, *b.get(i + 1)?]))
}

/// The query in `msg`, or the header's id and the code to answer with (a reply needs the id:
/// a message too short for one gets none).
pub fn parse(msg: &[u8]) -> Result<Query<'_>, Option<(u16, Rcode)>> {
    let id = u16_at(msg, 0).ok_or(None)?;
    let flags = u16_at(msg, 2).ok_or(None)?;
    let fail = |rc| Err(Some((id, rc)));
    // A response, or not a standard query (opcode 0): nothing a stub resolver sends.
    if flags & 0x8000 != 0 {
        return Err(None);
    }
    if (flags >> 11) & 0xf != 0 {
        return fail(Rcode::NotImp);
    }
    if u16_at(msg, 4) != Some(1) {
        return fail(Rcode::FormErr);
    }
    let mut i = 12;
    let mut name = String::new();
    loop {
        let Some(&len) = msg.get(i) else { return fail(Rcode::FormErr) };
        i += 1;
        if len == 0 {
            break;
        }
        // No compression in a question; labels are at most 63 bytes, names 255.
        if len > 63 || name.len() + len as usize > 254 {
            return fail(Rcode::FormErr);
        }
        let Some(label) = msg.get(i..i + len as usize) else { return fail(Rcode::FormErr) };
        let Ok(label) = core::str::from_utf8(label) else { return fail(Rcode::FormErr) };
        if !name.is_empty() {
            name.push('.');
        }
        name.extend(label.chars().map(|c| c.to_ascii_lowercase()));
        i += len as usize;
    }
    let (Some(qtype), Some(class)) = (u16_at(msg, i), u16_at(msg, i + 2)) else { return fail(Rcode::FormErr) };
    if class != CLASS_IN {
        return fail(Rcode::NotImp);
    }
    Ok(Query { id, flags, name, qtype, question: &msg[12..i + 4] })
}

/// The answer to `q`: `rcode`, and for an A query with NOERROR the addresses.
pub fn answer(q: &Query, rcode: Rcode, addrs: &[Ipv4Addr]) -> Vec<u8> {
    let a: &[Ipv4Addr] = if rcode == Rcode::NoError && q.qtype == TYPE_A { addrs } else { &[] };
    let mut out = header(q.id, q.flags, rcode, 1, a.len() as u16);
    out.extend_from_slice(q.question);
    for ip in a {
        // The name as a pointer to the question's (offset 12), type A, class IN, TTL, 4 bytes.
        out.extend_from_slice(&[0xc0, 12]);
        out.extend_from_slice(&TYPE_A.to_be_bytes());
        out.extend_from_slice(&CLASS_IN.to_be_bytes());
        out.extend_from_slice(&TTL.to_be_bytes());
        out.extend_from_slice(&4u16.to_be_bytes());
        out.extend_from_slice(&ip.octets());
    }
    out
}

/// A reply with no question (for a query that couldn't be parsed).
pub fn failure(id: u16, rcode: Rcode) -> Vec<u8> {
    header(id, 0, rcode, 0, 0)
}

fn header(id: u16, qflags: u16, rcode: Rcode, qd: u16, an: u16) -> Vec<u8> {
    // QR, the query's RD, RA; the opcode is 0 (only standard queries are answered).
    let flags = 0x8000 | (qflags & 0x0100) | 0x0080 | rcode as u16;
    let mut out = Vec::with_capacity(512);
    for v in [id, flags, qd, an, 0, 0] {
        out.extend_from_slice(&v.to_be_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(name: &str, qtype: u16) -> Vec<u8> {
        let mut q = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for l in name.split('.') {
            q.push(l.len() as u8);
            q.extend_from_slice(l.as_bytes());
        }
        q.push(0);
        q.extend_from_slice(&qtype.to_be_bytes());
        q.extend_from_slice(&1u16.to_be_bytes());
        q
    }

    #[test]
    fn a_query_answered() {
        let msg = query("Echo.Test", TYPE_A);
        let q = parse(&msg).unwrap();
        assert_eq!((q.id, q.name.as_str(), q.qtype), (0x1234, "echo.test", TYPE_A));
        let a = answer(&q, Rcode::NoError, &[Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2)]);
        assert_eq!(&a[..4], &[0x12, 0x34, 0x81, 0x80]);
        assert_eq!(u16_at(&a, 6), Some(2));
        assert_eq!(&a[12..12 + q.question.len()], q.question);
        let first = 12 + q.question.len();
        assert_eq!(&a[first..first + 2], &[0xc0, 12]);
        assert_eq!(&a[first + 12..first + 16], &[10, 0, 0, 1]);
        assert_eq!(a.len(), first + 2 * 16);
    }

    #[test]
    fn aaaa_is_nodata_and_errors_have_codes() {
        let msg = query("echo.test", TYPE_AAAA);
        let q = parse(&msg).unwrap();
        let a = answer(&q, Rcode::NoError, &[Ipv4Addr::new(10, 0, 0, 1)]);
        assert_eq!((u16_at(&a, 2), u16_at(&a, 6)), (Some(0x8180), Some(0)));
        let nx = answer(&q, Rcode::NxDomain, &[]);
        assert_eq!(u16_at(&nx, 2), Some(0x8183));
    }

    #[test]
    fn malformed() {
        assert_eq!(parse(&[1]), Err(None));
        let mut msg = query("a.b", TYPE_A);
        msg.truncate(15);
        assert_eq!(parse(&msg), Err(Some((0x1234, Rcode::FormErr))));
        let mut resp = query("a.b", TYPE_A);
        resp[2] |= 0x80;
        assert_eq!(parse(&resp), Err(None));
        assert_eq!(failure(7, Rcode::FormErr), vec![0, 7, 0x80, 0x81, 0, 0, 0, 0, 0, 0, 0, 0]);
    }
}
