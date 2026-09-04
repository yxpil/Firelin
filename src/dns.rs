//! Minimal hand-rolled UDP DNS client (A records only).
//!
//! Builds standard RFC 1035 query packets and parses responses (including
//! name-compression pointers) with no external crate. Each query is a single
//! UDP datagram with a short read timeout — good enough for a subdomain
//! brute-force loop, deliberately not a general-purpose resolver.

use anyhow::{bail, Result};
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const TYPE_A: u16 = 1;
const CLASS_IN: u16 = 1;

/// Build a recursive A-record query for `name`.
pub fn build_query(id: u16, name: &str) -> Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(64);
    buf.extend_from_slice(&id.to_be_bytes());
    // flags: RD=1; counts: QDCOUNT=1
    buf.extend_from_slice(&[0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    let mut labels = 0;
    for label in name.split('.') {
        if label.is_empty() {
            continue; // tolerate trailing dot
        }
        if label.len() > 63 {
            bail!("DNS name '{name}' has a label longer than 63 bytes");
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            bail!("DNS name '{name}' contains invalid characters in label '{label}'");
        }
        buf.push(label.len() as u8);
        buf.extend_from_slice(label.as_bytes());
        labels += 1;
    }
    if labels == 0 {
        bail!("DNS name '{name}' is empty");
    }
    buf.push(0); // root label
    buf.extend_from_slice(&TYPE_A.to_be_bytes());
    buf.extend_from_slice(&CLASS_IN.to_be_bytes());
    Ok(buf)
}

/// A parsed DNS response: the RCODE and any IPv4 addresses from A records.
pub struct DnsResponse {
    pub rcode: u8,
    pub ips: Vec<Ipv4Addr>,
}

/// Parse a DNS response message and collect A-record addresses.
pub fn parse_response(msg: &[u8]) -> Result<DnsResponse> {
    if msg.len() < 12 {
        bail!("truncated DNS response ({} bytes)", msg.len());
    }
    let rcode = msg[3] & 0x0F;
    let qdcount = u16::from_be_bytes([msg[4], msg[5]]);
    let ancount = u16::from_be_bytes([msg[6], msg[7]]);
    let mut pos = 12usize;
    for _ in 0..qdcount {
        skip_name(msg, &mut pos)?;
        pos += 4; // QTYPE + QCLASS
    }
    let mut ips = Vec::new();
    for _ in 0..ancount {
        skip_name(msg, &mut pos)?;
        if pos + 10 > msg.len() {
            break; // truncated answer; keep what we have
        }
        let rtype = u16::from_be_bytes([msg[pos], msg[pos + 1]]);
        let rdlength = u16::from_be_bytes([msg[pos + 8], msg[pos + 9]]) as usize;
        pos += 10;
        if rtype == TYPE_A && rdlength == 4 && pos + 4 <= msg.len() {
            ips.push(Ipv4Addr::new(
                msg[pos],
                msg[pos + 1],
                msg[pos + 2],
                msg[pos + 3],
            ));
        }
        pos += rdlength;
    }
    Ok(DnsResponse { rcode, ips })
}

/// Skip a (possibly compressed) domain name.
fn skip_name(msg: &[u8], pos: &mut usize) -> Result<()> {
    loop {
        let Some(&len) = msg.get(*pos) else {
            bail!("truncated DNS name");
        };
        if len == 0 {
            *pos += 1;
            return Ok(());
        }
        if len & 0xC0 == 0xC0 {
            if *pos + 2 > msg.len() {
                bail!("truncated DNS compression pointer");
            }
            *pos += 2;
            return Ok(());
        }
        *pos += 1 + len as usize;
    }
}

fn next_id() -> u16 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    nanos as u16 ^ (nanos >> 16) as u16
}

/// Resolve `name` to its A records via one UDP query to `resolver`.
/// A non-zero RCODE (e.g. NXDOMAIN) yields an empty list, not an error.
/// Errors mean "no answer obtained" (timeout, malformed reply, id mismatch).
pub fn resolve_a(resolver: SocketAddr, name: &str, timeout: Duration) -> Result<Vec<Ipv4Addr>> {
    let id = next_id();
    let query = build_query(id, name)?;
    let bind_addr = if resolver.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = UdpSocket::bind(bind_addr)?;
    socket.connect(resolver)?;
    socket.set_read_timeout(Some(timeout))?;
    socket.set_write_timeout(Some(timeout))?;
    socket.send(&query)?;
    let mut buf = [0u8; 1024];
    let n = socket.recv(&mut buf)?; // Err on timeout -> caller treats as "no record"
    let response = parse_response(&buf[..n])?;
    if buf[..2] != id.to_be_bytes() {
        bail!("mismatched DNS transaction id");
    }
    if response.rcode != 0 {
        return Ok(Vec::new()); // NXDOMAIN / SERVFAIL / ... -> no A record
    }
    Ok(response.ips)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_valid_query_wire_format() {
        let q = build_query(0x1234, "www.example.com").unwrap();
        assert_eq!(&q[..2], &[0x12, 0x34]);
        assert_eq!(&q[2..4], &[0x01, 0x00]); // RD set
        assert_eq!(&q[4..6], &[0x00, 0x01]); // QDCOUNT 1
        assert_eq!(q[12], 3);
        assert_eq!(&q[13..16], b"www");
        assert_eq!(q[16], 7);
        assert_eq!(&q[17..24], b"example");
        assert_eq!(q[24], 3);
        assert_eq!(&q[25..28], b"com");
        assert_eq!(q[28], 0);
        assert_eq!(&q[29..33], &[0, 1, 0, 1]); // A / IN
    }

    #[test]
    fn rejects_bad_names() {
        assert!(build_query(1, "").is_err());
        assert!(build_query(1, "a b.c").is_err());
        let long = "a".repeat(64);
        assert!(build_query(1, &long).is_err());
    }

    #[test]
    fn parses_response_with_compression_pointer() {
        // header + question (www.test) + answer pointing back at offset 12
        let mut msg = vec![0xAB, 0xCD, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
        msg.extend_from_slice(&[3, b'w', b'w', b'w', 4, b't', b'e', b's', b't', 0]);
        msg.extend_from_slice(&[0, 1, 0, 1]); // QTYPE A, QCLASS IN
        msg.extend_from_slice(&[0xC0, 0x0C]); // pointer to offset 12
        msg.extend_from_slice(&[0, 1, 0, 1]); // TYPE A, CLASS IN
        msg.extend_from_slice(&[0, 0, 0, 60]); // TTL 60
        msg.extend_from_slice(&[0, 4]); // RDLENGTH 4
        msg.extend_from_slice(&[93, 184, 216, 34]);
        let parsed = parse_response(&msg).unwrap();
        assert_eq!(parsed.rcode, 0);
        assert_eq!(parsed.ips, vec![Ipv4Addr::new(93, 184, 216, 34)]);
    }

    #[test]
    fn parses_nxdomain_rcode() {
        let msg = [
            0xAB, 0xCD, 0x81, 0x83, 0, 1, 0, 0, 0, 0, 0, 0, 3, b'w', b'w', b'w', 0, 0, 1, 0, 1,
        ];
        let parsed = parse_response(&msg).unwrap();
        assert_eq!(parsed.rcode, 3);
        assert!(parsed.ips.is_empty());
    }

    #[test]
    fn rejects_truncated_response() {
        assert!(parse_response(&[0, 1, 2]).is_err());
    }

    /// A tiny UDP responder that answers `www.*` with 93.184.216.34 and
    /// everything else with NXDOMAIN (rcode 3).
    fn spawn_mock_resolver() -> SocketAddr {
        use std::net::UdpSocket;
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = socket.local_addr().unwrap();
        std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            while let Ok((n, src)) = socket.recv_from(&mut buf) {
                if n < 12 {
                    continue;
                }
                let mut resp = buf[..12].to_vec();
                resp[2] = 0x81; // QR + RD
                                // find the first label and the end of the question name
                let first_len = buf[12] as usize;
                let first_label = &buf[13..13 + first_len];
                let mut pos = 12;
                while pos < n && buf[pos] != 0 {
                    pos += 1 + buf[pos] as usize;
                }
                pos += 1 + 4; // root byte + QTYPE + QCLASS
                resp.extend_from_slice(&buf[12..pos.min(n)]);
                if first_label == b"www" {
                    resp[3] = 0x80; // rcode 0
                    resp[7] = 0x01; // ANCOUNT 1
                    resp.extend_from_slice(&[0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
                    resp.extend_from_slice(&[93, 184, 216, 34]);
                } else {
                    resp[3] = 0x83; // rcode 3 (NXDOMAIN)
                }
                let _ = socket.send_to(&resp, src);
            }
        });
        addr
    }

    #[test]
    fn resolve_a_against_mock_resolver() {
        let resolver = spawn_mock_resolver();
        let ips = resolve_a(resolver, "www.example.test", Duration::from_secs(2)).unwrap();
        assert_eq!(ips, vec![Ipv4Addr::new(93, 184, 216, 34)]);
        let none = resolve_a(resolver, "nope.example.test", Duration::from_secs(2)).unwrap();
        assert!(none.is_empty(), "NXDOMAIN must yield no addresses");
    }
}
