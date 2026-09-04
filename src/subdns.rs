//! DNS subdomain enumeration: candidate labels (builtin or file wordlist)
//! are resolved as A records against a single UDP resolver with a worker
//! pool. Output lists alive subdomains with their addresses.

use crate::dns;
use anyhow::{Context, Result};
use serde::Serialize;
use std::collections::BTreeMap;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Per-query DNS read timeout (not user-configurable in v0.1; keep short).
const QUERY_TIMEOUT_MS: u64 = 2000;

#[derive(Serialize, Clone)]
pub struct SubdomainHit {
    pub subdomain: String,
    pub ips: Vec<String>,
}

#[derive(Serialize)]
pub struct SubdnsResult {
    pub domain: String,
    pub resolver: String,
    pub queried: usize,
    /// Queries that produced no usable answer (timeout, malformed reply).
    pub errors: usize,
    pub found: Vec<SubdomainHit>,
    pub duration_ms: u64,
}

/// Parse a resolver spec like `8.8.8.8:53` (default port 53 when omitted).
pub fn parse_resolver(spec: &str) -> Result<SocketAddr> {
    let spec = spec.trim();
    if spec.contains(':') {
        let addr: SocketAddr = spec
            .parse()
            .with_context(|| format!("invalid resolver '{spec}' (expected 'ip:port')"))?;
        return Ok(addr);
    }
    let mut addrs = (spec, 53u16)
        .to_socket_addrs()
        .with_context(|| format!("failed to resolve resolver host '{spec}'"))?;
    addrs
        .next()
        .ok_or_else(|| anyhow::anyhow!("resolver '{spec}' resolved to no addresses"))
}

/// Run the enumeration. Infallible; individual query failures are counted in
/// `errors` instead of aborting the run.
pub fn enumerate(
    domain: &str,
    candidates: &[String],
    resolver: SocketAddr,
    concurrency: usize,
) -> SubdnsResult {
    let started = Instant::now();
    let domain = domain.trim().trim_end_matches('.').to_string();
    let queue: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(candidates.to_vec()));
    let hits = Arc::new(Mutex::new(BTreeMap::<String, Vec<String>>::new()));
    let errors = Arc::new(AtomicUsize::new(0));
    let workers = concurrency.clamp(1, 512);
    let timeout = Duration::from_millis(QUERY_TIMEOUT_MS);

    let mut handles = Vec::with_capacity(workers);
    for _ in 0..workers {
        let queue = Arc::clone(&queue);
        let hits = Arc::clone(&hits);
        let errors = Arc::clone(&errors);
        let domain = domain.clone();
        handles.push(std::thread::spawn(move || loop {
            let candidate = {
                let mut q = match queue.lock() {
                    Ok(q) => q,
                    Err(poisoned) => poisoned.into_inner(),
                };
                q.pop()
            };
            let Some(candidate) = candidate else { break };
            let name = if candidate.contains('.') {
                candidate.clone()
            } else {
                format!("{candidate}.{domain}")
            };
            match dns::resolve_a(resolver, &name, timeout) {
                Ok(ips) if !ips.is_empty() => {
                    let ips: Vec<String> = ips.iter().map(|ip| ip.to_string()).collect();
                    hits.lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .insert(name, ips);
                }
                Ok(_) => {}
                Err(_) => {
                    errors.fetch_add(1, Ordering::Relaxed);
                }
            }
        }));
    }
    for handle in handles {
        let _ = handle.join();
    }
    let found: BTreeMap<String, Vec<String>> = Arc::try_unwrap(hits)
        .map(|m| m.into_inner().unwrap_or_default())
        .unwrap_or_default();
    let found = found
        .into_iter()
        .map(|(subdomain, ips)| SubdomainHit { subdomain, ips })
        .collect();
    SubdnsResult {
        domain,
        resolver: resolver.to_string(),
        queried: candidates.len(),
        errors: errors.load(Ordering::Relaxed),
        found,
        duration_ms: started.elapsed().as_millis() as u64,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_resolver_specs() {
        assert_eq!(
            parse_resolver("8.8.8.8:53").unwrap(),
            "8.8.8.8:53".parse().unwrap()
        );
        assert_eq!(
            parse_resolver("127.0.0.1").unwrap(),
            "127.0.0.1:53".parse().unwrap()
        );
        assert!(parse_resolver("999.1.1.1:53").is_err());
        assert!(parse_resolver("nope.invalid:53").is_err());
    }

    #[test]
    fn enumerates_against_mock_resolver() {
        // reuse the mock UDP responder from the dns module's tests
        let resolver = mock_resolver_socket();
        let candidates = vec!["www".to_string(), "nope".to_string(), "mail".to_string()];
        let result = enumerate("example.test", &candidates, resolver, 3);
        assert_eq!(result.queried, 3);
        assert_eq!(result.errors, 0);
        let names: Vec<&str> = result.found.iter().map(|h| h.subdomain.as_str()).collect();
        assert!(names.contains(&"www.example.test"), "{names:?}");
        assert!(
            !names.contains(&"nope.example.test"),
            "NXDOMAIN must not be listed"
        );
        let www = result
            .found
            .iter()
            .find(|h| h.subdomain == "www.example.test")
            .unwrap();
        assert_eq!(www.ips, vec!["93.184.216.34"]);
    }

    /// Same mock responder as in `dns::tests` (tests cannot share helpers
    /// across modules without making them public).
    fn mock_resolver_socket() -> SocketAddr {
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
                resp[2] = 0x81;
                let first_len = buf[12] as usize;
                let first_label = &buf[13..13 + first_len];
                let mut pos = 12;
                while pos < n && buf[pos] != 0 {
                    pos += 1 + buf[pos] as usize;
                }
                pos += 1 + 4;
                resp.extend_from_slice(&buf[12..pos.min(n)]);
                if first_label == b"www" || first_label == b"mail" {
                    resp[3] = 0x80;
                    resp[7] = 0x01;
                    resp.extend_from_slice(&[0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
                    resp.extend_from_slice(&[93, 184, 216, 34]);
                } else {
                    resp[3] = 0x83;
                }
                let _ = socket.send_to(&resp, src);
            }
        });
        addr
    }
}
