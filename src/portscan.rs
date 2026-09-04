//! TCP connect scanner: worker-thread pool over (host, port) pairs with a
//! per-connection timeout. Conservative defaults (200 concurrent connects,
//! 800 ms timeout) keep it polite on authorized internal networks.

use crate::cidr;
use anyhow::{bail, Result};
use serde::Serialize;
use std::collections::BTreeSet;
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Serialize, Clone, Debug)]
pub struct OpenPort {
    pub host: IpAddr,
    pub port: u16,
    /// Connect time in milliseconds.
    pub ms: u64,
}

#[derive(Serialize, Debug)]
pub struct PortScanResult {
    pub target: String,
    pub hosts: usize,
    pub ports: usize,
    /// Total (host, port) pairs attempted.
    pub scanned: usize,
    pub open: Vec<OpenPort>,
    pub duration_ms: u64,
}

/// Resolve the `TARGET` argument into a list of IP addresses.
/// Accepts a single IP, a hostname (all resolved addresses are used) or an
/// IPv4 CIDR (expanded with the size limit; `/16` and larger are rejected).
pub fn resolve_targets(target: &str) -> Result<Vec<IpAddr>> {
    let target = target.trim();
    if target.contains('/') {
        let list = cidr::parse_and_expand(target)?;
        return Ok(list.into_iter().map(IpAddr::V4).collect());
    }
    if target.is_empty() {
        bail!("empty target");
    }
    if let Ok(ip) = target.parse::<IpAddr>() {
        return Ok(vec![ip]);
    }
    let mut ips = Vec::new();
    for addr in (target, 0u16).to_socket_addrs()? {
        ips.push(addr.ip());
    }
    ips.sort();
    ips.dedup();
    if ips.is_empty() {
        bail!("could not resolve hostname '{target}'");
    }
    Ok(ips)
}

/// Run the scan. Infallible once targets/ports are resolved; connection
/// failures simply mean "closed or filtered" and are not reported.
pub fn scan(
    target: &str,
    targets: Vec<IpAddr>,
    ports: Vec<u16>,
    concurrency: usize,
    timeout_ms: u64,
) -> PortScanResult {
    let started = Instant::now();
    // (host, port) work queue, popped from the end by the worker pool.
    let mut queue = Vec::with_capacity(targets.len() * ports.len());
    let port_set: BTreeSet<u16> = ports.iter().copied().collect();
    for host in &targets {
        for port in &port_set {
            queue.push((*host, *port));
        }
    }
    let scanned = queue.len();
    let queue = Arc::new(Mutex::new(queue));
    let open = Arc::new(Mutex::new(Vec::<OpenPort>::new()));
    let timeout = Duration::from_millis(timeout_ms);
    let workers = concurrency.clamp(1, 4096);

    let mut handles = Vec::with_capacity(workers);
    for _ in 0..workers {
        let queue = Arc::clone(&queue);
        let open = Arc::clone(&open);
        handles.push(std::thread::spawn(move || loop {
            let job = {
                let mut q = match queue.lock() {
                    Ok(q) => q,
                    Err(poisoned) => poisoned.into_inner(),
                };
                q.pop()
            };
            let Some((host, port)) = job else { break };
            let started = Instant::now();
            if TcpStream::connect_timeout(&SocketAddr::new(host, port), timeout).is_ok() {
                open.lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .push(OpenPort {
                        host,
                        port,
                        ms: started.elapsed().as_millis() as u64,
                    });
            }
        }));
    }
    for handle in handles {
        let _ = handle.join();
    }
    let mut open = Arc::try_unwrap(open)
        .map(|m| m.into_inner().unwrap_or_default())
        .unwrap_or_default();
    open.sort_by_key(|p| (p.host, p.port));
    PortScanResult {
        target: target.to_string(),
        hosts: targets.len(),
        ports: port_set.len(),
        scanned,
        open,
        duration_ms: started.elapsed().as_millis() as u64,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_single_ip_hostname_and_rejects_bad() {
        assert_eq!(
            resolve_targets("127.0.0.1").unwrap(),
            vec![IpAddr::from([127, 0, 0, 1])]
        );
        // /30 expansion
        let list = resolve_targets("127.0.0.0/30").unwrap();
        assert_eq!(list.len(), 4);
        // hostname resolution (localhost always resolves)
        let list = resolve_targets("localhost").unwrap();
        assert!(!list.is_empty());
        assert!(resolve_targets("this-host-does-not-exist-firelin.invalid").is_err());
        assert!(resolve_targets("999.1.1.1").is_err());
        assert!(resolve_targets("").is_err());
    }

    #[test]
    fn rejects_oversized_cidr_targets() {
        let err = resolve_targets("10.0.0.0/8").unwrap_err().to_string();
        assert!(err.contains("too large"), "{err}");
        let err = resolve_targets("192.168.0.0/16").unwrap_err().to_string();
        assert!(err.contains("too large"), "{err}");
    }

    #[test]
    fn finds_open_and_skips_closed_ports() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let open_port = listener.local_addr().unwrap().port();
        // a port that is (almost certainly) closed: bind, note, drop
        let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let closed_port = closed.local_addr().unwrap().port();
        drop(closed);
        std::thread::sleep(Duration::from_millis(50));

        let result = scan(
            "127.0.0.1",
            vec![IpAddr::from([127, 0, 0, 1])],
            vec![open_port, closed_port],
            8,
            500,
        );
        assert_eq!(result.scanned, 2);
        assert_eq!(result.open.len(), 1, "{:?}", result.open);
        assert_eq!(result.open[0].port, open_port);
        assert_eq!(result.open[0].host, IpAddr::from([127, 0, 0, 1]));
        assert!(result.open[0].ms <= 500);
    }
}
