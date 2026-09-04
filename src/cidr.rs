//! IPv4 CIDR parsing and expansion with a hard size limit so that a typo
//! (`0.0.0.0/0`) can never fan out into millions of scan targets.

use anyhow::{bail, Result};
use std::net::Ipv4Addr;

/// Maximum number of addresses a single CIDR may expand to. `/16` (65536
/// addresses) and larger networks are rejected; the smallest accepted network
/// wider than that is `/17` (32768 addresses).
pub const MAX_ADDRESSES: u64 = 65_535;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParsedCidr {
    pub network: Ipv4Addr,
    pub prefix: u8,
}

/// Parse an IPv4 CIDR string (`192.168.1.0/24`). A bare address without `/`
/// is treated as a `/32`. IPv6 and garbage are rejected with clear errors.
pub fn parse_cidr(input: &str) -> Result<ParsedCidr> {
    let input = input.trim();
    let (addr_part, prefix_part) = match input.split_once('/') {
        Some((a, p)) => (a, Some(p)),
        None => (input, None),
    };
    if addr_part.contains(':') {
        bail!("invalid CIDR '{input}': only IPv4 is supported (e.g. 192.168.1.0/24)");
    }
    let network: Ipv4Addr = addr_part.parse().map_err(|_| {
        anyhow::anyhow!("invalid CIDR '{input}': '{addr_part}' is not a valid IPv4 address")
    })?;
    let prefix: u8 = match prefix_part {
        Some(p) => p.trim().parse().map_err(|_| {
            anyhow::anyhow!("invalid CIDR '{input}': prefix '{p}' is not a number 0-32")
        })?,
        None => 32,
    };
    if prefix > 32 {
        bail!("invalid CIDR '{input}': prefix /{prefix} is out of range (0-32)");
    }
    Ok(ParsedCidr { network, prefix })
}

/// Mask for a prefix length (host bits cleared).
pub fn mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix as u32)
    }
}

/// Expand a parsed CIDR into its address list. Networks larger than
/// [`MAX_ADDRESSES`] (i.e. `/16` and bigger) are rejected as too large.
pub fn expand(parsed: &ParsedCidr) -> Result<Vec<Ipv4Addr>> {
    let total: u64 = if parsed.prefix == 0 {
        1u64 << 32
    } else {
        1u64 << (32 - parsed.prefix as u64)
    };
    if total > MAX_ADDRESSES {
        bail!(
            "CIDR /{} is too large: {total} addresses (max {} to keep scans bounded; use a narrower prefix such as /24)",
            parsed.prefix,
            MAX_ADDRESSES
        );
    }
    let base = u32::from(parsed.network) & mask(parsed.prefix);
    Ok((0..total)
        .map(|offset| Ipv4Addr::from(base + offset as u32))
        .collect())
}

/// Convenience: parse + expand in one call.
pub fn parse_and_expand(input: &str) -> Result<Vec<Ipv4Addr>> {
    expand(&parse_cidr(input)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_cidr_and_bare_address() {
        let parsed = parse_cidr("192.168.1.0/24").unwrap();
        assert_eq!(parsed.network, Ipv4Addr::new(192, 168, 1, 0));
        assert_eq!(parsed.prefix, 24);

        let bare = parse_cidr("10.0.0.5").unwrap();
        assert_eq!(bare.prefix, 32, "bare address is a /32");
        assert_eq!(bare.network, Ipv4Addr::new(10, 0, 0, 5));

        // whitespace tolerated, host bits normalized on expand
        let sloppy = parse_cidr(" 192.168.1.77/24 ").unwrap();
        let list = expand(&sloppy).unwrap();
        assert_eq!(list[0], Ipv4Addr::new(192, 168, 1, 0));
    }

    #[test]
    fn expands_expected_addresses() {
        let list = parse_and_expand("192.168.1.0/30").unwrap();
        assert_eq!(
            list,
            vec![
                Ipv4Addr::new(192, 168, 1, 0),
                Ipv4Addr::new(192, 168, 1, 1),
                Ipv4Addr::new(192, 168, 1, 2),
                Ipv4Addr::new(192, 168, 1, 3),
            ]
        );
        let single = parse_and_expand("10.1.2.3").unwrap();
        assert_eq!(single, vec![Ipv4Addr::new(10, 1, 2, 3)]);
        assert_eq!(parse_and_expand("10.0.0.0/31").unwrap().len(), 2);
    }

    #[test]
    fn rejects_too_large_networks() {
        for spec in ["192.168.0.0/16", "10.0.0.0/8", "0.0.0.0/0", "10.0.0.0/1"] {
            let err = parse_and_expand(spec).unwrap_err().to_string();
            assert!(err.contains("too large"), "'{spec}': {err}");
        }
        // /17 is the widest allowed network
        assert_eq!(parse_and_expand("10.0.0.0/17").unwrap().len(), 32768);
    }

    #[test]
    fn rejects_invalid_input() {
        for spec in [
            "abc",
            "999.1.1.0/24",
            "10.0.0.0/33",
            "10.0.0.0/-1",
            "10.0.0.0/x",
            "10.0.0.0/24/8",
            "::1/128",
            "",
        ] {
            assert!(parse_cidr(spec).is_err(), "'{spec}' must be rejected");
        }
    }
}
