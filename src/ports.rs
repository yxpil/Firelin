//! Port specification parsing: comma-separated single ports and inclusive
//! ranges, e.g. `"22,80,1000-2000"`. Duplicates removed, output sorted.

use anyhow::{bail, Result};

/// Parse a port specification string into a sorted, deduplicated list of
/// ports. Port 0 is rejected; every item must be in 1-65535.
pub fn parse_ports(spec: &str) -> Result<Vec<u16>> {
    let spec = spec.trim();
    if spec.is_empty() {
        bail!("empty port specification (expected e.g. '1-1024' or '22,80,443')");
    }
    let mut out = Vec::new();
    for item in spec.split(',') {
        let item = item.trim();
        let invalid = || {
            anyhow::anyhow!(
                "invalid port item '{item}' in '{spec}' (expected 1-65535, ranges 'a-b')"
            )
        };
        if item.is_empty() {
            bail!("empty port item in '{spec}'");
        }
        if let Some((start_s, end_s)) = item.split_once('-') {
            let start: u16 = start_s.trim().parse().map_err(|_| invalid())?;
            let end: u16 = end_s.trim().parse().map_err(|_| invalid())?;
            if start == 0 || end == 0 {
                bail!("port 0 is not a valid target: '{item}'");
            }
            if start > end {
                bail!("invalid port range '{item}': start > end");
            }
            out.extend(start..=end);
        } else {
            let port: u16 = item.parse().map_err(|_| invalid())?;
            if port == 0 {
                bail!("port 0 is not a valid target: '{item}'");
            }
            out.push(port);
        }
    }
    out.sort_unstable();
    out.dedup();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ranges_and_lists() {
        assert_eq!(parse_ports("80").unwrap(), vec![80]);
        assert_eq!(parse_ports("80,443").unwrap(), vec![80, 443]);
        assert_eq!(
            parse_ports("8080-8083").unwrap(),
            vec![8080, 8081, 8082, 8083]
        );
        assert_eq!(parse_ports("443,80,80-81").unwrap(), vec![80, 81, 443]);
        assert_eq!(
            parse_ports(" 22 , 80 , 100-102 ").unwrap(),
            vec![22, 80, 100, 101, 102]
        );
        // full range is allowed
        assert_eq!(parse_ports("1-65535").unwrap().len(), 65535);
    }

    #[test]
    fn rejects_invalid_specs() {
        for spec in [
            "", "   ", "0", "70000", "-5", "80-70", "abc", "1,,2", "1-2,0", "80,", ",80",
        ] {
            assert!(parse_ports(spec).is_err(), "'{spec}' must be rejected");
        }
    }
}
