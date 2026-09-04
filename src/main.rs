//! Firelin — agent-oriented network penetration testing toolkit (BIT ecosystem).
//!
//! Subcommands: `portscan`, `subdns`, `dirscan` (authorization-gated active
//! scanning), `fingerprint`, `cidr` (read-only helpers) and `serve` (BIT
//! Remote-protocol HTTP API on 127.0.0.1:8755 by default).

mod auth;
mod cidr;
mod dirscan;
mod dns;
mod fingerprint;
mod ports;
mod portscan;
mod serve;
mod subdns;
mod wordlist;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use serde_json::{json, Value};
use std::io::{IsTerminal, Read};

/// Keys accepted in the piped-stdin JSON object (BIT exec contract). Unknown
/// keys produce a warning on stderr and are ignored.
const KNOWN_STDIN_KEYS: &[&str] = &[
    "target",
    "domain",
    "url",
    "cidr",
    "ports",
    "concurrency",
    "timeout_ms",
    "wordlist",
    "resolver",
    "follow_redirects",
    "host",
    "port",
    "token",
    "yes_i_have_permission",
];

#[derive(Parser)]
#[command(
    name = "firelin",
    version,
    about = "Agent-oriented network penetration testing toolkit for the BIT ecosystem (authorized use only)",
    long_about = "Firelin gives AI agents (especially BIT) building blocks for authorized network security \
assessments: TCP port scanning, DNS subdomain enumeration, directory enumeration and HTTP fingerprinting.\n\n\
Scan commands (portscan / subdns / dirscan) require an explicit authorization confirmation: pass \
--yes-i-have-permission or set FIRELIN_I_HAVE_PERMISSION=yes. Use Firelin only on systems you own \
or are permitted in writing to test."
)]
struct Cli {
    /// Emit machine-readable JSON on stdout
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// TCP connect scan a host, IP or CIDR (requires authorization)
    Portscan {
        /// Single IP, hostname or IPv4 CIDR (e.g. 192.168.1.0/24)
        target: Option<String>,
        /// Ports to scan: comma list and/or ranges (e.g. "22,80,1000-2000")
        #[arg(long, value_name = "SPEC", default_value = "1-1024")]
        ports: String,
        /// Parallel connections
        #[arg(long, value_name = "N", default_value_t = 200)]
        concurrency: usize,
        /// Per-connection timeout in milliseconds
        #[arg(long, value_name = "MS", default_value_t = 800)]
        timeout_ms: u64,
        /// Confirm you own the target or have written permission to test it
        #[arg(long)]
        yes_i_have_permission: bool,
    },
    /// DNS subdomain enumeration via A-record queries (requires authorization)
    Subdns {
        /// Base domain to enumerate (e.g. example.com)
        domain: Option<String>,
        /// 'builtin' or a path to a wordlist file (one entry per line)
        #[arg(long, value_name = "SPEC", default_value = "builtin")]
        wordlist: String,
        /// UDP resolver address ("ip:port", port defaults to 53)
        #[arg(long, value_name = "ADDR", default_value = "8.8.8.8:53")]
        resolver: String,
        /// Parallel DNS queries
        #[arg(long, value_name = "N", default_value_t = 50)]
        concurrency: usize,
        /// Confirm you own the target or have written permission to test it
        #[arg(long)]
        yes_i_have_permission: bool,
    },
    /// Directory/path enumeration against a base URL (requires authorization)
    Dirscan {
        /// Base URL (http:// or https://)
        url: Option<String>,
        /// 'builtin' or a path to a wordlist file (one entry per line)
        #[arg(long, value_name = "SPEC", default_value = "builtin")]
        wordlist: String,
        /// Parallel requests
        #[arg(long, value_name = "N", default_value_t = 20)]
        concurrency: usize,
        /// Per-request timeout in milliseconds
        #[arg(long, value_name = "MS", default_value_t = 3000)]
        timeout_ms: u64,
        /// Follow 3xx redirects (classification then reflects the target page)
        #[arg(long)]
        follow_redirects: bool,
        /// Confirm you own the target or have written permission to test it
        #[arg(long)]
        yes_i_have_permission: bool,
    },
    /// Single-target HTTP fingerprint (read-only, no authorization needed)
    Fingerprint {
        /// Target URL (http:// or https://)
        url: Option<String>,
        /// Request timeout in milliseconds
        #[arg(long, value_name = "MS", default_value_t = 5000)]
        timeout_ms: u64,
    },
    /// Expand an IPv4 CIDR into its address list (pure computation)
    Cidr {
        /// IPv4 CIDR (e.g. 192.168.1.0/24); /16 and larger are rejected
        cidr: Option<String>,
    },
    /// Run the HTTP API (BIT Remote tool compatible), default port 8755
    Serve {
        /// Bind host
        #[arg(long, value_name = "HOST", default_value = "127.0.0.1")]
        host: String,
        /// Bind port
        #[arg(long, value_name = "PORT", default_value_t = 8755)]
        port: u16,
        /// Require 'Authorization: Bearer <token>' on /invoke and /invoke-actions
        #[arg(long, value_name = "TOKEN")]
        token: Option<String>,
        /// Unlock scan actions for this server (otherwise they answer 403)
        #[arg(long)]
        yes_i_have_permission: bool,
    },
}

fn main() {
    let mut cli = Cli::parse();
    let stdin_overrides = read_stdin_overrides();
    if let Some(value) = &stdin_overrides {
        apply_cli_overrides(&mut cli, value);
    }
    match run(cli) {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("error: {e:#}");
            std::process::exit(2);
        }
    }
}

fn run(cli: Cli) -> Result<i32> {
    match cli.command {
        Command::Portscan {
            target,
            ports,
            concurrency,
            timeout_ms,
            yes_i_have_permission,
        } => {
            if !auth::confirmed(yes_i_have_permission) {
                return Ok(denied("portscan", cli.json));
            }
            let target = require(target, "TARGET")?;
            let targets = portscan::resolve_targets(&target)?;
            let ports_list = ports::parse_ports(&ports)?;
            eprintln!(
                "scanning {} host(s) x {} port(s) (concurrency {concurrency}, timeout {timeout_ms} ms)",
                targets.len(),
                ports_list.len()
            );
            let result = portscan::scan(&target, targets, ports_list, concurrency, timeout_ms);
            print_portscan(&result, cli.json);
            Ok(0)
        }
        Command::Subdns {
            domain,
            wordlist,
            resolver,
            concurrency,
            yes_i_have_permission,
        } => {
            if !auth::confirmed(yes_i_have_permission) {
                return Ok(denied("subdns", cli.json));
            }
            let domain = require(domain, "DOMAIN")?;
            let candidates = wordlist::load(&wordlist, wordlist::SUBDOMAINS)?;
            let resolver_addr = subdns::parse_resolver(&resolver)?;
            eprintln!(
                "resolving {} candidate(s) against {resolver_addr} (concurrency {concurrency})",
                candidates.len()
            );
            let result = subdns::enumerate(&domain, &candidates, resolver_addr, concurrency);
            if result.errors > 0 {
                eprintln!(
                    "warning: {} query(ies) produced no usable answer (timeout or resolver error)",
                    result.errors
                );
            }
            print_subdns(&result, cli.json);
            Ok(0)
        }
        Command::Dirscan {
            url,
            wordlist,
            concurrency,
            timeout_ms,
            follow_redirects,
            yes_i_have_permission,
        } => {
            if !auth::confirmed(yes_i_have_permission) {
                return Ok(denied("dirscan", cli.json));
            }
            let url = require(url, "URL")?;
            dirscan::validate_base_url(&url)?;
            let paths = wordlist::load(&wordlist, wordlist::PATHS)?;
            eprintln!(
                "probing {} path(s) on {url} (concurrency {concurrency}, timeout {timeout_ms} ms)",
                paths.len()
            );
            let result = dirscan::scan(&url, &paths, concurrency, timeout_ms, follow_redirects);
            if result.errors > 0 {
                eprintln!(
                    "warning: {} request(s) failed (connection error or timeout)",
                    result.errors
                );
            }
            print_dirscan(&result, cli.json);
            Ok(0)
        }
        Command::Fingerprint { url, timeout_ms } => {
            let url = require(url, "URL")?;
            let result = fingerprint::fingerprint(&url, timeout_ms)?;
            print_fingerprint(&result, cli.json);
            Ok(0)
        }
        Command::Cidr { cidr: spec } => {
            let spec = require(spec, "CIDR")?;
            let parsed = cidr::parse_cidr(&spec)?;
            let addresses = cidr::expand(&parsed)?;
            print_cidr(&spec, &parsed, &addresses, cli.json);
            Ok(0)
        }
        Command::Serve {
            host,
            port,
            token,
            yes_i_have_permission,
        } => {
            let scan_authorized = auth::confirmed(yes_i_have_permission);
            if !scan_authorized {
                eprintln!("note: scan actions are disabled; restart with {} (or set {}=yes) to enable them", auth::PERMISSION_FLAG, auth::PERMISSION_ENV);
            }
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .context("failed to build tokio runtime")?;
            runtime.block_on(serve::run(host, port, token, scan_authorized))?;
            Ok(0)
        }
    }
}

/// Exit path for refused scan commands: notice on stderr, JSON error on
/// stdout in --json mode, exit code 2.
fn denied(command: &str, json: bool) -> i32 {
    eprintln!("{}", auth::NOTICE);
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "error": "authorization_required",
                "message": auth::denial_message(command),
                "how_to_confirm": {
                    "flag": auth::PERMISSION_FLAG,
                    "env": format!("{}=yes", auth::PERMISSION_ENV),
                }
            }))
            .unwrap_or_default()
        );
    } else {
        eprintln!("error: {}", auth::denial_message(command));
    }
    2
}

fn require(value: Option<String>, name: &str) -> Result<String> {
    value.ok_or_else(|| {
        anyhow::anyhow!("missing required argument {name} — pass it on the command line or via piped stdin JSON")
    })
}

// ---- stdout printers (text mode) ----------------------------------------

fn print_portscan(result: &portscan::PortScanResult, json: bool) {
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(result).unwrap_or_default()
        );
        return;
    }
    for p in &result.open {
        println!("open  {}:{} ({} ms)", p.host, p.port, p.ms);
    }
    println!(
        "{} target(s) scanned ({} host(s) x {} port(s)), {} open, {} ms",
        result.scanned,
        result.hosts,
        result.ports,
        result.open.len(),
        result.duration_ms
    );
}

fn print_subdns(result: &subdns::SubdnsResult, json: bool) {
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(result).unwrap_or_default()
        );
        return;
    }
    for hit in &result.found {
        println!("found {} -> {}", hit.subdomain, hit.ips.join(", "));
    }
    println!(
        "{} found / {} queried ({} error(s)), {} ms",
        result.found.len(),
        result.queried,
        result.errors,
        result.duration_ms
    );
}

fn print_dirscan(result: &dirscan::DirScanResult, json: bool) {
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(result).unwrap_or_default()
        );
        return;
    }
    for r in &result.results {
        println!(
            "[{:>9}] {} {} ({} ms)",
            r.classification, r.status, r.path, r.ms
        );
    }
    println!(
        "{} path(s) scanned, {} reported, {} error(s), {} ms",
        result.scanned,
        result.results.len(),
        result.errors,
        result.duration_ms
    );
}

fn print_fingerprint(result: &fingerprint::Fingerprint, json: bool) {
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(result).unwrap_or_default()
        );
        return;
    }
    println!("url: {}", result.url);
    if result.final_url != result.url {
        println!("final_url: {}", result.final_url);
    }
    println!("status: {}", result.status);
    if let Some(v) = &result.server {
        println!("server: {v}");
    }
    if let Some(v) = &result.powered_by {
        println!("x-powered-by: {v}");
    }
    if let Some(v) = &result.aspnet_version {
        println!("x-aspnet-version: {v}");
    }
    if let Some(v) = &result.generator {
        println!("x-generator: {v}");
    }
    if let Some(t) = &result.title {
        println!("title: {t}");
    }
    println!("generated_at: {}", result.generated_at);
    println!("duration_ms: {}", result.duration_ms);
}

fn print_cidr(spec: &str, parsed: &cidr::ParsedCidr, addresses: &[std::net::Ipv4Addr], json: bool) {
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "cidr": spec,
                "network": parsed.network.to_string(),
                "prefix": parsed.prefix,
                "count": addresses.len(),
                "addresses": addresses.iter().map(|ip| ip.to_string()).collect::<Vec<_>>(),
            }))
            .unwrap_or_default()
        );
        return;
    }
    for ip in addresses {
        println!("{ip}");
    }
    println!("{} address(es) in {spec}", addresses.len());
}

// ---- BIT exec-mode stdin contract ----------------------------------------

/// When stdin is piped (not a TTY), read a JSON object and merge it over the
/// CLI args (stdin wins). Non-object or malformed stdin is ignored with a
/// warning.
fn read_stdin_overrides() -> Option<Value> {
    if std::io::stdin().is_terminal() {
        return None;
    }
    let mut buffer = String::new();
    if std::io::stdin().read_to_string(&mut buffer).is_err() {
        return None;
    }
    let trimmed = buffer.trim();
    if trimmed.is_empty() {
        return None;
    }
    match serde_json::from_str::<Value>(trimmed) {
        Ok(value) if value.is_object() => Some(value),
        Ok(_) => {
            eprintln!("warning: stdin JSON must be an object; ignoring");
            None
        }
        Err(e) => {
            eprintln!("warning: failed to parse stdin JSON ({e}); ignoring");
            None
        }
    }
}

fn stdin_flag(value: &Value) -> bool {
    match value.get("yes_i_have_permission") {
        Some(Value::Bool(true)) => true,
        Some(Value::String(s)) => s.eq_ignore_ascii_case("yes") || s == "true" || s == "1",
        _ => false,
    }
}

fn apply_cli_overrides(cli: &mut Cli, value: &Value) {
    if let Some(map) = value.as_object() {
        for key in map.keys() {
            if !KNOWN_STDIN_KEYS.contains(&key.as_str()) {
                eprintln!("warning: ignoring unknown stdin key '{key}'");
            }
        }
    }
    let flag = stdin_flag(value);
    match &mut cli.command {
        Command::Portscan {
            target,
            ports,
            concurrency,
            timeout_ms,
            yes_i_have_permission,
        } => {
            if let Some(t) = value.get("target").and_then(Value::as_str) {
                *target = Some(t.to_string());
            }
            if let Some(p) = value.get("ports").and_then(Value::as_str) {
                *ports = p.to_string();
            }
            if let Some(c) = value.get("concurrency").and_then(Value::as_u64) {
                if let Ok(c) = usize::try_from(c) {
                    *concurrency = c;
                }
            }
            if let Some(t) = value.get("timeout_ms").and_then(Value::as_u64) {
                *timeout_ms = t;
            }
            if flag {
                *yes_i_have_permission = true;
            }
        }
        Command::Subdns {
            domain,
            wordlist,
            resolver,
            concurrency,
            yes_i_have_permission,
        } => {
            if let Some(d) = value.get("domain").and_then(Value::as_str) {
                *domain = Some(d.to_string());
            }
            if let Some(w) = value.get("wordlist").and_then(Value::as_str) {
                *wordlist = w.to_string();
            }
            if let Some(r) = value.get("resolver").and_then(Value::as_str) {
                *resolver = r.to_string();
            }
            if let Some(c) = value.get("concurrency").and_then(Value::as_u64) {
                if let Ok(c) = usize::try_from(c) {
                    *concurrency = c;
                }
            }
            if flag {
                *yes_i_have_permission = true;
            }
        }
        Command::Dirscan {
            url,
            wordlist,
            concurrency,
            timeout_ms,
            follow_redirects,
            yes_i_have_permission,
        } => {
            if let Some(u) = value.get("url").and_then(Value::as_str) {
                *url = Some(u.to_string());
            }
            if let Some(w) = value.get("wordlist").and_then(Value::as_str) {
                *wordlist = w.to_string();
            }
            if let Some(c) = value.get("concurrency").and_then(Value::as_u64) {
                if let Ok(c) = usize::try_from(c) {
                    *concurrency = c;
                }
            }
            if let Some(t) = value.get("timeout_ms").and_then(Value::as_u64) {
                *timeout_ms = t;
            }
            if let Some(Value::Bool(b)) = value.get("follow_redirects") {
                *follow_redirects = *b;
            }
            if flag {
                *yes_i_have_permission = true;
            }
        }
        Command::Fingerprint { url, timeout_ms } => {
            if let Some(u) = value.get("url").and_then(Value::as_str) {
                *url = Some(u.to_string());
            }
            if let Some(t) = value.get("timeout_ms").and_then(Value::as_u64) {
                *timeout_ms = t;
            }
        }
        Command::Cidr { cidr: spec } => {
            if let Some(c) = value
                .get("cidr")
                .and_then(Value::as_str)
                .or_else(|| value.get("target").and_then(Value::as_str))
            {
                *spec = Some(c.to_string());
            }
        }
        Command::Serve {
            host,
            port,
            token,
            yes_i_have_permission,
        } => {
            if let Some(h) = value.get("host").and_then(Value::as_str) {
                *host = h.to_string();
            }
            if let Some(p) = value.get("port").and_then(Value::as_u64) {
                if let Ok(p) = u16::try_from(p) {
                    *port = p;
                }
            }
            if let Some(t) = value.get("token").and_then(Value::as_str) {
                *token = Some(t.to_string());
            }
            if flag {
                *yes_i_have_permission = true;
            }
        }
    }
}
