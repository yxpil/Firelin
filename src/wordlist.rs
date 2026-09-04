//! Wordlist support: small, neutral built-in lists plus loading from a file
//! (one entry per line, `#` comments and blank lines ignored).
//!
//! The built-in lists are deliberately compact and generic (no credentials,
//! no exploit paths, nothing attack-specific) — they cover the common
//! naming conventions an authorized assessment starts from.

use anyhow::{bail, Result};

/// Built-in subdomain candidates (~200 common labels).
pub const SUBDOMAINS: &[&str] = &[
    "www",
    "mail",
    "ftp",
    "admin",
    "api",
    "dev",
    "test",
    "staging",
    "git",
    "gitlab",
    "blog",
    "shop",
    "store",
    "app",
    "apps",
    "mobile",
    "web",
    "webmail",
    "smtp",
    "pop",
    "pop3",
    "imap",
    "ns",
    "ns1",
    "ns2",
    "dns",
    "vpn",
    "remote",
    "portal",
    "intranet",
    "extranet",
    "cdn",
    "static",
    "assets",
    "img",
    "images",
    "media",
    "video",
    "files",
    "download",
    "downloads",
    "upload",
    "uploads",
    "docs",
    "doc",
    "wiki",
    "help",
    "support",
    "status",
    "monitor",
    "monitoring",
    "grafana",
    "kibana",
    "jenkins",
    "ci",
    "cd",
    "build",
    "deploy",
    "jira",
    "confluence",
    "svn",
    "cloud",
    "aws",
    "azure",
    "gcp",
    "db",
    "database",
    "mysql",
    "postgres",
    "pgsql",
    "mongo",
    "redis",
    "cache",
    "memcached",
    "elastic",
    "es",
    "search",
    "solr",
    "rabbitmq",
    "mq",
    "kafka",
    "queue",
    "auth",
    "oauth",
    "sso",
    "login",
    "signin",
    "account",
    "accounts",
    "user",
    "users",
    "email",
    "mx",
    "mx1",
    "mx2",
    "relay",
    "gateway",
    "gw",
    "proxy",
    "firewall",
    "fw",
    "router",
    "nas",
    "backup",
    "backups",
    "bak",
    "old",
    "new",
    "beta",
    "alpha",
    "demo",
    "sandbox",
    "uat",
    "qa",
    "preprod",
    "prod",
    "production",
    "v2",
    "v3",
    "lab",
    "labs",
    "stage",
    "internal",
    "corp",
    "office",
    "hq",
    "partner",
    "partners",
    "b2b",
    "b2c",
    "crm",
    "erp",
    "hr",
    "ticket",
    "tickets",
    "dashboard",
    "panel",
    "cpanel",
    "plesk",
    "whm",
    "hosting",
    "server",
    "servers",
    "srv",
    "node",
    "nodes",
    "cluster",
    "k8s",
    "kube",
    "docker",
    "registry",
    "hub",
    "npm",
    "pypi",
    "maven",
    "apt",
    "yum",
    "repo",
    "repos",
    "mirror",
    "mirrors",
    "archive",
    "data",
    "bigdata",
    "bi",
    "etl",
    "airflow",
    "spark",
    "hadoop",
    "ml",
    "ai",
    "bot",
    "chat",
    "chatbot",
    "iot",
    "mqtt",
    "socket",
    "ws",
    "streaming",
    "stream",
    "live",
    "play",
    "games",
    "game",
    "lan",
    "dmz",
    "edge",
    "core",
    "master",
    "secondary",
    "cold",
    "hot",
    "temp",
    "tmp",
    "share",
    "shares",
    "samba",
    "nfs",
    "print",
    "printer",
];

/// Built-in directory/path candidates (~100 common paths).
pub const PATHS: &[&str] = &[
    "admin",
    "admin/login",
    "administrator",
    "login",
    "logout",
    "register",
    "signup",
    "signin",
    "dashboard",
    "panel",
    "api",
    "api/v1",
    "api/v2",
    "api/docs",
    "swagger",
    "swagger-ui",
    "openapi.json",
    "docs",
    "doc",
    "help",
    "wiki",
    "about",
    "contact",
    "robots.txt",
    "sitemap.xml",
    ".htaccess",
    ".env",
    ".git",
    ".git/config",
    ".git/HEAD",
    ".svn",
    ".DS_Store",
    "backup",
    "backup.zip",
    "backups",
    "db.sql",
    "database.sql",
    "dump.sql",
    "web.config",
    "server-status",
    "server-info",
    "phpinfo.php",
    "info.php",
    "test",
    "tests",
    "tmp",
    "temp",
    "logs",
    "log",
    "error.log",
    "access.log",
    "debug",
    "console",
    "upload",
    "uploads",
    "files",
    "download",
    "downloads",
    "media",
    "images",
    "img",
    "js",
    "css",
    "fonts",
    "static",
    "assets",
    "vendor",
    "node_modules",
    "config",
    "config.php",
    "settings",
    "setup",
    "install",
    "installation",
    "readme",
    "README.md",
    "readme.txt",
    "changelog",
    "license.txt",
    "todo.txt",
    "notes.txt",
    "private",
    "secret",
    "secrets",
    "internal",
    "hidden",
    "old",
    "new",
    "beta",
    "dev",
    "staging",
    "demo",
    "user",
    "users",
    "profile",
    "account",
    "adminer.php",
    "wp-admin",
    "wp-login.php",
    "wp-content",
];

/// Load a wordlist: the spec `builtin` selects the built-in list; anything
/// else is treated as a file path. File entries are trimmed; blank lines and
/// `#` comments are skipped; duplicates removed preserving first occurrence.
pub fn load(spec: &str, builtin: &[&str]) -> Result<Vec<String>> {
    if spec.eq_ignore_ascii_case("builtin") {
        return Ok(builtin.iter().map(|s| s.to_string()).collect());
    }
    let content = std::fs::read_to_string(spec)
        .map_err(|e| anyhow::anyhow!("failed to read wordlist file '{spec}': {e}"))?;
    let mut list: Vec<String> = Vec::new();
    for line in content.lines() {
        let entry = line.trim();
        if entry.is_empty() || entry.starts_with('#') {
            continue;
        }
        if !list.iter().any(|e| e == entry) {
            list.push(entry.to_string());
        }
    }
    if list.is_empty() {
        bail!("wordlist file '{spec}' contains no entries");
    }
    Ok(list)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn builtin_subdomains_is_about_200_unique_labels() {
        assert_eq!(SUBDOMAINS.len(), 200);
        let set: HashSet<_> = SUBDOMAINS.iter().collect();
        assert_eq!(
            set.len(),
            SUBDOMAINS.len(),
            "duplicates in builtin subdomains"
        );
        assert!(SUBDOMAINS.contains(&"www"));
        assert!(SUBDOMAINS.contains(&"api"));
        assert!(SUBDOMAINS.contains(&"staging"));
        for label in SUBDOMAINS {
            assert!(
                !label.is_empty()
                    && label.len() <= 63
                    && label
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
                "invalid label '{label}'"
            );
        }
    }

    #[test]
    fn builtin_paths_is_about_100() {
        assert_eq!(PATHS.len(), 100);
        let set: HashSet<_> = PATHS.iter().collect();
        assert_eq!(set.len(), PATHS.len(), "duplicates in builtin paths");
        assert!(PATHS.contains(&"admin"));
        assert!(PATHS.contains(&"robots.txt"));
        assert!(PATHS.contains(&".git/config"));
    }

    #[test]
    fn load_builtin_by_name() {
        let list = load("builtin", SUBDOMAINS).unwrap();
        assert_eq!(list.len(), 200);
        assert_eq!(list[0], "www");
        let list = load("BUILTIN", PATHS).unwrap();
        assert_eq!(list.len(), 100);
    }

    #[test]
    fn load_from_file_skips_comments_and_blank_lines() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("words.txt");
        std::fs::write(&path, "# comment\n\nwww\n  api  \nwww\nmail\n").unwrap();
        let list = load(path.to_str().unwrap(), &[]).unwrap();
        assert_eq!(list, vec!["www", "api", "mail"]);
    }

    #[test]
    fn load_missing_file_is_an_error() {
        assert!(load("/nonexistent/wordlist.txt", &[]).is_err());
    }
}
