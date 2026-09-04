//! Single-target HTTP fingerprint: one read-only GET request, then report
//! status, framework-revealing headers and the HTML <title>.

use anyhow::{bail, Result};
use serde::Serialize;
use std::io::Read;
use std::time::{Duration, Instant};

/// Cap the body read used for <title> extraction (titles live near the top).
const MAX_BODY_BYTES: u64 = 256 * 1024;

#[derive(Serialize)]
pub struct Fingerprint {
    pub url: String,
    /// Final URL after redirects (same as `url` when not redirected).
    pub final_url: String,
    pub status: u16,
    pub server: Option<String>,
    pub powered_by: Option<String>,
    pub aspnet_version: Option<String>,
    pub generator: Option<String>,
    pub title: Option<String>,
    pub generated_at: String,
    pub duration_ms: u64,
}

/// Validate the target URL (only http/https).
pub fn validate_url(url: &str) -> Result<()> {
    let url = url.trim();
    if !(url.starts_with("http://") || url.starts_with("https://")) {
        bail!("URL must start with http:// or https:// (got '{url}')");
    }
    Ok(())
}

/// Fingerprint one URL with a single GET request (follows up to 5 redirects,
/// still read-only). Transport errors propagate to the caller.
pub fn fingerprint(url: &str, timeout_ms: u64) -> Result<Fingerprint> {
    let url = url.trim();
    validate_url(url)?;
    let started = Instant::now();
    let resp = ureq::get(url)
        .timeout(Duration::from_millis(timeout_ms))
        .call()?;
    let status = resp.status();
    let final_url = resp.get_url().to_string();
    let server = header(&resp, "server");
    let powered_by = header(&resp, "x-powered-by");
    let aspnet_version = header(&resp, "x-aspnet-version");
    let generator = header(&resp, "x-generator");
    let mut body_bytes = Vec::new();
    {
        let mut reader = resp.into_reader().take(MAX_BODY_BYTES);
        let _ = reader.read_to_end(&mut body_bytes);
    }
    let body = String::from_utf8_lossy(&body_bytes);
    let title = extract_title(&body);
    Ok(Fingerprint {
        url: url.to_string(),
        final_url,
        status,
        server,
        powered_by,
        aspnet_version,
        generator,
        title,
        generated_at: chrono::Utc::now().to_rfc3339(),
        duration_ms: started.elapsed().as_millis() as u64,
    })
}

fn header(resp: &ureq::Response, name: &str) -> Option<String> {
    resp.header(name)
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

/// Case-insensitive `<title>...</title>` extraction (attributes tolerated,
/// whitespace trimmed). Returns None when absent/empty.
pub fn extract_title(html: &str) -> Option<String> {
    let hay: Vec<u8> = html
        .as_bytes()
        .iter()
        .map(|b| b.to_ascii_lowercase())
        .collect();
    let start = find(&hay, b"<title")?;
    let gt = find(&hay[start..], b">")? + start;
    let end = find(&hay[gt..], b"</title")? + gt;
    if gt + 1 > end {
        return None;
    }
    let title = html.get(gt + 1..end)?.trim();
    if title.is_empty() {
        None
    } else {
        Some(title.to_string())
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_titles() {
        assert_eq!(
            extract_title("<html><title>Home</title></html>"),
            Some("Home".into())
        );
        assert_eq!(
            extract_title("<TITLE  lang=\"en\">  My Page  </TITLE>"),
            Some("My Page".into())
        );
        assert_eq!(
            extract_title("<html>\n<head>\n<Title>Multi\nline</Title>\n</head>"),
            Some("Multi\nline".into())
        );
        assert_eq!(extract_title("<title></title>"), None);
        assert_eq!(extract_title("<html><body>no title</body></html>"), None);
        assert_eq!(extract_title(""), None);
        assert_eq!(extract_title("<title>unclosed"), None);
    }

    #[test]
    fn validates_urls() {
        assert!(validate_url("http://127.0.0.1:1/").is_ok());
        assert!(validate_url("https://example.com").is_ok());
        assert!(validate_url("ftp://example.com").is_err());
        assert!(validate_url("127.0.0.1").is_err());
    }
}
