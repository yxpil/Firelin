//! Directory / path enumeration: GET each candidate path against a base URL
//! with `ureq`, classify by status code and report the interesting ones.
//! 404/410 responses are ignored; 2xx = exists, 3xx = redirect,
//! 401/403 = forbidden (worth attention), everything else = other.

use anyhow::bail;
use serde::Serialize;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Serialize, Clone)]
pub struct DirFinding {
    pub path: String,
    pub url: String,
    pub status: u16,
    /// `exists` | `redirect` | `forbidden` | `other`
    pub classification: String,
    pub ms: u64,
}

#[derive(Serialize)]
pub struct DirScanResult {
    pub base_url: String,
    /// Total paths attempted.
    pub scanned: usize,
    /// Requests that failed at the transport level (timeout, refused, ...).
    pub errors: usize,
    /// Findings excluding ignored (404/410) responses.
    pub results: Vec<DirFinding>,
    pub duration_ms: u64,
}

/// Map an HTTP status to its classification.
pub fn classify(status: u16) -> &'static str {
    match status {
        200..=299 => "exists",
        301 | 302 | 307 | 308 => "redirect",
        401 | 403 => "forbidden",
        404 | 410 => "not_found",
        _ => "other",
    }
}

/// Validate the base URL (only http/https, as `ureq` speaks HTTP(S)).
pub fn validate_base_url(url: &str) -> anyhow::Result<()> {
    let url = url.trim();
    if !(url.starts_with("http://") || url.starts_with("https://")) {
        bail!("base URL must start with http:// or https:// (got '{url}')");
    }
    Ok(())
}

/// Run the enumeration. Infallible at the scan level: per-path transport
/// errors are counted in `errors` (they never abort the run).
pub fn scan(
    base_url: &str,
    paths: &[String],
    concurrency: usize,
    timeout_ms: u64,
    follow_redirects: bool,
) -> DirScanResult {
    let started = Instant::now();
    let base = base_url.trim().trim_end_matches('/').to_string();
    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_millis(timeout_ms))
        .redirects(if follow_redirects { 5 } else { 0 })
        .build();

    let queue: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(paths.to_vec()));
    let findings = Arc::new(Mutex::new(Vec::<DirFinding>::new()));
    let errors = Arc::new(AtomicUsize::new(0));
    let workers = concurrency.clamp(1, 128);

    let mut handles = Vec::with_capacity(workers);
    for _ in 0..workers {
        let queue = Arc::clone(&queue);
        let findings = Arc::clone(&findings);
        let errors = Arc::clone(&errors);
        let agent = agent.clone();
        let base = base.clone();
        handles.push(std::thread::spawn(move || loop {
            let path = {
                let mut q = match queue.lock() {
                    Ok(q) => q,
                    Err(poisoned) => poisoned.into_inner(),
                };
                q.pop()
            };
            let Some(path) = path else { break };
            let url = format!("{base}/{}", path.trim_start_matches('/'));
            let started = Instant::now();
            let status = match agent.get(&url).call() {
                Ok(resp) => resp.status(),
                Err(ureq::Error::Status(code, _)) => code,
                Err(_) => {
                    errors.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
            };
            let classification = classify(status);
            if classification == "not_found" {
                continue; // 404/410 are ignored, not reported
            }
            findings
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .push(DirFinding {
                    path,
                    url,
                    status,
                    classification: classification.to_string(),
                    ms: started.elapsed().as_millis() as u64,
                });
        }));
    }
    for handle in handles {
        let _ = handle.join();
    }
    let mut results = Arc::try_unwrap(findings)
        .map(|m| m.into_inner().unwrap_or_default())
        .unwrap_or_default();
    results.sort_by(|a, b| (a.path.as_str(), a.status).cmp(&(b.path.as_str(), b.status)));
    DirScanResult {
        base_url: base.to_string(),
        scanned: paths.len(),
        errors: errors.load(Ordering::Relaxed),
        results,
        duration_ms: started.elapsed().as_millis() as u64,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_statuses() {
        assert_eq!(classify(200), "exists");
        assert_eq!(classify(204), "exists");
        assert_eq!(classify(301), "redirect");
        assert_eq!(classify(302), "redirect");
        assert_eq!(classify(308), "redirect");
        assert_eq!(classify(401), "forbidden");
        assert_eq!(classify(403), "forbidden");
        assert_eq!(classify(404), "not_found");
        assert_eq!(classify(410), "not_found");
        assert_eq!(classify(500), "other");
        assert_eq!(classify(502), "other");
    }

    #[test]
    fn validates_base_url() {
        assert!(validate_base_url("http://127.0.0.1:1").is_ok());
        assert!(validate_base_url("https://example.com").is_ok());
        assert!(validate_base_url("ftp://example.com").is_err());
        assert!(validate_base_url("example.com").is_err());
        assert!(validate_base_url("").is_err());
    }
}
