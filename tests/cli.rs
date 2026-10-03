//! Integration tests: run the real `firelin` binary against local TCP/UDP
//! fixtures. No external network is required.

use serde_json::Value;
use std::io::{Read, Write};
use std::net::{TcpListener, UdpSocket};
use std::process::{Command, Stdio};
use std::time::Duration;

const PERMISSION_ENV: &str = "FIRELIN_I_HAVE_PERMISSION";

struct RunOutcome {
    code: i32,
    stdout: String,
    stderr: String,
}

/// Spawn the real binary. `stdin_payload` writes a JSON object to stdin
/// (the BIT exec contract) when provided; the permission env var is always
/// removed first unless `env_sets_permission` is set.
fn run(args: &[&str], stdin_payload: Option<&str>, env_sets_permission: bool) -> RunOutcome {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_firelin"));
    cmd.args(args)
        .env_remove(PERMISSION_ENV)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if env_sets_permission {
        cmd.env(PERMISSION_ENV, "yes");
    }
    if stdin_payload.is_some() {
        cmd.stdin(Stdio::piped());
    } else {
        cmd.stdin(Stdio::null());
    }
    let mut child = cmd.spawn().expect("failed to spawn firelin");
    if let Some(payload) = stdin_payload {
        child
            .stdin
            .take()
            .unwrap()
            .write_all(payload.as_bytes())
            .unwrap();
    }
    let out = child
        .wait_with_output()
        .expect("failed to wait for firelin");
    RunOutcome {
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).to_string(),
        stderr: String::from_utf8_lossy(&out.stderr).to_string(),
    }
}

fn parse_json(out: &RunOutcome) -> Value {
    serde_json::from_str(&out.stdout)
        .unwrap_or_else(|e| panic!("stdout is not JSON ({e}): {}", out.stdout))
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

// ---- raw HTTP fixture ------------------------------------------------------

type Handler =
    Box<dyn Fn(&str) -> (u16, Vec<(&'static str, &'static str)>, String) + Send + 'static>;

/// A minimal HTTP/1.1 server on 127.0.0.1 (one thread, connection: close).
fn spawn_http_server(handler: Handler) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut buf = [0u8; 8192];
            let n = stream.read(&mut buf).unwrap_or(0);
            let req = String::from_utf8_lossy(&buf[..n]).to_string();
            let path = req.split_whitespace().nth(1).unwrap_or("/").to_string();
            let (status, headers, body) = handler(&path);
            let reason = match status {
                200 => "OK",
                301 => "Moved Permanently",
                302 => "Found",
                401 => "Unauthorized",
                403 => "Forbidden",
                404 => "Not Found",
                _ => "OK",
            };
            let mut resp = format!(
                "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n",
                body.len()
            );
            for (k, v) in &headers {
                resp.push_str(&format!("{k}: {v}\r\n"));
            }
            resp.push_str("\r\n");
            let _ = stream.write_all(resp.as_bytes());
            let _ = stream.write_all(body.as_bytes());
            let _ = stream.flush();
        }
    });
    port
}

fn fingerprint_server() -> u16 {
    spawn_http_server(Box::new(|_path| {
        (
            200,
            vec![
                ("Server", "FirelinTest/1.0"),
                ("X-Powered-By", "TestPHP/8.2"),
                ("Content-Type", "text/html"),
            ],
            "<html><head><TITLE>Firelin Home</TITLE></head><body>hi</body></html>".to_string(),
        )
    }))
}

fn dirscan_server() -> u16 {
    spawn_http_server(Box::new(|path| match path {
        "/admin" | "/admin/login" => (200, vec![], "ok".to_string()),
        "/redirect" => (302, vec![("Location", "/admin")], "moved".to_string()),
        "/secret" => (403, vec![], "nope".to_string()),
        _ => (404, vec![], "not found".to_string()),
    }))
}

// ---- cidr -------------------------------------------------------------------

#[test]
fn cidr_command_expands_and_validates() {
    let out = run(&["cidr", "192.168.1.0/30", "--json"], None, false);
    assert_eq!(out.code, 0, "stderr: {}", out.stderr);
    let v = parse_json(&out);
    assert_eq!(v["count"], 4);
    assert_eq!(v["network"], "192.168.1.0");
    assert_eq!(
        v["addresses"],
        serde_json::json!(["192.168.1.0", "192.168.1.1", "192.168.1.2", "192.168.1.3"])
    );

    // bare address = /32
    let out = run(&["cidr", "10.0.0.5", "--json"], None, false);
    assert_eq!(out.code, 0);
    let v = parse_json(&out);
    assert_eq!(v["count"], 1);
    assert_eq!(v["prefix"], 32);

    // text mode lists addresses
    let out = run(&["cidr", "10.0.0.0/31"], None, false);
    assert_eq!(out.code, 0);
    assert!(out.stdout.contains("10.0.0.0") && out.stdout.contains("10.0.0.1"));

    // oversized /16 -> exit 2 with a clear message
    let out = run(&["cidr", "192.168.0.0/16", "--json"], None, false);
    assert_eq!(out.code, 2);
    assert!(out.stderr.contains("too large"), "stderr: {}", out.stderr);

    // invalid -> exit 2
    let out = run(&["cidr", "not-a-cidr"], None, false);
    assert_eq!(out.code, 2);
    assert!(out.stderr.contains("invalid"), "stderr: {}", out.stderr);
}

// ---- authorization gating ----------------------------------------------------

#[test]
fn scan_commands_require_authorization() {
    for args in [
        vec!["portscan", "127.0.0.1", "--ports", "80"],
        vec!["subdns", "example.com"],
        vec!["dirscan", "http://127.0.0.1:1"],
    ] {
        let out = run(&args, None, false);
        assert_eq!(out.code, 2, "{args:?} must exit 2 without authorization");
        assert!(
            out.stderr.contains("--yes-i-have-permission"),
            "{args:?} stderr must explain the flag: {}",
            out.stderr
        );
        assert!(
            out.stderr.contains("FIRELIN_I_HAVE_PERMISSION"),
            "{args:?} stderr must explain the env var: {}",
            out.stderr
        );
        assert!(out.stdout.is_empty(), "{args:?} must not emit results");
    }
}

#[test]
fn scan_commands_pass_with_flag_or_env() {
    let out = run(
        &[
            "portscan",
            "127.0.0.1",
            "--ports",
            "1",
            "--json",
            "--yes-i-have-permission",
        ],
        None,
        false,
    );
    assert_eq!(out.code, 0, "stderr: {}", out.stderr);

    let out = run(
        &["portscan", "127.0.0.1", "--ports", "1", "--json"],
        None,
        true,
    );
    assert_eq!(
        out.code, 0,
        "env authorization failed; stderr: {}",
        out.stderr
    );
}

#[test]
fn missing_positional_after_merge_is_an_error() {
    let out = run(
        &["portscan", "--yes-i-have-permission", "--json"],
        None,
        false,
    );
    assert_eq!(out.code, 2);
    assert!(
        out.stderr.contains("missing required argument TARGET"),
        "stderr: {}",
        out.stderr
    );
}

// ---- portscan -----------------------------------------------------------------

#[test]
fn portscan_finds_open_and_skips_closed() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let open_port = listener.local_addr().unwrap().port();
    let closed = TcpListener::bind("127.0.0.1:0").unwrap();
    let closed_port = closed.local_addr().unwrap().port();
    drop(closed);
    std::thread::sleep(Duration::from_millis(50));

    let out = run(
        &[
            "portscan",
            "127.0.0.1",
            "--ports",
            &format!("{open_port},{closed_port}"),
            "--concurrency",
            "4",
            "--timeout-ms",
            "500",
            "--json",
            "--yes-i-have-permission",
        ],
        None,
        false,
    );
    assert_eq!(out.code, 0, "stderr: {}", out.stderr);
    let v = parse_json(&out);
    assert_eq!(v["scanned"], 2);
    let open = v["open"].as_array().unwrap();
    assert_eq!(open.len(), 1, "open: {open:?}");
    assert_eq!(open[0]["port"], open_port);
    assert_eq!(open[0]["host"], "127.0.0.1");
    assert!(open[0]["ms"].is_u64());

    // text mode mentions the open port
    let out = run(
        &[
            "portscan",
            "127.0.0.1",
            "--ports",
            &format!("{open_port}"),
            "--yes-i-have-permission",
        ],
        None,
        false,
    );
    assert_eq!(out.code, 0);
    assert!(
        out.stdout.contains(&format!("open  127.0.0.1:{open_port}")),
        "stdout: {}",
        out.stdout
    );
}

#[test]
fn portscan_cidr_target_and_stdin_merge() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let open_port = listener.local_addr().unwrap().port();

    // /32 CIDR target
    let out = run(
        &[
            "portscan",
            "127.0.0.1/32",
            "--ports",
            &format!("{open_port}"),
            "--json",
            "--yes-i-have-permission",
        ],
        None,
        false,
    );
    assert_eq!(out.code, 0, "stderr: {}", out.stderr);
    let v = parse_json(&out);
    assert_eq!(v["scanned"], 1);
    assert_eq!(v["open"][0]["port"], open_port);

    // oversized CIDR target -> exit 2
    let out = run(
        &[
            "portscan",
            "10.0.0.0/8",
            "--yes-i-have-permission",
            "--json",
        ],
        None,
        false,
    );
    assert_eq!(out.code, 2);
    assert!(out.stderr.contains("too large"), "stderr: {}", out.stderr);

    // BIT exec contract: params JSON via stdin (no positional target)
    let payload = format!(
        r#"{{"target":"127.0.0.1","ports":"{open_port}","yes_i_have_permission":true,"concurrency":4}}"#
    );
    let out = run(&["portscan", "--json"], Some(&payload), false);
    assert_eq!(out.code, 0, "stderr: {}", out.stderr);
    let v = parse_json(&out);
    assert_eq!(v["open"][0]["port"], open_port);
}

// ---- fingerprint ----------------------------------------------------------------

#[test]
fn fingerprint_parses_status_server_and_title() {
    let port = fingerprint_server();
    let url = format!("http://127.0.0.1:{port}/");

    let out = run(&["fingerprint", &url, "--json"], None, false);
    assert_eq!(out.code, 0, "stderr: {}", out.stderr);
    let v = parse_json(&out);
    assert_eq!(v["status"], 200);
    assert_eq!(v["server"], "FirelinTest/1.0");
    assert_eq!(v["powered_by"], "TestPHP/8.2");
    assert_eq!(v["title"], "Firelin Home");
    assert!(v["generated_at"].is_string());
    assert_eq!(v["final_url"], url);

    // text mode
    let out = run(&["fingerprint", &url], None, false);
    assert_eq!(out.code, 0);
    assert!(
        out.stdout.contains("Firelin Home"),
        "stdout: {}",
        out.stdout
    );
    assert!(out.stdout.contains("server: FirelinTest/1.0"));

    // transport error -> exit 2
    let out = run(
        &["fingerprint", &format!("http://127.0.0.1:{}/", free_port())],
        None,
        false,
    );
    assert_eq!(out.code, 2);

    // invalid scheme -> exit 2
    let out = run(&["fingerprint", "ftp://example.com"], None, false);
    assert_eq!(out.code, 2);
}

// ---- dirscan ---------------------------------------------------------------------

#[test]
fn dirscan_classifies_statuses() {
    let port = dirscan_server();
    let base = format!("http://127.0.0.1:{port}");

    let dir = tempfile::tempdir().unwrap();
    let list = dir.path().join("paths.txt");
    std::fs::write(&list, "admin\nadmin/login\nredirect\nsecret\nnope\n").unwrap();

    let out = run(
        &[
            "dirscan",
            &base,
            "--wordlist",
            list.to_str().unwrap(),
            "--concurrency",
            "4",
            "--json",
            "--yes-i-have-permission",
        ],
        None,
        false,
    );
    assert_eq!(out.code, 0, "stderr: {}", out.stderr);
    let v = parse_json(&out);
    assert_eq!(v["scanned"], 5);
    let results = v["results"].as_array().unwrap();
    let find = |path: &str| {
        results
            .iter()
            .find(|r| r["path"] == path)
            .unwrap_or_else(|| panic!("missing finding for {path}: {results:?}"))
            .clone()
    };
    assert_eq!(find("admin")["classification"], "exists");
    assert_eq!(find("admin")["status"], 200);
    assert_eq!(find("admin/login")["classification"], "exists");
    assert_eq!(find("redirect")["classification"], "redirect");
    assert_eq!(find("redirect")["status"], 302);
    assert_eq!(find("secret")["classification"], "forbidden");
    assert_eq!(find("secret")["status"], 403);
    assert!(
        !results.iter().any(|r| r["path"] == "nope"),
        "404 paths must be ignored: {results:?}"
    );

    // with --follow-redirects the 302 is followed to /admin (200 exists)
    let out = run(
        &[
            "dirscan",
            &base,
            "--wordlist",
            list.to_str().unwrap(),
            "--follow-redirects",
            "--json",
            "--yes-i-have-permission",
        ],
        None,
        false,
    );
    assert_eq!(out.code, 0, "stderr: {}", out.stderr);
    let v = parse_json(&out);
    let redirect = v["results"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["path"] == "redirect")
        .unwrap()
        .clone();
    assert_eq!(redirect["status"], 200);
    assert_eq!(redirect["classification"], "exists");
}

#[test]
fn dirscan_builtin_wordlist_and_errors() {
    let port = dirscan_server();
    let base = format!("http://127.0.0.1:{port}");
    let out = run(
        &["dirscan", &base, "--json", "--yes-i-have-permission"],
        None,
        false,
    );
    assert_eq!(out.code, 0, "stderr: {}", out.stderr);
    let v = parse_json(&out);
    assert_eq!(v["scanned"], 100, "builtin path list has 100 entries");
    let results = v["results"].as_array().unwrap();
    assert!(results.iter().any(|r| r["path"] == "admin"), "{results:?}");

    // non-http base URL -> exit 2
    let out = run(
        &["dirscan", "ftp://127.0.0.1", "--yes-i-have-permission"],
        None,
        false,
    );
    assert_eq!(out.code, 2);
    assert!(out.stderr.contains("http"), "stderr: {}", out.stderr);

    // connection-refused base URL -> exit 0 with errors counted
    let dead = format!("http://127.0.0.1:{}", free_port());
    let out = run(
        &["dirscan", &dead, "--json", "--yes-i-have-permission"],
        None,
        false,
    );
    assert_eq!(out.code, 0);
    let v = parse_json(&out);
    assert_eq!(v["errors"], 100);
    assert_eq!(v["results"].as_array().unwrap().len(), 0);
}

// ---- subdns (via serve /invoke; CLI path covered by unit tests + mock) -------------

/// Minimal UDP responder: answers `www.*` with 93.184.216.34, NXDOMAIN otherwise.
fn spawn_mock_dns() -> u16 {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = socket.local_addr().unwrap().port();
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
            if first_label == b"www" {
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
    port
}

// ---- serve -----------------------------------------------------------------------

fn wait_for_health(base: &str) -> bool {
    for _ in 0..100 {
        if let Ok(resp) = ureq::get(&format!("{base}/health"))
            .timeout(Duration::from_secs(2))
            .call()
        {
            if let Ok(v) = resp.into_json::<Value>() {
                if v["ok"] == true {
                    return true;
                }
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

fn spawn_serve(extra: &[&str]) -> (u16, std::process::Child) {
    let port = free_port();
    let port_str = port.to_string();
    let mut args = vec!["serve", "--port", port_str.as_str()];
    args.extend_from_slice(extra);
    let child = Command::new(env!("CARGO_BIN_EXE_firelin"))
        .args(&args)
        .env_remove(PERMISSION_ENV)
        // serve reads stdin for the BIT exec contract when it is not a TTY;
        // closing it (EOF) keeps the server from blocking before it binds.
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn firelin serve");
    (port, child)
}

fn invoke(port: u16, params: Value) -> Result<Value, Box<ureq::Error>> {
    let resp = ureq::post(&format!("http://127.0.0.1:{port}/invoke"))
        .timeout(Duration::from_secs(30))
        .send_json(serde_json::json!({
            "tool_id": "tid",
            "tool": "firelin",
            "invoked_by": "integration-test",
            "params": params
        }))
        .map_err(Box::new)?;
    Ok(resp.into_json().unwrap())
}

#[test]
fn serve_health_actions_invoke_and_scan_authorization() {
    let http_port = fingerprint_server();
    let dns_port = spawn_mock_dns();

    // -- authorized serve: scan actions unlocked -------------------------
    let (port, mut child) = spawn_serve(&["--yes-i-have-permission"]);
    let base = format!("http://127.0.0.1:{port}");
    assert!(wait_for_health(&base), "serve did not become ready");

    // GET /health
    let resp: Value = ureq::get(&format!("{base}/health"))
        .timeout(Duration::from_secs(5))
        .call()
        .unwrap()
        .into_json()
        .unwrap();
    assert_eq!(resp["ok"], true);

    // GET /invoke-actions catalog
    let resp: Value = ureq::get(&format!("{base}/invoke-actions"))
        .timeout(Duration::from_secs(5))
        .call()
        .unwrap()
        .into_json()
        .unwrap();
    assert_eq!(resp["scan_authorized"], true);
    for action in ["portscan", "subdns", "dirscan", "fingerprint", "cidr"] {
        assert!(
            resp["actions"].get(action).is_some(),
            "missing action {action}: {resp}"
        );
    }

    // fingerprint action against the local fixture server
    let resp = invoke(
        port,
        serde_json::json!({"action": "fingerprint", "url": format!("http://127.0.0.1:{http_port}/")}),
    )
    .unwrap();
    assert_eq!(resp["status"], 200, "{resp}");
    assert_eq!(resp["title"], "Firelin Home");

    // portscan action: open port (fixture server) + closed port
    let closed_port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let resp = invoke(
        port,
        serde_json::json!({
            "action": "portscan",
            "target": "127.0.0.1",
            "ports": format!("{http_port},{closed_port}"),
            "concurrency": 4,
            "timeout_ms": 500
        }),
    )
    .unwrap();
    let open = resp["open"].as_array().unwrap();
    assert_eq!(open.len(), 1, "{resp}");
    assert_eq!(open[0]["port"], http_port);

    // subdns action against the mock resolver
    let resp = invoke(
        port,
        serde_json::json!({
            "action": "subdns",
            "domain": "example.test",
            "resolver": format!("127.0.0.1:{dns_port}"),
            "concurrency": 4
        }),
    )
    .unwrap();
    let names: Vec<&str> = resp["found"]
        .as_array()
        .unwrap()
        .iter()
        .map(|h| h["subdomain"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"www.example.test"), "{resp}");

    // cidr action
    let resp = invoke(
        port,
        serde_json::json!({"action": "cidr", "cidr": "10.0.0.0/30"}),
    )
    .unwrap();
    assert_eq!(resp["count"], 4);

    // unknown action -> 400, missing param -> 400
    for (params, expect) in [
        (serde_json::json!({"action": "nonsense"}), 400u16),
        (serde_json::json!({"action": "fingerprint"}), 400),
        (
            serde_json::json!({"action": "portscan", "target": "127.0.0.1", "ports": "99999"}),
            400,
        ),
    ] {
        let err = invoke(port, params).unwrap_err();
        match *err {
            ureq::Error::Status(code, _) => assert_eq!(code, expect),
            other => panic!("expected HTTP {expect}, got: {other}"),
        }
    }
    child.kill().unwrap();
    let _ = child.wait();

    // -- unauthorized serve: scan actions must answer 403 -----------------
    let (port, mut child) = spawn_serve(&[]);
    let base = format!("http://127.0.0.1:{port}");
    assert!(
        wait_for_health(&base),
        "unauthorized serve did not become ready"
    );

    // fingerprint is allowed without scan authorization
    let resp = invoke(
        port,
        serde_json::json!({"action": "fingerprint", "url": format!("http://127.0.0.1:{http_port}/")}),
    )
    .unwrap();
    assert_eq!(resp["status"], 200);

    // portscan / subdns / dirscan are forbidden
    for action in ["portscan", "subdns", "dirscan"] {
        let params = match action {
            "portscan" => {
                serde_json::json!({"action": action, "target": "127.0.0.1", "ports": "80"})
            }
            "subdns" => serde_json::json!({"action": action, "domain": "example.com"}),
            _ => {
                serde_json::json!({"action": action, "url": format!("http://127.0.0.1:{http_port}/")})
            }
        };
        let err = invoke(port, params).unwrap_err();
        match *err {
            ureq::Error::Status(code, resp) => {
                assert_eq!(code, 403, "{action}");
                let body = resp.into_json::<Value>().unwrap();
                assert_eq!(body["error"], "scan_action_forbidden", "{body}");
            }
            other => panic!("expected HTTP 403 for {action}, got: {other}"),
        }
    }
    child.kill().unwrap();
    let _ = child.wait();

    // -- token-protected serve --------------------------------------------
    let (port, mut child) = spawn_serve(&["--token", "sekrit", "--yes-i-have-permission"]);
    let base = format!("http://127.0.0.1:{port}");
    assert!(
        wait_for_health(&base),
        "token-protected serve did not become ready"
    );

    // /health stays open
    let resp: Value = ureq::get(&format!("{base}/health"))
        .timeout(Duration::from_secs(5))
        .call()
        .unwrap()
        .into_json()
        .unwrap();
    assert_eq!(resp["ok"], true);

    // /invoke without token -> 401
    let err = ureq::post(&format!("{base}/invoke"))
        .timeout(Duration::from_secs(5))
        .send_json(serde_json::json!({"params": {"action": "cidr", "cidr": "10.0.0.0/30"}}))
        .unwrap_err();
    match err {
        ureq::Error::Status(code, _) => assert_eq!(code, 401),
        other => panic!("expected HTTP 401, got: {other}"),
    }

    // /invoke with the right bearer token -> 200
    let resp = invoke_with_token(
        port,
        "sekrit",
        serde_json::json!({"action": "cidr", "cidr": "10.0.0.0/30"}),
    );
    assert_eq!(resp["count"], 4);

    // /invoke-actions also requires the token
    let err = ureq::get(&format!("{base}/invoke-actions"))
        .timeout(Duration::from_secs(5))
        .call()
        .unwrap_err();
    match err {
        ureq::Error::Status(code, _) => assert_eq!(code, 401),
        other => panic!("expected HTTP 401, got: {other}"),
    }

    child.kill().unwrap();
    let _ = child.wait();
}

fn invoke_with_token(port: u16, token: &str, params: Value) -> Value {
    ureq::post(&format!("http://127.0.0.1:{port}/invoke"))
        .timeout(Duration::from_secs(30))
        .set("Authorization", &format!("Bearer {token}"))
        .send_json(serde_json::json!({"params": params}))
        .unwrap()
        .into_json()
        .unwrap()
}

#[test]
fn help_and_version_work() {
    let out = run(&["--help"], None, false);
    assert_eq!(out.code, 0);
    for cmd in [
        "portscan",
        "subdns",
        "dirscan",
        "fingerprint",
        "cidr",
        "serve",
    ] {
        assert!(out.stdout.contains(cmd), "help missing '{cmd}'");
    }
    assert!(out.stdout.contains("--yes-i-have-permission"));
    let out = run(&["--version"], None, false);
    assert_eq!(out.code, 0);
    assert!(out.stdout.contains("firelin"), "stdout: {}", out.stdout);
}
