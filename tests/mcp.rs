//! Integration tests for the MCP surface of `firelin serve` (Streamable
//! HTTP JSON-RPC on `/` and `/mcp`). Runs the real binary against local
//! TCP/UDP/HTTP fixtures, so every tool call exercises the actual scanners —
//! including the scan-authorization gate and bearer-token protection.

use std::io::{Read, Write};
use std::net::{TcpListener, UdpSocket};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use serde_json::{json, Value};

const PERMISSION_ENV: &str = "FIRELIN_I_HAVE_PERMISSION";

struct ServeHandle {
    child: Child,
    port: u16,
}

impl Drop for ServeHandle {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn spawn_serve(extra: &[&str]) -> ServeHandle {
    let port = free_port();
    let port_str = port.to_string();
    let mut args = vec!["serve", "--port", port_str.as_str()];
    args.extend_from_slice(extra);
    let child = Command::new(env!("CARGO_BIN_EXE_firelin"))
        .args(&args)
        .env_remove(PERMISSION_ENV)
        // Close stdin (EOF) so serve's BIT-contract stdin reader never blocks.
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to spawn firelin serve");
    let handle = ServeHandle { child, port };
    let base = format!("http://127.0.0.1:{}", handle.port);
    for _ in 0..100 {
        if let Ok(resp) = ureq::get(&format!("{base}/health"))
            .timeout(Duration::from_secs(2))
            .call()
        {
            if let Ok(v) = resp.into_json::<Value>() {
                if v["ok"] == true {
                    return handle;
                }
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("serve did not become ready");
}

/// POST a JSON-RPC message; returns (status, Mcp-Session-Id?, body).
fn rpc(
    addr: &str,
    session: Option<&str>,
    token: Option<&str>,
    message: Value,
) -> (u16, Option<String>, Value) {
    let mut request = ureq::post(&format!("http://{addr}/mcp")).timeout(Duration::from_secs(30));
    if let Some(sid) = session {
        request = request.set("Mcp-Session-Id", sid);
    }
    if let Some(t) = token {
        request = request.set("Authorization", &format!("Bearer {t}"));
    }
    match request.send_string(&message.to_string()) {
        Ok(resp) => (
            resp.status(),
            resp.header("Mcp-Session-Id").map(str::to_string),
            resp.into_json().unwrap_or(Value::Null),
        ),
        Err(ureq::Error::Status(status, resp)) => (
            status,
            resp.header("Mcp-Session-Id").map(str::to_string),
            resp.into_json().unwrap_or(Value::Null),
        ),
        Err(e) => panic!("http request failed: {e}"),
    }
}

fn initialize(addr: &str) -> String {
    let (status, sid, body) = rpc(
        addr,
        None,
        None,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": { "name": "test", "version": "0" }
            }
        }),
    );
    assert_eq!(status, 200);
    assert_eq!(body["result"]["serverInfo"]["name"], "firelin");
    assert_eq!(body["result"]["protocolVersion"], "2025-03-26");
    sid.expect("initialize must issue an Mcp-Session-Id")
}

fn call(addr: &str, sid: &str, id: i64, name: &str, args: Value) -> Value {
    let (_, _, body) = rpc(
        addr,
        Some(sid),
        None,
        json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/call",
            "params": { "name": name, "arguments": args }
        }),
    );
    body["result"].clone()
}

fn payload(result: &Value) -> Value {
    serde_json::from_str(result["content"][0]["text"].as_str().expect("text content"))
        .expect("tool payload is JSON")
}

// ---- local fixtures (same style as tests/cli.rs) ----------------------------

type Handler =
    Box<dyn Fn(&str) -> (u16, Vec<(&'static str, &'static str)>, String) + Send + 'static>;

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
                302 => "Found",
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

/// Answers `www.*` with 93.184.216.34, NXDOMAIN otherwise.
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

#[test]
fn handshake_tools_list_and_all_five_tools_live() {
    let http_port = spawn_http_server(Box::new(|path| match path {
        "/admin" => (200, vec![("Server", "FirelinTest/1.0")], "ok".to_string()),
        "/redirect" => (302, vec![("Location", "/admin")], "moved".to_string()),
        "/secret" => (403, vec![], "nope".to_string()),
        _ if path == "/" => (
            200,
            vec![
                ("Server", "FirelinTest/1.0"),
                ("X-Powered-By", "TestPHP/8.2"),
                ("Content-Type", "text/html"),
            ],
            "<html><head><TITLE>Firelin Home</TITLE></head><body>hi</body></html>".to_string(),
        ),
        _ => (404, vec![], "not found".to_string()),
    }));
    let dns_port = spawn_mock_dns();
    let dir = tempfile::tempdir().unwrap();
    let list = dir.path().join("paths.txt");
    std::fs::write(&list, "admin\nredirect\nsecret\nnope\n").unwrap();

    // Authorized server: scan tools unlocked.
    let server = spawn_serve(&["--yes-i-have-permission"]);
    let addr = format!("127.0.0.1:{}", server.port);
    let sid = initialize(&addr);

    // Notifications are accepted silently.
    let (status, _, body) = rpc(
        &addr,
        Some(&sid),
        None,
        json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }),
    );
    assert_eq!(status, 202);
    assert_eq!(body, Value::Null);

    // tools/list: five tools with schemas, gated ones stay listed.
    let (_, _, body) = rpc(
        &addr,
        Some(&sid),
        None,
        json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {} }),
    );
    let tools = body["result"]["tools"].as_array().expect("tools");
    let names: Vec<&str> = tools
        .iter()
        .map(|t| t["name"].as_str().expect("name"))
        .collect();
    assert_eq!(
        names,
        vec!["portscan", "subdns", "dirscan", "fingerprint", "cidr"]
    );
    for tool in tools {
        assert_eq!(tool["inputSchema"]["type"], "object");
        assert!(!tool["description"].as_str().unwrap().is_empty());
    }
    assert!(tools[0]["description"]
        .as_str()
        .unwrap()
        .contains("--yes-i-have-permission"));

    // cidr (pure computation)
    let result = call(&addr, &sid, 3, "cidr", json!({"cidr": "10.0.0.0/30"}));
    assert_eq!(result["isError"], false);
    let v = payload(&result);
    assert_eq!(v["count"], 4);
    assert_eq!(
        v["addresses"],
        json!(["10.0.0.0", "10.0.0.1", "10.0.0.2", "10.0.0.3"])
    );

    // fingerprint (read-only HTTP helper)
    let result = call(
        &addr,
        &sid,
        4,
        "fingerprint",
        json!({"url": format!("http://127.0.0.1:{http_port}/")}),
    );
    assert_eq!(result["isError"], false);
    let v = payload(&result);
    assert_eq!(v["status"], 200);
    assert_eq!(v["server"], "FirelinTest/1.0");
    assert_eq!(v["title"], "Firelin Home");

    // portscan against the fixture server: exactly one open port
    let result = call(
        &addr,
        &sid,
        5,
        "portscan",
        json!({
            "target": "127.0.0.1",
            "ports": format!("{http_port},{}", {
                let l = TcpListener::bind("127.0.0.1:0").unwrap();
                let p = l.local_addr().unwrap().port();
                drop(l);
                p
            }),
            "concurrency": 4,
            "timeout_ms": 500
        }),
    );
    assert_eq!(result["isError"], false, "{}", result);
    let v = payload(&result);
    let open = v["open"].as_array().unwrap();
    assert_eq!(open.len(), 1, "{v}");
    assert_eq!(open[0]["port"], http_port);

    // subdns against the mock resolver
    let result = call(
        &addr,
        &sid,
        6,
        "subdns",
        json!({
            "domain": "example.test",
            "resolver": format!("127.0.0.1:{dns_port}"),
            "concurrency": 4
        }),
    );
    assert_eq!(result["isError"], false, "{}", result);
    let v = payload(&result);
    let found: Vec<&str> = v["found"]
        .as_array()
        .unwrap()
        .iter()
        .map(|h| h["subdomain"].as_str().unwrap())
        .collect();
    assert!(found.contains(&"www.example.test"), "{v}");

    // dirscan with a custom wordlist
    let result = call(
        &addr,
        &sid,
        7,
        "dirscan",
        json!({
            "url": format!("http://127.0.0.1:{http_port}"),
            "wordlist": list.to_str().unwrap(),
            "concurrency": 4
        }),
    );
    assert_eq!(result["isError"], false, "{}", result);
    let v = payload(&result);
    let results = v["results"].as_array().unwrap();
    let find = |path: &str| {
        results
            .iter()
            .find(|r| r["path"] == path)
            .unwrap_or_else(|| panic!("missing finding for {path}: {results:?}"))
            .clone()
    };
    assert_eq!(find("admin")["classification"], "exists");
    assert_eq!(find("redirect")["classification"], "redirect");
    assert_eq!(find("secret")["classification"], "forbidden");
    assert!(!results.iter().any(|r| r["path"] == "nope"), "{v}");
}

#[test]
fn scan_gate_refuses_via_is_error_and_names_the_flag() {
    let http_port = spawn_http_server(Box::new(|_path| (200, vec![], "ok".to_string())));
    // No --yes-i-have-permission: scan tools must refuse, helpers still work.
    let server = spawn_serve(&[]);
    let addr = format!("127.0.0.1:{}", server.port);
    let sid = initialize(&addr);

    for (name, args) in [
        ("portscan", json!({"target": "127.0.0.1", "ports": "80"})),
        ("subdns", json!({"domain": "example.com"})),
        (
            "dirscan",
            json!({"url": format!("http://127.0.0.1:{http_port}")}),
        ),
    ] {
        let result = call(&addr, &sid, 10, name, args);
        assert_eq!(result["isError"], true, "{name}: {result}");
        let text = result["content"][0]["text"].as_str().expect("text");
        assert!(
            text.contains("--yes-i-have-permission"),
            "{name} refusal must name the flag: {text}"
        );
        assert!(
            text.contains("FIRELIN_I_HAVE_PERMISSION"),
            "{name} refusal must name the env var: {text}"
        );
    }

    // fingerprint (read-only) still works without scan authorization.
    let result = call(
        &addr,
        &sid,
        11,
        "fingerprint",
        json!({"url": format!("http://127.0.0.1:{http_port}/")}),
    );
    assert_eq!(result["isError"], false, "{}", result);
    assert_eq!(payload(&result)["status"], 200);
}

#[test]
fn unknown_tool_bad_args_and_protocol_errors() {
    let server = spawn_serve(&["--yes-i-have-permission"]);
    let addr = format!("127.0.0.1:{}", server.port);
    let sid = initialize(&addr);

    // Unknown tool → JSON-RPC -32602.
    let (_, _, body) = rpc(
        &addr,
        Some(&sid),
        None,
        json!({
            "jsonrpc": "2.0",
            "id": 20,
            "method": "tools/call",
            "params": { "name": "noscan", "arguments": {} }
        }),
    );
    assert_eq!(body["error"]["code"], -32602);

    // Missing required arg → isError result naming the field.
    let result = call(&addr, &sid, 21, "portscan", json!({}));
    assert_eq!(result["isError"], true);
    assert!(result["content"][0]["text"]
        .as_str()
        .expect("text")
        .contains("target"));

    // Invalid port spec → isError result.
    let result = call(
        &addr,
        &sid,
        22,
        "portscan",
        json!({"target": "127.0.0.1", "ports": "99999"}),
    );
    assert_eq!(result["isError"], true);

    // Oversized CIDR → isError result (mirrors the CLI rule).
    let result = call(&addr, &sid, 23, "cidr", json!({"cidr": "10.0.0.0/8"}));
    assert_eq!(result["isError"], true);
    assert!(result["content"][0]["text"]
        .as_str()
        .expect("text")
        .contains("too large"));

    // Unknown method → -32601; ping → {}.
    let (_, _, body) = rpc(
        &addr,
        Some(&sid),
        None,
        json!({ "jsonrpc": "2.0", "id": 24, "method": "resources/list" }),
    );
    assert_eq!(body["error"]["code"], -32601);
    let (_, _, body) = rpc(
        &addr,
        Some(&sid),
        None,
        json!({ "jsonrpc": "2.0", "id": 25, "method": "ping" }),
    );
    assert_eq!(body["result"], json!({}));
}

#[test]
fn token_protects_mcp_endpoint_too() {
    let server = spawn_serve(&["--token", "sekrit", "--yes-i-have-permission"]);
    let addr = format!("127.0.0.1:{}", server.port);

    // Without the bearer token the MCP endpoint answers 401 like /invoke.
    let response = ureq::post(&format!("http://{addr}/mcp"))
        .timeout(Duration::from_secs(5))
        .set("Content-Type", "application/json")
        .send_string(r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#);
    match response {
        Err(ureq::Error::Status(401, _)) => {}
        other => panic!("expected 401 without token, got {other:?}"),
    }

    // With the token the handshake succeeds and a call works.
    let (status, sid, body) = rpc(
        &addr,
        None,
        Some("sekrit"),
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": { "protocolVersion": "2025-03-26", "capabilities": {} }
        }),
    );
    assert_eq!(status, 200);
    assert_eq!(body["result"]["serverInfo"]["name"], "firelin");
    let sid = sid.expect("session id");

    let result = call_with_token(
        &addr,
        &sid,
        "sekrit",
        2,
        "cidr",
        json!({"cidr": "10.0.0.0/30"}),
    );
    assert_eq!(result["isError"], false);
    assert_eq!(payload(&result)["count"], 4);
}

fn call_with_token(addr: &str, sid: &str, token: &str, id: i64, name: &str, args: Value) -> Value {
    let (_, _, body) = rpc(
        addr,
        Some(sid),
        Some(token),
        json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/call",
            "params": { "name": name, "arguments": args }
        }),
    );
    body["result"].clone()
}

#[test]
fn root_endpoint_serves_mcp_too() {
    let server = spawn_serve(&["--yes-i-have-permission"]);
    // BIT discovery probes the root: initialize must work on POST / as well.
    let response = ureq::post(&format!("http://127.0.0.1:{}/", server.port))
        .timeout(Duration::from_secs(5))
        .set("Content-Type", "application/json")
        .send_string(
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{}}}"#,
        )
        .expect("root request succeeds");
    assert_eq!(response.status(), 200);
    let body: Value = response.into_json().expect("json");
    assert_eq!(body["result"]["serverInfo"]["name"], "firelin");
}
