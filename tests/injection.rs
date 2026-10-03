//! Injection tests: `firelin fingerprint` consumes *untrusted* HTTP responses
//! from arbitrary hosts and re-emits them as JSON. A malicious upstream must
//! not be able to (a) break out of the JSON envelope, (b) inject headers that
//! the scanner then forwards, or (c) crash the scanner. Payloads that look like
//! XSS / SQLi must round-trip as opaque strings.

use serde_json::Value;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::{Command, Stdio};

const PERMISSION_ENV: &str = "FIRELIN_I_HAVE_PERMISSION";

struct Outcome {
    code: i32,
    stdout: String,
    stderr: String,
}

fn run(args: &[&str]) -> Outcome {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_firelin"));
    cmd.args(args)
        .env_remove(PERMISSION_ENV)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let o = cmd.spawn().unwrap().wait_with_output().unwrap();
    Outcome {
        code: o.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&o.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&o.stderr).into_owned(),
    }
}

/// A fixture upstream that answers a deliberately hostile response: XSS in the
/// `<title>` and body, SQLi-ish text in both the body and a response header.
fn hostile_server() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut buf = [0u8; 8192];
            let _ = stream.read(&mut buf).unwrap_or(0);
            let body = concat!(
                "<html><head><title><script>alert('xss')</script></title></head>",
                "<body>' OR '1'='1'-- <img src=x onerror=alert(2)></body></html>"
            );
            // X-Powered-By carries a SQLi-looking fragment; the scanner must treat
            // it as an opaque header value, never execute or reinterpret it.
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\
                 Server: Evil/1.0\r\nX-Powered-By: '; DROP TABLE users;--\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(resp.as_bytes());
            let _ = stream.flush();
        }
    });
    port
}

#[test]
fn hostile_http_response_is_treated_as_opaque_json_data() {
    let port = hostile_server();
    let url = format!("http://127.0.0.1:{port}/");

    let out = run(&["fingerprint", &url, "--json"]);
    assert_eq!(out.code, 0, "stderr: {}", out.stderr);

    // The whole stdout must be valid JSON — the payload must not have broken
    // out of the string envelope.
    let v: Value = serde_json::from_str(&out.stdout)
        .unwrap_or_else(|e| panic!("payload broke out of JSON: {e}\n{}", out.stdout));

    assert_eq!(v["status"], 200);
    // XSS payload in <title> is captured verbatim as a string — data, not script.
    let title = v["title"].as_str().expect("title");
    assert!(
        title.contains("<script>alert('xss')</script>"),
        "title must keep the payload verbatim, got: {title}"
    );
    // SQLi fragment in a response header is an opaque string, not executed.
    assert_eq!(v["server"], "Evil/1.0");
    assert_eq!(
        v["powered_by"].as_str().unwrap_or(""),
        "'; DROP TABLE users;--"
    );
}

#[test]
fn malformed_and_non_http_inputs_are_rejected_not_crashing() {
    // Random garbage on a raw TCP port must yield a clean exit-2 transport error,
    // never a panic / stack trace.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            // no HTTP response at all
            let _ = s.write_all(b"\x00\x01\x02 not http at all \xff\xfe");
            let _ = s.flush();
        }
    });

    let out = run(&["fingerprint", &format!("http://127.0.0.1:{port}/")]);
    assert_eq!(out.code, 2, "malformed response must be a clean error, got {}", out.code);
    assert!(!out.stderr.contains("panic"), "scanner panicked: {}", out.stderr);
}
