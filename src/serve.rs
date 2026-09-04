//! `serve` mode: BIT Remote-protocol-compatible HTTP API plus MCP.
//!
//! Endpoints: `GET /health` (liveness, never token-protected),
//! `GET /invoke-actions` (machine-readable action catalog),
//! `POST /invoke` (BIT Remote entry point, routing on `params.action`,
//! fallback `params.tool`) and the MCP Streamable-HTTP JSON-RPC surface on
//! `POST /` and `POST /mcp` (see [`crate::mcp`]).
//!
//! Both protocols share one action funnel ([`dispatch_action`]), so results
//! and authorization behavior always agree.
//!
//! Scan actions (`portscan`, `subdns`, `dirscan`) are gated at the server
//! level: unless the process was started with `--yes-i-have-permission` (or
//! `FIRELIN_I_HAVE_PERMISSION=yes`), they answer HTTP 403 (`/invoke`) or an
//! `isError` result (`/mcp`). `fingerprint` and `cidr` are
//! read-only/single-request helpers and always available. `--token` adds
//! optional Bearer protection on every endpoint except `/health`.

use crate::{cidr, dirscan, fingerprint, ports, portscan, subdns};
use anyhow::{Context, Result};
use axum::extract::{rejection::JsonRejection, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{json, Value};
use std::sync::Arc;

/// All invokable actions, in catalog order.
pub const ACTIONS: &[&str] = &["portscan", "subdns", "dirscan", "fingerprint", "cidr"];

/// Actions that require scan authorization at serve startup.
pub const SCAN_ACTIONS: &[&str] = &["portscan", "subdns", "dirscan"];

type ApiError = (StatusCode, Json<Value>);

#[derive(Clone)]
pub struct AppState {
    pub token: Option<Arc<String>>,
    /// Whether scan actions were unlocked when the server started.
    pub scan_authorized: bool,
}

/// Start the HTTP API (BIT Remote tool compatible).
pub async fn run(
    host: String,
    port: u16,
    token: Option<String>,
    scan_authorized: bool,
) -> Result<()> {
    let state = AppState {
        token: token.map(Arc::new),
        scan_authorized,
    };
    let app = Router::new()
        .route("/health", get(health))
        .route("/invoke-actions", get(invoke_actions))
        .route("/invoke", post(invoke))
        .merge(crate::mcp::routes())
        .with_state(state);
    let addr = format!("{host}:{port}");
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .with_context(|| format!("failed to bind {addr}"))?;
    eprintln!(
        "firelin serve listening on http://{} (scan actions: {})",
        listener.local_addr()?,
        if scan_authorized {
            "enabled"
        } else {
            "disabled (restart with --yes-i-have-permission or FIRELIN_I_HAVE_PERMISSION=yes)"
        }
    );
    axum::serve(listener, app).await?;
    Ok(())
}

async fn health() -> impl IntoResponse {
    Json(json!({"ok": true}))
}

async fn invoke_actions(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, ApiError> {
    if !authorized(&headers, &state) {
        return Err(unauthorized());
    }
    Ok(Json(json!({
        "bit_remote": true,
        "scan_authorized": state.scan_authorized,
        "actions": {
            "portscan": {
                "requires_scan_auth": true,
                "params": {
                    "target": "single ip | hostname | ipv4 cidr (required)",
                    "ports": "spec string, default '1-1024'",
                    "concurrency": "int, default 200",
                    "timeout_ms": "int, default 800"
                }
            },
            "subdns": {
                "requires_scan_auth": true,
                "params": {
                    "domain": "string (required)",
                    "wordlist": "'builtin' | file path, default 'builtin'",
                    "resolver": "'ip:port', default '8.8.8.8:53'",
                    "concurrency": "int, default 50"
                }
            },
            "dirscan": {
                "requires_scan_auth": true,
                "params": {
                    "url": "base url (required)",
                    "wordlist": "'builtin' | file path, default 'builtin'",
                    "concurrency": "int, default 20",
                    "timeout_ms": "int, default 3000",
                    "follow_redirects": "bool, default false"
                }
            },
            "fingerprint": {
                "requires_scan_auth": false,
                "params": {"url": "string (required)", "timeout_ms": "int, default 5000"}
            },
            "cidr": {
                "requires_scan_auth": false,
                "params": {"cidr": "ipv4 cidr string (required)"}
            }
        }
    })))
}

/// BIT Remote protocol entry point. Payload:
/// `{"tool_id": "...", "tool": "...", "invoked_by": "...", "params": {...}}`.
/// A bare `{"action": ...}` object is also accepted for convenience.
async fn invoke(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Result<Json<Value>, JsonRejection>,
) -> Result<Json<Value>, ApiError> {
    if !authorized(&headers, &state) {
        return Err(unauthorized());
    }
    let payload = match body {
        Ok(Json(value)) => value,
        Err(_) => json!({}),
    };
    let params = match payload.get("params") {
        Some(p) => p.clone(),
        None => payload, // tolerate a bare params object
    };
    let action = params
        .get("action")
        .and_then(Value::as_str)
        .or_else(|| params.get("tool").and_then(Value::as_str))
        .unwrap_or_default()
        .to_string();
    if action.is_empty() {
        return Err(bad_request(
            "missing params.action (expected one of: portscan, subdns, dirscan, fingerprint, cidr)",
        ));
    }
    match dispatch_action(&action, &params, state.scan_authorized).await {
        Ok(value) => Ok(Json(value)),
        Err(ActionError::Bad(message)) => Err(bad_request(message)),
        Err(ActionError::Forbidden(message)) => Err((
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "scan_action_forbidden", "message": message })),
        )),
        Err(ActionError::Internal(message)) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": message })),
        )),
    }
}

/// Why an action call failed. `Bad` maps to HTTP 400, `Forbidden` to 403,
/// `Internal` to 500; the MCP surface flattens all into `isError` results.
pub enum ActionError {
    Bad(String),
    Forbidden(String),
    Internal(String),
}

/// Shared action routing used by `POST /invoke` and the MCP `tools/call`.
/// `params` holds the action's arguments; unknown extra keys are ignored.
pub async fn dispatch_action(
    action: &str,
    params: &Value,
    scan_authorized: bool,
) -> std::result::Result<Value, ActionError> {
    if SCAN_ACTIONS.contains(&action) && !scan_authorized {
        return Err(ActionError::Forbidden(format!(
            "action '{action}' requires scan authorization; restart firelin serve with \
             --yes-i-have-permission or set FIRELIN_I_HAVE_PERMISSION=yes — only scan targets \
             you own or are authorized to test"
        )));
    }
    let outcome = match action {
        "portscan" => action_portscan(params).await,
        "subdns" => action_subdns(params).await,
        "dirscan" => action_dirscan(params).await,
        "fingerprint" => action_fingerprint(params).await,
        "cidr" => action_cidr(params),
        other => {
            return Err(ActionError::Bad(format!(
                "unknown action '{other}' — expected one of: {}",
                ACTIONS.join(", ")
            )))
        }
    };
    outcome.map_err(|message| match message {
        ActionError::Bad(m) => ActionError::Bad(m),
        other => other,
    })
}

async fn action_portscan(params: &Value) -> std::result::Result<Value, ActionError> {
    let target = req_str(params, "target")?.to_string();
    let ports_spec = opt_str(params, "ports").unwrap_or("1-1024").to_string();
    let ports_list = ports::parse_ports(&ports_spec).map_err(bad_req)?;
    let targets = portscan::resolve_targets(&target).map_err(bad_req)?;
    let concurrency = opt_usize(params, "concurrency", 200).clamp(1, 4096);
    let timeout_ms = opt_u64(params, "timeout_ms", 800);
    let result = tokio::task::spawn_blocking(move || {
        portscan::scan(&target, targets, ports_list, concurrency, timeout_ms)
    })
    .await
    .map_err(internal_blocking)?;
    serde_json::to_value(&result).map_err(internal_ser)
}

async fn action_subdns(params: &Value) -> std::result::Result<Value, ActionError> {
    let domain = req_str(params, "domain")?.to_string();
    let wordlist_spec = opt_str(params, "wordlist").unwrap_or("builtin").to_string();
    let resolver_spec = opt_str(params, "resolver")
        .unwrap_or("8.8.8.8:53")
        .to_string();
    let resolver = subdns::parse_resolver(&resolver_spec).map_err(bad_req)?;
    let candidates =
        crate::wordlist::load(&wordlist_spec, crate::wordlist::SUBDOMAINS).map_err(bad_req)?;
    let concurrency = opt_usize(params, "concurrency", 50).clamp(1, 512);
    let result = tokio::task::spawn_blocking(move || {
        subdns::enumerate(&domain, &candidates, resolver, concurrency)
    })
    .await
    .map_err(internal_blocking)?;
    serde_json::to_value(&result).map_err(internal_ser)
}

async fn action_dirscan(params: &Value) -> std::result::Result<Value, ActionError> {
    let base_url = req_str(params, "url")?.to_string();
    dirscan::validate_base_url(&base_url).map_err(bad_req)?;
    let wordlist_spec = opt_str(params, "wordlist").unwrap_or("builtin").to_string();
    let paths = crate::wordlist::load(&wordlist_spec, crate::wordlist::PATHS).map_err(bad_req)?;
    let concurrency = opt_usize(params, "concurrency", 20).clamp(1, 128);
    let timeout_ms = opt_u64(params, "timeout_ms", 3000);
    let follow_redirects = opt_bool(params, "follow_redirects", false);
    let result = tokio::task::spawn_blocking(move || {
        dirscan::scan(&base_url, &paths, concurrency, timeout_ms, follow_redirects)
    })
    .await
    .map_err(internal_blocking)?;
    serde_json::to_value(&result).map_err(internal_ser)
}

async fn action_fingerprint(params: &Value) -> std::result::Result<Value, ActionError> {
    let url = req_str(params, "url")?.to_string();
    let timeout_ms = opt_u64(params, "timeout_ms", 5000);
    let result = tokio::task::spawn_blocking(move || fingerprint::fingerprint(&url, timeout_ms))
        .await
        .map_err(internal_blocking)?
        .map_err(internal_err)?;
    serde_json::to_value(&result).map_err(internal_ser)
}

fn action_cidr(params: &Value) -> std::result::Result<Value, ActionError> {
    let spec = params
        .get("cidr")
        .and_then(Value::as_str)
        .or_else(|| params.get("target").and_then(Value::as_str))
        .ok_or_else(|| bad("missing required string param 'cidr'"))?;
    let parsed = cidr::parse_cidr(spec).map_err(bad_req)?;
    let addresses = cidr::expand(&parsed).map_err(bad_req)?;
    Ok(json!({
        "cidr": spec,
        "network": parsed.network.to_string(),
        "prefix": parsed.prefix,
        "count": addresses.len(),
        "addresses": addresses.iter().map(|ip| ip.to_string()).collect::<Vec<_>>(),
    }))
}

// ---- helpers ------------------------------------------------------------

pub(crate) fn authorized(headers: &HeaderMap, state: &AppState) -> bool {
    match &state.token {
        None => true,
        Some(token) => headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value == format!("Bearer {token}")),
    }
}

fn bad(message: impl Into<String>) -> ActionError {
    ActionError::Bad(message.into())
}

fn bad_request(message: impl Into<String>) -> ApiError {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({"error": "bad_request", "message": message.into()})),
    )
}

fn bad_req(e: anyhow::Error) -> ActionError {
    ActionError::Bad(e.to_string())
}

fn unauthorized() -> ApiError {
    (
        StatusCode::UNAUTHORIZED,
        Json(json!({"error": "missing or invalid bearer token"})),
    )
}

fn internal_blocking(e: tokio::task::JoinError) -> ActionError {
    ActionError::Internal(e.to_string())
}

fn internal_err(e: anyhow::Error) -> ActionError {
    ActionError::Internal(e.to_string())
}

fn internal_ser(e: serde_json::Error) -> ActionError {
    ActionError::Internal(e.to_string())
}

fn req_str<'a>(params: &'a Value, key: &str) -> std::result::Result<&'a str, ActionError> {
    params
        .get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| bad(format!("missing required string param '{key}'")))
}

fn opt_str<'a>(params: &'a Value, key: &str) -> Option<&'a str> {
    params.get(key).and_then(Value::as_str)
}

fn opt_u64(params: &Value, key: &str, default: u64) -> u64 {
    params.get(key).and_then(Value::as_u64).unwrap_or(default)
}

fn opt_usize(params: &Value, key: &str, default: usize) -> usize {
    params
        .get(key)
        .and_then(Value::as_u64)
        .and_then(|v| usize::try_from(v).ok())
        .unwrap_or(default)
}

fn opt_bool(params: &Value, key: &str, default: bool) -> bool {
    params.get(key).and_then(Value::as_bool).unwrap_or(default)
}
