# Firelin HTTP Protocol / Firelin HTTP 协议

Firelin `serve` mode exposes a small HTTP API on `127.0.0.1:8755` by default (`--host/--port` overridable). All responses are JSON.

Firelin `serve` 模式默认在 `127.0.0.1:8755` 提供一个小型 HTTP API（可用 `--host/--port` 覆盖）。所有响应均为 JSON。

## Endpoints / 端点

| Endpoint / 端点 | Method / 方法 | Auth / 认证 | Description / 说明 |
| --- | --- | --- | --- |
| `/health` | GET | none / 无 | Liveness probe. Returns / 返回 `{"ok":true}` |
| `/invoke-actions` | GET | Bearer (optional / 可选) | Action catalog + param hints + `scan_authorized` state / 动作目录、参数说明与扫描授权状态 |
| `/invoke` | POST | Bearer (optional / 可选) | BIT Remote protocol entry / BIT Remote 协议入口 |

With `serve --token <TOKEN>`, `/invoke` and `/invoke-actions` require `Authorization: Bearer <TOKEN>` (401 otherwise). `/health` stays open. / 使用 `serve --token <TOKEN>` 后，`/invoke` 与 `/invoke-actions` 需要 `Authorization: Bearer <TOKEN>`（否则 401）；`/health` 保持开放。

## Scan authorization / 扫描授权

Scan actions (`portscan`, `subdns`, `dirscan`) are only served when the process was started with `--yes-i-have-permission` or `FIRELIN_I_HAVE_PERMISSION=yes`. Otherwise `/invoke` answers HTTP 403 with `{"error":"scan_action_forbidden", ...}`. `fingerprint` and `cidr` are always available.

扫描动作（`portscan`、`subdns`、`dirscan`）仅在进程以 `--yes-i-have-permission` 或 `FIRELIN_I_HAVE_PERMISSION=yes` 启动时可用；否则 `/invoke` 对其返回 HTTP 403（`{"error":"scan_action_forbidden", ...}`）。`fingerprint` 与 `cidr` 始终可用。

## POST /invoke

Request body (BIT Remote payload) / 请求体（BIT Remote 载荷）:

```json
{
  "tool_id": "tool-uuid",
  "tool": "firelin",
  "invoked_by": "bit-agent",
  "params": { "action": "portscan", "target": "127.0.0.1", "ports": "80-90" }
}
```

Routing reads `params.action`, falling back to `params.tool`. Valid actions / 路由读取 `params.action`（回退 `params.tool`）。合法 action：

| action | Params / 参数 | Response payload / 响应载荷 |
| --- | --- | --- |
| `portscan` | `target`（必填，ip\|hostname\|cidr）、`ports`（默认 `"1-1024"`）、`concurrency`（200）、`timeout_ms`（800） | `{target, hosts, ports, scanned, open:[{host, port, ms}], duration_ms}` |
| `subdns` | `domain`（必填）、`wordlist`（默认 `"builtin"`）、`resolver`（默认 `"8.8.8.8:53"`）、`concurrency`（50） | `{domain, resolver, queried, errors, found:[{subdomain, ips:[...]}], duration_ms}` |
| `dirscan` | `url`（必填）、`wordlist`、`concurrency`（20）、`timeout_ms`（3000）、`follow_redirects`（false） | `{base_url, scanned, errors, results:[{path, url, status, classification, ms}], duration_ms}` |
| `fingerprint` | `url`（必填）、`timeout_ms`（5000） | `{url, final_url, status, server, powered_by, aspnet_version, generator, title, generated_at, duration_ms}` |
| `cidr` | `cidr`（必填） | `{cidr, network, prefix, count, addresses:[...]}` |

`dirscan` classifications / 状态分类: `exists` (2xx) · `redirect` (301/302/307/308) · `forbidden` (401/403) · `other`. 404/410 are ignored (not reported). / 404/410 忽略不报。

Errors / 错误:

| HTTP | Meaning / 含义 |
| --- | --- |
| 400 | Unknown `action`, missing/invalid param, invalid CIDR/ports/URL / 未知动作、参数缺失或非法 |
| 401 | Missing or invalid Bearer token / 缺失或错误的 Bearer token |
| 403 | Scan action on a serve started without authorization / 未授权启动的 serve 收到扫描动作 |
| 500 | Internal error / 内部错误 |

## Example session / 示例会话

```bash
# start with scan actions unlocked / 以解锁扫描动作的方式启动
firelin serve --port 8755 --yes-i-have-permission

# health
curl http://127.0.0.1:8755/health
# -> {"ok":true}

# action catalog
curl http://127.0.0.1:8755/invoke-actions

# fingerprint (read-only, always available)
curl -X POST http://127.0.0.1:8755/invoke \
     -H 'content-type: application/json' \
     -d '{"tool_id":"t1","tool":"firelin","invoked_by":"agent","params":{"action":"fingerprint","url":"http://127.0.0.1:8080/"}}'

# authorized portscan
curl -X POST http://127.0.0.1:8755/invoke \
     -H 'content-type: application/json' \
     -d '{"params":{"action":"portscan","target":"127.0.0.1","ports":"80-90"}}'
# -> {"target":"127.0.0.1","hosts":1,"ports":11,"scanned":11,"open":[{"host":"127.0.0.1","port":80,"ms":0}],"duration_ms":4}

# token-protected server / token 保护的服务
firelin serve --port 8755 --token sekrit --yes-i-have-permission
curl -H 'Authorization: Bearer sekrit' http://127.0.0.1:8755/invoke-actions
```

## CLI exit codes / CLI 退出码

| Command / 命令 | Codes / 退出码 |
| --- | --- |
| scan commands (authorized) / 扫描命令（已授权） | `0` (findings are data, not errors / 结果是数据不是错误) |
| scan commands without authorization / 未授权的扫描命令 | `2` (notice on stderr / stderr 输出授权声明) |
| `fingerprint` / `cidr` / other / 其他 | `0` success / `2` error |
