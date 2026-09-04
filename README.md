# Firelin

Authorized network assessment toolkit for AI agents — TCP port scanning, DNS subdomain enumeration, directory enumeration and HTTP fingerprinting, built for the BIT ecosystem.

[![Release](https://img.shields.io/github/v/release/yxpil/Firelin?style=flat-square)](https://github.com/yxpil/Firelin/releases/latest)
[![Downloads](https://img.shields.io/github/downloads/yxpil/Firelin/total?style=flat-square)](https://github.com/yxpil/Firelin/releases)
[![CI](https://img.shields.io/github/actions/workflow/status/yxpil/Firelin/ci.yml?style=flat-square&label=CI)](https://github.com/yxpil/Firelin/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-black?style=flat-square)](./LICENSE)
[![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux%20%7C%20Windows-black?style=flat-square)](https://github.com/yxpil/Firelin/releases)

---

> **⚠️ Legal notice / 法律声明**
>
> **EN**: Firelin performs active network probing. Use it **ONLY** on systems you own or on systems you have **written permission** to test. Scan commands (`portscan`, `subdns`, `dirscan`) refuse to run until you confirm authorization with `--yes-i-have-permission` (or the environment variable `FIRELIN_I_HAVE_PERMISSION=yes`). Unauthorized scanning of computer systems is illegal in most jurisdictions. The authors accept no liability for misuse.
>
> **中文**：Firelin 会主动探测网络。仅可用于**自有资产**或已获得**书面授权**的资产。扫描类命令（`portscan`、`subdns`、`dirscan`）必须先通过 `--yes-i-have-permission`（或环境变量 `FIRELIN_I_HAVE_PERMISSION=yes`）确认授权，否则拒绝执行。未经授权扫描计算机系统在绝大多数司法辖区属于违法行为。作者不对任何滥用行为承担责任。

---

## English

### About

Firelin is a compact network-assessment toolkit for AI agents (especially [BIT](https://github.com/yxpil/bit)). It packages the four reconnaissance primitives of an authorized engagement behind one CLI and one HTTP API, with authorization gating built in so an agent cannot start a scan without an explicit confirmation step.

**Scope (v0.1 policy)**: reconnaissance only — TCP connect scanning, DNS A-record enumeration, HTTP path enumeration and single-request fingerprinting. Firelin does **not** exploit, brute-force credentials or modify targets.

### Features

- **Authorization gating** — `portscan` / `subdns` / `dirscan` exit with code 2 and a prominent notice unless `--yes-i-have-permission` is passed or `FIRELIN_I_HAVE_PERMISSION=yes`. `fingerprint` and `cidr` are read-only helpers and never gated. In `serve` mode the same rule applies per action: a server started without confirmation answers **403** for scan actions (over MCP the refusal arrives as an `isError` result naming the flag).
- **`portscan`** — TCP connect scan over a worker-thread pool. Targets: single IP, hostname (all resolved A records) or IPv4 CIDR. Networks larger than `/17` are rejected as too large (a typo like `0.0.0.0/0` can never fan out). Conservative defaults: 200 concurrent connects, 800 ms timeout.
- **`subdns`** — DNS subdomain enumeration against one UDP resolver (default `8.8.8.8:53`) using a hand-rolled minimal DNS client (no external resolver crate): ~200 built-in candidate labels (or a custom wordlist file), parallel queries, alive subdomains reported with their A records.
- **`dirscan`** — directory/path enumeration with `ureq` GET against a base URL: ~100 built-in paths (or a custom wordlist), status classification (`exists` 2xx / `redirect` 3xx / `forbidden` 401+403 / everything else; 404/410 are ignored), optional `--follow-redirects`.
- **`fingerprint`** — single read-only GET: HTTP status, `Server`, `X-Powered-By`, `X-AspNet-Version`, `X-Generator`, HTML `<title>`, final URL after redirects, timestamp.
- **`cidr`** — pure computation: expand an IPv4 CIDR into its address list (same size limits).
- **`serve`** — HTTP API on `127.0.0.1:8755` by default, BIT Remote-protocol compatible (`POST /invoke`), action catalog at `GET /invoke-actions`, MCP (Streamable HTTP JSON-RPC) on `POST /mcp` and `POST /`, optional Bearer token protection (covers MCP too).
- **BIT exec contract** — every subcommand accepts `--json`; when stdin is piped (not a TTY) a JSON object is read and merged over the CLI args (stdin wins).
- Rust (edition 2021), single static binary, cross-platform (macOS / Linux / Windows).

### Install

Download a release binary:

| Platform | Asset |
| --- | --- |
| macOS Apple Silicon | `firelin-v0.2.0-aarch64-apple-darwin.tar.gz` |
| macOS Intel | `firelin-v0.2.0-x86_64-apple-darwin.tar.gz` |
| Linux x64 | `firelin-v0.2.0-x86_64-unknown-linux-gnu.tar.gz` |
| Windows x64 | `firelin-v0.2.0-x86_64-pc-windows-msvc.zip` |

```bash
tar xzf firelin-v0.2.0-aarch64-apple-darwin.tar.gz
sudo mv firelin-v0.2.0-aarch64-apple-darwin/firelin /usr/local/bin/
firelin --version
```

Or build from source: `cargo install --git https://github.com/yxpil/Firelin` (checksums are produced by the release CI).

### Quick start

```bash
# read-only helpers: no authorization confirmation needed
firelin fingerprint http://10.0.0.5:8080 --json
firelin cidr 192.168.1.0/24 --json

# active scans: confirm you own the target or have written permission
firelin portscan 192.168.1.0/24 --ports 1-1024 --yes-i-have-permission --json
firelin portscan 10.0.0.5 --ports 22,80,443,8000-8100 --yes-i-have-permission
firelin subdns example-corp.test --resolver 8.8.8.8:53 --yes-i-have-permission
firelin dirscan http://10.0.0.5:8080 --yes-i-have-permission --json

# one-time env confirmation instead of the flag
FIRELIN_I_HAVE_PERMISSION=yes firelin portscan 127.0.0.1 --ports 80-90

# HTTP API
firelin serve --port 8755 --yes-i-have-permission
```

Every subcommand accepts `--json`. When stdin is piped (not a TTY), a JSON object is read from stdin and merged over CLI args (stdin wins) — that is the BIT exec contract. Accepted stdin keys: `target`, `domain`, `url`, `cidr`, `ports`, `concurrency`, `timeout_ms`, `wordlist`, `resolver`, `follow_redirects` (command parameters) and `host`, `port`, `token`, `yes_i_have_permission` (mode overrides). Example: `echo '{"target":"127.0.0.1","ports":"80-90","yes_i_have_permission":true}' | firelin portscan --json`.

Wordlists: `--wordlist builtin` (default) or a file path with one entry per line (`#` comments and blank lines ignored). The built-in lists are deliberately compact and neutral (~200 subdomain labels, ~100 paths).

Exit codes: `0` success; `2` error **or** missing authorization. Scan results are data, not errors.

### BIT Integration

Three ways to attach Firelin to BIT ([bit](https://github.com/yxpil/bit) `tools.json` snippets — paste-ready).

> **Authorization in BIT scenarios**: BIT's AI must obtain the user's confirmation *before* supplying `--yes-i-have-permission` or invoking a scan action. The flag is the AI's attestation that the user authorized the target. In `serve` mode the confirmation is bound to the server process, so an agent can never grant it retroactively.

**1) CLI (BIT "exec" runtime)** — BIT spawns the binary and sends `params` as JSON on stdin; stdout returns JSON:

```json
{
  "name": "firelin-portscan",
  "kind": "Script",
  "runtime": "exec",
  "code": "portscan 127.0.0.1 --ports 80-90 --yes-i-have-permission",
  "command": "firelin",
  "args": ["portscan", "--json"],
  "description": "TCP port scan; the AI must pass target/ports/yes_i_have_permission via params (user-confirmed authorization)"
}
```

`params` are merged over the CLI args (stdin wins), e.g. `params`: `{"target": "192.168.1.0/24", "ports": "1-1024", "yes_i_have_permission": true}`.

**2) Remote tool (HTTP serve mode)** — start `firelin serve --yes-i-have-permission` (default `127.0.0.1:8755`), then register:

```json
{
  "name": "firelin",
  "kind": "Remote",
  "url": "http://127.0.0.1:8755/invoke",
  "access_key": "",
  "description": "Firelin network assessment; params.action = portscan | subdns | dirscan | fingerprint | cidr"
}
```

BIT POSTs `{"tool_id": "...", "tool": "...", "invoked_by": "...", "params": {"action": "portscan", "target": "127.0.0.1", "ports": "80-90"}}` and receives the corresponding JSON. A serve started **without** `--yes-i-have-permission`/env answers **403** for `portscan`/`subdns`/`dirscan` while `fingerprint`/`cidr` keep working.

**2b) MCP client (Streamable HTTP)** — the same server speaks MCP on `http://127.0.0.1:8755/mcp` (BIT discovery also probes `POST /`): `initialize` → `tools/list` → `tools/call`. The five actions surface as five tools with JSON-Schema inputs (`portscan`, `subdns`, `dirscan`, `fingerprint`, `cidr`); a scan call on an unauthorized server returns `isError: true` with the refusal text instead of a transport error.

**3) Plain HTTP API (curl)**:

```bash
# liveness (never token-protected)
curl http://127.0.0.1:8755/health
# -> {"ok":true}

# action catalog + param hints + whether scan actions are unlocked
curl http://127.0.0.1:8755/invoke-actions

# run a fingerprint via the BIT Remote payload
curl -X POST http://127.0.0.1:8755/invoke \
     -H 'content-type: application/json' \
     -d '{"tool_id":"t1","tool":"firelin","invoked_by":"agent","params":{"action":"fingerprint","url":"http://127.0.0.1:8080/"}}'

# run an authorized portscan (serve must have been started with --yes-i-have-permission)
curl -X POST http://127.0.0.1:8755/invoke \
     -H 'content-type: application/json' \
     -d '{"params":{"action":"portscan","target":"127.0.0.1","ports":"80-90"}}'

# token-protected server
firelin serve --port 8755 --token sekrit
curl -H 'Authorization: Bearer sekrit' -X POST http://127.0.0.1:8755/invoke \
     -H 'content-type: application/json' -d '{"params":{"action":"cidr","cidr":"10.0.0.0/30"}}'
```

### API

| Endpoint | Method | Auth | Description |
| --- | --- | --- | --- |
| `/health` | GET | none | Liveness probe → `{"ok":true}` |
| `/invoke-actions` | GET | Bearer (optional) | Action catalog with param hints and `scan_authorized` state |
| `/invoke` | POST | Bearer (optional) | BIT Remote entry; routes on `params.action` (fallback `params.tool`) |
| `/mcp`, `/` | POST | Bearer (optional) | MCP Streamable HTTP JSON-RPC: `initialize`, `tools/list`, `tools/call`, `ping` |

Actions and their `params`:

| action | params | Scan-gated |
| --- | --- | --- |
| `portscan` | `target` (required), `ports` (`"1-1024"`), `concurrency` (200), `timeout_ms` (800) | yes |
| `subdns` | `domain` (required), `wordlist` (`"builtin"`\|file), `resolver` (`"8.8.8.8:53"`), `concurrency` (50) | yes |
| `dirscan` | `url` (required), `wordlist`, `concurrency` (20), `timeout_ms` (3000), `follow_redirects` (false) | yes |
| `fingerprint` | `url` (required), `timeout_ms` (5000) | no |
| `cidr` | `cidr` (required) | no |

Errors: `400` unknown action / missing or invalid param · `401` missing or invalid Bearer token · `403` scan action on a serve started without authorization · `500` internal. Over MCP, all action failures (including the scan gate) are returned as `isError: true` results; only protocol problems (unknown tool `-32602`, unknown method `-32601`, parse error `-32700`) are JSON-RPC errors.

### Security and boundaries

- **Authorization first**: scan commands refuse to run (exit 2) without the flag or env confirmation; serve-level scan actions answer 403 unless the server was started with confirmation. There is no way to authorize a single scan through `/invoke` — restart the server with the flag if you intend to scan.
- **Conservative defaults**: short timeouts (800 ms connect / 2 s DNS query / 3 s HTTP), bounded concurrency, CIDR size limit (`> /17` rejected), no default credential lists, no exploit payloads.
- **Internal-network targets are allowed by default** (RFC 1918 / loopback / link-local) because authorized assessments usually happen there — the authorization confirmation is your responsibility. Scanning third-party or production systems without written permission is illegal; you bear the consequences.
- **No exploitation**: Firelin enumerates and reads. It never brute-forces credentials, never sends exploit payloads and never writes to targets. `fingerprint` issues exactly one GET (redirects up to 5, still read-only).
- **Logs go to stderr** and contain no sensitive data (no tokens, no collected results — results go to stdout).

---

## 中文

### 简介

Firelin 是面向 AI 智能体（尤其是 [BIT](https://github.com/yxpil/bit)）的紧凑型网络评估工具集。它把一次授权评估中最常用的四项侦察能力收进一个 CLI 和一个 HTTP API，并内置授权门控——智能体无法跳过显式确认直接发起扫描。

**范围（v0.1 策略）**：只做侦察——TCP connect 扫描、DNS A 记录枚举、HTTP 路径枚举与单次请求指纹识别。Firelin **不做**漏洞利用、不做凭据爆破、不修改目标。

### 功能

- **授权门控** —— 未通过 `--yes-i-have-permission`（或环境变量 `FIRELIN_I_HAVE_PERMISSION=yes`）确认时，`portscan` / `subdns` / `dirscan` 打印醒目声明并以退出码 2 拒绝执行；`fingerprint` 与 `cidr` 是只读辅助命令，无需门控。serve 模式下同样按动作门控：未确认授权启动的服务对扫描动作返回 **403**（MCP 调用则以 `isError` 结果返回拒绝原因，并说明解锁标志）。
- **`portscan`** —— 基于 worker 线程池的 TCP connect 扫描。目标支持单 IP、主机名（解析全部 A 记录）或 IPv4 CIDR；大于 `/17` 的网段会被拒绝（避免 `0.0.0.0/0` 这类笔误失控）。默认保守：并发 200、连接超时 800 ms。
- **`subdns`** —— 子域名枚举：向单个 UDP 解析器（默认 `8.8.8.8:53`）发起 A 记录查询。DNS 客户端为手写的最小实现（不依赖第三方解析库）；内置约 200 个常见子域标签（或自定义词表文件），并发查询，输出存活子域及其 IP。
- **`dirscan`** —— 目录/路径枚举：用 `ureq` 对基 URL 逐个 GET，内置约 100 个常见路径（或自定义词表），按状态码分类（`exists` 2xx / `redirect` 3xx / `forbidden` 401+403 / 其余为 other；404/410 忽略），可选 `--follow-redirects`。
- **`fingerprint`** —— 单次只读 GET：HTTP 状态、`Server`、`X-Powered-By`、`X-AspNet-Version`、`X-Generator`、HTML `<title>`、重定向后的最终 URL、生成时间。
- **`cidr`** —— 纯计算：把 IPv4 CIDR 展开为地址列表（同样的规模上限）。
- **`serve`** —— HTTP API，默认 `127.0.0.1:8755`，兼容 BIT Remote 协议（`POST /invoke`），`GET /invoke-actions` 输出动作目录，MCP（Streamable HTTP JSON-RPC）挂载在 `POST /mcp` 与 `POST /`，可选 Bearer token 保护（同样覆盖 MCP）。
- **BIT exec 契约** —— 所有子命令支持 `--json`；stdin 为管道（非 TTY）时读取 JSON 对象并合并覆盖 CLI 参数（stdin 优先）。
- Rust（edition 2021）、单一静态二进制、跨平台（macOS / Linux / Windows）。

### 安装

从 Release 下载对应平台二进制（macOS/Linux 为 `tar.gz`，Windows 为 `zip`），或从源码构建：`cargo install --git https://github.com/yxpil/Firelin`（校验和由 release CI 生成）。

```bash
tar xzf firelin-v0.2.0-aarch64-apple-darwin.tar.gz
sudo mv firelin-v0.2.0-aarch64-apple-darwin/firelin /usr/local/bin/
firelin --version
```

### 快速上手

```bash
# 只读辅助命令：无需授权确认
firelin fingerprint http://10.0.0.5:8080 --json
firelin cidr 192.168.1.0/24 --json

# 主动扫描：先确认目标为自有资产或已获书面授权
firelin portscan 192.168.1.0/24 --ports 1-1024 --yes-i-have-permission --json
firelin portscan 10.0.0.5 --ports 22,80,443,8000-8100 --yes-i-have-permission
firelin subdns example-corp.test --resolver 8.8.8.8:53 --yes-i-have-permission
firelin dirscan http://10.0.0.5:8080 --yes-i-have-permission --json

# 用环境变量代替标志做一次性确认
FIRELIN_I_HAVE_PERMISSION=yes firelin portscan 127.0.0.1 --ports 80-90

# HTTP API
firelin serve --port 8755 --yes-i-have-permission
```

所有子命令支持 `--json`。stdin 为管道时读取 JSON 对象并合并覆盖 CLI 参数（stdin 优先，即 BIT exec 契约）。可用的 stdin 键：`target`、`domain`、`url`、`cidr`、`ports`、`concurrency`、`timeout_ms`、`wordlist`、`resolver`、`follow_redirects`（命令参数）与 `host`、`port`、`token`、`yes_i_have_permission`（模式覆盖）。示例：`echo '{"target":"127.0.0.1","ports":"80-90","yes_i_have_permission":true}' | firelin portscan --json`。

词表：`--wordlist builtin`（默认）或文件路径（每行一条，忽略 `#` 注释与空行）。内置词表刻意保持精简且中性（约 200 个子域标签、约 100 个路径）。

退出码：`0` 成功；`2` 出错**或**未授权。扫描结果是数据而非错误。

### BIT 集成

三种方式把 Firelin 接入 BIT（可直接粘贴到 [bit](https://github.com/yxpil/bit) 的 `tools.json`）。

> **BIT 场景下的授权确认**：BIT 的 AI 必须先获得用户对目标的明确授权，才能在参数中携带 `--yes-i-have-permission`（或 `yes_i_have_permission: true`）或调用扫描动作。该标志是 AI 对"用户已授权此目标"的确认。serve 模式下授权绑定在服务进程上，智能体无法事后补授——需要扫描时必须带标志重启服务。

**1) CLI（BIT "exec" 运行时）** —— BIT 拉起二进制，通过 stdin 发送 `params` JSON，从 stdout 读取 JSON 结果：

```json
{
  "name": "firelin-portscan",
  "kind": "Script",
  "runtime": "exec",
  "code": "portscan 127.0.0.1 --ports 80-90 --yes-i-have-permission",
  "command": "firelin",
  "args": ["portscan", "--json"],
  "description": "TCP 端口扫描；AI 必须通过 params 传入 target/ports/yes_i_have_permission（需用户确认授权）"
}
```

`params` 会合并覆盖 CLI 参数（stdin 优先），例如 `params`: `{"target": "192.168.1.0/24", "ports": "1-1024", "yes_i_have_permission": true}`。

**2) Remote 工具（HTTP serve 模式）** —— 先启动 `firelin serve --yes-i-have-permission`（默认 `127.0.0.1:8755`），再注册：

```json
{
  "name": "firelin",
  "kind": "Remote",
  "url": "http://127.0.0.1:8755/invoke",
  "access_key": "",
  "description": "Firelin 网络评估；params.action = portscan | subdns | dirscan | fingerprint | cidr"
}
```

BIT 发送 `{"tool_id": "...", "tool": "...", "invoked_by": "...", "params": {"action": "portscan", "target": "127.0.0.1", "ports": "80-90"}}` 并获得对应 JSON。未带 `--yes-i-have-permission`/环境变量启动的 serve 对 `portscan`/`subdns`/`dirscan` 返回 **403**，`fingerprint`/`cidr` 不受影响。

**2b) MCP 客户端（Streamable HTTP）** —— 同一服务在 `http://127.0.0.1:8755/mcp` 提供 MCP（BIT 发现流程也会探测 `POST /`）：`initialize` → `tools/list` → `tools/call`。五个动作以五个工具暴露（带 JSON Schema 入参）；未授权服务上的扫描调用返回 `isError: true` 及拒绝原因，而不是传输层错误。

**3) 纯 HTTP API（curl）**：

```bash
# 存活探针（不受 token 保护）
curl http://127.0.0.1:8755/health
# -> {"ok":true}

# 动作目录 + 参数说明 + 扫描动作是否已解锁
curl http://127.0.0.1:8755/invoke-actions

# 通过 BIT Remote 载荷执行指纹识别
curl -X POST http://127.0.0.1:8755/invoke \
     -H 'content-type: application/json' \
     -d '{"tool_id":"t1","tool":"firelin","invoked_by":"agent","params":{"action":"fingerprint","url":"http://127.0.0.1:8080/"}}'

# 执行已授权的端口扫描（serve 必须带 --yes-i-have-permission 启动）
curl -X POST http://127.0.0.1:8755/invoke \
     -H 'content-type: application/json' \
     -d '{"params":{"action":"portscan","target":"127.0.0.1","ports":"80-90"}}'

# token 保护的服务
firelin serve --port 8755 --token sekrit
curl -H 'Authorization: Bearer sekrit' -X POST http://127.0.0.1:8755/invoke \
     -H 'content-type: application/json' -d '{"params":{"action":"cidr","cidr":"10.0.0.0/30"}}'
```

### API

| 端点 | 方法 | 认证 | 说明 |
| --- | --- | --- | --- |
| `/health` | GET | 无 | 存活探针 → `{"ok":true}` |
| `/invoke-actions` | GET | Bearer（可选） | 动作目录、参数说明与 `scan_authorized` 状态 |
| `/invoke` | POST | Bearer（可选） | BIT Remote 入口；按 `params.action` 路由（回退 `params.tool`） |
| `/mcp`、`/` | POST | Bearer（可选） | MCP Streamable HTTP JSON-RPC：`initialize`、`tools/list`、`tools/call`、`ping` |

动作与参数：

| action | params | 需扫描授权 |
| --- | --- | --- |
| `portscan` | `target`（必填）、`ports`（`"1-1024"`）、`concurrency`（200）、`timeout_ms`（800） | 是 |
| `subdns` | `domain`（必填）、`wordlist`（`"builtin"`\|文件）、`resolver`（`"8.8.8.8:53"`）、`concurrency`（50） | 是 |
| `dirscan` | `url`（必填）、`wordlist`、`concurrency`（20）、`timeout_ms`（3000）、`follow_redirects`（false） | 是 |
| `fingerprint` | `url`（必填）、`timeout_ms`（5000） | 否 |
| `cidr` | `cidr`（必填） | 否 |

错误：`400` 未知动作 / 参数缺失或非法 · `401` Bearer token 缺失或错误 · `403` 未授权启动的 serve 收到扫描动作 · `500` 内部错误。MCP 侧所有动作失败（含扫描门控）都以 `isError: true` 结果返回；只有协议层问题（未知工具 `-32602`、未知方法 `-32601`、解析错误 `-32700`）才是 JSON-RPC 错误。

### 安全与合规

- **授权优先**：扫描命令未经确认即拒绝执行（退出码 2）；serve 的扫描动作在未确认授权启动时一律 403。不存在"单次调用临时授权"——需要扫描就带标志重启服务。
- **保守默认**：短超时（连接 800 ms / DNS 查询 2 s / HTTP 3 s）、并发有上限、CIDR 有规模上限（大于 `/17` 拒绝）、不含默认凭据表、不含任何利用载荷。
- **内网目标默认放行**（RFC1918 / 回环 / 链路本地），因为授权评估通常发生在内网——授权确认由你负责。未经书面授权扫描第三方或生产系统属违法行为，后果自负。
- **只侦察、不利用**：Firelin 只做枚举与读取，绝不爆破凭据、绝不发送利用载荷、绝不向目标写入数据。`fingerprint` 只发一次 GET（重定向最多 5 次，仍为只读）。
- **日志只到 stderr** 且不含敏感信息（无 token、无结果数据——结果走 stdout）。

---

Part of the [BIT](https://github.com/yxpil/bit) ecosystem.
