# Firelin Wiki / Firelin 维基

**Firelin** — Authorized network assessment toolkit for AI agents around the [BIT](https://github.com/yxpil/bit) ecosystem: TCP port scanning, DNS subdomain enumeration, directory enumeration, HTTP fingerprinting. Scan commands require an explicit authorization confirmation (`--yes-i-have-permission` or `FIRELIN_I_HAVE_PERMISSION=yes`).

**Firelin** —— 面向 [BIT](https://github.com/yxpil/bit) 生态 AI 智能体的授权网络评估工具集：TCP 端口扫描、DNS 子域名枚举、目录枚举、HTTP 指纹识别。扫描类命令必须先通过授权确认（`--yes-i-have-permission` 或 `FIRELIN_I_HAVE_PERMISSION=yes`），否则拒绝执行。

> **⚠️ 仅限自有资产或已获书面授权的资产。未经授权扫描计算机系统属违法行为。 / Only for assets you own or have written permission to test. Unauthorized scanning is illegal.**

- Repo / 仓库: <https://github.com/yxpil/Firelin>
- Releases / 发行版: <https://github.com/yxpil/Firelin/releases>
- Binary name / 二进制名: `firelin`
- Default port / 默认端口: `8755`

---

## Install / 安装

Grab a per-platform binary from the [latest release](https://github.com/yxpil/Firelin/releases/latest) (`tar.gz` for macOS/Linux, `zip` for Windows), or:

从 [最新 Release](https://github.com/yxpil/Firelin/releases/latest) 下载对应平台二进制（macOS/Linux 为 `tar.gz`，Windows 为 `zip`），或：

```bash
cargo install --git https://github.com/yxpil/Firelin
```

## Usage / 使用

```bash
# read-only helpers / 只读辅助命令（无需授权确认）
firelin fingerprint http://10.0.0.5:8080 --json   # status, server, title... / 状态、server、标题等
firelin cidr 192.168.1.0/24 --json                # expand CIDR to addresses / 展开为地址列表

# active scans (require authorization) / 主动扫描（需授权确认）
firelin portscan 192.168.1.0/24 --ports 1-1024 --yes-i-have-permission --json
firelin subdns example-corp.test --resolver 8.8.8.8:53 --yes-i-have-permission
firelin dirscan http://10.0.0.5:8080 --yes-i-have-permission --json

# HTTP API (BIT Remote compatible) / HTTP API（兼容 BIT Remote）
firelin serve --port 8755 --yes-i-have-permission
```

Every subcommand accepts `--json`; piped stdin JSON merges over CLI args (stdin wins — the BIT exec contract):

所有子命令支持 `--json`；管道 stdin 的 JSON 会合并覆盖 CLI 参数（stdin 优先，即 BIT exec 契约）：

```bash
echo '{"target":"127.0.0.1","ports":"80-90","yes_i_have_permission":true}' | firelin portscan --json
```

Exit codes / 退出码: `0` success / 成功 · `2` error or missing authorization / 出错或未授权。

## BIT integration / BIT 集成

Three ways / 三种方式:

1. **CLI (exec runtime)** — BIT spawns `firelin portscan --json` with `code` like `portscan 127.0.0.1 --ports 80-90 --yes-i-have-permission`, sends `params` JSON via stdin (`target`, `ports`, `yes_i_have_permission`...), reads JSON from stdout. The AI must obtain the user's authorization **before** passing the confirmation flag.
2. **Remote tool** — run `firelin serve --yes-i-have-permission`, register URL `http://127.0.0.1:8755/invoke`; BIT POSTs `{"tool_id":"...","tool":"...","invoked_by":"...","params":{"action":"portscan","target":"127.0.0.1","ports":"80-90"}}`. A serve started without confirmation answers **403** for scan actions (`fingerprint`/`cidr` stay available).
3. **Plain REST** — `GET /health`, `GET /invoke-actions`, `POST /invoke` (see [Protocol](Protocol)).

## FAQ

**Q: Why does `portscan` exit with code 2 before doing anything? / 为什么 `portscan` 什么都没做就退出码 2？**
The authorization gate is working. Append `--yes-i-have-permission` or set `FIRELIN_I_HAVE_PERMISSION=yes` after you have confirmed the target is yours / covered by written permission.

这是授权门控在生效。确认目标为自有资产或已获书面授权后，加上 `--yes-i-have-permission` 或设置 `FIRELIN_I_HAVE_PERMISSION=yes` 即可。

**Q: Why is `192.168.0.0/16` rejected as "too large"? / 为什么 `192.168.0.0/16` 被拒绝"过大"？**
CIDRs larger than `/17` are refused (max 65535 addresses) so a typo like `0.0.0.0/0` can never fan out. Scan narrower ranges, e.g. `/24` blocks.

大于 `/17` 的网段被拒绝（最多 65535 个地址），避免 `0.0.0.0/0` 这类笔误失控。请改用更窄的网段（如 `/24`）。

**Q: Can I authorize scanning through the HTTP API? / 能通过 HTTP API 临时授权扫描吗？**
No. Scan authorization is bound to the serve process at startup (`--yes-i-have-permission` or env). `/invoke` on a non-authorized serve answers 403 for `portscan`/`subdns`/`dirscan`; `fingerprint`/`cidr` remain available.

不能。扫描授权在 serve 启动时绑定（`--yes-i-have-permission` 或环境变量）。未授权启动的 serve 对扫描动作返回 403；`fingerprint`/`cidr` 不受影响。

**Q: Does Firelin exploit anything or brute-force credentials? / 会利用漏洞或爆破凭据吗？**
No. v0.1 is reconnaissance only: connect scans, DNS A queries, HTTP GETs, fingerprinting. No payloads, no credential lists, no writes to targets.

不会。v0.1 只做侦察：connect 扫描、DNS A 查询、HTTP GET、指纹识别。没有利用载荷、没有凭据表、不向目标写数据。

**Q: What do dirscan classifications mean? / dirscan 的分类是什么意思？**
`exists` (2xx), `redirect` (301/302/307/308), `forbidden` (401/403 — worth attention), `other` (everything else). 404/410 are ignored entirely.

`exists`（2xx）、`redirect`（301/302/307/308）、`forbidden`（401/403 —— 值得关注）、`other`（其余）。404/410 完全忽略。

**Q: Where do logs and results go? / 日志和结果分别输出到哪里？**
Logs/progress go to stderr, results go to stdout (pure JSON with `--json`). Logs contain no tokens or scan results.

日志/进度走 stderr，结果走 stdout（`--json` 时为纯 JSON）。日志不含 token 与扫描结果。

---

Part of the [BIT](https://github.com/yxpil/bit) ecosystem.
