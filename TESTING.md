# 测试说明（Firelin）

Firelin 是一个扫描器 CLI + 本地 HTTP/MCP 服务。测试分两层：`src/` 内的单元测试，
以及仓库根 `tests/` 下的黑盒集成测试（直接跑真实 `firelin` 二进制，打本地 TCP/UDP/HTTP 桩）。

## 怎么跑

```powershell
cargo test                 # 全部
cargo test --test cli      # 只跑 CLI / serve 集成测试
cargo test --test mcp      # 只跑 MCP(JSON-RPC) 集成测试
cargo test --test injection # 只跑注入测试
```

集成测试会自己起本地桩服务器（127.0.0.1 随机端口），**不需要外网**。
扫描类命令需要授权：测试通过 `--yes-i-have-permission` 或 `FIRELIN_I_HAVE_PERMISSION` 解锁。

## 预期结果

- 单元测试（`src/main.rs` 内 `#[cfg(test)]`）：约 34 个，全过。
- 集成测试：`tests/cli.rs`（约 11）、`tests/mcp.rs`（5）、`tests/injection.rs`（2）。
- 全部应 **0 失败**；`serve` 相关用例应在数秒内就绪（不再卡住）。

## 测了什么

- **CLI**：`cidr` 展开与校验、端口扫描命中/漏报、指纹提取、目录扫描状态分类、
  授权闸门（无 flag/env 时退出码 2 并提示）、BIT stdin 契约合并。
- **serve / MCP**：`/health`、`/invoke-actions`、`/invoke`、MCP JSON-RPC 握手、
  `tools/list` 与五个工具实跑、扫描授权门、Bearer token 保护、协议错误码。
- **注入（`tests/injection.rs`）**：Firelin 消费**不可信 HTTP 响应**，
  证明恶意载荷被当作不透明数据处理：
  - `hostile_http_response_is_treated_as_opaque_json_data`：含
    `<script>alert()</script>` 的标题、含 `'; DROP TABLE--` 的响应头，
    原样进 JSON（不执行、不破出 JSON 信封）。
  - `malformed_and_non_http_inputs_are_rejected_not_crashing`：乱码响应得到干净的
    退出码 2，不 panic。

## 备注

- 本仓库**没有插件/钩子/事件回调机制**（纯扫描 CLI + 无状态 HTTP/MCP 服务），
  故不涉及钩子生命周期测试。
- `serve` 会在 stdin 非 TTY 时读取 BIT exec 契约；集成测试里给它 `Stdio::null()`
  （立即 EOF），避免它在绑定端口前阻塞读 stdin。
