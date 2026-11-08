# Meshlet MCP Server · 2026-11-08

Status: Proposed (user direction 2026-11-08). Supersedes the local-API scope in
`docs/analysis/agent-local-api-2026-10-19.md` — that research recommended an
OS-principal IPC boundary (unix socket / named pipe) for a **script/CLI/console**
control surface. The user has redirected the same intent to **MCP**: the consumer
is now an AI client, and the standard interop surface is the Model Context Protocol.
The 10-19 research's security analysis still applies; only the transport and
consumer change.

## Decision

- **MCP lives in the agent** (not a new binary, not the tray host). The agent
  already owns `{state_dir}/tray/status.json`, `direct-peers.json`,
  `applied.json` and `agent.toml` — every fact an AI needs is already local to it.
  No new process, no duplicate file readers, one lifecycle the tray already watches.
- **Transport: streamable HTTP on loopback** (`127.0.0.1:<port>`), rmcp
  `StreamableHttpService` + axum. Rationale vs stdio: the agent is a long-lived
  daemon; stdio would make it a child of whatever client launches it and die with
  it (the exact failure documented in windows-remote-ops §8). Loopback HTTP keeps
  the endpoint persistent and independently reachable by any local AI client.
- **`[mcp] enabled` defaults OFF** — matches the standing rule (数据外发/对外接口
  默认关，配置显式开，开启时明示范围). AI querying a node's mesh facts is a
  read surface, but it is still a listener, so it is opt-in.
- **Read-only tool set by default** (AI query, no mutation):
  `status`, `info`, `peers`, `routes`, `networks`, `diag`. Write tools
  (`peer dial`) are a later phase behind their own flag.
- **Secrets never exposed**: `agent.toml` fields `device_token` / `bootstrap_token`
  are redacted in any `config` output; the `config` tool is excluded from the
  default set anyway. `status.json` carries no secrets today.

## Tools

| Tool | Reads | Notes |
|---|---|---|
| `status` | `{state_dir}/tray/status.json` | agent state, device name, virtual IP, version, env |
| `info` | `agent.toml` (top-level only) + wg local IP | device_name, server_url, ip, state — same as `meshlet info` |
| `peers` | `direct-peers.json` | name, overlay IP, mode, RTT, endpoint, last handshake, public key |
| `routes` | `applied.json` (`last_good_plan.routes`, fallback ledger `routes`) | destination, next-hop, interface, source |
| `networks` | wg routes (Windows) / platform | destination + interface |
| `diag` | wg + interface snapshot | network diagnostics (same as `meshlet agent diag`) |

All read the same files the local panel and CLI read — one source, three surfaces.

## Config

```toml
[mcp]
# AI 可查询本机 mesh 事实（loopback HTTP）。默认关。
enabled = false
# 监听端口；0 = 随机（写 `{state_dir}/mcp.json` 的 `{port, pid}`，与
# local-panel.json 同款交接文件，托盘/CI/客户端据此拿端口）。
port = 0
```

- On enable the agent starts the MCP service on a loopback thread, writes
  `{state_dir}/mcp.json` atomically (`.tmp` + rename, same as local-panel.json).
- On disable/exit it stops the listener and removes the file.

## Tray menu (Windows)

`apps/tray-host/src/menu.rs` gains one row in the status block:

```
[MCP] 开启 : http://127.0.0.1:<port>/mcp      (enabled, disabled/grayed)
```

- The row is **read-only display** (状态，是否开启) — it reads `[mcp] enabled`
  from `agent.toml` and, when on, the live port from `{state_dir}/mcp.json`.
- Disabled → grayed "MCP：关闭"; enabled → normal "MCP：开启 <port>".
- No click action in v1 (toggling from tray is a later phase; the project rule
  is explicit config for enabling sensitive surfaces).

## Why not stdio / why not the server hub

- **stdio**: correct for a CLI-launched MCP server, wrong for a daemon — the
  agent must not die with the client. Also each AI client would spawn its own
  reader; loopback HTTP is one endpoint many clients can share.
- **hub-side MCP**: the user's ask is per-machine query ("ai 快速访问不同的机器").
  A hub-side server would need the hub to hold per-device facts and would re-route
  through the control plane — more moving parts, worse offline story, and it makes
  the hub a query target rather than the mesh the nodes form. The local agent is
  the truthful owner of each node's state.

## Phases

1. **P1 — read-only MCP in agent + config + `mcp.json` handoff.** Tools:
   status/info/peers/routes/networks/diag. Loopback streamable HTTP. No tray change.
2. **P2 — tray menu row** (MCP on/off + port). Depends on P1's `mcp.json`.
3. **P3 — write tool** `peer dial` behind `[mcp] allow_dial = false` (default off).
   Only if the user wants an AI to trigger dials.
4. **P4 — docs**: README.zh section "AI 访问（MCP）" + a client config snippet
   (Claude Code `mcp` block pointing at `http://127.0.0.1:<port>/mcp`).

## Scope limits

- Loopback only. No remote binding — an AI on another machine reaches this node's
  MCP via SSH (mesh alias) or via the mesh itself in a later phase; never by
  widening the listener.
- No secrets in any tool output; `config` excluded from the default set.
- This is agent-local. The server/hub API surface is unchanged (MOD-05 territory,
  separate).

## ADR

Follows ADR-013's pattern (agent-local read source, OS boundary). A separate ADR
is not required if this design doc is accepted — it supersedes the 10-19 proposal
for the MCP consumer; the 10-19 IPC recommendation remains valid for the
script/CLI control surface if that is ever built.
