# LOCAL-PANEL 响应式局部更新 + RTT 回退探测（imac 真机取证，2026-11-07）

对应 commit `2296ce9`（`feat(panel,agent): responsive local panel with partial updates
and RTT endpoint fallback`），修两个用户可见缺陷：

1. **面板刷新抖动**：原 `<meta http-equiv=refresh content=5>` 每 5s 整页重载
   （闪屏、丢滚动/焦点/复制钮状态）→ 改只读 `GET/HEAD /state.json`（与页面
   同一 `snapshot()` 三块数据源），页面去掉 meta refresh，内联 JS 每 5s
   fetch 后**值 diff 只 patch 变化单元格**；行数变化才整体替换 tbody（html
   与页面同一 Rust 代码生成）；初始仍服务端预渲染（无 JS 也见三块）；无
   bundler/React，`location.reload(` 全文不存在。
2. **RTT 恒「—」**：原 agent 只 ping 对端 overlay VIP，WireGuard 接口/防火墙
   不答 ICMP → 恒 None → 恒「—」。现 overlay 不通**回退 ping 对端 endpoint
   underlay 地址**；读数来源（`overlay` / `endpoint` / `unreachable` /
   `unprobed`）随 RTT 进 ledger → `direct-peers.json`（新字段 `rtt_source`，
   旧文件缺字段按「未测」标注）；面板 RTT 列 tooltip 标来源，「最近握手」
   列保留为链路活性主证据。

## 门禁（本机 Linux）

| 项 | 结果 |
|---|---|
| `cargo test --workspace` | **908 passed / 0 failed**（exit 0） |
| `cargo clippy --workspace --all-targets -- -D warnings` | 净 |
| `cargo fmt --check` | 净 |
| 新增测试 ① state.json 路由 | `state_json_route_serves_three_sections_and_stays_read_only`（GET 200 + JSON 三块 + POST 405 + HEAD 无 body + 未知路径 404） |
| 新增测试 ② RTT 回退选择逻辑 | `rtt_fallback_prefers_overlay_then_endpoint_then_unreachable`（overlay 通=overlay；不通→endpoint；两路都不通/无 endpoint=不可测；来源稳定字符串） |
| 新增测试 ③ 无 meta refresh + fetch patch | `page_polls_state_json_and_never_full_page_reloads`（无 `http-equiv="refresh"`、无 `location.reload(`、有 `fetch('/state.json'`、`setInterval(poll`、内联 seed、`data-f` diff 键） |
| CI（push `2296ce9`） | `CI` success、`Dataplane acceptance` success（其余作业见 run 42353937124/42353937159） |

## 部署（imac，SSH 别名 `imac` = 192.168.5.117）

- 产物：Linux 交叉编译 `x86_64-pc-windows-gnu` release。
  - `meshlet-agent.exe` SHA256 `E7C9E5A0…4EB529E`（落盘后远程 Get-FileHash 与本地一致）
  - `meshlet-tray-host.exe` SHA256 `61146220…6A6649`（同上核对一致）
- 部署路径：agent `%LOCALAPPDATA%\meshlet\meshlet-agent.exe`（计划任务
  `MeshletAgentDeploy` 管理，替换后任务自动重启拉起新 exe）；
  tray-host `C:\Program Files\Meshlet\meshlet-tray-host.exe`（计划任务
  `MeshletTrayHost`）。面板 URL：`http://127.0.0.1:60652/`（local-panel.json
  pid=65236）。
- 过程注意（如实记录）：手工 WMI 直启 agent 与任务自动重启短暂并存了两个
  agent 实例，已停掉手工实例，恢复「任务托管单实例」（agent 63880 +
  tray-host 65236，均晚于 exe 落盘时间，跑的是新二进制）。

## 真机取证

### ① 页面不再整页刷新（curl 原始字节 + 截图）

`curl http://127.0.0.1:60652/`（17,221 B）：

| 探针 | 结果 |
|---|---|
| `http-equiv="refresh"` | **不存在** |
| `location.reload(` | **不存在** |
| `fetch('/state.json'` + `setInterval(poll` | 存在 |
| 内联初始快照 `id="panel-state"` | 存在（JS diff 基线） |
| 三块 section id | `node` / `direct` / `routes` 全在 |
| 副标题 | 「每 5 秒局部更新（不整页刷新）」 |
| 截图 | `panel-reactive-imac.png`（98,028 B，Edge headless） |

### ② 局部更新数据源与只读纪律

`curl /state.json` → `200` + `Content-Type: application/json; charset=utf-8`，
JSON 三块齐全（`node` / `peers` / `routes`）；`POST /state.json` → **405**、
`POST /` → **405**、`HEAD` → 200 无 body、未知路径 → 404。`node.fields` 带
`data-f="node.{i}"` diff 键、`copy_index=1`（虚拟 IP 复制按钮），`peers.rows`
每行带 `data-f="peer.{i}.*"` 键与 `rtt_title`。

### ③ 值 diff 局部更新实锤（同结构、值变）

页面内联快照（16:15:44 落盘 seed）vs 57s 后 `GET /state.json`（16:16:41）：

| peer | seed（页面预渲染） | 57s 后 state.json | JS 行为 |
|---|---|---|---|
| coding-vm | 握手「80 秒前」 | 「2 分钟前」 | 仅 patch `data-f="peer.1.handshake"` |
| openclaw-win | 握手「80 秒前」 | 「2 分钟前」 | 同上 |

行数不变（4=4，结构稳定）→ 走单元格 diff 分支，滚动/焦点/复制钮状态保留，
无整页重载。两张快照全文不相等（`snapA != snapB`），证明轮询数据在变。

### ④ RTT 回退探测真机行为

替换前（旧 agent）`direct-peers.json`：4 个 peer 全部 `rtt_ms: null`（恒「—」，无来源）。
替换后（新 agent）：

```json
{"name":"cuihaitao", "mode":"p2p_direct", "rtt_ms":null, "rtt_source":"unreachable", "endpoint":"10.147.19.97:51820", "last_handshake_at":1794039046}
{"name":"coding-vm", "mode":"p2p_direct", "rtt_ms":null, "rtt_source":"unreachable", "endpoint":"10.147.19.130:51820", "last_handshake_at":1794039112}
{"name":"windows-desktop", "mode":"hub_relay", "rtt_ms":null, "rtt_source":null, ...}
{"name":"openclaw-win", "mode":"p2p_direct", "rtt_ms":null, "rtt_source":"unreachable", "endpoint":"10.147.19.49:51820", "last_handshake_at":1794038930}
```

面板 RTT 列显示「—」且 **tooltip 标明来源**：
`来源：不可测（overlay 与 endpoint 均无响应，以「最近握手」为活性证据）`；
`direct_pending`（拨号中）对端标 `来源：未测（对端无直连路径或探测尚未完成）`。

**「不可测」是真网络结论、不是实现缺陷**（已在 imac 上原生复核）：
`ping -n 1 10.147.19.97`（coding-vm endpoint）与 `ping -n 1 10.240.0.3`
（openclaw overlay VIP）均 **100% 丢包**——全 Windows 网格的对端防火墙不答
ICMP。回退路径已按设计打出（overlay 不通 → endpoint 也不通 → 如实标
「不可测」），「最近握手」列保持新鲜（`3 分钟前` 等），活性证据链完整。
overlay 或 endpoint 任一可达的网格（如同 LAN 直连、Linux 对端）即显示实测
毫秒并标注 `overlay 实测` / `endpoint 实测（underlay 回退）`——该分支由
门禁测试 ② 与面板测试 `rtt_column_labels_its_source` 覆盖。

## 证据文件

- `panel-reactive-imac.png`：imac 面板截图（三块齐全、副标题「局部更新
  （不整页刷新）」、RTT 列「—」、最近握手新鲜值、复制按钮在虚拟 IP 与各
  overlay IP 旁）。
- `state-snap-a.json` / `state-snap-b.json`：上述 ③ 的两张 `/state.json` 原文。
- `panel-page-imac.html`：页面原文（无 meta refresh、含 fetch patch 脚本）。
