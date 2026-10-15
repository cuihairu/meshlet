# 网络诊断

> 来源：[存档 §12.7](../review/chatgpt-2026-10-13.md)。实现：`apps/server/src/diagnostics.rs`、
> migration `006_diagnostics.sql`（`diagnostics_runs` 表）、控制台 Diagnostics 区块。

## 定位：只诊断，不修复

13 项检查按**故障层**归类（隧道 / 路由 / 转发 / Alias / 控制面），输出**准确诊断结果 +
可执行建议**。第一版**不做任何自动修复**——每条 `fail` / `warning` / `unavailable`
都给出一句
可执行的下一步（多为在目标机器上跑的命令），由运维照做。

判读纪律（§17.2 组合判读 + 本单硬要求）：

- **不假绿**：控制面观测不到的本机状态（WireGuard 接口、内核路由、IP forwarding、
  防火墙、NAT 规则）如实报 `unavailable`——它**不是「健康」**，并给出一句可在目标机器
  上执行的检查命令；
- **控制面在册 ≠ 隧道正常**：Peer 注册（③）与握手新鲜（④）是两项独立检查，③的
  detail 必须点名「registration only」（§12.4：握手只证明隧道连通，agent 上报才
  证明设备功能正常）；
- **记录 ≠ 发布**：路由/修订的 pass 只表示控制面口径（已记录 + 最新修订已应用），
  不证明网关内核装了路由（那是 ⑤⑦ 的本机读数）。

## 十三项检查

顺序与故障层为控制台与测试共用的契约。

| # | id | 层 | 判据 | 典型信号 |
|---|---|---|---|---|
| ① | `api_reachable` | 控制面 | 能读到报告即 API 在服务 | 恒 `pass`（报告由管理 API 产出） |
| ② | `wg_interface_exists` | 隧道 | 设备本机 WireGuard 接口存在 | 恒 `unavailable` → `wg show mesh0` |
| ③ | `server_peer_configured` | 隧道 | 注册表里有公钥（控制面在册） | `pass` + detail 点名「registration only」 |
| ④ | `recent_handshake` | 隧道 | 握手在 `handshake_window`（默认 120s）内 | 全新鲜 `pass`；缺失/过期 `fail`（§12.4 唯一隧道层证据） |
| ⑤ | `overlay_route_present` | 路由 | 内核有到 overlay 的路由 | 恒 `unavailable` → `ip route show to <overlay>` |
| ⑥ | `ip_forwarding_enabled` | 转发 | 网关机 `net.ipv4.ip_forward=1` | 恒 `unavailable` → `sysctl net.ipv4.ip_forward` |
| ⑦ | `firewall_allows_forwarding` | 转发 | 网关机 FORWARD 链允许 mesh 流量 | 恒 `unavailable` → `iptables -L FORWARD -n -v` |
| ⑧ | `lan_gateway_agent_online` | 路由 | 每条路由的网关 agent 有**新鲜上报** | 全在线 `pass`；仅握手新鲜 `warning`（tunnel_only）；离线/未注册 `fail` |
| ⑨ | `lan_route_published` | 路由 | 路由已记录 + 覆盖它的最新修订已应用 | `applied`→`pass`；`failed`→`fail`；否则 `warning` |
| ⑩ | `alias_prefix_conflict` | Alias | 域层冲突检测（overlay 重叠 / alias 互叠 / 绑定路由网段不一致） | 无冲突 `pass`；有冲突 `fail` 并列出对端（ADR-006） |
| ⑪ | `nat_rules_effective` | Alias | 网关机 NAT 规则存在且计数器增长 | 恒 `unavailable` → `iptables -t nat -L -n -v` |
| ⑫ | `config_revision_consistent` | 控制面 | 最新未回滚修订状态 = 期望/实际一致性 | `applied`→`pass`；`failed`→`fail`（带 error_summary）；否则 `warning` |
| ⑬ | `mtu_planned` | 隧道 | server 配置的计划隧道 MTU（§7.5，配置面事实） | 显式配置→`pass`（detail 点名计划值）；未配置→`warning`（默认 1420 + `ping -M do -s 1392` 实测建议） |

无对象的检查如实报 `not_applicable`（无设备→③④⑬、无路由→⑧⑨、无 Alias 映射→⑩、无
修订→⑫）——**如实区分于 `pass`**。

⑬ 只报告**计划值**（控制面知道的配置事实），不假装观测到实际接口/路径 MTU：未显式
配置时设备按 WireGuard 默认 1420 组接口，PPPoE/4G 等小 MTU 底层会出现大包黑洞——
建议命令 `ping -M do -s 1392 <overlay-peer-ip>`（1420−28）在设备侧实测（§7.5）。

②⑤⑥⑦⑪ 五项恒 `unavailable`：本机无 root/CAP_NET_ADMIN，控制面读不到这些主机本地
读数，agent 也只上报 `last_handshake_at`。这是**设计上的诚实**，不是缺陷：页面会把
`unavailable` 单独标色并在建议里给出命令，绝不把它渲染成通过项。

## API

| 端点 | 行为 |
|---|---|
| `GET /api/v1/networks/{network_id}/diagnostics` | 返回**最近一次**运行的报告（`DiagnosticsReport` JSON）；从未运行 → `404`（`code: "not_found"`，内部变体 `ServiceError::DiagnosticsNotRun`，消息点名 POST 触发方式） |
| `POST /api/v1/networks/{network_id}/diagnostics` 🔒 | 计算 13 项检查 → 落一行快照（`diagnostics_runs`）→ 返回报告；记审计 `diagnostics.run`（detail 含 checks/fail/unavailable 计数） |

- 门禁同其余管理端点：会话认证；POST 另需 `write` 权限 + CSRF 头；
- **快照语义**：`GET` 读的是上次 `POST` 落库的同份 JSON（逐字节相同，不是现算）——
  「没有结果」不等于「结果都是好的」；
- 持久化（migration 006）：`diagnostics_runs(id, network_id, checked_at, report JSON)`，
  `GET` 按 `id DESC` 取一行；
- 报告里每个 check 含 `id` / `name` / `layer` / `status` / `detail` / `suggestion`
  （`pass` 时 suggestion 为空串）。

## 控制台

网络详情页 Diagnostics 区块：进入时 `GET` 最近快照，未运行过显示「No diagnostics run yet」
提示；「Run checks」按钮触发 `POST` 并刷新展示。报告按层分组（Tunnel / Routing /
Forwarding / Alias / Control plane），状态词用彩色 pill，顶部一行计数（如
`2 pass · 1 fail · 5 unavailable`），每项附 detail 与建议（建议等宽显示，可直接照抄执行）。
页面固定声明：**unavailable ≠ pass**。

## 建议的走查顺序

1. ⑫ 先看：最新修订是否 `applied`——期望配置没应用，其余检查都在「未生效的
   期望」上判；
2. ④ 与 ⑧：隧道与路由层的分水岭——注册在册但握手过期/缺失，或网关只有
   tunnel_only，分别对应「接口/密钥/agent 进程」三类不同故障；
3. ⑨：路由层是否在册且已发布；
4. ⑬：握手新鲜但大包传输卡死（小包通、文件传不动）先查 MTU 计划值与实测建议（§7.5）；
5. ②⑤⑥⑦⑪：**去机器上**按建议逐项执行（控制面只能给命令，读数必须本机取）。

交叉阅读：§12.4（presence 判读）、§10.1（DB 写入 ≠ 生效）、§17.2（组合判读纪律）、
[API 契约](../architecture/api-contract.md)。
