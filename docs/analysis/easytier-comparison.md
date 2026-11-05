# Meshlet × EasyTier 功能对比（2026-11-04）

## Takeaway

EasyTier 的定位是**去中心化、开箱即用**：无服务端、`--network-name/--network-secret` 一行起网、自动 NAT 打洞、多协议传输。meshlet 的定位是**自托管 + 强管控**：
控制面（server）+ WG hub + agent 三层，bootstrap/invite 审批、修订状态机、审计、作用域 token。

两者不是竞争关系而是互补。值得从 EasyTier 借鉴的集中在连通性（WireGuard 门户、NAT 打洞、
多 hub 冗余）与可观测性（per-node 端点/NAT 类型展示）；meshlet 反过来在服务发布（L4/L7 转发、TLS 直通、健康探测、分流 DNS）与治理（审批、审计、
修订/回滚）上强于 EasyTier。

## 对比矩阵

| 能力 | EasyTier | meshlet | 判定 |
| --- | --- | --- | --- |
| 部署模型 | 去中心化，无服务端，节点对等 | 中心控制面 + WG hub + agent | 架构差异（设计使然） |
| 节点加入 | `--network-name/--network-secret` 即起网 | bootstrap token → pending → 审批；或 invite 一次性 | meshlet 管控更强 |
| 平台 | Win/macOS/Linux/FreeBSD/Android，x86/ARM/MIPS | Linux + Windows（agent/CLI/tray） | EasyTier 更广（无 macOS/Android） |
| 加密 | AES-GCM 或 WireGuard | WireGuard（ChaCha20-Poly1305） | 相当 |
| NAT 打洞 | UDP + IPv6 打洞，NAT4-NAT4 | 直连依赖端点候选 + SameLan 判中；**无打洞** | **EasyTier 强**（meshlet 直连在无端口映射 NAT 后回退 hub 中继） |
| 传输协议 | TCP/UDP/WSS/WG，零拷贝 | 仅 WG（UDP）+ 控制面 HTTP | EasyTier 多协议 |
| 丢包优化 | KCP/QUIC 代理 | 无 | EasyTier 有 |
| 子网共享 | `-n 10.1.1.0/24` 自动同步路由 | LanRoute CRUD（alias 前缀解决重叠） | 相当（meshlet 多了重叠前缀处理） |
| 智能路由 | 延迟优先、自动选路 | 直连/中继二值（握手年龄升降级），无按 RTT 多路选 | EasyTier 更强（多候选 RTT 选优） |
| WG 门户 | `--vpn-portal wg://`：任何原生 WG 客户端（含 iOS/Android）可入网 | 无——必须跑 meshlet agent | **EasyTier 强**（移动端关键缺口） |
| 中继/共享节点 | 社区共享节点 + 自建共享节点，可连多个 | 单一 hub = SPOF | **EasyTier 强**（多 hub 冗余） |
| peer 观测 | `easytier-cli peer` 表：lat_ms/loss_rate/rx/tx/tunnel_proto/**nat_type** | 控制面记录 `observed_ip`（hub 观测心跳源）但**丢端口、未暴露**；console 仅 `direct_links`（agent 上报的对端链路） | **EasyTier 强**（见 §meshlet 差距） |
| 服务发布 | 无（README 未提及） | PortForward/HTTP/HTTPS 发布、TLS SNI 直通、CIDR/Bearer 授权、健康探测、分流 DNS | **meshlet 强** |
| 治理 | 无审批/审计概念 | 设备审批、撤销、审计日志、作用域 token、CSRF/会话 | **meshlet 强** |
| 配置一致性 | 无 | 修订状态机（DB 写不声称生效直到 apply）、漂移检测、last-good 恢复 | **meshlet 强** |
| 运维入口 | web/CLI/客户端 | web console + CLI + Tauri tray | 相当 |
| 单二进制 | 静态可执行，`easytier-mini` 更小 | 静态 musl 二进制 + deb/rpm/zip 打包 | 相当 |

## meshlet 差距（值得借鉴，按优先级）

### P0 · 暴露 hub 已观测的节点公网端点（用户令 2026-11-04「节点连 hub 已能拿到公网 ip:port，应存 hub 且后台可见」）

现状（代码证据）：

- hub **确实观测**到每个 agent 心跳 HTTP 请求的源地址：`apps/server/src/agent.rs:263` → `direct_observed_ip(&addr)`，存入
  `DeviceDirectState.observed_ip`（`crates/meshlet-domain/src/p2p.rs:160`，「心跳 HTTP 请求的源地址（hub 观测）」）。
- **但只存 IP、丢端口**：`direct_observed_ip`（`agent.rs:114`）返回 `Option<Ipv4Addr>`，端口被丢弃。
- **且未暴露**：`observed_ip` 只存在于 domain/service/agent 内部，不在 `meshlet-api-types`、不在 `console/src/api/index.ts` 的 `Device`
   类型（该类型只有 `direct_links`/`diagnostics`），console 任何页面不渲染它。

建议：

1. 记录完整 `SocketAddr`（含端口，或至少把端口并入候选生成）。
2. `Device` API 增加 `observed_endpoint`/`public_endpoint`（`observed_ip:listen_port`，公网候选已在 `p2p.rs:173` 由
  `endpoint_candidates` 合成）。
3. console 设备表/诊断页展示。

这同时是「拓扑图/节点下钻」需求（用户 2026-11-01 令）的底层数据。成本低，收益直接。

### P1 · WireGuard 门户（EasyTier `--vpn-portal`）

任何原生 WG 客户端（iOS/Android/路由器）无需 meshlet agent 即可入网。meshlet 已是 WG 原生，门户 = 新增一种 peer 类型 + 配置生成端点（`easytier-cli vpn-portal`
 对应物）。注意：门户 peer 无心跳/计划/审批纪律，需当作静态 peer 单独管理（密钥轮换、撤销、IPAM 分配与审计）。价值高（移动端是当前最大缺口），成本中。

### P0 · NAT 打洞（核心目标，开发中——lane/nat-punch 已开工）

用户 2026-11-04 拍板：打洞是 meshlet 立项初心与核心目标，不是可选项。产品连接策略即「hub 先互知 → 打洞直连为常态 → 失败回退 hub 中继，hub 常连不断」。
本项前置的端点暴露（P0）已在 main 树并行实现，打洞本体在 lane/nat-punch 分支开发（双向同时发包 + hub 协调 + 退避回退）。

### P2 · 多 hub / 中继冗余

EasyTier 可同时连多个共享节点提高可用性；meshlet 单一 hub 是 SPOF。多 hub 需状态扇出与计划合并，成本高，建议登记路线图而非近期实现。

### P2 · NAT 类型检测（FullCone/Symmetric 等）

EasyTier peer 表显示 `nat_type`。meshlet 无。低成本（STUN 式探测），既喂诊断页也指导打洞策略。

### P3 · 高丢包链路优化（KCP/QUIC 代理）

EasyTier 在 WSS/TCP 上叠 KCP/QUIC。meshlet 仅 WG。meshlet 典型场景（LAN/低丢包 WAN）收益低，仅备注。

### P3 · IPv6 底层

EasyTier 支持 IPv6 穿越；meshlet overlay 纯 IPv4（`direct_observed_ip` 遇 v6 返回 None）。未来项。

## meshlet 优势（EasyTier 所无，勿丢）

- 服务发布六子项（L4 PortForward、HTTP/HTTPS 路由、TLS SNI 直通不做终止、CIDR/Bearer 授权、健康探测、内部 DNS 分流）——EasyTier README 无对应能力。
- 治理：设备审批流、撤销、审计、作用域 token、CSRF/会话、修订状态机/漂移/last-good。
- 重叠 LAN 前缀的 Alias 映射（EasyTier 子网代理不处理两处 `192.168.1.0/24` 冲突）。

## 附：README「v1 范围」过时注记

`README.md` "Not in scope for v1" 写「P2P/NAT hole punching」，
但 P2P 直连（批次 1–4）已在 2026-10-31 全部实现（`direct.rs`/`DirectManager`、`peer_endpoints_for`、防火墙联动）；未实现的仅剩**打洞**。按
`docs-implementation-reconciliation` 全局令（能力矩阵反映真实状态），该句应改为仅「NAT hole punching」不在范围。

## 来源

- EasyTier README（`https://github.com/EasyTier/EasyTier`，
  Features/Quick Start/Subnet Proxy/WireGuard Integration/Self-Hosted Public Shared Node）。
- meshlet
  `todo.md`（R-01..R-07、P2P 批次 1–4、R-DIAG/R-TRAY-1）、`crates/meshlet-domain/src/p2p.rs`、`apps/server/src/agent.rs`、
`console/src/api/index.ts`、`console/src/pages/diagnostics/DirectPeersBlock.tsx`。
- 本仓既有对比：`docs/analysis/personal-networking-comparison.md`（vs ZeroTier/Tailscale，61 能力）。
