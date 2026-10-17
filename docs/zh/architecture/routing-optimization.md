# 路由优化方案

> 外部 API 控制开工单条目「路由优化方案（含取舍与实测依据）」（2026-10-14）。
> 本文描述**数据面**路由的当前实现、瓶颈、候选方案与取舍。控制面路由对象
> （LAN Route / Alias 的增删与状态）见 [domain-model](domain-model.md) 与
> [api-contract](api-contract.md)。

## 现状（已实现的部分）

- **拓扑**：hub-and-spoke（[ADR-002](../decisions/adr-002-vps-hub-relay.md)）。
  全部设备与 VPS 上的单一 WireGuard 接口建隧道；设备间流量一律经 VPS 中继；
  设备与设备之间没有直接 Peer。
- **AllowedIPs 推导**（`crates/meshlet-domain/src/peer_routes.rs`，纯函数 +
  单测）：只路由 Overlay 网段与**明确发布**（`Applied`）的远端 LAN/Alias
  网段，绝不出现 `0.0.0.0/0` 全量指隧道；hub 侧每设备独立 Peer
  （`/32` + 该设备发布的 LAN/Alias），客户端到 hub 的 Peer 为
  Overlay + **其他**设备发布的网段（自己发布的本地网段不回灌，防环路）。
- **LAN 返回路径**（[ADR-005](../decisions/adr-005-lan-return-path.md)）：
  `dual_route`（LAN 路由器配回程静态路由，保留真实源 IP）或
  `controlled_snat`（网关把来自 Overlay 的流量 SNAT 成自身 LAN 地址）；
  Overlay 设备间通信不做 SNAT。
- **Alias**（[ADR-006](../decisions/adr-006-alias-prefix-nat.md)）：等长前缀
  一对一替换解决重叠网段，DNAT/SNAT 在 VPS 侧执行。

以下 P2P 直连不在第一版范围（ADR-002）；Linux 网络后端已接线（ADR-007，
`[dataplane] enabled = true` 时 apply 真实下发内核），Windows 后端仍为显式
拒绝的占位（ADR-008）；数据面未配置时 apply 显式失败可见
（`UnconfiguredBackend`，ADR-009）。

## 当前实现的瓶颈清单

| # | 瓶颈 | 机制 | 量化方式 |
|---|---|---|---|
| B1 | 全部流量经 VPS 中继：吞吐上限 = min(两端带宽, VPS 网卡, VPS 单核 WG 加密吞吐)；RTT ≈ 两端到 VPS 之和 | 单一中心 Peer 转发路径，无旁路 | iperf3 对照组（见下） |
| B2 | `controlled_snat` 网关的 conntrack 状态表：高并发长连接下表满即丢新连接 | `nf_conntrack` 每连接一条目 | `conntrack -C` 对 `nf_conntrack_max` |
| B3 | 路由变更若用 `wg setconf` 全量替换会**重置所有 Peer 会话**（在跑流量瞬断） | setconf 重建接口态 | 变更前后 `latest-handshakes` 是否清零 |
| B4 | MTU 错配：Overlay 包再套 UDP/IP 头，默认 MTU 1420；底层是 PPPoE/隧道时需再减，错配导致分片、吞吐骤降 | 分片 + 重传放大 | `ping -M do` 二分探测 |
| B5 | AllowedIPs 查找：WireGuard 内部是前缀 trie，单次查找 O(前缀长) | 千级 Peer 规模下非瓶颈 | 列出以供排除，不投入 |
| B6 | 同 VPS 多网络 = 多 WireGuard 接口，需 fwmark + policy routing 隔离；表泄漏/冲突是运维风险 | 内核路由表数量 | `ip rule` / `ip route show table all` |

B1 是 v1 的**产品边界**（公共中继/打洞后置），不是要「修」的缺陷；本文的
优化目标是在中继架构内把可拿的吞吐与稳定性拿满，并为 v2 的直连路径留好
度量基线。

## 候选方案对比

| 方案 | 预期收益 | 复杂度/风险 | 取舍 |
|---|---|---|---|
| A. 维持 hub 中继 + 最小 AllowedIPs（现状推导） | 基线 | 低——纯函数已实现并有单测 | **v1 选定**。安全面最小化：不加路由的网段不可达，泄漏面小 |
| B. 路由应用一律 `wg syncconf`（增量），禁用 `setconf` 全量替换 | 消除配置变更时的全量断流（B3） | 低——实现纪律 | **v1 选定**（实现红线，写入 ADR-007 接线检查单） |
| C. 只做 `dual_route`，砍掉 SNAT | 零开销 + 真实源 IP | 高——家庭路由器普遍不可配静态路由，挡掉主要场景 | **拒绝**（ADR-005 已定双模式；本文不推翻） |
| D. P2P 打洞直连（经 hub 信令，数据面旁路） | 带宽/延迟大幅改善（B1 根治） | 高——NAT 类型差异、成功率先要实测 | **v2 候选**。v1 先用下面的命令建立中继基线，直连收益用它量化 |
| E. VPS 内核网络多核调优（RPS/RFS、多队列网卡） | 多核 VPS 上中继吞吐约 1.5–2× | 中——纯部署侧，不动代码 | **可选**。给出验证命令，上线后按实测决定 |
| F. MTU 探测与下发（加入时探测路径 MTU，写进设备配置） | 消除分片损失（B4） | 低——agent 已有本地命令执行面 | **v1 实现检查单**；先给手工探测命令 |

## 选定结论（v1）

1. **A**：AllowedIPs 保持最小推导，不做全量指隧道；
2. **B**：server 端网络后端接线时，路由/Peer 变更只允许 `wg syncconf`，
   禁止 `setconf` 全量替换（对应验收：变更前后会话握手不清零）；
3. **F**：MTU 默认 1420，agent 加入时用探测命令核定后写入配置；
4. **D** 留给 v2，前提是本文命令在真实 VPS 上产出中继基线数据；
   **E** 作为部署选项，实测收益 ≥ 30% 才纳入默认部署文档。

## 可复现的验证命令

需要在具备 root 与 WireGuard 的环境执行（当前开发容器无
CAP_NET_ADMIN，跑不了这些命令；VPS 或实验机均可）。设
`wg0` = Overlay 接口，`10.240.0.1` = hub，`10.240.0.2/.3` = 两台客户端。

```bash
# 0. 拓扑与配置核验：Peer 数、AllowedIPs 是否等于推导值（对照 peer_routes 推导）
wg show wg0 allowed-ips
ip route show table all | grep -F wg0

# 1. B1 中继吞吐基线：客户端→hub vs 客户端→客户端（经中继）
#    hub 上:  iperf3 -s
#    客户端:  iperf3 -c 10.240.0.1 -t 30        # 单流；再加 -P 4 看多流
#             iperf3 -c 10.240.0.3 -t 30        # 经 VPS 中继的另一客户端
#    对照（同机房直连，不经隧道）: iperf3 -c <VPS 公网地址>
#    预期：中继吞吐 ≈ min(两端, VPS)；客户端↔客户端 ≈ 两条接入带宽的较小值

# 2. B1 延迟构成：客户端↔hub RTT vs 客户端↔客户端 RTT
ping -c 20 10.240.0.1
ping -c 20 10.240.0.3
#    预期：后者 ≈ 两条「客户端↔VPS」RTT 之和（偏差 > 2ms 说明有异常排队）

# 3. B4 MTU 探测（二分）：从 1392 起步（1420 - 28），不分片探测
ping -M do -s 1392 -c 3 10.240.0.1   # 通则逐步 +8 探上限
ip link show wg0                      # 核对接口 MTU 与探测上限 + 28 是否一致

# 4. B2 SNAT 模式 conntrack 占用（在启用了 controlled_snat 的网关设备上）
sysctl net.netfilter.nf_conntrack_count net.netfilter.nf_conntrack_max
conntrack -L -s 10.240.0.0/16 | head  # 应能看到 Overlay 源被 SNAT 成网关 LAN 地址
#    预期：count 长期 < 70% max；接近上限时优先调大 hashsize 而不是砍并发

# 5. B3 syncconf 不断流验收（网络后端接线后）
wg show wg0 latest-handshakes         # 记录 T0
#    …（控制台触发一次路由变更/设备加入）…
wg show wg0 latest-handshakes         # 预期：既有 Peer 的值不被清零
wg show wg0 transfer                  # 预期：既有 Peer 计数持续增长，不回落

# 6. B6 多网络隔离（多 wg 接口时）
ip rule show                          # 预期：每网络一条 fwmark 规则
ip route show table all | grep -cF table  # 预期：表数量与网络数对应，无孤儿表

# 7. E 多核调优收益对照（可选）
#    调优前 iperf3 -c 10.240.0.1 -P 4 -t 30 记录基线；然后：
ethtool -l <物理网卡>                 # 查队列数
#    开 RPS（多队列不可用时）: echo <掩码> > /sys/class/net/<网卡>/queues/rx-0/rps_cpus
#    调优后同命令复测，收益 < 30% 则不纳入默认部署
```

判据汇总：中继吞吐/延迟达到 B1 的机制上限（min 带宽 / RTT 之和）即视为
v1 数据面达标；任何一项显著低于预期时，按 3 → 5 → 7 的顺序排查
（MTU → 会话重置 → 内核多核）。

## 关联

- 实现：`crates/meshlet-domain/src/peer_routes.rs`（AllowedIPs 推导）
- [ADR-002](../decisions/adr-002-vps-hub-relay.md) ·
  [ADR-005](../decisions/adr-005-lan-return-path.md) ·
  [ADR-006](../decisions/adr-006-alias-prefix-nat.md) ·
  [ADR-007](../decisions/adr-007-linux-network-backend.md)
