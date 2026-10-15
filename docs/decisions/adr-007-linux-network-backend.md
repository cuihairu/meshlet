# ADR-007：Linux 网络配置后端

- 状态：Accepted
- 日期：2026-10-14
- 期次：Phase 0
- 来源：[存档 §15.2 / §4.3](../review/chatgpt-2026-10-13.md#_15-2-linux-backend)

## 背景

Linux 侧需要管理 WireGuard 接口、路由、IP 转发、防火墙与 Alias NAT（Server 与 Agent 共用机制）。

## 问题

用什么方式操作 Linux 网络栈？

## 候选方案

1. **Netlink（rtnetlink + WireGuard netlink 协议）+ nftables 规则管理**
2. 受控调用 `wg-quick` / `ip` / `nft` 系统命令
3. 随意拼接 Shell 命令（§4.3 明确禁止）

## 决定

- 接口/路由/Peer：优先 Netlink（rtnetlink + wireguard netlink）；系统命令仅作为受控降级路径，**不作为核心抽象**；
- NAT/防火墙：nftables，**Meshlet 拥有独立的 table/chain**，绝不改写用户已有规则；
- IP 转发：sysctl `net.ipv4.ip_forward` 检查与启用；
- 回滚 = 删除 Meshlet 自有对象，**不得清空系统路由/规则**（§10.3）；
- 实现 `NetworkBackend` trait（§15.1）：`inspect` / `apply_tunnel` / `apply_routes` / `rollback`。
- 第一版实际落地的是**受控命令降级路径**（选项 2），Netlink/nftables 未采用——见下方「实施记录」。

## 理由

- Netlink 是内核原生接口，事务性强、可编程、无解析文本输出；
- 独立 table/chain 让"只管理自己的规则"可机械保证；
- inspect→diff→apply 的模式支撑幂等与配置状态机（ADR-009）。

## 缺点与风险

- Netlink 编程复杂度高（消息序列化、错误码语义）；可先用 `rtnetlink`/`wireguard` 生态 crate 评估；
- 发行版 iptables/nft 混用历史问题——只依赖内核 nftables，绕开 iptables 兼容层；
- **集成测试需要 NET_ADMIN 与网络命名空间**：需免密 sudo（`sudo -n`）+ `wg`（wireguard-tools）+ `wireguard` 内核模块。开发主机已具备（2026-10-15 实测：`sudo -n true` 通过、wireguard-tools v1.0.20250521、模块可加载，双 netns 隧道端到端跑通），四项转发证明已落为 `crates/meshlet-network/tests/wg_forwarding.rs`（网桥 star underlay + 4 netns）。缺任一前置的环境打印 `SKIP:` 正常通过，数据面回归依赖特权 runner。已知坑：veth 默认 GRO/GSO/TSO offload 会让 wg-over-veth 握手静默失败（tx 有字节 rx=0），两端 `ethtool -K ... off` 后即通——测试拓扑已固化该处理；无特权 `unshare -Urn` 确实被拒（uid_map 拒写），用 sudo 绕过即可。

## 实施记录（2026-10-15 数据面接线）

第一版落地为**受控命令执行**（`crates/meshlet-network/src/linux.rs` 的
`LinuxNetworkBackend`），非 Netlink：控制面当前只需要逐配置下发（低频、
原子粒度小），命令路径已覆盖全部能力且被真实内核集成测试钉死；Netlink 的
事务性收益留到高频/大 peer 规模时再评估（见「重新评估条件」）。

- **命令纪律**：全部经 `ip` / `wg` / `iptables` / `sysctl` 逐参数 argv 执行，
  无任何字符串拼接 shell（§4.3）；`netns` / `sudo` 只是测试钩子字段（生产
  server 不带 netns、按部署用户权限直跑）。
- **幂等**：`ip address replace`、peer 对账（多退少补、allowed-ips 增量
  `wg set`）、`ip route replace`、iptables 先 `-C` 探测存在才 `-A`——重复
  应用不破坏网络（§10.3，集成测试断言）。
- **所有权**：NAT 规则带 `meshlet alias {id}` 注释、FORWARD 放行带
  `meshlet tunnel` 注释（nat.rs 计划层渲染）；`iptables -S` 引号感知分词
  定位自有规则；回滚/`remove_nat` 只按注释删 Meshlet 规则，预埋的用户规则
  原样保留（集成测试断言）；接口、接口地址与系统级 `ip_forward` 属系统状
  态，回滚不回收。
- **已知坑（固化进实现）**：`sudo -n ip netns exec` 下 `wg` 打开
  `/dev/stdin` 与 0600 临时文件都报 `fopen: Permission denied`，唯一可行通
  道是 bash 进程替换——`wg set wg0 private-key <(cat)`，密钥经 stdin 管道
  递入、不进 argv、不落盘（`run_bash_stdin`）；veth offload、endpoint 指
  netns 侧地址等坑位见 `wg_forwarding.rs` 头注。
- **trait 扩展**（随接线需要）：`apply_nat(rules, gateway_lan_addr)` /
  `remove_nat(owner)`；`TunnelConfig` 增 `address_prefix` 与
  `private_key: Option`（`None` = 保留接口现有私钥，幂等重应用；首装必须
  提供，否则无法握手——错误如实报出）；`RouteConfig` 增 `gateway`。
- **server 接线**（`apps/server/src/revision.rs`）：`[dataplane] enabled =
  true` 才启用 `HubDataPlaneBackend`，默认仍是显式失败的
  `UnconfiguredBackend`（升级不悄悄接管内核）；hub 私钥只从
  `private_key_file` 文件读、不落库（ADR-010）；hub 侧只下隧道与转发路
  由，网关侧 NAT 在网关设备上执行、随 agent 数据面交付（ADR-006）。
- **验证**：`crates/meshlet-network/tests/backend_wiring.rs`（真实内核 +
  netns，**全部数据面操作走 `LinuxNetworkBackend`** 而非裸命令）覆盖
  A↔B 互通、Alias 经 NAT 打到真实 LAN、幂等重应用、`remove_nat` 所有权
  边界（用户规则幸存）、Overlay 源保留（§7.4，UDP echo 观测源地址）、撤
  销即失效、回滚只删自有对象；SKIP 纪律与既有 netns 测试一致（CI 无
  root 全绿）。
- **未落地**：nftables 独立 table/chain（现为 iptables + 所有权注释，依赖
  内核 nft 后端；发行版 iptables/nft 混用兼容层保留为本 ADR 已记录风
  险）；`wg syncconf` 增量应用与最小 AllowedIPs（见
  [routing-optimization.md](../architecture/routing-optimization.md)，属性
  能优化非正确性）。

## 实施记录（2026-10-15 agent 侧交付）

hub 侧接线落地后，设备侧走同一条 `LinuxNetworkBackend` 路径，**服务端仍然
不向 agent 下发任何 Shell 命令**（§16.4）：

- **契约**：agent 用 enrollment 凭证调 `GET /api/v1/agent/device/desired`
  取回**自身**的结构化计划 `DevicePlan`（隧道 / 路由 / 网关侧 NAT 规则 +
  `desired_config_hash`，`private_key` 恒 `null`）；服务端 hub 公钥在请求时从
  `[dataplane] private_key_file` 现算（`wg pubkey`，不落库、不出站）。
  推导与 hub 侧同源（域层 `peer_routes::client_hub_peer_allowed_ips`），
  两端不会漂移（`apps/server/src/device_plan.rs`）。
- **对账与重放**（`apps/agent/src/reconcile.rs`，纯逻辑）：比较账本
  哈希 / 内核实际快照 / 服务端期望三者的差异——期望哈希变了、无账本
  （首装或状态文件损坏）、或内核漂移（隧道没了、路由缺失、peer 减少、
  NAT 规则消失）任一成立即重放 `apply_device_plan_sync`；都不成立则
  **不重放**（有变更才改，§10.1）。这覆盖了「主机重启后隧道消失但账本仍
  记 applied」的现场（TODO #32）。
- **所有权清理**：账本记 `nat_owners`（`meshlet alias {id}`）；映射从计划里
  消失时按注释精确移除该单元规则，绝不触碰非 Meshlet 规则（§12.6）。
- **期望项状态收敛**（`apps/server/src/service.rs::settle_desired_state`）：
  apply / rollback 的结论同步收敛到每条路由与 Alias 映射的 `status`——
  只有真下发到内核的前缀才转 `applied`，其余转 `failed`（与结论同事务
  落库）。否则「已记录未应用」的网段会出现在设备计划里，agent 会照着
  转发现网从未生效的前缀。
- **心跳**：每轮对账后带本地 `wg show` 握手时间上报（§14.1）；上报失败
  不影响数据面（计划对账是唯一事实源）。
- **验证**：`apps/agent/tests/agent_reconcile.rs`（真实内核 + netns，对象名
  `mlg<pid>`——前缀既不与既有 netns 测试互删，也不与崩溃残留/并行进程撞名）
  覆盖：首装应用 → A↔B 互通 →
  无变更不重放 → 新修订重放 → **模拟主机重启（删隧道）后按账本重放并恢复
  互通** → 网关侧 Alias NAT 下发与映射删除后的整单元清理（用户规则幸存）。
  纯逻辑部分另有 15 项单测（`reconcile` / `server` / `agent`）。
- **未落地**：真机部署走查（systemd 单元 + 真实设备）未做，见
  [安装指南](../guide/install.md) 的诚实边界与 TODO。

## 重新评估条件

- Netlink crate 维护性或平台覆盖不达预期；
- 需要支持无 nftables 的老内核；
- 集成测试基建表明命名空间方案不可持续。
