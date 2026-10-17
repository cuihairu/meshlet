# RG-02：重叠 LAN 的独立 Alias 设计

日期：2026-10-18。状态：设计草案已细化，整项实现与验收尚未完成。

本文细化已采纳的 [ADR-006](../decisions/adr-006-alias-prefix-nat.md)，不引入新传输或新的网络隔离模型。关联任务：RG-02；完整冲突检查归 RG-03，访问授权归 ADR-012 / PN-02，应用确认归 AR-02。

## 1. 用户场景与选择

家庭、办公室和客户端当前所在 LAN 都使用 `192.168.1.0/24`。用户需要同时访问三个站点，且不改原 LAN 地址、不影响本地设备。

采用“每个远端站点一个独立 Alias 前缀”的方式：

| 对象 | 原地址 | 用户访问地址 | 负责网关 |
|---|---|---|---|
| 本地设备 | `192.168.1.50` | `192.168.1.50` | 本地原路由 |
| 家庭主机 | `192.168.1.50` | `10.241.1.50` | G1：`10.240.0.2` |
| 办公主机 | `192.168.1.50` | `10.241.2.50` | G2：`10.240.0.3` |

示例客户端 C 的 Overlay 地址为 `10.240.0.4`，Overlay 为 `10.240.0.0/16`。示例前缀不是预留地址，创建和设备应用前均须检查占用。

Alias 与真实 LAN 必须等长，保留主机位。一条 Alias 绑定一条 `route_mode=alias` 的 LAN Route，目标前缀由路由推导。G1、G2 必须是不同站点的独立网关设备；同一个网关的普通路由域无法区分两个相同真实地址，本阶段拒绝这种配置，独立 VRF/netns 支持另行设计。

## 2. 包的路径

```text
C → 10.241.1.50 → hub → G1 → 192.168.1.50（家庭）
C → 10.241.2.50 → hub → G2 → 192.168.1.50（办公）
C → 192.168.1.50 → 原有本地 LAN
```

hub 只根据 Alias 前缀选择网关，不执行 LAN 地址转换。DNAT/NETMAP 在目标网关发生；应答经该连接的逆转换恢复为 Alias 来源地址。网关失效时不得把家庭 Alias 指向办公室，不提供隐式主备。

## 3. 路由与 AllowedIPs 契约

下面描述同一个默认 Segment 内、路由已获准发布时的地址集合。未来多 Segment 应先按 ADR-012 筛选可见路由，再使用同一地址推导，不把 AllowedIPs 列表视为完整访问授权。

| 位置 | 目的路由 / Peer AllowedIPs |
|---|---|
| C 的 hub Peer | Overlay + 家庭 Alias + 办公 Alias |
| C 的系统路由 | 家庭 Alias 经 G1 Overlay 地址、办公 Alias 经 G2 Overlay 地址，均进入受管隧道；实际 WireGuard 对端仍只有 hub |
| hub 的 G1 Peer | G1 Overlay `/32` + 家庭 Alias |
| hub 的 G2 Peer | G2 Overlay `/32` + 办公 Alias |
| hub 的系统路由 | 家庭 Alias → G1；办公 Alias → G2 |
| G1 的 hub Peer / 路由 | Overlay + 办公 Alias；不把自己发布的家庭 Alias 或真实 LAN 回灌隧道 |
| G2 的 hub Peer / 路由 | Overlay + 家庭 Alias；不把自己发布的办公 Alias 或真实 LAN 回灌隧道 |

两个真实远端 LAN 前缀均不进入 C 或 hub 的隧道路由和 Peer AllowedIPs，也不向 C 下发覆盖本地 `192.168.1.0/24` 的更具体真实地址路由。此场景不安装 Alias 超网聚合路由，只安装实际发布的前缀。

Alias 模式尚未绑定映射时，不能回退发布真实前缀。发布集合必须由有效 Route + Alias 共同确定；孤儿映射、跨 Network 引用、目标不匹配应在编译前报错。候选计划可包含当前待应用修订的资源，但不能因此把持久化状态或设备 ACK 标为成功。

## 4. 返回路径与边界

默认使用兼容的受控 SNAT：目标 LAN 主机看到网关在该 LAN 的地址，无需给目标主机另加 Overlay 返回路由。明确选择保留源地址时只做 DNAT，目标看到 C 的 Overlay 地址，LAN 必须有到 Overlay 经对应网关的返回路由。

沿用已有 `return_path_mode` 和 `translation_mode` 字段；两者表示的意图必须一致。草案建议创建或更新时拒绝显式矛盾的组合，并在响应中给出实际模式：`controlled_snat` 对应 `dnat_snat`，`dual_route` 对应 `dnat_only`。存量矛盾记录需要审计并由用户选择后迁移，不能在升级时静默改变 NAT 行为；这项兼容处理属于后续实现工作。

只保证已验收的 IPv4 单播协议。Alias 不自动提供广播发现、负载内嵌 IP 改写、LAN 主动访问其他站点、网关自身通过自己的 Alias 访问本地服务或跨 Network 连接。这些路径须分别设计和测试。

## 5. 创建、应用、故障与删除

1. 先登记 G1/G2 为同一 Network 的有效网关，再创建 Alias 模式 LAN Route 和等长映射。允许不同网关的真实 LAN 重复；可见 Alias 必须独立。
2. RG-03 检查 Alias 与共享路由域中的 Overlay、Direct、其他 Alias 及已知本地路由冲突。未知客户端的占用保持未知，在上线应用前预检；有冲突时阻止受影响设备应用并报告资源，不覆盖外来路由。
3. 计划分别表达 hub 转发、目标网关 NAT、客户端路由；展示期望修订、各设备确认和业务探测。只有 hub 已应用不能显示“全部可用”。
4. 网关离线时保留站点绑定并标降级，不把流量改投其他站点。应用失败沿用 AR-04 的恢复边界，不把失败的新计划发布为成功。
5. 删除一个 Alias 时只清理其自有路由、Peer 前缀和 NAT；另一个站点和本地路由必须保留。存量连接清理与阻止旧计划重放分别由 IM-06/IM-07/IM-08 的契约补齐。
6. 删除后不再保证该 Alias 可达；私人前缀不得泄漏默认出口的保留丢弃路由/防火墙方案仍由 RG-03 细化，本草案不把现有“删路由”视作这项隔离已完成。

## 6. 现有代码与差距

| 代码 | 当前核对结果 | 本项还需要的证据 |
|---|---|---|
| `crates/meshlet-domain/src/peer_routes.rs` | Direct 才发布真实 LAN；Alias 发布映射前缀；排除自己的发布集合 | 两站点同前缀的集合相等断言、孤儿/非法输入拒绝 |
| `apps/server/src/device_plan.rs`、`revision.rs` | 依据 RouteMode 分别选择真实或 Alias 目的；网关收到 NAT | 同一快照下客户端、hub、网关计划的一致性 |
| `apps/server/src/service.rs` | 不同 Alias 路由允许真实重叠；映射限制同网络 Alias 路由、一对一、等长 | 同网关重复目标的拒绝；返回模式兼容校验；与 RG-03 对齐 |
| `crates/meshlet-network/tests/alias_nat.rs` | 已有双重叠远端 LAN、站点标识、SNAT/源保留的测试拓扑 | 经正式 API/Agent 入口，同时加入客户端同前缀本地 LAN |
| `apps/server/tests/agent_plan.rs` | 已有网关 NAT 与自身 LAN 不回灌的覆盖 | 组合场景、删除单站点、重启和失败恢复 |
| `apps/server/tests/dual_site_end_to_end.rs` | 正式 API/Agent 流程已包含两个远端 LAN 与客户端本地同前缀 LAN；UDP 探测返回 local/site1/site2，内核保留本地路由，重复真实前缀不进隧道 | TCP 标识、返回模式变化、删除、重启、失败恢复和 RG-03 预检仍未完成 |

以上结论包含本轮实际执行的 `dual_same_prefix_lans_published_via_the_control_plane_reach_their_sites` Linux netns 验收；它只是集成验收，不等同 VPS 部署验收，也不能代表 RG-02 全项完成。

## 7. 验收矩阵

| 编号 | 场景 | 通过条件 |
|---|---|---|
| RG02-01 | 两远端 LAN + 客户端本地 LAN 同前缀 | 可用 netns 测试中 UDP 返回 local/site1/site2 且本地路由不变；TCP 标识仍待补 |
| RG02-02 | 计划一致性 | Alias 出现在正确 hub Peer、客户端路由/AllowedIPs；真实重复前缀不进入隧道；没有未发布 Alias 聚合前缀 |
| RG02-03 | 两种返回模式 | SNAT 时目标看到正确网关 LAN 地址；源保留时看到 Overlay 源，缺返回路由失败、补路由成功 |
| RG02-04 | 无映射或非法关联 | 不发布真实 LAN 兜底；孤儿、跨网络、目标不匹配和同网关歧义配置被拒绝，无部分写入 |
| RG02-05 | 删除家庭 Alias | 家庭入口失效；办公与本地仍可达；只清理家庭受管对象，不残留该 Alias 的 NAT |
| RG02-06 | G1 离线/应用失败 | 不误访 G2，不误报业务成功；按确定的失败/恢复契约收敛 |
| RG02-07 | 重启与备份恢复 | Route、Alias、网关引用、实际 NAT 模式保持一致；不恢复已删除的映射 |
| RG02-08 | 冲突与未知 | Alias 占用被拒绝；离线客户端未知有标识；上线预检不抢占外来路由（联合 RG-03） |

后续执行门禁：domain 的 `peer_routes` 测试、server 的计划/API 回归，以及严格数据面测试。严格模式设置 `MESHLET_REQUIRE_DATAPLANE=1`，缺前置条件应失败，不能把 SKIP 计为通过。组合场景通过后才能把 RG-02 标为已验收。

## 8. 取舍与后续顺序

不选 metric 竞争，因为同一个目标 IP 仍无法表达不同站点；不选 hub 集中 NAT，因为它会把重复真实地址带入共享转发域；不引入 IPv6 站点编码，先沿用 ADR-006 已采纳的等长 IPv4 Alias。

下一项 RG-03 将定义完整冲突矩阵、共享检查入口、设备本地预检和删除后防止默认出口泄漏的行为。RG-02 的完成不等于 RG-03 或 PN-02 完成。
