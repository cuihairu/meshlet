# ADR-012：网段即信任组

- 状态：Accepted（设计采纳；实现未开始）
- 日期：2026-10-17
- 详细设计：[网段即信任组](../design/network-segment-trust.md)

## 背景

用户需要 Network 内的设备分组：同组互信，跨组默认不可达。当前 Network 内 Overlay 与全部已发布路由对 Active 设备可见，没有 Segment 或段间授权模型。

## 决定

- 引入 Network 内 `Segment`：网段是地址前缀和默认信任边界；一台设备一次只属于一个段，地址必须落在段内。
- 同段默认互信；跨段默认拒绝，只有显式 Applied 的 `SegmentGrant source -> destination` 放行，且方向单向。
- 策略在 hub 执行两层：设备 AllowedIPs 收窄到 hub、本段与授权目的段及其可见路由；hub FORWARD 按隔离、同段、授权、默认拒绝顺序重放。
- LAN Route / Alias 的可见性跟随发布网关所属段，不新增路由级授权字段。
- 存量网络迁移为单一 default 段，单段行为与现有全放行等价；启用多段前必须清空并删除 default 段。

## 理由

- 地址位置直接映射信任身份，避免设备独立 ACL 先行带来的复杂度。
- hub 单点策略与 ADR-002 的 v1 中继拓扑一致；WireGuard AllowedIPs 与 FORWARD 规则分别提供路由与转发兜底。
- 默认段迁移保证存量单网行为不发生分叉，并为后续 API、修订链和内核验收提供稳定契约。

## 缺点与风险

- 换段必须换 Overlay 地址；旧 agent 更新期间依赖 hub 默认拒绝兜底。
- 同段仍是全端口网络可达，不解决应用层或端口级最小权限；后者留给 PN-02。
- 规则数量随段和授权线性增长；个人规模下先不用 ipset/nftset。

## 重新评估条件

- 引入 v2 P2P 直连，hub 单点执行不再充分；
- 需要 IPv6 或跨 Network 段；
- 设备/服务端口策略成熟后，确认 Segment 与更细粒度模型出现职责重叠。
