# R-03：统一网络规划与冲突分析

> **crate 已删除（2026-10-27）。** `meshlet-netplan` 从未被 server 消费，已于同日
> **删除**。冲突分析与计划确定性现在位于产品路径 `apps/server` 内部：路由与 Alias 的
> 冲突拒绝有集成测试（`apps/server/tests/routes.rs:239`、
> `apps/server/tests/aliases.rs:288`），计划哈希对路由重排的稳定性由
> `apps/server/src/device_plan.rs:590` 覆盖。没有搬过来的是该 crate 的设备/Segment/授权
> 打乱顺序独立性测试——这些输入在产品路径上没有对位验证。本文作为该部分能力的设计留档
> 保留。依据见 `todo.md` R-03。

R-03 引入纯逻辑、跨平台的 `meshlet-netplan`。它先校验完整期望状态，再编译出一个规范 HubPlan，其中包含 Hub Peer、网关分配和设备路由。Planner 不落库，也不接触平台执行器。

冲突分析覆盖 Overlay 与服务端已知路由、Segment 包含关系和两两重叠、Direct 路由所有权、Alias 唯一性与目标一致性、孤立或歧义 Alias 绑定、重复设备地址、未知网关，以及设备是否落在所属 Segment 内。服务端冲突集合返回前会排序去重，因此持久化顺序不同也会得到同一冲突集合。

网关选择沿用 Tailscale 和 NetBird 这类中心协调系统的 IPAM 与 Peer 路由分配机制：先基于完整状态协调所有权和重叠，再以稳定的设备标识选择网关。计划使用有序映射，并在最终结果上做字典序排序，不依赖无序迭代。专门测试会打乱同一组设备、Segment、授权、路由和 Alias 的输入顺序，并断言 HubPlan 完全一致；冲突输入则断言冲突集合和错误一致。

Direct 路由由每个网关发布唯一真实前缀。Alias 路由要求一对一映射、目标与 Alias 前缀长度一致，并使用互不重叠的虚拟空间；不同网关的真实前缀可以重叠，从而保留双站点 Alias 设计。Segment 授权收窄设备可见目的，Hub Peer 保留转发拓扑。本实现保持纯 IPv4 规划，API 迁移和平台后端接入拆入 R-04 和 R-05。
