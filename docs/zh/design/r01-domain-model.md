简体中文 | English
# R-01 领域模型（草案）

> 依据 docs/architecture/target-architecture.md；实现以本文件+crates/meshlet-planner 代码为准。

## 五种资源（互不混同，决策 4）
- Network：虚拟网络本体（id、名称、overlay 网段、默认 Segment）。
- Segment：信任分组（Network 内、策略模板、成员授权）。
- Route：LAN 路由发布（前缀、所有者、网关、metric、健康条件、故障切换）。
- Alias：重叠地址空间映射（本地 LAN ↔ 远端站点变换规则）。
- PortForward：L4 入口（TCP/UDP、入口绑定、目标服务、授权、健康探测）。
- HttpExposure：域名/路径 → 服务（含 TLS 终结策略）。

## Device 与 NetworkAttachment 分离
- Device：设备身份（公钥、平台、注册/撤销状态）。
- NetworkAttachment：设备在某 Network 的入网关系（overlay 地址、Segments、启用状态）。

## Revision 状态机（弃单一 Applied）
Pending → Preparing → Applying → Succeeded；失败路径 → Failed → RollingBack → RolledBack。
合法迁移以 crates/meshlet-planner/src/lib.rs can_transition_to 为准；回滚=新增修订（决策 6）。

## 四类状态不混用
1) DesiredState（期望态，唯一事实来源） 2) Revision/Plan/Receipt（执行记录，不可变）
3) ObservedState（内核真实状态，漂移检测输入） 4) Audit（审计，哈希链）。
