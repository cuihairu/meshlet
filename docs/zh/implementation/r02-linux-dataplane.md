# R-02：可靠 Linux 数据面

> **已不随产品发布（2026-10-27）。** 本文记录的是 `crates/meshlet-net-linux`
>（nftables 编译器、`defguard_wireguard_rs`、netlink）。该 crate 从未被任何 app
> 消费，已于同日**删除**；实际交付的数据面是
> `crates/meshlet-network/src/linux.rs`（`LinuxNetworkBackend`），执行 `ip`、`wg` 与
> **iptables**。本文件中的 nftables 内容仅作为早期方案的留档。修正依据见
> `todo.md` R-02 与完成状态审计。

R-02 已交付 Linux 中心节点主线，并沉淀为可复用 crate。期望的 Hub 状态先校验，再确定性编译成不可变计划；每个网络拥有独立的 WireGuard 接口、UDP 端口、IPv4 overlay、Peer 集合、路由集合和显式防火墙规则。

Linux 后端通过 `defguard_wireguard_rs`、netlink、`/proc/sys/net/ipv4/ip_forward` 和 nftables JSON ruleset 观测真实状态。协调器据漂移结果在“应用期望状态”“安全保留式恢复”“无操作”之间选择。只有清洗后的 last-good 能通过编译并完全匹配观测态时才选择恢复；last-good 与 desired 中的撤销都会保留，被撤销 Peer 不会复活，未被存活 Peer 覆盖的路由也不会恢复。

nftables 编译器生成自有的 `meshlet` 表、默认丢弃策略的 forward 基础链、先于同网络放行规则的撤销地址显式丢弃规则、跨网络隔离丢弃规则，以及带网络范围的规则注释。首次下发在一个事务中创建自有表；后续下发原子删除并重建该表。本里程碑范围保持 IPv4 转发和路由。

自动化测试覆盖确定性计划、路由/AllowedIP 冲突拒绝、漂移报告、last-good 文件持久化、撤销 Peer 恢复、防火墙事务编译和协调决策。
