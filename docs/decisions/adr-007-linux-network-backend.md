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

## 理由

- Netlink 是内核原生接口，事务性强、可编程、无解析文本输出；
- 独立 table/chain 让"只管理自己的规则"可机械保证；
- inspect→diff→apply 的模式支撑幂等与配置状态机（ADR-009）。

## 缺点与风险

- Netlink 编程复杂度高（消息序列化、错误码语义）；可先用 `rtnetlink`/`wireguard` 生态 crate 评估；
- 发行版 iptables/nft 混用历史问题——只依赖内核 nftables，绕开 iptables 兼容层；
- **集成测试需要 NET_ADMIN 与网络命名空间**：当前开发沙箱禁用 user namespace（uid_map 拒写）且无 root，四项转发证明（§7.3）与 Alias NAT 原型必须放到特权环境（root 主机或特权 CI runner）执行——已在 TODO 标注卡点。

## 重新评估条件

- Netlink crate 维护性或平台覆盖不达预期；
- 需要支持无 nftables 的老内核；
- 集成测试基建表明命名空间方案不可持续。
