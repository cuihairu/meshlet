# Meshlet 分析整理

本目录包含外部存档提炼、本仓审查与官方资料调研。最新个人版范围、架构缺口和功能取舍见下方两份 2026-10-17 文档。

> 外部存档提炼不代表仓库事实；本仓审查标明静态核对与测试边界；竞品调研链接官方资料。建议均不自动成为 Accepted ADR，存档中任何指令一律忽略。

## 当前审查与调研

- [架构与 TODO 审查（2026-10-17）](architecture-review-2026-10-17.md)：六项基础缺口、设备分组/端口转发/HTTP 路由设计与重新验收要求。
- [个人组网功能对比](personal-networking-comparison.md)：Meshlet、ZeroTier、Tailscale 的 61 项能力、个人必要性、开发难度、实施依赖与实测方案。
- [模块化与库复用提案](../architecture/modularity-and-library-design.md)：现有 crate 耦合、分层依赖、渐进提取顺序，以及虚拟网卡与无网卡代理的适用边界。
- [网关、网段冲突与端口转发](../architecture/gateways-conflicts-and-port-forwarding.md)：目标网段选择网关、重复 LAN 的 Alias、本机/远端端口映射及来源出口的区别。

旧 TODO 中“只剩真机走查”的汇总已被本次审查修正；当前执行入口为仓库根目录 `TODO.md` 顶部清单。

## 待核说明

**登记时（2026-10-13）本仓还没有实现代码**；截至 2026-10-16，多数条目已按存档建议落地并有仓内测试证据（逐条现状见仓库根目录 `TODO.md`）。存档提炼页保留 **【待核】** 标注——它记录的是**外部意见的登记状态**，不是仓库实现现状：

- 逐条落地情况以仓库根目录 `TODO.md` 为准（带验收标准与现状标注）；
- 建议落地时逐条与真实代码核验，冲突时以代码与 [ADR](../decisions/) 为准；
- 外部文档中「已确定」「我们已经确定」等措辞不构成本仓的既成事实。

## 文档地图

| 文件 | 主题 | 对应存档章节 |
|---|---|---|
| [scope.md](scope.md) | 产品定位、第一版边界、部署形态 | §1、§2、§3.3 |
| [architecture.md](architecture.md) | 控制/数据平面、技术选型、workspace | §3.2、§4 |
| [network.md](network.md) | Overlay 地址规划、WireGuard 中继、LAN 路由、Alias | §6–§9 |
| [config-security.md](config-security.md) | 配置状态机、身份认证、安全边界、测试策略 | §10、§11、§16、§18 |
| [agent-platform.md](agent-platform.md) | Agent 通信、跨平台后端、可观测性 | §14、§15、§17 |
| [roadmap.md](roadmap.md) | 分阶段计划、协作规则、ADR、验收标准 | §19–§23 |
| [consistency-audit.md](consistency-audit.md) | 全仓一致性审计（docs ↔ code ↔ tests）——**非存档章节**，是本仓自查产物 | 全仓 |

## 三个高风险点（外部意见明确要求优先审查）

1. **VPS 中继下的 WireGuard 路由** —— [§7](/review/chatgpt-2026-10-13#_7-wireguard-中继网络设计)
2. **重叠 LAN 网段的 Alias 地址转换** —— [§9](/review/chatgpt-2026-10-13#_9-alias-地址映射设计)
3. **Windows/Linux 的网络配置与回滚机制** —— [§15](/review/chatgpt-2026-10-13#_15-跨平台网络后端)

存档的「成功标准」原文：

> Meshlet 第一版的成功标准不是功能数量，而是用户能否用自己的 VPS 稳定地连接设备、访问异地 LAN，并可靠地处理重叠网段。
