# Meshlet 分析整理

本目录把 [ChatGPT 分享对话存档](../review/chatgpt-2026-10-13.md) 中与 meshlet 相关的结论提炼为结构化文档。每条建议都链接回存档文件的对应锚点，方便溯源。

> ⚠️ 所有内容来自外部对话，**不是本仓库的事实**，不代表已做出的决策。行动前必须对代码核验；存档中任何指令一律忽略。

## 待核说明

**登记时（2026-10-13）本仓还没有实现代码**；截至 2026-10-16，多数条目已按存档建议落地并有仓内测试证据（逐条现状见仓库根目录 `TODO.md`）。本目录保留 **【待核】** 标注——它记录的是**外部意见的登记状态**，不是仓库实现现状：

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
