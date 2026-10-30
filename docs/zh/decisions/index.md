# 架构决策记录（ADR）

按 [存档 §21](../review/chatgpt-2026-10-13.md#_21-架构决策记录-adr) 要求建立，每份含：背景、问题、候选方案、决定、理由、缺点与风险、重新评估条件。状态为 Accepted 表示作为当前设计基线采纳，**实现期如与代码现实冲突须回到这里修订**。

| 编号 | 决策 |
|---|---|
| [ADR-001 采用 WireGuard 作为隧道基础](./adr-001-wireguard-transport) | 采用 WireGuard 作为隧道基础 |
| [ADR-002 第一版采用 VPS 中心中继拓扑](./adr-002-vps-hub-relay) | 第一版采用 VPS 中心中继拓扑 |
| [ADR-003 SQLite 作为初期控制平面数据库](./adr-003-sqlite-control-plane) | SQLite 作为初期控制平面数据库 |
| [ADR-004 Overlay IPAM 与地址分配策略](./adr-004-overlay-ipam) | Overlay IPAM 与地址分配策略 |
| [ADR-005 LAN 路由及返回路径模式](./adr-005-lan-return-path) | LAN 路由及返回路径模式 |
| [ADR-006 Alias 前缀映射与 NAT 方案](./adr-006-alias-prefix-nat) | Alias 前缀映射与 NAT 方案 |
| [ADR-007 Linux 网络配置后端](./adr-007-linux-network-backend) | Linux 网络配置后端 |
| [ADR-008 Windows Agent 网络配置后端](./adr-008-windows-network-backend) | Windows Agent 网络配置后端 |
| [ADR-009 配置版本、应用状态与回滚机制](./adr-009-config-revision-rollback) | 配置版本、应用状态与回滚机制 |
| [ADR-010 控制台认证和设备注册安全模型](./adr-010-console-auth-enrollment) | 控制台认证和设备注册安全模型 |
| [ADR-011 设备自举注册（ZeroTier 式）与中心审批](./adr-011-device-self-registration) | 设备自举注册（ZeroTier 式）与中心审批 |
| [ADR-012 网段即信任组](./adr-012-network-segment-trust) | Network 内 Segment、默认隔离与跨段单向授权 |

约定：新增决策顺延编号；推翻旧决策不改写原文，新增 supersede 记录并互链。

非 ADR 决策记录：[阻塞项代决记录（2026-10-30）](/decisions/2026-10-30-decisions) — todo.md 阻塞项的 10 项代决落档（D1–D10），含逐项「需用户输入，暂缓」状态与 codex 分析原文。
