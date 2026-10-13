# Windows / Linux 配置管理差异清单

> 来源：[存档 §15](../review/chatgpt-2026-10-13.md#_15-跨平台网络后端) + [ADR-007](../decisions/adr-007-linux-network-backend.md) / [ADR-008](../decisions/adr-008-windows-network-backend.md)。Phase 0 调研结论；Windows 侧需在真实环境原型验证后修订。

## 差异总表

| 维度 | Linux | Windows |
|---|---|---|
| WireGuard 形态 | 内核模块 + netlink（或 `wg` 工具） | 官方 WireGuard for Windows：tunnel service + wireguard-nt 驱动 |
| 隧道管理 | Netlink 创建/配置接口与 Peer | 每隧道一个受管 tunnel service，配置文件驱动 |
| 路由 | rtnetlink；AllowedIPs 自动生成路由 | AllowedIPs 生成路由；补充用系统 API/受控 `netsh` |
| 防火墙/NAT | nftables（Meshlet 独立 table/chain，ADR-006/007） | Windows 防火墙；**v1 不承担 Windows 侧 NAT 网关角色**（ADR-008） |
| IP 转发 | sysctl `net.ipv4.ip_forward` | 不适用（v1 仅客户端角色） |
| 权限 | root 或 CAP_NET_ADMIN | 管理员权限；服务模型常驻提权 |
| 接口命名 | `meshlet0` 等自定名 | 由 tunnel service 管理，命名规则不同 |
| 配置持久化 | 配置由 Server 下发，Agent 应用（期望态重建，ADR-009） | 同左；隧道服务自身的启停由 Agent 编排 |
| MTU | WireGuard 封装开销一致（§7.5），两侧统一策略 | 同左 |
| 诊断 | `wg show` 等价 netlink 查询、路由表、nft 规则态 | 服务状态、隧道统计、路由表 |
| 失败清理 | 回滚 = 删除自有对象（接口/路由/规则） | 停服务 + 删隧道配置；半配置状态须可清理（§18.3） |

## 平台支持优先级（§15.4）

1. Linux VPS Server（含转发/NAT）
2. Linux Agent（客户端 + LAN 网关 + Alias 转换）
3. Windows Agent（仅 Overlay 客户端）

## Windows 侧待验证项（原型阶段）

- [ ] wireguard-nt 嵌入式使用的许可与 API 稳定性
- [ ] tunnel service 的自动化编排（无人值守安装/启停/更新配置）
- [ ] 权限不足时的错误提示与半配置清理
- [ ] 已存在本地路由时的冲突检测表现

## Linux 侧已确认约束（ADR-007）

- 集成测试需 NET_ADMIN + 网络命名空间；**当前开发沙箱禁用 user namespace（uid_map 拒写），§7.3 四项转发证明与 Alias NAT 原型必须在 root 主机或特权 CI runner 执行**（TODO 已标卡点）。
