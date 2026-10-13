# ADR-008：Windows Agent 网络配置后端

- 状态：Accepted
- 日期：2026-10-14
- 期次：Phase 0
- 来源：[存档 §15.3](../review/chatgpt-2026-10-13.md#_15-3-windows-backend)

## 背景

第一版支持 Windows Agent（优先级在 Linux Server / Linux Agent 之后，§15.4）。Windows 上 WireGuard 官方形态是 WireGuard for Windows（tunnel service + wireguard-nt 驱动）。

## 问题

Windows 上如何管理隧道、路由与权限？

## 候选方案

1. **官方 WireGuard for Windows tunnel service（可编程嵌入 wireguard-nt / 官方服务）+ 系统 API 配路由**
2. 逐次拉起 `wireguard.exe` GUI 进程
3. 第三方/自研 TUN 驱动（排除：自研协议红线）

## 决定

- 隧道生命周期交给官方 tunnel service 模型（每个隧道一个受管服务实例），Agent 负责生成/更新隧道配置与启停；
- 虚拟 IP 与路由：优先 WireGuard 隧道自身的 AllowedIPs 生成的路由，必要时以系统 API（如 `CreateIpForwardEntry2` / `netsh interface ipv4` 受控调用）补充；
- 需要管理员权限的 操作明确提示与失败清理；**不假设 Windows 与 Linux 行为一致**（差异清单见 [platform-notes](../architecture/platform-notes.md)）；
- Windows 第一版**只做 Overlay 客户端**，LAN 网关/Alias NAT 职责在 Linux 网关（ADR-006）。

## 理由

- 官方服务模型是受支持路径，密钥隔离与权限模型由官方处理；
- 避免 Agent 直接操作驱动层的维护负担。

## 缺点与风险

- wireguard-nt 嵌入式 API 的稳定性与签名要求需在实现期验证（Windows 侧调研是原型项，沙箱无 Windows 环境只能文档先行）；
- 路由补充用受控命令存在解析脆弱性，尽量收敛到最小集合；
- 权限不足时的半配置状态需要清理路径（§18.3 验收项）。

## 重新评估条件

- 官方嵌入方式许可或 API 变化；
- 需要 Windows 作为 LAN 网关/Alias 转换点；
- 路由 API 无法表达所需语义。
