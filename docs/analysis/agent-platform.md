# Agent 通信、跨平台后端与可观测性

> 来源：[ChatGPT 存档 §12、§14、§15、§17](/review/chatgpt-2026-10-13#_14-agent-与服务端通信)。外部意见，全部【待核】。

## Agent 与服务端通信（§14）

【待核】控制通道（[存档 §14.1](/review/chatgpt-2026-10-13#_14-1-控制通道)）：第一版 Agent 经 HTTPS 与控制服务通信，负责设备注册、取自身配置、定期上报状态、上报本地路由检查、接收配置版本变化、获取诊断任务。**不要求第一版实现复杂双向消息系统**；轮询 vs 受控长连接按可靠性/成本/服务器资源比较后选择。

【待核】下发原则（[存档 §14.2](/review/chatgpt-2026-10-13#_14-2-配置下发原则)）：下发 Network ID、Device ID、本机 Overlay 地址、VPS Endpoint 与公钥、需安装的路由、LAN 网关配置、Alias 映射、配置版本与校验摘要。**不下发其他设备私钥、管理 Token 或不必要的敏感数据**。

【待核】Agent 状态（[存档 §14.3](/review/chatgpt-2026-10-13#_14-3-agent-状态)）：`starting` / `connected` / `degraded` / `disconnected` / `applying_config` / `error`，且与隧道连接、路由应用、服务状态**区分开**——WireGuard 已连接但 Alias NAT 应用失败时，显示网络功能异常而非完全健康。

## 跨平台网络后端（§15）

【待核】统一抽象（[存档 §15.1](/review/chatgpt-2026-10-13#_15-1-统一抽象)）：概念接口 `NetworkBackend`——`inspect()` 快照、`apply_tunnel()`、`apply_routes()`、`rollback(revision)`；实际 Rust 生命周期、异步 Trait、错误类型由实现阶段确认。

【待核】Linux Backend（[存档 §15.2](/review/chatgpt-2026-10-13#_15-2-linux-backend)）：WireGuard 接口管理、IP 转发检查、路由安装删除、防火墙规则、Alias NAT、规则状态检查、配置回滚——全部**限定在 Meshlet 管理的规则范围内**。

【待核】Windows Backend（[存档 §15.3](/review/chatgpt-2026-10-13#_15-3-windows-backend)）：隧道启停、虚拟 IP 与路由、系统权限检查（需管理员权限时明确提示）、路由冲突检测、网络状态诊断、失败后的清理恢复。**不得假设 Windows 与 Linux 的路由、接口命名、防火墙、权限行为一致**。

【待核】平台优先级（[存档 §15.4](/review/chatgpt-2026-10-13#_15-4-平台支持策略)）：第一版依次验证 Linux VPS Server → Linux Agent → Windows Agent；其他平台等核心架构稳定后再加入。

## 可观测性（§17）

【待核】结构化日志（[存档 §17.1](/review/chatgpt-2026-10-13#_17-1-日志)）：时间、组件、操作、Network ID、Device ID（适用时）、Config Revision、错误类别、操作结果。

【待核】指标（[存档 §17.2](/review/chatgpt-2026-10-13#_17-2-指标)）：在线设备数、活跃 Peer 数、最近握手时间、配置应用成功率/失败数、路由冲突数、Alias 应用状态、服务端流量与接口状态。**不依赖单一指标判断端到端健康**。

【待核】故障处理（[存档 §17.3](/review/chatgpt-2026-10-13#_17-3-故障处理)）：覆盖 VPS 重启、WireGuard 接口意外停止、Agent 崩溃/离线、配置下发中断、SQLite 写入失败、NAT 规则安装失败、本机路由冲突、配置版本不一致。服务端重启后按数据库期望配置重建网络状态；客户端重启后重连、取配置、恢复其负责的路由。

【待核】备份（[存档 §17.4](/review/chatgpt-2026-10-13#_17-4-数据备份)）：备份 Network/Device 元数据、公钥与撤销状态、IPAM 分配、LAN Route 与 Alias、配置版本、审计记录。备份**不能靠直接复制正在写入的数据库文件**；恢复后检查实际 WireGuard/路由/NAT 状态并协调到期望状态。

## Web 控制台要点（§12）

【待核】导航与页面（[存档 §12](/review/chatgpt-2026-10-13#_12-web-控制台设计)）：Dashboard / Networks（Devices、LAN Routes、Aliases、Access Policy、Diagnostics）/ System（Server Status、Audit Logs、Settings）。第一版单管理员即可，但数据模型从开始就明确 Network 与用户的归属。

关键约束：

- Dashboard 不只给绿色图标，要说明数据来源与更新时间（[§12.2](/review/chatgpt-2026-10-13#_12-2-dashboard)）；
- 设备在线状态结合隧道握手 + Agent 心跳 + 状态上报判断；**"最近有握手"≠"所有网络功能正常"**（[§12.4](/review/chatgpt-2026-10-13#_12-4-devices-页面)）；
- 删除 Alias 必须同步清理路由与 NAT 规则（[§12.6](/review/chatgpt-2026-10-13#_12-6-aliases-页面)）；
- Diagnostics 至少覆盖 12 项检查（API 可达、接口存在、Peer 配置、握手、Overlay 路由、IP forwarding、防火墙、网关在线、Route 发布、Alias 冲突、NAT 生效、版本一致）；第一版先给准确诊断与建议，不做自动修复（[§12.7](/review/chatgpt-2026-10-13#_12-7-diagnostics-页面)）。
