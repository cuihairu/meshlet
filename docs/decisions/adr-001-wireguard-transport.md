# ADR-001：采用 WireGuard 作为隧道基础

- 状态：Accepted
- 日期：2026-10-14
- 期次：Phase 0
- 来源：[存档 §4.3 / §7](../review/chatgpt-2026-10-13.md#_7-wireguard-中继网络设计)（外部意见基线）

## 背景

Meshlet 第一版需要在一台公网 VPS 与多台 Linux/Windows 设备之间建立加密的三层隧道，承载 Overlay 网段、远端 LAN 与 Alias 网段的路由流量。

## 问题

选择哪种隧道与加密传输基础？

## 候选方案

1. **WireGuard**（Linux 内核接口 + 官方 Windows 实现）
2. OpenVPN / TLS 型 VPN
3. 自研 UDP 加密协议
4. 用户态 WireGuard 实现（wireguard-go / boringtun）

## 决定

采用 WireGuard：Linux 侧优先内核接口，Windows 侧评估官方 WireGuard for Windows 的受支持管理方式（详见 [ADR-007](adr-007-linux-network-backend.md)、[ADR-008](adr-008-windows-network-backend.md)）。不自研隧道协议。

## 理由

- 成熟、代码量小、攻击面小，密钥模型简单（静态公钥 + 预共享密钥可选）；
- Linux 内核态转发性能满足第一版 VPS 中继场景；
- 跨平台官方支持（Linux/Windows），符合 §4.3「Mature transport first」原则；
- Peer/AllowedIPs 语义与 Meshlet 的显式路由模型（§1.2.4）天然对齐。

## 缺点与风险

- 仅 UDP：极端网络环境（只放行 TCP）下第一版无回退路径——已接受（§7.6 明确的边界）；
- 封装开销带来 MTU 问题，需要可配置策略与诊断（§7.5）；
- 内核模块依赖：VPS 需加载 wireguard 模块（主流发行版默认可用）。

## 重新评估条件

- 需要浏览器内直连或 TCP 回退传输；
- 出现对等连接（P2P）需求超出中心中继能力；
- 目标平台缺少受支持的 WireGuard 管理方式。
