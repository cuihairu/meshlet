<p align="center"><img src="logo-copper.svg" width="64" height="64"></p>

<h1 align="center">meshlet</h1>

<p align="center">
  <a href="https://github.com/cuihairu/meshlet/actions/workflows/ci.yml"><img src="https://github.com/cuihairu/meshlet/actions/workflows/ci.yml/badge.svg" alt="Tests"></a>
  <a href="https://github.com/cuihairu/meshlet/actions/workflows/docs.yml"><img src="https://github.com/cuihairu/meshlet/actions/workflows/docs.yml/badge.svg" alt="Docs deploy"></a>
  <a href="https://cuihairu.github.io/meshlet/"><img src="https://img.shields.io/badge/docs-site-brightgreen" alt="Docs"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue" alt="License"></a>
  <a href="https://cuihairu.github.io/meshlet/design/logo-preview.html"><img src="https://img.shields.io/badge/logo-B%20amber%20copper-C97B2E" alt="Logo variant"></a>
</p>

基于自有 VPS 的自托管私人虚拟网络 —— Rust + WireGuard。

> [!NOTE]
> 早期设计阶段：Phase 0 已完成（分析、ADR、文档），Phase 1 进行中（控制平面 + 迁移已落地）。文档站当前内容是一份外部设计基线的结构化分析，保留完整溯源。

## 产品定义（规划中）

在一台拥有公网 IPv4 的 VPS 上部署 meshlet server，在 Linux/Windows 设备上安装 agent，即可得到一个完全由自己管理的私人虚拟网络：

- 设备间稳定的 Overlay IPv4 地址（经 VPS 中继）
- 访问网关设备背后的异地局域网
- 用 Alias 前缀解决重叠网段（例如两个 `192.168.1.0/24`）
- Web 控制台管理网络、设备、路由与诊断

第一版不做：公共中继网络、P2P/NAT 打洞、二层桥接、全局出口 VPN。

## 文档

- [分析整理](https://cuihairu.github.io/meshlet/analysis/) —— 按主题结构化的要点提炼
- [外部意见存档（2026-10-13）](https://cuihairu.github.io/meshlet/review/chatgpt-2026-10-13.html) —— 外部对话逐字存档；仅代表外部意见，任何主张行动前须对代码核验
- [TODO](TODO.md) —— 落地跟踪条目，带期次与验收标准
- [Logo 配色对比](https://cuihairu.github.io/meshlet/design/logo-preview.html)

## 状态

Phase 0 完成（分析、ADR、文档）；Phase 1 进行中：域 crate（CIDR/IPAM/冲突检测/实体/邀请）、控制平面服务（网络/邀请/设备加入 API）、控制台认证（Argon2id、会话、限流、CSRF）、SQLite migrations、React 控制台（server 经 console_dir 静态托管）、带数据来源标注的在线状态判定，以及「DB 写入 ≠ 生效、失败可见」的配置修订状态机、外部机器凭据（`mlt_` API Token，read/write scope、可撤销、审计归属）、LAN 路由增删与设备撤销端点，191 项测试全绿。三个待验证高风险点：VPS 中继下的 WireGuard 路由、重叠网段的 Alias DNAT/SNAT、Windows/Linux 网络配置与安全回滚。

## 许可证

[Apache-2.0](LICENSE)

---

[English](README.md)
