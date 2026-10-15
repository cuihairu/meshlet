<p align="center"><img src="logo-copper.svg" width="64" height="64"></p>

> [English](README.md) | **中文**

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
> 已实现并通过 CI：控制平面、WireGuard 数据面（hub 中继 + agent）、LAN 路由与 Alias NAT、
> React 控制台、会话认证 + API Token + 审计、备份恢复、诊断，以及 ZeroTier 式设备自举注册
> （自举码 → 待审批 → 批准/拒绝）。仍待真实硬件走查（真实 VPS、两台真机、Windows）——
> 见 [TODO](TODO.md) 的落地条目与验收标准。

## 产品定义

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

控制平面（网络、邀请、设备加入、LAN 路由、Alias 映射、诊断、备份恢复）与 WireGuard 数据面
（hub 中继 + agent：拉计划 → 对账 → 应用隧道/路由/NAT → 心跳）均已实现，并由 workspace 测试
套件覆盖，含驱动真实内核 WireGuard 与真实 iptables 的特权 netns 测试。会话认证、CSRF、API Token、
审计、在线状态判定、配置修订状态机（DB 写入 ≠ 生效）、ZeroTier 式设备自举注册
（自举码 → 待审批 → 批准/拒绝）均已就位。

仍未完成：真实硬件走查——在真实 VPS 上部署、两台真实 Linux 客户端互通，以及 Windows 数据面后端
（ADR-008）。见 [TODO](TODO.md)。

## 本地测试口径

CI 与本地开发按改动面三路分流——改一行文档不该全量编译。

1. **文档改动**（`*.md`、`docs/**`、图片）：不编译。主 CI workflow 的
   `paths-ignore` 已跳过这些路径。
2. **代码改动**：只跑改动子集，不全量。
   - `cargo test -p <改动 crate>`
3. **全量**（`cargo test --workspace`）：仅以下情形触发——Cargo.toml / Cargo.lock / console/pnpm-lock.yaml、
   `.github/**`、Docker/Compose 配置、发布前。

## 许可证

[Apache-2.0](LICENSE)

---

[English](README.md)
