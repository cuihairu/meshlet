<p align="center"><img src="logo-copper.svg" width="64" height="64"></p>

> [English](README.md) | **中文**

<h1 align="center">meshlet</h1>

<p align="center">
<a href="https://github.com/cuihairu/meshlet/releases"><img alt="Status" src="https://img.shields.io/badge/status-in%20development-orange"></a>
</p>

<p align="center">
  <a href="https://github.com/cuihairu/meshlet/actions/workflows/ci.yml"><img src="https://github.com/cuihairu/meshlet/actions/workflows/ci.yml/badge.svg" alt="Tests"></a>
  <a href="https://github.com/cuihairu/meshlet/actions/workflows/docs.yml"><img src="https://github.com/cuihairu/meshlet/actions/workflows/docs.yml/badge.svg" alt="Docs deploy"></a>
  <a href="https://cuihairu.github.io/meshlet/"><img src="https://img.shields.io/badge/docs-site-brightgreen" alt="Docs"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue" alt="License"></a>
  <a href="https://cuihairu.github.io/meshlet/design/logo-preview.html"><img src="https://img.shields.io/badge/logo-B%20amber%20copper-C97B2E" alt="Logo variant"></a>
</p>

基于自有 VPS 的自托管私人虚拟网络 —— Rust + WireGuard。

> [!NOTE]
> 已实现控制面、WireGuard hub/agent、LAN 路由与 Alias NAT、React 控制台、认证、审计、备份和设备审批。
> 本轮补充单实例多网络隔离、设备应用回执、hub 恢复、成功计划回滚、Direct LAN SNAT 和正式服务权限，
> 已有 Linux 真实内核与非 root 服务回归证据。Windows 完整后端、空 VPS 安装和真实设备走查仍待完成。
> 每日构建与一键安装见下节，当前验收范围见 [TODO](TODO.md)。

## 每日构建与一键安装

[每日构建](https://github.com/cuihairu/meshlet/actions/workflows/nightly.yml) 每天北京时间 **03:17** 触发，也可在 Actions 中手动运行。全部检查与 Linux 内核数据面测试通过后，发布 [nightly 预发布版本](https://github.com/cuihairu/meshlet/releases/tag/nightly)，同时保留带日期的不可变版本。安装包包含服务端、agent、CLI、Web 控制台和 systemd 单元；支持 Linux x86_64 / ARM64。

**在 VPS 安装服务端：**

```bash
curl -fsSL https://github.com/cuihairu/meshlet/releases/download/nightly/install.sh | sudo bash -s -- server
```

脚本会安装依赖、校验下载包的 SHA-256、创建专用用户与本地 WireGuard 密钥，并启用服务。默认控制台只监听 `127.0.0.1:8080`；远程 VPS 可先使用 SSH 转发访问：

```bash
ssh -L 8080:127.0.0.1:8080 user@你的VPS
```

打开 `http://127.0.0.1:8080` 创建管理员、网络和设备自举码。在 VPS 防火墙放行对应 UDP 端口：第一个网络默认 `51820`，后续网络依次递增。公网管理入口按[安装指南](docs/guide/install.md)配置 HTTPS 反代。

**在 Linux 设备安装 agent：**

```bash
curl -fsSL https://github.com/cuihairu/meshlet/releases/download/nightly/install.sh | sudo bash -s -- agent \
  --server-url 'https://meshlet.example.com' \
  --hub-endpoint '你的VPS公网IP:51820' \
  --bootstrap-token '控制台生成的自举码' \
  --name 'home-linux'
```

在控制台批准设备，再应用该网络的当前修订。控制台会分别显示 hub 应用结果、设备回执和业务探测状态。

**升级与定位版本：**重复执行同角色命令即可升级到最新成功的 nightly，已有 TOML、私钥、设备凭据和数据库保留；不会自动每天升级正在运行的设备。安装指定历史版本时，将下载地址中的 `nightly` 替换为 Releases 页上的完整日期标签，并增加 `--version '该标签'`。可用 `--no-start` 只安装不启动。

```bash
systemctl status meshlet-server   # 设备端改为 meshlet-agent
journalctl -u meshlet-server -n 100 --no-pager
cat /usr/local/share/meshlet/server-build-info
```

流水线须先合入默认分支并成功运行一次，下载链接才会产生可安装的资产。Windows 数据面仍在待办中，本脚本用于 Linux + systemd；更多配置见[安装指南](docs/guide/install.md)。

## 产品定义

在一台拥有公网 IPv4 的 VPS 上部署 meshlet server，在 Linux/Windows 设备上安装 agent，即可得到一个完全由自己管理的私人虚拟网络：

- 设备间稳定的 Overlay IPv4 地址（经 VPS 中继）
- 访问网关设备背后的异地局域网
- 用 Alias 前缀解决重叠网段（例如两个 `192.168.1.0/24`）
- Web 控制台管理网络、设备、路由与诊断

第一版不做：公共中继网络、P2P/NAT 打洞、二层桥接、全局出口 VPN。

## 文档

- [分析整理](https://cuihairu.github.io/meshlet/analysis/) —— 按主题结构化的要点提炼
- [架构与 TODO 审查](docs/analysis/architecture-review-2026-10-17.md) —— 实现缺口、重新验收要求与建议优先级
- [个人组网功能对比](docs/analysis/personal-networking-comparison.md) —— 与 ZeroTier、Tailscale 的 61 项能力对比、官方来源与开发可行性
- [外部意见存档（2026-10-13）](https://cuihairu.github.io/meshlet/review/chatgpt-2026-10-13.html) —— 外部对话逐字存档；仅代表外部意见，任何主张行动前须对代码核验
- [TODO](TODO.md) —— 落地跟踪条目，带期次与验收标准
- [Logo 配色对比](https://cuihairu.github.io/meshlet/design/logo-preview.html)

## 状态

控制平面（网络、邀请、设备加入、LAN 路由、Alias 映射、诊断、备份恢复）与 WireGuard 数据面
（hub 中继 + agent：拉计划 → 对账 → 应用隧道/路由/NAT → 心跳）均已实现，并由 workspace 测试
套件覆盖，含驱动真实内核 WireGuard 与真实 iptables 的特权 netns 测试。会话认证、CSRF、API Token、
审计、在线状态判定、配置修订状态机（DB 写入 ≠ 生效）、ZeroTier 式设备自举注册
（自举码 → 待审批 → 批准/拒绝）均已就位。

本轮架构修复及 Linux 回归记录见 [P0 修复与 nightly 实施记录](docs/implementation/fixes-and-nightly-2026-10-17.md)。
整体部署验收仍未完成：ARM64 构建、默认分支首次 nightly 发布、空 VPS 一键安装、Windows 后端（ADR-008）
和真实设备走查保持待验证。当前工作以 [TODO](TODO.md) 顶部清单为准，本地测试不替代真实部署验收。

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
