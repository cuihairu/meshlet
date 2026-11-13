> [English](README.md) | **中文**

<p align="center"><img src="logo-copper.svg" width="64" height="64"></p>

<h1 align="center">meshlet</h1>

<p align="center"><a href="https://github.com/cuihairu/meshlet/releases"><img alt="Status" src="https://img.shields.io/badge/status-in%20development-orange"></a> <a href="https://github.com/cuihairu/meshlet/actions/workflows/ci.yml"><img src="https://github.com/cuihairu/meshlet/actions/workflows/ci.yml/badge.svg" alt="Tests"></a> <a href="https://github.com/cuihairu/meshlet/actions/workflows/docs.yml"><img src="https://github.com/cuihairu/meshlet/actions/workflows/docs.yml/badge.svg" alt="Docs deploy"></a> <a href="https://cuihairu.github.io/meshlet/zh/"><img src="https://img.shields.io/badge/docs-site-brightgreen" alt="Docs"></a> <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue" alt="License"></a> <a href="https://cuihairu.github.io/meshlet/zh/design/logo-preview.html"><img src="https://img.shields.io/badge/logo-B%20amber%20copper-C97B2E" alt="logo-B amber copper (approved)"></a></p>

基于自有 VPS 的自托管私人虚拟网络 —— Rust + WireGuard。

> [!NOTE]
> 已实现控制面、WireGuard hub/agent、LAN 路由与 Alias NAT、React 控制台、认证、审计、备份和设备审批。
> 本轮补充单实例多网络隔离、设备应用回执、hub 恢复、成功计划回滚、Direct LAN SNAT 和正式服务权限，
> 已有 Linux 真实内核与非 root 服务回归证据。
> Windows 后端模块已实现并完成路由、防火墙、服务控制与卸载清理的真机验收。
> nightly 现已附带 Windows agent+CLI+tray-host zip 与 `install.ps1`。
> agent 数据面接线已按 ADR-008 落地（tunnel-only v1），R-05 三项真机验收 2026-11-12 全过；端到端 apply 真机走查与安装包/托盘真机验收（AGENT-WIN-3、NIGHTLY-MSI-1、#52）已于 2026-11-13 全部通过。
> 空 VPS 安装和真实设备
> 走查也仍待完成。每日构建与一键安装见下节，当前验收范围见 [TODO](todo.md)。

## 每日构建与一键安装

[每日构建](https://github.com/cuihairu/meshlet/actions/workflows/nightly.yml) 每天北京时间 **03:17** 触发，也可在 Actions 中手动运行。全部检查与 Linux 内核数据面测试通过后，发布 [nightly 预发布版本](https://github.com/cuihairu/meshlet/releases/tag/nightly)，同时保留带日期的不可变版本。发布包含 Linux x86_64 / ARM64 静态 tar 归档，以及按组件拆分的 `deb`/`rpm` 包（`meshlet-server` / `meshlet-agent` / `meshlet-cli`）。Windows agent+CLI+tray-host zip 与 `install.sh` / `install.ps1` 一键安装脚本同时发布。
在 VPS 安装服务端：

```bash
curl -fsSL https://github.com/cuihairu/meshlet/releases/download/nightly/install.sh | sudo bash -s -- server
```

脚本会安装依赖、校验下载包的 SHA-256、创建专用用户与本地 WireGuard 密钥，并启用服务。默认控制台只监听 `127.0.0.1:8080`；远程 VPS 可先使用 SSH 转发访问：

```bash
ssh -L 8080:127.0.0.1:8080 user@你的VPS
```

打开 `http://127.0.0.1:8080` 创建管理员、网络和设备自举码。在 VPS 防火墙放行对应 UDP 端口：第一个网络默认 `51820`，后续网络依次递增。公网管理入口按[安装指南](docs/guide/install.md)配置 HTTPS 反代。

在 Linux 设备安装 agent：

```bash
curl -fsSL https://github.com/cuihairu/meshlet/releases/download/nightly/install.sh | sudo bash -s -- agent \
  --server-url 'https://meshlet.example.com' \
  --hub-endpoint '你的VPS公网IP:51820' \
  --bootstrap-token '控制台生成的自举码' \
  --name 'home-linux'
```

在控制台批准设备，再应用该网络的当前修订。控制台会分别显示 hub 应用结果、设备回执和业务探测状态。

升级与定位版本：重复执行同角色命令即可升级到最新成功的 nightly，已有 TOML、私钥、设备凭据和数据库保留；不会自动每天升级正在运行的设备。安装指定历史版本时，将下载地址中的 `nightly` 替换为 Releases 页上的完整日期标签，并增加 `--version '该标签'`。可用 `--no-start` 只安装不启动。

```bash
systemctl status meshlet-server   # 设备端改为 meshlet-agent
journalctl -u meshlet-server -n 100 --no-pager
cat /usr/local/share/meshlet/server-build-info
```

用 Linux 包（deb / rpm）安装：

nightly 同时按组件发布两种架构的包。`meshlet-server` 含服务端二进制、systemd 单元、Web 控制台与示例配置；`meshlet-agent` 含 agent 二进制、systemd 单元与示例配置；`meshlet-cli` 是独立 CLI：

```bash
# Debian / Ubuntu（ARM 平台把 amd64 换成 arm64）
curl -fLO https://github.com/cuihairu/meshlet/releases/download/nightly/meshlet-server_0.0.0~nightly_amd64.deb
curl -fLO https://github.com/cuihairu/meshlet/releases/download/nightly/meshlet-agent_0.0.0~nightly_amd64.deb
sudo apt install ./meshlet-server_0.0.0~nightly_amd64.deb ./meshlet-agent_0.0.0~nightly_amd64.deb

# Fedora / RHEL（ARM 平台把 x86_64 换成 aarch64）
sudo dnf install https://github.com/cuihairu/meshlet/releases/download/nightly/meshlet-server-0.0.0~nightly-1.x86_64.rpm
sudo dnf install https://github.com/cuihairu/meshlet/releases/download/nightly/meshlet-agent-0.0.0~nightly-1.x86_64.rpm
```

包会创建服务账户与状态目录，但刻意不生成活动配置（配置因机而异，含密钥与 token）：复制 `/etc/meshlet/*.toml.example` 填好。生成密钥（服务端 `wg genkey > /etc/meshlet/hub.key`），再 `sudo systemctl enable --now meshlet-server`（或 `meshlet-agent`）。想要引导式首次安装请用上面的 `install.sh`。

流水线须先合入默认分支并成功运行一次，下载链接才会产生可安装的资产。`install.sh` 用于 Linux + systemd；Windows agent 用下文 [Windows 支持](#windows-支持) 的 `install.ps1` 安装。更多配置见[安装指南](docs/guide/install.md)。

**OpenWrt / iStoreOS 安装（opkg）：**

nightly 对每个架构（x86_64 / aarch64）发布三个 `.ipk`：`meshlet-nightly-openwrt-<arch>.ipk`（musl 静态二进制 + procd init + UCI 配置）、`meshlet-nightly-openwrt-luci-app.ipk`（LuCI 设置与状态页）、`meshlet-nightly-openwrt-app-meta.ipk`（iStore 元数据；装它会经依赖拉齐前两个）。按依赖链顺序安装：

```bash
opkg install meshlet-nightly-openwrt-x86_64.ipk        # 或 -aarch64
opkg install meshlet-nightly-openwrt-luci-app.ipk
opkg install meshlet-nightly-openwrt-app-meta.ipk      # 可选；连带装齐
```

典型部署：做 hub 的路由器跑 server 角色（可选再把 agent 角色打开，让路由器自身入网）；成员路由器只跑 agent 角色。两个角色都在 `/etc/config/meshlet`，各有独立 `enabled` 开关，默认关闭。procd init 每次启动都从 UCI 渲染 `/var/etc/meshlet-{server,agent}.toml`——UCI 是唯一配置源，LuCI 里 Apply 即重启生效。WireGuard 密钥首启自动生成（需 `wg` 工具，iStoreOS 自带）；hub 数据面另需 `kmod-wireguard`。升级保留 `/etc/config/meshlet`（新默认值落 `/etc/config/meshlet-opkg` 旁路），并把已启用的角色自动拉起。

LuCI 在 **服务 → Meshlet 组网**：双角色设置页 + 状态页（服务状态、设备在线计数、`logread` 日志摘录，10 秒自动刷新）。设备计数需在 server 控制台签发 read scope 的 API token 并填入设置页 `api_token`，页面只显示脱敏前缀。LuCI 是运维面而非完整管理控制台——设备批准、revision、拓扑仍在 server 的 web 控制台操作（默认 `127.0.0.1:8080` 只绑回环，请改成 LAN 可达的 bind 或加反代）。

server 角色在路由器上是可选的：x86_64 验收路由器（iStoreOS 24.10，1.6 GB 内存）实测，hub 开数据面空闲 RSS ~10.5 MB，agent ~6.4 MB。

## Windows 支持

Windows 是数据面目标平台，受真机验收门禁（[R-05](docs/implementation/r05-windows-acceptance.md)，ADR-008）。仓库现状：

- 后端模块，已真机验收（中文 Windows Server 2022，2026-10-25/26）。路由（`netsh interface ipv4`）、防火墙规则（`netsh advfirewall firewall`）、服务控制（`sc`）与卸载清理——增/读回/删/幂等重删均真机走通。含 zh-CN 输出（GBK/CP936）由 `windows_console` 解码。
- WireGuardNT 隧道计划层 + CI：`windows_tunnel` 渲染 `WireGuardTunnel$<name>` 服务配置并构造 `wireguard.exe` argv；其文件级测试在 `windows-latest` CI 真跑。隧道真机全生命周期已于 2026-11-12 通过验收（R-05 B1）。
- 跨平台证据：全 workspace `cargo test` 通过。`cargo clippy --workspace --all-targets -- -D warnings` 在 `stable-x86_64-pc-windows-gnu` 上同样绿。CI 在 `windows-latest` 原生跑 `cargo test --workspace`。

Windows 验收现状（2026-11-13，R-05/安装包/托盘/端到端 apply 已全过，余 NAT 为 ADR-008 显式拒绝项）：

- agent 数据面后端已按 ADR-008 接线（tunnel-only v1，`1324dd2`）：Windows 的 `SystemBackend` 已映射到真实 Windows 后端（隧道/路由/设备计划），R-05 三项真机验收（隧道生命周期、提权执行层、开机恢复）已于 2026-11-12 全过。NAT-bearing 计划仍按 ADR-008 显式拒绝。端到端真机 apply 走查已于 2026-11-13 通过（新二进制两轮真实 apply：隧道服务重装、路由重放、防火墙规则幂等收敛、ping 10.240.0.1 全程 8-9ms，见 `todo.md` #52）。
- MSI 已入 nightly，安装包真机验收已通过（NIGHTLY-MSI-1，2026-11-13）。nightly 已附带 Windows agent+CLI+tray-host zip（`meshlet-nightly-windows-x86_64.zip`）与 `install.ps1` 一键安装（[安装方法见下](#在-windows-安装-agent)）。MSI 安装包为 `meshlet-nightly-windows-x86_64.msi`，由 cargo-wix 构建。该 MSI 把 server、agent、CLI 与 tray-host 打进一个包，含开始菜单项与卸载项。zip/install.ps1 真机验收已通过（AGENT-WIN-2，2026-10-31）；MSI 已于 2026-11-12 真机走查安装/卸载/运行（顺带发现并修复 2 个 CLI 缺陷，`6a9ec71`），含 `b988ed8` nightly 的复装确认已于 2026-11-13 通过（哈希校验下载、ARP 项、快捷方式、exe 集合、卸载清理、agent 连续性，见 `todo.md` NIGHTLY-MSI-1）。
- Windows 托盘宿主已随包发布，真机验收已通过（AGENT-WIN-3，2026-11-13）。`apps/tray-host`（`meshlet-tray-host.exe`，Win32 `Shell_NotifyIcon` 薄封装）消费 agent 写出的四态状态 PNG（`TraySink`）。已随 nightly zip 发布；`install.ps1` 会把它装进 `%LOCALAPPDATA%\meshlet`、注册 HKCU 登录自启并默认启动（`-NoStartTray` 只跳过立即启动）。真机走查已验证：console 会话下图标状态色像素级命中（`NIM_ADD = 1`）、右键菜单双入口完整渲染、本地面板 HTTP 200。菜单分两个入口：**本地面板**（tray-host 自己在 `127.0.0.1` 上托管的只读页，读本机状态文件展示当前节点 / 直连节点 / 本地路由，**server 挂了也照样打开**）与**控制台(网页)**（打开 `server_url` 托管的控制台）。Linux 侧 agent 写同样的状态 PNG 并经 D-Bus 发桌面通知，但 Linux 侧尚无对应的桌面托盘宿主二进制。

### 在 Windows 安装 agent

nightly 发布 Windows agent+CLI+tray-host zip 与 `install.ps1`。安装（PowerShell，无需管理员——agent 运行在用户会话，不是机器服务）：

```powershell
Invoke-RestMethod https://github.com/cuihairu/meshlet/releases/download/nightly/install.ps1 -OutFile install.ps1
pwsh -File .\install.ps1 -ServerUrl 'https://meshlet.example.com' -HubEndpoint '203.0.113.10:51820' -BootstrapToken '控制台里的TOKEN' -DeviceName 'home-windows'
```

安装脚本会校验 zip 的 SHA-256（对照 release 的 `SHA256SUMS`），把 `meshlet-agent.exe` / `meshlet-cli.exe` / `meshlet-tray-host.exe` 装进 `%LOCALAPPDATA%\meshlet`。把该目录加入用户 PATH，一次性生成 agent 密钥与配置，并注册隐藏运行的 HKCU Run 开机自启。重复执行即为升级——已有 `agent.toml` 与密钥保留，设备凭据不丢。离线/分阶段安装设 `$env:MESHLET_INSTALL_ARCHIVE` 与 `$env:MESHLET_INSTALL_SHA256SUMS`。安装器同时安装并注册托盘宿主 `meshlet-tray-host.exe`（`-NoStartTray` 可跳过立即启动，登录自启仍在），托盘菜单提供**本地面板**与**控制台(网页)**两个入口；Windows 上数据面 apply 已按 ADR-008 接线（tunnel-only v1），端到端真机 apply 走查已于 2026-11-13 通过——见下文。

### 在 Windows 从源码构建并运行 agent

优先用上面的安装脚本；仅当需要本地构建时才从源码构建。Linux 交叉到 `x86_64-pc-windows-msvc` 只有 check/clippy 级；原生 Windows（MSVC，即 CI 工具链）构建才是受支持路径。需要 Rust（stable）与 Git：

```powershell
git clone https://github.com/cuihairu/meshlet.git
cd meshlet
cargo build --release --bin meshlet-agent
```

创建 `C:\ProgramData\meshlet\agent.toml`（键名与 [安装指南](docs/guide/install.md) 的 Linux 示例一致；`interface` 即 WireGuardNT 隧道名）：

```toml
server_url = "https://meshlet.example.com"
state_dir = "C:\\ProgramData\\meshlet-agent"
# device_token = "…enroll 返回的 agent_token…"   # 或下面自举对
# bootstrap_token = "…控制台签发的自举码…"
# device_name = "edge-win-1"

[dataplane]
enabled = true
interface = "wg-meshlet"                  # 服务显示为 WireGuardTunnel$wg-meshlet
private_key_file = "C:\\ProgramData\\meshlet\\agent.key"
hub_endpoint = "203.0.113.10:51820"
poll_interval_secs = 30
```

在管理员终端运行：

```powershell
meshlet-agent.exe C:\ProgramData\meshlet\agent.toml
```

在控制台批准设备，再应用该网络的当前修订。**Windows 上数据面 apply 已接线**（ADR-008 tunnel-only v1；R-05 三项真机验收 2026-11-12 通过，端到端真机 apply 走查 2026-11-13 通过）；控制面（注册、心跳、状态）可用。机器上只有 `WireGuardTunnel$…` 服务（如手工搭建）并**不**等于装了 agent——请在进程列表确认 `meshlet-agent.exe`。安装包与托盘宿主的真机验收已于 2026-11-13 通过——见 [TODO](todo.md)。

## 产品定义

在一台拥有公网 IPv4 的 VPS 上部署 meshlet server，在 Linux/Windows 设备上安装 agent，即可得到一个完全由自己管理的私人虚拟网络：

- 设备间稳定的 Overlay IPv4 地址（经 VPS 中继）
- 访问网关设备背后的异地局域网
- 用 Alias 前缀解决重叠网段（例如两个 `192.168.1.0/24`）
- Web 控制台管理网络、设备、路由与诊断

连接策略：hub 常在——设备先经 hub 互知，再升级 P2P 直连（同 LAN 直连，或向 hub 观测到的公网端点打洞拨号，见 `apps/agent/src/direct.rs`）；跨 NAT 广域打洞场景仍待真机验收。hub 中继始终兜底、连接不断。

第一版不做：公共中继网络、二层桥接、全局出口 VPN。

## 文档

| 文档 | 内容 |
| --- | --- |
| [分析整理](https://cuihairu.github.io/meshlet/analysis/) | 按主题结构化的要点提炼 |
| [架构与 TODO 审查](docs/analysis/architecture-review-2026-10-17.md) | 实现缺口、重新验收要求与建议优先级 |
| [个人组网功能对比](docs/analysis/personal-networking-comparison.md) | 与 ZeroTier、Tailscale 的 61 项能力对比、官方来源与开发可行性 |
| [外部意见存档（2026-10-13）](https://cuihairu.github.io/meshlet/review/chatgpt-2026-10-13.html) | 外部对话逐字存档；仅代表外部意见，任何主张行动前须对代码核验 |
| [TODO](todo.md) | 落地跟踪条目，带期次与验收标准 |
| [Logo 配色对比](https://cuihairu.github.io/meshlet/design/logo-preview.html) |  |

## 状态

控制平面（网络、邀请、设备加入、LAN 路由、Alias 映射、诊断、备份恢复）与 WireGuard 数据面（hub 中继 + agent：拉计划 → 对账 → 应用隧道/路由/NAT → 心跳）均已实现。并由 workspace 测试套件覆盖，含驱动真实内核 WireGuard 与真实 iptables 的特权 netns 测试。会话认证、CSRF、API Token、
审计、在线状态判定、配置修订状态机（DB 写入 ≠ 生效）、ZeroTier 式设备自举注册
（自举码 → 待审批 → 批准/拒绝）均已就位。

本轮架构修复及 Linux 回归记录见 [P0 修复与 nightly 实施记录](docs/implementation/fixes-and-nightly-2026-10-17.md)。
整体部署验收仍未完成：ARM64 构建、默认分支首次 nightly 发布、空 VPS 一键安装和真实设备走查保持
待验证；Windows 侧数据面接线（R-05）已于 2026-11-12 通过真机验收，安装包/托盘真机验收与端到端 apply 走查已于 2026-11-13 通过——见 [Windows 支持](#windows-支持)。
当前工作以 [TODO](todo.md) 顶部清单为准，本地测试不替代真实部署验收。

## 本地测试口径

CI 与本地开发按改动面三路分流——改一行文档不该全量编译。

1. **文档改动**（`*.md`、`docs/**`、图片）：不编译。主 CI workflow 的
   `paths-ignore` 已跳过这些路径。
2. 代码改动：只跑改动子集，不全量。
   - `cargo test -p <改动 crate>`
3. **全量**（`cargo test --workspace`）：仅以下情形触发——Cargo.toml / Cargo.lock / console/pnpm-lock.yaml、
   `.github/**`、Docker/Compose 配置、发布前。

## 许可证

[Apache-2.0](LICENSE)

---

[English](README.md)
