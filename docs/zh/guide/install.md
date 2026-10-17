# 安装指南（Linux VPS）

> 来源：[存档 §19 Phase 5](../review/chatgpt-2026-10-13.md)。目标：从一台空
> VPS 到 meshlet-server 常驻自启动、控制台可访问、备份可用。
>
> **诚实边界（2026-10-15）**：本指南的构建、配置、systemd 单元已在开发机
> 真验（见文末验证清单）；**真实空 VPS 的端到端部署**（含设备 agent 建立
> WireGuard 隧道、LAN 路由互通）**待真机验证**——agent 数据面已实装并有
> netns 集成测试覆盖（拉计划 → 对账 → 应用 → 心跳，含主机重启后重放），
> 但真机走查尚未做（ADR-007）。相关小节均标注了这一点，不会假装完成。

## 0. 已验证 / 待真机验证

| 步骤 | 状态 |
|---|---|
| `cargo build --release` 构建产物 | ✅ 已真验 |
| systemd 单元 `systemd-analyze verify` | ✅ 已真验（语法/依赖/硬化项组合） |
| 控制台静态构建 `pnpm run build` | ✅ 已真验 |
| 服务启动 / bootstrap / 控制台 / 备份（服务端控制面） | ⏳ 待真机（逻辑有 246 项测试覆盖，未在真实 VPS 走查） |
| agent 数据面逻辑（拉计划 / 对账 / 应用 / NAT 所有权清理） | ✅ 已实装（netns 集成测试 `apps/agent/tests/agent_reconcile.rs`） |
| agent 加入并建立 WireGuard 隧道、LAN Route/Alias 互通 | ⏳ 待真机（逻辑已实装，真实设备走查未做，ADR-007） |

## 1. 前置条件

- **服务器**：Linux x86_64 + systemd（Ubuntu 22.04+ / Debian 12 口径），root 或 sudo；
- **构建机**（可与服务器同一台）：Rust stable（`rustup`）；
- **控制台**（可选，建议要）：Node 20+ 与 pnpm（`corepack enable`）；
- **对外端口**：443/TCP（HTTPS 反代）+ WireGuard 的 UDP 端口
  （默认 51820/udp，`[dataplane] listen_port` 可改）——数据面开启后 hub
  在该端口监听，设备端 endpoint 指向它。

## 2. 构建 release 产物

```bash
git clone https://github.com/cuihairu/meshlet.git
cd meshlet

# 服务端 + agent（release profile 启用 thin LTO）
cargo build --release --bin meshlet-server --bin meshlet-agent
# → target/release/meshlet-server
# → target/release/meshlet-agent（设备端数据面，见 §4 agent 配置）

# 控制台静态文件（可选）
cd console && corepack enable && pnpm install && pnpm run build
# → console/dist
```

## 3. 安装布局与系统用户

```bash
# 专用系统用户（不可登录；家目录即数据目录）
useradd --system --home-dir /var/lib/meshlet --shell /usr/sbin/nologin meshlet
useradd --system --home-dir /var/lib/meshlet-agent --shell /usr/sbin/nologin meshlet-agent

# 二进制与控制台
install -m 0755 target/release/meshlet-server /usr/local/bin/meshlet-server
install -m 0755 target/release/meshlet-agent  /usr/local/bin/meshlet-agent   # 设备端（§4 配置后启用）
mkdir -p /usr/local/share/meshlet
cp -r console/dist /usr/local/share/meshlet/console

# 配置目录
mkdir -p /etc/meshlet
```

数据目录 `/var/lib/meshlet`（SQLite 库与备份）由 systemd 的
`StateDirectory=meshlet` 自动创建并归属 `meshlet` 用户，无需手动建。

## 4. 配置文件（安全默认）

`/etc/meshlet/meshlet.toml`（逐项注释；**所有默认值都是最保守的**——备份关、
无外发、只听回环）：

```toml
# 监听地址。默认只听回环——对外一律走 HTTPS 反代（§6）。
bind = "127.0.0.1:8080"

# SQLite 库路径（控制面状态 + 审计 + 会话）。目录由 systemd StateDirectory 管。
database_path = "/var/lib/meshlet/meshlet.db"

# Overlay 网段（ADR-004）。默认 10.240.0.0/16，可按需改。
overlay_cidr = "10.240.0.0/16"

# 会话 Cookie 的 Secure 属性。部署在 HTTPS 反代后**必须为 true**（§11.4）。
cookie_secure = true

# Web 控制台静态目录（§2 构建产物）。不配置则不托管控制台（纯 API 模式）。
console_dir = "/usr/local/share/meshlet/console"

# 在线判定窗口（§12.4）：agent 上报新鲜 300s / 握手新鲜 120s。默认即可。
# presence_agent_window_secs = 300
# presence_handshake_window_secs = 120

# 计划隧道 MTU（§7.5）。默认不配置——设备按 WireGuard 默认 1420 组接口，诊断
# 第 ⑬ 项会报 warning 并给出 `ping -M do -s 1392` 实测命令；底层是 PPPoE/4G
# 等小 MTU 网络时建议显式配置（范围 1280..=65535，低于 1280 会拒绝启动）。
# tunnel_mtu = 1380

# 数据面接线（ADR-007）：默认**全关**——apply 修订只记录、显式失败并说明
# 「已记录但未应用」，不碰内核。要让本机真正承担 hub 转发面（wg 接口/peer/
# 路由/FORWARD 放行）才打开；进程需要 CAP_NET_ADMIN（安装 §5 的 dataplane.conf drop-in 后授予）。私钥只从文件读取、绝不落库（ADR-010）。
# [dataplane]
# enabled = true                                 # 打开才真实执行 apply/rollback
# interface = "wg0"                              # 受管 WireGuard 接口名
# listen_port = 51820                            # net-1 端口；net-N 使用此端口 + N - 1
# private_key_file = "/etc/meshlet/hub.key"      # hub 私钥文件（首装必须，0600）

# 备份（§17.4「备份 ≠ 同步」）：默认**全关**——不写盘、不自动、无任何外发
# /云上传/遥测。下面整段注释掉 = 备份未配置 = POST /api/v1/system/backup
# 返回 503 backup_not_configured。要用备份必须显式给目录（auto 仍默认关）。
# [backup]
# dir = "/var/lib/meshlet/backups"   # 备份落盘目录（文件权限 0600）
# auto = false                       # 定时备份：显式 true 才开（默认关）
# interval_secs = 86400              # 定时间隔（秒）
```

设备端 `/etc/meshlet/agent.toml`：

```toml
# 控制面地址（走 HTTPS 反代域名）。
server_url = "https://meshlet.example.com"
# agent 本地状态目录（账本 applied.json 落在这里，用于启动对账）。
state_dir = "/var/lib/meshlet-agent"
# 设备凭证：加入（POST /api/v1/enroll）返回的 agent_token，仅此一次可见。
# 写入本机文件（0600）；服务端只存 SHA-256 摘要，撤销即失效（ADR-010）。
# 二选一：手工 enroll 后填这里，或走下面的自举注册（推荐批量部署）。
device_token = "…enroll 响应里的 agent_token…"

# 自举注册（ZeroTier 式，替代手工 enroll）：控制台先在网络里签发自举码
# （管理端 → 自举码 → 签发；原始码仅显示一次），设备只配这两项 +
# private_key_file，开机自动注册：控制中心出现待审批申请，管理员批准后
# 该设备即拿到虚拟 IP 并进入期望配置——全程无需在设备间传递 agent_token。
# bootstrap_token = "…控制台签发的自举码…"
# device_name = "edge-office-1"

# 数据面（ADR-007）：默认**全关**——关闭时 agent 只打印状态、不碰内核。
# 打开后 agent 启动即用 device_token 拉取自身计划
# （GET /api/v1/agent/device/desired），与本机内核对账：期望哈希变化或
# 隧道/路由/NAT 漂移（含主机重启后隧道消失）才重放，然后周期心跳上报。
# agent 只消费结构化配置对象，绝不执行服务端下发的 Shell 命令（§16.4）。
# [dataplane]
# enabled = true                                 # 打开才真实操作内核
# interface = "wg0"                              # 受管 WireGuard 接口名
# private_key_file = "/etc/meshlet/agent.key"    # 本设备私钥（首装必须，0600）
# hub_endpoint = "203.0.113.10:51820"            # hub 可达地址（服务端未通告时兜底）
# poll_interval_secs = 30                        # 轮询间隔（秒）
```

**自举注册的凭证解析顺序**（`device_token` → `{state_dir}/device_token` →
`bootstrap_token` 注册）：agent 首次启动无凭证时持自举码注册
（`POST /api/v1/device-registrations`），返回的 agent_token 落盘
`{state_dir}/device_token`（0600）后续启动复用——自举码只需配置一次；
WireGuard 密钥对本机生成（已有 `private_key_file` 则只推导公钥，
重装不换钥匙，私钥不出设备）。**批准前**设备处于待审批：计划端点 404
`pending approval`，agent 退避重试并继续心跳（证据在待审批列表可见），
管理员批准后无需任何设备侧操作，下一个轮询周期自动拉到计划。

**服务端必须先开数据面**，否则计划端点返回 `503 dataplane_not_configured`
（agent 退避重试，不会把「未配置」当成「已生效」）。hub 侧
`[dataplane] private_key_file` 首装必须配置：设备计划里的 hub 公钥由服务端
在请求时从该文件现算（`wg pubkey`，不落库、不出站，ADR-010）。

```bash
# 手动核对 agent 看到的计划（诊断用；需要 root 读私钥）
sudo -u meshlet-agent curl -s -H "Authorization: Bearer $TOKEN" \
  https://meshlet.example.com/api/v1/agent/device/desired
# 账本（上次真正应用的哈希/路由/NAT 所有权）
sudo cat /var/lib/meshlet-agent/applied.json
```

## 5. systemd 服务（自启动）

单元文件随仓库发布在 `deploy/systemd/`（`meshlet-server.service` 与
`meshlet-agent.service`），已按最小权限
硬化（`NoNewPrivileges` / `ProtectSystem=strict` / 空权限集 / 系统调用过滤等，
逐项见文件内注释）：

```bash
cp deploy/systemd/meshlet-server.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now meshlet-server
```

验证服务在跑：

```bash
systemctl status meshlet-server
# 公开状态端点（无需认证）：
curl -s http://127.0.0.1:8080/api/v1/system/status
# 日志是 JSON 行（§17.1 八字段）：
journalctl -u meshlet-server -f
```

开机自启由 `[Install] WantedBy=multi-user.target` + `enable` 保证；进程崩溃
由 `Restart=on-failure` 拉起；重启后按 §17.3 从 SQLite 重建期望状态（日志见
`mesh state rebuilt from database`）。

**agent 单元**（`deploy/systemd/meshlet-agent.service`）：agent 二进制已实装
数据面（拉计划 → 对账 → 应用 → 心跳），但单元的**真机部署走查尚未做**——
安装启用前请确认：`[dataplane] enabled = true`、`device_token` 或
`bootstrap_token` 之一已写入 `/etc/meshlet/agent.toml`（0600）、
`private_key_file` 存在（0600；自举注册时可不存在，agent 会生成），
并按单元注释授予 `CAP_NET_ADMIN`。启动后核对 `applied.json` 与
`wg show` 即可确认是否已按期望重放。**此段待真机验证。**

## 6. 反向代理（HTTPS）

控制台 Cookie 需要 HTTPS（`cookie_secure = true`）。Caddy 示例（自动签发证书）：

```text
# Caddyfile（自动签发证书）
meshlet.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

nginx 等价物：`proxy_pass http://127.0.0.1:8080;` + TLS 终止。要点：

- 服务器防火墙只开 443/TCP；`bind` 保持 `127.0.0.1`，8080 不对外；
- enroll / agent heartbeat 走同一域名（`/api/v1/enroll`、`/api/v1/agent/*`），
  反代无需额外路径规则；
- 反代后把 `cookie_secure` 置 `true`（§4）。

## 7. 初始化（首个管理员）

控制台是**无默认密码**设计（§11.4）：空库只有一个 bootstrap 机会。

```bash
curl -s -X POST https://meshlet.example.com/api/v1/auth/bootstrap \
  -H 'content-type: application/json' \
  -d '{"email":"admin@example.com","password":"<强口令>"}'
# 有用户后再调 → 409 already_bootstrapped（一次性窗口关闭）
```

随后浏览器打开 `https://meshlet.example.com`：登录 → 创建网络 → 生成邀请 →
（设备端流程见下）。

**设备加入与互通（⏳ 待真机验证）**：控制面流程（邀请 → enroll → 设备入列 →
虚拟 IP 分配）与 agent 数据面（拉计划 → 对账 → 应用隧道/路由/NAT → 心跳）均
已实现并有测试覆盖（netns 集成测试真跑 WireGuard 握手与双向互通，含主机重启后
按账本重放）。设备端流程：

```bash
# 1. 设备上放好本设备私钥（0600），写 /etc/meshlet/agent.toml（§4）
# 2. enroll 拿到 agent_token（仅此一次），写入 device_token
curl -s -X POST https://meshlet.example.com/api/v1/enroll \
  -H 'content-type: application/json' \
  -d '{"invite_token":"<邀请>","device_name":"edge-1","public_key":"<设备公钥>","platform":"linux"}'
# 3. 启动 agent：systemctl enable --now meshlet-agent
# 4. 控制台发布 LAN Route / Alias 映射后：应用对应修订（apply）
#    → agent 下轮轮询取到新计划并重放；主机重启后启动即对账重放
```

端到端「两台设备经 VPS 互通」的**真实设备**验收仍未做（ADR-007 真机走查），
因此对应 TODO 条目保持未勾。

## 8. 备份（可选，默认关）

备份默认不产生任何文件（§4 的 `[backup]` 段注释即关闭态）。开启后：

```bash
# 手动触发（需登录会话或 write scope API Token）：
curl -s -X POST https://meshlet.example.com/api/v1/system/backup \
  -b cookies.txt -H 'x-requested-with: XMLHttpRequest'
```

离线恢复（先停服务）：

```bash
systemctl stop meshlet-server
/usr/local/bin/meshlet-server restore /var/lib/meshlet/backups/<backup>.db /etc/meshlet/meshlet.toml
systemctl start meshlet-server   # §17.3 语义收敛到期望状态
```

详见 [备份与恢复](../architecture/backup-restore.md)（文件权限、校验、
恢复收敛语义）。

## 9. 升级与卸载

**升级**：换二进制 + 重启（§17.3 启动重建已由测试覆盖）：

```bash
install -m 0755 target/release/meshlet-server /usr/local/bin/meshlet-server
systemctl restart meshlet-server
```

**卸载**（数据不动请跳过最后一步）：

```bash
systemctl disable --now meshlet-server
rm /etc/systemd/system/meshlet-server.service && systemctl daemon-reload
rm -f /usr/local/bin/meshlet-server /usr/local/bin/meshlet-agent
rm -rf /usr/local/share/meshlet /etc/meshlet
rm -rf /var/lib/meshlet          # ⚠️ 删库（含备份）；确定不要了再执行
userdel meshlet meshlet-agent
```

## 10. 验证清单

本指南在开发机真验过（2026-10-15）：

- `cargo build --release`：成功产出 `target/release/meshlet-server` 与
  `meshlet-agent`（release profile：`lto = "thin"`）；
- `systemd-analyze verify deploy/systemd/meshlet-server.service` 与
  `meshlet-agent.service`：通过（语法、依赖、硬化指令组合均有效）；
- `pnpm run docs:build`：本页可构建。

**待真机验证**（对应 TODO「安装流程与自启动」条保持未勾的原因）：真实空
VPS 上按本指南从零走查一遍——bootstrap、控制台、备份开关、重启恢复；以及
数据面实装后的 agent 加入与互通。走查中发现的问题会回写本指南。

## 数据面服务权限与恢复

控制面默认 unit 不授予网络管理能力。开启 `[dataplane] enabled = true` 后，在 VPS 安装配套 drop-in：

```bash
install -d /etc/systemd/system/meshlet-server.service.d
install -m 0644 deploy/systemd/meshlet-server.service.d/dataplane.conf /etc/systemd/system/meshlet-server.service.d/dataplane.conf
systemctl daemon-reload
systemctl restart meshlet-server
```

Agent 使用专用用户及 ambient `CAP_NET_ADMIN` / `CAP_NET_RAW`，直接运行网络工具，不经过 sudo。两端都需要安装 `iproute2`、`wireguard-tools`、`iptables` 和 `iputils-ping`；unit 允许 AF_NETLINK 及写转发开关。配置和私钥必须对各自服务用户可读（例如 `chown meshlet:meshlet hub.key; chmod 0600 hub.key`），不能只对 root 可读。

`net-1` 保留配置的接口，后续网络使用 `mlt2`、`mlt3` 等独立接口；UDP 端口从 `listen_port`（默认 51820）依次递增，需要同步放行 VPS 防火墙。共享路由域拒绝不同网络的 Overlay、Direct 和 Alias 转发前缀重叠，hub 防火墙拒绝跨网络转发。旧版多网络部署应先停服务并清理已确认归属 Meshlet 的旧共享接口，再启用新版，避免遗留 Peer/地址。

成功的 hub 公共计划保存在 SQLite `hub_deployments`；私钥仍只从本地文件读取。启动后立即检查，随后每 30 秒检查并修复内核漂移。`apply_status=applied` 表示 hub 执行成功；`convergence.device_apply_status` 表示设备回执收敛，业务健康在未探测时为 `not_probed`。设备失败或离线不能当作端到端已生效。

回滚仅恢复上一份成功计划及其路由/Alias，重新等待设备回执；首次应用失败只清理该网络 hub 接口。恢复失败通过 `convergence.hub_recovery_error` 报告。

正式权限回归可在有 systemd、免密 sudo 与 WireGuard 的 Linux 上执行；脚本使用临时网络命名空间和临时服务，不创建永久用户，完成后清理：

```bash
cargo build -p meshlet-server --bin meshlet-server
sudo python3 scripts/verify-systemd.py target/debug/meshlet-server
```
