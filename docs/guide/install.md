# 安装指南（Linux VPS）

> 来源：[存档 §19 Phase 5](../review/chatgpt-2026-10-13.md)。目标：从一台空
> VPS 到 meshlet-server 常驻自启动、控制台可访问、备份可用。
>
> **诚实边界（2026-10-15）**：本指南的构建、配置、systemd 单元已在开发机
> 真验（见文末验证清单）；**真实空 VPS 的端到端部署**（含设备 agent 建立
> WireGuard 隧道、LAN 路由互通）**待真机验证**——设备端数据面尚未实装
> （ADR-007：开发环境无 CAP_NET_ADMIN，见 TODO 对应条目）。相关小节均
> 标注了这一点，不会假装完成。

## 0. 已验证 / 待真机验证

| 步骤 | 状态 |
|---|---|
| `cargo build --release` 构建产物 | ✅ 已真验 |
| systemd 单元 `systemd-analyze verify` | ✅ 已真验（语法/依赖/硬化项组合） |
| 控制台静态构建 `pnpm run build` | ✅ 已真验 |
| 服务启动 / bootstrap / 控制台 / 备份（服务端控制面） | ⏳ 待真机（逻辑有 246 项测试覆盖，未在真实 VPS 走查） |
| agent 加入并建立 WireGuard 隧道、LAN Route/Alias 互通 | ⛔ 待数据面实装 + 真机（ADR-007 卡点） |

## 1. 前置条件

- **服务器**：Linux x86_64 + systemd（Ubuntu 22.04+ / Debian 12 口径），root 或 sudo；
- **构建机**（可与服务器同一台）：Rust stable（`rustup`）；
- **控制台**（可选，建议要）：Node 20+ 与 pnpm（`corepack enable`）；
- **对外端口**：443/TCP（HTTPS 反代）。WireGuard 的 UDP 端口（默认预留
  51820/udp）在数据面实装后才需要开放——现在开了也没有进程在听。

## 2. 构建 release 产物

```bash
git clone https://github.com/cuihairu/meshlet.git
cd meshlet

# 服务端 + agent（release profile 启用 thin LTO）
cargo build --release --bin meshlet-server --bin meshlet-agent
# → target/release/meshlet-server
# → target/release/meshlet-agent（数据面骨架，见 §5 agent 一节）

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
install -m 0755 target/release/meshlet-agent  /usr/local/bin/meshlet-agent   # 模板，暂不启用
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

# 备份（§17.4「备份 ≠ 同步」）：默认**全关**——不写盘、不自动、无任何外发
# /云上传/遥测。下面整段注释掉 = 备份未配置 = POST /api/v1/system/backup
# 返回 503 backup_not_configured。要用备份必须显式给目录（auto 仍默认关）。
# [backup]
# dir = "/var/lib/meshlet/backups"   # 备份落盘目录（文件权限 0600）
# auto = false                       # 定时备份：显式 true 才开（默认关）
# interval_secs = 86400              # 定时间隔（秒）
```

设备端 `/etc/meshlet/agent.toml`（agent 数据面实装前仅作占位）：

```toml
# 控制面地址（走 HTTPS 反代域名）。
server_url = "https://meshlet.example.com"
# agent 本地状态目录。
state_dir = "/var/lib/meshlet-agent"
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

**agent 单元是模板**（`deploy/systemd/meshlet-agent.service`）：当前 agent
二进制是 Phase 1 骨架（无网络后端，启动即退出），**现在不要 enable**——
数据面实装（ADR-007 卡点解除）后按同法安装启用，届时其需要且仅需要
`CAP_NET_ADMIN`。**此段整体待真机验证。**

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

**设备加入与互通（⛔ 待真机验证）**：控制面流程（邀请 → enroll → 设备入列 →
虚拟 IP 分配）已实现并有测试，但设备侧 agent 尚不会建立 WireGuard 接口与
路由（ADR-007 卡点），因此「两台设备经 VPS 互通」的端到端验收未达成——
对应 TODO 条目保持未勾。

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
