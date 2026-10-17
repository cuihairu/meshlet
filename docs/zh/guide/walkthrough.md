# 真机走查手册

> 本手册把 [存档 §22](../review/chatgpt-2026-10-13.md) 中仍缺真实环境的四条验收转成**可执行走查**：
> #70 空 VPS 部署、#32 两台 Linux 客户端经 VPS 互通、#47 网关发布 LAN、#52 Windows 权限不足与清理。
>
> **诚实边界**：本手册是**执行模板**，不是走查结论。四条 TODO 目前**均未勾**——
> 走查结果须按 §5 的模板回写并判定后，对应条目才有资格勾选。本手册不预设任何走查结果。

## 0. 通用约定

### 0.1 版本与环境记录

每个走查记录以下版本信息（不编造、不省略）：

```bash
git -C <源码目录> rev-parse --short HEAD      # 二进制来源提交
stat -c '%y %n' target/release/meshlet-server target/release/meshlet-agent
cargo --version && rustc --version
uname -a                                       # Linux 主机
```

Windows 侧另记：

```powershell
winver                       # 系统版本
$PSVersionTable.PSVersion
```

### 0.2 单步记录模板

每个走查的每一步都按此表记录（**时间、主机、版本、结果**四要素齐全）：

| 时间 | 主机 | 版本/环境 | 命令 | 预期 | 实测（原文） | 判定 |
|---|---|---|---|---|---|---|
| | | | | | | |

### 0.3 安全纪律

- 走查只使用 **RFC 5737 文档保留网段**（`192.0.2.0/24` 等）或测试 overlay 网段，**不得**承载真实业务流量。
- 每条走查末尾按「清理」小节把环境还原到走查前状态；失败路径同样要清理。
- 不触碰生产数据面：只删自己创建的对象（自有网络/设备/路由），不做全局性变更。
- 命令原文照抄到记录表——预期输出不一致时**先记录差异**，不要改命令去迁就。

### 0.4 仓内已有证据（不重复走查）

以下事项已有仓内真机/CI 证据，本手册不要求重复走查，仅列出作对照：

| 事项 | 证据位置 |
|---|---|
| WireGuard 握手与双向互通、撤销失效 | `crates/meshlet-network/tests/backend_wiring.rs`（真实内核 WireGuard + netns） |
| 重启后重放恢复互通 | `apps/agent/tests/agent_reconcile.rs`（netns） |
| Windows netsh 路由 add/读回/delete/幂等 re-delete | `crates/meshlet-network/tests/windows_netsh.rs`（CI windows-latest 真跑 netsh） |
| 权限不足 / 幂等删除的文本映射 | `crates/meshlet-network/src/windows_routes.rs` 单测（canonical 文案） |

**仍需真机走查的部分**：真实 VPS 上的部署链路、两台真机客户端互通、真实设备上控制台发布 LAN 路由、真实**非提权** shell 的权限拒绝报文。

---

## 1. 走查 A — 空 VPS 部署（TODO #70）

**验收口径**：新用户从空 VPS 完成部署。
**前置条件**：一台空 VPS（Ubuntu LTS），SSH 可达，具备 `sudo`/`root`；本地已按 [安装指南](./install.md) 构建出 `target/release/{meshlet-server,meshlet-agent}`。

### A.1 安装与自启动

```bash
# 1) 部署产物与配置（安装布局见 install.md §3-§4）
sudo install -d -m 0755 /etc/meshlet
sudo install -m 0644 config.toml /etc/meshlet/config.toml

# 2) 单元文件校验与安装（install.md §5）
systemd-analyze verify /etc/systemd/system/meshlet-server.service   # 预期：无输出
systemd-analyze verify /etc/systemd/system/meshlet-agent.service    # 预期：无输出
systemctl daemon-reload
systemctl enable --now meshlet-server

# 3) 运行态
systemctl is-active meshlet-server        # 预期：active
systemctl is-active meshlet-agent         # 预期：active
journalctl -u meshlet-server -p err --since "5 min ago"   # 预期：空
```

### A.2 bootstrap 首管理员与控制面

```bash
# 4) bootstrap（空库一次性窗口，install.md §7）
curl -s -X POST https://meshlet.example.com/api/v1/auth/bootstrap \
  -H 'content-type: application/json' \
  -d '{"email":"admin@example.com","password":"<强口令>"}'
# 预期：200；再次调用 → 409 already_bootstrapped

# 5) 本机状态
curl -s http://127.0.0.1:8080/api/v1/system/status
# 预期：200 + JSON

# 6) 控制台可达
curl -sI https://meshlet.example.com/       # 预期：200
```

### A.3 备份（默认关闭）

```bash
# 7) 未配置 [backup] 时应明确失败，而非静默（install.md §8）
curl -s -X POST http://127.0.0.1:8080/api/v1/system/backup
# 预期：503 backup_not_configured

# 8) 配置 [backup] dir=… auto=true 后重启服务
systemctl restart meshlet-server
curl -s -X POST http://127.0.0.1:8080/api/v1/system/backup
# 预期：200；备份文件出现在 dir 下且权限 0600
ls -l /var/lib/meshlet/backups
```

### A.4 重启恢复与升级卸载

```bash
# 9) 写入数据后重启，数据须仍在（install.md §9）
curl -s http://127.0.0.1:8080/api/v1/networks     # 先记录当前网络
systemctl restart meshlet-server
curl -s http://127.0.0.1:8080/api/v1/networks     # 预期：与重启前一致

# 10) 升级：替换二进制 + 重启
sudo systemctl stop meshlet-server && sudo install -m 0755 meshlet-server /usr/local/bin/
systemctl start meshlet-server && systemctl is-active meshlet-server   # 预期：active

# 11) 卸载
systemctl disable --now meshlet-server
sudo rm /etc/systemd/system/meshlet-server.service && systemctl daemon-reload
```

### 判定

A.1–A.4 全部「符合」→ **#70 可勾**。任一步骤失败或与原安装指南不符 → 记录差异与差距，条目保持未勾。

---

## 2. 走查 B — 两台 Linux 客户端经 VPS 互通（TODO #32）

**验收口径**：互访 / 重启恢复 / 撤销失效 / IP 不重复。
**前置条件**：走查 A 已完成（VPS 上 server 在跑）；两台 Linux 主机 A、B（agent 可运行，WireGuard 可用）。

### B.1 建网与设备加入

```bash
# 1) 控制台或 API 建网（记录 overlay CIDR，如 10.241.1.0/24）
# 2) 生成邀请，A、B 分别 enroll 加入（install.md 设备加入流程）
#    curl -s -X POST https://meshlet.example.com/api/v1/enroll …

# 3) 核对两台设备的虚拟 IP 互不相同（验收：IP 不重复）
curl -s http://127.0.0.1:8080/api/v1/networks/<id>/devices   # 记录 A、B 的 overlay IP
```

### B.2 启动 agent 并核对隧道

```bash
# 4) 两台主机上
systemctl enable --now meshlet-agent
systemctl is-active meshlet-agent          # 预期：active
wg show                                    # 预期：接口与 peer 已配置
wg show latest-handshakes                  # 预期：非零时间戳（握手已发生）
```

### B.3 互访

```bash
# 5) A → B
ping -c 20 <B 的 overlay IP>                # 预期：0% packet loss
# 6) B → A
ping -c 20 <A 的 overlay IP>                # 预期：0% packet loss
```

### B.4 重启恢复

```bash
# 7) 在 A 上模拟主机重启（重启 agent，触发对账重放）
systemctl restart meshlet-agent
sleep 5
ping -c 20 <B 的 overlay IP>                # 预期：0% packet loss（隧道/路由被重放恢复）
```

### B.5 撤销失效

```bash
# 8) 控制台或 API 撤销 B 的设备
# 9) 立即验证 A → B 不通
ping -c 5 <B 的 overlay IP>                 # 预期：100% packet loss（隧道/路由已拆除）
# 10) hub 侧确认 B 的公钥已不在 peer 列表
```

### 清理

```bash
# 撤销 A、B 两台设备；删除测试网络
systemctl disable --now meshlet-agent
```

### 判定

「互访」「重启恢复」「撤销失效」「IP 不重复」四项**全部符合** → **#32 可勾**。缺任一项 → 记录差距，条目保持未勾。

---

## 3. 走查 C — 网关发布 LAN（TODO #47）

**验收口径**：发布 CIDR 后远端可访问。
**前置条件**：走查 B 已完成（A、B 已入网且互通）；一台真实 LAN 网关设备 G（agent 可运行，能配静态路由与防火墙）。

### C.1 选网关并发布路由

```bash
# 1) 把 G 加入同一网络并设为 Active（控制台）
# 2) 控制台 LAN routes 发布：网关 = G，目的网段 = 真实 LAN（如 192.168.1.0/24）
#    返回路径模式先选 dual_route
#    预期：创建成功并记录修订号
# 3) 应用修订（apply）
#    预期：200
```

### C.2 远端可访问（核心验收）

```bash
# 4) 客户端 A 侧确认到 LAN 的路由指向 hub
ip route get <真实 LAN 主机 IP>            # 预期：via <G 的 overlay IP>（或经 hub 转发）
# 5) A → 真实 LAN 主机
ping -c 20 <真实 LAN 主机 IP>              # 预期：0% packet loss   ← 验收点
```

### C.3 返回路径核对（按模式二选一）

- **dual_route**：LAN 主机侧 `ip route show <A 的 overlay IP>` 应指向网关自身的 LAN 地址；从 LAN 主机 `ping <A 的 overlay IP>` 应通（双向）。
- **controlled_snat**：LAN 主机侧 `conntrack -L` 应看到 overlay 源被 SNAT 成网关 LAN 地址（LAN 主机只看到网关地址，这是 §9.5 的已知限制，如实记录，不算失败）。

### C.4 冲突不静默

```bash
# 6) 把目的网段改成与既有路由重叠的 CIDR 再次发布
#    预期：409 并点名对端，且既有路由列表未被覆盖（§8.3）
```

### 清理

```bash
# 删除该 LAN 路由（记一个修订）→ 应用
# 验证：客户端侧 ip route get 不再指向 hub；LAN 主机不可达
```

### 判定

「远端可访问」符合 **且** 返回路径核对记录完整 **且** 冲突返回 409 不覆盖既有路由 → **#47 可勾**。仅部分符合 → 记录差距，条目保持未勾。

---

## 4. 走查 D — Windows 权限不足与清理（TODO #52）

**验收口径**：权限不足提示明确；失败可清理。
**前置条件**：一台 Windows 主机；**两个终端**——一个**非提权**（普通 PowerShell）、一个**提权**（以管理员身份运行）。测试前缀用 `192.0.2.0/24`。

> 说明：CI windows-latest 全程提权，无法自然产生权限拒绝；本走查是本条**唯一**的真实报文来源。

### D.1 确认提权状态

```powershell
# 1) 非提权终端
([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
# 预期：False
```

### D.2 权限拒绝原文取证

```powershell
# 2) 非提权终端：尝试添加路由
netsh interface ipv4 add route prefix=192.0.2.0/24 interface="Loopback Pseudo-Interface 1" store=active
# 预期（canonical 文案）：The requested operation requires elevation.   退出码 1
```

**把实际输出的原文照抄到记录表。** 对照计划层 `classify_netsh_route_failure`：子串 `requires elevation` 命中 → 映射为 `InsufficientPrivileges`，消息应点名操作（`route add`）与接口名，并携带 netsh 原文。

> **若实际文案与 canonical 不同**（如中文系统）：以实际原文为准，并在 `crates/meshlet-network/src/windows_routes.rs` 的匹配表补上该文案 + 单测。这是本条残留缺口的唯一代码动作，不虚构。

### D.3 提权后正常路径

```powershell
# 3) 提权终端：同一命令
netsh interface ipv4 add route prefix=192.0.2.0/24 interface="Loopback Pseudo-Interface 1" store=active
# 预期：Ok.

# 4) 读回
netsh interface ipv4 show route
# 预期：表中可见 192.0.2.0/24（经 route_prefixes_on_interface 解析应落在回环接口上）
```

### D.4 清理与幂等

```powershell
# 5) 删除
netsh interface ipv4 delete route prefix=192.0.2.0/24 interface="Loopback Pseudo-Interface 1" store=active
# 预期：Ok.

# 6) 再删一次（幂等）
netsh interface ipv4 delete route prefix=192.0.2.0/24 interface="Loopback Pseudo-Interface 1" store=active
# 预期（canonical）：Element not found.   退出码非 0
# 对照 route_already_absent：子串 element not found / cannot find → 幂等成功
```

### D.5 回环怪癖对照（已实测，供参考）

- 回环接口上**不要**带 `nexthop=` 参数——netsh 会报 `The parameter is incorrect.`；可用形式是 **on-link 路由**（无 `nexthop=`）。
- 含空格的接口名必须是**单个不带内嵌引号**的词元——netsh 分词器不认 `\"` 转义。

### 清理

```powershell
# 7) 确认前缀已不在路由表
netsh interface ipv4 show route    # 预期：无 192.0.2.0/24
```

### 判定

「权限拒绝原文命中映射表」「删除幂等原文命中」「清理完成」三项全部符合 → **#52 可勾**（另：Windows 接入 `SystemBackend` 属单独决策，不在此走查范围内）。任一不符 → 记录差距，条目保持未勾。

---

## E — Linux 托盘与状态通知（#104 剩余桌面验收）

**仓内已验证（bus 级/纯逻辑证据，不等于真实桌面显示）**

- `zbus@5.19` 的 Notify 参数、SNI 属性、16/24 ARGB32 图标、默认关闭与
  headless/no-bus/no-watcher 降级由 `apps/agent/src/desktop.rs` 单测覆盖。
- `agent` 只在状态变化时请求通知；初始状态只导出 SNI、不发通知。相关
  trigger 测试在 `apps/agent/src/desktop.rs::desktop_trigger`。
- Linux 编译内含 `org.kde.StatusNotifierItem` 导出、watcher 注册、后续
  `PropertiesChanged` 更新；无总线或 watcher 时降级为文件产物，不影响主循环。

**真机桌面仍需以下全部实测后才可勾 #104**

```bash
# 1) 在 agent 配置文件显式开启（默认仍关闭）：
printf '%s\n' '[tray]' 'status_notifier_item = true' 'notifications = true' >> /etc/meshlet/agent.toml

# 2) 会话总线上核对宿主收到注册项
busctl --user call org.kde.StatusNotifierWatcher /StatusNotifierWatcher \
  org.freedesktop.DBus.Properties Get ss \
  org.kde.StatusNotifierWatcher RegisteredStatusNotifierItems
# 预期：数组包含本进程 unique name + /org/meshlet/StatusNotifierItem

# 3) 核对图标与状态文本
busctl --user call <AGENT_UNIQUE_NAME> /org/meshlet/StatusNotifierItem \
  org.freedesktop.DBus.Properties Get ss \
  org.kde.StatusNotifierItem Title
busctl --user call <AGENT_UNIQUE_NAME> /org/meshlet/StatusNotifierItem \
  org.freedesktop.DBus.Properties Get ss \
  org.kde.StatusNotifierItem IconPixmap
# 预期：Title 为 Meshlet；IconPixmap 为 16x16 与 24x24 ARGB32 两条

# 4) 制造状态变化（例如停止/恢复服务端可达性），观察托盘图标轮廓变化
#    并核对收到一条本地通知；重复轮询同一状态不得再弹通知。

# 5) 无 watcher 回归：关闭托盘宿主后重启 agent。
#    预期：agent 正常运行，status.json 继续更新，无 panic、不退避数据面。
```

**判定**：2–5 全部符合才把 #104 的「真实 OS 托盘显示」标为通过；本机
headless 只能给出上述 bus 级/编译期证据，不得把 `status.json` 当作已上托盘。

## 5. 结果回写模板与判定

### 5.1 汇总记录表

| 走查 | 时间 | 主机/环境 | 版本来源 | 结果 | 结论 |
|---|---|---|---|---|---|
| A 空 VPS 部署 | | | `git rev-parse --short HEAD` | 符合 / 部分符合 | |
| B 两客户端互通 | | | `git rev-parse --short HEAD` | 四项：互访 / 重启恢复 / 撤销失效 / IP 不重复 | |
| C 网关发布 LAN | | | `git rev-parse --short HEAD` | 远端可达 / 返回路径 / 冲突不静默 | |
| D Windows 权限与清理 | | `winver` + PowerShell | `git rev-parse --short HEAD` | 权限原文 / 幂等原文 / 清理 | |
| E Linux 托盘与状态通知 | | Linux 桌面 + `busctl` | `git rev-parse --short HEAD` | watcher 注册 / 图标状态 / 变化通知 / 无 watcher 降级 | |

### 5.2 回写纪律

- **未执行的一律不填、不勾**；禁止用「应该可以」「理论上」代替实测。
- 部分符合 → 在对应 TODO 条目写明差距与差距所在步骤，条目保持未勾。
- 全部符合 → 勾选对应 TODO 条目，并把本手册的汇总表作为证据链接附上。
- 走查中发现的代码问题（如 Windows 文案需补匹配）→ 按 [安装指南](./install.md) 的诚实边界格式补注，不静默改验收标准。
