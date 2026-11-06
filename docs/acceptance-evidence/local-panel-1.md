# LOCAL-PANEL 真机验收：本地面板（imac，2026-11-07）

**状态：待用户亲验** — 自动化已覆盖「装包 → 面板服务 → 200 + 三块 → 页面截图 →
CI 菜单/面板门禁」，但「人在交互式会话里右键托盘 → 点『本地面板』」这一步留给用户
（见文末「未覆盖」）。对应 `todo.md` 条目：`LOCAL-PANEL-1`（实现+门禁）、
`LOCAL-PANEL-2`（真机手点）。

## 环境与产物

| 项 | 值 |
|---|---|
| 机器 | imac（`ssh imac` → 192.168.5.117，用户 `cui`，cmd 默认 shell） |
| 安装位置 | `C:\Users\cui\AppData\Local\meshlet\meshlet-tray-host.exe`（1,651,445 B，覆盖安装，安装前该机无 tray-host 进程） |
| 构建 | 本仓 `cargo build --release --target x86_64-pc-windows-gnu -p meshlet-tray-host`（Linux 交叉构建）后 `scp` 覆盖 |
| 数据源（该机真实文件） | `state\tray\status.json`（`Meshlet online` / `imac` / 10.240.0.7）、`state\applied.json`（rev31、`routes: []`、无 `local_public_key`）、`agent.toml`（`device_name = "imac"`、`server_url = http://106.14.216.177:8080`） |
| 会话 | `qwinsta`：`console  cui  20  断开`（console 会话断开态）→ 无人可代点的桌面 |

## 实测步骤与结果

单条 PowerShell 脚本：起 `meshlet-tray-host.exe "<state>"` → 读
`state\local-panel.json` → `curl.exe -i` → Edge headless 截图 → `POST` 探针 → 结束进程。

| 步骤 | 结果 |
|---|---|
| 面板启动（URL 交接文件） | `local-panel.json` = `{"url":"http://127.0.0.1:55058/","pid":45620}`（原子写入，进程存活期间可读） |
| `curl -i` | `HTTP/1.1 200 OK` |
| 三块齐全 | `id="node"` ✓ · `id="direct"` ✓ · `id="routes"` ✓ |
| ① 当前节点 | 设备名 `imac` · 虚拟 IP `10.240.0.7` · 状态灯 `在线（Meshlet online）` · hub/控制通道 `已连接（控制通道正常）` · 版本 `面板 meshlet-tray-host 0.1.0`（该机 agent 为旧版，未上报 `version`/`env` → 面板如实显示「未知/回落本进程环境」）· 控制台 `http://106.14.216.177:8080` · 账本时间 `2026-11-05T08:24:17Z` |
| ② 直连节点 | 该机 agent 未发布 `direct-peers.json` → 「直连节点数据不可用」（数据不可用 ≠ 没有节点） |
| ③ 本地路由 | 计划已应用但 `routes: []` → 「（计划未下发任何路由项）」+ 说明「计划修订 rev31 · 账本 applied.json · 应用于 2026-11-05T08:24:17Z」——**不是**「agent 尚未应用任何计划」（旧文案在真机数据上说过谎，本轮已修并加测试） |
| 只读语义 | `POST /` → `HTTP/1.1 405 Method Not Allowed` |
| 页面截图 | Edge headless → `local-panel.png`（75,855 B，1400×1900）：三块齐全、深色主题、无重叠/截断 |

同目录证据：[`local-panel.html`](local-panel.html)（页面原文，curl 原始字节）、
[`local-panel.png`](local-panel.png)（截图）。

## 本机（Linux）同批实测

`examples/local_panel` + mock 数据源：`HTTP/1.1 200 OK`、三块 section id 全中、
12/12 内容探针（设备名 / 状态 / overlay IP / 三种链路模式 / 路由三列 / EnvProbe 行）、
`POST`·`PUT` → 405、`GET /nope` → 404、`HEAD` → 200、改 `direct-peers.json` 后下一次
GET 即刷新（文件变更即刷新）。

## 自动化菜单与门禁证据

- **真实 Win32 菜单断言**（GitHub `windows-latest`，`cargo test -p meshlet-tray-host`）：
  `build_menu_contains_status_direct_dial_local_panel_console_and_quit` —— 菜单共 10 项，
  第 6 项 `本地面板`、第 7 项 `控制台(网页)`、第 9 项 `退出`。
- **面板门禁**（同作业新增）：从 `local-panel.json` 取 URL（有界重试直到解析出 loopback
  URL）→ 响应按**原始字节**校验：状态行完整匹配 `200`、`Content-Length` 与正文字节数
  一致、正文以 `</html>` 结尾、三块 section id 都在正文里（截断的 early-EOF 响应不再
  能假绿）；curl 用 `-sS --noproxy '*'` 且 stderr 落盘，失败时裸 TCP fallback 直连同一
  端口再验一遍；`POST` 必须 405 + 完整性校验。随后在 CI 桌面会话打开该页并截
  `tray-panel.png`，连同 `tray-panel.html`（正文原始字节，无 BOM）作为
  `tray-windows-evidence` 工件。
- **tray-host 跨步被回收的自愈**（run `42261037474`/`42267986109` 两轮红的真根因）：
  tray-host 在 launch 步与门禁步之间会被 CI 会话静默回收（stderr 日志无 panic、进程
  消失、连接拒绝被旧门禁 `-s` 吞成空串）。门禁步检测进程死则就地重拉：先删旧
  `local-panel.json`（删除失败即红），`Start-Process -PassThru` 拿新进程 PID，有界等待
  新交接文件且**pid 必须等于刚拉起的进程**——pid 复用/旧文件残留都不可能假绿。
- 门禁运行：CI run `42272101696`（push `27418e3`）**全绿**（8/8 作业）。真机日志实测
  自愈路径生效：`tray-host alive: False` → 重拉 → `relaunched tray-host:
  http://127.0.0.1:57452/ (pid 664)` → `GET via curl: HTTP/1.1 200 OK` + 三块齐全 +
  `POST via curl: 405`。
- 本机（Linux，pwsh 7.4.6）对**同一段门禁脚本逐字提取**做过行为级验证：截断响应
  fixture（真响应切尾 200 字节，`Content-Length 3623` 实发 `3423`）→ exit 1 带
  early-EOF 诊断；curl 不可用 → TCP fallback 全绿；重拉缺 pid 的交接文件 → exit 1。

## 未覆盖 / 待用户亲验

1. **托盘菜单手点**：imac 的 console 会话是「断开」态，SSH 落在 session 0，没有可代人
   操作的桌面。请在登录该机后右键托盘图标 → 点「本地面板」，确认浏览器打开的就是本页
   （三块信息齐全），再点「控制台(网页)」确认打开的是 `server_url` 控制台。
   **这一步确认后 `LOCAL-PANEL-2` 才能勾。**
2. **openclaw（次选机）**：已确认 `meshlet-tray-host.exe` 运行在交互会话
   `SessionId=2`（`Get-Process` 读数），并取到该机桌面截图；但该机桌面正被使用
   （多个应用窗口在前台），**未在其上执行菜单点击**，避免干扰用户正在使用的工作台。
3. agent 升级后 `status.json` 才会带 `version`/`env`；升级路径由单测
   `status_upgrade_backfills_version_and_env_without_rewriting_every_tick` 覆盖。

## 复现

```bash
# 交叉构建并部署
cargo build --release --target x86_64-pc-windows-gnu -p meshlet-tray-host
scp target/x86_64-pc-windows-gnu/release/meshlet-tray-host.exe \
    "imac:C:/Users/cui/AppData/Local/meshlet/meshlet-tray-host.exe"
# imac 上（PowerShell 单脚本）：起面板 → 读 state\local-panel.json → curl -i →
# Edge --headless --screenshot → curl -X POST 看 405 → 结束进程
```
