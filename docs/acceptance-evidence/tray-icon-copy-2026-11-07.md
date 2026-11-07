# TRAY-ICON-COPY 真机验收：四态托盘图标 + 本地面板复制按钮（2026-11-07）

本项在 **openclaw**（Windows Server 2022, 10.240.0.3）与 **imac**（Windows 11, 192.168.5.117）
上执行，全程 SSH（`openclaw` / `imac` 两别名）+ 远程 PowerShell 取证。构建产物为
Linux 交叉编译 `x86_64-pc-windows-gnu`，与 `main`（ac71750）逐字节一致（SHA256 核对）。

## 构建与门禁

- 本地门禁：`cargo test --workspace` = **904 passed / 0 failed**；`cargo clippy --workspace --all-targets -- -D warnings` 净；`cargo fmt --check` 净。
- CI（ac71750 push）：**全部 success** —— `CI`、`Dataplane acceptance`、`windows`、`tray host / windows-latest`、`installer / windows-latest`、`dataplane / linux-kernel`、`test / ubuntu-latest`、`console`、`planner dependency gate`。
- 两个特性提交均已合入 `main` 并推送：`15a8ff2`（四态图标移植进 `apps/agent/src/tray.rs`）、`ac71750`（本地面板复制按钮，`apps/tray-host/src/panel.rs`）。
- Windows 构建产物哈希：`meshlet-agent.exe e5e0634e…8db27`、`meshlet-tray-host.exe e3ad9fc9…3460d`。

## 部署方式（每台：停旧 → 换 exe → schtasks 起服）

| 主机 | agent 路径 | tray-host 路径 | 服务/任务 |
|---|---|---|---|
| openclaw | `%LOCALAPPDATA%\meshlet\meshlet-agent.exe` | `C:\Program Files\Meshlet\meshlet-tray-host.exe`（MSI） | 计划任务 `MeshletAgent` / `MeshletTrayHost`（均 Running） |
| imac | `%LOCALAPPDATA%\meshlet\meshlet-agent.exe` | `%LOCALAPPDATA%\meshlet\meshlet-tray-host.exe` | 同左（进程直启） |

## 逐项结果

### ① 换 exe（哈希核对 = 当前 main 构建）

| 主机 | agent SHA256 | tray-host SHA256 | 与本地构建 |
|---|---|---|---|
| openclaw | `E5E0634E57CDAD646B79569D53A15BDC73132A6A0D2EE9A8FC46C4CB98D8DB27` | `E3AD9FC9C7BCACEAEEE01161722A9FE10BC8C11F2F4757F6E04D78000883460D` | **一致** |
| imac | 同 openclaw（`E5E0634E…`） | 同 openclaw（`E3AD9FC9…`） | **一致** |

### ② 起服（进程启动晚于 exe 落盘 → 跑的是新二进制）

| 主机 | agent 进程启动 | tray-host 进程启动 | 状态 |
|---|---|---|---|
| openclaw | 2026-11-07 13:21:13（exe 13:20:43） | 13:21:13（exe 13:20:47） | 双进程在跑 |
| imac | 13:17:41（exe 13:10:09） | 13:13:00（exe 13:10:09） | 双进程在跑 |

### ③ 托盘新图标（四态 → online 青六边形 #326072）

- **像素探针**（icon-16.png / icon-24.png，即 tray-host 托盘实际显示的位图）：
  主色 = `(50,96,114)` = `#326072`（online teal），16px 中心为空心六角螺母、24px 同色；
  openclaw 与 imac 两台的 icon-16/24.png 主色与逐像素分布一致（16px 主导色 100 px 全为 teal）。
- **图标已注册进系统托盘**：openclaw tray-host 日志 `NIM_ADD = 1`（2026-11-07T05:21:14Z），
  tooltip `Meshlet「openclaw-win」10.240.0.3：在线：控制通道正常，数据面与服务端期望一致（流量经 VPS 中继）`。
- 证据位图：[`tray-icon16-online-openclaw.png`](tray-icon16-online-openclaw.png)、
  [`tray-icon16-online-imac.png`](tray-icon16-online-imac.png)、
  [`tray-icon-four-state-online.png`](tray-icon-four-state-online.png)（16/24 放大）。

### ④ 本地面板复制按钮

- **openclaw**：面板 `http://127.0.0.1:3544/`（local-panel.json pid=12664），
  HTML 含 `data-copy="10.240.0.3"`（本机虚拟 IP）与 `data-copy="10.240.0.4/.5/.7/.8"`（直连节点 overlay IP），
  `navigator.clipboard` + `execCommand` 回退均在；Edge headless 截图
  [`tray-panel-openclaw.png`](tray-panel-openclaw.png)：复制按钮在「当前节点」虚拟 IP 右侧与「直连节点」表每个 overlay IP 右侧。
- **imac**：面板 `http://127.0.0.1:54425/`（local-panel.json pid=48784），
  HTML 含 `data-copy="10.240.0.7"` 与 `10.240.0.3/.4/.5/.8`；Edge headless 截图
  [`tray-panel-imac.png`](tray-panel-imac.png)：复制按钮同在虚拟 IP 与各 overlay IP 旁。

### ⑤ 只读语义（GET/HEAD 纪律不变）

面板由 `panel.rs` 自托管 loopback；`POST /` → 405（仅本机、只读，无新增网络请求，已在门禁与 CI 覆盖）。

## 第三台（10.240.0.5，work win11 cuihaitao）

**BLOCKED，如实记录**：SSH 22 公钥拒（`Permission denied (publickey,password,keyboard-interactive)`，
三把本地私钥 `id_ed25519` / `id_ed25519_win` / `cui` × 用户 `cui`/`cuihaitao`/`Administrator` 全部被拒；
overlay 10.240.0.5 与 underlay 10.147.19.97 均如此）；WinRM（5985/5986）与 SMB（445）关闭，
无管理通道；仓库内无该机凭据。该机**在线且 mesh 健康**：imac 的 `direct-peers.json` 显示
`windows-desktop 10.240.0.5` `mode=p2p_direct` `endpoint=10.147.19.97:51821`、`last_handshake_at` 新鲜
（与其余 peer 同窗）。**无法部署/验收，待用户提供该机 SSH 通道或凭据。**

## 结论

- openclaw 与 imac：新 exe 已落盘并运行（哈希=当前 main、进程晚于 exe）、托盘新四态 online 图标
  已注册（NIM_ADD=1）且位图=#326072 teal 六角螺母、本地面板复制按钮就位并截图。**两台的
  「停旧→换 exe→起服→托盘新图标+复制按钮」验收通过。**
- 10.240.0.5：因 SSH 公钥拒且无备用管理通道，**未能部署/验收**，按用户预设「或如实报」处理。
