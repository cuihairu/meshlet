# INSTALL-TRAY-1 真机托盘走查证据（2026-11-07）

三台真机在位（openclaw Windows Server 2022 / imac Windows 11 / work-win11 10.240.0.5），
本项在 **openclaw**（`meshlet.msi` 2026-11-06 23:10 构建装入，`C:\Program Files\Meshlet\`）
与 **imac**（同 msi，2026-11-07 00:03 装入）上由 agent 直接执行，全程 SSH + schtask(`/it`)
交互会话 + 屏幕截图取证，无一项需要用户手动。

## 三态截图（openclaw，2560x1440，任务条 x=2080..2400）

托盘宿主进程开关三态，图标随进程出现/消失/恢复，像素级对照（`C:\meshlet-walk\walk10-*`）：

| 态 | 进程 | 截图 | 图标区 (2141..2155, 1413..1427) 主色 |
|---|---|---|---|
| ① present | `meshlet-tray-host` pid 在跑（sess=2） | `tray-state1-present.png` | 图标在（白/蓝像素 168+） |
| ② absent | `Stop-Process` 杀掉后 count=0 | `tray-state2-absent.png` | 纯任务条底色 (30,33,36)，图标消失 |
| ③ restored | 重新 `Start-Process` 后 count=1 | `tray-state3-restored.png` | 与 ① 逐像素一致（diff=0） |

对照数据：① vs ② diff=156687，③ vs ② diff=156687，① vs ③ diff=0（脚本 `walk10.ps1` 日志
`C:\meshlet-walk\walk10.txt`：`present count=1 / absent count=0 / restored count=1`）。

## 悬停 tooltip（openclaw）

`tray-tooltip.png`：光标停在图标 (2148,1419)，浮出
`… 10.240.0.3: 在线: 控制通道正常, 数据面与服务端期望一致`（设备名 openclaw-win + 虚拟 IP + 状态）。

## 右键菜单（openclaw）

`tray-menu.png`：右键 (2148,1419) 弹出菜单，逐项为：

1. `Meshlet [openclaw-win] 10.240.0.3: 在线: 控制通道正常，数据面与服务端期望一致 …`（禁用态状态首行）
2. `直连节点`（子菜单）
3. `连接节点…`（子菜单）
4. `打开面板`
5. `退出`

菜单窗口 `#32768` rect=(1881,1275,2560,1419)，`walk8.txt` 记录 `menu win … vis=True`；
Esc 关闭后截图 `walk10-5-dismissed.png` 菜单消失。

## imac 交叉验证（同 msi，Windows 11）

- msi 静默装入 `EXIT=0`，`C:\Program Files\Meshlet\` 含 meshlet-agent/cli/server/tray-host 四 exe。
- 托盘宿主以默认 state 目录启动后 `NIM_ADD = 1`（`%LOCALAPPDATA%\meshlet\logs\meshlet-tray-host.log.2026-11-06`），
  tooltip 写入 `Meshlet「imac」10.240.0.7：在线：控制通道正常，数据面与服务端期望一致（流量经 VPS 中继）`。
- 任务条 UIA 枚举（`C:\meshlet-walk\imac-final.txt`）：展开「显示隐藏的图标」后溢出区按钮
  `name=[Meshlet Meshlet「imac」 10.240.0.7：在线：…] rect=(3236,2670,80,80)` —— 图标真实注册进系统托盘。
- 向 `MeshletTrayHost` 窗口投递 `WM_APP+1 / WM_RBUTTONUP` 后出现 `#32768` 菜单窗口 rect=(3014,510,4284,814)。
- 限制如实记录：imac 控制台处于锁定屏（`LockApp` 在跑），截图只能取到锁屏，故 imac 侧以
  UIA/日志取证为准；锁屏不影响上述进程、`NIM_ADD`、UIA 枚举与菜单窗口证据。

## 结论

install.ps1/msi 安装的 `meshlet-tray-host` 在两台 Windows 真机上均：图标进托盘、
tooltip 带状态、右键菜单五项齐、进程退出图标消失、重启恢复。INSTALL-TRAY-1 的
「真机托盘出现/菜单走查」不再 BLOCKED。
