# 三机稳定观察快照（2026-11-14，巡检单 meshlet.md 任务 5）

24-48h 稳定观察（todo「稳定持续跑」/ R-07 soak 前置）首轮数据采集。**本轮只采集，未做任何重启/升级/改配置**。采集时刻：2026-11-14（c4e5038 双机部署完成后数小时）。

## 三机状态

| 机器 | device_id | 对端公钥前缀 | agent 进程 | 构建 | 切换事件 | 24h promote/demote |
|---|---|---|---|---|---|---|
| coding-vm（本机） | dev-reg-4 | b6txQ61F… | PID 2656680 活 | 本地 dev 构建 `f78490bc89c3396d`（2026-11-13 19:04，**早于 4174773/c4e5038 两修复**） | 无文件 = 零切换事件 | journal 296 行；00:30 后窗口 76 行 / 38 demoted |
| imac（windows-desktop） | dev-reg-5 | JMrE4SZy… | PID 10932 活 | nightly c4e5038（双位 exe 同哈希 `9B4199D11BCF9AE9`） | 3 行（648 字节）恒定不变 = **修复后零新切换** | —— |
| openclaw（openclaw-win） | dev-reg-9 | FSaf/1S9… | PID 2808 活 | nightly c4e5038（双位 exe 同哈希 `9B4199D11BCF9AE9`） | 1 行（详见下） | —— |

版本字段说明：三机 `--version` 均报 `0.1.0`（版本串未随 nightly 滚动，上游遗留），**构建身份以 exe 哈希/构建时间 + PID 为准**。

## 服务端 presence 事件（dev VPS）

- `journalctl -u meshlet-server` 近 24h 含 presence 行：**4**；
- 2026-11-14 00:30 以来：**0**。

## 读数解读（如实，不冒充干净）

- **切换闸修复字段面上成立**：全量切换事件清点后，**已知 4 起全部早于 c4e5038 部署（00:2x 11-14），修复后零新增**——imac 文件 3 行（648 字节，22:34/22:35/22:40）全程恒定（c4e5038 部署后 ~20min 三轮采样同证，见 `docs/acceptance-evidence/sel-002-realdeath-rerun-2026-11-13.md`）；openclaw 文件 1 行（本轮首读）：`at_ms 1794582719600` ≈ 11-13 23:11:59（部署前 ~1h10m，按测量勘误基线折算），reason `score 76.5 beats current inf` = ∞ 评分签名（旧构建行为），路径 `10.147.19.17:51820 → 10.147.19.226:51820`。
- **新缺口线索（如实记录）**：openclaw 该事件的 peer 公钥前缀 `QmAFaSKb…` 不在已知四钥（b6tx/JMrE/FSaf/vLkJ）之列，且端点涉及匿名成员 `.17`——与首轮验收遗留的「匿名 ZT 成员 10.147.19.17 身份待对账」同族，已并入上游对账项。
- **残余振荡仍在**：coding-vm journal 00:30 后仍 38 次 demote，promote 端点所见 `10.147.19.97/.49` = 两台 Windows 被旧构建踢上去的 ZT 面——与 stranded 残余一致（会话回不到 192.168.5.x roaming 面），上游决策项（见 `docs/analysis/stability-proposal-2026-11-13.md` 方案 1/7）。
- **coding-vm agent 落后于双修复**（本地 dev 构建 19:04 < 4174773）：属 dev 机常态（不走 nightly），其零切换事件与 b6tx 恒直连一致；升级随日常开发流程，本轮按纪律不动。
- openclaw sshd flap 仍在（本轮两次计数连接被断），根因未定位，挂待查——采集本身即其活体证据。
