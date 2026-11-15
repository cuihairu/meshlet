# 翻转循环复现调查（bc2d356 部署后）— 2026-11-14 17:2x–18:4x

巡检单 meshlet-fliploop-nov14。bc2d356（promote 偏好健康面）15:19 部署后，imac 的
agent-decisions.jsonl 在 08:40–09:39Z 复现 JMrE（windows-desktop）/FSaf（openclaw-win）
promote↔demote 循环（~1–5min/轮）。本文回答巡检单三疑点；**结论=疑点 2（WG roaming
锚定），非面错位实现缺陷，demote 属实**。本轮不改代码。

## 疑点 1：demote 的 probe_window 锚在哪个 endpoint？（代码级答案）

**锚在内核实况刷新后的现役面上，不是候选表任一面。**引用链：

1. `apps/agent/src/agent/direct.rs:132-139`——`current_paths` 只从 ledger
   `link_statuses()`（`link_state=="direct"`）的 **endpoint 字段**构造，
   `degraded = probe.degraded_map(&current_paths)`（`:139`）。
2. `apps/agent/src/probe.rs:134-149`——`degraded_map` 只迭代传入的 current map
   （4174773「现役 endpoint 窗口口径」），其余候选窗口与 demote 无关。
3. `apps/agent/src/agent/direct.rs:277-296`——`enrich_direct_peers` 每周期从
   `net.wg`（内核 wg dump 实况）读每对端 endpoint，`:296` `record_endpoint` 把
   ledger endpoint 刷成**内核实况**（880b49a 语义：含漫游出的表外面）。
4. `apps/agent/src/direct.rs:530-535`——SEL-003 demote 闸 `degraded.get(&key)`，
   该 key 的劣化值只来自第 1-2 步的现役面窗口。

即 4174773（现役面口径）与 c4e5038（现路径无窗口不切换）**已覆盖 demote 闸**，无
「切换闸修了、demote 闸漏了」的缺口。日志逐条核对：**全部 26 条 demote 记录的
endpoint 与其 probe_window 引用面一一相同**（.97 窗口配 .97 demote、.49 窗口配
.49 demote），无一处窗口面 ≠ demote 面。

## 疑点 2：promote 面 ≠ demote 面的真相 = WG roaming

时序小表（JMrE 主环，imac 视角；「漂移」= demote 时现役面已非 promote 下发面）：

| promote（面） | verified（握手年龄） | demote（面） | verified→demote | 备注 |
|---|---|---|---|---|
| 08:40:53 .97 (memory) | 08:43:21 .97 | 08:44:04 .97 | 43s | 同面环 |
| 08:46:19 **180.152.54.66** (table) | 08:47:03 180.x (28s) | 08:52:18 **.97** | 5m15s | 漂移 |
| 08:54:31 .97 (memory) | 08:55:17 .97 | 08:56:01 .97 | 44s | 同面环 |
| 08:58:14 .97 (memory) | 08:59:01 .97 | 09:00:33 .97 | 92s | 同面环 |
| 09:02:45 **180.x** (table) | 09:03:28 180.x (36s) | 09:04:12 **.97** | 44s | 漂移 |
| 09:06:27 **180.x** | 09:07:13 180.x (27s) | 09:07:59 **.97** | 46s | 漂移 |
| 09:10:13 .97 (memory) | 09:10:57 .97 | 09:11:41 .97 | 44s | 同面环 |
| 09:13:53 **180.x** | 09:14:37 180.x (14s) | 09:15:21 **.97** | 44s | 漂移 |
| 09:17:32 **180.x** | 09:18:17 180.x (27s) | 09:19:04 **.97** | 47s | 漂移 |
| 09:21:18 **180.x** | 09:22:02 180.x (35s) | 09:22:47 **.97** | 45s | loss=95% 窗 |
| 09:25:01 **180.x** | 09:25:45 180.x (10s) | 09:31:16 **.97** | 5m31s | 漂移 |
| 09:33:34 .97 (memory) | 09:35:07 .97 | 09:35:53 .97 | 46s | 同面环 |
| 09:38:11 .97 (memory) | 09:38:56 .97 | （取样止） | — | 环未停 |

FSaf 同型（imac 视角）：08:45:31 promote .49→08:46:19 verified→09:01:17 demote .49
（同面）；09:03:28 promote **180.153.160.8**→09:04:12 verified 180.x→09:25:01 demote
**.49**（21min 漂移）→09:27:15 promote 180.153.160.8→09:28:47 verified→09:32:50
demote .49（handshake stale 243s）→09:35:07 promote .49（memory）→09:35:53 verified。

**机制**：promote 下发 `wg set 180.x` 后，对端（wd）的 wg keepalive/握手从其 ZT 源
`10.147.19.97:51821` 到达 imac 内核——WireGuard 收到合法认证包即漫游现役 endpoint。
每周期 wg dump 把 ledger endpoint 刷成 .97（`agent/direct.rs:296`），ZT underlay 正处
劣化窗（窗口 med 8-19ms 但 L 突发，loss 25-95%），is_degraded 命中 → demote **锚
现役面 .97，属实**。两处佐证：

- 漂移间隔 44-47s ≈ 1-2 个 reconcile 周期（30s/周期）——漫游在下发后第一个周期内
  即完成，「verified @180.x」的握手证据是内核该 peer 的 last_handshake（**不区分
  面**），验证时会话可能已在 .97 上。
- 同面环（.97 memory promote）与漂移环交替：demote 清 Direct 态不清记忆面（面还
  在的语义），记忆面=内核实况面 .97，故 re-promote 回 .97。

**defer（bc2d356）为何挡不住**：defer 只挡「晋升时刻正处劣化集」的面；ZT 劣化是
**突发间隙型**（窗口 loss 25-95% 但每 8 拍里有 8-19ms 健康段），恢复门 3 连健康轮
在间隙内可通过，间隙够长（30-60s）时 pending 验证也过。defer 对「滑窗口径下的
间隙恢复」无免疫——这是设计边界，不是接线缺陷（07fda5f 的过滤集语义即如此）。

## 疑点 3：劣化窗现状

循环至取样末（09:38:56Z verified）仍在续，**劣化窗未收**，「恢复后未复现」口径
本轮不成立。coding-vm 直 ping .97/.166 100% 丢（Windows ZT ICMP 拦截+underlay 劣化
混合，不能单独定论；imac→.97 的 SEL-001 窗口 L 突发才是路径实证）。.49 本轮
0% 丢但 09:25/09:32Z 仍见 .49 面 demote——窗口历史与瞬时 ping 不同源，不冒充。

## 修复方向三选一（等用户拍板，本轮不动代码）

- **① 服务端候选表纳管 roaming/记忆面**（原 promote 三选一之①）：对端互见 ZT 面
  为正式候选，决策层与内核实况一致锚定，消除「表外面被内核漫游接管」错位。服务端
  协议改动。
- **② 客户端「下发面锚定」**：promote 后检测内核 endpoint ≠ 下发面即重下发拉回
  （或漂移视同该面失败清 pending 重选）；记忆面改记「下发面」而非「实况面」。纯
  客户端，但与对端 agent 的 endpoint 设置有拉锯风险（对端侧 wd 不动则反复互拽）。
- **③ demote 后冷却 backoff**：demote 后该 peer N 分钟不 re-promote，~5min 环压成
  低频事件。纯客户端最小改动，不解决锚定，直连恢复延迟一个冷却期。

## raw 清单

- `fliploop-imac-decisions-0840-0935-2026-11-14.txt`（08:40–09:35Z 全段 81 条）
- `fliploop-imac-decisions-after-0935-2026-11-14.txt`（09:35Z 后至取样末）
- switch-events 同窗 tail 已录入本文（imac direct-switch-events.json，与 decisions
  一一对应，kind=mode_flip）

## 21:3x 检查点（巡检单 meshlet-nov14-2139，2026-11-14 21:39–21:44 CST）

三机采样（imac/openclaw 直连 ZT 采到，未走隧道备路；coding-vm 本机台账）：

- **JMrE（windows-desktop）环仍在续**（fliploop 自 08:40Z 起已 5h+）：imac
  13:40:59Z demote `.97` → 13:43:14Z promote `180.152.54.66`；openclaw 同拍
  13:42:00Z + 13:43:06Z 连续 promote `180.152.54.66`（pending 尝试）。
- **FSaf（openclaw-win）在 imac 视角仍在续**：13:40:12Z demote `.49` →
  13:42:31Z promote `.49` → 13:43:14Z probe（waiting handshake）。
- **新况：openclaw-win 本体已漫游回家**——coding-vm 视角 openclaw-win
  `p2p_direct @ 192.168.5.11:51820`（rtt=1，hs 13:42:45Z 新鲜；NAT 后的真 L2 面）
  **稳定直连零翻转**——03:xx 纪要预言的「对端漫游回家解锁收益」几何条件已现。
  但 **imac↔openclaw kernel 会话仍锚 ZT `.49`**（hs 13:43:47Z 新鲜）：openclaw
  回家未自动传导到 imac 侧决策——imac 的记忆面/服务端候选表均无
  192.168.5.11 面，**候选表纳管 roaming 面缺口（三选一之①）在此实锤再现**。
- coding-vm↔imac 稳 `p2p_direct @ 192.168.5.117`（rtt≤1）；imac↔coding-vm 稳
  `.188`——LAN 面对零翻转照旧。
- 本机 agent 仍 2de57b1（无 agent-decisions.jsonl，台账口径）；无隧道残留。

## 04:0x 检查点（巡检单 meshlet-fliploop-checkpoint-1115，2026-11-14 20:00Z 取证）

取证时刻 **2026-11-15 04:00:37 CST（2026-11-14 20:00:37Z）**（取证时 agent-decisions.jsonl
最后事件 20:00:36Z）。
窗口 = 起点 07:19Z（15:19 CST）至取证时刻，**12.69 h**；距 24h 门槛**还差 11.31 h**，
未达标、不外推。

数据面：`%LOCALAPPDATA%\meshlet\state\agent-decisions.jsonl`（539,530 B，1,525 事件；
窗口内 1,023 事件）、`direct-switch-events.json`（265,797 B，871 事件）、`direct-peers.json`
（714 B）。窗口内事件按 peer/动作：

| peer | 窗口内 | promote | demote | hold_relay | probe | defer |
|---|---|---|---|---|---|---|
| windows-desktop（JMrE） | 812 | 311 | 158 | 307 | 35 | 1 |
| openclaw-win（FSaf） | 211 | 76 | 37 | 75 | 23 | 0 |

### JMrE（windows-desktop）：环仍在续，节奏中位 0.78 min

窗口内 165 个「promote→紧接 demote」周期，间隔中位 **0.78 min**，最短 0.7 min——仍是
分钟级翻转，未收口。窗口末端（取样止）：19:56:55Z / 19:57:39Z 两次 promote `.97:51821`
→ 19:58:23Z demote `.97`（sel003）→ 19:59:07Z、19:59:52Z hold_relay → **20:00:36Z
promote `180.152.54.66:51821`**（candidate table, probe Unhealthy），末拍即新环起点。
签名分布：`.97:51821` 331 条 / `180.152.54.66:51821` 174 条，ZT 面与公网面互拽照旧。
demote 主因 `sel003 degraded: probe window`（`.97` 154 条 / `.49` 32 条）。

**本轮不重复 19:11Z / 21:39Z 已记的结论**（sel003 瞬态回收、hold_relay 恢复门未过、
漂移环交替），只记新证据。

### FSaf（openclaw-win）：17:23Z 起静默，锚定 LAN 面

窗口内前段仍翻（37 次 demote / 76 次 promote），但**最后一条事件是 17:22:59Z**
（promote `192.168.5.11:51820`，pending verified: fresh handshake, probe Healthy），
此后 **2h37m 零事件**（`ts >= 17:23Z` 计 0 条）。窗口内 3 条 `192.168.5.11:51820`
事件是本检查点**新签名**：openclaw-win 漫游回家后的真 L2 NAT 面被 imac 侧记忆面
（`promote attempt via memory face (last_direct)`）接住并验证通过。`direct-peers.json`
实况亦印证——`openclaw-win` `mode=p2p_direct @ 192.168.5.11:51820`、`rtt_source=
handshake_fresh`。21:39Z 检查点记的「openclaw 回家未自动传导到 imac 侧决策」缺口，
在本检查点由 `880b49a` 的记忆面 re-promote 机制消化（非候选表纳管，见下）。

### 切换事件面：窗口内 582 条全为 mode_flip，零 endpoint_roam

窗口内 582 条切换事件 **100% `kind=mode_flip`**（`hub_relay` ↔ `direct_pending`），
**0 条 endpoint 漫游事件**；全文件 4 条 endpoint_roam 的最末一条早于本窗口
（`10.147.19.130:51820 → 192.168.5.188:51820`）。即「切换闸零新触发」口径成立——
agent 在窗口内只翻模式，没有再对 `wg set endpoint` 做漫游。

### 新签名汇总

- `192.168.5.11:51820`（FSaf 的 LAN 面）3 条——窗口内新增，见上节。
- `180.153.160.8:51820` 27 条（公网面，JMrE/FSaf 共用候选）。
- 无新 reason 文本；`defer` 仅 1 条（`promote deferred: candidate face degraded`，
  `.97:51821`）。

### 结论与边界

- **fliploop 仍在续**：JMrE 每分钟级一翻，至取样末未收；FSaf 是本检查点起转静的一侧
  （17:23Z 起 2h37m 无事件，锚 LAN 面）。
- **未宣称修复**：三选一修复方向（候选表纳管 roaming 面 / 下发面锚定 / demote backoff）
  仍待用户拍板，本轮不动代码、不改状态机、不碰 `crates/`。
- **窗口未满**：12.69 h / 24 h，差 11.31 h；不得外推为「已达标」。
- openclaw 侧数据留空：其 ZT 面 No route to host，按巡检单禁重试 SSH。

### raw 清单（本轮新增）

- `fliploop-imac-decisions-window-2026-11-14.txt`（窗口 07:19Z–20:00Z 全段 1,023 条，
  自 `agent-decisions.jsonl` 按 ts 切出）
- switch-events 同窗统计已录入本节（imac `direct-switch-events.json`，
  窗口内 582 条全 mode_flip，与 decisions 一一对应）

## 04:4x 检查点（巡检单 meshlet-fliploop-checkpoint-0848，2026-11-14 20:48Z 取证）

**取证时刻口径校正（重要）**：本单标题写「08:48 CST」、正文写「约 20:48Z、窗口应达
~29.5h」、背景写「距 24h 门槛还差约 6.5h」，三者互斥——20:48Z 对应 **04:48 CST**，
13.49h 才过。三个数都不自洽，**以本机 UTC 时钟实测为准**：取证时刻
**2026-11-14 20:48:10Z（04:48 CST）**，日志最后事件 20:49:17Z。窗口 =
07:19Z → 20:48Z = **13.49 h**，距 24h 门槛**还差 10.51 h**。按实测数记录，
不采纳单据的 29.5h / 6.5h 口径，不外推。

数据面：`agent-decisions.jsonl`（559,745 B / 1,583 事件，末事件 20:49:17Z）、
`direct-switch-events.json`（905 事件）、`direct-peers.json`（实况见下）。

### JMrE（windows-desktop）：环仍在续，节奏略慢

窗口增量 20:00:37Z→20:49Z（48min）**57 事件**，全部属 windows-desktop：
promote 22 / hold_relay 20 / demote 11 / probe 4；endpoint `.97:51821` 25 条、
`180.152.54.66:51821` 13 条，两面互拽照旧。

窗口累计（07:19Z→20:49:17Z，1,081 事件）：windows-desktop **870** 条（promote 333 /
hold_relay 327 / demote 170 / probe 39 / defer 1），openclaw-win 211 条（见下节）。

**周期节奏（同一 peer 内相邻 promote→demote 配对，146 个周期，中位 0.78min）**：

| 时段 | 周期数 | 中位 | 最短 | 最长 |
|---|---|---|---|---|
| 07–11Z | 44 | 0.78 min | 0.72 | 10.63 |
| 11–15Z | 50 | 0.78 min | 0.72 | 8.25 |
| 15–19Z | 46 | 0.87 min | 0.72 | 6.73 |
| 19–20Z | 24 | 1.48 min | 0.72 | 2.28 |

计数口径 = 至日志末事件 20:49:17Z（取证时已落盘的最新一条，较取证时刻
20:48:10Z 晚 67 秒，如实标注）；raw 文件与之一致，1,081 行。

节奏**未收口、末段略慢**（0.78→1.48min）但仍在分钟级翻转，不构成「已缓解」。
窗口末：20:47:02Z promote `180.152.54.66:51821`（candidate table）→ 20:47:46Z
pending verified（probe Healthy）→ **20:49:17Z demote `.97:51821`（sel003 degraded）**。
取证时刻 `direct-peers.json` 实况：windows-desktop `mode=hub_relay`、endpoint 空——
即末拍降级后正落在中继态。

### FSaf（openclaw-win）：静默延续，2h37m → 3.42h

末事件仍为 17:22:59Z（promote `192.168.5.11:51820` verified），此后 **3.42 h 零事件**。
窗口内 FSaf 计数与 04:0x 检查点完全一致（211 条：promote 76 / hold_relay 75 /
demote 37 / probe 23），**无新增**。`direct-peers.json` 实况 `p2p_direct @
192.168.5.11:51820`、`rtt_source=handshake_fresh`——锚 LAN 面照旧，静默稳定。
openclaw 侧数据留空：ZT 面 No route to host，按巡检单禁重试 SSH。

### 切换闸口径复核：零 endpoint_roam 延续

增量 33 条切换事件**全为 `mode_flip`**，**0 条 `endpoint_roam`**；全文件
905 条 = 901 mode_flip + 4 endpoint_roam，最末 roam 仍早于观察窗
（`10.147.19.130:51820 → 192.168.5.188:51820`）。

### 无新签名

增量 8 种 reason 文本**全在 20:00Z 前已出现的 10 种之内，零新增**。
`defer` 仍仅 1 条（窗口早期）。无新 endpoint 面。

### 24h 门槛判定（本检查点）

**未过 24h 门槛（13.49h / 24h，差 10.51h），无法按门槛口径判定，如实记录如下：**

- 「稳定持续跑」前置数据的要求是观察 24–48h 断线事件。本窗口内 imac 侧
  JMrE **持续翻转未收口**（146 个 promote→demote 周期），**不满足**「前置数据
  记录要求」——它记录的是未稳定，不是稳定。
- 如实列不达标项：①窗口未满（差 10.51h）；②JMrE fliploop 未消；③FSaf 侧虽静默
  但属「锚 LAN 面后停止动作」，非跨 NAT 广域打洞已验。
- **R-07 soak 本体（≥7 天）维持 BLOCKED 不动**；本判定仅为 soak 前置数据记录，
  不构成 soak 通过。
- 三选一修复方向仍待用户拍板；本轮未动 `crates/`、未改状态机、未 bump 版本。

### raw 清单（本轮新增）

- `fliploop-imac-decisions-window2-2026-11-14.txt`（窗口 07:19Z–20:49Z 全段 1,081 条，
  自 `agent-decisions.jsonl` 按 ts 切出）
- switch-events 同窗统计已录入本节（增量 33 条全 mode_flip，与 decisions 对应）

## 06:1x CST 检查点（巡检单 meshlet-fliploop-checkpoint-1219，2026-11-14 22:23Z 取证）

**取证时刻口径（双时区）**：本单标题写「12:19 CST / 04:19Z、窗口应达 ~21h」，但实际
执行时本机时钟为 **2026-11-15 06:23 CST = 2026-11-14 22:23Z**（imac 侧
22:24:04Z 互证），比单据标注晚约 2h——窗口实测 **15.08h** 而非 21h。按单据硬要求
「小时数以本机 date -u 实测计算」，一律以实测为准：取证时刻 **22:23:29Z（06:23 CST）**，
日志末事件 22:23:08Z。窗口 = 07:19Z → 22:23Z = **15.08h**，距 24h 门槛（2026-11-15
15:19 CST / 07:19Z）**还差 8.92h**。**本轮不做达标判定**（单据明确排除，判定留给
15:19 CST 之后的巡检）。

数据面：`agent-decisions.jsonl`（591,085 B / 1,670 事件，末事件 22:23:08Z）、
`direct-switch-events.json`（955 事件）、`direct-peers.json`（实况见下）。

### 增量（20:49:17Z→22:24Z，95min）：88 事件，全属 windows-desktop

promote 34 / hold_relay 34 / demote 17 / probe 3。末 6 拍：22:18:41Z promote `.97:51821`
verified → 22:20:14Z demote `.97`（sel003）→ hold_relay ×2 → 22:22:25Z promote
`180.152.54.66:51821`（candidate table）→ 22:23:08Z verified——**末拍即新环进行中，
环未收口**。取证时 `direct-peers.json` 实况：windows-desktop `mode=p2p_direct @
10.147.19.97:51821`（handshake_fresh）——恰在 `.97` 面上的 verified 态。

### 窗口累计（07:19Z→22:23Z，1,168 事件 = 15.08h）

| peer | 条数 | promote | demote | hold_relay | probe | defer |
|---|---|---|---|---|---|---|
| windows-desktop（JMrE） | 957 | 367 | 186 | 361 | 42 | 1 |
| openclaw-win（FSaf） | 211 | 76 | 37 | 75 | 23 | 0 |

### JMrE 周期节奏（180 个 promote→demote 周期）

| 时段 | 周期数 | 中位 | 最短 | 最长 |
|---|---|---|---|---|
| 07–11Z | 44 | 0.78 min | 0.72 | 10.63 |
| 11–15Z | 50 | 0.78 min | 0.72 | 8.25 |
| 15–19Z | 46 | 0.87 min | 0.72 | 6.73 |
| 19–23Z | 40 | 1.48 min | 0.72 | 10.58 |

末段（19–23Z）中位维持 1.48min，与上一检查点一致；末 10 个周期 0.87–5.22min
散布，仍分钟级翻转，**未收口也不构成「已缓解」**。两面互拽照旧（`.97:51821` 与
`180.152.54.66:51821`）。

### FSaf（openclaw-win）：静默延续 3.42h → 5.02h

末事件仍为 17:22:59Z，此后 **5.02h 零事件**；窗口内 FSaf 计数与上两个检查点完全
一致（211 条零新增）。`direct-peers.json` 实况 `p2p_direct @ 192.168.5.11:51820`、
`handshake_fresh`——锚 LAN 面稳定。openclaw 侧数据留空：ZT 面 No route to host，
按巡检单禁重试 SSH。

### 切换闸口径复核：零 endpoint_roam 延续

增量 51 条切换事件**全为 `mode_flip`**，**0 条 `endpoint_roam`**；全文件 955 条
= 951 mode_flip + 4 endpoint_roam，最末 roam 仍早于观察窗。口径连续三个检查点成立。

### 无新签名

增量 7 种 reason 文本全在此前已有的 10 种之内，**零新增**；无新 endpoint 面；
`defer` 全窗仍仅 1 条（窗口早期）。

### 边界与排除（沿用单据）

- 不做 24h 达标判定（窗口 15.08h 未满，差 8.92h；判定留给 2026-11-15 15:19 CST
  之后的巡检）。
- 三选一修复方向仍待用户拍板；本轮未动 `crates/`、未改状态机、未实施三选一。
- 未 bump 版本、未打 tag、未发 release、未 force push。

### raw 清单（本轮新增）

- `fliploop-imac-decisions-window3-2026-11-14.txt`（窗口 07:19Z–22:23Z 全段 1,168 条，
  自 `agent-decisions.jsonl` 按 ts 切出）
- switch-events 同窗统计已录入本节（增量 51 条全 mode_flip，与 decisions 对应）

## 08:0x CST 检查点（巡检单 meshlet-fliploop-checkpoint-0808，2026-11-15 00:09:48Z 取证）

**取证时刻（双时区）**：2026-11-15 **00:09:48Z（08:09 CST）**，imac 侧 00:10:23Z 互证；
本单标题 08:08 CST / 00:08Z 与实测一致（前两单的自相矛盾本次未再现）。窗口 =
07:19Z → 00:09Z = **16.86h**，距 24h 门槛（15:19 CST / 07:19Z）**还差 7.14h**。
**本轮不做达标判定**（单据明确排除）。

数据面：`agent-decisions.jsonl`（639,427 B / 1,807 事件，末事件 00:10:14Z）、
`direct-switch-events.json`（1,031 事件）、`direct-peers.json`（实况见下）。

### ⚠️ 三项新况（本检查点重点，均单独标注）

**① FSaf（openclaw-win）静默打破**：末事件不再停留在 17:22:59Z——增量 22:42:44Z 起
47 条事件（promote 17 / hold_relay 16 / demote 9 / probe 5），**恢复分钟级翻转**
（7 个 promote→demote 周期，中位 0.78min）。签名换了：翻转主体在 **`.49:51820`
（ZT 面，22 条）↔ `180.153.160.8:51820`（公网面，6 条）**，LAN 面 `192.168.5.11`
仅 3 条（23:52:00Z `handshake stale` demote + 23:54:15Z memory face promote +
23:55:01Z verified）。即 04:0x/06:1x 检查点的「锚 LAN 面静默」**已终结**，转为与
JMrE 同型的 ZT 面翻转——静默时段（17:23Z–22:42Z，5h19m）如实记录为已结束。
末拍 23:55:01Z verified `192.168.5.11` 后至取样末（15min）无事件，但实况
handshake fresh @ `.49:51820`（00:08:24Z）——内核实况面与 promote 下发面再次漂移
（WG roaming，同 fliploop 既证模式）。

**② 新 endpoint 面出现**：`192.168.36.153:51820`——**全新网段**（非 192.168.5.x 家
LAN、非 10.147.19.x ZT、非 180.x 公网）。23:04:09Z endpoint_roam 事件
`10.147.19.49:51820 → 192.168.36.153:51820`（reason：`score 10.5 beats current 27.5
by >= 30% for 3 consecutive samples`）。该面在 decisions 日志 0 命中（非 promote
候选，只在切换事件出现）——openclaw-win 的 agent 上报候选含此面且 score 竞争获胜
过一次；其后 23:06–23:35 的翻转仍回 `.49`。来源（何种网络接入）未知，如实记录不猜。

**③ 零 endpoint_roam 口径被打破**：连续三个检查点（04:0x / 04:4x / 06:1x）零 roam
后，增量出现 **1 条 endpoint_roam**（即上条 `→192.168.36.153`）。全文件
1,031 条 = 1,025 mode_flip + 5 endpoint_roam（前 4 条 roam 均早于观察窗）。
「切换闸零新触发」口径自此**不再成立**，如实降级为「增量 77 条切换事件中
76 mode_flip + 1 endpoint_roam」。

### JMrE（windows-desktop）：环仍在续

增量 107min **91 事件**（promote 33 / hold_relay 34 / demote 17 / probe 7）。
窗口累计 1,305 事件 = 16.86h：windows-desktop **1,047** 条（promote 399 /
hold_relay 395 / demote 203 / probe 49 / defer 1），openclaw-win **258** 条
（promote 93 / hold_relay 91 / demote 46 / probe 28）。

| 时段 | 周期数 | 中位 | 最短 | 最长 |
|---|---|---|---|---|
| 07–11Z | 44 | 0.78 min | 0.72 | 10.63 |
| 11–15Z | 50 | 0.78 min | 0.72 | 8.25 |
| 15–19Z | 46 | 0.87 min | 0.72 | 6.73 |
| 19Z–00Z+（11-14 19:00Z→11-15 00:10Z） | 57 | 1.50 min | 0.72 | 10.58 |

末段中位 1.50min 与前两检查点持平；末 12 周期 0.78–7.77min 散布，仍分钟级。
末拍：00:04:57Z verified `.97` → 00:08:42Z demote `.97`（sel003）→ hold_relay ×2
（至取样末）。取证时 `direct-peers.json` 实况：windows-desktop `mode=hub_relay`
（中继态），openclaw-win `p2p_direct @ .49:51820`，coding-vm 稳 `@ 192.168.5.188`。

### 无新 reason 文本

增量 8 种 reason 文本全在此前已有的 10 种之内（sel003 degraded / recovery gate /
pending verified / memory face promote / candidate table promote / waiting for
handshake ×2 / pending attempts exhausted），**零新增**；`defer` 全窗仍 1 条。

### 边界与排除（沿用单据）

- 不做 24h 达标判定（窗口 16.86h 未满，差 7.14h；判定留给 15:19 CST 之后的巡检）。
- FSaf 侧数据留空：ZT 面 No route to host 前科，按巡检单禁重试 SSH。
- 三选一修复方向仍待用户拍板；本轮未动 `crates/`、未改状态机、未实施三选一。
- 未 bump 版本、未打 tag、未发 release、未 force push。

### raw 清单（本轮新增）

- `fliploop-imac-decisions-window4-2026-11-14.txt`（窗口 07:19Z–00:10Z 全段 1,305 条，
  自 `agent-decisions.jsonl` 按 ts 切出）
- switch-events 同窗统计已录入本节（增量 77 条 = 76 mode_flip + 1 endpoint_roam）

## 08:5x CST 检查点（巡检单 meshlet-fliploop-checkpoint-0855，2026-11-15 00:59:25Z 取证）

**取证时刻（双时区）**：2026-11-15 **00:59:25Z（08:59 CST）**，imac 侧 01:00:00Z 互证；
本单标题 08:55 CST / 00:55Z 与实测一致。窗口 = 07:19Z → 00:59Z = **17.68h**，距 24h
门槛（15:19 CST / 07:19Z）**还差 6.32h**。**本轮不做达标判定**。

数据面：`agent-decisions.jsonl`（656,818 B / 1,856 事件，末事件 00:59:43Z）、
`direct-switch-events.json`（1,059 事件）、`direct-peers.json`（实况见下）。

### 增量（00:10:14Z→01:00Z，50min）：50 事件

JMrE 45 条（promote 17 / hold_relay 17 / demote 8 / probe 3）；FSaf 5 条
（promote 2 / hold_relay 2 / demote 1）。窗口累计 1,354 事件 = 17.68h：
windows-desktop **1,091** 条（promote 416 / hold_relay 411 / demote 211 / probe 52 /
defer 1），openclaw-win **263** 条（promote 95 / hold_relay 93 / demote 47 / probe 28）。

### JMrE：环仍在续，末段节奏持平

205 个周期分段中位 0.78 → 0.78 → 0.87 → **1.52min**（19Z–01Z+ 段与上两检查点的
1.48/1.50 持平）；末 10 周期 0.73–5.38min 散布，仍分钟级。末拍：00:53:42Z verified
`180.152.54.66:51821` → 00:57:25Z demote `.97:51821`（sel003）→ hold_relay ×2 →
00:59:43Z promote `.97`（memory face，至取样末未 verified）。取证时实况：
windows-desktop `mode=direct_pending`、endpoint `.97:51821`、`unprobed`（末拍
promote 后 pending 中）。

### FSaf：翻转收窄，单拍后暂稳，实况回锚家 LAN 面

增量内 FSaf 仅 5 拍：00:11:47Z demote `.49`（sel003）→ hold_relay ×2 → 00:14:08Z
promote `180.153.160.8`（candidate table）→ **00:14:53Z verified 后静默 45min**
（至取样末零事件）。上一检查点的分钟级连续翻转（22:42–23:55Z，47 条）**未延续**，
收窄为单轮 promote→demote→verified 后暂稳。

**实况面再次漂移**：取证时 `direct-peers.json` 实况 FSaf `p2p_direct @
192.168.5.11:51820`（handshake fresh @ 00:56:56Z）——00:14:53Z 下发/verified 的面是
`180.153.160.8`，内核实况面却是家 LAN `.11`（WG roaming 把 endpoint 漫游回
`.11`，同 fliploop 既证模式）。即 FSaf 当前实际会话走在**家 LAN 面**上，而决策日志
最后动作面是公网面——如实记录该错位。

上轮新面 `192.168.36.153`：增量 **0 命中**（全窗仍仅 23:04:09Z 一条 roam），
来源仍不猜。

### 切换闸口径复核

增量 28 条切换事件**全为 mode_flip，0 条 endpoint_roam**；全文件 1,059 = 1,054
flip + 5 roam（第 5 条即上轮 `→192.168.36.153`，早于本增量）。上轮被打破的
「零 roam」口径在本增量恢复为零，如实按增量计数。

### 无新签名

增量 reason 文本全在此前 10 种之内（sel003 degraded / recovery gate / pending
verified / candidate table promote / memory face promote / waiting handshake ×2 /
pending attempts exhausted——本增量实出现 5 种），**零新增**；`defer` 全窗仍 1 条；
无新 endpoint 面。

### 边界与排除（沿用单据）

- 不做 24h 达标判定（窗口 17.68h 未满，差 6.32h；判定留给 15:19 CST 之后巡检）。
- FSaf 侧数据留空：ZT 面 No route to host 前科，禁重试 SSH。
- 三选一修复方向仍待用户拍板；本轮未动 `crates/`、未改状态机、未实施三选一。
- 未 bump 版本、未打 tag、未发 release、未 force push。

### raw 清单（本轮新增）

- `fliploop-imac-decisions-window5-2026-11-15.txt`（窗口 07:19Z–00:59Z 全段 1,354 条，
  自 `agent-decisions.jsonl` 按 ts 切出；命名跨日至 2026-11-15）
- switch-events 同窗统计已录入本节（增量 28 条全 mode_flip）
