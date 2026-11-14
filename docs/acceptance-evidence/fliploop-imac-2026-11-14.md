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
