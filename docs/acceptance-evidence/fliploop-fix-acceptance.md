# fliploop 修复验收（FLIP-001 候选表纳管 roaming + FLIP-002 demote backoff）— 2026-11-15

巡检单 meshlet-fliploop-fix（用户拍板：①主修 + ③保底，②下发面锚定不做）。本文档
对账两条修复的实现、单测与集成模拟；2026-11-15 修复已随 nightly 部署双机（部署
节），修后 24h 观察窗起点已落盘，**判定与中位对比待窗口满后另单**。

## 基线（修前，判定口径不许动）

起点 2026-11-14 15:19 CST（commit bc2d356，**未含修复**）部署后 24h 判定窗
（docs/acceptance-evidence/fliploop-24h-2026-11-15.md）：

| 指标 | 基线（bc2d356，修前） |
|---|---|
| JMrE promote↔demote 环 | 12.69h 812 次 mode_flip（64 次/h） |
| promote→demote 中位时长 | 0.78min |
| 24h 判定窗（07:19Z→07:20Z） | 799 次 flip / 262 个环 / 中位 1.48min，末拍仍翻 |
| promote 时 probe=Unhealthy | 268/530 次（50.6%） |
| promote 面 | 100% 钉死 `10.147.19.97:51821`（JMrE ZT 面）单面 |

机理实锤：「无健康面可选 → 拨劣化面 → SEL-003 打回 → RecoveryGate 放行 →
re-promote 同一劣化面」闭环，正对 FLIP-001/FLIP-002。

## 修后真机数据：观察窗已开（2026-11-15 部署，判定另单）

修复二进制已于 2026-11-15 随 nightly（run 43695140898，tag 5fb7d81）部署双机
（见下部署节）；**修后 24h 观察窗起点 16:57:32 CST / 08:57:32Z**，判定与中位
对比等窗口满 24h 后另单执行，本节不预写任何修后指标数字。

## 部署节（2026-11-15 16:2x–17:0x CST，巡检单 meshlet-fliploop-deploy-1115）

**构建链**：nightly run `43694301073`（897fa53）checks job 挂 `cargo fmt --check`
（flip 测试批量补参留下 if/else 接管道与缩进偏差——本地门禁没跑 fmt 的教训），
`style: apply rustfmt to fliploop tests`（5fb7d81）修后重跑 nightly run
`43695140898` success。nightly tag sha = `5fb7d811…0b86f`，`merge-base --is-ancestor`
f99a7ef / 9f07ecb **双 OK**（release `target_commitish` 显示旧值 a231360——tag ref
sha 才是权威，巡检单预警的坑属实）。MSI `b6a5478b…d2de`（11,186,176B）对
SHA256SUMS `sha256sum -c` **OK**。

**双机部署**（schtasks 分离执行，S4U principal，非交互上下文；SSH 只注册+轮询）：

| 机器 | 升级窗(CST) | PID | 双位 exe 哈希 | MSIEXEC_RC | --version |
|---|---|---|---|---|---|
| imac | 16:56:11→16:56:16 | 35644→**42676**（单进程） | `EC36C7BA…597B`（PF=AD） | 0 | 0.1.0 |
| openclaw | 16:57:22→16:57:32 | 8128→**6608**（单进程） | `EC36C7BA…597B`（**与 imac 同构建**） | 0 | 0.1.0 |

两机 MSI 哈希均与本机下载件逐字节同哈希；升级前双机修前状态已采（imac 35644 /
openclaw 8128，exe `05f75c40…BDA6` = bc2d356 构建，与 11-14 证据一致——即两台
真机自 11-14 15:19 起持续跑修前构建，24h 判定窗的「修前基线」口径由此坐实）。

**核验**：coding-vm ping imac VIP 10.240.0.7 6/6 包 0% 丢（avg 6.4ms）、ping
openclaw VIP 10.240.0.3 6/6 包 0% 丢（avg 8.5ms）；两机 `agent-decisions.jsonl`
升级后持续在写（imac mtime 16:56、openclaw 16:58:04）。**修后行为首批实证**：
imac 重启后 15 秒（08:56:31Z）JMrE 出现 `defer`（`promote deferred: candidate
face degraded (probe window)`，endpoint `.97`）——ZT 劣化面正确拒拨（基线机理
「无健康面可选→拨劣化面→打回」的第一腿已被 defer 拦截）。收尾：两机 Temp 升级
文件清零、MeshletFlUp2 / MeshletOcFl2 任务自删实证、无残留计划任务。

**修后 24h 观察窗起点：2026-11-15 16:57:32 CST / 08:57:32Z**（两机新构建+新 PID
均确认时刻取后者）。基线=修前判定（本文件基线表 + fliploop-24h-2026-11-15.md：
799 flip / 262 环 / 中位 1.48min）。判定与中位对比按窗口满 24h 后另单执行，本单
只记录起点、不做中途判定、不外推。

**部署过程坑实录**（复用价值）：①schtasks `/Create` 不带 `/RU` 注册成
「只使用交互式」任务，SSH 非交互上下文 Last Result=1 且脚本一行未跑——imac 上
需 `Register-ScheduledTask -LogonType S4U -RunLevel Highest`（与
`MeshletAgentDeploy` 同款）；②`New-ScheduledTask` 产物绑 `-Task` 参数在 PS 5.1
歧义报错，直接 `-Action/-Principal/-Settings` 传参即可；③升级 ps1 首版
`if … else … | Out-File` 是解析错误（整脚本不执行、无任何产物），语句不能直接
接管道——CI fmt 门与这类「无日志无声失败」都指向同一教训：远端脚本先落一行日志
再干活，解析错误才能被看见。

## 20:2x 检查点（2026-11-15 20:48 CST / 12:48:49Z 实测，巡检单 meshlet-fixcp2-1120）

**纯取证检查点 #2，窗龄 3.85h/24h——禁中途达标判定、禁外推**（单据标题 20:17 CST
与实测 20:48 差 31min 按实测记录）。openclaw ZT SSH 本轮顺通，双机三文件齐取
（raw `fliploop-fix-window2-2026-11-15.txt`）。

**增量**（08:57:32Z 起 3.85h）：imac 388 决策（JMrE 253：promote 101/probe 36/
demote 51/hold 65/defer 17；FSaf 118：promote 55/probe 35/demote 28）；OC 322
（wd=JMrE 171：promote 25/hold 23/probe 14/demote 15/**defer 109**；imac 103；
coding-vm 29）。周期中位（promote→demote）：imac JMrE 0.88min（n=51）/ FSaf
1.52min（n=27）；OC wd 2.67min（n=14）/ imac 1.12min（n=26）/ coding-vm 9.26min
（n=6，max 105.8min）。

**切换闸**：imac 240 条=235 flip+**5 roam**（全 FSaf，SEL-002 评分合法切换
`.49`→`192.168.5.11:51820` 路由器面，score 0 beats 24.5-636 for 3 samples）；
OC 143 条=139 flip+4 roam（全 imac peer `.117`→`.226`，score 25-1000）。

**修后新签名生产可见（均符合预期，无未知新 reason）**：FLIP-002 defer——imac
JMrE 17 条（4→5 连续升级、最长连 5 条/3.0min）、OC wd 109 条（3→4→5→6→**7 连续**
升级、cooling 至 834s、最长连 **13 条/12.9min**）——退避指数拉伸在生产可观测；
FLIP-001 bypass promote——imac JMrE 22/FSaf 28、OC wd 28（另 coding-vm 12:48:41Z
bypass promote @ `.130`）。**早期信号（defer 拒劣化面）延续**：部署后首条
08:56:31Z defer 之后整个窗口持续。端点面：`.97`(155)/`.49`(70)/`192.168.5.11`
(48，路由器面)/`180.152.54.66`(33)，无 `192.168.36.153` 同类新面进决策。

**实况快照**（12:49Z）：imac——coding-vm p2p_direct @ `192.168.5.188` 稳定、
JMrE hub_relay（endpoint 空=冷却中）、FSaf direct_pending @ 路由器面；OC——
coding-vm direct_pending @ `.130`、JMrE 与 imac 均 hub_relay（endpoint 空）。
**末拍仍在翻**：imac JMrE 12:48:18Z promote verified @ `.97` → 39s 后
12:49:07Z demote sel003；OC imac peer 12:47:34Z verified @ `.17` → 12:48:41Z
demote——**环未收口**（事实记录；判定属另单）。率事实（非判定）：imac JMrE
demote 51/3.85h ≈13.2 次/h vs 修前 24h 窗 33 次/h、12.69h 基线 64 次/h。

## 21:3x 检查点（2026-11-15 21:36 CST / 13:36:48Z 实测，巡检单 fliploop-fixcp3-1120）

**纯取证检查点 #3，窗龄 4.65h/24h——禁中途达标判定、禁外推**（实测与单据标题
一致）。openclaw ZT SSH 本轮顺通，双机三文件齐取（raw
`fliploop-fix-window3-2026-11-15.txt`）。

**增量**（08:57:32Z 起 4.65h；cp2 后增量窗约 48min）：imac 全窗 487 决策
（JMrE 296：promote 115/probe 38/demote 58/hold 79/**defer 46**；FSaf 151：
promote 66/demote 36/probe 49）；OC 全窗 401（wd=JMrE 215：**defer 142**/
promote 29/demote 17/hold 27；imac 100；coding-vm 41）。周期中位：imac JMrE
0.82min（n=58）/ FSaf 2.20min（n=35）；OC wd 2.17min（n=16）/ imac 1.64min
（n=30）/ coding-vm 9.97min（n=9）。cp2 后增量：imac 102 条（JMrE promote
14/demote 8/**defer 29**/hold 14；FSaf promote 12/demote 8/6× pending
attempts exhausted）；OC 79 条（wd defer 33 含 **15→16→17 连续 demote**、
cooling 至 703s≈15min cap 区——FLIP-002 退避顶到封顶的生产行为可观测；
OC imac peer 本段首条 defer）。

**切换闸**：imac 全窗 281=275 flip+**6 roam**（第 6 条 13:00:39Z FSaf
`.49`→`192.168.5.11` score 0 beats 32）；OC 全窗 173=167 flip+**6 roam**
（新增 13:17:09Z imac peer `.117`→`.226` score 30、13:27:06Z `.117`→**`.17`
新面** score 42）。

**新 endpoint 面进决策（cp2 后新签名）**：imac 视角 **`192.168.5.11:44249`**
×7——路由器 NAT 临时端口面（FSaf roam 下发 `.11:51820` 后内核 NAT 漂移出的
临时端口），13:23:30Z 经 FLIP-001 bypass promote 并 verified @ `:44249`；
OC 视角 **`10.147.19.17`** ×64 新面（含 verified）。全部 reason 仍为修后预期
签名（FLIP-002 defer / FLIP-001 bypass / 既有 sel003 / recovery gate /
pending 系），**无未知新 reason**。FLIP-002 defer 与 FLIP-001 bypass 计数
延续（cp2 后 defer 增量 63 条、bypass 增量 7 条：imac JMrE 1/FSaf 3/
OC coding-vm 3）。

**实况快照与面漂移**（13:37Z）：imac——coding-vm p2p_direct @
`192.168.5.188` 稳定、**FSaf p2p_direct @ `192.168.5.11:44249`
handshake_fresh**（verified 后 ≥14min 稳直连）、JMrE hub_relay（endpoint
空=冷却中）；OC——coding-vm p2p_direct @ `.130` fresh、imac p2p_direct @
`.117` fresh、JMrE hub_relay。**下发面 vs 内核面**：FSaf 链路本轮收敛——
13:00:39Z roam 下发 `.11:51820` → 内核 NAT 漂到 `:44249` → bypass promote
落地临时端口面并 verified → 取证时下发面=内核面一致；JMrE 冷却中无直连面
（无漂移问题）。**末拍（13:37:41Z）imac JMrE 为 hold_relay（恢复门）——
取证时被抑制未翻转**（对照 cp2 末拍 39s 内 promote→demote 往复；FSaf 末拍
verified 距取证 ≥14min 未翻）。率事实（非判定）：imac JMrE cp2 后增量 demote
8/48min ≈10 次/h（全窗 58/4.65h ≈12.5 次/h）。

## 22:2x 检查点（2026-11-15 22:25 CST / 14:25:29Z 实测，巡检单 fliploop-fixcp4-1120）

**纯取证检查点 #4，窗龄 5.46h/24h——禁中途达标判定、禁外推**（单据标题 22:22
与实测 22:25 差 3min 按实测）。openclaw ZT SSH 首试即通，双机三文件齐取（raw
`fliploop-fix-window4-2026-11-15.txt`）。

**增量**（08:57:32Z 起 5.46h；cp3 后增量窗约 49min）：imac 全窗 548 决策
（JMrE promote 122/hold 83/**defer 83**/demote 63/probe 46；FSaf promote 66/
demote 36/probe 49——**13:23:30Z verified 后零决策**）；OC 全窗 439（wd=JMrE
**defer 166**/promote 34/hold 31/demote 20；imac peer promote 60/demote 31；
coding-vm 41）。周期中位：imac JMrE 0.83min（n=63）/ FSaf 2.20min（n=35）；
OC wd 2.18min（n=19）/ imac 1.64min（n=30）/ coding-vm 9.97min（n=9）。
cp3 后增量：imac 63 条（JMrE **defer 37**/promote 7/hold 6/demote 5/probe 8；
FSaf 零）；OC 38 条（wd defer 24/promote 5/demote 3）。**FLIP-002 退避双视图
钉死 cap**：imac 视 JMrE 连续 demote 升至 **7**（末拍 14:25:37Z defer cooling
723s≈cap 区）、OC 视升至 **20**（14:25:15Z defer cooling 777s——delay 远超
15min cap 钉死 900s）。**段内 bypass=0**（双机）：JMrE 面整段探测不健康无
放行，FSaf/OC 侧已稳直连无需 bypass（FLIP-001 bypass 全窗计数：imac JMrE
23/FSaf 30；OC imac peer 25/coding-vm 10——延续性为「存量维持、增量归零」）。

**切换闸与新面**：imac 全窗 293=287 flip+6 roam、OC 181=175 flip+6 roam——
**roam 计数与 cp3 完全持平（13:00:39Z / 13:27:06Z 后零新 roam），零新
endpoint 面进决策**（存量面：`.97`/`180.152.54.66`/`.11:51820`/`10.147.19.49`
/`:44249`；OC 视 `.17`×40/`.226`/`.130`/`.117`）。reason 全集（双机）仍为
既有+修后预期签名，**无未知新 reason**。

**实况快照与面漂移延续**（14:25Z）：imac——coding-vm p2p_direct @
`192.168.5.188` fresh、**FSaf p2p_direct @ `192.168.5.11:44249` fresh
hs=14:25:08Z——cp3 verified（13:23:30Z）后 62min 零决策稳直连，下发面=内核面
持续一致**；JMrE hub_relay（endpoint 空=冷却）。OC——coding-vm @ `.130`
fresh、imac peer p2p_direct @ `.117`（verified 13:22:48Z 后 63min 静默，
rtt_source=probe_failed 但握手新鲜）、wd hub_relay。三对直连（FSaf、OC↔imac、
双视 coding-vm）全稳，**末拍仅 JMrE 一对在退避冷却**。率事实（非判定）：JMrE
段内 demote imac 视 5/49min ≈6.1 次/h（cp3 段 ≈10/h、全窗 ≈11.5/h、修前
33/h）、OC 视 ≈3.7 次/h；末次环 14:20:24Z promote→14:22:39Z demote
（2.25min）——环仍在但段内 63 条中 37 defer（59%）+6 hold，promote 尝试被
退避拉稀。

## 23:1x 检查点（2026-11-15 23:14 CST / 15:14:06Z 实测，巡检单 fliploop-fixcp5-1120）

**纯取证检查点 #5，窗龄 6.28h/24h——禁中途达标判定、禁外推**（单据标题 23:13
与实测 23:14 差 1min）。openclaw ZT SSH 首试即通，双机三文件齐取（raw
`fliploop-fix-window5-2026-11-15.txt`）。

**增量**（08:57:32Z 起 6.28h；cp4 后增量窗约 49min）：imac 全窗 613 决策
（JMrE defer 133/promote 128/hold 89/demote 66/probe 46；FSaf promote 66/
demote 36/probe 49——**13:23:30Z verified 后持续零决策**）；OC 全窗 493
（wd **defer 201**/promote 37/hold 33/demote 22；imac peer promote 62/
demote 32；coding-vm 45）。周期中位：imac JMrE 0.82min（n=66）/ FSaf
2.20min（n=35）；OC wd 2.18min（n=21）/ imac 2.07min（n=31，max 86.15min
=13:22:48Z verified→14:48:57Z demote 的长稳周期）/ coding-vm 10.38min
（n=10）。cp4 后增量：imac 66 条（JMrE **defer 51**/promote 6/hold 6/
demote **3**；FSaf 零）；OC 54 条（wd defer 35/demote 2；imac peer demote
1/promote 2；coding-vm promote 2/demote 1）。**FLIP-002**：imac 视连续
demote 升至 **9**（cp4 为 7）、OC 视升至 **22**（cp4 为 20）——末拍
15:13:37Z cooling 仅余 **135s**（cap 窗将尽，下次 promote 尝试在即，结果
未观测）；段内 defer 占比 imac 视 51/66=77%（cp4 段 59%），连续 defer 流
14:25:37Z→14:30:52Z+ 后静默。**段内 bypass**：imac 机 0；OC coding-vm 1
（14:45:47Z demote→14:46:49Z bypass promote→14:47:51Z verified @ `.130`
稳直连——恢复路径工作正常）。

**切换闸与新面**：imac 全窗 302=296 flip+6 roam（与 cp3/cp4 持平，13:00:39Z
后零新）；OC 193=186 flip+**7 roam**——**新增第 7 条 14:47:51Z imac peer
`.117`→`.226` score 104.5**（SEL-002 评分合法切换），围绕它的段内小环：
roam→14:48:57Z demote→hold×2→14:52:07Z promote→**14:53:12Z verified @
`.117`（回 LAN 面）**→取证时 21min 静默稳直连。端点面集与 cp4 完全一致
（`:44249` ×3、`.17` ×40 等），**零新面**；reason 全集不变，**无未知新
reason**。

**实况快照与面漂移延续**（15:14Z）：imac——coding-vm p2p_direct @
`192.168.5.188` fresh、**FSaf p2p_direct @ `192.168.5.11:44249` fresh
hs=15:14:17Z——cp3 verified 后 111min 零决策稳直连，下发面=内核面跨
cp4/cp5 持续一致**；JMrE hub_relay（取证时 hold_relay 换挡抑制中）。
OC——coding-vm @ `.130` fresh、imac peer @ `.117` hs=15:13:26Z
（probe_failed 但握手新鲜）、wd hub_relay（defer 22 连续 cooling 135s）。
率事实（非判定）：JMrE 段内 demote imac 视 3/49min ≈3.7 次/h（cp4 段
≈6.1/h、全窗 ≈10.5/h、修前 33 次/h）、OC 视 2/49min ≈2.4 次/h（cp4 段
≈3.7/h）——压稀趋势在段间延续；末段 JMrE 环仍 ~44s 快速往复但仅 3 次
（n=3 median 0.73min）。

## 00:0x 检查点（2026-11-16 00:24 CST / 2026-11-15T16:24:07Z 实测，巡检单 fliploop-fixcp6-1120）

**纯取证检查点 #6，窗龄 7.44h/24h——禁中途达标判定、禁外推**（单据标题 00:01
与实测 00:24 差 23min 按实测）。**openclaw SSH 首试超时（exit 124，ZT 面不通）
——触发留空铁律未重试，本轮 OC 侧留空**（cp2–cp5 均顺通）。仅 imac 三文件
取证（raw `fliploop-fix-window6-2026-11-15.txt`）。

**挂起观测点解答（cp5 末拍 cooling 135s 将尽 → 退避到期首拍）**：到期前又落
一次 demote（连击 9→**10**、cooling 重置 766s，15:15:15Z–15:20:32Z 五拍 defer
倒计时）；到期 ~15:21:18Z **promote 恢复且 verified**（memory face @ `.97`，
15:22:01Z pending verified fresh handshake）——**43s 后 sel003 打回**。环按
cap/健康清零节奏延续：段内尝试 ~5–6min 一拍（15:21/15:28/15:34/15:38/15:43/
15:49/15:58/16:01/16:07/16:10/16:16/16:19），**FLIP-002 的健康清零生产可观测**
——连击 10 →（连续 3 轮健康确认）→ 清零 → 2→4→5 重涨（15:37:54Z defer 已示
「2 consecutive」）。

**增量**（08:57:32Z 起 7.44h；cp5 后增量窗约 70min）：imac 全窗 701 决策
（JMrE promote 153/defer 151/hold 105/demote 78/probe 55；FSaf promote 70/
demote 38/probe 51）。周期中位：imac JMrE 0.82min（n=78）/ FSaf 2.20min
（n=37，**max 171.90min=111min+ 稳直连成为最长周期**）。cp5 后增量 89 条
（JMrE promote 25/defer 18/hold 17/demote 12/probe 9——cycles n=12 median
0.75min；FSaf promote 4/demote 2/probe 2）。**段内 demote 回弹** ≈10.3 次/h
（cp5 段 ≈3.7/h 大部分在 cap 冷却窗内被拦；全窗 ≈10.5/h——拦截期与放行期的
率差可见，非判定）。段内 bypass：JMrE +4/FSaf +2（连击被健康清零后冷却缩到
base 30s，bypass 在冷却后放行，demote 后 <1min 的 bypass promote 可见）。

**FSaf 稳直连终结**：13:23:30Z verified 起 ~172min 零决策稳直连后，
16:15:24Z demote @ `.49`（sel003）→ bypass promote → verified 16:16:55Z →
demote → bypass promote → **16:19:10Z verified @ `.49`** → 取证时 live @
`.49:51820` fresh（下发面=内核面再次一致）。**`:44249` NAT 临时端口面消亡**
（16:15Z 前某刻 NAT 端口绑定过期，全窗 ×3 无新增）——cp3/cp4/cp5 追踪的
FSaf 面漂移链自然收尾。**JMrE 公网 WAN 面 `180.152.54.66:51821` 反复 promote
且 verified**（候选表纳管公网面参选成果；15:44/15:50/16:02/16:20 四次
verified），但内核数分钟内漂回 `.97`——末拍 16:20:41Z verified @ `180.152`
→ live @ `.97` fresh hs=16:24:20Z（**下发面≠内核面再现**，此类内核漂移不产生
roam 事件，同 cp3 `:44249` 端口漂移）。切换闸 345=339 flip+6 roam（零新
roam）；端点面集无新面（`.97` +14/`180.152` +11/`.49` +4 增量均为存量面）；
reason 全集不变，**无未知新 reason**。

**实况快照**（16:24Z）：三对全 p2p_direct——coding-vm @ `192.168.5.188`
fresh、**JMrE @ `.97` fresh hs=16:24:20Z**（rtt_source=probe_failed 但握手
新鲜）、**FSaf @ `.49` fresh hs=16:23:47Z**。末拍：FSaf 16:19:10Z verified、
JMrE 16:20:41Z verified——取证时两对均为 verified 后 <5min 的直连态。率事实
（非判定）：JMrE 段内 demote 12/70min ≈10.3 次/h（cp5 段 ≈3.7、全窗 ≈10.5、
修前 33 次/h）；末段环仍 ~44s 快速往复（median 0.75min）。

## 01:0x 检查点（2026-11-16 01:11 CST / 2026-11-15T17:11:50Z 实测，巡检单 fliploop-fixcp7-1121）

**纯取证检查点 #7，窗龄 8.24h/24h——禁中途达标判定、禁外推**（单据标题 01:09
与实测 01:11 差 3min）。openclaw SSH 本轮**恢复顺通**（cp6 超时后首试即通），
双机三文件齐取（raw `fliploop-fix-window7-2026-11-15.txt`）。

**挂起观测点核验**：①**`180.152.54.66` 公网面漂移模式延续**——OC 视末拍
17:11:33Z wd promote verified @ `180.152` → live @ `.97` fresh（下发≠内核
在 OC 视再现）；imac 视末拍 verified @ `.97` → live @ `.97`（下发=内核一致，
cp6 末拍漂移态未延续）。公网面持续参选（imac 视 ×54→×58 段内 +4；OC 视 wd
×37）。②**三对全直连延续**：cp6 取证时三对 p2p_direct 的态在 ~47min 后的
cp7 取证时**仍全直连**（coding-vm hs=17:11:26Z / JMrE @ `.97`
hs=17:10:27Z / FSaf @ `.49` hs=17:10:58Z 全 fresh）。③**`:44249` NAT 临时
端口面复活**（cp6 记录其消亡后）：路由器 NAT 重绑定重新给出临时端口——imac
视 ×3→×15（段内 +12），FSaf 末拍 17:11:39Z **promote verified @ `:44249`**
再入并再 verified；FSaf 段内 `.49`↔`:44249` 高频翻转（promote 24/demote
12/probe 14，bypass +14，cycles n=11 median 0.83min）。

**增量**（08:57:32Z 起 8.24h；cp6 后增量窗约 48min）：imac 全窗 783 决策
（JMrE promote 167/defer 151/hold 112/demote 85/probe 59；FSaf promote 94/
demote 50/probe 65）；OC 全窗 665（wd **defer 272**/promote 50/demote 28；
imac peer promote 84/demote 44；coding-vm 66）。周期中位：imac JMrE 0.82min
（n=85，max 14.48min 新长周期）/ FSaf 2.20min（n=49）；OC wd 2.15min（n=27）/
imac 2.15min（n=43）/ coding-vm 10.84min（n=16）。cp6 后增量：imac 82 条
（JMrE promote 14/demote 7/hold 7/probe 4——**段内 defer=0，全窗 151 不变、
连击冻结在 10**，promote 整段未被退避拦截，cycles n=6 median 3.34min 比全窗
0.82min 慢；FSaf promote 24/demote 12）；OC 82 条（wd defer 27/promote 6/
demote 2——连击升至 **28** cap 区持续；imac peer promote 16/demote 9；
coding-vm promote 4/demote 3）。段内 bypass：imac JMrE +4/FSaf +14；OC imac
peer +11/coding-vm +5。

**切换闸**：imac 全窗 402=396 flip+6 roam（零新）；OC 265=255 flip+**10
roam（段内 +4）**——#8 16:03:53Z imac peer `.117`→`.226` score 65；
**#9 16:22:22Z coding-vm `.130`→`192.168.5.188` score 7 beats 12
（coding-vm 首条 roam，跨到 LAN 面）**；#10 16:42:05Z imac peer `.226`→
`.17` score 17.5 beats 55。端点面集无新面（`:44249` 为复活的存量面非新）；
reason 全集不变，**无未知新 reason**。

**实况快照**（17:11:50Z）：imac 视三对全 p2p_direct fresh（见挂起观测点②）；
**OC 视取证瞬间直连断裂**——17:11:33Z 同秒 sel003 demote 使 coding-vm 与
imac peer 双双回 hub_relay（wd 仍 p2p_direct @ `.97` fresh hs=17:11:25Z），
OC 视 coding-vm @ `192.168.5.188`、imac peer @ `.226` 的直连在取证秒被打回
（后续是否恢复未观测）。率事实（非判定）：JMrE 段内 demote 7/48min
≈8.75 次/h（cp6 段 ≈10.3、全窗 ≈10.3、修前 33 次/h）；wd 段内 2/48min
≈2.5 次/h。

## 02:0x 检查点（2026-11-16 01:59 CST / 2026-11-15T17:59:04Z 实测，巡检单 fliploop-fixcp8-1122）

**纯取证检查点 #8，窗龄 9.02h/24h——禁中途达标判定、禁外推**（与单据标题
一致）。openclaw SSH 首试即通，双机三文件齐取（raw
`fliploop-fix-window8-2026-11-15.txt`）。

**五项挂起观测点全部有数据答案**：①**JMrE 回弹态延续（未再压稀）**——
连续第三段 defer=0（全窗 151 冻结、连击冻结 10），段内 demote 9/47min
≈11.5 次/h（cp6 ≈10.3、cp7 ≈8.75），cycles n=8 median 1.50min（含 9min 长
周期）；②**OC wd 连击继续爬升** 28→**31**（defer 272→298 段内 +26），末拍
17:58:42Z cooling 514s 仍在 cap 区，本段未观测到退避到期 promote；③**LAN 面
迁移/轮换延续**——OC 视 imac peer `.17` 成主导面（×55→×75 段内 +20）、
coding-vm 在 `.130`↔`.188` 轮换（`.188` LAN 面 ×6→×14 +8）；roam 计数 10
不变（零新 roam）；④**三对直连未全恢复，且同秒 demote 签名可重复**——imac
视 17:59:17Z **同秒** JMrE @ `.97` + FSaf @ `.49` 双双 sel003 demote 回
hub_relay（取证瞬间）、OC 视 17:58:42Z imac peer @ `.226` demote 回
hub_relay（cp7 的 17:11:33Z 同款）；**仅 coding-vm 双视直连稳**（imac 视 @
`192.168.5.188` fresh hs=17:58:05Z、OC 视 @ `.130` fresh hs=17:57:38Z）；⑤
**`180.152` 漂移模式重现无新签名**——17:48:39Z promote verified @
`180.152` → 17:56:16Z demote @ `.97`（内核 7.6min 后在 `.97`）。

**增量**（08:57:32Z 起 9.02h；cp7 后增量窗约 47min）：imac 全窗 887 决策
（JMrE promote 183/demote 94/hold 117/defer 151/probe 66；FSaf promote 126/
demote 67/probe 83）；OC 全窗 767（wd **defer 298**/promote 54/demote 31；
imac peer promote 104/demote 54；coding-vm 88）。周期中位：imac JMrE
0.86min（n=94）/ FSaf 1.49min（n=66）；OC wd 1.76min（n=30）/ imac 2.12min
（n=53）/ coding-vm 10.38min（n=20）。cp7 后增量：imac 104 条（JMrE promote
16/demote 9/hold 5/probe 7/**defer 0**；FSaf promote 32/demote 17——`.49`↔
`:44249` 翻转持续：`:44249` ×15→×35 +20、`.49` ×44→×56 +12）；OC 102 条
（wd defer 26/demote 3；imac peer promote 20/demote 10；coding-vm promote
10/demote 4，cycles n=4 median 6.16min max 20.50min）。段内 bypass：imac
JMrE +7/FSaf +16；OC imac peer +10/coding-vm +5。切换闸：imac 476=470
flip+6 roam、OC 316=306 flip+10 roam——**双双零新 roam**；端点面集无新面
（全部增量落在存量面）；reason 全集不变，**无未知新 reason**。

**实况快照**（17:59Z）：**仅 coding-vm 双视直连**（见挂起④），JMrE（imac
视 hub_relay、OC 视 wd defer 31 连击 hub_relay）、FSaf（imac 视 hub_relay）、
OC imac peer（hub_relay）均在退避/恢复门冷却中。率事实（非判定）：JMrE 段内
demote ≈11.5 次/h（cp6 ≈10.3、cp7 ≈8.75、全窗 ≈10.4、修前 33 次/h）；wd 段
内 3/47min ≈3.8 次/h。

## 02:5x 检查点（2026-11-16 02:46 CST / 2026-11-15T18:46:31Z 实测，巡检单 fliploop-fixcp9-1123）

**纯取证检查点 #9，窗龄 9.82h/24h——禁中途达标判定、禁外推**（与单据标题
一致；单据禁项「约 18h/24h」系笔误，按实测 9.82h 记录）。openclaw SSH 首试
即通，双机三文件齐取（raw `fliploop-fix-window9-2026-11-15.txt`）。

**五项挂起观测点全部有数据答案**：①**JMrE 回弹延续但持续放缓**——连续
**第四段 defer=0**（151 冻结、连击冻结 10），段内 demote 6/47min ≈7.7 次/h
（cp8 ≈11.5→cp7 ≈8.75→cp9 ≈7.7 逐段放缓），cycles n=5 median **4.53min**；
**窗口内最长直连保持新纪录 22.95min**（18:01:29Z verified @ `.97` →
18:24:26Z demote @ `.97`，此前 max 14.48min）；②**OC wd 连击继续爬升**
31→**33**（defer 272→325 段内 +27），末拍 18:46:35Z cooling 161s cap 窗将
尽，本段仍未观测到退避到期 promote；③**轮换延续且 +1 新 roam**——
**#11 18:18:28Z coding-vm `.130`→`192.168.5.188` score 32 beats 458.5**
（coding-vm 第二条 LAN 面 roam；`.188` ×14→×24 +10、`.130` +4；imac peer
`.17` 仍主导 ×75→×91 +16）；roam 计数 10→**11**；④**同秒双 demote 本段未
再现**——取证瞬间 18:46:46Z 为**反向交叉**：FSaf demote @ `.49`（sel003→
hub_relay）与 JMrE promote verified @ `.97` 同秒（**JMrE 取证时恢复直连**，
live fresh hs=18:46:26Z）；coding-vm 双视直连稳；FSaf 与 OC 视 imac peer
（18:46:35Z demote @ `.226`）刚打回；⑤**`180.152` 漂移本段未再现**——imac
视零参选（×60 不变），OC 视仅 +2（×40），无新签名。

**增量**（08:57:32Z 起 9.82h；cp8 后增量窗约 47min）：imac 全窗 968 决策
（JMrE promote 195/demote 99/hold 121/defer 151/probe 71；FSaf promote 152/
demote 80/probe 99）；OC 全窗 869（wd **defer 325**/promote 58/demote 33；
imac peer promote 122/demote 63；coding-vm 117）。周期中位：imac JMrE
1.45min（n=99）/ FSaf 0.83min（n=79）；OC wd 2.17min（n=32）/ imac 2.13min
（n=62）/ coding-vm 8.85min（n=27）。cp8 后增量：imac 83 条（JMrE promote
12/demote 6/hold 4/probe 5/**defer 0**；FSaf promote 26/demote 14——
`:44249` ×35→×47 +12、`.49` ×56→×70 +14 翻转持续）；OC 102 条（wd defer
27/demote 2；imac peer promote 18/demote 9；coding-vm promote 14/demote 7，
cycles n=6 median 3.90min）。段内 bypass：imac JMrE +5/FSaf +13；OC imac
peer +9/coding-vm +7。切换闸：imac 532=526 flip+6 roam（零新）；OC 371=360
flip+**11 roam（+1，见挂起③）**。端点面集无新面；reason 全集不变，**无未知
新 reason**。

**实况快照**（18:46Z）：imac 视——**JMrE p2p_direct @ `.97` fresh（末拍
verified 恢复直连）**、coding-vm @ `192.168.5.188` fresh hs=18:44:56Z、FSaf
hub_relay（取证瞬间刚打回）；OC 视——coding-vm @ `.188` fresh（probe_failed
但 hs=18:46:27Z 新鲜）、wd hub_relay（defer 33 连击 cooling 161s）、imac peer
hub_relay。率事实（非判定）：JMrE 段内 demote ≈7.7 次/h（全窗 ≈10.1、修前
33 次/h）；wd 段内 2/47min ≈2.6 次/h。

## 03:3x 检查点（2026-11-16 03:36 CST / 2026-11-15T19:36:48Z 实测，巡检单 fliploop-fixcp10-1124）

**纯取证检查点 #10，窗龄 10.66h/24h——禁中途达标判定、禁外推**（与单据标题
一致）。openclaw SSH 首试即通，双机三文件齐取（raw
`fliploop-fix-window10-2026-11-15.txt`）。

**六项挂起观测点全部有数据答案**：①**defer=0 第五段延续**（全窗 151 冻结、
连击冻结 10，promote 整段未被退避拦截）；②**22.95min 纪录未破**（段内
cycle max 8.88min，全窗 max 不变）；③**`180.152` 重新参选**——cp9 零参选
后本段恢复（imac 视 +2 至 ×62、OC 视 +4 至 ×44），本段无漂移快照；④**同秒
签名本段双型均未再现**（历史三次：17:11:33Z 双 demote、17:59:17Z 双
demote、18:46:46Z 对向交叉）；⑤**OC wd 连击继续爬升** 33→**36**（defer
325→352 段内 +28，末拍 19:36:05Z cooling 569s，仍未观测到退避到期
promote）；⑥**翻转/轮换延续且 FSaf churn 加剧**——promote 32/demote 16
（约 cp9 段两倍），`:44249` ×47→×70（+23）；**imac 视 roam +2**：
19:22:21Z 与 19:36:38Z FSaf `.49`→`:44249` score 0（NAT 临时端口面经
SEL-002 正式切换，14min 内两次）；OC 视 roam +1（#12 19:24:49Z imac peer
`.226`→`.17` score 14 beats 44），`.17` 主导 +12 至 ×103。

**增量**（08:57:32Z 起 10.66h；cp9 后增量窗约 50min）：imac 全窗 1071 决策
（JMrE promote 211/demote 108/hold 130/defer 151/probe 76；FSaf promote 184/
demote 95/probe 116）；OC 全窗 959（wd **defer 352**/promote 64/demote 36；
imac peer promote 140/demote 71；coding-vm 129）。周期中位：imac JMrE
1.46min（n=108）/ FSaf 0.83min（n=94）；OC wd 2.15min（n=35）/ imac 2.13min
（n=70）/ coding-vm 8.37min（n=30）。cp9 后增量：imac 105 条（JMrE promote
17/demote 9/hold 9/probe 5/**defer 0**，cycles n=9 median 2.27min；FSaf
promote 32/demote 16）；OC 92 条（wd defer 28/demote 3；imac peer promote
18/demote 9；coding-vm promote 6/demote 3，cycles n=2 median 15.79min max
30.25min）。段内 bypass：imac JMrE +5/FSaf +16；OC imac peer +9/coding-vm
+3。切换闸：imac 606=598 flip+**8 roam（+2）**、OC 417=405 flip+**12 roam
（+1）**。端点面集无新面；reason 全集不变，**无未知新 reason**。

**实况快照**（19:36Z）：imac 视——coding-vm @ `192.168.5.188` fresh、
**FSaf p2p_direct @ `:44249` fresh hs=19:34:50Z**（roam 落 NAT 临时端口面）、
JMrE hub_relay（19:36:38Z hold_relay 恢复门抑制中）；OC 视——coding-vm @
`.188` fresh hs=19:36:39Z、**imac peer hub_relay（19:35:04Z verified @
`.17` 后 ~1.5min 内握手丢失、demote 决策尚未落盘的瞬态）**、wd hub_relay
（defer 36 连击 cooling 569s）。率事实（非判定）：JMrE 段内 demote
9/50min ≈10.8 次/h（cp9 ≈7.7 回弹、全窗 ≈10.1、修前 33 次/h）；wd 段内
3/50min ≈3.6 次/h。

## 04:2x 检查点（2026-11-16 04:23 CST / 2026-11-15T20:23:47Z 实测，巡检单 fliploop-fixcp11-1125）

**纯取证检查点 #11，窗龄 11.44h/24h——禁中途达标判定、禁外推**（与单据标题
一致）。openclaw SSH 首试即通，双机三文件齐取（raw
`fliploop-fix-window11-2026-11-15.txt`）。单据挂起背景三处引旧/错数据已按
实测校正记录：③「cp10 全段零参选」实为重新参选 +2/+4；⑤连击「28→31」系
cp8 旧数（cp10 末态 36）；⑦「cp10 仍零新 roam」实为 imac 视 +2/OC 视 +1。

**七项挂起观测点全部有数据答案**：①**defer=0 第六段延续**（全窗 151 冻结、
连击冻结 10；OC 视 imac peer defer ×1 系 cp10 前旧事件 12:56:24Z 非新增）；
②**22.95min 纪录未破**（段内 cycle max 5.97min；FSaf 171.90min 亦为
13:23:30Z→16:15:24Z 存量，cp10 后无 >30min 长周期）；③**`180.152` 低频参选
延续**（imac 视 +2 至 ×64、OC 视 +2 至 ×46）；④**同秒签名大爆发**——imac
视 47min 内 4 次双 demote（19:38:50Z/19:44:11Z/19:59:31Z/20:15:23Z，均
JMrE@`.97`+FSaf@`.49`）+ 5 次对向交叉（19:41:55Z/19:54:00Z/20:01:50Z FSaf
demote+JMrE verified；20:03:18Z/20:12:18Z JMrE demote+FSaf verified），OC
视另 3 次双 demote（19:50:12Z wd+imac@`.226`；19:55:49Z coding-vm@`.188`
+imac@`.226`；20:22:13Z coding-vm@`.130`+imac@`.226`——imac peer 为三对
公因子）；⑤**wd 连击 36→37→38 继续爬升**（defer 352→382 段内 +30）且
**观测到两次完整退避到期 promote 环**（cp6 模式复现）：退避倒数到期→候选表
attempt @`180.152`→verified @`.97`（probe Healthy）→sel003 ~62–65s 内打回
——环 A 19:44:50Z cooling 45s→19:45:52Z attempt→19:49:10Z verified→
19:50:12Z demote（62s）；环 B 20:04:41Z cooling 31s→20:05:43Z attempt→
20:07:59Z verified→~20:09:04Z demote（65s，由 cooling 算术倒推）；取证瞬间
第三窗临近到期（20:23:15Z conn 38 cooling 49s more）；⑥**JMrE 段内 demote
率 12.8 次/h**（7.7→10.8→12.8 持续爬升、修前 33 次/h；FSaf 段内 16/0.78h
≈20.4 次/h）；⑦**LAN 轮换延续且零新 roam**——OC 视 coding-vm `.130` +5/
`.188` +4（实况面已轮转 `.188`→`.130`）、FSaf `.49` +20 与 `:44249` +11
双活、双机视 roam 计数不变（imac 8/OC 12）。

**增量**（08:57:32Z 起 11.44h；cp10 后增量窗约 47min）：imac 全窗 1184 决策
（JMrE promote 231/demote 118/hold 142/defer 151/probe 81；FSaf promote 215/
demote 111/probe 135）；OC 全窗 1046（wd **defer 382**/promote 68/demote 38；
imac peer promote 151/demote 77；coding-vm promote 71/demote 36）。周期中
位：imac JMrE 1.47min（n=118）/ FSaf 0.82min（n=110）；OC wd 1.37min
（n=37）/ imac 2.18min（n=76）/ coding-vm 7.88min（n=35）。cp10 后增量：
imac 113 条（JMrE promote 20/demote 10/hold 12/probe 5/**defer 0**，cycles
n=10 median 1.49min；FSaf promote 31/demote 16，cycles n=15 median
0.78min）；OC 87 条（wd defer 30/promote 4/demote 2；imac peer promote 11/
demote 6，cycles n=5 median 6.43min；coding-vm promote 9/demote 5，cycles
n=4 median 1.78min）。段内 bypass：imac JMrE +5/FSaf +16；OC imac peer
+6/coding-vm +5。切换闸：imac 683=675 flip+**8 roam（零新）**、OC
456=444 flip+**12 roam（零新）**。端点面集无新面；reason 全集不变，**无未
知新 reason**（含各机 ×1 的 handshake-stale 稀有头，事件均发生在 cp10 前：
imac 10:39:50Z/OC 08:58:04Z）。

**实况快照**（20:23Z）：imac 视——coding-vm @ `192.168.5.188` fresh
hs=20:22:04Z、FSaf direct_pending @ `:44249` unprobed（末拍 20:23:47Z bypass
probe）、JMrE hub_relay（末拍 20:23:47Z sel003 demote @`.97`）；OC 视——
coding-vm @ `.130` fresh hs=20:23:16Z（较 cp10 的 `.188` 已轮转）、**imac
peer p2p_direct @ `.17` fresh hs=20:23:20Z（cp10 瞬态 hub_relay 已回归直
连）**、wd direct_pending @ `.97` unprobed（defer 38 连击第三窗临近到期）。
率事实（非判定）：wd 段内 demote 2/47min ≈2.6 次/h（JMrE/FSaf 见⑥）。

## 05:1x 检查点（2026-11-16 05:12 CST / 2026-11-15T21:12:11Z 实测，巡检单 fliploop-fixcp12-1126）

**纯取证检查点 #12，窗龄 12.24h/24h——禁中途达标判定、禁外推**（与单据标题
一致）。openclaw SSH 首试即通，双机三文件齐取（raw
`fliploop-fix-window12-2026-11-15.txt`）。

**七项挂起观测点全部有数据答案**：①**defer=0 第七段延续**（151 冻结、连击
冻结 10）；②**22.95min 纪录未破**（JMrE 段内 max 15.07min 系段内新高但低于
纪录；FSaf 171.90min 存量、无新 >30min 周期）；③**`180.152` 低频参选延续**
（imac 视 +2 至 ×66；OC 视 +3 至 ×49——全部为 wd 退避到期环的候选表尝试，
含 20:52:56Z 一次完整 verified）；④**同秒签名回落但仍高于基座**——imac 视
5 次/~48min（2 双 demote：20:44:33Z、**21:12:26Z 正落在取证瞬间**；3 对向
交叉），较 cp11 的 9 次/~47min 减半；**OC 视归零**（cp11 曾 3 次）；累计
imac 视 8 双 demote+9 交叉；⑤**wd 第三窗如约复现环且新增形态**——环 C：
到期→**memory face（last_direct）attempt @`.97`**→20:25:23Z verified→
**保持 10.00min（wd 全窗周期新纪录，cp11 为 8.98）**→20:35:23Z 经
**handshake-stale（非 sel003）**打回；环 D：20:49:35Z cooling 48s 到期→候选
表 attempt @`180.152`→20:52:56Z **verified @`180.152`**（公网面完整
verified）→20:54:00Z sel003 @`.97` 打回（决策层 verified `180.152` 时内核
已漂回 `.97`，下发≠内核再现）；环 E：21:08:10Z cooling 50s→21:09:17Z
attempt→21:11:34Z verified @`.97`→取证瞬间仍 direct fresh（hs=21:11:44Z），
至文件尾未见打回；连击 **38→39→40** 继续爬升（defer 382→404 段内 +22）；
⑥**JMrE 段内 demote 率 ≈13.6 次/h**（7.7→10.8→12.8→13.6 持续爬升、修前
33；FSaf ≈17.3 次/h 较 cp11 ≈20.4 略降）；⑦**coding-vm 全窗最稳段**（48min
仅 1 条 20:24:20Z verified @`.130`，直连全程保持，bypass 冻结 ×36、`.188`
冻结 ×34）；imac peer `.226` 重新参选 +4（末拍 21:12:39Z verified @`.226`
与内核 @`.17` 并存）；FSaf `.49` +14 与 `:44249` +12 双活；**双机视 roam
连续第二段零新增**（imac 8/OC 12）。

**增量**（08:57:32Z 起 12.24h；cp11 后增量窗约 48min）：imac 全窗 1283 决策
（JMrE promote 251/demote 128/hold 148/defer 151/probe 89；FSaf promote 241/
demote 125/probe 150）；OC 全窗 1128（wd **defer 404**/promote 74/demote 40；
imac peer promote 173/demote 88；coding-vm promote 72/demote 36）。周期中
位：imac JMrE 1.47min（n=128）/ FSaf 0.83min（n=124）；OC wd 1.37min
（n=39，max 10.00 新 wd 纪录）/ imac 2.18min（n=87）/ coding-vm 7.88min
（n=35）。cp11 后增量：imac 102 条（JMrE promote 20/demote 11/hold 6/probe
8/**defer 0**，cycles n=10 median 1.15min；FSaf promote 27/demote 14，cycles
n=14 median 1.18min）；OC 82 条（wd defer 22/promote 6/demote 2，cycles n=2
median 5.53min；imac peer promote 22/demote 11，cycles n=11 median 2.10min；
coding-vm promote 1）。段内 bypass：imac JMrE +8/FSaf +12；OC imac peer
+10/coding-vm +0（冻结）。切换闸：imac 753=745 flip+**8 roam（零新）**、OC
495=483 flip+**12 roam（零新）**。端点面集无新面；reason 头集不变（各 11
头），**无未知新 reason**；稀有 handshake-stale 头 OC wd 第二次触发
（20:35:23Z，首次 08:58:04Z；imac 仍为 10:39:50Z 单次）。

**实况快照**（21:12Z）：imac 视——coding-vm @ `192.168.5.188` fresh
hs=21:11:01Z、**JMrE+FSaf 于取证瞬间 21:12:26Z 同秒 sel003 双 demote 回
hub_relay**（endpoint 空）；OC 视——**三对全部 p2p_direct fresh**
（coding-vm @`.130` hs=21:11:57Z、wd @`.97` hs=21:11:44Z、imac peer @`.17`
hs=21:11:35Z），与 imac 视 21:12:26Z 双 demote 构成跨机视角分歧（imac 决策
层已判劣、OC 内核侧握手仍新鲜）。率事实（非判定）：wd 段内 demote 2/~48min
≈2.5 次/h（JMrE/FSaf 见⑥）。

## 06:0x 检查点（2026-11-16 06:00 CST / 2026-11-15T22:00:27Z 实测，巡检单 fliploop-fixcp13-1116）

**纯取证检查点 #13，窗龄 13.05h/24h——禁中途达标判定、禁外推**（单据预计
~13.2h，实测 13.05h 按实测校正）。openclaw SSH 首试即通，双机三文件齐取
（raw `fliploop-fix-window13-2026-11-15.txt`）。

**承接观测点逐项数据答案**：①**defer=0 第八段延续**（151 冻结、连击冻结
10）；②**22.95min 纪录未破**（JMrE 段内 max 11.82min 系段内新高；FSaf 无
新 >30min 周期，171.90min 存量）；③**`180.152` 参选面扩容**——OC 视 +4 至
×53（全部为 wd 到期环尝试，含两次完整 verified @`180.152`）；imac 视 +1 至
×67 且**末拍 JMrE 本体 probe @`180.152` waiting-handshake attempt 3**
（LIVE direct_pending @`180.152` probe_failed，公网面尝试中）；④**同秒签名
维持高位**——imac 视 7 次/~48min（3 双 demote：21:12:26Z【cp12 取证瞬间】/
21:14:39Z/21:22:04Z 均 JMrE@`.97`+FSaf@`.49`；4 对向交叉），与 cp12 的
5 次同带；**OC 视 +2 双 demote**（21:36:59Z coding-vm@`.130`+imac@`.226`；
21:49:08Z wd@`.97`+imac@`.226`——OC 视系列 5 次双 demote 全部以 imac peer
为公因子）；累计 imac 视 11 双+13 交叉；⑤**wd 到期环本段续三环**——环 E
终局：cp12 末 21:11:34Z verified @`.97` 保持 **2min08s**（新节奏变体，非
62–65s）→21:13:42Z sel003 打回；环 F：21:27:38Z cooling 64s 到期→attempt
@`180.152`→21:29:47Z verified @`180.152`→21:31:04Z sel003 @`.97` 打回
（~77s，verified 面与内核面漂移再现）；环 G：21:45:33Z cooling 31s 到期→
attempt→21:47:52Z verified @`180.152`→21:49:08Z sel003 @`.97` 打回
（~76s）；连击 **40→41→42→43** 继续爬升（defer 404→434 段内 +30），取证
瞬间 conn 43 cooling 223s；⑥**JMrE 段内 demote 率 ≈11.2 次/h**（13.6→11.2
回落、连续爬升中断；**FSaf ≈23.6 次/h 创段内新高**、churn 向 `:44249` +22
倾斜）；⑦**LAN 轮换与 roam**——OC 视 imac peer 现 **`.17`↔`.226` 翻转
链**：本段 5 轮「verified @`.17`→sel003 demote @`.226`」（21:23–21:58Z），
段首 21:16:54Z demote @`.226` 系 **handshake-stale（OC 第三次触发、首次落
在 imac peer）**；coding-vm 两轮 sel003 demote @`.130` 均经 memory face
@`.130` 恢复（cycles n=1 median 8.80min）；**roam 连续第三段零新增**（imac
8/OC 12）；FSaf `.49` +14 与 `:44249` +22 双活。

**增量**（08:57:32Z 起 13.05h；cp12 后增量窗约 48min）：imac 全窗 1399 决策
（JMrE promote 268/demote 136/hold 156/defer 151/probe 97；FSaf promote 277/
demote 143/probe 171）；OC 全窗 1207（wd **defer 434**/promote 78/demote 43
/probe 冻结 32；imac peer promote 187/demote 95；coding-vm promote 76/
demote 38）。周期中位：imac JMrE 1.47min（n=136）/ FSaf 0.81min（n=142）；
OC wd 1.32min（n=42，max 10.00 存量）/ imac 2.22min（n=94）/ coding-vm
8.80min（n=37）。cp12 后增量：imac 118 条（JMrE promote 17/demote 9/hold
8/probe 8/**defer 0**，cycles n=8 median 1.14min max 11.82min；FSaf promote
36/demote 19，cycles n=18 median 0.77min）；OC 80 条（wd defer 30/promote
4/demote 3；imac peer promote 15/demote 7，cycles n=7 median 3.12min；
coding-vm promote 4/demote 2，cycles n=1 median 8.80min）。段内 bypass：
imac JMrE +6/FSaf +18；OC imac peer +7/coding-vm +2。切换闸：imac
832=824 flip+**8 roam（零新）**、OC 529=517 flip+**12 roam（零新）**。端点
面集无新面；reason 头集不变（各 11 头），**无未知新 reason**。

**实况快照**（22:00Z）：imac 视——coding-vm @ `192.168.5.188` fresh
hs=22:00:00Z、**JMrE direct_pending @ `180.152.54.66` probe_failed**
（waiting-handshake attempt 3）、FSaf direct_pending @ `:44249` unprobed
（末拍 bypass probe）；OC 视——coding-vm @ `.130` fresh hs=21:59:22Z、imac
peer @ `.226` fresh hs=21:59:50Z（决策层末拍 verified @`.17`，下发≠内核并
存）、wd hub_relay（defer 43 连击 cooling 223s）。率事实（非判定）：wd 段内
demote 3/~48min ≈3.7 次/h（JMrE/FSaf 见⑥）。

## 07:0x 检查点（2026-11-16 07:07 CST / 2026-11-15T23:07:31Z 实测，巡检单 fliploop-fixcp14-1116）

**纯取证检查点 #14，窗龄 14.08h/24h——禁中途达标判定、禁外推**（单据预计
~14.1h 吻合；实测落在 07:0x，节名按实测；raw 文件自本单起按取证日命名：
`fliploop-fix-window14-2026-11-16.txt`）。openclaw SSH 首试即通，双机三文件
齐取。**本段出现全窗首批新端点面（均在 OC 视）**：①**imac ZT 面新端口
`10.147.19.17:22079`**（区别于惯常 `:51820`）——22:40:12Z 候选表 attempt→
22:41:13Z verified，23:01:02Z 再次 verified（promote/defer 计数 ×8、全动作
×14，FLIP-001 候选表纳管+探测管线照常工作）；②**coding-vm 公网面
`114.86.101.169:51820`**（对标 JMrE 的 `180.152`）——22:10:40Z sel003
demote @`.130`→hold ×2→22:14:05Z 候选表 attempt→**22:16:15Z verified
@公网面**，此后无 demote 记录而 LIVE 内核已回 `.130` fresh（新面上的下发≠
内核变体）。

**承接观测点逐项数据答案**：①**defer=0 第九段延续**（151 冻结、连击冻结
10；OC wd 连击 **43→44→45→46** 爬升，defer 434→470 段内 +36）；②
**22.95min 纪录未破**（JMrE 段内 max 7.03min；FSaf 无新 >30min，171.90min
存量）；③**`180.152` 走势**——imac 视 +2 至 ×69 且 cp13 的 JMrE
probe_failed 已消解（本段回归 `.97` 直连 fresh）；OC 视 +7 至 ×60（wd 到期
环尝试，含 2 次再 verified）；④**同秒签名高位延续**——imac 视 8 次/~67min
（3 双 demote：22:28:10Z/22:37:01Z/22:42:20Z；5 对向交叉），**OC 视 +1 双
demote**（22:10:40Z coding-vm@`.130`+imac@`.226`——OC 视 6 次双 demote 全
以 imac peer 为公因子）；累计 imac 视 14 双+18 交叉；⑤**wd 到期环本段四
环**（G 终局/H/I/J）：环 G 终局 verified @`180.152`→~93s sel003 打回；环
H 出现**等待握手 attempt-2/3 后 verified @`.97`**→62s 打回；环 I verified
@`180.152` 后**保持 4m33s 经 handshake-stale 打回**（OC 稀有头第 4 次）；
环 J 23:06:50Z verified @`180.152` 而 LIVE 内核 @`.97` fresh（下发≠内核），
至文件尾仍 direct；⑥**段内 demote 率双降**：JMrE ≈9.8 次/h（11.2→9.8）、
FSaf ≈19.7 次/h（23.6→19.7）；⑦**roam 破零**——imac 视 **+1**：
22:00:59Z FSaf `.49`→`:44249` score 0 beats 55（cp13 取证后 32s，第三次
SEL-002 正式切换落 NAT 临时端口面，终结连续三段零 roam）；OC 视仍零
（12）；LAN 轮换延续（OC 视 imac peer `.17` +15/`.226` +7、FSaf `.49` +19
与 `:44249` +24 双活、`:44249` 加速）。

**增量**（08:57:32Z 起 14.08h；cp13 后增量窗约 67min）：imac 全窗 1541 决策
（JMrE promote 289/demote 147/hold 168/defer 151/probe 105；FSaf promote
320/demote 165/probe 196）；OC 全窗 1332（wd **defer 470**/promote 86/
demote 46；imac peer promote 217/demote 111；coding-vm promote 78/demote
39）。周期中位：imac JMrE 1.48min（n=147）/ FSaf 0.80min（n=164）；OC wd
1.37min（n=45，max 10.00 存量）/ imac 2.17min（n=110）/ coding-vm 8.82min
（n=38）。cp13 后增量：imac 142 条（JMrE promote 21/demote 11/hold 12/probe
8/**defer 0**，cycles n=10 median 2.67min；FSaf promote 43/demote 22，cycles
n=22 median 0.78min）；OC 125 条（wd defer 36/promote 8/demote 3，cycles n=3
median 1.63min；imac peer promote 30/demote 16，cycles n=15 median 1.15min；
coding-vm promote 2/demote 1）。段内 bypass：imac JMrE +4/FSaf +21；OC imac
peer +15/coding-vm +0（冻结）。切换闸：imac 930=921 flip+**9 roam（+1）**、
OC 589=577 flip+**12 roam（零新）**。端点面 **+2 新面**（见上）；reason 头
集不变（各 11 头），**无未知新 reason**；handshake-stale OC 计数 +1 至 ×4
（22:49:11Z wd）。

**实况快照**（23:07Z）：imac 视——coding-vm @ `192.168.5.188` fresh
hs=23:07:17Z、**JMrE p2p_direct @ `.97` fresh hs=23:06:06Z**（cp13 公网面
尝试已消解回归直连）、FSaf hub_relay（末拍 23:07:49Z sel003 demote @`.49`）；
OC 视——coding-vm @ `.130` fresh hs=23:06:57Z（verified @公网面后内核已漂
回）、wd @ `.97` fresh hs=23:07:20Z（决策层 23:06:50Z verified @`180.152`，
下发≠内核并存）、imac peer hub_relay（末拍 23:07:53Z sel003 demote
@`.226`）。率事实（非判定）：wd 段内 demote 3/~67min ≈2.7 次/h（JMrE/FSaf
见⑥）。

## 07:5x 检查点（2026-11-16 07:54 CST / 2026-11-15T23:54:53Z 实测，巡检单 fliploop-fixcp15-1116）

**纯取证检查点 #15，窗龄 14.96h/24h——禁中途达标判定、禁外推**（单据预计
~15.1h，实测 14.96h 按实测校正；实测落 07:5x，节名按实测）。openclaw SSH
首试即通，双机三文件齐取（raw `fliploop-fix-window15-2026-11-16.txt`）。

**cp14 两个新面走向**：①**imac ZT 新端口 `:22079` 坐实**——promote/defer
计数 ×8→×21（+13）；**OC 视 roam #13：23:16:40Z imac peer
`.17:51820`→`.17:22079` score 14 beats 24.5，正式 SEL-002 切换落新端口
面**（本窗首个 roam 落新面）；imac peer 轮换链由 `.17↔.226` **移位为
`:22079↔.226`**（本段 6+ 轮「demote @`.226`→attempt+verified @`:22079`」；
`.17` promote 计数冻结 ×157、`.226` +4 至 ×48），LIVE direct_pending
@`:22079`；②**coding-vm 公网面 `114.86.101.169` 消散**——冻结 ×2 无后续，
coding-vm 内核稳定 `.130`（两轮 demote @`.130` 均经 memory face 恢复，
verified 23:16:40Z/23:48:19Z，其中 23:16:40Z→23:46:11Z 构成 **29.52min 近
30min 直连长保持**，为本窗除存量外最长 closed coding-vm 周期）。

**承接观测点逐项数据答案**：①**defer=0 第十段延续**（151 冻结、连击冻结
10；OC wd 连击 **46→47→48→49** 爬升，defer 470→497 段内 +27）；②
**22.95min 纪录未破**（JMrE 段内 max 8.92min；FSaf 无新 >30min）；③
**`180.152`**：imac 视 +5 至 ×74、OC 视 +3 至 ×63（wd 到期环 K/L 尝试，环
L verified @`180.152` 后 62s 打回、内核 @`.97`）；④**同秒签名回落**——imac
视 4 次/~47min（1 双 demote 23:34:11Z + 3 对向交叉，较 cp14 的 8 次回落）；
OC 视 +1 双 demote（23:47:13Z wd@`.97`+imac@`.226`——OC 视 7 次双 demote
仍全以 imac peer 为公因子）；累计 imac 视 15 双+21 交叉；⑤**wd 到期环本段
三环**（J 终局/K/L）：环 J 终局保持 **~4min12s** 后 sel003 打回；环 K 等待
握手 attempt-2 后 verified @`.97`→61s 打回；环 L verified @`180.152`→62s
@`.97` 打回（下发≠内核持续）；取证瞬间 conn 49 cooling 440s；⑥**率走
势**：JMrE ≈10.1 次/h（9.8→10.1 持平）、FSaf ≈16.5 次/h（19.7→16.5 回
落）；⑦**双机视 roam 各 +1**——imac 视 #10 23:49:14Z FSaf `.49`→`:44249`
score 0（第四次 SEL-002 落 NAT 临时端口面，现 10）、OC 视 #13（见上，现
13）；FSaf 末拍 probe @`:44249` waiting-handshake attempt 2（LIVE
probe_failed，NAT 面尝试中）。

**增量**（08:57:32Z 起 14.96h；cp14 后增量窗约 47min）：imac 全窗 1628 决策
（JMrE promote 302/demote 155/hold 176/defer 151/probe 110；FSaf promote
342/demote 177/probe 215）；OC 全窗 1420（wd **defer 497**/promote 90/
demote 49；imac peer promote 234/demote 119；coding-vm promote 82/demote
41）。周期中位：imac JMrE 1.50min（n=155）/ FSaf 0.82min（n=176）；OC wd
1.32min（n=48，max 10.00 存量）/ imac 2.17min（n=110）/ coding-vm 9.38min
（n=40，本段出现 29.52min 长周期）。cp14 后增量：imac 88 条（JMrE promote
13/demote 8/hold 8/probe 5/**defer 0**，cycles n=7 median 2.20min；FSaf
promote 22/demote 13，cycles n=12 median 2.23min）；OC 89 条（wd defer 27/
promote 4/demote 3，cycles n=2 median 1.02min；imac peer promote 17/demote
9，cycles n=8 median 1.67min；coding-vm promote 4/demote 2，cycles n=1
median 29.52min）。段内 bypass：imac JMrE +3/FSaf +10；OC imac peer +9/
coding-vm +2。切换闸：imac 986=976 flip+**10 roam（+1）**、OC 628=615 flip+
**13 roam（+1）**。端点面集 **+0 新面**（cp14 两新面一坐实一消散，无第三新
面）；reason 头集不变（各 11 头），**无未知新 reason**（handshake-stale 计
数不变：OC ×4/imac ×1）。

**实况快照**（23:55Z）：imac 视——coding-vm @ `192.168.5.188` fresh
hs=23:54:15Z、JMrE hub_relay（23:55:14Z hold_relay 恢复门抑制中）、**FSaf
direct_pending @ `:44249` probe_failed**（waiting-handshake attempt 2）；OC
视——coding-vm @ `.130` fresh hs=23:53:17Z、**imac peer direct_pending @
`:22079` unprobed**（roam #13 已落新端口面）、wd hub_relay（defer 49 连击
cooling 440s）。率事实（非判定）：wd 段内 demote 3/~47min ≈3.8 次/h
（JMrE/FSaf 见⑥）。

## 08:4x 检查点（2026-11-16 08:43 CST / 2026-11-16T00:43:08Z 实测，巡检单 fliploop-fixcp16-1116）

**纯取证检查点 #16，窗龄 15.76h/24h——禁中途达标判定、禁外推**（单据预计
~16h，实测 15.76h 按实测校正；实测落 08:4x，节名按实测）。openclaw SSH
首试即通，双机三文件齐取（raw `fliploop-fix-window16-2026-11-16.txt`）。

**cp15 面走向**：①**`:22079` 持续坐实**——promote ×21→×36（+15）；轮换链
`:22079↔.226` 延续（本段 7 次 verified @`:22079` vs 7 次 sel003 demote
@`.226`，另有 2 次 demote @`:22079` 经 3 轮尝试耗尽）；`.17` promote 冻结
×157、`.226` promote 冻结 ×48（仅剩 demote）；LIVE OC 内核 @`.226` fresh vs
末拍 promote @`:22079`（下发≠内核）；②**coding-vm 内核本段迁移 `.130`→
`.188`**——OC 视 roam #14 00:24:01Z `.130`→`.188` score 7 beats 14（第三次
`.130`→`.188` LAN 面 roam，前两次 16:22:22Z/18:18:28Z 均回退，**本次取证瞬
间保持**：00:31:52Z+00:35:04Z 两次 verified @`.188`、LIVE fresh
hs=00:42:06Z）；`.188` ×34→×38、`.130` 冻结 ×46；③`114.86.101.169` 第三段
休眠冻结 ×2（消散保持）；④cp15 FSaf `:44249` probe_failed **消解**——内核
回 `.49`，`:44249` 仍 +7 参选计数，无新 roam。

**承接观测点逐项数据答案**：①**defer=0 第十一段延续**（151 冻结、连击冻结
10；OC wd 连击 **49→50→51** 爬升，defer 497→529 段内 +32）；②**22.95min
纪录未破**（JMrE 段内 max 13.73min——cp12 的 15.07 以来段内新高；FSaf 段内
max 6.05 无新 >30min）；③**`180.152` imac 视首次零参选段**（×74 冻结
+0；OC 视 +3 至 ×66——wd 环 M/O 尝试，**环 O 取证瞬间 verified @`180.152`
fresh probe Healthy**、内核 @`.97` fresh 下发≠内核）；④**同秒签名双 demote
归零**：imac 视 8 次全对向交叉/~48min（5 次 FSaf-d+JMrE-p + 3 次
JMrE-d+FSaf-p，双 demote 本段绝迹）；OC 视 +1 双 demote 00:29:45Z
（coding-vm@`.188` sel003 + imac@`:22079` 3 轮耗尽——**OC 视 8 双全含 imac
peer 公因子**；累计 imac 视 15 双+29 交叉）；⑤**wd 到期环本段两闭一飞**，
**新增形态「3 轮尝试耗尽」**（非 sel003、非 handshake-stale，头集内既有
head 的新用法）：环 M 00:02:34Z attempt @`180.152`→等待握手 attempt 2/3→
00:05:44Z **pending-attempts-exhausted demote @`180.152`（保持 ~3m10s）**
→conn 50；环 N 00:20:51Z attempt @`.97`→同形态 00:24:01Z 打回（~3m10s）
→conn 51；环 O 在飞 00:39:30Z attempt @`180.152`→00:40:33Z verified
@`180.152` fresh；⑥**率**：JMrE ≈7.5 次/h（10.1→7.5 续降）、FSaf ≈17.5
次/h（16.5→17.5 微升）、wd ≈2.5 次/h（3.8→2.5 降）；⑦**roam 双机
+0/+1**——imac 视零新增（10 持平）、OC 视 #14（现 14，本窗第二个 roam 落
新迁移面）。

**增量**（08:57:32Z 起 15.76h；cp15 后增量窗约 48min，含 23:54:53Z 边界秒
事件）：imac 全窗 1715 决策（JMrE promote 316/demote 161/hold 180/defer
151/probe 117；FSaf promote 362/demote 191/probe 237）；OC 全窗 1509（wd
**defer 529**/promote 94/demote 51/probe 41；imac peer promote 249/demote
127；coding-vm promote 86/demote 43）。周期中位：imac JMrE 1.52min（n=161，
max 22.95 存量）/ FSaf 0.83min（n=190，max 171.90 存量）；OC wd 1.50min
（n=50，max 10.00 存量）/ imac 2.13min（n=126，max 86.15）/ coding-vm
9.38min（n=42，max 105.80）。cp15 后增量：imac 89 条（JMrE promote
14/demote 6/hold 5/probe 7/**defer 0**，cycles n=6 median 2.62min max
13.73；FSaf promote 20/demote 14，cycles n=13 median 2.22min）；OC 92 条
（wd defer 33/promote 4/demote 2，cycles n=2 **均 3.17min**；imac peer
promote 16/demote 8，cycles n=8 median 2.12min；coding-vm promote 4/demote
2，cycles n=1 median 1.05min）。段内 bypass：imac JMrE +7/FSaf +6；OC imac
peer +6/coding-vm +2。切换闸：imac 1040=1030 flip+**10 roam（+0）**、OC
664=650 flip+**14 roam（+1）**。端点面集 **+0 新面**（两机面集与 cp15 完全
一致）；reason 头集不变（各 11 头），**无未知新 reason**（handshake-stale
OC ×4/imac ×1 不变；wd 到期环 demote 首用 pending-attempts-exhausted 头，
系既有 head 新用法非新头）。

**实况快照**（00:43Z）：imac 视——coding-vm @ `192.168.5.188` fresh
hs=00:41:14Z（roam #14 后 LAN 面保持）、JMrE @ `.97` direct fresh
hs=00:41:38Z、FSaf direct_pending @ `.49` unprobed（`:44249` 尝试消解回
`.49`）；OC 视——coding-vm @ `.188` fresh hs=00:42:06Z、**wd @ `.97` fresh
hs=00:42:25Z**（00:40:33Z 刚 verified @`180.152` 下发≠内核、环 O 直连保持
中）、**imac peer @ `.226` fresh hs=00:42:24Z**（末拍 promote @`:22079`
下发≠内核）。率事实（非判定）：wd 段内 demote 2/~48min ≈2.5 次/h
（JMrE/FSaf 见⑥）。

## 09:3x 检查点（2026-11-16 09:34 CST / 2026-11-16T01:34:21Z 实测，巡检单 fliploop-fixcp17-1116）

**纯取证检查点 #17，窗龄 16.61h/24h——禁中途达标判定、禁外推**（单据预计
~17h，实测 16.61h 按实测校正；节名按实测 09:3x）。**imac 侧本单缺测：imac
主机失联**——scp 两连失败（connection closed）、SSH「No route to host」、
LAN ping 100% 丢包、收尾复探仍不通；OC 视钉住失联起点 **00:47:17Z imac
peer handshake-stale demote @`.17:51820`**（cp16 取证后 ~4min）。cp16 文件
（00:43:08Z 取证）仍为最新 imac 侧数据。openclaw SSH 首试即通，oc 三文件齐
取（raw `fliploop-fix-window17-2026-11-16.txt`，**OC 单侧**）。

**头条实况（01:34Z OC 视）**：仅 coding-vm @ `.188` p2p_direct fresh
hs=01:32:17Z；**wd hub_relay**（defer conn 54 cooling 126s）；**imac peer
hub_relay**（endpoint 空、hs null——下线面）。

**imac peer 耗尽环（主机下线行为，OC 视）**：00:47:17Z handshake-stale
demote @`.17:51820`（**OC 第 5 次 stale**、imac peer 第 2 次）→00:48:18Z
memory face attempt @`.17` + FLIP-001 bypass probe @`:22079`→等待握手
attempt 2/3→00:51:29Z 3 轮耗尽 demote @`.17`；此后 **9 轮完整耗尽环
@`:22079`**（每轮 attempt→等待握手 attempt 2/3→exhausted 打回，间隔
~4m10s：00:55:46/01:00:04/01:04:29/01:08:43/01:12:56/01:17:13/01:21:25/
01:25:45/01:29:59/01:34:19Z——末拍即取证瞬间仍打回）；**全段零 verified**；
段内 cycles n=11 median 3.22min（3.07–3.32 全为耗尽环）；`:22079` promote
×36→×46（+10 全为耗尽尝试）、`.17` ×157→×158（+1 memory face）、`.226`
冻结 ×48（本段零事件）——**`:22079↔.226` 轮换链随失联死亡**；**耗尽环未
触发 FLIP-002 defer**（imac peer 全窗 defer 仍 1 pre-cp10，事实记录）。

**承接观测点逐项数据答案（OC 单侧）**：①**defer 链**：imac 视缺测；OC wd
连击 **51→52→53→54**（defer 529→563 段内 +34），取证瞬间 cooling 126s；②
22.95min 纪录：imac 视缺测（存量 22.95 不变）；OC 视 imac peer 段内 max
3.32min；③**`180.152`**：imac 视缺测（×74 冻结）；OC 视 +3 至 ×69（wd 环
P/Q 尝试）；④**同秒签名**：OC 视 **+1 双 demote**（01:21:25Z wd@`180.152`
exhausted + imac@`:22079` exhausted——**OC 第 9 双，9 双全含 imac peer**）
+ **10 次交叉全以 imac-demote 为一端**（wd-defer ×8/wd-promote ×1/coding-
vm-promote ×1——失联后 ~4m10s 耗尽环与 wd ~63s defer 链同秒共振）；imac
视缺测；⑤**wd 到期环三环**（O 终局/P/Q）：环 O 终局——cp16 取证瞬间
verified @`180.152` fresh 直连保持 ~4.5min 后 00:45:00Z sel003 demote
@`.97` 打回内核面→conn 52；环 P 01:00:04Z attempt @`180.152`→01:02:16Z
verified→**01:03:17Z sel003 demote @`.97`（61s，下发≠内核）**→conn 53；
环 Q 01:18:21Z attempt @`180.152`→等待握手 2/3→01:21:25Z
pending-attempts-exhausted @`180.152`→conn 54；取证瞬间 wd hub_relay；⑥
**率（OC 视）**：wd ≈3.5 次/h（2.5→3.5 微升、3 demote：sel003 ×2 @`.97` +
exhausted ×1 @`180.152`）；imac peer 12 demote ≈14 次/h（**下线耗尽环驱动
非健康度翻转**）；coding-vm 1；⑦**面走向**：`:22079` +10 全为耗尽尝试零
verified；**coding-vm `.188` 迁移保持**——cp16 的 00:35:04Z open cycle 于
00:46:11Z sel003 demote @`.188` 闭合（11.12min）→00:47:17Z memory face
attempt→00:48:18Z verified @`.188`→open 至取证 **44min 直连保持在飞**
（LIVE fresh hs=01:32:17Z）；`.188` ×40（+2）、`.130` ×46 冻结、
`114.86.101.169` **第四段休眠** ×2；**roam 双机 +0**（OC 14 持平；imac 视
缺测）。

**增量**（08:57:32Z 起 16.61h；cp16 后增量窗约 51min，**OC 单侧**）：OC
全窗 1606 决策（wd **defer 563**/promote 97/demote 54/probe 44/hold 89；
imac peer promote 260/demote 139/probe 164；coding-vm promote 88/demote
44/probe 46）。周期中位：OC wd 1.63min（n=53，max 10.00 存量）/ imac peer
2.27min（n=138，max 86.15）/ coding-vm 9.90min（n=43，max 105.80）。cp16
后增量：OC 97 条（wd defer 34/hold 4/demote 3/promote 3/probe 3，cycles
n=2 median 2.04min；imac peer probe 23/demote 12/promote 11，cycles n=11
median 3.22min；coding-vm promote 2/demote 1/probe 1，闭环 1 个 11.12min+
open 1 个）。段内 bypass：imac peer +1/coding-vm +1。切换闸：OC
696=682 flip+**14 roam（+0）**。端点面集 **+0 新面**（9 面不变）；reason
头集不变（11 头），**无未知新 reason**（handshake-stale OC ×4→**×5**：
00:47:17Z imac peer）。

**文件总行数** OC 3990；imac 侧自 cp16 文件（4122 行）后无新数据可取。

## 12:5x 检查点（2026-11-16 12:50 CST / 2026-11-16T04:50:15Z 实测，巡检单 fliploop-fixcp18-1116）

**纯取证检查点 #18，窗龄 19.88h/24h——禁中途达标判定、禁外推**（单据预计
~17.5h，实测 19.88h 按实测校正；节名按实测 12:5x；距窗满 ~4.12h）。
**imac 侧仍失联**：开单探测 LAN ping 100% 丢包、SSH「No route to host」；
单据所列 ping `10.240.0.3` 系**单据勘误**（imac meshlet 虚 IP 为
`10.240.0.7`，`10.240.0.3` 为他机——其 ping 通但 imac key SSH 被拒）；imac
存活以 OC 视判定——**SINCE_CP17 imac peer 45 次 demote 全为
pending-attempts-exhausted、零 verified/零新 stale/零 memory face**，失联
自 00:47:17Z 起至取证瞬间 **≥4h04m 持续中**，缺口按单据如实留空不补拍、
不反复重试 scp。openclaw SSH 首试即通，oc 三文件齐取（raw
`fliploop-fix-window18-2026-11-16.txt`，**OC 单侧**）。

**头条实况（04:51Z OC 视）**：coding-vm @ `.130` p2p_direct fresh
hs=04:51:02Z（roam #17 04:37:15Z **迁回 `.130`** 保持中）；wd hub_relay
（defer conn 64 cooling 267s）；**imac peer direct_pending @`:22079`
probe_failed**（取证瞬间 waiting-hs attempt 2，握手未完成）。

**wd 到期环本段十环**（conn 54→64，defer 563→682 +119，连击 54→64）：
R 环 verified @`.97` 62s 打回；S 环 attempt @`180.152` 后**握手落 `.97`
verified**（180.152 尝试、.97 完成握手）68s 打回；T/AA 环 verified
@`180.152` 后 sel003 @`.97` 打回（下发≠内核，63s/82s）；**U 环
verified→demote 14.00min——wd 保持时长新纪录（原 10.00）**；V 环 69s；W 环
memory face @`.97` verified 4.10min 保持；X/Y/Z 三环 3 轮尝试耗尽形态
（X 环 attempt 3 落 `.97`）。wd 段内 demote 10（sel003 ×7 + exhausted ×3）
≈3.0 次/h（3.5→3.0）。`180.152` wd 视 +12 至 ×81、`.97` +5 至 ×33。

**coding-vm 本段**：cp17 的 open cycle 00:48:18Z verified @`.188` 于
02:43:12Z sel003 闭合——**114.90min coding-vm 闭环新纪录（原 105.80）**；
此后 `.188` 内 5 环 sel003 全部经 memory face ~62s 恢复（re-verified
02:45:20/03:29:30/03:37:11/03:45:15/04:10:57Z），段内闭环 41.82/5.60/5.88/
22.38min（n=4 median 14.13）；04:37:15Z **roam #17 `.188`→`.130`** 落定，
LIVE fresh @`.130`。**roam 本段 +3 全为 coding-vm `.188↔.130` 摇摆**（#15
01:36:30Z `.188`→`.130`、#16 01:52:40Z 回 `.188`、#17 04:37:15Z 再落
`.130` 保持），OC 视 14→**17**（imac 视缺测）。`.188` ×50（+10）、`.130`
promote 计数 ×46 冻结（roam 落面，agent 决策层零 promote）；
`114.86.101.169` **第五段休眠** ×2。

**同秒签名失联期未消失（单据预期被证伪）**：本段 OC 视 **7 次双 demote**
（01:38:47/02:43:12/03:04:31/03:26:03/03:35:06/04:23:17/04:40:46Z——**全部
以 imac@`:22079` exhausted 为公因子**）+ 38 次交叉（全以 imac-demote 为一
端：wd-defer ×33+、wd-promote、coding-vm 对）；OC 累计 **16 双全含 imac
peer**。机理事实：双 demote 持续系 **OC 侧决策层每 ~4m10s 打回 imac 面尝
试与 wd/coding-vm demote 同秒共振**——签名源于 OC 决策层节奏而非 imac 主
机行为。22.95min 纪录 imac 视缺测（存量不变）。

**增量**（08:57:32Z 起 19.88h；cp17 后增量窗约 3h17min，**OC 单侧**）：OC
全窗 1976 决策（wd **defer 682**/promote 114/demote 64/probe 51/hold 103；
imac peer promote 306/demote 184/probe 255；coding-vm promote 98/demote
49/probe 51）。周期中位：OC wd 1.63min（n=63，**max 14.00 新纪录**）/ imac
peer 3.17min（n=183，max 86.15 存量）/ coding-vm 9.93min（n=48，**max
114.90 新纪录**）。cp17 后增量：OC 370 条（wd defer 119/hold 14/demote
10/promote 17/probe 7，cycles n=10 median 2.25min max 14.00；imac peer
probe 91/demote 45/promote 46，cycles n=45 median 3.23min 全耗尽环；
coding-vm promote 10/demote 5/probe 5/hold 1，cycles n=4 median 14.13min
max 41.82）。段内 bypass：imac peer **+0 冻结 118**（面 unhealthy 不放
行）、coding-vm +6 至 48。**耗尽环仍零 defer**（imac peer 全窗 defer 仍 1
pre-cp10）。切换闸：OC 832=815 flip+**17 roam（+3）**。端点面集 **+0 新
面**（9 面不变）；reason 头集不变（11 头），**无未知新 reason**（stale OC
×5 不变无新拍）。

**文件总行数** OC 4360；imac 侧停格 cp16 文件（4122 行），缺口
00:47:17Z→恢复点留空。

## 13:4x 检查点（2026-11-16 13:42 CST / 2026-11-16T05:42:23Z 实测，巡检单 fliploop-fixcp19-1116）

**纯取证检查点 #19，窗龄 20.75h/24h——禁中途达标判定、禁外推**（与单据开
单口径 13:39/05:39 吻合；节名按实测 13:4x；距窗满 ~3.25h）。**imac 侧仍失
联（第三个 OC 单侧段）**：按单据 ping 一次+SSH 一次即止——meshlet 虚 IP
`10.240.0.7` ping 100% 丢包、LAN `192.168.5.117` ping 无响应、SSH「No
route to host」；失联 00:47:17Z→取证 **≥4h55m 持续中**，缺口留空不补拍。
openclaw SSH 首试即通，oc 三文件齐取（raw
`fliploop-fix-window19-2026-11-16.txt`，**OC 单侧**）。

**头条实况（05:42Z OC 视）**：coding-vm @ `.130` p2p_direct fresh
hs=05:40:10Z（roam #17 04:37:15Z 起 `.130` 保持 65min+）；wd hub_relay
（**取证瞬间 05:42:15Z sel003 demote @`.97`**——AD 环 65s 打回）；imac
peer direct_pending @`:22079` unprobed（耗尽环延续）。

**coding-vm 首例全静默段**：SINCE_CP18 决策事件 **0 条**（全窗计数与 cp18
完全一致 promote 98/demote 49/probe 51/hold 7）；`.188` ×50/`.130` ×46/
`114.86.101.169` ×2 全冻结（**第六段休眠**）；**`.188↔.130` roam 摇摆停
歇**（roam OC 视 17 持平 +0）。

**承接观测点逐项数据答案（OC 单侧）**：①**imac 未恢复**——失联 ≥4h55m
持续；imac peer 段内 12 demote **全 exhausted**、13 promote 尝试
（`:22079` ×90→×101 +11、`.226` +1 至 ×51——某轮尝试落 `.226`），cycles
n=12 median 3.24min（3.12–3.38 全耗尽环），**defer 仍 1（耗尽环零
defer）、bypass 仍冻结 118**；②**wd 连击 64→66**（defer 682→708 +26）；
③**wd 到期环三环**（AB/AC/AD）全 attempt @`180.152`：AB 环 verified
@`180.152`→67s sel003 @`.97` 打回（下发≠内核）；AC 环等待握手 attempt 2/3
（attempt 3 落 `.97`）→**05:17:25Z verified @`.97`→05:24:47Z sel003（7.37min
保持）**；AD 环 verified @`180.152`→65s @`.97` 打回（取证瞬间）；无新纪录
（14.00 存量）；wd 段内 demote 3 全 sel003 @`.97` ≈3.5 次/h（3.0→3.5）；
`180.152` +5 至 ×86、`.97` +1 至 ×34；④**同秒双 demote 本段归零**（0 次
——OC 累计 16 双不变，全含 imac peer）+ 12 次交叉仍全以 imac-demote 为一
端（wd-defer ×7/wd-promote ×3/wd-demote+imac-promote ×2）——交叉碰撞延
续（imac 耗尽环与 wd defer/demote 节奏），本段同秒配对未落成双而已；⑤
22.95min 纪录 imac 视缺测（存量不变）。

**增量**（08:57:32Z 起 20.75h；cp18 后增量窗约 52min，**OC 单侧**）：OC
全窗 2064 决策（wd **defer 708**/promote 120/demote 67/probe 53/hold 107；
imac peer promote 318/demote 196/probe 278；coding-vm promote 98/demote
49/probe 51）。周期中位：OC wd 1.50min（n=66，max 14.00 存量）/ imac peer
3.18min（n=195，max 86.15 存量）/ coding-vm 9.93min（n=48，max 114.90 存
量）。cp18 后增量：OC 92 条（wd defer 28/hold 4/demote 3/promote 6/probe
2，cycles n=3 median 1.12min max 7.37；imac peer probe 24/promote 13/demote
12，cycles n=12 median 3.24min；coding-vm 0）。段内 bypass **双冻结**（imac
118/coding-vm 48 均 +0）。切换闸：OC 865=848 flip+**17 roam（+0）**。端点
面集 **+0 新面**（9 面不变）；reason 头集不变（11 头），**无未知新
reason**（stale OC ×5 不变无新拍）。

**文件总行数** OC 4448；imac 侧停格 cp16 文件（4122 行），缺口
00:47:17Z→恢复点留空。

## 14:3x 检查点（2026-11-16 14:33 CST / 2026-11-16T06:33:53Z 实测，巡检单 fliploop-fixcp20-1116）

**纯取证检查点 #20，窗龄 21.61h/24h——禁中途达标判定、禁外推**（与单据开
单口径 14:32/06:32 吻合；节名按实测 14:3x；距窗满 ~2.39h）。**imac 侧仍失
联（第四个 OC 单侧段）**：ping 一次+SSH 一次即止——vIP `10.240.0.7` ping
丢包、SSH「No route to host」；失联 00:47:17Z→取证 **≥5h46m 持续中**，缺
口留空不补拍。openclaw SSH 首试即通，oc 三文件齐取（raw
`fliploop-fix-window20-2026-11-16.txt`，**OC 单侧**）。

**头条实况（06:33Z OC 视）**：coding-vm @ `.130` p2p_direct fresh
hs=06:33:07Z（roam #17 起 `.130` 保持 **116min+**，peers 读取瞬间
probe_failed 系探测在飞瞬态）；wd hub_relay（defer conn 69 cooling 327s，
**与 imac promote attempt 同秒 06:33:25Z 取证瞬间**）；imac peer
direct_pending @`:22079` unprobed。

**coding-vm 连续第二段全静默**：SINCE_CP19 决策事件 **0 条**（全窗计数与
cp19 完全一致）；`.188↔.130` 摇摆持续停歇（roam 17 持平）；
`114.86.101.169` **第七段休眠** ×2。

**承接观测点逐项数据答案（OC 单侧）**：①**imac 未恢复**——失联 ≥5h46m；
imac peer 12 demote 全 exhausted、12 promote 尝试全 @`:22079`
（×101→×113 +12、`.226` ×51 持平），cycles n=11 median 3.17min（3.12–3.37
全耗尽环），**defer 仍 1/bypass 双冻结**；②**wd 连击 66→69**（defer
708→741 +33）；③**wd 到期环两环**：AE 环 05:58:13Z attempt
@`180.152`→等握手 2/3→06:01:21Z **exhausted demote @`.97`**（X/Y/Z 同款变
体）→conn 67；AF 环 06:17:17Z **候选表 attempt @`.97`**→等握手 2→
06:19:28Z verified @`.97`→06:23:52Z sel003（**4.40min 保持**）→hold ×2→
conn 69；无新纪录（14.00 存量）；wd 段内 demote 2（exhausted ×1+sel003
×1）≈2.4 次/h（3.5→2.4 降）；`180.152` +1 至 ×87、`.97` +2 至 ×36；④**
同秒签名 +1 双**（06:23:52Z wd sel003 @`.97` + imac exhausted
@`:22079`——**OC 累计 17 双全含 imac peer**）+ 11 交叉全 imac-demote 一端
（wd-defer ×8/wd-promote ×2/imac-demote+wd-promote ×1）；⑤22.95min 纪录
imac 视缺测（存量不变）。

**增量**（08:57:32Z 起 21.61h；cp19 后增量窗约 51min，**OC 单侧**）：OC
全窗 2157 决策（wd **defer 741**/promote 123/demote 69/probe 56/hold 111；
imac peer promote 330/demote 208/probe 302；coding-vm promote 98/demote
49/probe 51）。周期中位：OC wd 1.88min（n=68，max 14.00 存量）/ imac peer
3.18min（n=207，max 86.15 存量）/ coding-vm 9.93min（n=48，max 114.90 存
量）。cp19 后增量：OC 93 条（wd defer 33/hold 4/demote 2/promote 3/probe
3，cycles n=2 median 3.77min max 4.40；imac peer probe 24/demote 12/promote
12，cycles n=11 median 3.17min；coding-vm 0）。段内 bypass **双冻结**（imac
118/coding-vm 48 均 +0）。切换闸：OC 894=877 flip+**17 roam（+0）**。端点
面集 **+0 新面**（9 面不变）；reason 头集不变（11 头），**无未知新
reason**（stale OC ×5 不变无新拍）。

**文件总行数** OC 4541；imac 侧停格 cp16 文件（4122 行），缺口
00:47:17Z→恢复点留空。

### 修后窗检查点 #21（2026-11-16 15:28:18 CST / 07:28:18Z 实测取证）

窗龄 22h30m46s（**22.51h/24h**，单据预计 ~22.5h 吻合）；cp20 取证
06:33:53Z→本段增量 ~54min。**纯取证，禁中途判定禁外推**（率/中位一律
记「率事实非判定」；窗满四项判定 16:57:32 CST 后另单）。

**imac 失联复核**：第五个 OC 单侧段——vIP 10.240.0.7 ping 100% 丢包 +
LAN 192.168.5.117 无响应 + SSH No route to host（ping/SSH 各一次即止）；
失联 00:47:17Z 起 **≥6h41m 持续中**，缺口留空不补拍。OC SSH 首试即通，
三文件齐取（agent-decisions 1634057B / switch-events 678026B / peers
667B）。

**实况（07:28–07:29Z）**：coding-vm p2p_direct @`.130` fresh
hs=07:28:22Z（roam #17 起 `.130` 保持 **171min+**）；wd hub_relay
（conn72 cooling 708s @末条 07:29:34Z）；imac peer direct_pending
@`:22079` unprobed。

**coding-vm 连续第三段全静默**：SINCE_CP20 = 0 条（全窗计数与 cp20 逐项
相同 promote 98/demote 49/probe 51/hold 7）；`.188↔.130` 摇摆停歇
（roam 17 持平）；`114.86.101.169` 第七段休眠延续。

**cp20 后增量（~54min，OC 98 条）**：
- wd defer 31/hold 4/demote 3/promote 5/probe 3，cycles n=3 median
  3.10min（2.35–6.37）；
- imac peer probe 26/demote 13/promote 13，cycles n=12 median 3.20min
  （3.07–3.45 全耗尽环）；
- coding-vm 0。

**wd 到期环三环（AG/AH/AI）；连击 69→72（defer 741→772 +31）**：
- AG：06:39:49 候选表 attempt @`180.152` → 等握手 2/3 → 06:42:55
  **exhausted @`180.152`**（conn70）；
- AH：06:58:09 attempt @`180.152` → 等握手 2 → 07:00:27 verified
  @`180.152` → 07:06:49 sel003 @`.97`（**6.37min 保持**，落双秒）；
- AI：07:22:55 **memory face/last_direct attempt @`.97`** → 07:24:01
  verified @`.97` → 07:26:22 sel003 @`.97`（**2.35min 保持**，conn72）。
- 段内 demote 3（exhausted ×1 @`180.152` + sel003 ×2 @`.97`）≈3.2/h
  （2.4→3.2，率事实非判定）；`180.152` +3 至 ×90、`.97` +2 至 ×38；
  无新纪录（14.00 存量保持）。

**imac peer 耗尽环**：13 demote 全 exhausted + 13 promote 全
@`:22079`（×113→×126），环节奏 ~4min 不变；`.17` ×158/`.226`
×51 双冻结；**defer 仍 1、bypass 双冻结**（imac 118/coding-vm 48 +0）。

**同秒签名 +1 双**（07:06:49 wd sel003 @`.97` + imac exhausted
@`:22079`，**OC 累计 18 双全含 imac peer**）+10 交叉（含双秒共 11 对，
全 imac-demote 一端：wd-defer ×7/wd-promote ×2/wd-demote ×1）。

切换闸：OC 928=911 flip+**17 roam（+0）**。端点面集 **+0 新面**（9 面
不变）；reason 头集不变（系列口径 11 头，OC 可见 10 头），**无未知新
reason**（stale OC ×5 不变无新拍）。

**文件总行数** OC 4639；imac 侧停格 cp16 文件（4122 行），缺口
00:47:17Z→恢复点留空。raw 见 fliploop-fix-window21-2026-11-16.txt。

## FLIP-001：端点候选表纳管 roaming（commit f99a7ef）

实现（`apps/agent/src/candidates.rs` 新建 431 行）：

- `CandidateTable` 三来源：`Config`（服务端权威）/ `Roaming`（内核 wg dump 观测）/
  `Discovered`（探测证实）；Roaming 项 TTL 1800s，Config 不过期。
- `sync_config`：服务端候选权威写入；Roaming 面被服务端确认即升级 Config。
- `observe_roaming`：内核现况面进表（新面返回 true 触发重合并）；
  `refresh_probe_evidence`：探测健康面 last_seen 前移 + Roaming→Discovered 升级
  （demote 后 peer 移出内核、观测断，靠 TTL+探测保鲜续命）。
- `merge_into`：config 原序在前、表内新面按 (ip,port) 排序追加——有效候选集
  喂 SEL-001 探测（`probe.update_candidates`），全部已知面被持续探测。

接线（`apps/agent/src/agent/direct.rs` reconcile_direct）：

- 每 30s 对账：sync_config → retain_peers → expire → merge_into → 探测候选刷新。
- 每 tick：wg dump 过滤 wanted 对端 → observe_roaming → 重合并 + 刷新探测缓存
  （内核漫游出新面即刻进探测视野）。
- **换网立即对账**：`run()` net_events 唤醒处重置 `last_direct_probe = None`
  （30s 节流旁路），下一 tick 立即跑完整直连对账（link up/down、addr change、
  WG rehandshake 均经 net_event 唤醒；接口变化侦测走 platform 抽象，
  Windows 由既有 net_event 平台层对等提供）。
- **恢复门 bypass**：hold_relay 构造处，候选表内存在探测健康面即放行 promote
  （DecisionEvent 记 `probe` / `recovery gate bypassed: face probe-healthy
  (FLIP-001)`）——可达即回直连，不经「先 demote 再等恢复门」旧路径。
- 域层 promote 选面：记忆面（滤 unhealthy）→ healthy 滤后 decide_direct_path，
  候选表面自然参选；测试锚定 promote 落在健康 roaming 新面而非劣化 config 面。

单测（10 条，全绿）：

| 测试 | 锚定行为 |
|---|---|
| `sync_config_marks_and_refreshes_config_faces` | 服务端候选权威写入与刷新 |
| `observe_roaming_flags_new_face_only_once` | 内核新面进表只报一次 |
| `roaming_face_expires_after_ttl_but_refresh_keeps_it` | Roaming TTL 过期 / 探测保鲜续命 |
| `discovered_upgrade_then_expiry` | Discovered 升级与过期 |
| `config_authority_upgrades_roaming_entry` | 服务端确认升级 Roaming→Config |
| `merge_into_appends_table_only_faces_sorted_and_dedupes` | 有效候选集合并去重排序 |
| `retain_peers_drops_entries_of_peers_outside_candidate_set` | 逐出集外对端表项 |
| `refresh_probe_evidence_keeps_healthy_faces_alive` | 健康面保鲜 |
| `has_probe_healthy_face_requires_table_and_probe_agreement` | bypass 判据 = 表∩探测双确认 |
| `flip_sequence_promotes_healthy_roaming_face_without_ring` | **集成模拟**（下节） |

`probe.rs` 伴生：`face_healthy` / `healthy_faces`（单快照批量）；健康 = ≥1 个 Rtt
样本且未劣化（全丢面是「未知」不是「健康」，不许 bypass 放行）。

## FLIP-002：demote backoff promote 侧冷却（commit 9f07ecb）

实现（`apps/agent/src/backoff.rs` 新建 261 行）：

- 第 N 次连续 demote 的 promote 冷却 = `base × 2^(N-1)`，封顶 cap；
  移位防绕回（`checked_shl` 不查值溢出，30_000<<62 绕回 0 的坑已测锚定）。
- 链路持续健康（连续 M 轮探测有健康面，M=`recovery_confirmations` 默认 3）即
  整条清零；不健康轮打断连击但抑制保留。
- 只拦 promote 侧：域层 plan_updates 新增第 10 参 `suppress_promote`，抑制中的
  Relay 对端走 defer 分支（state 留 Relay、记忆面 `last_direct` 原样保留、
  DecisionRecord action=`defer` reason 带连续次数与剩余秒数）；**劣化判定与
  demote 不受影响**（测试锚定抑制中握手过期照常 demote）。
- 计数口径：只对候选集内的对端计数——stale 逐出与开关关闭的行政性 demote 不计。
- 离开候选集的对端状态回收（`retain`）。

配置（`crates/meshlet-config/src/agent.rs`，`[dataplane.backoff]`）：

| 项 | 默认 | 依据 |
|---|---|---|
| `backoff_base_ms` | 30_000（30s） | ≈一个对账周期（30s），首劣化最小拉开 |
| `backoff_cap_ms` | 900_000（15min） | 任务书口径——劣化源持续时不至全哑 |
| `recovery_confirmations` | 3 | 与 SEL-003 RecoveryGate 同值（同源探测证据、同一防抖口径） |

校验：`base ≥ 1`、`cap ≥ base`、`confirmations ≥ 1`，违者 `InvalidDataPlane`。
默认值即本文档表值，亦见 `BackoffConfig` rustdoc。

接线（`apps/agent/src/agent/direct.rs`）：healthy_faces 快照后 `note_health`
逐对端记账 → `suppress_map(now_ms)` 构建 → bypass 分支抑制优先（退避期内即便
有健康面也不 promote，拉开重试间隔）→ apply_plan 下传 → updates 循环对候选集内
demote 计数（`on_demote`）。

单测（13 条，全绿）：

| 测试 | 锚定行为 |
|---|---|
| `delay_grows_exponentially_then_caps` | 30s→60s→120s→240s 指数递增、960s 压到 15min cap、远超 cap 恒 15min |
| `on_demote_suppresses_for_the_backoff_window` | demote 后冷却窗内抑制、窗外解除 |
| `consecutive_demotes_stretch_and_restart_window` | 连续 demote 窗口递增、新 demote 重置计时 |
| `health_confirmations_clear_backoff_fully` | 连续 3 轮健康整条清零（指数计数归位） |
| `unhealthy_round_breaks_health_streak_but_keeps_suppression` | 不健康轮打断连击、抑制保留 |
| `note_health_without_state_is_noop` | 无 demote 历史的对端记账无害 |
| `retain_drops_departed_peers` | 离开候选集的状态回收 |
| `constructor_clamps_invalid_values` | 非法构造参数钳制 |
| `demote_backoff_suppresses_promote_but_keeps_memory_face` | 域层：抑制中 defer 留 Relay、记忆面保留、reason 来自抑制表 |
| `demote_backoff_does_not_touch_demote_sensitivity` | 域层：抑制中握手过期照常 demote（判定灵敏度不降） |
| `demote_backoff_expiry_restores_normal_promotion` | 域层：到期/清零后 promote 恢复、记忆面优先 |
| `agent_backoff_defaults_and_parses_explicit_section` | 配置默认值与显式解析 |
| `agent_backoff_rejects_zero_base_and_cap_below_base` | 配置校验三拒绝 |

## 集成模拟：接口翻转序列不产生 promote→demote 环

`flip_sequence_promotes_healthy_roaming_face_without_ring`
（`apps/agent/src/direct/tests/plan.rs`）三轮对账序列模拟 11-14 日志实锤的环：

1. 第 1 轮：现役面 face_a（ZT 劣化面）探测窗口劣化 → 立即 demote 回中继，
   Direct 记忆面保留（对应基线 demote 腿）。
2. 第 2 轮：Relay + 恢复门放行（FLIP-001 bypass 语义）+ face_a 仍劣化
   （unhealthy_faces 滤记忆面）→ promote 落在候选表健康 roaming 新面 face_b，
   **不重拨劣化面**（打断「无健康面可选→拨劣化面」闭环）。
3. 第 3 轮：face_b 直连、握手新鲜、探测健康 → Keep 无动作。

断言：三轮后无任何 promote→demote 往复（updates 序列 = Demote→Promote→空），
环收敛。FLIP-002 保底独立可证：同一劣化面若持续被拨（无健康面场景），
`demote_backoff_*` 三测锚定 promote 间隔 30s→60s→120s…15min 指数拉长——
基线中位 0.78min 的环频被结构性压低（最坏情况下每环 ≥30s 且逐环翻倍）。

## 门禁

- `cargo test -p meshlet-agent --lib`：**180 passed / 0 failed**。修前基线
  （8913132，161 个测试函数）→ FLIP-001 新增 10 条（9 candidates + 1 flip 序列）、
  FLIP-002 新增 11 条（8 backoff + 3 域层 suppress）；函数计数 182 与执行数 180
  差 2 = 平台 cfg 门控测试（Linux 不编译）。
- `cargo test -p meshlet-config`：**33 passed / 0 failed**（+2 backoff 配置）。
- clippy：host `--all-targets` 0 警告；windows-gnu 交叉 `--all-targets` 0 lint
  警告（仅既有 build-script 图标提示）。
- `cargo check --workspace --all-targets`：净。
- commits：f99a7ef（FLIP-001）、9f07ecb（FLIP-002），英文短句、无 AI 痕迹。

## 剩余边界

1. **修后判定数据未采（本单边界）**：2026-11-15 修复已部署双机（部署节），但
   24h 观察窗刚起步（16:57:32 CST / 08:57:32Z）——修后判定与中位对比必须等窗口
   满 24h 后另单执行，本单不预写。本环境亦无第二台 Windows 真机可复现 JMrE
   （ZT underlay 劣化源）。
2. **换网侦测的平台对等性未真机验证**：Linux 侧 net_event（netlink）为既有实现
   已真机实证（BACKOFF_MAX_SECS 30s 事件唤醒）；Windows 侧 net_event 平台层的
   接口起落/地址增删事件在 R-05 验收过链路存在性，但「换网 → 候选表刷新 + 立即
   探测 + bypass promote」整链路的真机时延未测（本轮仅单测与模拟）。
3. **广域打洞（FSaf 跨 NAT）未验**：24h 判定窗内零广域打洞证据；候选表让公网面
   参选探测，但跨 NAT 打洞成功率仍待真机窗。
4. **backoff 参数未经真机调优**：30s/15min/3 为任务书口径推导（对账周期/封顶
   惯例/RecoveryGate 同值），真机上若环频仍高可调 `backoff_base_ms`（如 60s）。
5. **roaming TTL 1800s 未真机校准**：demote 后内核观测断流场景下，表项保鲜
   依赖探测成功；若劣化源静默 >30min，表项过期后回到服务端单面候选——此为
   有意设计（表是加速器不是权威），但 TTL 值本身未经长跑校准。
