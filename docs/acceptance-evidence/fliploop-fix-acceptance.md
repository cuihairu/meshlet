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
