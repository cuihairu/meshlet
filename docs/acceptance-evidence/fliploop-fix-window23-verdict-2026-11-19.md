# fliploop 整定批真机观察窗判定（2026-11-19，巡检单 meshlet-fliploop-verdict-1119）

判定口径：todo 行 157 锁定（基线窗=2026-11-15T08:57:32Z→2026-11-16T09:11:32Z
OC 视 24.23h 全窗，flip 976=JMrE 214/QmAF 612/b6tx 150 + roam 18=FULLWIN 994，
判定口径 0dd4af4 不动）。本单纯取证判定，零 crates/ 代码改动。

## 闸门与窗满

- **观察窗**：2026-11-17T17:00:00Z → 2026-11-18T17:00:00Z（起点=L158 锁定：
  双机新构建+新 PID 齐活时刻取后者后的整分；oc 首条决策 16:55:46Z / imac
  16:59:07Z，取后者整分）。
- **窗满判定时刻**：2026-11-18T17:16:15Z（date -u 实测）≥ 起点+24h，
  **24h 整窗满，判定授权成立**。
- **构建连续性**：openclaw meshlet-agent PID 13908，StartTime
  2026-11-17T16:55:09Z（窗起点前 5 分钟），窗内全程未重启（2026-11-18T17:2xZ
  Get-Process 实测）；窗内 decisions >5min 断档最大 9.9min（静默非重启）。
  整定批三 commit（945da62/de86830/2a7592a）随 nightly 部署（MSI 8657f180、
  双 exe 同哈希 F42ABA34）即本窗构建（L158 记录）。
- **imac 侧 caveat（如实）**：imac 本机不可达（LAN 192.168.5.117 ping 100%
  丢、SSH No route to host，17:16-17:20Z 实测），imac 侧本机文件取不到，
  窗内覆盖 0h（较基线判定的 15.76h 更严）。四列判定全部按 OC 视单侧口径——
  与 L157 锁定基线同视角，自洽可比；imac 侧缺口留空不补拍。

## 方法自洽（先复现基线再判窗）

同一解析脚本对基线窗复现：flip 975/roam 18（锁定 976/18，差 1 条 flip=
direct-switch-events.json 2.5 天轮转漂移，如实注记）；peer 分布 JMrE 214=214、
QmAF 611 vs 612、b6tx 150=150；roam QmAF 11=11、b6tx 7=7。**口径还原成立**。
分类：flip=kind mode_flip；roam=无 kind 端点切换（score beats）；rollback=
reason 含 rollback。环数定义残差：基线 n=76 的 ad-hoc 脚本未入库，本单用
defB（verified→demote 直连存活期；基线两端 min/max ±0.01 吻合：1.02/13.99
vs 0.72-14.00 carryover RECORD）自洽计数，n 列与基线存在定义残差，如实声明。

## 四列对比（OC 视）

| 列 | 基线（24.23h） | 判定窗（24h） | 方向 |
|---|---|---|---|
| flip/peer | JMrE 214 / QmAF 612 / b6tx 150 = **976** | JMrE 227 / QmAF 441 / b6tx 294 = **962** | 总量 -1.4% 持平；QmAF -28% / b6tx +96% / JMrE +6% |
| 环数（defB） | wd n=76 / median 1.88min | JMrE 68/1.07 / QmAF 23/6.39 / b6tx 97/3.35 | 未收敛（demote 372→387 +4%） |
| roam | **18**（QmAF 11 / b6tx 7，全 in-gate beats-数值） | **75**（QmAF 67 全 beats-**inf** + b6tx 8 beats-数值 in-gate） | 18→75 恶化 |
| rollback | 0 | **0** | 「从 0 起>0」未达标 |

辅证列：demote 372→387；sel003 demote 230→187（b6tx 98/98=全部 demote 均
sel003）；FLIP-001 bypass（face probe-healthy 放行）coding-vm 64 起；
decisions 窗内 2,691 条（JMrE defer 887/hold 138、b6tx hold 116/demote 98、
QmAF probe 385/demote 209）。

## 预期方向逐项判定（任务书四项）

**① SEL-003 demote 升（半坏面提前拦）：未复现**——230→187 反降。
但形态存在：b6tx 窗内 98 个 demote **全部**为 sel003（20% 尖峰提前拦的
预期形态；基线 b6tx demote 50 里 sel003 占比无此纯度）。总量反降主因
JMrE sel003 67（基线 wd 面 sel003 为 77 中大头）+ QmAF 面转 exhausted
主导（196 条 exhausted=3 轮 probe 全败，面级无基线非半坏面）。

**② FLIP-001 bypass promote→demote 循环收敛：未收敛**——flip 976→962
（-1.4%）、demote 372→387（+4%）；bypass 活跃（coding-vm 64 起）但环率
未降；窗末 QmAF promote↔exhausted 环持续（16:46:35Z→16:59:01Z 最后一条
promote attempt）=**末拍仍翻复现**（基线判定 ② 的「末拍无一在翻」依据
在本窗不成立）。

**③ SEL-002 roam 18→≤17：未达标**——75（>17）。分层归因（不是单一恶化）：
- b6tx 同族 in-gate roam：7→8（持平 +1，判据内）；
- QmAF +67 全部「beats current **inf**」=现役面评分 ∞（无探测基线）时的
  判据内候选切换，集中在 imac 面全 Lost 期（小时分布：20-22Z 静默 5-9/h →
  00Z 起 56-57/h 恒频 14 小时）；基线 QmAF roam 11 系同族机制
  （「窗前半段面可用性变化期」），本窗 imac 面失联段更长故放大。
- 判据外误触发：0 起（75/75 全为判据内触发，与基线「无误触发成立」同结论）。

**④ rollback 事件从 0 起（>0）：未达标**——0。机制在位（2a7592a 的
"rollback within switch grace: path lost probe baseline" reason 字符串已
随窗内构建部署；测试面钉住
`switch_rollback_needs_death_evidence_and_is_one_shot`）。零触发原因=
窗内无满足触发判据的场景（回滚需「切换窗口有 RTT 基线+末尾连续 3 拍全
Lost」；本窗实际发生的路径切换=面切换/劣化切换，无「切到新面后新面死亡」
事件；全 Lost 无基线人群设计上永不触发——设计如此）。

## 结论

**整定批预期方向四项 0/4 达标，判定=未通过（保持 todo 未勾）。**

归因分层（不是回归判定）：窗内最大环境因子=imac 面大段全 Lost（QmAF 面从
00Z 起恒频环 14 小时），其驱动的 QmAF flip 441（-28% 反降）与 beats-inf
roam 67 既污染 flip 总量对比也放 roam；剔除该面后 JMrE 227（+6% 持平）、
b6tx flip 294（+96% 恶化，98 个 sel003 短环=提前拦把环变多变短）——
**b6tx 形态符合 sel003 提前拦的预期行为但未转化为环收敛**。整定批
（宽限/年轻豁免/预检/回滚）代码面无异常触发痕迹（rollback/precheck/grace
零误触发、reason 无未知新头、agent 无重启）。

**勾选缺什么（如实）**：需满足 L157 验收字面——①窗内 imac 面健康段足够长
（当前失联主导，面级基线不可得）②在面健康窗内复测 sel003 demote 上升方向
③roam ≤17（含 beats-inf 口径需先在锁定口径层拍板：基线 18 条全 beats-数值，
beats-inf 是否计入 roam 属口径新题，本单按无 kind 事件全数 roam 保守计入）
④rollback 自然触发 >0。四项均依赖 imac 面恢复后新窗复测；本窗数据不足
以支持勾选，也不足以归责整定批（环境混杂变量未控）。

## 交付

- raw：`fliploop-fix-window23-2026-11-19.txt`（本判定单配套，含全部统计与
  取证时刻）
- docs-only 单 commit；判定口径以 todo 行 157 为准，零新造指标（环数 defB
  为基线定义还原，残差如实注记）
