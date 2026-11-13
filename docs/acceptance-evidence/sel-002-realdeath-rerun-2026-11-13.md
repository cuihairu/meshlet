# SEL-002 真死复验第二轮：imac↔openclaw（2026-11-13 晚，巡检单 meshlet-nov13-1936）

## 结论速览

- **demote 真死复验仍未复现**——OS 级三重杀伤（防火墙规则〔首轮验收实锤〕/ 禁 ZT 适配器 / 双 null 路由）全部无法杀死 imac↔openclaw 的 WG 直连通路：内核握手以墙钟速率持续续期，classify 输入持续新鲜，Healthy 保持直连是**正确判定**，不是缺陷。
- 复验的真正产出是**插桩取证揪出三路消费全盲的实现缺陷**：探测窗口按 `device_id` 记键、而全部消费端（SEL-003 劣化映射/恢复门、SEL-002 迟滞闸、SEL-004 候选详情）按 `public_key` 查——生产环境三路全盲。连带修掉两处语义缺陷（「任一候选劣化拖垮整 peer」「无基线全 Lost 判劣化」）。**已修 `4174773`**（单 commit；network 187 / agent lib 135 全绿、clippy -D warnings 净、windows-gnu check 净）。
- **测量勘误**：PS 5.1 `Get-Date -UFormat %s` 把本地墙钟当 UTC 计算 epoch（+28800s，UTC+8 环境）——此前 recon 采样里「握手冻结 ~28800s / now_minus_ts≈28730」类读数**全部是采样器伪影**。agent（Rust `SystemTime`）、WG 内核握手戳、Linux `date +%s` 三者一致为真 UTC；今晚插桩实测握手年龄 33–120s 持续新鲜。
- **第二根因（修复部署后现场实锤）**：升级到 4174773 nightly 后两台 Windows 对进入 ~4–5min 的 demote 极限环。切换事件取证实锤：SEL-002 切换闸把「现役路径无探测窗口」（稳定 192.168.5.0/24 roaming 面，不在服务端候选表 → 无读数）按 ∞ 评分处理 → 22:34:02 / 22:35:30 把两台会话踢上 ZT 面 → ZT 面瞬态劣化 → SEL-003 / classify 轮番回收。**已修 `c4e5038`**：现路径无窗口 → 不切换（无证据不动现路径）；握手年龄轨迹证明 demote 发生在 age 56–66s（≪240）且握手正常续期，classify 无辜、触发者是 ZT 面探测瞬态。
- **c4e5038 双机部署后现场验证（2026-11-14 00:2x–00:4x）**：切换闸修复字段生效（~20min 三轮采样**零新切换事件**、b6tx 恒直连）；残余：JMrE/FSaf 仍 ~1–5min 回收——会话滞留旧构建踢上去的 ZT 面（demote 时 age 56–120s≪240，SEL-003 last-Lost 瞬态触发），re-promote 只能挑候选表（ZT 面）回不到 roaming 面，修复方向属上游（候选表纳管/promote 偏好/last-Lost 触发器软化），本轮如实记录不越界改动。openclaw sshd 在升级窗口 flap（根因未定位，升级经 schtasks 分离执行完成后机器恢复），挂待查。

## 前置：nightly 升级（巡检单任务 1–3）

- nightly：run 43419151175 success 14m21s；`nightly` tag → `704836005ba797441ce22559faca14f57da6d380`（含 7048360 时延劣化维度）。
- MSI SHA256 `9759aef2123ed1305de2ff11c41b8fe936c0ff12e2e208cdb3f4087575eabb62` 对 SHA256SUMS 两机一致；双位 exe（Program Files 服务位 + AppData 运行位）同哈希 `7425B7FD01EE6C2C42808E8D1C52BC995C71031762EE7463B26DD343B1955E76`；imac PID 38768→23888、openclaw PID 9320；升级后 ping 10.240.0.1 ✓。
- **imac ZT 恢复义务已履行**：v2 复验结束 RESTORE，20:53:47 `zt=Up`、p49=ok7ms（raw v2 RESTORE 段）。

## 实验（任务 4a–c）

### 4a baseline（≥5min，2s 采样）

ledger 稳态直连、零 demote（raw v1/v2 BASE 段）。

### 4b-v1：禁 imac ZT 适配器（≥10min）

demote 未现；WG 握手照常续期；恢复后 zt=Up。

### 4b-v2（权威轮）：禁适配器 + 双 null 路由（≥10min）

- 20:43:37 **KILL**：禁 ZT 适配器 + `route add 10.147.19.0/24` + `route add 192.168.5.11/32`（ROUTE_ADD rc OK、ZT_STATE Disabled）。
- KILL_VERIFY（+6s）：**p49=ok8ms pLan=fail**——null 路由已生效但隧道照通。
- 内核握手戳持续前进（真活铁证）：1794573787（20:43:43）→ 1794574035（20:48:39）→ 1794574406（20:53:38）。
- **RESTORE** 20:53:38–47：适配器恢复、null 路由删除、zt=Up。
- 全程 559 拍 ledger mode **零 hub_relay**。

### 「打不死」通路的侧写（环境缺口）

服务端候选表 openclaw-win = `10.147.19.49:51820/lan`、`192.168.36.153:51820/lan`、`180.153.160.8:51820/public`（raw deviceids json）——**不含 192.168.5.x**；而 imac↔openclaw 实际同处 192.168.5.0/24（imac .117 / openclaw .11，ledger 端点 .49↔.11 翻转）。被杀死的已知面之外存在**服务端不可见的同 L2 面**（与首轮验收「匿名成员 .17」同族现象）。真死需物理层断开（拔线/断 AP），超出远程巡检能力——**如实记为环境缺口，不冒充已验**。

## 任务 4d：插桩取证（21:13–21:16，windows-gnu 临时插桩构建，取证后已还原 7425B7FD 原件）

sel002diag 三轮对账 verbatim（raw: `sel-002-imac-diag-run-2026-11-13.log`）：

```
wanted=[(coding-vm,b6txQ61F…),(windows-desktop,JMrE4SZy…),(openclaw-win,FSaf/1S9…)]
states=[Direct,Direct,Direct]
ages={FSaf:120→40→83, JMrE:86, b6tx:33, vLkJ:38}   ← 全新鲜（≤240 健康窗口内）
degraded={"dev-reg-5":true,"dev-reg-9":true}        ← 键是 device_id，不是公钥！
hold={}
```

服务端 API 对账（raw: `sel-002-wanted-deviceids-2026-11-13.json`）：**dev-reg-4=coding-vm、dev-reg-5=windows-desktop、dev-reg-9=openclaw-win**——劣化信号本身在正常触发（两台 Windows 对端防火墙拦 ICMP → 候选窗口全 Lost），但三处缺陷让它到不了判定层：

1. **键失配（致命）**：`probe_round` 按 `peer.device_id` 记窗口（crates/meshlet-network/src/probe.rs），而 `plan_updates` 劣化闸 / hold_relay / RecoveryGate / SwitchGate / candidate_statuses 全按 `public_key` 查（apps/agent）→ **SEL-002 迟滞切换、SEL-003 探测降级、SEL-004 候选详情生产全盲**。单测全绿是因为合成键（"dev-b"）两边恰好一致。
2. **any-candidate 折叠**：旧 degraded_map「任一候选窗口劣化 → 整 peer 劣化」——openclaw-win 3 候选中异网 LAN / 公网常年 ICMP 不达，会把健康直连永久拖入劣化。
3. **无基线判劣化**：旧 is_degraded 对全 Lost 窗口（对端防火墙拦 ICMP，隧道可能健康）判劣化——与晋升门槛「ICMP 探测失败不拦晋升」（Windows 网格防火墙对 wg 接口 100% 丢包取证，2026-11-07）哲学矛盾。

## 修复（4174773，2026-11-13）

- ProbeTarget / `record` / `window` / `retain_peers` / `probe_round` 全部改按 `public_key` 记键；probe_netns 集成测试同步对齐（其 fixture 依赖旧键法，基线挂、修正后绿）。
- `degraded_map` 收窄为**现役 endpoint 窗口**口径（调用点从 `link_statuses` 构造 pubkey→现役候选）。
- `is_degraded` **无基线豁免**：窗口内无任何 RTT 样本 → 不判劣化；真死由握手年龄 classify 兜底（> `DIRECT_HEALTH_WINDOW_SECS`=240s → Demote），不依赖探测。
- 回归测试：network +2（公钥记键 / 全 Lost 不劣化）、agent +1（现役口径四分支：备份候选无关 / 由好变坏劣化 / 无基线不劣化 / 无窗口不劣化）。
- 门禁：network lib 187 / agent lib 135 / 全集成绿（agent_reconcile、instance_lock 三套、ledger/plan recovery、probe_netns）；clippy -D warnings 净；fmt 净；windows-gnu `--all-targets` check 净。
- 后续 nightly run 43437201158 滚动该修复。

## 升级后震荡：第二根因取证（22:34–23:03，现场观测）

4174773 nightly（FF6E9D53 双位构建，imac PID 25228 / openclaw PID 13140）部署后，两台 Windows 对进入 ~4–5min 周期的 demote→hub→promote 极限环（ledger mode 反复 `p2p_direct↔hub_relay`，b6tx/coding-vm 全程稳直）。

**切换事件（smoking gun，`state/direct-switch-events.json`，JSONL 原文存 raw）**：

- `22:34:02.507` JMrE4SZy（windows-desktop）`192.168.5.11:51821 → 10.147.19.97:51821`，reason `score 48.5 beats current inf by >= 30% for 3 consecutive samples`
- `22:35:30.115` FSaf/1S9（openclaw-win）`192.168.5.11:51820 → 10.147.19.49:51820`，reason `score 8.0 beats current inf by >= 30% for 3 consecutive samples`
- `22:40:51` b6txQ61F（coding-vm）`.130 → .188`（`score 0.0 beats 1.0`，良性）

**根因（SwitchGate ∞ 评分）**：`evaluate` 对现役 endpoint 无探测窗口时按 ∞ 评分（「无读数 = 最差」语义本意只用于候选间比较）。192.168.5.0/24 roaming 面稳定可通但**不在服务端候选表**（上游遗留：该面服务端不可见、永远无探测目标）→ 永无窗口 → 被当 ∞ → 换到候选表可见的 ZT 面。链条闭合：换面 → ZT 面 ICMP 瞬态（丢包/时延抖动）→ SEL-003 现役窗口判劣化 demote（或 classify 超窗）→ hub 期内核删 peer → 恢复门 3 轮健康 → promote → 单次握手后再次瞬态 → 极限环 ~4–5min。

**握手年龄轨迹（10s×48 拍，raw 存档）定性 demote 时点**：

- 握手按 ~118s 节奏正常续期（FSaf 111s→7s，14s 间隔内完成 rekey），路径在 demote 前后均健康。
- wd 在 22:58:50→22:59:00 之间被 demote，demote 时 age 仅 **56–66s ≪ 240**（classify 无辜）；同拍 FSaf 同 demote、b6tx（现役 LAN 面 .188）幸免 → 触发者是 ZT 面共同瞬态（现役窗口劣化命中）。
- 采样器里 `age≈1794581849s` 的行为 latest-handshake=0（promote 刚重加 peer、首次握手未落），非时钟伪影。
- demote 时序非全同步（23:00:5x FSaf 单独挂、wd 撑到 23:02:40），与「逐窗口瞬态劣化」一致。

## 第二修复（c4e5038，2026-11-13）

- `SwitchGate::evaluate`：现路径取不到窗口 → `?` 提前返回**不切换**（原 `else { return None }` 处改为 `let current_score = windows.get(&(peer.to_string(), current)).and_then(score)?;`）。「无 RTT 读数 = ∞」语义只保留在候选间比较；现路径死亡交给握手年龄 classify 与 SEL-003 劣化闸负责。
- 回归测试 `switch_gate_spares_current_path_without_window`：现役 c1 无窗口、候选 c2 有窗口（rtt 48）→ 5 轮评分恒 `None` 不切换。
- 门禁：network lib 33 绿（改后重验）；随 nightly run 43451086220 滚动（`4174773..c4e5038`）。（首次派出 43449300571 失败于 `scripts/verify-systemd.py` 步：runner 上 server 15s 重试窗内未监听 18080——与改动无关的 runner 瞬态；本机同源 c4e5038 重建复跑该脚本 PASS，重新派出。）

## 双机升级到 c4e5038 与现场验证（2026-11-14 00:2x–00:4x）

- **imac**：MSI 对 SHA256SUMS ✓、双位 exe 同哈希 `9B4199D11BCF9AE9`、PID 10932、hub ping ✓。
- **openclaw（波折）**：升级脚本执行到 msiexec 阶段 sshd 开始 flap（先挂起后连接即断；机器本身一直可达——imac ping 2/2 7-10ms），首次 SSH 会话中断致脚本半途死（agent 被 kill 未重启，overlay 10.240.0.3 100% 丢=真死窗口）。**sshd 恢复后改用 schtasks 分离执行**（`MeshletOcUp` ONCE 任务跑 oc-up.ps1、`*>>` 收 log、任务自删，SSH 只注册+收日志，不受会话断连影响）：MSIEXEC_RC 0、新 PID 2808、双位 exe `9B4199D11BCF9AE9`（与 imac 同构建）✓、hub ping ✓、DONE；MeshletOcUp 已自删确认、Temp 脚本清零（余下 oc-br-*/oc-mem-dream 为机器原有非本轮产物）。**openclaw sshd flap 根因未定位**（升级窗口强相关、简单短命令可过、长脚本/管道易死），挂待查。
- **切换闸修复字段验证 ✓**：修复部署前后共 ~20min 三轮采样（20×30s 稳定性 + 30×20s keyed），`direct-switch-events.json` 字节数全程恒定 648（=旧三事件，**零新切换**）——∞ 评分踢面消除。
- **b6tx（coding-vm）恒 p2p_direct**（keyed 30/30 拍，握手 ~120s 正常 rekey）；vLkJ（hub 面）健康。
- **残余（如实记录，不冒充已修）**：JMrE/FSaf 仍以 ~1–5min 周期 direct↔hub 回收——会话仍停在旧构建 22:34/22:35 踢上去的 ZT 面（wd@.97:51821 / openclaw@.49:51820），ZT 面 ICMP 瞬态（is_degraded 的 last-Lost 触发器对单包丢失即敏感）→ SEL-003 demote（keyed 实测 demote 时 age 56–120s ≪240，classify 无辜）；而 re-promote 只会在服务端候选表里挑（还是 ZT 面），**回不到稳定的 192.168.5.x roaming 面（不在候选表=结构性回不去）**。修复方向属上游决策：候选表纳管 roaming 面 / promote 偏好无探测窗口的健康面 / is_degraded last-Lost 触发器对单包丢失放行（持续 N 拍才判）。本轮不越界改动。
- 修复语义与 4174773「无基线不行动」同源：**无证据不动现路径**。预期部署后会话停在 .11 roaming 面回到升级前稳定性（该面永无探测目标 → 永无劣化误判 → 无切换）。

## 测量勘误（修正既有记录）

- **机制**：PS 5.1 `Get-Date -UFormat %s` 按本地墙钟 DateTime 直接折算 epoch → 本地 21:08:03（=真 UTC 13:08:03Z，真 epoch 1794575283）报出 1794604083（=+28800）。
- **交叉验证**：21:13:51 插桩轮 agent `now_secs`=1794575631 = 1794575283+348，与真 epoch 精确吻合 → agent/内核侧无偏移。
- **失效读数**：本轮及首轮 recon 中一切「PS epoch − 内核 ts」差值（「握手冻结 ~28800s」「now_minus_ts≈28730」等）——真值为新鲜 33–120s。
- **仍有效**：wg.exe 第三列内核 ago 读数（时区免疫，首轮 133–203s）、ledger mode/rtt_source 等非时间差字段、防火墙封堵验证（fw=True / zicmp fail）。

## 未决缺口（不冒充已验）

1. Windows 对上 demote 真死仍未复现：直连面无法 OS 级杀死（见「打不死」通路）。修复后的降级路径由单测证明接线正确（由好变坏 → 劣化 → demote、无基线不误伤），真机复现等物理层断开手段。**但升级后震荡意外提供了 demote 通路真机实锤**：SEL-003 现役窗口瞬态劣化 + classify 超窗两条 demote 路径都在真机上走到了终点（hub 期内核删 peer → hub_relay 通信恢复），链路完整可用。
2. 时延维度（≥800ms 中位数）在本环境无法主动触发（健康面实测 RTT 7–100ms）；ZT 面瞬态抖动是否曾以时延维度命中未逐窗归因（loss/last-Lost 时序足够解释本轮观测）。
3. SEL-001 探测目标（underlay 候选）与 enrich 探测（overlay VIP→endpoint 回退）口径差仍待统一（上游遗留）。
4. 匿名 ZT 成员 10.147.19.17 身份对账（上游遗留）。
5. 192.168.5.0/24 roaming 面不在服务端候选表（本轮事故的放大器）——是否纳管待上游决策；c4e5038 已保证其被选中使用时不会再被踢走。

## raw 证据

- `sel-002-imac-obs-v1-2026-11-13.txt`（禁适配器轮，2s 采样全程）
- `sel-002-imac-obs-v2-2026-11-13.txt`（禁适配器 + 双 null 路由权威轮，559 拍，KILL/RESTORE 标记）
- `sel-002-imac-diag-run-2026-11-13.log`（插桩三轮 sel002diag verbatim + 探测轮 debug）
- `sel-002-wanted-deviceids-2026-11-13.json`（服务端 device_id↔对端↔候选映射）
- `sel-002-imac-switch-events-2026-11-13.jsonl`（direct-switch-events.json 原文 3 行，∞ 评分 smoking gun）
- `sel-002-imac-age-trace-2026-11-13.txt`（10s×48 拍 modes+握手年龄轨迹，demote 时 age 56–66s 定性）
- `sel-002-imac-keyed-trace-2026-11-14.txt`（c4e5038 部署后 20s×30 拍 keyed 轨迹：b6tx 恒直、零新切换、JMrE/FSaf ZT 面残余回收 demote 时 age 56–120s）

前置文档：`sel-002-imac-openclaw-2026-11-13.md`（首轮验收：防火墙封锁 + 自然劣化窗，252+70 拍零 demote，.17 匿名面实锤）。

## 第三轮：stranded 残余根修 880b49a 部署与验证（2026-11-14 03:0x，巡检单 meshlet-nov14-0155）

### 修复内容

`880b49a`（fix(agent): re-promote returns to last direct face over table faces）：DirectPeer 增 `last_direct` 记忆面——promote 记下实拨面、`record_endpoint` 随内核实况刷新（含 wg 漫游出的表外面）；回中继后的再晋升优先选回记忆面（这类面常不在服务端候选表、且无探测目标=免 SEL-003 误判的最稳面）；pending 验证失败（3 拍无握手）清记忆=死面逃生；SwitchGate 短路语义（c4e5038）原样保留；记忆面不进探测目标（窗口免疫=稳定机制本身）。单测 5 例（记忆选回/死面清零/hold 穿透/首次记录/内核刷新），agent lib 144 全绿、windows-gnu 交叉 clippy 净。

### 部署（两机钉版本 MSI 流程）

- nightly run `43482891978`（workflow_dispatch，head `880b49a`）success；本机 `gh run download` 取 nightly-windows 资产，MSI 11,112,448B、SHA256 `769cf4f9f3f59ddbf723e5e042e77b48b6046b745af553096a61a601ec82ca4b`（SHA256SUMS 不在 artifact 内，本地按 release 步同公式生成后随 MSI 一起 scp）。
- **imac**（02:52）：HASH OK=上值、MSIEXEC_RC 0、PID 13712、APPDATA/PF 双哈希同 `EF3E86DF…CEBDE1`；`--version` 0.1.0；顺手清掉 11-07 遗留休眠任务 7 个（MeshletDIAG/FINAL/I1/IMAC×4）。首跑因 ps1 带中文注释在 PS 5.1 ANSI 解码下 ParserError 一行未执行（agent 无损），改纯 ASCII 后成功。
- **openclaw**（03:01–03:02，schtasks 分离任务 MeshletOcUp，任务自删）：HASH OK 同上、MSIEXEC_RC 0、PID 2396（03:01:45 起）、APPDATA/PF 双哈希同 imac。Temp 四文件已清。
- **插曲（如实记）**：一个 11-13 夜遗留的后台旧脚本任务（滚动 release 下载流程）在 openclaw 上推进到 HASH_MATCH 后 sshd flap 会话死亡——实测**未执行到停止步骤**（agent PID 2808 于 00:31:44 启动未被触碰、msiexec 计数 0、其下载的 MSI 已被自身清理），openclaw 状态未被污染；钉版本部署照常完成。

### 验证（imac 分离任务 MeshletImacSample，20s×70 拍 03:03:56–03:25:58 = 22min2s，PID 13712 恒定零重启；raw: sel-002-imac-keyed-trace-2026-11-14-postfix.txt）

| 对端 | 结果 |
|---|---|
| b6tx（coding-vm） | **70/70 恒 p2p_direct @ 192.168.5.188，零翻转**（无窗口 roaming 面持续稳定） |
| JMrE（windows-desktop） | 18 次翻转（hub 39 / pending 13 / direct 18 拍），~2min 周期 direct↔hub 回收——**未达「≥20min 无回收」判据** |
| FSaf（openclaw-win） | 17 次翻转（hub 32 / pending 25 / direct 13 拍），同期相位与 JMrE 同步——**未达判据** |

- 切换闸零新触发：imac `direct-switch-events.json` 全窗口 648B/LastWriteTime 11-13 22:40:51（升级前后字节恒定）；openclaw 同 217B/11-13 23:11:59 —— SEL-002 闸在 880b49a 下不回退。
- **残余如实定性（不冒充已验）**：JMrE/FSaf 的记忆面与候选面**同为 10.147.19.x ZT 面**（两台 Windows 现均漫游在外：wd@192.168.88.x、openclaw@192.168.36.x，无真 L2 面存在）——记忆机制「选回上次直连面」与「候选表决策」在此几何下选同一个 ZT 面，无无窗口面可回，震荡未被本次修复消除是**几何必然**而非实现缺陷。修复在单测层证明接线正确（含 192.168.5.11 记忆面 vs 10.x 表面用例）；fleet 可见收益要等对端漫游回家（192.168.5.x/88.x/36.x 任一真 L2 面出现）或 SEL-003 last-Lost 单包触发软化（上游决策清单方案 3，本轮不动）。观测期内每次 pending→direct 均成功握手（面本身可用），hub_relay 期通信正常——数据面无损，仅控制面频繁换道。
- 软化/几何条件齐备后的复验口径：同采样器 ≥20min，判据 JMrE/FSaf 零 hub_relay 拍。

### 收尾状态

- imac 临时文件已清（msi/sums/脚本）；采样任务 MeshletImacSample 与 openclaw MeshletOcUp 均为自删型（注册脚本首行 schtasks /Delete，无 23:59 重燃残留）。
- 待办：todo.md 103 行纪要追加（见下一 commit）；Windows 真死复现仍待物理断开手段；openclaw sshd flap 根因未定位（进程级挂起、升级窗口外复现）。
