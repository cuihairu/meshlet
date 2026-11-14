# SEL-002 残余真机复验：eb3b06d 软化 + 880b49a 记忆面部署后（2026-11-14 08:27 巡检单）

范围：把含 880b49a（re-promote 偏好记忆直连面）+ eb3b06d（is_degraded 末拍连续
LAST_LOST_TOLERANCE=3 拍 Lost 才判劣化）的 nightly 2de57b1 部署到 imac 与 openclaw，
真机验证软化语义与回直连表现，并对无注入净窗跑既有判据（sel-002-realdeath-rerun-2026-11-13.md
口径：「同采样器 ≥20min，判据 JMrE/FSaf 零 hub_relay 拍」）。

## 结论速览（三正一负，如实）

1. **软化语义成立（自然损失实证，非注入）**：b6tx 台账三态直读（probe_ok / probe_failed /
   handshake_fresh）显示连续 ≤2 拍 Lost 期间 mode 稳住 p2p_direct、探测恢复即回 probe_ok
   rtt=1；≥3 拍连续 Lost 才降 hub。实例：b6tx 对 imac 拍 1794619113–1794619173（2 拍 Lost
   →稳住→1794619188 probe_ok rtt=1）；b6tx 对 openclaw 拍 1794619264–1794619294（Lost 拍
   累计 ~60s→1794619324 降 hub）；wind 同窗先 2 拍容忍后随 3+ 拍降。与 eb3b06d 语义（单拍
   瞬态不动作、连续 3 拍才判）一致。首轮 FSaf 直连窗 1794618047→8136 ≈89s≈3 拍后降，同口径。
2. **880b49a 记忆面 re-promote 复现两例**：b6tx↔openclaw 降级后经 .130（该对上一活跃直连面）
   回直连（拍 1794620229 起）；openclaw↔imac 经 .17 面回直连（拍 1794619978 起）。
3. **3a 净窗判据 FAIL（如实，不冒充）**：注入撤除后净窗 58 拍/19.2min（1794618576–1794619696，
   采样器同源）内 JMrE 33 直/17 hub/8 pending、FSaf 9 直/28 hub/21 pending——**非零 hub_relay 拍**。
   残余 stranded 未消除：ZT 面链路质量撑不住持续直连（.226 自然 100% 丢窗、RTT 1828/789ms 尖峰
   均无注入），候选表不含同 L2 面（imac LAN .117、b6tx LAN .188 均不在对端候选内，对只能骑
   ZT 面）→ **方案②（候选表纳管 roaming/LAN 面）维持上游决策项，本轮未实现（遵巡检单指令）**。
4. **注入式受控断言未达成（方法失效，如实）**：见下节。

## 注入方法失效实录（三轮，RemoteAddress 封锁打不中直连数据路径）

- **round 3b（openclaw，封 .17+.226）**：封锁窗内 ping .226 死——当时判「生效」；事后对照发现
  .226 在 fw=False 时同样 100% 自然丢（oc-block5.log RECOVER2 段），ping 死亡与自然劣化不可分。
  且封锁起点恰逢会话在 hub/pending，软硬窗均无直连可打。
- **round 4（imac，封 192.168.5.188）**：fw=True 期间对端握手照常（BLOCK2 起 2s 内 wg 握手成功、
  b6tx 侧 probe_ok rtt=1 贯穿封锁窗，时钟 +36s 校正后对齐）——封锁对 WireGuardNT 数据路径无效。
- **round 5（openclaw，封 .17+.226，带正向对照）**：QmAF(imac) 内核端点 10.147.19.17:51820，
  BLOCK2 硬封锁 180s 内该端点握手持续重协商、累计 144MB 流量照走——**RemoteAddress 双向封锁
  对端点同名的隧道流量无效**（机制未解，同 2026-11-13 轮「握手穿封锁」观察；ZT tap/WireGuardNT
  与 WFP 的交互超出本轮范围，不再追）。
- 推论：该 fleet 几何下「注入式单拍/多拍 Lost 对照」不可实现；软化语义以自然损失轨迹实证为准
  （结论 1）。真死复现维持「待物理层断开手段」结论不变。

## 部署记录（nightly 2de57b1）

- nightly run 43533414505 SUCCESS，nightly tag → 2de57b1（≥ eb3b06d ✓，4 资产在挂）
- MSI SHA256 e9fc9ff0…829e 对 SHA256SUMS ✓（两机同一 MSI）
- imac：schtasks MeshletAgentDeploy（PF→AppData），双位 exe 同哈希 0d42d5c1…5cf9a，PID 14444，
  `meshlet-agent 0.1.0`
- openclaw：schtasks MeshletOcUp2（SYSTEM 分离执行，MSIEXEC_RC=0），双位同哈希 0d42d5c1…，
  PID 3284，`meshlet-agent 0.1.0`
- 升级后隧道恢复：各 VIP ping 通、server DB last_seen 全新鲜（部署段核验，2026-11-14 08:4x）

## 其它现场事实

- **.17 面身份维持未解**：openclaw wg 内核端点 10.147.19.17:51820（ledger 同步 .17），imac 本机
  ZT 仅 .226——与 2026-11-13 轮观察一致，待 controller/central 对账，不阻塞本轮结论。
- **.226 自然劣化窗**：oc-block5.log RECOVER2 段 fw=False 时 ping .226 连续 100% 丢（同期 .17
  面承载会话正常）——ZT 主面自身不稳是 FSaf 28/58 hub 拍的直接来源。
- **imac 自发降掉健康 LAN 会话一例**：拍 1794619072（本地 09:17:16，时钟校正后）imac 将 b6tx
  （对端 probe_ok rtt=1、hs=104）降 hub；随后 b6tx 侧探测才开始 Lost（09:18:33 起）——降级先于
  对端失败，因果方向=本端判定驱动，具体原因不可回放（见下条诊断缺口）。
- **诊断缺口（跟进项）**：Windows schtasks 上下文 agent 不落决策日志（agent-run.log 为 11-04 手动
  运行残留、agent.out.log 同陈旧）——降级原因无文件级回放能力；后续轮建议先补日志落盘再复验。
- **switch-events 观测**：全程 swsz=865 恒定零新事件（含大量 mode 翻转）——direct-switch-events.json
  不记录 hub↔direct 模式翻转（仅面切换类事件），判据侧勿以该文件推 mode 稳定性。
- b6tx 本地三会话白天整体直连稳定（LAN 对 .117 rtt=1–3ms 全程无翻转）；ZT 对按面质量周期
  direct/pending/hub 循环，hub 兜底通信始终正常。

## 清理核销

两机 Temp 全部工件（脚本/MSI/日志）删除；ONCE 任务核销（MeshletImacSample3、MeshletSel002Block4/5、
MeshletOcUp2、MeshletSel002Block3b 均确认不在；注册任务 MeshletOc3b 补删——其 /TR 目标已删但
按纪律核销防 09:16 重燃）；防火墙 sel002block* 孤儿规则两机 0；路由器 -L 2222 隧道进程已杀
（pkill 自匹配退出码 144 属已知陷阱，进程确死）。

## 原始证据（均在本目录）

- `sel-002-eb3b06d-imac-trace-2026-11-14.txt` — imac keyed 采样 90 拍全轨迹（08:58–09:28，含
  3b 注入窗与净窗分界 1794618560）
- `sel-002-eb3b06d-b6tx-trace-2026-11-14.txt` — b6tx 本地台账 42 拍（probe 三态直读，软化实例所在）
- `sel-002-eb3b06d-oc-logs-2026-11-14.txt` — openclaw 侧 oc-block3b / oc-block5 / oc-up2 全日志
  （##### 分隔；含 ping 对照、fw 标志、MSIEXEC/PID/哈希部署证据）
- `sel-002-eb3b06d-imac-final-2026-11-14.txt` — imac block4 日志 + --version + 终态台账
