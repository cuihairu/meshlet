# SEL-002 imac↔openclaw 双机真机验收（2026-11-13）——部分达成：demote→re-promote 未复现

对应巡检单「SEL-002 真机验收与三机 nightly 升级」。**结论先行**：

- ✅ openclaw 升级到与 imac 同版 nightly（含 df21f88 + 00da12b 探测默认开），升级证据闭环；
- ❌ 直连/中继切换场景（demote→re-promote 自愈周期）**未测得**：三轮防火墙注入 + ~50min 自然劣化窗连续采样中 `mode=p2p_direct` 零 demote，Linux 侧 32-34s 基线（coding-vm 2026-11-13 journalctl 实录，todo「spoke-to-spoke 转发断连调查」条目）**未在 Windows 双机复现**。不冒充已验；
- 🎯 但本轮抓到两个 Windows 实锤，解释了 demote 为什么结构性不可能：
  1. **握手新鲜短路**（todo「spoke-to-spoke」条目残余跟进的同类缺陷，本机 Windows 复现）：`last_handshake_at` 冻结 133–203s 期间 `rtt_source=handshake_fresh` 一直成立，`classify_probe` 按 `DIRECT_HEALTH_WINDOW_SECS=240` 判 Healthy，探测从不触发；
  2. **直连面骑在匿名 ZT 成员 `10.147.19.17:51820` 的中继面上**：openclaw 的 imac-peer WG 会话实际端点是 .17（既非 imac 的 ZT .226，也非 hub 的 .248），其握手穿过**已验证生效的**双向防火墙封锁持续刷新——「直连」的活性证据由一条打不死的中继面供给。

## 前置：openclaw 升级记录（2026-11-13 15:4x–16:0x）

升级前基线（ssh openclaw，PowerShell 原生）：

- AppData 运行位 `C:\Users\Administrator\AppData\Local\meshlet\meshlet-agent.exe` **8,759,731 B，mtime 2026-11-07 13:20:43**（11-07 后未升过，不含 df21f88/00da12b）；
- 计划任务 `MeshletAgent` Ready；单进程 PID 596（2026-11-10 23:09:21 起）；
- `--version` 报错（6a9ec71 修复前的旧构建把 `--version` 当配置路径）——反证待升级；
- 隧道：coding-vm → 10.240.0.3 **10/10 包 0% 丢，均值 9.7ms**。

升级与验收：

- nightly `meshlet-nightly-windows-x86_64.msi` SHA256 `5393763334eceb46f3f8810edafaed16371daf7c02b1f02a6c54e56058741bfe` 对 release SHA256SUMS ✓，scp 后 openclaw `certutil -hashfile` 复核同值 ✓；
- `msiexec /i /qn /norestart` exit 0；agent 经计划任务重启，**新单进程**；
- Program Files 与 AppData 双位 exe 同哈希 `96FA2777D4B0C819CFCC00D9EEAC2FC6C8AD58B940E4ED8FC01F341B49EAE3C3`——**与 imac 同一 nightly 构建一致**（血缘链：SHA256SUMS → MSI → Program Files exe → AppData exe）；
- ARP 注册 ✓；`meshlet-agent --version` → `meshlet-agent 0.1.0` 干净；
- 隧道恢复在线（coding-vm 复测实数：0% 丢，15.6/16.9/18.2ms 与 1.4/9.2/24.9ms 两组；另有一组 1626–2180ms 0% 丢为恰逢自然劣化窗，见下）。

## 拓扑事实（本轮硬确认）

| 节点 | ZT 地址 | WG 对端关系 |
|---|---|---|
| imac（192.168.5.117 LAN） | **.226 唯一**（接口深查：无 .17） | openclaw 的 ledger 名 `imac`；imac 的 ledger 名 `openclaw-win` |
| openclaw（ZT .49） | .49 | WG pubkey `FSaf/1S9…` |
| dev VPS hub | .248 | L3 无 NAT 中继（MLT_wg0 FORWARD wg0→wg0 ACCEPT，4.54M pkts，源地址保留） |
| **匿名成员** | **10.147.19.17:51820** | 身份未确认（非 imac、非 hub；应答 coding-vm ping 3/3，而 .226 同窗 100% 丢） |

环境敌意：16:3x–17:2x 下午为**滚动路径特定劣化窗**——openclaw↔imac 路径反复全死（100–3333ms RTT 与整段 100% 丢交替），同刻 openclaw↔coding-vm 正常。自然窗的烈度与时长超过注入窗，全部实验都在它的背景下进行。

## 方法

schtasks SYSTEM 模式（`/SC ONCE /ST 23:59 /RU SYSTEM` + `/Run`）驱动 PowerShell 注入脚本，2s 间隔快照 openclaw ledger `direct-peers.json` 的 imac 条目（mode/rtt_ms/rtt_source/endpoint/last_handshake_at）+ VIP ping。三轮：

1. **auto**（17:07:32–17:22:16，`sel-002-openclaw-obs-auto-2026-11-13.txt` 252 拍）：BASE 6 拍 + 2 轮×（BlockOn → 60 BLOCK → BlockOff → 60 RECOVER）；双向封锁 `10.147.19.17,10.147.19.226`；
2. **manual**（17:28:08–17:32:49，`sel-002-openclaw-obs-manual-2026-11-13.txt` 70 拍）：健康窗等待（连续 2 拍 <500ms，14 tries）后注入；每拍回读 `Get-NetFirewallAddressFilter` 验证规则在位（`addr_out=10.147.19.17 10.147.19.226`，`fw=True` 全程）；
3. **systest**（17:45:47–17:46:03，SYSTEM 语境判别实验）：规则创建+enabled 验证、ZT ICMP 对照封锁判别、`wg show wg-meshlet dump` 运行时真值。

imac 侧（LAN ssh）：`wg show wg-meshlet` 全 4 peer 握手新鲜；ledger 全 `p2p_direct`/`handshake_fresh`；ZT 接口 .226 唯一。

## 时间线（硬数字）

auto 轮（endpoint 简写：.226=imac ZT 端点，.17=匿名面；hs=ledger `last_handshake_at`）：

| 时刻 | 事件 | 关键读数 |
|---|---|---|
| 17:07:33–43 | BASE 健康 | ep=.226，ping 8–17ms，hs=1794560797 |
| 17:07:45 | R1 FW_ON | 封锁 .17+.226 双向 |
| 17:07:56 | VIP ping 全死 | mode 仍 p2p_direct |
| 17:09:33 | **ep 翻转 .226→.17** | hs 仍冻结 1794560797（已冻 111s） |
| 17:10:15–17:11:10 | **封锁中 ping 复活** 7–14ms×27 拍 | 规则在位却拦不住会话 |
| 17:10:35 | **hs +203s 跳变** →1794561000 | 封锁中经 .17 面完成新握手 |
| 17:11:31 | R1 FW_OFF | fail 持续至 17:12:41 |
| 17:12:49 | hs +158s →1794561158 | |
| 17:14:41 | R2 FW_ON | |
| 17:15:11 | **ep 翻转 .17→.226** + hs +80s →1794561238 | |
| 17:15:59–17:16:17 | 封锁中 ping 复活 8–25ms | |
| 17:16:19 | **ep 翻回 .226→.17** + hs +120s →1794561358 | |
| 17:18:25 | R2 FW_OFF | 17:18:41 ep 翻回 .226（hs 此刻已冻 142s） |
| 17:19:41 | hs +182s →1794561540 | 随后 397→2222ms→fail 滚动（自然窗） |
| 17:20:47 | hs +68s →1794561608 | 17:21:18 起短暂 5–15ms 后再劣化至 3333ms |
| 17:22:16 | RUN_END | **252 拍 mode=p2p_direct、src=handshake_fresh 无一例外** |

manual 轮（规则每拍验证在位）：17:29:11 注入 → 封锁中 hs 1794561975→1794562148（**+173s**，17:29:47，握手经 .17 面照常刷新）→ 17:30:54 ep 中途翻转 .17→.226 → 17:31:30 FW_OFF → hs +122s →1794562270（17:31:59）。70 拍全程 p2p_direct。

systest（SYSTEM 语境，verbatim）：

```
SYSTEST_START 17:45:47.896
created: out=True outEnabled=True in=True inEnabled=True
addr_out=10.147.19.17 10.147.19.226
zicmp226 fail ×4          ← 规则确实拦得住 ZT ICMP（判别对照）
vip ok 610ms / 1659ms / 74ms
wgimac: QmAFaSKbFqm3qGql/DH+mJOWSfN1n6VyNhXwaRrXdlg= (none) 10.147.19.17:51820 10.240.0.7/32 1794563144 2456757680 23415561600 15
zicmp130 fail             ← 自然窗同时压 .130（对照也失败，诚实记录）
SYSTEST_END 17:46:03.650
```

wg dump 证明运行时真值：imac-peer 的 roaming 端点 = `10.147.19.17:51820`，握手新鲜（1794563144，拍前 ~90s 内），keepalive 15s（`DIRECT_PERSISTENT_KEEPALIVE_SECS`）。

## 实锤 1：握手新鲜短路（Windows 复现 todo「spoke-to-spoke」残余跟进同类缺陷）

- `classify_probe`（crates/meshlet-domain/src/p2p/link.rs:88）按 `DIRECT_HEALTH_WINDOW_SECS=240`（link.rs:24）判 Healthy——本轮实测 hs 冻结 **133–203s**（封锁中 +203s 才跳变；R2 RECOVER 冻 142s 后 +182s 跳变）全部落在 240s 宽限内 → 探测（`DIRECT_PROBE_INTERVAL_SECS=30`，link.rs:11）从未获得触发理由；
- 冻结期内 `rtt_source=handshake_fresh` 全程成立——展示与判定都把「握手曾活」当「链路活着」，无时延维度（与 todo 记录的「openclaw 直连 1715ms probe_ok 仍钉直连」同一类）；
- 推论：**只要存在任何一个能维持握手新鲜的面，demote 在结构上不可能发生**——本轮的 .17 面恰好就是这样的面。

## 实锤 2：.17 匿名面——「直连」骑在打不死的中继面上

- openclaw 的 imac-peer WG 会话运行时端点 = `10.147.19.17:51820`（wg dump + ledger 双证）；而 imac 的 ZT 接口只有 .226（深查：接口表、路由表 10.147.19.0/24 仅 ZT 一条）——**.17 不是 imac**，也不是 hub（.248）；
- 封锁规则双向拦 .17+.226 且**验证过生效**（systest `zicmp226 fail×4` 判别对照成立；17:39 管理员手测 ping226 fail + ping130 ok 8ms 同证），但 WG 会话的握手仍穿封锁刷新（17:10:35、17:29:47、systest 17:45:58 三处独立实证）——**防火墙规则拦不住该隧道流量，机制未解**。假说：(a) `WireGuardTunnel$…` SYSTEM 服务的 WFP 层 bypass；(b) 会话实际走在另一条不被这些规则覆盖的路径上。诚实记录未解，不下结论；
- ledger endpoint 的 .226↔.17 翻转（17:09:33 / 17:15:11 / 17:16:19 / 17:18:41 / 17:30:54）是 WG roaming 与 agent 重下发（probe.rs:138「当前已下发的直连端点」）的效应，**不是**健康候选切换决策——翻转发生时 mode/src 从未变化；
- .17 是 ZT 网络里的匿名第三成员（应答 coding-vm ping 3/3，同窗 .226 是 100% 丢），应答者是谁、为何 openclaw→.17 的 WG 包免疫封锁，待 ZT 控制器/central 对账（本地 controller.d/network 为空，本轮未取到成员表）。

## 对照：imac 侧为何同样不 demote

imac 的 openclaw-win peer：endpoint `.49:51820`、握手 55s 新鲜；imac→openclaw 探测路径本身通（劣化窗是 openclaw↔imac 路径特定的）→ probe_ok → imac 同样钉死直连。**双侧各自握着一份「链路活着」的证据**（openclaw：.17 面握手新鲜；imac：probe_ok），劣化窗再深也到不了状态机。

## 与 Linux 基线对比

| 项 | Linux（coding-vm，2026-11-13） | Windows（imac↔openclaw，本轮） |
|---|---|---|
| demote→re-promote | 3 轮实测 32–34s（journalctl 直连事件实录） | **未测得**（零 demote） |
| 劣化证据到达状态机 | 探测失败 → 立即 demote | 被 handshake_fresh 短路 + .17 面供活 |
| 结论 | 切换机制本身工作 | 差异不在切换实现，在**劣化输入层** |

## 判定与剩余工作

**判定：部分达成。** 升级项完整闭环；切换场景未通过（未测得，非失败——是结构性测不到）。

1. **.17 身份对账**：ZT central/控制器取成员表，确认匿名成员与 openclaw→.17 路径的免疫机制；
2. **劣化判定加时延维度**（todo「spoke-to-spoke」残余跟进已立案）：hs 新鲜但 RTT 深劣化时应可 demote；
3. **复验环境**：需让直连面**真死**的手段——全 faces（.17+.226+hub）封锁、或直接禁用 ZT 接口制造确定性断链，届时 32-34s 口径可复跑；
4. 三机 24–48h 观察不在本单范围。

## 证据文件

- `sel-002-openclaw-obs-auto-2026-11-13.txt` — auto 轮 252 拍全量（17:07:32–17:22:16）
- `sel-002-openclaw-obs-manual-2026-11-13.txt` — manual 轮 70 拍（17:28:08–17:32:49，规则逐拍验证）
- `sel-002-openclaw-obs-naturalwin-2026-11-13.txt` — 自然劣化窗观察 297 拍（注入前环境基线）
- systest verbatim 嵌入本文档（原始落盘文件清理时未及抢收，从会话实录恢复）

## 清理记录

- openclaw：计划任务 `meshlet_sel002_run`/`_manual`/`_sys` 删除 ✓（23:59 无重燃）；防火墙规则 before 扫描为空=无孤儿规则（含被中断的 `.17` 封锁测试，其远端脚本从未建成规则）；`sel002*` 文件 14 个删净 ✓；
- imac：`C:\Users\cui\imac-deep.ps1` 删除 ✓；
- 本地原始副本留存 `/tmp/sel002-fetch/`。
