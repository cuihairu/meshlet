# 整定批真机观察窗启动：升级 BLOCKED（双机失联）取证（2026-11-19）

巡检单 meshlet-tuning-observe-1119（2026-11-19 14:44 CST 点火）。
目标=双机升含整定批 nightly + 开 ≥24h 观察窗。**结论：升级通道 BLOCKED
（双 Windows 对端失联，两轮探测即停按红线），T0 未启动，窗归集顺延。**

## 前置资产（本侧可做部分，已完成）

- 目标构建：nightly run 44435084924（2026-11-19T01:12:13Z schedule，
  success，36m23s），headSha=615c0342（含整定批三增量 945da62/de86830/
  2a7592a 的超集：另含 tray 单实例 7661152、CI verify 加固 758c97b）。
- 资产新鲜度：release `nightly` 全量 2026-11-19T01:48Z 更新。
- MSI 校验：`meshlet-nightly-windows-x86_64.msi`（11,161,600B）
  SHA256 `c69e8ae41ec37afd2432d1624408e0d09586da71ff0fa094cf691cf5dac76edc`
  对 SHA256SUMS `sha256sum -c` **OK**（本机 /tmp/tuning-deploy 留存，
  双机回网即可直装）。

## 双机失联证据（全 UTC，2026-11-19 ~06:50–07:02Z 取证）

**server 侧（dev VPS，权威面）**：

| 设备 | wg IP | key 前缀 | 最后 hub 握手 | 最后 last_seen |
|---|---|---|---|---|
| openclaw-win (dev-reg-9) | 10.240.0.3 | FSaf/1S9 | **05:05:59Z**（~2h 前） | 05:06:16Z |
| imac (dev-reg-7) | 10.240.0.7 | QmAFaSKb | **00:35:12Z**（~6.5h 前） | 00:34:39Z |
| 对照 coding-vm | 10.240.0.4 | b6txQ61F | 06:59:26Z（新鲜） | 06:59:31Z |
| 对照 windows-desktop | 10.240.0.5 | JMrE4SZy | 1m39s 前（新鲜） | — |

（07:02:16Z 复测 wg show：FSaf 1h56m / QmAF 6h29m 无恢复。）

**coding-vm 视（本机 LAN 192.168.5.188 / ZT 10.147.19.130 全健康）**：

- 本机基线自证：网关 192.168.5.1 ping 0.3ms；zerotier-cli ONLINE，
  PLANET 四节点 DIRECT；隧道面 10.240.0.1（server）ping 0% 丢 7.2ms。
- imac：192.168.5.117 ping 3/3 100% 丢 + **ARP INCOMPLETE**（不在此 LAN，
  整机下电/断网形态）；ZT 10.147.19.117 本就 No route（既有记录）。
- openclaw：10.147.19.49 ping 100% 丢（No route）；隧道面 10.240.0.3
  ping 100% 丢；hub 握手断 = agent 进程死或整机离网。
- 跳板 work-runner → openclaw 10.147.19.49 TCP22：**FAIL**（换路径第 2 轮）。
- 站点判定：openclaw 公网端点=180.153.160.8（**另站点**，非家内
  114.86.101.169 NAT）→ 无 LAN/WoL 触达路径；imac 在家内但整机不在网。

## 红线执行

「升级失败不硬重试超过 2 轮」——两轮探测（06:50Z / 07:00-07:02Z）
全黑即停，记 **BLOCKED（升级通道）**。零回滚需求（双机本就离网，
非升级致损）。未碰 win-worker（永久停用红线）。

## 任务书前提与仓内记录冲突（如实记录，待双机回网核对）

- 任务书称「双机仍跑 11-14 的 c4e5038，收窄后观察窗未启动」。
- **仓内记录与之矛盾**：todo L159（cf5d0a7，2026-11-18 收口）实锤
  双机已升 nightly tag=5760a75（整定批全量，MSI 8657f180、双 exe 同哈希
  F42ABA34、openclaw PID 13908 / imac PID 35160）；窗23 判定单
  （925a1d6）实测 openclaw PID 13908 窗内（11-17T17:00Z→11-18T17:00Z）
  全程未重启、构建连续性成立，且该窗已按四列判定 **0/4 未通过**。
- 现双机离网无法核 exe 哈希终裁。回网后顺序：先核双位 exe 哈希
  （=F42ABA34 则任务书前提不成立、窗23 数据即整定批真窗）→
  再升 615c034 nightly（c69e8ae4 已备好）→ 验隧道 → 记 T0 开新窗
  （新窗仍必要：窗23 判定明示「待 imac 面恢复后新窗复测四项」）。

## BLOCKED 恢复路径

双机回网（openclaw 站点开机 / imac 开机）后重点火本单剩余步骤：
升级→核验（哈希/PID/--version）→coding-vm 侧 ping 对端 20 包采样→
T0 整分落账→todo 批注更新。资产侧无阻塞（MSI 在本地留好）。
