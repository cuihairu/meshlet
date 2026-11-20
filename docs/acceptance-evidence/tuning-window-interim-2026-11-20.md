# 整定批观察窗归集实录（中期，窗未满——2026-11-20T10:0xZ 取证）

任务单 meshlet-tuning-window-judge 前提为「OC 判定窗 2026-11-20T17:17Z 已到、
imac 窗 14:08Z 已满」。**实测否决该前提**（下述时钟证据）：两窗均未满 24h，
本单按单内约束「数据缺失如实记录、不伪造判定」落**中期归集实录**，判定另候窗满。

## 时钟与窗口真值（取证 2026-11-20T09:56Z–10:06Z）

- 本机 coding-vm `date -u` = 2026-11-20T09:44:14Z；GitHub run 44672780434
  createdAt=04:11:51Z 同纪元互证。
- openclaw：TZ=China Standard Time；UTCNOW=2026-11-20T09:56Z 级；
  **exe mtime（LastWriteTimeUtc）= 2026-11-19T17:17:24Z**（真 UTC，非 CST）。
- imac：TZ=China Standard Time；UTCNOW=2026-11-20T09:49Z 级。
- 结论：OC 判定窗 T0=11-19T17:17:24Z，取证时窗龄 **16.6h/24h**（差 7.4h，
  满点=2026-11-20T17:17Z=北京 11-21 01:17）；imac 窗 T0=11-19T14:08Z（证据
  tuning-observe-start-2026-11-19b.md 锁定 UTC），窗龄 **19.8h/24h**（差 4.2h）。
  任务书「已满」为 CST/UTC 混算（17:17 与 14:08 均按 CST 折算则恰「刚满」，
  但两真锚均为 UTC）。**判定不授权，本单零判定。**

## 构建与进程连续性（窗内事实）

- openclaw agent：PID 5076，**start=2026-11-20T01:37:50Z**（窗内重启一次）；
  exe SHA256=cdf346c22cd87fba75afe373ffe1b508975735f6bfe597983de5b2cc050a95e1
  （mtime 11-19T17:17:24Z=tray 批 nightly，含整定码）。机器 boot=
  2026-11-19T14:08:18Z（EventLog 6008/6005 @14:08:47Z 佐证）——01:37Z 重启
  **非机器重启**（boot 早 11.5h），成因未证（exe 未换、事件流 01:35-01:50Z
  连续无断点）。RUN[meshlet]（tray 自启项）值为空=tray 未随启（只记不判）。
- imac agent：PID 13780，start=2026-11-19T14:28:16Z，exe SHA256=
  1ec59cbb425d9906797503166a2411a9493c4b4dd1f65d7da8252d18a18768de
  （615c034 nightly，tuning-observe-start-b 记账同哈希），窗内未重启；
  mtime=11-18T17:45:08Z 为 zip 内构建时戳（非部署时刻，部署=11-19T14:06Z）。

## 数据面（取证时刻）

- openclaw direct-switch-events.json：size=1,725,550B（10:0xZ），5725 行，
  span 2026-11-14T02:49Z→2026-11-20T09:58Z；agent-decisions.jsonl 13,224 行
  （last 09:58:14Z）——两流在写。
- imac：direct-switch-events.json size=1,207,611B，3,960 行，span
  2026-11-14T02:46Z→2026-11-20T10:00Z 级；decisions 6,701 行。
- **双机共同静默段**：OC 决策 03:45:39Z→07:30:57Z 断档 225min（切换事件
  03:57Z→06:57Z 整 3h 零条）；imac 决策 03:44:37Z→09:53:11Z 断档 369min。
  两机同一秒级（03:44-03:45Z）起静默、且 OC 事件流 09:53Z 与 imac 同刻
  恢复（imac 决策恢复首条=cuihaitao promote @09:53:11Z）——共同上游=hub
  （106.14.216.177 dev VPS）侧扰动的特征形态，非两 agent 各自故障。
  该段落在 OC 窗内占 3-4h，判读时按「hub 静默段」分层注记。

## 方法自洽（先复现已知窗再读本窗）

同解析脚本（flip=kind mode_flip；roam=无 kind 端点切换；rollback=reason 含
rollback；环数 defB=verified→demote 直连存活期）：

- 基线窗复现（11-15T08:57:32Z→11-16T09:11:32Z）：flip 975（JMrE 214/QmAF 611/
  b6tx 150）、roam 18（QmAF 11/b6tx 7）——对锁定值 976/18 差 1 条 flip
  （2.5 天轮转漂移，window23 判定单同源记载）；环数 JMrE 61/QmAF 122/b6tx 49
  （原 ad-hoc n=76 定义残差已声明）。
- window23 复现（11-17T17:00Z→11-18T17:00Z）：flip 962（227/441/294）、
  roam 75（QmAF 67/b6tx 8）、rollback 0、环数 68/23/97 中位 1.07/6.39/3.35
  ——与 fliploop-fix-window23-verdict-2026-11-19.md 全数吻合（含中位）。

## 中期四列（OC 视，T0=11-19T17:17:24Z→取证 09:5xZ，16.6h 未满窗）

| 列 | 基线（24.23h） | 中期（16.6h） | 折算注记 |
|---|---|---|---|
| flip/h 按 peer | 40.3/h（JMrE 214/QmAF 612/b6tx 150） | **24.1/h** 总 402（QmAF 298/b6tx 102/JMrE 0） | -40% 方向降；JMrE(wd) 已不在 mesh |
| 环数（defB） | n=76（ad-hoc 口径）/61+122+49=232 | QmAF 35（中位 2.27min）/b6tx 33（中位 13.66min）/JMrE 0 | 率折算约 -60% |
| roam | 18（QmAF 11/b6tx 7） | **33**（QmAF 24=beats-inf 21+beats-数值 3；b6tx 9 全 beats-数值） | 率折算≈48/24.23h，高于基线与 ≤17 预期 |
| rollback | 0 | **0** | 「从 0 起>0」未达（窗未满前不下终判） |

- 任务书引中期读数「26h 648 flip（QmAF 472/b6tx 138/JMrE 38）24.9/h」与本
  实测 24.1/h 同率级（-38% 对 -40%）；其绝对数未能用现文件任一起止窗复现
  （JMrE=38 需含 11-19 白天段，起窗早于 17:17Z），按单内口径以本实测为准。
- 滚动 3h（窗末向回）：7.7 / 0.0 / 34.7 / 40.0 / 33.7 / 29.3 flips/h——
  前 9.5h 均值 35.3/h 与基线同率级，「降 38-40%」主要由 hub 静默段与
  QmAF 翻转收敛贡献，非全窗匀降。
- imac 视交叉（14:28Z→03:44Z 数据实覆盖 13.3h）：flip 214（FSaf=OC 212/
  b6tx 2）、roam 1、rollback 0、环数 FSaf 61（中位 0.75min）；imac 视
  OC↔imac 链为主要翻转载荷（与 OC 视 QmAF 298 互证）。

## 结论

**窗未满（OC 16.6h/24h、imac 19.8h/24h），判定不授权，本单零判定零勾选。**
中期读数方向：flip 率 -40%、环数折算降序、roam 折算仍超预期上界、rollback
仍 0——与 todo L157 预期方向「部分行进、roam 未收敛」的形态一致，但含
hub 静默段混杂变量，最终四列判定须待 OC 窗满（2026-11-20T17:17Z 起）
后归集。窗满判定时应注意：①17:17Z 前再次重启/静默需同法分层；②beats-inf
是否计 roam 仍属待拍板口径（docs/analysis/roam-counting-kejing-2026-11-19.md）。

## raw 数据（repo 入库）

- `tuning-window-oc-switch-2026-11-20.jsonl`（437 行）=OC 视窗内切换事件原样，
  每行附 `at` 可读时间；`tuning-window-imac-switch-2026-11-20.jsonl`
  （215 行）=imac 视同。解析口径见「方法自洽」节；全量 6.4MB 原始文件不入库。
