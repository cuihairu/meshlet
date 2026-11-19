# 整定批观察窗启动（续）：imac 升 615c034 + T0 落账（2026-11-19）

巡检单 meshlet-tuning-resume-1119（21:5x CST 点火）。前单
tuning-observe-start-2026-11-19.md 因双机失联 BLOCKED；本单 imac 回网续做。
**T0 = 2026-11-19T14:08:00Z（UTC），新观察窗开启，≥24h 后归集判定。**

## 哈希终裁（任务书前提核对结论）

- **imac 侧实锤**：升级前真身 exe
  `C:\Users\cui\AppData\Local\meshlet\meshlet-agent.exe`
  SHA256=`f42aba34055631b9…c5c45`（本单 14:05Z 亲测，与巡检 21:5x 一致）
  = **整定批构建（5760a75/F42ABA34，与 todo L159 cf5d0a7 记账一致）**。
  → 任务书前提「双机仍跑 11-14 c4e5038」imac 侧否定；**窗23
  （11-17T17:00Z→11-18T17:00Z，0/4 判定）即整定批 imac 侧真窗**。
- **openclaw 待核维持**：10.147.19.49 仍离网（公网端点 180.153.160.8
  另站点），其侧前提无法终裁，BLOCKED 批注保持原样不追。

## imac 升级实录（全 UTC，升级窗口 14:05:13Z 点火 → 14:06:22Z 完成，28s）

**升级前**（state-pre 14:05Z 采集）：

- meshlet-agent PID 24028（2026-11-18T15:03:13Z 起），AppData 与 PF 双位
  同哈希 F42ABA34；meshlet-tray-host **双实例**（PID 3088+14996，PF 老
  构建 3f87e910=11-17 版无单实例防护）；AppData 残 tray a4f69f6f（11-13
  陈旧拷贝，本升级不动它——tray 只从 PF 跑，AppData tray 属遗迹）。
- 切换事件 direct-switch-events.json 1,135,323B（14:03:05Z 在写）。

**升级动作**（schtasks S4U 分离任务 MeshletImUp3，scp+-File 播种；
msiexec 不占 SSH 会话防 sshd flap）：

1. 机上 MSI 哈希复核 `c69e8ae4…` 对 SHA256SUMS **MATCH=YES**；
2. taskkill agent 24028 + tray 双实例（14996/3088）成功；
3. `msiexec /i … /qn /norestart` **exit 0**；
4. agent PF→AppData 覆盖拷贝；
5. schtasks /run 重启 MeshletAgentDeploy + MeshletTrayHost 均成功。

**升级后**（state-post 14:06-14:07Z 采集）：

- meshlet-agent **PID 16424**（2026-11-19T14:06:02Z 起，AppData 路径）
  单进程；
- **agent 双位同哈希 `1ec59cbb425d9906…a18768de`**（PF=AppData）；
- **tray-host 单实例**（PID 22712，14:06:17Z 起，PF 377ccd3d）——升级前
  双开形态消除（7661152 单实例防护随新构建就位；注：原双开是旧构建
  所生，此观测证明清理+新构建部署，非防护本身的触发实验）；
- 切换事件 1,135,925B（14:06:18Z 在写，agent 健康产证）；
- `--version` 输出仅 `meshlet-agent 0.1.0`（不含 commit 号）——构建归属
  由链条锁定：MSI 哈希 c69e8ae4 → SHA256SUMS → release `nightly`
  （01:48Z 更新）→ run 44435084924 headSha=615c0342。
- **隧道采样**：coding-vm→10.240.0.7 ping 20/20 **0% 丢**，rtt
  0.535/1.096/3.363ms（14:07:51Z 止）。
- **清理**：MeshletImUp3 已注销、Temp 七文件已删（14:07Z 核净）。

## 构建 artifact 哈希口径 gotcha（记档）

同 run 的 zip 内 exe（agent d82b4ab4/tray 7268a54d/cli a0e04d49）与
MSI 装出 exe（1ec59cbb/377ccd3d/2cd06ee6）**哈希不同**=Rust 默认非
复现构建+CI 分 job 编译所致，同 commit 不同 artifact 通道不可互比。
「双位 exe 同哈希」只在同通道内比较（MSI→装出 PF vs AppData ✓）。

## T0 与新观察窗

- **T0 = 2026-11-19T14:08:00Z**（验证齐 14:07:51Z 后整分；agent 重启
  14:06:02Z，imac warmup ~3 分钟瞬态至 ~14:09Z，归集时窗首 1 分钟
  含 warmup 尾巴，量级可忽略）。
- 窗长 ≥24h → 归集不早于 2026-11-20T14:08:00Z；本轮只记 T0 不判定。
- **对比口径**（todo L157 锁定）：基线窗 2026-11-15T08:57:32Z→
  2026-11-16T09:11:32Z，四列 flips/h 按 peer、环数、roam、rollback；
  预期 roam ≤17、rollback 从 0 起（回滚事件不计 roam）。
- **视角**：本窗按 imac 单视角口径先行（窗23 判定用 OC 视，imac 视
  同样自洽可比），**openclaw 缺位如实注明**（其侧哈希终裁与升级均待
  回网；若 openclaw 中途回网升级，则窗内含构建切换段，归集时分层）。
- **roam 计数口径注记**：beats-inf 是否计入 roam 属待拍板口径新题
  （提案 docs/analysis/roam-counting-kejing-2026-11-19.md，615c034）；
  归集巡检按拍板结果出 A/B 两列或按拍板单列，raw 原文全存。

## 红线执行

零 crates 改动；零 bump/tag/release；win-worker / rillane-runner 未碰；
openclaw 零重试；升级一次成功（<2 轮红线未触发）；todo L157 保持未勾。
