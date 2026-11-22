# WG-NT boot trigger 部署面：测试床开机自启验收（2026-11-22）

任务书 WG-NT-SWITCH（todo.md）遗留「boot trigger 部署面」：七项验收 item 7
归因收口已坐实 **nt 模型无服务自启面**（无 meshlet 服务、`\MeshletAgentDeploy`
仅 LogonTrigger、agent 由不明外部 session-0 拉起器所启），ADR-008 预判成立
——「nt 上线必须补 boot trigger（或等效 SYSTEM 级自启载体）才算满足 reboot
recovery」。本批补上该部署面并在测试床（imac，MS-7C70）真机重启验收。

## 实现

`scripts/install-agent-boot-task.ps1`（ASCII，PS 5.1 实机解析/运行验证）：

- 目标任务 = `\MeshletAgentDeploy`（升级流程既有 Stop/Start 的名字，就地收敛
  而非新增第二拉起器）；幂等：存在走 `Set-ScheduledTask`、缺席走
  `Register-ScheduledTask`，只改任务定义不触碰运行中的 agent 进程。
- 触发器：`BootTrigger`（AtStartup）+ `LogonTrigger`（限定目标用户）。
- Principal：S4U + HighestAvailable（与既有任务同款；item 2 已证 S4U/Highest
  任务内 adapter API 全成功无 UAC）。
- Settings（每条都有理由）：
  - `ExecutionTimeLimit=PT0S`——**默认 72h 会把任务启动的 agent 三天后杀掉**
    （旧任务 XML 无该元素=吃默认值，属潜伏缺陷，本批顺带修复）；
  - `MultipleInstancesPolicy=IgnoreNew`——boot 先启后用户登录时 LogonTrigger
    不再拉第二实例（agent 自身 instance lock 为兜底）；
  - `RestartOnFailure 3 次/1min`——agent 非零退出有界自愈；
  - `AllowStartIfOnBatteries/DontStopIfGoingOnBatteries`——笔记本上不被电池
    策略静默压掉 boot 自启；
  - `StartWhenAvailable`。
- 托盘刻意不入本任务：tray 需 console 会话（session 0 图标不可见，tray-host
  先例），维持原 LogonTrigger 任务/Run key 载体。
- 提权门槛校验（boot trigger + S4U + Highest 注册需管理员），参数校验先于任何
  任务变更（首跑抓到 `-UserId` 参数错时任务未被触碰=fail-safe 顺序生效）。
- **PS 5.1 gotcha 入账**：`New-ScheduledTaskTrigger -AtLogOn` 吃 `-User`，
  `-UserId` 报 NamedParameterNotFound（`-UserId` 是 `New-ScheduledTaskPrincipal`
  的参数）。

## 部署与真机验收（imac 测试床，2026-11-22 12:35-12:45 CST）

部署：SSH（High integrity）跑脚本 → `Set-ScheduledTask` 更新既有任务；运行中
agent（PID 11816）全程未受影响。生效 XML 见 `task-after.xml`（BootTrigger +
LogonTrigger IMAC\cui + S4U/HighestAvailable + PT0S + IgnoreNew + Restart 3x）。

**真机重启**（`shutdown /r /t 30`，12:36:56 起机，端口 22 断 38s 后恢复）：

| 判据 | 结果 | 证据 |
| --- | --- | --- |
| 无人登录 | `quser` = 没有用户（锁屏态，无 type-2 登录） | `attribution.txt` |
| agent 开机自启 | 新 PID 3528，session 0，**Created 12:37:13（起机后 17s）** | `attribution.txt` |
| 启动者归因 | 父进程 = `svchost.exe -k netsvcs -p -s Schedule`（**Task Scheduler 服务本体**）；任务 LastRunTime 12:37:13 与 agent 创建时刻精确一致 | `attribution.txt` |
| 隧道从账本重建 | 04:37:22Z agent starting → orphaned adapter 清理 → driver 1.1 → Creating adapter → 04:37:28Z `applied the desired device plan … reason=KernelDrift`（冷应用）；instance lock 正常持锁 | `log-boot-sequence.txt` |
| 无恢复循环 | 起机后日志无 ERROR/panic/could-not-restore（唯一 ERROR 行是驱动孤儿适配器扫描诊断 0x00000490，紧随 "Removed orphaned adapter" 成功重建，自愈面） | `log-boot-sequence.txt` |
| 数据面连通 | hub ping 全程 0% 丢；`wg show` hub/FSaf/b6tx 握手新鲜（`wg-dump-postboot.txt`） | `wg-dump-postboot.txt`、`ping-cvm-to-imac.txt` |
| RTT 收敛 | pre 重启基线 LAN 面 avg 1.97ms → 起机后 +1min 双端落 ZT 面（min 160.4 / avg 253.6 / max 518.0ms，冷启动面重收敛，fliploop 族既有动态）→ +8min 自然回 LAN 面 avg 2.71ms（端点 192.168.5.117/.188） | `ping-cvm-to-imac.txt` |
| 防火墙 | Meshlet* 规则在场（2 条） | 走查记录 |

**如实边界**：

- TaskScheduler Operational 日志通道被禁（查无事件）——归因不依赖它，由父进程
  PID + 任务 LastRunTime 精确一致 + 无用户登录三重钉死。
- 起机后 +1min ZT 面（avg 253.6ms）属直连面选择的既有动态（fliploop 族，用户
  待拍板残余），非 boot trigger 缺陷；boot trigger 契约=「agent 起 → 隧道从账本
  重建」，两项全 PASS。
- RTT 收敛耗时 ~8min（长于既有文档的 ~3min warmup 口径）——冷启动直连面选择
  重新收敛所致，0% 丢包贯穿，如实记录。

## 结论

- item 7 的部署缺口（**谁来起 agent**）在测试床已闭合：无人登录的开机自恢复
  现在是测试床的真实能力（任务 boot 自启 agent + agent 账本重建隧道，后者此前
  已两次实证）。
- `WireGuardTunnel$` 服务模型的生产三台不受影响也不需要本脚本（服务模型自带
  Automatic 自启）；boot trigger 部署面只服务 nt backend 部署。
- WG-NT-SWITCH 本条保持 `[ ]`：灰度、2-peer+LAN 验收仍待用户拍板/执行。
