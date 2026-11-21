# ADR-008 七项验收面（nt 模型）imac 重跑（8c1bb93 修复后）：items 1-6 PASS、item 7 部分通过

日期：2026-11-22（凌晨，imac 真机）。性质：ADR-008 七项验收面按 wireguard-nt
模型重跑的**第二轮**——首轮（`wgnt-seven-item-2026-11-21.md`）item 1 抓到
OS 别名缺陷（`InterfaceAlias 'wg-meshlet'` 在 nt 下不存在），修复
8c1bb93（InterfaceDescription 反查 OS Name）落 main 后，交叉重建 + 重部署
imac + 整轮重跑。结论：

- **items 1/2/3/4/5/6 全 PASS**——首轮缺陷修复实锤（防火墙步用反查别名
  `WireGuard` 通过），fail-closed、teardown 零残留、restore 全量重建均过。
- **item 7（reboot recovery）部分通过**——第一次 FAIL 归因为**测试床污染**
  （step12 实验残留的 probe 隧道服务开机自启抢 51820，非产品缺陷），清理后
  干净重跑：agent 启动后隧道从账本全量重建、无恢复循环。但**开机自启动
  机制的归因未收口**（计划任务无 boot trigger、LastRunTime 未变，agent 却在
  开机后 36s 起来了——谁拉起的未定位），且收尾时 imac 失联（LAN L2 不可达），
  归因脚本已备未跑。**boot 面语义按 ADR-008 预设记录为部署缺口：nt 模型
  无服务自启面，开机恢复依赖 boot trigger 或自动登录，未验证。**
- 相邻发现（按任务书指令**只记录不修**）：nt 下 direct 快路径调用
  `wg set wg-meshlet`（服务模型名）恒失败 → direct P2P 在 nt 模型下
  永远建立不起来（回落 hub_relay，功能不瘫但直连面失效）；item 4 诊断性
  缺口（缺 dll 静默退出）；step12 清理遗漏 probe 隧道服务的教训。

证据目录：`docs/acceptance-evidence/nt-seven-accept-2026-11-22/`
（PowerShell 重定向原始输出，GBK 控制台中文为 mojibake，属采集面目非内容问题）。

## 测试物

- `meshlet-agent.exe`：BUILD_INFO commit `8c1bb93f03f964304c41fa602d256852681546dd`、
  built_at `2026-11-21T17:12:13Z`、target `x86_64-pc-windows-gnu`、
  `source_dirty=true`（构建时工作区脏的是 todo.md/证据目录等文档面，
  代码即 8c1bb93，无未提交代码进二进制）。
  SHA256 `ab0c910df24a116bd3f4a136ee00a43af42e6af312a6d56dc12d1c98ff9f2a6d`。
- `wireguard.dll`：SHA256 `b1b85e072c45d81358be29d94c599dc76652f912be8c0f0a41e2d5d89a6461d3`
  （与 PoC/打包 vendor 同 dll）。
- 部署位 `C:\Users\cui\AppData\Local\meshlet\`（exe+dll+BUILD_INFO 三件套），
  来源本地交叉构建产物，哈希与部署副本一致。证据 `build-info.txt`。
- 运行载体：`\MeshletAgentDeploy`（S4U / Highest / UserId `cui` / LogonTrigger
  仅）——elevation 面由该任务承载（item 2）。
- 首轮对照物为 msvc e75e36e；本轮 gnu 8c1bb93，两目标均属支持面。

## item 1 installation（含首轮缺陷修复验证）——PASS

部署 8c1bb93 二进制 → 起 nt agent → 核验（证据 `item1-verify.txt`，01:26）：

- 首轮缺陷修复实锤：**mesh 可达性步用反查 OS 别名通过**——
  `Set-NetConnectionProfile -InterfaceAlias 'WireGuard'` 成功，连接类别
  `WireGuard … Private`（首轮该步 `-InterfaceAlias 'wg-meshlet'` exit 1 整 apply 被拒）。
- nt 隧道功能面全过：adapter `WireGuard` Up（ifIndex 42，Desc
  `wg-mlt-wg-mdc44 Tunnel`）、addr `10.240.0.7/16`、UDP 51820 由
  meshlet-agent.exe（PID 96252）进程内持有、`WireGuardTunnel$wg-meshlet`
  →1060（无服务）、路由三条齐、`wg show WireGuard` 读回一致（hub peer
  `vLkJ…`/keepalive 25s/handshake 1s）、hub ping 3/3 0% 丢 6ms、
  `applied.json` 更新（01:26:33，revision 33）、防火墙 Meshlet 双规则
  Any profile、`direct-port.json`=`{"listen_port":51820}`。
- 近窗日志 `could_not_restore=0`——首轮的恢复错误循环消失。
  `apply_rejected=6` 全部是 direct 快路径 `wg set wg-meshlet` 失败 WARN
  （相邻缺陷，见文末）；`applied=4`（reason=KernelDrift，由 direct 模块
  翻面引发的周期重放，见相邻发现①）。

## item 2 elevation——PASS

S4U/Highest 任务内 adapter 创建/set_config/up/地址路由装配/防火墙全成功，
无 UAC 弹窗、无提权失败。与首轮口径一致（本轮全程同载体复跑）。

## item 3 repeated apply / 重启进程重放——PASS

杀 agent → 计划任务重启（证据 `item3-restart.txt`、`item3-verify.txt`，01:34）：

- 新 PID 1712，adapter `WireGuard` Up、UDP 51820 归新进程、hub ping 0% 丢、
  `applied.json` 01:34:12 更新（revision 33）——账本在、状态从账本重放。
- 连接类别 Private 再次成立；近窗 `could_not_restore=0`。
- `apply_rejected=19` 同为 direct 快路径失败 WARN（非 apply 主路径）。

## item 4 partial failure——PASS（附诊断性缺口，记录不修）

**4a 缺 dll fail-closed**（证据 `item4a-failclosed.txt`，01:38）：
`wireguard.dll` 改名 `.hold` → 重启 agent：

- agent 起来读了 config（日志可见三连 `agent config loaded`）后退出，
  **无 adapter、无 UDP 51820、`applied.json` 不更新**（mtime 冻结 01:38:06）——
  坏件不落半态，fail-closed 成立。
- **诊断性缺口（记录）**：退出是静默的——日志窗口内没有一条指向
  「wireguard.dll 加载失败」的 ERROR/panic 行，现场只能靠「进程反复起又
  消失 + 无 adapter」倒推。缺 dll 应有一条明确日志。

**4b 恢复**（证据 `item4b-restore.txt`、`item4b-verify.txt`，01:41）：
dll 复原 → 新 PID 37128，adapter Up、51820、hub ping 0% 丢、
`applied.json` 01:40:44 更新——全量恢复，无残留半态。

## item 5 uninstall + item 6 route cleanup——PASS

停任务 + 杀 agent（完整卸载面，证据 `item56-teardown.txt`，03:00）——
**零残留**：

- 无 meshlet-agent 进程；无 `WireGuard`/`wg-mlt*` adapter（nt 模型
  adapter 随进程消亡的清理面天然成立）；无 UDP 51820；
- **无 10.240 路由（ActiveStore 与 PersistentStore 双查）**——nt 路由
  不进持久存储，进程死路由净（对照服务模型需 route cleanup 的差异点）；
- `WireGuardTunnel$wg-meshlet` →1060；`netsh portproxy` 空。
- 设计内保留：Meshlet 防火墙双规则、`applied.json`/`direct-port.json`
  账本（重装语义）。

**恢复面**（证据 `item56-restore.txt`、`item7r-preboot.txt`，03:07-03:08）：
重启任务 → agent PID 2344，隧道从账本全量重建（adapter Up、51820、
hub ping 0% 丢、`applied.json` 03:08:17）。

## item 7 reboot recovery——部分通过（污染事故 + 干净重跑 + 归因未收口）

### 第一次（01:42 重启）：FAIL，归因测试床污染而非产品缺陷

重启后核验（证据 `item7-postreboot.txt`、`item7-forensics.txt`）发现
第二隧道抢资源：

- 服务列表出现 `WireGuardTunnel$wg-meshlet-probe` **Running/Automatic**——
  这是 **step12 实验（2026-11-21 11:14）的残留**：`wg-meshlet-probe.conf`
  经 `installtunnelservice` 建的服务，step12 文档「机上残留全清」**漏了
  服务本体**（conf 删了、服务没卸）。Start=Automatic → 开机 01:45:10 自启，
  抢占 UDP 51820 + `10.240.0.7/16`（证据 `item7-probeconf.txt`）。
- nt agent 被挤到探测回退口 52900，且每 30s
  `could not restore the last successful device plan`（`set_config` 报
  Windows `os error 32` 另一程序正在使用此文件）——不收敛恢复循环。
  这反向坐实 §2.5 端口机器级独占：**任何**持有 51820 的第二隧道都会把
  nt 模型顶进该态；端口一旦释放立即收敛（下证）。
- **清理即自愈**（证据 `item7-probeclean.txt`、`item7-selfheal.txt`，
  02:15-02:16）：`sc stop/delete WireGuardTunnel$wg-meshlet-probe` + 删
  conf → agent 同轮自愈：51820 归 agent（PID 13552）、adapter `WireGuard`
  Up、路由齐、hub ping 0% 丢、`applied.json` 02:16:29 更新。无需重启 agent。
- 附带核账：overlay SSH（m-imac→10.240.0.7）超时归因为**本工作站**
  QmAF 死端点黑洞（10.147.19.17 老端点、0 B received），非 nt 切换造成，
  对照证据 imac↔hub 全健康——详见 `item7-overlay-note.txt`（step12 已记录
  的顽疾，本轮只取证明 nt 无辜）。

### 干净重跑（03:09:59 重启）：数据面恢复 PASS；自启归因 OPEN

清完污染后二次重启（证据 `item7r-preboot.txt` 起机前基线、
`item7r-early.txt` 03:15:31 核验）：

- **无 probe 残留**（`wg show wg-meshlet-probe` → No such file；服务列表
  仅 `WireGuardManager`）。
- **nt 隧道开机重建正确**：agent 新 PID 8564 持 51820、adapter `WireGuard`
  Up（ifIndex 2）、hub handshake 38s、keepalive 25s、无恢复循环
  （仅 direct-demote 的良性 WARN，见相邻发现①）——**agent 进程起来后
  隧道从账本全量重建，这条语义成立**。
- **归因未收口**：计划任务 `MeshletAgentDeploy` LastRunTime 仍为
  03:06:32（重启前）、LastTaskResult 1——**任务没有在开机时跑过**，
  但 agent 在开机后 36s（03:10:35）起来了。谁拉起的未定位（无 boot
  trigger、任务未跑、Run key/启动目录/事件日志未及核查）。归因脚本
  `item7startup.ps1`（枚举 meshlet 任务+trigger、TaskScheduler Operational
  100/102/107/110/129/200/201、Run key、启动目录）已备好，**执行前 imac
  失联**（见下）。
- **imac 失联**：03:15:31 最后一次成功 SSH 取证后，主机从 LAN 消失
  （192.168.5.117 ARP INCOMPLETE / No route to host，本机网关与外网正常，
  2026-11-22 ~04:45 多次重试未回）。归因脚本待主机回归后补跑。

### 判定

- **「agent 起来 → 隧道从账本重建」：PASS**（两次重启均证）。
- **「无人登录的开机自恢复」：未验证 + 部署缺口**——nt 模型无服务自启面
  （ADR-008 预设），boot 恢复需要 boot trigger 或自动登录；当前载体只有
  LogonTrigger，且本轮 36s 自启的机制不明。**在归因收口 + boot trigger
  落位前，不得宣称 nt 模型开机自愈。**
- 第一次 FAIL 不计入产品缺陷账（测试床污染），但两条教训入账：清理声明
  必须显式枚举 `WireGuardTunnel$*` 服务；Automatic 服务的实验残留会在
  重启类验收里引爆。

## 相邻发现（按任务书：记录不修，勿扩面）

1. **nt 下 direct 快路径恒失败（新 nt 缺陷）**：direct promote/demote 走
   `wg set wg-meshlet`（服务模型接口名），nt 下接口是 `WireGuard` →
   每次报 `apply rejected: wg set wg-meshlet: Unable to modify interface:
   No such file or directory`，peer 翻面回落 hub_relay（`probe Unknown`/
   `pending attempts exhausted`）。**后果：nt 模型 direct P2P 永远建立
   不起来**（hub relay 兜底、连通性不瘫）；且 direct 模块反复翻面引发
   reconcile 周期性 KernelDrift 重放（`applied=4/13/19` 观测）。证据：
   `item1-verify.txt` L121-123、`item4a-failclosed.txt` L15-19、
   `item7r-early.txt` 尾部。待修面与 8c1bb93 同源：direct 模块的 wg 工具
   调用面也要过 nt 别名解析。
2. **item 4 诊断性缺口——已修复（本批）**：缺 wireguard.dll 时 agent
   `Agent::new` 失败只 `eprintln` 到 stderr；本进程经 MeshletAgentDeploy
   （S4U/无 console 会话）运行，stderr 无人接 → 启动期失败原因在日志
   不可恢复（观察到的「config loaded ×3 后静默消失」）。修复：main.rs
   启动失败路径同写 `tracing::error!`（state/logs 文件 sink），失败原因
   落日志。**未改**：进程仍 fail-closed 退出（正确行为），只补了可观测性。
3. **QmAF 死端点黑洞**（既有、非 nt）：本工作站 10.240.0.7/32 钉死
   ZeroTier 死端点不回落 hub——`item7-overlay-note.txt`（step12 顽疾，
   overlay SSH 断连的既有成因，直连 imac 不受影响）。
4. **实验残留清理规程**：step12「残留全清」漏卸 probe 隧道服务（本轮
   item 7 第一次失败的直接根因）。wireguard.exe 模型的实验必须
   `sc delete WireGuardTunnel$*` 显式枚举后核对 1060。
5. lan 过收（is_windows_lan_interface 相邻已知）：本轮未见 lan 面异常
   表现，无新增可记（首轮亦无）。

## 判定汇总

| item | 面 | 判定 | 关键证据 |
|---|---|---|---|
| 1 | installation（含 8c1bb93 修复验证） | **PASS** | `item1-verify.txt`（反查别名防火墙步过、读回一致） |
| 2 | elevation | **PASS** | S4U/Highest 全程 adapter API 无 UAC |
| 3 | repeated apply/进程重启 | **PASS** | `item3-verify.txt`（账本重放、Private 复立） |
| 4 | partial failure | **PASS**（诊断性缺口记录） | `item4a-failclosed.txt`/`item4b-verify.txt` |
| 5 | uninstall | **PASS** | `item56-teardown.txt`（零残留） |
| 6 | route cleanup | **PASS** | 同上（Active+Persistent 双查空） |
| 7 | reboot recovery | **部分**：账本重建 PASS；boot 自启未验证（归因 OPEN + imac 失联） | `item7r-early.txt`、污染链 `item7-probe*.txt`/`item7-selfheal.txt` |

对 WG-NT-SWITCH 的含义：七项重跑完成，**1-6 PASS、7 部分**；未勾条件
「回滚与灰度走查 + 真机 2-peer」仍在；**现网三台仍 wireguard.exe 模型、
禁写「已切换」不变**；新增待办：direct 快路径 nt 别名缺陷、item 7 自启
归因（imac 回归后跑 `item7startup.ps1`）、boot trigger 部署面。
