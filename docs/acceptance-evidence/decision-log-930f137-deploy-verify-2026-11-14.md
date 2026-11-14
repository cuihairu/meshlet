# 决策日志 + 模式翻转入账 — 930f137 真机部署验证（2026-11-14）

巡检单 meshlet-nov14-1006（观测性欠账两条）落地与部署验证记录。前一轮（sel-002-eb3b06d）
的诊断缺口：Windows schtasks 上下文 agent 不落决策日志（降级原因无文件级回放）、
direct-switch-events.json 不记录 hub↔direct 模式翻转（swsz 恒 865）。本轮 930f137 两条全落地。

## 落地内容（commit 930f137，已推 main）

1. **决策日志**：`{state_dir}/agent-decisions.jsonl`（JSONL，8MiB 滚动 `.jsonl.1`）——
   状态机每条判定（promote/demote/hold_relay/probe、mode 迁移、reason、判据输入：
   握手年龄 / 劣化 / endpoint / 探测窗口摘要）逐条入账。RFC3339 真 UTC（chrono Utc，Z 后缀；
   PS 5.1 `Get-Date -UFormat %s` +28800s 伪影口径禁用，本轮又复现实锤一次：
   同刻 UFormat 读 1794653166 vs 真值 1794624372，差 28800±37s）。
2. **模式翻转**：SwitchEvent 增可选 `kind`/`detail`/`ts`（缺省 = endpoint 漫游，旧事件行
   零感知向后兼容，与旧事件同文件共存）；`from_mode ≠ to_mode` 即记一条
   `kind="mode_flip"`（方向、原因、对端 keyed、判据摘要 detail）。
   pending 验成（Keep 动作但 direct_pending→p2p_direct）也入账，不漏翻转。

门禁：network 193 / agent lib 153 全绿（基线 189/144 + 新测 4/9）、clippy -D warnings 净、fmt 净。

## nightly 与部署（run 43545872841，workflow_dispatch）

- nightly run 43545872841 SUCCESS；nightly tag → **930f137**（= HEAD，逐字符核对 ✓）
- MSI SHA256 `d14c774e3064f6345e9b73b22516407bd5f84421b9ac61d952ec74e6bab09f06` 对
  SHA256SUMS ✓（旧构建 e9fc9ff0… 已被替换 = 确为新构建）；两机同一 MSI
- **imac**（10:46:19–10:46:29，schtasks MeshletAgentDeploy 流程：MSI→PF→覆盖 AppData(cui)→重启任务）：
  BEFORE_PID 14444 → AFTER_PID 37448；MSIEXEC_RC=0；PF/AppData 双位 exe 同哈希
  `C412F459…3D405`；`meshlet-agent 0.1.0` ✓
- **openclaw**（10:48:48–10:49:01，schtasks MeshletOcUp3 SYSTEM 分离执行防 sshd flap）：
  BEFORE_PID 3284 → AFTER_PID 8988；MSIEXEC_RC=0；双位 exe 同哈希 `C412F459…`（与 imac
  逐字符一致 = 同构建）；`meshlet-agent 0.1.0` ✓；MeshletOcUp3 任务自删确认
- 隧道在线：openclaw VIP 10.240.0.3 ping 8–12.5ms ✓；imac VIP ICMP 由来不答（wg 接口
  防火墙，2026-11-07 取证），改证 direct-peers.json：三对端全 p2p_direct + handshake_fresh
  （last_handshake_at 与采集时刻差 <30s）

## 观测验证（两绿点全过）

**① 决策日志在 schtasks 上下文产出（此前缺口）**：
- imac `C:\Users\cui\AppData\Local\meshlet\state\agent-decisions.jsonl`：agent 启动后即出
  （695B→15 条），实录 JMrE 完整晋升生命周期：promote attempt via candidate table →
  pending verified: fresh handshake (probe Healthy)，handshake_age_secs=22 原样入账
- openclaw `C:\Users\Administrator\AppData\Local\meshlet\state\agent-decisions.jsonl`：3084B/11 条，
  **部署窗口恰逢 .226 ZT 面自然劣化，全决策路径被生产实录**：
  - `demote p2p_direct→hub_relay, reason "sel003 degraded: probe window (consecutive-lost /
    median-rtt gate)", probe_window "L,15,7,L,L,L,L loss=71% med=Some(11)ms"`——
    **此前不可回放的降级原因，现在窗口摘要逐拍可读**
  - `hold_relay hub_relay→hub_relay "recovery gate: not yet N consecutive healthy rounds"`（逐轮）
  - `demote direct_pending→hub_relay "pending attempts exhausted after 3 rounds"`
  - `promote via candidate table` 与 `promote via memory face (last_direct)` 两种来源同日志可辨
    （后者回 10.147.19.226:51820，880b49a 记忆面语义的入账面）

**② switch-events 出现翻转类型字段**：
- imac 尾部 2 条 `kind:"mode_flip"`（hub_relay→direct_pending、direct_pending→p2p_direct，
  带 detail 判据摘要与 RFC3339 ts）；同文件前部旧 endpoint 漫游事件无 kind 字段原样可读
  （向后兼容 ✓，文件内新旧共存实证）
- openclaw 尾部 3 条 `kind:"mode_flip"`（pending 超时降级、candidate 表晋升、memory 面晋升）

时间戳抽验：`2026-11-14T02:46:37Z` = 本地 10:46:37+08:00（imac 侧升级完成后 8s）✓；
imac 时钟较 coding-vm 快 +36s（[DateTimeOffset]::UtcNow 真值口径，非 UFormat）。

## 现场杂录

- 部署中段 coding-vm→openclaw ZT 直连面劣化（No route to host，~5min），overlay 数据面
  全程健康（10.240.0.3 恒 8ms）——改走 router 192.168.5.11 隧道（127.0.0.1:2222）完成
  openclaw 侧核验；收尾已闭隧道、清 2222 临时 known_hosts 条目
- cleanup：两机 C:\Windows\Temp 升级产物（msi/ps1/log）全删核验（imac if exist 双 GONE、
  openclaw 计数 0）；无新增防火墙规则；MeshletOcUp3 自删；本轮零注入、零残留任务

## raw

- `930f137-imac-up-2026-11-14.txt` / `930f137-oc-up3-2026-11-14.txt` — 两机升级日志全量
- `930f137-imac-decisions-2026-11-14.txt`（15 条）/ `930f137-oc-decisions-2026-11-14.txt`（11 条）
- `930f137-imac-switch-events-2026-11-14.txt` / `930f137-oc-switch-events-2026-11-14.txt` — 尾部事件
- `930f137-imac-direct-peers-2026-11-14.txt` / `930f137-oc-direct-peers-2026-11-14.txt` — 升级后链路态
