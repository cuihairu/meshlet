# fliploop 修复验收（FLIP-001 候选表纳管 roaming + FLIP-002 demote backoff）— 2026-11-15

巡检单 meshlet-fliploop-fix（用户拍板：①主修 + ③保底，②下发面锚定不做）。本文档
对账两条修复的实现、单测与集成模拟，并如实标注：**真机修后数据本环境不可采（imac
仍跑 bc2d356，部署不在本单范围），待部署后另起观察窗对比**。

## 基线（修前，判定口径不许动）

起点 2026-11-14 15:19 CST（commit bc2d356，**未含修复**）部署后 24h 判定窗
（docs/acceptance-evidence/fliploop-24h-2026-11-15.md）：

| 指标 | 基线（bc2d356，修前） |
|---|---|
| JMrE promote↔demote 环 | 12.69h 812 次 mode_flip（64 次/h） |
| promote→demote 中位时长 | 0.78min |
| 24h 判定窗（07:19Z→07:20Z） | 799 次 flip / 262 个环 / 中位 1.48min，末拍仍翻 |
| promote 时 probe=Unhealthy | 268/530 次（50.6%） |
| promote 面 | 100% 钉死 `10.147.19.97:51821`（JMrE ZT 面）单面 |

机理实锤：「无健康面可选 → 拨劣化面 → SEL-003 打回 → RecoveryGate 放行 →
re-promote 同一劣化面」闭环，正对 FLIP-001/FLIP-002。

## 修后真机数据：本环境不可采，待部署

imac 当前运行 bc2d356（2026-11-14 15:19 部署），修复二进制（f99a7ef + 9f07ecb）
**未部署**。本环境无法产出修后真机数据，本文不编造任何修后数字。部署属另单范围；
部署后需重起 ≥24h 观察窗，用同一判定口径（24h 判定文档四项）对比上表基线。

## FLIP-001：端点候选表纳管 roaming（commit f99a7ef）

实现（`apps/agent/src/candidates.rs` 新建 431 行）：

- `CandidateTable` 三来源：`Config`（服务端权威）/ `Roaming`（内核 wg dump 观测）/
  `Discovered`（探测证实）；Roaming 项 TTL 1800s，Config 不过期。
- `sync_config`：服务端候选权威写入；Roaming 面被服务端确认即升级 Config。
- `observe_roaming`：内核现况面进表（新面返回 true 触发重合并）；
  `refresh_probe_evidence`：探测健康面 last_seen 前移 + Roaming→Discovered 升级
  （demote 后 peer 移出内核、观测断，靠 TTL+探测保鲜续命）。
- `merge_into`：config 原序在前、表内新面按 (ip,port) 排序追加——有效候选集
  喂 SEL-001 探测（`probe.update_candidates`），全部已知面被持续探测。

接线（`apps/agent/src/agent/direct.rs` reconcile_direct）：

- 每 30s 对账：sync_config → retain_peers → expire → merge_into → 探测候选刷新。
- 每 tick：wg dump 过滤 wanted 对端 → observe_roaming → 重合并 + 刷新探测缓存
  （内核漫游出新面即刻进探测视野）。
- **换网立即对账**：`run()` net_events 唤醒处重置 `last_direct_probe = None`
  （30s 节流旁路），下一 tick 立即跑完整直连对账（link up/down、addr change、
  WG rehandshake 均经 net_event 唤醒；接口变化侦测走 platform 抽象，
  Windows 由既有 net_event 平台层对等提供）。
- **恢复门 bypass**：hold_relay 构造处，候选表内存在探测健康面即放行 promote
  （DecisionEvent 记 `probe` / `recovery gate bypassed: face probe-healthy
  (FLIP-001)`）——可达即回直连，不经「先 demote 再等恢复门」旧路径。
- 域层 promote 选面：记忆面（滤 unhealthy）→ healthy 滤后 decide_direct_path，
  候选表面自然参选；测试锚定 promote 落在健康 roaming 新面而非劣化 config 面。

单测（10 条，全绿）：

| 测试 | 锚定行为 |
|---|---|
| `sync_config_marks_and_refreshes_config_faces` | 服务端候选权威写入与刷新 |
| `observe_roaming_flags_new_face_only_once` | 内核新面进表只报一次 |
| `roaming_face_expires_after_ttl_but_refresh_keeps_it` | Roaming TTL 过期 / 探测保鲜续命 |
| `discovered_upgrade_then_expiry` | Discovered 升级与过期 |
| `config_authority_upgrades_roaming_entry` | 服务端确认升级 Roaming→Config |
| `merge_into_appends_table_only_faces_sorted_and_dedupes` | 有效候选集合并去重排序 |
| `retain_peers_drops_entries_of_peers_outside_candidate_set` | 逐出集外对端表项 |
| `refresh_probe_evidence_keeps_healthy_faces_alive` | 健康面保鲜 |
| `has_probe_healthy_face_requires_table_and_probe_agreement` | bypass 判据 = 表∩探测双确认 |
| `flip_sequence_promotes_healthy_roaming_face_without_ring` | **集成模拟**（下节） |

`probe.rs` 伴生：`face_healthy` / `healthy_faces`（单快照批量）；健康 = ≥1 个 Rtt
样本且未劣化（全丢面是「未知」不是「健康」，不许 bypass 放行）。

## FLIP-002：demote backoff promote 侧冷却（commit 9f07ecb）

实现（`apps/agent/src/backoff.rs` 新建 261 行）：

- 第 N 次连续 demote 的 promote 冷却 = `base × 2^(N-1)`，封顶 cap；
  移位防绕回（`checked_shl` 不查值溢出，30_000<<62 绕回 0 的坑已测锚定）。
- 链路持续健康（连续 M 轮探测有健康面，M=`recovery_confirmations` 默认 3）即
  整条清零；不健康轮打断连击但抑制保留。
- 只拦 promote 侧：域层 plan_updates 新增第 10 参 `suppress_promote`，抑制中的
  Relay 对端走 defer 分支（state 留 Relay、记忆面 `last_direct` 原样保留、
  DecisionRecord action=`defer` reason 带连续次数与剩余秒数）；**劣化判定与
  demote 不受影响**（测试锚定抑制中握手过期照常 demote）。
- 计数口径：只对候选集内的对端计数——stale 逐出与开关关闭的行政性 demote 不计。
- 离开候选集的对端状态回收（`retain`）。

配置（`crates/meshlet-config/src/agent.rs`，`[dataplane.backoff]`）：

| 项 | 默认 | 依据 |
|---|---|---|
| `backoff_base_ms` | 30_000（30s） | ≈一个对账周期（30s），首劣化最小拉开 |
| `backoff_cap_ms` | 900_000（15min） | 任务书口径——劣化源持续时不至全哑 |
| `recovery_confirmations` | 3 | 与 SEL-003 RecoveryGate 同值（同源探测证据、同一防抖口径） |

校验：`base ≥ 1`、`cap ≥ base`、`confirmations ≥ 1`，违者 `InvalidDataPlane`。
默认值即本文档表值，亦见 `BackoffConfig` rustdoc。

接线（`apps/agent/src/agent/direct.rs`）：healthy_faces 快照后 `note_health`
逐对端记账 → `suppress_map(now_ms)` 构建 → bypass 分支抑制优先（退避期内即便
有健康面也不 promote，拉开重试间隔）→ apply_plan 下传 → updates 循环对候选集内
demote 计数（`on_demote`）。

单测（13 条，全绿）：

| 测试 | 锚定行为 |
|---|---|
| `delay_grows_exponentially_then_caps` | 30s→60s→120s→240s 指数递增、960s 压到 15min cap、远超 cap 恒 15min |
| `on_demote_suppresses_for_the_backoff_window` | demote 后冷却窗内抑制、窗外解除 |
| `consecutive_demotes_stretch_and_restart_window` | 连续 demote 窗口递增、新 demote 重置计时 |
| `health_confirmations_clear_backoff_fully` | 连续 3 轮健康整条清零（指数计数归位） |
| `unhealthy_round_breaks_health_streak_but_keeps_suppression` | 不健康轮打断连击、抑制保留 |
| `note_health_without_state_is_noop` | 无 demote 历史的对端记账无害 |
| `retain_drops_departed_peers` | 离开候选集的状态回收 |
| `constructor_clamps_invalid_values` | 非法构造参数钳制 |
| `demote_backoff_suppresses_promote_but_keeps_memory_face` | 域层：抑制中 defer 留 Relay、记忆面保留、reason 来自抑制表 |
| `demote_backoff_does_not_touch_demote_sensitivity` | 域层：抑制中握手过期照常 demote（判定灵敏度不降） |
| `demote_backoff_expiry_restores_normal_promotion` | 域层：到期/清零后 promote 恢复、记忆面优先 |
| `agent_backoff_defaults_and_parses_explicit_section` | 配置默认值与显式解析 |
| `agent_backoff_rejects_zero_base_and_cap_below_base` | 配置校验三拒绝 |

## 集成模拟：接口翻转序列不产生 promote→demote 环

`flip_sequence_promotes_healthy_roaming_face_without_ring`
（`apps/agent/src/direct/tests/plan.rs`）三轮对账序列模拟 11-14 日志实锤的环：

1. 第 1 轮：现役面 face_a（ZT 劣化面）探测窗口劣化 → 立即 demote 回中继，
   Direct 记忆面保留（对应基线 demote 腿）。
2. 第 2 轮：Relay + 恢复门放行（FLIP-001 bypass 语义）+ face_a 仍劣化
   （unhealthy_faces 滤记忆面）→ promote 落在候选表健康 roaming 新面 face_b，
   **不重拨劣化面**（打断「无健康面可选→拨劣化面」闭环）。
3. 第 3 轮：face_b 直连、握手新鲜、探测健康 → Keep 无动作。

断言：三轮后无任何 promote→demote 往复（updates 序列 = Demote→Promote→空），
环收敛。FLIP-002 保底独立可证：同一劣化面若持续被拨（无健康面场景），
`demote_backoff_*` 三测锚定 promote 间隔 30s→60s→120s…15min 指数拉长——
基线中位 0.78min 的环频被结构性压低（最坏情况下每环 ≥30s 且逐环翻倍）。

## 门禁

- `cargo test -p meshlet-agent --lib`：**180 passed / 0 failed**。修前基线
  （8913132，161 个测试函数）→ FLIP-001 新增 10 条（9 candidates + 1 flip 序列）、
  FLIP-002 新增 11 条（8 backoff + 3 域层 suppress）；函数计数 182 与执行数 180
  差 2 = 平台 cfg 门控测试（Linux 不编译）。
- `cargo test -p meshlet-config`：**33 passed / 0 failed**（+2 backoff 配置）。
- clippy：host `--all-targets` 0 警告；windows-gnu 交叉 `--all-targets` 0 lint
  警告（仅既有 build-script 图标提示）。
- `cargo check --workspace --all-targets`：净。
- commits：f99a7ef（FLIP-001）、9f07ecb（FLIP-002），英文短句、无 AI 痕迹。

## 剩余边界

1. **真机修后数据本环境不可采**：imac 跑 bc2d356，修复二进制未部署——部署与
   ≥24h 修后观察窗不在本单范围（判定口径与基线已备好，部署后按同口径对比）。
   本环境亦无第二台 Windows 真机可复现 JMrE（ZT underlay 劣化源）。
2. **换网侦测的平台对等性未真机验证**：Linux 侧 net_event（netlink）为既有实现
   已真机实证（BACKOFF_MAX_SECS 30s 事件唤醒）；Windows 侧 net_event 平台层的
   接口起落/地址增删事件在 R-05 验收过链路存在性，但「换网 → 候选表刷新 + 立即
   探测 + bypass promote」整链路的真机时延未测（本轮仅单测与模拟）。
3. **广域打洞（FSaf 跨 NAT）未验**：24h 判定窗内零广域打洞证据；候选表让公网面
   参选探测，但跨 NAT 打洞成功率仍待真机窗。
4. **backoff 参数未经真机调优**：30s/15min/3 为任务书口径推导（对账周期/封顶
   惯例/RecoveryGate 同值），真机上若环频仍高可调 `backoff_base_ms`（如 60s）。
5. **roaming TTL 1800s 未真机校准**：demote 后内核观测断流场景下，表项保鲜
   依赖探测成功；若劣化源静默 >30min，表项过期后回到服务端单面候选——此为
   有意设计（表是加速器不是权威），但 TTL 值本身未经长跑校准。
