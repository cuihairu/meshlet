简体中文 | English
# Meshlet TODO

当前需求以个人自托管为边界：不同设备、网络内分组、受控的端口转发与 HTTP 服务路由。2026-10-17 静态审查发现，历史条目中部分“已完成”结论超出代码和测试的覆盖范围；不能继续采用“只剩两项环境走查”的汇总。

- 架构与 TODO 审查：代码证据、六项缺口、新需求模型和重新验收条件。
- Meshlet / ZeroTier / Tailscale 个人组网调研：61 项功能对比、官方来源、个人必要性、开发难度与实测方案。
- 模块化与库复用提案：依赖边界、公共库与渐进迁移；常规虚拟网卡为主，无网卡服务入口按需评估。
- 网关、网段冲突与端口转发专题：分网段选网关、Alias 冲突域和 A 端口到 B 服务的完整场景与验收。
- 网段即信任组设计：ADR-012 已采纳 Network 内 Segment、同段互信、跨段默认拒绝与单向授权契约；IM-01 的模型字段与编译接线、IM-02 的默认段创建/持久化、IM-03 的模型与启动恢复边界校验均已完成；内核策略执行仍由 PN-02 验收。

## 当前执行清单（2026-10-17）

以下优先级为本轮审查建议，未实施方案仍需 ADR；不因登记而自动改变既有技术决策。按依赖推进，先修基础，再扩展服务。状态：待设计 / 设计草案完成 / 待实现 / 修复中 / 待验证 / 已验收 / 暂缓；仅完成对应范围的验收才勾选。

| ID | 优先级 / 状态 | 目标与验收 | 依赖 / 证据 |
|---|---|---|---|
| AR-01 | P0 / 已验收（Linux netns） | 单实例同时承载两个 Network；应用、撤销、清理、恢复互不干扰；主动越权流量被拒绝 | 实测 `MESHLET_REQUIRE_DATAPLANE=1 cargo test -p meshlet-server --locked --test single_instance -- --test-threads=1`：2 passed / 0 failed（128.18s）。双网络建链与恢复断言 `apps/server/tests/single_instance.rs:277`、`:303`、`:360`；失败回滚与另一网络保留 `:389`；跨网拒绝/撤销后断流且同机另一网络存活 `:623`、`:638`。空 VPS 走查仍归 AR-06 |
| AR-02 | P0 / 已验收（API 与控制台验证；业务探测仍显式未接入） | 设备按版本/计划哈希确认应用；hub 成功、设备成功、业务健康分别显示；旧 ACK 不覆盖新状态 | 2026-10-20：`agent_plan.rs::resource_status_waits_for_exact_device_receipts_and_rejects_stale_acks` 10 passed / 0 failed，计划哈希拒绝 `apps/server/tests/agent_plan.rs:772`；设备 pending/failed/applied 收敛 `:762`、`:783`、`:801`；新修订旧 ACK 拒绝 `:823`、`:826`。控制台 Hub / Devices / Connectivity 分别渲染于 `console/src/App.tsx:1804`、`:1808`、`:1816`，`console/src/revisions.test.tsx:37` 断言 9 passed / 0 failed。`business_health` 只验证独立显示和 `not_probed` 默认值，真实业务探测不在本行范围 |
| AR-03 | P0 / 部分验收（Linux netns） | hub 启动与周期漂移对账；接口丢失、VPS 重启后按期望恢复 | 本机复跑 `MESHLET_REQUIRE_DATAPLANE=1 cargo test -p meshlet-server --locked --test single_instance -- --test-threads=1`：2 passed / 0 failed（70.62s）。接口删除、按 SQLite 重建状态与周期恢复断言 `apps/server/tests/single_instance.rs:358`、`:359`、`:363`，恢复后 A 链路与 B 网络保留见 `:366`、`:367`；真实 VPS 整机重启仍未验收 |
| AR-04 | P0 / 已验收（Linux netns） | 保存并恢复上次成功计划；失败恢复不清掉正常连接及其他网络资源 | 实测 `MESHLET_REQUIRE_DATAPLANE=1 cargo test -p meshlet-agent --locked --test plan_recovery -- --test-threads=1`：3 passed / 0 failed（17.85s）。last-good 读回与外来规则保护 `apps/agent/tests/plan_recovery.rs:184`；tunnel/route/NAT 失败恢复分别 `:274`、`:314`、`:347`；重试收敛 `:408`。另一网络保留证据见 AR-01 `apps/server/tests/single_instance.rs:389` |
| AR-05 | P0 / 已验收（四种 Linux netns 组合实测） | 补 Direct LAN 的 controlled_snat；Direct/Alias × 保留源/SNAT 分别验证 | 2026-10-20：`MESHLET_REQUIRE_DATAPLANE=1` 运行 `single_instance.rs` 2 passed / 0 failed。Direct×controlled_snat 见 `apps/server/tests/single_instance.rs:430`、`:462`、`:469`（POSTROUTING 与连通）；Direct×dual_route 见 `:531`、`:562`、`:567`（无返回路由失败→显式路由后连通）；Alias×SNAT 见 `:934`、`:946`、`:954`、`:998`（API 创建、TCP/UDP、精确 POSTROUTING SNAT）；Alias×dual_route 见 `:1070`、`:1081`、`:1086`（无返回路由失败→显式路由后连通）。四组合均含业务连通证据 |
| AR-06 | P0 / 待验证 | 正式 systemd 权限与 hub 执行方式一致；空 VPS 按指南部署并验证数据面 | 正式 unit + drop-in 已以 uid 65534 在隔离 netns 完成真实 apply；空 VPS 走查待做 |
| REL-01 | P0 / 已验收（GitHub Actions） | 每天北京时间 03:17 构建；检查与数据面门禁通过后发布双架构 nightly、日期版本和 SHA256SUMS | `.github/workflows/nightly.yml`；首次 hosted 双架构构建/发布成功，下载及 SHA256SUMS 已核对 |
| REL-02 | P0 / 待验证 | 中英文 README 提供 nightly 一键安装/升级；保留配置与密钥、校验包、安装服务 | `scripts/install.sh` / `scripts/package-release.sh`；脚本检查与空 VPS 验收 |
| CR-01 | P0 / 已验收（API / Linux netns） | 旧修订不能执行当前快照或将新资源误标 Applied；只应用当前修订并保持幂等 | `revisions.rs::old_pending_and_applied_revisions_cannot_publish_new_resources` |
| CR-02 | P0 / 已验收（API / Linux netns） | agent 真实入口执行 dnat_only，无需虚构 SNAT 地址；保留 Overlay 源地址 | `single_instance.rs` 经 agent.reconcile 验仅 DNAT、缺/有返回路由 |
| CR-03 | P0 / 已验收（API / Linux netns） | 单网关多 LAN 按各目标网段解析 SNAT 源地址；删除规则不残留 | `single_instance.rs` 两 LAN 无返回路由可达；内核规则源分别为 .60.1/.61.1 |
| CR-04 | P0 / 已验收（API / Linux netns） | 空库并发 bootstrap 仅创建一个管理员，失败请求不能得到会话 | `auth_console.rs::concurrent_bootstrap_has_exactly_one_admin_session` |
| CR-05 | P0 / 已验收（API / Linux netns） | agent 检查实际地址、Peer/AllowedIPs、转发、路由下一跳和逐条 NAT；局部漂移可修复 | `single_instance.rs` 验证部分 SNAT 丢失、关闭转发后的重放与通信恢复 |
| QA-01 | P0 / 部分验收（hosted 门禁稳定化） | 独立数据面 CI 门禁：前置缺失不算通过，记录实际执行/跳过；重做最终验收矩阵 | `dataplane.yml` hosted 严格门禁与日志制品已通过，`:33` 显式纳入 `ledger_recovery`/`plan_recovery`；普通 CI 缺 `wg` 时明确 SKIP，`MESHLET_REQUIRE_DATAPLANE=1` 仍硬失败；实现 `apps/agent/tests/ledger_recovery.rs:38`、`apps/agent/tests/plan_recovery.rs:1`，Windows 临时库 `apps/server/tests/transaction_boundary.rs:20`，备份清理 `apps/server/tests/segments.rs:370`。本机 SKIP 4/4、严格数据面 ledger 4/4 + plan 3/3、segments 6/6 + transaction 2/2、workspace/clippy/fmt/docs 全绿；真实 VPS 验收矩阵待补 |
| RG-01 | P1 / 待验证 | 不同目标网段分别走指定网关；返回路径正确，网关失效不串站点 | 网关专题；AR-02/AR-05，当前已有基础路由模型 |
| RG-02 | P0 核验 / 部分验收（Linux netns） | 双站点和客户端本地 LAN 同前缀时用独立 Alias；正式 API/Agent + netns 已验 UDP/TCP 分别命中 local/site1/site2、tcpdump 记录三条目标/端口元组、本地路由保留且重复真实前缀不进隧道；删除 site1 后其路由与 NAT 消失、site2/本地仍可达且 `ip rule` 不变；server/agent 重启后剩余计划精确重建并自动恢复。返回模式变化、同网关歧义、业务失败恢复、备份恢复和 RG-03 冲突/预检仍未验收，不标整项完成 | 重叠 LAN Alias 设计；AR-01/MOD-03；测试证据：`apps/server/tests/dual_site_end_to_end.rs:1299` TCP、`:1313` 抓包、`:1381` 删除清理、`:1528` 重启恢复；漂移修复：`apps/agent/src/reconcile.rs:138` 实际通过 |
| RG-03 | 随 P0 修复 / 待设计 | 完整检查 Overlay/Alias/Direct/本地路由及共享多网络冲突域；拒绝覆盖，未知可追踪 | 网关专题；AR-01，精确前缀预检不代表完整冲突检测 |
| PN-01 | P1 / 部分实现（Segment 授权管理 API 与控制台） | 网络内分组已接入计划编译：默认段保持全量可见；自定义段默认只看到同段网关，`Applied` 单向授权才恢复目标可见性，AllowedIPs 缩到源段 CIDR；Segment/授权 CRUD API 已按网络隔离并拒绝未知段、同段、重复与重叠输入，Pending 不进哈希、Applied 进 v4 哈希、Revoked 恢复；控制台可创建/查看/应用/撤销授权；SQLite 提交与备份重载恢复完整。设备/能力模型与真实内核拒绝策略仍未验收 | ADR-012；实现 `apps/server/src/segment.rs:13`、`apps/server/src/service.rs:1924`、`:2038`、`:2102`、`apps/server/src/persist.rs:334`、`:361`、`:391`、`console/src/App.tsx:1082`、`console/src/api.ts:371`；测试 `apps/server/tests/segments.rs:184`、`:252`、`:318`、`console/src/segment-grants.test.tsx:47`；本轮 `MESHLET_REQUIRE_DATAPLANE=1 cargo test -p meshlet-server -p meshlet-domain --locked -- --test-threads=1` 与 workspace clippy `-D warnings` 全绿 |
| PN-02 | P1 / 待设计 | 最小组到设备/服务端口策略；明确默认行为，允许与拒绝均有内核证据 | PN-01、AR-01、AR-02；P2P 前需端点执行 |
| PN-03 | P1 / 待实现 | Windows 完整 Overlay 客户端：隧道服务、提权、开机恢复和清理 | ADR-008；现有 netsh 原语非完整客户端 |
| PN-04 | P1 / 待设计 | 路径诊断与实测基线：业务成功率、直连率、首连/恢复时间、吞吐分开报告 | 调研 C11/C13/O01 及实验矩阵；本次未测速 |
| PN-05 | P1 原型 / 待设计 | 验证 UDP 禁用时 HTTPS/TCP 回退；记录传输、MTU、身份授权和恢复边界 | 调研 C07；新 ADR；不是修改 WG 端口 |
| PN-06 | P1 原型 / 待设计 | 验证 LAN/已知公网 v4/v6 端点直连，再评估 NAT 穿透与自动切换 | PN-02、PN-04；调研 C02…C05/C08；原型通过后决定正式排期 |
| PN-07 | P2 / 部分待验证 | TCP/UDP 端口转发：A 入口到 B/站点服务；验本机与远端入站、监听冲突、回环后端、返回路径、UDP 会话和撤销 | **2026-10-17 已落地单主机全端口子集**：`/networks/{id}/host-forwards` 原子创建/删除 `/32` Route+Alias，控制台可管，计划含 NETMAP/SNAT，`routes.rs`/`agent_plan.rs` 测试覆盖创建、冲突、删除与计划；**未勾整项原因**：A 入口监听、回环后端、逐端口映射、UDP 会话实测与 PN-02 策略仍缺 ； AR-02、AR-04、PN-02；NAT/LAN 方案另依赖 AR-05/RG-02；见网关专题与调研 S01/S02 |
| PN-08 | P2 / 待设计 | Nginx HTTP 域名/路径路由；校验、reload、失败恢复与业务探测分开 | PN-07 的服务模型、AR-02/AR-04；调研 S03/S04 |
| PN-09 | P2 / 待设计 | 轻量名称解析与服务目录；不覆盖外来 DNS 配置 | 调研 S06/S08；按日常使用频率排期 |
| PN-10 | 按需 / 暂缓 | 一机多网、macOS/手机、备用中继、访客服务授权 | 调研 N02/P03…P05/C10/A08；以实际设备和场景决定 |
| MOD-01 | P1 / 待设计 | 明确公共库职责、依赖方向与兼容范围；先模块、后按需提 crate | 模块化提案；不拆微服务，不提前承诺稳定 API |
| MOD-02 | P1 / 待设计 | domain 减少默认认证依赖；完整 DTO 归位，避免 Agent/Server 重复与文本判错 | MOD-01；轻量独立消费者验证 |
| MOD-03 | 随 P0 修复 / 待设计 | 提取纯计划边界，和执行器/本地私钥分离 | AR-01/AR-02/AR-04；不先搬目录再补语义 |
| MOD-04 | P1 / 待设计 | 协调核心注入后端/客户端/状态；桌面依赖可选，支持宿主停止 | MOD-01/MOD-03；保留真实内核行为验收 |
| MOD-05 | 按需 / 待设计 | 提取管理 SDK、独立消费示例、公共 API 文档与包发布准备 | MOD-02；本项不授权发布或版本变更 |
| MOD-06 | P1 / 待设计 | 常规客户端一次注册、后台自启、分流与恢复；无 TUN 场景再评估服务代理 | AR-03/AR-06/PN-03；无网卡不作为通用组网替代，不承诺本期第二套传输 |

P0 验收完成前，不以旧的“25/27 有测试证据”口径判断可发布。P1 连接原型不代表立刻实现全部穿透或全球中继；若实测发现主要问题是受限网络或绕路，应优先解决相应连接能力。

## 实现审查拆分清单（2026-10-17）

以下是对当前工作区的补充审查，不替代上表已有任务。IM 条目将具体修复、设计决策与验收分别追踪；代码路径均相对仓库根目录。除编译失败已有本地命令证据外，其余问题来自静态代码核对，尚未新增运行复现或验收。方案需要改变既有契约时先补 ADR；列出的实现方向不代表已采纳决策。

| ID | 优先级 / 状态 | 拆分任务与验收 | 关联 / 代码依据 |
|---|---|---|---|
| IM-01 | P0 / 已完成 | 接齐 Segment 字段与测试构造：修复 Device 加载缺 `segment_id`、BootstrapToken 误填字段、domain 内测试 crate 引用及漏字段；离线 workspace check、domain 测试与 server lib 测试通过 | PN-01；`apps/server/src/persist.rs`、`service.rs`、`crates/meshlet-domain/src/peer_routes.rs`；本轮验证：check 通过，domain 105 passed，server lib 17 passed |
| IM-02 | P0 / 已完成 | 统一默认 Segment ID 为 `seg-<network_id>`；新网络在同一事务创建默认段，邀请加入与审批转正写入设备段归属，启动加载校验网络归属；迁移、空库建网、审批/邀请加入、重启及备份恢复回归通过 | IM-01、PN-01；`migrations/010_segments.sql`、`011_segment_defaults.sql`、`apps/server/src/service.rs`、`persist.rs`；server 全套测试通过 |
| IM-03 | P0 / 已完成（模型与启动恢复边界） | Segment 采用完整 CIDR 包含而非重叠判断：默认段必须精确等于 Overlay，非默认段必须严格包含且不得等于 Overlay；启动加载拒绝更大/越界/非默认整 Overlay 段与跨网络或越界设备地址，含边界回归。默认段与新增子段的共存/迁移策略以及内核策略编译仍未实现，不代表 PN-02 验收 | IM-01、PN-01；`crates/meshlet-domain/src/cidr.rs::contains_cidr`、`segments.rs::Segment::validate_cidr`、`validate_device_segment`、`conflict.rs::segment_overlay_containment`、`apps/server/src/service.rs::restore_segment/restore_device`、`apps/server/src/persist.rs`；域边界与持久化测试通过；跨段默认拒绝和单向授权仍由 PN-02 验收 |
| IM-04 | P0 / 已完成（实现与 Linux netns 测试） | `/32` Host Forward 按实际出口路由选择 SNAT 源，应用与读回共用解析逻辑；真实 agent 的 API 创建→NETMAP/SNAT→双向通信→删除已覆盖多 LAN、无出口与 dnat_only。结论限当前 Linux netns/API 场景，不扩大到真实 VPS 或 PN-07 全量端口转发验收 | PN-07、AR-05、CR-03；commit `5f73809`；`crates/meshlet-network/src/linux.rs::lan_source_for/route_source/apply_device_plan_sync/device_plan_matches_sync`、`crates/meshlet-network/tests/lan_source.rs`、`apps/server/tests/single_instance.rs::host_forward_agent_roundtrip_sources_and_cleanup` |
| IM-05 | P0 / 已完成（控制面冲突语义） | `check_new_forward_prefix` 统一 Host Forward / Alias / Direct 新建入口的共享转发空间与本网络已有转发前缀检查；Alias 先完成 ADR-006 目标推导、等长与目标不同校验，再进入前缀冲突检查；不同入口和顺序拒绝时无部分状态。完整跨端/客户端冲突发现仍归 RG-03 | RG-03、AR-01；commit `5f73809`；`apps/server/src/service.rs::check_new_forward_prefix` 与 Host Forward / Alias / Direct 入口、`routes.rs::host_forward_conflicts_do_not_write_partial_state`、`service.rs::forwarding_prefix_entrypoints_reject_each_other_atomically`、`aliases.rs::prefix_length_must_equal_target_and_must_differ` |
| IM-06 | P1 / 已完成（撤销生效契约与 Linux netns 验收） | Revoke 立即撤销 agent 凭证并记录不含该设备的 Pending 修订；用户显式 apply 成功后，hub 只保留 Active 设备 peer（`apps/server/src/revision.rs:414`、`apps/server/src/revision.rs:459`），Linux 后端显式删除目标 peer 集之外旧 peer（`crates/meshlet-network/src/linux.rs:209`）。持久化失败不自动生效，恢复任务过滤已撤销 peer 并用过滤后的 last-good 重放（`apps/server/src/revision.rs:170`）；真实 netns 实测断流、同网存活、Token 401、reconcile 不复活、删接口重启恢复后仍断流且 peer 数为 1 | AR-01、AR-03、AR-04；凭证测试 `apps/server/tests/device_revoke.rs:190` 与 `apps/server/tests/agent_plan.rs:653`；期望移除测试 `apps/server/tests/device_revoke.rs:158`、`apps/server/tests/device_revoke.rs:268`；真实 netns 流量/重启断言 `apps/server/tests/single_instance.rs:623`、`apps/server/tests/single_instance.rs:657`；OpenAPI 契约 `docs/public/api/openapi.yaml:524`；实测 single_instance 2 passed、server/domain/agent 套件全绿、`MESHLET_REQUIRE_DATAPLANE=1 cargo test --locked --workspace -- --test-threads=1` 全绿 |
| IM-07 | P1 / 已验收 | Agent 成功后把去私钥、已本地化的完整 `DevicePlan` 写入 last-good（`apps/agent/src/reconcile.rs:45`、`apps/agent/src/agent.rs:276`）；NAT 预清理、受管路由清理、`apply_device_plan_sync` 及最终 readback 任一失败均重放旧计划并回读，失败组合返回而不写成功账本（`apps/agent/src/agent.rs:192`、`:234`、`:289`，执行入口 `crates/meshlet-network/src/linux.rs:907`）。真实 netns 在 tunnel、route、NAT 三阶段注入失败，验证旧隧道地址、`proto 198` 路由与 Meshlet NAT 恢复，外来路由/NAT保留，回执为 `Err`，移除故障后重试收敛 | AR-04、MOD-04；新增测试 `apps/agent/tests/plan_recovery.rs:251`、`:291`、`:324`；兼容回归 `apps/agent/tests/ledger_recovery.rs:246`、`:264`、`:279`、`:306`；实测 `MESHLET_REQUIRE_DATAPLANE=1 cargo test -p meshlet-agent --locked -- --test-threads=1`：lib 50 passed、main 0 passed、agent_reconcile 1 passed、ledger_recovery 4 passed、plan_recovery 3 passed、doc-tests 0 passed（全部 0 failed）；workspace clippy `--all-targets -D warnings` 0 error；`pnpm docs:build` complete in 6.26s |
| IM-08 | P1 / 已完成（Linux 真实 netns 验收） | 本地账本缺失/损坏时按内核所有权清单清理：枚举 `meshlet alias *` NAT owner（`crates/meshlet-network/src/linux.rs:823`）并仅按 `proto 198` 删除旧路由（`crates/meshlet-network/src/linux.rs:842`）；外来 NAT 与外来路由保留，覆盖缺失、损坏、映射删除重启及局部失败 | IM-07、CR-05；对象装配/对账见 `apps/agent/tests/ledger_recovery.rs:106`、`apps/agent/tests/ledger_recovery.rs:185`；测试 `apps/agent/tests/ledger_recovery.rs:246`、`apps/agent/tests/ledger_recovery.rs:264`、`apps/agent/tests/ledger_recovery.rs:279`、`apps/agent/tests/ledger_recovery.rs:306`；实现入口 `apps/agent/src/agent.rs:223`、`apps/agent/src/reconcile.rs:194`；`cargo test -p meshlet-agent --locked` 4 passed、workspace clippy `-D warnings` 与 docs build 通过 |
| IM-09 | P1 / 已完成（写入事务与内存提交边界） | Handler 在 persist 锁内克隆 MeshState 暂存资源、修订与序列，组合事务一次提交资源、修订、序列、审计和一次性凭据，成功后才替换共享内存；失败时内存不发布、事务回滚。覆盖网络创建、邀请加入、审批转正、Direct Route、Alias、Host Forward、Route/Alias/Host Forward 删除和设备撤销。触发器注入资源、修订、审计和 Agent Token 失败，验证 DB 无孤儿、内存不吞入失败草稿、邀请 used_count 不重复消耗且重试收敛；另修复删除重试读取暂存修订导致的唯一键冲突 | IM-02、MOD-03；`apps/server/src/lib.rs::create_network_handler`、`apps/server/src/persist.rs::commit_network/commit_enrollment/commit_route/commit_alias/commit_host_forward/commit_approve_registration/commit_revoke_device/commit_route_delete`、`apps/server/tests/transaction_boundary.rs`；本轮 domain 116 passed，server lib 21 passed，routes 12/aliases 11/enroll 13/device_revoke 7/audit 4/backup 7/recovery 5/transaction_boundary 2 passed，workspace clippy `-D warnings` 与 `pnpm docs:build` 通过 |
| IM-10 | P1 / 已完成（备份业务一致性与恢复边界） | 并发路由写入在资源行与修订行之间被 SQL 触发器暂停时执行 `VACUUM INTO` 备份，备份只含已完成的网络/设备/修订（0 孤儿路由、修订 1→2 连续）；离线恢复后按原成功计划继续，下一条路由为 `rt-1`、修订 3。修订写入失败同样回滚资源，备份与恢复后均无缺修订或孤儿资源，重试得到修订 3。备份包含口令/Token/邀请/自举码摘要与撤销状态但不含原始秘密，也不含服务端/agent 本地 WireGuard 私钥；新机必须单独恢复 `DataPlaneConfig::private_key_file` 指向文件或显式轮换 | IM-09、AR-03、AR-04；`apps/server/tests/backup.rs::concurrent_backup_contains_only_complete_business_commits`、`failed_revision_write_never_backs_up_or_restores_orphan_resource`、`docs/zh/architecture/backup-restore.md`；实测 `cargo test -p meshlet-server --locked --test backup -- --test-threads=1` 9 passed，`cargo test -p meshlet-server --locked --test transaction_boundary --test recovery -- --test-threads=1` 7 passed，workspace clippy `-D warnings` 与 `pnpm docs:build` 通过 |
| IM-11 | P1 / 已完成（请求路径阻塞隔离） | Apply/rollback 先记录数据库 intent 并在同一网络锁内预留内存状态，再把 backend 快照与内核执行移入 `spawn_blocking`，成功后再收敛/提交结论；重复 apply 不重复调用 backend，同网络串行、不同网络并行。Argon2 哈希/校验在信号量内运行于 `spawn_blocking`。覆盖慢内核、跨网络并行、失败回执、重复 apply、慢登录容量 | MOD-03、MOD-04、IM-08、IM-09；实现 `apps/server/src/revision.rs:640`、`apps/server/src/revision.rs:852`、`apps/server/src/auth.rs:570`、`apps/server/src/auth.rs:637`、`apps/server/src/auth.rs:668`；测试 `apps/server/tests/revisions.rs:504`、`:555`、`:573`、`:611`、`apps/server/tests/auth_console.rs:436`；实测 `cargo test -p meshlet-server -p meshlet-domain -p meshlet-agent --locked` 全绿（server 235、domain 116、agent 55） |
| IM-12 | P2 / 已完成（console 测试） | 控制台正确展示修订加载失败并刷新收敛状态：401/500 显示错误态而非空列表；最新设备 ACK pending 时周期刷新；切换网络按 React key 重挂载，旧请求由 AbortController 取消并丢弃旧响应；设备失败不误报生效 | AR-02；`console/src/App.tsx:1522`、`console/src/api.ts:222`、`console/src/api.ts:291`；测试 `console/src/revisions.test.tsx:29`（401/500）、`:46`（空列表）、`:55`（设备失败）、`:70`（延迟 ACK）、`:93`（切网）；`pnpm --dir console lint`、`pnpm --dir console test` 6 passed、`pnpm --dir console build`、`pnpm docs:build` 通过 |

建议执行批次：IM-01…IM-03 已完成 Segment 模型与启动边界接线；IM-04…IM-05 已修复现有转发链路；IM-06…IM-08 明确撤销与端点恢复；IM-09…IM-11 收紧一致性和执行边界；IM-12 完成控制台状态闭环。可独立推进的条目按依赖安排，PN-02 的内核策略验收不能因模型或迁移完成而勾选。

后续能力继续沿用已有条目：逐端口 TCP/UDP 映射与监听入口归 PN-07，Windows 完整后端归 PN-03，共享 DTO/协议归 MOD-02，模块拆分归 MOD-01/MOD-03。多用户逐网络授权维持个人自托管边界，随 PN-10 的访客需求再设计；本次不新增多租户承诺。

## 历史记录的修正口径

历史记录已移至 历史实施记录，保留原始证据与执行过程；其中复选框不是当前整项产品能力的完成率。返回路径双模式、回滚安全、故障恢复和恢复后协调的原勾选已重开，分别追踪 AR-05、AR-04、AR-03。配置状态机的既有单机簿记证据保留，分布式应用确认另由 AR-02 验收；多网络隔离由 AR-01 重验。

状态按实际平台、拓扑和执行结果判定。静态审查、注入测试、真实内核 netns 和真实部署的证据分别列出；缺特权而跳过不能算数据面通过。依赖、目标、状态与验收放在本节，详细历史通过上述独立记录保留；新增进度只更新本页稳定 ID 和对应证据。

## 本轮验证记录

详见 P0 修复与 nightly 实施记录。

Segment 实测：`cargo check --workspace --all-targets --offline` 通过；`cargo test -p meshlet-domain -p meshlet-server --offline` 全绿（domain 109 passed；server lib 21 passed，集成套件全部 0 failed，含迁移 12、recovery 5、审批注册 6、邀请加入 13、备份恢复 7、旧备份升级 7）；`pnpm docs:build`（VitePress 1.6.4）打包与页面渲染通过。IM-03 仅验收模型与启动恢复边界；策略执行和真实数据面仍不视为已验收。

- CR-01…CR-05 已按 API / Linux netns 范围验收；AR-01…AR-06 已实现，实际 CI 已通过，空 VPS 验收保持待验证。
- 覆盖率实测（`cargo llvm-cov --workspace --all-targets --offline --summary-only`）：workspace line coverage 90.98%；主要未覆盖项是进程入口、Linux/Windows 外壳、DBus 桌面集成和错误路径。当前未达到 98%，不标已验收；后续需要按可测边界拆出纯逻辑并注入平台依赖，而不是排除源码凑数。
- 正式 server unit + drop-in 已在隔离 netns 以 uid 65534 执行；私钥 0600、WireGuard、转发、防火墙和应用读回通过。
- x86_64 musl release 已构建并打包；console / 文档构建、ShellCheck、actionlint 通过。
- 全仓严格测试通过：`MESHLET_REQUIRE_DATAPLANE=1 cargo test --locked --workspace -- --test-threads=1`，381 passed / 0 failed / 0 ignored，0 SKIP。首次 hosted nightly 双架构构建与发布已通过，归档和安装脚本下载校验通过；真实空 VPS 一键安装仍待验收。
- PN / MOD 等后续功能尚未全部实现，保留各项当前状态；Windows / 手机验收环境仍需提供。

- 远端验收：首次 [nightly 发布](https://github.com/cuihairu/meshlet/actions/runs/39023899317)成功；[Windows/Linux CI](https://github.com/cuihairu/meshlet/actions/runs/39024292854) 已在迁移失败显式关闭连接池修复后通过。

- [x] 文档接 VitePress 官方 locales 双语（2026-10-17 用户令）：已配置 `locales.root`（en-US）与 `locales.zh`（`link: '/zh/'`），两种语言各有独立 nav/sidebar；英文编辑页位于 `docs/` 根目录（41 页），中文原稿位于 `docs/zh/`（41 页），未添加自制语言切换链接。`pnpm docs:build`（VitePress 1.6.4）通过，死链与锚点检查通过。
