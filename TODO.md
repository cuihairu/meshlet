# Meshlet TODO

当前需求以个人自托管为边界：不同设备、网络内分组、受控的端口转发与 HTTP 服务路由。2026-10-17 静态审查发现，历史条目中部分“已完成”结论超出代码和测试的覆盖范围；不能继续采用“只剩两项环境走查”的汇总。

- [架构与 TODO 审查](docs/analysis/architecture-review-2026-10-17.md)：代码证据、六项缺口、新需求模型和重新验收条件。
- [Meshlet / ZeroTier / Tailscale 个人组网调研](docs/analysis/personal-networking-comparison.md)：61 项功能对比、官方来源、个人必要性、开发难度与实测方案。
- [模块化与库复用提案](docs/architecture/modularity-and-library-design.md)：依赖边界、公共库与渐进迁移；常规虚拟网卡为主，无网卡服务入口按需评估。
- [网关、网段冲突与端口转发专题](docs/architecture/gateways-conflicts-and-port-forwarding.md)：分网段选网关、Alias 冲突域和 A 端口到 B 服务的完整场景与验收。
- [网段即信任组设计](docs/design/network-segment-trust.md)：ADR-012 已采纳 Network 内 Segment、同段互信、跨段默认拒绝与单向授权契约；工作区已有模型与迁移草稿，编译、持久化和策略执行尚未接齐，见 IM-01…IM-03。

## 当前执行清单（2026-10-17）

以下优先级为本轮审查建议，未实施方案仍需 ADR；不因登记而自动改变既有技术决策。按依赖推进，先修基础，再扩展服务。状态：待设计 / 待实现 / 修复中 / 待验证 / 已验收 / 暂缓；仅完成对应范围的验收才勾选。

| ID | 优先级 / 状态 | 目标与验收 | 依赖 / 证据 |
|---|---|---|---|
| AR-01 | P0 / 待验证 | 单实例同时承载两个 Network；应用、撤销、清理、恢复互不干扰；主动越权流量被拒绝 | `single_instance.rs` 已覆盖单实例互通/越权拒绝/恢复/回滚；VPS 走查待做 |
| AR-02 | P0 / 待验证 | 设备按版本/计划哈希确认应用；hub 成功、设备成功、业务健康分别显示；旧 ACK 不覆盖新状态 | `agent_plan.rs` 已覆盖等待/失败/正确 ACK/旧 ACK；控制台拆分状态 |
| AR-03 | P0 / 待验证 | hub 启动与周期漂移对账；接口丢失、VPS 重启后按期望恢复 | 已持久化成功计划，启动与周期恢复已实现；netns 删接口后恢复通过 |
| AR-04 | P0 / 待验证 | 保存并恢复上次成功计划；失败恢复不清掉正常连接及其他网络资源 | 已重放成功计划；netns 失败后旧通路恢复、另一网络保留；旧备份升级有回归 |
| AR-05 | P0 / 待验证 | 补 Direct LAN 的 controlled_snat；Direct/Alias × 保留源/SNAT 分别验证 | 已逐 LAN 编译/解析 SNAT；Direct SNAT、Alias 两模式有真实内核证据；见本轮修复记录 |
| AR-06 | P0 / 待验证 | 正式 systemd 权限与 hub 执行方式一致；空 VPS 按指南部署并验证数据面 | 正式 unit + drop-in 已以 uid 65534 在隔离 netns 完成真实 apply；空 VPS 走查待做 |
| REL-01 | P0 / 已验收（GitHub Actions） | 每天北京时间 03:17 构建；检查与数据面门禁通过后发布双架构 nightly、日期版本和 SHA256SUMS | `.github/workflows/nightly.yml`；首次 hosted 双架构构建/发布成功，下载及 SHA256SUMS 已核对 |
| REL-02 | P0 / 待验证 | 中英文 README 提供 nightly 一键安装/升级；保留配置与密钥、校验包、安装服务 | `scripts/install.sh` / `scripts/package-release.sh`；脚本检查与空 VPS 验收 |
| CR-01 | P0 / 已验收（API / Linux netns） | 旧修订不能执行当前快照或将新资源误标 Applied；只应用当前修订并保持幂等 | `revisions.rs::old_pending_and_applied_revisions_cannot_publish_new_resources` |
| CR-02 | P0 / 已验收（API / Linux netns） | agent 真实入口执行 dnat_only，无需虚构 SNAT 地址；保留 Overlay 源地址 | `single_instance.rs` 经 agent.reconcile 验仅 DNAT、缺/有返回路由 |
| CR-03 | P0 / 已验收（API / Linux netns） | 单网关多 LAN 按各目标网段解析 SNAT 源地址；删除规则不残留 | `single_instance.rs` 两 LAN 无返回路由可达；内核规则源分别为 .60.1/.61.1 |
| CR-04 | P0 / 已验收（API / Linux netns） | 空库并发 bootstrap 仅创建一个管理员，失败请求不能得到会话 | `auth_console.rs::concurrent_bootstrap_has_exactly_one_admin_session` |
| CR-05 | P0 / 已验收（API / Linux netns） | agent 检查实际地址、Peer/AllowedIPs、转发、路由下一跳和逐条 NAT；局部漂移可修复 | `single_instance.rs` 验证部分 SNAT 丢失、关闭转发后的重放与通信恢复 |
| QA-01 | P0 / 待验证 | 独立数据面 CI 门禁：前置缺失不算通过，记录实际执行/跳过；重做最终验收矩阵 | `dataplane.yml` hosted 严格门禁与日志制品已通过；真实 VPS 验收矩阵待补 |
| RG-01 | P1 / 待验证 | 不同目标网段分别走指定网关；返回路径正确，网关失效不串站点 | 网关专题；AR-02/AR-05，当前已有基础路由模型 |
| RG-02 | P0 核验 / 待设计 | 双站点和本地 LAN 重复时用独立 Alias；收敛客户端/hub 路由与 AllowedIPs 的真实/Alias 前缀口径 | 网关专题；AR-01/MOD-03，现有辅助函数与计划生成需对照 |
| RG-03 | 随 P0 修复 / 待设计 | 完整检查 Overlay/Alias/Direct/本地路由及共享多网络冲突域；拒绝覆盖，未知可追踪 | 网关专题；AR-01，精确前缀预检不代表完整冲突检测 |
| PN-01 | P1 / 待实现 | Device/网络成员/设备组/能力模型；先明确网络内分组，一机多网按需实现 | 分组部分由 ADR-012 覆盖；调研 N01…N03、P01…P06 |
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
| IM-01 | P0 / 修复中 | 接齐 Segment 字段与测试构造：修复 Device 加载缺 `segment_id`、BootstrapToken 误填字段、domain 内测试 crate 引用及漏字段；workspace check、domain 测试与受影响 server 测试通过 | PN-01；`apps/server/src/persist.rs`、`service.rs`、`crates/meshlet-domain/src/peer_routes.rs`；已有未提交改动 |
| IM-02 | P0 / 待实现 | 统一默认 Segment ID、创建与持久化：消除 `seg-default` 与迁移 `seg-net-N` 的差异；设备写入/加载保留归属，新网络也创建默认段；验旧库迁移、新库、审批/邀请加入、重启及备份恢复，段归属不丢失且不串网络 | IM-01、PN-01；`migrations/010_segments.sql`、`apps/server/src/service.rs`、`persist.rs` |
| IM-03 | P0 / 待实现 | 修正 Segment 包含关系与默认段规则：不能用重叠代替包含；拒绝覆盖 Overlay 的更大前缀、越界段、跨网络成员与非法设备地址；明确默认段与新增子段的共存/迁移规则，覆盖边界测试 | IM-01、PN-01；`crates/meshlet-domain/src/segments.rs`、`conflict.rs`；策略编译、跨段默认拒绝和单向授权仍由 PN-02 验收 |
| IM-04 | P0 / 待实现 | 修复 `/32` Host Forward 的 SNAT 源地址选择：目标主机地址与网关本机地址不同也能应用；评估按实际出口路由解析源地址，应用与读回使用一致逻辑；验真实 agent 的 API 创建→NETMAP/SNAT→双向通信→删除，并覆盖多 LAN、无出口与 dnat_only | PN-07、AR-05、CR-03；`crates/meshlet-network/src/linux.rs` 的 `lan_addr_in`、`apply_device_plan_sync`、`device_plan_matches_sync`；现有计划断言不覆盖此执行失败 |
| IM-05 | P0 / 待实现 | 统一 Host Forward / Alias / Direct 的地址冲突校验：复用共享转发空间检查，拒绝与其他网络 Overlay/Direct/Alias 以及本网络已有转发前缀冲突；验不同创建入口及先后顺序结果一致、拒绝后无部分状态 | RG-03、AR-01；`apps/server/src/service.rs` 的 `create_host_forward` 未调用 `check_forward_prefix`，校验与 `create_alias` 不一致 |
| IM-06 | P1 / 待设计 | 明确设备撤销的生效契约：分别定义凭证失效与内核 Peer 阻断；决定是否要求即时阻断，以及持久化失败、进程重启和旧成功计划恢复时的行为；验被撤销设备不能在约定时限后继续旧流量或被恢复任务重新放行 | AR-01、AR-03、AR-04；`apps/server/src/lib.rs` 的 `revoke_device_handler` 当前仅生成 Pending 修订并撤销 Token，切断 WireGuard 需另行 apply |
| IM-07 | P1 / 待设计 | 补 Agent 应用失败的恢复边界：评估保存并重放上次成功完整计划；在隧道、路由、NAT 各阶段注入失败，验证恢复旧通路或明确安全失败，回执不得标成功，重试能收敛且不破坏其他网络/外来规则 | AR-04、MOD-04；`apps/agent/src/agent.rs` 的 `reconcile`、`crates/meshlet-network/src/linux.rs` 的 `apply_device_plan_sync`；目前按步骤修改，无完整旧计划恢复 |
| IM-08 | P1 / 待实现 | 本地账本丢失时仍清理内核旧对象：枚举有明确 Meshlet 所有权的 NAT/路由，与期望集合对账；验账本缺失/损坏、映射删除后重启及部分应用失败，不残留旧入口，不删除外来对象 | IM-07、CR-05；`apps/agent/src/reconcile.rs` 的 `AgentState` / `stale_owners`；目前旧 NAT 清理依赖账本中的 owner 集合 |
| IM-09 | P1 / 待设计 | 收紧业务写入的事务与内存提交边界：将同次操作的资源、修订、序列和必要审计原子提交，再发布内存状态或可靠撤销；逐步覆盖网络创建、加入/审批、路由/Alias/Host Forward、撤销；验各写入阶段失败后内存/DB 一致，重试不重复消耗凭据或产生孤儿记录 | IM-02、MOD-03；`apps/server/src/lib.rs`、`persist.rs`；已有全局互斥仅保证顺序，部分业务写入分次提交 |
| IM-10 | P1 / 待实现 | 验证备份的业务一致性：并发变更时备份只能包含完整业务提交；注入资源写入与修订写入之间的暂停/失败，备份恢复后无缺修订或孤儿资源，并可按成功计划恢复；明确凭据库与本地私钥的恢复边界 | IM-09、AR-03、AR-04；`apps/server/src/persist.rs` 的 `backup_to` 使用 SQLite 快照，不能替代业务事务 |
| IM-11 | P1 / 待设计 | 缩小控制面阻塞范围：将应用/回滚的同步内核操作移出 async worker，评估按网络串行并保留共享宿主资源协调；认证密码哈希/校验使用阻塞任务并限制并发；验慢命令/慢认证下其他网络查询可响应，同网络修订不乱序，失败与取消可追踪 | MOD-03、MOD-04、IM-09；`apps/server/src/revision.rs`、`auth.rs`、`crates/meshlet-network/src/linux.rs`；恢复任务已有 `spawn_blocking`，请求应用路径仍持全局锁同步执行 |
| IM-12 | P2 / 待实现 | 控制台正确展示加载失败并刷新收敛状态：修订请求失败不能显示成空列表；等待设备 ACK 时周期刷新并在卸载/切网时取消或忽略旧请求；验 401、500、空列表、延迟 ACK、设备失败及切网，不串状态且不误报生效 | AR-02；`console/src/App.tsx` 的 `RevisionsSection` 当前吞加载错误并只在挂载/操作后刷新 |

建议执行批次：IM-01…IM-03 完成 Segment 基础接线；IM-04…IM-05 修复现有转发链路；IM-06…IM-08 明确撤销与端点恢复；IM-09…IM-11 收紧一致性和执行边界；IM-12 完成控制台状态闭环。可独立推进的条目按依赖安排，PN-02 的内核策略验收不能因模型或迁移完成而勾选。

后续能力继续沿用已有条目：逐端口 TCP/UDP 映射与监听入口归 PN-07，Windows 完整后端归 PN-03，共享 DTO/协议归 MOD-02，模块拆分归 MOD-01/MOD-03。多用户逐网络授权维持个人自托管边界，随 PN-10 的访客需求再设计；本次不新增多租户承诺。

## 历史记录的修正口径

历史记录已移至 [历史实施记录](docs/implementation/history-2026-10-17.md)，保留原始证据与执行过程；其中复选框不是当前整项产品能力的完成率。返回路径双模式、回滚安全、故障恢复和恢复后协调的原勾选已重开，分别追踪 AR-05、AR-04、AR-03。配置状态机的既有单机簿记证据保留，分布式应用确认另由 AR-02 验收；多网络隔离由 AR-01 重验。

状态按实际平台、拓扑和执行结果判定。静态审查、注入测试、真实内核 netns 和真实部署的证据分别列出；缺特权而跳过不能算数据面通过。依赖、目标、状态与验收放在本节，详细历史通过上述独立记录保留；新增进度只更新本页稳定 ID 和对应证据。

## 本轮验证记录

详见 [P0 修复与 nightly 实施记录](docs/implementation/fixes-and-nightly-2026-10-17.md)。

当前工作区补充验证（Segment 未提交改动之后）：`cargo check --workspace --offline` 因 `persist.rs` 缺 Device.segment_id、`service.rs` 向 BootstrapToken 填入不存在的字段而失败；`cargo test -p meshlet-domain --offline --quiet` 因 `peer_routes.rs` 测试 crate 引用与 Device 字段未接齐而编译失败，未进入测试执行。以下全仓/CI 通过记录属于此前验证快照，不能代表当前工作区通过；修复追踪 IM-01，真实数据面尚未在本次审查中重跑。

- CR-01…CR-05 已按 API / Linux netns 范围验收；AR-01…AR-06 已实现，实际 CI 已通过，空 VPS 验收保持待验证。
- 正式 server unit + drop-in 已在隔离 netns 以 uid 65534 执行；私钥 0600、WireGuard、转发、防火墙和应用读回通过。
- x86_64 musl release 已构建并打包；console / 文档构建、ShellCheck、actionlint 通过。
- 全仓严格测试通过：`MESHLET_REQUIRE_DATAPLANE=1 cargo test --locked --workspace -- --test-threads=1`，381 passed / 0 failed / 0 ignored，0 SKIP。首次 hosted nightly 双架构构建与发布已通过，归档和安装脚本下载校验通过；真实空 VPS 一键安装仍待验收。
- PN / MOD 等后续功能尚未全部实现，保留各项当前状态；Windows / 手机验收环境仍需提供。

- 远端验收：首次 [nightly 发布](https://github.com/cuihairu/meshlet/actions/runs/39023899317)成功；[Windows/Linux CI](https://github.com/cuihairu/meshlet/actions/runs/39024292854) 已在迁移失败显式关闭连接池修复后通过。

- [ ] 文档接 vitepress 官方 locales 双语（2026-10-17 用户令）：现状 locales=0、41 篇英文页、0 中文页。要求：locales.root=en + locales.zh（link:'/zh/'），各自独立 nav/sidebar；英文在 docs/ 根、中文在 docs/zh/；中文必须真中文禁机翻禁复制英文顶替；构建通过贴输出；**禁止自造切换链接**（`> **中文** | [English](...)` 这类一律不许）；完成后标记并 commit+push，回报 hash 与中英文页数
