# Meshlet TODO

当前需求以个人自托管为边界：不同设备、网络内分组、受控的端口转发与 HTTP 服务路由。2026-10-17 静态审查发现，历史条目中部分“已完成”结论超出代码和测试的覆盖范围；不能继续采用“只剩两项环境走查”的汇总。

- [架构与 TODO 审查](docs/analysis/architecture-review-2026-10-17.md)：代码证据、六项缺口、新需求模型和重新验收条件。
- [Meshlet / ZeroTier / Tailscale 个人组网调研](docs/analysis/personal-networking-comparison.md)：61 项功能对比、官方来源、个人必要性、开发难度与实测方案。
- [模块化与库复用提案](docs/architecture/modularity-and-library-design.md)：依赖边界、公共库与渐进迁移；常规虚拟网卡为主，无网卡服务入口按需评估。
- [网关、网段冲突与端口转发专题](docs/architecture/gateways-conflicts-and-port-forwarding.md)：分网段选网关、Alias 冲突域和 A 端口到 B 服务的完整场景与验收。
- [网段即信任组设计](docs/design/network-segment-trust.md)：ADR-012 已采纳 Network 内 Segment、同段互信、跨段默认拒绝与单向授权契约；实现未开始。

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

## 历史记录的修正口径

历史记录已移至 [历史实施记录](docs/implementation/history-2026-10-17.md)，保留原始证据与执行过程；其中复选框不是当前整项产品能力的完成率。返回路径双模式、回滚安全、故障恢复和恢复后协调的原勾选已重开，分别追踪 AR-05、AR-04、AR-03。配置状态机的既有单机簿记证据保留，分布式应用确认另由 AR-02 验收；多网络隔离由 AR-01 重验。

状态按实际平台、拓扑和执行结果判定。静态审查、注入测试、真实内核 netns 和真实部署的证据分别列出；缺特权而跳过不能算数据面通过。依赖、目标、状态与验收放在本节，详细历史通过上述独立记录保留；新增进度只更新本页稳定 ID 和对应证据。

## 本轮验证记录

详见 [P0 修复与 nightly 实施记录](docs/implementation/fixes-and-nightly-2026-10-17.md)。

- CR-01…CR-05 已按 API / Linux netns 范围验收；AR-01…AR-06 已实现，实际 CI 已通过，空 VPS 验收保持待验证。
- 正式 server unit + drop-in 已在隔离 netns 以 uid 65534 执行；私钥 0600、WireGuard、转发、防火墙和应用读回通过。
- x86_64 musl release 已构建并打包；console / 文档构建、ShellCheck、actionlint 通过。
- 全仓严格测试通过：`MESHLET_REQUIRE_DATAPLANE=1 cargo test --locked --workspace -- --test-threads=1`，381 passed / 0 failed / 0 ignored，0 SKIP。首次 hosted nightly 双架构构建与发布已通过，归档和安装脚本下载校验通过；真实空 VPS 一键安装仍待验收。
- PN / MOD 等后续功能尚未全部实现，保留各项当前状态；Windows / 手机验收环境仍需提供。

- 远端验收：首次 [nightly 发布](https://github.com/cuihairu/meshlet/actions/runs/39023899317)成功；[Windows/Linux CI](https://github.com/cuihairu/meshlet/actions/runs/39024292854) 已在迁移失败显式关闭连接池修复后通过。
