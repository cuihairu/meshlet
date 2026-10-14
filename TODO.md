# Meshlet TODO

条目来源：[ChatGPT 存档 · 落地跟踪](docs/review/chatgpt-2026-10-13.md)（外部意见，**执行前必须对代码核验**；本仓当前无实现代码，全部条目为「待核」状态）。

期次对应存档 §19 的 Phase 0–5。每条含：建议（链接回存档锚点）、期次、验收标准。

## Phase 0 · 架构审查与原型

- [ ] 锁定第一版边界与排除项（[存档 §1.3](docs/review/chatgpt-2026-10-13.md)）— 验收：边界清单进入 docs 并经用户确认（清单已就绪：[docs/analysis/scope.md](docs/analysis/scope.md)；**待用户一句确认**）
- [x] 确认单 VPS 部署形态，排除 K8s/微服务/消息队列（[存档 §3.3](docs/review/chatgpt-2026-10-13.md)）— 验收：部署形态写入 ADR-002 ✅ [ADR-002](docs/decisions/adr-002-vps-hub-relay.md)
- [x] 技术选型核验：Rust/Tokio/Axum/Serde/SQLx/SQLite/Tracing（[存档 §4.1](docs/review/chatgpt-2026-10-13.md)）— 验收：选型写入 ADR 并通过最小 spike ✅ ADR-001/005/006 已入库；workspace spike 通过：`cargo test --workspace` 全绿（79 passed），tokio/axum/serde/toml/tracing/sqlx 编译+运行+集成测试（axum oneshot、sqlx migrate + PRAGMA 外键）验证
- [ ] WireGuard 中心转发原型：A→B、B→A、未授权不可达、撤销后失效（[存档 §7.3](docs/review/chatgpt-2026-10-13.md)）— 验收：四项真实集成测试通过 ⛔ **卡点：开发环境无 root/CAP_NET_ADMIN，user namespace 禁用（uid_map 拒写），`wg` 未安装**；需 root 环境或特权 CI runner（ADR-007 已记录该前提）
- [ ] Alias DNAT/SNAT 原型：等长前缀映射 + 受控 SNAT 返回路径（[存档 §9.2–§9.5](docs/review/chatgpt-2026-10-13.md)）— 验收：双 `192.168.1.0/24` 经不同 Alias 访问成功 ⛔ **卡点同上（nftables/NET_ADMIN/netns 不可用）**；可先落等长前缀映射的纯逻辑单测（见 meshlet-domain）
- [x] Windows/Linux 配置管理差异调研（[存档 §15.2–§15.3](docs/review/chatgpt-2026-10-13.md)）— 验收：差异清单 + ADR-007/008 ✅ [platform-notes](docs/architecture/platform-notes.md)、[ADR-007](docs/decisions/adr-007-linux-network-backend.md)、[ADR-008](docs/decisions/adr-008-windows-network-backend.md)
- [x] 建立 ADR-001~010（[存档 §21](docs/review/chatgpt-2026-10-13.md)）— 验收：10 份 ADR 入库，含背景/方案/取舍/风险 ✅ [docs/decisions/](docs/decisions/index.md)
- [ ] 领域模型与 API 契约初稿（[存档 §5、§13](docs/review/chatgpt-2026-10-13.md)）— 验收：实体关系图 + OpenAPI 初稿评审通过（初稿就绪：[domain-model](docs/architecture/domain-model.md) + [api-contract](docs/architecture/api-contract.md) + [openapi.yaml](docs/public/api/openapi.yaml)；**待用户评审**）

## 仓库事务

- [ ] License 徽章与许可证一致性 — README 徽章按实际 LICENSE 挂 **Apache-2.0**；**待用户确认是否换 MIT**（许可证变更属用户拍板事项，不代改；确认换则同步改 LICENSE 文件与两份 README 徽章）

## Phase 1 · 最小 Overlay

- [x] Rust workspace 骨架（[存档 §4.4](docs/review/chatgpt-2026-10-13.md)）— 验收：cargo build 通过，目录边界与 §3.2 职责一致 ✅ `cargo test --workspace` 全绿（49 passed / 0 failed）；crates/{domain,api-types,config,network} + apps/{server,agent,cli}，职责与 §3.2 一致
- [x] 控制平面/数据平面职责拆分落地（[存档 §3.2](docs/review/chatgpt-2026-10-13.md)）— 验收：控制平面无逐包代理路径 ✅ 控制平面服务层落地（`apps/server/src/service.rs`：网络/邀请/设备加入 + IPAM/冲突检测调用）；数据平面边界为 `NetworkBackend` trait（meshlet-network）；全仓无逐包转发路径。配置生成/下发（设备拉取自身 WireGuard 配置）随 WireGuard 接入条目落地
- [x] 核心实体：User/Network/Device/DeviceKey/LAN Route/Alias Mapping/Config Revision（[存档 §5](docs/review/chatgpt-2026-10-13.md)）— 验收：migrations + 单元测试覆盖实体约束 ✅ migrations 落库（`migrations/001_init.sql` 9 表 + 索引，编译期嵌入 `store::MIGRATIONS`）；约束集成测试（`apps/server/tests/migrations.rs` 7 项）：同网络设备名/虚拟 IP 唯一、`token_hash` 唯一、复合主键 `(network_id, revision)`、外键拒绝孤儿设备、schema 无私钥列；实体约束单测延续（Device 撤销幂等、DeviceKey 生效期、AliasMapping 等长前缀+一对一、ConfigRevision 状态机、DeviceRegistry 唯一性，meshlet-domain 43 tests）
- [x] Overlay IPAM：默认 `10.240.0.0/16` 可配置、按 CIDR 计算分配（[存档 §6.1](docs/review/chatgpt-2026-10-13.md)）— 验收：分配无重复；CIDR 校验单测通过 ✅ hub 保留（10.240.0.1）+ 顺序分配（.2 起）+ 耗尽报错不复用（6 tests）；CIDR 校验：坏记法/前缀越界/主机位非零拒绝、包含与重叠边界（10 tests）；`ServerConfig.overlay_cidr` 可配置（config crate）
- [x] CIDR 冲突检测六项（[存档 §6.2–§6.3](docs/review/chatgpt-2026-10-13.md)）— 验收：三类冲突（服务端/客户端/未知）区分上报，未知时仅警告 ✅ 六项检查全部实现（overlay↔alias / 已有路由 / alias↔alias / LAN Route / alias-target 一致性 / 聚合入口）；三类分级 `ServerKnown`/`ClientLocal`/`Unverifiable`，未知仅警告不阻断（`existing_route_conflict_classified_by_source` + `aggregate_check_network_reports_all_categories` 等 6 tests）
- [x] 每设备独立 Peer；AllowedIPs 与目标路由一致（[存档 §7.2](docs/review/chatgpt-2026-10-13.md)）— 验收：默认只路由 Overlay+已发布 LAN+Alias ✅ 推导逻辑落地（`meshlet-domain/src/peer_routes.rs` 纯函数 + 10 tests）：VPS 侧每设备独立 Peer（本机 /32 + 已发布 LAN + Alias）；客户端侧 Overlay + 他人已发布 LAN + Alias（自己本地网段不回灌）；仅 `Applied` 状态进 AllowedIPs；Overlay 边界校验；去重+确定性排序；文档同步（domain-model.md「Peer AllowedIPs 推导」节）。配置下发（设备拉取自身隧道配置）随 WireGuard 接入条目落地
- [x] 设备加入邀请流程，私钥不出客户端（[存档 §11.2](docs/review/chatgpt-2026-10-13.md)）— 验收：端到端加入成功；DB 无私钥 ✅ 端到端 HTTP 测试（`apps/server/tests/enroll.rs` 13 项）：网络→邀请→加入→虚拟 IP 分配（10.240.0.2 起）→设备列表；私钥不出客户端——API `deny_unknown_fields` 拒绝私钥字段 + 状态/响应全链路无私钥材料（测试断言）；持久化已落库：`devices`/`device_keys` 表无 private/secret/seed 列（`schema_stores_no_private_key_material` 断言）
- [ ] 两台 Linux 客户端经 VPS 互通（[存档 §19 Phase 1](docs/review/chatgpt-2026-10-13.md)）— 验收：互访/重启恢复/撤销失效/IP 不重复

## Phase 2 · Web 控制台

- [x] 用户认证与管理授权（[存档 §11.4](docs/review/chatgpt-2026-10-13.md)）— 验收：全部管理 API 需认证；哈希/限流/Cookie 安全属性/CSRF 就位 ✅ 全部管理端点挂 `AuthenticatedUser`（Cookie 会话）+ 写请求 `CsrfHeader` 提取器（`apps/server/src/auth.rs`，集成测试 12 项 `auth_console.rs`）：Argon2id 哈希（32MiB/2轮/4并行，域层 9 tests）；登录限流（每 email 15 分钟 5 次失败→429，成功清零，未知账号恒时校验）；Cookie HttpOnly+SameSite=Strict+Max-Age=12h+Path=/api/v1（`Secure` 配置位）；CSRF 双防线；**无默认管理员密码**（空库 bootstrap 一次性，409 关闭）；enroll/status 保持公开；会话/用户持久化 SQLite（migration 002 sessions 表）；审计事件随「审计日志」条目
- [x] 邀请 Token 安全（[存档 §11.3](docs/review/chatgpt-2026-10-13.md)）— 验收：只存摘要；过期/撤销/一次性可测；日志无 Token ✅ 安全随机 Token（32B→64hex）+ SHA-256 摘要存储（`meshlet-domain/src/invites.rs`）；过期/撤销/次数上限/并发单胜全部单测；Debug 形态不含原始 Token（摘要之外不落地）
- [x] React 控制台：Network/Device/邀请/撤销页面（[存档 §12](docs/review/chatgpt-2026-10-13.md)）— 验收：不手工改库即可完成基本管理 ✅ `console/`（Vite+React+TS，`npm run build` 过）：bootstrap/login 门（409 冲突自动转登录）、Network 列表/创建、Device 表格、邀请创建（一次性 Token 仅显示一次）/撤销；API 层统一带 `X-Requested-With`（CSRF）；server 可静态托管 `console_dir`（`router_with_console` + ServeDir 回落，`/api` 路由优先、缺失文件 404，5 项集成测试 `console_static.rs`）；CI 增加 console build job
- [ ] 配置版本页面（依赖「配置状态机」条目落地后才有 API 可展示）
- [x] 在线状态判定（握手+心跳+上报）（[存档 §12.4](docs/review/chatgpt-2026-10-13.md)）— 验收：状态标注数据来源与更新时间 ✅ 判定引擎 `meshlet-domain/src/presence.rs`（纯函数，窗口/判定时刻可注入，12 单测）：三类证据（agent 上报 > 握手 > 加入）→ `online` / `tunnel_only` / `offline`；**握手新鲜 ≠ 在线**（§12.4：握手只证明隧道连通，单握手写 `tunnel_only` 而非 `online`）；窗口默认 5min/2min 且可配置（`presence_agent_window_secs` / `presence_handshake_window_secs`）；非法时间戳保守忽略。采集路径：加入签发 `agent_token`（Bearer，仅返回一次，`agent_tokens` 表只存 SHA-256 摘要，migration 003）→ `POST /api/v1/agent/heartbeat`（agent API，与管理 API 认证边界分离）带上 `wg show` 握手读数 → 写 `devices.last_handshake_at` / `last_report_at` / `last_seen_at`。控制台设备行标注 `online_state` + `presence_source` + 更新时间（§12.2：不出现无来源的绿色图标）；集成测试 8 项 `presence.rs`（含 tunnel_only 端到端、无 Token 401 且状态不被污染、未知路径仍 404）
- [x] 配置状态机（[存档 §10](docs/review/chatgpt-2026-10-13.md)）— 验收：DB 写入 ≠ 显示生效；失败可见；状态可区分 ✅ 簿记 `meshlet-domain/src/config_state.rs`（`ConfigLedger` + 注入式 `ConfigApplyBackend` + `desired_config_hash` 确定性哈希，15 单测）：每次变更先 `record`（恒 `pending`）；`apply` 走 `pending → applying → applied | failed`，**失败含结果不确定一律落 `failed` + `error_summary`，不假装成功**（§10.3）；已 `applied` 幂等重放不再调用 backend；对 `failed` 原地重试非法（`RevisionError::IllegalTransition` → 409），重试路径是记录新修订（§10.4 版本号网络内单调递增）；`rollback` 只针对 `failed`/未确认的 `rollback_pending`，未确认则留在 `rollback_pending` 并合并诊断。API `apps/server/src/revision.rs`：`GET /networks/{id}/config-revisions`、`GET .../{revision}`、`POST .../apply`、`POST .../rollback`（🔒 会话 + CSRF）；`POST /networks` 与 `POST /enroll` 现记录修订并在响应带 `revision_id` + `apply_status`（ADR-009 契约）。本进程无数据面 backend（WireGuard 应用需 CAP_NET_ADMIN，见上卡点）→ 显式 apply 确定性 `failed` 且 `error_summary` 说明「已记录但未应用」，SQLite `config_revisions` 表（migration 001）字段与领域模型逐列对齐；集成测试 7 项 `apps/server/tests/revisions.rs`（DB 写入 ≠ 生效、失败在列表/详情都可见、重试 409、无 backend 回滚停在 rollback_pending、认证/CSRF、404）
- [ ] 撤销设备完整链路（[存档 §11.5](docs/review/chatgpt-2026-10-13.md)）— 验收：Peer/路由/Alias 关系全部移除；不确定生效时报失败
- [ ] 审计日志（[存档 §16.5](docs/review/chatgpt-2026-10-13.md)）— 验收：敏感操作全记录；无密码/私钥/Token 明文

## Phase 3 · LAN Subnet Routing

- [ ] LAN Route 模型与网关配置（[存档 §8.1](docs/review/chatgpt-2026-10-13.md)）— 验收：发布 CIDR 后远端可访问
- [ ] 返回路径双模式（真实双向 / 受控 SNAT），UI 显示所采用模式（[存档 §8.2](docs/review/chatgpt-2026-10-13.md)）— 验收：SNAT 模式 LAN 响应可返回 Overlay
- [ ] 路由冲突不静默（[存档 §8.3](docs/review/chatgpt-2026-10-13.md)）— 验收：同网段冲突提示配 Alias；不覆盖已有路由 ⚠️ 现状：冲突检测已就位（`lan_route_conflicts` 等，见「CIDR 冲突检测六项」条）；**发布路由时的冲突拒绝/提示行为需服务层**（随 Phase 2/3 落地）
- [ ] SNAT 纪律（[存档 §7.4](docs/review/chatgpt-2026-10-13.md)）— 验收：Overlay 设备间保留原始源地址
- [ ] MTU 可配置 + 诊断（[存档 §7.5](docs/review/chatgpt-2026-10-13.md)）— 验收：大包问题可解释 ⚠️ 现状：`TunnelConfig.mtu: Option<u32>` 已就位（meshlet-network）；**诊断能力（区分隧道/路由/转发/Alias 故障层）待 Diagnostics 条目**（Phase 5）
- [ ] Windows 路由处理（[存档 §15.3](docs/review/chatgpt-2026-10-13.md)）— 验收：权限不足提示明确；失败可清理

## Phase 4 · Alias Routing

- [x] Alias 模型与等长前缀映射（[存档 §9.2](docs/review/chatgpt-2026-10-13.md)）— 验收：六项转换前检查全过；非等长被拒 ✅ 等长前缀约束 + 一对一 `translate` + 同前缀拒绝（`alias_requires_equal_prefix_length`、`alias_rejects_identity_mapping`，meshlet-domain）；六项转换前检查全部实现并有测试（conflict.rs，见「CIDR 冲突检测六项」条）
- [ ] 网关侧 DNAT/SNAT 实施（[存档 §9.4–§9.5](docs/review/chatgpt-2026-10-13.md)）— 验收：双重叠 LAN 各自可达；默认 SNAT 限制 UI 可见
- [ ] NAT 规则所有权与清理（[存档 §12.6](docs/review/chatgpt-2026-10-13.md)）— 验收：删除 Alias 同步清理路由与 NAT；失败不报成功
- [ ] Alias 协议边界声明（[存档 §9.6](docs/review/chatgpt-2026-10-13.md)）— 验收：文档明示不保证广播/组播/二层发现

## Phase 5 · 稳定性与发布

- [ ] 配置应用幂等与回滚安全（[存档 §10.3–§10.4](docs/review/chatgpt-2026-10-13.md)）— 验收：重复应用不破坏网络；回滚不触碰非 Meshlet 规则
- [ ] 并发版本顺序（[存档 §10.4](docs/review/chatgpt-2026-10-13.md)）— 验收：并发修改不交叉破坏 Peer/路由/NAT
- [ ] 结构化日志与指标（[存档 §17.1–§17.2](docs/review/chatgpt-2026-10-13.md)）— 验收：规定字段齐全；不依赖单一指标
- [ ] 故障恢复（[存档 §17.3](docs/review/chatgpt-2026-10-13.md)）— 验收：服务端/客户端重启后按期望状态恢复
- [ ] 备份与恢复（[存档 §17.4](docs/review/chatgpt-2026-10-13.md)）— 验收：一致性备份；恢复后协调到期望状态
- [ ] 测试体系：单元 + 集成 12 项 + 跨平台 + 安全（[存档 §18](docs/review/chatgpt-2026-10-13.md)）— 验收：全部通过并入 CI ⚠️ 现状：CI（`.github/workflows/ci.yml`）跑 `cargo fmt --check` + `cargo clippy --workspace --all-targets -- -D warnings` + `cargo test --workspace`（72 项，含 axum oneshot 集成测试），矩阵 ubuntu/windows（§15 支持的 Agent 平台）；存档 §18 的 12 项集成测试依赖 WireGuard/特权环境，随对应条目落地；安全测试（§18.4）部分覆盖（邀请 Token/私钥路径已有断言）
- [ ] Diagnostics 页面 12 项检查（[存档 §12.7](docs/review/chatgpt-2026-10-13.md)）— 验收：能区分隧道/路由/转发/Alias 故障层
- [ ] 安装流程与自启动（[存档 §19 Phase 5](docs/review/chatgpt-2026-10-13.md)）— 验收：新用户从空 VPS 完成部署
- [ ] 第一版最终验收逐条核对（[存档 §22](docs/review/chatgpt-2026-10-13.md)）— 验收：五组验收全绿后方可谈发布

## 外部 API 控制（供外部系统集成，2026-10-14 用户需求）

> 背景：曾设想把这套控制并入 cockpit 的 agent，但重启 agent 会断网、不可接受；meshlet 独立部署后集成才成立，因此需要可被外部系统调用的控制面。

- [x] 外部机器凭据（API Token），而非只有浏览器会话登录 — 验收：外部系统可长期调用；token 可撤销、最小权限、审计归属明确；与既有 session auth 并存且不削弱 CSRF 防护（2026-10-14 完成：`mlt_` Bearer 与 Cookie 会话并存，`read`/`write` scope（write 隐含 read，读 token 写操作 403），属主可撤销即失效、`last_used_at` 节流审计，写请求统一要求 CSRF 头；migration 004 摘要存储；测试 `apps/server/tests/api_token.rs` 8 项 + migrations 1 项，workspace 176 绿）
- [x] 控制面端点补齐（设备上/下线、路由增删、peer 撤销、配置下发）— 验收：与 `docs/public/api/openapi.yaml` 逐条一致，逐端点集成测试；**先核验现状**——现有 `/auth/*`、`/networks`、`/networks/{id}/devices`、`/networks/{id}/invites` 已实现，只补缺口不重复造（2026-10-14 完成：核验后缺口为路由增删与 peer 撤销——设备上/下线=心跳+presence（2bc0083）、配置下发=revisions apply/rollback（9e39f94）已在先前落地；新增 `GET/POST /networks/{id}/routes`、`GET/DELETE /networks/{id}/routes/{route_id}`、`POST /networks/{id}/devices/{device_id}/revoke`（202+RevisionRef、agent 凭证即失效、被撤销设备出配置哈希）；路由纳入 `desired_config_hash`（`meshlet-desired-v2`）；测试 `routes.rs` 8 项 + `device_revoke.rs` 6 项 + 域层 1 项，workspace 191 绿；网络/设备 PATCH、rotate-key、aliases、diagnostics 属后续 Phase，未在本单范围）
- [ ] 路由优化方案（含取舍与实测依据）— 验收：进 docs，写清当前实现瓶颈、候选方案对比、选定理由；结论须能被复现的命令验证
- [ ] 性能方案与基准（吞吐 / 延迟 / 并发连接数 / 内存）— 验收：给出可复现 bench 命令与实测数字进 docs，附优化前后对照

## 说明

- 本文件是外部建议的登记表，不代表承诺的路线图；每条落地前先与实际代码核验。
- 按用户红线：**发布正式版本必须由用户明确给出版本号并触发**，验收未通过的二进制不进 Releases 页面。
