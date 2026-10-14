# API 契约（初稿）

> 来源：[存档 §13](../review/chatgpt-2026-10-13.md#_13-api-设计)。机器可读版本：[openapi.yaml](/api/openapi.yaml)（OpenAPI 3.1）。初稿待评审；实现以本文件 + openapi.yaml 为契约，代码生成或类型同步（§4.2）。

## 约定

- 所有 API 使用版本前缀 `/api/v1`；JSON 请求与响应；统一错误响应结构（见下）；
- 输入验证在服务端执行；有副作用的操作记录审计事件（ADR-010）；
- 列表接口分页（`limit`/`offset`，响应带 `total`）；
- 可区分的错误码：`conflict` / `unauthorized` / `forbidden` / `not_found` / `validation_failed` / `too_many_requests` / `apply_failed`；
- 配置修改类响应必须携带 `revision_id` 与 `apply_status`（ADR-009）；
- 敏感可重试操作提供幂等语义；
- **Agent API 与管理 API 认证边界清晰分离**（§13.7）。

## 统一错误响应

```json
{ "error": { "code": "conflict", "message": "alias prefix overlaps overlay cidr", "details": {} } }
```

## 端点清单

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/api/v1/auth/bootstrap` | 空库创建首个管理员（有用户后 409 关闭） |
| POST | `/api/v1/auth/login` | 登录（限流：每 email 15 分钟 5 次失败，ADR-010） |
| POST | `/api/v1/auth/logout` | 登出（撤销会话） |
| GET | `/api/v1/auth/me` | 当前用户 |
| POST | `/api/v1/auth/tokens` | 签发 API Token（外部机器凭据；原始 Token 仅此一次返回）🔒 |
| GET | `/api/v1/auth/tokens` | 当前用户的 Token 列表（不含任何 Token 材料）🔒 |
| DELETE | `/api/v1/auth/tokens/{token_id}` | 撤销 API Token（即失效；仅属主可撤）🔒 |
| GET/POST | `/api/v1/networks` | 网络列表 / 创建（CIDR 验证，ADR-004）🔒 |
| GET/PATCH/DELETE | `/api/v1/networks/{network_id}` | 网络详情 / 更新 / 删除 🔒 |
| GET | `/api/v1/networks/{network_id}/devices` | 设备列表 🔒 |
| POST | `/api/v1/networks/{network_id}/invites` | 生成一次性邀请（ADR-010）🔒 |
| DELETE | `/api/v1/networks/{network_id}/invites/{invite_id}` | 撤销邀请（ADR-010）🔒 |
| POST | `/api/v1/enroll` | 设备加入（邀请 Token + 公钥；私钥不出客户端，§11.2） |
| POST | `/api/v1/agent/heartbeat` | Agent 心跳/状态上报（Bearer agent_token；可带 `last_handshake_at`，§14.1） |
| GET/PATCH/DELETE | `/api/v1/networks/{network_id}/devices/{device_id}` | 设备详情 / 更新 / 删除 🔒 |
| POST | `/api/v1/networks/{network_id}/devices/{device_id}/rotate-key` | 密钥轮换 🔒 |
| POST | `/api/v1/networks/{network_id}/devices/{device_id}/revoke` | 撤销设备（完整链路，§11.5）🔒 |
| GET/POST | `/api/v1/networks/{network_id}/routes` | LAN Route 列表 / 创建（含返回路径模式，ADR-005）；与 overlay/既有路由重叠 → `409 conflict` 且**消息点名冲突对端**（既有路由 id + 网段），拒绝发生在任何状态变更前——既有路由绝不被覆盖，客户端应提示改用 Alias 等长前缀映射（§8.3 不静默）🔒 |
| GET/PATCH/DELETE | `/api/v1/networks/{network_id}/routes/{route_id}` | 详情 / 更新 / 删除 🔒 |
| GET/POST | `/api/v1/networks/{network_id}/aliases` | Alias 列表 / 创建（等长前缀校验，ADR-006）🔒 |
| GET/PATCH/DELETE | `/api/v1/networks/{network_id}/aliases/{alias_id}` | 详情 / 更新 / 删除（删除同步清理 NAT）🔒 |
| GET | `/api/v1/system/status` | 服务端状态（公开） |
| GET | `/api/v1/networks/{network_id}/status` | 网络状态 🔒 |
| GET/POST | `/api/v1/networks/{network_id}/diagnostics` | 诊断结果 / 触发诊断（§12.7 十二项检查）🔒 |
| GET | `/api/v1/networks/{network_id}/config-revisions` | 配置版本列表 🔒 |
| GET | `/api/v1/networks/{network_id}/config-revisions/{revision}` | 版本详情（含 apply_status）🔒 |
| POST | `/api/v1/networks/{network_id}/config-revisions/{revision}/apply` | 应用指定版本到实际环境（响应即该版本视图）🔒 |
| POST | `/api/v1/networks/{network_id}/config-revisions/{revision}/rollback` | 回滚失败版本（仅删除/恢复 Meshlet 自有对象，ADR-007；只允许回滚当前修订，被取代者 409，§10.4）🔒 |

- 撤销设备语义（§11.5，已实现）：`POST .../devices/{device_id}/revoke`
  返回 `202` + `RevisionRef`（新修订号）；设备状态转 `revoked`（列表可见），
  该设备的 agent 凭证**立即失效**，且**其已发布的全部 LAN Route 一并移除**
  （不给 AllowedIPs 推导留下指向已撤销 Peer 的网段）；重复撤销 → `409 conflict`。

## 认证与 CSRF（已实现）

- 🔒 管理端点要求 Cookie 会话：`meshlet_session`（HttpOnly、SameSite=Strict、
  Path=/api/v1、Max-Age=12h；生产在 HTTPS 反代后由 `cookie_secure = true` 加 `Secure`）；
  无效/缺失会话 → `401 unauthorized`；
- 🔒 管理端「写」请求（POST/PUT/PATCH/DELETE）必须携带
  `X-Requested-With: XMLHttpRequest` 请求头，否则 `403 forbidden`（CSRF 双重防线，
  Console 前端约定）；
- 登录失败统一 `401`（不区分用户不存在/密码错误，含恒时校验）；
  超限 `429 too_many_requests`（每 email 15 分钟 5 次失败，成功登录清零）；
- 密码 Argon2id 哈希存储（32 MiB/2 轮/4 并行）；**无默认管理员密码**，
  首个管理员仅经空库 `POST /api/v1/auth/bootstrap` 创建；
- `/api/v1/enroll`（邀请 Token 即凭证）、`/api/v1/system/status` 与
  `/api/v1/agent/heartbeat`（Bearer `agent_token`）不属于管理 API；agent_token
  由加入时签发、原始 Token 仅返回一次，服务端只存 SHA-256 摘要（`agent_tokens`
  表，migration 003）——agent 凭证与控制台会话是两条互不交叉的认证边界（§13.7）。

### API Token（外部机器凭据，已实现）

外部系统（如 cockpit）可长期调用管理 API，不必依赖浏览器会话：

- **签发**：已认证用户 `POST /api/v1/auth/tokens`（同样要求 CSRF 头），
  请求 `{"name": "cockpit", "scopes": "read" | "write"}`；响应 `201` 携带
  `{"id", "token", "name", "scopes", "created_at"}`——原始 Token
  （`mlt_` 前缀 + 64 hex）**仅此一次返回**，服务端只存 SHA-256 摘要
  （`api_tokens` 表，migration 004）；
- **调用**：`Authorization: Bearer mlt_…` 请求头。管理端点（🔒）接受
  Cookie 会话或 API Token；请求带会话 Cookie 时按会话校验（无效一律 401，
  不回退到 Bearer），无会话头时按 Bearer 校验；
- **最小权限**：`read` 可调所有读端点；`write` 可调读写端点并隐含 `read`。
  scope 不足的写请求 → `403 forbidden`；
- **CSRF 防线不削弱**：管理端「写」请求（含 Token 调用方）仍必须携带
  `X-Requested-With: XMLHttpRequest`，否则 `403 forbidden`——与 Cookie 会话
  完全同一防线（Bearer 本不可被浏览器跨站伪造，此处为语义统一与纵深防御）；
- **可撤销 + 审计归属**：Token 归属创建者（`user_id`），`last_used_at`
  节流记录使用时刻（60s 内不重复写）；`DELETE /api/v1/auth/tokens/{token_id}`
  撤销后立即失效（`401`），撤销后的 Token 仍留在列表中并带 `revoked_at`；
  列表/撤销仅限属主，未知或不属于自己的 id → `404 not_found`；
- **边界分离**：API Token 只对管理 API 有效；`/api/v1/agent/heartbeat`
  仍只认 agent_token，反之 agent_token 也过不了管理 API 认证（§13.7）。

## 在线状态判定（已实现）

设备列表每个设备携带 `online_state` / `presence_source` / `last_seen_at`——
**状态必须标注数据来源与更新时间**（§12.2），不允许只给一个绿色「在线」图标：

| `online_state` | 判定条件 | `presence_source` |
|---|---|---|
| `online` | agent 上报在窗口内（默认 5 分钟） | `agent_report` |
| `tunnel_only` | 仅握手在窗口内（默认 2 分钟） | `handshake` |
| `offline` | 无任何新鲜证据 | 最新一条证据的来源：`handshake` / `agent_report` / `enrollment` / `none` |

- **握手新鲜 ≠ 在线**（§12.4）：WireGuard latest-handshake 只证明隧道连通，
  不能等同于设备全部网络功能正常，因此单独握手证据只给 `tunnel_only`；
- 判定输入是三类证据时间戳（`devices.last_handshake_at` /
  `last_report_at` / 加入时刻），纯函数实现于 `meshlet-domain/src/presence.rs`
  （窗口与判定时刻可注入，确定性单测）；
- 握手时间由 agent 从本地 `wg show` 读取后随心跳上报（§14.1），不需要
  WireGuard 内核集成即可采集；
- 窗口可配置：`presence_agent_window_secs`（默认 300）/
  `presence_handshake_window_secs`（默认 120）；
- 设备未持久化到 SQLite 前，证据时间戳仅存于内存 `MeshState`
  （schema 列已就位：migration 003）。

## 配置版本与应用状态（已实现）

「数据库写入成功 ≠ WireGuard/路由/NAT 已生效」（§10.1）：期望配置的每次变更
（建网络、设备加入等）只生成新的配置修订，初始状态 `pending`；只有把配置
应用到实际网络环境成功后才是 `applied`。控制台与外部调用方以 `apply_status`
为准，不以 DB 写入为准。

| `apply_status` | 含义 | `applied_at` | `error_summary` |
|---|---|---|---|
| `pending` | 已记录期望配置，尚未应用 | `null` | `null` |
| `applying` | 应用进行中（同步 API 内短暂出现） | `null` | `null` |
| `applied` | 已生效 | 应用时刻 | `null` |
| `failed` | 应用失败，含**结果不确定**（§10.3：不确定时进入明确失败态，不假装成功） | `null` | 失败诊断 |
| `rollback_pending` | 回滚发起但未能确认 | `null` | 应用失败 + 回滚失败诊断 |
| `rolled_back` | 已回滚（当前期望回落至更早版本） | `null` | 原失败诊断 |

- **失败可见**：apply 失败返回 `200` + 该修订视图（`apply_status: "failed"`
  与 `error_summary`），错误同时在版本详情与列表中可见；命令本身不吞失败；
- **幂等**：对已 `applied` 的版本重复 apply 直接返回该版本视图，**不再调用
  backend**（重复执行不破坏网络，§10.3）；
- **并发顺序（§10.4）**：修订号在同一网络内单调递增，配置修改由「先记录修订、
  再应用修订」串行化；对 `failed` 版本原地重试返回 `409 conflict`
  ——重试路径是记录新修订（版本号递增）；
- **回滚**只针对 `failed` 版本，且只删除/恢复 Meshlet 自有对象，
  **不得清空系统路由**（ADR-007、§10.3）；已生效版本的撤销走前滚新版本；
- 状态机与哈希实现于 `meshlet-domain/src/config_state.rs`（`ConfigLedger` /
  `ConfigApplyBackend` / `desired_config_hash`（覆盖 overlay/hub/Active 设备/LAN 路由，标签 `meshlet-desired-v2`），纯函数 + 16 项单测）；
  SQLite `config_revisions` 表字段与之逐列对齐（migration 001），
  持久化接线与控制平面其余内存状态（网络/设备）同批处理。



## 已核验的最小实现

`apps/server` 已实现：`GET /api/v1/system/status`、`GET/POST /api/v1/networks`、`POST /api/v1/networks/{id}/invites`、`DELETE /api/v1/networks/{id}/invites/{invite_id}`、`GET /api/v1/networks/{id}/devices`、`POST /api/v1/enroll`、`POST /api/v1/auth/bootstrap`、`POST /api/v1/auth/login`、`POST /api/v1/auth/logout`、`GET /api/v1/auth/me`、`GET/POST /api/v1/auth/tokens`、`DELETE /api/v1/auth/tokens/{token_id}`、`POST /api/v1/agent/heartbeat`、`GET/POST /api/v1/networks/{id}/routes`、`GET/DELETE /api/v1/networks/{id}/routes/{route_id}`、`POST /api/v1/networks/{id}/devices/{device_id}/revoke`、`GET /api/v1/audit`、`GET /api/v1/networks/{id}/config-revisions`、`GET/POST /api/v1/networks/{id}/config-revisions/{revision}`、`POST /api/v1/networks/{id}/config-revisions/{revision}/apply`、`POST /api/v1/networks/{id}/config-revisions/{revision}/rollback`、`GET /api/v1/system/metrics`；管理端点已挂会话/Token 认证 + CSRF 提取器（写端点另挂 `WriteUser` scope 检查），agent 端点挂 Bearer 提取器；全部 `/api` 路由另挂访问日志中间件（结构化日志 + HTTP 指标）。测试见 `apps/server/tests/{status,enroll,auth_console,api_token,migrations,presence,revisions,routes,device_revoke,audit,observability}.rs`。控制平面 Mesh 状态（含配置修订簿记）当前存于内存（`MeshState`）；用户/会话/agent/API Token 凭证持久化 SQLite（migrations 001/002/003/004）；审计事件持久化 SQLite（`audit_events`，migration 001，§16.5：敏感操作全记录、秘密材料不入表）。运行指标（§17.2 八项，Prometheus 文本格式，`GET /api/v1/system/metrics`）与结构化日志（§17.1 八字段，JSON 行）见 [可观测性](observability.md)。
